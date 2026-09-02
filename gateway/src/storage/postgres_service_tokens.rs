//! PostgreSQL service-token store (issue #241, PR 9).
//!
//! The cluster-mode authority for service tokens, satisfying the same
//! [`ServiceTokenStore`] contract the standalone SQLite adapter satisfies,
//! with the SQLite store's exact semantics (plaintext once, idempotent
//! monotonic revoke, rotate-after-revoke is a conflict, keyset listing
//! newest-first) plus what cluster mode adds:
//!
//! - **Every token mutation is a committed control-plane mutation.** Create,
//!   revoke, and rotate each run one transaction that advances the shared
//!   `security_revision_state` counter, SETS this resource's high-water mark
//!   to that revision, and appends a `security_outbox` row naming the token.
//!   The strict gate therefore observes a revoke on its next
//!   `current_revision` read, on every replica, which is what makes
//!   "the next request after commit refuses the token" true cluster-wide.
//! - **Database time is authoritative.** Expiry is compared against
//!   `now()` inside the statement; no replica clock participates.
//! - **A revoke cannot be undone by a racing verify.** `verify` writes
//!   `last_used_at` with the revoked/expired guard in the same statement's
//!   `WHERE`, so it either finds a live row and touches it, or finds
//!   nothing and reports why -- there is no window in which it touches a
//!   row a revoke has closed.
//!
//! Lock order, identical in every mutating path so no two paths can
//! deadlock: (1) `service_token_state_revision` `FOR UPDATE`, which
//! serializes token mutations against each other; (2) the token row
//! `FOR UPDATE`; (3) `security_revision_state`, always last. No transaction
//! in the tree takes another store's singleton after this one, so the
//! order composes with the connection store's.
//!
//! Errors carry a classification and a static operation label only -- no
//! SQL, no values, no token material. The plaintext token exists in one
//! `CreatedToken`; it is never logged, never formatted, never stored.

use async_trait::async_trait;
use tokio_postgres::types::{FromSql, ToSql};

use crate::auth::tokens::{
    decode_cursor, display_prefix, encode_cursor, generate_plaintext_token, hash_token,
    new_token_id, query_limit, validate_optional_timestamp, CreateTokenRequest, CreatedToken,
    TokenCursor, TokenListFilters, TokenPage, TokenRecord, TokenStoreError, TokenVerification,
    TokenVerificationFailure, VerifiedToken,
};

use super::{
    log_classified, postgres::classify_pool_error, postgres_policy::SecurityRevisionSource,
    RepositoryError, RepositoryErrorKind, ServiceTokenStore,
};

/// The shared revision counter is the validator's per-request authority
/// check in cluster mode.
#[async_trait]
impl crate::auth::service_token_validator::AuthRevisionSource for SecurityRevisionSource {
    async fn current(&self) -> Result<i64, RepositoryError> {
        SecurityRevisionSource::current(self).await
    }
}

const OPERATION_CREATE: &str = "service_token_create";
const OPERATION_LIST: &str = "service_token_list";
const OPERATION_GET: &str = "service_token_get";
const OPERATION_REVOKE: &str = "service_token_revoke";
const OPERATION_ROTATE: &str = "service_token_rotate";
const OPERATION_VERIFY: &str = "service_token_verify";
const OPERATION_TOUCH: &str = "service_token_touch_last_used";
const OPERATION_STATE_REVISION: &str = "service_token_state_revision_read";

/// The outbox label. `from_version`/`to_version` carry the token row's
/// `revision` (a create is `NULL -> 1`), and `resource_id` the token id.
const RESOURCE_TYPE: &str = "service_token";

/// RFC 3339 in UTC with microseconds, the precision `timestamptz` holds, so
/// a listing cursor round-trips through the database to the same instant.
const TIMESTAMP_FORMAT: &str = r#"'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'"#;

/// The columns every read returns, in the order [`RawRow::from_row`]
/// decodes them. `revision` is the per-row change counter the race tests
/// observe; it is not part of the public record.
fn select_columns() -> String {
    format!(
        "id, token_prefix, scopes_json, created_by, \
         to_char(created_at AT TIME ZONE 'UTC', {f}), \
         to_char(expires_at AT TIME ZONE 'UTC', {f}), \
         to_char(last_used_at AT TIME ZONE 'UTC', {f}), \
         to_char(revoked_at AT TIME ZONE 'UTC', {f}), \
         revision",
        f = TIMESTAMP_FORMAT
    )
}

pub struct PostgresServiceTokenStore {
    pool: deadpool_postgres::Pool,
}

impl PostgresServiceTokenStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }

    /// The shared revision-counter view over this store's pool: the
    /// validator's per-request authority check.
    pub fn revision_source(&self) -> SecurityRevisionSource {
        SecurityRevisionSource::new(self.pool.clone())
    }

    /// The security revision at which a service token last changed: this
    /// resource's activation revision for the cluster gate. Always a value
    /// of the shared counter (set on every mutation), never a private
    /// count, so it compares directly against the gate's watermark.
    pub async fn state_revision(&self) -> Result<i64, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_opt(
                "SELECT last_revision FROM greengateway.service_token_state_revision WHERE singleton",
                &[],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_STATE_REVISION))?;
        // Seeded by migration 7 and never deleted; absence means the
        // schema is not the one this build expects.
        let row = row.ok_or_else(|| invalid_data(OPERATION_STATE_REVISION))?;
        column(&row, 0, OPERATION_STATE_REVISION)
    }

    async fn load_by_id(
        client: &deadpool_postgres::Object,
        id: &str,
        operation: &'static str,
        for_update: bool,
    ) -> Result<Option<RawRow>, RepositoryError> {
        let sql = format!(
            "SELECT {} FROM greengateway.service_tokens WHERE id = $1{}",
            select_columns(),
            if for_update { " FOR UPDATE" } else { "" }
        );
        let row = client
            .query_opt(sql.as_str(), &[&id])
            .await
            .map_err(|error| classify_query(error, operation))?;
        row.map(|row| RawRow::from_row(&row, operation)).transpose()
    }
}

#[async_trait]
impl ServiceTokenStore for PostgresServiceTokenStore {
    async fn create(&self, request: CreateTokenRequest) -> Result<CreatedToken, RepositoryError> {
        // A malformed expiry is the caller's input, answered 400 by the
        // admin API through the parameter-carrying classification; it is
        // rejected before any connection is taken.
        validate_optional_timestamp(request.expires_at.as_deref(), "expires_at")
            .map_err(|error| map_helper_error(OPERATION_CREATE, error))?;
        let plaintext_token = generate_plaintext_token()
            .map_err(|error| map_helper_error(OPERATION_CREATE, error))?;
        let token_hash = hash_token(&plaintext_token);
        let token_prefix = display_prefix(&plaintext_token);
        let id = new_token_id();
        let scopes_json =
            serde_json::to_string(&request.scopes).map_err(|_| invalid_data(OPERATION_CREATE))?;

        let client = self.pool.get().await.map_err(classify_pool_error)?;
        begin_mutation(&client, OPERATION_CREATE).await?;
        let outcome: Result<TokenRecord, RepositoryError> = async {
            let security_revision = reserve_shared_revision(&client, OPERATION_CREATE).await?;
            let sql = format!(
                r#"
                INSERT INTO greengateway.service_tokens (
                    id, token_hash, token_prefix, scopes_json, created_by,
                    expires_at, revision, security_revision
                ) VALUES ($1, $2, $3, $4, $5, $6::text::timestamptz, 1, $7)
                RETURNING {}
                "#,
                select_columns()
            );
            let row = client
                .query_one(
                    sql.as_str(),
                    &[
                        &id,
                        &token_hash,
                        &token_prefix,
                        &scopes_json,
                        &request.created_by,
                        &request.expires_at,
                        &security_revision,
                    ],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_CREATE))?;
            let raw = RawRow::from_row(&row, OPERATION_CREATE)?;
            record_revision(
                &client,
                OPERATION_CREATE,
                security_revision,
                &id,
                None,
                raw.revision,
            )
            .await?;
            Ok(raw.record)
        }
        .await;
        let record = finish(&client, OPERATION_CREATE, outcome).await?;
        Ok(CreatedToken {
            record,
            plaintext_token,
        })
    }

    async fn list(&self, filters: &TokenListFilters) -> Result<TokenPage, RepositoryError> {
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<TokenCursor>("cursor", value))
            .transpose()
            .map_err(|error| map_helper_error(OPERATION_LIST, error))?;
        let limit = query_limit(filters.limit);
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        // The keyset predicate mirrors the SQLite store's
        // `build_token_list_query`: strictly older, or the same instant and
        // a greater id. The cursor's `created_at` is the text this store
        // rendered, so the cast recovers the exact instant.
        let rows = match cursor.as_ref() {
            Some(cursor) => {
                let sql = format!(
                    r#"
                    SELECT {} FROM greengateway.service_tokens
                    WHERE created_at < $1::text::timestamptz
                       OR (created_at = $1::text::timestamptz AND id > $2)
                    ORDER BY created_at DESC, id ASC
                    LIMIT $3
                    "#,
                    select_columns()
                );
                client
                    .query(sql.as_str(), &[&cursor.created_at, &cursor.id, &limit])
                    .await
            }
            None => {
                let sql = format!(
                    "SELECT {} FROM greengateway.service_tokens \
                     ORDER BY created_at DESC, id ASC LIMIT $1",
                    select_columns()
                );
                client.query(sql.as_str(), &[&limit]).await
            }
        }
        .map_err(|error| classify_query(error, OPERATION_LIST))?;

        let mut rows = rows
            .iter()
            .map(|row| RawRow::from_row(row, OPERATION_LIST))
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = rows.len() > filters.limit;
        if has_more {
            rows.truncate(filters.limit);
        }
        let next_cursor = if has_more {
            rows.last()
                .map(|row| {
                    encode_cursor(&TokenCursor {
                        created_at: row.record.created_at.clone(),
                        id: row.record.id.clone(),
                    })
                })
                .transpose()
                .map_err(|error| map_helper_error(OPERATION_LIST, error))?
        } else {
            None
        };
        Ok(TokenPage {
            tokens: rows.into_iter().map(|row| row.record).collect(),
            next_cursor,
        })
    }

    async fn get_by_id(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        Ok(Self::load_by_id(&client, id, OPERATION_GET, false)
            .await?
            .map(|row| row.record))
    }

    async fn revoke(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        begin_mutation(&client, OPERATION_REVOKE).await?;
        let outcome: Result<Option<TokenRecord>, RepositoryError> = async {
            let Some(current) = Self::load_by_id(&client, id, OPERATION_REVOKE, true).await? else {
                return Ok(None);
            };
            // Idempotent and monotonic: the first revoked_at is the one that
            // stands, and a repeat neither rewrites it nor spends a revision.
            if current.record.revoked_at.is_some() {
                return Ok(Some(current.record));
            }
            let security_revision = reserve_shared_revision(&client, OPERATION_REVOKE).await?;
            let sql = format!(
                r#"
                UPDATE greengateway.service_tokens
                SET revoked_at = now(), revision = revision + 1, security_revision = $2
                WHERE id = $1 AND revoked_at IS NULL
                RETURNING {}
                "#,
                select_columns()
            );
            let row = client
                .query_one(sql.as_str(), &[&id, &security_revision])
                .await
                .map_err(|error| classify_query(error, OPERATION_REVOKE))?;
            let revoked = RawRow::from_row(&row, OPERATION_REVOKE)?;
            record_revision(
                &client,
                OPERATION_REVOKE,
                security_revision,
                id,
                Some(current.revision),
                revoked.revision,
            )
            .await?;
            Ok(Some(revoked.record))
        }
        .await;
        finish(&client, OPERATION_REVOKE, outcome).await
    }

    async fn rotate(&self, id: &str) -> Result<Option<CreatedToken>, RepositoryError> {
        let plaintext_token = generate_plaintext_token()
            .map_err(|error| map_helper_error(OPERATION_ROTATE, error))?;
        let token_hash = hash_token(&plaintext_token);
        let token_prefix = display_prefix(&plaintext_token);

        let client = self.pool.get().await.map_err(classify_pool_error)?;
        begin_mutation(&client, OPERATION_ROTATE).await?;
        let outcome: Result<Option<TokenRecord>, RepositoryError> = async {
            let Some(current) = Self::load_by_id(&client, id, OPERATION_ROTATE, true).await? else {
                return Ok(None);
            };
            // A revoked token stays revoked: rotating it would mint a live
            // plaintext for a token an operator has already withdrawn.
            if current.record.revoked_at.is_some() {
                return Err(RepositoryError::new(
                    RepositoryErrorKind::Conflict,
                    OPERATION_ROTATE,
                ));
            }
            let security_revision = reserve_shared_revision(&client, OPERATION_ROTATE).await?;
            let sql = format!(
                r#"
                UPDATE greengateway.service_tokens
                SET token_hash = $2, token_prefix = $3,
                    revision = revision + 1, security_revision = $4
                WHERE id = $1 AND revoked_at IS NULL
                RETURNING {}
                "#,
                select_columns()
            );
            let row = client
                .query_one(
                    sql.as_str(),
                    &[&id, &token_hash, &token_prefix, &security_revision],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_ROTATE))?;
            let rotated = RawRow::from_row(&row, OPERATION_ROTATE)?;
            record_revision(
                &client,
                OPERATION_ROTATE,
                security_revision,
                id,
                Some(current.revision),
                rotated.revision,
            )
            .await?;
            Ok(Some(rotated.record))
        }
        .await;
        let record = finish(&client, OPERATION_ROTATE, outcome).await?;
        Ok(record.map(|record| CreatedToken {
            record,
            plaintext_token,
        }))
    }

    async fn verify(&self, plaintext_token: &str) -> Result<TokenVerification, RepositoryError> {
        let token_hash = hash_token(plaintext_token);
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        // One statement decides validity and records use. The guard is in
        // the WHERE, so a revoke that committed first leaves nothing for
        // this to touch: the revoked row can never be "resurrected" by a
        // trailing last_used_at write, and expiry is judged by the
        // database clock.
        let sql = format!(
            r#"
            UPDATE greengateway.service_tokens
            SET last_used_at = now()
            WHERE token_hash = $1
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
            RETURNING {},
              CASE WHEN expires_at IS NULL THEN NULL
                   ELSE GREATEST(EXTRACT(EPOCH FROM (expires_at - now())), 0)::double precision
              END
            "#,
            select_columns()
        );
        let touched = client
            .query_opt(sql.as_str(), &[&token_hash])
            .await
            .map_err(|error| classify_query(error, OPERATION_VERIFY))?;
        if let Some(row) = touched {
            let raw = RawRow::from_row(&row, OPERATION_VERIFY)?;
            return Ok(TokenVerification::Valid(VerifiedToken {
                id: raw.record.id,
                token_prefix: raw.record.token_prefix,
                scopes: raw.record.scopes,
                expires_at: raw.record.expires_at,
                last_used_at: raw.record.last_used_at,
                remaining_lifetime: remaining_lifetime_from_row(&row)?,
            }));
        }
        // Not live: say why, without touching anything.
        let sql = format!(
            "SELECT {} FROM greengateway.service_tokens WHERE token_hash = $1",
            select_columns()
        );
        let row = client
            .query_opt(sql.as_str(), &[&token_hash])
            .await
            .map_err(|error| classify_query(error, OPERATION_VERIFY))?;
        let failure = match row {
            None => TokenVerificationFailure::NotFound,
            Some(row) => {
                let raw = RawRow::from_row(&row, OPERATION_VERIFY)?;
                if raw.record.revoked_at.is_some() {
                    TokenVerificationFailure::Revoked
                } else {
                    TokenVerificationFailure::Expired
                }
            }
        };
        Ok(TokenVerification::Invalid(failure))
    }

    async fn touch_last_used(&self, id: &str) -> Result<Option<TokenRecord>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let sql = format!(
            r#"
            UPDATE greengateway.service_tokens
            SET last_used_at = now()
            WHERE id = $1
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > now())
            RETURNING {}
            "#,
            select_columns()
        );
        let touched = client
            .query_opt(sql.as_str(), &[&id])
            .await
            .map_err(|error| classify_query(error, OPERATION_TOUCH))?;
        match touched {
            Some(row) => Ok(Some(RawRow::from_row(&row, OPERATION_TOUCH)?.record)),
            // A revoked or expired token is returned as it stands, untouched;
            // an unknown id is None. Same contract as the SQLite store.
            None => Ok(Self::load_by_id(&client, id, OPERATION_TOUCH, false)
                .await?
                .map(|row| row.record)),
        }
    }
}

struct RawRow {
    record: TokenRecord,
    revision: i64,
}

impl RawRow {
    fn from_row(
        row: &tokio_postgres::Row,
        operation: &'static str,
    ) -> Result<Self, RepositoryError> {
        let scopes_json: String = column(row, 2, operation)?;
        let scopes = serde_json::from_str::<Vec<String>>(&scopes_json)
            .map_err(|_| invalid_data(operation))?;
        Ok(Self {
            record: TokenRecord {
                id: column(row, 0, operation)?,
                token_prefix: column(row, 1, operation)?,
                scopes,
                created_by: column(row, 3, operation)?,
                created_at: column(row, 4, operation)?,
                expires_at: column(row, 5, operation)?,
                last_used_at: column(row, 6, operation)?,
                revoked_at: column(row, 7, operation)?,
            },
            revision: column(row, 8, operation)?,
        })
    }
}

/// Open a mutating transaction and take the first lock of the documented
/// order: the resource's high-water-mark row. Rolls back if the lock step
/// itself fails, so no open transaction returns to the pool.
async fn begin_mutation(
    client: &deadpool_postgres::Object,
    operation: &'static str,
) -> Result<(), RepositoryError> {
    client
        .batch_execute("BEGIN")
        .await
        .map_err(|error| classify_query(error, operation))?;
    let locked = client
        .query_opt(
            "SELECT last_revision FROM greengateway.service_token_state_revision \
             WHERE singleton FOR UPDATE",
            &[],
        )
        .await;
    match locked {
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            let _ = client.batch_execute("ROLLBACK").await;
            Err(invalid_data(operation))
        }
        Err(error) => {
            let _ = client.batch_execute("ROLLBACK").await;
            Err(classify_query(error, operation))
        }
    }
}

/// Reserve the next shared security revision. Last in the lock order; a
/// rollback returns the reservation with everything else.
async fn reserve_shared_revision(
    client: &deadpool_postgres::Object,
    operation: &'static str,
) -> Result<i64, RepositoryError> {
    let row = client
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
        .map_err(|error| classify_query(error, operation))?;
    column(&row, 0, operation)
}

/// SET the high-water mark to the reserved revision and append the outbox
/// row. Set, never incremented: see the migration header.
async fn record_revision(
    client: &deadpool_postgres::Object,
    operation: &'static str,
    security_revision: i64,
    token_id: &str,
    from_version: Option<i64>,
    to_version: i64,
) -> Result<(), RepositoryError> {
    client
        .execute(
            "UPDATE greengateway.service_token_state_revision SET last_revision = $1 WHERE singleton",
            &[&security_revision],
        )
        .await
        .map_err(|error| classify_query(error, operation))?;
    client
        .execute(
            r#"
            INSERT INTO greengateway.security_outbox (
                revision, resource_type, from_version, to_version, resource_id
            ) VALUES ($1, $2, $3, $4, $5)
            "#,
            &[
                &security_revision,
                &RESOURCE_TYPE,
                &from_version,
                &to_version,
                &token_id,
            ],
        )
        .await
        .map_err(|error| classify_query(error, operation))?;
    Ok(())
}

/// COMMIT on success, ROLLBACK on failure. A future dropped between BEGIN
/// and here is covered by the pool's ROLLBACK-on-recycle (PR 8).
async fn finish<T>(
    client: &deadpool_postgres::Object,
    operation: &'static str,
    outcome: Result<T, RepositoryError>,
) -> Result<T, RepositoryError> {
    match outcome {
        Ok(value) => {
            client
                .batch_execute("COMMIT")
                .await
                .map_err(|error| classify_query(error, operation))?;
            Ok(value)
        }
        Err(error) => {
            let _ = client.batch_execute("ROLLBACK").await;
            Err(error)
        }
    }
}

fn column<'a, T: FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    index: usize,
    operation: &'static str,
) -> Result<T, RepositoryError> {
    row.try_get(index).map_err(|error| {
        tracing::error!(operation, error = %error, "service-token row did not decode");
        invalid_data(operation)
    })
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

/// The shared token-format helpers report through the SQLite store's error
/// type; classify them the way the SQLite adapter does so both backends
/// answer the same client input the same way.
/// The trailing `RETURNING` column of `verify`: seconds the database clock
/// says remain before `expires_at`, or NULL without an expiry.
fn remaining_lifetime_from_row(
    row: &tokio_postgres::Row,
) -> Result<Option<std::time::Duration>, RepositoryError> {
    let seconds: Option<f64> = row.try_get(row.len() - 1).map_err(|_| {
        RepositoryError::new(
            crate::storage::RepositoryErrorKind::InvalidData,
            OPERATION_VERIFY,
        )
    })?;
    Ok(seconds.map(|seconds| std::time::Duration::from_secs_f64(seconds.max(0.0))))
}

fn map_helper_error(operation: &'static str, error: TokenStoreError) -> RepositoryError {
    let classified = match &error {
        TokenStoreError::TimeParse { context, .. } if operation == OPERATION_CREATE => {
            RepositoryError::invalid_parameter(operation, context)
        }
        TokenStoreError::InvalidCursor { parameter } => {
            RepositoryError::invalid_parameter(operation, parameter)
        }
        TokenStoreError::Random(_) => {
            RepositoryError::new(RepositoryErrorKind::Internal, operation)
        }
        _ => RepositoryError::new(RepositoryErrorKind::InvalidData, operation),
    };
    log_classified(operation, &error, classified)
}

// Silence the unused-import lint on the one trait object we only name in
// signatures.
#[allow(dead_code)]
fn _assert_to_sql(_: &dyn ToSql) {}
