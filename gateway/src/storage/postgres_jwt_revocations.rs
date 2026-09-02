//! PostgreSQL JWT revocation store (issue #241, PR 9).
//!
//! The production `RevocationStore` for cluster mode. Standalone mode has
//! only the no-op store: a `jti` names a JWT, and nothing in the process
//! remembers one as withdrawn. Cluster mode records withdrawn JWTs in the
//! authority so every replica refuses them on the next request.
//!
//! What is stored, and what is not:
//!
//! - **The row is keyed by the normalized issuer and a digest of the
//!   `jti`, never the raw `jti`.** The digest is `SHA-256(deployment_id ||
//!   0x00 || issuer || 0x00 || jti)`: the deployment ID is the domain
//!   separator the HA state model requires ("every authoritative key
//!   derives from the deployment ID"), and the issuer is inside the digest
//!   as well as beside it so an equal `jti` from two issuers can never
//!   collide -- a `jti` is unique per issuer, not globally.
//! - **A `jti` is not consume-once.** This is a denylist: a row means "this
//!   JWT was withdrawn", and its absence means nothing. Bearer reuse stays
//!   valid; a separate explicit consume-once token type is out of scope
//!   (the issue says so in as many words).
//! - **Expiry is judged by the database clock**, and a row stays effective
//!   for the validator's `exp` leeway past its `expires_at` -- the token is
//!   accepted until then -- before it is a no-op on the read path and
//!   reclaimable by cleanup.
//!   `expires_at` is the JWT's own `exp` when the caller knows it: a
//!   revocation need not outlive the token it revokes. `NULL` means
//!   "until cleaned up by an operator".
//! - **A revoke is a committed control-plane mutation**: one transaction
//!   that reserves the shared security revision, inserts the row with it,
//!   and appends a `security_outbox` row (`resource_type =
//!   'jwt_revocation'`, `resource_id` = the digest). A repeat revoke of a
//!   `jti` whose row is still effective for at least as long spends
//!   nothing; one whose earlier finite row has lapsed, or that carries a
//!   later or unbounded expiry, replaces the row -- a lapsed row must never
//!   turn a break-glass revoke into a silent no-op.
//!
//! Failure classification on the read path: a store that cannot be
//! consulted is `AuthError::Upstream`, which the middleware answers with
//! `503`. It is never `InvalidSession` -- an unreachable denylist must not
//! look like an invalid credential -- and never a silent `false`.

use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::auth::{AuthError, RevocationStore};

use super::{log_classified, postgres::classify_pool_error, RepositoryError, RepositoryErrorKind};

const OPERATION_LOOKUP: &str = "jwt_revocation_lookup";
const OPERATION_REVOKE: &str = "jwt_revocation_revoke";
const OPERATION_CLEANUP: &str = "jwt_revocation_cleanup";
const RESOURCE_TYPE: &str = "jwt_revocation";
/// Retained past the validator's `exp` leeway as well: the validator
/// samples a whole-second clock and accepts while `exp < now - leeway` is
/// false, so a row that lapsed exactly at `exp + leeway` on the database
/// clock could still meet an accepting validator for up to a second --
/// longer with skew between the two clocks. Two seconds covers the
/// rounding and ordinary NTP skew; the decisions are still two clocks, so
/// this is a margin, not an equivalence.
pub const REVOCATION_RETENTION_MARGIN_SECS: u64 = 2;

/// What a revoke did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JwtRevocationOutcome {
    /// The row was inserted and the shared security revision advanced.
    Revoked { security_revision: i64 },
    /// The `jti` was already revoked for this issuer; nothing changed.
    AlreadyRevoked,
}

/// One issuer's view of the shared denylist. Constructed per JWT provider
/// with that provider's principal issuer baked in, so the store key and
/// the principal's identity boundary derive from the same value and can
/// never disagree.
pub struct PostgresJwtRevocationStore {
    pool: deadpool_postgres::Pool,
    deployment_id: Arc<str>,
    issuer: Arc<str>,
    /// How long past `expires_at` a row stays effective: the validator's
    /// `exp` leeway plus [`REVOCATION_RETENTION_MARGIN_SECS`], so a
    /// revocation keyed on the token's own `exp` covers the whole window in
    /// which some validator may still accept the token.
    retention_leeway_secs: f64,
}

impl PostgresJwtRevocationStore {
    pub fn new(pool: deadpool_postgres::Pool, deployment_id: &str, issuer: &str) -> Self {
        Self {
            pool,
            deployment_id: Arc::from(deployment_id),
            issuer: Arc::from(issuer),
            retention_leeway_secs: (crate::auth::jwt::JWT_EXP_LEEWAY_SECS
                + REVOCATION_RETENTION_MARGIN_SECS) as f64,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_retention_leeway_for_test(mut self, seconds: f64) -> Self {
        self.retention_leeway_secs = seconds;
        self
    }

    /// The stored key for a `jti`: a digest under the deployment and
    /// issuer, so the raw identifier never reaches the database.
    pub fn jti_digest(&self, jti: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.deployment_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(self.issuer.as_bytes());
        hasher.update([0u8]);
        hasher.update(jti.trim().as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Record a JWT as withdrawn. `expires_at` is RFC 3339 (the token's
    /// own `exp` when known); `None` keeps the row until cleanup.
    pub async fn revoke(
        &self,
        jti: &str,
        expires_at: Option<&str>,
        actor_user_id: &str,
    ) -> Result<JwtRevocationOutcome, RepositoryError> {
        // An empty `jti` names no token: the validator never consults the
        // store for one, so a row for it would be a false assurance.
        if jti.trim().is_empty() {
            return Err(RepositoryError::invalid_parameter(OPERATION_REVOKE, "jti"));
        }
        // The expiry is RFC 3339 by contract: parsed here, so a value only
        // PostgreSQL would accept (`tomorrow`, a zone-less date,
        // `infinity`) is the caller's error rather than a server-dependent
        // or unbounded lifetime.
        let expires_at = expires_at
            .map(|value| canonical_rfc3339(value, OPERATION_REVOKE, "expires_at"))
            .transpose()?;
        let digest = self.jti_digest(jti);
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        if let Some(expires_at) = expires_at.as_deref() {
            // An expiry the validator can no longer accept a token at (by
            // the database clock, past the retention window) could only
            // produce a row nothing is refused by, reported as "revoked":
            // the caller's input, refused before anything is written or
            // any revision spent. An expiry inside the window -- a token's
            // own `exp` a few seconds ago -- is still a live revocation.
            let still_effective: bool = client
                .query_one(
                    "SELECT $1::text::timestamptz > now() - make_interval(secs => $2)",
                    &[&expires_at, &self.retention_leeway_secs],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_REVOKE))?
                .try_get(0)
                .map_err(|_| invalid_data(OPERATION_REVOKE))?;
            if !still_effective {
                return Err(RepositoryError::invalid_parameter(
                    OPERATION_REVOKE,
                    "expires_at",
                ));
            }
        }
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| classify_query(error, OPERATION_REVOKE))?;
        let outcome: Result<JwtRevocationOutcome, RepositoryError> = async {
            // The reservation is rollback-safe: an already-revoked jti rolls
            // the transaction back and returns the revision with it.
            let revision_row = client
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
                .map_err(|error| classify_query(error, OPERATION_REVOKE))?;
            let security_revision: i64 = revision_row
                .try_get(0)
                .map_err(|_| invalid_data(OPERATION_REVOKE))?;
            let inserted = client
                .execute(
                    r#"
                    INSERT INTO greengateway.jwt_revocations (
                        issuer, jti_hash, expires_at, actor_user_id, security_revision
                    ) VALUES ($1, $2, $3::text::timestamptz, $4, $5)
                    ON CONFLICT (issuer, jti_hash) DO UPDATE SET
                        expires_at = CASE
                            WHEN EXCLUDED.expires_at IS NULL
                              OR greengateway.jwt_revocations.expires_at IS NULL THEN NULL
                            ELSE GREATEST(greengateway.jwt_revocations.expires_at, EXCLUDED.expires_at)
                        END,
                        revoked_at = now(),
                        actor_user_id = EXCLUDED.actor_user_id,
                        security_revision = EXCLUDED.security_revision
                    WHERE greengateway.jwt_revocations.expires_at IS NOT NULL
                      AND (
                          greengateway.jwt_revocations.expires_at <= now() - make_interval(secs => $6)
                          OR EXCLUDED.expires_at IS NULL
                          OR EXCLUDED.expires_at > greengateway.jwt_revocations.expires_at
                      )
                    "#,
                    &[
                        &self.issuer.as_ref(),
                        &digest,
                        &expires_at.as_deref(),
                        &actor_user_id,
                        &security_revision,
                        &self.retention_leeway_secs,
                    ],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_REVOKE))?;
            if inserted == 0 {
                return Ok(JwtRevocationOutcome::AlreadyRevoked);
            }
            client
                .execute(
                    r#"
                    INSERT INTO greengateway.security_outbox (
                        revision, resource_type, from_version, to_version, resource_id
                    ) VALUES ($1, $2, NULL, 1, $3)
                    "#,
                    &[&security_revision, &RESOURCE_TYPE, &digest],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_REVOKE))?;
            Ok(JwtRevocationOutcome::Revoked { security_revision })
        }
        .await;
        match outcome {
            Ok(JwtRevocationOutcome::Revoked { security_revision }) => {
                client
                    .batch_execute("COMMIT")
                    .await
                    .map_err(|error| classify_query(error, OPERATION_REVOKE))?;
                Ok(JwtRevocationOutcome::Revoked { security_revision })
            }
            Ok(JwtRevocationOutcome::AlreadyRevoked) => {
                // Nothing to keep: give the reserved revision back.
                let _ = client.batch_execute("ROLLBACK").await;
                Ok(JwtRevocationOutcome::AlreadyRevoked)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    /// Delete up to `limit` rows whose `expires_at` has passed. Idempotent
    /// and bounded; the singleton scheduling of this work arrives with the
    /// membership PR. Returns how many rows were deleted.
    pub async fn cleanup_expired(&self, limit: usize) -> Result<u64, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        client
            .execute(
                r#"
                DELETE FROM greengateway.jwt_revocations
                WHERE ctid IN (
                    SELECT ctid FROM greengateway.jwt_revocations
                    WHERE expires_at IS NOT NULL
                      AND expires_at <= now() - make_interval(secs => $2)
                    LIMIT $1
                )
                "#,
                &[&limit, &self.retention_leeway_secs],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_CLEANUP))
    }
}

#[async_trait]
impl RevocationStore for PostgresJwtRevocationStore {
    async fn is_revoked(&self, jti: &str) -> Result<bool, AuthError> {
        let digest = self.jti_digest(jti);
        let client = self
            .pool
            .get()
            .await
            .map_err(classify_pool_error)
            .map_err(dependency_failure)?;
        let row = client
            .query_one(
                r#"
                SELECT EXISTS (
                    SELECT 1 FROM greengateway.jwt_revocations
                    WHERE issuer = $1 AND jti_hash = $2
                      AND (expires_at IS NULL OR expires_at > now() - make_interval(secs => $3))
                )
                "#,
                &[&self.issuer.as_ref(), &digest, &self.retention_leeway_secs],
            )
            .await
            .map_err(|error| dependency_failure(classify_query(error, OPERATION_LOOKUP)))?;
        row.try_get::<_, bool>(0)
            .map_err(|_| dependency_failure(invalid_data(OPERATION_LOOKUP)))
    }
}

/// A denylist that cannot be consulted is a dependency failure, answered
/// `503`; it is never an invalid credential and never "not revoked".
fn dependency_failure(error: RepositoryError) -> AuthError {
    AuthError::Upstream(format!("JWT revocation store error: {error}"))
}

/// Parse an RFC 3339 instant and return it re-serialized in RFC 3339, so
/// only that grammar reaches the database.
fn canonical_rfc3339(
    value: &str,
    operation: &'static str,
    parameter: &'static str,
) -> Result<String, RepositoryError> {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .and_then(|instant| instant.format(&Rfc3339).ok())
        .ok_or_else(|| RepositoryError::invalid_parameter(operation, parameter))
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}
