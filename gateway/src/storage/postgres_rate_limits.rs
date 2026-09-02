//! PostgreSQL rate-limit store (issue #241, PR 10).
//!
//! Cluster mode's shared rate limiter. The process-local limiter in
//! `middleware/rate_limit.rs` keeps one bucket per caller per replica, so
//! N replicas grant N times the configured burst; this store keeps one
//! bucket per caller for the whole deployment and decides every request
//! with one atomic statement on database time, so one configured burst of
//! N permits N requests across the cluster.
//!
//! What is stored, and what is not:
//!
//! - **The caller key never reaches the database.** The row is keyed by
//!   `HMAC-SHA-256(primary rate-limit key, deployment_id || 0 || lane || 0
//!   || key)`. The key string is the same one the local limiter hashes
//!   (`ip:<canonical address>` for the global lanes; the issuer- and
//!   method-qualified principal for the policy lane, prefixed by the
//!   rule's fingerprint), so the identity boundaries the local limiter
//!   keeps are kept here, and a reader of the table or of a backup cannot
//!   enumerate the IPv4 space against the digests without the key.
//! - **The decision is GCRA on database time.** With emission interval
//!   `T = 1/rps` and tolerance `tau = (burst - 1) * T`, a request is
//!   allowed iff `GREATEST(tat, now()) - now() <= tau`, and an allowed
//!   request advances `tat` to `GREATEST(tat, now()) + T`. That is the
//!   local token bucket (burst `B`, starting full, refilling at `rps`)
//!   written as one comparison and one assignment, including the local
//!   store's rule that a zero burst denies the very first request
//!   (`tau < 0`). No replica keeps a private count.
//! - **Cardinality is bounded exactly.** `rate_limit_cardinality` counts
//!   live buckets per deployment and moves in the same statement that
//!   inserts or deletes rows, so it cannot drift; when a new key pushes
//!   the count past the bound, one bounded statement evicts the oldest
//!   buckets. An idle sweep for the cluster's maintenance singleton
//!   reclaims buckets nobody has touched for the configured TTL.
//!
//! A store that cannot be consulted is a [`RepositoryError`]; the
//! middleware answers `503` with zero upstream attempts. It is never a
//! silent allow and never a `429`.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::connections::local_secret::LocalSecretKeyring;

use super::{log_classified, postgres::classify_pool_error, RepositoryError, RepositoryErrorKind};

const OPERATION_DECIDE: &str = "rate_limit_decide";
const OPERATION_EVICT: &str = "rate_limit_evict";
const OPERATION_CLEANUP: &str = "rate_limit_cleanup";

/// The largest number of buckets one eviction statement removes: enough to
/// bring a deployment back under its bound quickly without one request
/// paying for a long delete.
const EVICTION_BATCH: i64 = 256;

/// An emission interval standing in for "never refills" when a limit's
/// rate is not positive: the local limiter's bucket with `rps = 0` never
/// refills either, and denies once its burst is spent.
const NEVER_REFILLS_SECS: f64 = 1.0e9;

/// The shared bucket family a decision is made in: the two global,
/// pre-authentication lanes and the policy (per-principal) lane.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedLane {
    Read,
    Write,
    Policy,
}

impl SharedLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Policy => "policy",
        }
    }
}

/// The configured limit a decision is made against.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SharedLimit {
    pub requests_per_second: f64,
    pub burst: u32,
}

impl SharedLimit {
    fn emission_interval_secs(self) -> f64 {
        if self.requests_per_second.is_finite() && self.requests_per_second > 0.0 {
            1.0 / self.requests_per_second
        } else {
            NEVER_REFILLS_SECS
        }
    }

    fn tolerance_secs(self) -> f64 {
        (f64::from(self.burst) - 1.0) * self.emission_interval_secs()
    }
}

/// The shared limiter's answer for one request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedDecision {
    Allowed,
    Denied,
}

/// The cluster-wide rate limiter over one PostgreSQL pool.
#[derive(Clone)]
pub struct PostgresRateLimitStore {
    pool: deadpool_postgres::Pool,
    deployment_id: String,
    keyring: LocalSecretKeyring,
    max_buckets: i64,
}

impl PostgresRateLimitStore {
    pub fn new(
        pool: deadpool_postgres::Pool,
        deployment_id: &str,
        keyring: LocalSecretKeyring,
        max_buckets: usize,
    ) -> Self {
        Self {
            pool,
            deployment_id: deployment_id.to_owned(),
            keyring,
            max_buckets: i64::try_from(max_buckets.max(1)).unwrap_or(i64::MAX),
        }
    }

    /// The digest a caller key is stored under: an HMAC under the primary
    /// rate-limit key, domain-separated by deployment and lane.
    fn key_digest(&self, lane: SharedLane, key: &str) -> Result<Vec<u8>, RepositoryError> {
        let material = self
            .keyring
            .key(self.keyring.primary_id())
            .ok_or_else(|| internal(OPERATION_DECIDE))?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(material).map_err(|_| internal(OPERATION_DECIDE))?;
        mac.update(self.deployment_id.as_bytes());
        mac.update(&[0u8]);
        mac.update(lane.as_str().as_bytes());
        mac.update(&[0u8]);
        mac.update(key.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Decide one request for `key` in `lane` against `limit`: one atomic
    /// statement that creates or advances the bucket and, for a new key,
    /// counts it; then, only when the count passed the bound, one bounded
    /// eviction of the oldest buckets.
    pub async fn decide(
        &self,
        lane: SharedLane,
        key: &str,
        limit: SharedLimit,
    ) -> Result<SharedDecision, RepositoryError> {
        let digest = self.key_digest(lane, key)?;
        let emission = limit.emission_interval_secs();
        let tolerance = limit.tolerance_secs();
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_one(
                "WITH upsert AS (
                     INSERT INTO greengateway.rate_limit_buckets AS b
                         (deployment_id, lane, key_digest, tat, allowed, updated_at)
                     VALUES ($1, $2, $3,
                         now() + CASE WHEN $5::double precision >= 0
                                      THEN make_interval(secs => $4::double precision)
                                      ELSE interval '0' END,
                         $5::double precision >= 0,
                         now())
                     ON CONFLICT (deployment_id, lane, key_digest) DO UPDATE SET
                         allowed = (GREATEST(b.tat, now()) - now())
                             <= make_interval(secs => $5::double precision),
                         tat = CASE WHEN (GREATEST(b.tat, now()) - now())
                                         <= make_interval(secs => $5::double precision)
                                    THEN GREATEST(b.tat, now())
                                         + make_interval(secs => $4::double precision)
                                    ELSE b.tat END,
                         updated_at = now()
                     RETURNING b.allowed AS allowed, (b.xmax = 0) AS inserted
                 ),
                 counted AS (
                     INSERT INTO greengateway.rate_limit_cardinality AS c (deployment_id, live)
                     SELECT $1, 1 FROM upsert WHERE upsert.inserted
                     ON CONFLICT (deployment_id) DO UPDATE SET live = c.live + 1
                     RETURNING c.live AS live
                 )
                 SELECT upsert.allowed, upsert.inserted,
                        (SELECT live FROM counted) AS live
                 FROM upsert",
                &[
                    &self.deployment_id,
                    &lane.as_str(),
                    &digest,
                    &emission,
                    &tolerance,
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_DECIDE))?;
        let allowed: bool = row
            .try_get("allowed")
            .map_err(|_| invalid_data(OPERATION_DECIDE))?;
        let inserted: bool = row
            .try_get("inserted")
            .map_err(|_| invalid_data(OPERATION_DECIDE))?;
        let live: Option<i64> = row
            .try_get("live")
            .map_err(|_| invalid_data(OPERATION_DECIDE))?;
        if inserted {
            if let Some(live) = live {
                if live > self.max_buckets {
                    self.evict_oldest(live - self.max_buckets).await?;
                }
            }
        }
        Ok(if allowed {
            SharedDecision::Allowed
        } else {
            SharedDecision::Denied
        })
    }

    /// Remove the `excess` oldest buckets (bounded per statement) and
    /// bring the count down with them, in one statement.
    async fn evict_oldest(&self, excess: i64) -> Result<(), RepositoryError> {
        let batch = excess.clamp(1, EVICTION_BATCH);
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        client
            .execute(
                "WITH gone AS (
                     DELETE FROM greengateway.rate_limit_buckets
                     WHERE ctid = ANY(ARRAY(
                         SELECT ctid FROM greengateway.rate_limit_buckets
                         WHERE deployment_id = $1
                         ORDER BY updated_at ASC
                         LIMIT $2))
                     RETURNING 1
                 )
                 UPDATE greengateway.rate_limit_cardinality
                 SET live = GREATEST(live - (SELECT count(*) FROM gone), 0)
                 WHERE deployment_id = $1",
                &[&self.deployment_id, &batch],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_EVICT))?;
        Ok(())
    }

    /// Reclaim up to `limit` buckets idle for at least `idle_secs` by the
    /// database clock, keeping the count exact. For the maintenance
    /// singleton; returns how many were removed.
    pub async fn cleanup_idle(&self, idle_secs: f64, limit: u32) -> Result<u64, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        self.cleanup_idle_with(&client, idle_secs, limit).await
    }

    /// [`Self::cleanup_idle`] over a connection the caller holds: the
    /// maintenance singleton (issue #241, PR 13) runs its step on the
    /// dedicated session that holds the maintenance advisory lock, so the
    /// lock covers the statement itself.
    pub(crate) async fn cleanup_idle_with(
        &self,
        client: &tokio_postgres::Client,
        idle_secs: f64,
        limit: u32,
    ) -> Result<u64, RepositoryError> {
        let limit = i64::from(limit.max(1));
        let row = client
            .query_opt(
                "WITH gone AS (
                     DELETE FROM greengateway.rate_limit_buckets
                     WHERE ctid = ANY(ARRAY(
                         SELECT ctid FROM greengateway.rate_limit_buckets
                         WHERE deployment_id = $1
                           AND updated_at <= now() - make_interval(secs => $2::double precision)
                         ORDER BY updated_at ASC
                         LIMIT $3))
                     RETURNING 1
                 )
                 UPDATE greengateway.rate_limit_cardinality
                 SET live = GREATEST(live - (SELECT count(*) FROM gone), 0)
                 WHERE deployment_id = $1
                 RETURNING (SELECT count(*) FROM gone) AS removed",
                &[&self.deployment_id, &idle_secs, &limit],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_CLEANUP))?;
        let removed: i64 = match row {
            Some(row) => row
                .try_get("removed")
                .map_err(|_| invalid_data(OPERATION_CLEANUP))?,
            None => 0,
        };
        Ok(u64::try_from(removed).unwrap_or(0))
    }

    /// The exact number of live buckets for this deployment, from the
    /// counter (never a table scan).
    pub async fn live_buckets(&self) -> Result<i64, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_opt(
                "SELECT live FROM greengateway.rate_limit_cardinality WHERE deployment_id = $1",
                &[&self.deployment_id],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_CLEANUP))?;
        match row {
            Some(row) => row
                .try_get("live")
                .map_err(|_| invalid_data(OPERATION_CLEANUP)),
            None => Ok(0),
        }
    }
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

fn internal(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::Internal, operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tolerance_is_the_local_buckets_burst_minus_one_emission() {
        let limit = SharedLimit {
            requests_per_second: 4.0,
            burst: 3,
        };
        assert!((limit.emission_interval_secs() - 0.25).abs() < 1e-9);
        assert!((limit.tolerance_secs() - 0.5).abs() < 1e-9);
        let zero_burst = SharedLimit {
            requests_per_second: 4.0,
            burst: 0,
        };
        assert!(
            zero_burst.tolerance_secs() < 0.0,
            "a zero burst denies the first request, as the local store does"
        );
        let never = SharedLimit {
            requests_per_second: 0.0,
            burst: 2,
        };
        assert_eq!(never.emission_interval_secs(), NEVER_REFILLS_SECS);
    }
}
