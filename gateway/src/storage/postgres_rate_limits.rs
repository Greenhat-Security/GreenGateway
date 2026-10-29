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
//!   `T = 1/rps` and tolerance `tau = (burst - 1) * T`, a request decided
//!   at `t` is allowed iff `GREATEST(tat, t) - t <= tau`, and an allowed
//!   request advances `tat` to `GREATEST(tat, t) + T`. That is the
//!   local token bucket (burst `B`, starting full, refilling at `rps`)
//!   written as one comparison and one assignment, including the local
//!   store's rule that a zero burst denies the very first request
//!   (`tau < 0`). No replica keeps a private count.
//! - **Decision time follows the row lock.** `t` is `GREATEST(now(),
//!   updated_at)`: the statement's start, or the bucket's last decision
//!   when that is later. `now()` is fixed when the statement begins,
//!   before it waits for the bucket row, so two decisions can take the row
//!   in the opposite order to their starts; judged at its own start, the
//!   one that took it second would be charged for debt accrued after it
//!   began and denied below the configured burst. Clamping to the last
//!   decision makes `t` monotonic per bucket, so decisions are judged in
//!   the order the row lock serializes them, as the local bucket judges
//!   its own. `t` never runs ahead of the database clock, so the clamp
//!   never admits more than the configured burst and rate.
//! - **One decision per bucket waits on its row, per replica.** The row
//!   lock serializes a bucket's decisions in the database, each held to its
//!   commit; a decision waiting for it holds a pooled connection that
//!   cannot make progress. A burst from one caller would therefore park
//!   the replica's whole pool on one row, and the revision gate (250 ms for
//!   its checkout and read together), the audit sink and every other
//!   caller would queue behind a line that moves one commit at a time.
//!   `BucketTurns` lines a bucket's decisions up in the process instead,
//!   holding nothing, so at most one connection per bucket per replica
//!   waits on the row. Each request is still decided by its own statement.
//! - **Cardinality is bounded exactly.** `rate_limit_cardinality` counts
//!   live buckets per deployment and moves in the same statement that
//!   inserts or deletes rows, so it cannot drift; when a new key pushes
//!   the count past the bound, one bounded statement on the same
//!   connection evicts the oldest buckets. An idle sweep for the cluster's
//!   maintenance singleton reclaims buckets nobody has touched for the
//!   configured TTL.
//!
//! A store that cannot be consulted is a [`RepositoryError`]; the
//! middleware answers `503` with zero upstream attempts. It is never a
//! silent allow and never a `429`.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::connections::local_secret::LocalSecretKeyring;

use super::{
    log_classified,
    postgres::{checkout, timed_operation, CheckoutClass},
    RepositoryError, RepositoryErrorKind,
};

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
    /// Shared by every clone: one replica's store, one line per bucket.
    turns: Arc<BucketTurns>,
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
            turns: Arc::new(BucketTurns::default()),
        }
    }

    /// Buckets with a decision in flight on this store, for the tests that
    /// prove the lines are torn down.
    #[cfg(test)]
    pub(crate) fn buckets_in_flight(&self) -> usize {
        self.turns.buckets_in_flight()
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
    /// eviction of the oldest buckets on the same connection. The decision
    /// is the statement's: an eviction that fails after it is logged, not
    /// returned.
    pub async fn decide(
        &self,
        lane: SharedLane,
        key: &str,
        limit: SharedLimit,
    ) -> Result<SharedDecision, RepositoryError> {
        let digest = self.key_digest(lane, key)?;
        let emission = limit.emission_interval_secs();
        let tolerance = limit.tolerance_secs();
        // The bucket's turn on this replica comes before a connection (see
        // `BucketTurns`). It waits no longer than a checkout may wait for
        // the pool, and a decision that cannot get it in time is a
        // `Timeout`: the middleware's 503, as an exhausted pool would be.
        let turn = self
            .turns
            .take(&digest, self.pool.timeouts().wait)
            .await
            .ok_or_else(|| RepositoryError::new(RepositoryErrorKind::Timeout, OPERATION_DECIDE))?;
        let client = checkout(&self.pool, CheckoutClass::RateLimit).await?;
        let (allowed, inserted, live) = timed_operation(OPERATION_DECIDE, async {
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
                             allowed = (GREATEST(b.tat, now(), b.updated_at)
                                           - GREATEST(now(), b.updated_at))
                                 <= make_interval(secs => $5::double precision),
                             tat = CASE WHEN (GREATEST(b.tat, now(), b.updated_at)
                                                 - GREATEST(now(), b.updated_at))
                                             <= make_interval(secs => $5::double precision)
                                        THEN GREATEST(b.tat, now(), b.updated_at)
                                             + make_interval(secs => $4::double precision)
                                        ELSE b.tat END,
                             updated_at = GREATEST(now(), b.updated_at)
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
            Ok((allowed, inserted, live))
        })
        .await?;
        // The statement committed and let go of the row: the bucket's next
        // decision may take its connection now, not after the eviction.
        drop(turn);
        if inserted {
            if let Some(live) = live {
                if live > self.max_buckets {
                    // On this decision's own connection. A second checkout
                    // would hold this one while it waited, and a pool's
                    // worth of new keys at the bound would then wait on
                    // each other until the acquire timeout, with every
                    // other authority call on the pool queued behind them.
                    //
                    // The decision committed with its statement, so a
                    // failed eviction (classified and logged by
                    // `classify_query`, counted by `timed_operation`)
                    // cannot take it back, and refusing the request would
                    // not remove the bucket either: the next key past the
                    // bound evicts the excess, and the idle sweep reclaims
                    // what nobody touches.
                    let _ = self.evict_oldest(&client, live - self.max_buckets).await;
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
    /// bring the count down with them, in one statement, over the
    /// connection the deciding caller already holds.
    async fn evict_oldest(
        &self,
        client: &tokio_postgres::Client,
        excess: i64,
    ) -> Result<(), RepositoryError> {
        let batch = excess.clamp(1, EVICTION_BATCH);
        timed_operation(OPERATION_EVICT, async {
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
        })
        .await
    }

    /// Reclaim up to `limit` buckets idle for at least `idle_secs` by the
    /// database clock, keeping the count exact. For the maintenance
    /// singleton; returns how many were removed.
    pub async fn cleanup_idle(&self, idle_secs: f64, limit: u32) -> Result<u64, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::Maintenance).await?;
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
        let client = checkout(&self.pool, CheckoutClass::Maintenance).await?;
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

/// One replica's lines of shared decisions, one line per bucket: at most one
/// decision per bucket holds a pooled connection at a time.
///
/// Every decision for a bucket takes that bucket's row lock and keeps it to
/// its commit, so concurrent decisions for one bucket finish one after
/// another in the database whatever this process does. What the process
/// chooses is what they hold while they wait. Without a line, each waiter
/// holds a pooled connection on which it can do nothing until the decision
/// ahead of it commits. One caller's burst (one client address on a global
/// lane, one principal under one rule on the policy lane: the case a limiter
/// is for) then parks up to the whole pool on one row, and the rest of the
/// replica's authority work queues behind a line that advances one commit,
/// one WAL flush, at a time. The security-revision gate gives its checkout
/// and read 250 ms together, so it is refused first: every caller's request
/// on that replica answers `503 policy state unavailable` while one caller
/// is limited. In the line, the waiters hold nothing, and the pool stays
/// free for the rest of that work.
///
/// Nothing about a decision changes. Each request is still decided by its
/// own statement on database time and judged in the order the row lock
/// admits it. Replicas still meet on the row, with at most one connection
/// each. The line removes only waits that could not have made progress, and
/// it is FIFO, as the pool's own queue is.
///
/// The map holds only buckets that have a decision in flight here. An entry
/// is created by the first decision to arrive and removed by the last to
/// leave, including one whose wait was abandoned, so its size is bounded by
/// the requests in flight, not by the callers ever seen.
#[derive(Default)]
struct BucketTurns {
    lines: Mutex<HashMap<Vec<u8>, BucketLine>>,
}

/// One bucket's line.
struct BucketLine {
    turn: Arc<tokio::sync::Mutex<()>>,
    /// Decisions holding or waiting for the turn.
    members: usize,
}

impl BucketTurns {
    fn lines(&self) -> std::sync::MutexGuard<'_, HashMap<Vec<u8>, BucketLine>> {
        // Nothing panics under this lock (a map lookup and a counter), and
        // the map stays structurally valid if something ever did.
        self.lines
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Join `digest`'s line and wait for its turn: at most `wait`, or for as
    /// long as it takes when there is no bound. `None` when the bound ran
    /// out first; the place in the line is given up either way.
    async fn take(&self, digest: &[u8], wait: Option<Duration>) -> Option<BucketTurn<'_>> {
        let (turn, member) = {
            let mut lines = self.lines();
            let line = lines.entry(digest.to_vec()).or_insert_with(|| BucketLine {
                turn: Arc::new(tokio::sync::Mutex::new(())),
                members: 0,
            });
            line.members += 1;
            (
                Arc::clone(&line.turn),
                LineMember {
                    turns: self,
                    digest: digest.to_vec(),
                },
            )
        };
        let guard = match wait {
            Some(wait) => tokio::time::timeout(wait, turn.lock_owned()).await.ok()?,
            None => turn.lock_owned().await,
        };
        Some(BucketTurn {
            _guard: guard,
            _member: member,
        })
    }

    #[cfg(test)]
    fn buckets_in_flight(&self) -> usize {
        self.lines().len()
    }
}

/// A place in one bucket's line, given up on drop: the last member to leave
/// removes the line.
struct LineMember<'a> {
    turns: &'a BucketTurns,
    digest: Vec<u8>,
}

impl Drop for LineMember<'_> {
    fn drop(&mut self) {
        let mut lines = self.turns.lines();
        if let Some(line) = lines.get_mut(&self.digest) {
            line.members = line.members.saturating_sub(1);
            if line.members == 0 {
                lines.remove(&self.digest);
            }
        }
    }
}

/// A bucket's turn. The fields drop in declaration order, so the turn is
/// handed on before the place in the line is given up, and a line is never
/// removed while its turn is still held.
struct BucketTurn<'a> {
    _guard: tokio::sync::OwnedMutexGuard<()>,
    _member: LineMember<'a>,
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

    /// A bucket's decisions take turns; another bucket's never wait on
    /// them; and the line is gone once the last decision has left.
    #[tokio::test]
    async fn a_buckets_decisions_take_turns_and_other_buckets_do_not_wait() {
        use futures_util::FutureExt as _;

        let turns = BucketTurns::default();
        let first = turns.take(b"bucket-a", None).await.expect("unbounded");
        let mut second = Box::pin(turns.take(b"bucket-a", None));
        assert!(
            (&mut second).now_or_never().is_none(),
            "a second decision for the same bucket waits for the first"
        );
        let other = turns
            .take(b"bucket-b", None)
            .now_or_never()
            .expect("another bucket's decision does not wait")
            .expect("unbounded");
        assert_eq!(turns.buckets_in_flight(), 2);

        drop(first);
        let second = second.await.expect("the turn is handed on");
        drop(other);
        assert_eq!(turns.buckets_in_flight(), 1, "bucket-a is still in flight");
        drop(second);
        assert_eq!(
            turns.buckets_in_flight(),
            0,
            "a line is removed by the last decision to leave it"
        );
    }

    /// A wait past its bound gives up its place, as does a wait whose
    /// request went away: neither leaves a line behind, and neither stops
    /// the bucket's next decision.
    #[tokio::test]
    async fn an_abandoned_wait_gives_up_its_place_in_the_line() {
        use futures_util::FutureExt as _;

        let turns = BucketTurns::default();
        let held = turns.take(b"bucket-a", None).await.expect("unbounded");
        assert!(
            turns
                .take(b"bucket-a", Some(Duration::from_millis(20)))
                .await
                .is_none(),
            "a wait past its bound answers None"
        );
        let mut dropped = Box::pin(turns.take(b"bucket-a", None));
        assert!((&mut dropped).now_or_never().is_none());
        drop(dropped);
        assert_eq!(
            turns.buckets_in_flight(),
            1,
            "only the holder is left in the line"
        );

        drop(held);
        assert_eq!(turns.buckets_in_flight(), 0);
        let next = turns
            .take(b"bucket-a", Some(Duration::from_millis(20)))
            .now_or_never()
            .expect("nobody is ahead of the next decision");
        assert!(next.is_some());
    }
}
