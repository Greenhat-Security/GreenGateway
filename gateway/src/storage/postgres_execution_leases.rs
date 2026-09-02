//! PostgreSQL execution-lease store (issue #241, PR 10): the cluster-mode
//! [`ExecutionLeaseStore`] behind the tool runtime's global and per-tool
//! concurrency limits.
//!
//! Every slot of a scope is one row of `execution_leases`; a running
//! invocation holds one slot's lease at a fence drawn from one sequence
//! for the whole deployment, so every acquisition -- of any slot in any
//! scope -- carries a strictly larger fence than every earlier one.
//!
//! - **Acquire** is one statement: select the lowest slot that is absent
//!   or expired by the database clock, insert it with a fresh fence, and
//!   on conflict (the slot exists) take it over only if its lease has
//!   expired. Two replicas racing for the same slot serialize on the row:
//!   the loser's conditional update sees a live lease and returns no row,
//!   and the runtime retries. `nextval` may be drawn for slots the `LIMIT`
//!   discards; a discarded value is never held, so fences stay strictly
//!   increasing across acquisitions.
//! - **Renew** moves `expires_at` only where holder and fence still match
//!   and the lease is unexpired; no row means the lease was lost.
//! - **Release** deletes only where holder and fence match, so a stale
//!   holder cannot free a successor's slot.
//! - **`is_current`** is the fence check for shared follow-up state.
//!
//! Every expiry comparison is against `now()`: database time is
//! authoritative for leases (HA state model), and a replica's wall clock
//! never decides whether a slot is free.

use std::time::Duration;

use async_trait::async_trait;

use crate::tools::lease::{ExecutionLease, ExecutionLeaseStore, LeaseAttempt};

use super::{log_classified, postgres::classify_pool_error, RepositoryError, RepositoryErrorKind};

const OPERATION_ACQUIRE: &str = "execution_lease_acquire";
const OPERATION_RENEW: &str = "execution_lease_renew";
const OPERATION_RELEASE: &str = "execution_lease_release";
const OPERATION_CHECK: &str = "execution_lease_check";

/// The largest scope capacity one acquisition enumerates: the configured
/// global concurrency is bounded far below this, and `generate_series`
/// over it stays a trivial statement.
const MAX_CAPACITY: u32 = 100_000;

/// The bound the schema puts on an invocation identifier; longer request
/// IDs are truncated at a character boundary for the row, never refused.
const MAX_INVOCATION_BYTES: usize = 128;

#[derive(Clone)]
pub struct PostgresExecutionLeaseStore {
    pool: deadpool_postgres::Pool,
    deployment_id: String,
    holder: uuid::Uuid,
    ttl: Duration,
}

impl PostgresExecutionLeaseStore {
    pub fn new(
        pool: deadpool_postgres::Pool,
        deployment_id: &str,
        holder: uuid::Uuid,
        ttl: Duration,
    ) -> Self {
        Self {
            pool,
            deployment_id: deployment_id.to_owned(),
            holder,
            ttl,
        }
    }

    fn ttl_secs(&self) -> f64 {
        self.ttl.as_secs_f64()
    }
}

fn bounded_invocation(invocation: &str) -> &str {
    if invocation.len() <= MAX_INVOCATION_BYTES {
        return invocation;
    }
    let mut end = MAX_INVOCATION_BYTES;
    while !invocation.is_char_boundary(end) {
        end -= 1;
    }
    &invocation[..end]
}

#[async_trait]
impl ExecutionLeaseStore for PostgresExecutionLeaseStore {
    async fn try_acquire(
        &self,
        scope: &str,
        capacity: u32,
        invocation: &str,
    ) -> Result<LeaseAttempt, RepositoryError> {
        let capacity = i32::try_from(capacity.clamp(1, MAX_CAPACITY)).unwrap_or(1);
        let invocation = match bounded_invocation(invocation) {
            "" => "unknown",
            bounded => bounded,
        };
        let holder = self.holder.to_string();
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_opt(
                "INSERT INTO greengateway.execution_leases AS l
                     (deployment_id, scope, slot, fence, holder_instance, invocation,
                      acquired_at, renewed_at, expires_at)
                 SELECT $1, $2, s.slot, nextval('greengateway.execution_lease_fence'),
                        $4::text::uuid, $5, now(), now(), now() + make_interval(secs => $6::double precision)
                 FROM generate_series(0, $3::integer - 1) AS s(slot)
                 WHERE NOT EXISTS (
                     SELECT 1 FROM greengateway.execution_leases e
                     WHERE e.deployment_id = $1 AND e.scope = $2 AND e.slot = s.slot
                       AND e.expires_at > now())
                 ORDER BY s.slot
                 LIMIT 1
                 ON CONFLICT (deployment_id, scope, slot) DO UPDATE SET
                     fence = EXCLUDED.fence,
                     holder_instance = EXCLUDED.holder_instance,
                     invocation = EXCLUDED.invocation,
                     acquired_at = now(),
                     renewed_at = now(),
                     expires_at = EXCLUDED.expires_at
                 WHERE l.expires_at <= now()
                 RETURNING l.slot, l.fence",
                &[
                    &self.deployment_id,
                    &scope,
                    &capacity,
                    &holder,
                    &invocation,
                    &self.ttl_secs(),
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_ACQUIRE))?;
        match row {
            Some(row) => {
                let slot: i32 = row
                    .try_get("slot")
                    .map_err(|_| invalid_data(OPERATION_ACQUIRE))?;
                let fence: i64 = row
                    .try_get("fence")
                    .map_err(|_| invalid_data(OPERATION_ACQUIRE))?;
                Ok(LeaseAttempt::Acquired(ExecutionLease {
                    scope: scope.to_owned(),
                    slot,
                    fence,
                }))
            }
            None => Ok(LeaseAttempt::Full),
        }
    }

    async fn renew(&self, lease: &ExecutionLease) -> Result<bool, RepositoryError> {
        let holder = self.holder.to_string();
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let renewed = client
            .execute(
                "UPDATE greengateway.execution_leases
                 SET renewed_at = now(),
                     expires_at = now() + make_interval(secs => $6::double precision)
                 WHERE deployment_id = $1 AND scope = $2 AND slot = $3
                   AND fence = $4 AND holder_instance = $5::text::uuid
                   AND expires_at > now()",
                &[
                    &self.deployment_id,
                    &lease.scope,
                    &lease.slot,
                    &lease.fence,
                    &holder,
                    &self.ttl_secs(),
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_RENEW))?;
        Ok(renewed == 1)
    }

    async fn release(&self, lease: &ExecutionLease) -> Result<(), RepositoryError> {
        let holder = self.holder.to_string();
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        client
            .execute(
                "DELETE FROM greengateway.execution_leases
                 WHERE deployment_id = $1 AND scope = $2 AND slot = $3
                   AND fence = $4 AND holder_instance = $5::text::uuid",
                &[
                    &self.deployment_id,
                    &lease.scope,
                    &lease.slot,
                    &lease.fence,
                    &holder,
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_RELEASE))?;
        Ok(())
    }

    async fn is_current(&self, lease: &ExecutionLease) -> Result<bool, RepositoryError> {
        let holder = self.holder.to_string();
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_one(
                "SELECT EXISTS (
                     SELECT 1 FROM greengateway.execution_leases
                     WHERE deployment_id = $1 AND scope = $2 AND slot = $3
                       AND fence = $4 AND holder_instance = $5::text::uuid
                       AND expires_at > now()) AS current",
                &[
                    &self.deployment_id,
                    &lease.scope,
                    &lease.slot,
                    &lease.fence,
                    &holder,
                ],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_CHECK))?;
        row.try_get("current")
            .map_err(|_| invalid_data(OPERATION_CHECK))
    }

    fn ttl(&self) -> Duration {
        self.ttl
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
mod tests {
    use super::bounded_invocation;

    #[test]
    fn an_overlong_invocation_id_is_cut_at_a_character_boundary() {
        let id = "é".repeat(100);
        let bounded = bounded_invocation(&id);
        assert!(bounded.len() <= 128);
        assert!(bounded.chars().all(|c| c == 'é'));
        assert_eq!(bounded_invocation("short"), "short");
    }
}
