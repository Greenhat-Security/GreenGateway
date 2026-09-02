//! Dedicated advisory-lock sessions (issue #241, PR 13, section 5).
//!
//! A [`DedicatedSession`] is one pooled connection held for the lifetime
//! of a piece of singleton work, with a session-scoped advisory lock
//! (`pg_try_advisory_lock`) taken on it at the start and released at the
//! end. It is the belt alongside the lease's braces: the maintenance
//! lease (`execution_leases`, scope `maintenance`) already admits one
//! leader, and the fence on every ledger write already refuses a stale
//! one; the advisory lock adds a database-enforced guarantee that two
//! processes cannot run the same singleton work at the same instant even
//! if a lease were ever mis-adjudicated, and that losing the connection
//! is noticed rather than silently ignored.
//!
//! That guarantee holds only for statements that run *on this
//! connection* ([`DedicatedSession::client`]): a session lock is released
//! when the session ends, and the server ends a session only once the
//! statement it is running has finished, so a step run here is covered
//! for as long as it runs even if the client side is cancelled mid-way.
//! A statement run on some other pooled connection is not covered at all
//! -- the lock could be released while it runs -- which is why the
//! maintenance runner hands every job the session's client rather than
//! the pool.
//!
//! What is stored: nothing. The lock lives in the server's lock table for
//! as long as the session does. What is held: the connection, which is
//! why the helper is strict about how the connection leaves:
//!
//! - **A clean end** ([`DedicatedSession::release`]) unlocks and lets the
//!   connection return to the pool.
//! - **Any failure** -- the lock statement, a probe, the unlock -- marks
//!   the session broken and *detaches* the connection from the pool
//!   (`deadpool_postgres::Object::take`) so it closes instead of being
//!   recycled while possibly still holding the lock. A session-scoped
//!   advisory lock on a recycled connection would be held by whichever
//!   request checked that connection out next, invisibly and for as long
//!   as the pool kept it; closing the connection is the only release the
//!   server guarantees.
//! - **A drop without release** (the job's future was cancelled: the
//!   lease was lost, or the lifecycle is draining) detaches the connection
//!   for the same reason. Nothing is remembered, nothing dangles.
//!
//! The lock is *tried*, never waited for: a session that finds the key
//! held answers [`RepositoryErrorKind::Conflict`], and the caller runs
//! nothing. Waiting would only be correct if the lease had failed, and in
//! that case running second is exactly the wrong outcome.
//!
//! Lock keys are derived from a name the same way the migration and audit
//! stream locks are (`SHA-256(name)[..8]`, sign bit cleared), pinned by
//! tests so two binaries cannot drift onto different keys.

use sha2::{Digest, Sha256};

use super::{log_classified, postgres::classify_pool_error, RepositoryError, RepositoryErrorKind};

const OPERATION_LOCK: &str = "dedicated_session_lock";
const OPERATION_PROBE: &str = "dedicated_session_probe";
const OPERATION_UNLOCK: &str = "dedicated_session_unlock";

/// Derive a session advisory-lock key from a name: the first eight bytes
/// of `SHA-256(name)` with the sign bit cleared, as the migration and audit
/// stream locks do.
pub(crate) fn advisory_lock_key(name: &str) -> i64 {
    let digest = Sha256::digest(name.as_bytes());
    let mut value = [0_u8; 8];
    value.copy_from_slice(&digest[..8]);
    value[0] &= 0x7f;
    i64::from_be_bytes(value)
}

/// One pooled connection holding one session advisory lock.
pub struct DedicatedSession {
    /// `None` once the connection has left (released to the pool, or
    /// detached and closed).
    client: Option<deadpool_postgres::Object>,
    key: i64,
}

impl DedicatedSession {
    /// Check a connection out and try the lock on it. `Conflict` means
    /// another session holds the key -- the caller must not run.
    pub async fn acquire(
        pool: &deadpool_postgres::Pool,
        key: i64,
    ) -> Result<Self, RepositoryError> {
        let client = pool.get().await.map_err(classify_pool_error)?;
        let row = match client
            .query_one("SELECT pg_try_advisory_lock($1) AS locked", &[&key])
            .await
        {
            Ok(row) => row,
            Err(error) => {
                detach(client);
                return Err(classify_query(error, OPERATION_LOCK));
            }
        };
        let locked: bool = match row.try_get("locked") {
            Ok(locked) => locked,
            Err(_) => {
                detach(client);
                return Err(RepositoryError::new(
                    RepositoryErrorKind::InvalidData,
                    OPERATION_LOCK,
                ));
            }
        };
        if !locked {
            // Nothing was taken; the connection is as clean as it came.
            drop(client);
            return Err(RepositoryError::new(
                RepositoryErrorKind::Conflict,
                OPERATION_LOCK,
            ));
        }
        Ok(Self {
            client: Some(client),
            key,
        })
    }

    /// The connection holding the lock, for the work the lock protects to
    /// run its statements on. A statement that runs here is covered by the
    /// lock for as long as it runs -- the server releases a session lock
    /// only when the session ends, and a session ends only once its
    /// statement in flight has -- and losing the connection fails that
    /// statement rather than going unnoticed. `None` once the session is
    /// broken.
    pub fn client(&self) -> Option<&tokio_postgres::Client> {
        self.client
            .as_ref()
            .map(|client| -> &tokio_postgres::Client { client })
    }

    /// Confirm the connection (and so the lock) is still alive. An error
    /// breaks the session: the connection is detached, and the caller
    /// must cancel the work the lock was protecting.
    pub async fn probe(&mut self) -> Result<(), RepositoryError> {
        let Some(client) = self.client.as_ref() else {
            return Err(RepositoryError::new(
                RepositoryErrorKind::Unavailable,
                OPERATION_PROBE,
            ));
        };
        if let Err(error) = client.simple_query("SELECT 1").await {
            if let Some(client) = self.client.take() {
                detach(client);
            }
            return Err(classify_query(error, OPERATION_PROBE));
        }
        Ok(())
    }

    /// Unlock and return the connection to the pool. On a failed unlock
    /// the connection is closed instead, which releases the lock anyway.
    pub async fn release(mut self) -> Result<(), RepositoryError> {
        let Some(client) = self.client.take() else {
            return Ok(());
        };
        match client
            .execute("SELECT pg_advisory_unlock($1)", &[&self.key])
            .await
        {
            Ok(_) => {
                drop(client);
                Ok(())
            }
            Err(error) => {
                detach(client);
                Err(classify_query(error, OPERATION_UNLOCK))
            }
        }
    }
}

impl Drop for DedicatedSession {
    fn drop(&mut self) {
        // Reached only when `release` was not called: the work was
        // cancelled mid-flight. The lock may still be held on this
        // connection, so it must not go back into the pool.
        if let Some(client) = self.client.take() {
            detach(client);
        }
    }
}

/// Take the connection out of the pool for good: dropping the bare client
/// closes the session, and the server releases every lock it held.
fn detach(client: deadpool_postgres::Object) {
    drop(deadpool_postgres::Object::take(client));
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

#[cfg(test)]
mod tests {
    use super::advisory_lock_key;

    #[test]
    fn lock_keys_are_derived_from_the_name_and_never_negative() {
        let key = advisory_lock_key("greengateway.maintenance");
        assert!(key >= 0);
        assert_eq!(key, advisory_lock_key("greengateway.maintenance"));
        assert_ne!(key, advisory_lock_key("greengateway.audit-stream"));
        // The audit stream key is derived the same way (postgres_audit.rs).
        assert_eq!(
            advisory_lock_key("greengateway.audit-stream"),
            *crate::storage::postgres_audit::AUDIT_STREAM_LOCK_KEY
        );
    }
}
