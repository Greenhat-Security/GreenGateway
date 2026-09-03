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
//! The last of those is the one that has to be *structural* rather than
//! remembered, because cancellation is not a path anybody writes: it is
//! every `await`, at once. So the connection is owned by a
//! [`DedicatedSession`] -- the thing whose [`Drop`] detaches -- from the
//! moment it is checked out until the server has answered an unlock, and
//! never sits in a local across an `await` in between. A connection in a
//! local is returned to the pool by deadpool's own `Drop`, and the pool
//! recycles with `ROLLBACK` (see `postgres::build_pool`), which ends a
//! transaction and releases nothing else: a connection recycled while
//! holding a session lock holds it for as long as the pool lives, and
//! every later pass is answered `Conflict` for ever. That is the wedge
//! the two cancellation tests below exist to keep shut.
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
    ///
    /// The connection is put inside a session *before* the lock statement
    /// is sent, and not for tidiness: the statement is an `await`, and a
    /// caller that is cancelled there (the maintenance runner races every
    /// pass against its lease, and opening the session is the pass's first
    /// act) drops this future wherever it is parked. Held in a local, the
    /// connection would then go back to the pool by its ordinary `Drop` --
    /// possibly with the lock already granted by the server and the answer
    /// still on the wire. Held by a session, every such drop goes through
    /// [`Drop`] and detaches instead.
    pub async fn acquire(
        pool: &deadpool_postgres::Pool,
        key: i64,
    ) -> Result<Self, RepositoryError> {
        let client = pool.get().await.map_err(classify_pool_error)?;
        // From here to the end of this function the connection has exactly
        // one owner, and that owner detaches it on every path out but the
        // two that are provably clean.
        let mut session = Self {
            client: Some(client),
            key,
        };
        let row = {
            let client = session
                .client
                .as_ref()
                .expect("the session was just given its connection");
            client
                .query_one("SELECT pg_try_advisory_lock($1) AS locked", &[&key])
                .await
        };
        let row = match row {
            Ok(row) => row,
            // Dropping `session` detaches: the statement may have taken
            // the lock before it failed.
            Err(error) => return Err(classify_query(error, OPERATION_LOCK)),
        };
        let locked: bool = match row.try_get("locked") {
            Ok(locked) => locked,
            Err(_) => {
                return Err(RepositoryError::new(
                    RepositoryErrorKind::InvalidData,
                    OPERATION_LOCK,
                ))
            }
        };
        if !locked {
            // Nothing was taken -- the server said so -- and there is no
            // await between here and the return, so the connection is as
            // clean as it came and goes back to the pool.
            drop(session.client.take());
            return Err(RepositoryError::new(
                RepositoryErrorKind::Conflict,
                OPERATION_LOCK,
            ));
        }
        Ok(session)
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
    ///
    /// The connection stays inside `self` for the whole round trip and
    /// leaves only once the server has answered the unlock. Taking it out
    /// first would put it in a local across an `await`, and a release
    /// cancelled there -- the runner's `select!` can drop the pass at its
    /// last act as readily as at its first -- would hand a connection that
    /// is still holding the lock back to the pool.
    pub async fn release(mut self) -> Result<(), RepositoryError> {
        if self.client.is_none() {
            return Ok(());
        }
        let unlocked = {
            let client = self
                .client
                .as_ref()
                .expect("the session still holds its connection");
            client
                .execute("SELECT pg_advisory_unlock($1)", &[&self.key])
                .await
        };
        match unlocked {
            Ok(_) => {
                // The server has released the lock, so the connection is
                // clean and may be recycled.
                drop(self.client.take());
                Ok(())
            }
            // Dropping `self` detaches: the unlock did not land.
            Err(error) => Err(classify_query(error, OPERATION_UNLOCK)),
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

    // --- real-database tests ------------------------------------------
    //
    // Cancellation safety cannot be argued from the client's side: the
    // only authority on whether a session lock is still held is the
    // server's own lock table. These tests cancel a session's future at a
    // named point and then ask `pg_locks` -- and, when the key is still
    // held, `pg_stat_activity` -- what the server thinks. Gated on the
    // same harness locator as the rest of the storage suite; a checkout
    // without a database skips rather than fails.

    use std::time::{Duration, Instant};

    use super::DedicatedSession;

    /// How long a cancelled session's key may still be held. A detached
    /// connection closes as soon as the statement it had in flight ends,
    /// and these statements are a lock and an unlock: milliseconds. The
    /// budget is generous only so a loaded CI box does not fail on
    /// scheduling.
    const RELEASE_BUDGET: Duration = Duration::from_secs(15);

    fn real_dsn() -> Option<String> {
        // Read through a runtime key, exactly as `postgres.rs` and
        // `contract_tests.rs` do: the configuration-drift test walks the
        // `env::var` literals under `gateway/src` to keep the operator's
        // reference complete, and this locator is harness plumbing, not
        // an operator setting.
        let key = "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned();
        let file = std::env::var(&key).ok()?;
        if file.trim().is_empty() {
            return None;
        }
        let contents = std::fs::read_to_string(file).ok()?;
        let trimmed = contents.trim().to_owned();
        (!trimmed.is_empty()).then_some(trimmed)
    }

    /// A pool that recycles the way the production pool does
    /// (`RecyclingMethod::Custom("ROLLBACK")`, see `postgres::build_pool`).
    /// That detail is the whole point: `ROLLBACK` ends a transaction and
    /// releases nothing else, so a connection handed back to the pool
    /// while it holds a session advisory lock keeps holding it for as
    /// long as the pool keeps the connection -- which is for ever.
    fn recycling_pool(dsn: &str) -> deadpool_postgres::Pool {
        let config: tokio_postgres::Config = dsn.parse().expect("the test DSN parses");
        let manager = deadpool_postgres::Manager::from_config(
            config,
            tokio_postgres::NoTls,
            deadpool_postgres::ManagerConfig {
                recycling_method: deadpool_postgres::RecyclingMethod::Custom("ROLLBACK".to_owned()),
            },
        );
        deadpool_postgres::Pool::builder(manager)
            .max_size(4)
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .build()
            .expect("the test pool builds")
    }

    /// A connection outside the pool, so the observation is never made by
    /// the thing being observed.
    async fn observer(dsn: &str) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
            .await
            .expect("the observer connects");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        client
    }

    /// What the server says about every backend granted `key` as a
    /// session advisory lock: pid, backend state, wait event, and the
    /// query it last ran. A holder that is `active` on a statement is a
    /// pass still running; a holder that is `idle` on `ClientRead` is a
    /// connection sitting in the pool with the lock on it.
    async fn holders(observer: &tokio_postgres::Client, key: i64) -> Vec<String> {
        // The bigint form of an advisory lock is stored split across
        // `classid` (high half) and `objid` (low half), with
        // `objsubid = 1`.
        let rows = observer
            .query(
                "SELECT l.pid, \
                        coalesce(a.state, '<gone>'), \
                        coalesce(a.wait_event_type || ':' || a.wait_event, '<none>'), \
                        coalesce(a.query, '<none>') \
                 FROM pg_locks l LEFT JOIN pg_stat_activity a ON a.pid = l.pid \
                 WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 1 \
                   AND ((l.classid::bigint << 32) | l.objid::bigint) = $1",
                &[&key],
            )
            .await
            .expect("pg_locks is readable");
        rows.iter()
            .map(|row| {
                format!(
                    "pid {} state={} wait={} query={:?}",
                    row.get::<_, i32>(0),
                    row.get::<_, &str>(1),
                    row.get::<_, &str>(2),
                    row.get::<_, &str>(3),
                )
            })
            .collect()
    }

    /// Wait for `key` to be free, and report what is holding it if it
    /// never becomes free.
    async fn assert_released(observer: &tokio_postgres::Client, key: i64, what: &str) -> Duration {
        let started = Instant::now();
        loop {
            let held = holders(observer, key).await;
            if held.is_empty() {
                return started.elapsed();
            }
            assert!(
                started.elapsed() < RELEASE_BUDGET,
                "the advisory key was still held {:?} after {what}; the server says: {}\n\
                 A holder that is idle on ClientRead is a pooled connection that went back \
                 into the pool with the lock on it: every later pass is answered Conflict, \
                 for ever, and the deployment's housekeeping stops.",
                started.elapsed(),
                held.join(" | ")
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Cancelling a pass in the window where the server has granted the
    /// lock but the client has not yet been told must not leave the key
    /// held.
    ///
    /// This is the window a lost lease actually lands in: `run_pass`
    /// opens its dedicated session as its first act, and the `select!`
    /// that races the pass against `lost.cancelled()` drops the pass
    /// future wherever it happens to be parked. The test does not wait
    /// for luck -- it polls the acquiring future until the *server* says
    /// the key is taken, and drops it there.
    #[tokio::test]
    async fn a_cancelled_acquire_does_not_leave_the_key_held() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let pool = recycling_pool(&dsn);
        let observer = observer(&dsn).await;
        let key = advisory_lock_key(&format!(
            "greengateway.test.cancelled-acquire.{}",
            uuid::Uuid::new_v4().simple()
        ));

        // Warm the pool: the window under test is the lock statement, not
        // the checkout.
        drop(pool.get().await.expect("the pool reaches the database"));

        // `Box::pin`, not `tokio::pin!`: the macro shadows the future with
        // a `Pin<&mut _>`, and dropping *that* drops a reference and
        // cancels nothing. This test's whole subject is the drop.
        let mut acquire = Box::pin(DedicatedSession::acquire(&pool, key));
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut granted = false;
        while Instant::now() < deadline {
            // Poll first, ask the server second, and stop the instant the
            // server says the key is taken -- without polling again. The
            // future is then parked exactly where the lock is the
            // server's and the client does not know it yet.
            if let std::task::Poll::Ready(result) = futures_util::poll!(acquire.as_mut()) {
                if let Ok(session) = result {
                    let _ = session.release().await;
                }
                panic!(
                    "the acquiring future completed before the server was observed holding \
                     the key; the test could not reach the window it exists to cover"
                );
            }
            if !holders(&observer, key).await.is_empty() {
                granted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(
            granted,
            "the server never granted the key, so there was no cancellation window to test"
        );

        drop(acquire);
        let elapsed = assert_released(&observer, key, "the acquiring future was cancelled").await;
        eprintln!("cancelled acquire: key released after {elapsed:?}");

        // The consequence, stated directly: the next pass must be able to
        // take the key rather than be told Conflict for ever.
        let session = DedicatedSession::acquire(&pool, key)
            .await
            .expect("a later pass must be able to take the key a cancelled one left behind");
        session.release().await.expect("the unlock succeeds");
    }

    /// Cancelling a pass while it is unlocking must not hand the
    /// connection back to the pool with the lock still on it.
    ///
    /// `run_pass` releases its session as its last act, inside the same
    /// `select!`, so this window is as reachable as the first. The
    /// cancellation is placed deterministically: the future is polled
    /// once (which sends the unlock's `PREPARE`) and then never again, so
    /// the unlock itself is provably never sent.
    #[tokio::test]
    async fn a_cancelled_release_does_not_leave_the_key_held() {
        let Some(dsn) = real_dsn() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let pool = recycling_pool(&dsn);
        let observer = observer(&dsn).await;
        let key = advisory_lock_key(&format!(
            "greengateway.test.cancelled-release.{}",
            uuid::Uuid::new_v4().simple()
        ));

        let session = DedicatedSession::acquire(&pool, key)
            .await
            .expect("the session takes the key");
        assert!(
            !holders(&observer, key).await.is_empty(),
            "the server must show the key held once the session has it"
        );

        // `Box::pin` for the same reason as above: the drop is the test.
        let mut release = Box::pin(session.release());
        assert!(
            futures_util::poll!(release.as_mut()).is_pending(),
            "the unlock is a round trip; it cannot complete in one poll"
        );
        // Let the connection task run the round trip the unlock's
        // statement preparation needs, then cancel without polling
        // again -- the unlock is never sent.
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(release);

        let elapsed = assert_released(&observer, key, "the releasing future was cancelled").await;
        eprintln!("cancelled release: key released after {elapsed:?}");

        let session = DedicatedSession::acquire(&pool, key)
            .await
            .expect("a later pass must be able to take the key a cancelled unlock left behind");
        session.release().await.expect("the unlock succeeds");
    }
}
