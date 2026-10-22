//! The durable authority-event dispatcher (issue #425, PR 3).
//!
//! Every committed evidence row is journaled in its own transaction
//! (`storage::postgres_authority_events`). ONE replica -- whichever holds the
//! `authority-event-dispatcher` execution lease -- reads the journal after
//! the durable cursor, projects each row into a [`DeliveryRecord`] with keyed
//! safe references, hands the batch to the configured
//! [`AuthorityEventSink`], and only then advances the cursor under its lease
//! fence. Nothing here runs inside an authority transaction, so a downstream
//! outage can delay delivery but never a mutation (until the journal reaches
//! its capacity, which refuses mutations rather than dropping events).
//!
//! The term of one leader:
//!
//! 1. Acquire the single slot of the dispatcher scope. `Full` means another
//!    replica leads; wait with jitter and retry.
//! 2. Claim the cursor at the lease's fence. A newer fence there means this
//!    lease is stale; release and retry.
//! 3. Renew the lease at a third of its TTL; a renewal that reports the lease
//!    gone, or that cannot be answered for half the TTL, stops the term.
//! 4. Deliver: read at most `batch_size` rows after the committed position,
//!    project them all (any row that cannot be projected faithfully stops the
//!    batch -- it is never skipped), offer the batch to the sink, and advance
//!    the cursor to the batch's last position.
//!
//! Failures and what they cost:
//!
//! - **The sink refuses or fails.** The same projected batch is offered again
//!   after an exponential backoff (`retry_base` doubling to `retry_cap`, with
//!   jitter); the cursor does not move and nothing is re-read.
//! - **The cursor advance fails after the sink accepted.** Only the advance is
//!   retried, so the batch is not offered twice by this term. An advance the
//!   store refuses because the fence moved ends the term.
//! - **The process dies between acceptance and the advance.** The next leader
//!   resumes from the committed cursor and offers that batch again, with the
//!   same event IDs and, under the same key, byte-identical records: at least
//!   once, never exactly once. Consumers deduplicate on
//!   `(authority_id, event_id)`.
//! - **A row cannot be projected.** The batch is refused and retried with the
//!   same backoff, so the dispatcher stalls at that position, counts
//!   `projection` failures and logs the position; the oldest-undelivered age
//!   keeps growing until an operator intervenes.
//!
//! Metrics (bounded labels only): delivered events, failures by step, and the
//! journal gauges (retained, capacity, undelivered, oldest undelivered age)
//! published by the leader after every step.

use std::{
    hash::BuildHasher,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    delivery::{project, DeliveryRecord, ProjectionError},
    pseudonym::PseudonymKeyring,
    sink::{AuthorityEventSink, SinkError},
};
use crate::{
    lifecycle::GatewayLifecycle,
    storage::{
        postgres_authority_events::{JournalStats, PostgresAuthorityEventStore, MAX_READ_BATCH},
        RepositoryError, RepositoryErrorKind,
    },
    tools::{
        lease::{ExecutionLeaseStore, LeaseAttempt},
        runtime::renew_until_lost,
    },
};

/// The execution-lease scope the single dispatcher slot lives in.
pub(crate) const DISPATCHER_LEASE_SCOPE: &str = "authority-event-dispatcher";
const DISPATCHER_LEASE_INVOCATION: &str = "dispatcher";

/// The dispatcher's lease time to live. Long enough that an authority slow
/// for a few seconds does not move leadership; short enough that a crashed
/// leader is replaced well inside any delivery objective.
pub(crate) const DISPATCHER_LEASE_TTL: Duration = Duration::from_secs(15);

// The `kind` vocabulary of `greengateway_authority_event_delivery_failures_total`:
// which step of a term failed, never why. The causes go to the log line.
/// The lease could not be tried at all.
pub(crate) const FAILURE_LEASE: &str = "lease_acquire";
/// The lease was taken but the cursor claim failed or was refused.
pub(crate) const FAILURE_CLAIM: &str = "cursor_claim";
/// The journal could not be read.
pub(crate) const FAILURE_READ: &str = "journal_read";
/// A journaled row could not be projected faithfully; delivery stalls there.
pub(crate) const FAILURE_PROJECTION: &str = "projection";
/// The sink refused or failed the batch.
pub(crate) const FAILURE_SINK: &str = "sink";
/// The sink accepted but the cursor advance did not commit.
pub(crate) const FAILURE_CURSOR: &str = "cursor_advance";
/// A newer fence holds the cursor: this leader was fenced out mid-term.
pub(crate) const FAILURE_FENCED: &str = "fenced";

/// The whole vocabulary of the `kind` label. Read by the registry label
/// audit; the call sites pass their own constant.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) const FAILURE_KINDS: [&str; 7] = [
    FAILURE_LEASE,
    FAILURE_CLAIM,
    FAILURE_READ,
    FAILURE_PROJECTION,
    FAILURE_SINK,
    FAILURE_CURSOR,
    FAILURE_FENCED,
];

/// Defaults for the cadence. These are not settings: they bound load on the
/// authority, not anything an operator's sink needs to tune.
pub(crate) const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub(crate) const DEFAULT_BATCH_SIZE: usize = 100;
pub(crate) const DEFAULT_RETRY_BASE: Duration = Duration::from_millis(500);
pub(crate) const DEFAULT_RETRY_CAP: Duration = Duration::from_secs(60);

/// Count one dispatcher failure by the step that failed.
pub(crate) fn record_failure(kind: &'static str) {
    ::metrics::counter!(crate::metrics::AUTHORITY_EVENT_DELIVERY_FAILURES_TOTAL, "kind" => kind)
        .increment(1);
}

/// Count events a sink accepted and the cursor committed past.
pub(crate) fn record_delivered(events: usize) {
    ::metrics::counter!(crate::metrics::AUTHORITY_EVENT_DELIVERED_TOTAL)
        .increment(u64::try_from(events).unwrap_or(u64::MAX));
}

/// Publish the journal gauges from one consistent read.
pub(crate) fn record_journal_stats(stats: &JournalStats) {
    ::metrics::gauge!(crate::metrics::AUTHORITY_EVENT_JOURNAL_RETAINED).set(stats.retained as f64);
    ::metrics::gauge!(crate::metrics::AUTHORITY_EVENT_JOURNAL_CAPACITY).set(stats.capacity as f64);
    ::metrics::gauge!(crate::metrics::AUTHORITY_EVENT_UNDELIVERED).set(stats.undelivered() as f64);
    ::metrics::gauge!(crate::metrics::AUTHORITY_EVENT_OLDEST_UNDELIVERED_AGE_SECONDS)
        .set(stats.oldest_undelivered_age_secs.unwrap_or(0.0).max(0.0));
}

/// How the dispatcher runs.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DispatcherConfig {
    /// The wait when the journal has nothing after the cursor.
    pub(crate) poll_interval: Duration,
    /// Journal rows per batch, at most [`MAX_READ_BATCH`].
    pub(crate) batch_size: usize,
    /// The first retry wait after a failure; it doubles per consecutive
    /// failure up to `retry_cap`.
    pub(crate) retry_base: Duration,
    pub(crate) retry_cap: Duration,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            poll_interval: DEFAULT_POLL_INTERVAL,
            batch_size: DEFAULT_BATCH_SIZE,
            retry_base: DEFAULT_RETRY_BASE,
            retry_cap: DEFAULT_RETRY_CAP,
        }
    }
}

/// The wait before retry number `failures` (1 for the first): `base`
/// doubled per earlier failure, capped, plus up to a quarter more of jitter
/// so a fleet of dispatchers recovering from one outage does not retry in
/// lockstep. Never below one millisecond.
pub(crate) fn retry_backoff(base: Duration, cap: Duration, failures: u32) -> Duration {
    let exponent = failures.saturating_sub(1).min(20);
    let doubled = base.saturating_mul(1_u32 << exponent);
    let capped = doubled.min(cap).max(Duration::from_millis(1));
    let jitter_steps = std::collections::hash_map::RandomState::new().hash_one(failures) % 256;
    capped + capped.mul_f64(jitter_steps as f64 / 1024.0)
}

/// What one [`DispatcherTerm::step`] did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StepOutcome {
    /// Nothing after the cursor.
    Idle,
    /// A batch was accepted and the cursor committed through `through`.
    Delivered { events: usize, through: i64 },
    /// A newer fence holds the cursor; the term is over.
    Fenced,
    /// The stop token fired before anything more was written.
    Stopped,
}

/// Why a step did not finish. The term keeps whatever it can retry.
#[derive(Debug)]
pub(crate) enum StepError {
    Read(RepositoryError),
    Projection {
        position: i64,
        error: ProjectionError,
    },
    Sink(SinkError),
    Cursor(RepositoryError),
}

impl StepError {
    /// The failure-metric kind of this error.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Read(_) => FAILURE_READ,
            Self::Projection { .. } => FAILURE_PROJECTION,
            Self::Sink(_) => FAILURE_SINK,
            Self::Cursor(_) => FAILURE_CURSOR,
        }
    }
}

impl std::fmt::Display for StepError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read(error) => write!(formatter, "journal read failed: {error}"),
            Self::Projection { position, error } => {
                write!(formatter, "journal position {position}: {error}")
            }
            Self::Sink(error) => write!(formatter, "{error}"),
            Self::Cursor(error) => write!(formatter, "cursor advance failed: {error}"),
        }
    }
}

/// A batch the sink has accepted whose cursor advance has not committed.
#[derive(Clone, Copy, Debug)]
struct AcceptedBatch {
    through: i64,
    events: usize,
}

/// One leader's term: the fence, the committed cursor, and whatever is in
/// flight between reading the journal and committing the cursor.
pub(crate) struct DispatcherTerm {
    store: Arc<PostgresAuthorityEventStore>,
    sink: Arc<dyn AuthorityEventSink>,
    keyring: Arc<PseudonymKeyring>,
    config: DispatcherConfig,
    fence: i64,
    committed: i64,
    /// Projected records the sink has not accepted yet, and the position of
    /// the last one.
    pending: Vec<DeliveryRecord>,
    pending_through: i64,
    accepted: Option<AcceptedBatch>,
}

impl DispatcherTerm {
    /// Claim the cursor at `fence` and begin a term from its committed
    /// position. A stale fence is `Conflict`.
    pub(crate) async fn begin(
        store: Arc<PostgresAuthorityEventStore>,
        sink: Arc<dyn AuthorityEventSink>,
        keyring: Arc<PseudonymKeyring>,
        config: DispatcherConfig,
        fence: i64,
        holder: Uuid,
    ) -> Result<Self, RepositoryError> {
        let committed = store.claim(fence, holder).await?;
        Ok(Self {
            store,
            sink,
            keyring,
            config,
            fence,
            committed,
            pending: Vec::new(),
            pending_through: committed,
            accepted: None,
        })
    }

    /// The last position the cursor has committed for this term.
    pub(crate) fn committed_position(&self) -> i64 {
        self.committed
    }

    /// Advance delivery by at most one batch. A batch left in flight by an
    /// earlier failure is finished first, without re-reading: an accepted
    /// batch only needs its cursor advance, a refused one is offered to the
    /// sink again.
    pub(crate) async fn step(
        &mut self,
        stop: &CancellationToken,
    ) -> Result<StepOutcome, StepError> {
        if stop.is_cancelled() {
            return Ok(StepOutcome::Stopped);
        }
        if self.accepted.is_none() {
            if self.pending.is_empty() && !self.fill().await? {
                return Ok(StepOutcome::Idle);
            }
            // The rule every leased term follows: stop before the slot can be
            // reclaimed, never after. A lost lease may not have been reclaimed
            // yet, so nothing more is offered once the stop has fired.
            if stop.is_cancelled() {
                return Ok(StepOutcome::Stopped);
            }
            self.offer().await?;
        }
        self.commit().await
    }

    /// Read and project the next batch. `false` when there is none. A row
    /// that cannot be projected refuses the whole batch, so nothing after it
    /// is offered ahead of it.
    async fn fill(&mut self) -> Result<bool, StepError> {
        let limit = self.config.batch_size.clamp(1, MAX_READ_BATCH);
        let rows = self
            .store
            .read_after(self.committed, limit)
            .await
            .map_err(StepError::Read)?;
        let Some(last) = rows.last() else {
            return Ok(false);
        };
        let through = last.position;
        let mut projected = Vec::with_capacity(rows.len());
        for row in &rows {
            projected.push(
                project(row, &self.keyring).map_err(|error| StepError::Projection {
                    position: row.position,
                    error,
                })?,
            );
        }
        self.pending = projected;
        self.pending_through = through;
        Ok(true)
    }

    /// Offer the pending batch to the sink.
    async fn offer(&mut self) -> Result<(), StepError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.sink
            .deliver(&self.pending)
            .await
            .map_err(StepError::Sink)?;
        self.accepted = Some(AcceptedBatch {
            through: self.pending_through,
            events: self.pending.len(),
        });
        self.pending.clear();
        Ok(())
    }

    /// Commit the cursor past an accepted batch.
    async fn commit(&mut self) -> Result<StepOutcome, StepError> {
        let Some(batch) = self.accepted else {
            return Ok(StepOutcome::Idle);
        };
        let events = i64::try_from(batch.events).unwrap_or(i64::MAX);
        match self
            .store
            .advance(self.fence, self.committed, batch.through, events)
            .await
        {
            Ok(()) => {
                self.committed = batch.through;
                self.accepted = None;
                record_delivered(batch.events);
                Ok(StepOutcome::Delivered {
                    events: batch.events,
                    through: batch.through,
                })
            }
            Err(error) if error.kind() == RepositoryErrorKind::Conflict => {
                record_failure(FAILURE_FENCED);
                tracing::warn!(
                    fence = self.fence,
                    "authority event dispatcher fenced out; a newer leader holds the cursor"
                );
                Ok(StepOutcome::Fenced)
            }
            Err(error) => Err(StepError::Cursor(error)),
        }
    }

    /// Step until the journal after the cursor is empty, retrying a failure
    /// after its backoff at most `MAX_TEST_RETRIES` times in a row. Returns
    /// the events delivered; `Ok(None)` means the term ended (fenced out or
    /// stopped) first. The tests' driver, bounded so a broken statement
    /// fails the test instead of retrying forever; the running dispatcher
    /// interleaves the same steps with lease renewal and metrics, and never
    /// gives up.
    #[cfg(test)]
    pub(crate) async fn deliver_until_caught_up(
        &mut self,
        stop: &CancellationToken,
    ) -> Result<Option<usize>, StepError> {
        const MAX_TEST_RETRIES: u32 = 5;
        let mut delivered = 0;
        let mut failures = 0_u32;
        loop {
            match self.step(stop).await {
                Ok(StepOutcome::Idle) => return Ok(Some(delivered)),
                Ok(StepOutcome::Delivered { events, .. }) => {
                    failures = 0;
                    delivered += events;
                }
                Ok(StepOutcome::Fenced | StepOutcome::Stopped) => return Ok(None),
                Err(error) if failures >= MAX_TEST_RETRIES => return Err(error),
                Err(error) => {
                    failures = failures.saturating_add(1);
                    self.report(&error, failures);
                    sleep_or_stop(
                        stop,
                        retry_backoff(self.config.retry_base, self.config.retry_cap, failures),
                    )
                    .await;
                }
            }
        }
    }

    fn report(&self, error: &StepError, failures: u32) {
        record_failure(error.kind());
        match error {
            StepError::Projection { .. } => tracing::error!(
                error = %error,
                committed = self.committed,
                failures,
                "authority event dispatcher cannot project the next journaled event; delivery is stalled there"
            ),
            _ => tracing::warn!(
                error = %error,
                committed = self.committed,
                failures,
                "authority event delivery failed; retrying after backoff"
            ),
        }
    }

    async fn publish_stats(&self) {
        match self.store.stats().await {
            Ok(stats) => record_journal_stats(&stats),
            Err(error) => {
                tracing::debug!(error = %error, "authority event journal stats unavailable");
            }
        }
    }
}

/// Run the dispatcher for the life of the process: contend for the lease,
/// lead while it holds, and contend again when it is lost. The task ends
/// when the lifecycle's background cancellation fires.
pub(crate) fn spawn_authority_event_dispatcher(
    lifecycle: &GatewayLifecycle,
    store: Arc<PostgresAuthorityEventStore>,
    sink: Arc<dyn AuthorityEventSink>,
    keyring: Arc<PseudonymKeyring>,
    leases: Arc<dyn ExecutionLeaseStore>,
    holder: Uuid,
    config: DispatcherConfig,
) {
    let shutdown = lifecycle.background_cancellation();
    let handle = tokio::spawn(async move {
        run_dispatcher(shutdown, store, sink, keyring, leases, holder, config).await;
    });
    lifecycle.register_background_task(handle);
}

pub(crate) async fn run_dispatcher(
    shutdown: CancellationToken,
    store: Arc<PostgresAuthorityEventStore>,
    sink: Arc<dyn AuthorityEventSink>,
    keyring: Arc<PseudonymKeyring>,
    leases: Arc<dyn ExecutionLeaseStore>,
    holder: Uuid,
    config: DispatcherConfig,
) {
    let poll = config.poll_interval.max(Duration::from_millis(1));
    while !shutdown.is_cancelled() {
        let lease = match leases
            .try_acquire(DISPATCHER_LEASE_SCOPE, 1, DISPATCHER_LEASE_INVOCATION)
            .await
        {
            Ok(LeaseAttempt::Acquired(lease)) => lease,
            Ok(LeaseAttempt::Full) => {
                sleep_or_stop(&shutdown, contention_backoff(poll)).await;
                continue;
            }
            Err(error) => {
                record_failure(FAILURE_LEASE);
                tracing::warn!(error = %error, "authority event dispatcher lease acquisition failed");
                sleep_or_stop(&shutdown, contention_backoff(poll)).await;
                continue;
            }
        };

        let mut term = match DispatcherTerm::begin(
            Arc::clone(&store),
            Arc::clone(&sink),
            Arc::clone(&keyring),
            config,
            lease.fence,
            holder,
        )
        .await
        {
            Ok(term) => term,
            Err(error) => {
                record_failure(FAILURE_CLAIM);
                if error.kind() == RepositoryErrorKind::Conflict {
                    tracing::warn!(
                        fence = lease.fence,
                        "authority event dispatcher lease is stale; a newer fence holds the cursor"
                    );
                } else {
                    tracing::warn!(error = %error, "authority event dispatcher cursor claim failed");
                }
                release_lease(&leases, &lease).await;
                sleep_or_stop(&shutdown, contention_backoff(poll)).await;
                continue;
            }
        };
        let held_since = Instant::now();
        crate::tools::lease::record_lease_age(
            crate::tools::lease::LEASE_SCOPE_AUTHORITY_EVENT_DISPATCHER,
            Duration::ZERO,
        );
        term.publish_stats().await;
        tracing::info!(
            fence = lease.fence,
            committed = term.committed_position(),
            sink = sink.kind(),
            key_id = keyring.current_key_id(),
            "authority event dispatcher leading"
        );

        let lost = CancellationToken::new();
        let stop = lost.clone();
        let renewal = tokio::spawn(renew_until_lost(
            Arc::clone(&leases),
            lease.clone(),
            lost.clone(),
        ));
        let shutdown_watch = {
            let stop = stop.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                shutdown.cancelled().await;
                stop.cancel();
            })
        };

        let mut failures = 0_u32;
        loop {
            match term.step(&stop).await {
                Ok(StepOutcome::Delivered { .. }) => failures = 0,
                Ok(StepOutcome::Idle) => {
                    failures = 0;
                    sleep_or_stop(&stop, poll).await;
                }
                Ok(StepOutcome::Fenced | StepOutcome::Stopped) => break,
                Err(error) => {
                    failures = failures.saturating_add(1);
                    term.report(&error, failures);
                    sleep_or_stop(
                        &stop,
                        retry_backoff(config.retry_base, config.retry_cap, failures),
                    )
                    .await;
                }
            }
            crate::tools::lease::record_lease_age(
                crate::tools::lease::LEASE_SCOPE_AUTHORITY_EVENT_DISPATCHER,
                held_since.elapsed(),
            );
            term.publish_stats().await;
            if stop.is_cancelled() {
                break;
            }
        }

        renewal.abort();
        shutdown_watch.abort();
        drop(term);
        crate::tools::lease::record_lease_age(
            crate::tools::lease::LEASE_SCOPE_AUTHORITY_EVENT_DISPATCHER,
            Duration::ZERO,
        );
        release_lease(&leases, &lease).await;
        tracing::info!(fence = lease.fence, "authority event dispatcher term ended");
        if !shutdown.is_cancelled() {
            sleep_or_stop(&shutdown, contention_backoff(poll)).await;
        }
    }
}

async fn release_lease(
    leases: &Arc<dyn ExecutionLeaseStore>,
    lease: &crate::tools::lease::ExecutionLease,
) {
    if let Err(error) = leases.release(lease).await {
        crate::tools::lease::record_lease_failure(
            crate::tools::lease::LEASE_FAILURE_RELEASE_FAILED,
        );
        tracing::warn!(
            error = %error,
            "authority event dispatcher lease release failed; the slot lapses by expiry"
        );
    }
}

/// Four poll intervals plus up to one more of jitter, so replicas that lost
/// the same election do not retry in lockstep.
fn contention_backoff(poll: Duration) -> Duration {
    let jitter_steps = std::collections::hash_map::RandomState::new().hash_one(0_u8) % 16;
    poll * 4 + poll.mul_f64(jitter_steps as f64 / 16.0)
}

async fn sleep_or_stop(stop: &CancellationToken, duration: Duration) {
    tokio::select! {
        () = stop.cancelled() => {}
        () = tokio::time::sleep(duration) => {}
    }
}

#[cfg(test)]
#[path = "dispatcher_tests.rs"]
mod tests;
