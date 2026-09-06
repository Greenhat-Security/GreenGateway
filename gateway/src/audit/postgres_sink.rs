//! PostgreSQL audit sink: the request-path audit of record in cluster mode
//! (issue #11, PR 3).
//!
//! What it is for. Before this sink no serving replica wrote a durable audit
//! row: cluster mode's sinks were stdout, the optional file and the
//! in-process broadcast, and `greengateway.audit_events` was written only by
//! `gateway import-standalone`. This sink puts every replica's events into
//! the shared store through the ONE batch write path the store already has,
//! [`PostgresAuditEventStore::insert_events`] -- the same call the import
//! runs -- so a request-path batch gets exactly what an imported one gets:
//! `ON CONFLICT (event_id) DO NOTHING` for the events, and the stream append
//! in presentation order under the transaction-scoped advisory lock, which
//! is what makes positions contiguous and commit-ordered whichever replica
//! wrote them. Every row carries the replica's [`IngestIdentity`], because
//! the store was built with it.
//!
//! The contract is the SQLite sink's, copied without its SQL:
//!
//! - `emit` runs on the audit writer thread and never blocks on I/O. It
//!   pushes onto a bounded in-memory buffer and returns; it never awaits
//!   and never touches the pool on the caller's thread.
//! - A flusher the sink owns batches the buffer every [`POSTGRES_BATCH_SIZE`]
//!   events or [`POSTGRES_FLUSH_INTERVAL`] into one store call.
//! - A batch the authority refuses is retried a bounded number of times
//!   with backoff, then DROPPED and counted under
//!   `audit_events_dropped_total{reason="postgres"}`. It never blocks the
//!   writer, and the buffer's bound means an outage drops events rather
//!   than growing memory; those drops land on the same counter.
//! - `flush_by` (what the audit writer calls through the composite at the
//!   shutdown drain, with the drain's OWN deadline) hands the flusher that
//!   deadline less a grace and waits for it synchronously until the
//!   deadline itself, so the sink never outlives the drain that is waiting
//!   on it; `flush` and `Drop` do the same against the configured bound
//!   from the moment they are called.
//! - The batch the flusher holds is counted as in flight until it is
//!   stored or dropped, and a flush that ends without the flusher's report
//!   -- the deadline passed, or the runtime tore the flusher down under a
//!   batch, which is what happens when the drain's clock runs out first --
//!   counts the buffer AND that batch as dropped. Nothing the sink accepted
//!   can be lost uncounted; a batch that landed after being counted is
//!   over-counted, which keeps `rows + dropped >= served` true.
//!
//! Threading model. The SQLite sink runs its flusher on a thread of its own
//! because rusqlite is synchronous: the I/O needs a thread the writer does
//! not run on, and one the sink can join at `flush`. The contract that
//! thread encodes is "the sink's I/O runs on a worker the sink owns, off the
//! writer thread, and the sink can wait for it with a bound". The store here
//! is async over the foundation's `deadpool` pool, whose connection drivers
//! are tasks on the gateway runtime, so the worker that satisfies the same
//! contract is a TASK ON THAT RUNTIME, spawned from the constructor's
//! runtime handle -- not a second runtime on a private thread. A private
//! runtime would spawn a connection driver of its own for every connection
//! it checked out, and those drivers would die with the thread at `flush`,
//! leaving pooled clients other subsystems still hold without anything
//! driving them. The writer thread is a plain thread with no runtime, so
//! every handoff is a runtime-free primitive: a `std` mutex for the buffer,
//! a `Notify` (whose `notify_one` is synchronous) for the batch-size wakeup,
//! and a `std` channel `flush` blocks on. `flush` is therefore called OFF
//! the runtime, as the drain does (the writer thread calls it); `Drop` only
//! signals when it finds itself on a runtime thread, and the task -- which
//! owns everything it needs -- finishes its bounded drain alone.

use std::{
    collections::{HashSet, VecDeque},
    error::Error,
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use tokio::{runtime::Handle, sync::Notify};

use crate::{
    audit::{record_flush_outcome, AuditEvent, AuditSink, AUDIT_EVENTS_DROPPED_TOTAL},
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
    storage::{postgres_audit::PostgresAuditEventStore, AuditEventStore as _},
};

#[cfg(doc)]
use crate::storage::postgres_audit::IngestIdentity;

/// The `reason` this sink's drops carry on `audit_events_dropped_total`: a
/// batch the authority refused past the retry budget, or an event that
/// arrived while the buffer was full. Fixed; never derived from an error.
pub const POSTGRES_DROP_REASON: &str = "postgres";

/// Batch size and flush interval match the SQLite sink's, so the two sinks
/// have the same latency to durable.
const POSTGRES_BATCH_SIZE: usize = 200;
const POSTGRES_FLUSH_INTERVAL: Duration = Duration::from_millis(250);

/// The buffer's bound: the audit writer's own channel capacity, so the sink
/// can hold at most what the queue feeding it can hold.
const POSTGRES_BUFFER_CAPACITY: usize = crate::audit::AUDIT_CHANNEL_CAPACITY;

/// A refused batch is offered this many times before it is dropped, waiting
/// [`POSTGRES_RETRY_BACKOFF`] doubled per attempt between offers.
const POSTGRES_BATCH_ATTEMPTS: u32 = 3;
const POSTGRES_RETRY_BACKOFF: Duration = Duration::from_millis(100);

/// One store call may take at most this long before it counts as failed.
/// The pool's acquire and connect timeouts are inside it; this is the bound
/// on a statement that hangs.
const POSTGRES_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);

/// How much before the waiter's deadline the flusher must have finished:
/// the flusher gives up at the deadline less this, and the slack is for it
/// to notice, count, and report before the waiter stops listening.
const POSTGRES_FLUSH_GRACE: Duration = Duration::from_millis(250);

/// What the sink is built from in production.
#[derive(Clone)]
pub struct PostgresSinkConfig {
    /// The store, built against the foundation's pool with the replica's
    /// ingest identity.
    pub store: Arc<PostgresAuditEventStore>,
    /// How long a flush may take to land what the buffer holds when nobody
    /// hands it a deadline of their own: `Drop`, and a bare `flush`. The
    /// shutdown drain hands the writer its deadline and the writer passes
    /// it on (`flush_by`), so this is the bound only when that did not
    /// happen. Production passes the configured audit drain budget
    /// (`AUDIT_DRAIN_TIMEOUT_MS`): a sink that outlived the drain would
    /// only turn a reported timeout into a hung shutdown.
    pub flush_deadline: Duration,
}

/// Every knob the flusher runs under. Production uses the constants above
/// with the configured flush deadline; tests shrink them.
#[derive(Clone, Copy, Debug)]
struct PostgresSinkSettings {
    batch_size: usize,
    flush_interval: Duration,
    buffer_capacity: usize,
    batch_attempts: u32,
    retry_backoff: Duration,
    attempt_timeout: Duration,
    flush_deadline: Duration,
}

#[derive(Debug)]
pub enum PostgresSinkError {
    /// The constructor ran outside a Tokio runtime, so there is nothing to
    /// spawn the flusher on.
    NoRuntime,
}

impl fmt::Display for PostgresSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRuntime => write!(
                formatter,
                "the PostgreSQL audit sink needs a Tokio runtime to spawn its flusher on"
            ),
        }
    }
}

impl Error for PostgresSinkError {}

pub struct PostgresSink {
    shared: Arc<PostgresSinkShared>,
    /// The flusher's completion signal, taken by the first `flush`.
    completion: Mutex<Option<Receiver<()>>>,
}

impl PostgresSink {
    pub fn new(config: PostgresSinkConfig) -> Result<Self, PostgresSinkError> {
        Self::new_with_settings(
            config.store,
            PostgresSinkSettings {
                batch_size: POSTGRES_BATCH_SIZE,
                flush_interval: POSTGRES_FLUSH_INTERVAL,
                buffer_capacity: POSTGRES_BUFFER_CAPACITY,
                batch_attempts: POSTGRES_BATCH_ATTEMPTS,
                retry_backoff: POSTGRES_RETRY_BACKOFF,
                attempt_timeout: POSTGRES_ATTEMPT_TIMEOUT,
                flush_deadline: config.flush_deadline,
            },
        )
    }

    fn new_with_settings(
        store: Arc<PostgresAuditEventStore>,
        settings: PostgresSinkSettings,
    ) -> Result<Self, PostgresSinkError> {
        let handle = Handle::try_current().map_err(|_| PostgresSinkError::NoRuntime)?;
        let shared = Arc::new(PostgresSinkShared {
            store,
            settings,
            buffer: Mutex::new(VecDeque::with_capacity(settings.batch_size)),
            wake: Notify::new(),
            shutdown: AtomicBool::new(false),
            deadline: Mutex::new(None),
            overflowing: AtomicBool::new(false),
            flush_failure: Mutex::new(None),
            in_flight: AtomicU64::new(0),
            in_flight_since: Mutex::new(None),
            dropped: AtomicU64::new(0),
            stored: AtomicU64::new(0),
        });
        let (completion_tx, completion_rx) = mpsc::channel();
        handle.spawn(flusher_loop(Arc::clone(&shared), completion_tx));

        Ok(Self {
            shared,
            completion: Mutex::new(Some(completion_rx)),
        })
    }

    /// Events this sink has dropped since boot: buffer overflows and
    /// batches refused past the retry budget. The metric counts the same
    /// events; this is the in-process reading of it, which the tests
    /// assert on because the flusher's counter increments happen on the
    /// runtime, outside a thread-local recorder's scope.
    #[cfg(test)]
    fn dropped_total(&self) -> u64 {
        self.shared.dropped.load(Ordering::Acquire)
    }

    /// Events the flusher has durably stored since boot.
    #[cfg(test)]
    fn stored_total(&self) -> u64 {
        self.shared.stored.load(Ordering::Acquire)
    }

    fn completion_guard(&self) -> MutexGuard<'_, Option<Receiver<()>>> {
        match self.completion.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "audit",
                    "lock" => "postgres_sink_completion"
                )
                .increment(1);
                tracing::error!("PostgreSQL audit sink completion lock poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }

    /// Stop admission, hand the flusher its deadline (`deadline` less the
    /// grace), and (when `wait`) block until it reports or `deadline`
    /// passes. Idempotent: the completion receiver is taken by the first
    /// waiter, and later calls only return the sticky failure.
    ///
    /// A wait that ends without the flusher's report -- the deadline
    /// passed, or the flusher went away because its runtime shut down under
    /// it -- counts everything the sink still holds as dropped right here,
    /// on the waiter's thread: the buffer, and the batch the flusher had
    /// taken. Leaving that to the flusher would leave it to a task that may
    /// never run again (the process is exiting), and an uncounted loss is
    /// the one thing the drop-and-count contract forbids.
    fn shutdown_and_flush(&self, wait: bool, deadline: Instant) -> Result<(), String> {
        self.shared.begin_shutdown(deadline);
        let completion = if wait {
            self.completion_guard().take()
        } else {
            None
        };
        if let Some(completion) = completion {
            let budget = deadline.saturating_duration_since(Instant::now());
            match completion.recv_timeout(budget) {
                Ok(()) => {}
                Err(RecvTimeoutError::Timeout) => {
                    let stranded = self.shared.count_stranded();
                    self.shared.record_failure(format!(
                        "PostgreSQL audit flush did not complete by its deadline; \
                         {stranded} event(s) dropped"
                    ));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let stranded = self.shared.count_stranded();
                    self.shared.record_failure(format!(
                        "PostgreSQL audit flusher stopped before the drain completed; \
                         {stranded} event(s) dropped"
                    ));
                }
            }
        }
        self.shared.failure()
    }
}

impl AuditSink for PostgresSink {
    fn backlog(&self) -> crate::audit::sink::SinkBacklog {
        let buffer = self.shared.buffer_guard();
        let buffered_since = buffer.front().map(|(since, _)| *since);
        let in_flight_since = *recover_lock(&self.shared.in_flight_since, "postgres_sink_age");
        let oldest = buffered_since.into_iter().chain(in_flight_since).min();
        crate::audit::sink::SinkBacklog {
            depth: buffer
                .len()
                .saturating_add(self.shared.in_flight.load(Ordering::Acquire) as usize),
            capacity: self.shared.settings.buffer_capacity + self.shared.settings.batch_size,
            oldest_age: oldest.map(|since| since.elapsed()).unwrap_or_default(),
            dropped: self.shared.dropped.load(Ordering::Acquire),
        }
    }

    fn name(&self) -> &'static str {
        "postgres"
    }

    fn emit(&self, event: &AuditEvent) {
        if self.shared.push_event(event) == Push::BatchReady {
            self.shared.wake.notify_one();
        }
    }

    fn flush(&self) -> Result<(), String> {
        self.shutdown_and_flush(true, Instant::now() + self.shared.settings.flush_deadline)
    }

    /// The drain's deadline is the sink's: the drain's clock started before
    /// the writer emptied its channel, and a flush timed from now against
    /// the same budget would outlive it, to be torn down mid-batch. The
    /// configured bound still caps it, so a drain with a longer budget than
    /// the sink was built for gets the sink's.
    fn flush_by(&self, deadline: Instant) -> Result<(), String> {
        let own = Instant::now() + self.shared.settings.flush_deadline;
        self.shutdown_and_flush(true, deadline.min(own))
    }
}

impl Drop for PostgresSink {
    fn drop(&mut self) {
        if self.completion_guard().is_none() {
            // `flush` already ran; the sticky failure was reported then.
            return;
        }
        // Off a runtime thread waiting is safe. On one it would starve the
        // very task the wait depends on (a current-thread runtime cannot run
        // it at all), so signal only: the task holds its own `Arc` of the
        // shared state and finishes the bounded drain by itself.
        let wait = Handle::try_current().is_err();
        let deadline = Instant::now() + self.shared.settings.flush_deadline;
        if let Err(error) = self.shutdown_and_flush(wait, deadline) {
            tracing::error!(%error, "PostgreSQL audit sink failed during shutdown");
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Push {
    Accepted,
    BatchReady,
    Refused,
}

struct PostgresSinkShared {
    store: Arc<PostgresAuditEventStore>,
    settings: PostgresSinkSettings,
    buffer: Mutex<VecDeque<(Instant, AuditEvent)>>,
    wake: Notify,
    shutdown: AtomicBool,
    /// When the flusher must have finished, set by `begin_shutdown`; `None`
    /// while the sink is serving.
    deadline: Mutex<Option<Instant>>,
    /// Whether the last push was refused for a full buffer, so the overflow
    /// is logged once per episode rather than once per event.
    overflowing: AtomicBool,
    flush_failure: Mutex<Option<String>>,
    /// How many events the batch the flusher currently holds carries, from
    /// the moment it leaves the buffer until it is stored or dropped; zero
    /// between batches. Whoever swaps it to zero owns the accounting for
    /// those events: the flusher on store or drop, or a waiter that stopped
    /// listening before the flusher reported (`count_stranded`).
    in_flight: AtomicU64,
    in_flight_since: Mutex<Option<Instant>>,
    dropped: AtomicU64,
    stored: AtomicU64,
}

impl PostgresSinkShared {
    fn push_event(&self, event: &AuditEvent) -> Push {
        let mut buffer = self.buffer_guard();
        if self.shutdown.load(Ordering::Acquire) || buffer.len() >= self.settings.buffer_capacity {
            drop(buffer);
            self.note_dropped(1);
            if !self.overflowing.swap(true, Ordering::AcqRel) {
                tracing::error!(
                    capacity = self.settings.buffer_capacity,
                    "PostgreSQL audit sink buffer is full; dropping events until the flusher catches up"
                );
            }
            return Push::Refused;
        }
        buffer.push_back((Instant::now(), event.clone()));
        if buffer.len() >= self.settings.batch_size {
            Push::BatchReady
        } else {
            Push::Accepted
        }
    }

    /// Up to one batch, in emission order. Ids are unique within the batch:
    /// the writer emits each event once and ids are fresh UUIDs, but the
    /// stream append reserves a position per id a batch PRESENTS that is
    /// not yet in the stream, so one id twice in a batch would leave a
    /// permanent gap (the import's `PageDedup` guards the same edge).
    fn take_batch(&self) -> Vec<AuditEvent> {
        let mut buffer = self.buffer_guard();
        let take = buffer.len().min(self.settings.batch_size);
        if take > 0 {
            self.overflowing.store(false, Ordering::Release);
        }
        *recover_lock(&self.in_flight_since, "postgres_sink_age") =
            buffer.front().map(|(since, _)| *since);
        let mut seen = HashSet::with_capacity(take);
        let batch: Vec<_> = buffer
            .drain(..take)
            .map(|(_, event)| event)
            .filter(|event| seen.insert(event.event_id.clone()))
            .collect();
        // Publish the handoff before releasing the buffer lock, so status
        // cannot observe an empty buffer and no batch between these stages.
        self.in_flight.store(batch.len() as u64, Ordering::Release);
        batch
    }

    /// One batch through the store's single write path, retried within the
    /// budget, then dropped and counted.
    ///
    /// The timeout around each attempt drops the store's future mid-
    /// transaction, and that is safe only because the store's transaction
    /// rolls itself back when dropped (`postgres_audit.rs`); a hand-driven
    /// `BEGIN` would leave the stream lock held on a pooled connection.
    async fn write_batch(&self, batch: Vec<AuditEvent>) {
        let count = batch.len();
        let mut attempt = 0_u32;
        loop {
            attempt += 1;
            let remaining = self.remaining_budget();
            if remaining.is_some_and(|left| left.is_zero()) {
                self.drop_batch(count, "the flush deadline passed");
                return;
            }
            let budget = remaining.map_or(self.settings.attempt_timeout, |left| {
                left.min(self.settings.attempt_timeout)
            });
            let failure = match tokio::time::timeout(budget, self.store.insert_events(&batch)).await
            {
                Ok(Ok(())) => {
                    record_flush_outcome(true);
                    // Zero if a waiter already counted this batch as lost;
                    // the rows are there regardless.
                    let landed = self.in_flight.swap(0, Ordering::AcqRel);
                    self.stored.fetch_add(landed, Ordering::AcqRel);
                    *recover_lock(&self.in_flight_since, "postgres_sink_age") = None;
                    return;
                }
                Ok(Err(error)) => error.to_string(),
                Err(_) => format!("store call exceeded {budget:?}"),
            };
            if attempt >= self.settings.batch_attempts {
                self.drop_batch(count, &failure);
                return;
            }
            let backoff = self
                .settings
                .retry_backoff
                .saturating_mul(1_u32 << (attempt - 1).min(16));
            let backoff = self
                .remaining_budget()
                .map_or(backoff, |left| backoff.min(left));
            tracing::warn!(
                attempt,
                event_count = count,
                error = %failure,
                "PostgreSQL audit batch refused; retrying"
            );
            tokio::time::sleep(backoff).await;
        }
    }

    fn drop_batch(&self, count: usize, error: &str) {
        record_flush_outcome(false);
        *recover_lock(&self.in_flight_since, "postgres_sink_age") = None;
        // Zero if a waiter already counted this batch as lost.
        let dropped = self.in_flight.swap(0, Ordering::AcqRel);
        if dropped > 0 {
            self.note_dropped(dropped);
        }
        self.record_failure(format!("PostgreSQL audit flush failed: {error}"));
        tracing::error!(
            event_count = count,
            error,
            "failed to flush PostgreSQL audit events; dropping batch"
        );
    }

    /// Count dropped events in the metric and in the in-process counter, so
    /// the two can never disagree about a drop.
    fn note_dropped(&self, count: u64) {
        self.dropped.fetch_add(count, Ordering::AcqRel);
        ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => POSTGRES_DROP_REASON)
            .increment(count);
    }

    /// Everything the sink still holds once its waiter stops listening --
    /// the buffer and the batch in flight -- counted as dropped, and the
    /// count returned. Taking the buffer here also ends the flusher's loop
    /// on its next turn, if it gets one.
    fn count_stranded(&self) -> u64 {
        let buffered = self.buffer_guard().drain(..).count() as u64;
        let stranded = buffered + self.in_flight.swap(0, Ordering::AcqRel);
        *recover_lock(&self.in_flight_since, "postgres_sink_age") = None;
        if stranded > 0 {
            self.note_dropped(stranded);
        }
        stranded
    }

    /// Stop admission and give the flusher its deadline: the waiter's, less
    /// the grace it needs to report. The first deadline given wins, so a
    /// later `flush` cannot extend a drain already under way.
    fn begin_shutdown(&self, waiter_deadline: Instant) {
        {
            let mut deadline = self.deadline_guard();
            if deadline.is_none() {
                *deadline = Some(
                    waiter_deadline
                        .checked_sub(POSTGRES_FLUSH_GRACE)
                        .unwrap_or(waiter_deadline),
                );
            }
        }
        self.shutdown.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    fn is_drained_after_shutdown(&self) -> bool {
        // Recheck under the admission lock after observing shutdown. A writer
        // may have enqueued its final event after take_batch observed empty,
        // but before shutdown closed admission. An earlier empty observation
        // cannot establish that those accepted events have been drained.
        self.shutdown.load(Ordering::Acquire) && self.buffer_guard().is_empty()
    }

    /// `None` while serving; the time left before the flush deadline once
    /// shutdown began (zero when it has passed).
    fn remaining_budget(&self) -> Option<Duration> {
        self.deadline_guard()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    fn record_failure(&self, message: String) {
        let mut failure = self.failure_guard();
        if failure.is_none() {
            *failure = Some(message);
        }
    }

    fn failure(&self) -> Result<(), String> {
        self.failure_guard().clone().map_or(Ok(()), Err)
    }

    fn buffer_guard(&self) -> MutexGuard<'_, VecDeque<(Instant, AuditEvent)>> {
        recover_lock(&self.buffer, "postgres_sink_buffer")
    }

    fn deadline_guard(&self) -> MutexGuard<'_, Option<Instant>> {
        recover_lock(&self.deadline, "postgres_sink_deadline")
    }

    fn failure_guard(&self) -> MutexGuard<'_, Option<String>> {
        recover_lock(&self.flush_failure, "postgres_sink_failure")
    }
}

fn recover_lock<'a, T>(mutex: &'a Mutex<T>, lock_name: &'static str) -> MutexGuard<'a, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            ::metrics::counter!(
                LOCK_POISON_RECOVERIES_TOTAL,
                "component" => "audit",
                "lock" => lock_name
            )
            .increment(1);
            tracing::error!(
                lock = lock_name,
                "PostgreSQL audit sink lock poisoned; recovering"
            );
            poisoned.into_inner()
        }
    }
}

/// The flusher: batches until the buffer is empty, then waits for a
/// batch-size wakeup or the interval; after shutdown it drains what is left
/// (each batch bounded by the deadline) and reports completion.
async fn flusher_loop(shared: Arc<PostgresSinkShared>, completion: Sender<()>) {
    loop {
        let batch = shared.take_batch();
        if batch.is_empty() {
            if shared.is_drained_after_shutdown() {
                break;
            }
            tokio::select! {
                () = shared.wake.notified() => {}
                () = tokio::time::sleep(shared.settings.flush_interval) => {}
            }
            continue;
        }
        shared.write_batch(batch).await;
    }
    let _ = completion.send(());
}

#[cfg(test)]
mod tests {
    use std::{net::TcpListener, thread};

    use serde_json::json;

    use super::*;
    use crate::{
        audit::sink::tests::CountingRecorder,
        storage::{
            contract_tests::postgres_audit_tests::{
                create_test_database, locator, write_dsn_file, TestDatabase, DATABASE,
            },
            migrations,
            postgres::PostgresFoundation,
            postgres_audit::IngestIdentity,
        },
    };

    fn test_settings(
        batch_size: usize,
        flush_interval: Duration,
        buffer_capacity: usize,
        flush_deadline: Duration,
    ) -> PostgresSinkSettings {
        PostgresSinkSettings {
            batch_size,
            flush_interval,
            buffer_capacity,
            batch_attempts: 2,
            retry_backoff: Duration::from_millis(20),
            attempt_timeout: Duration::from_secs(5),
            flush_deadline,
        }
    }

    fn test_event(index: usize) -> AuditEvent {
        AuditEvent::new(
            format!("audit.postgres_sink.{index}"),
            format!("request-{index}"),
            "203.0.113.10",
            None,
            json!({ "method": "GET", "path": format!("/sink/{index}"), "status": 200 }),
        )
    }

    fn identity() -> IngestIdentity {
        IngestIdentity {
            instance_id: uuid::Uuid::new_v4(),
            boot_id: uuid::Uuid::new_v4(),
        }
    }

    /// `flush` blocks on the flusher, which lives on the test runtime, so
    /// it runs where production runs it: off the runtime (the drain calls
    /// it from the writer thread).
    async fn flush_off_runtime(sink: &Arc<PostgresSink>) -> Result<(), String> {
        let sink = Arc::clone(sink);
        tokio::task::spawn_blocking(move || sink.flush())
            .await
            .expect("flush should not panic")
    }

    /// Emit from a plain thread with no runtime, as the audit writer thread
    /// does, and report how long the whole burst took.
    fn emit_from_writer_thread(sink: &Arc<PostgresSink>, events: Vec<AuditEvent>) -> Duration {
        let sink = Arc::clone(sink);
        thread::spawn(move || {
            let started = Instant::now();
            for event in &events {
                sink.emit(event);
            }
            started.elapsed()
        })
        .join()
        .expect("the writer thread should not panic")
    }

    async fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        condition()
    }

    /// A pool whose server accepts the TCP connection and never answers the
    /// startup message, so a checkout hangs for the create timeout: the
    /// flusher is stuck without a database being involved.
    fn hanging_pool() -> (deadpool_postgres::Pool, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener should bind");
        let port = listener
            .local_addr()
            .expect("listener should have an address")
            .port();
        let mut config = tokio_postgres::Config::new();
        config
            .host("127.0.0.1")
            .port(port)
            .user("gateway_sink_test")
            .dbname("gateway_sink_test");
        let mut pool_config = deadpool_postgres::PoolConfig::new(1);
        pool_config.timeouts.create = Some(Duration::from_secs(60));
        let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
            config,
            tokio_postgres::NoTls,
        ))
        .config(pool_config)
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .build()
        .expect("hanging pool should build");
        (pool, listener)
    }

    #[tokio::test]
    async fn a_full_buffer_drops_and_counts_without_blocking_emit() {
        let (pool, _listener) = hanging_pool();
        let store = Arc::new(PostgresAuditEventStore::new(pool, Some(identity())));
        let capacity = 8;
        let sink = PostgresSink::new_with_settings(
            store,
            test_settings(
                4,
                Duration::from_secs(3_600),
                capacity,
                Duration::from_millis(100),
            ),
        )
        .expect("sink should build inside a runtime");
        let recorder = CountingRecorder::default();

        // The flusher cannot run until this thread yields, so every push
        // lands in the buffer or is refused by its bound.
        let offered = capacity + 12;
        let started = Instant::now();
        ::metrics::with_local_recorder(&recorder, || {
            for index in 0..offered {
                sink.emit(&test_event(index));
            }
        });
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(200),
            "emitting {offered} events took {elapsed:?}; emit must never wait on the flusher"
        );
        assert_eq!(
            sink.dropped_total(),
            12,
            "everything past the bound is dropped, nothing past it is held"
        );
        assert_eq!(
            recorder.count(
                AUDIT_EVENTS_DROPPED_TOTAL,
                &[("reason", POSTGRES_DROP_REASON)]
            ),
            12,
            "buffer drops must be counted under the sink's fixed reason"
        );
        assert_eq!(
            sink.shared.buffer_guard().len(),
            capacity,
            "the buffer must hold exactly its bound"
        );
        let batch = sink.shared.take_batch();
        assert_eq!(batch.len(), 4);
        assert_eq!(
            sink.backlog().depth,
            capacity,
            "buffer-to-batch handoff must not hide pending deliveries"
        );
        sink.shared.drop_batch(batch.len(), "test cleanup");
    }

    #[test]
    fn the_sink_refuses_to_build_without_a_runtime() {
        let (pool, _listener) = hanging_pool();
        let store = Arc::new(PostgresAuditEventStore::new(pool, Some(identity())));
        let error = PostgresSink::new(PostgresSinkConfig {
            store,
            flush_deadline: Duration::from_secs(1),
        })
        .err()
        .expect("no runtime means no flusher to spawn");
        assert!(matches!(error, PostgresSinkError::NoRuntime));
    }

    // -----------------------------------------------------------------------
    // Against a real PostgreSQL (the contract tests' per-test database).
    // Gated on the test harness locator; a checkout without a database
    // skips, CI runs them.
    // -----------------------------------------------------------------------

    async fn migrated_pool(database: &TestDatabase) -> deadpool_postgres::Pool {
        let mut config = crate::config::Config::test_defaults();
        config.state_backend = crate::config::StateBackend::Postgres;
        config.deployment_id = Some("deploy-audit-sink".to_owned());
        let dsn_file = write_dsn_file(&database.dsn);
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = crate::config::DatabaseTlsMode::LoopbackDev;
        let foundation = PostgresFoundation::establish(&config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the audit schema should migrate");
        foundation.pool().clone()
    }

    /// Every stream row joined to its event: position, event id, and the
    /// ingest identity the row carries.
    async fn stream_rows(
        pool: &deadpool_postgres::Pool,
    ) -> Vec<(i64, String, Option<String>, Option<String>)> {
        let client = pool.get().await.expect("checkout");
        client
            .query(
                "SELECT s.position, s.event_id, e.instance_id::text, e.boot_id::text \
                 FROM greengateway.audit_stream s \
                 JOIN greengateway.audit_events e ON e.event_id = s.event_id \
                 ORDER BY s.position",
                &[],
            )
            .await
            .expect("stream rows should query")
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
            .collect()
    }

    async fn event_row_count(pool: &deadpool_postgres::Pool) -> i64 {
        let client = pool.get().await.expect("checkout");
        client
            .query_one("SELECT count(*) FROM greengateway.audit_events", &[])
            .await
            .expect("count should query")
            .get(0)
    }

    #[tokio::test]
    async fn n_events_become_n_rows_in_presentation_order_with_the_writers_identity() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database).await;
        let identity = identity();
        let store = Arc::new(PostgresAuditEventStore::new(pool.clone(), Some(identity)));
        // Two full batches and a partial one, so batch boundaries fall
        // inside the run.
        let sink = Arc::new(
            PostgresSink::new_with_settings(
                store,
                test_settings(
                    200,
                    Duration::from_millis(50),
                    POSTGRES_BUFFER_CAPACITY,
                    Duration::from_secs(5),
                ),
            )
            .expect("sink should build"),
        );
        let events = (0..450).map(test_event).collect::<Vec<_>>();
        let expected_ids = events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();

        let elapsed = emit_from_writer_thread(&sink, events);
        assert!(
            elapsed < Duration::from_millis(500),
            "450 emits took {elapsed:?}; emit must be a buffer push"
        );
        flush_off_runtime(&sink)
            .await
            .expect("a healthy authority makes the flush clean");

        let rows = stream_rows(&pool).await;
        assert_eq!(rows.len(), 450, "N events must become N rows");
        assert_eq!(event_row_count(&pool).await, 450);
        for (index, (position, event_id, instance_id, boot_id)) in rows.iter().enumerate() {
            assert_eq!(
                *position,
                index as i64 + 1,
                "positions must be contiguous from 1"
            );
            assert_eq!(
                event_id, &expected_ids[index],
                "position {position} must hold the event emitted {index}th"
            );
            assert_eq!(
                instance_id.as_deref(),
                Some(identity.instance_id.to_string().as_str()),
                "every row must carry the writing replica's instance id"
            );
            assert_eq!(
                boot_id.as_deref(),
                Some(identity.boot_id.to_string().as_str()),
                "every row must carry the writing replica's boot id"
            );
        }
        assert_eq!(sink.dropped_total(), 0);
    }

    #[tokio::test]
    async fn the_same_batch_offered_twice_is_stored_once() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database).await;
        let store = Arc::new(PostgresAuditEventStore::new(pool.clone(), Some(identity())));
        let sink = Arc::new(
            PostgresSink::new_with_settings(
                store,
                test_settings(
                    200,
                    Duration::from_millis(20),
                    POSTGRES_BUFFER_CAPACITY,
                    Duration::from_secs(5),
                ),
            )
            .expect("sink should build"),
        );
        let events = (0..120).map(test_event).collect::<Vec<_>>();

        // First offer lands on the interval; the second is the same batch
        // again (an at-least-once replay), offered only once the first is
        // durable so it is a second store call, not a merged one.
        emit_from_writer_thread(&sink, events.clone());
        assert!(
            wait_until(Duration::from_secs(5), || sink.stored_total() == 120).await,
            "the first offer should land on the interval"
        );
        emit_from_writer_thread(&sink, events.clone());
        flush_off_runtime(&sink)
            .await
            .expect("a replayed batch is not a failure");

        assert_eq!(
            sink.stored_total(),
            240,
            "both offers are accepted by the store"
        );
        assert_eq!(
            event_row_count(&pool).await,
            120,
            "the replay must insert nothing"
        );
        let rows = stream_rows(&pool).await;
        assert_eq!(rows.len(), 120, "the replay must append nothing");
        for (index, (position, event_id, _, _)) in rows.iter().enumerate() {
            assert_eq!(*position, index as i64 + 1, "no gap and no second row");
            assert_eq!(event_id, &events[index].event_id);
        }
    }

    #[tokio::test]
    async fn a_refusing_authority_drops_and_counts_without_blocking_emit() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database).await;
        // The authority refuses every insert: a trigger, so the refusal is
        // the database's answer to the batch, not a pool that cannot connect.
        pool.get()
            .await
            .expect("checkout")
            .batch_execute(
                "CREATE FUNCTION greengateway.refuse_audit() RETURNS trigger \
                 LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'authority refuses'; END $$; \
                 CREATE TRIGGER refuse_audit BEFORE INSERT ON greengateway.audit_events \
                 FOR EACH STATEMENT EXECUTE FUNCTION greengateway.refuse_audit();",
            )
            .await
            .expect("the refusing trigger should install");
        let store = Arc::new(PostgresAuditEventStore::new(pool.clone(), Some(identity())));
        let sink = Arc::new(
            PostgresSink::new_with_settings(
                store,
                test_settings(
                    100,
                    Duration::from_millis(20),
                    POSTGRES_BUFFER_CAPACITY,
                    Duration::from_secs(5),
                ),
            )
            .expect("sink should build"),
        );

        let elapsed = emit_from_writer_thread(&sink, (0..300).map(test_event).collect());
        assert!(
            elapsed < Duration::from_millis(500),
            "300 emits against a refusing authority took {elapsed:?}; emit must not wait"
        );
        assert!(
            wait_until(Duration::from_secs(10), || sink.dropped_total() == 300).await,
            "every refused batch must be dropped and counted, got {} dropped",
            sink.dropped_total()
        );
        assert_eq!(sink.stored_total(), 0);
        assert_eq!(event_row_count(&pool).await, 0);
        assert!(
            sink.shared.buffer_guard().is_empty(),
            "a dropped batch must not be held for a later retry"
        );

        // The authority recovers: later events land, and the drain reports
        // the earlier loss rather than hiding it.
        pool.get()
            .await
            .expect("checkout")
            .batch_execute("DROP TRIGGER refuse_audit ON greengateway.audit_events")
            .await
            .expect("the refusing trigger should uninstall");
        emit_from_writer_thread(&sink, (300..305).map(test_event).collect());
        let error = flush_off_runtime(&sink)
            .await
            .expect_err("the drain must report the dropped batches");
        assert!(
            error.contains("PostgreSQL audit flush failed"),
            "flush error should name the sink: {error}"
        );
        assert_eq!(sink.stored_total(), 5);
        assert_eq!(event_row_count(&pool).await, 5);
        assert_eq!(sink.dropped_total(), 300);
    }

    #[tokio::test]
    async fn flush_lands_the_buffer_within_its_deadline() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let _guard = DATABASE.lock().await;
        let database = create_test_database(&admin_dsn).await;
        let pool = migrated_pool(&database).await;
        let store = Arc::new(PostgresAuditEventStore::new(pool.clone(), Some(identity())));
        // Neither the batch size nor the interval can fire: only the drain
        // can land these events.
        let deadline = Duration::from_secs(2);
        let sink = Arc::new(
            PostgresSink::new_with_settings(
                store,
                test_settings(
                    1_000,
                    Duration::from_secs(3_600),
                    POSTGRES_BUFFER_CAPACITY,
                    deadline,
                ),
            )
            .expect("sink should build"),
        );
        emit_from_writer_thread(&sink, (0..50).map(test_event).collect());
        assert_eq!(
            event_row_count(&pool).await,
            0,
            "nothing lands before the drain"
        );

        let started = Instant::now();
        flush_off_runtime(&sink)
            .await
            .expect("the drain should be clean");
        let elapsed = started.elapsed();

        assert!(
            elapsed < deadline,
            "flush took {elapsed:?}, longer than its {deadline:?} deadline"
        );
        let rows = stream_rows(&pool).await;
        assert_eq!(rows.len(), 50, "the drain must land every buffered event");
        assert_eq!(rows.last().map(|row| row.0), Some(50));
        assert_eq!(
            flush_off_runtime(&sink).await,
            Ok(()),
            "flush must be idempotent"
        );
        assert_eq!(sink.dropped_total(), 0);
    }

    #[tokio::test]
    async fn a_drain_past_its_deadline_drops_and_counts_instead_of_hanging() {
        let (pool, _listener) = hanging_pool();
        let store = Arc::new(PostgresAuditEventStore::new(pool, Some(identity())));
        let deadline = Duration::from_millis(300);
        let sink = Arc::new(
            PostgresSink::new_with_settings(
                store,
                test_settings(1_000, Duration::from_secs(3_600), 64, deadline),
            )
            .expect("sink should build"),
        );
        emit_from_writer_thread(&sink, (0..10).map(test_event).collect());

        let started = Instant::now();
        let error = flush_off_runtime(&sink)
            .await
            .expect_err("a drain that cannot land its batch must say so");
        let elapsed = started.elapsed();

        // What this rules out is the hang: without the deadline, flush
        // would sit in the pool's 60 s connect timeout. The bound is placed
        // far below that and far above scheduler jitter -- on a loaded
        // machine the blocking pool that runs `flush` and the runtime that
        // runs the flusher are both contended, and a bound a few hundred
        // milliseconds past the deadline measured the machine, not the sink.
        assert!(
            elapsed < deadline + POSTGRES_FLUSH_GRACE + Duration::from_secs(5),
            "flush took {elapsed:?} against a {deadline:?} deadline; it must be bounded by \
             the deadline, not by the pool's connect timeout"
        );
        assert!(
            error.contains("PostgreSQL audit flush"),
            "flush error should name the sink: {error}"
        );
        assert!(
            wait_until(Duration::from_secs(2), || sink.dropped_total() == 10).await,
            "the unlanded batch must be dropped and counted, got {}",
            sink.dropped_total()
        );
    }

    #[tokio::test]
    async fn shutdown_rechecks_events_enqueued_after_an_empty_batch() {
        let (pool, _listener) = hanging_pool();
        let store = Arc::new(PostgresAuditEventStore::new(pool, Some(identity())));
        let sink = PostgresSink::new_with_settings(
            store,
            test_settings(
                1_000,
                Duration::from_secs(3_600),
                64,
                Duration::from_secs(30),
            ),
        )
        .expect("sink should build");

        // No await: drive the critical interleaving before the spawned flusher
        // can run on this current-thread runtime.
        assert!(sink.shared.take_batch().is_empty());
        sink.emit(&test_event(0));
        sink.shared
            .begin_shutdown(Instant::now() + Duration::from_secs(30));
        assert!(!sink.shared.is_drained_after_shutdown());
        assert_eq!(sink.shared.take_batch().len(), 1);
        assert!(sink.shared.is_drained_after_shutdown());
    }

    /// The batch the flusher holds when its runtime is torn down under it
    /// is counted, not just the buffer behind it. The teardown is what
    /// happens when the drain's clock runs out before the sink's: `main`
    /// returns and the runtime drops the flusher wherever it is parked.
    /// `flush` is still waiting -- it runs on the writer thread, which has
    /// no runtime -- and it is the one that must do the counting, because
    /// the task that would have is gone.
    #[test]
    fn a_flusher_torn_down_mid_batch_counts_the_batch_it_held() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the test runtime should build");
        let (pool, _listener) = hanging_pool();
        let store = Arc::new(PostgresAuditEventStore::new(pool, Some(identity())));
        // A deadline far past the teardown, so the only way the wait ends
        // is the flusher going away.
        let sink = runtime.block_on(async {
            Arc::new(
                PostgresSink::new_with_settings(
                    store,
                    test_settings(
                        1_000,
                        Duration::from_secs(3_600),
                        64,
                        Duration::from_secs(30),
                    ),
                )
                .expect("sink should build"),
            )
        });
        // This regression needs one in-flight batch. Seed it atomically so
        // the flusher cannot take a partial batch while the producer is
        // still emitting, then park in I/O with the remaining events buffered.
        sink.shared
            .buffer_guard()
            .extend((0..10).map(|index| (Instant::now(), test_event(index))));
        let flushing = {
            let sink = Arc::clone(&sink);
            thread::spawn(move || sink.flush())
        };
        // The flusher wakes on the shutdown, takes the batch, and parks in
        // the pool's checkout: the buffer is empty and the batch in flight.
        let deadline = Instant::now() + Duration::from_secs(5);
        while !sink.shared.buffer_guard().is_empty() {
            assert!(
                Instant::now() < deadline,
                "the flusher should have taken the batch by now"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            sink.dropped_total(),
            0,
            "nothing is lost before the teardown"
        );
        assert_eq!(sink.shared.in_flight.load(Ordering::Acquire), 10);

        drop(runtime);

        let error = flushing
            .join()
            .expect("flush should not panic")
            .expect_err("a flusher torn down mid-batch must be reported");
        assert!(
            error.contains("stopped before the drain completed"),
            "flush should name the teardown: {error}"
        );
        assert_eq!(
            sink.dropped_total(),
            10,
            "the batch the flusher held when it was torn down must be counted as dropped"
        );
        assert_eq!(sink.stored_total(), 0);
    }

    /// A drain deadline earlier than the sink's own bound wins: the flush
    /// returns by that deadline and counts what it could not land, instead
    /// of running on its own clock past the drain that was waiting on it.
    #[tokio::test]
    async fn flush_by_an_earlier_drain_deadline_gives_up_at_that_deadline() {
        let (pool, _listener) = hanging_pool();
        let store = Arc::new(PostgresAuditEventStore::new(pool, Some(identity())));
        let sink = Arc::new(
            PostgresSink::new_with_settings(
                store,
                test_settings(
                    1_000,
                    Duration::from_secs(3_600),
                    64,
                    Duration::from_secs(30),
                ),
            )
            .expect("sink should build"),
        );
        emit_from_writer_thread(&sink, (0..10).map(test_event).collect());

        let budget = Duration::from_millis(300);
        let started = Instant::now();
        let flushing = {
            let sink = Arc::clone(&sink);
            let deadline = started + budget;
            tokio::task::spawn_blocking(move || sink.flush_by(deadline))
        };
        let error = flushing
            .await
            .expect("flush should not panic")
            .expect_err("a drain that cannot land its batch must say so");
        let elapsed = started.elapsed();

        // The same scheduler slack as the deadline test above; what this
        // rules out is the sink's own 30 s bound, not jitter.
        assert!(
            elapsed < budget + Duration::from_secs(5),
            "flush_by took {elapsed:?} against a {budget:?} drain deadline; it ran on the \
             sink's own clock instead"
        );
        assert!(
            error.contains("PostgreSQL audit flush"),
            "flush error should name the sink: {error}"
        );
        assert_eq!(
            sink.dropped_total(),
            10,
            "what the drain could not land must be counted when the drain gives up"
        );
    }
}
