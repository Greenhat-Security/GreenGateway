//! Audit event primitives and asynchronous emission.

use std::{
    fmt, io,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc::{self, SyncSender, TrySendError},
        Arc, Mutex, MutexGuard,
    },
    thread,
    time::{Duration, Instant},
};

use crate::config::Config;

pub mod event;
pub mod query;
pub mod redact;
pub mod sink;
pub mod sqlite_sink;

pub use event::{Actor, AuditEvent};
pub use sink::AuditSink;

pub type AuditEventSender = tokio::sync::broadcast::Sender<AuditEvent>;

pub const AUDIT_EVENTS_DROPPED_TOTAL: &str = "audit_events_dropped_total";
pub const AUDIT_SQLITE_FLUSH_ERRORS_TOTAL: &str = "audit_sqlite_flush_errors_total";

const AUDIT_CHANNEL_CAPACITY: usize = 8192;
const AUDIT_CONTROL_RESERVE: usize = 8;
const AUDIT_NORMAL_CAPACITY: usize = AUDIT_CHANNEL_CAPACITY - AUDIT_CONTROL_RESERVE;

/// The two outcomes [`record_flush_outcome`] reports, and the whole
/// vocabulary of `greengateway_audit_flush_total`'s `outcome` label.
///
/// Declared as a list because the registry label audit
/// (`the_ha_metric_registry_never_labels_by_a_caller_influenced_value`)
/// checks the rendered label against it; the emitter itself picks between
/// the two constants directly, so nothing but the audit reads the array.
#[cfg_attr(not(test), allow(dead_code))]
pub const AUDIT_FLUSH_OUTCOMES: [&str; 2] = [FLUSH_SUCCESS, FLUSH_FAILURE];
pub(crate) const FLUSH_SUCCESS: &str = "success";
pub(crate) const FLUSH_FAILURE: &str = "failure";

/// Count one durable flush of a sink's buffer (issue #241, PR 14).
///
/// A flush is the moment accepted events become recoverable, so the
/// failure count is the number of times a batch the gateway had already
/// told a caller it recorded was in fact lost. Only the outcome is a
/// label: the error's text goes to the log and its operation to
/// `audit_sqlite_flush_errors_total`.
/// The queue gauges, split from the [`AuditLog`] that owns the values so
/// the registry label audit (`metrics.rs`) can drive the real emitter
/// without starting a writer thread. None of the three carries a label:
/// there is one audit writer per process, and the process is what a
/// scrape target already identifies.
pub(crate) fn record_queue_gauges(depth: usize, capacity: usize, oldest_age: Duration) {
    ::metrics::gauge!(crate::metrics::AUDIT_QUEUE_DEPTH).set(depth as f64);
    ::metrics::gauge!(crate::metrics::AUDIT_QUEUE_CAPACITY).set(capacity as f64);
    ::metrics::gauge!(crate::metrics::AUDIT_QUEUE_OLDEST_AGE_SECONDS).set(oldest_age.as_secs_f64());
}

pub(crate) fn record_flush_outcome(succeeded: bool) {
    let outcome = if succeeded {
        FLUSH_SUCCESS
    } else {
        FLUSH_FAILURE
    };
    ::metrics::counter!(crate::metrics::AUDIT_FLUSH_TOTAL, "outcome" => outcome).increment(1);
}

#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<AuditLogInner>,
}

struct AuditLogInner {
    tx: Mutex<Option<SyncSender<QueuedEvent>>>,
    writer: Mutex<Option<thread::JoinHandle<Result<(), String>>>>,
    closed: AtomicBool,
    queued: Arc<AtomicUsize>,
    /// Events refused admission since boot, for the same reasons
    /// `audit_events_dropped_total` counts. The metric is a counter in the
    /// Prometheus registry and cannot be read back in-process; the admin
    /// status view needs the number, so it is kept here too and both are
    /// incremented in one place ([`AuditLog::note_dropped`]).
    dropped: Arc<AtomicU64>,
    /// When the event the writer is currently delivering was enqueued, or
    /// `None` while the writer is idle. It is the oldest event in the
    /// system: the channel is FIFO and the writer takes one at a time, so
    /// its age is how far behind a stalled sink has fallen -- the number
    /// `queued` alone cannot tell you, because a sink stuck on a single
    /// event has an empty queue behind it.
    in_flight_since: Arc<Mutex<Option<Instant>>>,
}

/// One event on its way to the writer, stamped when it was admitted.
struct QueuedEvent {
    enqueued_at: Instant,
    event: AuditEvent,
}

/// Record (or clear) the enqueue instant of the event the writer holds.
/// Written only by the writer thread; a poisoned lock is recovered rather
/// than propagated, because losing the age of one event must never stop
/// audit delivery.
fn set_in_flight(slot: &Mutex<Option<Instant>>, since: Option<Instant>) {
    *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = since;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AuditDrainError {
    Timeout,
    WriterPanicked,
    Sink(String),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuditControlError {
    Closed,
    Full,
    Disconnected,
}

impl fmt::Display for AuditDrainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(formatter, "audit drain exceeded its configured timeout"),
            Self::WriterPanicked => write!(formatter, "audit writer thread panicked"),
            Self::Sink(error) => write!(formatter, "audit sink flush failed: {error}"),
        }
    }
}

impl std::error::Error for AuditDrainError {}

impl fmt::Display for AuditControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed => write!(formatter, "audit admission is closed"),
            Self::Full => write!(formatter, "reserved audit control capacity is exhausted"),
            Self::Disconnected => write!(formatter, "audit writer is unavailable"),
        }
    }
}

impl std::error::Error for AuditControlError {}

impl AuditLogInner {
    fn tx_guard(&self) -> MutexGuard<'_, Option<SyncSender<QueuedEvent>>> {
        self.tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn writer_guard(&self) -> MutexGuard<'_, Option<thread::JoinHandle<Result<(), String>>>> {
        self.writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl AuditLog {
    #[cfg(test)]
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self::try_new(sink).expect("audit writer thread should start")
    }

    pub fn try_new(sink: Arc<dyn AuditSink>) -> io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<QueuedEvent>(AUDIT_CHANNEL_CAPACITY);
        let queued = Arc::new(AtomicUsize::new(0));
        let in_flight_since = Arc::new(Mutex::new(None));
        let writer_queued = Arc::clone(&queued);
        let writer_in_flight = Arc::clone(&in_flight_since);
        let writer = thread::Builder::new()
            .name("audit-log-writer".to_owned())
            .spawn(move || {
                while let Ok(queued_event) = rx.recv() {
                    writer_queued.fetch_sub(1, Ordering::AcqRel);
                    set_in_flight(&writer_in_flight, Some(queued_event.enqueued_at));
                    sink.emit(&queued_event.event);
                    set_in_flight(&writer_in_flight, None);
                }
                // The terminal flush at shutdown, counted like every other
                // one: a gateway whose last flush failed lost the tail of
                // its audit record, and that is the run where knowing it
                // matters most.
                let flushed = sink.flush();
                record_flush_outcome(flushed.is_ok());
                flushed
            })
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("failed to spawn audit writer thread: {error}"),
                )
            })?;

        Ok(Self {
            inner: Arc::new(AuditLogInner {
                tx: Mutex::new(Some(tx)),
                writer: Mutex::new(Some(writer)),
                closed: AtomicBool::new(false),
                queued,
                dropped: Arc::new(AtomicU64::new(0)),
                in_flight_since,
            }),
        })
    }

    /// Events waiting in the writer's channel.
    pub fn queue_depth(&self) -> usize {
        self.inner.queued.load(Ordering::Acquire)
    }

    /// The channel's bound. Ordinary events are refused
    /// [`AUDIT_CONTROL_RESERVE`] short of it so lifecycle events always
    /// have room; the capacity reported is the channel's, which is what an
    /// operator comparing it with the depth wants.
    pub fn queue_capacity(&self) -> usize {
        AUDIT_CHANNEL_CAPACITY
    }

    /// How long the oldest event the writer has not finished delivering
    /// has been waiting, or zero when the writer is idle.
    pub fn oldest_queued_age(&self) -> Duration {
        self.inner
            .in_flight_since
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .map(|since| Instant::now().saturating_duration_since(since))
            .unwrap_or_default()
    }

    /// Events refused admission since boot.
    pub fn dropped_total(&self) -> u64 {
        self.inner.dropped.load(Ordering::Acquire)
    }

    /// Publish the writer queue's shape as gauges (issue #241, PR 14).
    ///
    /// Called when `/metrics` is scraped rather than from the writer
    /// thread: the writer is a blocking consumer, so publishing from it
    /// would sample only the instants it happens to be awake -- exactly
    /// the instants a backlog is being drained rather than accumulating.
    pub(crate) fn publish_queue_gauges(&self) {
        record_queue_gauges(
            self.queue_depth(),
            self.queue_capacity(),
            self.oldest_queued_age(),
        );
    }

    /// Count one refused event, in the metric and in the in-process
    /// counter, so the two can never disagree about a drop.
    fn note_dropped(&self, reason: &'static str) {
        self.inner.dropped.fetch_add(1, Ordering::AcqRel);
        ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => reason).increment(1);
    }

    pub fn from_config(
        config: &Config,
    ) -> Result<(Self, AuditEventSender), Box<dyn std::error::Error>> {
        let (sink, broadcast_sender) = sink::build_sink_from_config(config)?;
        Ok((Self::try_new(sink)?, broadcast_sender))
    }

    /// Queue an audit event for best-effort background emission.
    ///
    /// This method never blocks the caller. Under extreme load, if the bounded
    /// audit channel is full or the writer thread is unavailable, the event is
    /// dropped and `audit_events_dropped_total` is incremented. Dropping audit
    /// events is preferable to stalling request handling on blocking stdout or
    /// file I/O.
    pub fn emit(&self, event: AuditEvent) {
        if self.inner.closed.load(Ordering::Acquire) {
            self.note_dropped("closed");
            return;
        }
        let tx = self.inner.tx_guard();
        let Some(tx) = tx.as_ref() else {
            self.note_dropped("closed");
            return;
        };
        if self.inner.queued.load(Ordering::Acquire) >= AUDIT_NORMAL_CAPACITY {
            self.note_dropped("full");
            return;
        }
        self.inner.queued.fetch_add(1, Ordering::AcqRel);
        match tx.try_send(QueuedEvent {
            enqueued_at: Instant::now(),
            event,
        }) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.inner.queued.fetch_sub(1, Ordering::AcqRel);
                self.note_dropped("full");
            }
            Err(TrySendError::Disconnected(_)) => {
                self.inner.queued.fetch_sub(1, Ordering::AcqRel);
                self.note_dropped("disconnected");
            }
        }
    }

    /// Queue a lifecycle/control event using capacity reserved from ordinary
    /// request traffic. Success acknowledges ordered admission to the same
    /// writer queue used by normal events; `close_and_drain` provides the
    /// durable completion acknowledgement.
    pub fn emit_control(&self, event: AuditEvent) -> Result<(), AuditControlError> {
        if self.inner.closed.load(Ordering::Acquire) {
            self.note_dropped("closed");
            return Err(AuditControlError::Closed);
        }
        let tx = self.inner.tx_guard();
        let Some(tx) = tx.as_ref() else {
            self.note_dropped("closed");
            return Err(AuditControlError::Closed);
        };
        self.inner.queued.fetch_add(1, Ordering::AcqRel);
        match tx.try_send(QueuedEvent {
            enqueued_at: Instant::now(),
            event,
        }) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.inner.queued.fetch_sub(1, Ordering::AcqRel);
                self.note_dropped("control_full");
                Err(AuditControlError::Full)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.inner.queued.fetch_sub(1, Ordering::AcqRel);
                self.note_dropped("disconnected");
                Err(AuditControlError::Disconnected)
            }
        }
    }

    /// Close audit admission and wait for the writer to deliver every queued
    /// event in order. The timeout bounds slow or stuck sinks during process
    /// shutdown.
    pub async fn close_and_drain(&self, timeout: Duration) -> Result<(), AuditDrainError> {
        self.inner.closed.store(true, Ordering::Release);
        drop(self.inner.tx_guard().take());
        let writer = self.inner.writer_guard().take();
        let Some(writer) = writer else {
            return Ok(());
        };

        tokio::task::spawn_blocking(move || {
            let deadline = Instant::now() + timeout;
            while !writer.is_finished() {
                if Instant::now() >= deadline {
                    return Err(AuditDrainError::Timeout);
                }
                thread::sleep(Duration::from_millis(5));
            }
            match writer.join() {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(AuditDrainError::Sink(error)),
                Err(_) => Err(AuditDrainError::WriterPanicked),
            }
        })
        .await
        .map_err(|_| AuditDrainError::WriterPanicked)?
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{mpsc, Arc, Mutex},
        time::{Duration, Instant},
    };

    use serde_json::json;

    use super::*;
    use crate::audit::sink::tests::CaptureSink;

    #[test]
    fn audit_log_emits_to_sink_asynchronously() {
        let capture = CaptureSink::new();
        let audit_log = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);

        audit_log.emit(test_event("audit.async"));

        assert_eventually(Duration::from_secs(1), || capture.len() == 1);
        assert_eq!(capture.events()[0].event_type, "audit.async");
    }

    #[test]
    fn emit_does_not_block_or_panic_when_channel_is_full() {
        let (release_tx, release_rx) = mpsc::channel();
        let audit_log = AuditLog::new(Arc::new(BlockingSink {
            release_rx: Mutex::new(release_rx),
        }) as Arc<dyn AuditSink>);
        let event = test_event("audit.burst");

        audit_log.emit(event.clone());
        std::thread::sleep(Duration::from_millis(20));

        let started = Instant::now();
        for _ in 0..(AUDIT_CHANNEL_CAPACITY * 2) {
            audit_log.emit(event.clone());
        }

        assert!(
            started.elapsed() < Duration::from_secs(1),
            "non-blocking audit emits took {:?}",
            started.elapsed()
        );

        drop(audit_log);
        let _ = release_tx.send(());
        drop(release_tx);
    }

    /// The queue facts the cluster status API reports (issue #241,
    /// PR 14): a stalled sink shows a non-empty queue, an in-flight event
    /// whose age grows, and every refused event counted.
    #[test]
    fn queue_facts_report_depth_capacity_age_and_drops() {
        let (release_tx, release_rx) = mpsc::channel();
        let audit_log = AuditLog::new(Arc::new(BlockingSink {
            release_rx: Mutex::new(release_rx),
        }) as Arc<dyn AuditSink>);
        let event = test_event("audit.queue_facts");

        assert!(audit_log.queue_capacity() >= AUDIT_NORMAL_CAPACITY);
        assert_eq!(audit_log.dropped_total(), 0);

        // The first event is taken by the writer, which then blocks in the
        // sink: from here it is the oldest event in the system and its age
        // is the queue's lag.
        audit_log.emit(event.clone());
        assert_eventually(Duration::from_secs(1), || {
            audit_log.oldest_queued_age() > Duration::ZERO
        });

        // Fill past the ordinary capacity: the reserve keeps the channel
        // from ever being fully consumed by request traffic, so the drops
        // are counted rather than blocking anybody.
        for _ in 0..(AUDIT_CHANNEL_CAPACITY * 2) {
            audit_log.emit(event.clone());
        }
        assert!(
            audit_log.queue_depth() >= AUDIT_NORMAL_CAPACITY - 1,
            "a stalled writer leaves the queue full, not empty: {}",
            audit_log.queue_depth()
        );
        assert!(
            audit_log.dropped_total() > 0,
            "events refused by a full queue must be counted"
        );

        drop(audit_log);
        let _ = release_tx.send(());
        drop(release_tx);
    }

    #[tokio::test]
    async fn close_and_drain_delivers_queued_events_in_order_and_closes_admission() {
        let capture = CaptureSink::new();
        let audit_log = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);

        audit_log.emit(test_event("audit.first"));
        audit_log.emit(test_event("audit.second"));
        audit_log.emit(test_event("audit.third"));
        audit_log
            .close_and_drain(Duration::from_secs(1))
            .await
            .expect("queued audit events should drain");
        audit_log.emit(test_event("audit.after_close"));

        assert_eq!(
            capture
                .events()
                .iter()
                .map(|event| event.event_type.as_str())
                .collect::<Vec<_>>(),
            vec!["audit.first", "audit.second", "audit.third"]
        );
        audit_log
            .close_and_drain(Duration::from_millis(10))
            .await
            .expect("closing an already-drained log should be idempotent");
    }

    #[tokio::test]
    async fn close_and_drain_times_out_when_sink_is_stuck() {
        let (release_tx, release_rx) = mpsc::channel();
        let audit_log = AuditLog::new(Arc::new(BlockingSink {
            release_rx: Mutex::new(release_rx),
        }) as Arc<dyn AuditSink>);
        audit_log.emit(test_event("audit.blocked"));
        std::thread::sleep(Duration::from_millis(20));

        let started = Instant::now();
        let result = audit_log.close_and_drain(Duration::from_millis(25)).await;

        assert_eq!(result, Err(AuditDrainError::Timeout));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "audit drain timeout must remain bounded"
        );
        release_tx
            .send(())
            .expect("blocked writer should still be waiting for release");
    }

    #[tokio::test]
    async fn reserved_control_event_is_admitted_when_normal_queue_is_saturated() {
        let (release_tx, release_rx) = mpsc::channel();
        let sink = Arc::new(BlockFirstCaptureSink {
            release_rx: Mutex::new(Some(release_rx)),
            event_types: Mutex::new(Vec::new()),
        });
        let audit_log = AuditLog::new(Arc::clone(&sink) as Arc<dyn AuditSink>);
        audit_log.emit(test_event("audit.block-writer"));
        std::thread::sleep(Duration::from_millis(20));

        for _ in 0..(AUDIT_NORMAL_CAPACITY * 2) {
            audit_log.emit(test_event("audit.normal"));
        }
        audit_log
            .emit_control(test_event("gateway.shutdown_completed"))
            .expect("control capacity must remain reserved from normal traffic");

        release_tx
            .send(())
            .expect("blocked writer should still be waiting for release");
        audit_log
            .close_and_drain(Duration::from_secs(5))
            .await
            .expect("saturated audit queue should drain after the sink is released");
        assert!(
            sink.event_types
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .any(|event_type| event_type == "gateway.shutdown_completed"),
            "admitted control event must reach the sink"
        );
    }

    #[tokio::test]
    async fn close_and_drain_propagates_sink_flush_failure() {
        let audit_log = AuditLog::new(Arc::new(FailingFlushSink) as Arc<dyn AuditSink>);
        audit_log.emit(test_event("audit.before-failed-flush"));

        let result = audit_log.close_and_drain(Duration::from_secs(1)).await;

        assert_eq!(
            result,
            Err(AuditDrainError::Sink(
                "injected durable flush failure".to_owned()
            ))
        );
    }

    struct BlockingSink {
        release_rx: Mutex<mpsc::Receiver<()>>,
    }

    struct BlockFirstCaptureSink {
        release_rx: Mutex<Option<mpsc::Receiver<()>>>,
        event_types: Mutex<Vec<String>>,
    }

    impl AuditSink for BlockFirstCaptureSink {
        fn emit(&self, event: &AuditEvent) {
            let receiver = self
                .release_rx
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            if let Some(receiver) = receiver {
                let _ = receiver.recv();
            }
            self.event_types
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(event.event_type.clone());
        }
    }

    struct FailingFlushSink;

    impl AuditSink for FailingFlushSink {
        fn emit(&self, _event: &AuditEvent) {}

        fn flush(&self) -> Result<(), String> {
            Err("injected durable flush failure".to_owned())
        }
    }

    impl AuditSink for BlockingSink {
        fn emit(&self, _event: &AuditEvent) {
            let guard = match self.release_rx.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let _ = guard.recv();
        }
    }

    fn assert_eventually(timeout: Duration, condition: impl Fn() -> bool) {
        let started = Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }

    fn test_event(event_type: &str) -> AuditEvent {
        AuditEvent::new(
            event_type,
            "request-123",
            "203.0.113.10",
            None,
            json!({ "test": true }),
        )
    }
}
