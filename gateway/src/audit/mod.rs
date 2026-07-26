//! Audit event primitives and asynchronous emission.

use std::{
    fmt, io,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
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

#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<AuditLogInner>,
}

struct AuditLogInner {
    tx: Mutex<Option<SyncSender<AuditEvent>>>,
    writer: Mutex<Option<thread::JoinHandle<Result<(), String>>>>,
    closed: AtomicBool,
    queued: Arc<AtomicUsize>,
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
    fn tx_guard(&self) -> MutexGuard<'_, Option<SyncSender<AuditEvent>>> {
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
        let (tx, rx) = mpsc::sync_channel::<AuditEvent>(AUDIT_CHANNEL_CAPACITY);
        let queued = Arc::new(AtomicUsize::new(0));
        let writer_queued = Arc::clone(&queued);
        let writer = thread::Builder::new()
            .name("audit-log-writer".to_owned())
            .spawn(move || {
                while let Ok(event) = rx.recv() {
                    writer_queued.fetch_sub(1, Ordering::AcqRel);
                    sink.emit(&event);
                }
                sink.flush()
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
            }),
        })
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
            ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "closed").increment(1);
            return;
        }
        let tx = self.inner.tx_guard();
        let Some(tx) = tx.as_ref() else {
            ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "closed").increment(1);
            return;
        };
        if self.inner.queued.load(Ordering::Acquire) >= AUDIT_NORMAL_CAPACITY {
            ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "full").increment(1);
            return;
        }
        self.inner.queued.fetch_add(1, Ordering::AcqRel);
        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.inner.queued.fetch_sub(1, Ordering::AcqRel);
                ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "full").increment(1);
            }
            Err(TrySendError::Disconnected(_)) => {
                self.inner.queued.fetch_sub(1, Ordering::AcqRel);
                ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "disconnected")
                    .increment(1);
            }
        }
    }

    /// Queue a lifecycle/control event using capacity reserved from ordinary
    /// request traffic. Success acknowledges ordered admission to the same
    /// writer queue used by normal events; `close_and_drain` provides the
    /// durable completion acknowledgement.
    pub fn emit_control(&self, event: AuditEvent) -> Result<(), AuditControlError> {
        if self.inner.closed.load(Ordering::Acquire) {
            ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "closed").increment(1);
            return Err(AuditControlError::Closed);
        }
        let tx = self.inner.tx_guard();
        let Some(tx) = tx.as_ref() else {
            ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "closed").increment(1);
            return Err(AuditControlError::Closed);
        };
        self.inner.queued.fetch_add(1, Ordering::AcqRel);
        match tx.try_send(event) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.inner.queued.fetch_sub(1, Ordering::AcqRel);
                ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "control_full")
                    .increment(1);
                Err(AuditControlError::Full)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.inner.queued.fetch_sub(1, Ordering::AcqRel);
                ::metrics::counter!(
                    AUDIT_EVENTS_DROPPED_TOTAL,
                    "reason" => "disconnected"
                )
                .increment(1);
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
