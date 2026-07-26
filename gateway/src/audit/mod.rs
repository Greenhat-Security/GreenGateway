//! Audit event primitives and asynchronous emission.

use std::{
    fmt, io,
    sync::{
        atomic::{AtomicBool, Ordering},
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

#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<AuditLogInner>,
}

struct AuditLogInner {
    tx: Mutex<Option<SyncSender<AuditEvent>>>,
    writer: Mutex<Option<thread::JoinHandle<()>>>,
    closed: AtomicBool,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuditDrainError {
    Timeout,
    WriterPanicked,
}

impl fmt::Display for AuditDrainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(formatter, "audit drain exceeded its configured timeout"),
            Self::WriterPanicked => write!(formatter, "audit writer thread panicked"),
        }
    }
}

impl std::error::Error for AuditDrainError {}

impl AuditLogInner {
    fn tx_guard(&self) -> MutexGuard<'_, Option<SyncSender<AuditEvent>>> {
        self.tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn writer_guard(&self) -> MutexGuard<'_, Option<thread::JoinHandle<()>>> {
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
        let writer = thread::Builder::new()
            .name("audit-log-writer".to_owned())
            .spawn(move || {
                while let Ok(event) = rx.recv() {
                    sink.emit(&event);
                }
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
        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "full").increment(1);
            }
            Err(TrySendError::Disconnected(_)) => {
                ::metrics::counter!(AUDIT_EVENTS_DROPPED_TOTAL, "reason" => "disconnected")
                    .increment(1);
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
            writer.join().map_err(|_| AuditDrainError::WriterPanicked)
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

    struct BlockingSink {
        release_rx: Mutex<mpsc::Receiver<()>>,
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
