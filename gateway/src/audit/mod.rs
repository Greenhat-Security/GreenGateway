//! Audit event primitives and asynchronous emission.

use std::{
    sync::{
        mpsc::{self, SyncSender, TrySendError},
        Arc,
    },
    thread,
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
    tx: SyncSender<AuditEvent>,
}

impl AuditLog {
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        let (tx, rx) = mpsc::sync_channel::<AuditEvent>(AUDIT_CHANNEL_CAPACITY);

        // TODO: Add graceful shutdown so queued audit events drain before process exit.
        if let Err(err) = thread::Builder::new()
            .name("audit-log-writer".to_owned())
            .spawn(move || {
                while let Ok(event) = rx.recv() {
                    sink.emit(&event);
                }
            })
        {
            tracing::error!(
                error = %err,
                "failed to spawn audit writer thread; audit events will be dropped"
            );
        }

        Self { tx }
    }

    pub fn from_config(
        config: &Config,
    ) -> Result<(Self, AuditEventSender), Box<dyn std::error::Error>> {
        let (sink, broadcast_sender) = sink::build_sink_from_config(config)?;
        Ok((Self::new(sink), broadcast_sender))
    }

    /// Queue an audit event for best-effort background emission.
    ///
    /// This method never blocks the caller. Under extreme load, if the bounded
    /// audit channel is full or the writer thread is unavailable, the event is
    /// dropped and `audit_events_dropped_total` is incremented. Dropping audit
    /// events is preferable to stalling request handling on blocking stdout or
    /// file I/O.
    pub fn emit(&self, event: AuditEvent) {
        match self.tx.try_send(event) {
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
