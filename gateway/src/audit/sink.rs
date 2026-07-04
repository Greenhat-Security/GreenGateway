use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::{
    audit::{
        sqlite_sink::{SqliteSink, SqliteSinkConfig},
        AuditEvent, AuditEventSender, AUDIT_EVENTS_DROPPED_TOTAL,
    },
    config::Config,
    discovery::aggregator::{EndpointAggregatorSink, EndpointAggregatorSinkConfig},
    discovery::signals::SignalDetectorConfig,
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
};

pub const AUDIT_BROADCAST_CAPACITY: usize = 512;

pub trait AuditSink: Send + Sync {
    fn emit(&self, event: &AuditEvent);
}

pub type ConfiguredAuditSink = (Arc<dyn AuditSink>, AuditEventSender);

#[derive(Debug, Default)]
pub struct StdoutSink;

impl StdoutSink {
    pub fn new() -> Self {
        Self
    }
}

impl AuditSink for StdoutSink {
    fn emit(&self, event: &AuditEvent) {
        let line = match serde_json::to_string(event) {
            Ok(line) => line,
            Err(err) => {
                tracing::error!(error = %err, "failed to serialize audit event for stdout");
                return;
            }
        };

        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        if let Err(err) = writeln!(handle, "{line}") {
            tracing::error!(error = %err, "failed to write audit event to stdout");
            return;
        }

        if let Err(err) = handle.flush() {
            tracing::error!(error = %err, "failed to flush audit event to stdout");
        }
    }
}

#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    file: Mutex<Option<File>>,
}

impl FileSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            file: Mutex::new(None),
        }
    }

    fn file_guard(&self) -> MutexGuard<'_, Option<File>> {
        match self.file.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "audit",
                    "lock" => "file_sink"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "audit file sink lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }

    fn write_locked(&self, file: &mut Option<File>, line: &str) -> io::Result<()> {
        if file.is_none() {
            *file = Some(
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)?,
            );
        }

        let Some(file) = file.as_mut() else {
            return Err(io::Error::other("audit file handle was not opened"));
        };

        writeln!(file, "{line}")?;
        file.flush()
    }
}

impl AuditSink for FileSink {
    fn emit(&self, event: &AuditEvent) {
        let line = match serde_json::to_string(event) {
            Ok(line) => line,
            Err(err) => {
                tracing::error!(error = %err, "failed to serialize audit event for file sink");
                return;
            }
        };

        let mut file = self.file_guard();
        if let Err(err) = self.write_locked(&mut file, &line) {
            tracing::error!(
                path = %self.path.display(),
                error = %err,
                "failed to write audit event to file; reopening once"
            );
            *file = None;

            if let Err(err) = self.write_locked(&mut file, &line) {
                ::metrics::counter!(
                    AUDIT_EVENTS_DROPPED_TOTAL,
                    "reason" => "sink_error"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    error = %err,
                    "failed to write audit event to file after reopen"
                );
            }
        }
    }
}

#[derive(Clone)]
pub struct BroadcastSink {
    sender: AuditEventSender,
}

impl BroadcastSink {
    pub fn new(sender: AuditEventSender) -> Self {
        Self { sender }
    }
}

impl AuditSink for BroadcastSink {
    fn emit(&self, event: &AuditEvent) {
        if self.sender.send(event.clone()).is_err() {
            tracing::trace!("no active audit event stream subscribers");
        }
    }
}

#[derive(Clone)]
pub struct CompositeSink {
    sinks: Vec<Arc<dyn AuditSink>>,
}

impl CompositeSink {
    pub fn new(sinks: Vec<Arc<dyn AuditSink>>) -> Self {
        Self { sinks }
    }
}

impl AuditSink for CompositeSink {
    fn emit(&self, event: &AuditEvent) {
        for sink in &self.sinks {
            sink.emit(event);
        }
    }
}

pub fn build_sink(
    audit_log_file: Option<&str>,
    audit_sqlite_path: Option<&str>,
    audit_sqlite_retention_days: Option<u32>,
    discovery_sqlite_path: Option<&str>,
    payload_capture_enabled: bool,
    signal_detector_config: SignalDetectorConfig,
) -> Result<Arc<dyn AuditSink>, Box<dyn Error>> {
    let sinks = build_sink_members(
        audit_log_file,
        audit_sqlite_path,
        audit_sqlite_retention_days,
        discovery_sqlite_path,
        payload_capture_enabled,
        signal_detector_config,
    )?;

    let sink = if sinks.len() == 1 {
        Arc::clone(&sinks[0])
    } else {
        Arc::new(CompositeSink::new(sinks))
    };

    Ok(sink)
}

fn build_sink_members(
    audit_log_file: Option<&str>,
    audit_sqlite_path: Option<&str>,
    audit_sqlite_retention_days: Option<u32>,
    discovery_sqlite_path: Option<&str>,
    payload_capture_enabled: bool,
    signal_detector_config: SignalDetectorConfig,
) -> Result<Vec<Arc<dyn AuditSink>>, Box<dyn Error>> {
    let stdout: Arc<dyn AuditSink> = Arc::new(StdoutSink::new());
    let mut sinks = vec![stdout];

    if let Some(path) = audit_log_file
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        sinks.push(Arc::new(FileSink::new(path)) as Arc<dyn AuditSink>);
    }

    if let Some(path) = audit_sqlite_path
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        sinks.push(Arc::new(SqliteSink::new(SqliteSinkConfig {
            path: PathBuf::from(path),
            retention_days: audit_sqlite_retention_days,
        })?) as Arc<dyn AuditSink>);
    } else if audit_sqlite_retention_days.is_some() {
        tracing::warn!(
            "AUDIT_SQLITE_RETENTION_DAYS is set but AUDIT_SQLITE_PATH is unset; SQLite retention is disabled"
        );
    }

    if let Some(path) = discovery_sqlite_path
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        sinks.push(
            Arc::new(EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
                path: PathBuf::from(path),
                payload_capture_enabled,
                signal_detector_config,
            })?) as Arc<dyn AuditSink>,
        );
    } else if payload_capture_enabled {
        return Err("PAYLOAD_CAPTURE_ENABLED=true requires DISCOVERY_SQLITE_PATH to be set".into());
    }

    Ok(sinks)
}

pub fn build_sink_from_config(config: &Config) -> Result<ConfiguredAuditSink, Box<dyn Error>> {
    let (broadcast_sender, _) = tokio::sync::broadcast::channel(AUDIT_BROADCAST_CAPACITY);
    let base_sink = build_sink(
        config.audit_log_file.as_deref(),
        config.audit_sqlite_path.as_deref(),
        config.audit_sqlite_retention_days,
        config.discovery_sqlite_path.as_deref(),
        config.payload_capture_enabled,
        config.signal_detector_config(),
    )?;
    let sink = Arc::new(CompositeSink::new(vec![
        base_sink,
        Arc::new(BroadcastSink::new(broadcast_sender.clone())) as Arc<dyn AuditSink>,
    ])) as Arc<dyn AuditSink>;

    Ok((sink, broadcast_sender))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::{
        fs,
        path::PathBuf,
        sync::MutexGuard,
        time::{Duration, Instant},
    };

    #[derive(Clone, Default)]
    pub struct CaptureSink {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl CaptureSink {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn events(&self) -> Vec<AuditEvent> {
            self.events_guard().clone()
        }

        pub fn len(&self) -> usize {
            self.events_guard().len()
        }

        fn events_guard(&self) -> MutexGuard<'_, Vec<AuditEvent>> {
            match self.events.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            }
        }
    }

    impl AuditSink for CaptureSink {
        fn emit(&self, event: &AuditEvent) {
            self.events_guard().push(event.clone());
        }
    }

    #[test]
    fn capture_records_events() {
        let sink = CaptureSink::new();
        let event = test_event("audit.capture");

        sink.emit(&event);

        let events = sink.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "audit.capture");
    }

    #[test]
    fn stdout_sink_emit_does_not_panic() {
        let sink = StdoutSink::new();

        sink.emit(&test_event("audit.stdout"));
    }

    #[test]
    fn composite_fans_out_to_multiple_sinks() {
        let first = CaptureSink::new();
        let second = CaptureSink::new();
        let sink = CompositeSink::new(vec![
            Arc::new(first.clone()) as Arc<dyn AuditSink>,
            Arc::new(second.clone()) as Arc<dyn AuditSink>,
        ]);

        sink.emit(&test_event("audit.composite"));

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first.events()[0].event_type, "audit.composite");
        assert_eq!(second.events()[0].event_type, "audit.composite");
    }

    #[tokio::test]
    async fn broadcast_sink_emits_to_subscribed_receiver() {
        let (sender, _) = tokio::sync::broadcast::channel(4);
        let sink = BroadcastSink::new(sender.clone());
        let mut receiver = sender.subscribe();
        let event = test_event("audit.broadcast");

        sink.emit(&event);

        let received = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("broadcast receive should not time out")
            .expect("broadcast receive should succeed");
        assert_eq!(received.event_id, event.event_id);
        assert_eq!(received.event_type, "audit.broadcast");
    }

    #[test]
    fn broadcast_sink_emit_with_zero_receivers_does_not_panic() {
        let (sender, receiver) = tokio::sync::broadcast::channel(4);
        drop(receiver);
        let sink = BroadcastSink::new(sender);

        sink.emit(&test_event("audit.broadcast.no_receivers"));
    }

    #[tokio::test]
    async fn broadcast_sink_lagging_receiver_misses_events_without_blocking_sender() {
        let (sender, _) = tokio::sync::broadcast::channel(4);
        let sink = BroadcastSink::new(sender.clone());
        let mut receiver = sender.subscribe();
        let event = test_event("audit.broadcast.lagged");

        let started = Instant::now();
        for _ in 0..128 {
            sink.emit(&event);
        }

        assert!(
            started.elapsed() < Duration::from_millis(100),
            "broadcast sink emit burst took {:?}",
            started.elapsed()
        );

        let result = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("lagged receiver should complete promptly");
        match result {
            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                assert!(skipped > 0, "lagged count should be positive");
            }
            other => panic!("expected lagged receiver error, got {other:?}"),
        }
    }

    #[test]
    fn file_sink_writes_json_lines() {
        let path = std::env::temp_dir().join(format!(
            "greengateway-audit-sink-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        let sink = FileSink::new(&path);

        sink.emit(&test_event("audit.file"));

        let contents = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        let mut lines = contents.lines();
        let line = lines.next().expect("file should contain one audit line");
        assert!(lines.next().is_none());

        let value: Value = serde_json::from_str(line).expect("audit line should be JSON");
        assert_eq!(value["event_type"], "audit.file");

        fs::remove_file(&path)
            .unwrap_or_else(|err| panic!("failed to remove {}: {err}", path.display()));
    }

    #[test]
    fn discovery_aggregator_member_is_only_added_when_path_is_configured() {
        let without_path = build_sink_members(
            None,
            None,
            None,
            None,
            false,
            SignalDetectorConfig::default(),
        )
        .expect("sink members should build");
        assert_eq!(without_path.len(), 1);

        let blank_path = build_sink_members(
            None,
            None,
            None,
            Some("   "),
            false,
            SignalDetectorConfig::default(),
        )
        .expect("sink members should build");
        assert_eq!(blank_path.len(), 1);

        let path = std::env::temp_dir().join(format!(
            "greengateway-discovery-sink-config-{}.sqlite",
            uuid::Uuid::new_v4()
        ));
        let with_path = build_sink_members(
            None,
            None,
            None,
            Some(path.to_str().expect("test path should be valid UTF-8")),
            false,
            SignalDetectorConfig::default(),
        )
        .expect("sink members should build");
        assert_eq!(with_path.len(), 2);
        drop(with_path);

        for suffix in ["", "-wal", "-shm"] {
            let path = PathBuf::from(format!("{}{}", path.display(), suffix));
            let _ = fs::remove_file(path);
        }
    }

    pub fn test_event(event_type: &str) -> AuditEvent {
        AuditEvent::new(
            event_type,
            "request-123",
            "203.0.113.10",
            None,
            json!({ "test": true }),
        )
    }
}
