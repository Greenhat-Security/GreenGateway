use std::{
    error::Error,
    fmt,
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

    /// Finish any sink-owned background work and durably flush accepted events.
    ///
    /// The audit writer calls this exactly after its admission channel closes
    /// and all queued events have been emitted. Implementations must be
    /// idempotent and return a bounded, display-safe error on failure.
    fn flush(&self) -> Result<(), String> {
        Ok(())
    }
}

pub type ConfiguredAuditSink = (Arc<dyn AuditSink>, AuditEventSender);

#[derive(Clone, Copy)]
struct DiscoverySinkOptions<'a> {
    sqlite_path: Option<&'a str>,
    endpoint_limit: usize,
    payload_capture_enabled: bool,
}

/// Byte destination for [`StdoutSink`].
///
/// Production always writes to process stdout. Tests substitute a failing
/// target so the sink's drop accounting and sticky-failure reporting can be
/// exercised without breaking the harness's own stdout.
trait StdoutWriteTarget: Send + Sync {
    fn write_line(&self, line: &str) -> io::Result<()>;
}

#[derive(Debug, Default)]
struct ProcessStdout;

impl StdoutWriteTarget for ProcessStdout {
    fn write_line(&self, line: &str) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        writeln!(handle, "{line}")?;
        handle.flush()
    }
}

/// Always-present audit sink writing one JSON event per line to stdout.
///
/// Stdout is the only sink every deployment has, so a failed write is audit
/// loss even when no other sink is configured. Failures are therefore counted
/// on `audit_events_dropped_total{reason="sink_error"}` and recorded stickily,
/// so `flush` reports them during the shutdown drain the same way [`FileSink`]
/// does. The `tracing::error!` companion is best effort only: the default
/// tracing writer is the same stdout descriptor that just failed.
pub struct StdoutSink {
    target: Arc<dyn StdoutWriteTarget>,
    failure: Mutex<Option<String>>,
}

impl StdoutSink {
    pub fn new() -> Self {
        Self::with_target(Arc::new(ProcessStdout))
    }

    fn with_target(target: Arc<dyn StdoutWriteTarget>) -> Self {
        Self {
            target,
            failure: Mutex::new(None),
        }
    }

    fn failure_guard(&self) -> MutexGuard<'_, Option<String>> {
        match self.failure.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "audit",
                    "lock" => "stdout_sink"
                )
                .increment(1);
                tracing::error!("audit stdout sink lock poisoned; recovering");
                poisoned.into_inner()
            }
        }
    }

    fn record_failure(&self, error: impl fmt::Display) {
        let mut failure = self.failure_guard();
        if failure.is_none() {
            *failure = Some(format!("audit stdout sink failed: {error}"));
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StdoutSink {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StdoutSink")
            .field("failure", &*self.failure_guard())
            .finish()
    }
}

impl AuditSink for StdoutSink {
    fn emit(&self, event: &AuditEvent) {
        let line = match serde_json::to_string(event) {
            Ok(line) => line,
            Err(err) => {
                self.record_failure(&err);
                tracing::error!(error = %err, "failed to serialize audit event for stdout");
                return;
            }
        };

        if let Err(err) = self.target.write_line(&line) {
            self.record_failure(&err);
            ::metrics::counter!(
                AUDIT_EVENTS_DROPPED_TOTAL,
                "reason" => "sink_error"
            )
            .increment(1);
            tracing::error!(error = %err, "failed to write audit event to stdout");
        }
    }

    fn flush(&self) -> Result<(), String> {
        self.failure_guard().clone().map_or(Ok(()), Err)
    }
}

#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    file: Mutex<Option<File>>,
    failure: Mutex<Option<String>>,
}

impl FileSink {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            file: Mutex::new(None),
            failure: Mutex::new(None),
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

    fn record_failure(&self, error: impl fmt::Display) {
        let mut failure = self
            .failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if failure.is_none() {
            *failure = Some(format!("audit file sink failed: {error}"));
        }
    }
}

impl AuditSink for FileSink {
    fn emit(&self, event: &AuditEvent) {
        let line = match serde_json::to_string(event) {
            Ok(line) => line,
            Err(err) => {
                self.record_failure(&err);
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
                self.record_failure(&err);
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

    fn flush(&self) -> Result<(), String> {
        let flush_result = {
            let mut file = self.file_guard();
            match file.as_mut() {
                Some(file) => file.flush().map_err(|error| error.to_string()),
                None => Ok(()),
            }
        };
        if let Err(error) = flush_result {
            self.record_failure(&error);
        }
        self.failure
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .map_or(Ok(()), Err)
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

    fn flush(&self) -> Result<(), String> {
        let mut first_error = None;
        for sink in &self.sinks {
            if let Err(error) = sink.flush() {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

fn build_sink(
    audit_log_file: Option<&str>,
    audit_sqlite_path: Option<&str>,
    audit_sqlite_retention_days: Option<u32>,
    discovery: DiscoverySinkOptions<'_>,
    signal_event_sender: Option<AuditEventSender>,
    signal_detector_config: SignalDetectorConfig,
) -> Result<Arc<dyn AuditSink>, Box<dyn Error>> {
    let sinks = build_sink_members(
        audit_log_file,
        audit_sqlite_path,
        audit_sqlite_retention_days,
        discovery,
        signal_event_sender,
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
    discovery: DiscoverySinkOptions<'_>,
    signal_event_sender: Option<AuditEventSender>,
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

    if let Some(path) = discovery
        .sqlite_path
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        sinks.push(
            Arc::new(EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
                path: PathBuf::from(path),
                payload_capture_enabled: discovery.payload_capture_enabled,
                endpoint_limit: discovery.endpoint_limit,
                signal_event_sender,
                signal_detector_config,
            })?) as Arc<dyn AuditSink>,
        );
    } else if discovery.payload_capture_enabled {
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
        DiscoverySinkOptions {
            sqlite_path: config.discovery_sqlite_path.as_deref(),
            endpoint_limit: config.discovery_endpoint_limit,
            payload_capture_enabled: config.payload_capture_enabled,
        },
        Some(broadcast_sender.clone()),
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
    fn stdout_sink_flush_is_clean_while_writes_succeed() {
        let target = Arc::new(RecordingTarget::default());
        let sink = StdoutSink::with_target(Arc::clone(&target) as Arc<dyn StdoutWriteTarget>);

        sink.emit(&test_event("audit.stdout.ok"));

        assert_eq!(target.lines().len(), 1);
        assert_eq!(sink.flush(), Ok(()));
        assert_eq!(sink.flush(), Ok(()));
    }

    #[test]
    fn stdout_sink_counts_dropped_event_and_fails_flush_after_write_error() {
        let target = Arc::new(RecordingTarget::default());
        target.fail_with(io::ErrorKind::BrokenPipe, "stdout reader went away");
        let sink = StdoutSink::with_target(Arc::clone(&target) as Arc<dyn StdoutWriteTarget>);
        let recorder = CountingRecorder::default();

        ::metrics::with_local_recorder(&recorder, || {
            sink.emit(&test_event("audit.stdout.broken"));
        });

        assert_eq!(
            recorder.count("audit_events_dropped_total", &[("reason", "sink_error")]),
            1,
            "a dropped stdout audit event must be counted like a dropped file-sink event"
        );

        let error = sink
            .flush()
            .expect_err("a stdout write failure must make the audit drain report unclean");
        assert!(
            error.contains("audit stdout sink failed"),
            "flush error should name the sink: {error}"
        );
        assert!(
            error.contains("stdout reader went away"),
            "flush error should carry the underlying cause: {error}"
        );
        assert_eq!(
            sink.flush(),
            Err(error),
            "the failure must stay sticky across idempotent flushes"
        );
    }

    #[derive(Default)]
    struct RecordingTarget {
        lines: Mutex<Vec<String>>,
        failure: Mutex<Option<(io::ErrorKind, String)>>,
    }

    impl RecordingTarget {
        fn fail_with(&self, kind: io::ErrorKind, message: &str) {
            *self.failure.lock().expect("failure lock") = Some((kind, message.to_owned()));
        }

        fn lines(&self) -> Vec<String> {
            self.lines.lock().expect("lines lock").clone()
        }
    }

    impl StdoutWriteTarget for RecordingTarget {
        fn write_line(&self, line: &str) -> io::Result<()> {
            if let Some((kind, message)) = self.failure.lock().expect("failure lock").clone() {
                return Err(io::Error::new(kind, message));
            }

            self.lines.lock().expect("lines lock").push(line.to_owned());
            Ok(())
        }
    }

    /// Minimal in-process `metrics` recorder so counter emissions can be
    /// asserted without adding a test-only dependency.
    #[derive(Clone, Default)]
    struct CountingRecorder {
        counts: Arc<Mutex<Vec<(String, u64)>>>,
    }

    impl CountingRecorder {
        fn count(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
            let key = render_counter_key(name, labels);
            self.counts
                .lock()
                .expect("counts lock")
                .iter()
                .filter(|(recorded, _)| recorded == &key)
                .map(|(_, value)| value)
                .sum()
        }
    }

    struct RecordedCounter {
        key: String,
        counts: Arc<Mutex<Vec<(String, u64)>>>,
    }

    impl ::metrics::CounterFn for RecordedCounter {
        fn increment(&self, value: u64) {
            self.counts
                .lock()
                .expect("counts lock")
                .push((self.key.clone(), value));
        }

        fn absolute(&self, value: u64) {
            self.increment(value);
        }
    }

    impl ::metrics::Recorder for CountingRecorder {
        fn describe_counter(
            &self,
            _key: ::metrics::KeyName,
            _unit: Option<::metrics::Unit>,
            _description: ::metrics::SharedString,
        ) {
        }

        fn describe_gauge(
            &self,
            _key: ::metrics::KeyName,
            _unit: Option<::metrics::Unit>,
            _description: ::metrics::SharedString,
        ) {
        }

        fn describe_histogram(
            &self,
            _key: ::metrics::KeyName,
            _unit: Option<::metrics::Unit>,
            _description: ::metrics::SharedString,
        ) {
        }

        fn register_counter(
            &self,
            key: &::metrics::Key,
            _metadata: &::metrics::Metadata<'_>,
        ) -> ::metrics::Counter {
            let labels = key
                .labels()
                .map(|label| (label.key().to_owned(), label.value().to_owned()))
                .collect::<Vec<_>>();
            let borrowed = labels
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            ::metrics::Counter::from_arc(Arc::new(RecordedCounter {
                key: render_counter_key(key.name(), &borrowed),
                counts: Arc::clone(&self.counts),
            }))
        }

        fn register_gauge(
            &self,
            _key: &::metrics::Key,
            _metadata: &::metrics::Metadata<'_>,
        ) -> ::metrics::Gauge {
            ::metrics::Gauge::noop()
        }

        fn register_histogram(
            &self,
            _key: &::metrics::Key,
            _metadata: &::metrics::Metadata<'_>,
        ) -> ::metrics::Histogram {
            ::metrics::Histogram::noop()
        }
    }

    fn render_counter_key(name: &str, labels: &[(&str, &str)]) -> String {
        let mut rendered = name.to_owned();
        for (label, value) in labels {
            rendered.push_str(&format!("|{label}={value}"));
        }
        rendered
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
            DiscoverySinkOptions {
                sqlite_path: None,
                endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
                payload_capture_enabled: false,
            },
            None,
            SignalDetectorConfig::default(),
        )
        .expect("sink members should build");
        assert_eq!(without_path.len(), 1);

        let blank_path = build_sink_members(
            None,
            None,
            None,
            DiscoverySinkOptions {
                sqlite_path: Some("   "),
                endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
                payload_capture_enabled: false,
            },
            None,
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
            DiscoverySinkOptions {
                sqlite_path: Some(path.to_str().expect("test path should be valid UTF-8")),
                endpoint_limit: crate::config::DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
                payload_capture_enabled: false,
            },
            None,
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
