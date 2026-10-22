use std::{
    error::Error,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::Instant,
};

use crate::{
    audit::{
        sqlite_sink::{SqliteSink, SqliteSinkConfig},
        AuditEvent, AuditEventSender, DurableAck, AUDIT_EVENTS_DROPPED_TOTAL,
    },
    config::{AuditDurability, Config, StateBackend},
    discovery::aggregator::{EndpointAggregatorSink, EndpointAggregatorSinkConfig},
    discovery::signals::SignalDetectorConfig,
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
};

pub const AUDIT_BROADCAST_CAPACITY: usize = 512;

#[derive(Clone, Copy, Debug, Default)]
pub struct SinkBacklog {
    pub depth: usize,
    pub capacity: usize,
    pub oldest_age: std::time::Duration,
    pub dropped: u64,
}

pub trait AuditSink: Send + Sync {
    /// Pending asynchronous delivery, beyond AuditLog's input channel.
    fn backlog(&self) -> SinkBacklog {
        SinkBacklog::default()
    }

    /// A fixed, label-safe name for the sink. Read by the tests that pin
    /// which sinks each mode constructs (standalone never the PostgreSQL
    /// one, cluster never the SQLite one); never derived from runtime data.
    #[cfg_attr(not(test), allow(dead_code))]
    fn name(&self) -> &'static str {
        "sink"
    }

    fn emit(&self, event: &AuditEvent);

    /// Whether this sink is an audit store of record: one that can report,
    /// per event, that the transaction carrying it committed. The SQLite and
    /// PostgreSQL sinks are; stdout, the file, the broadcast and the
    /// discovery aggregator are not, and neither is anything that only
    /// accepts into memory. Required durability (issue #425) needs one.
    fn is_durable(&self) -> bool {
        false
    }

    /// [`Self::emit`] for a record a request is waiting on: deliver `event`
    /// and report through `ack` once it is durably stored, or once it cannot
    /// be. Called on the audit writer thread, so it must not block on I/O
    /// beyond what [`Self::emit`] already does. A sink that is not a store of
    /// record emits and reports `not_stored`; it can never be the one a
    /// waiter relies on.
    fn emit_durable(&self, event: &AuditEvent, ack: DurableAck) {
        self.emit(event);
        ack.not_stored();
    }

    /// Finish any sink-owned background work and durably flush accepted events.
    ///
    /// The audit writer calls this exactly after its admission channel closes
    /// and all queued events have been emitted. Implementations must be
    /// idempotent and return a bounded, display-safe error on failure.
    fn flush(&self) -> Result<(), String> {
        Ok(())
    }

    /// [`Self::flush`] with the caller's own deadline: the instant after
    /// which nobody is waiting for the result. The audit writer passes the
    /// deadline of the `close_and_drain` that closed its channel, whose
    /// clock started before the writer emptied that channel, so a sink
    /// whose flush is itself bounded can give up when the drain does rather
    /// than on a clock of its own that started later -- and be torn down
    /// mid-batch by the runtime the drain's caller then drops. The default
    /// ignores it and flushes; only a sink that owns background work has
    /// anything to bound.
    fn flush_by(&self, deadline: Instant) -> Result<(), String> {
        let _ = deadline;
        self.flush()
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
    fn name(&self) -> &'static str {
        "stdout"
    }

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
    fn name(&self) -> &'static str {
        "file"
    }

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
    fn name(&self) -> &'static str {
        "broadcast"
    }

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

    /// The members' names, in fan-out order.
    #[cfg(test)]
    pub(crate) fn member_names(&self) -> Vec<&'static str> {
        self.sinks.iter().map(|sink| sink.name()).collect()
    }
}

impl AuditSink for CompositeSink {
    fn backlog(&self) -> SinkBacklog {
        self.sinks
            .iter()
            .fold(SinkBacklog::default(), |mut total, sink| {
                let next = sink.backlog();
                total.depth = total.depth.saturating_add(next.depth);
                total.capacity = total.capacity.saturating_add(next.capacity);
                total.oldest_age = total.oldest_age.max(next.oldest_age);
                total.dropped = total.dropped.saturating_add(next.dropped);
                total
            })
    }

    fn name(&self) -> &'static str {
        "composite"
    }

    fn is_durable(&self) -> bool {
        self.sinks.iter().any(|sink| sink.is_durable())
    }

    fn emit(&self, event: &AuditEvent) {
        for sink in &self.sinks {
            sink.emit(event);
        }
    }

    /// The acknowledgement goes to the first durable member in fan-out
    /// order -- a configuration has one store of record, the SQLite file or
    /// the shared PostgreSQL store, never both -- and every other member
    /// gets the plain emit it always got. With no durable member the record
    /// is reported not stored, which refuses the request waiting on it.
    fn emit_durable(&self, event: &AuditEvent, ack: DurableAck) {
        let mut ack = Some(ack);
        for sink in &self.sinks {
            if sink.is_durable() {
                if let Some(ack) = ack.take() {
                    sink.emit_durable(event, ack);
                    continue;
                }
            }
            sink.emit(event);
        }
        if let Some(ack) = ack {
            ack.not_stored();
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

    fn flush_by(&self, deadline: Instant) -> Result<(), String> {
        let mut first_error = None;
        for sink in &self.sinks {
            if let Err(error) = sink.flush_by(deadline) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
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

/// Cluster mode's durable audit sink, as the builder receives it. The type
/// only exists with the `postgres` feature; a feature-off build has no
/// value of it to pass, which `Infallible` makes a type-level fact.
#[cfg(feature = "postgres")]
type DurableSinkConfig = crate::audit::postgres_sink::PostgresSinkConfig;
#[cfg(not(feature = "postgres"))]
type DurableSinkConfig = std::convert::Infallible;

// The feature-off entry point (and the tests'); a `postgres` build's `main`
// goes through `build_sink_from_config_with_durable_store`.
#[cfg_attr(all(feature = "postgres", not(test)), allow(dead_code))]
pub fn build_sink_from_config(config: &Config) -> Result<ConfiguredAuditSink, Box<dyn Error>> {
    build_configured_sink(config, None)
}

/// [`build_sink_from_config`] with cluster mode's durable sink (issue #11,
/// PR 3) registered beside the configured ones: `None` builds exactly what
/// `build_sink_from_config` builds.
#[cfg(feature = "postgres")]
pub fn build_sink_from_config_with_durable_store(
    config: &Config,
    durable: Option<DurableSinkConfig>,
) -> Result<ConfiguredAuditSink, Box<dyn Error>> {
    build_configured_sink(config, durable)
}

fn build_configured_sink(
    config: &Config,
    durable: Option<DurableSinkConfig>,
) -> Result<ConfiguredAuditSink, Box<dyn Error>> {
    let (broadcast_sender, _) = tokio::sync::broadcast::channel(AUDIT_BROADCAST_CAPACITY);
    let members = configured_sink_members(config, durable, &broadcast_sender)?;
    let sink = CompositeSink::new(members);
    check_audit_durability(config, &sink)?;

    Ok((Arc::new(sink) as Arc<dyn AuditSink>, broadcast_sender))
}

/// Refuse at startup a required-durability configuration with no audit
/// store of record (issue #425), rather than serve a mode that would refuse
/// every request -- or, worse, quietly run as best effort. The opt-out is
/// announced once, so a deployment that chose it says so in its own log.
fn check_audit_durability(config: &Config, sink: &CompositeSink) -> Result<(), Box<dyn Error>> {
    match config.audit_durability {
        AuditDurability::Required if !sink.is_durable() => {
            Err(if config.state_backend == StateBackend::Postgres {
                "AUDIT_DURABILITY=required needs the shared PostgreSQL audit store, and this \
                 replica has none; set AUDIT_DURABILITY=best_effort only if requests may be \
                 served when their audit records are lost"
                    .into()
            } else {
                "AUDIT_DURABILITY=required needs a durable audit store: set AUDIT_SQLITE_PATH, \
                 or set AUDIT_DURABILITY=best_effort to serve requests whose audit records may be \
                 lost"
                    .into()
            })
        }
        AuditDurability::Required => Ok(()),
        AuditDurability::BestEffort => {
            tracing::warn!(
                "AUDIT_DURABILITY=best_effort: requests are served without waiting for their audit \
                 records, and a record the audit store later loses is only counted on \
                 audit_events_dropped_total"
            );
            Ok(())
        }
    }
}

/// Every sink a configuration gets, flat and in fan-out order: stdout, the
/// optional file, the standalone SQLite sinks, cluster mode's durable sink,
/// and the broadcast. Flat so the parity tests can read the members by
/// name; the composite over it fans out and flushes in this order.
fn configured_sink_members(
    config: &Config,
    durable: Option<DurableSinkConfig>,
    broadcast_sender: &AuditEventSender,
) -> Result<Vec<Arc<dyn AuditSink>>, Box<dyn Error>> {
    // Cluster mode has no SQLite sinks. `DISCOVERY_SQLITE_PATH` and
    // `AUDIT_SQLITE_PATH` are rejected there (config.rs): captured payload
    // shapes reach the fenced discovery projector through the durable
    // audit stream instead of a local file (issue #241, PR 11), and the
    // audit of record is the shared store (issue #11, PR 3). The builder
    // holds the same line itself, so a `Config` that bypassed validation
    // still cannot put a local audit file on a cluster replica.
    let cluster_mode = config.state_backend == StateBackend::Postgres;
    let mut members = build_sink_members(
        config.audit_log_file.as_deref(),
        if cluster_mode {
            None
        } else {
            config.audit_sqlite_path.as_deref()
        },
        if cluster_mode {
            None
        } else {
            config.audit_sqlite_retention_days
        },
        DiscoverySinkOptions {
            sqlite_path: if cluster_mode {
                None
            } else {
                config.discovery_sqlite_path.as_deref()
            },
            endpoint_limit: config.discovery_endpoint_limit,
            payload_capture_enabled: config.payload_capture_enabled && !cluster_mode,
        },
        Some(broadcast_sender.clone()),
        config.signal_detector_config(),
    )?;
    #[cfg(feature = "postgres")]
    if let Some(durable) = durable {
        members.push(
            Arc::new(crate::audit::postgres_sink::PostgresSink::new(durable)?)
                as Arc<dyn AuditSink>,
        );
    }
    #[cfg(not(feature = "postgres"))]
    let _: Option<DurableSinkConfig> = durable;
    members.push(Arc::new(BroadcastSink::new(broadcast_sender.clone())) as Arc<dyn AuditSink>);

    Ok(members)
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

    /// What a [`DurableCaptureSink`] does with the next required record.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub enum DurableBehaviour {
        /// Capture it and report it stored, like a healthy store of record.
        Store,
        /// Capture nothing and report it not stored, like a failed commit.
        Refuse,
        /// Capture it and hold the acknowledgement unreported, like a
        /// commit stuck behind a lock; [`DurableCaptureSink::release`]
        /// reports the held ones stored.
        Hold,
    }

    /// A store of record for tests of required audit durability (issue
    /// #425): it is durable as far as the composite is concerned, captures
    /// what it stores, and does with each acknowledgement what the test set.
    #[derive(Clone)]
    pub struct DurableCaptureSink {
        stored: CaptureSink,
        behaviour: Arc<Mutex<DurableBehaviour>>,
        held: Arc<Mutex<Vec<DurableAck>>>,
    }

    impl Default for DurableCaptureSink {
        fn default() -> Self {
            Self {
                stored: CaptureSink::new(),
                behaviour: Arc::new(Mutex::new(DurableBehaviour::Store)),
                held: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl DurableCaptureSink {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn set(&self, behaviour: DurableBehaviour) {
            *self
                .behaviour
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = behaviour;
        }

        /// Everything this sink stored (or holds), in arrival order.
        pub fn events(&self) -> Vec<AuditEvent> {
            self.stored.events()
        }

        pub fn held(&self) -> usize {
            self.held
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
        }

        /// Report every held acknowledgement stored.
        pub fn release(&self) {
            let held = std::mem::take(
                &mut *self
                    .held
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            );
            for ack in held {
                ack.stored();
            }
        }

        fn behaviour(&self) -> DurableBehaviour {
            *self
                .behaviour
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }
    }

    impl AuditSink for DurableCaptureSink {
        fn is_durable(&self) -> bool {
            true
        }

        fn emit(&self, event: &AuditEvent) {
            if self.behaviour() != DurableBehaviour::Refuse {
                self.stored.emit(event);
            }
        }

        fn emit_durable(&self, event: &AuditEvent, ack: DurableAck) {
            match self.behaviour() {
                DurableBehaviour::Store => {
                    self.stored.emit(event);
                    ack.stored();
                }
                DurableBehaviour::Refuse => ack.not_stored(),
                DurableBehaviour::Hold => {
                    self.stored.emit(event);
                    self.held
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(ack);
                }
            }
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
    ///
    /// Shared with `inbound_tls_tests` rather than duplicated: two hand-rolled
    /// recorders would drift, and a recorder that silently stopped matching
    /// would turn every assertion built on it into a tautology.
    #[derive(Clone, Default)]
    pub struct CountingRecorder {
        counts: Arc<Mutex<Vec<(String, u64)>>>,
        gauges: Arc<Mutex<Vec<(String, f64)>>>,
        histograms: Arc<Mutex<Vec<(String, f64)>>>,
    }

    impl CountingRecorder {
        /// Every value recorded into one histogram, in order.
        ///
        /// Histograms were a noop here until issue #241's PR 14 needed to
        /// assert that a store operation is timed under its classified
        /// outcome; a noop would have made that assertion a tautology.
        // The store histogram is cluster-mode only, so a
        // `--no-default-features` test build has no caller for this yet.
        #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
        pub fn histogram_values(&self, name: &str, labels: &[(&str, &str)]) -> Vec<f64> {
            let key = render_counter_key(name, labels);
            self.histograms
                .lock()
                .expect("histograms lock")
                .iter()
                .filter(|(recorded, _)| recorded == &key)
                .map(|(_, value)| *value)
                .collect()
        }

        pub fn count(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
            let key = render_counter_key(name, labels);
            self.counts
                .lock()
                .expect("counts lock")
                .iter()
                .filter(|(recorded, _)| recorded == &key)
                .map(|(_, value)| value)
                .sum()
        }

        /// The last recorded value of one gauge, or `None` if never set.
        pub fn gauge_value(&self, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
            let key = render_counter_key(name, labels);
            self.gauges
                .lock()
                .expect("gauges lock")
                .iter()
                .rev()
                .find(|(recorded, _)| recorded == &key)
                .map(|(_, value)| *value)
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

    struct RecordedGauge {
        key: String,
        gauges: Arc<Mutex<Vec<(String, f64)>>>,
    }

    impl ::metrics::GaugeFn for RecordedGauge {
        fn set(&self, value: f64) {
            self.gauges
                .lock()
                .expect("gauges lock")
                .push((self.key.clone(), value));
        }

        fn increment(&self, value: f64) {
            self.adjust(value);
        }

        fn decrement(&self, value: f64) {
            self.adjust(-value);
        }
    }

    impl RecordedGauge {
        /// The `metrics` gauge interface exposes increment/decrement without a
        /// read, so the last recorded value is the baseline for adjustments.
        fn adjust(&self, delta: f64) {
            let mut gauges = self.gauges.lock().expect("gauges lock");
            let current = gauges
                .iter()
                .rev()
                .find(|(recorded, _)| *recorded == self.key)
                .map(|(_, value)| *value)
                .unwrap_or(0.0);
            gauges.push((self.key.clone(), current + delta));
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
            key: &::metrics::Key,
            _metadata: &::metrics::Metadata<'_>,
        ) -> ::metrics::Gauge {
            let labels = key
                .labels()
                .map(|label| (label.key().to_owned(), label.value().to_owned()))
                .collect::<Vec<_>>();
            let borrowed = labels
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            ::metrics::Gauge::from_arc(Arc::new(RecordedGauge {
                key: render_counter_key(key.name(), &borrowed),
                gauges: Arc::clone(&self.gauges),
            }))
        }

        fn register_histogram(
            &self,
            key: &::metrics::Key,
            _metadata: &::metrics::Metadata<'_>,
        ) -> ::metrics::Histogram {
            let labels = key
                .labels()
                .map(|label| (label.key().to_owned(), label.value().to_owned()))
                .collect::<Vec<_>>();
            let borrowed = labels
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            ::metrics::Histogram::from_arc(Arc::new(RecordedHistogram {
                key: render_counter_key(key.name(), &borrowed),
                histograms: Arc::clone(&self.histograms),
            }))
        }
    }

    struct RecordedHistogram {
        key: String,
        histograms: Arc<Mutex<Vec<(String, f64)>>>,
    }

    impl ::metrics::HistogramFn for RecordedHistogram {
        fn record(&self, value: f64) {
            self.histograms
                .lock()
                .expect("histograms lock")
                .push((self.key.clone(), value));
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

    /// The members a configuration's production sink is assembled from, by
    /// name and in fan-out order.
    fn configured_member_names(
        config: &Config,
        durable: Option<DurableSinkConfig>,
    ) -> Vec<&'static str> {
        let (broadcast_sender, _) = tokio::sync::broadcast::channel(AUDIT_BROADCAST_CAPACITY);
        CompositeSink::new(
            configured_sink_members(config, durable, &broadcast_sender)
                .expect("configured sink members should build"),
        )
        .member_names()
    }

    fn temp_sqlite_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "greengateway-audit-sink-parity-{label}-{}.sqlite",
            uuid::Uuid::new_v4()
        ))
    }

    fn remove_sqlite(path: &std::path::Path) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = fs::remove_file(PathBuf::from(format!("{}{}", path.display(), suffix)));
        }
    }

    #[test]
    fn standalone_mode_constructs_the_sqlite_sinks_and_never_the_postgres_one() {
        let audit_db = temp_sqlite_path("standalone-audit");
        let mut config = Config::test_defaults();
        config.state_backend = StateBackend::Sqlite;
        config.audit_sqlite_path = Some(
            audit_db
                .to_str()
                .expect("test path should be valid UTF-8")
                .to_owned(),
        );

        let names = configured_member_names(&config, None);
        remove_sqlite(&audit_db);

        assert_eq!(
            names,
            ["stdout", "sqlite", "broadcast"],
            "standalone's audit of record is its SQLite file"
        );
        assert!(
            !names.contains(&"postgres"),
            "standalone must never construct the PostgreSQL sink"
        );
    }

    #[test]
    fn standalone_without_a_sqlite_path_is_stdout_and_broadcast_only() {
        let mut config = Config::test_defaults();
        config.state_backend = StateBackend::Sqlite;
        config.audit_sqlite_path = None;

        assert_eq!(
            configured_member_names(&config, None),
            ["stdout", "broadcast"]
        );
    }

    /// The acknowledgement of a required record reaches the store of record
    /// and nobody else, and every member still sees the event (issue #425).
    #[test]
    fn composite_hands_the_acknowledgement_to_its_durable_member_only() {
        use crate::audit::durable::DurableOutcome;

        let before = CaptureSink::new();
        let durable = DurableCaptureSink::new();
        let after = CaptureSink::new();
        let sink = CompositeSink::new(vec![
            Arc::new(before.clone()) as Arc<dyn AuditSink>,
            Arc::new(durable.clone()) as Arc<dyn AuditSink>,
            Arc::new(after.clone()) as Arc<dyn AuditSink>,
        ]);
        assert!(sink.is_durable());

        let (ack, mut outcome) = DurableAck::channel();
        sink.emit_durable(&test_event("audit.composite.durable"), ack);

        assert_eq!(outcome.try_recv(), Ok(DurableOutcome::Stored));
        for (name, events) in [
            ("before", before.events()),
            ("durable", durable.events()),
            ("after", after.events()),
        ] {
            assert_eq!(events.len(), 1, "the {name} member must see the event once");
        }

        // The store of record refusing is what the waiter hears, whatever
        // the other members did with the event.
        durable.set(DurableBehaviour::Refuse);
        let (ack, mut outcome) = DurableAck::channel();
        sink.emit_durable(&test_event("audit.composite.refused"), ack);
        assert_eq!(outcome.try_recv(), Ok(DurableOutcome::NotStored));
        assert_eq!(before.len(), 2);
        assert_eq!(after.len(), 2);
    }

    /// With no store of record nothing can vouch for the record, so it is
    /// reported not stored rather than taken on stdout's word.
    #[test]
    fn composite_without_a_durable_member_reports_the_record_not_stored() {
        use crate::audit::durable::DurableOutcome;

        let capture = CaptureSink::new();
        let sink = CompositeSink::new(vec![
            Arc::new(StdoutSink::with_target(
                Arc::new(RecordingTarget::default()),
            )) as Arc<dyn AuditSink>,
            Arc::new(capture.clone()) as Arc<dyn AuditSink>,
        ]);
        assert!(!sink.is_durable());

        let (ack, mut outcome) = DurableAck::channel();
        sink.emit_durable(&test_event("audit.composite.no_store"), ack);

        assert_eq!(outcome.try_recv(), Ok(DurableOutcome::NotStored));
        assert_eq!(capture.len(), 1, "the event is still delivered");
    }

    /// `AUDIT_DURABILITY=required`, the default, with no audit store of
    /// record is a startup error that names both ways out, never a gateway
    /// that silently runs best effort.
    #[test]
    fn required_durability_without_a_store_of_record_is_refused_at_startup() {
        let mut config = Config::test_defaults();
        assert_eq!(
            config.audit_durability,
            AuditDurability::Required,
            "required is the default"
        );
        config.state_backend = StateBackend::Sqlite;
        config.audit_sqlite_path = None;
        config.audit_log_file = None;

        let error = build_sink_from_config(&config)
            .err()
            .expect("required durability over stdout alone must not build")
            .to_string();
        assert!(error.contains("AUDIT_DURABILITY=required"), "{error}");
        assert!(error.contains("AUDIT_SQLITE_PATH"), "{error}");
        assert!(error.contains("AUDIT_DURABILITY=best_effort"), "{error}");

        // A JSONL file is not a store of record either.
        let file = std::env::temp_dir().join(format!(
            "greengateway-audit-durability-{}.jsonl",
            uuid::Uuid::new_v4()
        ));
        config.audit_log_file = Some(file.to_string_lossy().into_owned());
        assert!(build_sink_from_config(&config).is_err());
        let _ = fs::remove_file(&file);
    }

    #[test]
    fn required_durability_builds_over_the_sqlite_store_and_best_effort_builds_without_one() {
        let audit_db = temp_sqlite_path("required-sqlite");
        let mut config = Config::test_defaults();
        config.state_backend = StateBackend::Sqlite;
        config.audit_sqlite_path = Some(
            audit_db
                .to_str()
                .expect("test path should be valid UTF-8")
                .to_owned(),
        );
        let (sink, _) =
            build_sink_from_config(&config).expect("required durability over SQLite builds");
        assert!(sink.is_durable());
        drop(sink);
        remove_sqlite(&audit_db);

        config.audit_sqlite_path = None;
        config.audit_durability = AuditDurability::BestEffort;
        let (sink, _) =
            build_sink_from_config(&config).expect("the explicit opt-out builds without a store");
        assert!(!sink.is_durable());
    }

    /// A cluster replica without the shared store has no store of record
    /// either; the refusal names the store it is missing.
    #[cfg(feature = "postgres")]
    #[test]
    fn required_durability_in_cluster_mode_without_the_shared_store_is_refused() {
        let mut config = Config::test_defaults();
        config.state_backend = StateBackend::Postgres;
        let error = build_sink_from_config_with_durable_store(&config, None)
            .err()
            .expect("a cluster replica with no audit store cannot be required")
            .to_string();
        assert!(error.contains("shared PostgreSQL audit store"), "{error}");
        assert!(error.contains("AUDIT_DURABILITY=best_effort"), "{error}");
    }

    /// The audit log refuses the same mismatch on its own, so a sink built
    /// some other way cannot leave required mode with nothing to settle it.
    #[test]
    fn a_required_audit_log_refuses_a_sink_with_no_store_of_record() {
        let error = crate::audit::AuditLog::try_new_with_durability(
            Arc::new(CaptureSink::new()),
            AuditDurability::Required,
            Duration::from_secs(1),
        )
        .err()
        .expect("required durability needs a durable sink");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    /// Cluster mode's members with and without the durable store. A pool
    /// that never connects stands in for the foundation's: the sink is
    /// constructed, not exercised, and the flusher has nothing to write.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn cluster_mode_constructs_the_postgres_sink_and_never_the_sqlite_one() {
        use crate::storage::postgres_audit::{IngestIdentity, PostgresAuditEventStore};

        let audit_db = temp_sqlite_path("cluster-audit");
        let mut config = Config::test_defaults();
        config.state_backend = StateBackend::Postgres;
        // Config validation rejects this pairing; the builder must hold the
        // line on its own for a `Config` that never went through it.
        config.audit_sqlite_path = Some(
            audit_db
                .to_str()
                .expect("test path should be valid UTF-8")
                .to_owned(),
        );
        config.audit_sqlite_retention_days = Some(7);

        let mut pg = tokio_postgres::Config::new();
        pg.host("127.0.0.1")
            .port(1)
            .user("gateway_sink_parity")
            .dbname("gateway_sink_parity");
        let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(
            pg,
            tokio_postgres::NoTls,
        ))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .build()
        .expect("an unconnected pool should build");
        let durable = DurableSinkConfig {
            store: Arc::new(PostgresAuditEventStore::new(
                pool,
                Some(IngestIdentity {
                    instance_id: uuid::Uuid::new_v4(),
                    boot_id: uuid::Uuid::new_v4(),
                }),
            )),
            flush_deadline: Duration::from_millis(100),
        };

        let with_store = configured_member_names(&config, Some(durable));
        let without_store = configured_member_names(&config, None);
        remove_sqlite(&audit_db);

        assert_eq!(
            with_store,
            ["stdout", "postgres", "broadcast"],
            "cluster mode's audit of record is the shared store, and no SQLite file is opened"
        );
        assert_eq!(
            without_store,
            ["stdout", "broadcast"],
            "without a store there is still no SQLite sink"
        );
        assert!(
            !audit_db.exists(),
            "a cluster replica must not have created a local audit database"
        );
    }
}
