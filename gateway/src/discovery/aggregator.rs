//! SQLite-backed endpoint discovery aggregation.
//!
//! The aggregator is an `AuditSink`, so request handlers only enqueue audit
//! events on the existing bounded audit channel. This sink runs on the audit
//! writer thread, keeps an in-memory working set, and periodically flushes
//! endpoint inventory to SQLite.
//!
//! Aggregates are keyed by `(method, endpoint_template)`. Status counts are
//! exact per status code. Distinct principal counts are exact by storing one
//! principal row per observed `actor.user_id`; unauthenticated requests increase
//! call counts but not distinct principal counts. Latency percentiles are
//! computed from a bounded deterministic reservoir sample, which keeps memory
//! bounded while making percentiles approximate once an endpoint has more than
//! `LATENCY_SAMPLE_LIMIT` observations.
//!
//! Known limitation: exact distinct-principal tracking is unbounded. Each
//! distinct `actor.user_id` observed for a `(method, endpoint_template)` is kept
//! in memory for the lifetime of the process and stored in
//! `discovery_endpoint_principals` for the lifetime of the database.

use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    error::Error,
    fmt, io,
    path::PathBuf,
    sync::{
        mpsc::{self, RecvTimeoutError, Sender},
        Arc, Mutex, MutexGuard,
    },
    thread::{self, JoinHandle},
    time::Duration as StdDuration,
};

use rusqlite::{params, Connection};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    audit::{event, redact::hash_args, AuditEvent, AuditEventSender, AuditSink},
    discovery::{
        path_template::{template_stateless, PathTemplateLearner},
        signals::{
            self, EndpointSignalObservation, ErrorRateSpikeSignalObservation, NewSignal,
            PrincipalNewToEndpointSignalObservation, SchemaMismatchSignalObservation,
            SignalDetectorConfig, SignalEvaluator, VolumeOutlierSignalObservation,
        },
    },
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
};

const HTTP_REQUEST_OBSERVED: &str = "http.request_observed";
const AGGREGATOR_BATCH_SIZE: usize = 200;
const AGGREGATOR_FLUSH_INTERVAL: StdDuration = StdDuration::from_millis(250);
const LATENCY_SAMPLE_LIMIT: usize = 1024;
const PAYLOAD_SHAPE_SAMPLE_LIMIT: usize = 128;
const ID_PLACEHOLDER: &str = "{id}";
const PARAM_PLACEHOLDER: &str = "{param}";

const CREATE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS discovery_endpoint_aggregates (
    method TEXT NOT NULL,
    endpoint_template TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    call_count INTEGER NOT NULL,
    schema_mismatch_count INTEGER NOT NULL DEFAULT 0,
    latency_count INTEGER NOT NULL,
    latency_p50_ms INTEGER NOT NULL,
    latency_p95_ms INTEGER NOT NULL,
    latency_p99_ms INTEGER NOT NULL,
    latency_samples_json TEXT NOT NULL,
    distinct_principal_count INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (method, endpoint_template)
);

CREATE TABLE IF NOT EXISTS discovery_endpoint_status_counts (
    method TEXT NOT NULL,
    endpoint_template TEXT NOT NULL,
    status INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (method, endpoint_template, status)
);

CREATE TABLE IF NOT EXISTS discovery_endpoint_principals (
    method TEXT NOT NULL,
    endpoint_template TEXT NOT NULL,
    user_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    PRIMARY KEY (method, endpoint_template, user_id)
);

CREATE INDEX IF NOT EXISTS idx_discovery_endpoint_last_seen
ON discovery_endpoint_aggregates(last_seen);

CREATE INDEX IF NOT EXISTS idx_discovery_endpoint_template
ON discovery_endpoint_aggregates(endpoint_template);
"#;

const CREATE_PAYLOAD_CAPTURE_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS discovery_payload_shape_stats (
    method TEXT NOT NULL,
    endpoint_template TEXT NOT NULL,
    shape_observation_count INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (method, endpoint_template)
);

CREATE TABLE IF NOT EXISTS discovery_payload_shape_samples (
    method TEXT NOT NULL,
    endpoint_template TEXT NOT NULL,
    sample_slot INTEGER NOT NULL,
    observed_at TEXT NOT NULL,
    shape_hash TEXT NOT NULL,
    shape_json TEXT NOT NULL,
    PRIMARY KEY (method, endpoint_template, sample_slot)
);

CREATE INDEX IF NOT EXISTS idx_discovery_payload_shape_template
ON discovery_payload_shape_samples(endpoint_template);
"#;

const UPSERT_AGGREGATE_SQL: &str = r#"
INSERT INTO discovery_endpoint_aggregates (
    method,
    endpoint_template,
    first_seen,
    last_seen,
    call_count,
    schema_mismatch_count,
    latency_count,
    latency_p50_ms,
    latency_p95_ms,
    latency_p99_ms,
    latency_samples_json,
    distinct_principal_count,
    updated_at
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
ON CONFLICT(method, endpoint_template) DO UPDATE SET
    first_seen = excluded.first_seen,
    last_seen = excluded.last_seen,
    call_count = excluded.call_count,
    schema_mismatch_count = excluded.schema_mismatch_count,
    latency_count = excluded.latency_count,
    latency_p50_ms = excluded.latency_p50_ms,
    latency_p95_ms = excluded.latency_p95_ms,
    latency_p99_ms = excluded.latency_p99_ms,
    latency_samples_json = excluded.latency_samples_json,
    distinct_principal_count = excluded.distinct_principal_count,
    updated_at = excluded.updated_at
"#;

#[derive(Debug, Clone)]
pub struct EndpointAggregatorSinkConfig {
    pub path: PathBuf,
    pub payload_capture_enabled: bool,
    pub signal_event_sender: Option<AuditEventSender>,
    pub signal_detector_config: SignalDetectorConfig,
}

pub struct EndpointAggregatorSink {
    shared: Arc<EndpointAggregatorShared>,
    shutdown_tx: Mutex<Option<Sender<()>>>,
    flusher: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Debug)]
pub enum EndpointAggregatorSinkError {
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Setup {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Load {
        path: PathBuf,
        source: EndpointAggregatorLoadError,
    },
    ThreadSpawn {
        source: io::Error,
    },
}

#[derive(Debug)]
pub enum EndpointAggregatorLoadError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

#[derive(Debug)]
enum EndpointAggregatorFlushError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Signal(signals::SignalStorageError),
}

impl fmt::Display for EndpointAggregatorSinkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => write!(
                formatter,
                "failed to open SQLite discovery aggregator at {}: {source}",
                path.display()
            ),
            Self::Setup { path, source } => write!(
                formatter,
                "failed to initialize SQLite discovery aggregator at {}: {source}",
                path.display()
            ),
            Self::Load { path, source } => write!(
                formatter,
                "failed to load SQLite discovery aggregates at {}: {source}",
                path.display()
            ),
            Self::ThreadSpawn { source } => write!(
                formatter,
                "failed to spawn SQLite discovery aggregator flusher: {source}"
            ),
        }
    }
}

impl Error for EndpointAggregatorSinkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Setup { source, .. } => Some(source),
            Self::Load { source, .. } => Some(source),
            Self::ThreadSpawn { source } => Some(source),
        }
    }
}

impl fmt::Display for EndpointAggregatorLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(err) => write!(formatter, "SQLite error: {err}"),
            Self::Json(err) => write!(formatter, "JSON deserialization error: {err}"),
        }
    }
}

impl Error for EndpointAggregatorLoadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(err) => Some(err),
            Self::Json(err) => Some(err),
        }
    }
}

impl From<rusqlite::Error> for EndpointAggregatorLoadError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

impl From<serde_json::Error> for EndpointAggregatorLoadError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl fmt::Display for EndpointAggregatorFlushError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(err) => write!(formatter, "SQLite error: {err}"),
            Self::Json(err) => write!(formatter, "JSON serialization error: {err}"),
            Self::Signal(err) => write!(formatter, "signal storage error: {err}"),
        }
    }
}

impl Error for EndpointAggregatorFlushError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite(err) => Some(err),
            Self::Json(err) => Some(err),
            Self::Signal(err) => Some(err),
        }
    }
}

impl From<rusqlite::Error> for EndpointAggregatorFlushError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

impl From<serde_json::Error> for EndpointAggregatorFlushError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl From<signals::SignalStorageError> for EndpointAggregatorFlushError {
    fn from(err: signals::SignalStorageError) -> Self {
        Self::Signal(err)
    }
}

impl EndpointAggregatorSink {
    pub fn new(config: EndpointAggregatorSinkConfig) -> Result<Self, EndpointAggregatorSinkError> {
        Self::new_with_flush_interval(config, AGGREGATOR_FLUSH_INTERVAL)
    }

    fn new_with_flush_interval(
        config: EndpointAggregatorSinkConfig,
        flush_interval: StdDuration,
    ) -> Result<Self, EndpointAggregatorSinkError> {
        let connection =
            Connection::open(&config.path).map_err(|source| EndpointAggregatorSinkError::Open {
                path: config.path.clone(),
                source,
            })?;
        configure_connection(&connection).map_err(|source| EndpointAggregatorSinkError::Setup {
            path: config.path.clone(),
            source,
        })?;
        if config.payload_capture_enabled {
            configure_payload_capture_connection(&connection).map_err(|source| {
                EndpointAggregatorSinkError::Setup {
                    path: config.path.clone(),
                    source,
                }
            })?;
        }
        let state = AggregatorState::load(
            &connection,
            config.payload_capture_enabled,
            config.signal_detector_config,
        )
        .map_err(|source| EndpointAggregatorSinkError::Load {
            path: config.path.clone(),
            source,
        })?;

        let shared = Arc::new(EndpointAggregatorShared {
            path: config.path,
            signal_event_sender: config.signal_event_sender,
            connection: Mutex::new(connection),
            state: Mutex::new(state),
        });
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let flusher_shared = Arc::clone(&shared);
        let flusher = thread::Builder::new()
            .name("discovery-aggregator-flusher".to_owned())
            .spawn(move || flusher_loop(flusher_shared, shutdown_rx, flush_interval))
            .map_err(|source| EndpointAggregatorSinkError::ThreadSpawn { source })?;

        Ok(Self {
            shared,
            shutdown_tx: Mutex::new(Some(shutdown_tx)),
            flusher: Mutex::new(Some(flusher)),
        })
    }

    #[cfg(test)]
    fn flush_for_test(&self) {
        self.shared.flush_state();
    }
}

impl AuditSink for EndpointAggregatorSink {
    fn emit(&self, event: &AuditEvent) {
        let Some(observation) = ObservedRequest::from_event(event) else {
            return;
        };

        if self.shared.observe(observation) {
            self.shared.flush_state();
        }
    }
}

impl Drop for EndpointAggregatorSink {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = take_mutex_value(&self.shutdown_tx, "shutdown_tx", &self.shared)
        {
            let _ = shutdown_tx.send(());
        }

        if let Some(flusher) = take_mutex_value(&self.flusher, "flusher", &self.shared) {
            if flusher.join().is_err() {
                tracing::error!(
                    path = %self.shared.path.display(),
                    "SQLite discovery aggregator flusher thread panicked during shutdown"
                );
            }
        }

        self.shared.flush_state();
    }
}

struct EndpointAggregatorShared {
    path: PathBuf,
    signal_event_sender: Option<AuditEventSender>,
    connection: Mutex<Connection>,
    state: Mutex<AggregatorState>,
}

impl EndpointAggregatorShared {
    fn observe(&self, observation: ObservedRequest) -> bool {
        let mut state = self.state_guard();
        state.observe(observation)
    }

    fn flush_state(&self) {
        let mut state = self.state_guard();
        if !state.has_pending_flush() {
            return;
        }

        let deleted_keys = state.deleted_keys.iter().cloned().collect::<Vec<_>>();
        let dirty_keys = state.dirty_keys.iter().cloned().collect::<Vec<_>>();
        let pending_signals = state.pending_signals.clone();
        let dirty_aggregates = dirty_keys
            .iter()
            .filter_map(|key| state.aggregates.get(key).cloned())
            .collect::<Vec<_>>();
        let payload_capture_enabled = state.payload_capture_enabled;

        let result = {
            let mut connection = self.connection_guard();
            write_flush(
                &mut connection,
                &deleted_keys,
                &dirty_aggregates,
                &pending_signals,
                payload_capture_enabled,
            )
        };

        match result {
            Ok(opened_signals) => {
                state.mark_flushed(&deleted_keys, &dirty_keys, pending_signals.len());
                self.emit_signal_opened_events(&opened_signals);
            }
            Err(err) => {
                tracing::error!(
                    path = %self.path.display(),
                    deleted_count = deleted_keys.len(),
                    aggregate_count = dirty_aggregates.len(),
                    signal_count = pending_signals.len(),
                    error = %err,
                    "failed to flush SQLite discovery aggregates; keeping dirty state for retry"
                );
            }
        }
    }

    fn emit_signal_opened_events(&self, signals: &[signals::Signal]) {
        let Some(sender) = &self.signal_event_sender else {
            return;
        };

        for signal in signals {
            let payload = json!({
                "id": &signal.id,
                "signal_type": &signal.signal_type,
                "target": &signal.target,
                "explanation": &signal.explanation,
                "evidence": &signal.evidence,
                "state": signal.state.as_str(),
                "created_at": &signal.created_at,
                "updated_at": &signal.updated_at,
                "transitioned_at": &signal.transitioned_at,
                "transitioned_by": &signal.transitioned_by,
            });
            let event = AuditEvent::new(
                event::SIGNAL_OPENED,
                "discovery-signal",
                "127.0.0.1",
                None,
                payload,
            );

            if sender.send(event).is_err() {
                tracing::trace!("no active audit event stream subscribers for signal.opened");
            }
        }
    }

    fn state_guard(&self) -> MutexGuard<'_, AggregatorState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "discovery",
                    "lock" => "endpoint_aggregator_state"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "discovery aggregator state lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "discovery",
                    "lock" => "endpoint_aggregator_connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "discovery aggregator SQLite connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct EndpointKey {
    method: String,
    endpoint_template: String,
}

impl EndpointKey {
    fn new(method: impl Into<String>, endpoint_template: impl Into<String>) -> Self {
        Self {
            method: method.into(),
            endpoint_template: endpoint_template.into(),
        }
    }
}

#[derive(Clone, Debug)]
struct EndpointAggregate {
    key: EndpointKey,
    first_seen: String,
    last_seen: String,
    call_count: u64,
    schema_mismatch_count: u64,
    error_count: u64,
    status_counts: BTreeMap<u16, u64>,
    latency_count: u64,
    latency_samples: Vec<u64>,
    payload_shape_observation_count: u64,
    payload_shape_samples: Vec<PayloadShapeSample>,
    /// Known limitation: exact principal entries are never capped or evicted.
    /// This map grows one entry per distinct `actor.user_id` seen for this
    /// endpoint for the lifetime of the process, and the matching
    /// `discovery_endpoint_principals` rows grow for the lifetime of the
    /// database. Future work should add TTL pruning or a configured
    /// cardinality cap if exactness becomes too costly.
    principals: HashMap<String, PrincipalSeen>,
    recent_error_window: RecentErrorWindow,
    volume_window: VolumeWindow,
}

impl EndpointAggregate {
    fn new(key: EndpointKey, timestamp: &str) -> Self {
        Self {
            key,
            first_seen: timestamp.to_owned(),
            last_seen: timestamp.to_owned(),
            call_count: 0,
            schema_mismatch_count: 0,
            error_count: 0,
            status_counts: BTreeMap::new(),
            latency_count: 0,
            latency_samples: Vec::new(),
            payload_shape_observation_count: 0,
            payload_shape_samples: Vec::new(),
            principals: HashMap::new(),
            recent_error_window: RecentErrorWindow::default(),
            volume_window: VolumeWindow::default(),
        }
    }

    fn observe(&mut self, observation: &ObservedRequest) -> EndpointAggregateObservation {
        if timestamp_before(&observation.timestamp, &self.first_seen) {
            self.first_seen = observation.timestamp.clone();
        }
        if timestamp_after(&observation.timestamp, &self.last_seen) {
            self.last_seen = observation.timestamp.clone();
        }

        self.call_count = self.call_count.saturating_add(1);
        if observation.schema_mismatch {
            self.schema_mismatch_count = self.schema_mismatch_count.saturating_add(1);
        }
        let error_status = is_error_status(observation.status);
        if error_status {
            self.error_count = self.error_count.saturating_add(1);
        }
        *self.status_counts.entry(observation.status).or_insert(0) += 1;
        self.record_latency(observation.latency_ms);
        if let Some(payload_shape) = observation.payload_shape.as_ref() {
            self.record_payload_shape(&observation.timestamp, payload_shape.clone());
        }
        let recent_error_window = self.recent_error_window.observe(error_status);
        let completed_volume_window = self.volume_window.observe(&observation.timestamp);

        if let Some(user_id) = observation.user_id.as_deref() {
            if !user_id.is_empty() {
                self.principals
                    .entry(user_id.to_owned())
                    .and_modify(|seen| {
                        if timestamp_before(&observation.timestamp, &seen.first_seen) {
                            seen.first_seen = observation.timestamp.clone();
                        }
                        if timestamp_after(&observation.timestamp, &seen.last_seen) {
                            seen.last_seen = observation.timestamp.clone();
                        }
                    })
                    .or_insert_with(|| PrincipalSeen {
                        first_seen: observation.timestamp.clone(),
                        last_seen: observation.timestamp.clone(),
                    });
            }
        }

        EndpointAggregateObservation {
            recent_error_window,
            completed_volume_window,
        }
    }

    fn merge_from(&mut self, other: EndpointAggregate) {
        if timestamp_before(&other.first_seen, &self.first_seen) {
            self.first_seen = other.first_seen;
        }
        if timestamp_after(&other.last_seen, &self.last_seen) {
            self.last_seen = other.last_seen;
        }

        self.call_count = self.call_count.saturating_add(other.call_count);
        self.schema_mismatch_count = self
            .schema_mismatch_count
            .saturating_add(other.schema_mismatch_count);
        self.error_count = self.error_count.saturating_add(other.error_count);
        for (status, count) in other.status_counts {
            *self.status_counts.entry(status).or_insert(0) += count;
        }
        self.merge_latency(other.latency_count, other.latency_samples);
        self.merge_payload_shapes(
            other.payload_shape_observation_count,
            other.payload_shape_samples,
        );

        for (user_id, other_seen) in other.principals {
            self.principals
                .entry(user_id)
                .and_modify(|seen| seen.merge(other_seen.clone()))
                .or_insert(other_seen);
        }

        self.reset_transient_signal_windows();
    }

    fn record_latency(&mut self, latency_ms: u64) {
        self.latency_count = self.latency_count.saturating_add(1);
        offer_latency_sample(
            self.latency_count,
            latency_ms,
            &mut self.latency_samples,
            LATENCY_SAMPLE_LIMIT,
        );
    }

    fn merge_latency(&mut self, other_count: u64, other_samples: Vec<u64>) {
        let original_count = self.latency_count;
        self.latency_count = self.latency_count.saturating_add(other_count);

        if self.latency_samples.len() + other_samples.len() <= LATENCY_SAMPLE_LIMIT {
            self.latency_samples.extend(other_samples);
            return;
        }

        for (index, latency_ms) in other_samples.into_iter().enumerate() {
            let synthetic_count = original_count
                .saturating_add(u64::try_from(index).unwrap_or(u64::MAX))
                .saturating_add(1);
            offer_latency_sample(
                synthetic_count,
                latency_ms,
                &mut self.latency_samples,
                LATENCY_SAMPLE_LIMIT,
            );
        }
    }

    fn record_payload_shape(&mut self, observed_at: &str, shape: Value) {
        self.payload_shape_observation_count =
            self.payload_shape_observation_count.saturating_add(1);
        offer_payload_shape_sample(
            self.payload_shape_observation_count,
            PayloadShapeSample::new(observed_at, shape),
            &mut self.payload_shape_samples,
            PAYLOAD_SHAPE_SAMPLE_LIMIT,
        );
    }

    fn merge_payload_shapes(&mut self, other_count: u64, other_samples: Vec<PayloadShapeSample>) {
        let original_count = self.payload_shape_observation_count;
        self.payload_shape_observation_count = self
            .payload_shape_observation_count
            .saturating_add(other_count);

        if self.payload_shape_samples.len() + other_samples.len() <= PAYLOAD_SHAPE_SAMPLE_LIMIT {
            self.payload_shape_samples.extend(other_samples);
            return;
        }

        for (index, sample) in other_samples.into_iter().enumerate() {
            let synthetic_count = original_count
                .saturating_add(u64::try_from(index).unwrap_or(u64::MAX))
                .saturating_add(1);
            offer_payload_shape_sample(
                synthetic_count,
                sample,
                &mut self.payload_shape_samples,
                PAYLOAD_SHAPE_SAMPLE_LIMIT,
            );
        }
    }

    fn latency_percentiles(&self) -> LatencyPercentiles {
        LatencyPercentiles::from_samples(&self.latency_samples)
    }

    fn reset_transient_signal_windows(&mut self) {
        self.recent_error_window = RecentErrorWindow::default();
        self.volume_window = VolumeWindow::default();
    }
}

#[derive(Clone, Debug)]
struct EndpointAggregateObservation {
    recent_error_window: ErrorRateWindowSnapshot,
    completed_volume_window: Option<CompletedVolumeWindow>,
}

#[derive(Clone, Debug, Default)]
struct RecentErrorWindow {
    samples: VecDeque<bool>,
    error_count: u64,
}

impl RecentErrorWindow {
    fn observe(&mut self, error_status: bool) -> ErrorRateWindowSnapshot {
        let limit = signals::ERROR_RATE_SPIKE_MIN_SAMPLE_COUNT as usize;
        if self.samples.len() == limit && self.samples.pop_front().unwrap_or(false) {
            self.error_count = self.error_count.saturating_sub(1);
        }

        self.samples.push_back(error_status);
        if error_status {
            self.error_count = self.error_count.saturating_add(1);
        }

        ErrorRateWindowSnapshot {
            sample_count: self.samples.len() as u64,
            error_count: self.error_count,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct ErrorRateWindowSnapshot {
    sample_count: u64,
    error_count: u64,
}

#[derive(Clone, Debug, Default)]
struct VolumeWindow {
    current: Option<OpenVolumeWindow>,
    baseline_window_count: u64,
    baseline_rate_per_second: f64,
}

impl VolumeWindow {
    fn observe(&mut self, timestamp: &str) -> Option<CompletedVolumeWindow> {
        let timestamp_seconds = timestamp_seconds(timestamp)?;
        let current = self.current.get_or_insert(OpenVolumeWindow {
            first_timestamp_seconds: timestamp_seconds,
            last_timestamp_seconds: timestamp_seconds,
            call_count: 0,
        });

        if timestamp_seconds < current.last_timestamp_seconds {
            self.current = Some(OpenVolumeWindow {
                first_timestamp_seconds: timestamp_seconds,
                last_timestamp_seconds: timestamp_seconds,
                call_count: 1,
            });
            return None;
        }

        current.call_count = current.call_count.saturating_add(1);
        current.last_timestamp_seconds = timestamp_seconds;

        if current.call_count < signals::VOLUME_OUTLIER_WINDOW_SAMPLE_COUNT {
            return None;
        }

        let duration_secs = current.duration_secs();
        let rate_per_second = current.rate_per_second(duration_secs);
        let completed = CompletedVolumeWindow {
            call_count: current.call_count,
            duration_secs,
            rate_per_second,
            baseline_window_count: self.baseline_window_count,
            baseline_rate_per_second: self.baseline_rate_per_second,
        };
        self.observe_baseline_window(rate_per_second);
        self.current = None;

        Some(completed)
    }

    fn observe_baseline_window(&mut self, rate_per_second: f64) {
        if !rate_per_second.is_finite() || rate_per_second <= 0.0 {
            return;
        }

        let total = self.baseline_rate_per_second * self.baseline_window_count as f64;
        self.baseline_window_count = self.baseline_window_count.saturating_add(1);
        self.baseline_rate_per_second =
            (total + rate_per_second) / self.baseline_window_count as f64;
    }
}

#[derive(Clone, Copy, Debug)]
struct OpenVolumeWindow {
    first_timestamp_seconds: i64,
    last_timestamp_seconds: i64,
    call_count: u64,
}

impl OpenVolumeWindow {
    fn duration_secs(&self) -> u64 {
        let elapsed = self
            .last_timestamp_seconds
            .saturating_sub(self.first_timestamp_seconds);
        u64::try_from(elapsed).unwrap_or(0).max(1)
    }

    fn rate_per_second(&self, duration_secs: u64) -> f64 {
        self.call_count.saturating_sub(1) as f64 / duration_secs as f64
    }
}

#[derive(Clone, Copy, Debug)]
struct CompletedVolumeWindow {
    call_count: u64,
    duration_secs: u64,
    rate_per_second: f64,
    baseline_window_count: u64,
    baseline_rate_per_second: f64,
}

#[derive(Clone, Debug)]
struct PayloadShapeSample {
    observed_at: String,
    shape_hash: String,
    shape: Value,
}

impl PayloadShapeSample {
    fn new(observed_at: &str, shape: Value) -> Self {
        let shape_hash = hash_args(&shape);
        Self {
            observed_at: observed_at.to_owned(),
            shape_hash,
            shape,
        }
    }
}

#[derive(Clone, Debug)]
struct PrincipalSeen {
    first_seen: String,
    last_seen: String,
}

impl PrincipalSeen {
    fn merge(&mut self, other: Self) {
        if timestamp_before(&other.first_seen, &self.first_seen) {
            self.first_seen = other.first_seen;
        }
        if timestamp_after(&other.last_seen, &self.last_seen) {
            self.last_seen = other.last_seen;
        }
    }
}

#[derive(Debug, Default)]
struct AggregatorState {
    payload_capture_enabled: bool,
    signal_evaluator: SignalEvaluator,
    learner: PathTemplateLearner,
    aggregates: HashMap<EndpointKey, EndpointAggregate>,
    dirty_keys: HashSet<EndpointKey>,
    deleted_keys: HashSet<EndpointKey>,
    pending_signals: Vec<NewSignal>,
    queued_signal_identities: HashSet<SignalIdentity>,
    dirty_events: usize,
}

impl AggregatorState {
    fn load(
        connection: &Connection,
        payload_capture_enabled: bool,
        signal_detector_config: SignalDetectorConfig,
    ) -> Result<Self, EndpointAggregatorLoadError> {
        let mut state = Self {
            payload_capture_enabled,
            signal_evaluator: SignalEvaluator::new(signal_detector_config),
            ..Self::default()
        };

        for row in load_aggregate_rows(connection)? {
            let key = EndpointKey::new(row.method, row.endpoint_template);
            let latency_samples = serde_json::from_str::<Vec<u64>>(&row.latency_samples_json)?;
            state.aggregates.insert(
                key.clone(),
                EndpointAggregate {
                    key,
                    first_seen: row.first_seen,
                    last_seen: row.last_seen,
                    call_count: non_negative_i64_to_u64(row.call_count),
                    schema_mismatch_count: non_negative_i64_to_u64(row.schema_mismatch_count),
                    error_count: 0,
                    status_counts: BTreeMap::new(),
                    latency_count: non_negative_i64_to_u64(row.latency_count),
                    latency_samples,
                    payload_shape_observation_count: 0,
                    payload_shape_samples: Vec::new(),
                    principals: HashMap::new(),
                    recent_error_window: RecentErrorWindow::default(),
                    volume_window: VolumeWindow::default(),
                },
            );
        }

        for row in load_status_rows(connection)? {
            let key = EndpointKey::new(row.method, row.endpoint_template);
            let Some(aggregate) = state.aggregates.get_mut(&key) else {
                continue;
            };
            let Ok(status) = u16::try_from(row.status) else {
                continue;
            };
            let count = non_negative_i64_to_u64(row.count);
            aggregate.status_counts.insert(status, count);
            if is_error_status(status) {
                aggregate.error_count = aggregate.error_count.saturating_add(count);
            }
        }

        for row in load_principal_rows(connection)? {
            let key = EndpointKey::new(row.method, row.endpoint_template);
            let Some(aggregate) = state.aggregates.get_mut(&key) else {
                continue;
            };
            aggregate.principals.insert(
                row.user_id,
                PrincipalSeen {
                    first_seen: row.first_seen,
                    last_seen: row.last_seen,
                },
            );
        }

        if payload_capture_enabled {
            for row in load_payload_shape_stat_rows(connection)? {
                let key = EndpointKey::new(row.method, row.endpoint_template);
                let Some(aggregate) = state.aggregates.get_mut(&key) else {
                    continue;
                };
                aggregate.payload_shape_observation_count =
                    non_negative_i64_to_u64(row.shape_observation_count);
            }

            for row in load_payload_shape_sample_rows(connection)? {
                let key = EndpointKey::new(row.method, row.endpoint_template);
                let Some(aggregate) = state.aggregates.get_mut(&key) else {
                    continue;
                };
                let shape = serde_json::from_str::<Value>(&row.shape_json)?;
                aggregate.payload_shape_samples.push(PayloadShapeSample {
                    observed_at: row.observed_at,
                    shape_hash: row.shape_hash,
                    shape,
                });
            }
        }

        Ok(state)
    }

    fn observe(&mut self, observation: ObservedRequest) -> bool {
        let endpoint_template = self.endpoint_template(&observation.method, &observation.path);
        let key = EndpointKey::new(observation.method.clone(), endpoint_template);
        let is_new_endpoint = !self.aggregates.contains_key(&key);
        let principal = observation
            .user_id
            .as_deref()
            .filter(|user_id| !user_id.is_empty());
        let (
            previous_schema_mismatch_count,
            previous_distinct_principal_count,
            principal_seen_before,
            aggregate_call_count,
            aggregate_schema_mismatch_count,
            aggregate_error_count,
            observation_effects,
        ) = {
            let aggregate = self
                .aggregates
                .entry(key.clone())
                .or_insert_with(|| EndpointAggregate::new(key.clone(), &observation.timestamp));
            let previous_schema_mismatch_count = aggregate.schema_mismatch_count;
            let previous_distinct_principal_count = aggregate.principals.len() as u64;
            let principal_seen_before =
                principal.is_some_and(|user_id| aggregate.principals.contains_key(user_id));
            let observation_effects = aggregate.observe(&observation);

            (
                previous_schema_mismatch_count,
                previous_distinct_principal_count,
                principal_seen_before,
                aggregate.call_count,
                aggregate.schema_mismatch_count,
                aggregate.error_count,
                observation_effects,
            )
        };

        let mut signals = Vec::new();
        if is_new_endpoint {
            signals.extend(self.signal_evaluator.evaluate_new_endpoint(
                EndpointSignalObservation {
                    method: &key.method,
                    endpoint_template: &key.endpoint_template,
                    first_seen: &observation.timestamp,
                    status: observation.status,
                    latency_ms: observation.latency_ms,
                    user_id: observation.user_id.as_deref(),
                },
            ));
        }
        signals.extend(self.signal_evaluator.evaluate_schema_mismatch(
            SchemaMismatchSignalObservation {
                method: &key.method,
                endpoint_template: &key.endpoint_template,
                observed_at: &observation.timestamp,
                call_count: aggregate_call_count,
                previous_schema_mismatch_count,
                schema_mismatch_count: aggregate_schema_mismatch_count,
            },
        ));

        let recent = observation_effects.recent_error_window;
        signals.extend(self.signal_evaluator.evaluate_error_rate_spike(
            ErrorRateSpikeSignalObservation {
                method: &key.method,
                endpoint_template: &key.endpoint_template,
                observed_at: &observation.timestamp,
                recent_sample_count: recent.sample_count,
                recent_error_count: recent.error_count,
                baseline_sample_count: aggregate_call_count.saturating_sub(recent.sample_count),
                baseline_error_count: aggregate_error_count.saturating_sub(recent.error_count),
            },
        ));

        if let Some(principal) = principal {
            if !is_new_endpoint && !principal_seen_before {
                signals.extend(self.signal_evaluator.evaluate_principal_new_to_endpoint(
                    PrincipalNewToEndpointSignalObservation {
                        method: &key.method,
                        endpoint_template: &key.endpoint_template,
                        observed_at: &observation.timestamp,
                        principal,
                        prior_distinct_principal_count: previous_distinct_principal_count,
                    },
                ));
            }
        }

        if let Some(completed) = observation_effects.completed_volume_window {
            signals.extend(self.signal_evaluator.evaluate_volume_outlier(
                VolumeOutlierSignalObservation {
                    method: &key.method,
                    endpoint_template: &key.endpoint_template,
                    observed_at: &observation.timestamp,
                    window_call_count: completed.call_count,
                    window_duration_secs: completed.duration_secs,
                    current_rate_per_second: completed.rate_per_second,
                    baseline_window_count: completed.baseline_window_count,
                    baseline_rate_per_second: completed.baseline_rate_per_second,
                },
            ));
        }

        self.queue_signals(signals);
        self.deleted_keys.remove(&key);
        self.dirty_keys.insert(key);
        self.dirty_events += 1;

        self.dirty_events >= AGGREGATOR_BATCH_SIZE
    }

    fn endpoint_template(&mut self, method: &str, path: &str) -> String {
        let learned = self.learner.observe(path);

        if !contains_param_placeholder(&learned) {
            if let Some(existing) = self.best_existing_generalized_template(method, path) {
                return existing;
            }
        }

        if contains_param_placeholder(&learned) {
            self.merge_matching_templates(method, &learned);
        }

        learned
    }

    fn best_existing_generalized_template(&self, method: &str, path: &str) -> Option<String> {
        self.aggregates
            .keys()
            .filter(|key| key.method == method)
            .filter(|key| contains_placeholder(&key.endpoint_template))
            .filter_map(|key| {
                match_template_score(&key.endpoint_template, path)
                    .map(|score| (score, key.endpoint_template.clone()))
            })
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(_, template)| template)
    }

    fn merge_matching_templates(&mut self, method: &str, target_template: &str) {
        let target_key = EndpointKey::new(method, target_template);
        let source_keys = self
            .aggregates
            .keys()
            .filter(|key| {
                key.method == method
                    && key.endpoint_template != target_template
                    && endpoint_matches_target_template(&key.endpoint_template, target_template)
            })
            .cloned()
            .collect::<Vec<_>>();

        if source_keys.is_empty() {
            return;
        }

        let initial_timestamp = source_keys
            .iter()
            .filter_map(|key| self.aggregates.get(key))
            .map(|aggregate| aggregate.first_seen.as_str())
            .min_by(|left, right| compare_timestamps(left, right))
            .map(str::to_owned)
            .unwrap_or_else(utc_timestamp_rfc3339);

        let mut target = self
            .aggregates
            .remove(&target_key)
            .unwrap_or_else(|| EndpointAggregate::new(target_key.clone(), &initial_timestamp));

        for source_key in source_keys {
            let Some(source) = self.aggregates.remove(&source_key) else {
                continue;
            };
            target.merge_from(source);
            self.deleted_keys.insert(source_key.clone());
            self.dirty_keys.remove(&source_key);
        }

        self.deleted_keys.remove(&target_key);
        self.dirty_keys.insert(target_key.clone());
        self.aggregates.insert(target_key, target);
    }

    fn has_pending_flush(&self) -> bool {
        !self.dirty_keys.is_empty()
            || !self.deleted_keys.is_empty()
            || !self.pending_signals.is_empty()
    }

    fn mark_flushed(
        &mut self,
        deleted_keys: &[EndpointKey],
        dirty_keys: &[EndpointKey],
        signal_count: usize,
    ) {
        for key in deleted_keys {
            self.deleted_keys.remove(key);
        }
        for key in dirty_keys {
            self.dirty_keys.remove(key);
        }
        let signal_count = signal_count.min(self.pending_signals.len());
        self.pending_signals.drain(..signal_count);
        if self.dirty_keys.is_empty() {
            self.dirty_events = 0;
        }
    }

    fn queue_signals(&mut self, signals: impl IntoIterator<Item = NewSignal>) {
        for signal in signals {
            let identity = SignalIdentity::from(&signal);
            if self.queued_signal_identities.insert(identity) {
                self.pending_signals.push(signal);
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct SignalIdentity {
    signal_type: String,
    target_kind: String,
    target_key: String,
}

impl From<&NewSignal> for SignalIdentity {
    fn from(signal: &NewSignal) -> Self {
        Self {
            signal_type: signal.signal_type.clone(),
            target_kind: signal.target_kind.clone(),
            target_key: signal.target_key.clone(),
        }
    }
}

struct ObservedRequest {
    method: String,
    path: String,
    status: u16,
    latency_ms: u64,
    timestamp: String,
    user_id: Option<String>,
    payload_shape: Option<Value>,
    schema_mismatch: bool,
}

impl ObservedRequest {
    fn from_event(event: &AuditEvent) -> Option<Self> {
        if event.event_type != HTTP_REQUEST_OBSERVED {
            return None;
        }

        let method = event.payload.get("method")?.as_str()?.trim();
        let path = event.payload.get("path")?.as_str()?.trim();
        let status = parse_u16(event.payload.get("status")?)?;
        let latency_ms = parse_u64(event.payload.get("latency_ms")?)?;

        if method.is_empty() || path.is_empty() {
            return None;
        }

        Some(Self {
            method: method.to_owned(),
            path: path.to_owned(),
            status,
            latency_ms,
            timestamp: event.timestamp.clone(),
            user_id: event.actor.as_ref().map(|actor| actor.user_id.clone()),
            payload_shape: event.payload.get("payload_shape").cloned(),
            schema_mismatch: event
                .payload
                .get("schema_mismatch")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }
}

#[derive(Debug)]
struct AggregateRow {
    method: String,
    endpoint_template: String,
    first_seen: String,
    last_seen: String,
    call_count: i64,
    schema_mismatch_count: i64,
    latency_count: i64,
    latency_samples_json: String,
}

#[derive(Debug)]
struct StatusRow {
    method: String,
    endpoint_template: String,
    status: i64,
    count: i64,
}

#[derive(Debug)]
struct PrincipalRow {
    method: String,
    endpoint_template: String,
    user_id: String,
    first_seen: String,
    last_seen: String,
}

#[derive(Debug)]
struct PayloadShapeStatRow {
    method: String,
    endpoint_template: String,
    shape_observation_count: i64,
}

#[derive(Debug)]
struct PayloadShapeSampleRow {
    method: String,
    endpoint_template: String,
    observed_at: String,
    shape_hash: String,
    shape_json: String,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct TemplateMatchScore {
    exact_literals: usize,
    wildcard_segments: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct LatencyPercentiles {
    p50_ms: u64,
    p95_ms: u64,
    p99_ms: u64,
}

impl LatencyPercentiles {
    fn from_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self {
                p50_ms: 0,
                p95_ms: 0,
                p99_ms: 0,
            };
        }

        let mut sorted = samples.to_vec();
        sorted.sort_unstable();

        Self {
            p50_ms: percentile(&sorted, 50),
            p95_ms: percentile(&sorted, 95),
            p99_ms: percentile(&sorted, 99),
        }
    }
}

fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        "#,
    )?;
    connection.execute_batch(CREATE_SCHEMA_SQL)?;
    ensure_discovery_endpoint_aggregate_column(
        connection,
        "schema_mismatch_count",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    signals::configure_connection(connection)
}

fn ensure_discovery_endpoint_aggregate_column(
    connection: &Connection,
    column_name: &str,
    column_type: &str,
) -> rusqlite::Result<()> {
    if discovery_endpoint_aggregates_has_column(connection, column_name)? {
        return Ok(());
    }

    let sql =
        format!("ALTER TABLE discovery_endpoint_aggregates ADD COLUMN {column_name} {column_type}");
    connection.execute(&sql, [])?;
    Ok(())
}

fn discovery_endpoint_aggregates_has_column(
    connection: &Connection,
    column_name: &str,
) -> rusqlite::Result<bool> {
    let mut statement = connection.prepare("PRAGMA table_info(discovery_endpoint_aggregates)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;

    for column in columns {
        if column? == column_name {
            return Ok(true);
        }
    }

    Ok(false)
}

fn configure_payload_capture_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(CREATE_PAYLOAD_CAPTURE_SCHEMA_SQL)
}

fn load_aggregate_rows(
    connection: &Connection,
) -> Result<Vec<AggregateRow>, EndpointAggregatorLoadError> {
    let mut statement = connection.prepare(
        r#"
        SELECT
            method,
            endpoint_template,
            first_seen,
            last_seen,
            call_count,
            schema_mismatch_count,
            latency_count,
            latency_samples_json
        FROM discovery_endpoint_aggregates
        "#,
    )?;

    let rows = statement
        .query_map([], |row| {
            Ok(AggregateRow {
                method: row.get(0)?,
                endpoint_template: row.get(1)?,
                first_seen: row.get(2)?,
                last_seen: row.get(3)?,
                call_count: row.get(4)?,
                schema_mismatch_count: row.get(5)?,
                latency_count: row.get(6)?,
                latency_samples_json: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(EndpointAggregatorLoadError::from)?;
    Ok(rows)
}

fn load_status_rows(
    connection: &Connection,
) -> Result<Vec<StatusRow>, EndpointAggregatorLoadError> {
    let mut statement = connection.prepare(
        r#"
        SELECT method, endpoint_template, status, count
        FROM discovery_endpoint_status_counts
        "#,
    )?;

    let rows = statement
        .query_map([], |row| {
            Ok(StatusRow {
                method: row.get(0)?,
                endpoint_template: row.get(1)?,
                status: row.get(2)?,
                count: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(EndpointAggregatorLoadError::from)?;
    Ok(rows)
}

fn load_principal_rows(
    connection: &Connection,
) -> Result<Vec<PrincipalRow>, EndpointAggregatorLoadError> {
    let mut statement = connection.prepare(
        r#"
        SELECT method, endpoint_template, user_id, first_seen, last_seen
        FROM discovery_endpoint_principals
        "#,
    )?;

    let rows = statement
        .query_map([], |row| {
            Ok(PrincipalRow {
                method: row.get(0)?,
                endpoint_template: row.get(1)?,
                user_id: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(EndpointAggregatorLoadError::from)?;
    Ok(rows)
}

fn load_payload_shape_stat_rows(
    connection: &Connection,
) -> Result<Vec<PayloadShapeStatRow>, EndpointAggregatorLoadError> {
    let mut statement = connection.prepare(
        r#"
        SELECT method, endpoint_template, shape_observation_count
        FROM discovery_payload_shape_stats
        "#,
    )?;

    let rows = statement
        .query_map([], |row| {
            Ok(PayloadShapeStatRow {
                method: row.get(0)?,
                endpoint_template: row.get(1)?,
                shape_observation_count: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(EndpointAggregatorLoadError::from)?;
    Ok(rows)
}

fn load_payload_shape_sample_rows(
    connection: &Connection,
) -> Result<Vec<PayloadShapeSampleRow>, EndpointAggregatorLoadError> {
    let mut statement = connection.prepare(
        r#"
        SELECT method, endpoint_template, observed_at, shape_hash, shape_json
        FROM discovery_payload_shape_samples
        ORDER BY method, endpoint_template, sample_slot
        "#,
    )?;

    let rows = statement
        .query_map([], |row| {
            Ok(PayloadShapeSampleRow {
                method: row.get(0)?,
                endpoint_template: row.get(1)?,
                observed_at: row.get(2)?,
                shape_hash: row.get(3)?,
                shape_json: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(EndpointAggregatorLoadError::from)?;
    Ok(rows)
}

fn write_flush(
    connection: &mut Connection,
    deleted_keys: &[EndpointKey],
    dirty_aggregates: &[EndpointAggregate],
    pending_signals: &[NewSignal],
    payload_capture_enabled: bool,
) -> Result<Vec<signals::Signal>, EndpointAggregatorFlushError> {
    let transaction = connection.transaction()?;

    for key in deleted_keys {
        delete_key(&transaction, key, payload_capture_enabled)?;
    }

    for aggregate in dirty_aggregates {
        upsert_aggregate(&transaction, aggregate, payload_capture_enabled)?;
    }

    let opened_signals = signals::insert_signals(&transaction, pending_signals)?;

    transaction.commit()?;
    Ok(opened_signals)
}

fn delete_key(
    connection: &Connection,
    key: &EndpointKey,
    payload_capture_enabled: bool,
) -> rusqlite::Result<()> {
    if payload_capture_enabled {
        connection.execute(
            r#"
            DELETE FROM discovery_payload_shape_samples
            WHERE method = ?1 AND endpoint_template = ?2
            "#,
            params![key.method.as_str(), key.endpoint_template.as_str()],
        )?;
        connection.execute(
            r#"
            DELETE FROM discovery_payload_shape_stats
            WHERE method = ?1 AND endpoint_template = ?2
            "#,
            params![key.method.as_str(), key.endpoint_template.as_str()],
        )?;
    }

    connection.execute(
        r#"
        DELETE FROM discovery_endpoint_status_counts
        WHERE method = ?1 AND endpoint_template = ?2
        "#,
        params![key.method.as_str(), key.endpoint_template.as_str()],
    )?;
    connection.execute(
        r#"
        DELETE FROM discovery_endpoint_principals
        WHERE method = ?1 AND endpoint_template = ?2
        "#,
        params![key.method.as_str(), key.endpoint_template.as_str()],
    )?;
    connection.execute(
        r#"
        DELETE FROM discovery_endpoint_aggregates
        WHERE method = ?1 AND endpoint_template = ?2
        "#,
        params![key.method.as_str(), key.endpoint_template.as_str()],
    )?;
    Ok(())
}

fn upsert_aggregate(
    connection: &Connection,
    aggregate: &EndpointAggregate,
    payload_capture_enabled: bool,
) -> Result<(), EndpointAggregatorFlushError> {
    let percentiles = aggregate.latency_percentiles();
    let latency_samples_json = serde_json::to_string(&aggregate.latency_samples)?;
    let distinct_principal_count = i64_from_usize(aggregate.principals.len());

    connection.execute(
        UPSERT_AGGREGATE_SQL,
        params![
            aggregate.key.method.as_str(),
            aggregate.key.endpoint_template.as_str(),
            aggregate.first_seen.as_str(),
            aggregate.last_seen.as_str(),
            i64_from_u64(aggregate.call_count),
            i64_from_u64(aggregate.schema_mismatch_count),
            i64_from_u64(aggregate.latency_count),
            i64_from_u64(percentiles.p50_ms),
            i64_from_u64(percentiles.p95_ms),
            i64_from_u64(percentiles.p99_ms),
            latency_samples_json,
            distinct_principal_count,
            utc_timestamp_rfc3339(),
        ],
    )?;

    connection.execute(
        r#"
        DELETE FROM discovery_endpoint_status_counts
        WHERE method = ?1 AND endpoint_template = ?2
        "#,
        params![
            aggregate.key.method.as_str(),
            aggregate.key.endpoint_template.as_str()
        ],
    )?;
    for (status, count) in &aggregate.status_counts {
        connection.execute(
            r#"
            INSERT INTO discovery_endpoint_status_counts (
                method, endpoint_template, status, count
            ) VALUES (?1, ?2, ?3, ?4)
            "#,
            params![
                aggregate.key.method.as_str(),
                aggregate.key.endpoint_template.as_str(),
                i64::from(*status),
                i64_from_u64(*count),
            ],
        )?;
    }

    connection.execute(
        r#"
        DELETE FROM discovery_endpoint_principals
        WHERE method = ?1 AND endpoint_template = ?2
        "#,
        params![
            aggregate.key.method.as_str(),
            aggregate.key.endpoint_template.as_str()
        ],
    )?;
    for (user_id, seen) in &aggregate.principals {
        connection.execute(
            r#"
            INSERT INTO discovery_endpoint_principals (
                method, endpoint_template, user_id, first_seen, last_seen
            ) VALUES (?1, ?2, ?3, ?4, ?5)
            "#,
            params![
                aggregate.key.method.as_str(),
                aggregate.key.endpoint_template.as_str(),
                user_id,
                seen.first_seen.as_str(),
                seen.last_seen.as_str(),
            ],
        )?;
    }

    if payload_capture_enabled {
        upsert_payload_shape_samples(connection, aggregate)?;
    }

    Ok(())
}

fn upsert_payload_shape_samples(
    connection: &Connection,
    aggregate: &EndpointAggregate,
) -> Result<(), EndpointAggregatorFlushError> {
    connection.execute(
        r#"
        DELETE FROM discovery_payload_shape_samples
        WHERE method = ?1 AND endpoint_template = ?2
        "#,
        params![
            aggregate.key.method.as_str(),
            aggregate.key.endpoint_template.as_str()
        ],
    )?;

    for (slot, sample) in aggregate.payload_shape_samples.iter().enumerate() {
        connection.execute(
            r#"
            INSERT INTO discovery_payload_shape_samples (
                method,
                endpoint_template,
                sample_slot,
                observed_at,
                shape_hash,
                shape_json
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                aggregate.key.method.as_str(),
                aggregate.key.endpoint_template.as_str(),
                i64_from_usize(slot),
                sample.observed_at.as_str(),
                sample.shape_hash.as_str(),
                serde_json::to_string(&sample.shape)?,
            ],
        )?;
    }

    if aggregate.payload_shape_observation_count > 0 {
        connection.execute(
            r#"
            INSERT INTO discovery_payload_shape_stats (
                method,
                endpoint_template,
                shape_observation_count,
                updated_at
            ) VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(method, endpoint_template) DO UPDATE SET
                shape_observation_count = excluded.shape_observation_count,
                updated_at = excluded.updated_at
            "#,
            params![
                aggregate.key.method.as_str(),
                aggregate.key.endpoint_template.as_str(),
                i64_from_u64(aggregate.payload_shape_observation_count),
                utc_timestamp_rfc3339(),
            ],
        )?;
    } else {
        connection.execute(
            r#"
            DELETE FROM discovery_payload_shape_stats
            WHERE method = ?1 AND endpoint_template = ?2
            "#,
            params![
                aggregate.key.method.as_str(),
                aggregate.key.endpoint_template.as_str()
            ],
        )?;
    }

    Ok(())
}

fn flusher_loop(
    shared: Arc<EndpointAggregatorShared>,
    shutdown_rx: mpsc::Receiver<()>,
    flush_interval: StdDuration,
) {
    loop {
        match shutdown_rx.recv_timeout(flush_interval) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                shared.flush_state();
                return;
            }
            Err(RecvTimeoutError::Timeout) => shared.flush_state(),
        }
    }
}

fn take_mutex_value<T>(
    mutex: &Mutex<Option<T>>,
    lock_name: &'static str,
    shared: &EndpointAggregatorShared,
) -> Option<T> {
    match mutex.lock() {
        Ok(mut guard) => guard.take(),
        Err(poisoned) => {
            ::metrics::counter!(
                LOCK_POISON_RECOVERIES_TOTAL,
                "component" => "discovery",
                "lock" => lock_name
            )
            .increment(1);
            tracing::error!(
                path = %shared.path.display(),
                lock = lock_name,
                "discovery aggregator shutdown lock poisoned; recovering"
            );
            let mut guard = poisoned.into_inner();
            guard.take()
        }
    }
}

fn parse_u16(value: &Value) -> Option<u16> {
    parse_u64(value).and_then(|value| u16::try_from(value).ok())
}

fn parse_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_i64().and_then(|value| u64::try_from(value).ok()))
        .or_else(|| {
            let value = value.as_f64()?;
            if value.is_finite() && value.fract() == 0.0 && value >= 0.0 && value <= u64::MAX as f64
            {
                Some(value as u64)
            } else {
                None
            }
        })
}

fn is_error_status(status: u16) -> bool {
    (400..=599).contains(&status)
}

fn timestamp_seconds(timestamp: &str) -> Option<i64> {
    OffsetDateTime::parse(timestamp, &Rfc3339)
        .map(|timestamp| timestamp.unix_timestamp())
        .ok()
}

fn contains_placeholder(template: &str) -> bool {
    template.contains(ID_PLACEHOLDER) || template.contains(PARAM_PLACEHOLDER)
}

fn contains_param_placeholder(template: &str) -> bool {
    template.contains(PARAM_PLACEHOLDER)
}

fn match_template_score(template: &str, path: &str) -> Option<TemplateMatchScore> {
    let template_segments = split_path(template);
    let path_segments = split_path(path);

    if template_segments.len() != path_segments.len() {
        return None;
    }

    let mut score = TemplateMatchScore {
        exact_literals: 0,
        wildcard_segments: 0,
    };

    for (template_segment, path_segment) in template_segments.iter().zip(path_segments.iter()) {
        match *template_segment {
            PARAM_PLACEHOLDER => score.wildcard_segments += 1,
            ID_PLACEHOLDER if is_id_segment(path_segment) => score.wildcard_segments += 1,
            value if value == *path_segment => score.exact_literals += 1,
            _ => return None,
        }
    }

    Some(score)
}

fn endpoint_matches_target_template(endpoint_template: &str, target_template: &str) -> bool {
    let endpoint_segments = split_path(endpoint_template);
    let target_segments = split_path(target_template);

    if endpoint_segments.len() != target_segments.len() {
        return false;
    }

    endpoint_segments.iter().zip(target_segments.iter()).all(
        |(endpoint_segment, target_segment)| match *target_segment {
            PARAM_PLACEHOLDER => {
                *endpoint_segment == PARAM_PLACEHOLDER
                    || (*endpoint_segment != ID_PLACEHOLDER
                        && !endpoint_segment.starts_with('{')
                        && !endpoint_segment.ends_with('}'))
            }
            ID_PLACEHOLDER => {
                *endpoint_segment == ID_PLACEHOLDER || is_id_segment(endpoint_segment)
            }
            target => target == *endpoint_segment,
        },
    )
}

fn split_path(path: &str) -> Vec<&str> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let path = path.strip_prefix('/').unwrap_or(path);

    if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    }
}

fn is_id_segment(segment: &str) -> bool {
    let path = format!("/{segment}");
    template_stateless(&path) == "/{id}"
}

fn offer_latency_sample(
    observation_count: u64,
    latency_ms: u64,
    samples: &mut Vec<u64>,
    sample_limit: usize,
) {
    if samples.len() < sample_limit {
        samples.push(latency_ms);
        return;
    }

    let slot = deterministic_sample_slot(observation_count, latency_ms) % observation_count.max(1);
    if slot < sample_limit as u64 {
        samples[slot as usize] = latency_ms;
    }
}

fn offer_payload_shape_sample(
    observation_count: u64,
    sample: PayloadShapeSample,
    samples: &mut Vec<PayloadShapeSample>,
    sample_limit: usize,
) {
    if samples.len() < sample_limit {
        samples.push(sample);
        return;
    }

    let slot = deterministic_sample_slot(
        observation_count,
        hash_prefix_u64(&sample.shape_hash).rotate_left(17),
    ) % observation_count.max(1);
    if slot < sample_limit as u64 {
        samples[slot as usize] = sample;
    }
}

fn deterministic_sample_slot(observation_count: u64, sample_seed: u64) -> u64 {
    let mut value = observation_count ^ sample_seed.rotate_left(13);
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

fn hash_prefix_u64(hash: &str) -> u64 {
    let hex = hash.strip_prefix("sha256:").unwrap_or(hash);
    let prefix = hex.get(..16).unwrap_or(hex);
    u64::from_str_radix(prefix, 16).unwrap_or(0)
}

fn percentile(sorted_samples: &[u64], percentile: usize) -> u64 {
    debug_assert!(!sorted_samples.is_empty());
    let rank = ((percentile * sorted_samples.len()).div_ceil(100)).saturating_sub(1);
    sorted_samples[rank.min(sorted_samples.len() - 1)]
}

fn timestamp_before(left: &str, right: &str) -> bool {
    compare_timestamps(left, right).is_lt()
}

fn timestamp_after(left: &str, right: &str) -> bool {
    compare_timestamps(left, right).is_gt()
}

fn compare_timestamps(left: &str, right: &str) -> std::cmp::Ordering {
    match (
        OffsetDateTime::parse(left, &Rfc3339),
        OffsetDateTime::parse(right, &Rfc3339),
    ) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => left.cmp(right),
    }
}

fn utc_timestamp_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current UTC timestamp should format as RFC 3339")
}

fn non_negative_i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}

fn i64_from_u64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn i64_from_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::Arc,
        time::Instant,
    };

    use serde_json::json;

    use super::*;
    use crate::audit::{Actor, AuditLog};
    use crate::discovery::signals::SignalDetectorConfig;

    #[test]
    fn varied_parameter_noise_rolls_up_to_stable_endpoint_rows() {
        let db = TempDb::new("path-noise");
        let sink = aggregator_sink(&db.path);

        for (index, path) in [
            "/v1/widgets/123",
            "/v1/widgets/550e8400-e29b-41d4-a716-446655440000",
            "/v1/widgets/alpha-widget",
            "/v1/widgets/beta_widget",
            "/v1/widgets/gamma.widget",
            "/v1/widgets/delta~widget",
        ]
        .iter()
        .enumerate()
        {
            sink.emit(&observed_event(
                "GET",
                path,
                200,
                10,
                Some("user-1"),
                timestamp(index),
            ));
        }

        sink.flush_for_test();

        assert_eq!(
            aggregate_counts(&db.path),
            vec![
                ("GET".to_owned(), "/v1/widgets/{id}".to_owned(), 2),
                ("GET".to_owned(), "/v1/widgets/{param}".to_owned(), 4),
            ]
        );
    }

    #[test]
    fn status_timestamps_and_latency_percentiles_accumulate() {
        let db = TempDb::new("status-latency");
        let sink = aggregator_sink(&db.path);

        for (path, status, latency, timestamp) in [
            ("/reports/123", 200, 10, "2024-06-01T12:00:01Z"),
            ("/reports/456", 500, 30, "2024-06-01T12:00:03Z"),
            ("/reports/789", 200, 20, "2024-06-01T12:00:02Z"),
        ] {
            sink.emit(&observed_event(
                "GET",
                path,
                status,
                latency,
                Some("user-1"),
                timestamp,
            ));
        }

        sink.flush_for_test();

        let aggregate = aggregate_snapshot(&db.path, "GET", "/reports/{id}");
        assert_eq!(aggregate.first_seen, "2024-06-01T12:00:01Z");
        assert_eq!(aggregate.last_seen, "2024-06-01T12:00:03Z");
        assert_eq!(aggregate.call_count, 3);
        assert_eq!(aggregate.latency_p50_ms, 20);
        assert_eq!(aggregate.latency_p95_ms, 30);
        assert_eq!(aggregate.latency_p99_ms, 30);
        assert_eq!(
            status_counts(&db.path, "GET", "/reports/{id}"),
            BTreeMap::from([(200, 2), (500, 1)])
        );
    }

    #[test]
    fn schema_mismatch_true_events_roll_up_per_endpoint() {
        let db = TempDb::new("schema-mismatch-rollup");
        let sink = aggregator_sink(&db.path);

        sink.emit(&observed_event_with_schema_mismatch(
            "GET",
            "/reports/123",
            200,
            10,
            Some("user-1"),
            "2024-06-01T12:00:00Z",
            true,
        ));
        sink.emit(&observed_event_with_schema_mismatch(
            "GET",
            "/reports/456",
            200,
            12,
            Some("user-1"),
            "2024-06-01T12:00:01Z",
            false,
        ));
        sink.emit(&observed_event(
            "GET",
            "/reports/789",
            200,
            14,
            Some("user-1"),
            "2024-06-01T12:00:02Z",
        ));
        sink.flush_for_test();

        let aggregate = aggregate_snapshot(&db.path, "GET", "/reports/{id}");
        assert_eq!(aggregate.call_count, 3);
        assert_eq!(aggregate.schema_mismatch_count, 1);
    }

    #[test]
    fn distinct_principals_are_tracked_exactly_and_ignore_unauthenticated_requests() {
        let db = TempDb::new("principals");
        let sink = aggregator_sink(&db.path);

        for (index, user_id) in [
            Some("alice"),
            Some("bob"),
            Some("alice"),
            None,
            Some("charlie"),
        ]
        .into_iter()
        .enumerate()
        {
            sink.emit(&observed_event(
                "POST",
                "/sessions/123",
                201,
                5,
                user_id,
                timestamp(index),
            ));
        }

        sink.flush_for_test();

        let aggregate = aggregate_snapshot(&db.path, "POST", "/sessions/{id}");
        assert_eq!(aggregate.call_count, 5);
        assert_eq!(aggregate.distinct_principal_count, 3);
        assert_eq!(
            principal_ids(&db.path, "POST", "/sessions/{id}"),
            vec!["alice".to_owned(), "bob".to_owned(), "charlie".to_owned(),]
        );
    }

    #[test]
    fn persisted_state_loads_after_restart_and_continues_accumulating() {
        let db = TempDb::new("restart");

        {
            let sink = aggregator_sink(&db.path);
            sink.emit(&observed_event(
                "GET",
                "/accounts/123",
                200,
                7,
                Some("alice"),
                "2024-06-01T12:00:00Z",
            ));
            sink.emit(&observed_event(
                "GET",
                "/accounts/456",
                404,
                9,
                Some("bob"),
                "2024-06-01T12:00:01Z",
            ));
        }

        {
            let sink = aggregator_sink(&db.path);
            sink.emit(&observed_event(
                "GET",
                "/accounts/789",
                200,
                11,
                Some("alice"),
                "2024-06-01T12:00:02Z",
            ));
            sink.flush_for_test();
        }

        let aggregate = aggregate_snapshot(&db.path, "GET", "/accounts/{id}");
        assert_eq!(aggregate.call_count, 3);
        assert_eq!(aggregate.distinct_principal_count, 2);
        assert_eq!(
            status_counts(&db.path, "GET", "/accounts/{id}"),
            BTreeMap::from([(200, 2), (404, 1)])
        );
    }

    #[test]
    fn new_endpoint_seen_signal_fires_once_for_genuinely_new_endpoint() {
        let db = TempDb::new("new-endpoint-signal-once");
        let sink = aggregator_sink(&db.path);

        sink.emit(&observed_event(
            "GET",
            "/signals/123",
            200,
            11,
            Some("alice"),
            "2024-06-01T12:00:00Z",
        ));
        sink.emit(&observed_event(
            "GET",
            "/signals/456",
            200,
            9,
            Some("bob"),
            "2024-06-01T12:00:01Z",
        ));
        sink.flush_for_test();

        let rows = signal_rows_by_type(&db.path, "new_endpoint_seen");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].signal_type, "new_endpoint_seen");
        assert_eq!(rows[0].target_kind, "endpoint");
        assert_eq!(rows[0].target_key, "GET /signals/{id}");
        assert_eq!(rows[0].state, "open");
        assert!(
            rows[0].explanation.contains("GET /signals/{id}"),
            "signal explanation should name the endpoint: {}",
            rows[0].explanation
        );

        let evidence: Value =
            serde_json::from_str(&rows[0].evidence_json).expect("evidence should be JSON");
        assert_eq!(evidence["first_seen"], json!("2024-06-01T12:00:00Z"));
        assert_eq!(evidence["initial_call_count"], json!(1));
        assert_eq!(evidence["initial_principal"], json!("alice"));
    }

    #[test]
    fn new_endpoint_seen_signal_does_not_backfill_preexisting_discovery_rows() {
        let db = TempDb::new("new-endpoint-signal-preexisting");

        drop(aggregator_sink(&db.path));
        insert_aggregate_without_signal(&db.path, "GET", "/preexisting/{id}");

        {
            let sink = aggregator_sink(&db.path);
            sink.emit(&observed_event(
                "GET",
                "/preexisting/456",
                200,
                9,
                Some("bob"),
                "2024-06-01T12:00:01Z",
            ));
            sink.flush_for_test();
        }

        assert_eq!(
            signal_rows_by_type(&db.path, "new_endpoint_seen"),
            Vec::<SignalRow>::new()
        );
    }

    #[test]
    fn schema_mismatch_signal_fires_once_when_count_crosses_threshold() {
        let db = TempDb::new("schema-mismatch-signal");
        let sink = aggregator_sink_with_signal_config(
            &db.path,
            SignalDetectorConfig {
                schema_mismatch_threshold: 2,
                ..SignalDetectorConfig::default()
            },
        );

        sink.emit(&observed_event_with_schema_mismatch(
            "GET",
            "/schemas/123",
            200,
            10,
            Some("alice"),
            "2024-06-01T12:00:00Z",
            true,
        ));
        sink.flush_for_test();
        assert!(
            signal_rows_by_type(&db.path, "schema_mismatch").is_empty(),
            "schema mismatch signal should wait until the configured count threshold is crossed"
        );

        sink.emit(&observed_event_with_schema_mismatch(
            "GET",
            "/schemas/456",
            200,
            12,
            Some("alice"),
            "2024-06-01T12:00:01Z",
            true,
        ));
        sink.flush_for_test();

        let rows = signal_rows_by_type(&db.path, "schema_mismatch");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target_kind, "endpoint");
        assert_eq!(rows[0].target_key, "GET /schemas/{id}");
        assert!(rows[0].explanation.contains("2 schema mismatches"));
        let evidence: Value =
            serde_json::from_str(&rows[0].evidence_json).expect("evidence should be JSON");
        assert_eq!(evidence["schema_mismatch_count"], json!(2));
        assert_eq!(evidence["call_count"], json!(2));
        assert_eq!(evidence["threshold"], json!(2));

        sink.emit(&observed_event_with_schema_mismatch(
            "GET",
            "/schemas/789",
            200,
            11,
            Some("alice"),
            "2024-06-01T12:00:02Z",
            true,
        ));
        sink.flush_for_test();
        assert_eq!(
            signal_rows_by_type(&db.path, "schema_mismatch").len(),
            1,
            "schema mismatch signal should be idempotent per endpoint"
        );
    }

    #[test]
    fn error_rate_spike_signal_waits_for_sample_floor_then_fires_once() {
        let db = TempDb::new("error-rate-spike-signal");
        let sink = aggregator_sink_with_signal_config(
            &db.path,
            SignalDetectorConfig {
                error_rate_spike_threshold: 0.40,
                ..SignalDetectorConfig::default()
            },
        );

        for index in 0..20 {
            sink.emit(&observed_event(
                "GET",
                "/errors/steady",
                200,
                10,
                Some("alice"),
                timestamp_at(index),
            ));
        }
        for index in 20..39 {
            sink.emit(&observed_event(
                "GET",
                "/errors/steady",
                500,
                10,
                Some("alice"),
                timestamp_at(index),
            ));
        }
        sink.flush_for_test();
        assert!(
            signal_rows_by_type(&db.path, "error_rate_spike").is_empty(),
            "error rate spike signal should wait for both recent and baseline sample floors"
        );

        sink.emit(&observed_event(
            "GET",
            "/errors/steady",
            500,
            10,
            Some("alice"),
            timestamp_at(39),
        ));
        sink.flush_for_test();

        let rows = signal_rows_by_type(&db.path, "error_rate_spike");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target_key, "GET /errors/steady");
        assert!(rows[0].explanation.contains("100.0%"));
        let evidence: Value =
            serde_json::from_str(&rows[0].evidence_json).expect("evidence should be JSON");
        assert_eq!(evidence["recent_sample_count"], json!(20));
        assert_eq!(evidence["recent_error_count"], json!(20));
        assert_eq!(evidence["baseline_sample_count"], json!(20));
        assert_eq!(evidence["baseline_error_count"], json!(0));
        assert_eq!(evidence["threshold_delta"], json!(0.40));

        for index in 40..45 {
            sink.emit(&observed_event(
                "GET",
                "/errors/steady",
                500,
                10,
                Some("alice"),
                timestamp_at(index),
            ));
        }
        sink.flush_for_test();
        assert_eq!(
            signal_rows_by_type(&db.path, "error_rate_spike").len(),
            1,
            "error rate spike signal should be idempotent per endpoint"
        );
    }

    #[test]
    fn principal_new_to_endpoint_signal_uses_existing_principal_history() {
        let db = TempDb::new("principal-new-signal");
        let sink = aggregator_sink(&db.path);

        sink.emit(&observed_event(
            "POST",
            "/principal-pairs/123",
            200,
            10,
            Some("alice"),
            "2024-06-01T12:00:00Z",
        ));
        sink.flush_for_test();
        assert!(
            signal_rows_by_type(&db.path, "principal_new_to_endpoint").is_empty(),
            "principal-new signal should not double-fire with new_endpoint_seen"
        );

        sink.emit(&observed_event(
            "POST",
            "/principal-pairs/456",
            200,
            10,
            Some("bob"),
            "2024-06-01T12:00:01Z",
        ));
        sink.flush_for_test();

        let rows = signal_rows_by_type(&db.path, "principal_new_to_endpoint");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target_kind, "principal_endpoint");
        assert_eq!(rows[0].target_key, "POST /principal-pairs/{id} bob");
        assert!(rows[0].explanation.contains("principal bob"));
        let evidence: Value =
            serde_json::from_str(&rows[0].evidence_json).expect("evidence should be JSON");
        assert_eq!(evidence["principal"], json!("bob"));
        assert_eq!(evidence["prior_distinct_principal_count"], json!(1));
        assert_eq!(evidence["threshold"], json!(1));

        sink.emit(&observed_event(
            "POST",
            "/principal-pairs/789",
            200,
            10,
            Some("bob"),
            "2024-06-01T12:00:02Z",
        ));
        sink.flush_for_test();
        assert_eq!(
            signal_rows_by_type(&db.path, "principal_new_to_endpoint").len(),
            1,
            "same principal/endpoint pair should not create duplicate signals"
        );
    }

    #[test]
    fn principal_new_to_endpoint_signal_respects_prior_principal_threshold() {
        let db = TempDb::new("principal-new-threshold");
        let sink = aggregator_sink_with_signal_config(
            &db.path,
            SignalDetectorConfig {
                principal_new_to_endpoint_threshold: 2,
                ..SignalDetectorConfig::default()
            },
        );

        sink.emit(&observed_event(
            "GET",
            "/threshold-principals/123",
            200,
            10,
            Some("alice"),
            "2024-06-01T12:00:00Z",
        ));
        sink.emit(&observed_event(
            "GET",
            "/threshold-principals/456",
            200,
            10,
            Some("bob"),
            "2024-06-01T12:00:01Z",
        ));
        sink.flush_for_test();
        assert!(
            signal_rows_by_type(&db.path, "principal_new_to_endpoint").is_empty(),
            "one prior principal is below the configured threshold of two"
        );

        sink.emit(&observed_event(
            "GET",
            "/threshold-principals/789",
            200,
            10,
            Some("charlie"),
            "2024-06-01T12:00:02Z",
        ));
        sink.flush_for_test();
        assert_eq!(
            signal_rows_by_type(&db.path, "principal_new_to_endpoint").len(),
            1
        );
    }

    #[test]
    fn volume_outlier_signal_waits_for_baseline_then_fires_once_on_surge() {
        let db = TempDb::new("volume-outlier-surge");
        let sink = aggregator_sink_with_signal_config(
            &db.path,
            SignalDetectorConfig {
                volume_outlier_threshold: 3.0,
                ..SignalDetectorConfig::default()
            },
        );

        for index in 0..60 {
            sink.emit(&observed_event(
                "GET",
                "/volume/surge",
                200,
                10,
                Some("alice"),
                timestamp_at(index),
            ));
        }
        sink.flush_for_test();
        assert!(
            signal_rows_by_type(&db.path, "volume_outlier").is_empty(),
            "volume outlier signal should wait for baseline windows before evaluating"
        );

        for _ in 0..20 {
            sink.emit(&observed_event(
                "GET",
                "/volume/surge",
                200,
                10,
                Some("alice"),
                "2024-06-01T12:01:00Z",
            ));
        }
        sink.flush_for_test();

        let rows = signal_rows_by_type(&db.path, "volume_outlier");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].target_key, "GET /volume/surge");
        assert!(rows[0].explanation.contains("volume increase"));
        let evidence: Value =
            serde_json::from_str(&rows[0].evidence_json).expect("evidence should be JSON");
        assert_eq!(evidence["direction"], json!("increase"));
        assert_eq!(evidence["window_call_count"], json!(20));
        assert_eq!(evidence["baseline_window_count"], json!(3));
        assert_eq!(evidence["threshold_multiple"], json!(3.0));

        for _ in 0..20 {
            sink.emit(&observed_event(
                "GET",
                "/volume/surge",
                200,
                10,
                Some("alice"),
                "2024-06-01T12:01:01Z",
            ));
        }
        sink.flush_for_test();
        assert_eq!(
            signal_rows_by_type(&db.path, "volume_outlier").len(),
            1,
            "volume outlier signal should be idempotent per endpoint"
        );
    }

    #[test]
    fn volume_outlier_signal_fires_on_slow_window_decrease() {
        let db = TempDb::new("volume-outlier-decrease");
        let sink = aggregator_sink_with_signal_config(
            &db.path,
            SignalDetectorConfig {
                volume_outlier_threshold: 3.0,
                ..SignalDetectorConfig::default()
            },
        );

        for index in 0..60 {
            sink.emit(&observed_event(
                "GET",
                "/volume/decrease",
                200,
                10,
                Some("alice"),
                timestamp_at(index),
            ));
        }
        for index in 0..20 {
            sink.emit(&observed_event(
                "GET",
                "/volume/decrease",
                200,
                10,
                Some("alice"),
                timestamp_at(120 + index * 10),
            ));
        }
        sink.flush_for_test();

        let rows = signal_rows_by_type(&db.path, "volume_outlier");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].explanation.contains("volume decrease"));
        let evidence: Value =
            serde_json::from_str(&rows[0].evidence_json).expect("evidence should be JSON");
        assert_eq!(evidence["direction"], json!("decrease"));
    }

    #[test]
    fn learned_templates_are_reused_after_restart_without_new_literal_fragments() {
        let db = TempDb::new("restart-template");

        {
            let sink = aggregator_sink(&db.path);
            for (index, slug) in ["alpha", "beta", "gamma", "delta"].into_iter().enumerate() {
                sink.emit(&observed_event(
                    "GET",
                    &format!("/catalog/{slug}"),
                    200,
                    10,
                    Some("user-1"),
                    timestamp(index),
                ));
            }
            sink.flush_for_test();
        }

        {
            let sink = aggregator_sink(&db.path);
            sink.emit(&observed_event(
                "GET",
                "/catalog/epsilon",
                200,
                12,
                Some("user-2"),
                "2024-06-01T12:00:10Z",
            ));
            sink.flush_for_test();
        }

        assert_eq!(
            aggregate_counts(&db.path),
            vec![("GET".to_owned(), "/catalog/{param}".to_owned(), 5)]
        );
    }

    #[test]
    fn payload_capture_disabled_does_not_create_capture_tables() {
        let db = TempDb::new("payload-disabled");
        let sink = aggregator_sink(&db.path);

        sink.emit(&observed_event_with_payload_shape(
            "POST",
            "/widgets/123",
            200,
            10,
            Some("user-1"),
            "2024-06-01T12:00:00Z",
            json!({
                "query_params": [{"name": "debug", "redacted": false, "value_type": "string"}],
                "json_body": {"top_level_keys": [{"name": "name", "redacted": false}]}
            }),
        ));
        sink.flush_for_test();

        assert!(!table_exists(&db.path, "discovery_payload_shape_samples"));
        assert!(!table_exists(&db.path, "discovery_payload_shape_stats"));
    }

    #[test]
    fn payload_capture_enabled_persists_shapes_by_method_and_endpoint_template() {
        let db = TempDb::new("payload-enabled");
        let sink = aggregator_sink_with_payload_capture(&db.path);

        sink.emit(&observed_event_with_payload_shape(
            "POST",
            "/widgets/123?debug=true",
            201,
            15,
            Some("user-1"),
            "2024-06-01T12:00:00Z",
            json!({
                "query_params": [{"name": "debug", "redacted": false, "value_type": "string"}],
                "json_body": {"top_level_keys": [{"name": "name", "redacted": false}]}
            }),
        ));
        sink.flush_for_test();

        let rows = payload_shape_rows(&db.path);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].method, "POST");
        assert_eq!(rows[0].endpoint_template, "/widgets/{id}");
        assert_eq!(rows[0].sample_slot, 0);
        assert_eq!(rows[0].observed_at, "2024-06-01T12:00:00Z");
        assert!(rows[0].shape_hash.starts_with("sha256:"));
        assert_eq!(
            serde_json::from_str::<Value>(&rows[0].shape_json).expect("shape JSON should parse"),
            json!({
                "query_params": [{"name": "debug", "redacted": false, "value_type": "string"}],
                "json_body": {"top_level_keys": [{"name": "name", "redacted": false}]}
            })
        );
    }

    #[test]
    fn payload_capture_persisted_shape_does_not_include_values_or_sensitive_key_names() {
        let db = TempDb::new("payload-shape-only");
        let sink = aggregator_sink_with_payload_capture(&db.path);
        let shape = crate::middleware::observation::captured_payload_shape(
            Some("token=fake-token-value&account=4111111111111111"),
            Some("application/json"),
            Some(br#"{"password":"hunter2","name":"Alice","ssn":"123-45-6789"}"#),
        )
        .expect("shape should be captured");

        sink.emit(&observed_event_with_payload_shape(
            "POST",
            "/payments/123",
            200,
            10,
            Some("user-1"),
            "2024-06-01T12:00:00Z",
            serde_json::to_value(shape).expect("shape should serialize"),
        ));
        sink.flush_for_test();

        let stored = payload_shape_rows(&db.path)
            .into_iter()
            .map(|row| row.shape_json)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(stored.contains(r#""name":"account""#));
        assert!(stored.contains(r#""name":"name""#));
        assert!(stored.contains(r#""redacted":true"#));
        for forbidden in [
            "fake-token-value",
            "4111111111111111",
            "hunter2",
            "Alice",
            "123-45-6789",
            "token",
            "password",
            "ssn",
        ] {
            assert!(
                !stored.contains(forbidden),
                "captured payload shape leaked forbidden text {forbidden}: {stored}"
            );
        }
    }

    #[test]
    fn payload_capture_reservoir_stays_bounded_per_endpoint() {
        let db = TempDb::new("payload-reservoir");
        let sink = aggregator_sink_with_payload_capture(&db.path);
        let total = PAYLOAD_SHAPE_SAMPLE_LIMIT + 75;

        for index in 0..total {
            sink.emit(&observed_event_with_payload_shape(
                "POST",
                &format!("/bounded/{index}"),
                200,
                10,
                Some("user-1"),
                timestamp(index),
                json!({
                    "query_params": [{"name": "sample", "redacted": false, "value_type": "number"}],
                    "json_body": {"top_level_keys": [{"name": format!("field_{index}"), "redacted": false}]}
                }),
            ));
        }
        sink.flush_for_test();

        assert_eq!(
            payload_shape_rows(&db.path).len(),
            PAYLOAD_SHAPE_SAMPLE_LIMIT
        );
        assert_eq!(
            payload_shape_observation_count(&db.path, "POST", "/bounded/{id}"),
            total as i64
        );
    }

    #[test]
    fn audit_log_emit_latency_gross_regression_guard_for_aggregator_sink() {
        const EVENT_COUNT: usize = 5_000;
        let events = (0..EVENT_COUNT)
            .map(|index| {
                observed_event(
                    "GET",
                    &format!("/latency/{index}"),
                    200,
                    1,
                    Some("user-1"),
                    timestamp(index),
                )
            })
            .collect::<Vec<_>>();

        let baseline = measure_audit_emit_latency(AuditLog::new(Arc::new(NoopSink)), &events);

        let db = TempDb::new("emit-latency");
        let aggregator = Arc::new(aggregator_sink_with_interval(
            &db.path,
            StdDuration::from_secs(60),
        ));
        let with_aggregator =
            measure_audit_emit_latency(AuditLog::new(aggregator as Arc<dyn AuditSink>), &events);

        eprintln!(
            "audit emit latency sanity check: baseline_total={:?}, baseline_p99={:?}, with_aggregator_total={:?}, with_aggregator_p99={:?}, events={EVENT_COUNT}",
            baseline.total,
            baseline.p99,
            with_aggregator.total,
            with_aggregator.p99
        );

        // Hot-path safety comes from `AuditLog::emit` using a non-blocking
        // bounded-channel `try_send`; sink work runs on the audit writer
        // thread. This is only a coarse regression guard that would catch
        // accidentally adding blocking sink work directly to the caller-facing
        // emit path, not a benchmark of aggregator processing speed.
        assert!(
            with_aggregator.total <= baseline.total * 20 + StdDuration::from_millis(50),
            "aggregator changed total AuditLog::emit time enough to trip the coarse non-blocking-path guard: baseline={:?}, with_aggregator={:?}",
            baseline.total,
            with_aggregator.total
        );
        assert!(
            with_aggregator.p99 <= baseline.p99 * 20 + StdDuration::from_millis(10),
            "aggregator changed p99 AuditLog::emit time enough to trip the coarse non-blocking-path guard: baseline={:?}, with_aggregator={:?}",
            baseline.p99,
            with_aggregator.p99
        );
    }

    fn aggregator_sink(path: &Path) -> EndpointAggregatorSink {
        aggregator_sink_with_interval(path, StdDuration::from_secs(60))
    }

    fn aggregator_sink_with_signal_config(
        path: &Path,
        signal_detector_config: SignalDetectorConfig,
    ) -> EndpointAggregatorSink {
        EndpointAggregatorSink::new_with_flush_interval(
            EndpointAggregatorSinkConfig {
                path: path.to_owned(),
                payload_capture_enabled: false,
                signal_event_sender: None,
                signal_detector_config,
            },
            StdDuration::from_secs(60),
        )
        .expect("aggregator sink should build")
    }

    fn aggregator_sink_with_interval(
        path: &Path,
        flush_interval: StdDuration,
    ) -> EndpointAggregatorSink {
        EndpointAggregatorSink::new_with_flush_interval(
            EndpointAggregatorSinkConfig {
                path: path.to_owned(),
                payload_capture_enabled: false,
                signal_event_sender: None,
                signal_detector_config: SignalDetectorConfig::default(),
            },
            flush_interval,
        )
        .expect("aggregator sink should build")
    }

    fn aggregator_sink_with_payload_capture(path: &Path) -> EndpointAggregatorSink {
        EndpointAggregatorSink::new_with_flush_interval(
            EndpointAggregatorSinkConfig {
                path: path.to_owned(),
                payload_capture_enabled: true,
                signal_event_sender: None,
                signal_detector_config: SignalDetectorConfig::default(),
            },
            StdDuration::from_secs(60),
        )
        .expect("aggregator sink should build")
    }

    fn observed_event(
        method: &str,
        path: &str,
        status: u16,
        latency_ms: u64,
        user_id: Option<&str>,
        timestamp: impl Into<String>,
    ) -> AuditEvent {
        let actor = user_id.map(|user_id| Actor {
            user_id: user_id.to_owned(),
            roles: Some(vec!["reader".to_owned()]),
            auth_mode: "bearer_token".to_owned(),
        });
        let mut event = AuditEvent::new(
            HTTP_REQUEST_OBSERVED,
            "request-123",
            "203.0.113.10",
            actor,
            json!({
                "method": method,
                "path": path,
                "status": status,
                "latency_ms": latency_ms
            }),
        );
        event.timestamp = timestamp.into();
        event
    }

    fn observed_event_with_payload_shape(
        method: &str,
        path: &str,
        status: u16,
        latency_ms: u64,
        user_id: Option<&str>,
        timestamp: impl Into<String>,
        payload_shape: Value,
    ) -> AuditEvent {
        let mut event = observed_event(method, path, status, latency_ms, user_id, timestamp);
        event.payload["payload_shape"] = payload_shape;
        event
    }

    fn observed_event_with_schema_mismatch(
        method: &str,
        path: &str,
        status: u16,
        latency_ms: u64,
        user_id: Option<&str>,
        timestamp: impl Into<String>,
        schema_mismatch: bool,
    ) -> AuditEvent {
        let mut event = observed_event(method, path, status, latency_ms, user_id, timestamp);
        event.payload["schema_mismatch"] = json!(schema_mismatch);
        event
    }

    fn timestamp(index: usize) -> String {
        format!("2024-06-01T12:00:{:02}Z", index % 60)
    }

    fn timestamp_at(second: usize) -> String {
        format!(
            "2024-06-01T12:{:02}:{:02}Z",
            (second / 60) % 60,
            second % 60
        )
    }

    #[derive(Clone, Copy, Debug)]
    struct EmitLatencyMeasurement {
        total: StdDuration,
        p99: StdDuration,
    }

    fn measure_audit_emit_latency(
        audit_log: AuditLog,
        events: &[AuditEvent],
    ) -> EmitLatencyMeasurement {
        let mut samples = Vec::with_capacity(events.len());
        let started = Instant::now();
        for event in events {
            let emit_started = Instant::now();
            audit_log.emit(event.clone());
            samples.push(emit_started.elapsed());
        }
        let elapsed = started.elapsed();
        drop(audit_log);
        samples.sort_unstable();

        EmitLatencyMeasurement {
            total: elapsed,
            p99: duration_percentile(&samples, 99),
        }
    }

    fn duration_percentile(sorted_samples: &[StdDuration], percentile: usize) -> StdDuration {
        let rank = ((percentile * sorted_samples.len()).div_ceil(100)).saturating_sub(1);
        sorted_samples[rank.min(sorted_samples.len() - 1)]
    }

    #[derive(Clone)]
    struct NoopSink;

    impl AuditSink for NoopSink {
        fn emit(&self, _event: &AuditEvent) {}
    }

    #[derive(Debug)]
    struct AggregateSnapshot {
        first_seen: String,
        last_seen: String,
        call_count: i64,
        schema_mismatch_count: i64,
        latency_p50_ms: i64,
        latency_p95_ms: i64,
        latency_p99_ms: i64,
        distinct_principal_count: i64,
    }

    fn aggregate_snapshot(path: &Path, method: &str, endpoint_template: &str) -> AggregateSnapshot {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .query_row(
                r#"
                SELECT
                    first_seen,
                    last_seen,
                    call_count,
                    schema_mismatch_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    distinct_principal_count
                FROM discovery_endpoint_aggregates
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
                params![method, endpoint_template],
                |row| {
                    Ok(AggregateSnapshot {
                        first_seen: row.get(0)?,
                        last_seen: row.get(1)?,
                        call_count: row.get(2)?,
                        schema_mismatch_count: row.get(3)?,
                        latency_p50_ms: row.get(4)?,
                        latency_p95_ms: row.get(5)?,
                        latency_p99_ms: row.get(6)?,
                        distinct_principal_count: row.get(7)?,
                    })
                },
            )
            .expect("aggregate snapshot should query")
    }

    fn aggregate_counts(path: &Path) -> Vec<(String, String, i64)> {
        let connection = Connection::open(path).expect("test database should open");
        let mut statement = connection
            .prepare(
                r#"
                SELECT method, endpoint_template, call_count
                FROM discovery_endpoint_aggregates
                ORDER BY method, endpoint_template
                "#,
            )
            .expect("aggregate count query should prepare");

        statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("aggregate count query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("aggregate count rows should read")
    }

    fn status_counts(path: &Path, method: &str, endpoint_template: &str) -> BTreeMap<i64, i64> {
        let connection = Connection::open(path).expect("test database should open");
        let mut statement = connection
            .prepare(
                r#"
                SELECT status, count
                FROM discovery_endpoint_status_counts
                WHERE method = ?1 AND endpoint_template = ?2
                ORDER BY status
                "#,
            )
            .expect("status count query should prepare");

        statement
            .query_map(params![method, endpoint_template], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .expect("status count query should run")
            .collect::<Result<BTreeMap<_, _>, _>>()
            .expect("status count rows should read")
    }

    fn principal_ids(path: &Path, method: &str, endpoint_template: &str) -> Vec<String> {
        let connection = Connection::open(path).expect("test database should open");
        let mut statement = connection
            .prepare(
                r#"
                SELECT user_id
                FROM discovery_endpoint_principals
                WHERE method = ?1 AND endpoint_template = ?2
                ORDER BY user_id
                "#,
            )
            .expect("principal query should prepare");

        statement
            .query_map(params![method, endpoint_template], |row| row.get(0))
            .expect("principal query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("principal rows should read")
    }

    fn insert_aggregate_without_signal(path: &Path, method: &str, endpoint_template: &str) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute(
                r#"
                INSERT INTO discovery_endpoint_aggregates (
                    method,
                    endpoint_template,
                    first_seen,
                    last_seen,
                    call_count,
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', 1, 1, 11, 11, 11, '[11]', 1, '2024-06-01T12:00:00Z')
                "#,
                params![method, endpoint_template],
            )
            .expect("preexisting aggregate should insert");
        connection
            .execute(
                r#"
                INSERT INTO discovery_endpoint_status_counts (
                    method, endpoint_template, status, count
                ) VALUES (?1, ?2, 200, 1)
                "#,
                params![method, endpoint_template],
            )
            .expect("preexisting status count should insert");
        connection
            .execute(
                r#"
                INSERT INTO discovery_endpoint_principals (
                    method, endpoint_template, user_id, first_seen, last_seen
                ) VALUES (?1, ?2, 'alice', '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z')
                "#,
                params![method, endpoint_template],
            )
            .expect("preexisting principal should insert");
    }

    #[derive(Debug, Eq, PartialEq)]
    struct SignalRow {
        signal_type: String,
        target_kind: String,
        target_key: String,
        explanation: String,
        evidence_json: String,
        state: String,
    }

    fn signal_rows(path: &Path) -> Vec<SignalRow> {
        let connection = Connection::open(path).expect("test database should open");
        let mut statement = connection
            .prepare(
                r#"
                SELECT signal_type, target_kind, target_key, explanation, evidence_json, state
                FROM discovery_signals
                ORDER BY created_at, id
                "#,
            )
            .expect("signal query should prepare");

        statement
            .query_map([], |row| {
                Ok(SignalRow {
                    signal_type: row.get(0)?,
                    target_kind: row.get(1)?,
                    target_key: row.get(2)?,
                    explanation: row.get(3)?,
                    evidence_json: row.get(4)?,
                    state: row.get(5)?,
                })
            })
            .expect("signal query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("signal rows should read")
    }

    fn signal_rows_by_type(path: &Path, signal_type: &str) -> Vec<SignalRow> {
        signal_rows(path)
            .into_iter()
            .filter(|row| row.signal_type == signal_type)
            .collect()
    }

    #[derive(Debug)]
    struct PayloadShapeRow {
        method: String,
        endpoint_template: String,
        sample_slot: i64,
        observed_at: String,
        shape_json: String,
        shape_hash: String,
    }

    fn payload_shape_rows(path: &Path) -> Vec<PayloadShapeRow> {
        let connection = Connection::open(path).expect("test database should open");
        let mut statement = connection
            .prepare(
                r#"
                SELECT method, endpoint_template, sample_slot, observed_at, shape_json, shape_hash
                FROM discovery_payload_shape_samples
                ORDER BY method, endpoint_template, sample_slot
                "#,
            )
            .expect("payload shape query should prepare");

        statement
            .query_map([], |row| {
                Ok(PayloadShapeRow {
                    method: row.get(0)?,
                    endpoint_template: row.get(1)?,
                    sample_slot: row.get(2)?,
                    observed_at: row.get(3)?,
                    shape_json: row.get(4)?,
                    shape_hash: row.get(5)?,
                })
            })
            .expect("payload shape query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("payload shape rows should read")
    }

    fn payload_shape_observation_count(path: &Path, method: &str, endpoint_template: &str) -> i64 {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .query_row(
                r#"
                SELECT shape_observation_count
                FROM discovery_payload_shape_stats
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
                params![method, endpoint_template],
                |row| row.get(0),
            )
            .expect("payload shape count should query")
    }

    fn table_exists(path: &Path, table: &str) -> bool {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .query_row(
                r#"
                SELECT EXISTS(
                    SELECT 1
                    FROM sqlite_master
                    WHERE type = 'table' AND name = ?1
                )
                "#,
                params![table],
                |row| row.get::<_, i64>(0),
            )
            .expect("table existence should query")
            == 1
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-discovery-aggregator-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            ));

            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = fs::remove_file(path);
            }
        }
    }
}
