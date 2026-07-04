use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const NEW_ENDPOINT_SEEN_SIGNAL_TYPE: &str = "new_endpoint_seen";
pub const SCHEMA_MISMATCH_SIGNAL_TYPE: &str = "schema_mismatch";
pub const ERROR_RATE_SPIKE_SIGNAL_TYPE: &str = "error_rate_spike";
pub const PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_TYPE: &str = "principal_new_to_endpoint";
pub const VOLUME_OUTLIER_SIGNAL_TYPE: &str = "volume_outlier";
pub const ENDPOINT_TARGET_KIND: &str = "endpoint";
pub const PRINCIPAL_ENDPOINT_TARGET_KIND: &str = "principal_endpoint";
pub const DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD: u64 = 5;
pub const DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD: f64 = 0.40;
pub const DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD: u64 = 1;
pub const DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD: f64 = 3.0;
pub const ERROR_RATE_SPIKE_MIN_SAMPLE_COUNT: u64 = 20;
pub const VOLUME_OUTLIER_WINDOW_SAMPLE_COUNT: u64 = 20;
pub const VOLUME_OUTLIER_MIN_BASELINE_WINDOWS: u64 = 3;

const CREATE_SIGNAL_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS discovery_signals (
    id TEXT PRIMARY KEY,
    signal_type TEXT NOT NULL,
    target_kind TEXT NOT NULL,
    target_key TEXT NOT NULL,
    target_identity_json TEXT NOT NULL,
    explanation TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    transitioned_at TEXT,
    transitioned_by TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_signals_identity
ON discovery_signals(signal_type, target_kind, target_key);

CREATE INDEX IF NOT EXISTS idx_discovery_signals_state_created
ON discovery_signals(state, created_at, id);
"#;

const INSERT_SIGNAL_SQL: &str = r#"
INSERT OR IGNORE INTO discovery_signals (
    id,
    signal_type,
    target_kind,
    target_key,
    target_identity_json,
    explanation,
    evidence_json,
    state,
    created_at,
    updated_at,
    transitioned_at,
    transitioned_by
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, NULL, NULL)
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalLifecycleState {
    Open,
    Acknowledged,
    Dismissed,
}

impl SignalLifecycleState {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "open" => Ok(Self::Open),
            "acknowledged" => Ok(Self::Acknowledged),
            "dismissed" => Ok(Self::Dismissed),
            _ => Err("state"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acknowledged => "acknowledged",
            Self::Dismissed => "dismissed",
        }
    }
}

impl Serialize for SignalLifecycleState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SignalLifecycleState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SignalTarget {
    pub kind: String,
    pub identity: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct Signal {
    pub id: String,
    pub signal_type: String,
    pub target: SignalTarget,
    pub explanation: String,
    pub evidence: Value,
    pub state: SignalLifecycleState,
    pub created_at: String,
    pub updated_at: String,
    pub transitioned_at: Option<String>,
    pub transitioned_by: Option<String>,
}

#[derive(Serialize)]
pub struct SignalListPage {
    pub signals: Vec<Signal>,
    pub next_cursor: Option<String>,
}

#[derive(Clone)]
pub struct SignalListFilters {
    pub state: Option<SignalLifecycleState>,
    pub signal_type: Option<String>,
    pub target_kind: Option<String>,
    pub target_key: Option<String>,
    pub limit: usize,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NewSignal {
    pub id: String,
    pub signal_type: String,
    pub target_kind: String,
    pub target_key: String,
    pub target_identity: Value,
    pub explanation: String,
    pub evidence: Value,
    pub state: SignalLifecycleState,
    pub created_at: String,
}

impl NewSignal {
    fn new(
        signal_type: impl Into<String>,
        target_kind: impl Into<String>,
        target_key: impl Into<String>,
        target_identity: Value,
        explanation: impl Into<String>,
        evidence: Value,
        created_at: impl Into<String>,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            signal_type: signal_type.into(),
            target_kind: target_kind.into(),
            target_key: target_key.into(),
            target_identity,
            explanation: explanation.into(),
            evidence,
            state: SignalLifecycleState::Open,
            created_at: created_at.into(),
        }
    }

    fn as_signal(&self) -> Signal {
        Signal {
            id: self.id.clone(),
            signal_type: self.signal_type.clone(),
            target: SignalTarget {
                kind: self.target_kind.clone(),
                identity: self.target_identity.clone(),
            },
            explanation: self.explanation.clone(),
            evidence: self.evidence.clone(),
            state: self.state,
            created_at: self.created_at.clone(),
            updated_at: self.created_at.clone(),
            transitioned_at: None,
            transitioned_by: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EndpointSignalObservation<'a> {
    pub method: &'a str,
    pub endpoint_template: &'a str,
    pub first_seen: &'a str,
    pub status: u16,
    pub latency_ms: u64,
    pub user_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SignalDetectorConfig {
    pub schema_mismatch_threshold: u64,
    pub error_rate_spike_threshold: f64,
    pub principal_new_to_endpoint_threshold: u64,
    pub volume_outlier_threshold: f64,
}

impl Default for SignalDetectorConfig {
    fn default() -> Self {
        Self {
            schema_mismatch_threshold: DEFAULT_SCHEMA_MISMATCH_SIGNAL_THRESHOLD,
            error_rate_spike_threshold: DEFAULT_ERROR_RATE_SPIKE_SIGNAL_THRESHOLD,
            principal_new_to_endpoint_threshold: DEFAULT_PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD,
            volume_outlier_threshold: DEFAULT_VOLUME_OUTLIER_SIGNAL_THRESHOLD,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SchemaMismatchSignalObservation<'a> {
    pub method: &'a str,
    pub endpoint_template: &'a str,
    pub observed_at: &'a str,
    pub call_count: u64,
    pub previous_schema_mismatch_count: u64,
    pub schema_mismatch_count: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ErrorRateSpikeSignalObservation<'a> {
    pub method: &'a str,
    pub endpoint_template: &'a str,
    pub observed_at: &'a str,
    pub recent_sample_count: u64,
    pub recent_error_count: u64,
    pub baseline_sample_count: u64,
    pub baseline_error_count: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct PrincipalNewToEndpointSignalObservation<'a> {
    pub method: &'a str,
    pub endpoint_template: &'a str,
    pub observed_at: &'a str,
    pub principal: &'a str,
    pub prior_distinct_principal_count: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct VolumeOutlierSignalObservation<'a> {
    pub method: &'a str,
    pub endpoint_template: &'a str,
    pub observed_at: &'a str,
    pub window_call_count: u64,
    pub window_duration_secs: u64,
    pub current_rate_per_second: f64,
    pub baseline_window_count: u64,
    pub baseline_rate_per_second: f64,
}

#[derive(Debug)]
pub struct SignalEvaluator {
    config: SignalDetectorConfig,
    new_endpoint_seen: NewEndpointSeenDetector,
    schema_mismatch: SchemaMismatchDetector,
    error_rate_spike: ErrorRateSpikeDetector,
    principal_new_to_endpoint: PrincipalNewToEndpointDetector,
    volume_outlier: VolumeOutlierDetector,
}

impl Default for SignalEvaluator {
    fn default() -> Self {
        Self::new(SignalDetectorConfig::default())
    }
}

impl SignalEvaluator {
    pub fn new(config: SignalDetectorConfig) -> Self {
        Self {
            config,
            new_endpoint_seen: NewEndpointSeenDetector,
            schema_mismatch: SchemaMismatchDetector,
            error_rate_spike: ErrorRateSpikeDetector,
            principal_new_to_endpoint: PrincipalNewToEndpointDetector,
            volume_outlier: VolumeOutlierDetector,
        }
    }

    pub fn evaluate_new_endpoint(
        &self,
        observation: EndpointSignalObservation<'_>,
    ) -> Vec<NewSignal> {
        self.new_endpoint_seen
            .evaluate(observation)
            .into_iter()
            .collect()
    }

    pub fn evaluate_schema_mismatch(
        &self,
        observation: SchemaMismatchSignalObservation<'_>,
    ) -> Vec<NewSignal> {
        self.schema_mismatch
            .evaluate(observation, self.config.schema_mismatch_threshold)
            .into_iter()
            .collect()
    }

    pub fn evaluate_error_rate_spike(
        &self,
        observation: ErrorRateSpikeSignalObservation<'_>,
    ) -> Vec<NewSignal> {
        self.error_rate_spike
            .evaluate(observation, self.config.error_rate_spike_threshold)
            .into_iter()
            .collect()
    }

    pub fn evaluate_principal_new_to_endpoint(
        &self,
        observation: PrincipalNewToEndpointSignalObservation<'_>,
    ) -> Vec<NewSignal> {
        self.principal_new_to_endpoint
            .evaluate(observation, self.config.principal_new_to_endpoint_threshold)
            .into_iter()
            .collect()
    }

    pub fn evaluate_volume_outlier(
        &self,
        observation: VolumeOutlierSignalObservation<'_>,
    ) -> Vec<NewSignal> {
        self.volume_outlier
            .evaluate(observation, self.config.volume_outlier_threshold)
            .into_iter()
            .collect()
    }
}

#[derive(Debug, Default)]
struct NewEndpointSeenDetector;

impl NewEndpointSeenDetector {
    fn evaluate(&self, observation: EndpointSignalObservation<'_>) -> Option<NewSignal> {
        let target_identity = json!({
            "method": observation.method,
            "endpoint_template": observation.endpoint_template,
        });
        let evidence = json!({
            "first_seen": observation.first_seen,
            "initial_call_count": 1,
            "initial_status": observation.status,
            "initial_latency_ms": observation.latency_ms,
            "initial_principal": observation.user_id,
        });
        let explanation = match observation.user_id {
            Some(user_id) => format!(
                "New endpoint observed: {} {} was first seen at {} by principal {} with status {}.",
                observation.method,
                observation.endpoint_template,
                observation.first_seen,
                user_id,
                observation.status
            ),
            None => format!(
                "New endpoint observed: {} {} was first seen at {} without an authenticated principal, with status {}.",
                observation.method,
                observation.endpoint_template,
                observation.first_seen,
                observation.status
            ),
        };

        Some(NewSignal::new(
            NEW_ENDPOINT_SEEN_SIGNAL_TYPE,
            ENDPOINT_TARGET_KIND,
            endpoint_target_key(observation.method, observation.endpoint_template),
            target_identity,
            explanation,
            evidence,
            observation.first_seen,
        ))
    }
}

#[derive(Debug, Default)]
struct SchemaMismatchDetector;

impl SchemaMismatchDetector {
    fn evaluate(
        &self,
        observation: SchemaMismatchSignalObservation<'_>,
        threshold: u64,
    ) -> Option<NewSignal> {
        if threshold == 0
            || observation.previous_schema_mismatch_count >= threshold
            || observation.schema_mismatch_count < threshold
        {
            return None;
        }

        let target_identity =
            endpoint_target_identity(observation.method, observation.endpoint_template);
        let evidence = json!({
            "observed_at": observation.observed_at,
            "call_count": observation.call_count,
            "schema_mismatch_count": observation.schema_mismatch_count,
            "previous_schema_mismatch_count": observation.previous_schema_mismatch_count,
            "threshold": threshold,
        });
        let explanation = format!(
            "Schema mismatch signal for {} {}: {} schema mismatches across {} observed calls crossed the configured threshold of {}.",
            observation.method,
            observation.endpoint_template,
            observation.schema_mismatch_count,
            observation.call_count,
            threshold
        );

        Some(NewSignal::new(
            SCHEMA_MISMATCH_SIGNAL_TYPE,
            ENDPOINT_TARGET_KIND,
            endpoint_target_key(observation.method, observation.endpoint_template),
            target_identity,
            explanation,
            evidence,
            observation.observed_at,
        ))
    }
}

#[derive(Debug, Default)]
struct ErrorRateSpikeDetector;

impl ErrorRateSpikeDetector {
    fn evaluate(
        &self,
        observation: ErrorRateSpikeSignalObservation<'_>,
        threshold_delta: f64,
    ) -> Option<NewSignal> {
        if !threshold_delta.is_finite()
            || threshold_delta <= 0.0
            || observation.recent_sample_count < ERROR_RATE_SPIKE_MIN_SAMPLE_COUNT
            || observation.baseline_sample_count < ERROR_RATE_SPIKE_MIN_SAMPLE_COUNT
        {
            return None;
        }

        let recent_error_rate = rate(
            observation.recent_error_count,
            observation.recent_sample_count,
        )?;
        let baseline_error_rate = rate(
            observation.baseline_error_count,
            observation.baseline_sample_count,
        )?;
        let delta = recent_error_rate - baseline_error_rate;
        if delta < threshold_delta {
            return None;
        }

        let target_identity =
            endpoint_target_identity(observation.method, observation.endpoint_template);
        let evidence = json!({
            "observed_at": observation.observed_at,
            "recent_sample_count": observation.recent_sample_count,
            "recent_error_count": observation.recent_error_count,
            "recent_error_rate": recent_error_rate,
            "baseline_sample_count": observation.baseline_sample_count,
            "baseline_error_count": observation.baseline_error_count,
            "baseline_error_rate": baseline_error_rate,
            "error_rate_delta": delta,
            "threshold_delta": threshold_delta,
            "error_status_range": "400-599",
        });
        let explanation = format!(
            "Error rate spike for {} {}: recent error rate is {} over {} calls versus baseline {} over {} calls, crossing the configured {} delta threshold.",
            observation.method,
            observation.endpoint_template,
            percent(recent_error_rate),
            observation.recent_sample_count,
            percent(baseline_error_rate),
            observation.baseline_sample_count,
            percent(threshold_delta)
        );

        Some(NewSignal::new(
            ERROR_RATE_SPIKE_SIGNAL_TYPE,
            ENDPOINT_TARGET_KIND,
            endpoint_target_key(observation.method, observation.endpoint_template),
            target_identity,
            explanation,
            evidence,
            observation.observed_at,
        ))
    }
}

#[derive(Debug, Default)]
struct PrincipalNewToEndpointDetector;

impl PrincipalNewToEndpointDetector {
    fn evaluate(
        &self,
        observation: PrincipalNewToEndpointSignalObservation<'_>,
        threshold: u64,
    ) -> Option<NewSignal> {
        if threshold == 0 || observation.prior_distinct_principal_count < threshold {
            return None;
        }

        let target_identity = json!({
            "method": observation.method,
            "endpoint_template": observation.endpoint_template,
            "principal": observation.principal,
        });
        let evidence = json!({
            "observed_at": observation.observed_at,
            "principal": observation.principal,
            "prior_distinct_principal_count": observation.prior_distinct_principal_count,
            "threshold": threshold,
        });
        let explanation = format!(
            "Principal new to endpoint: principal {} first accessed {} {} after {} other distinct principals had already been observed, meeting the configured threshold of {}.",
            observation.principal,
            observation.method,
            observation.endpoint_template,
            observation.prior_distinct_principal_count,
            threshold
        );

        Some(NewSignal::new(
            PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_TYPE,
            PRINCIPAL_ENDPOINT_TARGET_KIND,
            principal_endpoint_target_key(
                observation.method,
                observation.endpoint_template,
                observation.principal,
            ),
            target_identity,
            explanation,
            evidence,
            observation.observed_at,
        ))
    }
}

#[derive(Debug, Default)]
struct VolumeOutlierDetector;

impl VolumeOutlierDetector {
    fn evaluate(
        &self,
        observation: VolumeOutlierSignalObservation<'_>,
        threshold_multiple: f64,
    ) -> Option<NewSignal> {
        if !threshold_multiple.is_finite()
            || threshold_multiple <= 1.0
            || observation.baseline_window_count < VOLUME_OUTLIER_MIN_BASELINE_WINDOWS
            || observation.baseline_rate_per_second <= 0.0
            || observation.current_rate_per_second <= 0.0
        {
            return None;
        }

        let direction = if observation.current_rate_per_second
            >= observation.baseline_rate_per_second * threshold_multiple
        {
            "increase"
        } else if observation.current_rate_per_second
            <= observation.baseline_rate_per_second / threshold_multiple
        {
            "decrease"
        } else {
            return None;
        };

        let target_identity =
            endpoint_target_identity(observation.method, observation.endpoint_template);
        let evidence = json!({
            "observed_at": observation.observed_at,
            "direction": direction,
            "window_call_count": observation.window_call_count,
            "window_duration_secs": observation.window_duration_secs,
            "current_rate_per_second": observation.current_rate_per_second,
            "baseline_window_count": observation.baseline_window_count,
            "baseline_rate_per_second": observation.baseline_rate_per_second,
            "threshold_multiple": threshold_multiple,
        });
        let explanation = format!(
            "Endpoint volume {} for {} {}: the latest {}-call window ran at {:.3} calls/sec versus a {:.3} calls/sec baseline across {} windows, crossing the configured {:.2}x threshold.",
            direction,
            observation.method,
            observation.endpoint_template,
            observation.window_call_count,
            observation.current_rate_per_second,
            observation.baseline_rate_per_second,
            observation.baseline_window_count,
            threshold_multiple
        );

        Some(NewSignal::new(
            VOLUME_OUTLIER_SIGNAL_TYPE,
            ENDPOINT_TARGET_KIND,
            endpoint_target_key(observation.method, observation.endpoint_template),
            target_identity,
            explanation,
            evidence,
            observation.observed_at,
        ))
    }
}

pub fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(CREATE_SIGNAL_SCHEMA_SQL)
}

pub fn insert_signals(
    connection: &Connection,
    signals: &[NewSignal],
) -> Result<Vec<Signal>, SignalStorageError> {
    let mut statement = connection.prepare_cached(INSERT_SIGNAL_SQL)?;
    let mut inserted_signals = Vec::new();

    for signal in signals {
        let target_identity_json = serde_json::to_string(&signal.target_identity)?;
        let evidence_json = serde_json::to_string(&signal.evidence)?;

        let inserted = statement.execute(params![
            signal.id.as_str(),
            signal.signal_type.as_str(),
            signal.target_kind.as_str(),
            signal.target_key.as_str(),
            target_identity_json.as_str(),
            signal.explanation.as_str(),
            evidence_json.as_str(),
            signal.state.as_str(),
            signal.created_at.as_str(),
        ])?;
        if inserted > 0 {
            inserted_signals.push(signal.as_signal());
        }
    }

    Ok(inserted_signals)
}

pub fn endpoint_target_key(method: &str, endpoint_template: &str) -> String {
    format!("{method} {endpoint_template}")
}

pub fn principal_endpoint_target_key(
    method: &str,
    endpoint_template: &str,
    principal: &str,
) -> String {
    format!("{method} {endpoint_template} {principal}")
}

fn endpoint_target_identity(method: &str, endpoint_template: &str) -> Value {
    json!({
        "method": method,
        "endpoint_template": endpoint_template,
    })
}

fn rate(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator > 0).then_some(numerator as f64 / denominator as f64)
}

fn percent(value: f64) -> String {
    format!("{:.1}%", value * 100.0)
}

#[derive(Debug)]
pub enum SignalStorageError {
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for SignalStorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(err) => write!(formatter, "SQLite error: {err}"),
            Self::Json(err) => write!(formatter, "JSON serialization error: {err}"),
        }
    }
}

impl std::error::Error for SignalStorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sqlite(err) => Some(err),
            Self::Json(err) => Some(err),
        }
    }
}

impl From<rusqlite::Error> for SignalStorageError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

impl From<serde_json::Error> for SignalStorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}
