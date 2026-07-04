use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const NEW_ENDPOINT_SEEN_SIGNAL_TYPE: &str = "new_endpoint_seen";
pub const ENDPOINT_TARGET_KIND: &str = "endpoint";

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

#[derive(Debug, Default)]
pub struct SignalEvaluator {
    new_endpoint_seen: NewEndpointSeenDetector,
}

impl SignalEvaluator {
    pub fn evaluate_new_endpoint(
        &self,
        observation: EndpointSignalObservation<'_>,
    ) -> Vec<NewSignal> {
        self.new_endpoint_seen
            .evaluate(observation)
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

pub fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(CREATE_SIGNAL_SCHEMA_SQL)
}

pub fn insert_signals(
    connection: &Connection,
    signals: &[NewSignal],
) -> Result<(), SignalStorageError> {
    let mut statement = connection.prepare_cached(INSERT_SIGNAL_SQL)?;

    for signal in signals {
        let target_identity_json = serde_json::to_string(&signal.target_identity)?;
        let evidence_json = serde_json::to_string(&signal.evidence)?;

        statement.execute(params![
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
    }

    Ok(())
}

pub fn endpoint_target_key(method: &str, endpoint_template: &str) -> String {
    format!("{method} {endpoint_template}")
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
