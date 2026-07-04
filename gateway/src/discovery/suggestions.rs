use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

use crate::{
    audit::query::{
        AuditQueryStore, RoleEndpointObservationFilters, MAX_RULE_SUGGESTION_AUDIT_SCAN_ROWS,
    },
    auth::{AuthMethod, Principal},
    discovery::{
        query::{DiscoveryQueryError, DiscoveryQueryStore},
        signals::{self, Signal, SignalLifecycleState, SignalListFilters},
    },
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
    rbac::{Policy, PrincipalMatcher, Rule, RuleAction, RuleMatcher},
};

pub const BASELINE_ALLOW_SUGGESTION_TYPE: &str = "baseline_allow";
pub const BASELINE_AUDIT_UNAVAILABLE_REASON: &str =
    "baseline role suggestions require AUDIT_SQLITE_PATH because role claims are only stored in audit history";
pub const DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS: u64 = 24;
pub const MAX_RULE_SUGGESTION_BASELINE_WINDOW_HOURS: u64 = 876_000;

const RULE_SUGGESTION_STATE_OPEN: &str = "open";
const RULE_SUGGESTION_STATE_DISMISSED: &str = "dismissed";
const RULE_SUGGESTION_STATE_ACCEPTED: &str = "accepted";

const CREATE_RULE_SUGGESTION_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS discovery_rule_suggestions (
    id TEXT PRIMARY KEY,
    suggestion_type TEXT NOT NULL,
    method TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    principal_key TEXT NOT NULL,
    proposed_rule_json TEXT NOT NULL,
    rationale TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    transitioned_at TEXT,
    transitioned_by TEXT,
    source_signal_id TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_rule_suggestions_identity
ON discovery_rule_suggestions(suggestion_type, method, path_pattern, principal_key);

CREATE INDEX IF NOT EXISTS idx_discovery_rule_suggestions_state_created
ON discovery_rule_suggestions(state, created_at, id);

CREATE INDEX IF NOT EXISTS idx_discovery_rule_suggestions_source_signal
ON discovery_rule_suggestions(source_signal_id);
"#;

const INSERT_RULE_SUGGESTION_SQL: &str = r#"
INSERT OR IGNORE INTO discovery_rule_suggestions (
    id,
    suggestion_type,
    method,
    path_pattern,
    principal_key,
    proposed_rule_json,
    rationale,
    evidence_json,
    state,
    created_at,
    updated_at,
    transitioned_at,
    transitioned_by,
    source_signal_id
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, NULL, NULL, ?11)
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleSuggestionLifecycleState {
    Open,
    Dismissed,
    Accepted,
}

impl RuleSuggestionLifecycleState {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            RULE_SUGGESTION_STATE_OPEN => Ok(Self::Open),
            RULE_SUGGESTION_STATE_DISMISSED => Ok(Self::Dismissed),
            RULE_SUGGESTION_STATE_ACCEPTED => Ok(Self::Accepted),
            _ => Err("state"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => RULE_SUGGESTION_STATE_OPEN,
            Self::Dismissed => RULE_SUGGESTION_STATE_DISMISSED,
            Self::Accepted => RULE_SUGGESTION_STATE_ACCEPTED,
        }
    }
}

impl Serialize for RuleSuggestionLifecycleState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RuleSuggestionLifecycleState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RuleSuggestion {
    pub id: String,
    pub suggestion_type: String,
    pub method: String,
    pub path_pattern: String,
    pub principal_key: String,
    pub proposed_rule: Rule,
    pub rationale: String,
    pub evidence: Value,
    pub state: RuleSuggestionLifecycleState,
    pub created_at: String,
    pub updated_at: String,
    pub transitioned_at: Option<String>,
    pub transitioned_by: Option<String>,
    pub source_signal_id: Option<String>,
}

#[derive(Serialize)]
pub struct RuleSuggestionListPage {
    pub suggestions: Vec<RuleSuggestion>,
    pub next_cursor: Option<String>,
}

#[derive(Clone)]
pub struct RuleSuggestionListFilters {
    pub state: Option<RuleSuggestionLifecycleState>,
    pub suggestion_type: Option<String>,
    pub limit: usize,
    pub cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleSuggestionConfig {
    pub baseline_window_hours: u64,
}

impl Default for RuleSuggestionConfig {
    fn default() -> Self {
        Self {
            baseline_window_hours: DEFAULT_RULE_SUGGESTION_BASELINE_WINDOW_HOURS,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RuleSuggestionRun {
    pub inserted_count: usize,
    pub baseline: BaselineSuggestionRun,
    pub anomaly: AnomalySuggestionRun,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BaselineSuggestionRun {
    pub available: bool,
    pub omitted_reason: Option<String>,
    pub observed_role_endpoint_count: usize,
    pub skipped_policy_covered: usize,
    pub skipped_unauthenticated_observations: u64,
    pub skipped_without_roles_observations: u64,
    pub skipped_denied_observations: u64,
    pub scanned_event_count: u64,
    pub scan_truncated: bool,
}

impl Default for BaselineSuggestionRun {
    fn default() -> Self {
        Self {
            available: true,
            omitted_reason: None,
            observed_role_endpoint_count: 0,
            skipped_policy_covered: 0,
            skipped_unauthenticated_observations: 0,
            skipped_without_roles_observations: 0,
            skipped_denied_observations: 0,
            scanned_event_count: 0,
            scan_truncated: false,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct AnomalySuggestionRun {
    pub open_signal_count: usize,
    pub skipped_policy_covered: usize,
    pub skipped_unusable_target: usize,
}

pub struct RuleSuggestionEngine {
    discovery_store: DiscoveryQueryStore,
    audit_store: Option<AuditQueryStore>,
    suggestion_store: RuleSuggestionStore,
    config: RuleSuggestionConfig,
}

impl RuleSuggestionEngine {
    pub fn open<P, A>(
        discovery_path: P,
        audit_path: Option<A>,
        config: RuleSuggestionConfig,
    ) -> Result<Self, RuleSuggestionError>
    where
        P: AsRef<Path>,
        A: AsRef<Path>,
    {
        let discovery_path = discovery_path.as_ref().to_path_buf();
        let discovery_store = DiscoveryQueryStore::open(&discovery_path)?;
        let suggestion_store = RuleSuggestionStore::open(&discovery_path)?;
        let audit_store = audit_path
            .map(|path| AuditQueryStore::open(path.as_ref()))
            .transpose()?;

        Ok(Self {
            discovery_store,
            audit_store,
            suggestion_store,
            config,
        })
    }

    pub fn generate(&self, policy: &Policy) -> Result<RuleSuggestionRun, RuleSuggestionError> {
        let created_at = utc_timestamp_rfc3339();
        let mut run = RuleSuggestionRun::default();
        let mut suggestions = self.baseline_suggestions(policy, &created_at, &mut run.baseline)?;
        suggestions.extend(self.anomaly_suggestions(policy, &created_at, &mut run.anomaly)?);

        let inserted = self.suggestion_store.insert_suggestions(&suggestions)?;
        run.inserted_count = inserted.len();
        Ok(run)
    }

    pub fn list_suggestions(&self) -> Result<Vec<RuleSuggestion>, RuleSuggestionError> {
        self.suggestion_store.list_suggestions()
    }

    pub fn list_suggestion_page(
        &self,
        filters: &RuleSuggestionListFilters,
    ) -> Result<RuleSuggestionListPage, RuleSuggestionError> {
        self.suggestion_store.list_suggestion_page(filters)
    }

    pub fn get_suggestion(
        &self,
        suggestion_id: &str,
    ) -> Result<Option<RuleSuggestion>, RuleSuggestionError> {
        self.suggestion_store.get_suggestion(suggestion_id)
    }

    pub fn transition_suggestion(
        &self,
        suggestion_id: &str,
        state: RuleSuggestionLifecycleState,
        transitioned_by: Option<&str>,
    ) -> Result<Option<RuleSuggestion>, RuleSuggestionError> {
        self.suggestion_store
            .transition_suggestion(suggestion_id, state, transitioned_by)
    }

    fn baseline_suggestions(
        &self,
        policy: &Policy,
        created_at: &str,
        run: &mut BaselineSuggestionRun,
    ) -> Result<Vec<NewRuleSuggestion>, RuleSuggestionError> {
        let Some(audit_store) = self.audit_store.as_ref() else {
            run.available = false;
            run.omitted_reason = Some(BASELINE_AUDIT_UNAVAILABLE_REASON.to_owned());
            return Ok(Vec::new());
        };

        let endpoints = self.discovery_store.observed_endpoints()?;
        if endpoints.is_empty() {
            return Ok(Vec::new());
        }

        let from = lookback_cutoff(self.config.baseline_window_hours);
        let matrix =
            audit_store.observed_role_endpoint_matrix(&RoleEndpointObservationFilters {
                endpoints,
                from: Some(from.clone()),
                to: Some(created_at.to_owned()),
                max_scan_rows: MAX_RULE_SUGGESTION_AUDIT_SCAN_ROWS,
            })?;
        run.observed_role_endpoint_count = matrix.observations.len();
        run.scanned_event_count = matrix.scanned_event_count;
        run.scan_truncated = matrix.scan_truncated;
        run.skipped_unauthenticated_observations = matrix.skipped_unauthenticated_observations;
        run.skipped_without_roles_observations = matrix.skipped_without_roles_observations;
        run.skipped_denied_observations = matrix.skipped_denied_observations;

        let mut suggestions = Vec::new();
        for observation in matrix.observations {
            let principal = PrincipalMatcher {
                roles: vec![observation.role.clone()],
                auth_methods: Vec::new(),
                principal_ids: Vec::new(),
            };
            if policy_has_covering_action(
                policy,
                &observation.method,
                &observation.endpoint_template,
                &principal,
                &[RuleAction::Allow, RuleAction::Shadow],
            ) {
                run.skipped_policy_covered = run.skipped_policy_covered.saturating_add(1);
                continue;
            }

            let proposed_rule = Rule {
                id: None,
                enabled: true,
                methods: vec![observation.method.clone()],
                path: observation.endpoint_template.clone(),
                principal,
                action: RuleAction::Allow,
            };
            let rationale = baseline_rationale(
                &observation.method,
                &observation.endpoint_template,
                &observation.role,
                observation.observation_count,
                observation.error_count,
                self.config.baseline_window_hours,
            );
            let evidence = json!({
                "source": "audit_sqlite",
                "lookback_window_hours": self.config.baseline_window_hours,
                "from": from,
                "to": created_at,
                "method": observation.method,
                "endpoint_template": observation.endpoint_template,
                "role": observation.role,
                "observation_count": observation.observation_count,
                "error_count": observation.error_count,
                "first_seen": observation.first_seen,
                "last_seen": observation.last_seen,
                "audit_scan_truncated": matrix.scan_truncated,
                "audit_scanned_event_count": matrix.scanned_event_count,
                "match_strategy": crate::audit::query::ENDPOINT_AUDIT_MATCH_STRATEGY,
                "match_limitations": crate::audit::query::ENDPOINT_AUDIT_MATCH_LIMITATIONS,
                "skipped_denied_observations": matrix.skipped_denied_observations,
                "skipped_unauthenticated_observations": matrix.skipped_unauthenticated_observations,
                "skipped_without_roles_observations": matrix.skipped_without_roles_observations,
            });
            suggestions.push(NewRuleSuggestion::new(
                BASELINE_ALLOW_SUGGESTION_TYPE,
                proposed_rule,
                rationale,
                evidence,
                created_at,
                None,
            )?);
        }

        Ok(suggestions)
    }

    fn anomaly_suggestions(
        &self,
        policy: &Policy,
        created_at: &str,
        run: &mut AnomalySuggestionRun,
    ) -> Result<Vec<NewRuleSuggestion>, RuleSuggestionError> {
        let signals = self.open_signals()?;
        run.open_signal_count = signals.len();
        let mut suggestions = Vec::new();

        for signal in signals {
            let Some(target) = suggestion_target_from_signal(&signal) else {
                run.skipped_unusable_target = run.skipped_unusable_target.saturating_add(1);
                continue;
            };
            if policy_has_covering_action(
                policy,
                &target.method,
                &target.path_pattern,
                &target.principal,
                &[RuleAction::Deny, RuleAction::Shadow],
            ) {
                run.skipped_policy_covered = run.skipped_policy_covered.saturating_add(1);
                continue;
            }

            let proposed_rule = Rule {
                id: None,
                enabled: true,
                methods: vec![target.method.clone()],
                path: target.path_pattern.clone(),
                principal: target.principal,
                action: RuleAction::Shadow,
            };
            let suggestion_type = signal_shadow_suggestion_type(&signal.signal_type);
            let rationale = anomaly_rationale(&signal, &target.method, &target.path_pattern);
            let evidence = json!({
                "source": "discovery_signal",
                "source_signal_id": signal.id,
                "source_signal_type": signal.signal_type,
                "source_signal_target": signal.target,
                "source_signal_explanation": signal.explanation,
                "source_signal_evidence": signal.evidence,
                "mapped_action": "shadow",
                "mapping_reason": "Discovery signals are deterministic advisory signals with false-positive risk; Shadow records would-deny observations without proposing an immediate hard block.",
            });
            suggestions.push(NewRuleSuggestion::new(
                suggestion_type,
                proposed_rule,
                rationale,
                evidence,
                created_at,
                Some(signal.id),
            )?);
        }

        Ok(suggestions)
    }

    fn open_signals(&self) -> Result<Vec<Signal>, RuleSuggestionError> {
        let mut cursor = None;
        let mut signals = Vec::new();

        loop {
            let page = self.discovery_store.list_signals(&SignalListFilters {
                state: Some(SignalLifecycleState::Open),
                signal_type: None,
                target_kind: None,
                target_key: None,
                limit: 500,
                cursor,
            })?;
            signals.extend(page.signals);
            let Some(next_cursor) = page.next_cursor else {
                break;
            };
            cursor = Some(next_cursor);
        }

        Ok(signals)
    }
}

#[derive(Debug)]
pub enum RuleSuggestionError {
    Discovery(DiscoveryQueryError),
    Audit(crate::audit::query::AuditQueryError),
    Sqlite {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Json {
        context: &'static str,
        source: serde_json::Error,
    },
    InvalidState {
        state: String,
    },
    InvalidCursor {
        parameter: &'static str,
    },
}

impl fmt::Display for RuleSuggestionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Discovery(err) => write!(formatter, "{err}"),
            Self::Audit(err) => write!(formatter, "{err}"),
            Self::Sqlite { path, source } => write!(
                formatter,
                "failed to persist rule suggestions at {}: {source}",
                path.display()
            ),
            Self::Json { context, source } => {
                write!(
                    formatter,
                    "failed to encode or decode rule suggestion {context}: {source}"
                )
            }
            Self::InvalidState { state } => {
                write!(
                    formatter,
                    "invalid rule suggestion state in database: {state}"
                )
            }
            Self::InvalidCursor { parameter } => {
                write!(formatter, "invalid rule suggestion cursor: {parameter}")
            }
        }
    }
}

impl Error for RuleSuggestionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Discovery(err) => Some(err),
            Self::Audit(err) => Some(err),
            Self::Sqlite { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::InvalidState { .. } => None,
            Self::InvalidCursor { .. } => None,
        }
    }
}

impl From<DiscoveryQueryError> for RuleSuggestionError {
    fn from(err: DiscoveryQueryError) -> Self {
        Self::Discovery(err)
    }
}

impl From<crate::audit::query::AuditQueryError> for RuleSuggestionError {
    fn from(err: crate::audit::query::AuditQueryError) -> Self {
        Self::Audit(err)
    }
}

#[derive(Clone, Debug)]
struct NewRuleSuggestion {
    id: String,
    suggestion_type: String,
    method: String,
    path_pattern: String,
    principal_key: String,
    proposed_rule: Rule,
    rationale: String,
    evidence: Value,
    state: RuleSuggestionLifecycleState,
    created_at: String,
    source_signal_id: Option<String>,
}

impl NewRuleSuggestion {
    fn new(
        suggestion_type: impl Into<String>,
        proposed_rule: Rule,
        rationale: impl Into<String>,
        evidence: Value,
        created_at: impl Into<String>,
        source_signal_id: Option<String>,
    ) -> Result<Self, RuleSuggestionError> {
        let principal_key = principal_key(&proposed_rule.principal)?;

        Ok(Self {
            id: uuid::Uuid::new_v4().to_string(),
            suggestion_type: suggestion_type.into(),
            method: proposed_rule
                .methods
                .first()
                .cloned()
                .unwrap_or_else(|| "*".to_owned()),
            path_pattern: proposed_rule.path.clone(),
            principal_key,
            proposed_rule,
            rationale: rationale.into(),
            evidence,
            state: RuleSuggestionLifecycleState::Open,
            created_at: created_at.into(),
            source_signal_id,
        })
    }

    fn as_suggestion(&self) -> RuleSuggestion {
        RuleSuggestion {
            id: self.id.clone(),
            suggestion_type: self.suggestion_type.clone(),
            method: self.method.clone(),
            path_pattern: self.path_pattern.clone(),
            principal_key: self.principal_key.clone(),
            proposed_rule: self.proposed_rule.clone(),
            rationale: self.rationale.clone(),
            evidence: self.evidence.clone(),
            state: self.state,
            created_at: self.created_at.clone(),
            updated_at: self.created_at.clone(),
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id: self.source_signal_id.clone(),
        }
    }
}

struct RuleSuggestionStore {
    path: PathBuf,
    connection: Mutex<Connection>,
}

impl RuleSuggestionStore {
    fn open(path: impl AsRef<Path>) -> Result<Self, RuleSuggestionError> {
        let path = path.as_ref().to_path_buf();
        let connection = Connection::open(&path).map_err(|source| RuleSuggestionError::Sqlite {
            path: path.clone(),
            source,
        })?;
        configure_connection(&connection).map_err(|source| RuleSuggestionError::Sqlite {
            path: path.clone(),
            source,
        })?;

        Ok(Self {
            path,
            connection: Mutex::new(connection),
        })
    }

    fn insert_suggestions(
        &self,
        suggestions: &[NewRuleSuggestion],
    ) -> Result<Vec<RuleSuggestion>, RuleSuggestionError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare_cached(INSERT_RULE_SUGGESTION_SQL)
            .map_err(|source| RuleSuggestionError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let mut inserted_suggestions = Vec::new();

        for suggestion in suggestions {
            let proposed_rule_json =
                serde_json::to_string(&suggestion.proposed_rule).map_err(|source| {
                    RuleSuggestionError::Json {
                        context: "proposed rule",
                        source,
                    }
                })?;
            let evidence_json = serde_json::to_string(&suggestion.evidence).map_err(|source| {
                RuleSuggestionError::Json {
                    context: "evidence",
                    source,
                }
            })?;
            let inserted = statement
                .execute(params![
                    suggestion.id.as_str(),
                    suggestion.suggestion_type.as_str(),
                    suggestion.method.as_str(),
                    suggestion.path_pattern.as_str(),
                    suggestion.principal_key.as_str(),
                    proposed_rule_json.as_str(),
                    suggestion.rationale.as_str(),
                    evidence_json.as_str(),
                    suggestion.state.as_str(),
                    suggestion.created_at.as_str(),
                    suggestion.source_signal_id.as_deref(),
                ])
                .map_err(|source| RuleSuggestionError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;

            if inserted > 0 {
                inserted_suggestions.push(suggestion.as_suggestion());
            }
        }

        Ok(inserted_suggestions)
    }

    fn list_suggestions(&self) -> Result<Vec<RuleSuggestion>, RuleSuggestionError> {
        Ok(self
            .list_suggestion_page(&RuleSuggestionListFilters {
                state: None,
                suggestion_type: None,
                limit: usize::MAX,
                cursor: None,
            })?
            .suggestions)
    }

    fn list_suggestion_page(
        &self,
        filters: &RuleSuggestionListFilters,
    ) -> Result<RuleSuggestionListPage, RuleSuggestionError> {
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<RuleSuggestionCursor>("cursor", value))
            .transpose()?;
        let (sql, params) = build_rule_suggestion_list_query(filters, cursor.as_ref());
        let connection = self.connection_guard();
        let mut statement =
            connection
                .prepare(&sql)
                .map_err(|source| RuleSuggestionError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), RawRuleSuggestion::from_row)
            .map_err(|source| RuleSuggestionError::Sqlite {
                path: self.path.clone(),
                source,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| RuleSuggestionError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        let mut rows = rows;
        let has_more = rows.len() > filters.limit;
        if has_more {
            rows.truncate(filters.limit);
        }

        let next_cursor = if has_more {
            rows.last()
                .map(|row| {
                    encode_cursor(&RuleSuggestionCursor {
                        created_at: row.created_at.clone(),
                        id: row.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };

        let suggestions = rows
            .into_iter()
            .map(RawRuleSuggestion::into_suggestion)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(RuleSuggestionListPage {
            suggestions,
            next_cursor,
        })
    }

    fn get_suggestion(
        &self,
        suggestion_id: &str,
    ) -> Result<Option<RuleSuggestion>, RuleSuggestionError> {
        let connection = self.connection_guard();
        load_suggestion_by_id(&connection, &self.path, suggestion_id)
    }

    fn transition_suggestion(
        &self,
        suggestion_id: &str,
        state: RuleSuggestionLifecycleState,
        transitioned_by: Option<&str>,
    ) -> Result<Option<RuleSuggestion>, RuleSuggestionError> {
        let transitioned_at = utc_timestamp_rfc3339();
        let connection = self.connection_guard();
        let updated = connection
            .execute(
                r#"
                UPDATE discovery_rule_suggestions
                SET state = ?2,
                    updated_at = ?3,
                    transitioned_at = ?3,
                    transitioned_by = ?4
                WHERE id = ?1
                "#,
                params![
                    suggestion_id,
                    state.as_str(),
                    transitioned_at,
                    transitioned_by,
                ],
            )
            .map_err(|source| RuleSuggestionError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        if updated == 0 {
            return Ok(None);
        }

        load_suggestion_by_id(&connection, &self.path, suggestion_id)
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "discovery",
                    "lock" => "rule_suggestion_connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite rule suggestion connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

struct RawRuleSuggestion {
    id: String,
    suggestion_type: String,
    method: String,
    path_pattern: String,
    principal_key: String,
    proposed_rule_json: String,
    rationale: String,
    evidence_json: String,
    state: String,
    created_at: String,
    updated_at: String,
    transitioned_at: Option<String>,
    transitioned_by: Option<String>,
    source_signal_id: Option<String>,
}

impl RawRuleSuggestion {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            suggestion_type: row.get(1)?,
            method: row.get(2)?,
            path_pattern: row.get(3)?,
            principal_key: row.get(4)?,
            proposed_rule_json: row.get(5)?,
            rationale: row.get(6)?,
            evidence_json: row.get(7)?,
            state: row.get(8)?,
            created_at: row.get(9)?,
            updated_at: row.get(10)?,
            transitioned_at: row.get(11)?,
            transitioned_by: row.get(12)?,
            source_signal_id: row.get(13)?,
        })
    }

    fn into_suggestion(self) -> Result<RuleSuggestion, RuleSuggestionError> {
        let proposed_rule =
            serde_json::from_str::<Rule>(&self.proposed_rule_json).map_err(|source| {
                RuleSuggestionError::Json {
                    context: "proposed rule",
                    source,
                }
            })?;
        let evidence = serde_json::from_str::<Value>(&self.evidence_json).map_err(|source| {
            RuleSuggestionError::Json {
                context: "evidence",
                source,
            }
        })?;
        let state = RuleSuggestionLifecycleState::parse(&self.state).map_err(|_| {
            RuleSuggestionError::InvalidState {
                state: self.state.clone(),
            }
        })?;

        Ok(RuleSuggestion {
            id: self.id,
            suggestion_type: self.suggestion_type,
            method: self.method,
            path_pattern: self.path_pattern,
            principal_key: self.principal_key,
            proposed_rule,
            rationale: self.rationale,
            evidence,
            state,
            created_at: self.created_at,
            updated_at: self.updated_at,
            transitioned_at: self.transitioned_at,
            transitioned_by: self.transitioned_by,
            source_signal_id: self.source_signal_id,
        })
    }
}

struct SignalSuggestionTarget {
    method: String,
    path_pattern: String,
    principal: PrincipalMatcher,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RuleSuggestionCursor {
    created_at: String,
    id: String,
}

pub fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(CREATE_RULE_SUGGESTION_SCHEMA_SQL)
}

fn load_suggestion_by_id(
    connection: &Connection,
    path: &Path,
    suggestion_id: &str,
) -> Result<Option<RuleSuggestion>, RuleSuggestionError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT
                id,
                suggestion_type,
                method,
                path_pattern,
                principal_key,
                proposed_rule_json,
                rationale,
                evidence_json,
                state,
                created_at,
                updated_at,
                transitioned_at,
                transitioned_by,
                source_signal_id
            FROM discovery_rule_suggestions
            WHERE id = ?1
            "#,
        )
        .map_err(|source| RuleSuggestionError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
    let mut rows = statement
        .query_map(params![suggestion_id], RawRuleSuggestion::from_row)
        .map_err(|source| RuleSuggestionError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;

    let Some(row) = rows.next() else {
        return Ok(None);
    };
    let raw = row.map_err(|source| RuleSuggestionError::Sqlite {
        path: path.to_path_buf(),
        source,
    })?;

    raw.into_suggestion().map(Some)
}

fn build_rule_suggestion_list_query(
    filters: &RuleSuggestionListFilters,
    cursor: Option<&RuleSuggestionCursor>,
) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        r#"
        SELECT
            id,
            suggestion_type,
            method,
            path_pattern,
            principal_key,
            proposed_rule_json,
            rationale,
            evidence_json,
            state,
            created_at,
            updated_at,
            transitioned_at,
            transitioned_by,
            source_signal_id
        FROM discovery_rule_suggestions
        "#,
    );
    let mut clauses = Vec::new();
    let mut params = Vec::new();

    if let Some(state) = filters.state {
        clauses.push("state = ?");
        params.push(SqlValue::Text(state.as_str().to_owned()));
    }
    if let Some(suggestion_type) = &filters.suggestion_type {
        clauses.push("suggestion_type = ?");
        params.push(SqlValue::Text(suggestion_type.clone()));
    }
    if let Some(cursor) = cursor {
        clauses.push(
            "(julianday(created_at) < julianday(?) OR (julianday(created_at) = julianday(?) AND id > ?))",
        );
        params.push(SqlValue::Text(cursor.created_at.clone()));
        params.push(SqlValue::Text(cursor.created_at.clone()));
        params.push(SqlValue::Text(cursor.id.clone()));
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }

    sql.push_str(" ORDER BY julianday(created_at) DESC, id ASC LIMIT ?");
    params.push(SqlValue::Integer(query_limit(filters.limit)));

    (sql, params)
}

fn policy_has_covering_action(
    policy: &Policy,
    method: &str,
    path_pattern: &str,
    principal: &PrincipalMatcher,
    covering_actions: &[RuleAction],
) -> bool {
    if policy.rules.is_empty() {
        return false;
    }

    let matcher = RuleMatcher::new(&policy.rules);
    let path = representative_path_from_endpoint_template(path_pattern);
    let principal = representative_principal_for_matcher(principal);

    matcher
        .evaluate(method, &path, principal.as_ref())
        .is_some_and(|decision| covering_actions.contains(&decision.action))
}

fn representative_path_from_endpoint_template(endpoint_template: &str) -> String {
    let Some(tail) = endpoint_template.strip_prefix('/') else {
        return endpoint_template.to_owned();
    };
    if tail.is_empty() {
        return "/".to_owned();
    }

    let segments = tail
        .split('/')
        .map(representative_path_segment)
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn representative_path_segment(segment: &str) -> String {
    let Some(capture) = segment
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        return segment.to_owned();
    };

    if capture.eq_ignore_ascii_case("id") {
        "123".to_owned()
    } else {
        "sample".to_owned()
    }
}

fn representative_principal_for_matcher(matcher: &PrincipalMatcher) -> Option<Principal> {
    if matcher.is_unconstrained() {
        return None;
    }

    let auth_method = if matcher
        .auth_methods
        .iter()
        .any(|method| method == crate::rbac::rule::AUTH_METHOD_SESSION_COOKIE)
    {
        AuthMethod::Cookie
    } else {
        AuthMethod::Bearer
    };

    Some(Principal {
        user_id: matcher
            .principal_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "rule-suggestion-principal".to_owned()),
        email: None,
        org_id: None,
        roles: matcher.roles.clone(),
        session_id: "rule-suggestion".to_owned(),
        auth_method,
    })
}

fn principal_key(principal: &PrincipalMatcher) -> Result<String, RuleSuggestionError> {
    if principal.is_unconstrained() {
        return Ok("principal:any".to_owned());
    }

    let canonical = PrincipalMatcher {
        roles: sorted_unique(&principal.roles),
        auth_methods: sorted_unique(&principal.auth_methods),
        principal_ids: sorted_unique(&principal.principal_ids),
    };
    serde_json::to_string(&canonical).map_err(|source| RuleSuggestionError::Json {
        context: "principal key",
        source,
    })
}

fn sorted_unique(values: &[String]) -> Vec<String> {
    values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn baseline_rationale(
    method: &str,
    endpoint_template: &str,
    role: &str,
    observation_count: u64,
    error_count: u64,
    window_hours: u64,
) -> String {
    let call_word = if observation_count == 1 {
        "call"
    } else {
        "calls"
    };
    let error_clause = if error_count == 0 {
        "with zero 4xx/5xx responses".to_owned()
    } else {
        format!("with {error_count} 4xx/5xx responses")
    };

    format!(
        "Baseline allow candidate: observed {observation_count} {call_word} from role '{role}' to {method} {endpoint_template} over the last {window_hours}h, {error_clause}."
    )
}

fn suggestion_target_from_signal(signal: &Signal) -> Option<SignalSuggestionTarget> {
    let method = signal
        .target
        .identity
        .get("method")
        .and_then(Value::as_str)?
        .to_owned();
    let path_pattern = signal
        .target
        .identity
        .get("endpoint_template")
        .and_then(Value::as_str)?
        .to_owned();
    let principal = if signal.target.kind == signals::PRINCIPAL_ENDPOINT_TARGET_KIND {
        let principal = signal
            .target
            .identity
            .get("principal")
            .and_then(Value::as_str)?
            .to_owned();
        PrincipalMatcher {
            roles: Vec::new(),
            auth_methods: Vec::new(),
            principal_ids: vec![principal],
        }
    } else {
        PrincipalMatcher::default()
    };

    Some(SignalSuggestionTarget {
        method,
        path_pattern,
        principal,
    })
}

fn signal_shadow_suggestion_type(signal_type: &str) -> String {
    format!("signal_shadow_{signal_type}")
}

fn anomaly_rationale(signal: &Signal, method: &str, endpoint_template: &str) -> String {
    format!(
        "Signal-derived shadow candidate: open signal {} ({}) targets {method} {endpoint_template}. Suggested Shadow rather than Deny because anomaly signals can be false positives; review the signal evidence before enforcing a blocking rule.",
        signal.id, signal.signal_type
    )
}

fn lookback_cutoff(lookback_hours: u64) -> String {
    let hours = i64::try_from(lookback_hours).unwrap_or(i64::MAX);
    (OffsetDateTime::now_utc() - TimeDuration::hours(hours))
        .format(&Rfc3339)
        .expect("UTC timestamp should format as RFC 3339")
}

fn encode_cursor<T: Serialize>(cursor: &T) -> Result<String, RuleSuggestionError> {
    let json = serde_json::to_vec(cursor).map_err(|source| RuleSuggestionError::Json {
        context: "cursor",
        source,
    })?;
    Ok(hex::encode(json))
}

fn decode_cursor<T: DeserializeOwned>(
    parameter: &'static str,
    value: &str,
) -> Result<T, RuleSuggestionError> {
    let bytes = hex::decode(value).map_err(|_| RuleSuggestionError::InvalidCursor { parameter })?;
    serde_json::from_slice(&bytes).map_err(|_| RuleSuggestionError::InvalidCursor { parameter })
}

fn query_limit(limit: usize) -> i64 {
    i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
}

fn utc_timestamp_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current UTC timestamp should format as RFC 3339")
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rusqlite::{params, Connection};
    use serde_json::{json, Value};

    use super::*;
    use crate::rbac::{Policy, PrincipalMatcher, Rule, RuleAction};

    #[test]
    fn baseline_generation_persists_role_allow_suggestions_from_audit_history() {
        let discovery_db = TempDb::new("baseline-discovery");
        let audit_db = TempDb::new("baseline-audit");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/invoices/{id}");
        seed_discovery_endpoint(&discovery_db.path, "POST", "/refunds");
        create_audit_schema(&audit_db.path);
        insert_observation_event(
            &audit_db.path,
            SeedObservationEvent {
                event_id: "invoice-reader-1",
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: "alice",
                roles: &["billing-reader"],
                method: "GET",
                request_path: "/invoices/123",
                status: 200,
                policy_decision: Some("allowed"),
            },
        );
        insert_observation_event(
            &audit_db.path,
            SeedObservationEvent {
                event_id: "invoice-reader-2",
                timestamp: "2024-06-01T12:00:01Z",
                actor_user_id: "bob",
                roles: &["billing-reader"],
                method: "GET",
                request_path: "/invoices/456",
                status: 200,
                policy_decision: Some("allowed"),
            },
        );
        insert_observation_event(
            &audit_db.path,
            SeedObservationEvent {
                event_id: "refund-writer",
                timestamp: "2024-06-01T12:00:02Z",
                actor_user_id: "carol",
                roles: &["billing-writer"],
                method: "POST",
                request_path: "/refunds",
                status: 201,
                policy_decision: Some("allowed"),
            },
        );
        insert_observation_event(
            &audit_db.path,
            SeedObservationEvent {
                event_id: "denied-admin",
                timestamp: "2024-06-01T12:00:03Z",
                actor_user_id: "mallory",
                roles: &["admin"],
                method: "GET",
                request_path: "/invoices/999",
                status: 403,
                policy_decision: Some("denied"),
            },
        );

        let engine = suggestion_engine(&discovery_db.path, Some(&audit_db.path));
        let run = engine
            .generate(&empty_policy())
            .expect("suggestion generation should succeed");

        assert!(run.baseline.available);
        assert_eq!(run.baseline.skipped_denied_observations, 1);
        assert_eq!(run.inserted_count, 2);

        let suggestions = engine.list_suggestions().expect("suggestions should query");
        assert_eq!(suggestions.len(), 2);

        let invoice = suggestion_for(&suggestions, "GET", "/invoices/{id}", "billing-reader");
        assert_eq!(invoice.suggestion_type, BASELINE_ALLOW_SUGGESTION_TYPE);
        assert_eq!(invoice.proposed_rule.action, RuleAction::Allow);
        assert_eq!(invoice.proposed_rule.methods, vec!["GET".to_owned()]);
        assert_eq!(invoice.proposed_rule.path, "/invoices/{id}");
        assert_eq!(
            invoice.proposed_rule.principal.roles,
            vec!["billing-reader".to_owned()]
        );
        assert!(invoice.rationale.contains("observed 2 calls"));
        assert!(invoice.rationale.contains("zero 4xx/5xx responses"));
        assert_eq!(invoice.evidence["observation_count"], json!(2));
        assert_eq!(invoice.evidence["error_count"], json!(0));
        assert_eq!(invoice.state, RuleSuggestionLifecycleState::Open);

        let refund = suggestion_for(&suggestions, "POST", "/refunds", "billing-writer");
        assert_eq!(refund.proposed_rule.action, RuleAction::Allow);
        assert_eq!(refund.evidence["observation_count"], json!(1));
    }

    #[test]
    fn baseline_generation_skips_combinations_already_covered_by_allow_or_shadow_rules() {
        let discovery_db = TempDb::new("baseline-dedup-discovery");
        let audit_db = TempDb::new("baseline-dedup-audit");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/invoices/{id}");
        create_audit_schema(&audit_db.path);
        insert_observation_event(
            &audit_db.path,
            SeedObservationEvent {
                event_id: "reader",
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: "alice",
                roles: &["billing-reader"],
                method: "GET",
                request_path: "/invoices/123",
                status: 200,
                policy_decision: Some("allowed"),
            },
        );
        insert_observation_event(
            &audit_db.path,
            SeedObservationEvent {
                event_id: "writer",
                timestamp: "2024-06-01T12:00:01Z",
                actor_user_id: "bob",
                roles: &["billing-writer"],
                method: "GET",
                request_path: "/invoices/456",
                status: 200,
                policy_decision: Some("allowed"),
            },
        );
        let mut policy = empty_policy();
        policy.rules.push(Rule {
            id: Some("existing-reader-allow".to_owned()),
            enabled: true,
            methods: vec!["GET".to_owned()],
            path: "/invoices/{id}".to_owned(),
            principal: PrincipalMatcher {
                roles: vec!["billing-reader".to_owned()],
                auth_methods: Vec::new(),
                principal_ids: Vec::new(),
            },
            action: RuleAction::Allow,
        });

        let engine = suggestion_engine(&discovery_db.path, Some(&audit_db.path));
        let run = engine
            .generate(&policy)
            .expect("suggestion generation should succeed");

        assert_eq!(run.baseline.skipped_policy_covered, 1);
        let suggestions = engine.list_suggestions().expect("suggestions should query");
        assert_eq!(suggestions.len(), 1);
        assert_eq!(
            suggestions[0].proposed_rule.principal.roles,
            vec!["billing-writer"]
        );
    }

    #[test]
    fn anomaly_generation_persists_shadow_suggestion_for_open_signal_only() {
        let discovery_db = TempDb::new("anomaly-discovery");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/invoices/{id}");
        seed_signal(
            &discovery_db.path,
            SeedSignal {
                id: "sig-open-error-rate",
                signal_type: "error_rate_spike",
                target_kind: "endpoint",
                target_identity: json!({
                    "method": "GET",
                    "endpoint_template": "/invoices/{id}"
                }),
                evidence: json!({
                    "recent_error_rate": 0.75,
                    "baseline_error_rate": 0.05
                }),
                state: "open",
            },
        );
        seed_signal(
            &discovery_db.path,
            SeedSignal {
                id: "sig-dismissed-volume",
                signal_type: "volume_outlier",
                target_kind: "endpoint",
                target_identity: json!({
                    "method": "GET",
                    "endpoint_template": "/invoices/{id}"
                }),
                evidence: json!({ "direction": "increase" }),
                state: "dismissed",
            },
        );

        let engine = suggestion_engine(&discovery_db.path, None);
        let run = engine
            .generate(&empty_policy())
            .expect("suggestion generation should succeed");

        assert!(!run.baseline.available);
        assert_eq!(run.anomaly.open_signal_count, 1);
        assert_eq!(run.inserted_count, 1);

        let suggestions = engine.list_suggestions().expect("suggestions should query");
        assert_eq!(suggestions.len(), 1);
        let suggestion = &suggestions[0];
        assert_eq!(suggestion.suggestion_type, "signal_shadow_error_rate_spike");
        assert_eq!(suggestion.proposed_rule.action, RuleAction::Shadow);
        assert_eq!(suggestion.proposed_rule.methods, vec!["GET"]);
        assert_eq!(suggestion.proposed_rule.path, "/invoices/{id}");
        assert!(suggestion.proposed_rule.principal.is_unconstrained());
        assert!(suggestion.rationale.contains("sig-open-error-rate"));
        assert!(suggestion.rationale.contains("error_rate_spike"));
        assert_eq!(
            suggestion.evidence["source_signal_id"],
            json!("sig-open-error-rate")
        );
        assert_eq!(
            suggestion.evidence["source_signal_type"],
            json!("error_rate_spike")
        );
    }

    #[test]
    fn anomaly_generation_targets_signal_principal_and_skips_existing_shadow_coverage() {
        let discovery_db = TempDb::new("anomaly-principal-discovery");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/invoices/{id}");
        seed_signal(
            &discovery_db.path,
            SeedSignal {
                id: "sig-covered-principal",
                signal_type: "principal_new_to_endpoint",
                target_kind: "principal_endpoint",
                target_identity: json!({
                    "method": "GET",
                    "endpoint_template": "/invoices/{id}",
                    "principal": "alice"
                }),
                evidence: json!({ "prior_distinct_principal_count": 5 }),
                state: "open",
            },
        );
        seed_signal(
            &discovery_db.path,
            SeedSignal {
                id: "sig-uncovered-principal",
                signal_type: "principal_new_to_endpoint",
                target_kind: "principal_endpoint",
                target_identity: json!({
                    "method": "GET",
                    "endpoint_template": "/invoices/{id}",
                    "principal": "bob"
                }),
                evidence: json!({ "prior_distinct_principal_count": 5 }),
                state: "open",
            },
        );
        let mut policy = empty_policy();
        policy.rules.push(Rule {
            id: Some("shadow-alice".to_owned()),
            enabled: true,
            methods: vec!["GET".to_owned()],
            path: "/invoices/{id}".to_owned(),
            principal: PrincipalMatcher {
                roles: Vec::new(),
                auth_methods: Vec::new(),
                principal_ids: vec!["alice".to_owned()],
            },
            action: RuleAction::Shadow,
        });

        let engine = suggestion_engine(&discovery_db.path, None);
        let run = engine
            .generate(&policy)
            .expect("suggestion generation should succeed");

        assert_eq!(run.anomaly.open_signal_count, 2);
        assert_eq!(run.anomaly.skipped_policy_covered, 1);
        let suggestions = engine.list_suggestions().expect("suggestions should query");
        assert_eq!(suggestions.len(), 1);
        assert_eq!(
            suggestions[0].proposed_rule.principal.principal_ids,
            vec!["bob".to_owned()]
        );
        assert!(suggestions[0].rationale.contains("sig-uncovered-principal"));
    }

    #[test]
    fn generation_is_idempotent_for_same_logical_suggestion_target() {
        let discovery_db = TempDb::new("idempotent-discovery");
        let audit_db = TempDb::new("idempotent-audit");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/invoices/{id}");
        create_audit_schema(&audit_db.path);
        insert_observation_event(
            &audit_db.path,
            SeedObservationEvent {
                event_id: "reader",
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: "alice",
                roles: &["billing-reader"],
                method: "GET",
                request_path: "/invoices/123",
                status: 200,
                policy_decision: Some("allowed"),
            },
        );

        let engine = suggestion_engine(&discovery_db.path, Some(&audit_db.path));
        let first = engine
            .generate(&empty_policy())
            .expect("first generation should succeed");
        let second = engine
            .generate(&empty_policy())
            .expect("second generation should succeed");

        assert_eq!(first.inserted_count, 1);
        assert_eq!(second.inserted_count, 0);
        assert_eq!(
            engine
                .list_suggestions()
                .expect("suggestions should query")
                .len(),
            1
        );
    }

    #[test]
    fn baseline_generation_reports_audit_unavailable_without_principal_fallback() {
        let discovery_db = TempDb::new("audit-unavailable-discovery");
        seed_discovery_endpoint(&discovery_db.path, "GET", "/invoices/{id}");

        let engine = suggestion_engine(&discovery_db.path, None);
        let run = engine
            .generate(&empty_policy())
            .expect("suggestion generation should succeed");

        assert!(!run.baseline.available);
        assert_eq!(
            run.baseline.omitted_reason.as_deref(),
            Some(BASELINE_AUDIT_UNAVAILABLE_REASON)
        );
        assert_eq!(run.inserted_count, 0);
        assert!(engine
            .list_suggestions()
            .expect("suggestions should query")
            .is_empty());
    }

    fn suggestion_engine(
        discovery_path: &PathBuf,
        audit_path: Option<&PathBuf>,
    ) -> RuleSuggestionEngine {
        RuleSuggestionEngine::open(
            discovery_path,
            audit_path,
            RuleSuggestionConfig {
                baseline_window_hours: 876_000,
            },
        )
        .expect("suggestion engine should open")
    }

    fn empty_policy() -> Policy {
        Policy {
            schema_version: "0.1.0".to_owned(),
            id: Some("test-policy".to_owned()),
            default_action: crate::rbac::DefaultAction::Deny,
            enforcement_mode: crate::rbac::EnforcementMode::Enforce,
            roles: Default::default(),
            routes: Vec::new(),
            rules: Vec::new(),
            egress: Default::default(),
            rate_limits: Vec::new(),
        }
    }

    fn suggestion_for<'a>(
        suggestions: &'a [RuleSuggestion],
        method: &str,
        path_pattern: &str,
        role: &str,
    ) -> &'a RuleSuggestion {
        suggestions
            .iter()
            .find(|suggestion| {
                suggestion.method == method
                    && suggestion.path_pattern == path_pattern
                    && suggestion.proposed_rule.principal.roles == vec![role.to_owned()]
            })
            .expect("matching suggestion should exist")
    }

    fn seed_discovery_endpoint(path: &PathBuf, method: &str, endpoint_template: &str) {
        let connection = Connection::open(path).expect("test discovery database should open");
        connection
            .execute_batch(
                r#"
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
                "#,
            )
            .expect("discovery schema should create");
        connection
            .execute(
                r#"
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
                ) VALUES (?1, ?2, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', 1, 0, 1, 1, 1, 1, '[]', 0, '2024-06-01T12:00:00Z')
                "#,
                params![method, endpoint_template],
            )
            .expect("endpoint aggregate should insert");
    }

    fn create_audit_schema(path: &PathBuf) {
        let connection = Connection::open(path).expect("test audit database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    schema_version TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    user_agent TEXT,
                    actor_user_id TEXT,
                    actor_json TEXT,
                    payload_method TEXT,
                    payload_path TEXT,
                    payload_status INTEGER,
                    payload_matched_rule_id TEXT,
                    payload_json TEXT NOT NULL
                );
                "#,
            )
            .expect("audit schema should create");
    }

    struct SeedObservationEvent<'a> {
        event_id: &'a str,
        timestamp: &'a str,
        actor_user_id: &'a str,
        roles: &'a [&'a str],
        method: &'a str,
        request_path: &'a str,
        status: i64,
        policy_decision: Option<&'a str>,
    }

    fn insert_observation_event(path: &PathBuf, event: SeedObservationEvent<'_>) {
        let connection = Connection::open(path).expect("test audit database should open");
        let actor_json = json!({
            "user_id": event.actor_user_id,
            "roles": event.roles,
            "auth_mode": "bearer_token"
        })
        .to_string();
        let mut payload = json!({
            "method": event.method,
            "path": event.request_path,
            "status": event.status
        });
        if let Some(policy_decision) = event.policy_decision {
            payload["policy_decision"] = json!(policy_decision);
        }
        let payload_json = payload.to_string();

        connection
            .execute(
                r#"
                INSERT INTO audit_events (
                    event_id,
                    event_type,
                    timestamp,
                    schema_version,
                    request_id,
                    source_ip,
                    actor_user_id,
                    actor_json,
                    payload_method,
                    payload_path,
                    payload_status,
                    payload_json
                ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', ?3, '203.0.113.10', ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    event.event_id,
                    event.timestamp,
                    format!("request-{}", event.event_id),
                    event.actor_user_id,
                    actor_json,
                    event.method,
                    event.request_path,
                    event.status,
                    payload_json,
                ],
            )
            .expect("observation event should insert");
    }

    struct SeedSignal {
        id: &'static str,
        signal_type: &'static str,
        target_kind: &'static str,
        target_identity: Value,
        evidence: Value,
        state: &'static str,
    }

    fn seed_signal(path: &PathBuf, signal: SeedSignal) {
        let connection = Connection::open(path).expect("test discovery database should open");
        crate::discovery::signals::configure_connection(&connection)
            .expect("signal schema should create");
        let target_key = match signal.target_kind {
            "endpoint" => crate::discovery::signals::endpoint_target_key(
                signal
                    .target_identity
                    .get("method")
                    .and_then(Value::as_str)
                    .expect("signal method should exist"),
                signal
                    .target_identity
                    .get("endpoint_template")
                    .and_then(Value::as_str)
                    .expect("signal endpoint template should exist"),
            ),
            _ => signal.id.to_owned(),
        };
        connection
            .execute(
                r#"
                INSERT INTO discovery_signals (
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
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', NULL, NULL)
                "#,
                params![
                    signal.id,
                    signal.signal_type,
                    signal.target_kind,
                    target_key,
                    signal.target_identity.to_string(),
                    format!("seeded {} signal", signal.signal_type),
                    signal.evidence.to_string(),
                    signal.state,
                ],
            )
            .expect("signal should insert");
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-rule-suggestions-{test_name}-{}.sqlite",
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
