use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

use rusqlite::{params_from_iter, types::Value as SqlValue, Connection};
use serde::Serialize;
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    audit::{Actor, AuditEvent},
    discovery::path_template::template_stateless,
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
};

pub const MAX_ENDPOINT_AUDIT_SCAN_ROWS: usize = 100_000;
pub const ENDPOINT_AUDIT_MATCH_STRATEGY: &str = "stateless_path_template";
pub const ENDPOINT_AUDIT_MATCH_LIMITATIONS: &str =
    "Matches literal paths and immediate well-known identifier templates such as /users/{id}; statefully learned slug templates such as /catalog/{param} are not reverse-mapped from raw audit paths.";

pub struct AuditQueryStore {
    path: PathBuf,
    connection: Mutex<Connection>,
}

pub struct AuditQueryFilters {
    pub from: Option<String>,
    pub to: Option<String>,
    pub event_type: Option<String>,
    pub actor: Option<String>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub status: Option<i64>,
    pub matched_rule_id: Option<String>,
    pub limit: usize,
    pub before_id: Option<i64>,
}

pub struct RequestObservationFilters {
    pub from: Option<String>,
    pub to: Option<String>,
    pub methods: Vec<String>,
    pub path_exact: Option<String>,
    pub path_prefix: Option<String>,
    pub before_id: Option<i64>,
}

pub struct RequestObservation {
    pub id: i64,
    pub event_id: String,
    pub timestamp: String,
    pub request_id: String,
    pub source_ip: String,
    pub user_agent: Option<String>,
    pub actor: Option<Actor>,
    pub method: String,
    pub path: String,
    pub status: Option<i64>,
    pub matched_rule_id: Option<String>,
    pub payload_json: String,
}

pub struct AuditQueryPage {
    pub events: Vec<AuditEvent>,
    pub next_cursor: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointAuditBucket {
    Hour,
    Day,
}

pub struct EndpointAuditFilters {
    pub method: String,
    pub endpoint_template: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub bucket: EndpointAuditBucket,
    pub recent_limit: usize,
    pub recent_before_id: Option<i64>,
}

#[derive(Serialize)]
pub struct EndpointAuditActivity {
    pub time_series: Vec<EndpointTimeSeriesPoint>,
    pub time_series_truncated: bool,
    pub recent_events: Vec<EndpointRecentEvent>,
    pub recent_events_next_cursor: Option<i64>,
    pub recent_events_scan_truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EndpointTimeSeriesPoint {
    pub bucket_start: String,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointRecentEvent {
    pub id: i64,
    pub event_id: String,
    pub request_id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub status: Option<i64>,
    pub actor: Option<String>,
}

#[derive(Debug)]
pub enum AuditQueryError {
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Sqlite {
        path: PathBuf,
        source: rusqlite::Error,
    },
    ActorJson {
        event_id: String,
        source: serde_json::Error,
    },
    PayloadJson {
        event_id: String,
        source: serde_json::Error,
    },
}

impl fmt::Display for AuditQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(
                    formatter,
                    "failed to open SQLite audit query store at {}: {source}",
                    path.display()
                )
            }
            Self::Sqlite { path, source } => {
                write!(
                    formatter,
                    "failed to query SQLite audit events at {}: {source}",
                    path.display()
                )
            }
            Self::ActorJson { event_id, source } => {
                write!(
                    formatter,
                    "failed to deserialize audit actor JSON for event {event_id}: {source}"
                )
            }
            Self::PayloadJson { event_id, source } => {
                write!(
                    formatter,
                    "failed to deserialize audit payload JSON for event {event_id}: {source}"
                )
            }
        }
    }
}

impl Error for AuditQueryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Sqlite { source, .. } => Some(source),
            Self::ActorJson { source, .. } | Self::PayloadJson { source, .. } => Some(source),
        }
    }
}

impl AuditQueryStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditQueryError> {
        let path = path.into();
        let connection = Connection::open(&path).map_err(|source| AuditQueryError::Open {
            path: path.clone(),
            source,
        })?;

        Ok(Self {
            path,
            connection: Mutex::new(connection),
        })
    }

    pub fn query(&self, filters: &AuditQueryFilters) -> Result<AuditQueryPage, AuditQueryError> {
        let (sql, params) = build_query(filters);
        let raw_rows = {
            let connection = self.connection_guard();
            let mut statement =
                connection
                    .prepare(&sql)
                    .map_err(|source| AuditQueryError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            let rows = statement
                .query_map(params_from_iter(params.iter()), raw_event_row)
                .map_err(|source| AuditQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| AuditQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
            rows
        };

        let mut rows = raw_rows;
        let has_more = rows.len() > filters.limit;
        if has_more {
            rows.truncate(filters.limit);
        }

        let next_cursor = has_more.then(|| {
            rows.last()
                .expect("over-limit query should leave at least one row")
                .id
        });
        let events = rows
            .into_iter()
            .map(RawAuditEventRow::into_event)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(AuditQueryPage {
            events,
            next_cursor,
        })
    }

    pub fn query_endpoint_activity(
        &self,
        filters: &EndpointAuditFilters,
    ) -> Result<EndpointAuditActivity, AuditQueryError> {
        self.query_endpoint_activity_with_scan_limit(filters, MAX_ENDPOINT_AUDIT_SCAN_ROWS)
    }

    fn query_endpoint_activity_with_scan_limit(
        &self,
        filters: &EndpointAuditFilters,
        max_scan_rows: usize,
    ) -> Result<EndpointAuditActivity, AuditQueryError> {
        let mut buckets = BTreeMap::<String, u64>::new();
        let mut scanned_rows = 0_usize;
        let mut time_series_truncated = false;
        self.scan_request_observations(
            &endpoint_request_observation_filters(filters, None),
            |observation| {
                if scanned_rows >= max_scan_rows {
                    time_series_truncated = true;
                    return false;
                }
                scanned_rows = scanned_rows.saturating_add(1);
                if endpoint_observation_matches(&observation.method, &observation.path, filters) {
                    if let Some(bucket_start) = bucket_start(&observation.timestamp, filters.bucket)
                    {
                        *buckets.entry(bucket_start).or_insert(0) += 1;
                    }
                }

                true
            },
        )?;
        let time_series = buckets
            .into_iter()
            .map(|(bucket_start, count)| EndpointTimeSeriesPoint {
                bucket_start,
                count,
            })
            .collect();

        let mut recent_events = Vec::with_capacity(filters.recent_limit.saturating_add(1));
        let mut recent_events_scanned_rows = 0_usize;
        let mut recent_events_scan_truncated = false;
        self.scan_request_observations(
            &endpoint_request_observation_filters(filters, filters.recent_before_id),
            |observation| {
                if recent_events_scanned_rows >= max_scan_rows {
                    recent_events_scan_truncated = true;
                    return false;
                }
                recent_events_scanned_rows = recent_events_scanned_rows.saturating_add(1);
                if let Some(event) = endpoint_recent_event_from_observation(observation, filters) {
                    recent_events.push(event);
                    if recent_events.len() > filters.recent_limit {
                        return false;
                    }
                }

                true
            },
        )?;
        let has_more = recent_events.len() > filters.recent_limit;
        let recent_events_next_cursor = if has_more && filters.recent_limit > 0 {
            Some(recent_events[filters.recent_limit - 1].id)
        } else {
            None
        };
        if has_more {
            recent_events.truncate(filters.recent_limit);
        }

        Ok(EndpointAuditActivity {
            time_series,
            time_series_truncated,
            recent_events,
            recent_events_next_cursor,
            recent_events_scan_truncated,
        })
    }

    pub fn scan_request_observations(
        &self,
        filters: &RequestObservationFilters,
        mut visitor: impl FnMut(RequestObservation) -> bool,
    ) -> Result<(), AuditQueryError> {
        let (sql, params) = build_request_observation_query(filters);
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(&sql)
            .map_err(|source| AuditQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let mut rows = statement
            .query(params_from_iter(params.iter()))
            .map_err(|source| AuditQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        while let Some(row) = rows.next().map_err(|source| AuditQueryError::Sqlite {
            path: self.path.clone(),
            source,
        })? {
            let observation = request_observation_row(row)
                .map_err(|source| AuditQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?
                .into_observation()?;

            if !visitor(observation) {
                break;
            }
        }

        Ok(())
    }

    pub fn rule_hit_counts(&self) -> Result<HashMap<String, u64>, AuditQueryError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT payload_matched_rule_id, COUNT(*)
                FROM audit_events
                WHERE event_type = 'http.request_observed'
                  AND payload_matched_rule_id IS NOT NULL
                GROUP BY payload_matched_rule_id
                "#,
            )
            .map_err(|source| AuditQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let rows = statement
            .query_map([], |row| {
                let rule_id: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok((rule_id, u64::try_from(count).unwrap_or(u64::MAX)))
            })
            .map_err(|source| AuditQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?
            .collect::<Result<HashMap<_, _>, _>>()
            .map_err(|source| AuditQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        Ok(rows)
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "audit",
                    "lock" => "audit_query_connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite audit query connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

fn build_query(filters: &AuditQueryFilters) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        r#"
        SELECT
            id,
            event_id,
            event_type,
            timestamp,
            schema_version,
            request_id,
            source_ip,
            user_agent,
            actor_json,
            payload_json
        FROM audit_events
        "#,
    );
    let mut clauses = Vec::new();
    let mut params = Vec::new();

    if let Some(from) = &filters.from {
        clauses.push("julianday(timestamp) >= julianday(?)");
        params.push(SqlValue::Text(from.clone()));
    }
    if let Some(to) = &filters.to {
        clauses.push("julianday(timestamp) <= julianday(?)");
        params.push(SqlValue::Text(to.clone()));
    }
    if let Some(event_type) = &filters.event_type {
        clauses.push("event_type = ?");
        params.push(SqlValue::Text(event_type.clone()));
    }
    if let Some(actor) = &filters.actor {
        clauses.push("actor_user_id = ?");
        params.push(SqlValue::Text(actor.clone()));
    }
    if let Some(method) = &filters.method {
        clauses.push("payload_method = ?");
        params.push(SqlValue::Text(method.clone()));
    }
    if let Some(path) = &filters.path {
        clauses.push("payload_path = ?");
        params.push(SqlValue::Text(path.clone()));
    }
    if let Some(status) = filters.status {
        clauses.push("payload_status = ?");
        params.push(SqlValue::Integer(status));
    }
    if let Some(matched_rule_id) = &filters.matched_rule_id {
        clauses.push("payload_matched_rule_id = ?");
        params.push(SqlValue::Text(matched_rule_id.clone()));
    }
    if let Some(before_id) = filters.before_id {
        clauses.push("id < ?");
        params.push(SqlValue::Integer(before_id));
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }

    sql.push_str(" ORDER BY id DESC LIMIT ?");
    params.push(SqlValue::Integer(query_limit(filters.limit)));

    (sql, params)
}

fn build_request_observation_query(filters: &RequestObservationFilters) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        r#"
        SELECT
            id,
            event_id,
            timestamp,
            request_id,
            source_ip,
            user_agent,
            actor_json,
            payload_method,
            payload_path,
            payload_status,
            payload_matched_rule_id,
            payload_json
        FROM audit_events
        "#,
    );
    let mut clauses = vec![
        "event_type = 'http.request_observed'".to_owned(),
        "payload_method IS NOT NULL".to_owned(),
        "payload_path IS NOT NULL".to_owned(),
    ];
    let mut params = Vec::new();

    if let Some(from) = &filters.from {
        clauses.push("julianday(timestamp) >= julianday(?)".to_owned());
        params.push(SqlValue::Text(from.clone()));
    }
    if let Some(to) = &filters.to {
        clauses.push("julianday(timestamp) <= julianday(?)".to_owned());
        params.push(SqlValue::Text(to.clone()));
    }
    if let Some(before_id) = filters.before_id {
        clauses.push("id < ?".to_owned());
        params.push(SqlValue::Integer(before_id));
    }

    let methods = exact_method_filters(&filters.methods);
    if !methods.is_empty() {
        clauses.push(format!(
            "payload_method IN ({})",
            std::iter::repeat_n("?", methods.len())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        params.extend(methods.into_iter().map(SqlValue::Text));
    }
    if let Some(path_exact) = &filters.path_exact {
        clauses.push("payload_path = ?".to_owned());
        params.push(SqlValue::Text(path_exact.clone()));
    } else if let Some(path_prefix) = filters
        .path_prefix
        .as_deref()
        .filter(|prefix| !prefix.is_empty())
    {
        if let Some(upper_bound) = string_prefix_upper_bound(path_prefix) {
            clauses.push("payload_path >= ?".to_owned());
            params.push(SqlValue::Text(path_prefix.to_owned()));
            clauses.push("payload_path < ?".to_owned());
            params.push(SqlValue::Text(upper_bound));
        }
    }

    sql.push_str(" WHERE ");
    sql.push_str(&clauses.join(" AND "));
    sql.push_str(" ORDER BY id DESC");

    (sql, params)
}

fn exact_method_filters(methods: &[String]) -> Vec<String> {
    if methods.iter().any(|method| method.trim() == "*") {
        return Vec::new();
    }

    let mut exact = methods
        .iter()
        .map(|method| method.trim())
        .filter(|method| !method.is_empty())
        .map(str::to_ascii_uppercase)
        .collect::<Vec<_>>();
    exact.sort();
    exact.dedup();
    exact
}

fn string_prefix_upper_bound(prefix: &str) -> Option<String> {
    let mut bytes = prefix.as_bytes().to_vec();
    for index in (0..bytes.len()).rev() {
        if bytes[index] < u8::MAX {
            bytes[index] += 1;
            bytes.truncate(index + 1);
            return String::from_utf8(bytes).ok();
        }
    }

    None
}

fn query_limit(limit: usize) -> i64 {
    i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
}

struct RawAuditEventRow {
    id: i64,
    event_id: String,
    event_type: String,
    timestamp: String,
    schema_version: String,
    request_id: String,
    source_ip: String,
    user_agent: Option<String>,
    actor_json: Option<String>,
    payload_json: String,
}

struct RawRequestObservationRow {
    id: i64,
    event_id: String,
    timestamp: String,
    request_id: String,
    source_ip: String,
    user_agent: Option<String>,
    actor_json: Option<String>,
    method: String,
    path: String,
    status: Option<i64>,
    matched_rule_id: Option<String>,
    payload_json: String,
}

impl RawAuditEventRow {
    fn into_event(self) -> Result<AuditEvent, AuditQueryError> {
        let actor = self
            .actor_json
            .as_deref()
            .map(|json| {
                serde_json::from_str::<Actor>(json).map_err(|source| AuditQueryError::ActorJson {
                    event_id: self.event_id.clone(),
                    source,
                })
            })
            .transpose()?;
        let payload = serde_json::from_str(&self.payload_json).map_err(|source| {
            AuditQueryError::PayloadJson {
                event_id: self.event_id.clone(),
                source,
            }
        })?;

        Ok(AuditEvent {
            event_id: self.event_id,
            event_type: self.event_type,
            timestamp: self.timestamp,
            schema_version: self.schema_version,
            request_id: self.request_id,
            source_ip: self.source_ip,
            user_agent: self.user_agent,
            actor,
            payload,
        })
    }
}

impl RawRequestObservationRow {
    fn into_observation(self) -> Result<RequestObservation, AuditQueryError> {
        let actor = self
            .actor_json
            .as_deref()
            .map(|json| {
                serde_json::from_str::<Actor>(json).map_err(|source| AuditQueryError::ActorJson {
                    event_id: self.event_id.clone(),
                    source,
                })
            })
            .transpose()?;

        Ok(RequestObservation {
            id: self.id,
            event_id: self.event_id,
            timestamp: self.timestamp,
            request_id: self.request_id,
            source_ip: self.source_ip,
            user_agent: self.user_agent,
            actor,
            method: self.method,
            path: self.path,
            status: self.status,
            matched_rule_id: self.matched_rule_id,
            payload_json: self.payload_json,
        })
    }
}

fn raw_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawAuditEventRow> {
    Ok(RawAuditEventRow {
        id: row.get(0)?,
        event_id: row.get(1)?,
        event_type: row.get(2)?,
        timestamp: row.get(3)?,
        schema_version: row.get(4)?,
        request_id: row.get(5)?,
        source_ip: row.get(6)?,
        user_agent: row.get(7)?,
        actor_json: row.get(8)?,
        payload_json: row.get(9)?,
    })
}

fn endpoint_request_observation_filters(
    filters: &EndpointAuditFilters,
    before_id: Option<i64>,
) -> RequestObservationFilters {
    let path_filter = endpoint_audit_path_filter(&filters.endpoint_template);

    RequestObservationFilters {
        from: filters.from.clone(),
        to: filters.to.clone(),
        methods: vec![filters.method.clone()],
        path_exact: path_filter.exact,
        path_prefix: path_filter.prefix,
        before_id,
    }
}

struct EndpointAuditPathFilter {
    exact: Option<String>,
    prefix: Option<String>,
}

fn endpoint_audit_path_filter(template: &str) -> EndpointAuditPathFilter {
    let Some(tail) = template.strip_prefix('/') else {
        return EndpointAuditPathFilter {
            exact: None,
            prefix: None,
        };
    };
    if tail.is_empty() {
        return EndpointAuditPathFilter {
            exact: Some("/".to_owned()),
            prefix: None,
        };
    }

    let mut literal_segments = Vec::new();
    let mut first_dynamic_segment = None;
    for segment in tail.split('/') {
        if segment == "*" || segment == "**" || segment.contains('{') || segment.contains('}') {
            first_dynamic_segment = Some(segment);
            break;
        }
        literal_segments.push(segment);
    }

    let Some(first_dynamic_segment) = first_dynamic_segment else {
        return EndpointAuditPathFilter {
            exact: Some(template.to_owned()),
            prefix: None,
        };
    };
    if literal_segments.is_empty() {
        return EndpointAuditPathFilter {
            exact: None,
            prefix: None,
        };
    }

    let literal_prefix = format!("/{}", literal_segments.join("/"));
    let prefix = if first_dynamic_segment == "**" {
        literal_prefix
    } else {
        format!("{literal_prefix}/")
    };

    EndpointAuditPathFilter {
        exact: None,
        prefix: Some(prefix),
    }
}

fn endpoint_recent_event_from_observation(
    observation: RequestObservation,
    filters: &EndpointAuditFilters,
) -> Option<EndpointRecentEvent> {
    if !endpoint_observation_matches(&observation.method, &observation.path, filters) {
        return None;
    }

    let status = observation.status.or_else(|| {
        serde_json::from_str::<Value>(&observation.payload_json)
            .ok()
            .and_then(|payload| payload_status(&payload))
    });

    Some(EndpointRecentEvent {
        id: observation.id,
        event_id: observation.event_id,
        request_id: observation.request_id,
        timestamp: observation.timestamp,
        method: observation.method,
        path: observation.path,
        status,
        actor: observation.actor.map(|actor| actor.user_id),
    })
}

fn endpoint_observation_matches(
    method: &str,
    concrete_path: &str,
    filters: &EndpointAuditFilters,
) -> bool {
    method == filters.method && template_stateless(concrete_path) == filters.endpoint_template
}

fn bucket_start(timestamp: &str, bucket: EndpointAuditBucket) -> Option<String> {
    let timestamp = OffsetDateTime::parse(timestamp, &Rfc3339).ok()?;
    let month: u8 = timestamp.month().into();

    Some(match bucket {
        EndpointAuditBucket::Hour => format!(
            "{:04}-{month:02}-{:02}T{:02}:00:00Z",
            timestamp.year(),
            timestamp.day(),
            timestamp.hour()
        ),
        EndpointAuditBucket::Day => format!(
            "{:04}-{month:02}-{:02}T00:00:00Z",
            timestamp.year(),
            timestamp.day()
        ),
    })
}

fn payload_status(payload: &Value) -> Option<i64> {
    payload
        .get("status")
        .and_then(|status| {
            status
                .as_i64()
                .or_else(|| status.as_u64().and_then(|value| i64::try_from(value).ok()))
        })
        .or_else(|| {
            let value = payload.get("status")?.as_f64()?;
            if value.is_finite()
                && value.fract() == 0.0
                && value >= i64::MIN as f64
                && value <= i64::MAX as f64
            {
                Some(value as i64)
            } else {
                None
            }
        })
}

fn request_observation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawRequestObservationRow> {
    Ok(RawRequestObservationRow {
        id: row.get(0)?,
        event_id: row.get(1)?,
        timestamp: row.get(2)?,
        request_id: row.get(3)?,
        source_ip: row.get(4)?,
        user_agent: row.get(5)?,
        actor_json: row.get(6)?,
        method: row.get(7)?,
        path: row.get(8)?,
        status: row.get(9)?,
        matched_rule_id: row.get(10)?,
        payload_json: row.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, time::Instant};

    use rusqlite::{params, Connection};
    use serde_json::json;

    use super::*;
    use crate::audit::sqlite_sink::{SqliteSink, SqliteSinkConfig};

    const BENCHMARK_EVENT_COUNT: usize = 1_000_000;

    #[test]
    fn filters_compare_variable_precision_timestamps_chronologically() {
        let db = TempDb::new("query-subsecond");
        create_schema(&db.path);
        insert_event(
            &db.path,
            SeedEvent {
                event_id: "older-event",
                event_type: "audit.test",
                timestamp: "2024-06-01T11:59:59.5Z",
                actor_user_id: "user-1",
                path: "/items/1",
                status: 200,
            },
        );
        insert_event(
            &db.path,
            SeedEvent {
                event_id: "cutoff-event",
                event_type: "audit.test",
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: "user-1",
                path: "/items/1",
                status: 200,
            },
        );
        insert_event(
            &db.path,
            SeedEvent {
                event_id: "fractionally-newer-event",
                event_type: "audit.test",
                timestamp: "2024-06-01T12:00:00.5Z",
                actor_user_id: "user-1",
                path: "/items/1",
                status: 200,
            },
        );

        let page = AuditQueryStore::open(&db.path)
            .expect("query store should open")
            .query(&AuditQueryFilters {
                from: Some("2024-06-01T12:00:00Z".to_owned()),
                to: None,
                event_type: None,
                actor: None,
                method: None,
                path: None,
                status: None,
                matched_rule_id: None,
                limit: 10,
                before_id: None,
            })
            .expect("query should succeed");

        let event_ids = event_ids(&page.events);
        assert_eq!(
            event_ids,
            vec![
                "fractionally-newer-event".to_owned(),
                "cutoff-event".to_owned()
            ]
        );
    }

    #[test]
    fn scans_request_observations_with_method_and_time_filters() {
        let db = TempDb::new("request-observation-scan");
        create_schema(&db.path);
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "old-get",
                timestamp: "2024-06-01T11:59:59Z",
                actor_user_id: "reader-1",
                method: "GET",
                path: "/items/1",
                status: 200,
                matched_rule_id: Some("allow-items"),
            },
        );
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "matching-get",
                timestamp: "2024-06-01T12:00:01Z",
                actor_user_id: "reader-1",
                method: "GET",
                path: "/items/2",
                status: 200,
                matched_rule_id: Some("allow-items"),
            },
        );
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "matching-newer-get",
                timestamp: "2024-06-01T12:00:02Z",
                actor_user_id: "reader-2",
                method: "GET",
                path: "/items/3",
                status: 404,
                matched_rule_id: Some("deny-items"),
            },
        );
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "post",
                timestamp: "2024-06-01T12:00:03Z",
                actor_user_id: "reader-1",
                method: "POST",
                path: "/items/4",
                status: 201,
                matched_rule_id: None,
            },
        );

        let store = AuditQueryStore::open(&db.path).expect("query store should open");
        let mut observed = Vec::new();
        store
            .scan_request_observations(
                &RequestObservationFilters {
                    from: Some("2024-06-01T12:00:00Z".to_owned()),
                    to: Some("2024-06-01T12:00:02Z".to_owned()),
                    methods: vec!["get".to_owned()],
                    path_exact: None,
                    path_prefix: None,
                    before_id: None,
                },
                |event| {
                    observed.push((event.event_id, event.method, event.status));
                    true
                },
            )
            .expect("request observation scan should succeed");

        assert_eq!(
            observed,
            vec![
                ("matching-newer-get".to_owned(), "GET".to_owned(), Some(404)),
                ("matching-get".to_owned(), "GET".to_owned(), Some(200)),
            ]
        );
    }

    #[test]
    fn query_endpoint_activity_uses_sql_method_and_path_filters_before_scan_cap() {
        let db = TempDb::new("endpoint-activity-pushdown");
        create_schema(&db.path);
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "target",
                timestamp: "2024-06-01T00:05:00Z",
                actor_user_id: "reader-1",
                method: "GET",
                path: "/users/123",
                status: 200,
                matched_rule_id: Some("allow-users"),
            },
        );
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "wrong-method",
                timestamp: "2024-06-01T00:06:00Z",
                actor_user_id: "reader-1",
                method: "POST",
                path: "/users/456",
                status: 201,
                matched_rule_id: Some("allow-users"),
            },
        );
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "wrong-path",
                timestamp: "2024-06-01T00:07:00Z",
                actor_user_id: "reader-1",
                method: "GET",
                path: "/admin/status",
                status: 200,
                matched_rule_id: Some("allow-admin"),
            },
        );

        let activity = AuditQueryStore::open(&db.path)
            .expect("query store should open")
            .query_endpoint_activity_with_scan_limit(
                &EndpointAuditFilters {
                    method: "GET".to_owned(),
                    endpoint_template: "/users/{id}".to_owned(),
                    from: Some("2024-06-01T00:00:00Z".to_owned()),
                    to: Some("2024-06-01T01:00:00Z".to_owned()),
                    bucket: EndpointAuditBucket::Hour,
                    recent_limit: 5,
                    recent_before_id: None,
                },
                1,
            )
            .expect("endpoint activity should query");

        assert_eq!(
            activity.time_series,
            vec![EndpointTimeSeriesPoint {
                bucket_start: "2024-06-01T00:00:00Z".to_owned(),
                count: 1,
            }]
        );
        assert!(!activity.time_series_truncated);
        assert_eq!(activity.recent_events.len(), 1);
        assert_eq!(activity.recent_events[0].event_id, "target");
        assert!(!activity.recent_events_scan_truncated);
    }

    #[test]
    fn query_endpoint_activity_flags_truncated_time_series_at_scan_cap() {
        let db = TempDb::new("endpoint-activity-truncated");
        create_schema(&db.path);
        for index in 0..3 {
            insert_observation_event(
                &db.path,
                SeedObservationEvent {
                    event_id: &format!("target-{index}"),
                    timestamp: &format!("2024-06-01T00:0{index}:00Z"),
                    actor_user_id: "reader-1",
                    method: "GET",
                    path: &format!("/users/{index}"),
                    status: 200,
                    matched_rule_id: Some("allow-users"),
                },
            );
        }

        let activity = AuditQueryStore::open(&db.path)
            .expect("query store should open")
            .query_endpoint_activity_with_scan_limit(
                &EndpointAuditFilters {
                    method: "GET".to_owned(),
                    endpoint_template: "/users/{id}".to_owned(),
                    from: Some("2024-06-01T00:00:00Z".to_owned()),
                    to: Some("2024-06-01T01:00:00Z".to_owned()),
                    bucket: EndpointAuditBucket::Hour,
                    recent_limit: 10,
                    recent_before_id: None,
                },
                2,
            )
            .expect("endpoint activity should query");

        assert_eq!(
            activity.time_series,
            vec![EndpointTimeSeriesPoint {
                bucket_start: "2024-06-01T00:00:00Z".to_owned(),
                count: 2,
            }]
        );
        assert!(activity.time_series_truncated);
        assert_eq!(activity.recent_events.len(), 2);
        assert!(activity.recent_events_scan_truncated);
    }

    #[test]
    fn rule_hit_counts_count_observed_requests_by_matched_rule_id() {
        let db = TempDb::new("rule-hit-counts");
        create_schema(&db.path);
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "allow-1",
                timestamp: "2024-06-01T12:00:00Z",
                actor_user_id: "reader-1",
                method: "GET",
                path: "/items/1",
                status: 200,
                matched_rule_id: Some("allow-items"),
            },
        );
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "allow-2",
                timestamp: "2024-06-01T12:00:01Z",
                actor_user_id: "reader-1",
                method: "GET",
                path: "/items/2",
                status: 200,
                matched_rule_id: Some("allow-items"),
            },
        );
        insert_observation_event(
            &db.path,
            SeedObservationEvent {
                event_id: "deny-1",
                timestamp: "2024-06-01T12:00:02Z",
                actor_user_id: "reader-1",
                method: "GET",
                path: "/items/3",
                status: 403,
                matched_rule_id: Some("deny-items"),
            },
        );
        insert_event(
            &db.path,
            SeedEvent {
                event_id: "authz-duplicate",
                event_type: "authz.allowed",
                timestamp: "2024-06-01T12:00:03Z",
                actor_user_id: "reader-1",
                path: "/items/1",
                status: 200,
            },
        );

        let counts = AuditQueryStore::open(&db.path)
            .expect("query store should open")
            .rule_hit_counts()
            .expect("rule hit counts should query");

        assert_eq!(counts.get("allow-items"), Some(&2));
        assert_eq!(counts.get("deny-items"), Some(&1));
        assert_eq!(counts.get("authz-duplicate"), None);
    }

    /// Run with:
    /// `cargo test --workspace -- --ignored million_row_filtered_queries_complete_under_500ms --nocapture`
    #[test]
    #[ignore]
    fn million_row_filtered_queries_complete_under_500ms() {
        let db = TempDb::new("query-benchmark");
        create_schema(&db.path);
        let setup_started = Instant::now();
        bulk_insert_benchmark_events(&db.path, BENCHMARK_EVENT_COUNT);
        println!(
            "inserted {BENCHMARK_EVENT_COUNT} audit rows in {:?}",
            setup_started.elapsed()
        );

        let store = AuditQueryStore::open(&db.path).expect("query store should open");
        let max_latency = std::time::Duration::from_millis(500);

        let time_and_type = assert_query_under(
            &store,
            AuditQueryFilters {
                from: Some("2026-01-06T18:53:20Z".to_owned()),
                to: Some("2026-01-06T21:40:00Z".to_owned()),
                event_type: Some("audit.benchmark.42".to_owned()),
                actor: None,
                method: None,
                path: None,
                status: None,
                matched_rule_id: None,
                limit: 100,
                before_id: None,
            },
            "time-range + event_type",
            max_latency,
        );
        let actor_and_path = assert_query_under(
            &store,
            AuditQueryFilters {
                from: None,
                to: None,
                event_type: None,
                actor: Some("actor-123".to_owned()),
                method: None,
                path: Some("/benchmark/123".to_owned()),
                status: None,
                matched_rule_id: None,
                limit: 100,
                before_id: None,
            },
            "actor + path",
            max_latency,
        );
        let status_only = assert_query_under(
            &store,
            AuditQueryFilters {
                from: None,
                to: None,
                event_type: None,
                actor: None,
                method: None,
                path: None,
                status: Some(204),
                matched_rule_id: None,
                limit: 100,
                before_id: None,
            },
            "status only",
            max_latency,
        );
        let deep_page = assert_query_under(
            &store,
            AuditQueryFilters {
                from: None,
                to: None,
                event_type: None,
                actor: None,
                method: None,
                path: None,
                status: None,
                matched_rule_id: None,
                limit: 100,
                before_id: Some(500_000),
            },
            "deep page",
            max_latency,
        );

        println!(
            "benchmark query latencies: time-range + event_type={time_and_type:?}, actor + path={actor_and_path:?}, status only={status_only:?}, deep page={deep_page:?}"
        );
    }

    fn assert_query_under(
        store: &AuditQueryStore,
        filters: AuditQueryFilters,
        label: &str,
        max_latency: std::time::Duration,
    ) -> std::time::Duration {
        let started = Instant::now();
        let page = store.query(&filters).expect("benchmark query should run");
        let elapsed = started.elapsed();
        println!("{label}: {elapsed:?} for {} rows", page.events.len());
        assert!(
            !page.events.is_empty(),
            "{label} should return benchmark rows"
        );
        assert!(
            elapsed < max_latency,
            "{label} took {elapsed:?}, expected under {max_latency:?}"
        );
        elapsed
    }

    fn create_schema(path: &PathBuf) {
        drop(
            SqliteSink::new(SqliteSinkConfig {
                path: path.clone(),
                retention_days: None,
            })
            .expect("SQLite sink should create schema"),
        );
    }

    struct SeedEvent<'a> {
        event_id: &'a str,
        event_type: &'a str,
        timestamp: &'a str,
        actor_user_id: &'a str,
        path: &'a str,
        status: i64,
    }

    fn insert_event(path: &PathBuf, event: SeedEvent<'_>) {
        let connection = Connection::open(path).expect("test database should open");
        let actor_json = json!({
            "user_id": event.actor_user_id,
            "roles": ["reader"],
            "auth_mode": "bearer_token"
        })
        .to_string();
        let payload_json = json!({
            "method": "GET",
            "path": event.path,
            "status": event.status,
            "matched_rule_id": "authz-duplicate"
        })
        .to_string();

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
                    payload_matched_rule_id,
                    payload_json
                ) VALUES (?1, ?2, ?3, '0.1.0', 'request-test', '203.0.113.10', ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                "#,
                params![
                    event.event_id,
                    event.event_type,
                    event.timestamp,
                    event.actor_user_id,
                    actor_json,
                    "GET",
                    event.path,
                    event.status,
                    "authz-duplicate",
                    payload_json
                ],
            )
            .expect("event should insert");
    }

    struct SeedObservationEvent<'a> {
        event_id: &'a str,
        timestamp: &'a str,
        actor_user_id: &'a str,
        method: &'a str,
        path: &'a str,
        status: i64,
        matched_rule_id: Option<&'a str>,
    }

    fn insert_observation_event(path: &PathBuf, event: SeedObservationEvent<'_>) {
        let connection = Connection::open(path).expect("test database should open");
        let actor_json = json!({
            "user_id": event.actor_user_id,
            "roles": ["reader"],
            "auth_mode": "bearer_token"
        })
        .to_string();
        let mut payload = json!({
            "method": event.method,
            "path": event.path,
            "status": event.status,
            "policy_decision": "allowed"
        });
        if let Some(matched_rule_id) = event.matched_rule_id {
            payload["matched_rule_id"] = json!(matched_rule_id);
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
                    payload_matched_rule_id,
                    payload_json
                ) VALUES (?1, 'http.request_observed', ?2, '0.1.0', 'request-test', '203.0.113.10', ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                "#,
                params![
                    event.event_id,
                    event.timestamp,
                    event.actor_user_id,
                    actor_json,
                    event.method,
                    event.path,
                    event.status,
                    event.matched_rule_id,
                    payload_json
                ],
            )
            .expect("observation event should insert");
    }

    fn bulk_insert_benchmark_events(path: &PathBuf, event_count: usize) {
        let mut connection = Connection::open(path).expect("benchmark database should open");
        connection
            .execute_batch(
                r#"
                PRAGMA synchronous=OFF;
                PRAGMA temp_store=MEMORY;
                "#,
            )
            .expect("benchmark pragmas should apply");

        let chunk_size = 10_000;
        for chunk_start in (0..event_count).step_by(chunk_size) {
            let chunk_end = (chunk_start + chunk_size).min(event_count);
            let transaction = connection
                .transaction()
                .expect("benchmark transaction should start");

            {
                let mut statement = transaction
                    .prepare_cached(
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
                            payload_matched_rule_id,
                            payload_json
                        ) VALUES (?1, ?2, ?3, '0.1.0', ?4, '203.0.113.10', ?5, ?6, ?7, ?8, ?9, ?10, ?11)
                        "#,
                    )
                    .expect("benchmark insert should prepare");

                for index in chunk_start..chunk_end {
                    let event_type = format!("audit.benchmark.{}", index % 100);
                    let actor_user_id = format!("actor-{}", index % 1000);
                    let payload_method = if index % 3 == 0 { "POST" } else { "GET" };
                    let payload_path = format!("/benchmark/{}", index % 1000);
                    let status = 200 + i64::try_from(index % 5).expect("status should fit");
                    let actor_json = format!(
                        r#"{{"user_id":"{actor_user_id}","roles":["admin"],"auth_mode":"bearer_token"}}"#
                    );
                    let payload_json = format!(
                        r#"{{"method":"{payload_method}","path":"{payload_path}","status":{status}}}"#
                    );

                    statement
                        .execute(params![
                            format!("benchmark-event-{index:07}"),
                            event_type,
                            benchmark_timestamp(index),
                            format!("benchmark-request-{index:07}"),
                            actor_user_id,
                            actor_json,
                            payload_method,
                            payload_path,
                            status,
                            Option::<String>::None,
                            payload_json
                        ])
                        .expect("benchmark event should insert");
                }
            }

            transaction
                .commit()
                .expect("benchmark transaction should commit");
        }
    }

    fn benchmark_timestamp(index: usize) -> String {
        let second_of_day = index % 86_400;
        let day = 1 + index / 86_400;
        let hour = second_of_day / 3_600;
        let minute = (second_of_day % 3_600) / 60;
        let second = second_of_day % 60;

        format!("2026-01-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    }

    fn event_ids(events: &[AuditEvent]) -> Vec<String> {
        events.iter().map(|event| event.event_id.clone()).collect()
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-audit-query-{test_name}-{}.sqlite",
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
