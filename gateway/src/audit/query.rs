use std::{
    collections::BTreeMap,
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

const HTTP_REQUEST_OBSERVED: &str = "http.request_observed";
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
    pub path: Option<String>,
    pub status: Option<i64>,
    pub limit: usize,
    pub before_id: Option<i64>,
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
    pub recent_events: Vec<EndpointRecentEvent>,
    pub recent_events_next_cursor: Option<i64>,
}

#[derive(Clone, Debug, Serialize)]
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
        let series_rows =
            self.query_endpoint_audit_rows(filters.from.as_deref(), filters.to.as_deref(), None)?;
        let time_series = endpoint_time_series(&series_rows, filters);

        let recent_rows = self.query_endpoint_audit_rows(
            filters.from.as_deref(),
            filters.to.as_deref(),
            filters.recent_before_id,
        )?;
        let mut recent_events = recent_rows
            .into_iter()
            .filter_map(|row| row.into_recent_event(filters))
            .collect::<Vec<_>>();
        let has_more = recent_events.len() > filters.recent_limit;
        if has_more {
            recent_events.truncate(filters.recent_limit);
        }
        let recent_events_next_cursor = has_more.then(|| {
            recent_events
                .last()
                .expect("over-limit recent event query should leave at least one row")
                .id
        });

        Ok(EndpointAuditActivity {
            time_series,
            recent_events,
            recent_events_next_cursor,
        })
    }

    fn query_endpoint_audit_rows(
        &self,
        from: Option<&str>,
        to: Option<&str>,
        before_id: Option<i64>,
    ) -> Result<Vec<EndpointAuditRow>, AuditQueryError> {
        let (sql, params) = build_endpoint_audit_query(from, to, before_id);
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(&sql)
            .map_err(|source| AuditQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        let rows = statement
            .query_map(params_from_iter(params.iter()), endpoint_audit_row)
            .map_err(|source| AuditQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?
            .collect::<Result<Vec<_>, _>>()
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
    if let Some(path) = &filters.path {
        clauses.push("payload_path = ?");
        params.push(SqlValue::Text(path.clone()));
    }
    if let Some(status) = filters.status {
        clauses.push("payload_status = ?");
        params.push(SqlValue::Integer(status));
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

fn build_endpoint_audit_query(
    from: Option<&str>,
    to: Option<&str>,
    before_id: Option<i64>,
) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        r#"
        SELECT
            id,
            event_id,
            timestamp,
            request_id,
            actor_user_id,
            payload_path,
            payload_status,
            payload_json
        FROM audit_events
        WHERE event_type = ? AND payload_path IS NOT NULL
        "#,
    );
    let mut params = vec![SqlValue::Text(HTTP_REQUEST_OBSERVED.to_owned())];

    if let Some(from) = from {
        sql.push_str(" AND julianday(timestamp) >= julianday(?)");
        params.push(SqlValue::Text(from.to_owned()));
    }
    if let Some(to) = to {
        sql.push_str(" AND julianday(timestamp) <= julianday(?)");
        params.push(SqlValue::Text(to.to_owned()));
    }
    if let Some(before_id) = before_id {
        sql.push_str(" AND id < ?");
        params.push(SqlValue::Integer(before_id));
    }

    sql.push_str(" ORDER BY id DESC");
    (sql, params)
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

struct EndpointAuditRow {
    id: i64,
    event_id: String,
    timestamp: String,
    request_id: String,
    actor_user_id: Option<String>,
    payload_path: String,
    payload_status: Option<i64>,
    payload_json: String,
}

impl EndpointAuditRow {
    fn into_recent_event(self, filters: &EndpointAuditFilters) -> Option<EndpointRecentEvent> {
        let payload = serde_json::from_str::<Value>(&self.payload_json).ok()?;
        let method = payload.get("method")?.as_str()?.to_owned();
        if !endpoint_audit_row_matches(&method, &self.payload_path, filters) {
            return None;
        }

        Some(EndpointRecentEvent {
            id: self.id,
            event_id: self.event_id,
            request_id: self.request_id,
            timestamp: self.timestamp,
            method,
            path: self.payload_path,
            status: self.payload_status.or_else(|| payload_status(&payload)),
            actor: self.actor_user_id,
        })
    }
}

fn endpoint_audit_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EndpointAuditRow> {
    Ok(EndpointAuditRow {
        id: row.get(0)?,
        event_id: row.get(1)?,
        timestamp: row.get(2)?,
        request_id: row.get(3)?,
        actor_user_id: row.get(4)?,
        payload_path: row.get(5)?,
        payload_status: row.get(6)?,
        payload_json: row.get(7)?,
    })
}

fn endpoint_time_series(
    rows: &[EndpointAuditRow],
    filters: &EndpointAuditFilters,
) -> Vec<EndpointTimeSeriesPoint> {
    let mut buckets = BTreeMap::<String, u64>::new();

    for row in rows {
        let Ok(payload) = serde_json::from_str::<Value>(&row.payload_json) else {
            continue;
        };
        let Some(method) = payload.get("method").and_then(Value::as_str) else {
            continue;
        };
        if !endpoint_audit_row_matches(method, &row.payload_path, filters) {
            continue;
        }
        let Some(bucket_start) = bucket_start(&row.timestamp, filters.bucket) else {
            continue;
        };

        *buckets.entry(bucket_start).or_insert(0) += 1;
    }

    buckets
        .into_iter()
        .map(|(bucket_start, count)| EndpointTimeSeriesPoint {
            bucket_start,
            count,
        })
        .collect()
}

fn endpoint_audit_row_matches(
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
                path: None,
                status: None,
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
                path: None,
                status: None,
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
                path: Some("/benchmark/123".to_owned()),
                status: None,
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
                path: None,
                status: Some(204),
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
                path: None,
                status: None,
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
            "path": event.path,
            "status": event.status
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
                    payload_path,
                    payload_status,
                    payload_json
                ) VALUES (?1, ?2, ?3, '0.1.0', 'request-test', '203.0.113.10', ?4, ?5, ?6, ?7, ?8)
                "#,
                params![
                    event.event_id,
                    event.event_type,
                    event.timestamp,
                    event.actor_user_id,
                    actor_json,
                    event.path,
                    event.status,
                    payload_json
                ],
            )
            .expect("event should insert");
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
                            payload_path,
                            payload_status,
                            payload_json
                        ) VALUES (?1, ?2, ?3, '0.1.0', ?4, '203.0.113.10', ?5, ?6, ?7, ?8, ?9)
                        "#,
                    )
                    .expect("benchmark insert should prepare");

                for index in chunk_start..chunk_end {
                    let event_type = format!("audit.benchmark.{}", index % 100);
                    let actor_user_id = format!("actor-{}", index % 1000);
                    let payload_path = format!("/benchmark/{}", index % 1000);
                    let status = 200 + i64::try_from(index % 5).expect("status should fit");
                    let actor_json = format!(
                        r#"{{"user_id":"{actor_user_id}","roles":["admin"],"auth_mode":"bearer_token"}}"#
                    );
                    let payload_json = format!(r#"{{"path":"{payload_path}","status":{status}}}"#);

                    statement
                        .execute(params![
                            format!("benchmark-event-{index:07}"),
                            event_type,
                            benchmark_timestamp(index),
                            format!("benchmark-request-{index:07}"),
                            actor_user_id,
                            actor_json,
                            payload_path,
                            status,
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
