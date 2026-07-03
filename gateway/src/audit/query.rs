use std::{
    error::Error,
    fmt,
    path::PathBuf,
    sync::{Mutex, MutexGuard},
};

use rusqlite::{params_from_iter, types::Value as SqlValue, Connection};

use crate::{
    audit::{Actor, AuditEvent},
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
};

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
