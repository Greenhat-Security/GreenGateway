use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::metrics::LOCK_POISON_RECOVERIES_TOTAL;

#[derive(Clone)]
pub struct DiscoveryQueryStore {
    path: PathBuf,
    connection: std::sync::Arc<Mutex<Connection>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointSort {
    LastSeen,
    CallCount,
    FirstSeen,
}

pub struct EndpointListFilters {
    pub method: Option<String>,
    pub endpoint_template_contains: Option<String>,
    pub endpoint_template_prefix: Option<String>,
    pub first_seen_after: Option<String>,
    pub first_seen_before: Option<String>,
    pub last_seen_after: Option<String>,
    pub last_seen_before: Option<String>,
    pub min_call_count: Option<i64>,
    pub sort: EndpointSort,
    pub limit: usize,
    pub cursor: Option<String>,
}

pub struct PrincipalPageFilters {
    pub limit: usize,
    pub cursor: Option<String>,
}

#[derive(Serialize)]
pub struct EndpointListPage {
    pub endpoints: Vec<EndpointSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointSummary {
    pub method: String,
    pub endpoint_template: String,
    pub first_seen: String,
    pub last_seen: String,
    pub call_count: u64,
    pub distinct_principal_count: u64,
    pub latency: EndpointLatencySummary,
    pub status_counts: Vec<StatusCount>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointAggregateDetail {
    pub method: String,
    pub endpoint_template: String,
    pub first_seen: String,
    pub last_seen: String,
    pub call_count: u64,
    pub distinct_principal_count: u64,
    pub latency: EndpointLatencyDetail,
    pub status_counts: Vec<StatusCount>,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointLatencySummary {
    pub count: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointLatencyDetail {
    pub count: u64,
    pub p50_ms: u64,
    pub p95_ms: u64,
    pub p99_ms: u64,
    pub sample_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct StatusCount {
    pub status: u16,
    pub count: u64,
}

#[derive(Serialize)]
pub struct PrincipalPage {
    pub principals: Vec<EndpointPrincipal>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointPrincipal {
    pub user_id: String,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug)]
pub enum DiscoveryQueryError {
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Sqlite {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Json {
        context: &'static str,
        source: serde_json::Error,
    },
    InvalidCursor {
        parameter: &'static str,
    },
}

impl fmt::Display for DiscoveryQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => write!(
                formatter,
                "failed to open SQLite discovery query store at {}: {source}",
                path.display()
            ),
            Self::Sqlite { path, source } => write!(
                formatter,
                "failed to query SQLite discovery inventory at {}: {source}",
                path.display()
            ),
            Self::Json { context, source } => {
                write!(formatter, "failed to decode discovery {context}: {source}")
            }
            Self::InvalidCursor { parameter } => {
                write!(formatter, "invalid discovery query cursor: {parameter}")
            }
        }
    }
}

impl Error for DiscoveryQueryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Sqlite { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::InvalidCursor { .. } => None,
        }
    }
}

impl DiscoveryQueryStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DiscoveryQueryError> {
        let path = path.into();
        let connection = Connection::open(&path).map_err(|source| DiscoveryQueryError::Open {
            path: path.clone(),
            source,
        })?;

        Ok(Self {
            path,
            connection: std::sync::Arc::new(Mutex::new(connection)),
        })
    }

    pub fn list_endpoints(
        &self,
        filters: &EndpointListFilters,
    ) -> Result<EndpointListPage, DiscoveryQueryError> {
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<EndpointCursor>("cursor", value))
            .transpose()?;
        if let Some(cursor) = cursor.as_ref() {
            if cursor.sort != filters.sort {
                return Err(DiscoveryQueryError::InvalidCursor {
                    parameter: "cursor",
                });
            }
        }

        let (sql, params) = build_endpoint_list_query(filters, cursor.as_ref());
        let raw_rows = {
            let connection = self.connection_guard();
            let mut statement =
                connection
                    .prepare(&sql)
                    .map_err(|source| DiscoveryQueryError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            let rows = statement
                .query_map(
                    params_from_iter(params.iter()),
                    RawEndpointAggregate::from_row,
                )
                .map_err(|source| DiscoveryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| DiscoveryQueryError::Sqlite {
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

        let next_cursor = if has_more {
            rows.last()
                .map(|row| endpoint_cursor(row, filters.sort))
                .transpose()?
        } else {
            None
        };

        let connection = self.connection_guard();
        let endpoints = rows
            .into_iter()
            .map(|row| {
                let status_counts = load_status_counts(
                    &connection,
                    &self.path,
                    &row.method,
                    &row.endpoint_template,
                )?;
                Ok(row.into_summary(status_counts))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(EndpointListPage {
            endpoints,
            next_cursor,
        })
    }

    pub fn get_endpoint(
        &self,
        method: &str,
        endpoint_template: &str,
    ) -> Result<Option<EndpointAggregateDetail>, DiscoveryQueryError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT
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
                FROM discovery_endpoint_aggregates
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
            )
            .map_err(|source| DiscoveryQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        let Some(row) = statement
            .query_row(
                params![method, endpoint_template],
                RawEndpointAggregate::from_row,
            )
            .optional()
            .map_err(|source| DiscoveryQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?
        else {
            return Ok(None);
        };

        let status_counts =
            load_status_counts(&connection, &self.path, &row.method, &row.endpoint_template)?;
        Ok(Some(row.into_detail(status_counts)?))
    }

    pub fn list_principals(
        &self,
        method: &str,
        endpoint_template: &str,
        filters: &PrincipalPageFilters,
    ) -> Result<PrincipalPage, DiscoveryQueryError> {
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<PrincipalCursor>("principal_cursor", value))
            .transpose()?;
        let (sql, params) =
            build_principal_query(method, endpoint_template, filters.limit, cursor.as_ref());

        let rows = {
            let connection = self.connection_guard();
            let mut statement =
                connection
                    .prepare(&sql)
                    .map_err(|source| DiscoveryQueryError::Sqlite {
                        path: self.path.clone(),
                        source,
                    })?;
            let rows = statement
                .query_map(params_from_iter(params.iter()), |row| {
                    Ok(EndpointPrincipal {
                        user_id: row.get(0)?,
                        first_seen: row.get(1)?,
                        last_seen: row.get(2)?,
                    })
                })
                .map_err(|source| DiscoveryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|source| DiscoveryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
            rows
        };

        let mut principals = rows;
        let has_more = principals.len() > filters.limit;
        if has_more {
            principals.truncate(filters.limit);
        }
        let next_cursor = if has_more {
            principals
                .last()
                .map(|principal| {
                    encode_cursor(&PrincipalCursor {
                        last_seen: principal.last_seen.clone(),
                        user_id: principal.user_id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };

        Ok(PrincipalPage {
            principals,
            next_cursor,
        })
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "discovery",
                    "lock" => "discovery_query_connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite discovery query connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

#[derive(Debug)]
struct RawEndpointAggregate {
    method: String,
    endpoint_template: String,
    first_seen: String,
    last_seen: String,
    call_count: i64,
    latency_count: i64,
    latency_p50_ms: i64,
    latency_p95_ms: i64,
    latency_p99_ms: i64,
    latency_samples_json: String,
    distinct_principal_count: i64,
    updated_at: String,
}

impl RawEndpointAggregate {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            method: row.get(0)?,
            endpoint_template: row.get(1)?,
            first_seen: row.get(2)?,
            last_seen: row.get(3)?,
            call_count: row.get(4)?,
            latency_count: row.get(5)?,
            latency_p50_ms: row.get(6)?,
            latency_p95_ms: row.get(7)?,
            latency_p99_ms: row.get(8)?,
            latency_samples_json: row.get(9)?,
            distinct_principal_count: row.get(10)?,
            updated_at: row.get(11)?,
        })
    }

    fn latency_summary(&self) -> EndpointLatencySummary {
        EndpointLatencySummary {
            count: non_negative_i64_to_u64(self.latency_count),
            p50_ms: non_negative_i64_to_u64(self.latency_p50_ms),
            p95_ms: non_negative_i64_to_u64(self.latency_p95_ms),
            p99_ms: non_negative_i64_to_u64(self.latency_p99_ms),
        }
    }

    fn into_summary(self, status_counts: Vec<StatusCount>) -> EndpointSummary {
        let latency = self.latency_summary();

        EndpointSummary {
            method: self.method,
            endpoint_template: self.endpoint_template,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            call_count: non_negative_i64_to_u64(self.call_count),
            distinct_principal_count: non_negative_i64_to_u64(self.distinct_principal_count),
            latency,
            status_counts,
        }
    }

    fn into_detail(
        self,
        status_counts: Vec<StatusCount>,
    ) -> Result<EndpointAggregateDetail, DiscoveryQueryError> {
        let samples =
            serde_json::from_str::<Vec<u64>>(&self.latency_samples_json).map_err(|source| {
                DiscoveryQueryError::Json {
                    context: "latency samples",
                    source,
                }
            })?;
        let latency = EndpointLatencyDetail {
            count: non_negative_i64_to_u64(self.latency_count),
            p50_ms: non_negative_i64_to_u64(self.latency_p50_ms),
            p95_ms: non_negative_i64_to_u64(self.latency_p95_ms),
            p99_ms: non_negative_i64_to_u64(self.latency_p99_ms),
            sample_count: samples.len(),
        };

        Ok(EndpointAggregateDetail {
            method: self.method,
            endpoint_template: self.endpoint_template,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            call_count: non_negative_i64_to_u64(self.call_count),
            distinct_principal_count: non_negative_i64_to_u64(self.distinct_principal_count),
            latency,
            status_counts,
            updated_at: self.updated_at,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct EndpointCursor {
    sort: EndpointSort,
    sort_value: String,
    method: String,
    endpoint_template: String,
}

#[derive(Deserialize, Serialize)]
struct PrincipalCursor {
    last_seen: String,
    user_id: String,
}

impl Serialize for EndpointSort {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EndpointSort {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl EndpointSort {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "last_seen" => Ok(Self::LastSeen),
            "call_count" => Ok(Self::CallCount),
            "first_seen" => Ok(Self::FirstSeen),
            _ => Err("sort"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::LastSeen => "last_seen",
            Self::CallCount => "call_count",
            Self::FirstSeen => "first_seen",
        }
    }

    fn order_expression(self) -> &'static str {
        match self {
            Self::LastSeen => "julianday(a.last_seen)",
            Self::CallCount => "a.call_count",
            Self::FirstSeen => "julianday(a.first_seen)",
        }
    }
}

fn build_endpoint_list_query(
    filters: &EndpointListFilters,
    cursor: Option<&EndpointCursor>,
) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        r#"
        SELECT
            a.method,
            a.endpoint_template,
            a.first_seen,
            a.last_seen,
            a.call_count,
            a.latency_count,
            a.latency_p50_ms,
            a.latency_p95_ms,
            a.latency_p99_ms,
            a.latency_samples_json,
            a.distinct_principal_count,
            a.updated_at
        FROM discovery_endpoint_aggregates a
        "#,
    );
    let mut clauses = Vec::new();
    let mut params = Vec::new();

    if let Some(method) = &filters.method {
        clauses.push("a.method = ?");
        params.push(SqlValue::Text(method.clone()));
    }
    if let Some(endpoint_template_contains) = &filters.endpoint_template_contains {
        clauses.push("a.endpoint_template LIKE ? ESCAPE '\\'");
        params.push(SqlValue::Text(format!(
            "%{}%",
            like_escape(endpoint_template_contains)
        )));
    }
    if let Some(endpoint_template_prefix) = &filters.endpoint_template_prefix {
        clauses.push("a.endpoint_template LIKE ? ESCAPE '\\'");
        params.push(SqlValue::Text(format!(
            "{}%",
            like_escape(endpoint_template_prefix)
        )));
    }
    if let Some(first_seen_after) = &filters.first_seen_after {
        clauses.push("julianday(a.first_seen) >= julianday(?)");
        params.push(SqlValue::Text(first_seen_after.clone()));
    }
    if let Some(first_seen_before) = &filters.first_seen_before {
        clauses.push("julianday(a.first_seen) <= julianday(?)");
        params.push(SqlValue::Text(first_seen_before.clone()));
    }
    if let Some(last_seen_after) = &filters.last_seen_after {
        clauses.push("julianday(a.last_seen) >= julianday(?)");
        params.push(SqlValue::Text(last_seen_after.clone()));
    }
    if let Some(last_seen_before) = &filters.last_seen_before {
        clauses.push("julianday(a.last_seen) <= julianday(?)");
        params.push(SqlValue::Text(last_seen_before.clone()));
    }
    if let Some(min_call_count) = filters.min_call_count {
        clauses.push("a.call_count >= ?");
        params.push(SqlValue::Integer(min_call_count));
    }
    if let Some(cursor) = cursor {
        let expression = filters.sort.order_expression();
        clauses.push(cursor_clause(filters.sort));
        match filters.sort {
            EndpointSort::CallCount => {
                let value = cursor.sort_value.parse::<i64>().unwrap_or(i64::MAX);
                params.push(SqlValue::Integer(value));
                params.push(SqlValue::Integer(value));
            }
            EndpointSort::LastSeen | EndpointSort::FirstSeen => {
                params.push(SqlValue::Text(cursor.sort_value.clone()));
                params.push(SqlValue::Text(cursor.sort_value.clone()));
            }
        }
        params.push(SqlValue::Text(cursor.method.clone()));
        params.push(SqlValue::Text(cursor.method.clone()));
        params.push(SqlValue::Text(cursor.endpoint_template.clone()));
        debug_assert!(cursor_clause(filters.sort).contains(expression));
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }

    sql.push_str(" ORDER BY ");
    sql.push_str(filters.sort.order_expression());
    sql.push_str(" DESC, a.method ASC, a.endpoint_template ASC LIMIT ?");
    params.push(SqlValue::Integer(query_limit(filters.limit)));

    (sql, params)
}

fn cursor_clause(sort: EndpointSort) -> &'static str {
    match sort {
        EndpointSort::CallCount => {
            "(a.call_count < ? OR (a.call_count = ? AND (a.method > ? OR (a.method = ? AND a.endpoint_template > ?))))"
        }
        EndpointSort::LastSeen => {
            "(julianday(a.last_seen) < julianday(?) OR (julianday(a.last_seen) = julianday(?) AND (a.method > ? OR (a.method = ? AND a.endpoint_template > ?))))"
        }
        EndpointSort::FirstSeen => {
            "(julianday(a.first_seen) < julianday(?) OR (julianday(a.first_seen) = julianday(?) AND (a.method > ? OR (a.method = ? AND a.endpoint_template > ?))))"
        }
    }
}

fn build_principal_query(
    method: &str,
    endpoint_template: &str,
    limit: usize,
    cursor: Option<&PrincipalCursor>,
) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        r#"
        SELECT user_id, first_seen, last_seen
        FROM discovery_endpoint_principals
        WHERE method = ? AND endpoint_template = ?
        "#,
    );
    let mut params = vec![
        SqlValue::Text(method.to_owned()),
        SqlValue::Text(endpoint_template.to_owned()),
    ];

    if let Some(cursor) = cursor {
        sql.push_str(
            " AND (julianday(last_seen) < julianday(?) OR (julianday(last_seen) = julianday(?) AND user_id > ?))",
        );
        params.push(SqlValue::Text(cursor.last_seen.clone()));
        params.push(SqlValue::Text(cursor.last_seen.clone()));
        params.push(SqlValue::Text(cursor.user_id.clone()));
    }

    sql.push_str(" ORDER BY julianday(last_seen) DESC, user_id ASC LIMIT ?");
    params.push(SqlValue::Integer(query_limit(limit)));

    (sql, params)
}

fn endpoint_cursor(
    row: &RawEndpointAggregate,
    sort: EndpointSort,
) -> Result<String, DiscoveryQueryError> {
    let sort_value = match sort {
        EndpointSort::LastSeen => row.last_seen.clone(),
        EndpointSort::CallCount => row.call_count.to_string(),
        EndpointSort::FirstSeen => row.first_seen.clone(),
    };

    encode_cursor(&EndpointCursor {
        sort,
        sort_value,
        method: row.method.clone(),
        endpoint_template: row.endpoint_template.clone(),
    })
}

fn load_status_counts(
    connection: &Connection,
    path: &Path,
    method: &str,
    endpoint_template: &str,
) -> Result<Vec<StatusCount>, DiscoveryQueryError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT status, count
            FROM discovery_endpoint_status_counts
            WHERE method = ?1 AND endpoint_template = ?2
            ORDER BY count DESC, status ASC
            "#,
        )
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;

    let rows = statement
        .query_map(params![method, endpoint_template], |row| {
            let status: i64 = row.get(0)?;
            Ok(StatusCount {
                status: u16::try_from(status).unwrap_or(0),
                count: non_negative_i64_to_u64(row.get(1)?),
            })
        })
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(rows)
}

fn encode_cursor<T: Serialize>(cursor: &T) -> Result<String, DiscoveryQueryError> {
    let json = serde_json::to_vec(cursor).map_err(|source| DiscoveryQueryError::Json {
        context: "cursor",
        source,
    })?;

    Ok(hex::encode(json))
}

fn decode_cursor<T: DeserializeOwned>(
    parameter: &'static str,
    value: &str,
) -> Result<T, DiscoveryQueryError> {
    let bytes = hex::decode(value).map_err(|_| DiscoveryQueryError::InvalidCursor { parameter })?;
    serde_json::from_slice(&bytes).map_err(|_| DiscoveryQueryError::InvalidCursor { parameter })
}

fn like_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' | '%' | '_' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

fn query_limit(limit: usize) -> i64 {
    i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
}

fn non_negative_i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or(0)
}
