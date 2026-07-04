use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

use crate::metrics::LOCK_POISON_RECOVERIES_TOTAL;

pub const DEFAULT_NEW_SINCE_HOURS: u64 = 24;
/// 100 years, comfortably inside `OffsetDateTime`'s representable range and
/// far beyond any meaningful "new since" window; guards against overflow in
/// `TimeDuration::hours` for pathological caller-supplied values.
pub const MAX_NEW_SINCE_HOURS: u64 = 876_000;
/// A field is inferred as likely required when it appears in at least this
/// fraction of the payload-shape reservoir samples for an endpoint.
pub const INFERRED_SCHEMA_REQUIRED_THRESHOLD: f64 = 0.95;

const CREATE_REVIEW_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS discovery_endpoint_reviews (
    method TEXT NOT NULL,
    endpoint_template TEXT NOT NULL,
    reviewed_at TEXT NOT NULL,
    reviewed_by TEXT,
    PRIMARY KEY (method, endpoint_template)
);
"#;

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

#[derive(Clone)]
pub struct EndpointListFilters {
    pub method: Option<String>,
    pub endpoint_template_contains: Option<String>,
    pub endpoint_template_prefix: Option<String>,
    pub first_seen_after: Option<String>,
    pub first_seen_before: Option<String>,
    pub last_seen_after: Option<String>,
    pub last_seen_before: Option<String>,
    pub min_call_count: Option<i64>,
    pub new_since_hours: u64,
    pub is_new: Option<bool>,
    pub reviewed: Option<bool>,
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
    pub schema_mismatch_count: u64,
    pub distinct_principal_count: u64,
    pub is_new: bool,
    pub reviewed: bool,
    pub reviewed_at: Option<String>,
    pub reviewed_by: Option<String>,
    pub covered_by_rule: bool,
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
    pub schema_mismatch_count: u64,
    pub distinct_principal_count: u64,
    pub is_new: bool,
    pub reviewed: bool,
    pub reviewed_at: Option<String>,
    pub reviewed_by: Option<String>,
    pub covered_by_rule: bool,
    pub latency: EndpointLatencyDetail,
    pub status_counts: Vec<StatusCount>,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointReviewState {
    pub reviewed: bool,
    pub reviewed_at: Option<String>,
    pub reviewed_by: Option<String>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservedEndpoint {
    pub method: String,
    pub endpoint_template: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct InferredRequestSchema {
    pub method: String,
    pub endpoint_template: String,
    pub sample_count: u64,
    pub required_threshold: f64,
    pub query_params: Vec<InferredQueryParam>,
    pub json_body_keys: Vec<InferredJsonBodyKey>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct InferredQueryParam {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_hash: Option<String>,
    pub redacted: bool,
    pub present_count: u64,
    pub frequency: f64,
    pub required: bool,
    pub value_types: Vec<InferredValueTypeCount>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InferredValueTypeCount {
    pub value_type: String,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct InferredJsonBodyKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_hash: Option<String>,
    pub redacted: bool,
    pub present_count: u64,
    pub frequency: f64,
    pub required: bool,
}

impl DiscoveryQueryStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DiscoveryQueryError> {
        let path = path.into();
        let connection = Connection::open(&path).map_err(|source| DiscoveryQueryError::Open {
            path: path.clone(),
            source,
        })?;
        configure_connection(&connection).map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.clone(),
            source,
        })?;

        Ok(Self {
            path,
            connection: std::sync::Arc::new(Mutex::new(connection)),
        })
    }

    pub fn observed_endpoints(&self) -> Result<Vec<ObservedEndpoint>, DiscoveryQueryError> {
        let connection = self.connection_guard();
        let mut statement = match connection.prepare(
            r#"
            SELECT method, endpoint_template
            FROM discovery_endpoint_aggregates
            ORDER BY method, endpoint_template
            "#,
        ) {
            Ok(statement) => statement,
            Err(source) if is_missing_discovery_table(&source) => return Ok(Vec::new()),
            Err(source) => {
                return Err(DiscoveryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })
            }
        };

        let rows = statement
            .query_map([], |row| {
                Ok(ObservedEndpoint {
                    method: row.get(0)?,
                    endpoint_template: row.get(1)?,
                })
            })
            .map_err(|source| DiscoveryQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|source| DiscoveryQueryError::Sqlite {
                path: self.path.clone(),
                source,
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

        let new_since_cutoff = new_since_cutoff(filters.new_since_hours);
        let (sql, params) = build_endpoint_list_query(filters, cursor.as_ref(), &new_since_cutoff);
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
                Ok(row.into_summary(status_counts, &new_since_cutoff))
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
        new_since_hours: u64,
    ) -> Result<Option<EndpointAggregateDetail>, DiscoveryQueryError> {
        let new_since_cutoff = new_since_cutoff(new_since_hours);
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
                    schema_mismatch_count,
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at,
                    r.reviewed_at,
                    r.reviewed_by
                FROM discovery_endpoint_aggregates
                LEFT JOIN discovery_endpoint_reviews r
                    USING (method, endpoint_template)
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
        Ok(Some(row.into_detail(status_counts, &new_since_cutoff)?))
    }

    pub fn inferred_request_schema(
        &self,
        method: &str,
        endpoint_template: &str,
    ) -> Result<Option<InferredRequestSchema>, DiscoveryQueryError> {
        let connection = self.connection_guard();
        let mut statement = match connection.prepare(
            r#"
            SELECT shape_json
            FROM discovery_payload_shape_samples
            WHERE method = ?1 AND endpoint_template = ?2
            ORDER BY sample_slot
            "#,
        ) {
            Ok(statement) => statement,
            Err(source) if is_missing_payload_shape_sample_table(&source) => return Ok(None),
            Err(source) => {
                return Err(DiscoveryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })
            }
        };

        let shape_jsons = statement
            .query_map(params![method, endpoint_template], |row| {
                row.get::<_, String>(0)
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

        if shape_jsons.is_empty() {
            return Ok(None);
        }

        let shapes = shape_jsons
            .iter()
            .map(|shape_json| {
                serde_json::from_str::<CapturedPayloadShapeSample>(shape_json).map_err(|source| {
                    DiscoveryQueryError::Json {
                        context: "payload shape sample",
                        source,
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(infer_request_schema(
            method,
            endpoint_template,
            &shapes,
        )))
    }

    pub fn set_endpoint_review(
        &self,
        method: &str,
        endpoint_template: &str,
        reviewed: bool,
        reviewed_by: Option<&str>,
    ) -> Result<Option<EndpointReviewState>, DiscoveryQueryError> {
        let connection = self.connection_guard();
        let exists = connection
            .query_row(
                r#"
                SELECT 1
                FROM discovery_endpoint_aggregates
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
                params![method, endpoint_template],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(|source| DiscoveryQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?
            .is_some();
        if !exists {
            return Ok(None);
        }

        if reviewed {
            let reviewed_at = utc_timestamp_rfc3339();
            connection
                .execute(
                    r#"
                    INSERT INTO discovery_endpoint_reviews (
                        method,
                        endpoint_template,
                        reviewed_at,
                        reviewed_by
                    ) VALUES (?1, ?2, ?3, ?4)
                    ON CONFLICT(method, endpoint_template) DO UPDATE SET
                        reviewed_at = excluded.reviewed_at,
                        reviewed_by = excluded.reviewed_by
                    "#,
                    params![method, endpoint_template, reviewed_at, reviewed_by],
                )
                .map_err(|source| DiscoveryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;

            Ok(Some(EndpointReviewState {
                reviewed: true,
                reviewed_at: Some(reviewed_at),
                reviewed_by: reviewed_by.map(str::to_owned),
            }))
        } else {
            connection
                .execute(
                    r#"
                    DELETE FROM discovery_endpoint_reviews
                    WHERE method = ?1 AND endpoint_template = ?2
                    "#,
                    params![method, endpoint_template],
                )
                .map_err(|source| DiscoveryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;

            Ok(Some(EndpointReviewState {
                reviewed: false,
                reviewed_at: None,
                reviewed_by: None,
            }))
        }
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
    schema_mismatch_count: i64,
    latency_count: i64,
    latency_p50_ms: i64,
    latency_p95_ms: i64,
    latency_p99_ms: i64,
    latency_samples_json: String,
    distinct_principal_count: i64,
    updated_at: String,
    reviewed_at: Option<String>,
    reviewed_by: Option<String>,
}

#[derive(Deserialize)]
struct CapturedPayloadShapeSample {
    #[serde(default)]
    query_params: Vec<CapturedQueryParamSample>,
    json_body: Option<CapturedJsonBodyShapeSample>,
}

#[derive(Deserialize)]
struct CapturedQueryParamSample {
    #[serde(flatten)]
    field: CapturedFieldNameSample,
    value_type: String,
}

#[derive(Deserialize)]
struct CapturedJsonBodyShapeSample {
    #[serde(default)]
    top_level_keys: Vec<CapturedFieldNameSample>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
struct CapturedFieldNameSample {
    name: Option<String>,
    name_hash: Option<String>,
    redacted: bool,
}

impl CapturedFieldNameSample {
    fn is_identified(&self) -> bool {
        self.name.is_some() || self.name_hash.is_some()
    }
}

#[derive(Default)]
struct QueryParamInference {
    present_count: u64,
    value_type_counts: BTreeMap<String, u64>,
}

#[derive(Default)]
struct FieldPresenceInference {
    present_count: u64,
}

fn infer_request_schema(
    method: &str,
    endpoint_template: &str,
    shapes: &[CapturedPayloadShapeSample],
) -> InferredRequestSchema {
    let sample_count = u64::try_from(shapes.len()).unwrap_or(u64::MAX);
    let mut query_params = BTreeMap::<CapturedFieldNameSample, QueryParamInference>::new();
    let mut json_body_keys = BTreeMap::<CapturedFieldNameSample, FieldPresenceInference>::new();

    for shape in shapes {
        let mut sample_query_params = BTreeMap::<CapturedFieldNameSample, BTreeSet<String>>::new();
        for param in &shape.query_params {
            if !param.field.is_identified() {
                continue;
            }
            sample_query_params
                .entry(param.field.clone())
                .or_default()
                .insert(param.value_type.clone());
        }
        for (field, value_types) in sample_query_params {
            let inference = query_params.entry(field).or_default();
            inference.present_count = inference.present_count.saturating_add(1);
            for value_type in value_types {
                *inference.value_type_counts.entry(value_type).or_insert(0) += 1;
            }
        }

        let mut sample_body_keys = BTreeSet::<CapturedFieldNameSample>::new();
        if let Some(json_body) = shape.json_body.as_ref() {
            for field in &json_body.top_level_keys {
                if field.is_identified() {
                    sample_body_keys.insert(field.clone());
                }
            }
        }
        for field in sample_body_keys {
            let inference = json_body_keys.entry(field).or_default();
            inference.present_count = inference.present_count.saturating_add(1);
        }
    }

    let mut query_params = query_params
        .into_iter()
        .map(|(field, inference)| inferred_query_param(field, inference, sample_count))
        .collect::<Vec<_>>();
    query_params.sort_by(compare_inferred_query_params);

    let mut json_body_keys = json_body_keys
        .into_iter()
        .map(|(field, inference)| inferred_json_body_key(field, inference, sample_count))
        .collect::<Vec<_>>();
    json_body_keys.sort_by(compare_inferred_json_body_keys);

    InferredRequestSchema {
        method: method.to_owned(),
        endpoint_template: endpoint_template.to_owned(),
        sample_count,
        required_threshold: INFERRED_SCHEMA_REQUIRED_THRESHOLD,
        query_params,
        json_body_keys,
    }
}

fn inferred_query_param(
    field: CapturedFieldNameSample,
    inference: QueryParamInference,
    sample_count: u64,
) -> InferredQueryParam {
    let frequency = inferred_frequency(inference.present_count, sample_count);
    let mut value_types = inference
        .value_type_counts
        .into_iter()
        .map(|(value_type, count)| InferredValueTypeCount { value_type, count })
        .collect::<Vec<_>>();
    value_types.sort_by(compare_value_type_counts);

    InferredQueryParam {
        name: field.name,
        name_hash: field.name_hash,
        redacted: field.redacted,
        present_count: inference.present_count,
        frequency,
        required: frequency >= INFERRED_SCHEMA_REQUIRED_THRESHOLD,
        value_types,
    }
}

fn inferred_json_body_key(
    field: CapturedFieldNameSample,
    inference: FieldPresenceInference,
    sample_count: u64,
) -> InferredJsonBodyKey {
    let frequency = inferred_frequency(inference.present_count, sample_count);

    InferredJsonBodyKey {
        name: field.name,
        name_hash: field.name_hash,
        redacted: field.redacted,
        present_count: inference.present_count,
        frequency,
        required: frequency >= INFERRED_SCHEMA_REQUIRED_THRESHOLD,
    }
}

fn inferred_frequency(present_count: u64, sample_count: u64) -> f64 {
    if sample_count == 0 {
        0.0
    } else {
        present_count as f64 / sample_count as f64
    }
}

fn compare_inferred_query_params(
    left: &InferredQueryParam,
    right: &InferredQueryParam,
) -> Ordering {
    right.present_count.cmp(&left.present_count).then_with(|| {
        compare_field_names(
            left.redacted,
            &left.name,
            &left.name_hash,
            right.redacted,
            &right.name,
            &right.name_hash,
        )
    })
}

fn compare_inferred_json_body_keys(
    left: &InferredJsonBodyKey,
    right: &InferredJsonBodyKey,
) -> Ordering {
    right.present_count.cmp(&left.present_count).then_with(|| {
        compare_field_names(
            left.redacted,
            &left.name,
            &left.name_hash,
            right.redacted,
            &right.name,
            &right.name_hash,
        )
    })
}

fn compare_field_names(
    left_redacted: bool,
    left_name: &Option<String>,
    left_name_hash: &Option<String>,
    right_redacted: bool,
    right_name: &Option<String>,
    right_name_hash: &Option<String>,
) -> Ordering {
    left_redacted
        .cmp(&right_redacted)
        .then_with(|| {
            left_name
                .as_deref()
                .unwrap_or("")
                .cmp(right_name.as_deref().unwrap_or(""))
        })
        .then_with(|| {
            left_name_hash
                .as_deref()
                .unwrap_or("")
                .cmp(right_name_hash.as_deref().unwrap_or(""))
        })
}

fn compare_value_type_counts(
    left: &InferredValueTypeCount,
    right: &InferredValueTypeCount,
) -> Ordering {
    right
        .count
        .cmp(&left.count)
        .then_with(|| left.value_type.cmp(&right.value_type))
}

impl RawEndpointAggregate {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            method: row.get(0)?,
            endpoint_template: row.get(1)?,
            first_seen: row.get(2)?,
            last_seen: row.get(3)?,
            call_count: row.get(4)?,
            schema_mismatch_count: row.get(5)?,
            latency_count: row.get(6)?,
            latency_p50_ms: row.get(7)?,
            latency_p95_ms: row.get(8)?,
            latency_p99_ms: row.get(9)?,
            latency_samples_json: row.get(10)?,
            distinct_principal_count: row.get(11)?,
            updated_at: row.get(12)?,
            reviewed_at: row.get(13)?,
            reviewed_by: row.get(14)?,
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

    fn into_summary(
        self,
        status_counts: Vec<StatusCount>,
        new_since_cutoff: &str,
    ) -> EndpointSummary {
        let latency = self.latency_summary();
        let is_new = is_new_since(&self.first_seen, new_since_cutoff);
        let review = self.review_state();

        EndpointSummary {
            method: self.method,
            endpoint_template: self.endpoint_template,
            is_new,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            call_count: non_negative_i64_to_u64(self.call_count),
            schema_mismatch_count: non_negative_i64_to_u64(self.schema_mismatch_count),
            distinct_principal_count: non_negative_i64_to_u64(self.distinct_principal_count),
            reviewed: review.reviewed,
            reviewed_at: review.reviewed_at,
            reviewed_by: review.reviewed_by,
            covered_by_rule: false,
            latency,
            status_counts,
        }
    }

    fn into_detail(
        self,
        status_counts: Vec<StatusCount>,
        new_since_cutoff: &str,
    ) -> Result<EndpointAggregateDetail, DiscoveryQueryError> {
        let samples =
            serde_json::from_str::<Vec<u64>>(&self.latency_samples_json).map_err(|source| {
                DiscoveryQueryError::Json {
                    context: "latency samples",
                    source,
                }
            })?;
        let is_new = is_new_since(&self.first_seen, new_since_cutoff);
        let review = self.review_state();
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
            is_new,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            call_count: non_negative_i64_to_u64(self.call_count),
            schema_mismatch_count: non_negative_i64_to_u64(self.schema_mismatch_count),
            distinct_principal_count: non_negative_i64_to_u64(self.distinct_principal_count),
            reviewed: review.reviewed,
            reviewed_at: review.reviewed_at,
            reviewed_by: review.reviewed_by,
            covered_by_rule: false,
            latency,
            status_counts,
            updated_at: self.updated_at,
        })
    }

    fn review_state(&self) -> EndpointReviewState {
        EndpointReviewState {
            reviewed: self.reviewed_at.is_some(),
            reviewed_at: self.reviewed_at.clone(),
            reviewed_by: self.reviewed_by.clone(),
        }
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
    new_since_cutoff: &str,
) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        r#"
        SELECT
            a.method,
            a.endpoint_template,
            a.first_seen,
            a.last_seen,
            a.call_count,
            a.schema_mismatch_count,
            a.latency_count,
            a.latency_p50_ms,
            a.latency_p95_ms,
            a.latency_p99_ms,
            a.latency_samples_json,
            a.distinct_principal_count,
            a.updated_at,
            r.reviewed_at,
            r.reviewed_by
        FROM discovery_endpoint_aggregates a
        LEFT JOIN discovery_endpoint_reviews r
            USING (method, endpoint_template)
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
    if let Some(is_new) = filters.is_new {
        if is_new {
            clauses.push("julianday(a.first_seen) >= julianday(?)");
        } else {
            clauses.push("julianday(a.first_seen) < julianday(?)");
        }
        params.push(SqlValue::Text(new_since_cutoff.to_owned()));
    }
    if let Some(reviewed) = filters.reviewed {
        if reviewed {
            clauses.push("r.reviewed_at IS NOT NULL");
        } else {
            clauses.push("r.reviewed_at IS NULL");
        }
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

fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        "#,
    )?;
    connection.execute_batch(CREATE_REVIEW_SCHEMA_SQL)?;
    ensure_discovery_endpoint_aggregate_column(
        connection,
        "schema_mismatch_count",
        "INTEGER NOT NULL DEFAULT 0",
    )
}

fn ensure_discovery_endpoint_aggregate_column(
    connection: &Connection,
    column_name: &str,
    column_type: &str,
) -> rusqlite::Result<()> {
    let columns = discovery_endpoint_aggregate_columns(connection)?;
    if columns.is_empty() || columns.iter().any(|column| column == column_name) {
        return Ok(());
    }

    let sql =
        format!("ALTER TABLE discovery_endpoint_aggregates ADD COLUMN {column_name} {column_type}");
    connection.execute(&sql, [])?;
    Ok(())
}

fn discovery_endpoint_aggregate_columns(connection: &Connection) -> rusqlite::Result<Vec<String>> {
    let mut statement = connection.prepare("PRAGMA table_info(discovery_endpoint_aggregates)")?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(columns)
}

fn new_since_cutoff(new_since_hours: u64) -> String {
    let hours = i64::try_from(new_since_hours).unwrap_or(i64::MAX);
    (OffsetDateTime::now_utc() - TimeDuration::hours(hours))
        .format(&Rfc3339)
        .expect("UTC timestamp should format as RFC 3339")
}

fn is_new_since(first_seen: &str, new_since_cutoff: &str) -> bool {
    let Ok(first_seen) = OffsetDateTime::parse(first_seen, &Rfc3339) else {
        return false;
    };
    let Ok(new_since_cutoff) = OffsetDateTime::parse(new_since_cutoff, &Rfc3339) else {
        return false;
    };

    first_seen >= new_since_cutoff
}

fn utc_timestamp_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current UTC timestamp should format as RFC 3339")
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

fn is_missing_discovery_table(error: &rusqlite::Error) -> bool {
    match error {
        rusqlite::Error::SqliteFailure(_, Some(message)) => {
            message.contains("no such table: discovery_endpoint_aggregates")
        }
        _ => false,
    }
}

fn is_missing_payload_shape_sample_table(error: &rusqlite::Error) -> bool {
    match error {
        rusqlite::Error::SqliteFailure(_, Some(message)) => {
            message.contains("no such table: discovery_payload_shape_samples")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rusqlite::{params, Connection};
    use serde_json::json;

    use super::*;

    #[test]
    fn loads_observed_endpoint_templates_from_discovery_aggregates() {
        let db = TempDb::new("query-observed");
        seed_endpoint(&db.path, "GET", "/users/{id}");
        seed_endpoint(&db.path, "POST", "/users");

        let store = DiscoveryQueryStore::open(&db.path).expect("discovery query store should open");
        let observed = store
            .observed_endpoints()
            .expect("observed endpoints should query");

        assert_eq!(
            observed,
            vec![
                ObservedEndpoint {
                    method: "GET".to_owned(),
                    endpoint_template: "/users/{id}".to_owned(),
                },
                ObservedEndpoint {
                    method: "POST".to_owned(),
                    endpoint_template: "/users".to_owned(),
                },
            ]
        );
    }

    #[test]
    fn infers_request_schema_from_payload_shape_samples() {
        let db = TempDb::new("query-inferred-schema");
        seed_payload_shape_samples(
            &db.path,
            "POST",
            "/users/{id}",
            &[
                json!({
                    "query_params": [
                        { "name": "page", "redacted": false, "value_type": "number" },
                        { "name": "filter", "redacted": false, "value_type": "string" }
                    ],
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false },
                            { "name_hash": "sha256:redacted-token-key", "redacted": true }
                        ]
                    }
                }),
                json!({
                    "query_params": [
                        { "name": "page", "redacted": false, "value_type": "number" }
                    ],
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false },
                            { "name_hash": "sha256:redacted-token-key", "redacted": true }
                        ]
                    }
                }),
                json!({
                    "query_params": [
                        { "name": "page", "redacted": false, "value_type": "string" },
                        { "name": "filter", "redacted": false, "value_type": "string" }
                    ],
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false },
                            { "name_hash": "sha256:redacted-token-key", "redacted": true }
                        ]
                    }
                }),
                json!({
                    "query_params": [
                        { "name": "page", "redacted": false, "value_type": "number" },
                        { "name": "debug", "redacted": false, "value_type": "string" }
                    ],
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false }
                        ]
                    }
                }),
            ],
        );
        let store = DiscoveryQueryStore::open(&db.path).expect("discovery query store should open");

        let schema = store
            .inferred_request_schema("POST", "/users/{id}")
            .expect("inferred schema should query")
            .expect("inferred schema should exist");

        assert_eq!(schema.method, "POST");
        assert_eq!(schema.endpoint_template, "/users/{id}");
        assert_eq!(schema.sample_count, 4);
        assert_eq!(
            schema.required_threshold,
            INFERRED_SCHEMA_REQUIRED_THRESHOLD
        );
        assert_eq!(schema.query_params.len(), 3);
        assert_eq!(schema.query_params[0].name.as_deref(), Some("page"));
        assert_eq!(schema.query_params[0].present_count, 4);
        assert_eq!(schema.query_params[0].frequency, 1.0);
        assert!(schema.query_params[0].required);
        assert_eq!(
            schema.query_params[0].value_types,
            vec![
                InferredValueTypeCount {
                    value_type: "number".to_owned(),
                    count: 3,
                },
                InferredValueTypeCount {
                    value_type: "string".to_owned(),
                    count: 1,
                },
            ]
        );
        assert_eq!(schema.query_params[1].name.as_deref(), Some("filter"));
        assert_eq!(schema.query_params[1].present_count, 2);
        assert_eq!(schema.query_params[1].frequency, 0.5);
        assert!(!schema.query_params[1].required);
        assert_eq!(schema.query_params[2].name.as_deref(), Some("debug"));
        assert_eq!(schema.query_params[2].present_count, 1);
        assert!(!schema.query_params[2].required);

        assert_eq!(schema.json_body_keys.len(), 2);
        assert_eq!(
            schema.json_body_keys[0].name.as_deref(),
            Some("display_name")
        );
        assert_eq!(schema.json_body_keys[0].name_hash, None);
        assert_eq!(schema.json_body_keys[0].present_count, 4);
        assert!(schema.json_body_keys[0].required);
        assert_eq!(schema.json_body_keys[1].name, None);
        assert_eq!(
            schema.json_body_keys[1].name_hash.as_deref(),
            Some("sha256:redacted-token-key")
        );
        assert!(schema.json_body_keys[1].redacted);
        assert_eq!(schema.json_body_keys[1].present_count, 3);
        assert_eq!(schema.json_body_keys[1].frequency, 0.75);
        assert!(!schema.json_body_keys[1].required);
    }

    #[test]
    fn inferred_request_schema_keeps_redacted_fields_hash_identified() {
        let db = TempDb::new("query-inferred-redacted");
        seed_payload_shape_samples(
            &db.path,
            "POST",
            "/login",
            &[json!({
                "query_params": [
                    { "name_hash": "sha256:redacted-query-key", "redacted": true, "value_type": "string" }
                ],
                "json_body": {
                    "top_level_keys": [
                        { "name_hash": "sha256:redacted-body-key", "redacted": true }
                    ]
                }
            })],
        );
        let store = DiscoveryQueryStore::open(&db.path).expect("discovery query store should open");

        let schema = store
            .inferred_request_schema("POST", "/login")
            .expect("inferred schema should query")
            .expect("inferred schema should exist");

        assert_eq!(schema.query_params[0].name, None);
        assert_eq!(
            schema.query_params[0].name_hash.as_deref(),
            Some("sha256:redacted-query-key")
        );
        assert!(schema.query_params[0].redacted);
        assert_eq!(schema.json_body_keys[0].name, None);
        assert_eq!(
            schema.json_body_keys[0].name_hash.as_deref(),
            Some("sha256:redacted-body-key")
        );
        assert!(schema.json_body_keys[0].redacted);
        let serialized = serde_json::to_string(&schema).expect("schema should serialize");
        assert!(!serialized.contains("password"));
        assert!(!serialized.contains("token"));
        assert!(!serialized.contains("secret"));
    }

    #[test]
    fn inferred_request_schema_returns_none_without_samples_for_endpoint() {
        let db = TempDb::new("query-inferred-none");
        seed_payload_shape_samples(
            &db.path,
            "GET",
            "/users",
            &[json!({
                "query_params": [
                    { "name": "page", "redacted": false, "value_type": "number" }
                ]
            })],
        );
        let store = DiscoveryQueryStore::open(&db.path).expect("discovery query store should open");

        let schema = store
            .inferred_request_schema("POST", "/users")
            .expect("inferred schema should query");

        assert!(schema.is_none());
    }

    fn seed_endpoint(path: &PathBuf, method: &str, endpoint_template: &str) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS discovery_endpoint_aggregates (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    call_count INTEGER NOT NULL,
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
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', 1, 1, 1, 1, 1, '[]', 0, '2024-06-01T12:00:00Z')
                "#,
                params![method, endpoint_template],
            )
            .expect("endpoint aggregate should insert");
    }

    fn seed_payload_shape_samples(
        path: &PathBuf,
        method: &str,
        endpoint_template: &str,
        shapes: &[serde_json::Value],
    ) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch(
                r#"
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
                "#,
            )
            .expect("payload shape schema should create");
        connection
            .execute(
                r#"
                INSERT INTO discovery_payload_shape_stats (
                    method,
                    endpoint_template,
                    shape_observation_count,
                    updated_at
                ) VALUES (?1, ?2, ?3, '2024-06-01T12:00:00Z')
                "#,
                params![
                    method,
                    endpoint_template,
                    i64::try_from(shapes.len()).expect("shape count should fit i64")
                ],
            )
            .expect("payload shape stats should insert");

        for (index, shape) in shapes.iter().enumerate() {
            connection
                .execute(
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
                        method,
                        endpoint_template,
                        i64::try_from(index).expect("sample slot should fit i64"),
                        format!("2024-06-01T12:00:0{index}Z"),
                        format!("sha256:test-shape-{index}"),
                        shape.to_string(),
                    ],
                )
                .expect("payload shape sample should insert");
        }
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-discovery-query-{test_name}-{}.sqlite",
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
