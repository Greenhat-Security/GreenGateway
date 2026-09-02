use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap},
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
};

#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use async_trait::async_trait;
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, Duration as TimeDuration, OffsetDateTime};

use crate::{
    discovery::{
        lifecycle::{
            self, TransitionOutcome, TransitionPrecondition, TransitionRefused, UNREVIEWED_REVISION,
        },
        signals::{self, Signal, SignalLifecycleState, SignalListFilters, SignalTarget},
        suggestions,
    },
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
    storage::{run_blocking, RepositoryError},
};

/// The backend-neutral read side of the discovery inventory (issue #241,
/// PR 11): what the admin traffic, signals, principals, and schema surfaces
/// ask of the store. Standalone mode answers from the SQLite file the
/// aggregator sink writes; cluster mode answers from the PostgreSQL tables
/// the projector writes. Both implementations return the same shapes,
/// orderings, cursors, and filter semantics, so a handler is written once.
///
/// Every method is `async` and must never block a request executor: the
/// SQLite implementation runs its synchronous queries on the blocking pool,
/// the PostgreSQL one awaits the driver.
#[async_trait]
pub trait DiscoveryReadStore: Send + Sync {
    /// Every observed endpoint, one row per routing context it was seen
    /// under (or one row with no context when it was never classified),
    /// ordered by method, template, then context.
    async fn observed_endpoints(&self) -> Result<Vec<ObservedEndpoint>, DiscoveryQueryError>;

    /// One page of the endpoint inventory. `include_open_signals` attaches
    /// the open-signal summary to each endpoint; a caller without the
    /// signals permission passes `false` and gets no summary field.
    async fn list_endpoints_with_open_signal_summaries(
        &self,
        filters: &EndpointListFilters,
        include_open_signals: bool,
    ) -> Result<EndpointListPage, DiscoveryQueryError>;

    /// One endpoint's detail, or `None` when it was never observed.
    async fn get_endpoint_with_open_signal_summaries(
        &self,
        method: &str,
        endpoint_template: &str,
        new_since_hours: u64,
        include_open_signals: bool,
    ) -> Result<Option<EndpointAggregateDetail>, DiscoveryQueryError>;

    /// The request schema inferred from the endpoint's retained payload
    /// shape samples, or `None` when it has no samples.
    async fn inferred_request_schema(
        &self,
        method: &str,
        endpoint_template: &str,
    ) -> Result<Option<InferredRequestSchema>, DiscoveryQueryError>;

    /// `inferred_request_schema` for many endpoints at once, one entry per
    /// requested `(method, endpoint_template)` in the same order. The
    /// default asks one endpoint at a time; a backend a network away
    /// answers the whole set in one round trip.
    async fn inferred_request_schemas(
        &self,
        endpoints: &[(String, String)],
    ) -> Result<Vec<Option<InferredRequestSchema>>, DiscoveryQueryError> {
        let mut schemas = Vec::with_capacity(endpoints.len());
        for (method, endpoint_template) in endpoints {
            schemas.push(
                self.inferred_request_schema(method, endpoint_template)
                    .await?,
            );
        }
        Ok(schemas)
    }

    /// Mark or clear an endpoint's review, conditionally (issue #241,
    /// PR 12): `expected_revision` is the review revision the caller last
    /// read (`UNREVIEWED_REVISION` for "not yet reviewed"), or `None` for an
    /// unconditional write. A review that moved since is refused with its
    /// current state; `NotFound` when the endpoint was never observed.
    async fn set_endpoint_review(
        &self,
        method: &str,
        endpoint_template: &str,
        reviewed: bool,
        reviewed_by: Option<&str>,
        expected_revision: Option<i64>,
    ) -> Result<TransitionOutcome<EndpointReviewState>, DiscoveryQueryError>;

    /// One page of signals, newest first.
    async fn list_signals(
        &self,
        filters: &SignalListFilters,
    ) -> Result<signals::SignalListPage, DiscoveryQueryError>;

    /// The `principal_new_to_endpoint` signals raised for one principal
    /// identity, newest first, at most `limit`.
    async fn list_principal_endpoint_signals(
        &self,
        principal: &str,
        issuer: &str,
        auth_method: &str,
        limit: usize,
    ) -> Result<Vec<Signal>, DiscoveryQueryError>;

    /// Move a signal to `state` if it is still in `expected.from_state`
    /// (and at `expected.revision`, when given): one conditional statement
    /// on both backends, refused with the current row when the predicate
    /// no longer holds; `NotFound` when no signal has that id.
    async fn transition_signal(
        &self,
        signal_id: &str,
        state: SignalLifecycleState,
        transitioned_by: Option<&str>,
        expected: TransitionPrecondition<SignalLifecycleState>,
    ) -> Result<TransitionOutcome<Signal>, DiscoveryQueryError>;

    /// One page of the principals seen on an endpoint, most recently seen
    /// first.
    async fn list_principals(
        &self,
        method: &str,
        endpoint_template: &str,
        filters: &PrincipalPageFilters,
    ) -> Result<PrincipalPage, DiscoveryQueryError>;
}

/// The SQLite store satisfies the read contract by running its synchronous
/// queries on the blocking pool. The synchronous methods stay: the
/// standalone sink, the suggestion engine, and the standalone conformance
/// hot path call them directly.
#[async_trait]
impl DiscoveryReadStore for DiscoveryQueryStore {
    async fn observed_endpoints(&self) -> Result<Vec<ObservedEndpoint>, DiscoveryQueryError> {
        let store = self.clone();
        blocking_query(move || store.observed_endpoints()).await
    }

    async fn list_endpoints_with_open_signal_summaries(
        &self,
        filters: &EndpointListFilters,
        include_open_signals: bool,
    ) -> Result<EndpointListPage, DiscoveryQueryError> {
        let store = self.clone();
        let filters = filters.clone();
        blocking_query(move || {
            store.list_endpoints_with_open_signal_summaries(&filters, include_open_signals)
        })
        .await
    }

    async fn get_endpoint_with_open_signal_summaries(
        &self,
        method: &str,
        endpoint_template: &str,
        new_since_hours: u64,
        include_open_signals: bool,
    ) -> Result<Option<EndpointAggregateDetail>, DiscoveryQueryError> {
        let store = self.clone();
        let method = method.to_owned();
        let endpoint_template = endpoint_template.to_owned();
        blocking_query(move || {
            store.get_endpoint_with_open_signal_summaries(
                &method,
                &endpoint_template,
                new_since_hours,
                include_open_signals,
            )
        })
        .await
    }

    async fn inferred_request_schema(
        &self,
        method: &str,
        endpoint_template: &str,
    ) -> Result<Option<InferredRequestSchema>, DiscoveryQueryError> {
        let store = self.clone();
        let method = method.to_owned();
        let endpoint_template = endpoint_template.to_owned();
        blocking_query(move || store.inferred_request_schema(&method, &endpoint_template)).await
    }

    async fn set_endpoint_review(
        &self,
        method: &str,
        endpoint_template: &str,
        reviewed: bool,
        reviewed_by: Option<&str>,
        expected_revision: Option<i64>,
    ) -> Result<TransitionOutcome<EndpointReviewState>, DiscoveryQueryError> {
        let store = self.clone();
        let method = method.to_owned();
        let endpoint_template = endpoint_template.to_owned();
        let reviewed_by = reviewed_by.map(str::to_owned);
        blocking_query(move || {
            store.set_endpoint_review(
                &method,
                &endpoint_template,
                reviewed,
                reviewed_by.as_deref(),
                expected_revision,
            )
        })
        .await
    }

    async fn list_signals(
        &self,
        filters: &SignalListFilters,
    ) -> Result<signals::SignalListPage, DiscoveryQueryError> {
        let store = self.clone();
        let filters = filters.clone();
        blocking_query(move || store.list_signals(&filters)).await
    }

    async fn list_principal_endpoint_signals(
        &self,
        principal: &str,
        issuer: &str,
        auth_method: &str,
        limit: usize,
    ) -> Result<Vec<Signal>, DiscoveryQueryError> {
        let store = self.clone();
        let principal = principal.to_owned();
        let issuer = issuer.to_owned();
        let auth_method = auth_method.to_owned();
        blocking_query(move || {
            store.list_principal_endpoint_signals(&principal, &issuer, &auth_method, limit)
        })
        .await
    }

    async fn transition_signal(
        &self,
        signal_id: &str,
        state: SignalLifecycleState,
        transitioned_by: Option<&str>,
        expected: TransitionPrecondition<SignalLifecycleState>,
    ) -> Result<TransitionOutcome<Signal>, DiscoveryQueryError> {
        let store = self.clone();
        let signal_id = signal_id.to_owned();
        let transitioned_by = transitioned_by.map(str::to_owned);
        blocking_query(move || {
            store.transition_signal(&signal_id, state, transitioned_by.as_deref(), expected)
        })
        .await
    }

    async fn list_principals(
        &self,
        method: &str,
        endpoint_template: &str,
        filters: &PrincipalPageFilters,
    ) -> Result<PrincipalPage, DiscoveryQueryError> {
        let store = self.clone();
        let method = method.to_owned();
        let endpoint_template = endpoint_template.to_owned();
        let filters = PrincipalPageFilters {
            limit: filters.limit,
            cursor: filters.cursor.clone(),
        };
        blocking_query(move || store.list_principals(&method, &endpoint_template, &filters)).await
    }
}

/// Run one synchronous SQLite query on the blocking pool. The query's own
/// error is carried through unchanged; only a failed blocking task (a panic
/// or cancellation) becomes a classified repository failure.
async fn blocking_query<T, F>(query: F) -> Result<T, DiscoveryQueryError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, DiscoveryQueryError> + Send + 'static,
{
    run_blocking(move || Ok(query()))
        .await
        .map_err(DiscoveryQueryError::Repository)?
}

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
    revision INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (method, endpoint_template)
);
"#;

const CREATE_ROUTING_CONTEXT_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS discovery_endpoint_routing_contexts (
    method TEXT NOT NULL,
    endpoint_template TEXT NOT NULL,
    route_host TEXT NOT NULL,
    route_path_prefix TEXT NOT NULL,
    upstream_origin TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    call_count INTEGER NOT NULL,
    distinct_principal_count INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (
        method,
        endpoint_template,
        route_host,
        route_path_prefix,
        upstream_origin
    )
);

CREATE TABLE IF NOT EXISTS discovery_endpoint_routing_classifications (
    method TEXT NOT NULL,
    endpoint_template TEXT NOT NULL,
    first_classified_at TEXT NOT NULL,
    PRIMARY KEY (method, endpoint_template)
);
"#;

#[derive(Clone)]
pub struct DiscoveryQueryStore {
    path: PathBuf,
    connection: std::sync::Arc<Mutex<Connection>>,
    #[cfg(test)]
    query_counts: std::sync::Arc<DiscoveryQueryCounts>,
}

#[cfg(test)]
#[derive(Default)]
struct DiscoveryQueryCounts {
    observed_endpoints: AtomicU64,
    inferred_request_schema: AtomicU64,
    open_signal_summaries: AtomicU64,
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
    /// The stored review row's revision (`UNREVIEWED_REVISION` when there
    /// is none): what a conditional review write must expect.
    pub review_revision: i64,
    pub covered_by_rule: bool,
    pub coverage_scope: EndpointCoverageScope,
    pub routing_context_known: bool,
    pub routing_context_known_since: Option<String>,
    pub routing_contexts: Vec<EndpointRoutingContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_signals: Option<OpenSignalSummary>,
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
    /// The stored review row's revision (`UNREVIEWED_REVISION` when there
    /// is none): what a conditional review write must expect.
    pub review_revision: i64,
    pub covered_by_rule: bool,
    pub coverage_scope: EndpointCoverageScope,
    pub routing_context_known: bool,
    pub routing_context_known_since: Option<String>,
    pub routing_contexts: Vec<EndpointRoutingContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_signals: Option<OpenSignalSummary>,
    pub latency: EndpointLatencyDetail,
    pub status_counts: Vec<StatusCount>,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EndpointReviewState {
    pub reviewed: bool,
    pub reviewed_at: Option<String>,
    pub reviewed_by: Option<String>,
    /// The review row's revision, `UNREVIEWED_REVISION` (0) while the
    /// endpoint has no review; the expected value a conditional write
    /// can require.
    pub revision: i64,
}

impl EndpointReviewState {
    pub(crate) fn unreviewed() -> Self {
        Self {
            reviewed: false,
            reviewed_at: None,
            reviewed_by: None,
            revision: UNREVIEWED_REVISION,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointCoverageScope {
    #[default]
    None,
    Unknown,
    Principal,
    Endpoint,
    Mixed,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointRoutingContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_path_prefix: Option<String>,
    pub upstream_origin: Option<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub call_count: u64,
    pub distinct_principal_count: u64,
    pub covered_by_rule: bool,
    pub coverage_scope: EndpointCoverageScope,
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

#[derive(Clone, Debug, Default, Serialize)]
pub struct OpenSignalSummary {
    pub count: u64,
    pub signal_types: Vec<String>,
}

#[derive(Serialize)]
pub struct PrincipalPage {
    pub principals: Vec<EndpointPrincipal>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EndpointPrincipal {
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    pub auth_method: String,
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
    InvalidSignalState {
        state: String,
    },
    /// A classified failure of the backend-neutral repository layer: the
    /// PostgreSQL read store's driver and pool failures, and a failed
    /// blocking task in the SQLite adapter.
    Repository(RepositoryError),
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
            Self::InvalidSignalState { state } => {
                write!(
                    formatter,
                    "invalid discovery signal state in database: {state}"
                )
            }
            Self::Repository(source) => {
                write!(formatter, "discovery repository query failed: {source}")
            }
        }
    }
}

impl Error for DiscoveryQueryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Sqlite { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Repository(source) => Some(source),
            Self::InvalidCursor { .. } | Self::InvalidSignalState { .. } => None,
        }
    }
}

impl From<RepositoryError> for DiscoveryQueryError {
    fn from(source: RepositoryError) -> Self {
        Self::Repository(source)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservedEndpoint {
    pub method: String,
    pub endpoint_template: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_path_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_context_known_since: Option<String>,
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
            #[cfg(test)]
            query_counts: std::sync::Arc::new(DiscoveryQueryCounts::default()),
        })
    }

    pub fn observed_endpoints(&self) -> Result<Vec<ObservedEndpoint>, DiscoveryQueryError> {
        #[cfg(test)]
        self.query_counts
            .observed_endpoints
            .fetch_add(1, AtomicOrdering::Relaxed);

        let connection = self.connection_guard();
        let mut statement = match connection.prepare(
            r#"
            SELECT
                a.method,
                a.endpoint_template,
                NULL AS route_host,
                NULL AS route_path_prefix,
                NULL AS upstream_origin,
                k.first_classified_at
            FROM discovery_endpoint_aggregates a
            LEFT JOIN discovery_endpoint_routing_classifications k
                USING (method, endpoint_template)
            WHERE NOT EXISTS (
                SELECT 1
                FROM discovery_endpoint_routing_contexts c
                WHERE c.method = a.method
                  AND c.endpoint_template = a.endpoint_template
            )
            UNION ALL
            SELECT
                c.method,
                c.endpoint_template,
                NULLIF(c.route_host, ''),
                NULLIF(c.route_path_prefix, ''),
                NULLIF(c.upstream_origin, ''),
                k.first_classified_at
            FROM discovery_endpoint_routing_contexts c
            LEFT JOIN discovery_endpoint_routing_classifications k
                USING (method, endpoint_template)
            ORDER BY method, endpoint_template, route_host, route_path_prefix, upstream_origin
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
                    route_host: row.get(2)?,
                    route_path_prefix: row.get(3)?,
                    upstream_origin: row.get(4)?,
                    routing_context_known_since: row.get(5)?,
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
        self.list_endpoints_with_open_signal_summaries(filters, true)
    }

    pub fn list_endpoints_with_open_signal_summaries(
        &self,
        filters: &EndpointListFilters,
        include_open_signals: bool,
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
        let open_signal_summaries = if include_open_signals {
            self.open_signal_summaries_for_rows(&connection, &rows)?
        } else {
            HashMap::new()
        };
        let endpoints = rows
            .into_iter()
            .map(|row| {
                let status_counts = load_status_counts(
                    &connection,
                    &self.path,
                    &row.method,
                    &row.endpoint_template,
                )?;
                let open_signals = if include_open_signals {
                    Some(
                        open_signal_summaries
                            .get(&(row.method.clone(), row.endpoint_template.clone()))
                            .cloned()
                            .unwrap_or_default(),
                    )
                } else {
                    None
                };
                let routing_contexts = load_routing_contexts(
                    &connection,
                    &self.path,
                    &row.method,
                    &row.endpoint_template,
                )?;
                let routing_context_known_since = load_routing_context_known_since(
                    &connection,
                    &self.path,
                    &row.method,
                    &row.endpoint_template,
                )?;
                Ok(row.into_summary(
                    status_counts,
                    open_signals,
                    routing_contexts,
                    routing_context_known_since,
                    &new_since_cutoff,
                ))
            })
            .collect::<Result<Vec<_>, DiscoveryQueryError>>()?;

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
        self.get_endpoint_with_open_signal_summaries(
            method,
            endpoint_template,
            new_since_hours,
            true,
        )
    }

    pub fn get_endpoint_with_open_signal_summaries(
        &self,
        method: &str,
        endpoint_template: &str,
        new_since_hours: u64,
        include_open_signals: bool,
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
                    r.reviewed_by,
                    r.revision
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
        let routing_contexts =
            load_routing_contexts(&connection, &self.path, &row.method, &row.endpoint_template)?;
        let routing_context_known_since = load_routing_context_known_since(
            &connection,
            &self.path,
            &row.method,
            &row.endpoint_template,
        )?;
        let open_signals = if include_open_signals {
            let summaries = self.open_signal_summaries_for_keys(
                &connection,
                &[(row.method.clone(), row.endpoint_template.clone())],
            )?;
            Some(
                summaries
                    .get(&(row.method.clone(), row.endpoint_template.clone()))
                    .cloned()
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        Ok(Some(row.into_detail(
            status_counts,
            open_signals,
            routing_contexts,
            routing_context_known_since,
            &new_since_cutoff,
        )?))
    }

    pub fn inferred_request_schema(
        &self,
        method: &str,
        endpoint_template: &str,
    ) -> Result<Option<InferredRequestSchema>, DiscoveryQueryError> {
        #[cfg(test)]
        self.query_counts
            .inferred_request_schema
            .fetch_add(1, AtomicOrdering::Relaxed);

        let shape_jsons = {
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

            let rows = statement
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
            rows
        };

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

    #[cfg(test)]
    pub fn query_counts_for_test(&self) -> (u64, u64) {
        (
            self.query_counts
                .observed_endpoints
                .load(AtomicOrdering::Relaxed),
            self.query_counts
                .inferred_request_schema
                .load(AtomicOrdering::Relaxed),
        )
    }

    #[cfg(test)]
    pub fn open_signal_summary_query_count_for_test(&self) -> u64 {
        self.query_counts
            .open_signal_summaries
            .load(AtomicOrdering::Relaxed)
    }

    fn open_signal_summaries_for_rows(
        &self,
        connection: &Connection,
        rows: &[RawEndpointAggregate],
    ) -> Result<HashMap<(String, String), OpenSignalSummary>, DiscoveryQueryError> {
        let endpoint_keys = rows
            .iter()
            .map(|row| (row.method.clone(), row.endpoint_template.clone()))
            .collect::<Vec<_>>();
        self.open_signal_summaries_for_keys(connection, &endpoint_keys)
    }

    fn open_signal_summaries_for_keys(
        &self,
        connection: &Connection,
        endpoint_keys: &[(String, String)],
    ) -> Result<HashMap<(String, String), OpenSignalSummary>, DiscoveryQueryError> {
        if endpoint_keys.is_empty() {
            return Ok(HashMap::new());
        }

        #[cfg(test)]
        self.query_counts
            .open_signal_summaries
            .fetch_add(1, AtomicOrdering::Relaxed);

        load_open_signal_summaries(connection, &self.path, endpoint_keys)
    }

    /// The conditional review write (issue #241, PR 12). A mark is an
    /// upsert whose predicate is the expected revision: `None` replaces
    /// whatever is there (revision + 1), `UNREVIEWED_REVISION` inserts only
    /// when no row exists, and any other value updates only the row at that
    /// revision. A clear deletes only the row at the expected revision (or
    /// any row, for `None`); clearing an unreviewed endpoint that was
    /// expected unreviewed is a no-op that applies. Zero rows is a refusal
    /// carrying the review as stored now.
    pub fn set_endpoint_review(
        &self,
        method: &str,
        endpoint_template: &str,
        reviewed: bool,
        reviewed_by: Option<&str>,
        expected_revision: Option<i64>,
    ) -> Result<TransitionOutcome<EndpointReviewState>, DiscoveryQueryError> {
        let connection = self.connection_guard();
        let sqlite_error = |source| DiscoveryQueryError::Sqlite {
            path: self.path.clone(),
            source,
        };
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
            .map_err(sqlite_error)?
            .is_some();
        if !exists {
            return Ok(TransitionOutcome::NotFound);
        }

        if reviewed {
            let reviewed_at = utc_timestamp_rfc3339();
            let written = match expected_revision {
                None => connection
                    .query_row(
                        r#"
                        INSERT INTO discovery_endpoint_reviews (
                            method,
                            endpoint_template,
                            reviewed_at,
                            reviewed_by,
                            revision
                        ) VALUES (?1, ?2, ?3, ?4, 1)
                        ON CONFLICT(method, endpoint_template) DO UPDATE SET
                            reviewed_at = excluded.reviewed_at,
                            reviewed_by = excluded.reviewed_by,
                            revision = discovery_endpoint_reviews.revision + 1
                        RETURNING revision
                        "#,
                        params![method, endpoint_template, reviewed_at, reviewed_by],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(sqlite_error)?,
                Some(UNREVIEWED_REVISION) => connection
                    .query_row(
                        r#"
                        INSERT INTO discovery_endpoint_reviews (
                            method,
                            endpoint_template,
                            reviewed_at,
                            reviewed_by,
                            revision
                        ) VALUES (?1, ?2, ?3, ?4, 1)
                        ON CONFLICT(method, endpoint_template) DO NOTHING
                        RETURNING revision
                        "#,
                        params![method, endpoint_template, reviewed_at, reviewed_by],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(sqlite_error)?,
                Some(expected) => connection
                    .query_row(
                        r#"
                        UPDATE discovery_endpoint_reviews
                        SET reviewed_at = ?3,
                            reviewed_by = ?4,
                            revision = revision + 1
                        WHERE method = ?1 AND endpoint_template = ?2 AND revision = ?5
                        RETURNING revision
                        "#,
                        params![
                            method,
                            endpoint_template,
                            reviewed_at,
                            reviewed_by,
                            expected
                        ],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(sqlite_error)?,
            };
            match written {
                Some(revision) => Ok(TransitionOutcome::Applied(EndpointReviewState {
                    reviewed: true,
                    reviewed_at: Some(reviewed_at),
                    reviewed_by: reviewed_by.map(str::to_owned),
                    revision,
                })),
                None => Ok(TransitionOutcome::Refused(TransitionRefused {
                    current: load_review_by_key(
                        &connection,
                        &self.path,
                        method,
                        endpoint_template,
                    )?,
                })),
            }
        } else {
            let deleted = match expected_revision {
                None => connection
                    .execute(
                        r#"
                        DELETE FROM discovery_endpoint_reviews
                        WHERE method = ?1 AND endpoint_template = ?2
                        "#,
                        params![method, endpoint_template],
                    )
                    .map_err(sqlite_error)?,
                Some(expected) => connection
                    .execute(
                        r#"
                        DELETE FROM discovery_endpoint_reviews
                        WHERE method = ?1 AND endpoint_template = ?2 AND revision = ?3
                        "#,
                        params![method, endpoint_template, expected],
                    )
                    .map_err(sqlite_error)?,
            };
            if deleted > 0 {
                return Ok(TransitionOutcome::Applied(EndpointReviewState::unreviewed()));
            }
            let current = load_review_by_key(&connection, &self.path, method, endpoint_template)?;
            if !current.reviewed && matches!(expected_revision, None | Some(UNREVIEWED_REVISION)) {
                return Ok(TransitionOutcome::Applied(current));
            }
            Ok(TransitionOutcome::Refused(TransitionRefused { current }))
        }
    }

    pub fn list_signals(
        &self,
        filters: &SignalListFilters,
    ) -> Result<signals::SignalListPage, DiscoveryQueryError> {
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<SignalCursor>("cursor", value))
            .transpose()?;
        let (sql, params) = build_signal_list_query(filters, cursor.as_ref());

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
                .query_map(params_from_iter(params.iter()), RawSignal::from_row)
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

        let mut rows = rows;
        let has_more = rows.len() > filters.limit;
        if has_more {
            rows.truncate(filters.limit);
        }

        let next_cursor = if has_more {
            rows.last()
                .map(|row| {
                    encode_cursor(&SignalCursor {
                        created_at: row.created_at.clone(),
                        id: row.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };

        let signals = rows
            .into_iter()
            .map(RawSignal::into_signal)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(signals::SignalListPage {
            signals,
            next_cursor,
        })
    }

    pub fn list_principal_endpoint_signals(
        &self,
        principal: &str,
        issuer: &str,
        auth_method: &str,
        limit: usize,
    ) -> Result<Vec<Signal>, DiscoveryQueryError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let rows = {
            let connection = self.connection_guard();
            let mut statement = connection
                .prepare(&format!(
                    r#"
                    SELECT {SIGNAL_COLUMNS}
                    FROM discovery_signals
                    WHERE signal_type = ?1
                      AND target_kind = ?2
                      AND CASE
                            WHEN json_valid(target_identity_json) = 1 THEN
                                json_extract(target_identity_json, '$.principal') = ?3
                                AND COALESCE(json_extract(target_identity_json, '$.issuer'), '') = ?4
                                AND json_extract(target_identity_json, '$.auth_method') = ?5
                            ELSE 0
                          END
                    ORDER BY julianday(created_at) DESC, id ASC
                    LIMIT ?6
                    "#
                ))
                .map_err(|source| DiscoveryQueryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
            let rows = statement
                .query_map(
                    params![
                        signals::PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_TYPE,
                        signals::PRINCIPAL_ENDPOINT_TARGET_KIND,
                        principal,
                        issuer,
                        auth_method,
                        i64::try_from(limit).unwrap_or(i64::MAX),
                    ],
                    RawSignal::from_row,
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

        rows.into_iter().map(RawSignal::into_signal).collect()
    }

    /// The conditional transition (issue #241, PR 12): one statement whose
    /// predicate is the id, the expected state, and (when given) the
    /// expected revision. Zero rows is a refusal carrying the row as it is
    /// now, or `NotFound` when there is no such row.
    pub fn transition_signal(
        &self,
        signal_id: &str,
        state: SignalLifecycleState,
        transitioned_by: Option<&str>,
        expected: TransitionPrecondition<SignalLifecycleState>,
    ) -> Result<TransitionOutcome<Signal>, DiscoveryQueryError> {
        let transitioned_at = utc_timestamp_rfc3339();
        let connection = self.connection_guard();
        let updated = connection
            .execute(
                r#"
                UPDATE discovery_signals
                SET state = ?2,
                    updated_at = ?3,
                    transitioned_at = ?3,
                    transitioned_by = ?4,
                    revision = revision + 1
                WHERE id = ?1
                  AND state = ?5
                  AND (?6 IS NULL OR revision = ?6)
                "#,
                params![
                    signal_id,
                    state.as_str(),
                    transitioned_at,
                    transitioned_by,
                    expected.from_state.as_str(),
                    expected.revision,
                ],
            )
            .map_err(|source| DiscoveryQueryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        let current = load_signal_by_id(&connection, &self.path, signal_id)?;
        Ok(match (updated, current) {
            (0, None) => TransitionOutcome::NotFound,
            (0, Some(current)) => TransitionOutcome::Refused(TransitionRefused { current }),
            (_, Some(transitioned)) => TransitionOutcome::Applied(transitioned),
            (_, None) => TransitionOutcome::NotFound,
        })
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
                        issuer: {
                            let issuer = row.get::<_, String>(1)?;
                            (!issuer.is_empty()).then_some(issuer)
                        },
                        auth_method: row.get(2)?,
                        first_seen: row.get(3)?,
                        last_seen: row.get(4)?,
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
                        issuer: principal.issuer.clone().unwrap_or_default(),
                        auth_method: principal.auth_method.clone(),
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

/// One aggregate row joined with its review, before the derived fields
/// (`is_new`, the effective review state, routing coverage) are computed.
/// Shared with the PostgreSQL read store so both backends derive those
/// fields with the same code.
#[derive(Debug)]
pub(crate) struct RawEndpointAggregate {
    pub(crate) method: String,
    pub(crate) endpoint_template: String,
    pub(crate) first_seen: String,
    pub(crate) last_seen: String,
    pub(crate) call_count: i64,
    pub(crate) schema_mismatch_count: i64,
    pub(crate) latency_count: i64,
    pub(crate) latency_p50_ms: i64,
    pub(crate) latency_p95_ms: i64,
    pub(crate) latency_p99_ms: i64,
    pub(crate) latency_samples_json: String,
    pub(crate) distinct_principal_count: i64,
    pub(crate) updated_at: String,
    pub(crate) reviewed_at: Option<String>,
    pub(crate) reviewed_by: Option<String>,
    /// The joined review row's revision; `None` (no row) reads as
    /// `UNREVIEWED_REVISION`.
    pub(crate) review_revision: Option<i64>,
}

#[derive(Deserialize)]
pub(crate) struct CapturedPayloadShapeSample {
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

pub(crate) fn infer_request_schema(
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
            review_revision: row.get(15)?,
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

    pub(crate) fn into_summary(
        self,
        status_counts: Vec<StatusCount>,
        open_signals: Option<OpenSignalSummary>,
        routing_contexts: Vec<EndpointRoutingContext>,
        routing_context_known_since: Option<String>,
        new_since_cutoff: &str,
    ) -> EndpointSummary {
        let latency = self.latency_summary();
        let is_new = is_new_since(&self.first_seen, new_since_cutoff);
        let review = self.review_state(&routing_contexts);
        let routing_context_known = routing_context_covers_full_history(
            &self.first_seen,
            routing_context_known_since.as_deref(),
        );

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
            review_revision: review.revision,
            covered_by_rule: false,
            coverage_scope: EndpointCoverageScope::None,
            routing_context_known,
            routing_context_known_since,
            routing_contexts,
            open_signals,
            latency,
            status_counts,
        }
    }

    pub(crate) fn into_detail(
        self,
        status_counts: Vec<StatusCount>,
        open_signals: Option<OpenSignalSummary>,
        routing_contexts: Vec<EndpointRoutingContext>,
        routing_context_known_since: Option<String>,
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
        let review = self.review_state(&routing_contexts);
        let routing_context_known = routing_context_covers_full_history(
            &self.first_seen,
            routing_context_known_since.as_deref(),
        );
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
            review_revision: review.revision,
            covered_by_rule: false,
            coverage_scope: EndpointCoverageScope::None,
            routing_context_known,
            routing_context_known_since,
            routing_contexts,
            open_signals,
            latency,
            status_counts,
            updated_at: self.updated_at,
        })
    }

    /// The effective review: a review made before the endpoint's routing
    /// context changed no longer counts, but its row (and revision) is
    /// still what a conditional re-review must expect.
    fn review_state(&self, routing_contexts: &[EndpointRoutingContext]) -> EndpointReviewState {
        let reviewed_at = self.reviewed_at.clone().filter(|reviewed_at| {
            routing_contexts
                .iter()
                .all(|context| !timestamp_after(&context.first_seen, reviewed_at))
        });
        EndpointReviewState {
            reviewed: reviewed_at.is_some(),
            reviewed_at: reviewed_at.clone(),
            reviewed_by: reviewed_at.and(self.reviewed_by.clone()),
            revision: self.review_revision.unwrap_or(UNREVIEWED_REVISION),
        }
    }
}

/// The keyset cursors are hex-encoded JSON and identical for both backends,
/// so a page cursor minted by one replica is valid on any other.
#[derive(Deserialize, Serialize)]
pub(crate) struct EndpointCursor {
    pub(crate) sort: EndpointSort,
    pub(crate) sort_value: String,
    pub(crate) method: String,
    pub(crate) endpoint_template: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct PrincipalCursor {
    pub(crate) last_seen: String,
    pub(crate) user_id: String,
    #[serde(default)]
    pub(crate) issuer: String,
    #[serde(default)]
    pub(crate) auth_method: String,
}

#[derive(Deserialize, Serialize)]
pub(crate) struct SignalCursor {
    pub(crate) created_at: String,
    pub(crate) id: String,
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
            r.reviewed_by,
            r.revision
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
            clauses.push(
                r#"r.reviewed_at IS NOT NULL
                AND NOT EXISTS (
                    SELECT 1
                    FROM discovery_endpoint_routing_contexts c
                    WHERE c.method = a.method
                      AND c.endpoint_template = a.endpoint_template
                      AND julianday(c.first_seen) > julianday(r.reviewed_at)
                )"#,
            );
        } else {
            clauses.push(
                r#"(
                    r.reviewed_at IS NULL
                    OR EXISTS (
                        SELECT 1
                        FROM discovery_endpoint_routing_contexts c
                        WHERE c.method = a.method
                          AND c.endpoint_template = a.endpoint_template
                          AND julianday(c.first_seen) > julianday(r.reviewed_at)
                    )
                )"#,
            );
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
        SELECT user_id, issuer, auth_method, first_seen, last_seen
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
            " AND (julianday(last_seen) < julianday(?) OR (julianday(last_seen) = julianday(?) AND (user_id > ? OR (user_id = ? AND (issuer > ? OR (issuer = ? AND auth_method > ?))))))",
        );
        params.push(SqlValue::Text(cursor.last_seen.clone()));
        params.push(SqlValue::Text(cursor.last_seen.clone()));
        params.push(SqlValue::Text(cursor.user_id.clone()));
        params.push(SqlValue::Text(cursor.user_id.clone()));
        params.push(SqlValue::Text(cursor.issuer.clone()));
        params.push(SqlValue::Text(cursor.issuer.clone()));
        params.push(SqlValue::Text(cursor.auth_method.clone()));
    }

    sql.push_str(
        " ORDER BY julianday(last_seen) DESC, user_id ASC, issuer ASC, auth_method ASC LIMIT ?",
    );
    params.push(SqlValue::Integer(query_limit(limit)));

    (sql, params)
}

fn build_signal_list_query(
    filters: &SignalListFilters,
    cursor: Option<&SignalCursor>,
) -> (String, Vec<SqlValue>) {
    let mut sql = format!("SELECT {SIGNAL_COLUMNS} FROM discovery_signals");
    let mut clauses = Vec::new();
    let mut params = Vec::new();

    if let Some(state) = filters.state {
        clauses.push("state = ?");
        params.push(SqlValue::Text(state.as_str().to_owned()));
    }
    if let Some(signal_type) = &filters.signal_type {
        clauses.push("signal_type = ?");
        params.push(SqlValue::Text(signal_type.clone()));
    }
    if let Some(target_kind) = &filters.target_kind {
        clauses.push("target_kind = ?");
        params.push(SqlValue::Text(target_kind.clone()));
    }
    if let Some(target_key) = &filters.target_key {
        clauses.push("target_key = ?");
        params.push(SqlValue::Text(target_key.clone()));
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

pub(crate) fn endpoint_cursor(
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

/// One `discovery_signals` row as stored, shared with the PostgreSQL read
/// store so both backends decode it into a `Signal` identically.
#[derive(Debug)]
pub(crate) struct RawSignal {
    pub(crate) id: String,
    pub(crate) signal_type: String,
    pub(crate) target_kind: String,
    pub(crate) target_key: String,
    pub(crate) target_identity_json: String,
    pub(crate) explanation: String,
    pub(crate) evidence_json: String,
    pub(crate) state: String,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) transitioned_at: Option<String>,
    pub(crate) transitioned_by: Option<String>,
    pub(crate) revision: i64,
}

/// The signal columns every read selects, in the order `RawSignal` reads
/// them; identical on both backends.
pub(crate) const SIGNAL_COLUMNS: &str = "id, signal_type, target_kind, target_key, \
     target_identity_json, explanation, evidence_json, state, created_at, updated_at, \
     transitioned_at, transitioned_by, revision";

impl RawSignal {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            signal_type: row.get(1)?,
            target_kind: row.get(2)?,
            target_key: row.get(3)?,
            target_identity_json: row.get(4)?,
            explanation: row.get(5)?,
            evidence_json: row.get(6)?,
            state: row.get(7)?,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
            transitioned_at: row.get(10)?,
            transitioned_by: row.get(11)?,
            revision: row.get(12)?,
        })
    }

    pub(crate) fn into_signal(self) -> Result<Signal, DiscoveryQueryError> {
        let identity =
            serde_json::from_str::<Value>(&self.target_identity_json).map_err(|source| {
                DiscoveryQueryError::Json {
                    context: "signal target identity",
                    source,
                }
            })?;
        let evidence = serde_json::from_str::<Value>(&self.evidence_json).map_err(|source| {
            DiscoveryQueryError::Json {
                context: "signal evidence",
                source,
            }
        })?;
        let state = SignalLifecycleState::parse(&self.state).map_err(|_| {
            DiscoveryQueryError::InvalidSignalState {
                state: self.state.clone(),
            }
        })?;
        let _ = self.target_key;

        Ok(Signal {
            id: self.id,
            signal_type: self.signal_type,
            target: SignalTarget {
                kind: self.target_kind,
                identity,
            },
            explanation: self.explanation,
            evidence,
            state,
            created_at: self.created_at,
            updated_at: self.updated_at,
            transitioned_at: self.transitioned_at,
            transitioned_by: self.transitioned_by,
            revision: self.revision,
        })
    }
}

fn load_signal_by_id(
    connection: &Connection,
    path: &Path,
    signal_id: &str,
) -> Result<Option<Signal>, DiscoveryQueryError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {SIGNAL_COLUMNS} FROM discovery_signals WHERE id = ?1"
        ))
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;

    statement
        .query_row(params![signal_id], RawSignal::from_row)
        .optional()
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?
        .map(RawSignal::into_signal)
        .transpose()
}

/// The review row as stored (not the effective, reclassification-aware
/// state): what a refused conditional write hands back.
fn load_review_by_key(
    connection: &Connection,
    path: &Path,
    method: &str,
    endpoint_template: &str,
) -> Result<EndpointReviewState, DiscoveryQueryError> {
    connection
        .query_row(
            r#"
            SELECT reviewed_at, reviewed_by, revision
            FROM discovery_endpoint_reviews
            WHERE method = ?1 AND endpoint_template = ?2
            "#,
            params![method, endpoint_template],
            |row| {
                Ok(EndpointReviewState {
                    reviewed: true,
                    reviewed_at: Some(row.get(0)?),
                    reviewed_by: row.get(1)?,
                    revision: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })
        .map(|review| review.unwrap_or_else(EndpointReviewState::unreviewed))
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

fn load_routing_contexts(
    connection: &Connection,
    path: &Path,
    method: &str,
    endpoint_template: &str,
) -> Result<Vec<EndpointRoutingContext>, DiscoveryQueryError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT
                NULLIF(route_host, ''),
                NULLIF(route_path_prefix, ''),
                NULLIF(upstream_origin, ''),
                first_seen,
                last_seen,
                call_count,
                distinct_principal_count
            FROM discovery_endpoint_routing_contexts
            WHERE method = ?1 AND endpoint_template = ?2
            ORDER BY route_host, route_path_prefix, upstream_origin
            "#,
        )
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;

    let rows = statement
        .query_map(params![method, endpoint_template], |row| {
            Ok(EndpointRoutingContext {
                route_host: row.get(0)?,
                route_path_prefix: row.get(1)?,
                upstream_origin: row.get(2)?,
                first_seen: row.get(3)?,
                last_seen: row.get(4)?,
                call_count: non_negative_i64_to_u64(row.get(5)?),
                distinct_principal_count: non_negative_i64_to_u64(row.get(6)?),
                covered_by_rule: false,
                coverage_scope: EndpointCoverageScope::None,
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

fn load_routing_context_known_since(
    connection: &Connection,
    path: &Path,
    method: &str,
    endpoint_template: &str,
) -> Result<Option<String>, DiscoveryQueryError> {
    connection
        .query_row(
            r#"
            SELECT first_classified_at
            FROM discovery_endpoint_routing_classifications
            WHERE method = ?1 AND endpoint_template = ?2
            "#,
            params![method, endpoint_template],
            |row| row.get(0),
        )
        .optional()
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })
}

fn load_open_signal_summaries(
    connection: &Connection,
    path: &Path,
    endpoint_keys: &[(String, String)],
) -> Result<HashMap<(String, String), OpenSignalSummary>, DiscoveryQueryError> {
    let values_sql = std::iter::repeat_n("(?, ?, ?)", endpoint_keys.len())
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        r#"
        WITH requested(method, endpoint_template, target_key) AS (
            VALUES {values_sql}
        )
        SELECT
            r.method,
            r.endpoint_template,
            s.signal_type,
            COUNT(s.id)
        FROM requested r
        JOIN discovery_signals s
            ON s.target_kind = ?
            AND s.target_key = r.target_key
            AND s.state = ?
        GROUP BY r.method, r.endpoint_template, s.signal_type
        ORDER BY r.method ASC, r.endpoint_template ASC, s.signal_type ASC
        "#
    );
    let mut params = Vec::with_capacity(endpoint_keys.len() * 3 + 2);
    for (method, endpoint_template) in endpoint_keys {
        params.push(SqlValue::Text(method.clone()));
        params.push(SqlValue::Text(endpoint_template.clone()));
        params.push(SqlValue::Text(signals::endpoint_target_key(
            method,
            endpoint_template,
        )));
    }
    params.push(SqlValue::Text(signals::ENDPOINT_TARGET_KIND.to_owned()));
    params.push(SqlValue::Text(
        SignalLifecycleState::Open.as_str().to_owned(),
    ));

    let mut statement = connection
        .prepare(&sql)
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
    let rows = statement
        .query_map(params_from_iter(params.iter()), |row| {
            let count: i64 = row.get(3)?;
            Ok((
                (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                row.get::<_, String>(2)?,
                non_negative_i64_to_u64(count),
            ))
        })
        .map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;

    let mut summaries = HashMap::<(String, String), OpenSignalSummary>::new();
    for row in rows {
        let (key, signal_type, count) = row.map_err(|source| DiscoveryQueryError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?;
        let summary = summaries.entry(key).or_default();
        summary.count += count;
        summary.signal_types.push(signal_type);
    }

    Ok(summaries)
}

fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        r#"
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
        "#,
    )?;
    connection.execute_batch(CREATE_REVIEW_SCHEMA_SQL)?;
    lifecycle::ensure_sqlite_column(
        connection,
        "discovery_endpoint_reviews",
        "revision",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    super::aggregator::ensure_discovery_endpoint_principal_identity_schema(connection)?;
    connection.execute_batch(CREATE_ROUTING_CONTEXT_SCHEMA_SQL)?;
    ensure_discovery_endpoint_aggregate_column(
        connection,
        "schema_mismatch_count",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    signals::configure_connection(connection)?;
    suggestions::configure_connection(connection)
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

pub(crate) fn new_since_cutoff(new_since_hours: u64) -> String {
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

fn timestamp_after(left: &str, right: &str) -> bool {
    match (
        OffsetDateTime::parse(left, &Rfc3339),
        OffsetDateTime::parse(right, &Rfc3339),
    ) {
        (Ok(left), Ok(right)) => left > right,
        _ => left > right,
    }
}

fn routing_context_covers_full_history(
    first_seen: &str,
    routing_context_known_since: Option<&str>,
) -> bool {
    routing_context_known_since.is_some_and(|known_since| !timestamp_after(known_since, first_seen))
}

pub(crate) fn utc_timestamp_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current UTC timestamp should format as RFC 3339")
}

pub(crate) fn encode_cursor<T: Serialize>(cursor: &T) -> Result<String, DiscoveryQueryError> {
    let json = serde_json::to_vec(cursor).map_err(|source| DiscoveryQueryError::Json {
        context: "cursor",
        source,
    })?;

    Ok(hex::encode(json))
}

pub(crate) fn decode_cursor<T: DeserializeOwned>(
    parameter: &'static str,
    value: &str,
) -> Result<T, DiscoveryQueryError> {
    let bytes = hex::decode(value).map_err(|_| DiscoveryQueryError::InvalidCursor { parameter })?;
    serde_json::from_slice(&bytes).map_err(|_| DiscoveryQueryError::InvalidCursor { parameter })
}

pub(crate) fn like_escape(value: &str) -> String {
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

pub(crate) fn query_limit(limit: usize) -> i64 {
    i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
}

pub(crate) fn non_negative_i64_to_u64(value: i64) -> u64 {
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
                    route_host: None,
                    route_path_prefix: None,
                    upstream_origin: None,
                    routing_context_known_since: None,
                },
                ObservedEndpoint {
                    method: "POST".to_owned(),
                    endpoint_template: "/users".to_owned(),
                    route_host: None,
                    route_path_prefix: None,
                    upstream_origin: None,
                    routing_context_known_since: None,
                },
            ]
        );
    }

    #[test]
    fn observed_endpoints_preserve_routing_context_identity() {
        let db = TempDb::new("query-observed-routing");
        seed_endpoint(&db.path, "GET", "/users/{id}");
        let store = DiscoveryQueryStore::open(&db.path).expect("discovery query store should open");
        let connection = Connection::open(&db.path).expect("database should open");
        for (host, origin) in [
            ("api.example.test", "https://api.internal"),
            ("admin.example.test", "https://admin.internal"),
        ] {
            connection
                .execute(
                    r#"
                    INSERT INTO discovery_endpoint_routing_contexts (
                        method,
                        endpoint_template,
                        route_host,
                        route_path_prefix,
                        upstream_origin,
                        first_seen,
                        last_seen,
                        call_count,
                        distinct_principal_count,
                        updated_at
                    ) VALUES ('GET', '/users/{id}', ?1, '/users', ?2, ?3, ?3, 1, 1, ?3)
                    "#,
                    params![host, origin, "2024-06-01T12:00:00Z"],
                )
                .expect("routing context should insert");
        }

        assert_eq!(
            store
                .observed_endpoints()
                .expect("observed endpoints should query"),
            vec![
                ObservedEndpoint {
                    method: "GET".to_owned(),
                    endpoint_template: "/users/{id}".to_owned(),
                    route_host: Some("admin.example.test".to_owned()),
                    route_path_prefix: Some("/users".to_owned()),
                    upstream_origin: Some("https://admin.internal".to_owned()),
                    routing_context_known_since: None,
                },
                ObservedEndpoint {
                    method: "GET".to_owned(),
                    endpoint_template: "/users/{id}".to_owned(),
                    route_host: Some("api.example.test".to_owned()),
                    route_path_prefix: Some("/users".to_owned()),
                    upstream_origin: Some("https://api.internal".to_owned()),
                    routing_context_known_since: None,
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

    #[test]
    fn principal_cursor_decodes_pre_identity_pagination_shape() {
        let legacy_cursor =
            hex::encode(br#"{"last_seen":"2024-06-01T12:00:00Z","user_id":"alice"}"#);

        let cursor = decode_cursor::<PrincipalCursor>("principal_cursor", &legacy_cursor)
            .expect("legacy principal cursor should remain decodable");

        assert_eq!(cursor.last_seen, "2024-06-01T12:00:00Z");
        assert_eq!(cursor.user_id, "alice");
        assert_eq!(cursor.issuer, "");
        assert_eq!(cursor.auth_method, "");
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

    // ------------------------------------------------------------------
    // Conditional lifecycle transitions (issue #241, PR 12). Standalone
    // has one process, so the "two handles" here are two query stores
    // over the same file taking turns: the second one's transition must
    // be refused with the row the first one wrote, never overwrite it.
    // ------------------------------------------------------------------

    fn seed_open_signal(path: &PathBuf, id: &str, method: &str, endpoint_template: &str) {
        let connection = Connection::open(path).expect("test database should open");
        signals::configure_connection(&connection).expect("signal schema should configure");
        connection
            .execute(
                r#"
                INSERT INTO discovery_signals (
                    id, signal_type, target_kind, target_key, target_identity_json,
                    explanation, evidence_json, state, created_at, updated_at,
                    transitioned_at, transitioned_by
                ) VALUES (?1, 'new_endpoint_seen', 'endpoint', ?2, ?3, 'seeded', '{}',
                          'open', '2024-06-01T00:00:00Z', '2024-06-01T00:00:00Z', NULL, NULL)
                "#,
                params![
                    id,
                    signals::endpoint_target_key(method, endpoint_template),
                    json!({"method": method, "endpoint_template": endpoint_template}).to_string(),
                ],
            )
            .expect("open signal should insert");
    }

    fn two_stores(db: &TempDb) -> (DiscoveryQueryStore, DiscoveryQueryStore) {
        (
            DiscoveryQueryStore::open(&db.path).expect("first store opens"),
            DiscoveryQueryStore::open(&db.path).expect("second store opens"),
        )
    }

    #[test]
    fn signal_revision_column_is_added_in_place_and_starts_at_one() {
        let db = TempDb::new("signal-revision-column");
        // The table predates the column (the seed creates it without one
        // through the same CREATE the sink uses, then the column is added).
        let connection = Connection::open(&db.path).expect("test database should open");
        connection
            .execute_batch(
                "CREATE TABLE discovery_signals (
                    id TEXT PRIMARY KEY, signal_type TEXT NOT NULL, target_kind TEXT NOT NULL,
                    target_key TEXT NOT NULL, target_identity_json TEXT NOT NULL,
                    explanation TEXT NOT NULL, evidence_json TEXT NOT NULL, state TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    transitioned_at TEXT, transitioned_by TEXT
                );",
            )
            .expect("legacy signal table should create");
        drop(connection);
        seed_open_signal(&db.path, "sig-legacy", "GET", "/legacy");

        let store = DiscoveryQueryStore::open(&db.path).expect("store opens");
        let page = store
            .list_signals(&SignalListFilters {
                state: None,
                signal_type: None,
                target_kind: None,
                target_key: None,
                limit: 10,
                cursor: None,
            })
            .expect("signals list");
        assert_eq!(page.signals.len(), 1);
        assert_eq!(page.signals[0].revision, 1);
    }

    #[test]
    fn two_handles_acknowledging_one_signal_get_exactly_one_winner() {
        for target in [
            SignalLifecycleState::Acknowledged,
            SignalLifecycleState::Dismissed,
        ] {
            let db = TempDb::new("signal-race");
            seed_open_signal(&db.path, "sig-race", "GET", "/race");
            let (replica_a, replica_b) = two_stores(&db);
            let from_open = TransitionPrecondition::from_state(SignalLifecycleState::Open);

            let winner = replica_a
                .transition_signal("sig-race", target, Some("admin-a"), from_open)
                .expect("first transition")
                .expect_applied("the first replica wins");
            assert_eq!(winner.state, target);
            assert_eq!(winner.revision, 2);
            assert_eq!(winner.transitioned_by.as_deref(), Some("admin-a"));

            let refused = replica_b
                .transition_signal("sig-race", target, Some("admin-b"), from_open)
                .expect("second transition")
                .expect_refused("the second replica is refused");
            assert_eq!(refused.state, target);
            assert_eq!(refused.revision, 2);
            assert_eq!(
                refused.transitioned_by.as_deref(),
                Some("admin-a"),
                "the refusal carries the winner's row; nothing was overwritten"
            );

            // The revision predicate on its own: the right revision applies
            // (a re-dismissal of an acknowledged signal from Acknowledged),
            // a stale one is refused even though the state matches.
            let stale = replica_b
                .transition_signal(
                    "sig-race",
                    SignalLifecycleState::Dismissed,
                    Some("admin-b"),
                    TransitionPrecondition::from_state(target).with_revision(Some(1)),
                )
                .expect("stale transition")
                .expect_refused("a stale revision is refused");
            assert_eq!(stale.revision, 2);
            let moved = replica_b
                .transition_signal(
                    "sig-race",
                    SignalLifecycleState::Dismissed,
                    Some("admin-b"),
                    TransitionPrecondition::from_state(target).with_revision(Some(2)),
                )
                .expect("exact transition")
                .expect_applied("the exact revision applies");
            assert_eq!(moved.revision, 3);
            assert!(replica_a
                .transition_signal("sig-missing", target, None, from_open)
                .expect("unknown transition")
                .is_not_found());
        }
    }

    #[test]
    fn two_handles_marking_and_clearing_one_review_get_exactly_one_winner() {
        let db = TempDb::new("review-race");
        seed_endpoint(&db.path, "GET", "/reviewed");
        Connection::open(&db.path)
            .expect("test database should open")
            .execute_batch(
                "CREATE TABLE IF NOT EXISTS discovery_endpoint_status_counts (
                    method TEXT NOT NULL, endpoint_template TEXT NOT NULL,
                    status INTEGER NOT NULL, count INTEGER NOT NULL,
                    PRIMARY KEY (method, endpoint_template, status)
                );",
            )
            .expect("status count table should create");
        let (replica_a, replica_b) = two_stores(&db);
        let expect_unreviewed = Some(UNREVIEWED_REVISION);

        // Two first marks: one row, one winner.
        let marked = replica_a
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-a"), expect_unreviewed)
            .expect("first mark")
            .expect_applied("the first mark wins");
        assert!(marked.reviewed);
        assert_eq!(marked.revision, 1);
        let refused = replica_b
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-b"), expect_unreviewed)
            .expect("second mark")
            .expect_refused("the second mark is refused");
        assert_eq!(refused.reviewed_by.as_deref(), Some("admin-a"));
        assert_eq!(refused.revision, 1);
        let detail = replica_b
            .get_endpoint_with_open_signal_summaries("GET", "/reviewed", 24, false)
            .expect("detail")
            .expect("exists");
        assert_eq!(detail.reviewed_by.as_deref(), Some("admin-a"));
        assert_eq!(detail.review_revision, 1);

        // Two clears of revision 1: one wins, the other finds no review.
        let cleared = replica_b
            .set_endpoint_review("GET", "/reviewed", false, Some("admin-b"), Some(1))
            .expect("first clear")
            .expect_applied("the first clear wins");
        assert_eq!(cleared, EndpointReviewState::unreviewed());
        let refused = replica_a
            .set_endpoint_review("GET", "/reviewed", false, Some("admin-a"), Some(1))
            .expect("second clear")
            .expect_refused("the second clear is refused");
        assert_eq!(refused, EndpointReviewState::unreviewed());

        // A re-mark against a stale revision is refused; against the row's
        // revision it applies; unconditional always applies.
        let remarked = replica_a
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-a"), None)
            .expect("unconditional mark")
            .expect_applied("unconditional");
        assert_eq!(remarked.revision, 1);
        let stale = replica_b
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-b"), Some(7))
            .expect("stale mark")
            .expect_refused("stale");
        assert_eq!(stale.reviewed_by.as_deref(), Some("admin-a"));
        let exact = replica_b
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-b"), Some(1))
            .expect("exact mark")
            .expect_applied("exact");
        assert_eq!(exact.revision, 2);
        assert_eq!(exact.reviewed_by.as_deref(), Some("admin-b"));
        let replaced = replica_a
            .set_endpoint_review("GET", "/reviewed", true, Some("admin-a"), None)
            .expect("unconditional replace")
            .expect_applied("unconditional");
        assert_eq!(replaced.revision, 3);

        // A clear names a revision too: a stale one deletes nothing.
        let stale_clear = replica_b
            .set_endpoint_review("GET", "/reviewed", false, Some("admin-b"), Some(9))
            .expect("stale clear")
            .expect_refused("a stale clear is refused");
        assert!(stale_clear.reviewed);
        assert_eq!(stale_clear.revision, 3);

        // Clearing an unreviewed endpoint expecting it unreviewed is a
        // no-op that applies; an unknown endpoint is not found.
        replica_a
            .set_endpoint_review("GET", "/reviewed", false, None, None)
            .expect("clear")
            .expect_applied("clear");
        let noop = replica_b
            .set_endpoint_review("GET", "/reviewed", false, None, expect_unreviewed)
            .expect("no-op clear")
            .expect_applied("clearing nothing, expecting nothing, applies");
        assert_eq!(noop, EndpointReviewState::unreviewed());
        assert!(replica_a
            .set_endpoint_review("GET", "/missing", true, None, None)
            .expect("unknown endpoint")
            .is_not_found());
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
