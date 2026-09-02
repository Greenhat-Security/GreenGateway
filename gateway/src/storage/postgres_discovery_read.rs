//! PostgreSQL discovery read store (issue #241, PR 11): the cluster
//! implementation of [`DiscoveryReadStore`], answering the admin traffic,
//! signals, principals, and schema surfaces from the tables the discovery
//! projector writes (migration 9).
//!
//! What is read and why it matches the SQLite store:
//!
//! - **The same rows, the same derivation.** The tables mirror the SQLite
//!   sink's column for column, so every query here is the SQLite query
//!   ported statement by statement, and the rows are handed to the SAME
//!   post-processing code the SQLite store uses (`RawEndpointAggregate`,
//!   `RawSignal`, the cursor codecs, `infer_request_schema`). A summary,
//!   a detail, a cursor, or an inferred schema is derived by one function
//!   whichever backend produced the row, so the two backends cannot drift
//!   in `is_new`, the effective review state, the 0.95 required threshold,
//!   or the cursor format.
//! - **Ordering is byte order.** SQLite compares text bytewise; PostgreSQL
//!   compares text under the database's collation, which for a locale
//!   collation is neither bytewise nor even case-sensitive at the first
//!   level. Every text tiebreaker and every keyset-cursor comparison here
//!   is `COLLATE "C"` so the page order, and therefore the cursor a page
//!   hands back, is identical to the SQLite store's. `LIKE` is likewise
//!   ported as `ILIKE` under `COLLATE "C"`, which folds ASCII case only --
//!   SQLite's default `LIKE` behaviour.
//! - **Timestamps compare as instants.** SQLite orders and compares the
//!   RFC 3339 text through `julianday`; here the columns cast to
//!   `timestamptz`. Column values are always castable (the projector only
//!   applies events the audit store already accepted as `timestamptz`, and
//!   the store generates the rest), but a timestamp a CALLER supplies -- a
//!   filter or a cursor -- is guarded with `pg_input_is_valid`, so an
//!   unparsable value compares as NULL and excludes rows, exactly as
//!   `julianday` of unparsable text does, instead of failing the query.
//!   One deliberate difference: `timestamptz` keeps microseconds where
//!   `julianday` rounds to the millisecond, so two rows within the same
//!   millisecond tie under SQLite (and fall to the key tiebreak) but order
//!   by their instants here. Each backend's cursors are consistent with
//!   its own order, and the full-precision order is the one the Rust-side
//!   comparisons (`timestamp_after`, `new_since`) already use, so it is
//!   not degraded to match SQLite's rounding.
//! - **Timestamp text is the stream's rendering.** The projector stores
//!   `first_seen`/`last_seen` and the routing-context times as the durable
//!   audit stream renders them (fixed microseconds, `...:26.000000Z`),
//!   where the standalone sink keeps the event's own text (`...:26Z`).
//!   The instants are the same and both are RFC 3339; response bodies and
//!   page cursors differ in that text only.
//! - **No request-path fan-out.** A page's child rows (status counts,
//!   routing contexts, classification, open-signal summaries) load with
//!   one `UNNEST`-keyed query per table for the whole page, not one query
//!   per endpoint per table.
//!
//! Writes here are the two admin transitions the SQLite store also owns:
//! endpoint review and signal lifecycle. Both are the conditional writes of
//! [`crate::discovery::lifecycle`] (issue #241, PR 12): one statement whose
//! predicate is the expected state and revision, refused with the current
//! row when it no longer holds, so two replicas transitioning the same row
//! get exactly one winner. Errors classify into the repository vocabulary
//! and carry an operation label only: no SQL text, no values.

use std::collections::HashMap;

use async_trait::async_trait;
use tokio_postgres::{
    types::{FromSql, ToSql},
    Row,
};

use crate::discovery::{
    lifecycle::{
        TransitionOutcome, TransitionPrecondition, TransitionRefused, UNREVIEWED_REVISION,
    },
    query::{
        decode_cursor, encode_cursor, endpoint_cursor, infer_request_schema, like_escape,
        new_since_cutoff, non_negative_i64_to_u64, query_limit, utc_timestamp_rfc3339,
        CapturedPayloadShapeSample, DiscoveryQueryError, DiscoveryReadStore,
        EndpointAggregateDetail, EndpointCoverageScope, EndpointCursor, EndpointListFilters,
        EndpointListPage, EndpointPrincipal, EndpointReviewState, EndpointRoutingContext,
        EndpointSort, InferredRequestSchema, ObservedEndpoint, OpenSignalSummary, PrincipalCursor,
        PrincipalPage, PrincipalPageFilters, RawEndpointAggregate, RawSignal, SignalCursor,
        StatusCount, SIGNAL_COLUMNS,
    },
    signals::{self, Signal, SignalLifecycleState, SignalListFilters},
};

use super::{log_classified, postgres::classify_pool_error, RepositoryError, RepositoryErrorKind};

const OPERATION_OBSERVED_ENDPOINTS: &str = "discovery_read_observed_endpoints";
const OPERATION_LIST_ENDPOINTS: &str = "discovery_read_list_endpoints";
const OPERATION_GET_ENDPOINT: &str = "discovery_read_get_endpoint";
const OPERATION_INFERRED_SCHEMA: &str = "discovery_read_inferred_schema";
const OPERATION_SET_REVIEW: &str = "discovery_set_endpoint_review";
const OPERATION_LIST_SIGNALS: &str = "discovery_read_list_signals";
const OPERATION_PRINCIPAL_SIGNALS: &str = "discovery_read_principal_signals";
const OPERATION_TRANSITION_SIGNAL: &str = "discovery_transition_signal";
const OPERATION_LIST_PRINCIPALS: &str = "discovery_read_list_principals";

/// The discovery read store over one PostgreSQL pool. Cheap to construct;
/// holds no per-instance state.
#[derive(Clone)]
pub struct PostgresDiscoveryReadStore {
    pool: deadpool_postgres::Pool,
}

impl PostgresDiscoveryReadStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }

    async fn client(&self) -> Result<deadpool_postgres::Object, DiscoveryQueryError> {
        self.pool
            .get()
            .await
            .map_err(|error| DiscoveryQueryError::Repository(classify_pool_error(error)))
    }
}

#[async_trait]
impl DiscoveryReadStore for PostgresDiscoveryReadStore {
    async fn observed_endpoints(&self) -> Result<Vec<ObservedEndpoint>, DiscoveryQueryError> {
        let operation = OPERATION_OBSERVED_ENDPOINTS;
        let client = self.client().await?;
        // `NULLS FIRST` where SQLite's ASC order puts NULL, so an endpoint
        // that was never classified (the first branch) and a context with
        // an empty host (NULLIF) land where the SQLite store lists them.
        // The union is wrapped because PostgreSQL only orders a set
        // operation by plain output columns, not by collated expressions.
        let rows = client
            .query(
                "SELECT method, endpoint_template, route_host, route_path_prefix, upstream_origin,
                        first_classified_at
                 FROM (
                     SELECT
                         a.method,
                         a.endpoint_template,
                         NULL::text AS route_host,
                         NULL::text AS route_path_prefix,
                         NULL::text AS upstream_origin,
                         k.first_classified_at
                     FROM greengateway.discovery_endpoint_aggregates a
                     LEFT JOIN greengateway.discovery_endpoint_routing_classifications k
                         USING (method, endpoint_template)
                     WHERE NOT EXISTS (
                         SELECT 1
                         FROM greengateway.discovery_endpoint_routing_contexts c
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
                     FROM greengateway.discovery_endpoint_routing_contexts c
                     LEFT JOIN greengateway.discovery_endpoint_routing_classifications k
                         USING (method, endpoint_template)
                 ) AS observed
                 ORDER BY method COLLATE \"C\", endpoint_template COLLATE \"C\",
                          route_host COLLATE \"C\" NULLS FIRST,
                          route_path_prefix COLLATE \"C\" NULLS FIRST,
                          upstream_origin COLLATE \"C\" NULLS FIRST",
                &[],
            )
            .await
            .map_err(|error| classify_query(error, operation))?;
        rows.iter()
            .map(|row| {
                Ok(ObservedEndpoint {
                    method: column(row, 0, operation)?,
                    endpoint_template: column(row, 1, operation)?,
                    route_host: column(row, 2, operation)?,
                    route_path_prefix: column(row, 3, operation)?,
                    upstream_origin: column(row, 4, operation)?,
                    routing_context_known_since: column(row, 5, operation)?,
                })
            })
            .collect()
    }

    async fn list_endpoints_with_open_signal_summaries(
        &self,
        filters: &EndpointListFilters,
        include_open_signals: bool,
    ) -> Result<EndpointListPage, DiscoveryQueryError> {
        let operation = OPERATION_LIST_ENDPOINTS;
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
        let client = self.client().await?;
        let mut rows = client
            .query(sql.as_str(), &params.refs())
            .await
            .map_err(|error| classify_query(error, operation))?
            .iter()
            .map(|row| raw_endpoint_aggregate(row, operation))
            .collect::<Result<Vec<_>, _>>()?;

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

        let keys = rows
            .iter()
            .map(|row| (row.method.clone(), row.endpoint_template.clone()))
            .collect::<Vec<_>>();
        let mut status_counts = load_status_counts(&client, &keys, operation).await?;
        let mut routing_contexts = load_routing_contexts(&client, &keys, operation).await?;
        let mut known_since = load_routing_context_known_since(&client, &keys, operation).await?;
        let open_signal_summaries = if include_open_signals {
            load_open_signal_summaries(&client, &keys, operation).await?
        } else {
            HashMap::new()
        };

        let endpoints = rows
            .into_iter()
            .map(|row| {
                let key = (row.method.clone(), row.endpoint_template.clone());
                let open_signals = include_open_signals
                    .then(|| open_signal_summaries.get(&key).cloned().unwrap_or_default());
                row.into_summary(
                    status_counts.remove(&key).unwrap_or_default(),
                    open_signals,
                    routing_contexts.remove(&key).unwrap_or_default(),
                    known_since.remove(&key),
                    &new_since_cutoff,
                )
            })
            .collect();

        Ok(EndpointListPage {
            endpoints,
            next_cursor,
        })
    }

    async fn get_endpoint_with_open_signal_summaries(
        &self,
        method: &str,
        endpoint_template: &str,
        new_since_hours: u64,
        include_open_signals: bool,
    ) -> Result<Option<EndpointAggregateDetail>, DiscoveryQueryError> {
        let operation = OPERATION_GET_ENDPOINT;
        let new_since_cutoff = new_since_cutoff(new_since_hours);
        let client = self.client().await?;
        let Some(row) = client
            .query_opt(
                &format!(
                    "SELECT {AGGREGATE_COLUMNS}
                     FROM greengateway.discovery_endpoint_aggregates a
                     LEFT JOIN greengateway.discovery_endpoint_reviews r
                         USING (method, endpoint_template)
                     WHERE a.method = $1 AND a.endpoint_template = $2"
                ),
                &[&method, &endpoint_template],
            )
            .await
            .map_err(|error| classify_query(error, operation))?
        else {
            return Ok(None);
        };
        let row = raw_endpoint_aggregate(&row, operation)?;

        let key = (row.method.clone(), row.endpoint_template.clone());
        let keys = [key.clone()];
        let status_counts = load_status_counts(&client, &keys, operation)
            .await?
            .remove(&key)
            .unwrap_or_default();
        let routing_contexts = load_routing_contexts(&client, &keys, operation)
            .await?
            .remove(&key)
            .unwrap_or_default();
        let routing_context_known_since =
            load_routing_context_known_since(&client, &keys, operation)
                .await?
                .remove(&key);
        let open_signals = if include_open_signals {
            Some(
                load_open_signal_summaries(&client, &keys, operation)
                    .await?
                    .remove(&key)
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

    async fn inferred_request_schema(
        &self,
        method: &str,
        endpoint_template: &str,
    ) -> Result<Option<InferredRequestSchema>, DiscoveryQueryError> {
        let operation = OPERATION_INFERRED_SCHEMA;
        let client = self.client().await?;
        let shape_jsons = client
            .query(
                "SELECT shape_json
                 FROM greengateway.discovery_payload_shape_samples
                 WHERE method = $1 AND endpoint_template = $2
                 ORDER BY sample_slot",
                &[&method, &endpoint_template],
            )
            .await
            .map_err(|error| classify_query(error, operation))?
            .iter()
            .map(|row| column::<String>(row, 0, operation))
            .collect::<Result<Vec<_>, _>>()?;
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

    /// One `UNNEST`-keyed query for the whole set (the cluster conformance
    /// refresher asks for every endpoint a replica tracks, every interval).
    /// An endpoint whose samples do not parse is reported as having no
    /// schema, with the corruption logged, rather than failing every other
    /// endpoint's answer with it; the single-endpoint read still surfaces
    /// the error to the admin surface that asks about that endpoint.
    async fn inferred_request_schemas(
        &self,
        endpoints: &[(String, String)],
    ) -> Result<Vec<Option<InferredRequestSchema>>, DiscoveryQueryError> {
        if endpoints.is_empty() {
            return Ok(Vec::new());
        }
        let operation = OPERATION_INFERRED_SCHEMA;
        let methods = endpoints
            .iter()
            .map(|(method, _)| method.as_str())
            .collect::<Vec<_>>();
        let templates = endpoints
            .iter()
            .map(|(_, endpoint_template)| endpoint_template.as_str())
            .collect::<Vec<_>>();
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT s.method, s.endpoint_template, s.shape_json
                 FROM greengateway.discovery_payload_shape_samples AS s
                 JOIN UNNEST($1::text[], $2::text[]) AS wanted(method, endpoint_template)
                   ON wanted.method = s.method
                  AND wanted.endpoint_template = s.endpoint_template
                 ORDER BY s.method, s.endpoint_template, s.sample_slot",
                &[&methods, &templates],
            )
            .await
            .map_err(|error| classify_query(error, operation))?;
        let mut shape_jsons = HashMap::<(String, String), Vec<String>>::new();
        for row in &rows {
            let method = column::<String>(row, 0, operation)?;
            let endpoint_template = column::<String>(row, 1, operation)?;
            let shape_json = column::<String>(row, 2, operation)?;
            shape_jsons
                .entry((method, endpoint_template))
                .or_default()
                .push(shape_json);
        }
        Ok(endpoints
            .iter()
            .map(|key| {
                let (method, endpoint_template) = key;
                let shape_jsons = shape_jsons.get(key)?;
                let shapes = shape_jsons
                    .iter()
                    .map(|shape_json| serde_json::from_str::<CapturedPayloadShapeSample>(shape_json))
                    .collect::<Result<Vec<_>, _>>();
                match shapes {
                    Ok(shapes) => Some(infer_request_schema(method, endpoint_template, &shapes)),
                    Err(error) => {
                        tracing::error!(
                            operation,
                            method,
                            endpoint_template,
                            error = %error,
                            "payload shape sample failed to parse; the endpoint is served without an inferred schema"
                        );
                        None
                    }
                }
            })
            .collect())
    }

    async fn set_endpoint_review(
        &self,
        method: &str,
        endpoint_template: &str,
        reviewed: bool,
        reviewed_by: Option<&str>,
        expected_revision: Option<i64>,
    ) -> Result<TransitionOutcome<EndpointReviewState>, DiscoveryQueryError> {
        let operation = OPERATION_SET_REVIEW;
        let client = self.client().await?;
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| classify_query(error, operation))?;
        let result = set_endpoint_review_transaction(
            &client,
            method,
            endpoint_template,
            reviewed,
            reviewed_by,
            expected_revision,
        )
        .await;
        match result {
            Ok(review) => {
                client
                    .batch_execute("COMMIT")
                    .await
                    .map_err(|error| classify_query(error, operation))?;
                Ok(review)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    async fn list_signals(
        &self,
        filters: &SignalListFilters,
    ) -> Result<signals::SignalListPage, DiscoveryQueryError> {
        let operation = OPERATION_LIST_SIGNALS;
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<SignalCursor>("cursor", value))
            .transpose()?;
        let (sql, params) = build_signal_list_query(filters, cursor.as_ref());
        let client = self.client().await?;
        let mut rows = client
            .query(sql.as_str(), &params.refs())
            .await
            .map_err(|error| classify_query(error, operation))?
            .iter()
            .map(|row| raw_signal(row, operation))
            .collect::<Result<Vec<_>, _>>()?;

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

    async fn list_principal_endpoint_signals(
        &self,
        principal: &str,
        issuer: &str,
        auth_method: &str,
        limit: usize,
    ) -> Result<Vec<Signal>, DiscoveryQueryError> {
        let operation = OPERATION_PRINCIPAL_SIGNALS;
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let client = self.client().await?;
        // The identity JSON is matched the way SQLite's json_extract does:
        // a row whose identity is not valid JSON never matches, rather than
        // failing the query, and a missing issuer reads as the empty string.
        let rows = client
            .query(
                &format!(
                    "SELECT {SIGNAL_COLUMNS}
                     FROM greengateway.discovery_signals
                     WHERE signal_type = $1
                       AND target_kind = $2
                       AND CASE
                             WHEN pg_input_is_valid(target_identity_json, 'json') THEN
                                 (target_identity_json::json ->> 'principal') = $3
                                 AND COALESCE(target_identity_json::json ->> 'issuer', '') = $4
                                 AND (target_identity_json::json ->> 'auth_method') = $5
                             ELSE false
                           END
                     ORDER BY created_at::timestamptz DESC, id COLLATE \"C\" ASC
                     LIMIT $6"
                ),
                &[
                    &signals::PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_TYPE,
                    &signals::PRINCIPAL_ENDPOINT_TARGET_KIND,
                    &principal,
                    &issuer,
                    &auth_method,
                    &limit,
                ],
            )
            .await
            .map_err(|error| classify_query(error, operation))?;
        rows.iter()
            .map(|row| raw_signal(row, operation)?.into_signal())
            .collect()
    }

    /// One conditional statement: the predicate is the id, the expected
    /// state, and (when given) the expected revision. Zero rows is a
    /// refusal carrying the row as it is now, or `NotFound`.
    async fn transition_signal(
        &self,
        signal_id: &str,
        state: SignalLifecycleState,
        transitioned_by: Option<&str>,
        expected: TransitionPrecondition<SignalLifecycleState>,
    ) -> Result<TransitionOutcome<Signal>, DiscoveryQueryError> {
        let operation = OPERATION_TRANSITION_SIGNAL;
        let transitioned_at = utc_timestamp_rfc3339();
        let client = self.client().await?;
        let row = client
            .query_opt(
                &format!(
                    "UPDATE greengateway.discovery_signals
                     SET state = $2,
                         updated_at = $3,
                         transitioned_at = $3,
                         transitioned_by = $4,
                         revision = revision + 1
                     WHERE id = $1
                       AND state = $5
                       AND ($6::bigint IS NULL OR revision = $6::bigint)
                     RETURNING {SIGNAL_COLUMNS}"
                ),
                &[
                    &signal_id,
                    &state.as_str(),
                    &transitioned_at,
                    &transitioned_by,
                    &expected.from_state.as_str(),
                    &expected.revision,
                ],
            )
            .await
            .map_err(|error| classify_query(error, operation))?;
        if let Some(row) = row {
            return Ok(TransitionOutcome::Applied(
                raw_signal(&row, operation)?.into_signal()?,
            ));
        }
        let current = client
            .query_opt(
                &format!(
                    "SELECT {SIGNAL_COLUMNS} FROM greengateway.discovery_signals WHERE id = $1"
                ),
                &[&signal_id],
            )
            .await
            .map_err(|error| classify_query(error, operation))?;
        Ok(match current {
            Some(row) => TransitionOutcome::Refused(TransitionRefused {
                current: raw_signal(&row, operation)?.into_signal()?,
            }),
            None => TransitionOutcome::NotFound,
        })
    }

    async fn list_principals(
        &self,
        method: &str,
        endpoint_template: &str,
        filters: &PrincipalPageFilters,
    ) -> Result<PrincipalPage, DiscoveryQueryError> {
        let operation = OPERATION_LIST_PRINCIPALS;
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<PrincipalCursor>("principal_cursor", value))
            .transpose()?;
        let (sql, params) =
            build_principal_query(method, endpoint_template, filters.limit, cursor.as_ref());
        let client = self.client().await?;
        let mut principals = client
            .query(sql.as_str(), &params.refs())
            .await
            .map_err(|error| classify_query(error, operation))?
            .iter()
            .map(|row| {
                let issuer: String = column(row, 1, operation)?;
                Ok(EndpointPrincipal {
                    user_id: column(row, 0, operation)?,
                    issuer: (!issuer.is_empty()).then_some(issuer),
                    auth_method: column(row, 2, operation)?,
                    first_seen: column(row, 3, operation)?,
                    last_seen: column(row, 4, operation)?,
                })
            })
            .collect::<Result<Vec<_>, DiscoveryQueryError>>()?;

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
}

/// The aggregate columns every endpoint query selects, in the order
/// `raw_endpoint_aggregate` reads them (the SQLite store's order).
const AGGREGATE_COLUMNS: &str = "a.method, a.endpoint_template, a.first_seen, a.last_seen, \
     a.call_count, a.schema_mismatch_count, a.latency_count, a.latency_p50_ms, \
     a.latency_p95_ms, a.latency_p99_ms, a.latency_samples_json, a.distinct_principal_count, \
     a.updated_at, r.reviewed_at, r.reviewed_by, r.revision";

/// The statements between BEGIN and COMMIT of one review change: the
/// SQLite store's conditional write, statement for statement. A mark is an
/// upsert whose predicate is the expected revision (`None` replaces at
/// revision + 1, `UNREVIEWED_REVISION` inserts only when no row exists, any
/// other value updates only the row at that revision); a clear deletes only
/// the row at the expected revision. Zero rows is a refusal carrying the
/// review as stored now.
async fn set_endpoint_review_transaction(
    client: &deadpool_postgres::Object,
    method: &str,
    endpoint_template: &str,
    reviewed: bool,
    reviewed_by: Option<&str>,
    expected_revision: Option<i64>,
) -> Result<TransitionOutcome<EndpointReviewState>, DiscoveryQueryError> {
    let operation = OPERATION_SET_REVIEW;
    let exists = client
        .query_opt(
            "SELECT 1 FROM greengateway.discovery_endpoint_aggregates
             WHERE method = $1 AND endpoint_template = $2",
            &[&method, &endpoint_template],
        )
        .await
        .map_err(|error| classify_query(error, operation))?
        .is_some();
    if !exists {
        return Ok(TransitionOutcome::NotFound);
    }

    if reviewed {
        let reviewed_at = utc_timestamp_rfc3339();
        let written = match expected_revision {
            None => client
                .query_opt(
                    "INSERT INTO greengateway.discovery_endpoint_reviews AS r
                         (method, endpoint_template, reviewed_at, reviewed_by, revision)
                     VALUES ($1, $2, $3, $4, 1)
                     ON CONFLICT (method, endpoint_template) DO UPDATE SET
                         reviewed_at = EXCLUDED.reviewed_at,
                         reviewed_by = EXCLUDED.reviewed_by,
                         revision = r.revision + 1
                     RETURNING revision",
                    &[&method, &endpoint_template, &reviewed_at, &reviewed_by],
                )
                .await
                .map_err(|error| classify_query(error, operation))?,
            Some(UNREVIEWED_REVISION) => client
                .query_opt(
                    "INSERT INTO greengateway.discovery_endpoint_reviews
                         (method, endpoint_template, reviewed_at, reviewed_by, revision)
                     VALUES ($1, $2, $3, $4, 1)
                     ON CONFLICT (method, endpoint_template) DO NOTHING
                     RETURNING revision",
                    &[&method, &endpoint_template, &reviewed_at, &reviewed_by],
                )
                .await
                .map_err(|error| classify_query(error, operation))?,
            Some(expected) => client
                .query_opt(
                    "UPDATE greengateway.discovery_endpoint_reviews
                     SET reviewed_at = $3,
                         reviewed_by = $4,
                         revision = revision + 1
                     WHERE method = $1 AND endpoint_template = $2 AND revision = $5
                     RETURNING revision",
                    &[
                        &method,
                        &endpoint_template,
                        &reviewed_at,
                        &reviewed_by,
                        &expected,
                    ],
                )
                .await
                .map_err(|error| classify_query(error, operation))?,
        };
        match written {
            Some(row) => Ok(TransitionOutcome::Applied(EndpointReviewState {
                reviewed: true,
                reviewed_at: Some(reviewed_at),
                reviewed_by: reviewed_by.map(str::to_owned),
                revision: column(&row, 0, operation)?,
            })),
            None => Ok(TransitionOutcome::Refused(TransitionRefused {
                current: load_review(client, method, endpoint_template, operation).await?,
            })),
        }
    } else {
        let deleted = match expected_revision {
            None => client
                .execute(
                    "DELETE FROM greengateway.discovery_endpoint_reviews
                     WHERE method = $1 AND endpoint_template = $2",
                    &[&method, &endpoint_template],
                )
                .await
                .map_err(|error| classify_query(error, operation))?,
            Some(expected) => client
                .execute(
                    "DELETE FROM greengateway.discovery_endpoint_reviews
                     WHERE method = $1 AND endpoint_template = $2 AND revision = $3",
                    &[&method, &endpoint_template, &expected],
                )
                .await
                .map_err(|error| classify_query(error, operation))?,
        };
        if deleted > 0 {
            return Ok(TransitionOutcome::Applied(EndpointReviewState::unreviewed()));
        }
        let current = load_review(client, method, endpoint_template, operation).await?;
        if !current.reviewed && matches!(expected_revision, None | Some(UNREVIEWED_REVISION)) {
            return Ok(TransitionOutcome::Applied(current));
        }
        Ok(TransitionOutcome::Refused(TransitionRefused { current }))
    }
}

/// The review row as stored (not the effective, reclassification-aware
/// state): what a refused conditional write hands back.
async fn load_review(
    client: &deadpool_postgres::Object,
    method: &str,
    endpoint_template: &str,
    operation: &'static str,
) -> Result<EndpointReviewState, DiscoveryQueryError> {
    let row = client
        .query_opt(
            "SELECT reviewed_at, reviewed_by, revision
             FROM greengateway.discovery_endpoint_reviews
             WHERE method = $1 AND endpoint_template = $2",
            &[&method, &endpoint_template],
        )
        .await
        .map_err(|error| classify_query(error, operation))?;
    match row {
        Some(row) => Ok(EndpointReviewState {
            reviewed: true,
            reviewed_at: Some(column(&row, 0, operation)?),
            reviewed_by: column(&row, 1, operation)?,
            revision: column(&row, 2, operation)?,
        }),
        None => Ok(EndpointReviewState::unreviewed()),
    }
}

/// Positional parameters for a dynamically assembled statement; shared
/// with the lifecycle store's suggestion list.
#[derive(Default)]
pub(crate) struct SqlParams {
    values: Vec<Box<dyn ToSql + Sync + Send>>,
}

impl SqlParams {
    /// Bind `value` and return its `$n` placeholder.
    pub(crate) fn bind<T: ToSql + Sync + Send + 'static>(&mut self, value: T) -> String {
        self.values.push(Box::new(value));
        format!("${}", self.values.len())
    }

    pub(crate) fn refs(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.values
            .iter()
            .map(|value| value.as_ref() as &(dyn ToSql + Sync))
            .collect()
    }
}

/// A caller-supplied timestamp as an instant, or NULL when it does not
/// parse: the `julianday` behaviour, so a bad filter or a tampered cursor
/// excludes rows instead of failing the query. `placeholder` is text-typed
/// by the caller (`$n`), and is referenced twice on purpose.
pub(crate) fn caller_timestamp(placeholder: &str) -> String {
    format!(
        "(CASE WHEN pg_input_is_valid({placeholder}::text, 'timestamptz') \
         THEN {placeholder}::text::timestamptz END)"
    )
}

/// The sort expression of an endpoint list, the SQLite `order_expression`
/// with `julianday` replaced by the `timestamptz` cast.
fn endpoint_order_expression(sort: EndpointSort) -> &'static str {
    match sort {
        EndpointSort::LastSeen => "a.last_seen::timestamptz",
        EndpointSort::CallCount => "a.call_count",
        EndpointSort::FirstSeen => "a.first_seen::timestamptz",
    }
}

fn build_endpoint_list_query(
    filters: &EndpointListFilters,
    cursor: Option<&EndpointCursor>,
    new_since_cutoff: &str,
) -> (String, SqlParams) {
    let mut sql = format!(
        "SELECT {AGGREGATE_COLUMNS}
         FROM greengateway.discovery_endpoint_aggregates a
         LEFT JOIN greengateway.discovery_endpoint_reviews r
             USING (method, endpoint_template)"
    );
    let mut clauses = Vec::new();
    let mut params = SqlParams::default();

    if let Some(method) = &filters.method {
        let placeholder = params.bind(method.clone());
        clauses.push(format!("a.method = {placeholder}"));
    }
    if let Some(endpoint_template_contains) = &filters.endpoint_template_contains {
        let placeholder = params.bind(format!("%{}%", like_escape(endpoint_template_contains)));
        clauses.push(format!(
            "a.endpoint_template COLLATE \"C\" ILIKE {placeholder} ESCAPE '\\'"
        ));
    }
    if let Some(endpoint_template_prefix) = &filters.endpoint_template_prefix {
        let placeholder = params.bind(format!("{}%", like_escape(endpoint_template_prefix)));
        clauses.push(format!(
            "a.endpoint_template COLLATE \"C\" ILIKE {placeholder} ESCAPE '\\'"
        ));
    }
    if let Some(first_seen_after) = &filters.first_seen_after {
        let placeholder = params.bind(first_seen_after.clone());
        clauses.push(format!(
            "a.first_seen::timestamptz >= {}",
            caller_timestamp(&placeholder)
        ));
    }
    if let Some(first_seen_before) = &filters.first_seen_before {
        let placeholder = params.bind(first_seen_before.clone());
        clauses.push(format!(
            "a.first_seen::timestamptz <= {}",
            caller_timestamp(&placeholder)
        ));
    }
    if let Some(last_seen_after) = &filters.last_seen_after {
        let placeholder = params.bind(last_seen_after.clone());
        clauses.push(format!(
            "a.last_seen::timestamptz >= {}",
            caller_timestamp(&placeholder)
        ));
    }
    if let Some(last_seen_before) = &filters.last_seen_before {
        let placeholder = params.bind(last_seen_before.clone());
        clauses.push(format!(
            "a.last_seen::timestamptz <= {}",
            caller_timestamp(&placeholder)
        ));
    }
    if let Some(min_call_count) = filters.min_call_count {
        let placeholder = params.bind(min_call_count);
        clauses.push(format!("a.call_count >= {placeholder}::bigint"));
    }
    if let Some(is_new) = filters.is_new {
        let placeholder = params.bind(new_since_cutoff.to_owned());
        let cutoff = caller_timestamp(&placeholder);
        if is_new {
            clauses.push(format!("a.first_seen::timestamptz >= {cutoff}"));
        } else {
            clauses.push(format!("a.first_seen::timestamptz < {cutoff}"));
        }
    }
    if let Some(reviewed) = filters.reviewed {
        const RECLASSIFIED_SINCE_REVIEW: &str = "EXISTS (
                    SELECT 1
                    FROM greengateway.discovery_endpoint_routing_contexts c
                    WHERE c.method = a.method
                      AND c.endpoint_template = a.endpoint_template
                      AND c.first_seen::timestamptz > r.reviewed_at::timestamptz
                )";
        if reviewed {
            clauses.push(format!(
                "r.reviewed_at IS NOT NULL AND NOT {RECLASSIFIED_SINCE_REVIEW}"
            ));
        } else {
            clauses.push(format!(
                "(r.reviewed_at IS NULL OR {RECLASSIFIED_SINCE_REVIEW})"
            ));
        }
    }
    if let Some(cursor) = cursor {
        let method = params.bind(cursor.method.clone());
        let endpoint_template = params.bind(cursor.endpoint_template.clone());
        let tiebreak = format!(
            "(a.method COLLATE \"C\" > {method} OR (a.method = {method} \
             AND a.endpoint_template COLLATE \"C\" > {endpoint_template}))"
        );
        let expression = endpoint_order_expression(filters.sort);
        let sort_value = match filters.sort {
            EndpointSort::CallCount => {
                let value = cursor.sort_value.parse::<i64>().unwrap_or(i64::MAX);
                let placeholder = params.bind(value);
                format!("{placeholder}::bigint")
            }
            EndpointSort::LastSeen | EndpointSort::FirstSeen => {
                let placeholder = params.bind(cursor.sort_value.clone());
                caller_timestamp(&placeholder)
            }
        };
        clauses.push(format!(
            "({expression} < {sort_value} OR ({expression} = {sort_value} AND {tiebreak}))"
        ));
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }

    sql.push_str(" ORDER BY ");
    sql.push_str(endpoint_order_expression(filters.sort));
    sql.push_str(" DESC, a.method COLLATE \"C\" ASC, a.endpoint_template COLLATE \"C\" ASC LIMIT ");
    let limit = params.bind(query_limit(filters.limit));
    sql.push_str(&limit);
    sql.push_str("::bigint");

    (sql, params)
}

fn build_principal_query(
    method: &str,
    endpoint_template: &str,
    limit: usize,
    cursor: Option<&PrincipalCursor>,
) -> (String, SqlParams) {
    let mut params = SqlParams::default();
    let method = params.bind(method.to_owned());
    let endpoint_template = params.bind(endpoint_template.to_owned());
    let mut sql = format!(
        "SELECT user_id, issuer, auth_method, first_seen, last_seen
         FROM greengateway.discovery_endpoint_principals
         WHERE method = {method} AND endpoint_template = {endpoint_template}"
    );

    if let Some(cursor) = cursor {
        let last_seen = caller_timestamp(&params.bind(cursor.last_seen.clone()));
        let user_id = params.bind(cursor.user_id.clone());
        let issuer = params.bind(cursor.issuer.clone());
        let auth_method = params.bind(cursor.auth_method.clone());
        sql.push_str(&format!(
            " AND (last_seen::timestamptz < {last_seen} OR (last_seen::timestamptz = {last_seen} \
             AND (user_id COLLATE \"C\" > {user_id} OR (user_id = {user_id} \
             AND (issuer COLLATE \"C\" > {issuer} OR (issuer = {issuer} \
             AND auth_method COLLATE \"C\" > {auth_method}))))))"
        ));
    }

    let limit = params.bind(query_limit(limit));
    sql.push_str(&format!(
        " ORDER BY last_seen::timestamptz DESC, user_id COLLATE \"C\" ASC, \
         issuer COLLATE \"C\" ASC, auth_method COLLATE \"C\" ASC LIMIT {limit}::bigint"
    ));

    (sql, params)
}

fn build_signal_list_query(
    filters: &SignalListFilters,
    cursor: Option<&SignalCursor>,
) -> (String, SqlParams) {
    let mut sql = format!("SELECT {SIGNAL_COLUMNS} FROM greengateway.discovery_signals");
    let mut clauses = Vec::new();
    let mut params = SqlParams::default();

    if let Some(state) = filters.state {
        let placeholder = params.bind(state.as_str().to_owned());
        clauses.push(format!("state = {placeholder}"));
    }
    if let Some(signal_type) = &filters.signal_type {
        let placeholder = params.bind(signal_type.clone());
        clauses.push(format!("signal_type = {placeholder}"));
    }
    if let Some(target_kind) = &filters.target_kind {
        let placeholder = params.bind(target_kind.clone());
        clauses.push(format!("target_kind = {placeholder}"));
    }
    if let Some(target_key) = &filters.target_key {
        let placeholder = params.bind(target_key.clone());
        clauses.push(format!("target_key = {placeholder}"));
    }
    if let Some(cursor) = cursor {
        let created_at = caller_timestamp(&params.bind(cursor.created_at.clone()));
        let id = params.bind(cursor.id.clone());
        clauses.push(format!(
            "(created_at::timestamptz < {created_at} OR (created_at::timestamptz = {created_at} \
             AND id COLLATE \"C\" > {id}))"
        ));
    }

    if !clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&clauses.join(" AND "));
    }

    let limit = params.bind(query_limit(filters.limit));
    sql.push_str(&format!(
        " ORDER BY created_at::timestamptz DESC, id COLLATE \"C\" ASC LIMIT {limit}::bigint"
    ));

    (sql, params)
}

/// Endpoint keys as two parallel arrays, the shape `UNNEST` binds.
fn key_columns(keys: &[(String, String)]) -> (Vec<String>, Vec<String>) {
    keys.iter().cloned().unzip()
}

async fn load_status_counts(
    client: &deadpool_postgres::Object,
    keys: &[(String, String)],
    operation: &'static str,
) -> Result<HashMap<(String, String), Vec<StatusCount>>, DiscoveryQueryError> {
    let mut grouped = HashMap::<(String, String), Vec<StatusCount>>::new();
    if keys.is_empty() {
        return Ok(grouped);
    }
    let (methods, templates) = key_columns(keys);
    let rows = client
        .query(
            "SELECT s.method, s.endpoint_template, s.status, s.count
             FROM UNNEST($1::text[], $2::text[]) AS k(method, endpoint_template)
             JOIN greengateway.discovery_endpoint_status_counts s
                 ON s.method = k.method AND s.endpoint_template = k.endpoint_template
             ORDER BY s.method COLLATE \"C\", s.endpoint_template COLLATE \"C\",
                      s.count DESC, s.status ASC",
            &[&methods, &templates],
        )
        .await
        .map_err(|error| classify_query(error, operation))?;
    for row in &rows {
        let key = (column(row, 0, operation)?, column(row, 1, operation)?);
        let status: i32 = column(row, 2, operation)?;
        let count: i64 = column(row, 3, operation)?;
        grouped.entry(key).or_default().push(StatusCount {
            status: u16::try_from(status).unwrap_or(0),
            count: non_negative_i64_to_u64(count),
        });
    }
    Ok(grouped)
}

async fn load_routing_contexts(
    client: &deadpool_postgres::Object,
    keys: &[(String, String)],
    operation: &'static str,
) -> Result<HashMap<(String, String), Vec<EndpointRoutingContext>>, DiscoveryQueryError> {
    let mut grouped = HashMap::<(String, String), Vec<EndpointRoutingContext>>::new();
    if keys.is_empty() {
        return Ok(grouped);
    }
    let (methods, templates) = key_columns(keys);
    let rows = client
        .query(
            "SELECT
                 c.method,
                 c.endpoint_template,
                 NULLIF(c.route_host, ''),
                 NULLIF(c.route_path_prefix, ''),
                 NULLIF(c.upstream_origin, ''),
                 c.first_seen,
                 c.last_seen,
                 c.call_count,
                 c.distinct_principal_count
             FROM UNNEST($1::text[], $2::text[]) AS k(method, endpoint_template)
             JOIN greengateway.discovery_endpoint_routing_contexts c
                 ON c.method = k.method AND c.endpoint_template = k.endpoint_template
             ORDER BY c.method COLLATE \"C\", c.endpoint_template COLLATE \"C\",
                      c.route_host COLLATE \"C\", c.route_path_prefix COLLATE \"C\",
                      c.upstream_origin COLLATE \"C\"",
            &[&methods, &templates],
        )
        .await
        .map_err(|error| classify_query(error, operation))?;
    for row in &rows {
        let key = (column(row, 0, operation)?, column(row, 1, operation)?);
        let call_count: i64 = column(row, 7, operation)?;
        let distinct_principal_count: i64 = column(row, 8, operation)?;
        grouped
            .entry(key)
            .or_default()
            .push(EndpointRoutingContext {
                route_host: column(row, 2, operation)?,
                route_path_prefix: column(row, 3, operation)?,
                upstream_origin: column(row, 4, operation)?,
                first_seen: column(row, 5, operation)?,
                last_seen: column(row, 6, operation)?,
                call_count: non_negative_i64_to_u64(call_count),
                distinct_principal_count: non_negative_i64_to_u64(distinct_principal_count),
                covered_by_rule: false,
                coverage_scope: EndpointCoverageScope::None,
            });
    }
    Ok(grouped)
}

async fn load_routing_context_known_since(
    client: &deadpool_postgres::Object,
    keys: &[(String, String)],
    operation: &'static str,
) -> Result<HashMap<(String, String), String>, DiscoveryQueryError> {
    let mut known_since = HashMap::new();
    if keys.is_empty() {
        return Ok(known_since);
    }
    let (methods, templates) = key_columns(keys);
    let rows = client
        .query(
            "SELECT c.method, c.endpoint_template, c.first_classified_at
             FROM UNNEST($1::text[], $2::text[]) AS k(method, endpoint_template)
             JOIN greengateway.discovery_endpoint_routing_classifications c
                 ON c.method = k.method AND c.endpoint_template = k.endpoint_template",
            &[&methods, &templates],
        )
        .await
        .map_err(|error| classify_query(error, operation))?;
    for row in &rows {
        known_since.insert(
            (column(row, 0, operation)?, column(row, 1, operation)?),
            column::<String>(row, 2, operation)?,
        );
    }
    Ok(known_since)
}

async fn load_open_signal_summaries(
    client: &deadpool_postgres::Object,
    keys: &[(String, String)],
    operation: &'static str,
) -> Result<HashMap<(String, String), OpenSignalSummary>, DiscoveryQueryError> {
    let mut summaries = HashMap::<(String, String), OpenSignalSummary>::new();
    if keys.is_empty() {
        return Ok(summaries);
    }
    let (methods, templates) = key_columns(keys);
    let target_keys = keys
        .iter()
        .map(|(method, endpoint_template)| signals::endpoint_target_key(method, endpoint_template))
        .collect::<Vec<_>>();
    let rows = client
        .query(
            "SELECT r.method, r.endpoint_template, s.signal_type, count(s.id)
             FROM UNNEST($1::text[], $2::text[], $3::text[])
                 AS r(method, endpoint_template, target_key)
             JOIN greengateway.discovery_signals s
                 ON s.target_kind = $4
                 AND s.target_key = r.target_key
                 AND s.state = $5
             GROUP BY r.method, r.endpoint_template, s.signal_type
             ORDER BY r.method COLLATE \"C\" ASC, r.endpoint_template COLLATE \"C\" ASC,
                      s.signal_type COLLATE \"C\" ASC",
            &[
                &methods,
                &templates,
                &target_keys,
                &signals::ENDPOINT_TARGET_KIND,
                &SignalLifecycleState::Open.as_str(),
            ],
        )
        .await
        .map_err(|error| classify_query(error, operation))?;
    for row in &rows {
        let key = (column(row, 0, operation)?, column(row, 1, operation)?);
        let signal_type: String = column(row, 2, operation)?;
        let count: i64 = column(row, 3, operation)?;
        let summary = summaries.entry(key).or_default();
        summary.count += non_negative_i64_to_u64(count);
        summary.signal_types.push(signal_type);
    }
    Ok(summaries)
}

fn raw_endpoint_aggregate(
    row: &Row,
    operation: &'static str,
) -> Result<RawEndpointAggregate, DiscoveryQueryError> {
    Ok(RawEndpointAggregate {
        method: column(row, 0, operation)?,
        endpoint_template: column(row, 1, operation)?,
        first_seen: column(row, 2, operation)?,
        last_seen: column(row, 3, operation)?,
        call_count: column(row, 4, operation)?,
        schema_mismatch_count: column(row, 5, operation)?,
        latency_count: column(row, 6, operation)?,
        latency_p50_ms: column(row, 7, operation)?,
        latency_p95_ms: column(row, 8, operation)?,
        latency_p99_ms: column(row, 9, operation)?,
        latency_samples_json: column(row, 10, operation)?,
        distinct_principal_count: column(row, 11, operation)?,
        updated_at: column(row, 12, operation)?,
        reviewed_at: column(row, 13, operation)?,
        reviewed_by: column(row, 14, operation)?,
        review_revision: column(row, 15, operation)?,
    })
}

fn raw_signal(row: &Row, operation: &'static str) -> Result<RawSignal, DiscoveryQueryError> {
    Ok(RawSignal {
        id: column(row, 0, operation)?,
        signal_type: column(row, 1, operation)?,
        target_kind: column(row, 2, operation)?,
        target_key: column(row, 3, operation)?,
        target_identity_json: column(row, 4, operation)?,
        explanation: column(row, 5, operation)?,
        evidence_json: column(row, 6, operation)?,
        state: column(row, 7, operation)?,
        created_at: column(row, 8, operation)?,
        updated_at: column(row, 9, operation)?,
        transitioned_at: column(row, 10, operation)?,
        transitioned_by: column(row, 11, operation)?,
        revision: column(row, 12, operation)?,
    })
}

/// Read one column; a row that does not decode is data this binary cannot
/// use (`InvalidData`), never a panic on the request path.
fn column<'a, T: FromSql<'a>>(
    row: &'a Row,
    index: usize,
    operation: &'static str,
) -> Result<T, DiscoveryQueryError> {
    row.try_get(index).map_err(|error| {
        tracing::error!(operation, column = index, error = %error, "discovery row failed to decode");
        DiscoveryQueryError::Repository(RepositoryError::new(
            RepositoryErrorKind::InvalidData,
            operation,
        ))
    })
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> DiscoveryQueryError {
    let kind = super::postgres::classify_postgres_error(&error);
    DiscoveryQueryError::Repository(log_classified(
        operation,
        &error,
        RepositoryError::new(kind, operation),
    ))
}
