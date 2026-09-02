//! PostgreSQL discovery write store (issue #241, PR 11): where the cluster
//! discovery projector persists the endpoint inventory it aggregates from
//! the durable audit stream, and the checkpoint that makes that
//! aggregation exactly-once.
//!
//! The tables of migration 9 mirror the SQLite sink's tables column for
//! column, so the in-memory model (`AggregatorState`) is rebuilt from them
//! with the same `LoadedRows` the SQLite sink uses, plus two things SQLite
//! does not keep: each endpoint's serialized detector windows and the
//! path-template learner's groups, so a successor leader continues the
//! same history instead of starting the rolling detectors over.
//!
//! What is written and why it is safe:
//!
//! - **One leader, fenced.** `discovery_projector_state` is a singleton
//!   carrying the current leader's execution-lease fence. `claim_leadership`
//!   moves the fence only forward; every `flush` is one transaction that
//!   locks the row (`SELECT ... FOR UPDATE`), verifies the fence it was
//!   asked to write under is still the one on the row, applies the batch,
//!   and advances the checkpoint. A stale leader -- one whose lease lapsed
//!   and was reclaimed at a higher fence -- fails the comparison and
//!   commits nothing, however late its flush arrives.
//! - **Absolute values are fine under the fence.** The SQLite sink writes
//!   each dirty aggregate's absolute counters and rewrites its child rows
//!   (delete, then insert). That is only correct when one process owns the
//!   memory; here the fence guarantees exactly one writer whose memory was
//!   loaded from these very rows after the previous writer was fenced out,
//!   so the same absolute writes are used, unchanged.
//! - **The checkpoint moves with the data.** `checkpoint_position` is the
//!   last stream position the batch consumed and it is updated in the same
//!   transaction as the aggregates, so a crash anywhere before COMMIT
//!   leaves both untouched and the successor resumes from the committed
//!   checkpoint; positions are never applied twice or skipped.
//! - **A retry of an ambiguously committed flush changes nothing.** The
//!   client cannot tell a COMMIT the server applied but never acknowledged
//!   (the connection dropped) from one that rolled back, so the projector
//!   retries the identical batch at the identical checkpoint. Every write
//!   is absolute or conflict-suppressed, and the one additive write --
//!   `projected_events` -- is guarded by the checkpoint the row already
//!   carries, so the retry re-applies the same values and counts nothing
//!   twice; the signals that batch opened are found by their ids and
//!   announced by the retry, since the lost acknowledgement meant the
//!   first attempt never announced them.
//! - **Signals insert once cluster-wide.** `discovery_signals` keeps the
//!   SQLite UNIQUE identity and inserts `ON CONFLICT DO NOTHING`; a
//!   crossing already recorded (by this leader, a predecessor, or a
//!   replayed batch) inserts nothing and is not announced again.
//! - **Every deletion is the leader's.** Evicted endpoints (the global
//!   cardinality bound, or templates merged by the learner) delete their
//!   rows and their signals here, under the fence, exactly as the SQLite
//!   sink's `delete_key` does; no replica evicts on its own.
//!
//! Audit retention (PR 13) must not pass the checkpoint:
//! [`PostgresDiscoveryStore::minimum_retained_position`] is the boundary
//! that job has to respect. Errors classify into the repository vocabulary
//! and carry an operation label only: no SQL text, no values.

use std::collections::HashSet;

use crate::discovery::{
    aggregator::{
        AggregateRow, ClassifiedSignalPrincipalRow, ClassifiedSignalStatRow, DetectorStateRow,
        EndpointAggregate, EndpointKey, LoadedRows, PayloadShapeSampleRow, PayloadShapeStatRow,
        PendingFlush, PrincipalRow, RoutingClassificationRow, RoutingContextRow,
        RoutingPrincipalRow, StatusRow,
    },
    signals::{self, NewSignal, Signal, ENDPOINT_TARGET_KIND, PRINCIPAL_ENDPOINT_TARGET_KIND},
};

use super::{log_classified, postgres::classify_pool_error, RepositoryError, RepositoryErrorKind};

const OPERATION_LOAD: &str = "discovery_load";
const OPERATION_CLAIM: &str = "discovery_claim_leadership";
const OPERATION_FLUSH: &str = "discovery_flush";
const OPERATION_CHECKPOINT: &str = "discovery_checkpoint";

/// The schema's bound on a serialized detector state. The serialized form
/// is the counters and the two rolling windows -- a few hundred bytes for
/// any endpoint, since the unbounded principal set is deliberately not
/// part of it (see `ClassifiedSignalState`) -- so the bound is not reached
/// in practice. Should it ever be, the state is not written (and any stale
/// row is removed) so the flush never fails on the CHECK; the successor
/// then rebuilds that endpoint's windows from the counters, which is the
/// SQLite restart behaviour.
pub(crate) const DETECTOR_STATE_MAX_BYTES: usize = 65_536;

/// The schema's bound on the learner's serialized groups. The projector
/// exports the groups within this bound (dropping the least recently used
/// from the working set when they do not fit), so a write here is always
/// within it; an export past it is a bug and fails the flush rather than
/// leaving a stale snapshot a successor would template differently from.
pub(crate) const TEMPLATE_GROUPS_MAX_BYTES: usize = 4_194_304;

/// Where a flush's checkpoint lands and under which fence it is written.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlushCheckpoint {
    /// The last stream position the batch consumed (projectable or not).
    pub(crate) position: i64,
    /// The leader fence the caller believes it holds.
    pub(crate) fence: i64,
    /// Observations applied in this batch, added to `projected_events`.
    pub(crate) projected_events: i64,
}

/// The projector's committed position and the fence it was committed under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectorCheckpoint {
    pub checkpoint_position: i64,
    pub fence: i64,
    pub projected_events: i64,
}

/// The discovery write store over one PostgreSQL pool. Cheap to construct;
/// holds no per-instance state.
#[derive(Clone)]
pub struct PostgresDiscoveryStore {
    pool: deadpool_postgres::Pool,
}

impl PostgresDiscoveryStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }

    /// Every persisted row the aggregator rebuilds from, including the
    /// detector states and learner groups the SQLite sink does not keep.
    pub(crate) async fn load_rows(&self) -> Result<LoadedRows, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let query = |sql: &'static str| {
            let client = &client;
            async move {
                client
                    .query(sql, &[])
                    .await
                    .map_err(|error| classify_query(error, OPERATION_LOAD))
            }
        };

        let aggregates = query(
            "SELECT method, endpoint_template, first_seen, last_seen, call_count,
                    schema_mismatch_count, latency_count, latency_samples_json
             FROM greengateway.discovery_endpoint_aggregates",
        )
        .await?
        .iter()
        .map(|row| AggregateRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            first_seen: row.get(2),
            last_seen: row.get(3),
            call_count: row.get(4),
            schema_mismatch_count: row.get(5),
            latency_count: row.get(6),
            latency_samples_json: row.get(7),
        })
        .collect();

        let statuses = query(
            "SELECT method, endpoint_template, status, count
             FROM greengateway.discovery_endpoint_status_counts",
        )
        .await?
        .iter()
        .map(|row| StatusRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            status: i64::from(row.get::<_, i32>(2)),
            count: row.get(3),
        })
        .collect();

        let principals = query(
            "SELECT method, endpoint_template, user_id, issuer, auth_method, first_seen, last_seen
             FROM greengateway.discovery_endpoint_principals",
        )
        .await?
        .iter()
        .map(|row| PrincipalRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            user_id: row.get(2),
            issuer: row.get(3),
            auth_method: row.get(4),
            first_seen: row.get(5),
            last_seen: row.get(6),
        })
        .collect();

        let routing_contexts = query(
            "SELECT method, endpoint_template, route_host, route_path_prefix, upstream_origin,
                    first_seen, last_seen, call_count
             FROM greengateway.discovery_endpoint_routing_contexts",
        )
        .await?
        .iter()
        .map(|row| RoutingContextRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            route_host: row.get(2),
            route_path_prefix: row.get(3),
            upstream_origin: row.get(4),
            first_seen: row.get(5),
            last_seen: row.get(6),
            call_count: row.get(7),
        })
        .collect();

        let routing_principals = query(
            "SELECT method, endpoint_template, route_host, route_path_prefix, upstream_origin,
                    user_id, issuer, auth_method
             FROM greengateway.discovery_endpoint_routing_principals",
        )
        .await?
        .iter()
        .map(|row| RoutingPrincipalRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            route_host: row.get(2),
            route_path_prefix: row.get(3),
            upstream_origin: row.get(4),
            user_id: row.get(5),
            issuer: row.get(6),
            auth_method: row.get(7),
        })
        .collect();

        let classifications = query(
            "SELECT method, endpoint_template, first_classified_at
             FROM greengateway.discovery_endpoint_routing_classifications",
        )
        .await?
        .iter()
        .map(|row| RoutingClassificationRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            first_classified_at: row.get(2),
        })
        .collect();

        let classified_stats = query(
            "SELECT method, endpoint_template, call_count, schema_mismatch_count, error_count
             FROM greengateway.discovery_endpoint_classified_signal_stats",
        )
        .await?
        .iter()
        .map(|row| ClassifiedSignalStatRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            call_count: row.get(2),
            schema_mismatch_count: row.get(3),
            error_count: row.get(4),
        })
        .collect();

        let classified_principals = query(
            "SELECT method, endpoint_template, user_id, issuer, auth_method
             FROM greengateway.discovery_endpoint_classified_signal_principals",
        )
        .await?
        .iter()
        .map(|row| ClassifiedSignalPrincipalRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            user_id: row.get(2),
            issuer: row.get(3),
            auth_method: row.get(4),
        })
        .collect();

        let payload_stats = query(
            "SELECT method, endpoint_template, shape_observation_count
             FROM greengateway.discovery_payload_shape_stats",
        )
        .await?
        .iter()
        .map(|row| PayloadShapeStatRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            shape_observation_count: row.get(2),
        })
        .collect();

        let payload_samples = query(
            "SELECT method, endpoint_template, observed_at, shape_hash, shape_json
             FROM greengateway.discovery_payload_shape_samples
             ORDER BY method, endpoint_template, sample_slot",
        )
        .await?
        .iter()
        .map(|row| PayloadShapeSampleRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            observed_at: row.get(2),
            shape_hash: row.get(3),
            shape_json: row.get(4),
        })
        .collect();

        let detector_states = query(
            "SELECT method, endpoint_template, state_json
             FROM greengateway.discovery_detector_state",
        )
        .await?
        .iter()
        .map(|row| DetectorStateRow {
            method: row.get(0),
            endpoint_template: row.get(1),
            state_json: row.get(2),
        })
        .collect();

        let template_groups_json =
            query("SELECT groups_json FROM greengateway.discovery_template_groups WHERE singleton")
                .await?
                .first()
                .map(|row| row.get::<_, String>(0));

        Ok(LoadedRows {
            aggregates,
            statuses,
            principals,
            routing_contexts,
            routing_principals,
            classifications,
            classified_stats,
            classified_principals,
            payload_stats,
            payload_samples,
            detector_states,
            template_groups_json,
        })
    }

    /// Take leadership at `fence`, which must be newer than the fence on
    /// the row. Returns the committed checkpoint the new leader resumes
    /// from. `Conflict` means a newer fence already holds leadership: the
    /// caller's lease is stale and it must not project.
    pub async fn claim_leadership(
        &self,
        fence: i64,
        holder: uuid::Uuid,
    ) -> Result<i64, RepositoryError> {
        let holder = holder.to_string();
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_opt(
                "UPDATE greengateway.discovery_projector_state
                 SET fence = $1, leader_instance = $2::text::uuid, updated_at = now()
                 WHERE singleton AND fence < $1
                 RETURNING checkpoint_position",
                &[&fence, &holder],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_CLAIM))?;
        match row {
            Some(row) => row
                .try_get("checkpoint_position")
                .map_err(|_| invalid_data(OPERATION_CLAIM)),
            None => Err(RepositoryError::new(
                RepositoryErrorKind::Conflict,
                OPERATION_CLAIM,
            )),
        }
    }

    /// The committed checkpoint, the fence it was committed under, and the
    /// running count of applied observations.
    #[allow(dead_code)] // Read by the admin/health surfaces of the later PR 11 stages.
    pub async fn checkpoint(&self) -> Result<ProjectorCheckpoint, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_one(
                "SELECT checkpoint_position, fence, projected_events
                 FROM greengateway.discovery_projector_state WHERE singleton",
                &[],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_CHECKPOINT))?;
        Ok(ProjectorCheckpoint {
            checkpoint_position: row
                .try_get(0)
                .map_err(|_| invalid_data(OPERATION_CHECKPOINT))?,
            fence: row
                .try_get(1)
                .map_err(|_| invalid_data(OPERATION_CHECKPOINT))?,
            projected_events: row
                .try_get(2)
                .map_err(|_| invalid_data(OPERATION_CHECKPOINT))?,
        })
    }

    /// The lowest audit stream position retention must keep: one past the
    /// committed checkpoint. The maintenance singleton's audit retention
    /// job (PR 13) deletes stream rows only below the checkpoint it reads
    /// through `AuditRetentionFloor`, which is inside this bound, so the
    /// projector can never find its next batch already trimmed.
    #[allow(dead_code)] // The contract the retention floor satisfies.
    pub async fn minimum_retained_position(&self) -> Result<i64, RepositoryError> {
        Ok(self
            .checkpoint()
            .await?
            .checkpoint_position
            .saturating_add(1))
    }

    /// Persist one batch under `checkpoint.fence` in one transaction and
    /// advance the checkpoint with it. Returns the signals this flush
    /// actually opened (a duplicate identity opens nothing). `Conflict`
    /// means the fence on the row is no longer the caller's: nothing was
    /// applied and the caller has been fenced out.
    pub(crate) async fn flush(
        &self,
        batch: &PendingFlush,
        detector_states: &[(EndpointKey, String)],
        template_groups_json: Option<&str>,
        checkpoint: FlushCheckpoint,
        payload_capture_enabled: bool,
    ) -> Result<Vec<Signal>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
        let result = flush_transaction(
            &client,
            batch,
            detector_states,
            template_groups_json,
            checkpoint,
            payload_capture_enabled,
        )
        .await;
        match result {
            Ok(opened) => {
                client
                    .batch_execute("COMMIT")
                    .await
                    .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
                Ok(opened)
            }
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }
}

/// The statements between BEGIN and COMMIT of one flush.
async fn flush_transaction(
    client: &deadpool_postgres::ClientWrapper,
    batch: &PendingFlush,
    detector_states: &[(EndpointKey, String)],
    template_groups_json: Option<&str>,
    checkpoint: FlushCheckpoint,
    payload_capture_enabled: bool,
) -> Result<Vec<Signal>, RepositoryError> {
    // The fence check, under the row lock every flush takes: concurrent
    // flushes serialize here, and the one holding a fence the row no longer
    // carries writes nothing.
    let row = client
        .query_one(
            "SELECT fence FROM greengateway.discovery_projector_state WHERE singleton FOR UPDATE",
            &[],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    let current_fence: i64 = row.try_get(0).map_err(|_| invalid_data(OPERATION_FLUSH))?;
    if current_fence != checkpoint.fence {
        return Err(RepositoryError::new(
            RepositoryErrorKind::Conflict,
            OPERATION_FLUSH,
        ));
    }

    // Child rows are rewritten for every dirty aggregate and removed for
    // every deleted key, so one delete over the union serves both.
    let rewritten = KeyColumns::from_keys(
        batch.deleted_keys.iter().chain(
            batch
                .dirty_aggregates
                .iter()
                .map(|aggregate| &aggregate.key),
        ),
    );
    if !rewritten.is_empty() {
        for table in CHILD_TABLES {
            delete_by_keys(client, table, &rewritten).await?;
        }
        if payload_capture_enabled {
            delete_by_keys(client, "discovery_payload_shape_samples", &rewritten).await?;
            delete_by_keys(client, "discovery_payload_shape_stats", &rewritten).await?;
        }
    }

    let deleted = KeyColumns::from_keys(batch.deleted_keys.iter());
    if !deleted.is_empty() {
        if !payload_capture_enabled {
            // The tables always exist here (unlike SQLite's optional
            // capture schema), so an evicted key leaves no orphans.
            delete_by_keys(client, "discovery_payload_shape_samples", &deleted).await?;
            delete_by_keys(client, "discovery_payload_shape_stats", &deleted).await?;
        }
        delete_by_keys(client, "discovery_detector_state", &deleted).await?;
        delete_by_keys(client, "discovery_endpoint_aggregates", &deleted).await?;
        delete_signals_for_keys(client, &batch.deleted_keys).await?;
    }

    if !batch.dirty_aggregates.is_empty() {
        let now = utc_timestamp_rfc3339();
        upsert_aggregates(client, &batch.dirty_aggregates, &now).await?;
        insert_status_counts(client, &batch.dirty_aggregates).await?;
        insert_principals(client, &batch.dirty_aggregates).await?;
        insert_routing_contexts(client, &batch.dirty_aggregates, &now).await?;
        insert_routing_principals(client, &batch.dirty_aggregates).await?;
        insert_routing_classifications(client, &batch.dirty_aggregates).await?;
        insert_classified_signal_stats(client, &batch.dirty_aggregates).await?;
        insert_classified_signal_principals(client, &batch.dirty_aggregates).await?;
        if payload_capture_enabled {
            insert_payload_shapes(client, &batch.dirty_aggregates, &now).await?;
        }
    }

    upsert_detector_states(client, detector_states).await?;

    if let Some(groups_json) = template_groups_json {
        upsert_template_groups(client, groups_json).await?;
    }

    // A key admitted and evicted inside one flush window has had its rows
    // deleted above, so its queued signals would be rows no eviction can
    // ever reach again (the SQLite sink drops them the same way).
    let pending_signals = batch.signals_surviving_deletions();
    let opened = insert_signals(client, &pending_signals).await?;

    // Every write above is absolute (or conflict-suppressed), so a retry
    // of a flush whose COMMIT the server applied but the client never
    // heard about (the connection dropped on the acknowledgement) applies
    // nothing new. The counter is the one additive write, so it is guarded
    // by the checkpoint: a batch whose position the row already carries
    // was counted when it was first committed.
    let advanced = client
        .execute(
            "UPDATE greengateway.discovery_projector_state
             SET checkpoint_position = $1::bigint,
                 projected_events = projected_events
                     + CASE WHEN checkpoint_position < $1::bigint THEN $2::bigint ELSE 0 END,
                 updated_at = now()
             WHERE singleton AND fence = $3",
            &[
                &checkpoint.position,
                &checkpoint.projected_events.max(0),
                &checkpoint.fence,
            ],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    if advanced != 1 {
        // Unreachable while the row lock above is held; refusing rather
        // than committing keeps the invariant explicit.
        return Err(RepositoryError::new(
            RepositoryErrorKind::Conflict,
            OPERATION_FLUSH,
        ));
    }

    Ok(opened)
}

/// The tables keyed by endpoint identity that every dirty aggregate
/// rewrites and every deleted key clears. The aggregates table, the
/// detector state, and the payload tables are handled separately.
const CHILD_TABLES: [&str; 7] = [
    "discovery_endpoint_classified_signal_principals",
    "discovery_endpoint_classified_signal_stats",
    "discovery_endpoint_routing_classifications",
    "discovery_endpoint_routing_principals",
    "discovery_endpoint_routing_contexts",
    "discovery_endpoint_status_counts",
    "discovery_endpoint_principals",
];

/// Endpoint keys as two parallel arrays, the shape `UNNEST` binds.
struct KeyColumns {
    methods: Vec<String>,
    templates: Vec<String>,
}

impl KeyColumns {
    fn from_keys<'a>(keys: impl Iterator<Item = &'a EndpointKey>) -> Self {
        let mut seen = HashSet::new();
        let mut methods = Vec::new();
        let mut templates = Vec::new();
        for key in keys {
            if seen.insert(key.clone()) {
                methods.push(key.method.clone());
                templates.push(key.endpoint_template.clone());
            }
        }
        Self { methods, templates }
    }

    fn is_empty(&self) -> bool {
        self.methods.is_empty()
    }
}

async fn delete_by_keys(
    client: &deadpool_postgres::ClientWrapper,
    table: &str,
    keys: &KeyColumns,
) -> Result<(), RepositoryError> {
    // `table` is one of this module's compile-time names, never input.
    client
        .execute(
            &format!(
                "DELETE FROM greengateway.{table} AS t
                 USING UNNEST($1::text[], $2::text[]) AS k(method, endpoint_template)
                 WHERE t.method = k.method AND t.endpoint_template = k.endpoint_template"
            ),
            &[&keys.methods, &keys.templates],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

/// Remove the signals derived from evicted endpoints, exactly as the SQLite
/// sink does: the endpoint signal keyed on `"{method} {template}"` and the
/// principal signals keyed on that prefix plus a space. `left`/`length`
/// count characters on both sides, and no pattern matching is involved,
/// so a template containing `%` or `_` is matched literally.
async fn delete_signals_for_keys(
    client: &deadpool_postgres::ClientWrapper,
    keys: &[EndpointKey],
) -> Result<(), RepositoryError> {
    let mut endpoint_targets = Vec::with_capacity(keys.len());
    let mut principal_prefixes = Vec::with_capacity(keys.len());
    for key in keys {
        let endpoint_target = signals::endpoint_target_key(&key.method, &key.endpoint_template);
        principal_prefixes.push(format!("{endpoint_target} "));
        endpoint_targets.push(endpoint_target);
    }
    client
        .execute(
            "DELETE FROM greengateway.discovery_signals AS s
             USING UNNEST($1::text[], $2::text[]) AS d(endpoint_target, principal_prefix)
             WHERE (s.target_kind = $3 AND s.target_key = d.endpoint_target)
                OR (s.target_kind = $4
                    AND left(s.target_key, length(d.principal_prefix)) = d.principal_prefix)",
            &[
                &endpoint_targets,
                &principal_prefixes,
                &ENDPOINT_TARGET_KIND,
                &PRINCIPAL_ENDPOINT_TARGET_KIND,
            ],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

async fn upsert_aggregates(
    client: &deadpool_postgres::ClientWrapper,
    aggregates: &[EndpointAggregate],
    now: &str,
) -> Result<(), RepositoryError> {
    let count = aggregates.len();
    let mut methods = Vec::with_capacity(count);
    let mut templates = Vec::with_capacity(count);
    let mut first_seen = Vec::with_capacity(count);
    let mut last_seen = Vec::with_capacity(count);
    let mut call_counts = Vec::with_capacity(count);
    let mut mismatch_counts = Vec::with_capacity(count);
    let mut latency_counts = Vec::with_capacity(count);
    let mut p50 = Vec::with_capacity(count);
    let mut p95 = Vec::with_capacity(count);
    let mut p99 = Vec::with_capacity(count);
    let mut samples_json = Vec::with_capacity(count);
    let mut principal_counts = Vec::with_capacity(count);
    for aggregate in aggregates {
        let percentiles = aggregate.latency_percentiles();
        methods.push(aggregate.key.method.clone());
        templates.push(aggregate.key.endpoint_template.clone());
        first_seen.push(aggregate.first_seen.clone());
        last_seen.push(aggregate.last_seen.clone());
        call_counts.push(i64_from_u64(aggregate.call_count));
        mismatch_counts.push(i64_from_u64(aggregate.schema_mismatch_count));
        latency_counts.push(i64_from_u64(aggregate.latency_count));
        p50.push(i64_from_u64(percentiles.p50_ms));
        p95.push(i64_from_u64(percentiles.p95_ms));
        p99.push(i64_from_u64(percentiles.p99_ms));
        samples_json.push(
            serde_json::to_string(&aggregate.latency_samples)
                .map_err(|_| invalid_data(OPERATION_FLUSH))?,
        );
        principal_counts.push(i64_from_usize(aggregate.principals.len()));
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_endpoint_aggregates (
                 method, endpoint_template, first_seen, last_seen, call_count,
                 schema_mismatch_count, latency_count, latency_p50_ms, latency_p95_ms,
                 latency_p99_ms, latency_samples_json, distinct_principal_count, updated_at)
             SELECT method, endpoint_template, first_seen, last_seen, call_count,
                    schema_mismatch_count, latency_count, latency_p50_ms, latency_p95_ms,
                    latency_p99_ms, latency_samples_json, distinct_principal_count, $13
             FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::bigint[],
                         $6::bigint[], $7::bigint[], $8::bigint[], $9::bigint[],
                         $10::bigint[], $11::text[], $12::bigint[])
                  AS a(method, endpoint_template, first_seen, last_seen, call_count,
                       schema_mismatch_count, latency_count, latency_p50_ms, latency_p95_ms,
                       latency_p99_ms, latency_samples_json, distinct_principal_count)
             ON CONFLICT (method, endpoint_template) DO UPDATE SET
                 first_seen = EXCLUDED.first_seen,
                 last_seen = EXCLUDED.last_seen,
                 call_count = EXCLUDED.call_count,
                 schema_mismatch_count = EXCLUDED.schema_mismatch_count,
                 latency_count = EXCLUDED.latency_count,
                 latency_p50_ms = EXCLUDED.latency_p50_ms,
                 latency_p95_ms = EXCLUDED.latency_p95_ms,
                 latency_p99_ms = EXCLUDED.latency_p99_ms,
                 latency_samples_json = EXCLUDED.latency_samples_json,
                 distinct_principal_count = EXCLUDED.distinct_principal_count,
                 updated_at = EXCLUDED.updated_at",
            &[
                &methods,
                &templates,
                &first_seen,
                &last_seen,
                &call_counts,
                &mismatch_counts,
                &latency_counts,
                &p50,
                &p95,
                &p99,
                &samples_json,
                &principal_counts,
                &now,
            ],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

async fn insert_status_counts(
    client: &deadpool_postgres::ClientWrapper,
    aggregates: &[EndpointAggregate],
) -> Result<(), RepositoryError> {
    let mut methods = Vec::new();
    let mut templates = Vec::new();
    let mut statuses = Vec::new();
    let mut counts = Vec::new();
    for aggregate in aggregates {
        for (status, count) in &aggregate.status_counts {
            methods.push(aggregate.key.method.clone());
            templates.push(aggregate.key.endpoint_template.clone());
            statuses.push(i32::from(*status));
            counts.push(i64_from_u64(*count));
        }
    }
    if methods.is_empty() {
        return Ok(());
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_endpoint_status_counts
                 (method, endpoint_template, status, count)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::integer[], $4::bigint[])",
            &[&methods, &templates, &statuses, &counts],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

async fn insert_principals(
    client: &deadpool_postgres::ClientWrapper,
    aggregates: &[EndpointAggregate],
) -> Result<(), RepositoryError> {
    let mut methods = Vec::new();
    let mut templates = Vec::new();
    let mut user_ids = Vec::new();
    let mut issuers = Vec::new();
    let mut auth_methods = Vec::new();
    let mut first_seen = Vec::new();
    let mut last_seen = Vec::new();
    for aggregate in aggregates {
        for (principal, seen) in &aggregate.principals {
            methods.push(aggregate.key.method.clone());
            templates.push(aggregate.key.endpoint_template.clone());
            user_ids.push(principal.user_id.clone());
            issuers.push(principal.issuer.clone());
            auth_methods.push(principal.auth_method.clone());
            first_seen.push(seen.first_seen.clone());
            last_seen.push(seen.last_seen.clone());
        }
    }
    if methods.is_empty() {
        return Ok(());
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_endpoint_principals
                 (method, endpoint_template, user_id, issuer, auth_method, first_seen, last_seen)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
                                  $6::text[], $7::text[])",
            &[
                &methods,
                &templates,
                &user_ids,
                &issuers,
                &auth_methods,
                &first_seen,
                &last_seen,
            ],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

async fn insert_routing_contexts(
    client: &deadpool_postgres::ClientWrapper,
    aggregates: &[EndpointAggregate],
    now: &str,
) -> Result<(), RepositoryError> {
    let mut methods = Vec::new();
    let mut templates = Vec::new();
    let mut hosts = Vec::new();
    let mut prefixes = Vec::new();
    let mut origins = Vec::new();
    let mut first_seen = Vec::new();
    let mut last_seen = Vec::new();
    let mut call_counts = Vec::new();
    let mut principal_counts = Vec::new();
    for aggregate in aggregates {
        for context in aggregate.routing_contexts.values() {
            methods.push(aggregate.key.method.clone());
            templates.push(aggregate.key.endpoint_template.clone());
            hosts.push(context.key.route_host.clone());
            prefixes.push(context.key.route_path_prefix.clone());
            origins.push(context.key.upstream_origin.clone());
            first_seen.push(context.first_seen.clone());
            last_seen.push(context.last_seen.clone());
            call_counts.push(i64_from_u64(context.call_count));
            principal_counts.push(i64_from_usize(context.principals.len()));
        }
    }
    if methods.is_empty() {
        return Ok(());
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_endpoint_routing_contexts
                 (method, endpoint_template, route_host, route_path_prefix, upstream_origin,
                  first_seen, last_seen, call_count, distinct_principal_count, updated_at)
             SELECT method, endpoint_template, route_host, route_path_prefix, upstream_origin,
                    first_seen, last_seen, call_count, distinct_principal_count, $10
             FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
                         $6::text[], $7::text[], $8::bigint[], $9::bigint[])
                  AS c(method, endpoint_template, route_host, route_path_prefix, upstream_origin,
                       first_seen, last_seen, call_count, distinct_principal_count)",
            &[
                &methods,
                &templates,
                &hosts,
                &prefixes,
                &origins,
                &first_seen,
                &last_seen,
                &call_counts,
                &principal_counts,
                &now,
            ],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

async fn insert_routing_principals(
    client: &deadpool_postgres::ClientWrapper,
    aggregates: &[EndpointAggregate],
) -> Result<(), RepositoryError> {
    let mut methods = Vec::new();
    let mut templates = Vec::new();
    let mut hosts = Vec::new();
    let mut prefixes = Vec::new();
    let mut origins = Vec::new();
    let mut user_ids = Vec::new();
    let mut issuers = Vec::new();
    let mut auth_methods = Vec::new();
    for aggregate in aggregates {
        for context in aggregate.routing_contexts.values() {
            for principal in &context.principals {
                methods.push(aggregate.key.method.clone());
                templates.push(aggregate.key.endpoint_template.clone());
                hosts.push(context.key.route_host.clone());
                prefixes.push(context.key.route_path_prefix.clone());
                origins.push(context.key.upstream_origin.clone());
                user_ids.push(principal.user_id.clone());
                issuers.push(principal.issuer.clone());
                auth_methods.push(principal.auth_method.clone());
            }
        }
    }
    if methods.is_empty() {
        return Ok(());
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_endpoint_routing_principals
                 (method, endpoint_template, route_host, route_path_prefix, upstream_origin,
                  user_id, issuer, auth_method)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[],
                                  $6::text[], $7::text[], $8::text[])",
            &[
                &methods,
                &templates,
                &hosts,
                &prefixes,
                &origins,
                &user_ids,
                &issuers,
                &auth_methods,
            ],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

/// The in-memory `routing_context_known_since` is already the earliest of
/// what was loaded and what was observed, and the fence makes this writer
/// the only one, so the absolute value is written (the SQLite sink's
/// `MIN` against the row is the same value under one writer).
async fn insert_routing_classifications(
    client: &deadpool_postgres::ClientWrapper,
    aggregates: &[EndpointAggregate],
) -> Result<(), RepositoryError> {
    let mut methods = Vec::new();
    let mut templates = Vec::new();
    let mut classified_at = Vec::new();
    for aggregate in aggregates {
        if let Some(first_classified_at) = aggregate.routing_context_known_since.as_deref() {
            methods.push(aggregate.key.method.clone());
            templates.push(aggregate.key.endpoint_template.clone());
            classified_at.push(first_classified_at.to_owned());
        }
    }
    if methods.is_empty() {
        return Ok(());
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_endpoint_routing_classifications
                 (method, endpoint_template, first_classified_at)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[])",
            &[&methods, &templates, &classified_at],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

async fn insert_classified_signal_stats(
    client: &deadpool_postgres::ClientWrapper,
    aggregates: &[EndpointAggregate],
) -> Result<(), RepositoryError> {
    let count = aggregates.len();
    let mut methods = Vec::with_capacity(count);
    let mut templates = Vec::with_capacity(count);
    let mut call_counts = Vec::with_capacity(count);
    let mut mismatch_counts = Vec::with_capacity(count);
    let mut error_counts = Vec::with_capacity(count);
    for aggregate in aggregates {
        let state = &aggregate.classified_signal_state;
        methods.push(aggregate.key.method.clone());
        templates.push(aggregate.key.endpoint_template.clone());
        call_counts.push(i64_from_u64(state.call_count));
        mismatch_counts.push(i64_from_u64(state.schema_mismatch_count));
        error_counts.push(i64_from_u64(state.error_count));
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_endpoint_classified_signal_stats
                 (method, endpoint_template, call_count, schema_mismatch_count, error_count)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::bigint[], $4::bigint[], $5::bigint[])",
            &[
                &methods,
                &templates,
                &call_counts,
                &mismatch_counts,
                &error_counts,
            ],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

async fn insert_classified_signal_principals(
    client: &deadpool_postgres::ClientWrapper,
    aggregates: &[EndpointAggregate],
) -> Result<(), RepositoryError> {
    let mut methods = Vec::new();
    let mut templates = Vec::new();
    let mut user_ids = Vec::new();
    let mut issuers = Vec::new();
    let mut auth_methods = Vec::new();
    for aggregate in aggregates {
        for principal in &aggregate.classified_signal_state.principals {
            methods.push(aggregate.key.method.clone());
            templates.push(aggregate.key.endpoint_template.clone());
            user_ids.push(principal.user_id.clone());
            issuers.push(principal.issuer.clone());
            auth_methods.push(principal.auth_method.clone());
        }
    }
    if methods.is_empty() {
        return Ok(());
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_endpoint_classified_signal_principals
                 (method, endpoint_template, user_id, issuer, auth_method)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[])",
            &[&methods, &templates, &user_ids, &issuers, &auth_methods],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

/// The payload reservoir, rewritten whole per dirty aggregate exactly as
/// the SQLite sink does; the stats row exists only while the endpoint has
/// observed a shape.
async fn insert_payload_shapes(
    client: &deadpool_postgres::ClientWrapper,
    aggregates: &[EndpointAggregate],
    now: &str,
) -> Result<(), RepositoryError> {
    let mut methods = Vec::new();
    let mut templates = Vec::new();
    let mut slots = Vec::new();
    let mut observed_at = Vec::new();
    let mut hashes = Vec::new();
    let mut shapes = Vec::new();
    let mut stat_methods = Vec::new();
    let mut stat_templates = Vec::new();
    let mut stat_counts = Vec::new();
    for aggregate in aggregates {
        for (slot, sample) in aggregate.payload_shape_samples.iter().enumerate() {
            methods.push(aggregate.key.method.clone());
            templates.push(aggregate.key.endpoint_template.clone());
            slots.push(i32::try_from(slot).unwrap_or(i32::MAX));
            observed_at.push(sample.observed_at.clone());
            hashes.push(sample.shape_hash.clone());
            shapes.push(
                serde_json::to_string(&sample.shape).map_err(|_| invalid_data(OPERATION_FLUSH))?,
            );
        }
        if aggregate.payload_shape_observation_count > 0 {
            stat_methods.push(aggregate.key.method.clone());
            stat_templates.push(aggregate.key.endpoint_template.clone());
            stat_counts.push(i64_from_u64(aggregate.payload_shape_observation_count));
        }
    }
    if !methods.is_empty() {
        client
            .execute(
                "INSERT INTO greengateway.discovery_payload_shape_samples
                     (method, endpoint_template, sample_slot, observed_at, shape_hash, shape_json)
                 SELECT * FROM UNNEST($1::text[], $2::text[], $3::integer[], $4::text[],
                                      $5::text[], $6::text[])",
                &[&methods, &templates, &slots, &observed_at, &hashes, &shapes],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    }
    if !stat_methods.is_empty() {
        client
            .execute(
                "INSERT INTO greengateway.discovery_payload_shape_stats
                     (method, endpoint_template, shape_observation_count, updated_at)
                 SELECT method, endpoint_template, shape_observation_count, $4
                 FROM UNNEST($1::text[], $2::text[], $3::bigint[])
                      AS s(method, endpoint_template, shape_observation_count)",
                &[&stat_methods, &stat_templates, &stat_counts, &now],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    }
    Ok(())
}

async fn upsert_detector_states(
    client: &deadpool_postgres::ClientWrapper,
    detector_states: &[(EndpointKey, String)],
) -> Result<(), RepositoryError> {
    let mut methods = Vec::new();
    let mut templates = Vec::new();
    let mut states = Vec::new();
    let mut oversized = Vec::new();
    for (key, state_json) in detector_states {
        if state_json.len() > DETECTOR_STATE_MAX_BYTES {
            oversized.push(key);
            continue;
        }
        methods.push(key.method.clone());
        templates.push(key.endpoint_template.clone());
        states.push(state_json.clone());
    }
    if !oversized.is_empty() {
        tracing::warn!(
            endpoints = oversized.len(),
            "discovery detector state exceeds its persisted bound; a successor rebuilds \
             those endpoints' windows from counters"
        );
        let keys = KeyColumns::from_keys(oversized.into_iter());
        delete_by_keys(client, "discovery_detector_state", &keys).await?;
    }
    if methods.is_empty() {
        return Ok(());
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_detector_state
                 (method, endpoint_template, state_json)
             SELECT * FROM UNNEST($1::text[], $2::text[], $3::text[])
             ON CONFLICT (method, endpoint_template) DO UPDATE SET
                 state_json = EXCLUDED.state_json",
            &[&methods, &templates, &states],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

async fn upsert_template_groups(
    client: &deadpool_postgres::ClientWrapper,
    groups_json: &str,
) -> Result<(), RepositoryError> {
    if groups_json.len() > TEMPLATE_GROUPS_MAX_BYTES {
        // Unreachable: the projector exports within the bound. Refusing is
        // right because a stale persisted snapshot would make a successor
        // template paths differently from the leader, permanently.
        tracing::error!(
            bytes = groups_json.len(),
            "discovery template groups exceed their persisted bound; refusing the flush"
        );
        return Err(invalid_data(OPERATION_FLUSH));
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_template_groups (singleton, groups_json, updated_at)
             VALUES (true, $1, now())
             ON CONFLICT (singleton) DO UPDATE SET
                 groups_json = EXCLUDED.groups_json,
                 updated_at = now()",
            &[&groups_json],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    Ok(())
}

/// Insert the queued signals, one row per identity cluster-wide: an
/// identity already present under another id (this leader's earlier
/// flush, a predecessor's, or a replayed batch) inserts nothing and is
/// not reported as opened.
///
/// What is reported as opened is every queued signal whose own id is in
/// the table after the insert, not only the rows this statement inserted:
/// the ids are minted by the leader when the signals are queued and stay
/// the same across retries of the same batch, so a signal committed by an
/// attempt whose COMMIT acknowledgement was lost (and therefore never
/// announced) is found and announced by the retry, once.
async fn insert_signals(
    client: &deadpool_postgres::ClientWrapper,
    pending: &[NewSignal],
) -> Result<Vec<Signal>, RepositoryError> {
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    let count = pending.len();
    let mut ids = Vec::with_capacity(count);
    let mut types = Vec::with_capacity(count);
    let mut kinds = Vec::with_capacity(count);
    let mut keys = Vec::with_capacity(count);
    let mut identities = Vec::with_capacity(count);
    let mut explanations = Vec::with_capacity(count);
    let mut evidence = Vec::with_capacity(count);
    let mut states = Vec::with_capacity(count);
    let mut created_at = Vec::with_capacity(count);
    for signal in pending {
        ids.push(signal.id.clone());
        types.push(signal.signal_type.clone());
        kinds.push(signal.target_kind.clone());
        keys.push(signal.target_key.clone());
        identities.push(
            serde_json::to_string(&signal.target_identity)
                .map_err(|_| invalid_data(OPERATION_FLUSH))?,
        );
        explanations.push(signal.explanation.clone());
        evidence.push(
            serde_json::to_string(&signal.evidence).map_err(|_| invalid_data(OPERATION_FLUSH))?,
        );
        states.push(signal.state.as_str().to_owned());
        created_at.push(signal.created_at.clone());
    }
    client
        .execute(
            "INSERT INTO greengateway.discovery_signals
                 (id, signal_type, target_kind, target_key, target_identity_json, explanation,
                  evidence_json, state, created_at, updated_at, transitioned_at, transitioned_by)
             SELECT id, signal_type, target_kind, target_key, target_identity_json, explanation,
                    evidence_json, state, created_at, created_at, NULL, NULL
             FROM UNNEST($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::text[],
                         $7::text[], $8::text[], $9::text[])
                  AS s(id, signal_type, target_kind, target_key, target_identity_json,
                       explanation, evidence_json, state, created_at)
             ON CONFLICT (signal_type, target_kind, target_key) DO NOTHING",
            &[
                &ids,
                &types,
                &kinds,
                &keys,
                &identities,
                &explanations,
                &evidence,
                &states,
                &created_at,
            ],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?;
    let present = client
        .query(
            "SELECT id FROM greengateway.discovery_signals WHERE id = ANY($1::text[])",
            &[&ids],
        )
        .await
        .map_err(|error| classify_query(error, OPERATION_FLUSH))?
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<HashSet<_>>();
    Ok(pending
        .iter()
        .filter(|signal| present.contains(&signal.id))
        .map(NewSignal::as_signal)
        .collect())
}

fn utc_timestamp_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .expect("current UTC timestamp should format as RFC 3339")
}

fn i64_from_u64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn i64_from_usize(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}
