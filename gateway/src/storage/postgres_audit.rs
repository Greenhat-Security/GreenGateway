//! PostgreSQL audit event/query store (issue #241, PR 5).
//!
//! Implements PR 2's [`AuditEventStore`] contract against the
//! `greengateway.audit_events` table of migration 2, and owns the
//! commit-safe stream protocol that makes durable cursors possible
//! (the HA state model's section 6 requirement):
//!
//! 1. One batch transaction inserts the events
//!    (`ON CONFLICT (event_id) DO NOTHING` -- replayed batches store exactly
//!    once) **and** appends their ids to `greengateway.audit_stream`.
//! 2. Both statements run under a transaction-scoped advisory lock
//!    (`pg_advisory_xact_lock`), held from stream-position assignment until
//!    COMMIT. Because the next writer's append cannot even assign a position
//!    until this transaction commits, **position order is commit order**: a
//!    reader following the stream can never observe a higher position whose
//!    lower predecessor has not committed, and an aborted transaction
//!    leaves no stream row and no hole. This is the property a bare
//!    `GENERATED ... AS IDENTITY` column does not have on its own, and it
//!    is pinned by tests that race concurrent batches and roll back
//!    mid-flight ones.
//! 3. The stream append is `ON CONFLICT DO NOTHING` on `event_id`, so an
//!    at-least-once retry of a batch appends nothing new; exactly one
//!    stream row exists per stored event.
//!
//! Redaction follows the foundation's rules: no SQL text, no query values,
//! and no DSN-derived material cross the error boundary; failures classify
//! into PR 2's `RepositoryErrorKind` vocabulary.

use std::sync::LazyLock;

use async_trait::async_trait;
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};

use crate::audit::{
    query::{
        AuditQueryFilters, AuditQueryPage, RequestObservation, RoleEndpointMatrixAccumulator,
        RoleEndpointObservationFilters, RoleEndpointObservationMatrix,
    },
    Actor, AuditEvent,
};

use super::{
    log_classified, postgres::classify_pool_error, AuditEventStore, RepositoryError,
    RepositoryErrorKind,
};

/// Advisory-lock key for the audit stream, derived from its name the same
/// way the migration lock is, and pinned by a test so two binaries cannot
/// drift onto different keys.
pub(crate) static AUDIT_STREAM_LOCK_KEY: LazyLock<i64> = LazyLock::new(|| {
    let digest = Sha256::digest(b"greengateway.audit-stream");
    let mut value = [0_u8; 8];
    value.copy_from_slice(&digest[..8]);
    value[0] &= 0x7f;
    i64::from_be_bytes(value)
});

const INSERT_EVENTS_SQL: &str = r#"
INSERT INTO greengateway.audit_events (
    event_id, event_type, occurred_at, instance_id, boot_id, schema_version,
    request_id, source_ip, user_agent, actor_user_id, actor_issuer,
    actor_auth_mode, actor_json, payload_method, payload_path, payload_status,
    payload_matched_rule_id, payload_json
)
SELECT * FROM UNNEST(
    $1::text[], $2::text[], $3::text[]::timestamptz[],
    $4::text[]::uuid[], $5::text[]::uuid[],
    $6::text[], $7::text[], $8::text[], $9::text[], $10::text[],
    $11::text[], $12::text[], $13::text[]::jsonb[], $14::text[], $15::text[],
    $16::int[], $17::text[], $18::text[]::jsonb[]
)
ON CONFLICT (event_id) DO NOTHING
"#;

/// The stream append runs as two statements in the batch's transaction
/// (the extended protocol allows one statement per prepared call, and the
/// transaction-scoped lock persists to COMMIT regardless): take the lock,
/// then append.
///
/// Positions are reserved from `greengateway.audit_stream_state` -- a
/// single counter row that retention never deletes -- inside the append
/// transaction. Three properties come from that shape:
///
/// - **Rollback-safe reservation**: an aborted append's counter update
///   rolls back with the transaction, so its numbers are immediately
///   reused (the property a bare `GENERATED ... AS IDENTITY` sequence
///   does not have).
/// - **Strictly monotonic across retention**: the counter survives
///   retention deletes of stream rows, so numbering never restarts at 1
///   the way a `max(position)` read over an emptied table would. A
///   restart would silently strand every durable cursor at a position
///   that gets renumbered.
/// - **Commit-ordered**: the advisory lock (held from reservation until
///   COMMIT) means the next writer's statement snapshot postdates this
///   transaction's commit, so its anti-join sees these rows and a
///   retried batch reserves positions only for ids that will actually
///   append -- no over-reservation, no gaps.
///
/// The anti-join is load-bearing for gaplessness: an at-least-once retry
/// may carry ids whose stream rows already exist, and assigning
/// `row_number()` over those ids before `ON CONFLICT` skipped them would
/// reserve positions for rows that are never inserted.
///
/// **Within a batch, positions follow the ORDER THE CALLER PRESENTED THE
/// EVENTS IN, not their ids.** `UNNEST ... WITH ORDINALITY` carries the
/// array index through the anti-join and `row_number()` orders by it. The
/// caller's order is the log's order -- the ingestion sink queues events as
/// they happen, and the standalone-to-cluster import pages the source log in
/// `id` order -- while an `event_id` is a random UUIDv4, whose lexicographic
/// order is unrelated to anything. Ordering by the id would leave every
/// batch internally shuffled, which contradicts the whole contract a durable
/// cursor reads the stream under (`audit::query`: positions advance in
/// commit order, and within a commit in event order).
const LOCK_STREAM_SQL: &str = "SELECT pg_advisory_xact_lock($1)";

const APPEND_STREAM_SQL: &str = r#"
WITH pending AS (
    SELECT batch.event_id, batch.offered
    FROM UNNEST($1::text[]) WITH ORDINALITY AS batch(event_id, offered)
    WHERE NOT EXISTS (
        SELECT 1 FROM greengateway.audit_stream s WHERE s.event_id = batch.event_id
    )
),
reserved AS (
    UPDATE greengateway.audit_stream_state
    SET last_position = last_position + (SELECT count(*) FROM pending)
    WHERE singleton
    RETURNING last_position - (SELECT count(*) FROM pending) AS base_position
),
assigned AS (
    SELECT reserved.base_position
           + row_number() OVER (ORDER BY pending.offered) AS position,
           pending.event_id
    FROM pending CROSS JOIN reserved
)
INSERT INTO greengateway.audit_stream (position, event_id)
SELECT position, event_id FROM assigned
ON CONFLICT (event_id) DO NOTHING
"#;

const QUERY_EVENTS_SQL: &str = r#"
SELECT
    id,
    event_id,
    event_type,
    to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    schema_version,
    request_id,
    source_ip,
    user_agent,
    actor_json::text,
    payload_json::text
FROM greengateway.audit_events
"#;

/// The durable PostgreSQL audit store. Cheap to construct: it borrows the
/// foundation's pool and holds no per-instance state.
pub struct PostgresAuditEventStore {
    pool: deadpool_postgres::Pool,
    identity: Option<IngestIdentity>,
}

/// Which replica ingested the events in a batch. Recorded per the HA state
/// model so an event's provenance survives the queue that delivered it.
#[derive(Clone, Copy)]
pub struct IngestIdentity {
    pub instance_id: uuid::Uuid,
    pub boot_id: uuid::Uuid,
}

impl PostgresAuditEventStore {
    /// Unused by production yet: the runtime ingestion sink and PR 6's SSE
    /// transport construct this against the serving pool. Exercised today
    /// by the contract and stream tests.
    #[allow(dead_code)]
    pub fn new(pool: deadpool_postgres::Pool, identity: Option<IngestIdentity>) -> Self {
        Self { pool, identity }
    }

    /// Stream rows after a cursor, oldest-first, joining their events.
    ///
    /// The durable-cursor read PR 6's SSE transport builds on: positions
    /// advance in commit order, so `after_position` never skips a committed
    /// event, and a bounded `limit` keeps replay bounded.
    pub async fn stream_after(
        &self,
        after_position: i64,
        limit: usize,
    ) -> Result<Vec<(i64, AuditEvent)>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let rows = client
            .query(
                r#"
                SELECT s.position,
                    e.event_id,
                    e.event_type,
                    to_char(e.occurred_at AT TIME ZONE 'UTC',
                            'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                    e.schema_version,
                    e.request_id,
                    e.source_ip,
                    e.user_agent,
                    e.actor_json::text,
                    e.payload_json::text
                FROM greengateway.audit_stream s
                JOIN greengateway.audit_events e ON e.event_id = s.event_id
                WHERE s.position > $1
                ORDER BY s.position
                LIMIT $2
                "#,
                &[&after_position, &(limit as i64)],
            )
            .await
            .map_err(|error| classify_query(error, "audit_stream_after"))?;
        Ok(rows
            .iter()
            .map(|row| (row.get::<_, i64>(0), event_from_row(row, 0)))
            .collect())
    }

    /// The highest assigned stream position, for cursor initialization.
    pub async fn stream_head(&self) -> Result<i64, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_one(
                "SELECT coalesce(max(position), 0) FROM greengateway.audit_stream",
                &[],
            )
            .await
            .map_err(|error| classify_query(error, "audit_stream_head"))?;
        Ok(row.get::<_, i64>(0))
    }

    /// The smallest position a reader can still obtain: the oldest
    /// retained stream row, or, when retention has removed every row,
    /// one past the never-deleted position counter. A client whose
    /// cursor is below `first_available - 1` has permanently missed
    /// events and must resynchronize rather than stream.
    pub async fn stream_first_available(&self) -> Result<i64, RepositoryError> {
        const OPERATION: &str = "audit_stream_first_available";
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = client
            .query_one(
                r#"
                SELECT coalesce(
                    (SELECT min(position) FROM greengateway.audit_stream),
                    (SELECT last_position + 1
                     FROM greengateway.audit_stream_state WHERE singleton)
                )
                "#,
                &[],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION))?;
        Ok(row.get::<_, i64>(0))
    }

    /// Retention: delete up to `limit` of the oldest events whose
    /// `occurred_at` is at least `retention` old on the database clock,
    /// never at or past `min_retained_position` on the stream (issue #241,
    /// PR 13). The stream row goes with the event (`ON DELETE CASCADE`) and
    /// the position counter is never touched, so cursors keep their
    /// meaning across retention ([`Self::stream_first_available`] moves
    /// forward, numbering never restarts).
    ///
    /// The position floor is what keeps retention from deleting an event a
    /// durable consumer has not yet projected: with `Some(p)` only
    /// positions strictly below `p` are candidates, whatever their age. An
    /// event that was never appended to the stream (the import path can
    /// write one) has no position to protect and is judged by age alone.
    /// Oldest positions go first, so a bounded step always frees the
    /// stream's tail rather than a random slice of it.
    #[allow(dead_code)] // the singleton runs `prune_older_than_with` on its session; this is the store-level surface, pinned by the contract tests
    pub async fn prune_older_than(
        &self,
        retention: std::time::Duration,
        min_retained_position: Option<i64>,
        limit: u32,
    ) -> Result<u64, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        self.prune_older_than_with(&client, retention, min_retained_position, limit)
            .await
    }

    /// [`Self::prune_older_than`] over a connection the caller holds (the
    /// maintenance singleton's dedicated session, so its advisory lock
    /// covers the statements themselves).
    ///
    /// The work of one step is bounded by the step, not by the backlog:
    /// the candidates are drawn from a window of `limit x`
    /// [`RETENTION_SCAN_FACTOR`] rows walked in index order, never from a
    /// scan of the whole table, so a deployment that turns retention on
    /// over a large history (or fell far behind) drains it one bounded step
    /// per pass instead of timing out every pass on a sort of everything.
    /// Two statements do it: the first walks `audit_stream` by position
    /// (its primary key) below the floor and deletes the old events among
    /// the lowest positions; only when that frees fewer than `limit` rows
    /// does the second walk `audit_events` by `occurred_at` (its index)
    /// for old events that were never streamed. Because positions are
    /// assigned in commit order, the oldest events sit at the lowest
    /// positions, so the window hides a deletable row only behind a burst
    /// of younger rows larger than the window -- and finds it once those
    /// are gone.
    pub(crate) async fn prune_older_than_with(
        &self,
        client: &tokio_postgres::Client,
        retention: std::time::Duration,
        min_retained_position: Option<i64>,
        limit: u32,
    ) -> Result<u64, RepositoryError> {
        const OPERATION: &str = "audit_retention_prune";
        let retention_secs = retention.as_secs_f64();
        let limit = i64::from(limit.clamp(1, MAX_RETENTION_BATCH));
        let window = limit.saturating_mul(RETENTION_SCAN_FACTOR);
        let streamed = client
            .execute(
                PRUNE_STREAMED_SQL,
                &[&retention_secs, &min_retained_position, &limit, &window],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION))?;
        let remaining = limit.saturating_sub(i64::try_from(streamed).unwrap_or(i64::MAX));
        if remaining <= 0 {
            return Ok(streamed);
        }
        let unstreamed = client
            .execute(
                PRUNE_UNSTREAMED_SQL,
                &[&retention_secs, &remaining, &window],
            )
            .await
            .map_err(|error| classify_query(error, OPERATION))?;
        Ok(streamed + unstreamed)
    }
    /// The role/endpoint matrix cluster mode's rule-suggestion generation
    /// reads (issue #241, PR 12): the SQLite `AuditQueryStore`'s
    /// `observed_role_endpoint_matrix`, ported statement for statement.
    /// The scan is the same newest-first `http.request_observed` scan over
    /// the same window, bounded by the same `max_scan_rows` (one row past
    /// it decides truncation exactly as the visitor scan does), and the
    /// rows are folded by the SAME `RoleEndpointMatrixAccumulator`, so a
    /// given set of events yields one matrix whichever store holds them.
    /// Rows stream through the accumulator rather than buffering the whole
    /// scan: the budget is 100k events with their payloads.
    pub async fn observed_role_endpoint_matrix(
        &self,
        filters: &RoleEndpointObservationFilters,
    ) -> Result<RoleEndpointObservationMatrix, RepositoryError> {
        const OPERATION: &str = "audit_role_endpoint_matrix";
        if filters.endpoints.is_empty() {
            return Ok(RoleEndpointObservationMatrix::default());
        }
        let client = self.pool.get().await.map_err(classify_pool_error)?;

        let mut clauses = vec![
            "event_type = 'http.request_observed'".to_owned(),
            "payload_method IS NOT NULL".to_owned(),
            "payload_path IS NOT NULL".to_owned(),
        ];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        // The bounds bind as text and cast in SQL (`::text::timestamptz`),
        // so the driver sends the RFC 3339 string rather than being asked
        // for a `timestamptz` it cannot encode a `String` as.
        if let Some(from) = filters.from.as_deref() {
            params.push(Box::new(from.to_owned()));
            clauses.push(format!(
                "occurred_at >= ${}::text::timestamptz",
                params.len()
            ));
        }
        if let Some(to) = filters.to.as_deref() {
            params.push(Box::new(to.to_owned()));
            clauses.push(format!(
                "occurred_at <= ${}::text::timestamptz",
                params.len()
            ));
        }
        // One row past the budget: the accumulator refuses it and reports
        // the scan as truncated, exactly as the SQLite visitor scan does.
        let fetch_limit =
            i64::try_from(filters.max_scan_rows.saturating_add(1)).unwrap_or(i64::MAX);
        params.push(Box::new(fetch_limit));
        let sql = format!(
            r#"
            SELECT
                id,
                event_id,
                to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                request_id,
                source_ip,
                user_agent,
                actor_json::text,
                payload_method,
                payload_path,
                payload_status,
                payload_matched_rule_id,
                payload_json::text
            FROM greengateway.audit_events
            WHERE {}
            ORDER BY id DESC
            LIMIT ${}
            "#,
            clauses.join(" AND "),
            params.len()
        );
        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();

        let mut accumulator =
            RoleEndpointMatrixAccumulator::new(&filters.endpoints, filters.max_scan_rows);
        let stream = client
            .query_raw(sql.as_str(), params)
            .await
            .map_err(|error| classify_query(error, OPERATION))?;
        let mut stream = std::pin::pin!(stream);
        while let Some(row) = stream
            .try_next()
            .await
            .map_err(|error| classify_query(error, OPERATION))?
        {
            let observation = request_observation_from_row(&row, OPERATION)?;
            if !accumulator.observe(&observation) {
                break;
            }
        }
        Ok(accumulator.finish())
    }
}

/// Decode one scanned `http.request_observed` row into the shape the
/// SQLite scan hands its visitor. An actor JSON that does not decode is
/// `InvalidData`, the SQLite scan's `ActorJson` failure.
fn request_observation_from_row(
    row: &tokio_postgres::Row,
    operation: &'static str,
) -> Result<RequestObservation, RepositoryError> {
    let event_id: String = observation_column(row, 1, operation)?;
    let actor = observation_column::<Option<String>>(row, 6, operation)?
        .map(|json| serde_json::from_str::<Actor>(&json))
        .transpose()
        .map_err(|error| {
            tracing::error!(operation, event_id, error = %error, "audit actor JSON failed to decode");
            RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
        })?;
    Ok(RequestObservation {
        id: observation_column(row, 0, operation)?,
        event_id,
        timestamp: observation_column(row, 2, operation)?,
        request_id: observation_column(row, 3, operation)?,
        source_ip: observation_column(row, 4, operation)?,
        user_agent: observation_column(row, 5, operation)?,
        actor,
        method: observation_column(row, 7, operation)?,
        path: observation_column(row, 8, operation)?,
        status: observation_column::<Option<i32>>(row, 9, operation)?.map(i64::from),
        matched_rule_id: observation_column(row, 10, operation)?,
        payload_json: observation_column(row, 11, operation)?,
    })
}

/// Read one column of a scanned row; a row that does not decode is data
/// this binary cannot use (`InvalidData`), never a panic.
fn observation_column<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    index: usize,
    operation: &'static str,
) -> Result<T, RepositoryError> {
    row.try_get(index).map_err(|error| {
        tracing::error!(operation, column = index, error = %error, "audit row failed to decode");
        RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
    })
}

/// The bound on one retention step, so the singleton's delete stays a short
/// statement however far behind retention fell.
const MAX_RETENTION_BATCH: u32 = 10_000;

/// How many index-ordered rows one retention step examines per row it may
/// delete: the window the candidates are drawn from. The step's cost is
/// `O(limit x this)` whatever the backlog; a window this many times the
/// limit absorbs bursts of younger rows interleaved with older ones (clock
/// skew between replicas, a slow commit) without ever scanning the table.
pub(crate) const RETENTION_SCAN_FACTOR: i64 = 10;

/// Retention over streamed events: `$1` retention seconds, `$2` the
/// position floor (`NULL` for none), `$3` the row limit, `$4` the scan
/// window. Walks `audit_stream` by position, looks each event up, keeps
/// the old ones, deletes the lowest positions first.
///
/// The event lookup is a correlated scalar subquery rather than a join on
/// purpose: a join leaves the planner free to hash or scan the whole
/// events table when its estimates make that look cheap, and a stale
/// estimate on a large table is exactly the O(backlog) step this shape
/// exists to rule out. A per-row subplan is one index probe per window
/// row whatever the planner thinks of the table.
pub(crate) const PRUNE_STREAMED_SQL: &str = r#"
DELETE FROM greengateway.audit_events
WHERE id = ANY(ARRAY(
    SELECT candidate.id
    FROM (SELECT tail.position,
                 (SELECT e.id FROM greengateway.audit_events e
                  WHERE e.event_id = tail.event_id
                    AND e.occurred_at <= now() - make_interval(secs => $1::double precision)) AS id
          FROM (SELECT s.position, s.event_id
                FROM greengateway.audit_stream s
                WHERE $2::bigint IS NULL OR s.position < $2::bigint
                ORDER BY s.position ASC
                LIMIT $4) AS tail) AS candidate
    WHERE candidate.id IS NOT NULL
    ORDER BY candidate.position ASC
    LIMIT $3))
"#;

/// Retention over events that were never appended to the stream: `$1`
/// retention seconds, `$2` the row limit, `$3` the scan window. Walks
/// `audit_events` by `occurred_at`, keeps the ones without a stream row,
/// deletes the oldest first. The stream lookup is a correlated scalar
/// subquery for the reason given on [`PRUNE_STREAMED_SQL`]: `NOT EXISTS`
/// becomes an anti-join the planner may run as a scan of the whole stream.
pub(crate) const PRUNE_UNSTREAMED_SQL: &str = r#"
DELETE FROM greengateway.audit_events
WHERE id = ANY(ARRAY(
    SELECT oldest.id
    FROM (SELECT e.id, e.event_id, e.occurred_at
          FROM greengateway.audit_events e
          WHERE e.occurred_at <= now() - make_interval(secs => $1::double precision)
          ORDER BY e.occurred_at ASC, e.id ASC
          LIMIT $3) AS oldest
    WHERE (SELECT s.position FROM greengateway.audit_stream s
           WHERE s.event_id = oldest.event_id) IS NULL
    ORDER BY oldest.occurred_at ASC, oldest.id ASC
    LIMIT $2))
"#;

#[async_trait]
impl AuditEventStore for PostgresAuditEventStore {
    async fn insert_events(&self, events: &[AuditEvent]) -> Result<(), RepositoryError> {
        if events.is_empty() {
            return Ok(());
        }
        let client = self.pool.get().await.map_err(classify_pool_error)?;

        let mut event_ids: Vec<String> = Vec::with_capacity(events.len());
        let mut event_types: Vec<String> = Vec::with_capacity(events.len());
        let mut occurred_at: Vec<String> = Vec::with_capacity(events.len());
        let mut instance_ids: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut boot_ids: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut schema_versions: Vec<String> = Vec::with_capacity(events.len());
        let mut request_ids: Vec<String> = Vec::with_capacity(events.len());
        let mut source_ips: Vec<String> = Vec::with_capacity(events.len());
        let mut user_agents: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut actor_user_ids: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut actor_issuers: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut actor_auth_modes: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut actor_jsons: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut payload_methods: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut payload_paths: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut payload_statuses: Vec<Option<i32>> = Vec::with_capacity(events.len());
        let mut payload_rule_ids: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut payload_jsons: Vec<String> = Vec::with_capacity(events.len());

        for event in events {
            event_ids.push(event.event_id.clone());
            event_types.push(event.event_type.clone());
            occurred_at.push(event.timestamp.clone());
            instance_ids.push(
                self.identity
                    .map(|identity| identity.instance_id.to_string()),
            );
            boot_ids.push(self.identity.map(|identity| identity.boot_id.to_string()));
            schema_versions.push(event.schema_version.clone());
            request_ids.push(event.request_id.clone());
            source_ips.push(event.source_ip.clone());
            user_agents.push(event.user_agent.clone());
            actor_user_ids.push(event.actor.as_ref().map(|actor| actor.user_id.clone()));
            actor_issuers.push(event.actor.as_ref().and_then(|actor| actor.issuer.clone()));
            actor_auth_modes.push(event.actor.as_ref().map(|actor| actor.auth_mode.clone()));
            actor_jsons.push(
                event
                    .actor
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(|_| {
                        RepositoryError::new(RepositoryErrorKind::InvalidData, "audit_event_insert")
                    })?,
            );
            payload_methods.push(
                event
                    .payload
                    .get("method")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            );
            payload_paths.push(
                event
                    .payload
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            );
            payload_statuses.push(payload_status(&event.payload));
            payload_rule_ids.push(
                event
                    .payload
                    .get("matched_rule_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
            );
            payload_jsons.push(serde_json::to_string(&event.payload).map_err(|_| {
                RepositoryError::new(RepositoryErrorKind::InvalidData, "audit_event_insert")
            })?);
        }

        // One transaction: the advisory lock (released at commit or
        // rollback) serializes stream-position assignment so position order
        // is commit order; both statements roll back together, so an
        // aborted batch leaves no event rows and no stream rows. The
        // transaction is driven explicitly over the simple protocol, like
        // the migrator's, so no &mut borrow of the pooled client is needed.
        client
            .batch_execute("BEGIN")
            .await
            .map_err(|error| classify_query(error, "audit_event_insert"))?;
        let result: Result<(), RepositoryError> = async {
            client
                .execute(
                    INSERT_EVENTS_SQL,
                    &[
                        &event_ids,
                        &event_types,
                        &occurred_at,
                        &instance_ids,
                        &boot_ids,
                        &schema_versions,
                        &request_ids,
                        &source_ips,
                        &user_agents,
                        &actor_user_ids,
                        &actor_issuers,
                        &actor_auth_modes,
                        &actor_jsons,
                        &payload_methods,
                        &payload_paths,
                        &payload_statuses,
                        &payload_rule_ids,
                        &payload_jsons,
                    ],
                )
                .await
                .map_err(|error| classify_query(error, "audit_event_insert"))?;
            client
                .execute(LOCK_STREAM_SQL, &[&*AUDIT_STREAM_LOCK_KEY])
                .await
                .map_err(|error| classify_query(error, "audit_event_insert"))?;
            client
                .execute(APPEND_STREAM_SQL, &[&event_ids])
                .await
                .map_err(|error| classify_query(error, "audit_event_insert"))?;
            Ok(())
        }
        .await;
        match result {
            Ok(()) => client
                .batch_execute("COMMIT")
                .await
                .map_err(|error| classify_query(error, "audit_event_insert")),
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                Err(error)
            }
        }
    }

    async fn query_events(
        &self,
        filters: &AuditQueryFilters,
    ) -> Result<AuditQueryPage, RepositoryError> {
        // A zero limit is a caller contract violation; answer it as an
        // empty page rather than the panic a limit+1 fetch would reach
        // ("has_more implies at least one returned row").
        if filters.limit == 0 {
            return Ok(AuditQueryPage {
                events: Vec::new(),
                next_cursor: None,
            });
        }
        let client = self.pool.get().await.map_err(classify_pool_error)?;

        let mut clauses: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();

        if let Some(from) = filters.from.as_deref() {
            params.push(Box::new(from.to_owned()));
            clauses.push(format!("occurred_at >= ${}::timestamptz", params.len()));
        }
        if let Some(to) = filters.to.as_deref() {
            params.push(Box::new(to.to_owned()));
            clauses.push(format!("occurred_at <= ${}::timestamptz", params.len()));
        }
        if let Some(event_type) = filters.event_type.as_deref() {
            params.push(Box::new(event_type.to_owned()));
            clauses.push(format!("event_type = ${}", params.len()));
        }
        if let Some(actor) = filters.actor.as_deref() {
            params.push(Box::new(actor.to_owned()));
            clauses.push(format!("actor_user_id = ${}", params.len()));
        }
        if let Some(actor_issuer) = filters.actor_issuer.as_deref() {
            params.push(Box::new(actor_issuer.to_owned()));
            clauses.push(format!("actor_issuer = ${}", params.len()));
        }
        if let Some(actor_auth_mode) = filters.actor_auth_mode.as_deref() {
            params.push(Box::new(actor_auth_mode.to_owned()));
            clauses.push(format!("actor_auth_mode = ${}", params.len()));
        }
        if let Some(method) = filters.method.as_deref() {
            params.push(Box::new(method.to_owned()));
            clauses.push(format!("payload_method = ${}", params.len()));
        }
        if let Some(path) = filters.path.as_deref() {
            params.push(Box::new(path.to_owned()));
            clauses.push(format!("payload_path = ${}", params.len()));
        }
        if let Some(status) = filters.status {
            params.push(Box::new(status as i32));
            clauses.push(format!("payload_status = ${}", params.len()));
        }
        if let Some(matched_rule_id) = filters.matched_rule_id.as_deref() {
            params.push(Box::new(matched_rule_id.to_owned()));
            clauses.push(format!("payload_matched_rule_id = ${}", params.len()));
        }
        if let Some(before_id) = filters.before_id {
            params.push(Box::new(before_id));
            clauses.push(format!("id < ${}", params.len()));
        }
        let fetch_limit = filters.limit.saturating_add(1) as i64;
        params.push(Box::new(fetch_limit));

        let sql = format!(
            "{QUERY_EVENTS_SQL}{}ORDER BY id DESC LIMIT ${}",
            if clauses.is_empty() {
                String::new()
            } else {
                format!("WHERE {} ", clauses.join(" AND "))
            },
            params.len()
        );

        let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
            .iter()
            .map(|value| value.as_ref() as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        let rows = client
            .query(&sql, params.as_slice())
            .await
            .map_err(|error| classify_query(error, "audit_event_query"))?;

        // Fetched one row beyond the limit: its presence decides whether a
        // next page exists, and the cursor is the last row *returned* (the
        // keyset `id < cursor` then resumes strictly below it).
        let has_more = rows.len() > filters.limit;
        let returned = &rows[..rows.len().min(filters.limit)];
        let next_cursor = has_more.then(|| {
            returned
                .last()
                .expect("has_more implies at least one returned row")
                .get::<_, i64>(0)
        });
        let events = returned.iter().map(|row| event_from_row(row, 0)).collect();
        Ok(AuditQueryPage {
            events,
            next_cursor,
        })
    }
}

fn payload_status(payload: &serde_json::Value) -> Option<i32> {
    payload
        .get("status")
        .and_then(serde_json::Value::as_i64)
        .and_then(|status| i32::try_from(status).ok())
}

/// Rebuild an [`AuditEvent`] from a query row. `offset` selects where the
/// event columns start: the query projection puts `id` first and the
/// stream projection puts `position` first, and the event columns follow
/// identically in both.
fn event_from_row(row: &tokio_postgres::Row, offset: usize) -> AuditEvent {
    let actor = row
        .get::<_, Option<String>>(offset + 8)
        .map(|json| serde_json::from_str::<Actor>(&json))
        .transpose()
        .ok()
        .flatten();
    let payload =
        serde_json::from_str(&row.get::<_, String>(offset + 9)).unwrap_or(serde_json::Value::Null);
    AuditEvent {
        event_id: row.get::<_, String>(offset + 1),
        event_type: row.get::<_, String>(offset + 2),
        timestamp: row.get::<_, String>(offset + 3),
        schema_version: row.get::<_, String>(offset + 4),
        request_id: row.get::<_, String>(offset + 5),
        source_ip: row.get::<_, String>(offset + 6),
        user_agent: row.get::<_, Option<String>>(offset + 7),
        actor,
        payload,
    }
}

/// Classify a query failure, logging the detail at its site.
fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_lock_key_is_stable_and_positive() {
        let digest = Sha256::digest(b"greengateway.audit-stream");
        let mut expected = [0_u8; 8];
        expected.copy_from_slice(&digest[..8]);
        expected[0] &= 0x7f;
        assert_eq!(*AUDIT_STREAM_LOCK_KEY, i64::from_be_bytes(expected));
        assert!(*AUDIT_STREAM_LOCK_KEY > 0);
    }
}
