//! The cluster audit stream as a historical policy replay source (issue
//! #243): the PostgreSQL reader behind [`ReplaySource`], the trait the
//! standalone audit log's reader implements, over the tables
//! [`super::postgres_audit`] writes.
//!
//! ## The cutoff
//!
//! A job's cutoff ([`PostgresReplayReader::cutoff`]) is the highest position
//! the stream has assigned when the job is created -- the never-deleted
//! counter in `greengateway.audit_stream_state` -- together with how many
//! stream rows at or below it hold an event inside the window, and the
//! lowest and highest of their positions. One statement reads all four, so
//! they come from one snapshot. The stream's commit-order guarantee
//! ([`super::postgres_audit`]: a writer cannot reserve a position until the
//! writer before it has committed) is what makes the cutoff immutable: every
//! position at or below it was committed when it was read, and every event
//! committed later -- whatever its timestamp, including one a replica had
//! queued but not flushed -- is appended above it and can never enter the
//! job. The [`ReplayCutoff`] fields a standalone job fills with row ids hold
//! stream positions here.
//!
//! ## Pages
//!
//! A page ([`PostgresReplayReader::read_page`]) walks the stream by position
//! above the last one read and at or below the cutoff, and keeps the events
//! inside `[from, to)`. The event is looked up per stream row behind an
//! optimisation fence, so the walk follows the stream's primary key and stops
//! at the page's row bound rather than sorting the window for every page.
//! Its bounds are the standalone reader's: at most `limit` rows, and past
//! the first row no more than `max_page_bytes` of actor and payload JSON.
//! A row whose JSON exceeds `max_record_bytes` is [`ReplayRow::Oversized`]
//! and its JSON never leaves the database; one whose actor JSON is not the
//! shape the audit sink writes is [`ReplayRow::Unreadable`]. Every other row
//! is handed to the replay adapters as stored, so malformed and legacy
//! records are counted by the same codes a standalone job counts them by.
//!
//! ## Pruning and gaps
//!
//! Committed stream positions are gapless from 1 by construction, and
//! retention never renumbers them, so a missing position at or below the
//! cutoff is a deleted event -- retention, or a removal from outside the
//! gateway. When a run ends, [`PostgresReplayReader::check_window`] counts
//! the window's rows again and looks for missing positions around the
//! window: from the newest retained event that occurred before `from` to the
//! oldest retained event at or after `to`, both at or below the cutoff, and
//! across every position the cutoff selected. With no retained event before
//! the window, the span reaches back to position 1, so retention that
//! reached past the window's start is always seen. Any missing position in
//! the span is `source_pruned`, never a silent omission. The span relies on
//! the stream's commit order: an event deleted below the newest retained
//! event older than the window is taken to be older than the window too.
//!
//! ## Sharing the database
//!
//! Every read checks a connection out under its own class,
//! [`CheckoutClass::PolicyReplay`], and runs in a short read-only
//! transaction with `SET LOCAL` statement and lock timeouts, never looser
//! than the session's own ([`REPLAY_STATEMENT_TIMEOUT`],
//! [`REPLAY_LOCK_TIMEOUT`]). A replay holds one connection per replica, only
//! for the length of one statement or two, holds no snapshot between pages
//! (so it never holds back vacuum or retention), takes only the shared
//! table locks plain reads take, never the stream's advisory lock, and gives
//! up quickly rather than holding a pooled connection while it waits behind
//! a migration. The data plane, the audit writer and retention are never
//! queued behind it.
//!
//! ## Errors
//!
//! Failures classify into [`RepositoryErrorKind`] at the site that met them
//! and are logged there, as the rest of the foundation's stores do: no SQL
//! text, no window bound, position or record value crosses the error
//! boundary, and the job sees only an opaque [`ReplaySourceError`].
//!
//! The reader's callers are the cluster replay routes, which fix a job's
//! cutoff when it is admitted, and the replay worker every cluster replica
//! runs, which reads the job's pages and its closing check
//! (`admin_policy_replays`'s cluster module).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::TryStreamExt;
use tokio_postgres::IsolationLevel;

use crate::{
    audit::{
        query::{ReplayCutoff, ReplayPageQuery, ReplayRow},
        Actor, AuditEvent,
    },
    config::DatabaseSettings,
    policy_replay::job::{ReplayScope, ReplaySource, ReplaySourceCheck, ReplaySourceError},
};

use super::{
    log_classified,
    postgres::{checkout, classify_postgres_error, CheckoutClass},
    RepositoryError, RepositoryErrorKind,
};

/// How a result names the cluster audit stream: its `source.kind`.
pub(crate) const CLUSTER_REPLAY_SOURCE_KIND: &str = "cluster_audit_stream";
/// The most one replay statement may run. A cutoff and a closing check count
/// the window's rows, so this is the bound on the window a cluster job can
/// take; a page is far shorter. Never looser than the session's
/// `DATABASE_STATEMENT_TIMEOUT_MS`.
pub(crate) const REPLAY_STATEMENT_TIMEOUT: Duration = Duration::from_secs(10);
/// The most one replay statement may wait for a lock. Replay reads take only
/// the shared lock every read takes, which waits only behind DDL; giving up
/// at once keeps a replay from holding a pooled connection in that queue.
/// Never looser than the session's `DATABASE_LOCK_TIMEOUT_MS`.
pub(crate) const REPLAY_LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// The cutoff in one statement: the stream's high-water position and the
/// window's rows at or below it. `$1` and `$2` are the window's bounds.
const CUTOFF_SQL: &str = r#"
SELECT
    state.last_position,
    count(windowed.position),
    min(windowed.position),
    max(windowed.position)
FROM greengateway.audit_stream_state AS state
LEFT JOIN LATERAL (
    SELECT s.position
    FROM greengateway.audit_events AS e
    JOIN greengateway.audit_stream AS s ON s.event_id = e.event_id
    WHERE e.occurred_at >= $1
      AND e.occurred_at < $2
      AND s.position <= state.last_position
) AS windowed ON true
WHERE state.singleton
GROUP BY state.last_position
"#;

/// One page: `$1 < position <= $2`, events inside `[$3, $4)`, at most `$5`
/// rows, JSON withheld past `$6` bytes. `OFFSET 0` keeps the event lookup a
/// per-row subquery, so the plan walks the stream's primary key in order and
/// the row bound ends the walk; the JSON is rendered once, measured, and
/// sent only for a row within the bound.
const PAGE_SQL: &str = r#"
SELECT
    s.position,
    e.event_id,
    e.event_type,
    to_char(e.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    e.schema_version,
    e.request_id,
    e.source_ip,
    e.user_agent,
    CASE WHEN sized.record_bytes > $6 THEN NULL ELSE e.actor END,
    CASE WHEN sized.record_bytes > $6 THEN NULL ELSE e.payload END,
    sized.record_bytes
FROM greengateway.audit_stream AS s
CROSS JOIN LATERAL (
    SELECT
        event_id,
        event_type,
        occurred_at,
        schema_version,
        request_id,
        source_ip,
        user_agent,
        actor_json::text AS actor,
        payload_json::text AS payload
    FROM greengateway.audit_events
    WHERE event_id = s.event_id
      AND occurred_at >= $3
      AND occurred_at < $4
    OFFSET 0
) AS e
CROSS JOIN LATERAL (
    SELECT octet_length(e.payload)::bigint
        + coalesce(octet_length(e.actor), 0)::bigint AS record_bytes
) AS sized
WHERE s.position > $1
  AND s.position <= $2
ORDER BY s.position
LIMIT $5
"#;

/// What a closing check needs from the window, at or below cutoff `$3`: the
/// position of the newest event before `$1`, of the oldest event at or after
/// `$2`, and how many events of `[$1, $2)` are stored. The two bracketing
/// lookups walk the timestamp index from the window's edges and stop at the
/// first streamed event.
const CHECK_SQL: &str = r#"
SELECT
    (SELECT s.position
     FROM greengateway.audit_events AS e
     JOIN greengateway.audit_stream AS s ON s.event_id = e.event_id
     WHERE e.occurred_at < $1
       AND s.position <= $3
     ORDER BY e.occurred_at DESC
     LIMIT 1),
    (SELECT s.position
     FROM greengateway.audit_events AS e
     JOIN greengateway.audit_stream AS s ON s.event_id = e.event_id
     WHERE e.occurred_at >= $2
       AND s.position <= $3
     ORDER BY e.occurred_at ASC
     LIMIT 1),
    (SELECT count(*)
     FROM greengateway.audit_events AS e
     JOIN greengateway.audit_stream AS s ON s.event_id = e.event_id
     WHERE e.occurred_at >= $1
       AND e.occurred_at < $2
       AND s.position <= $3)
"#;

/// How many stream positions in `[$1, $2]` are still stored: an index-only
/// count over the stream's primary key.
const PRESENT_SQL: &str = r#"
SELECT count(*)
FROM greengateway.audit_stream
WHERE position >= $1
  AND position <= $2
"#;

const CUTOFF_OPERATION: &str = "audit_replay_cutoff";
const PAGE_OPERATION: &str = "audit_replay_page";
const CHECK_OPERATION: &str = "audit_replay_check";

/// The statement and lock bounds every replay transaction sets, in
/// milliseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReplayTimeouts {
    statement_ms: u64,
    lock_ms: u64,
}

impl ReplayTimeouts {
    /// The replay's own bounds, tightened to the session's where the
    /// operator configured shorter ones.
    fn for_settings(settings: &DatabaseSettings) -> Self {
        Self {
            statement_ms: tighter(settings.statement_timeout_ms, REPLAY_STATEMENT_TIMEOUT),
            lock_ms: tighter(settings.lock_timeout_ms, REPLAY_LOCK_TIMEOUT),
        }
    }

    /// `SET LOCAL`: bounded to the transaction, so the pooled session goes
    /// back to the pool with its own settings. Both values are integers this
    /// module computed; nothing from a request reaches the text.
    fn set_local(self) -> String {
        format!(
            "SET LOCAL statement_timeout = {}; SET LOCAL lock_timeout = {};",
            self.statement_ms, self.lock_ms
        )
    }
}

/// The smaller of a session timeout and the replay's. `0` disables a
/// PostgreSQL timeout, so a session without one gets the replay's own.
fn tighter(session_ms: u64, replay: Duration) -> u64 {
    let replay_ms = u64::try_from(replay.as_millis()).unwrap_or(u64::MAX);
    if session_ms == 0 {
        replay_ms
    } else {
        session_ms.min(replay_ms)
    }
}

/// The cluster audit stream, read for replay jobs. Cheap to construct: it
/// borrows the foundation's pool and holds no per-job state.
pub(crate) struct PostgresReplayReader {
    pool: deadpool_postgres::Pool,
    timeouts: ReplayTimeouts,
    runtime: tokio::runtime::Handle,
}

impl PostgresReplayReader {
    /// `settings` are the pool's own, so the replay's bounds never loosen
    /// the operator's; `runtime` is the runtime that drives the pool's
    /// connections, on which a run's blocking thread waits for each read
    /// ([`ReplaySource`] is called from a blocking thread, never from an
    /// asynchronous task).
    pub(crate) fn new(
        pool: deadpool_postgres::Pool,
        settings: &DatabaseSettings,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            pool,
            timeouts: ReplayTimeouts::for_settings(settings),
            runtime,
        }
    }

    /// Fix the rows a job reads: the stream's high-water position now, and
    /// the window `[from_epoch_us, to_epoch_us)`'s rows at or below it.
    pub(crate) async fn cutoff(
        &self,
        from_epoch_us: i64,
        to_epoch_us: i64,
    ) -> Result<ReplayCutoff, RepositoryError> {
        let from = epoch_time(from_epoch_us, CUTOFF_OPERATION)?;
        let to = epoch_time(to_epoch_us, CUTOFF_OPERATION)?;
        let mut client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        let transaction = self
            .read_only(&mut client, IsolationLevel::ReadCommitted, CUTOFF_OPERATION)
            .await?;
        let row = transaction
            .query_one(CUTOFF_SQL, &[&from, &to])
            .await
            .map_err(|error| classify(error, CUTOFF_OPERATION))?;
        let high_water: i64 = column(&row, 0, CUTOFF_OPERATION)?;
        let selected: i64 = column(&row, 1, CUTOFF_OPERATION)?;
        let first_id: Option<i64> = column(&row, 2, CUTOFF_OPERATION)?;
        let last_id: Option<i64> = column(&row, 3, CUTOFF_OPERATION)?;
        transaction
            .commit()
            .await
            .map_err(|error| classify(error, CUTOFF_OPERATION))?;
        Ok(ReplayCutoff {
            high_water,
            selected: u64::try_from(selected).unwrap_or(0),
            first_id,
            last_id,
        })
    }

    /// One page of a replay window, oldest first: the stream rows `page`
    /// names, at most `limit` of them and, past the first, no more than
    /// `max_page_bytes` of actor and payload JSON in total. An oversized
    /// row costs the page nothing, since none of its JSON is read.
    pub(crate) async fn read_page(
        &self,
        page: &ReplayPageQuery,
    ) -> Result<Vec<(i64, ReplayRow)>, RepositoryError> {
        let from = epoch_time(page.from_epoch_us, PAGE_OPERATION)?;
        let to = epoch_time(page.to_epoch_us, PAGE_OPERATION)?;
        let limit = i64::try_from(page.limit).unwrap_or(i64::MAX);
        let max_record_bytes = i64::try_from(page.max_record_bytes).unwrap_or(i64::MAX);
        let mut client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        let transaction = self
            .read_only(&mut client, IsolationLevel::ReadCommitted, PAGE_OPERATION)
            .await?;
        // Prepared once per pooled connection, as the audit writer's
        // statements are: a job reads up to two hundred pages.
        let statement = transaction
            .prepare_cached(PAGE_SQL)
            .await
            .map_err(|error| classify(error, PAGE_OPERATION))?;
        let params: [&(dyn tokio_postgres::types::ToSql + Sync); 6] = [
            &page.after_id,
            &page.through_id,
            &from,
            &to,
            &limit,
            &max_record_bytes,
        ];
        let read = {
            let stream = transaction
                .query_raw(&statement, params)
                .await
                .map_err(|error| classify(error, PAGE_OPERATION))?;
            let mut stream = std::pin::pin!(stream);
            let mut read = Vec::new();
            let mut page_bytes = 0_usize;
            // Rows are taken as they arrive. Once the page's byte budget is
            // spent the stream is dropped -- here, before the commit, which
            // could not complete behind a result nobody is reading -- and
            // the rows after it are discarded unread.
            while let Some(row) = stream
                .try_next()
                .await
                .map_err(|error| classify(error, PAGE_OPERATION))?
            {
                let position: i64 = column(&row, 0, PAGE_OPERATION)?;
                let record_bytes =
                    usize::try_from(column::<i64>(&row, 10, PAGE_OPERATION)?).unwrap_or(usize::MAX);
                if record_bytes > page.max_record_bytes {
                    read.push((position, ReplayRow::Oversized));
                    continue;
                }
                if !read.is_empty() && page_bytes.saturating_add(record_bytes) > page.max_page_bytes
                {
                    break;
                }
                page_bytes = page_bytes.saturating_add(record_bytes);
                read.push((position, replay_row(&row)?));
            }
            read
        };
        transaction
            .commit()
            .await
            .map_err(|error| classify(error, PAGE_OPERATION))?;
        Ok(read)
    }

    /// What the stream holds of `scope`'s window now: how many of its rows
    /// at or below the cutoff are stored, and whether any stream position
    /// the window's rows may have occupied is missing (module docs). One
    /// repeatable-read snapshot answers both.
    pub(crate) async fn check_window(
        &self,
        scope: &ReplayScope,
    ) -> Result<ReplaySourceCheck, RepositoryError> {
        let from = epoch_time(scope.from_epoch_us, CHECK_OPERATION)?;
        let to = epoch_time(scope.to_epoch_us, CHECK_OPERATION)?;
        let high_water = scope.cutoff.high_water;
        let mut client = checkout(&self.pool, CheckoutClass::PolicyReplay).await?;
        let transaction = self
            .read_only(&mut client, IsolationLevel::RepeatableRead, CHECK_OPERATION)
            .await?;
        let row = transaction
            .query_one(CHECK_SQL, &[&from, &to, &high_water])
            .await
            .map_err(|error| classify(error, CHECK_OPERATION))?;
        let before: Option<i64> = column(&row, 0, CHECK_OPERATION)?;
        let after: Option<i64> = column(&row, 1, CHECK_OPERATION)?;
        let stored: i64 = column(&row, 2, CHECK_OPERATION)?;
        let pruned = match bracketed_span(&scope.cutoff, before, after) {
            None => false,
            Some((low, high)) => {
                let present_row = transaction
                    .query_one(PRESENT_SQL, &[&low, &high])
                    .await
                    .map_err(|error| classify(error, CHECK_OPERATION))?;
                let present: i64 = column(&present_row, 0, CHECK_OPERATION)?;
                present < high.saturating_sub(low).saturating_add(1)
            }
        };
        transaction
            .commit()
            .await
            .map_err(|error| classify(error, CHECK_OPERATION))?;
        Ok(ReplaySourceCheck {
            stored: u64::try_from(stored).unwrap_or(0),
            pruned,
        })
    }

    /// A read-only transaction under the replay's own timeouts. Dropped
    /// without a commit, it rolls back: `Transaction`'s `Drop` queues the
    /// `ROLLBACK`, so a cancelled read never returns its connection to the
    /// pool mid-transaction.
    async fn read_only<'a>(
        &self,
        client: &'a mut deadpool_postgres::Object,
        isolation: IsolationLevel,
        operation: &'static str,
    ) -> Result<deadpool_postgres::Transaction<'a>, RepositoryError> {
        let transaction = client
            .build_transaction()
            .isolation_level(isolation)
            .read_only(true)
            .start()
            .await
            .map_err(|error| classify(error, operation))?;
        transaction
            .batch_execute(&self.timeouts.set_local())
            .await
            .map_err(|error| classify(error, operation))?;
        Ok(transaction)
    }
}

impl ReplaySource for PostgresReplayReader {
    fn kind(&self) -> &'static str {
        CLUSTER_REPLAY_SOURCE_KIND
    }

    fn page(&self, query: &ReplayPageQuery) -> Result<Vec<(i64, ReplayRow)>, ReplaySourceError> {
        self.runtime.block_on(self.read_page(query)).map_err(|error| {
            tracing::error!(error = %error, "policy replay could not read a page of the cluster audit stream");
            ReplaySourceError
        })
    }

    fn check(&self, scope: &ReplayScope) -> Result<ReplaySourceCheck, ReplaySourceError> {
        self.runtime.block_on(self.check_window(scope)).map_err(|error| {
            tracing::error!(error = %error, "policy replay could not check its cluster audit window");
            ReplaySourceError
        })
    }
}

/// The stream positions that must all still be stored for the window to be
/// whole, or `None` when the stream had assigned none at the cutoff: from
/// the newest retained event before the window (position 1 when there is
/// none) to the oldest retained event after it (the cutoff when there is
/// none), widened to cover every position the cutoff selected and both
/// bracketing events whatever order they were committed in.
fn bracketed_span(
    cutoff: &ReplayCutoff,
    before: Option<i64>,
    after: Option<i64>,
) -> Option<(i64, i64)> {
    if cutoff.high_water < 1 {
        return None;
    }
    let mut low = before.unwrap_or(1);
    let mut high = after.unwrap_or(cutoff.high_water);
    for position in [before, after, cutoff.first_id, cutoff.last_id]
        .into_iter()
        .flatten()
    {
        low = low.min(position);
        high = high.max(position);
    }
    let (low, high) = (low.max(1), high.min(cutoff.high_water));
    (low <= high).then_some((low, high))
}

/// A window bound in audit epoch microseconds as the timestamp PostgreSQL
/// compares `occurred_at` with, exactly: the driver sends microseconds.
fn epoch_time(epoch_us: i64, operation: &'static str) -> Result<SystemTime, RepositoryError> {
    let magnitude = Duration::from_micros(epoch_us.unsigned_abs());
    let time = if epoch_us >= 0 {
        UNIX_EPOCH.checked_add(magnitude)
    } else {
        UNIX_EPOCH.checked_sub(magnitude)
    };
    time.ok_or_else(|| RepositoryError::new(RepositoryErrorKind::InvalidData, operation))
}

/// Rebuild the stored event of one page row, strictly: an actor or payload
/// that is not the JSON the audit sink writes is [`ReplayRow::Unreadable`],
/// never a guess at what it meant. The adapters judge everything else.
fn replay_row(row: &tokio_postgres::Row) -> Result<ReplayRow, RepositoryError> {
    let event_id: String = column(row, 1, PAGE_OPERATION)?;
    let actor_json: Option<String> = column(row, 8, PAGE_OPERATION)?;
    let payload_json: Option<String> = column(row, 9, PAGE_OPERATION)?;
    let actor = match actor_json.as_deref().map(serde_json::from_str::<Actor>) {
        None => None,
        Some(Ok(actor)) => Some(actor),
        Some(Err(_)) => return Ok(ReplayRow::Unreadable),
    };
    let Some(Ok(payload)) = payload_json
        .as_deref()
        .map(serde_json::from_str::<serde_json::Value>)
    else {
        return Ok(ReplayRow::Unreadable);
    };
    Ok(ReplayRow::Event(Box::new(AuditEvent {
        event_id,
        event_type: column(row, 2, PAGE_OPERATION)?,
        timestamp: column(row, 3, PAGE_OPERATION)?,
        schema_version: column(row, 4, PAGE_OPERATION)?,
        request_id: column(row, 5, PAGE_OPERATION)?,
        source_ip: column(row, 6, PAGE_OPERATION)?,
        user_agent: column(row, 7, PAGE_OPERATION)?,
        actor,
        payload,
    })))
}

/// Read one column; a row that does not decode is data this binary cannot
/// use (`InvalidData`), never a panic. The driver's decode error names the
/// column's type, not its value.
fn column<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    index: usize,
    operation: &'static str,
) -> Result<T, RepositoryError> {
    row.try_get(index).map_err(|error| {
        tracing::error!(operation, column = index, error = %error, "replay row failed to decode");
        RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
    })
}

/// Classify a statement failure, logging the driver's detail at its site.
fn classify(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

#[cfg(test)]
#[path = "postgres_audit_replay_tests.rs"]
mod tests;
