//! PostgreSQL authority-event journal and delivery cursor (issue #425, PR 3).
//!
//! Migration 21 adds three tables beside the evidence tables of migrations 16
//! and 18 (and, since migration 26, migration 19's admin session evidence):
//!
//! - `authority_event_journal`: one row per committed evidence row, appended
//!   by the producer in the evidence row's own transaction, naming the
//!   evidence table and carrying its `event_id`. Identifiers only.
//! - `authority_event_state`: the singleton that assigns journal positions,
//!   counts retained rows against the configured capacity, and holds the
//!   persisted `authority_id`.
//! - `authority_event_cursors`: the dispatcher's durable consumer cursor and
//!   the execution-lease fence it was last advanced under.
//!
//! The protocol, in the order the pieces meet:
//!
//! 1. **Append** ([`append_to_journal`]). One statement inside the producer's
//!    transaction updates the state row -- reserving the next position and
//!    one unit of capacity, and only while `retained_events < capacity` --
//!    and inserts the journal row at that position. The state row lock is
//!    held until the producer commits or rolls back, so position order is
//!    commit order and the committed journal is gapless. A full journal
//!    reserves nothing and the producer's whole mutation rolls back: no
//!    accepted event is ever evicted to admit a new one.
//!
//!    Admin sessions (migration 26) append in the statement that writes
//!    their evidence (`storage::postgres_admin_sessions`), with one
//!    difference: a withdrawal must never be refused for capacity. So a
//!    grant takes two units, one for its own event and one *held* for its
//!    withdrawal (`reserved_withdrawals`), and only while
//!    `retained_events + 2 <= capacity`; a withdrawal spends its grant's
//!    held unit and checks no capacity. `retained_events` counts the units
//!    in use, the retained rows plus the held units, so the append above can
//!    never spend a unit a session holds.
//! 2. **Claim** ([`PostgresAuthorityEventStore::claim`]). A replica that took
//!    the dispatcher's execution lease raises the cursor's fence to the
//!    lease's fence (never lowering it) and learns the committed position.
//! 3. **Read** ([`PostgresAuthorityEventStore::read_after`]). A bounded batch
//!    of journal rows after the cursor, each joined to its evidence row.
//! 4. **Advance** ([`PostgresAuthorityEventStore::advance`]). After a sink
//!    accepted the batch, a compare-and-set on `(fence, position)` moves the
//!    cursor. A fenced-out leader's advance matches no row. A crash between
//!    acceptance and the advance means the next leader delivers the batch
//!    again under the same event IDs: delivery is at least once.
//! 5. **Retention** ([`PostgresAuthorityEventStore::prune_with`]). The
//!    maintenance singleton deletes journal rows at or below every cursor and
//!    older than the retention window, decrementing `retained_events` in the
//!    same statement. It never touches an evidence table.
//!
//! Lock order: a producer has already taken its own store's locks and the
//! shared `security_revision_state` row when it appends, and the state row
//! is the last row it locks. Retention, the claim, the advance and the
//! capacity update each lock at most the state row or the cursor row and
//! nothing a producer holds, so no cycle can form.
//!
//! Errors carry a classification and a static operation label only.

use std::time::Duration;

use uuid::Uuid;

use super::{
    log_classified,
    postgres::{checkout, timed_operation, CheckoutClass},
    RepositoryError, RepositoryErrorKind,
};

const OPERATION_CONFIGURE: &str = "authority_event_configure";
const OPERATION_AUTHORITY_ID: &str = "authority_event_authority_id";
const OPERATION_CLAIM: &str = "authority_event_cursor_claim";
const OPERATION_READ: &str = "authority_event_journal_read";
const OPERATION_ADVANCE: &str = "authority_event_cursor_advance";
const OPERATION_STATS: &str = "authority_event_journal_stats";
const OPERATION_RETENTION: &str = "authority_event_retention_prune";

/// The operation label a producer reports a refused or failed journal
/// append under.
pub(crate) const OPERATION_JOURNAL_APPEND: &str = "authority_event_journal_append";

/// The one consumer of this slice. The cursor table's CHECK holds the same
/// closed vocabulary.
pub(crate) const DISPATCHER_CONSUMER: &str = "dispatcher";

/// The bound on one retention step and the scan window it draws from, as
/// for audit retention: the step's cost is bounded by the step, never by
/// the backlog.
const MAX_RETENTION_BATCH: u32 = 10_000;
const RETENTION_SCAN_FACTOR: i64 = 10;

/// The most journal rows one read returns.
pub(crate) const MAX_READ_BATCH: usize = 1_000;

/// Which evidence table a journal row indexes. The values are the table
/// names, and migration 26's CHECK holds the same closed list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JournalSource {
    ConnectionChange,
    ServiceTokenChange,
    JwtRevocation,
    /// Migration 19's admin session grants and withdrawals, journaled since
    /// migration 26.
    AdminSession,
}

impl JournalSource {
    pub(crate) const ALL: [Self; 4] = [
        Self::ConnectionChange,
        Self::ServiceTokenChange,
        Self::JwtRevocation,
        Self::AdminSession,
    ];

    pub(crate) const fn table(self) -> &'static str {
        match self {
            Self::ConnectionChange => "connection_change_evidence",
            Self::ServiceTokenChange => "service_token_change_evidence",
            Self::JwtRevocation => "jwt_revocation_evidence",
            Self::AdminSession => "admin_session_evidence",
        }
    }

    fn from_table(table: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|source| source.table() == table)
    }
}

/// Why a producer's journal append did not happen.
#[derive(Debug)]
pub(crate) enum JournalAppendError {
    /// The journal holds `capacity` retained events. Nothing was reserved;
    /// the producer must roll its mutation back.
    CapacityExhausted,
    /// The statement failed. The producer classifies it as it classifies its
    /// own statements.
    Store(tokio_postgres::Error),
}

/// Reserve the next position and one unit of capacity, and journal one
/// evidence row at that position, inside the caller's transaction. `$1` is
/// the evidence row's `event_id`, `$2` its table.
///
/// The update matches no row when the journal is full, so nothing is
/// inserted and the statement reports zero rows. (The state row is seeded
/// by migration 21 and never deleted; a schema without it fails the same
/// way, closed.)
const APPEND_SQL: &str = r#"
WITH reserved AS (
    UPDATE greengateway.authority_event_state
    SET last_position = last_position + 1,
        retained_events = retained_events + 1
    WHERE singleton AND retained_events < capacity
    RETURNING last_position
)
INSERT INTO greengateway.authority_event_journal (position, event_id, source)
SELECT reserved.last_position, $1::text::uuid, $2 FROM reserved
"#;

/// Journal one evidence row inside the producer's transaction, which has
/// already inserted the evidence row with `event_id`. A refusal or a failed
/// statement is counted once here, so every producer reports both the same
/// way.
pub(crate) async fn append_to_journal(
    client: &tokio_postgres::Client,
    source: JournalSource,
    event_id: &str,
) -> Result<(), JournalAppendError> {
    let appended = match client
        .execute(APPEND_SQL, &[&event_id, &source.table()])
        .await
    {
        Ok(appended) => appended,
        Err(error) => {
            record_evidence_failure();
            return Err(JournalAppendError::Store(error));
        }
    };
    if appended == 1 {
        return Ok(());
    }
    report_capacity_refusal(source);
    Err(JournalAppendError::CapacityExhausted)
}

/// Count and log one mutation refused because the journal was full. Every
/// producer that finds no room calls this once, before it rolls back.
pub(crate) fn report_capacity_refusal(source: JournalSource) {
    record_capacity_refusal();
    tracing::warn!(
        source = source.table(),
        "authority event journal is at capacity; the change was refused and nothing was committed"
    );
}

/// Count one mutation refused because the journal was full.
pub(crate) fn record_capacity_refusal() {
    ::metrics::counter!(crate::metrics::AUTHORITY_EVENT_CAPACITY_REFUSALS_TOTAL).increment(1);
}

/// Count one mutation refused because its evidence row or journal entry
/// could not be written for a reason other than capacity. Called once per
/// refused mutation, where the evidence statement failed: the journal
/// append counts its own failures, each producer counts its evidence
/// insert's.
pub(crate) fn record_evidence_failure() {
    ::metrics::counter!(crate::metrics::AUTHORITY_EVENT_EVIDENCE_FAILURES_TOTAL).increment(1);
}

/// One journal row and the evidence row it indexes, exactly as stored.
/// Every evidence column is `None` when the evidence row is missing, which
/// the dispatcher refuses to deliver rather than skip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct JournaledEvidence {
    pub(crate) position: i64,
    pub(crate) event_id: String,
    pub(crate) source: JournalSource,
    pub(crate) operation_id: Option<String>,
    pub(crate) actor_user_id: Option<String>,
    pub(crate) action: Option<String>,
    /// The resource's owner, when it has one: the issuer of a JWT
    /// revocation's `jti` digest.
    pub(crate) resource_owner: Option<String>,
    /// The Connection ID, the token ID, the `jti` digest or the admin
    /// session ID.
    pub(crate) resource_id: Option<String>,
    pub(crate) prior_version: Option<i64>,
    pub(crate) new_version: Option<i64>,
    /// `None` for an admin session, which takes no shared revision.
    pub(crate) security_revision: Option<i64>,
    /// RFC 3339 UTC with microseconds, from the evidence row.
    pub(crate) committed_at: Option<String>,
    /// The actor's canonical issuer, kind and auth mode (migration 24). All
    /// three are `None` for evidence committed before migration 24, which
    /// recorded none of them, and for admin session evidence, which records
    /// none of them; the issuer is also `None` for an actor that has none.
    pub(crate) actor_issuer: Option<String>,
    pub(crate) actor_kind: Option<String>,
    pub(crate) actor_auth_mode: Option<String>,
}

/// The journal and the cursor, as one read sees them.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct JournalStats {
    /// The units of capacity in use: retained rows plus the units held for
    /// admin session withdrawals.
    pub(crate) retained: i64,
    /// Of those, the units held for the withdrawal of every admin session
    /// granted and not yet withdrawn (migration 26).
    pub(crate) reserved: i64,
    pub(crate) capacity: i64,
    /// The last position ever assigned.
    pub(crate) head: i64,
    /// The dispatcher's committed position, when it has ever claimed.
    pub(crate) cursor: Option<i64>,
    /// The lowest retained position.
    pub(crate) first_retained: Option<i64>,
    /// How long the oldest retained row above the cursor has waited.
    pub(crate) oldest_undelivered_age_secs: Option<f64>,
}

impl JournalStats {
    /// Retained rows above the cursor (every retained row before the first
    /// claim). Never negative, whatever order the values were read in.
    pub(crate) fn undelivered(&self) -> i64 {
        let Some(first) = self.first_retained else {
            return 0;
        };
        let delivered_through = self.cursor.unwrap_or(0).max(first.saturating_sub(1));
        self.head.saturating_sub(delivered_through).max(0)
    }
}

/// The dispatcher's store: the cursor, the journal reads, and the state the
/// journal's metrics come from. Cheap to construct.
pub struct PostgresAuthorityEventStore {
    pool: deadpool_postgres::Pool,
}

impl PostgresAuthorityEventStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }

    /// Apply the configured capacity. Called by every replica at startup;
    /// replicas agree on the value because it is fingerprinted. A capacity
    /// below the units in use admits no new event until retention frees
    /// room; admin session withdrawals are still recorded.
    pub async fn configure_capacity(&self, capacity: u64) -> Result<(), RepositoryError> {
        let capacity = i64::try_from(capacity)
            .map_err(|_| RepositoryError::invalid_parameter(OPERATION_CONFIGURE, "capacity"))?;
        let client = checkout(&self.pool, CheckoutClass::Maintenance).await?;
        timed_operation(OPERATION_CONFIGURE, async {
            let updated = client
                .execute(
                    "UPDATE greengateway.authority_event_state SET capacity = $1 WHERE singleton",
                    &[&capacity],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_CONFIGURE))?;
            if updated == 1 {
                Ok(())
            } else {
                Err(invalid_data(OPERATION_CONFIGURE))
            }
        })
        .await
    }

    /// The persisted authority ID, written once from `candidate` by the
    /// first caller and returned unchanged to every later one.
    pub async fn authority_id(&self, candidate: Uuid) -> Result<Uuid, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::Maintenance).await?;
        timed_operation(OPERATION_AUTHORITY_ID, async {
            let candidate = candidate.to_string();
            let row = client
                .query_opt(
                    "UPDATE greengateway.authority_event_state \
                     SET authority_id = coalesce(authority_id, $1::text::uuid) \
                     WHERE singleton RETURNING authority_id::text",
                    &[&candidate],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_AUTHORITY_ID))?
                .ok_or_else(|| invalid_data(OPERATION_AUTHORITY_ID))?;
            let stored: String = column(&row, 0, OPERATION_AUTHORITY_ID)?;
            Uuid::parse_str(&stored).map_err(|_| invalid_data(OPERATION_AUTHORITY_ID))
        })
        .await
    }

    /// Take the cursor for a dispatcher term at `fence`, returning the
    /// committed position to resume after. A cursor held at a higher fence
    /// (or at this fence by another holder) refuses the claim as
    /// `Conflict`: this lease is stale. The first claim creates the cursor at
    /// position 0, so every retained event is delivered.
    pub async fn claim(&self, fence: i64, holder: Uuid) -> Result<i64, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::ExecutionLease).await?;
        timed_operation(OPERATION_CLAIM, async {
            let holder = holder.to_string();
            let row = client
                .query_opt(
                    r#"
                    INSERT INTO greengateway.authority_event_cursors AS c
                        (consumer, position, fence, holder)
                    VALUES ($1, 0, $2, $3::text::uuid)
                    ON CONFLICT (consumer) DO UPDATE
                    SET fence = EXCLUDED.fence, holder = EXCLUDED.holder, claimed_at = now()
                    WHERE c.fence < EXCLUDED.fence
                       OR (c.fence = EXCLUDED.fence AND c.holder = EXCLUDED.holder)
                    RETURNING c.position
                    "#,
                    &[&DISPATCHER_CONSUMER, &fence, &holder],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_CLAIM))?;
            match row {
                Some(row) => column(&row, 0, OPERATION_CLAIM),
                None => Err(RepositoryError::new(
                    RepositoryErrorKind::Conflict,
                    OPERATION_CLAIM,
                )),
            }
        })
        .await
    }

    /// Up to `limit` journal rows after `position`, oldest first, each with
    /// its evidence row. Positions are commit-ordered and gapless, so a read
    /// after the cursor never skips an event that commits later.
    pub(crate) async fn read_after(
        &self,
        position: i64,
        limit: usize,
    ) -> Result<Vec<JournaledEvidence>, RepositoryError> {
        let limit = i64::try_from(limit.clamp(1, MAX_READ_BATCH)).unwrap_or(1);
        let client = checkout(&self.pool, CheckoutClass::Maintenance).await?;
        timed_operation(OPERATION_READ, async {
            let rows = client
                .query(READ_AFTER_SQL, &[&position, &limit])
                .await
                .map_err(|error| classify_query(error, OPERATION_READ))?;
            rows.iter().map(journaled_evidence_from_row).collect()
        })
        .await
    }

    /// Move the cursor from `from` to `to` after a sink accepted the events
    /// between them, at `fence`. A cursor at another fence or another
    /// position refuses the advance as `Conflict`, and nothing changes. An
    /// identical retry of an advance whose commit the caller never heard
    /// about succeeds without counting the batch twice.
    pub async fn advance(
        &self,
        fence: i64,
        from: i64,
        to: i64,
        delivered: i64,
    ) -> Result<(), RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::Maintenance).await?;
        timed_operation(OPERATION_ADVANCE, async {
            let updated = client
                .execute(
                    r#"
                    UPDATE greengateway.authority_event_cursors
                    SET position = $4::bigint,
                        delivered_events = delivered_events
                            + CASE WHEN position = $3::bigint THEN $5::bigint ELSE 0 END,
                        advanced_at = now()
                    WHERE consumer = $1 AND fence = $2::bigint
                      AND (position = $3::bigint OR position = $4::bigint)
                    "#,
                    &[&DISPATCHER_CONSUMER, &fence, &from, &to, &delivered],
                )
                .await
                .map_err(|error| classify_query(error, OPERATION_ADVANCE))?;
            if updated == 1 {
                Ok(())
            } else {
                Err(RepositoryError::new(
                    RepositoryErrorKind::Conflict,
                    OPERATION_ADVANCE,
                ))
            }
        })
        .await
    }

    /// The journal's size, capacity, head, the cursor and the age of the
    /// oldest undelivered row, in one statement.
    pub(crate) async fn stats(&self) -> Result<JournalStats, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::Maintenance).await?;
        timed_operation(OPERATION_STATS, async { read_stats(&client).await }).await
    }

    /// One bounded retention step on the caller's session (the maintenance
    /// singleton's dedicated connection): delete up to `limit` journal rows
    /// at or below every cursor's position and journaled at least
    /// `retention` ago on the database clock, lowest positions first, and
    /// give their capacity back. Before any cursor exists, age alone decides.
    /// The candidates come from a window of `limit x RETENTION_SCAN_FACTOR`
    /// rows walked by primary key, so the step never scans the backlog.
    pub(crate) async fn prune_with(
        client: &tokio_postgres::Client,
        retention: Duration,
        limit: u32,
    ) -> Result<u64, RepositoryError> {
        let retention_secs = retention.as_secs_f64();
        let limit = i64::from(limit.clamp(1, MAX_RETENTION_BATCH));
        let window = limit.saturating_mul(RETENTION_SCAN_FACTOR);
        let row = client
            .query_opt(PRUNE_SQL, &[&retention_secs, &limit, &window])
            .await
            .map_err(|error| classify_query(error, OPERATION_RETENTION))?
            .ok_or_else(|| invalid_data(OPERATION_RETENTION))?;
        let deleted: i64 = column(&row, 0, OPERATION_RETENTION)?;
        Ok(u64::try_from(deleted).unwrap_or(0))
    }

    /// [`Self::stats`] on the caller's session.
    pub(crate) async fn stats_with(
        client: &tokio_postgres::Client,
    ) -> Result<JournalStats, RepositoryError> {
        read_stats(client).await
    }
}

/// `$1` the cursor position, `$2` the row limit. Every evidence join is
/// keyed on the journal row's own table, so a row joins at most one
/// evidence row; the evidence tables' primary keys are their event IDs.
/// Admin session evidence names the session's own identity as its actor
/// and records no actor kind, auth mode, version or shared revision, so
/// those columns stay empty for it.
const READ_AFTER_SQL: &str = r#"
SELECT j.position,
       j.event_id::text,
       j.source,
       coalesce(c.operation_id, t.operation_id, r.operation_id, a.operation_id)::text,
       coalesce(c.actor_user_id, t.actor_user_id, r.actor_user_id, a.user_id),
       coalesce(c.action, t.action, r.action, a.action),
       r.issuer,
       coalesce(c.connection_id::text, t.token_id, r.jti_hash, a.session_id::text),
       coalesce(c.prior_version, t.prior_version),
       t.new_version,
       coalesce(c.security_revision, t.security_revision, r.security_revision),
       to_char(coalesce(c.committed_at, t.committed_at, r.committed_at, a.committed_at)
                   AT TIME ZONE 'UTC',
               'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
       coalesce(c.actor_issuer, t.actor_issuer, r.actor_issuer),
       coalesce(c.actor_kind, t.actor_kind, r.actor_kind),
       coalesce(c.actor_auth_mode, t.actor_auth_mode, r.actor_auth_mode)
FROM greengateway.authority_event_journal j
LEFT JOIN greengateway.connection_change_evidence c
    ON j.source = 'connection_change_evidence' AND c.event_id = j.event_id
LEFT JOIN greengateway.service_token_change_evidence t
    ON j.source = 'service_token_change_evidence' AND t.event_id = j.event_id
LEFT JOIN greengateway.jwt_revocation_evidence r
    ON j.source = 'jwt_revocation_evidence' AND r.event_id = j.event_id
LEFT JOIN greengateway.admin_session_evidence a
    ON j.source = 'admin_session_evidence' AND a.event_id = j.event_id
WHERE j.position > $1
ORDER BY j.position
LIMIT $2
"#;

const STATS_SQL: &str = r#"
SELECT s.retained_events,
       s.reserved_withdrawals,
       s.capacity,
       s.last_position,
       c.position,
       (SELECT min(j.position) FROM greengateway.authority_event_journal j),
       (SELECT greatest(extract(epoch FROM (now() - j.journaled_at)), 0)::double precision
        FROM greengateway.authority_event_journal j
        WHERE j.position > coalesce(c.position, 0)
        ORDER BY j.position
        LIMIT 1)
FROM greengateway.authority_event_state s
LEFT JOIN greengateway.authority_event_cursors c ON c.consumer = 'dispatcher'
WHERE s.singleton
"#;

/// `$1` retention seconds, `$2` the row limit, `$3` the scan window. The
/// floor is the lowest cursor position; with no cursor there is none.
const PRUNE_SQL: &str = r#"
WITH floor AS (
    SELECT min(position) AS position FROM greengateway.authority_event_cursors
),
candidates AS (
    SELECT j.position, j.journaled_at
    FROM greengateway.authority_event_journal j
    WHERE (SELECT position FROM floor) IS NULL
       OR j.position <= (SELECT position FROM floor)
    ORDER BY j.position
    LIMIT $3
),
doomed AS (
    SELECT position FROM candidates
    WHERE journaled_at <= now() - make_interval(secs => $1::double precision)
    ORDER BY position
    LIMIT $2
),
deleted AS (
    DELETE FROM greengateway.authority_event_journal j
    USING doomed
    WHERE j.position = doomed.position
    RETURNING j.position
)
UPDATE greengateway.authority_event_state
SET retained_events = retained_events - (SELECT count(*) FROM deleted)
WHERE singleton
RETURNING (SELECT count(*) FROM deleted)::bigint
"#;

async fn read_stats(client: &tokio_postgres::Client) -> Result<JournalStats, RepositoryError> {
    let row = client
        .query_opt(STATS_SQL, &[])
        .await
        .map_err(|error| classify_query(error, OPERATION_STATS))?
        .ok_or_else(|| invalid_data(OPERATION_STATS))?;
    Ok(JournalStats {
        retained: column(&row, 0, OPERATION_STATS)?,
        reserved: column(&row, 1, OPERATION_STATS)?,
        capacity: column(&row, 2, OPERATION_STATS)?,
        head: column(&row, 3, OPERATION_STATS)?,
        cursor: column(&row, 4, OPERATION_STATS)?,
        first_retained: column(&row, 5, OPERATION_STATS)?,
        oldest_undelivered_age_secs: column(&row, 6, OPERATION_STATS)?,
    })
}

fn journaled_evidence_from_row(
    row: &tokio_postgres::Row,
) -> Result<JournaledEvidence, RepositoryError> {
    let source: String = column(row, 2, OPERATION_READ)?;
    Ok(JournaledEvidence {
        position: column(row, 0, OPERATION_READ)?,
        event_id: column(row, 1, OPERATION_READ)?,
        source: JournalSource::from_table(&source).ok_or_else(|| invalid_data(OPERATION_READ))?,
        operation_id: column(row, 3, OPERATION_READ)?,
        actor_user_id: column(row, 4, OPERATION_READ)?,
        action: column(row, 5, OPERATION_READ)?,
        resource_owner: column(row, 6, OPERATION_READ)?,
        resource_id: column(row, 7, OPERATION_READ)?,
        prior_version: column(row, 8, OPERATION_READ)?,
        new_version: column(row, 9, OPERATION_READ)?,
        security_revision: column(row, 10, OPERATION_READ)?,
        committed_at: column(row, 11, OPERATION_READ)?,
        actor_issuer: column(row, 12, OPERATION_READ)?,
        actor_kind: column(row, 13, OPERATION_READ)?,
        actor_auth_mode: column(row, 14, OPERATION_READ)?,
    })
}

fn column<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    index: usize,
    operation: &'static str,
) -> Result<T, RepositoryError> {
    row.try_get(index).map_err(|error| {
        tracing::error!(operation, column = index, error = %error, "authority event row did not decode");
        invalid_data(operation)
    })
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The source vocabulary is migration 26's CHECK, value for value, and
    /// every value round-trips.
    #[test]
    fn the_journal_sources_are_the_migrations_closed_vocabulary() {
        let journal = include_str!("migrations/0021_authority_event_journal.sql");
        let migration = include_str!("migrations/0026_admin_session_evidence_journal.sql");
        let (_, check) = migration
            .split_once("ADD CONSTRAINT authority_event_journal_source_check CHECK (")
            .expect("migration 26 replaces the source CHECK");
        let (check, _) = check.split_once(");").expect("the CHECK ends");
        assert_eq!(
            check.matches("_evidence'").count(),
            JournalSource::ALL.len(),
            "{check}"
        );
        for source in JournalSource::ALL {
            assert!(
                check.contains(&format!("'{}'", source.table())),
                "migration 26 must allow {}",
                source.table()
            );
            assert_eq!(JournalSource::from_table(source.table()), Some(source));
        }
        assert_eq!(JournalSource::from_table("security_outbox"), None);
        assert!(journal.contains(&format!("consumer IN ('{DISPATCHER_CONSUMER}')")));
    }

    /// Undelivered is the distance from the cursor (or, before the first
    /// claim, from below the oldest retained row) to the head, and it never
    /// goes negative when the values were read at different instants.
    #[test]
    fn undelivered_counts_retained_rows_above_the_cursor() {
        let empty = JournalStats::default();
        assert_eq!(empty.undelivered(), 0);

        let unclaimed = JournalStats {
            retained: 4,
            head: 10,
            first_retained: Some(7),
            ..JournalStats::default()
        };
        assert_eq!(unclaimed.undelivered(), 4);

        let claimed = JournalStats {
            cursor: Some(8),
            ..unclaimed
        };
        assert_eq!(claimed.undelivered(), 2);

        let caught_up = JournalStats {
            cursor: Some(10),
            ..unclaimed
        };
        assert_eq!(caught_up.undelivered(), 0);

        let raced = JournalStats {
            cursor: Some(12),
            ..unclaimed
        };
        assert_eq!(raced.undelivered(), 0);
    }
}
