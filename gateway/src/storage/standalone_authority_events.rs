//! Standalone authority-event delivery state (issue #425).
//!
//! Standalone mode has no journal. Each SQLite store that owns an authority
//! already keeps that authority's change evidence in tables whose `sequence`
//! is an `AUTOINCREMENT` assigned while the writer holds the file's write
//! lock, so within one table sequence order is commit order, a committed
//! sequence is never reused, and no sequence below a committed one can still
//! commit later. Delivery therefore reads the evidence tables themselves,
//! after a cursor kept in the same file, and never copies a row anywhere
//! inside the authority's transaction:
//!
//! - `authority_event_state` holds the file's persisted `authority_id`,
//!   written once by the first dispatcher start ([`authority_id`]) and never
//!   changed. Each owning store is its own evidence authority: the token
//!   database and the Connections database derive their references under
//!   different authority IDs, and a consumer deduplicates on
//!   `(authority_id, event_id)`.
//! - `authority_event_cursors` holds, per evidence table (`source`), the last
//!   sequence a sink accepted and how many events it accepted in total.
//!
//! The owning store creates both tables: the token store in its open-time
//! schema, the Connections store in its migration 14. They have one
//! definition ([`AUTHORITY_EVENT_TABLES_SQL`]), so a token store and a
//! Connections store pointed at the same file share one authority and keep
//! one cursor per table.
//!
//! The protocol: [`open_cursor`] creates the cursor at position 0 the first
//! time, so every retained row is delivered; [`read_after`] returns a bounded
//! batch of rows after it; once the sink accepted them [`advance`] moves the
//! cursor with a compare-and-set in an IMMEDIATE transaction. A process that
//! dies between acceptance and the advance reads the same rows again: delivery
//! is at least once. Nothing here ever updates or deletes an evidence row.
//!
//! Errors carry a classification and a static operation label only.

use std::sync::MutexGuard;

use rusqlite::{params, Connection, TransactionBehavior};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use super::{
    classify_rusqlite, log_classified, RepositoryError, RepositoryErrorKind,
    StandaloneEvidenceStore,
};

const OPERATION_AUTHORITY_ID: &str = "standalone_authority_event_authority_id";
const OPERATION_CURSOR_OPEN: &str = "standalone_authority_event_cursor_open";
const OPERATION_READ: &str = "standalone_authority_event_evidence_read";
const OPERATION_ADVANCE: &str = "standalone_authority_event_cursor_advance";
const OPERATION_BACKLOG: &str = "standalone_authority_event_backlog";

/// The most evidence rows one read returns.
pub(crate) const MAX_READ_BATCH: usize = 1_000;

/// The delivery state both owning stores create. The `source` vocabulary is
/// [`StandaloneEvidenceSource::ALL`], value for value, so either store's
/// tables accept the other's cursors when they share a file. `IF NOT EXISTS`
/// for the same reason: whichever store opens a shared file first creates
/// the tables, and the other finds them.
pub(crate) const AUTHORITY_EVENT_TABLES_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS authority_event_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    authority_id TEXT NOT NULL CHECK (length(authority_id) = 36),
    created_at TEXT NOT NULL CHECK (length(CAST(created_at AS BLOB)) BETWEEN 1 AND 64)
);

CREATE TABLE IF NOT EXISTS authority_event_cursors (
    source TEXT PRIMARY KEY CHECK (
        source IN (
            'service_token_change_evidence', 'connection_change_evidence',
            'connection_local_secret_change_evidence', 'catalog_change_evidence'
        )
    ),
    position INTEGER NOT NULL CHECK (position >= 0),
    delivered_events INTEGER NOT NULL CHECK (delivered_events >= 0),
    advanced_at TEXT NOT NULL CHECK (length(CAST(advanced_at AS BLOB)) BETWEEN 1 AND 64)
);
"#;

/// One standalone evidence table: a source of delivered events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum StandaloneEvidenceSource {
    /// The token database's issue, rotate and revoke evidence.
    ServiceTokenChange,
    /// The Connections database's Connection create, replace, credential
    /// binding change and delete evidence (its migration 12).
    ConnectionChange,
    /// The Connections database's local-secret evidence (its migration 12).
    LocalSecretChange,
    /// The Connections database's catalog and overlay publication evidence
    /// (its migration 13).
    CatalogChange,
}

impl StandaloneEvidenceSource {
    /// Every source. Read by the tests; each store names its own.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const ALL: [Self; 4] = [
        Self::ServiceTokenChange,
        Self::ConnectionChange,
        Self::LocalSecretChange,
        Self::CatalogChange,
    ];

    /// The evidence table, which is also the cursor's `source` value.
    pub(crate) const fn table(self) -> &'static str {
        match self {
            Self::ServiceTokenChange => "service_token_change_evidence",
            Self::ConnectionChange => "connection_change_evidence",
            Self::LocalSecretChange => "connection_local_secret_change_evidence",
            Self::CatalogChange => "catalog_change_evidence",
        }
    }

    /// The store that owns the table.
    pub(crate) const fn store(self) -> StandaloneEvidenceStore {
        match self {
            Self::ServiceTokenChange => StandaloneEvidenceStore::ServiceTokens,
            Self::ConnectionChange | Self::LocalSecretChange | Self::CatalogChange => {
                StandaloneEvidenceStore::Connections
            }
        }
    }

    /// One bounded batch after `$1`, oldest first, in the one column order
    /// every source shares. A table without revision columns reads none.
    const fn read_after_sql(self) -> &'static str {
        match self {
            Self::ServiceTokenChange => {
                "SELECT sequence, event_id, operation_id, actor_user_id, actor_issuer, \
                 actor_kind, actor_auth_mode, action, token_id, NULL, NULL, committed_at \
                 FROM service_token_change_evidence \
                 WHERE sequence > ?1 ORDER BY sequence LIMIT ?2"
            }
            Self::ConnectionChange => {
                "SELECT sequence, event_id, operation_id, actor_user_id, actor_issuer, \
                 actor_kind, actor_auth_mode, action, connection_id, prior_version, \
                 new_version, committed_at \
                 FROM connection_change_evidence \
                 WHERE sequence > ?1 ORDER BY sequence LIMIT ?2"
            }
            Self::LocalSecretChange => {
                "SELECT sequence, event_id, operation_id, actor_user_id, actor_issuer, \
                 actor_kind, actor_auth_mode, action, secret_id, prior_version, \
                 new_version, committed_at \
                 FROM connection_local_secret_change_evidence \
                 WHERE sequence > ?1 ORDER BY sequence LIMIT ?2"
            }
            Self::CatalogChange => {
                "SELECT sequence, event_id, operation_id, actor_user_id, actor_issuer, \
                 actor_kind, actor_auth_mode, action, connection_id, prior_version, \
                 new_version, committed_at \
                 FROM catalog_change_evidence \
                 WHERE sequence > ?1 ORDER BY sequence LIMIT ?2"
            }
        }
    }

    /// The cursor (0 before it exists), the table's highest sequence and the
    /// commit time of the first row after the cursor, in one statement.
    const fn backlog_sql(self) -> &'static str {
        match self {
            Self::ServiceTokenChange => {
                "SELECT c.position, \
                 (SELECT coalesce(max(e.sequence), 0) FROM service_token_change_evidence e), \
                 (SELECT e.committed_at FROM service_token_change_evidence e \
                  WHERE e.sequence > c.position ORDER BY e.sequence LIMIT 1) \
                 FROM (SELECT coalesce((SELECT position FROM authority_event_cursors \
                       WHERE source = ?1), 0) AS position) c"
            }
            Self::ConnectionChange => {
                "SELECT c.position, \
                 (SELECT coalesce(max(e.sequence), 0) FROM connection_change_evidence e), \
                 (SELECT e.committed_at FROM connection_change_evidence e \
                  WHERE e.sequence > c.position ORDER BY e.sequence LIMIT 1) \
                 FROM (SELECT coalesce((SELECT position FROM authority_event_cursors \
                       WHERE source = ?1), 0) AS position) c"
            }
            Self::LocalSecretChange => {
                "SELECT c.position, \
                 (SELECT coalesce(max(e.sequence), 0) \
                  FROM connection_local_secret_change_evidence e), \
                 (SELECT e.committed_at FROM connection_local_secret_change_evidence e \
                  WHERE e.sequence > c.position ORDER BY e.sequence LIMIT 1) \
                 FROM (SELECT coalesce((SELECT position FROM authority_event_cursors \
                       WHERE source = ?1), 0) AS position) c"
            }
            Self::CatalogChange => {
                "SELECT c.position, \
                 (SELECT coalesce(max(e.sequence), 0) FROM catalog_change_evidence e), \
                 (SELECT e.committed_at FROM catalog_change_evidence e \
                  WHERE e.sequence > c.position ORDER BY e.sequence LIMIT 1) \
                 FROM (SELECT coalesce((SELECT position FROM authority_event_cursors \
                       WHERE source = ?1), 0) AS position) c"
            }
        }
    }
}

/// One evidence row exactly as stored, in the shape every source shares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StandaloneEvidence {
    pub(crate) source: StandaloneEvidenceSource,
    /// The row's commit-ordered sequence in its own table.
    pub(crate) sequence: i64,
    pub(crate) event_id: String,
    pub(crate) operation_id: String,
    pub(crate) actor_user_id: String,
    /// The actor's canonical issuer, kind and auth mode. The Connections
    /// tables require kind and auth mode; the token table has them only for
    /// rows written since its actor columns were added on open.
    pub(crate) actor_issuer: Option<String>,
    pub(crate) actor_kind: Option<String>,
    pub(crate) actor_auth_mode: Option<String>,
    pub(crate) action: String,
    /// The token ID, the Connection ID or the local secret's ID; `None` for
    /// a re-encryption batch, which names no secret.
    pub(crate) resource_id: Option<String>,
    /// The revisions on the action's axis. The token table records none.
    pub(crate) prior_version: Option<i64>,
    pub(crate) new_version: Option<i64>,
    /// The change's own process-clock RFC 3339 timestamp.
    pub(crate) committed_at: String,
}

/// How far one source's delivery is behind its table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SourceBacklog {
    /// The cursor: the last sequence a sink accepted.
    pub(crate) cursor: i64,
    /// The table's highest sequence.
    pub(crate) head: i64,
    /// The commit time of the oldest row the sink has not accepted.
    pub(crate) oldest_undelivered_committed_at: Option<String>,
}

impl SourceBacklog {
    /// Rows above the cursor. Sequences are never reused and no row is ever
    /// deleted, so the distance is the count; never negative.
    pub(crate) fn undelivered(&self) -> i64 {
        self.head.saturating_sub(self.cursor).max(0)
    }

    /// How long the oldest undelivered row has waited at `now`, when there
    /// is one and its timestamp reads; never negative.
    pub(crate) fn oldest_undelivered_age_secs(&self, now: OffsetDateTime) -> Option<f64> {
        let committed_at = self.oldest_undelivered_committed_at.as_deref()?;
        let committed_at = OffsetDateTime::parse(committed_at, &Rfc3339).ok()?;
        Some((now - committed_at).as_seconds_f64().max(0.0))
    }
}

/// An SQLite store that owns evidence tables and their delivery cursors.
/// Every method holds the store's own connection for one short statement or
/// IMMEDIATE transaction; callers run them on the blocking pool.
pub(crate) trait StandaloneEvidenceAuthority: Send + Sync {
    /// The store, for logs and metric labels.
    fn evidence_store(&self) -> StandaloneEvidenceStore;

    /// The evidence tables this store owns.
    fn evidence_sources(&self) -> &'static [StandaloneEvidenceSource];

    /// The store's connection, locked.
    fn evidence_connection(&self) -> MutexGuard<'_, Connection>;

    /// The persisted authority ID, written once from `candidate` by the
    /// first caller and returned unchanged to every later one.
    fn authority_id(&self, candidate: Uuid) -> Result<Uuid, RepositoryError> {
        authority_id(&self.evidence_connection(), candidate)
    }

    /// The committed position of `source`'s cursor, creating it at 0.
    fn open_cursor(&self, source: StandaloneEvidenceSource) -> Result<i64, RepositoryError> {
        open_cursor(&self.evidence_connection(), source)
    }

    /// Up to `limit` rows of `source` after `position`, oldest first.
    fn read_after(
        &self,
        source: StandaloneEvidenceSource,
        position: i64,
        limit: usize,
    ) -> Result<Vec<StandaloneEvidence>, RepositoryError> {
        read_after(&self.evidence_connection(), source, position, limit)
    }

    /// Move `source`'s cursor from `from` to `to` after a sink accepted the
    /// `delivered` events between them. `Conflict` when the cursor is at
    /// neither.
    fn advance(
        &self,
        source: StandaloneEvidenceSource,
        from: i64,
        to: i64,
        delivered: i64,
    ) -> Result<(), RepositoryError> {
        advance(&self.evidence_connection(), source, from, to, delivered)
    }

    /// How far `source`'s delivery is behind.
    fn backlog(&self, source: StandaloneEvidenceSource) -> Result<SourceBacklog, RepositoryError> {
        backlog(&self.evidence_connection(), source)
    }
}

/// Write `candidate` as the authority ID unless one is stored, and return
/// the stored one, in one IMMEDIATE transaction.
pub(crate) fn authority_id(
    connection: &Connection,
    candidate: Uuid,
) -> Result<Uuid, RepositoryError> {
    let now = timestamp(OPERATION_AUTHORITY_ID)?;
    let stored = immediate(connection, OPERATION_AUTHORITY_ID, |transaction| {
        transaction.execute(
            "INSERT INTO authority_event_state (singleton, authority_id, created_at) \
             VALUES (1, ?1, ?2) ON CONFLICT (singleton) DO NOTHING",
            params![candidate.to_string(), now],
        )?;
        transaction.query_row(
            "SELECT authority_id FROM authority_event_state WHERE singleton = 1",
            [],
            |row| row.get::<_, String>(0),
        )
    })?;
    Uuid::parse_str(&stored).map_err(|_| invalid_data(OPERATION_AUTHORITY_ID))
}

/// Create `source`'s cursor at position 0 unless it exists, and return its
/// committed position, in one IMMEDIATE transaction.
pub(crate) fn open_cursor(
    connection: &Connection,
    source: StandaloneEvidenceSource,
) -> Result<i64, RepositoryError> {
    let now = timestamp(OPERATION_CURSOR_OPEN)?;
    immediate(connection, OPERATION_CURSOR_OPEN, |transaction| {
        transaction.execute(
            "INSERT INTO authority_event_cursors (source, position, delivered_events, advanced_at) \
             VALUES (?1, 0, 0, ?2) ON CONFLICT (source) DO NOTHING",
            params![source.table(), now],
        )?;
        transaction.query_row(
            "SELECT position FROM authority_event_cursors WHERE source = ?1",
            params![source.table()],
            |row| row.get(0),
        )
    })
}

/// Up to `limit` rows of `source` after `position`, oldest first. One
/// statement reads one snapshot, and a sequence above every committed one
/// is assigned only to a later commit, so a read after the cursor never
/// skips a row that commits afterwards.
pub(crate) fn read_after(
    connection: &Connection,
    source: StandaloneEvidenceSource,
    position: i64,
    limit: usize,
) -> Result<Vec<StandaloneEvidence>, RepositoryError> {
    let limit = i64::try_from(limit.clamp(1, MAX_READ_BATCH)).unwrap_or(1);
    let read = || -> rusqlite::Result<Vec<StandaloneEvidence>> {
        let mut statement = connection.prepare(source.read_after_sql())?;
        let rows = statement.query_map(params![position, limit], |row| {
            Ok(StandaloneEvidence {
                source,
                sequence: row.get(0)?,
                event_id: row.get(1)?,
                operation_id: row.get(2)?,
                actor_user_id: row.get(3)?,
                actor_issuer: row.get(4)?,
                actor_kind: row.get(5)?,
                actor_auth_mode: row.get(6)?,
                action: row.get(7)?,
                resource_id: row.get(8)?,
                prior_version: row.get(9)?,
                new_version: row.get(10)?,
                committed_at: row.get(11)?,
            })
        })?;
        rows.collect()
    };
    read().map_err(|error| failure(OPERATION_READ, &error))
}

/// Move `source`'s cursor from `from` to `to`, counting `delivered` events
/// once, in one IMMEDIATE transaction. A cursor already at `to` -- the
/// retry of an advance whose commit the caller never heard about --
/// succeeds without counting the batch twice; a cursor at any other
/// position is `Conflict`, and nothing changes.
pub(crate) fn advance(
    connection: &Connection,
    source: StandaloneEvidenceSource,
    from: i64,
    to: i64,
    delivered: i64,
) -> Result<(), RepositoryError> {
    let now = timestamp(OPERATION_ADVANCE)?;
    let updated = immediate(connection, OPERATION_ADVANCE, |transaction| {
        transaction.execute(
            "UPDATE authority_event_cursors \
             SET position = ?3, \
                 delivered_events = delivered_events \
                     + CASE WHEN position = ?2 THEN ?4 ELSE 0 END, \
                 advanced_at = ?5 \
             WHERE source = ?1 AND (position = ?2 OR position = ?3)",
            params![source.table(), from, to, delivered, now],
        )
    })?;
    if updated == 1 {
        Ok(())
    } else {
        Err(RepositoryError::new(
            RepositoryErrorKind::Conflict,
            OPERATION_ADVANCE,
        ))
    }
}

/// `source`'s cursor, head and oldest undelivered commit time. Before the
/// cursor exists every row is undelivered.
pub(crate) fn backlog(
    connection: &Connection,
    source: StandaloneEvidenceSource,
) -> Result<SourceBacklog, RepositoryError> {
    connection
        .query_row(source.backlog_sql(), params![source.table()], |row| {
            Ok(SourceBacklog {
                cursor: row.get(0)?,
                head: row.get(1)?,
                oldest_undelivered_committed_at: row.get(2)?,
            })
        })
        .map_err(|error| failure(OPERATION_BACKLOG, &error))
}

/// Run `work` in one IMMEDIATE transaction on `connection`, which is held
/// for the store by the caller's lock.
fn immediate<T>(
    connection: &Connection,
    operation: &'static str,
    work: impl FnOnce(&rusqlite::Transaction<'_>) -> rusqlite::Result<T>,
) -> Result<T, RepositoryError> {
    let run = || -> rusqlite::Result<T> {
        let transaction =
            rusqlite::Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
        let value = work(&transaction)?;
        transaction.commit()?;
        Ok(value)
    };
    run().map_err(|error| failure(operation, &error))
}

fn timestamp(operation: &'static str) -> Result<String, RepositoryError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| RepositoryError::new(RepositoryErrorKind::Internal, operation))
}

fn failure(operation: &'static str, error: &rusqlite::Error) -> RepositoryError {
    log_classified(operation, error, classify_rusqlite(operation, error))
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file holding one evidence table of each source and the delivery
    /// tables, as the two owning stores create them.
    fn evidence_file() -> Connection {
        let connection = Connection::open_in_memory().expect("an in-memory database opens");
        connection
            .execute_batch(AUTHORITY_EVENT_TABLES_SQL)
            .expect("the delivery tables create");
        connection
            .execute_batch(
                "CREATE TABLE catalog_change_evidence (
                     sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                     event_id TEXT, operation_id TEXT, actor_user_id TEXT,
                     actor_issuer TEXT, actor_kind TEXT, actor_auth_mode TEXT,
                     action TEXT, connection_id TEXT, prior_version INTEGER,
                     new_version INTEGER, committed_at TEXT
                 );",
            )
            .expect("an evidence table creates");
        connection
    }

    fn append(connection: &Connection, committed_at: &str) {
        connection
            .execute(
                "INSERT INTO catalog_change_evidence (event_id, operation_id, actor_user_id, \
                 actor_kind, actor_auth_mode, action, connection_id, new_version, committed_at) \
                 VALUES (?1, ?2, 'publisher', 'system', 'system', 'catalog.mcp.publish', \
                 'connection-a', 1, ?3)",
                params![
                    Uuid::new_v4().to_string(),
                    Uuid::new_v4().to_string(),
                    committed_at
                ],
            )
            .expect("an evidence row inserts");
    }

    /// The `source` vocabulary is the evidence tables, one for one, and the
    /// cursor table refuses anything else.
    #[test]
    fn the_cursor_sources_are_the_evidence_tables() {
        let connection = evidence_file();
        for source in StandaloneEvidenceSource::ALL {
            assert!(AUTHORITY_EVENT_TABLES_SQL.contains(&format!("'{}'", source.table())));
            open_cursor(&connection, source).expect("every source's cursor opens");
        }
        assert_eq!(
            AUTHORITY_EVENT_TABLES_SQL.matches("_evidence'").count(),
            StandaloneEvidenceSource::ALL.len()
        );
        assert!(connection
            .execute(
                "INSERT INTO authority_event_cursors VALUES ('security_outbox', 0, 0, 'now')",
                [],
            )
            .is_err());
    }

    /// The authority ID is written once: a later candidate reads back the
    /// first one.
    #[test]
    fn the_authority_id_is_created_once() {
        let connection = evidence_file();
        let first = Uuid::new_v4();
        assert_eq!(authority_id(&connection, first).expect("written"), first);
        assert_eq!(
            authority_id(&connection, Uuid::new_v4()).expect("read back"),
            first
        );
    }

    /// The cursor starts at 0, moves only from where it is, and an advance
    /// retried after it committed succeeds without counting twice.
    #[test]
    fn the_cursor_advances_by_compare_and_set() {
        let connection = evidence_file();
        let source = StandaloneEvidenceSource::CatalogChange;
        for _ in 0..3 {
            append(&connection, "2026-11-05T10:00:00Z");
        }
        assert_eq!(open_cursor(&connection, source).expect("opens"), 0);
        let rows = read_after(&connection, source, 0, 2).expect("reads");
        assert_eq!(
            rows.iter().map(|row| row.sequence).collect::<Vec<_>>(),
            [1, 2]
        );
        advance(&connection, source, 0, 2, 2).expect("advances");
        advance(&connection, source, 0, 2, 2).expect("an identical retry succeeds");
        assert_eq!(
            advance(&connection, source, 1, 3, 2)
                .expect_err("a stale position is refused")
                .kind(),
            RepositoryErrorKind::Conflict
        );
        assert_eq!(open_cursor(&connection, source).expect("reopens"), 2);
        let delivered: i64 = connection
            .query_row(
                "SELECT delivered_events FROM authority_event_cursors WHERE source = ?1",
                params![source.table()],
                |row| row.get(0),
            )
            .expect("the count reads");
        assert_eq!(delivered, 2);
        assert_eq!(
            read_after(&connection, source, 2, 100)
                .expect("reads")
                .iter()
                .map(|row| row.sequence)
                .collect::<Vec<_>>(),
            [3]
        );
    }

    /// The backlog is the distance from the cursor to the head, and the age
    /// is the first undelivered row's.
    #[test]
    fn the_backlog_counts_rows_above_the_cursor() {
        let connection = evidence_file();
        let source = StandaloneEvidenceSource::CatalogChange;
        append(&connection, "2026-11-05T10:00:00Z");
        assert_eq!(
            backlog(&connection, source)
                .expect("reads before the cursor exists")
                .undelivered(),
            1,
            "before the cursor exists every row is undelivered"
        );
        connection
            .execute("DELETE FROM catalog_change_evidence", [])
            .expect("the fixture row deletes");
        connection
            .execute("DELETE FROM sqlite_sequence", [])
            .expect("the fixture sequence resets");
        open_cursor(&connection, source).expect("opens");
        assert_eq!(
            backlog(&connection, source).expect("reads"),
            SourceBacklog::default()
        );
        append(&connection, "2026-11-05T10:00:00Z");
        append(&connection, "2026-11-05T10:00:30.5Z");
        advance(&connection, source, 0, 1, 1).expect("advances");
        let behind = backlog(&connection, source).expect("reads");
        assert_eq!(behind.undelivered(), 1);
        let now = OffsetDateTime::parse("2026-11-05T10:01:00.5Z", &Rfc3339).expect("parses");
        assert_eq!(behind.oldest_undelivered_age_secs(now), Some(30.0));
        assert_eq!(
            behind.oldest_undelivered_age_secs(
                OffsetDateTime::parse("2026-11-05T09:00:00Z", &Rfc3339).expect("parses")
            ),
            Some(0.0),
            "a clock behind the row never reads as a negative age"
        );
        advance(&connection, source, 1, 2, 1).expect("advances");
        let caught_up = backlog(&connection, source).expect("reads");
        assert_eq!(caught_up.undelivered(), 0);
        assert_eq!(caught_up.oldest_undelivered_age_secs(now), None);
    }
}
