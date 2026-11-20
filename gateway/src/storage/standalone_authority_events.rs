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
//! The same owners also create the file's caller-key reservations
//! ([`CALLER_OPERATION_TABLE_SQL`]): one row per caller-assigned operation ID
//! a committed change used, so a key belongs to one action and one request.
//!
//! Errors carry a classification and a static operation label only.

use std::sync::MutexGuard;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

use crate::authority_events::caller_operation::{
    CallerKeyReservation, CallerKeyState, CallerOperation,
};

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

/// The standalone caller keys (issue #425): one row per caller-assigned
/// operation ID used in this file, the action it is reserved for and, for
/// every action but a keyed revoke, the binding digest of the one request it
/// belongs to (`authority_events::caller_operation`). The row commits in the
/// IMMEDIATE transaction of the change and its evidence row, so a key is
/// reserved exactly when its change committed. The operation ID is a
/// canonical lowercase RFC UUIDv7, the text form the evidence tables store;
/// gateway-assigned IDs are v4 and can never be reserved.
///
/// Both owning stores create it from this one definition, as they create
/// [`AUTHORITY_EVENT_TABLES_SQL`]: the token store in its open-time schema
/// and the Connections store in its migration 16, each `IF NOT EXISTS`, so a
/// token store and a Connections store pointed at the same file share one
/// table whichever opens it first. That is also why the action list is
/// complete for every keyable standalone action now: SQLite cannot widen a
/// CHECK in place, and whichever store creates the table fixes it. A later
/// standalone action needs a table rebuild in both places, the token store's
/// open-time schema and a new Connections migration.
///
/// Each SQLite file is its own authority, so a key is unique within one
/// file, as `(authority_id, event_id)` identifies its delivered events: the
/// token database and a separate Connections database each accept a key
/// once.
pub(crate) const CALLER_OPERATION_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS authority_caller_operation_ids (
    operation_id TEXT NOT NULL PRIMARY KEY CHECK (
        operation_id GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-7[0-9a-f][0-9a-f][0-9a-f]-[89ab][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'
    ),
    action TEXT NOT NULL CHECK (
        action IN (
            'service_token.issue', 'service_token.rotate', 'service_token.revoke',
            'connection.create', 'connection.replace', 'connection.delete',
            'catalog.mcp.publish', 'catalog.openapi.publish',
            'catalog.overlay.replace', 'catalog.overlay.delete',
            'secret.create', 'secret.rotate', 'secret.delete'
        )
    ),
    binding_digest TEXT CHECK (
        binding_digest IS NULL
        OR (length(binding_digest) = 64 AND binding_digest NOT GLOB '*[^0-9a-f]*')
    ),
    CHECK (binding_digest IS NOT NULL OR action IN ('service_token.revoke'))
);
"#;

/// Every action [`CALLER_OPERATION_TABLE_SQL`] admits, value for value.
pub(crate) const STANDALONE_CALLER_OPERATION_ACTIONS: [&str; 13] = [
    "service_token.issue",
    "service_token.rotate",
    "service_token.revoke",
    "connection.create",
    "connection.replace",
    "connection.delete",
    "catalog.mcp.publish",
    "catalog.openapi.publish",
    "catalog.overlay.replace",
    "catalog.overlay.delete",
    "secret.create",
    "secret.rotate",
    "secret.delete",
];

/// The one standalone action keyed before binding digests existed: its
/// reservation has no digest, and the token store's own evidence check
/// decides its replays.
pub(crate) const STANDALONE_UNBOUND_CALLER_OPERATION_ACTIONS: [&str; 1] = ["service_token.revoke"];

const OPERATION_CALLER_KEY_READ: &str = "standalone_caller_operation_read";
const OPERATION_CALLER_KEY_RESERVE: &str = "standalone_caller_operation_reserve";

/// Whether `action` is one a key is bound to by digest in a standalone file.
fn is_bound_standalone_action(action: &str) -> bool {
    STANDALONE_CALLER_OPERATION_ACTIONS.contains(&action)
        && !STANDALONE_UNBOUND_CALLER_OPERATION_ACTIONS.contains(&action)
}

/// The stored action and digest of `id`'s reservation, if it has one.
fn stored_caller_operation(
    connection: &Connection,
    id: Uuid,
) -> rusqlite::Result<Option<(String, Option<String>)>> {
    connection
        .query_row(
            "SELECT action, binding_digest FROM authority_caller_operation_ids \
             WHERE operation_id = ?1",
            params![id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
}

/// What this file's reservation table says about `operation`'s key: read
/// only, so a handler can ask before it does any external work. The answer
/// is advisory until the change's own transaction reserves the key with
/// [`reserve_bound_operation`].
#[cfg_attr(not(test), allow(dead_code))] // Asked by the operation families that bind keys.
pub(crate) fn read_caller_operation(
    connection: &Connection,
    operation: &CallerOperation,
) -> Result<CallerKeyState, RepositoryError> {
    if !is_bound_standalone_action(operation.action()) {
        return Err(RepositoryError::invalid_parameter(
            OPERATION_CALLER_KEY_READ,
            "action",
        ));
    }
    let stored = stored_caller_operation(connection, operation.id())
        .map_err(|error| failure(OPERATION_CALLER_KEY_READ, &error))?;
    Ok(match stored {
        None => CallerKeyState::Unused,
        Some((action, digest)) => operation.judge(&action, digest.as_deref()),
    })
}

/// Reserve `operation`'s key with its binding digest inside the caller's
/// IMMEDIATE transaction, which also commits the change and its evidence.
/// A key already reserved is judged instead: the same action and digest is
/// an exact retry, anything else a conflict, and nothing is written either
/// way. The caller holds the file's write lock, so no other writer can
/// reserve the key between the look and the insert.
#[cfg_attr(not(test), allow(dead_code))] // Called by the operation families that bind keys.
pub(crate) fn reserve_bound_operation(
    connection: &Connection,
    operation: &CallerOperation,
) -> Result<CallerKeyReservation, RepositoryError> {
    if !is_bound_standalone_action(operation.action()) {
        return Err(RepositoryError::invalid_parameter(
            OPERATION_CALLER_KEY_RESERVE,
            "action",
        ));
    }
    let reserve = || -> rusqlite::Result<CallerKeyReservation> {
        let inserted = connection.execute(
            "INSERT INTO authority_caller_operation_ids (operation_id, action, binding_digest) \
             VALUES (?1, ?2, ?3) ON CONFLICT (operation_id) DO NOTHING",
            params![
                operation.id().to_string(),
                operation.action(),
                operation.binding_digest()
            ],
        )?;
        if inserted == 1 {
            return Ok(CallerKeyReservation::Reserved);
        }
        Ok(
            match stored_caller_operation(connection, operation.id())?
                .map(|(action, digest)| operation.judge(&action, digest.as_deref()))
            {
                Some(CallerKeyState::SameBinding) => CallerKeyReservation::SameBinding,
                // A key that refused the insert and then reads as absent is
                // not this request's either.
                _ => CallerKeyReservation::OtherBinding,
            },
        )
    };
    reserve().map_err(|error| failure(OPERATION_CALLER_KEY_RESERVE, &error))
}

/// The action `id` is reserved for in this file, if any. The keyed revoke
/// reads it in its IMMEDIATE transaction before its own evidence check.
pub(crate) fn caller_operation_action(
    connection: &Connection,
    id: Uuid,
) -> rusqlite::Result<Option<String>> {
    Ok(stored_caller_operation(connection, id)?.map(|(action, _)| action))
}

/// Reserve `id` for a keyed revoke, with no digest, inside the caller's
/// IMMEDIATE transaction. `false` when the key is taken; the revoke then
/// commits nothing.
pub(crate) fn reserve_unbound_operation(
    connection: &Connection,
    id: Uuid,
    action: &str,
) -> rusqlite::Result<bool> {
    connection
        .execute(
            "INSERT INTO authority_caller_operation_ids (operation_id, action) \
             VALUES (?1, ?2) ON CONFLICT (operation_id) DO NOTHING",
            params![id.to_string(), action],
        )
        .map(|inserted| inserted == 1)
}

/// One standalone evidence table: a source of delivered events. Each
/// variant is named for its table, as the journal's sources are.
#[allow(clippy::enum_variant_names)]
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

    /// The quoted values between `opening` and the next `)` of `sql`.
    fn quoted_list(sql: &str, opening: &str) -> Vec<String> {
        let (_, rest) = sql
            .split_once(opening)
            .unwrap_or_else(|| panic!("the table states {opening}"));
        let (list, _) = rest.split_once(')').expect("the list closes");
        list.split('\'')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    }

    /// The table's action CHECK is the Rust list, value for value, and only
    /// the keyed revoke may go without a binding digest.
    #[test]
    fn the_caller_operation_actions_are_the_tables_closed_vocabulary() {
        let actions = quoted_list(CALLER_OPERATION_TABLE_SQL, "action IN (");
        assert_eq!(actions, STANDALONE_CALLER_OPERATION_ACTIONS);
        let unbound = quoted_list(
            CALLER_OPERATION_TABLE_SQL,
            "binding_digest IS NOT NULL OR action IN (",
        );
        assert_eq!(unbound, STANDALONE_UNBOUND_CALLER_OPERATION_ACTIONS);
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../docs/schemas/authority_event.v1.schema.json"
        ))
        .expect("the published schema is JSON");
        let published = schema.to_string();
        for action in STANDALONE_CALLER_OPERATION_ACTIONS {
            assert!(
                published.contains(&format!("\"{action}\"")),
                "{action} is an authority_event.v1 operation"
            );
        }
    }

    /// The table refuses a key the caller did not assign, an action outside
    /// its list, a digest that is not lowercase SHA-256 hex, and a bound
    /// action without one; a second row for a key is a conflict.
    #[test]
    fn the_caller_operation_table_refuses_rows_that_do_not_fit() {
        let connection = Connection::open_in_memory().expect("an in-memory database opens");
        connection
            .execute_batch(CALLER_OPERATION_TABLE_SQL)
            .expect("the table creates");
        connection
            .execute_batch(CALLER_OPERATION_TABLE_SQL)
            .expect("and again, unchanged");
        let key = crate::authority_events::caller_operation::test_caller_key(1).to_string();
        let digest = "a".repeat(64);
        let insert = |id: &str, action: &str, digest: Option<&str>| {
            connection.execute(
                "INSERT INTO authority_caller_operation_ids (operation_id, action, binding_digest) \
                 VALUES (?1, ?2, ?3)",
                params![id, action, digest],
            )
        };
        insert(&key, "connection.create", Some(&digest)).expect("a bound key inserts");
        for (id, action, stored) in [
            (key.clone(), "connection.replace", Some(digest.clone())),
            (
                Uuid::new_v4().to_string(),
                "connection.create",
                Some(digest.clone()),
            ),
            (
                key.to_uppercase(),
                "connection.create",
                Some(digest.clone()),
            ),
            (
                crate::authority_events::caller_operation::test_caller_key(2).to_string(),
                "policy.publish",
                Some(digest.clone()),
            ),
            (
                crate::authority_events::caller_operation::test_caller_key(3).to_string(),
                "connection.create",
                None,
            ),
            (
                crate::authority_events::caller_operation::test_caller_key(4).to_string(),
                "connection.create",
                Some("A".repeat(64)),
            ),
            (
                crate::authority_events::caller_operation::test_caller_key(5).to_string(),
                "connection.create",
                Some("a".repeat(63)),
            ),
        ] {
            assert!(
                insert(&id, action, stored.as_deref()).is_err(),
                "{id} {action} {stored:?}"
            );
        }
        insert(
            &crate::authority_events::caller_operation::test_caller_key(6).to_string(),
            "service_token.revoke",
            None,
        )
        .expect("a keyed revoke reserves without a digest");
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
