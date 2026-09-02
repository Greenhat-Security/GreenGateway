//! The conditional-transition vocabulary shared by signals, rule
//! suggestions, and endpoint reviews (issue #241, PR 12).
//!
//! Every lifecycle row carries a `revision` (starting at 1, incremented by
//! every write) and a transition is one conditional statement:
//! `UPDATE ... SET state = to, revision = revision + 1 WHERE id = ? AND
//! state = from AND (expected revision IS NULL OR revision = expected)`.
//! Zero rows means the predicate did not hold -- another admin, on this or
//! any other replica, got there first -- and the caller receives the row as
//! it is NOW ([`TransitionRefused`]) so it can answer `409` with it and never
//! overwrite. Both backends implement exactly this shape, so standalone mode
//! and cluster mode refuse the same races the same way; the only difference
//! is that a single SQLite process cannot actually lose one.
//!
//! The admin API exposes the revision on every read and accepts an
//! `If-Match`-style expected value; `None` means "any revision, but the
//! from-state must still hold".

use serde::Serialize;

/// What a transition requires of the row before it applies: the lifecycle
/// state it must be in, and optionally the exact revision it must carry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionPrecondition<S> {
    pub from_state: S,
    pub revision: Option<i64>,
}

impl<S> TransitionPrecondition<S> {
    pub fn from_state(from_state: S) -> Self {
        Self {
            from_state,
            revision: None,
        }
    }

    pub fn with_revision(mut self, revision: Option<i64>) -> Self {
        self.revision = revision;
        self
    }
}

/// The predicate did not hold: `current` is the row as it is now, unchanged
/// by this call.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct TransitionRefused<T> {
    pub current: T,
}

/// The result of one conditional transition.
#[derive(Clone, Debug, PartialEq)]
pub enum TransitionOutcome<T> {
    /// The predicate held; the row after the update.
    Applied(T),
    /// The predicate did not hold; nothing was written.
    Refused(TransitionRefused<T>),
    /// No row has that identity.
    NotFound,
}

impl<T> TransitionOutcome<T> {
    /// The applied row, panicking otherwise; for tests.
    #[cfg(test)]
    pub fn expect_applied(self, context: &str) -> T {
        match self {
            Self::Applied(value) => value,
            Self::Refused(_) => panic!("{context}: the transition was refused"),
            Self::NotFound => panic!("{context}: the row was not found"),
        }
    }

    /// The refusal's current row, panicking otherwise; for tests.
    #[cfg(test)]
    pub fn expect_refused(self, context: &str) -> T {
        match self {
            Self::Refused(refused) => refused.current,
            Self::Applied(_) => panic!("{context}: the transition was applied"),
            Self::NotFound => panic!("{context}: the row was not found"),
        }
    }

    #[cfg(test)]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound)
    }
}

/// The revision an endpoint review reports while it has no review row:
/// a caller expecting exactly this value is asking for "not yet reviewed",
/// so two admins marking the same endpoint from two replicas get exactly one
/// winner.
pub const UNREVIEWED_REVISION: i64 = 0;

/// Add `column_name` to a standalone SQLite table that predates it (the
/// in-place `ensure_*_column` pattern the aggregator uses): a no-op when the
/// table does not exist yet or already has the column.
pub(crate) fn ensure_sqlite_column(
    connection: &rusqlite::Connection,
    table: &str,
    column_name: &str,
    column_type: &str,
) -> rusqlite::Result<()> {
    let columns = {
        let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
        let columns = statement
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<Result<Vec<_>, _>>()?;
        columns
    };
    if columns.is_empty() || columns.iter().any(|column| column == column_name) {
        return Ok(());
    }
    connection.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column_name} {column_type}"),
        [],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_sqlite_column_adds_once_and_fills_existing_rows_with_the_default() {
        let connection = rusqlite::Connection::open_in_memory().expect("sqlite opens");
        connection
            .execute_batch(
                "CREATE TABLE rows (id TEXT PRIMARY KEY); INSERT INTO rows VALUES ('a');",
            )
            .expect("schema");
        ensure_sqlite_column(
            &connection,
            "rows",
            "revision",
            "INTEGER NOT NULL DEFAULT 1",
        )
        .expect("first add");
        ensure_sqlite_column(
            &connection,
            "rows",
            "revision",
            "INTEGER NOT NULL DEFAULT 1",
        )
        .expect("second call is a no-op");
        let revision: i64 = connection
            .query_row("SELECT revision FROM rows WHERE id = 'a'", [], |row| {
                row.get(0)
            })
            .expect("existing row carries the default");
        assert_eq!(revision, 1);
        ensure_sqlite_column(&connection, "missing", "revision", "INTEGER")
            .expect("a table that does not exist yet is left to its CREATE");
    }

    #[test]
    fn precondition_builder_carries_the_expected_revision() {
        let precondition = TransitionPrecondition::from_state("open").with_revision(Some(3));
        assert_eq!(precondition.from_state, "open");
        assert_eq!(precondition.revision, Some(3));
        assert_eq!(TransitionPrecondition::from_state("open").revision, None);
    }
}
