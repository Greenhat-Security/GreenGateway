//! The SQLite side of a backup: a consistent snapshot of each store, and
//! the description and integrity check of a snapshot or of an entry read
//! back from an archive.
//!
//! A snapshot is `VACUUM INTO` from a read-only connection, as `gateway
//! import-standalone` takes its copies: SQLite writes one consistent
//! database file from a single read transaction, with whatever a write-ahead
//! log holds folded in. The store's files are never copied, and its main
//! file and write-ahead log are never written; like any reader, SQLite may
//! create or update the `-shm` index beside a write-ahead store, which
//! holds no data. The snapshot is then put in rollback-journal
//! mode, so the entry is one self-contained file that opens read-only
//! anywhere.
//!
//! Every connection is defensive and distrusts the schema, as the ledger's
//! are: a database read back from an archive is untrusted input. No message
//! SQLite gives is kept, because it can name a path or quote SQL.

use std::{path::Path, time::Duration};

use rusqlite::{config::DbConfig, Connection, ErrorCode, OpenFlags};
use sha2::{Digest, Sha256};

use super::manifest::{is_table_name, DatabaseRecord, TableRecord, MAX_TABLES};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// What every SQLite database file starts with.
const HEADER_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// The header's file format write and read versions for a database in
/// rollback-journal mode; WAL mode writes 2.
const LEGACY_FORMAT: u8 = 1;

/// Why a database could not be snapshotted, described or checked.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SqliteFailure {
    /// SQLite reports a malformed database, the integrity check fails, or
    /// the database is not one a backup can describe.
    Corrupt,
    /// The database could not be opened, read or written: busy, locked, a
    /// journal a read-only connection cannot roll back, or an I/O failure.
    Unavailable,
}

fn failure(error: &rusqlite::Error) -> SqliteFailure {
    match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => SqliteFailure::Corrupt,
        _ => SqliteFailure::Unavailable,
    }
}

fn configure(connection: &Connection) -> Result<(), SqliteFailure> {
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|error| failure(&error))?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
        .map_err(|error| failure(&error))?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(|error| failure(&error))
}

fn open(path: &Path, flags: OpenFlags) -> Result<Connection, SqliteFailure> {
    let connection = Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(|error| failure(&error))?;
    configure(&connection)?;
    Ok(connection)
}

/// Writes a consistent snapshot of the database at `source` into the empty
/// file at `destination`.
///
/// The source is opened read-only: `VACUUM INTO` only reads it, and writes
/// nothing but the file its clause names, which SQLite fills only when it is
/// empty.
pub(super) fn snapshot(source: &Path, destination: &Path) -> Result<(), SqliteFailure> {
    let Some(destination) = destination.to_str() else {
        return Err(SqliteFailure::Unavailable);
    };
    let connection = open(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    // Opening is lazy; a file that is not a database fails here.
    connection
        .query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
        .map_err(|error| failure(&error))?;
    connection
        .execute("VACUUM INTO ?1", [destination])
        .map_err(|error| failure(&error))?;
    connection.close().map_err(|(_, error)| failure(&error))
}

/// Puts the snapshot at `path`, which this process owns, in rollback-journal
/// mode.
pub(super) fn normalize(path: &Path) -> Result<(), SqliteFailure> {
    let connection = open(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .map_err(|error| failure(&error))?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err(SqliteFailure::Unavailable);
    }
    connection.close().map_err(|(_, error)| failure(&error))
}

/// Whether `header`, a database file's first bytes, is a SQLite database in
/// rollback-journal mode, as every backup entry is.
pub(super) fn is_rollback_database(header: &[u8]) -> bool {
    header.len() >= 20
        && header[..16] == HEADER_MAGIC[..]
        && header[18] == LEGACY_FORMAT
        && header[19] == LEGACY_FORMAT
}

/// Checks the integrity of the database at `path` and describes it, through
/// a read-only connection.
pub(super) fn describe(path: &Path) -> Result<DatabaseRecord, SqliteFailure> {
    let connection = open(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let integrity: Vec<String> = {
        let mut statement = connection
            .prepare("PRAGMA integrity_check")
            .map_err(|error| failure(&error))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| failure(&error))?;
        rows.collect::<Result<_, _>>()
            .map_err(|error| failure(&error))?
    };
    if integrity != ["ok"] {
        return Err(SqliteFailure::Corrupt);
    }
    let pragma = |name: &str| {
        connection
            .query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, i64>(0))
            .map_err(|error| failure(&error))
    };
    let application_id =
        i32::try_from(pragma("application_id")?).map_err(|_| SqliteFailure::Corrupt)?;
    let user_version =
        i32::try_from(pragma("user_version")?).map_err(|_| SqliteFailure::Corrupt)?;
    let page_size = u32::try_from(pragma("page_size")?).map_err(|_| SqliteFailure::Corrupt)?;
    let pages = u64::try_from(pragma("page_count")?).map_err(|_| SqliteFailure::Corrupt)?;

    let mut schema: Vec<(String, String, String, String)> = {
        let mut statement = connection
            .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE sql IS NOT NULL")
            .map_err(|error| failure(&error))?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|error| failure(&error))?;
        rows.collect::<Result<_, _>>()
            .map_err(|error| failure(&error))?
    };
    schema.sort();
    let encoded = serde_json::to_vec(&schema).map_err(|_| SqliteFailure::Corrupt)?;
    let schema_sha256 = hex::encode(Sha256::digest(&encoded));

    let mut names: Vec<String> = {
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'",
            )
            .map_err(|error| failure(&error))?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| failure(&error))?;
        rows.collect::<Result<_, _>>()
            .map_err(|error| failure(&error))?
    };
    names.sort();
    if names.len() > MAX_TABLES {
        return Err(SqliteFailure::Corrupt);
    }
    let mut tables = Vec::with_capacity(names.len());
    for name in names {
        // Only a name of the plain grammar is quoted into a statement.
        if !is_table_name(&name) {
            return Err(SqliteFailure::Corrupt);
        }
        let rows: i64 = connection
            .query_row(&format!("SELECT count(*) FROM \"{name}\""), [], |row| {
                row.get(0)
            })
            .map_err(|error| failure(&error))?;
        let rows = u64::try_from(rows).map_err(|_| SqliteFailure::Corrupt)?;
        tables.push(TableRecord { name, rows });
    }
    connection.close().map_err(|(_, error)| failure(&error))?;
    Ok(DatabaseRecord {
        application_id,
        user_version,
        page_size,
        pages,
        schema_sha256,
        tables,
    })
}
