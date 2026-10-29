//! The ledger's SQLite database: its exact schema, the connection discipline
//! of the existing standalone stores (WAL, `synchronous = FULL`, immediate
//! transactions), and the reads and writes that verify as they go.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::Duration,
};

use rusqlite::{config::DbConfig, params, Connection, ErrorCode, OpenFlags, OptionalExtension};

use crate::bundle::{sha256_pin, SourceFile};

use super::{
    record::{self, Pending},
    ActivationClass, Corruption, LedgerError, LedgerState, Operation, ParentLink, RecordedBundle,
    RevisionId, RevisionSummary, StoredRevision,
};

/// `PRAGMA application_id`: "GGLG", so the file identifies itself as a
/// GreenGateway configuration ledger.
const APPLICATION_ID: i32 = 0x4747_4C47;
/// `PRAGMA user_version`: the ledger format this binary reads and writes.
const FORMAT_VERSION: i32 = 1;
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// The documents a ledger can hold: four files for each revision.
const FILES_PER_REVISION: usize = 4;

/// Every schema object, as `(type, name, table, sql)`, with `sql` exactly as
/// SQLite keeps it. Opening a ledger requires precisely these objects and no
/// others, so a dropped append-only trigger or an added object is corruption.
const SCHEMA: &[(&str, &str, &str, &str)] = &[
    (
        "table",
        "config_ledger_documents",
        "config_ledger_documents",
        "CREATE TABLE config_ledger_documents (
    sha256 TEXT PRIMARY KEY NOT NULL CHECK (length(sha256) = 64),
    content BLOB NOT NULL
) STRICT",
    ),
    (
        "table",
        "config_revisions",
        "config_revisions",
        "CREATE TABLE config_revisions (
    sequence INTEGER PRIMARY KEY CHECK (sequence >= 1),
    revision_id TEXT NOT NULL UNIQUE,
    record_hash TEXT NOT NULL UNIQUE,
    record BLOB NOT NULL
) STRICT",
    ),
    (
        "table",
        "config_ledger_pointer",
        "config_ledger_pointer",
        "CREATE TABLE config_ledger_pointer (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    desired_sequence INTEGER NOT NULL REFERENCES config_revisions (sequence),
    desired_record_hash TEXT NOT NULL,
    active_sequence INTEGER REFERENCES config_revisions (sequence),
    CHECK (active_sequence IS NULL OR active_sequence <= desired_sequence)
) STRICT",
    ),
    (
        "trigger",
        "config_ledger_documents_no_update",
        "config_ledger_documents",
        "CREATE TRIGGER config_ledger_documents_no_update
BEFORE UPDATE ON config_ledger_documents
BEGIN
    SELECT RAISE(ABORT, 'configuration ledger documents are immutable');
END",
    ),
    (
        "trigger",
        "config_ledger_documents_no_delete",
        "config_ledger_documents",
        "CREATE TRIGGER config_ledger_documents_no_delete
BEFORE DELETE ON config_ledger_documents
BEGIN
    SELECT RAISE(ABORT, 'configuration ledger documents are immutable');
END",
    ),
    (
        "trigger",
        "config_revisions_no_update",
        "config_revisions",
        "CREATE TRIGGER config_revisions_no_update
BEFORE UPDATE ON config_revisions
BEGIN
    SELECT RAISE(ABORT, 'configuration revisions are append-only');
END",
    ),
    (
        "trigger",
        "config_revisions_no_delete",
        "config_revisions",
        "CREATE TRIGGER config_revisions_no_delete
BEFORE DELETE ON config_revisions
BEGIN
    SELECT RAISE(ABORT, 'configuration revisions are append-only');
END",
    ),
    (
        "trigger",
        "config_revisions_in_sequence",
        "config_revisions",
        "CREATE TRIGGER config_revisions_in_sequence
BEFORE INSERT ON config_revisions
WHEN NEW.sequence IS NOT (SELECT COALESCE(MAX(sequence), 0) + 1 FROM config_revisions)
BEGIN
    SELECT RAISE(ABORT, 'configuration revisions are appended in sequence');
END",
    ),
    (
        "trigger",
        "config_ledger_pointer_no_delete",
        "config_ledger_pointer",
        "CREATE TRIGGER config_ledger_pointer_no_delete
BEFORE DELETE ON config_ledger_pointer
BEGIN
    SELECT RAISE(ABORT, 'the configuration ledger pointer is permanent');
END",
    ),
    (
        "trigger",
        "config_ledger_pointer_forward",
        "config_ledger_pointer",
        "CREATE TRIGGER config_ledger_pointer_forward
BEFORE UPDATE ON config_ledger_pointer
WHEN NEW.desired_sequence < OLD.desired_sequence
    OR (OLD.active_sequence IS NOT NULL
        AND (NEW.active_sequence IS NULL OR NEW.active_sequence < OLD.active_sequence))
BEGIN
    SELECT RAISE(ABORT, 'the configuration ledger pointer only moves forward');
END",
    ),
];

/// The schema SQL, for tests that tamper with a ledger the way an edit
/// outside the gateway would.
#[cfg(test)]
pub(super) fn schema_sql(name: &str) -> Option<&'static str> {
    SCHEMA
        .iter()
        .find(|(_, object, _, _)| *object == name)
        .map(|(_, _, _, sql)| *sql)
}

/// Maps a SQLite failure during `operation`: a malformed database is
/// corruption, anything else is unavailability. The SQLite message is
/// dropped, because it can name a path or quote SQL.
fn failure(operation: &'static str) -> impl Fn(rusqlite::Error) -> LedgerError {
    move |error| match error.sqlite_error_code() {
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => {
            LedgerError::Corrupt(Corruption::Integrity)
        }
        _ => LedgerError::Unavailable { operation },
    }
}

fn connect(path: &Path) -> Result<Connection, LedgerError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(failure("open"))?;
    // Defensive mode refuses the statements that can corrupt a database
    // file; an untrusted schema may not call functions with side effects.
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(failure("configuration"))?;
    connection
        .set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)
        .map_err(failure("configuration"))?;
    connection
        .busy_timeout(BUSY_TIMEOUT)
        .map_err(failure("configuration"))?;
    connection
        .execute_batch("PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;")
        .map_err(failure("configuration"))?;
    Ok(connection)
}

/// Opens an existing ledger file for reading and writing. A file that is not
/// a ledger is refused before anything changes it, including its journal
/// mode.
pub(super) fn open(path: &Path) -> Result<Connection, LedgerError> {
    let connection = connect(path)?;
    check_header(&connection)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))
        .map_err(failure("journal mode"))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(LedgerError::Unavailable {
            operation: "journal mode",
        });
    }
    Ok(connection)
}

/// Writes a new ledger into the empty database file at `path`: the header,
/// the schema, the seed's documents and record, and the pointer, in one
/// immediate transaction, then closes it. The file stays in rollback-journal
/// mode until it is published and opened.
pub(super) fn initialize(
    path: &Path,
    pending: Pending,
    files: &[SourceFile],
) -> Result<(), LedgerError> {
    let mut connection = connect(path)?;
    let encoded = record::encode(&pending, 1, None)?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(failure("seed transaction"))?;
    transaction
        .pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(failure("seed header"))?;
    transaction
        .pragma_update(None, "user_version", FORMAT_VERSION)
        .map_err(failure("seed header"))?;
    for (_, _, _, sql) in SCHEMA {
        transaction
            .execute_batch(sql)
            .map_err(failure("seed schema"))?;
    }
    check_schema(&transaction)?;
    insert_documents(&transaction, files)?;
    insert_revision(&transaction, &encoded)?;
    transaction
        .execute(
            "INSERT INTO config_ledger_pointer (singleton, desired_sequence, desired_record_hash, active_sequence) VALUES (1, 1, ?1, NULL)",
            params![encoded.summary.record_hash],
        )
        .map_err(failure("seed pointer"))?;
    transaction.commit().map_err(failure("seed commit"))?;
    connection
        .close()
        .map_err(|(_, error)| failure("seed close")(error))
}

fn check_header(connection: &Connection) -> Result<(), LedgerError> {
    let read = |pragma: &str| {
        connection
            .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get::<_, i32>(0))
            .map_err(failure("header"))
    };
    if read("application_id")? != APPLICATION_ID {
        return Err(LedgerError::Corrupt(Corruption::Format));
    }
    match read("user_version")? {
        FORMAT_VERSION => Ok(()),
        version if version > FORMAT_VERSION => Err(LedgerError::Unsupported),
        _ => Err(LedgerError::Corrupt(Corruption::Format)),
    }
}

fn check_integrity(connection: &Connection) -> Result<(), LedgerError> {
    let mut statement = connection
        .prepare("PRAGMA quick_check")
        .map_err(failure("integrity check"))?;
    let results = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(failure("integrity check"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(failure("integrity check"))?;
    if results != ["ok"] {
        return Err(LedgerError::Corrupt(Corruption::Integrity));
    }
    Ok(())
}

fn check_schema(connection: &Connection) -> Result<(), LedgerError> {
    let mut statement = connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema WHERE sql IS NOT NULL")
        .map_err(failure("schema check"))?;
    let mut found = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(failure("schema check"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(failure("schema check"))?;
    let mut expected: Vec<_> = SCHEMA
        .iter()
        .map(|(kind, name, table, sql)| {
            (
                (*kind).to_owned(),
                (*name).to_owned(),
                (*table).to_owned(),
                (*sql).to_owned(),
            )
        })
        .collect();
    found.sort();
    expected.sort();
    if found != expected {
        return Err(LedgerError::Corrupt(Corruption::Schema));
    }
    Ok(())
}

/// The whole ledger, verified: header, page structure, schema, every
/// document against its pin, every record and its place in the chain, every
/// rollback against its target, and the pointer against the head.
pub(super) fn verify(
    connection: &Connection,
    max_revisions: usize,
) -> Result<LedgerState, LedgerError> {
    const CHAIN: LedgerError = LedgerError::Corrupt(Corruption::Chain);
    const DOCUMENT: LedgerError = LedgerError::Corrupt(Corruption::Document);
    check_header(connection)?;
    check_integrity(connection)?;
    let snapshot = connection
        .unchecked_transaction()
        .map_err(failure("verification"))?;
    check_schema(&snapshot)?;

    let mut documents = HashSet::new();
    {
        let mut statement = snapshot
            .prepare("SELECT sha256, content FROM config_ledger_documents")
            .map_err(failure("verification"))?;
        let mut rows = statement.query([]).map_err(failure("verification"))?;
        while let Some(row) = rows.next().map_err(failure("verification"))? {
            let sha256: String = row.get(0).map_err(failure("verification"))?;
            let content: Vec<u8> = row.get(1).map_err(failure("verification"))?;
            if sha256_pin(&content) != sha256
                || documents.len() >= max_revisions.saturating_mul(FILES_PER_REVISION)
            {
                return Err(DOCUMENT);
            }
            documents.insert(sha256);
        }
    }

    let mut referenced = HashSet::new();
    // Each revision's ID and source digest, by sequence and by ID.
    let mut ids = Vec::new();
    let mut digests = HashMap::new();
    let mut head: Option<RevisionSummary> = None;
    {
        let mut statement = snapshot
            .prepare(
                "SELECT sequence, revision_id, record_hash, record FROM config_revisions ORDER BY sequence",
            )
            .map_err(failure("verification"))?;
        let mut rows = statement.query([]).map_err(failure("verification"))?;
        while let Some(row) = rows.next().map_err(failure("verification"))? {
            if ids.len() >= max_revisions {
                return Err(CHAIN);
            }
            let summary = summary_of_row(row)?;
            let expected_sequence = head.as_ref().map_or(1, |head| head.sequence + 1);
            if summary.sequence != expected_sequence {
                return Err(CHAIN);
            }
            let linked = match (&head, &summary.parent) {
                (None, None) => summary.operation == Operation::Seed,
                (Some(previous), Some(parent)) => {
                    parent.revision == previous.revision
                        && parent.record_hash == previous.record_hash
                        && summary.operation != Operation::Seed
                }
                _ => false,
            };
            if !linked {
                return Err(CHAIN);
            }
            if let Operation::Rollback { target } = &summary.operation {
                let previous = head.as_ref().map(|head| &head.revision);
                if previous == Some(target)
                    || digests.get(target) != Some(&summary.bundle.source_digest)
                {
                    return Err(CHAIN);
                }
            }
            for file in &summary.bundle.files {
                if !documents.contains(&file.sha256) {
                    return Err(DOCUMENT);
                }
                referenced.insert(file.sha256.clone());
            }
            let manifest = read_documents(&snapshot, &summary.bundle, 1)?;
            check_manifest(&summary.bundle, &manifest)?;
            ids.push(summary.revision.clone());
            digests.insert(
                summary.revision.clone(),
                summary.bundle.source_digest.clone(),
            );
            head = Some(summary);
        }
    }
    if referenced.len() != documents.len() {
        return Err(DOCUMENT);
    }
    let head = head.ok_or(CHAIN)?;
    let pointer = read_pointer(&snapshot)?;
    if pointer.desired_sequence != head.sequence || pointer.desired_record_hash != head.record_hash
    {
        return Err(LedgerError::Corrupt(Corruption::Pointer));
    }
    let active = match pointer.active_sequence {
        None => None,
        Some(sequence) => Some(
            usize::try_from(sequence)
                .ok()
                .and_then(|sequence| sequence.checked_sub(1))
                .and_then(|index| ids.get(index))
                .cloned()
                .ok_or(LedgerError::Corrupt(Corruption::Pointer))?,
        ),
    };
    Ok(LedgerState {
        revisions: head.sequence,
        desired: head,
        active,
    })
}

/// The manifest alone against the source digest; [`record::check_documents`]
/// needs every file, and the verification pass has already checked each
/// file's pin.
fn check_manifest(bundle: &RecordedBundle, manifest: &[SourceFile]) -> Result<(), LedgerError> {
    let only_manifest = RecordedBundle {
        files: bundle.files.iter().take(1).cloned().collect(),
        ..bundle.clone()
    };
    record::check_documents(&only_manifest, manifest)
}

/// The pointer and the head it names.
pub(super) fn state(connection: &Connection) -> Result<LedgerState, LedgerError> {
    let snapshot = connection
        .unchecked_transaction()
        .map_err(failure("state read"))?;
    let (pointer, head) = pointer_and_head(&snapshot)?;
    let active = match pointer.active_sequence {
        None => None,
        Some(sequence) => Some(
            revision_at(&snapshot, sequence)?
                .ok_or(LedgerError::Corrupt(Corruption::Pointer))?
                .revision,
        ),
    };
    Ok(LedgerState {
        revisions: head.sequence,
        desired: head,
        active,
    })
}

/// Appends `pending` on top of `expected_head` (see
/// [`super::RevisionLedger::append`]).
pub(super) fn append(
    connection: &mut Connection,
    max_revisions: usize,
    expected_head: &RevisionId,
    pending: Pending,
    files: &[SourceFile],
) -> Result<RevisionSummary, LedgerError> {
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(failure("append transaction"))?;
    let (pointer, head) = pointer_and_head(&transaction)?;
    if &head.revision != expected_head {
        return Err(LedgerError::Stale {
            head: head.revision,
        });
    }
    if usize::try_from(head.sequence).unwrap_or(usize::MAX) >= max_revisions {
        return Err(LedgerError::Full);
    }
    if let Operation::Rollback { target } = pending.operation() {
        if target == &head.revision {
            return Err(LedgerError::Refused(super::Refusal::RollbackTargetIsHead));
        }
        let target = revision_by_id(&transaction, target)?
            .ok_or(LedgerError::Refused(super::Refusal::RollbackTargetUnknown))?;
        if target.bundle.source_digest != pending.bundle().source_digest {
            return Err(LedgerError::Refused(super::Refusal::RollbackContentDiffers));
        }
    }
    let sequence = head.sequence + 1;
    let encoded = record::encode(
        &pending,
        sequence,
        Some(ParentLink {
            revision: head.revision.clone(),
            record_hash: head.record_hash.clone(),
        }),
    )?;
    insert_documents(&transaction, files)?;
    insert_revision(&transaction, &encoded)?;
    let active = match (pending.activation(), pointer.active_sequence) {
        (ActivationClass::Live, Some(active)) if active == head.sequence => Some(sequence),
        (_, active) => active,
    };
    let updated = transaction
        .execute(
            "UPDATE config_ledger_pointer SET desired_sequence = ?1, desired_record_hash = ?2, active_sequence = ?3 WHERE singleton = 1",
            params![
                sql_sequence(sequence)?,
                encoded.summary.record_hash,
                active.map(sql_sequence).transpose()?
            ],
        )
        .map_err(failure("pointer update"))?;
    if updated != 1 {
        return Err(LedgerError::Corrupt(Corruption::Pointer));
    }
    transaction.commit().map_err(failure("append commit"))?;
    Ok(encoded.summary)
}

/// Moves the active pointer to the desired revision, which must be
/// `desired`.
pub(super) fn activate(
    connection: &mut Connection,
    desired: &RevisionId,
) -> Result<(), LedgerError> {
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(failure("activation transaction"))?;
    let (pointer, head) = pointer_and_head(&transaction)?;
    if &head.revision != desired {
        return Err(LedgerError::Stale {
            head: head.revision,
        });
    }
    if pointer.active_sequence != Some(head.sequence) {
        transaction
            .execute(
                "UPDATE config_ledger_pointer SET active_sequence = desired_sequence WHERE singleton = 1",
                [],
            )
            .map_err(failure("pointer update"))?;
    }
    transaction.commit().map_err(failure("activation commit"))
}

/// Up to `limit` records below `before`, newest first.
pub(super) fn revisions(
    connection: &Connection,
    before: Option<u64>,
    limit: usize,
) -> Result<Vec<RevisionSummary>, LedgerError> {
    let before = before.map_or(i64::MAX, |before| i64::try_from(before).unwrap_or(i64::MAX));
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let mut statement = connection
        .prepare(
            "SELECT sequence, revision_id, record_hash, record FROM config_revisions WHERE sequence < ?1 ORDER BY sequence DESC LIMIT ?2",
        )
        .map_err(failure("revision list"))?;
    let mut rows = statement
        .query(params![before, limit])
        .map_err(failure("revision list"))?;
    let mut page = Vec::new();
    while let Some(row) = rows.next().map_err(failure("revision list"))? {
        page.push(summary_of_row(row)?);
    }
    Ok(page)
}

/// One revision with its files, each checked against its pin.
pub(super) fn revision(
    connection: &Connection,
    id: &RevisionId,
) -> Result<Option<StoredRevision>, LedgerError> {
    let snapshot = connection
        .unchecked_transaction()
        .map_err(failure("revision read"))?;
    let Some(summary) = revision_by_id(&snapshot, id)? else {
        return Ok(None);
    };
    let files = read_documents(&snapshot, &summary.bundle, summary.bundle.files.len())?;
    record::check_documents(&summary.bundle, &files)?;
    Ok(Some(StoredRevision { summary, files }))
}

struct Pointer {
    desired_sequence: u64,
    desired_record_hash: String,
    active_sequence: Option<u64>,
}

fn read_pointer(connection: &Connection) -> Result<Pointer, LedgerError> {
    let row = connection
        .query_row(
            "SELECT desired_sequence, desired_record_hash, active_sequence FROM config_ledger_pointer WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )
        .optional()
        .map_err(failure("pointer read"))?;
    let (desired, desired_record_hash, active) =
        row.ok_or(LedgerError::Corrupt(Corruption::Pointer))?;
    let sequence =
        |value: i64| u64::try_from(value).map_err(|_| LedgerError::Corrupt(Corruption::Pointer));
    Ok(Pointer {
        desired_sequence: sequence(desired)?,
        desired_record_hash,
        active_sequence: active.map(sequence).transpose()?,
    })
}

/// The pointer and the verified head record it names, which must be the
/// newest revision.
fn pointer_and_head(connection: &Connection) -> Result<(Pointer, RevisionSummary), LedgerError> {
    const POINTER: LedgerError = LedgerError::Corrupt(Corruption::Pointer);
    let pointer = read_pointer(connection)?;
    let newest: Option<i64> = connection
        .query_row("SELECT MAX(sequence) FROM config_revisions", [], |row| {
            row.get(0)
        })
        .map_err(failure("head read"))?;
    if newest.and_then(|newest| u64::try_from(newest).ok()) != Some(pointer.desired_sequence) {
        return Err(POINTER);
    }
    let head = revision_at(connection, pointer.desired_sequence)?.ok_or(POINTER)?;
    if head.record_hash != pointer.desired_record_hash {
        return Err(POINTER);
    }
    Ok((pointer, head))
}

fn revision_at(
    connection: &Connection,
    sequence: u64,
) -> Result<Option<RevisionSummary>, LedgerError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, revision_id, record_hash, record FROM config_revisions WHERE sequence = ?1",
        )
        .map_err(failure("revision read"))?;
    let mut rows = statement
        .query(params![sql_sequence(sequence)?])
        .map_err(failure("revision read"))?;
    match rows.next().map_err(failure("revision read"))? {
        Some(row) => summary_of_row(row).map(Some),
        None => Ok(None),
    }
}

fn revision_by_id(
    connection: &Connection,
    id: &RevisionId,
) -> Result<Option<RevisionSummary>, LedgerError> {
    let mut statement = connection
        .prepare(
            "SELECT sequence, revision_id, record_hash, record FROM config_revisions WHERE revision_id = ?1",
        )
        .map_err(failure("revision read"))?;
    let mut rows = statement
        .query(params![id.as_str()])
        .map_err(failure("revision read"))?;
    match rows.next().map_err(failure("revision read"))? {
        Some(row) => summary_of_row(row).map(Some),
        None => Ok(None),
    }
}

/// A `(sequence, revision_id, record_hash, record)` row, decoded and held to
/// its own sequence column.
fn summary_of_row(row: &rusqlite::Row<'_>) -> Result<RevisionSummary, LedgerError> {
    let sequence: i64 = row.get(0).map_err(failure("revision read"))?;
    let revision_id: String = row.get(1).map_err(failure("revision read"))?;
    let record_hash: String = row.get(2).map_err(failure("revision read"))?;
    let bytes: Vec<u8> = row.get(3).map_err(failure("revision read"))?;
    let summary = record::decode(&bytes, &record_hash, &revision_id)?;
    if u64::try_from(sequence).ok() != Some(summary.sequence) {
        return Err(LedgerError::Corrupt(Corruption::Chain));
    }
    Ok(summary)
}

/// The first `count` files `bundle` records, with their stored bytes.
fn read_documents(
    connection: &Connection,
    bundle: &RecordedBundle,
    count: usize,
) -> Result<Vec<SourceFile>, LedgerError> {
    let mut statement = connection
        .prepare("SELECT content FROM config_ledger_documents WHERE sha256 = ?1")
        .map_err(failure("document read"))?;
    let mut files = Vec::new();
    for file in bundle.files.iter().take(count) {
        let bytes: Vec<u8> = statement
            .query_row(params![file.sha256], |row| row.get(0))
            .optional()
            .map_err(failure("document read"))?
            .ok_or(LedgerError::Corrupt(Corruption::Document))?;
        files.push(SourceFile {
            role: file.role,
            name: file.name.clone(),
            bytes,
        });
    }
    Ok(files)
}

/// Stores each file once by its pin. A pin already stored must hold exactly
/// these bytes, or the ledger was changed outside this code.
fn insert_documents(connection: &Connection, files: &[SourceFile]) -> Result<(), LedgerError> {
    for file in files {
        let sha256 = sha256_pin(&file.bytes);
        let inserted = connection
            .execute(
                "INSERT OR IGNORE INTO config_ledger_documents (sha256, content) VALUES (?1, ?2)",
                params![sha256, file.bytes],
            )
            .map_err(failure("document insert"))?;
        if inserted == 0 {
            let stored: Vec<u8> = connection
                .query_row(
                    "SELECT content FROM config_ledger_documents WHERE sha256 = ?1",
                    params![sha256],
                    |row| row.get(0),
                )
                .map_err(failure("document read"))?;
            if stored != file.bytes {
                return Err(LedgerError::Corrupt(Corruption::Document));
            }
        }
    }
    Ok(())
}

fn insert_revision(connection: &Connection, encoded: &record::Encoded) -> Result<(), LedgerError> {
    connection
        .execute(
            "INSERT INTO config_revisions (sequence, revision_id, record_hash, record) VALUES (?1, ?2, ?3, ?4)",
            params![
                sql_sequence(encoded.summary.sequence)?,
                encoded.summary.revision.as_str(),
                encoded.summary.record_hash,
                encoded.bytes
            ],
        )
        .map_err(failure("revision insert"))?;
    Ok(())
}

fn sql_sequence(sequence: u64) -> Result<i64, LedgerError> {
    i64::try_from(sequence).map_err(|_| LedgerError::Corrupt(Corruption::Chain))
}
