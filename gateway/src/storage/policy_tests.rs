//! The stored policy test suite (issue #243): one exact-version
//! `policy-tests.v1` suite kept beside the policy, its repository contract
//! and its standalone SQLite adapter.
//!
//! A deployment holds at most one active suite. Every write is a new
//! immutable version under a strong ETag, and both adapters satisfy one
//! contract (`policy_tests_tests`):
//!
//! - **The ETag is the suite's semantic digest.** It is the ADR-0004 digest
//!   [`crate::policy_testing::suite::parse_suite`] computes, in quotes, so two
//!   versions carry the same ETag exactly when they are the same suite, and a
//!   test report's `suite.digest` names the stored version it ran.
//! - **Compare-and-set.** A write names the ETag it replaces, or that no suite
//!   exists yet; the precondition is re-checked inside the writing transaction,
//!   so of two writers holding one ETag exactly one wins and the other changes
//!   nothing.
//! - **Accepted, bounded, verified.** A store writes only a suite the parser
//!   accepts, at most [`MAX_POLICY_TEST_SUITE_BYTES`] as RFC 8785 bytes and
//!   with no U+0000 in any string (PostgreSQL's `jsonb` cannot hold one, so
//!   neither mode stores it). Every read re-parses the stored suite and
//!   requires it to reproduce the ETag recorded beside it; a row that does not
//!   is `InvalidData` and is never served or run.
//!
//! The standalone adapter keeps a `policy_test_suite_versions` table in the
//! policy history database, beside `policy_versions`: the active suite is the
//! newest row, and a write is one `IMMEDIATE` SQLite transaction that reads it,
//! checks the precondition and appends, so a crash leaves either the old
//! version or the new one active, never a half-written row. The cluster adapter
//! (`postgres_policy_tests`) commits through the shared versioned-document
//! transaction instead.
//!
//! A stored suite is not enforced and activates nothing: requiring a passing
//! suite before a policy change is a later slice.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    auth::Principal,
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
    policy_testing::suite::{parse_suite, Suite},
};

use super::{
    classify_rusqlite, log_classified, run_blocking, RepositoryError, RepositoryErrorKind,
};

/// The largest suite a store holds, as its RFC 8785 bytes: the same 2 MiB a
/// test run accepts as its whole body.
pub const MAX_POLICY_TEST_SUITE_BYTES: usize = 2 * 1024 * 1024;

const OPERATION_OPEN: &str = "policy_tests_open";
const OPERATION_ACTIVE: &str = "policy_tests_active_read";
const OPERATION_COMMIT: &str = "policy_tests_commit";

/// What a writer believes about the active suite. The store re-checks it in
/// the writing transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyTestSuitePrecondition {
    /// The active suite carries this strong ETag (an HTTP `If-Match`).
    Expected { etag: String },
    /// No suite has been stored yet (`If-None-Match: *`).
    Absent,
}

/// Why a write did not happen. Nothing was written in either case.
#[derive(Debug)]
pub enum PolicyTestSuiteCommitError {
    /// The precondition no longer (or never) held.
    PreconditionFailed,
    Store(RepositoryError),
}

impl fmt::Display for PolicyTestSuiteCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreconditionFailed => formatter.write_str(
                "the stored policy test suite changed before the write committed; nothing was written",
            ),
            Self::Store(error) => write!(formatter, "policy test suite commit failed: {error}"),
        }
    }
}

impl std::error::Error for PolicyTestSuiteCommitError {}

/// One stored version, verified on read.
///
/// It does not derive `Debug`: the suite holds fixture values, and a
/// formatted one in a log line is the secondary output ADR-0004 keeps them
/// out of. It formats as its version, ETag and size.
pub(crate) struct PolicyTestSuiteRecord {
    pub(crate) version: i64,
    /// The strong ETag: `"` + [`Self::digest`] + `"`.
    pub(crate) etag: String,
    /// The suite's ADR-0004 semantic digest.
    pub(crate) digest: String,
    /// The suite document as stored.
    pub(crate) document: Value,
    /// The suite as the runner reads it, parsed from [`Self::document`].
    pub(crate) suite: Suite,
    /// The shared security revision the version was committed at. Cluster
    /// mode only: the standalone authority has no shared revision.
    pub(crate) security_revision: Option<i64>,
}

impl fmt::Debug for PolicyTestSuiteRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PolicyTestSuiteRecord")
            .field("version", &self.version)
            .field("etag", &self.etag)
            .field("cases", &self.suite.cases.len())
            .field("security_revision", &self.security_revision)
            .finish()
    }
}

impl PolicyTestSuiteRecord {
    pub(crate) fn case_count(&self) -> usize {
        self.suite.cases.len()
    }
}

/// Contract for the stored policy test suite.
#[async_trait]
pub(crate) trait PolicyTestSuiteStore: Send + Sync {
    /// The active version, or `None` when no suite has been stored.
    async fn active(&self) -> Result<Option<PolicyTestSuiteRecord>, RepositoryError>;

    /// Store `document` as the next version if `precondition` still holds.
    /// The caller has already accepted the document with the suite parser;
    /// the store parses it again and refuses one it does not accept, so it
    /// never holds a suite this build would refuse.
    async fn commit(
        &self,
        precondition: PolicyTestSuitePrecondition,
        document: &Value,
        actor: &Principal,
    ) -> Result<PolicyTestSuiteRecord, PolicyTestSuiteCommitError>;
}

/// The strong ETag of a suite whose semantic digest is `digest`.
pub fn policy_test_suite_etag(digest: &str) -> String {
    format!("\"{digest}\"")
}

/// Whether any string in `value` holds U+0000, which a stored suite may not.
/// Object member names are not visited: the parser refuses every name it
/// does not define, and none it defines holds one.
pub fn contains_nul_character(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains('\0'),
        Value::Array(items) => items.iter().any(contains_nul_character),
        Value::Object(members) => members.values().any(contains_nul_character),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

/// A suite as both adapters write it.
pub(crate) struct StorableSuite {
    /// The RFC 8785 bytes, which are what the store keeps.
    pub(crate) canonical_json: String,
    pub(crate) digest: String,
    pub(crate) etag: String,
    pub(crate) document: Value,
    pub(crate) suite: Suite,
}

impl StorableSuite {
    /// The record of this suite once committed as `version`.
    pub(crate) fn into_record(
        self,
        version: i64,
        security_revision: Option<i64>,
    ) -> PolicyTestSuiteRecord {
        PolicyTestSuiteRecord {
            version,
            etag: self.etag,
            digest: self.digest,
            document: self.document,
            suite: self.suite,
            security_revision,
        }
    }
}

/// Accept `document` for storage, or refuse it as a parameter the caller
/// should have refused first: one the parser refuses, one holding U+0000,
/// or one over [`MAX_POLICY_TEST_SUITE_BYTES`].
pub(crate) fn storable_suite(
    document: &Value,
    operation: &'static str,
) -> Result<StorableSuite, RepositoryError> {
    let refused = || RepositoryError::invalid_parameter(operation, "suite");
    let suite = parse_suite(document).map_err(|_| refused())?;
    if contains_nul_character(document) {
        return Err(refused());
    }
    let canonical = crate::canonical_json::canonical_json_bytes(document).map_err(|_| refused())?;
    if canonical.len() > MAX_POLICY_TEST_SUITE_BYTES {
        return Err(refused());
    }
    let canonical_json = String::from_utf8(canonical)
        .map_err(|_| RepositoryError::new(RepositoryErrorKind::InvalidData, operation))?;
    let digest = suite.digest.clone();
    Ok(StorableSuite {
        canonical_json,
        etag: policy_test_suite_etag(&digest),
        digest,
        document: document.clone(),
        suite,
    })
}

/// Read a stored suite back: parse it, accept it with this build's parser,
/// and require it to reproduce `recorded_etag`. A row edited out of band, or
/// written by a build whose suite format this one does not accept, fails
/// closed here.
pub(crate) fn suite_from_stored(
    json: &str,
    recorded_etag: &str,
    version: i64,
    security_revision: Option<i64>,
    operation: &'static str,
) -> Result<PolicyTestSuiteRecord, RepositoryError> {
    let invalid = || RepositoryError::new(RepositoryErrorKind::InvalidData, operation);
    let document = serde_json::from_str::<Value>(json).map_err(|_| invalid())?;
    let suite = parse_suite(&document).map_err(|_| invalid())?;
    let etag = policy_test_suite_etag(&suite.digest);
    if etag != recorded_etag {
        tracing::error!(
            operation,
            version,
            "a stored policy test suite does not reproduce its recorded ETag; refusing it"
        );
        return Err(invalid());
    }
    Ok(PolicyTestSuiteRecord {
        version,
        digest: suite.digest.clone(),
        etag,
        document,
        suite,
        security_revision,
    })
}

const CREATE_POLICY_TEST_SUITES_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS policy_test_suite_versions (
    version INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    suite_json TEXT NOT NULL,
    suite_etag TEXT NOT NULL,
    case_count INTEGER NOT NULL CHECK (case_count >= 1)
);
"#;

/// The standalone suite store. It opens the policy history database
/// (`POLICY_HISTORY_SQLITE_PATH`, or the `<POLICY_FILE>.history.sqlite`
/// default) and keeps its own `policy_test_suite_versions` table there.
#[derive(Clone)]
pub struct SqlitePolicyTestSuiteStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
}

/// Why the standalone suite store could not open. Startup reports it, so
/// unlike a [`RepositoryError`] it names the path.
#[derive(Debug)]
pub struct PolicyTestSuiteStoreOpenError {
    path: PathBuf,
    source: rusqlite::Error,
}

impl fmt::Display for PolicyTestSuiteStoreOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to open the policy test suite store at {}: {}",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for PolicyTestSuiteStoreOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl SqlitePolicyTestSuiteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PolicyTestSuiteStoreOpenError> {
        let path = path.as_ref().to_path_buf();
        let opened = Connection::open(&path)
            .and_then(|connection| {
                connection
                    .execute_batch(CREATE_POLICY_TEST_SUITES_SCHEMA_SQL)
                    .map(|()| connection)
            })
            .map_err(|source| {
                tracing::error!(operation = OPERATION_OPEN, error = %source, "policy test suite store failed to open");
                PolicyTestSuiteStoreOpenError {
                    path: path.clone(),
                    source,
                }
            })?;
        Ok(Self {
            path,
            connection: Arc::new(Mutex::new(opened)),
        })
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "policy_tests",
                    "lock" => "connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite policy test suite connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }

    fn active_blocking(&self) -> Result<Option<PolicyTestSuiteRecord>, RepositoryError> {
        let connection = self.connection_guard();
        let row = newest_row(&connection, true)
            .map_err(|error| sqlite_failure(OPERATION_ACTIVE, &error))?;
        let Some(row) = row else {
            return Ok(None);
        };
        suite_from_stored(
            &row.suite_json,
            &row.suite_etag,
            row.version,
            None,
            OPERATION_ACTIVE,
        )
        .map(Some)
    }

    fn commit_blocking(
        &self,
        precondition: &PolicyTestSuitePrecondition,
        actor_user_id: &str,
        stored: StorableSuite,
    ) -> Result<PolicyTestSuiteRecord, PolicyTestSuiteCommitError> {
        let fail = |error: rusqlite::Error| {
            PolicyTestSuiteCommitError::Store(sqlite_failure(OPERATION_COMMIT, &error))
        };
        let created_at = OffsetDateTime::now_utc().format(&Rfc3339).map_err(|_| {
            PolicyTestSuiteCommitError::Store(RepositoryError::new(
                RepositoryErrorKind::Internal,
                OPERATION_COMMIT,
            ))
        })?;
        let case_count = i64::try_from(stored.suite.cases.len()).map_err(|_| {
            PolicyTestSuiteCommitError::Store(RepositoryError::invalid_parameter(
                OPERATION_COMMIT,
                "suite",
            ))
        })?;
        let mut connection = self.connection_guard();
        // IMMEDIATE takes the write lock before the active row is read, so
        // the precondition check and the append are one unit: a second
        // connection to this file waits instead of reading the same ETag.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(fail)?;
        let current = newest_row(&transaction, false).map_err(fail)?;
        let holds = match (precondition, &current) {
            (PolicyTestSuitePrecondition::Expected { etag }, Some(row)) => *etag == row.suite_etag,
            (PolicyTestSuitePrecondition::Absent, None) => true,
            _ => false,
        };
        if !holds {
            // Dropping the transaction rolls it back; nothing was written.
            return Err(PolicyTestSuiteCommitError::PreconditionFailed);
        }
        transaction
            .execute(
                "INSERT INTO policy_test_suite_versions (
                     actor_user_id, created_at, suite_json, suite_etag, case_count
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    actor_user_id,
                    created_at,
                    stored.canonical_json,
                    stored.etag,
                    case_count
                ],
            )
            .map_err(fail)?;
        let version = transaction.last_insert_rowid();
        transaction.commit().map_err(fail)?;
        Ok(stored.into_record(version, None))
    }
}

/// The newest stored row, which is the active version.
struct NewestRow {
    version: i64,
    suite_json: String,
    suite_etag: String,
}

fn newest_row(connection: &Connection, with_document: bool) -> rusqlite::Result<Option<NewestRow>> {
    let sql = if with_document {
        "SELECT version, suite_json, suite_etag FROM policy_test_suite_versions
         ORDER BY version DESC LIMIT 1"
    } else {
        "SELECT version, '', suite_etag FROM policy_test_suite_versions
         ORDER BY version DESC LIMIT 1"
    };
    connection
        .query_row(sql, [], |row| {
            Ok(NewestRow {
                version: row.get(0)?,
                suite_json: row.get(1)?,
                suite_etag: row.get(2)?,
            })
        })
        .optional()
}

#[async_trait]
impl PolicyTestSuiteStore for SqlitePolicyTestSuiteStore {
    async fn active(&self) -> Result<Option<PolicyTestSuiteRecord>, RepositoryError> {
        let store = self.clone();
        run_blocking(move || store.active_blocking()).await
    }

    async fn commit(
        &self,
        precondition: PolicyTestSuitePrecondition,
        document: &Value,
        actor: &Principal,
    ) -> Result<PolicyTestSuiteRecord, PolicyTestSuiteCommitError> {
        let stored = storable_suite(document, OPERATION_COMMIT)
            .map_err(PolicyTestSuiteCommitError::Store)?;
        let store = self.clone();
        let actor_user_id = actor.user_id.clone();
        run_blocking(move || {
            Ok::<_, RepositoryError>(store.commit_blocking(&precondition, &actor_user_id, stored))
        })
        .await
        .map_err(PolicyTestSuiteCommitError::Store)?
    }
}

fn sqlite_failure(operation: &'static str, error: &rusqlite::Error) -> RepositoryError {
    log_classified(operation, error, classify_rusqlite(operation, error))
}

#[cfg(test)]
#[path = "policy_tests_tests.rs"]
mod tests;
