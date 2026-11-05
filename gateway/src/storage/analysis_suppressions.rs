//! Policy analysis suppressions (issue #243, slice 15): the repository
//! contract and its standalone SQLite adapter.
//!
//! A suppression is an operator's reviewed decision that one analyzer
//! finding, in one policy and against one set of resources, needs no change
//! until a stated time. It hides nothing by itself: the analysis report
//! (`policy_analysis::suppression`) marks a finding suppressed only when the
//! finding's fingerprint and code, the analyzed policy's ETag and semantic
//! digest and the resource snapshot digest all equal the record's, and the
//! record has not ended. Nothing in this module reaches the policy authority
//! or the evaluator.
//!
//! Both adapters satisfy one contract (`contract_tests`):
//!
//! - Every suppression has an expiry, at most [`MAX_ANALYSIS_SUPPRESSION_TTL_SECS`]
//!   after its creation on the authority's own clock: the process clock for
//!   SQLite, which is the standalone authority, and database time for
//!   PostgreSQL (`docs/architecture/ha-state-model.md`, section 2 rule 5).
//!   A create whose expiry is not inside that window writes nothing.
//! - A suppression is never edited. It is created at revision 1 and can only
//!   be withdrawn, which ends it at once and moves it to revision 2; a
//!   withdrawal names the revision it read (compare-and-set), so of two
//!   writers holding one revision exactly one wins, and an ended suppression
//!   takes no write at all.
//! - Creation is bounded per deployment, counted over suppressions that have
//!   not ended, inside the inserting transaction, so two creators cannot both
//!   take the last slot. A create is also refused while an unended
//!   suppression with the same finding and binding exists.
//! - Ended suppressions stay readable, so a report can say a finding's
//!   suppression expired, until a create needs their room: the table never
//!   holds more than the deployment bound, and the earliest-ended rows go
//!   first.
//! - A row whose shape no gateway path writes is `InvalidData` and is never
//!   served.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use time::OffsetDateTime;

use crate::metrics::LOCK_POISON_RECOVERIES_TOTAL;

use super::{
    classify_rusqlite, log_classified, policy_drafts::count_reaches, run_blocking, RepositoryError,
    RepositoryErrorKind,
};

/// The longest a suppression may last, from its creation. A compile-time
/// ceiling, not configuration: a reviewed decision is reviewed again at
/// least this often.
pub const MAX_ANALYSIS_SUPPRESSION_TTL_SECS: i64 = 90 * 24 * 60 * 60;
/// Suppressions that have not ended one deployment may hold. With the
/// retained ended rows this is also the most rows the table holds.
pub const MAX_ANALYSIS_SUPPRESSIONS: usize = 256;
/// The largest reason, in bytes. The reason is shown to policy readers who
/// may analyze, and never enters an audit event, a metric or a report.
pub const MAX_ANALYSIS_SUPPRESSION_REASON_BYTES: usize = 512;
/// The prefix of every suppression identifier. The rest is 32 lowercase
/// hexadecimal characters of operating-system randomness.
pub const ANALYSIS_SUPPRESSION_ID_PREFIX: &str = "pas_";
const ANALYSIS_SUPPRESSION_ID_HEX_LEN: usize = 32;
/// The bounds of an actor, exactly the bounds authentication enforces.
const MAX_ACTOR_ISSUER_BYTES: usize = crate::auth::principal::MAX_PRINCIPAL_ISSUER_BYTES;
const MAX_ACTOR_SUBJECT_BYTES: usize = crate::auth::principal::MAX_PRINCIPAL_SUBJECT_BYTES;
/// The longest finding code a row may carry: the analyzer's codes are short
/// identifiers, and a row written by a later analyzer is still bounded.
const MAX_CODE_BYTES: usize = 64;

const OPERATION_OPEN: &str = "analysis_suppression_open";
const OPERATION_CREATE: &str = "analysis_suppression_create";
const OPERATION_GET: &str = "analysis_suppression_get";
const OPERATION_LIST: &str = "analysis_suppression_list";
const OPERATION_WITHDRAW: &str = "analysis_suppression_withdraw";

/// The bounds a suppression store enforces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalysisSuppressionLimits {
    pub max_ttl_secs: i64,
    pub max_total: usize,
}

impl Default for AnalysisSuppressionLimits {
    fn default() -> Self {
        Self {
            max_ttl_secs: MAX_ANALYSIS_SUPPRESSION_TTL_SECS,
            max_total: MAX_ANALYSIS_SUPPRESSIONS,
        }
    }
}

/// Who created a suppression: the canonical issuer (empty when the
/// principal has none) and the subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisSuppressionActor {
    pub issuer: String,
    pub subject: String,
}

/// A suppression to insert. Its creation time is the store's.
pub struct NewAnalysisSuppression<'a> {
    pub suppression_id: &'a str,
    /// The finding's `sha256:` fingerprint.
    pub fingerprint: &'a str,
    /// The finding's stable code.
    pub code: &'a str,
    pub reason: &'a str,
    pub actor: &'a AnalysisSuppressionActor,
    /// The ETag of the policy the finding was reviewed in.
    pub policy_etag: &'a str,
    /// That policy's ADR-0004 semantic digest, when its document format has
    /// one (policy v1).
    pub policy_semantic_digest: Option<&'a str>,
    /// The digest of the resource snapshot the finding was reviewed against.
    pub resource_snapshot_digest: &'a str,
    /// Unix seconds. Must be after the store's now and no more than the
    /// maximum TTL after it.
    pub expires_at: i64,
}

/// A stored suppression. Times are Unix seconds on the store's clock;
/// `ended` was judged on that clock when the row was read: the suppression
/// was withdrawn, or its expiry has passed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisSuppressionRecord {
    pub suppression_id: String,
    pub revision: i64,
    pub fingerprint: String,
    pub code: String,
    pub reason: String,
    pub actor: AnalysisSuppressionActor,
    pub policy_etag: String,
    pub policy_semantic_digest: Option<String>,
    pub resource_snapshot_digest: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub withdrawn_at: Option<i64>,
    pub ended: bool,
}

/// The outcome of a create. Only `Created` wrote anything.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnalysisSuppressionCreated {
    Created(Box<AnalysisSuppressionRecord>),
    /// The expiry is not after the store's now, or is more than the maximum
    /// TTL after it.
    ExpiryOutOfRange,
    /// An unended suppression of the same finding under the same binding
    /// exists; it is named.
    Duplicate {
        suppression_id: String,
    },
    /// The deployment already holds the maximum of unended suppressions.
    DeploymentQuotaExceeded,
}

/// Contract for the deployment's analysis suppressions.
#[async_trait]
pub trait AnalysisSuppressionStore: Send + Sync {
    /// The bounds this store enforces, for clients to be told.
    fn limits(&self) -> AnalysisSuppressionLimits;

    /// Insert a suppression at revision 1, within the expiry window, the
    /// deployment bound and the duplicate rule.
    async fn create(
        &self,
        suppression: NewAnalysisSuppression<'_>,
    ) -> Result<AnalysisSuppressionCreated, RepositoryError>;

    /// One suppression, ended or not, or `None`.
    async fn get(
        &self,
        suppression_id: &str,
    ) -> Result<Option<AnalysisSuppressionRecord>, RepositoryError>;

    /// Every retained suppression, ended ones included, oldest first, at
    /// most the deployment bound of them.
    async fn list(&self) -> Result<Vec<AnalysisSuppressionRecord>, RepositoryError>;

    /// End the suppression now if it is still at `expected_revision` and has
    /// not ended. `None` means nothing was written.
    async fn withdraw(
        &self,
        suppression_id: &str,
        expected_revision: i64,
    ) -> Result<Option<AnalysisSuppressionRecord>, RepositoryError>;
}

/// Whether `value` has the shape of a suppression identifier. Anything else
/// names no suppression, so it never reaches a store.
pub fn is_analysis_suppression_id(value: &str) -> bool {
    value
        .strip_prefix(ANALYSIS_SUPPRESSION_ID_PREFIX)
        .is_some_and(|hex| hex.len() == ANALYSIS_SUPPRESSION_ID_HEX_LEN && is_lower_hex(hex))
}

/// Whether `value` is `sha256:` and 64 lowercase hexadecimal characters: a
/// finding fingerprint, a semantic digest or a resource snapshot digest.
pub fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && is_lower_hex(hex))
}

/// Whether `value` has the exact shape of a policy ETag.
pub fn is_policy_etag(value: &str) -> bool {
    value
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .is_some_and(is_sha256_digest)
}

/// Whether `value` is a reason a suppression may carry: 1 to
/// [`MAX_ANALYSIS_SUPPRESSION_REASON_BYTES`] bytes, not only whitespace,
/// and no control character.
pub fn is_analysis_suppression_reason(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_ANALYSIS_SUPPRESSION_REASON_BYTES
        && !value.chars().any(char::is_control)
}

fn is_lower_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_code(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= MAX_CODE_BYTES
        && bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_actor(actor: &AnalysisSuppressionActor) -> bool {
    actor.issuer.len() <= MAX_ACTOR_ISSUER_BYTES
        && !actor.subject.is_empty()
        && actor.subject.len() <= MAX_ACTOR_SUBJECT_BYTES
}

/// Refuse a suppression no gateway path would write, before any store work.
/// The handler checks the same fields first and answers `422`; this is the
/// store's own guard.
pub(crate) fn check_new(
    suppression: &NewAnalysisSuppression<'_>,
    operation: &'static str,
) -> Result<(), RepositoryError> {
    let checks = [
        (
            is_analysis_suppression_id(suppression.suppression_id),
            "suppression_id",
        ),
        (is_sha256_digest(suppression.fingerprint), "fingerprint"),
        (is_code(suppression.code), "code"),
        (is_analysis_suppression_reason(suppression.reason), "reason"),
        (is_actor(suppression.actor), "actor"),
        (is_policy_etag(suppression.policy_etag), "policy_etag"),
        (
            suppression
                .policy_semantic_digest
                .is_none_or(is_sha256_digest),
            "policy_semantic_digest",
        ),
        (
            is_sha256_digest(suppression.resource_snapshot_digest),
            "resource_snapshot_digest",
        ),
    ];
    match checks.into_iter().find(|(valid, _)| !valid) {
        Some((_, parameter)) => Err(RepositoryError::invalid_parameter(operation, parameter)),
        None => Ok(()),
    }
}

/// Confirm a row read back is one a gateway path writes. A row edited out of
/// band fails closed here rather than being matched against findings.
pub(crate) fn check_record(
    record: AnalysisSuppressionRecord,
    operation: &'static str,
) -> Result<AnalysisSuppressionRecord, RepositoryError> {
    let well_formed = is_analysis_suppression_id(&record.suppression_id)
        && (record.revision == 1) == record.withdrawn_at.is_none()
        && (1..=2).contains(&record.revision)
        && is_sha256_digest(&record.fingerprint)
        && is_code(&record.code)
        && is_analysis_suppression_reason(&record.reason)
        && is_actor(&record.actor)
        && is_policy_etag(&record.policy_etag)
        && record
            .policy_semantic_digest
            .as_deref()
            .is_none_or(is_sha256_digest)
        && is_sha256_digest(&record.resource_snapshot_digest)
        && record.expires_at > record.created_at;
    if !well_formed {
        tracing::error!(
            operation,
            "a stored analysis suppression is not one the gateway writes; refusing it"
        );
        return Err(RepositoryError::new(
            RepositoryErrorKind::InvalidData,
            operation,
        ));
    }
    Ok(record)
}

/// How many ended rows a create must remove so that, with its own row, the
/// table holds no more than `max_total`.
pub(crate) fn excess_rows(total: i64, max_total: usize) -> i64 {
    let max_total = i64::try_from(max_total).unwrap_or(i64::MAX);
    total.saturating_add(1).saturating_sub(max_total).max(0)
}

const CREATE_ANALYSIS_SUPPRESSIONS_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS policy_analysis_suppressions (
    suppression_id TEXT PRIMARY KEY NOT NULL,
    revision INTEGER NOT NULL CHECK (revision IN (1, 2)),
    fingerprint TEXT NOT NULL,
    code TEXT NOT NULL,
    reason TEXT NOT NULL,
    actor_issuer TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    policy_etag TEXT NOT NULL,
    policy_semantic_digest TEXT,
    resource_snapshot_digest TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > created_at),
    withdrawn_at INTEGER CHECK (
        withdrawn_at IS NULL OR (withdrawn_at >= created_at AND withdrawn_at < expires_at)
    ),
    CHECK ((revision = 1) = (withdrawn_at IS NULL))
);
"#;

const SELECT_COLUMNS: &str = "suppression_id, revision, fingerprint, code, reason, \
     actor_issuer, actor_subject, policy_etag, policy_semantic_digest, \
     resource_snapshot_digest, created_at, expires_at, withdrawn_at";

/// The standalone suppression store. It opens the policy history database
/// (`POLICY_HISTORY_SQLITE_PATH`, or the `<POLICY_FILE>.history.sqlite`
/// default) and keeps its own `policy_analysis_suppressions` table there,
/// beside `policy_versions` and `policy_drafts`.
#[derive(Clone)]
pub struct SqliteAnalysisSuppressionStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
    limits: AnalysisSuppressionLimits,
}

/// Why the standalone suppression store could not open. Startup reports
/// it, so unlike a [`RepositoryError`] it names the path.
#[derive(Debug)]
pub struct AnalysisSuppressionStoreOpenError {
    path: PathBuf,
    source: rusqlite::Error,
}

impl fmt::Display for AnalysisSuppressionStoreOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to open the policy analysis suppression store at {}: {}",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for AnalysisSuppressionStoreOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl SqliteAnalysisSuppressionStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AnalysisSuppressionStoreOpenError> {
        let path = path.as_ref().to_path_buf();
        let opened = Connection::open(&path)
            .and_then(|connection| {
                connection
                    .execute_batch(CREATE_ANALYSIS_SUPPRESSIONS_SCHEMA_SQL)
                    .map(|()| connection)
            })
            .map_err(|source| {
                tracing::error!(operation = OPERATION_OPEN, error = %source, "policy analysis suppression store failed to open");
                AnalysisSuppressionStoreOpenError {
                    path: path.clone(),
                    source,
                }
            })?;
        Ok(Self {
            path,
            connection: Arc::new(Mutex::new(opened)),
            limits: AnalysisSuppressionLimits::default(),
        })
    }

    /// The same store under smaller bounds, so the quota and expiry
    /// contracts are testable without filling a deployment.
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, limits: AnalysisSuppressionLimits) -> Self {
        self.limits = limits;
        self
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "policy_analysis_suppressions",
                    "lock" => "connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite policy analysis suppression connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }

    fn create_blocking(
        &self,
        new: &OwnedNew,
    ) -> Result<AnalysisSuppressionCreated, RepositoryError> {
        let fail = |error: rusqlite::Error| sqlite_failure(OPERATION_CREATE, &error);
        let now = now_unix();
        if new.expires_at <= now || new.expires_at > now.saturating_add(self.limits.max_ttl_secs) {
            return Ok(AnalysisSuppressionCreated::ExpiryOutOfRange);
        }
        let mut connection = self.connection_guard();
        // IMMEDIATE takes the write lock before anything is counted, so the
        // duplicate check, the quota, the room-making delete and the insert
        // are one unit: a second connection to this file waits.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(fail)?;
        let duplicate: Option<String> = transaction
            .query_row(
                "SELECT suppression_id FROM policy_analysis_suppressions
                 WHERE fingerprint = ?1 AND code = ?2 AND policy_etag = ?3
                   AND policy_semantic_digest IS ?4 AND resource_snapshot_digest = ?5
                   AND withdrawn_at IS NULL AND expires_at > ?6
                 ORDER BY created_at, suppression_id
                 LIMIT 1",
                params![
                    new.fingerprint,
                    new.code,
                    new.policy_etag,
                    new.policy_semantic_digest,
                    new.resource_snapshot_digest,
                    now
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(fail)?;
        if let Some(suppression_id) = duplicate {
            return Ok(AnalysisSuppressionCreated::Duplicate { suppression_id });
        }
        let (unended, total): (i64, i64) = transaction
            .query_row(
                "SELECT
                     COALESCE(SUM(CASE WHEN withdrawn_at IS NULL AND expires_at > ?1
                                       THEN 1 ELSE 0 END), 0),
                     COUNT(*)
                 FROM policy_analysis_suppressions",
                params![now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(fail)?;
        if count_reaches(unended, self.limits.max_total) {
            return Ok(AnalysisSuppressionCreated::DeploymentQuotaExceeded);
        }
        let excess = excess_rows(total, self.limits.max_total);
        if excess > 0 {
            transaction
                .execute(
                    "DELETE FROM policy_analysis_suppressions WHERE suppression_id IN (
                         SELECT suppression_id FROM policy_analysis_suppressions
                         WHERE withdrawn_at IS NOT NULL OR expires_at <= ?1
                         ORDER BY COALESCE(withdrawn_at, expires_at), suppression_id
                         LIMIT ?2
                     )",
                    params![now, excess],
                )
                .map_err(fail)?;
        }
        transaction
            .execute(
                "INSERT INTO policy_analysis_suppressions (
                     suppression_id, revision, fingerprint, code, reason,
                     actor_issuer, actor_subject, policy_etag, policy_semantic_digest,
                     resource_snapshot_digest, created_at, expires_at, withdrawn_at
                 ) VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)",
                params![
                    new.suppression_id,
                    new.fingerprint,
                    new.code,
                    new.reason,
                    new.actor.issuer,
                    new.actor.subject,
                    new.policy_etag,
                    new.policy_semantic_digest,
                    new.resource_snapshot_digest,
                    now,
                    new.expires_at
                ],
            )
            .map_err(fail)?;
        transaction.commit().map_err(fail)?;
        Ok(AnalysisSuppressionCreated::Created(Box::new(
            AnalysisSuppressionRecord {
                suppression_id: new.suppression_id.clone(),
                revision: 1,
                fingerprint: new.fingerprint.clone(),
                code: new.code.clone(),
                reason: new.reason.clone(),
                actor: new.actor.clone(),
                policy_etag: new.policy_etag.clone(),
                policy_semantic_digest: new.policy_semantic_digest.clone(),
                resource_snapshot_digest: new.resource_snapshot_digest.clone(),
                created_at: now,
                expires_at: new.expires_at,
                withdrawn_at: None,
                ended: false,
            },
        )))
    }

    fn get_blocking(
        &self,
        suppression_id: &str,
    ) -> Result<Option<AnalysisSuppressionRecord>, RepositoryError> {
        let connection = self.connection_guard();
        read_record(&connection, suppression_id, now_unix(), OPERATION_GET)
    }

    fn list_blocking(&self) -> Result<Vec<AnalysisSuppressionRecord>, RepositoryError> {
        let fail = |error: rusqlite::Error| sqlite_failure(OPERATION_LIST, &error);
        let now = now_unix();
        let limit = i64::try_from(self.limits.max_total).unwrap_or(i64::MAX);
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(&format!(
                "SELECT {SELECT_COLUMNS} FROM policy_analysis_suppressions
                 ORDER BY created_at, suppression_id
                 LIMIT ?1"
            ))
            .map_err(fail)?;
        let rows = statement
            .query_map(params![limit], |row| record_from_row(row, now))
            .map_err(fail)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(fail)?;
        rows.into_iter()
            .map(|record| check_record(record, OPERATION_LIST))
            .collect()
    }

    fn withdraw_blocking(
        &self,
        suppression_id: &str,
        expected_revision: i64,
    ) -> Result<Option<AnalysisSuppressionRecord>, RepositoryError> {
        let fail = |error: rusqlite::Error| sqlite_failure(OPERATION_WITHDRAW, &error);
        let now = now_unix();
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(fail)?;
        // MAX keeps the row's own order of events if the process clock
        // stepped back since the suppression was created.
        let changed = transaction
            .execute(
                "UPDATE policy_analysis_suppressions
                 SET withdrawn_at = MAX(?1, created_at), revision = revision + 1
                 WHERE suppression_id = ?2 AND revision = ?3
                   AND withdrawn_at IS NULL AND expires_at > ?1",
                params![now, suppression_id, expected_revision],
            )
            .map_err(fail)?;
        if changed != 1 {
            return Ok(None);
        }
        let record = read_record(&transaction, suppression_id, now, OPERATION_WITHDRAW)?;
        transaction.commit().map_err(fail)?;
        Ok(record)
    }
}

/// A new suppression with every field owned, so the blocking closure owns
/// everything it writes.
struct OwnedNew {
    suppression_id: String,
    fingerprint: String,
    code: String,
    reason: String,
    actor: AnalysisSuppressionActor,
    policy_etag: String,
    policy_semantic_digest: Option<String>,
    resource_snapshot_digest: String,
    expires_at: i64,
}

#[async_trait]
impl AnalysisSuppressionStore for SqliteAnalysisSuppressionStore {
    fn limits(&self) -> AnalysisSuppressionLimits {
        self.limits
    }

    async fn create(
        &self,
        suppression: NewAnalysisSuppression<'_>,
    ) -> Result<AnalysisSuppressionCreated, RepositoryError> {
        check_new(&suppression, OPERATION_CREATE)?;
        let new = OwnedNew {
            suppression_id: suppression.suppression_id.to_owned(),
            fingerprint: suppression.fingerprint.to_owned(),
            code: suppression.code.to_owned(),
            reason: suppression.reason.to_owned(),
            actor: suppression.actor.clone(),
            policy_etag: suppression.policy_etag.to_owned(),
            policy_semantic_digest: suppression.policy_semantic_digest.map(str::to_owned),
            resource_snapshot_digest: suppression.resource_snapshot_digest.to_owned(),
            expires_at: suppression.expires_at,
        };
        let store = self.clone();
        run_blocking(move || store.create_blocking(&new)).await
    }

    async fn get(
        &self,
        suppression_id: &str,
    ) -> Result<Option<AnalysisSuppressionRecord>, RepositoryError> {
        let store = self.clone();
        let suppression_id = suppression_id.to_owned();
        run_blocking(move || store.get_blocking(&suppression_id)).await
    }

    async fn list(&self) -> Result<Vec<AnalysisSuppressionRecord>, RepositoryError> {
        let store = self.clone();
        run_blocking(move || store.list_blocking()).await
    }

    async fn withdraw(
        &self,
        suppression_id: &str,
        expected_revision: i64,
    ) -> Result<Option<AnalysisSuppressionRecord>, RepositoryError> {
        let store = self.clone();
        let suppression_id = suppression_id.to_owned();
        run_blocking(move || store.withdraw_blocking(&suppression_id, expected_revision)).await
    }
}

fn read_record(
    connection: &Connection,
    suppression_id: &str,
    now: i64,
    operation: &'static str,
) -> Result<Option<AnalysisSuppressionRecord>, RepositoryError> {
    let record = connection
        .query_row(
            &format!(
                "SELECT {SELECT_COLUMNS} FROM policy_analysis_suppressions
                 WHERE suppression_id = ?1"
            ),
            params![suppression_id],
            |row| record_from_row(row, now),
        )
        .optional()
        .map_err(|error| sqlite_failure(operation, &error))?;
    record
        .map(|record| check_record(record, operation))
        .transpose()
}

fn record_from_row(
    row: &rusqlite::Row<'_>,
    now: i64,
) -> rusqlite::Result<AnalysisSuppressionRecord> {
    let expires_at: i64 = row.get(11)?;
    let withdrawn_at: Option<i64> = row.get(12)?;
    Ok(AnalysisSuppressionRecord {
        suppression_id: row.get(0)?,
        revision: row.get(1)?,
        fingerprint: row.get(2)?,
        code: row.get(3)?,
        reason: row.get(4)?,
        actor: AnalysisSuppressionActor {
            issuer: row.get(5)?,
            subject: row.get(6)?,
        },
        policy_etag: row.get(7)?,
        policy_semantic_digest: row.get(8)?,
        resource_snapshot_digest: row.get(9)?,
        created_at: row.get(10)?,
        expires_at,
        withdrawn_at,
        ended: withdrawn_at.is_some() || expires_at <= now,
    })
}

fn sqlite_failure(operation: &'static str, error: &rusqlite::Error) -> RepositoryError {
    log_classified(operation, error, classify_rusqlite(operation, error))
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
