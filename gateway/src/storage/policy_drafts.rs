//! Server-side policy drafts (issue #243, slice 9): the repository contract
//! and its standalone SQLite adapter.
//!
//! A draft is an owner-scoped, expiring candidate policy pinned to the live
//! policy ETag it was edited from. It is inactive by construction: nothing in
//! this module reaches the policy authority, and a draft only ever becomes
//! enforcement through the separate publish operation
//! (`admin_policy_drafts`), which commits it through the ordinary policy
//! mutation path under the live `If-Match`.
//!
//! Both adapters satisfy one contract (`contract_tests`):
//!
//! - Every read and write is scoped to its owner, the issuer and subject of
//!   the principal that created the draft. Another owner's draft is
//!   indistinguishable from a missing one.
//! - `revision` starts at 1 and advances on every successful write. A write
//!   names the revision it read and changes nothing when the row has moved
//!   on, expired, or been published (compare-and-set), so of two writers
//!   holding the same revision exactly one wins.
//! - Expiry is judged on the authority's own clock: the process clock for
//!   SQLite, which is the standalone authority, and database time for
//!   PostgreSQL (`docs/architecture/ha-state-model.md`, section 2 rule 5).
//!   An expired draft is never written, counted against a quota, or listed;
//!   reading it reports it expired until a later create prunes it.
//! - Creation is bounded per owner and per deployment, counted over
//!   unexpired drafts inside the inserting transaction after a bounded prune
//!   of expired rows, so two creators cannot both take the last slot.
//! - A stored candidate is re-validated on every read and must reproduce the
//!   ETag recorded beside it. A row that does not is `InvalidData` and is
//!   never served.

use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde_json::Value;
use time::OffsetDateTime;

use crate::metrics::LOCK_POISON_RECOVERIES_TOTAL;
use crate::rbac::Policy;

use super::{
    classify_rusqlite, log_classified, run_blocking, RepositoryError, RepositoryErrorKind,
};

/// How long a draft lives after its last write. Publication does not extend
/// it. A compile-time ceiling, not configuration (ADR-0004: every ephemeral
/// draft has a positive TTL that configuration can never raise).
pub const POLICY_DRAFT_TTL_SECS: i64 = 24 * 60 * 60;
/// Unexpired drafts one owner may hold, published ones included.
pub const MAX_POLICY_DRAFTS_PER_OWNER: usize = 8;
/// Unexpired drafts one deployment may hold across every owner.
pub const MAX_POLICY_DRAFTS: usize = 128;
/// The largest candidate a draft stores, as its serialized JSON. With the
/// deployment bound this caps what drafts can occupy at 128 MiB.
pub const MAX_POLICY_DRAFT_CANDIDATE_BYTES: usize = 1024 * 1024;
/// Expired rows removed per create, oldest expiry first, so cleanup work is
/// bounded by the create rate rather than by how long drafts sat unused.
pub(crate) const POLICY_DRAFT_PRUNE_BATCH: i64 = 64;

/// The prefix of every draft identifier. The rest is 32 lowercase
/// hexadecimal characters of operating-system randomness.
pub const POLICY_DRAFT_ID_PREFIX: &str = "pd_";
const POLICY_DRAFT_ID_HEX_LEN: usize = 32;

const OPERATION_OPEN: &str = "policy_draft_open";
const OPERATION_CREATE: &str = "policy_draft_create";
const OPERATION_GET: &str = "policy_draft_get";
const OPERATION_LIST: &str = "policy_draft_list";
const OPERATION_UPDATE: &str = "policy_draft_update";
const OPERATION_DELETE: &str = "policy_draft_delete";

/// The bounds a draft store enforces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyDraftLimits {
    pub ttl_secs: i64,
    pub max_per_owner: usize,
    pub max_total: usize,
}

impl Default for PolicyDraftLimits {
    fn default() -> Self {
        Self {
            ttl_secs: POLICY_DRAFT_TTL_SECS,
            max_per_owner: MAX_POLICY_DRAFTS_PER_OWNER,
            max_total: MAX_POLICY_DRAFTS,
        }
    }
}

/// Who a draft belongs to: the canonical issuer (empty when the principal
/// has none) and the subject. Both are compared exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDraftOwner {
    pub issuer: String,
    pub subject: String,
}

/// A draft to insert. The store derives the candidate's ETag itself, so a
/// caller cannot record one that does not describe the candidate.
pub struct NewPolicyDraft<'a> {
    pub draft_id: &'a str,
    pub owner: &'a PolicyDraftOwner,
    pub base_etag: &'a str,
    pub candidate: &'a Policy,
}

/// One compare-and-set write to an open, unexpired draft.
pub enum PolicyDraftChange<'a> {
    /// Replace the candidate and the base it is pinned to (either may be
    /// unchanged), and restart the TTL.
    Candidate {
        candidate: &'a Policy,
        base_etag: &'a str,
    },
    /// Record that the candidate was published as `published_etag`. Terminal:
    /// a published draft accepts no further change. The TTL is not extended.
    Published { published_etag: &'a str },
}

/// A draft's metadata. Times are Unix seconds on the store's clock;
/// `expired` was judged on that clock when the row was read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyDraftSummary {
    pub draft_id: String,
    pub revision: i64,
    pub base_etag: String,
    pub candidate_etag: String,
    pub published_etag: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
    pub expired: bool,
}

/// A draft with its validated candidate.
#[derive(Clone, Debug)]
pub struct PolicyDraftRecord {
    pub summary: PolicyDraftSummary,
    pub candidate: Policy,
}

/// The outcome of a create. The record is boxed: it carries a whole policy
/// document, and the refusals carry nothing.
#[derive(Debug)]
pub enum PolicyDraftCreated {
    Created(Box<PolicyDraftRecord>),
    /// The owner already holds the per-owner maximum. Nothing was inserted.
    OwnerQuotaExceeded,
    /// The deployment already holds the deployment-wide maximum. Nothing
    /// was inserted.
    DeploymentQuotaExceeded,
}

/// Contract for the server-side policy draft workspace.
#[async_trait]
pub trait PolicyDraftStore: Send + Sync {
    /// The bounds this store enforces, for clients to be told.
    fn limits(&self) -> PolicyDraftLimits;

    /// Insert a draft at revision 1, within the quotas.
    async fn create(
        &self,
        draft: NewPolicyDraft<'_>,
    ) -> Result<PolicyDraftCreated, RepositoryError>;

    /// The owner's draft, expired or not, or `None`.
    async fn get(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
    ) -> Result<Option<PolicyDraftRecord>, RepositoryError>;

    /// The owner's unexpired drafts, most recently written first.
    async fn list(
        &self,
        owner: &PolicyDraftOwner,
    ) -> Result<Vec<PolicyDraftSummary>, RepositoryError>;

    /// Apply `change` if the draft is still at `expected_revision`, open and
    /// unexpired. `None` means nothing was written.
    async fn update(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
        change: PolicyDraftChange<'_>,
    ) -> Result<Option<PolicyDraftRecord>, RepositoryError>;

    /// Delete the draft if it is still at `expected_revision` and unexpired.
    /// Published drafts may be deleted. `false` means nothing was deleted.
    async fn delete(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
    ) -> Result<bool, RepositoryError>;
}

/// Whether `value` has the shape of a draft identifier. Anything else names
/// no draft, so it never reaches a store.
pub fn is_policy_draft_id(value: &str) -> bool {
    value
        .strip_prefix(POLICY_DRAFT_ID_PREFIX)
        .is_some_and(|hex| {
            hex.len() == POLICY_DRAFT_ID_HEX_LEN
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// A candidate as both adapters store it: its serialized JSON and the
/// policy ETag of that document.
pub(crate) struct StoredCandidate {
    pub(crate) json: String,
    pub(crate) etag: String,
}

pub(crate) fn stored_candidate(
    candidate: &Policy,
    operation: &'static str,
) -> Result<StoredCandidate, RepositoryError> {
    let json = serde_json::to_string(candidate)
        .map_err(|_| RepositoryError::new(RepositoryErrorKind::InvalidData, operation))?;
    if json.len() > MAX_POLICY_DRAFT_CANDIDATE_BYTES {
        return Err(RepositoryError::invalid_parameter(operation, "candidate"));
    }
    let etag = crate::policy_etag(candidate)
        .map_err(|_| RepositoryError::new(RepositoryErrorKind::InvalidData, operation))?;
    Ok(StoredCandidate { json, etag })
}

/// Parse a stored candidate back into a policy this binary serves, and
/// confirm it is the document its recorded ETag describes. A row edited
/// out of band, or written by a build whose policy schema this one does not
/// accept, fails closed here rather than being offered for publication.
pub(crate) fn candidate_from_stored(
    json: &str,
    recorded_etag: &str,
    operation: &'static str,
) -> Result<Policy, RepositoryError> {
    let invalid = || RepositoryError::new(RepositoryErrorKind::InvalidData, operation);
    let value = serde_json::from_str::<Value>(json).map_err(|_| invalid())?;
    let policy = Policy::validate_json_value(value).map_err(|_| invalid())?;
    let etag = crate::policy_etag(&policy).map_err(|_| invalid())?;
    if etag != recorded_etag {
        tracing::error!(
            operation,
            "a stored policy draft does not reproduce its recorded ETag; refusing it"
        );
        return Err(invalid());
    }
    Ok(policy)
}

const CREATE_POLICY_DRAFTS_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS policy_drafts (
    draft_id TEXT PRIMARY KEY NOT NULL,
    owner_issuer TEXT NOT NULL,
    owner_subject TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision >= 1),
    base_etag TEXT NOT NULL,
    candidate_json TEXT NOT NULL,
    candidate_etag TEXT NOT NULL,
    published_etag TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (expires_at > updated_at)
);

CREATE INDEX IF NOT EXISTS idx_policy_drafts_expires_at
ON policy_drafts(expires_at);
"#;

const SELECT_SUMMARY_COLUMNS: &str = "draft_id, revision, base_etag, candidate_etag, \
     published_etag, created_at, updated_at, expires_at";

/// The standalone draft store. It opens the policy history database
/// (`POLICY_HISTORY_SQLITE_PATH`, or the `<POLICY_FILE>.history.sqlite`
/// default) and keeps its own `policy_drafts` table there, beside
/// `policy_versions`.
#[derive(Clone)]
pub struct SqlitePolicyDraftStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
    limits: PolicyDraftLimits,
}

/// Why the standalone draft store could not open. Startup reports it, so
/// unlike a [`RepositoryError`] it names the path.
#[derive(Debug)]
pub struct PolicyDraftStoreOpenError {
    path: PathBuf,
    source: rusqlite::Error,
}

impl fmt::Display for PolicyDraftStoreOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "failed to open the policy draft store at {}: {}",
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for PolicyDraftStoreOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl SqlitePolicyDraftStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PolicyDraftStoreOpenError> {
        let path = path.as_ref().to_path_buf();
        let opened = Connection::open(&path)
            .and_then(|connection| {
                connection
                    .execute_batch(CREATE_POLICY_DRAFTS_SCHEMA_SQL)
                    .map(|()| connection)
            })
            .map_err(|source| {
                tracing::error!(operation = OPERATION_OPEN, error = %source, "policy draft store failed to open");
                PolicyDraftStoreOpenError {
                    path: path.clone(),
                    source,
                }
            })?;
        Ok(Self {
            path,
            connection: Arc::new(Mutex::new(opened)),
            limits: PolicyDraftLimits::default(),
        })
    }

    /// The same store under smaller bounds, so the quota and TTL contracts
    /// are testable without filling a deployment.
    #[cfg(test)]
    pub(crate) fn with_limits(mut self, limits: PolicyDraftLimits) -> Self {
        self.limits = limits;
        self
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "policy_drafts",
                    "lock" => "connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite policy draft connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }

    fn create_blocking(
        &self,
        draft_id: &str,
        owner: &PolicyDraftOwner,
        base_etag: &str,
        candidate: Policy,
        stored: &StoredCandidate,
    ) -> Result<PolicyDraftCreated, RepositoryError> {
        let fail = |error: rusqlite::Error| sqlite_failure(OPERATION_CREATE, &error);
        let now = now_unix();
        let expires_at = now.saturating_add(self.limits.ttl_secs);
        let mut connection = self.connection_guard();
        // IMMEDIATE takes the write lock before the counts are read, so the
        // prune, the quota check and the insert are one unit: a second
        // connection to this file waits instead of counting the same slot.
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(fail)?;
        transaction
            .execute(
                "DELETE FROM policy_drafts WHERE draft_id IN (
                     SELECT draft_id FROM policy_drafts
                     WHERE expires_at <= ?1
                     ORDER BY expires_at, draft_id
                     LIMIT ?2
                 )",
                params![now, POLICY_DRAFT_PRUNE_BATCH],
            )
            .map_err(fail)?;
        let (owned, total): (i64, i64) = transaction
            .query_row(
                "SELECT
                     COALESCE(SUM(CASE WHEN owner_issuer = ?1 AND owner_subject = ?2
                                       THEN 1 ELSE 0 END), 0),
                     COUNT(*)
                 FROM policy_drafts
                 WHERE expires_at > ?3",
                params![owner.issuer, owner.subject, now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(fail)?;
        let quota = if count_reaches(owned, self.limits.max_per_owner) {
            Some(PolicyDraftCreated::OwnerQuotaExceeded)
        } else if count_reaches(total, self.limits.max_total) {
            Some(PolicyDraftCreated::DeploymentQuotaExceeded)
        } else {
            None
        };
        if let Some(refused) = quota {
            // The prune is kept: cleanup progress never depends on a slot.
            transaction.commit().map_err(fail)?;
            return Ok(refused);
        }
        transaction
            .execute(
                "INSERT INTO policy_drafts (
                     draft_id, owner_issuer, owner_subject, revision, base_etag,
                     candidate_json, candidate_etag, published_etag,
                     created_at, updated_at, expires_at
                 ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, NULL, ?7, ?7, ?8)",
                params![
                    draft_id,
                    owner.issuer,
                    owner.subject,
                    base_etag,
                    stored.json,
                    stored.etag,
                    now,
                    expires_at
                ],
            )
            .map_err(fail)?;
        transaction.commit().map_err(fail)?;
        Ok(PolicyDraftCreated::Created(Box::new(PolicyDraftRecord {
            summary: PolicyDraftSummary {
                draft_id: draft_id.to_owned(),
                revision: 1,
                base_etag: base_etag.to_owned(),
                candidate_etag: stored.etag.clone(),
                published_etag: None,
                created_at: now,
                updated_at: now,
                expires_at,
                expired: false,
            },
            candidate,
        })))
    }

    fn get_blocking(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
    ) -> Result<Option<PolicyDraftRecord>, RepositoryError> {
        let connection = self.connection_guard();
        read_record(&connection, owner, draft_id, now_unix(), OPERATION_GET)
    }

    fn list_blocking(
        &self,
        owner: &PolicyDraftOwner,
    ) -> Result<Vec<PolicyDraftSummary>, RepositoryError> {
        let fail = |error: rusqlite::Error| sqlite_failure(OPERATION_LIST, &error);
        let now = now_unix();
        let limit = i64::try_from(self.limits.max_total).unwrap_or(i64::MAX);
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(&format!(
                "SELECT {SELECT_SUMMARY_COLUMNS} FROM policy_drafts
                 WHERE owner_issuer = ?1 AND owner_subject = ?2 AND expires_at > ?3
                 ORDER BY updated_at DESC, draft_id ASC
                 LIMIT ?4"
            ))
            .map_err(fail)?;
        let rows = statement
            .query_map(params![owner.issuer, owner.subject, now, limit], |row| {
                summary_from_row(row, now)
            })
            .map_err(fail)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(fail)?;
        Ok(rows)
    }

    fn update_blocking(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
        change: OwnedChange,
    ) -> Result<Option<PolicyDraftRecord>, RepositoryError> {
        let fail = |error: rusqlite::Error| sqlite_failure(OPERATION_UPDATE, &error);
        let now = now_unix();
        let mut connection = self.connection_guard();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(fail)?;
        let changed = match &change {
            OwnedChange::Candidate { stored, base_etag } => transaction
                .execute(
                    "UPDATE policy_drafts
                     SET candidate_json = ?1, candidate_etag = ?2, base_etag = ?3,
                         revision = revision + 1, updated_at = ?4, expires_at = ?5
                     WHERE draft_id = ?6 AND owner_issuer = ?7 AND owner_subject = ?8
                       AND revision = ?9 AND published_etag IS NULL AND expires_at > ?4",
                    params![
                        stored.json,
                        stored.etag,
                        base_etag,
                        now,
                        now.saturating_add(self.limits.ttl_secs),
                        draft_id,
                        owner.issuer,
                        owner.subject,
                        expected_revision
                    ],
                )
                .map_err(fail)?,
            OwnedChange::Published { published_etag } => transaction
                .execute(
                    "UPDATE policy_drafts
                     SET published_etag = ?1, revision = revision + 1, updated_at = ?2
                     WHERE draft_id = ?3 AND owner_issuer = ?4 AND owner_subject = ?5
                       AND revision = ?6 AND published_etag IS NULL AND expires_at > ?2",
                    params![
                        published_etag,
                        now,
                        draft_id,
                        owner.issuer,
                        owner.subject,
                        expected_revision
                    ],
                )
                .map_err(fail)?,
        };
        if changed != 1 {
            return Ok(None);
        }
        let record = read_record(&transaction, owner, draft_id, now, OPERATION_UPDATE)?;
        transaction.commit().map_err(fail)?;
        Ok(record)
    }

    fn delete_blocking(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
    ) -> Result<bool, RepositoryError> {
        let connection = self.connection_guard();
        let deleted = connection
            .execute(
                "DELETE FROM policy_drafts
                 WHERE draft_id = ?1 AND owner_issuer = ?2 AND owner_subject = ?3
                   AND revision = ?4 AND expires_at > ?5",
                params![
                    draft_id,
                    owner.issuer,
                    owner.subject,
                    expected_revision,
                    now_unix()
                ],
            )
            .map_err(|error| sqlite_failure(OPERATION_DELETE, &error))?;
        Ok(deleted == 1)
    }
}

/// A change with its candidate already serialized, so the blocking closure
/// owns everything it writes.
enum OwnedChange {
    Candidate {
        stored: StoredCandidate,
        base_etag: String,
    },
    Published {
        published_etag: String,
    },
}

#[async_trait]
impl PolicyDraftStore for SqlitePolicyDraftStore {
    fn limits(&self) -> PolicyDraftLimits {
        self.limits
    }

    async fn create(
        &self,
        draft: NewPolicyDraft<'_>,
    ) -> Result<PolicyDraftCreated, RepositoryError> {
        let stored = stored_candidate(draft.candidate, OPERATION_CREATE)?;
        let store = self.clone();
        let draft_id = draft.draft_id.to_owned();
        let owner = draft.owner.clone();
        let base_etag = draft.base_etag.to_owned();
        let candidate = draft.candidate.clone();
        run_blocking(move || {
            store.create_blocking(&draft_id, &owner, &base_etag, candidate, &stored)
        })
        .await
    }

    async fn get(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
    ) -> Result<Option<PolicyDraftRecord>, RepositoryError> {
        let store = self.clone();
        let owner = owner.clone();
        let draft_id = draft_id.to_owned();
        run_blocking(move || store.get_blocking(&owner, &draft_id)).await
    }

    async fn list(
        &self,
        owner: &PolicyDraftOwner,
    ) -> Result<Vec<PolicyDraftSummary>, RepositoryError> {
        let store = self.clone();
        let owner = owner.clone();
        run_blocking(move || store.list_blocking(&owner)).await
    }

    async fn update(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
        change: PolicyDraftChange<'_>,
    ) -> Result<Option<PolicyDraftRecord>, RepositoryError> {
        let change = match change {
            PolicyDraftChange::Candidate {
                candidate,
                base_etag,
            } => OwnedChange::Candidate {
                stored: stored_candidate(candidate, OPERATION_UPDATE)?,
                base_etag: base_etag.to_owned(),
            },
            PolicyDraftChange::Published { published_etag } => OwnedChange::Published {
                published_etag: published_etag.to_owned(),
            },
        };
        let store = self.clone();
        let owner = owner.clone();
        let draft_id = draft_id.to_owned();
        run_blocking(move || store.update_blocking(&owner, &draft_id, expected_revision, change))
            .await
    }

    async fn delete(
        &self,
        owner: &PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
    ) -> Result<bool, RepositoryError> {
        let store = self.clone();
        let owner = owner.clone();
        let draft_id = draft_id.to_owned();
        run_blocking(move || store.delete_blocking(&owner, &draft_id, expected_revision)).await
    }
}

/// Whether `count` rows already fill a bound of `limit`.
pub(crate) fn count_reaches(count: i64, limit: usize) -> bool {
    usize::try_from(count).map_or(true, |count| count >= limit)
}

fn read_record(
    connection: &Connection,
    owner: &PolicyDraftOwner,
    draft_id: &str,
    now: i64,
    operation: &'static str,
) -> Result<Option<PolicyDraftRecord>, RepositoryError> {
    let row = connection
        .query_row(
            &format!(
                "SELECT {SELECT_SUMMARY_COLUMNS}, candidate_json FROM policy_drafts
                 WHERE draft_id = ?1 AND owner_issuer = ?2 AND owner_subject = ?3"
            ),
            params![draft_id, owner.issuer, owner.subject],
            |row| Ok((summary_from_row(row, now)?, row.get::<_, String>(8)?)),
        )
        .optional()
        .map_err(|error| sqlite_failure(operation, &error))?;
    let Some((summary, candidate_json)) = row else {
        return Ok(None);
    };
    let candidate = candidate_from_stored(&candidate_json, &summary.candidate_etag, operation)?;
    Ok(Some(PolicyDraftRecord { summary, candidate }))
}

fn summary_from_row(row: &rusqlite::Row<'_>, now: i64) -> rusqlite::Result<PolicyDraftSummary> {
    let expires_at: i64 = row.get(7)?;
    Ok(PolicyDraftSummary {
        draft_id: row.get(0)?,
        revision: row.get(1)?,
        base_etag: row.get(2)?,
        candidate_etag: row.get(3)?,
        published_etag: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        expires_at,
        expired: expires_at <= now,
    })
}

fn sqlite_failure(operation: &'static str, error: &rusqlite::Error) -> RepositoryError {
    log_classified(operation, error, classify_rusqlite(operation, error))
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}
