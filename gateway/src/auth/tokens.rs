#![allow(dead_code)] // Service-token storage is wired into admin APIs and validators in issue #39 PR2.

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{
    auth::change_actor::ChangeActor,
    authority_events::caller_operation::{
        CallerKeyReservation, CallerKeyState, CallerOperation, CallerOutcome, OperationReceipt,
    },
    metrics::LOCK_POISON_RECOVERIES_TOTAL,
};

const CREATE_SERVICE_TOKEN_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS service_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    scopes_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    last_used_at TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_service_tokens_created
ON service_tokens(created_at DESC, id ASC);

CREATE INDEX IF NOT EXISTS idx_service_tokens_revoked
ON service_tokens(revoked_at);
"#;

/// The change evidence table (issue #425): one append-only row per committed
/// issue, rotate or revoke, written in the same transaction as the token
/// change, naming who made it. Created on open like the token table, so a
/// database an older binary wrote gains it on the first open by this one and
/// an older binary simply never reads it. No foreign key, so a removed token
/// row leaves its evidence; identifiers and the actor only, never the
/// plaintext, hash, prefix or scopes. The actor bound is the principal
/// subject bound (MAX_TOKEN_CHANGE_ACTOR_BYTES).
///
/// The column list is shared by the create-on-open statement and by the
/// rebuild that widens an older table's action vocabulary
/// ([`rebuild_change_evidence_for_issue`]), so both produce the same table.
const CHANGE_EVIDENCE_COLUMNS_SQL: &str = r#"
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 36),
    operation_id TEXT NOT NULL CHECK (length(operation_id) = 36),
    actor_user_id TEXT NOT NULL CHECK (
        length(CAST(actor_user_id AS BLOB)) BETWEEN 1 AND 4096
    ),
    action TEXT NOT NULL CHECK (
        action IN ('service_token.issue', 'service_token.rotate', 'service_token.revoke')
    ),
    token_id TEXT NOT NULL CHECK (length(CAST(token_id AS BLOB)) BETWEEN 1 AND 128),
    committed_at TEXT NOT NULL,
    UNIQUE (operation_id, action)
"#;

/// The evidence table's one index: a token's evidence in commit order.
const CHANGE_EVIDENCE_INDEX_SQL: &str = r#"
CREATE INDEX IF NOT EXISTS idx_service_token_change_evidence_token
ON service_token_change_evidence(token_id, sequence);
"#;

/// The name the widened table is built under before it replaces the older
/// one. It exists only inside the rebuild's transaction.
const CHANGE_EVIDENCE_REBUILD_TABLE: &str = "service_token_change_evidence_rebuild";

/// Every column of the evidence table once the actor columns are present, in
/// table order: what the rebuild copies, row for row.
const CHANGE_EVIDENCE_COPIED_COLUMNS: &str = "sequence, event_id, operation_id, actor_user_id, \
     action, token_id, committed_at, actor_kind, actor_auth_mode, actor_issuer";

/// How long one statement on a token-store connection waits for a writer on
/// another connection to the same file before the change is refused with
/// [`TokenStoreError::Busy`]. It is the Connections store's budget, set
/// explicitly rather than inherited from the driver's default.
pub(crate) const SERVICE_TOKEN_SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-connection settings, applied on every open before the schema.
///
/// Write-ahead logging, like the Connections, discovery and principal
/// stores. In the rollback-journal mode this store used to run in, a commit
/// needs an EXCLUSIVE lock that every reader of the file holds off, and it
/// holds the write lock across creating, syncing and deleting a journal
/// file and syncing the database: on a loaded Windows runner a rotate racing
/// a revoke on another connection waited out that I/O and ran out of its
/// budget. Under WAL a commit appends to the log with one sync, readers never
/// hold it up, and only writers queue, each for one short IMMEDIATE
/// transaction. `synchronous = FULL` keeps every committed revoke durable
/// across a power loss, as rollback mode did. The mode persists in the file;
/// an older binary opens a WAL database unchanged.
const CONFIGURE_SERVICE_TOKEN_CONNECTION_SQL: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
"#;

/// The actor metadata of the change evidence (issue #425, the v1 contract
/// metadata PostgreSQL migration 24 adds): the actor's kind, its auth mode
/// and, for a principal that has one, its canonical issuer. They are added to
/// the table above whenever a database is opened, in this order, because a
/// database an older binary wrote has the table without them; a fresh
/// database gets them the same way, so there is one schema. The columns are
/// nullable and nothing is backfilled: a row written before them recorded
/// none of the three, and evidence is never rewritten. The last column carries
/// the CHECK that a row records all three or none, in a pairing
/// authentication can produce, exactly as migration 24 does. The issuer bound
/// is the principal issuer bound (MAX_TOKEN_CHANGE_ACTOR_ISSUER_BYTES).
const CHANGE_EVIDENCE_ACTOR_COLUMNS: [(&str, &str); 3] = [
    ("actor_kind", "TEXT"),
    ("actor_auth_mode", "TEXT"),
    (
        "actor_issuer",
        r#"TEXT CHECK (
    actor_issuer IS NULL OR length(CAST(actor_issuer AS BLOB)) BETWEEN 1 AND 4096
) CHECK (
    (actor_kind IS NULL AND actor_auth_mode IS NULL AND actor_issuer IS NULL)
    OR (actor_kind IS NOT NULL AND actor_auth_mode IS NOT NULL AND (
        (actor_kind = 'principal'
            AND actor_auth_mode IN ('bearer_token', 'session_cookie', 'client_certificate'))
        OR (actor_kind = 'service_token'
            AND actor_auth_mode = 'service_token' AND actor_issuer IS NULL)
        OR (actor_kind = 'system' AND actor_auth_mode = 'system' AND actor_issuer IS NULL)
    ))
)"#,
    ),
];

/// The token row's store-owned revision (issue #425, plan P5): 1 when the
/// token is issued, advanced by one by every rotation and revocation this
/// build commits, so a change's evidence can name the revision before and
/// after it as authority_event.v1 needs. Added on open like the actor
/// columns: an older binary inserts tokens by an explicit column list, so
/// its rows take the default, and it never reads or advances the column.
const SERVICE_TOKEN_REVISION_COLUMNS: [(&str, &str); 1] = [(
    "revision",
    "INTEGER NOT NULL DEFAULT 1 CHECK (revision >= 1)",
)];

/// The revisions a change's evidence records (issue #425, plan P5), and the
/// per-row marker `revised` that says whether the row's writer records them.
/// Added on open after the actor columns, so an older table and a fresh one
/// end with one schema. Nothing is backfilled: an existing row keeps NULL
/// revisions and `revised = 0`, and so does every row an older binary still
/// writes (its insert names its columns, and the token database has no
/// version fence that would keep an older binary away), so delivery reads
/// such a row as the unrevised legacy record it is. Every row this build
/// writes has `revised = 1` and a revision transition: an issue NULL to 1,
/// a rotation or revocation one step up. The last CHECK holds that pairing
/// for each action exactly as standalone delivery projects it (an issue is a
/// create, anything else an advance), so the table refuses a revised row
/// delivery would stall on; PostgreSQL migration 27 ties the NULL prior to
/// the issue the same way. SQLite cannot change a column's CHECK in place,
/// so it is complete from the start.
const CHANGE_EVIDENCE_REVISION_COLUMNS: [(&str, &str); 3] = [
    (
        "prior_version",
        "INTEGER CHECK (prior_version IS NULL OR prior_version >= 1)",
    ),
    (
        "new_version",
        "INTEGER CHECK (new_version IS NULL OR new_version >= 1)",
    ),
    (
        "revised",
        r#"INTEGER NOT NULL DEFAULT 0 CHECK (revised IN (0, 1)) CHECK (
    (revised = 0 AND prior_version IS NULL AND new_version IS NULL)
    OR (revised = 1 AND action = 'service_token.issue'
        AND prior_version IS NULL AND new_version = 1)
    OR (revised = 1 AND action <> 'service_token.issue'
        AND prior_version IS NOT NULL AND new_version > prior_version)
)"#,
    ),
];

/// The longest actor an issue, rotate or revoke records as its change
/// evidence, in both the SQLite table above and PostgreSQL migration 18. It is exactly
/// the principal subject bound authentication enforces, so evidence never
/// refuses a principal a validator produced; the assertion keeps the SQL
/// bounds and the Rust bound from drifting apart silently.
pub(crate) const MAX_TOKEN_CHANGE_ACTOR_BYTES: usize = 4096;
const _: () =
    assert!(MAX_TOKEN_CHANGE_ACTOR_BYTES == crate::auth::principal::MAX_PRINCIPAL_SUBJECT_BYTES);

/// The longest actor issuer the evidence records, in the SQLite column above
/// and in every table of PostgreSQL migration 24: exactly the principal
/// issuer bound, for the same reason.
pub(crate) const MAX_TOKEN_CHANGE_ACTOR_ISSUER_BYTES: usize = 4096;
const _: () = assert!(
    MAX_TOKEN_CHANGE_ACTOR_ISSUER_BYTES == crate::auth::principal::MAX_PRINCIPAL_ISSUER_BYTES
);

/// The closed action vocabulary of service-token change evidence. Values are
/// the proposed authority-event operation codes
/// (`docs/schemas/authority_event.v1.schema.json`); both stores' CHECK
/// constraints refuse anything else. An issue is the token's first evidence
/// row; a token created before issue evidence existed has only its
/// `created_by`, and nothing is backfilled for it.
pub(crate) const TOKEN_CHANGE_ACTION_ISSUE: &str = "service_token.issue";
pub(crate) const TOKEN_CHANGE_ACTION_ROTATE: &str = "service_token.rotate";
pub(crate) const TOKEN_CHANGE_ACTION_REVOKE: &str = "service_token.revoke";

/// An unattributable change has no evidence to record, so a store refuses
/// it before it changes anything rather than committing it anonymously. An
/// authenticated principal always satisfies this
/// ([`ChangeActor::is_recordable`]); the CHECK constraints are the backstop.
pub(crate) fn is_valid_change_actor(actor: &ChangeActor) -> bool {
    actor.is_recordable()
}

const TOKEN_MARKER: &str = "ggw_";
const TOKEN_RANDOM_BYTES: usize = 32;
// Reveals 40 of 256 random bits for operator correlation, leaving 216 bits unknown.
const TOKEN_DISPLAY_PREFIX_HEX_CHARS: usize = 10;

#[derive(Clone)]
pub struct SqliteTokenStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
}

pub(crate) const REVOKE_OPERATION_BINDING: &str = "service_token_revoke_binding";

/// The operation label of a keyed issue or rotation refused because its
/// caller key is bound to another request (issue #425): a `Conflict` with
/// this label means exactly that, and nothing changed.
pub(crate) const CALLER_OPERATION_BINDING: &str = "service_token_caller_operation_binding";

/// Unkeyed service-token operations, including historical ones, use v4.
/// Reserving v7 for the caller prevents a legacy operation from ever being
/// presented as a matching keyed request.
pub(crate) fn valid_caller_operation_id(id: uuid::Uuid) -> bool {
    id.get_version() == Some(uuid::Version::SortRand) && id.get_variant() == uuid::Variant::RFC4122
}

#[cfg(test)]
pub(crate) fn test_revoke_operation_id(seed: u8) -> uuid::Uuid {
    uuid::Builder::from_unix_timestamp_millis(1_700_000_000_000, &[seed; 10]).into_uuid()
}

pub trait TokenStore: Send + Sync {
    /// Issue a token on behalf of `actor`, who is recorded as the issue's
    /// evidence in the same transaction as the token row.
    fn create(
        &self,
        request: CreateTokenRequest,
        actor: &ChangeActor,
    ) -> Result<CreatedToken, TokenStoreError> {
        match self.create_with_operation(request, actor, None)? {
            CallerOutcome::Committed(created) => Ok(created),
            // Only a caller key is answered from a receipt.
            CallerOutcome::Replayed(_) => Err(TokenStoreError::CallerOperationAction),
        }
    }

    /// [`Self::create`] under a caller key bound to this request (issue
    /// #425): the key is reserved with the issue and its evidence in one
    /// transaction, and an exact retry is answered with the receipt of what
    /// committed, never a second token or its plaintext.
    fn create_with_operation(
        &self,
        request: CreateTokenRequest,
        actor: &ChangeActor,
        caller: Option<&CallerOperation>,
    ) -> Result<CallerOutcome<CreatedToken>, TokenStoreError>;

    fn list(&self, filters: &TokenListFilters) -> Result<TokenPage, TokenStoreError>;

    fn get_by_id(&self, id: &str) -> Result<Option<TokenRecord>, TokenStoreError>;

    /// Revoke on behalf of `actor`, who is recorded as the change's
    /// evidence in the same transaction. A repeat revoke changes nothing
    /// and records nothing.
    #[cfg(test)]
    fn revoke(
        &self,
        id: &str,
        actor: &ChangeActor,
    ) -> Result<Option<TokenRecord>, TokenStoreError> {
        self.revoke_with_operation(id, actor, None)
    }

    fn revoke_with_operation(
        &self,
        id: &str,
        actor: &ChangeActor,
        operation_id: Option<uuid::Uuid>,
    ) -> Result<Option<TokenRecord>, TokenStoreError>;

    /// Rotate on behalf of `actor`, who is recorded as the change's
    /// evidence in the same transaction. Rotating a revoked token is a
    /// conflict and records nothing.
    fn rotate(
        &self,
        id: &str,
        actor: &ChangeActor,
    ) -> Result<Option<CreatedToken>, TokenStoreError> {
        match self.rotate_with_operation(id, actor, None)? {
            None => Ok(None),
            Some(CallerOutcome::Committed(created)) => Ok(Some(created)),
            Some(CallerOutcome::Replayed(_)) => Err(TokenStoreError::CallerOperationAction),
        }
    }

    /// [`Self::rotate`] under a caller key bound to this request (issue
    /// #425). An exact retry is answered with the receipt of the committed
    /// rotation whatever the token's state since, never a plaintext.
    fn rotate_with_operation(
        &self,
        id: &str,
        actor: &ChangeActor,
        caller: Option<&CallerOperation>,
    ) -> Result<Option<CallerOutcome<CreatedToken>>, TokenStoreError>;

    fn verify(&self, plaintext_token: &str) -> Result<TokenVerification, TokenStoreError>;

    fn touch_last_used(&self, id: &str) -> Result<Option<TokenRecord>, TokenStoreError>;
}

/// The bound on the serialized scope list, judged before the store is
/// asked (the PostgreSQL column carries the same bound as a check
/// constraint, so an oversized list is the client's error, not a store
/// failure).
pub const MAX_SERVICE_TOKEN_SCOPES_JSON_BYTES: usize = 65_536;

/// The bound on a token's `created_by` (the creating principal's ID) in
/// the PostgreSQL store, judged before the insert so an oversized principal
/// is the caller's error rather than the column's check constraint.
pub const MAX_SERVICE_TOKEN_CREATED_BY_BYTES: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateTokenRequest {
    pub scopes: Vec<String>,
    pub created_by: String,
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TokenRecord {
    pub id: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub created_by: String,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

pub struct CreatedToken {
    pub record: TokenRecord,
    pub plaintext_token: String,
}

/// Written by hand so the plaintext can never reach a log line or a test
/// failure message through `{:?}`.
impl fmt::Debug for CreatedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedToken")
            .field("record", &self.record)
            .field("plaintext_token", &"<redacted>")
            .finish()
    }
}

/// One `service_tokens` row exactly as stored, for the standalone-to-cluster
/// import (issue #241, PR 15).
///
/// [`TokenRecord`] is the ADMIN view and deliberately omits `token_hash`,
/// because no API response may carry it. The import is not an API
/// response: the hash is the whole reason an already-issued token keeps
/// working after the cutover, so it is carried across verbatim. It is
/// never serialized into the import's report -- that type derives no
/// `Serialize` for exactly that reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportedServiceToken {
    pub id: String,
    /// SHA-256 of the plaintext, hex-encoded: a verifier, not a credential.
    pub token_hash: String,
    pub token_prefix: String,
    pub scopes_json: String,
    pub created_by: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TokenPage {
    pub tokens: Vec<TokenRecord>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenListFilters {
    pub limit: usize,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenVerification {
    Valid(VerifiedToken),
    Invalid(TokenVerificationFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenVerificationFailure {
    NotFound,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    pub id: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    /// How long the store's own clock says the token remains valid;
    /// `None` for a token without an expiry. A cache must not serve the
    /// token past it, whatever the caching replica's clock says.
    pub remaining_lifetime: Option<std::time::Duration>,
}

#[derive(Debug)]
pub enum TokenStoreError {
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Sqlite {
        path: PathBuf,
        source: rusqlite::Error,
    },
    /// Another connection held the file's write lock for the store's whole
    /// contention budget ([`SERVICE_TOKEN_SQLITE_BUSY_TIMEOUT`] unless the
    /// store was opened with another). The change was refused before
    /// it committed, so nothing it would have written exists; the caller may
    /// retry it. A store statement that runs out of the budget is reported
    /// as this, not as the raw `SQLITE_BUSY`/`SQLITE_LOCKED` failure.
    Busy {
        path: PathBuf,
    },
    Json {
        context: &'static str,
        source: serde_json::Error,
    },
    TimeFormat(time::error::Format),
    TimeParse {
        context: &'static str,
        value: String,
        source: time::error::Parse,
    },
    InvalidCursor {
        parameter: &'static str,
    },
    Random(getrandom::Error),
    RevokedToken {
        id: String,
    },
    /// An issue, rotate or revoke named no actor, one longer than
    /// [`MAX_TOKEN_CHANGE_ACTOR_BYTES`], or an issuer evidence cannot record
    /// ([`ChangeActor::is_recordable`]); refused before anything changed.
    InvalidChangeActor,
    InvalidRevokeOperationId,
    RevokeOperationConflict,
    InconsistentRevokeEvidence,
    /// The change's evidence could not be written, so the change was
    /// rolled back with it.
    ChangeEvidence {
        path: PathBuf,
        source: rusqlite::Error,
    },
    /// A keyed issue or rotation whose caller key is reserved for another
    /// action or another request in this file (issue #425): nothing changed.
    CallerOperationConflict,
    /// A caller key bound to another action than the change it was handed
    /// to, or a receipt where none can be: the gateway's defect, refused
    /// before anything changed.
    CallerOperationAction,
    /// The caller key's reservation could not be read or written, or its
    /// receipt could not be read; nothing committed. Already classified and
    /// logged by the reservation table's own functions.
    CallerOperation(crate::storage::RepositoryError),
}

impl SqliteTokenStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TokenStoreError> {
        Self::open_with_busy_timeout(path, SERVICE_TOKEN_SQLITE_BUSY_TIMEOUT)
    }

    /// [`Self::open`] with a contention budget other than the default, for
    /// tests that hold the write lock past it.
    pub(crate) fn open_with_busy_timeout(
        path: impl AsRef<Path>,
        busy_timeout: Duration,
    ) -> Result<Self, TokenStoreError> {
        let path = path.as_ref().to_path_buf();
        let connection = Connection::open(&path).map_err(|source| TokenStoreError::Open {
            path: path.clone(),
            source,
        })?;
        // The budget is set before the first statement, so even the journal
        // mode switch and the schema statements below wait for a writer on
        // another connection rather than failing at once.
        connection
            .busy_timeout(busy_timeout)
            .map_err(|source| store_failure(&path, source))?;
        connection
            .execute_batch(CONFIGURE_SERVICE_TOKEN_CONNECTION_SQL)
            .map_err(|source| store_failure(&path, source))?;
        configure_connection(&connection).map_err(|source| store_failure(&path, source))?;

        Ok(Self {
            path,
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Every service token as STORED, in id order, INCLUDING its hash.
    ///
    /// For the standalone-to-cluster import (issue #241, PR 15). The hash
    /// is the only thing that makes a token still work after the cutover:
    /// verification hashes the presented plaintext and looks the digest up,
    /// so an import that carried the display prefix but not the hash would
    /// silently invalidate every issued token. The PLAINTEXT is not here
    /// and never was -- it exists once, in the response to create or
    /// rotate -- so nothing this returns can authenticate anything on its
    /// own; it is the verifier, not the credential. It is still never
    /// printed: the import writes it and reports counts.
    pub(crate) fn exported_tokens(&self) -> Result<Vec<ExportedServiceToken>, TokenStoreError> {
        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(
                r#"
                SELECT id, token_hash, token_prefix, scopes_json, created_by, created_at,
                       expires_at, last_used_at, revoked_at
                FROM service_tokens
                ORDER BY id
                "#,
            )
            .map_err(|source| store_failure(&self.path, source))?;
        let tokens = statement
            .query_map([], |row| {
                Ok(ExportedServiceToken {
                    id: row.get(0)?,
                    token_hash: row.get(1)?,
                    token_prefix: row.get(2)?,
                    scopes_json: row.get(3)?,
                    created_by: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                    last_used_at: row.get(7)?,
                    revoked_at: row.get(8)?,
                })
            })
            .map_err(|source| store_failure(&self.path, source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| store_failure(&self.path, source));
        tokens
    }

    fn sqlite_error(&self, source: rusqlite::Error) -> TokenStoreError {
        store_failure(&self.path, source)
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "auth_tokens",
                    "lock" => "connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite service-token connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

/// The token database is its own evidence authority: its one evidence table
/// is delivered after a cursor kept beside it (issue #425).
impl crate::storage::standalone_authority_events::StandaloneEvidenceAuthority for SqliteTokenStore {
    fn evidence_store(&self) -> crate::storage::StandaloneEvidenceStore {
        crate::storage::StandaloneEvidenceStore::ServiceTokens
    }

    fn evidence_sources(
        &self,
    ) -> &'static [crate::storage::standalone_authority_events::StandaloneEvidenceSource] {
        &[crate::storage::standalone_authority_events::StandaloneEvidenceSource::ServiceTokenChange]
    }

    fn evidence_connection(&self) -> MutexGuard<'_, Connection> {
        self.connection_guard()
    }
}

impl SqliteTokenStore {
    /// What this file's reservation table says about `caller`'s key: the
    /// read-only pre-check a handler asks before it does any work (issue
    /// #425). Advisory: the change's own transaction decides again.
    pub(crate) fn caller_operation_state(
        &self,
        caller: &CallerOperation,
    ) -> Result<CallerKeyState, TokenStoreError> {
        let connection = self.connection_guard();
        crate::storage::standalone_authority_events::read_caller_operation(&connection, caller)
            .map_err(TokenStoreError::CallerOperation)
    }

    /// The receipt of the issue or rotation `caller`'s key committed, read
    /// from its evidence row, or `None` when there is none.
    pub(crate) fn caller_operation_receipt(
        &self,
        caller: &CallerOperation,
    ) -> Result<Option<OperationReceipt>, TokenStoreError> {
        let connection = self.connection_guard();
        token_operation_receipt(&connection, caller).map_err(|source| self.sqlite_error(source))
    }

    /// Step 1 of a keyed issue or rotation, inside its IMMEDIATE transaction
    /// (issue #425): `None` for no key or an unused one; the receipt for an
    /// exact retry of a committed change; a conflict for a key reserved for
    /// anything else, or used by a keyed revoke an older build committed
    /// without reserving it (the next open reserves those, but an older
    /// build can serve this file meanwhile). A reservation without its
    /// evidence row is refused.
    fn keyed_receipt(
        &self,
        transaction: &Connection,
        caller: Option<&CallerOperation>,
        action: &'static str,
    ) -> Result<Option<OperationReceipt>, TokenStoreError> {
        let Some(caller) = caller else {
            return Ok(None);
        };
        if caller.action() != action {
            return Err(TokenStoreError::CallerOperationAction);
        }
        let state =
            crate::storage::standalone_authority_events::read_caller_operation(transaction, caller)
                .map_err(TokenStoreError::CallerOperation)?;
        match state {
            CallerKeyState::Unused => {
                let used: bool = transaction
                    .query_row(
                        "SELECT EXISTS (SELECT 1 FROM service_token_change_evidence \
                         WHERE operation_id = ?1)",
                        params![caller.id().to_string()],
                        |row| row.get(0),
                    )
                    .map_err(|source| self.sqlite_error(source))?;
                if used {
                    return Err(TokenStoreError::CallerOperationConflict);
                }
                Ok(None)
            }
            CallerKeyState::OtherBinding => Err(TokenStoreError::CallerOperationConflict),
            CallerKeyState::SameBinding => self.committed_receipt(transaction, caller).map(Some),
        }
    }

    /// Step 3 of a keyed issue or rotation: reserve the key with its binding
    /// digest in the change's transaction. The write lock is held and step 1
    /// found the key free, so a taken key means the file disagrees with
    /// itself and nothing commits. A reservation that cannot be written is
    /// part of the change's evidence failing (I2): counted on the standalone
    /// evidence-failure counter, and nothing commits.
    fn reserve_caller_key(
        &self,
        transaction: &Connection,
        caller: Option<&CallerOperation>,
    ) -> Result<(), TokenStoreError> {
        let Some(caller) = caller else {
            return Ok(());
        };
        let reservation = crate::storage::standalone_authority_events::reserve_bound_operation(
            transaction,
            caller,
        )
        .map_err(|error| {
            crate::storage::record_standalone_evidence_failure(
                crate::storage::StandaloneEvidenceStore::ServiceTokens,
            );
            TokenStoreError::CallerOperation(error)
        })?;
        match reservation {
            CallerKeyReservation::Reserved => Ok(()),
            CallerKeyReservation::SameBinding | CallerKeyReservation::OtherBinding => {
                Err(TokenStoreError::CallerOperationConflict)
            }
        }
    }

    /// The committed receipt of an exact retry, or a refusal when the
    /// reservation has no evidence row.
    fn committed_receipt(
        &self,
        transaction: &Connection,
        caller: &CallerOperation,
    ) -> Result<OperationReceipt, TokenStoreError> {
        token_operation_receipt(transaction, caller)
            .map_err(|source| self.sqlite_error(source))?
            .ok_or_else(|| {
                tracing::error!(
                    "a caller operation is reserved without its service-token evidence row; the change is refused"
                );
                TokenStoreError::InconsistentRevokeEvidence
            })
    }
}

/// The receipt of the token change `caller`'s key committed: its evidence
/// row for the key's action, never anything from the request and never
/// token material.
fn token_operation_receipt(
    connection: &Connection,
    caller: &CallerOperation,
) -> rusqlite::Result<Option<OperationReceipt>> {
    connection
        .query_row(
            "SELECT token_id, new_version, committed_at FROM service_token_change_evidence \
             WHERE operation_id = ?1 AND action = ?2",
            params![caller.id().to_string(), caller.action()],
            |row| {
                Ok(OperationReceipt {
                    operation_id: caller.id().to_string(),
                    operation: caller.action().to_owned(),
                    resource_id: row.get(0)?,
                    revision: row.get(1)?,
                    committed_at: row.get(2)?,
                })
            },
        )
        .optional()
}

/// The token row's store-owned revision, read inside the change's
/// transaction.
fn token_revision(connection: &Connection, path: &Path, id: &str) -> Result<i64, TokenStoreError> {
    connection
        .query_row(
            "SELECT revision FROM service_tokens WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )
        .map_err(|source| store_failure(path, source))
}

impl TokenStore for SqliteTokenStore {
    fn create_with_operation(
        &self,
        request: CreateTokenRequest,
        actor: &ChangeActor,
        caller: Option<&CallerOperation>,
    ) -> Result<CallerOutcome<CreatedToken>, TokenStoreError> {
        validate_optional_timestamp(request.expires_at.as_deref(), "expires_at")?;
        if !is_valid_change_actor(actor) {
            return Err(TokenStoreError::InvalidChangeActor);
        }

        let plaintext_token = generate_plaintext_token()?;
        let token_hash = hash_token(&plaintext_token);
        let token_prefix = display_prefix(&plaintext_token);
        let id = new_token_id();
        let created_at = utc_timestamp_rfc3339()?;
        let scopes_json =
            serde_json::to_string(&request.scopes).map_err(|source| TokenStoreError::Json {
                context: "scopes",
                source,
            })?;

        let mut connection = self.connection_guard();
        // One unit, as in `revoke` and `rotate`: the token row, the evidence
        // of its issue and a caller key's reservation commit together or not
        // at all. An early return drops the transaction, which rolls it back
        // with nothing written.
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|source| self.sqlite_error(source))?;
        // An exact retry is answered from what committed: no second token,
        // and never a plaintext (the first one was returned once).
        if let Some(receipt) =
            self.keyed_receipt(&transaction, caller, TOKEN_CHANGE_ACTION_ISSUE)?
        {
            return Ok(CallerOutcome::Replayed(receipt));
        }
        self.reserve_caller_key(&transaction, caller)?;
        transaction
            .execute(
                r#"
                INSERT INTO service_tokens (
                    id,
                    token_hash,
                    token_prefix,
                    scopes_json,
                    created_by,
                    created_at,
                    expires_at,
                    last_used_at,
                    revoked_at,
                    revision
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL, 1)
                "#,
                params![
                    id.as_str(),
                    token_hash.as_str(),
                    token_prefix.as_str(),
                    scopes_json.as_str(),
                    request.created_by.as_str(),
                    created_at.as_str(),
                    request.expires_at.as_deref(),
                ],
            )
            .map_err(|source| self.sqlite_error(source))?;
        // The issue's commit time is the token's own `created_at`, as a
        // revoke's is its `revoked_at`. Neither the plaintext nor the hash
        // is passed: the evidence names the token by its ID alone. An issue
        // creates the token's first revision.
        record_change_evidence(
            &transaction,
            &self.path,
            &ChangeEvidence {
                operation_id: caller.map(CallerOperation::id),
                action: TOKEN_CHANGE_ACTION_ISSUE,
                token_id: &id,
                actor,
                committed_at: &created_at,
                prior_version: None,
                new_version: 1,
            },
        )?;
        transaction
            .commit()
            .map_err(|source| self.sqlite_error(source))?;

        Ok(CallerOutcome::Committed(CreatedToken {
            record: TokenRecord {
                id,
                token_prefix,
                scopes: request.scopes,
                created_by: request.created_by,
                created_at,
                expires_at: request.expires_at,
                last_used_at: None,
                revoked_at: None,
            },
            plaintext_token,
        }))
    }

    fn list(&self, filters: &TokenListFilters) -> Result<TokenPage, TokenStoreError> {
        let cursor = filters
            .cursor
            .as_deref()
            .map(|value| decode_cursor::<TokenCursor>("cursor", value))
            .transpose()?;
        let (sql, params) = build_token_list_query(filters, cursor.as_ref());

        let connection = self.connection_guard();
        let mut statement = connection
            .prepare(&sql)
            .map_err(|source| store_failure(&self.path, source))?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), RawTokenRecord::from_row)
            .map_err(|source| store_failure(&self.path, source))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| store_failure(&self.path, source))?;

        let mut rows = rows;
        let has_more = rows.len() > filters.limit;
        if has_more {
            rows.truncate(filters.limit);
        }

        let next_cursor = if has_more {
            rows.last()
                .map(|row| {
                    encode_cursor(&TokenCursor {
                        created_at: row.created_at.clone(),
                        id: row.id.clone(),
                    })
                })
                .transpose()?
        } else {
            None
        };
        let tokens = rows
            .into_iter()
            .map(RawTokenRecord::into_record)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(TokenPage {
            tokens,
            next_cursor,
        })
    }

    fn get_by_id(&self, id: &str) -> Result<Option<TokenRecord>, TokenStoreError> {
        let connection = self.connection_guard();
        load_record_by_id(&connection, &self.path, id)
    }

    fn revoke_with_operation(
        &self,
        id: &str,
        actor: &ChangeActor,
        operation_id: Option<uuid::Uuid>,
    ) -> Result<Option<TokenRecord>, TokenStoreError> {
        if operation_id.is_some_and(|id| !valid_caller_operation_id(id)) {
            return Err(TokenStoreError::InvalidRevokeOperationId);
        }
        if !is_valid_change_actor(actor) || (operation_id.is_some() && !actor.can_bind_operation())
        {
            return Err(TokenStoreError::InvalidChangeActor);
        }
        let revoked_at = utc_timestamp_rfc3339()?;
        let mut connection = self.connection_guard();
        // IMMEDIATE takes the write lock before the read, so the revoked
        // guard, the update and its evidence are judged and written as one
        // unit: another connection to this file waits rather than
        // interleaving. Every early return drops the transaction, which
        // rolls it back with nothing written.
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|source| self.sqlite_error(source))?;
        let record = load_record_by_id(&transaction, &self.path, id)?;
        if let Some(operation_id) = operation_id {
            // The key's reservation first: a key another action reserved in
            // this file -- through this store or a Connections store on the
            // same file -- is never a revoke's.
            let reserved_for =
                crate::storage::standalone_authority_events::caller_operation_action(
                    &transaction,
                    operation_id,
                )
                .map_err(|source| self.sqlite_error(source))?;
            if reserved_for.is_some_and(|action| action != TOKEN_CHANGE_ACTION_REVOKE) {
                return Err(TokenStoreError::RevokeOperationConflict);
            }
            // All token writers take the same SQLite write lock. Check every
            // action sharing the key, including historical rows with no actor
            // and keyed revokes an older build committed without reserving.
            let matches: Option<bool> = transaction
                .query_row(
                    "SELECT min(CASE WHEN action = 'service_token.revoke' AND token_id = ?2
                          AND actor_user_id = ?3 AND actor_issuer IS ?4
                          AND actor_kind = ?5 AND actor_auth_mode = ?6 THEN 1 ELSE 0 END)
                 FROM service_token_change_evidence WHERE operation_id = ?1",
                    params![
                        operation_id.to_string(),
                        id,
                        actor.subject(),
                        actor.issuer(),
                        actor.kind().as_str(),
                        actor.auth_mode()
                    ],
                    |row| row.get(0),
                )
                .map_err(|source| self.sqlite_error(source))?;
            match matches {
                Some(false) => return Err(TokenStoreError::RevokeOperationConflict),
                Some(true) => {
                    return record
                        .filter(|row| row.revoked_at.is_some())
                        .map(Some)
                        .ok_or(TokenStoreError::InconsistentRevokeEvidence)
                }
                None if record.as_ref().is_some_and(|row| row.revoked_at.is_some()) => {
                    return Err(TokenStoreError::RevokeOperationConflict)
                }
                None => {}
            }
        }
        let Some(record) = record else {
            return Ok(None);
        };
        // Idempotent and monotonic: the first revoked_at stands, and a
        // repeat neither rewrites it nor records evidence of a change that
        // did not happen.
        if record.revoked_at.is_some() {
            return Ok(Some(record));
        }
        // A keyed revoke reserves its key with its evidence, in this
        // transaction, so no later keyed issue, rotation or Connection change
        // in this file can claim it. The look above found it free, and the
        // write lock is held, so a taken key here means the file disagrees
        // with itself: nothing commits. A reservation insert that fails is
        // part of the change's evidence failing (I2): it is counted on the
        // standalone evidence-failure counter, as a failed evidence insert
        // is, and nothing commits.
        if let Some(operation_id) = operation_id {
            let reserved = crate::storage::standalone_authority_events::reserve_unbound_operation(
                &transaction,
                operation_id,
                TOKEN_CHANGE_ACTION_REVOKE,
            )
            .map_err(|source| {
                crate::storage::record_standalone_evidence_failure(
                    crate::storage::StandaloneEvidenceStore::ServiceTokens,
                );
                self.sqlite_error(source)
            })?;
            if !reserved {
                return Err(TokenStoreError::RevokeOperationConflict);
            }
        }

        // A revocation advances the token's revision by one, so its evidence
        // names the revision it withdrew and the one it left (issue #425).
        let prior_revision = token_revision(&transaction, &self.path, id)?;
        let changed = transaction
            .execute(
                "UPDATE service_tokens SET revoked_at = ?1, revision = ?3 \
                 WHERE id = ?2 AND revoked_at IS NULL AND revision = ?4",
                params![revoked_at.as_str(), id, prior_revision + 1, prior_revision],
            )
            .map_err(|source| self.sqlite_error(source))?;
        // The evidence describes exactly one changed row or nothing commits.
        if changed != 1 {
            return Err(self.sqlite_error(rusqlite::Error::StatementChangedRows(changed)));
        }
        record_change_evidence(
            &transaction,
            &self.path,
            &ChangeEvidence {
                operation_id,
                action: TOKEN_CHANGE_ACTION_REVOKE,
                token_id: id,
                actor,
                committed_at: &revoked_at,
                prior_version: Some(prior_revision),
                new_version: prior_revision + 1,
            },
        )?;
        let record = load_record_by_id(&transaction, &self.path, id)?;
        transaction
            .commit()
            .map_err(|source| self.sqlite_error(source))?;
        Ok(record)
    }

    fn rotate_with_operation(
        &self,
        id: &str,
        actor: &ChangeActor,
        caller: Option<&CallerOperation>,
    ) -> Result<Option<CallerOutcome<CreatedToken>>, TokenStoreError> {
        if !is_valid_change_actor(actor) {
            return Err(TokenStoreError::InvalidChangeActor);
        }
        let plaintext_token = generate_plaintext_token()?;
        let token_hash = hash_token(&plaintext_token);
        let token_prefix = display_prefix(&plaintext_token);
        let rotated_at = utc_timestamp_rfc3339()?;

        let mut connection = self.connection_guard();
        // One unit, as in `revoke`: a rotate cannot interleave with a
        // revoke on another connection and mint a plaintext for a token
        // that revoke has already withdrawn.
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|source| self.sqlite_error(source))?;
        // The key first: an exact retry is answered from the committed
        // rotation whatever happened to the token since, and never with a
        // plaintext.
        if let Some(receipt) =
            self.keyed_receipt(&transaction, caller, TOKEN_CHANGE_ACTION_ROTATE)?
        {
            return Ok(Some(CallerOutcome::Replayed(receipt)));
        }
        let Some(record) = load_record_by_id(&transaction, &self.path, id)? else {
            return Ok(None);
        };
        if record.revoked_at.is_some() {
            return Err(TokenStoreError::RevokedToken { id: id.to_owned() });
        }
        self.reserve_caller_key(&transaction, caller)?;

        // A rotation advances the token's revision by one (issue #425).
        let prior_revision = token_revision(&transaction, &self.path, id)?;
        let changed = transaction
            .execute(
                r#"
                UPDATE service_tokens
                SET token_hash = ?1,
                    token_prefix = ?2,
                    revision = ?4
                WHERE id = ?3 AND revoked_at IS NULL AND revision = ?5
                "#,
                params![
                    token_hash.as_str(),
                    token_prefix.as_str(),
                    id,
                    prior_revision + 1,
                    prior_revision
                ],
            )
            .map_err(|source| self.sqlite_error(source))?;
        if changed != 1 {
            return Err(self.sqlite_error(rusqlite::Error::StatementChangedRows(changed)));
        }
        record_change_evidence(
            &transaction,
            &self.path,
            &ChangeEvidence {
                operation_id: caller.map(CallerOperation::id),
                action: TOKEN_CHANGE_ACTION_ROTATE,
                token_id: id,
                actor,
                committed_at: &rotated_at,
                prior_version: Some(prior_revision),
                new_version: prior_revision + 1,
            },
        )?;
        // The row was read inside this transaction, which holds the write
        // lock, so it cannot be gone; if it somehow is, nothing commits.
        let record = load_record_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| self.sqlite_error(rusqlite::Error::QueryReturnedNoRows))?;
        transaction
            .commit()
            .map_err(|source| self.sqlite_error(source))?;
        Ok(Some(CallerOutcome::Committed(CreatedToken {
            record,
            plaintext_token,
        })))
    }

    fn verify(&self, plaintext_token: &str) -> Result<TokenVerification, TokenStoreError> {
        let token_hash = hash_token(plaintext_token);
        let now = OffsetDateTime::now_utc();
        let last_used_at = format_timestamp_rfc3339(now)?;

        let connection = self.connection_guard();
        let Some(mut record) = load_record_by_hash(&connection, &self.path, &token_hash)? else {
            return Ok(TokenVerification::Invalid(
                TokenVerificationFailure::NotFound,
            ));
        };

        if record.revoked_at.is_some() {
            return Ok(TokenVerification::Invalid(
                TokenVerificationFailure::Revoked,
            ));
        }
        if is_expired(record.expires_at.as_deref(), now)? {
            return Ok(TokenVerification::Invalid(
                TokenVerificationFailure::Expired,
            ));
        }

        connection
            .execute(
                "UPDATE service_tokens SET last_used_at = ?1 WHERE id = ?2",
                params![last_used_at.as_str(), record.id.as_str()],
            )
            .map_err(|source| store_failure(&self.path, source))?;
        record.last_used_at = Some(last_used_at);

        Ok(TokenVerification::Valid(VerifiedToken {
            id: record.id,
            token_prefix: record.token_prefix,
            scopes: record.scopes,
            remaining_lifetime: remaining_lifetime(record.expires_at.as_deref(), now)?,
            expires_at: record.expires_at,
            last_used_at: record.last_used_at,
        }))
    }

    fn touch_last_used(&self, id: &str) -> Result<Option<TokenRecord>, TokenStoreError> {
        let now = OffsetDateTime::now_utc();
        let last_used_at = format_timestamp_rfc3339(now)?;

        let connection = self.connection_guard();
        let Some(record) = load_record_by_id(&connection, &self.path, id)? else {
            return Ok(None);
        };
        if record.revoked_at.is_some() || is_expired(record.expires_at.as_deref(), now)? {
            return Ok(Some(record));
        }

        connection
            .execute(
                "UPDATE service_tokens SET last_used_at = ?1 WHERE id = ?2",
                params![last_used_at.as_str(), id],
            )
            .map_err(|source| store_failure(&self.path, source))?;

        load_record_by_id(&connection, &self.path, id)
    }
}

impl fmt::Display for TokenStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => {
                write!(
                    formatter,
                    "failed to open service-token store at {}: {source}",
                    path.display()
                )
            }
            Self::Sqlite { path, source } => {
                write!(
                    formatter,
                    "failed to access service-token store at {}: {source}",
                    path.display()
                )
            }
            Self::Busy { path } => {
                write!(
                    formatter,
                    "service-token store at {} stayed locked by another writer past its contention budget; nothing was changed",
                    path.display()
                )
            }
            Self::Json { context, source } => {
                write!(
                    formatter,
                    "failed to encode or decode service-token {context}: {source}"
                )
            }
            Self::TimeFormat(source) => {
                write!(
                    formatter,
                    "failed to format service-token timestamp: {source}"
                )
            }
            Self::TimeParse {
                context,
                value,
                source,
            } => {
                write!(
                    formatter,
                    "failed to parse service-token {context} timestamp {value:?}: {source}"
                )
            }
            Self::InvalidCursor { parameter } => {
                write!(formatter, "invalid service-token cursor: {parameter}")
            }
            Self::Random(source) => {
                write!(
                    formatter,
                    "failed to generate service-token random secret: {source}"
                )
            }
            Self::RevokedToken { id } => {
                write!(formatter, "cannot rotate revoked service token {id}")
            }
            Self::InvalidRevokeOperationId => {
                formatter.write_str("invalid revocation operation identifier")
            }
            Self::RevokeOperationConflict => {
                formatter.write_str("revocation operation conflicts with committed evidence")
            }
            Self::InconsistentRevokeEvidence => {
                formatter.write_str("revocation evidence disagrees with token state")
            }
            Self::InvalidChangeActor => {
                write!(
                    formatter,
                    "a service-token change actor must be between 1 and {MAX_TOKEN_CHANGE_ACTOR_BYTES} bytes, and only a principal may carry an issuer, of at most {MAX_TOKEN_CHANGE_ACTOR_ISSUER_BYTES} bytes"
                )
            }
            Self::ChangeEvidence { path, source } => {
                write!(
                    formatter,
                    "failed to record service-token change evidence at {}: {source}",
                    path.display()
                )
            }
            Self::CallerOperationConflict => formatter
                .write_str("the caller operation is bound to another request; nothing was changed"),
            Self::CallerOperationAction => {
                formatter.write_str("a caller operation was handed to a change it is not bound to")
            }
            Self::CallerOperation(error) => {
                write!(
                    formatter,
                    "the caller operation could not be read or reserved: {error}"
                )
            }
        }
    }
}

impl Error for TokenStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. }
            | Self::Sqlite { source, .. }
            | Self::ChangeEvidence { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::TimeFormat(source) => Some(source),
            Self::TimeParse { source, .. } => Some(source),
            Self::Busy { .. }
            | Self::InvalidCursor { .. }
            | Self::RevokedToken { .. }
            | Self::InvalidChangeActor
            | Self::InvalidRevokeOperationId
            | Self::RevokeOperationConflict
            | Self::InconsistentRevokeEvidence
            | Self::CallerOperationConflict
            | Self::CallerOperationAction => None,
            Self::CallerOperation(error) => Some(error),
            Self::Random(source) => Some(source),
        }
    }
}

/// The keyset cursor both stores encode identically, so a page cursor
/// minted by one backend is opaque to callers in exactly the same way.
#[derive(Serialize, Deserialize)]
pub(crate) struct TokenCursor {
    pub(crate) created_at: String,
    pub(crate) id: String,
}

struct RawTokenRecord {
    id: String,
    token_prefix: String,
    scopes_json: String,
    created_by: String,
    created_at: String,
    expires_at: Option<String>,
    last_used_at: Option<String>,
    revoked_at: Option<String>,
}

impl RawTokenRecord {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            token_prefix: row.get(1)?,
            scopes_json: row.get(2)?,
            created_by: row.get(3)?,
            created_at: row.get(4)?,
            expires_at: row.get(5)?,
            last_used_at: row.get(6)?,
            revoked_at: row.get(7)?,
        })
    }

    fn into_record(self) -> Result<TokenRecord, TokenStoreError> {
        let scopes = serde_json::from_str::<Vec<String>>(&self.scopes_json).map_err(|source| {
            TokenStoreError::Json {
                context: "scopes",
                source,
            }
        })?;

        Ok(TokenRecord {
            id: self.id,
            token_prefix: self.token_prefix,
            scopes,
            created_by: self.created_by,
            created_at: self.created_at,
            expires_at: self.expires_at,
            last_used_at: self.last_used_at,
            revoked_at: self.revoked_at,
        })
    }
}

/// One committed change's evidence: identifiers and the actor, never the
/// plaintext, hash, prefix or scopes of the token it describes.
struct ChangeEvidence<'a> {
    operation_id: Option<uuid::Uuid>,
    action: &'static str,
    token_id: &'a str,
    actor: &'a ChangeActor,
    committed_at: &'a str,
    /// The token's revision before the change: `None` exactly for an issue.
    prior_version: Option<i64>,
    /// The token's revision after it.
    new_version: i64,
}

/// Append one evidence row inside the caller's transaction, with its
/// revisions and `revised = 1` (issue #425, plan P5). Its event and
/// operation IDs are minted here unless a caller key supplies its operation ID. Any failure is
/// returned for the caller to roll back, so the change it describes never
/// commits without it, and it is reported as an evidence failure rather
/// than as whatever constraint class SQLite gave it: a rotate whose
/// evidence failed is not a revoked-token conflict. A failed insert is
/// counted here, once per refused change, on the standalone
/// evidence-failure counter the rule pack pages on.
fn record_change_evidence(
    connection: &Connection,
    path: &Path,
    evidence: &ChangeEvidence<'_>,
) -> Result<(), TokenStoreError> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let operation_id = evidence
        .operation_id
        .unwrap_or_else(uuid::Uuid::new_v4)
        .to_string();
    connection
        .execute(
            r#"
            INSERT INTO service_token_change_evidence (
                event_id, operation_id, actor_user_id, actor_issuer, actor_kind,
                actor_auth_mode, action, token_id, committed_at,
                prior_version, new_version, revised
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 1)
            "#,
            params![
                event_id.as_str(),
                operation_id.as_str(),
                evidence.actor.subject(),
                evidence.actor.issuer(),
                evidence.actor.kind().as_str(),
                evidence.actor.auth_mode(),
                evidence.action,
                evidence.token_id,
                evidence.committed_at,
                evidence.prior_version,
                evidence.new_version,
            ],
        )
        .map_err(|source| {
            crate::storage::record_standalone_evidence_failure(
                crate::storage::StandaloneEvidenceStore::ServiceTokens,
            );
            TokenStoreError::ChangeEvidence {
                path: path.to_path_buf(),
                source,
            }
        })?;
    Ok(())
}

/// A failed store statement as the store reports it: a lock the busy budget
/// could not outwait is [`TokenStoreError::Busy`] (the statement, and any
/// transaction it was part of, committed nothing), everything else is
/// [`TokenStoreError::Sqlite`].
fn store_failure(path: &Path, source: rusqlite::Error) -> TokenStoreError {
    let path = path.to_path_buf();
    // The primary result codes 5 (SQLITE_BUSY) and 6 (SQLITE_LOCKED); the
    // extended codes share the low byte, as `storage::classify_rusqlite`
    // reads them.
    let lock_failure = match &source {
        rusqlite::Error::SqliteFailure(failure, _) => {
            let primary = failure.extended_code & 0xff;
            primary == 5 || primary == 6
        }
        _ => false,
    };
    if lock_failure {
        TokenStoreError::Busy { path }
    } else {
        TokenStoreError::Sqlite { path, source }
    }
}

pub fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(CREATE_SERVICE_TOKEN_SCHEMA_SQL)?;
    connection.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS service_token_change_evidence ({CHANGE_EVIDENCE_COLUMNS_SQL});"
    ))?;
    connection.execute_batch(CHANGE_EVIDENCE_INDEX_SQL)?;
    add_change_evidence_actor_columns(connection)?;
    rebuild_change_evidence_for_issue(connection)?;
    // The store-owned token revision and the evidence revisions (issue
    // #425, plan P5), after the rebuild, which copies only the columns
    // before them.
    add_missing_columns(
        connection,
        "service_tokens",
        &SERVICE_TOKEN_REVISION_COLUMNS,
    )?;
    add_missing_columns(
        connection,
        "service_token_change_evidence",
        &CHANGE_EVIDENCE_REVISION_COLUMNS,
    )?;
    // The delivery state of the evidence above (issue #425): this file's
    // authority ID and its cursor, created empty on open like the evidence
    // table, so an older binary simply never reads them.
    connection
        .execute_batch(crate::storage::standalone_authority_events::AUTHORITY_EVENT_TABLES_SQL)?;
    // The caller keys used in this file (issue #425), from the one
    // definition the Connections store's migration 16 also executes. An
    // older binary never reads the table, so it can still serve this file.
    connection
        .execute_batch(crate::storage::standalone_authority_events::CALLER_OPERATION_TABLE_SQL)?;
    let collisions = reserve_keyed_revocations(connection)?;
    if collisions > 0 {
        tracing::warn!(
            collisions,
            "keyed service-token revocations use a caller key this file reserved for another \
             action; the key stays with that action and the revocations stay unreserved"
        );
    }
    Ok(())
}

/// Every keyed revoke evidence row -- one whose operation ID is
/// caller-assigned (canonical UUIDv7 text) -- beside the reservation of its
/// key, if there is one. Gateway-assigned v4 operation IDs are never keys.
const KEYED_REVOCATIONS_SQL: &str = r#"
FROM service_token_change_evidence e
LEFT JOIN authority_caller_operation_ids k ON k.operation_id = e.operation_id
WHERE e.action = 'service_token.revoke'
  AND e.operation_id GLOB '[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f]-7[0-9a-f][0-9a-f][0-9a-f]-[89ab][0-9a-f][0-9a-f][0-9a-f]-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]'
"#;

/// Reserve the key of every keyed revoke whose evidence has none, on every
/// open, not once. The token database has no version fence, so an older
/// build can serve this file after the upgrade and commit keyed revokes
/// that check only the evidence table; the next open by this build reserves
/// their keys, so a reservation exists for every keyed revoke's evidence row
/// again. A key already reserved is left as it is.
///
/// One exception cannot be repaired: an older build checks only the
/// evidence table, so it can commit a keyed revoke whose key this file
/// already reserved for another action (by the token store or a Connections
/// store on a shared file). That key stays with the action that reserved it,
/// and the revoke keeps no reservation. Such rows are counted and returned,
/// and the caller logs the count under a static message, so the collision is
/// visible; no key, token or actor is logged.
///
/// Cost: one read of the revoke evidence per open (the evidence table has no
/// index on `action`, so it is a scan, paid once per process start and per
/// offline command). When nothing needs reserving it writes nothing and takes
/// no write lock. The insert is one statement with the same predicate, so
/// two processes opening the file together cannot reserve a key twice.
fn reserve_keyed_revocations(connection: &Connection) -> rusqlite::Result<i64> {
    let (unreserved, collisions): (i64, i64) = connection.query_row(
        &format!(
            "SELECT COALESCE(SUM(k.operation_id IS NULL), 0), \
                    COALESCE(SUM(k.action IS NOT NULL AND k.action <> e.action), 0) \
             {KEYED_REVOCATIONS_SQL}"
        ),
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if unreserved > 0 {
        connection.execute(
            &format!(
                "INSERT OR IGNORE INTO authority_caller_operation_ids (operation_id, action) \
                 SELECT e.operation_id, e.action {KEYED_REVOCATIONS_SQL} \
                 AND k.operation_id IS NULL"
            ),
            [],
        )?;
    }
    Ok(collisions)
}

/// Widen an evidence table created before token issue evidence existed, so it
/// admits `service_token.issue` (issue #425).
///
/// SQLite cannot change a CHECK constraint in place, so the table is rebuilt:
/// in one IMMEDIATE transaction that looks again under the write lock, a new
/// table is created from [`CHANGE_EVIDENCE_COLUMNS_SQL`] and gains the actor
/// columns exactly as a fresh database's table does, every row is copied with
/// its own `sequence`, the older table is dropped, the new one takes its name
/// and the index is recreated. Dropping a table forgets its AUTOINCREMENT
/// high-water mark, so the older table's is carried over: a sequence number
/// once used is never handed out again. Nothing is backfilled: a token issued
/// before this table admitted its issue keeps `created_by` as its only record.
///
/// The common case -- a table that already admits the issue action, which is
/// every table this build created -- reads the schema and writes nothing. A
/// failure leaves the older table as it was; the store then does not open.
fn rebuild_change_evidence_for_issue(connection: &Connection) -> rusqlite::Result<()> {
    if change_evidence_admits_issue(connection)? {
        return Ok(());
    }
    let transaction =
        rusqlite::Transaction::new_unchecked(connection, rusqlite::TransactionBehavior::Immediate)?;
    // Another process may have rebuilt it while this one waited for the lock.
    if change_evidence_admits_issue(&transaction)? {
        return transaction.commit();
    }
    let high_water: Option<i64> = transaction
        .query_row(
            "SELECT seq FROM sqlite_sequence WHERE name = 'service_token_change_evidence'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    transaction.execute_batch(&format!(
        "CREATE TABLE {CHANGE_EVIDENCE_REBUILD_TABLE} ({CHANGE_EVIDENCE_COLUMNS_SQL});"
    ))?;
    for (name, definition) in CHANGE_EVIDENCE_ACTOR_COLUMNS {
        transaction.execute(
            &format!("ALTER TABLE {CHANGE_EVIDENCE_REBUILD_TABLE} ADD COLUMN {name} {definition}"),
            [],
        )?;
    }
    transaction.execute(
        &format!(
            "INSERT INTO {CHANGE_EVIDENCE_REBUILD_TABLE} ({CHANGE_EVIDENCE_COPIED_COLUMNS}) \
             SELECT {CHANGE_EVIDENCE_COPIED_COLUMNS} FROM service_token_change_evidence \
             ORDER BY sequence"
        ),
        [],
    )?;
    transaction.execute_batch(&format!(
        "DROP TABLE service_token_change_evidence; \
         ALTER TABLE {CHANGE_EVIDENCE_REBUILD_TABLE} RENAME TO service_token_change_evidence;"
    ))?;
    transaction.execute_batch(CHANGE_EVIDENCE_INDEX_SQL)?;
    if let Some(high_water) = high_water {
        transaction.execute(
            "DELETE FROM sqlite_sequence WHERE name = 'service_token_change_evidence'",
            [],
        )?;
        transaction.execute(
            "INSERT INTO sqlite_sequence (name, seq) \
             SELECT 'service_token_change_evidence', max(?1, coalesce(max(sequence), 0)) \
             FROM service_token_change_evidence",
            [high_water],
        )?;
    }
    transaction.commit()
}

/// Whether the evidence table's own definition admits the issue action.
fn change_evidence_admits_issue(connection: &Connection) -> rusqlite::Result<bool> {
    let definition: String = connection.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'service_token_change_evidence'",
        [],
        |row| row.get(0),
    )?;
    Ok(definition.contains(&format!("'{TOKEN_CHANGE_ACTION_ISSUE}'")))
}

/// Add whichever actor metadata columns the evidence table lacks. The common
/// case -- every column present -- reads the schema and writes nothing. A
/// database that lacks one is altered in one IMMEDIATE transaction that looks
/// again under the write lock, so two processes opening the same older file
/// cannot both add a column, and a failure leaves the table as it was.
fn add_change_evidence_actor_columns(connection: &Connection) -> rusqlite::Result<()> {
    if missing_change_evidence_actor_columns(connection)?.is_empty() {
        return Ok(());
    }
    let transaction =
        rusqlite::Transaction::new_unchecked(connection, rusqlite::TransactionBehavior::Immediate)?;
    for (name, definition) in missing_change_evidence_actor_columns(&transaction)? {
        transaction.execute(
            &format!("ALTER TABLE service_token_change_evidence ADD COLUMN {name} {definition}"),
            [],
        )?;
    }
    transaction.commit()
}

fn missing_change_evidence_actor_columns(
    connection: &Connection,
) -> rusqlite::Result<Vec<(&'static str, &'static str)>> {
    missing_columns(
        connection,
        "service_token_change_evidence",
        &CHANGE_EVIDENCE_ACTOR_COLUMNS,
    )
}

/// Add whichever of `columns` `table` lacks, in order, exactly as
/// [`add_change_evidence_actor_columns`] does: the common case reads the
/// schema and writes nothing; otherwise one IMMEDIATE transaction looks again
/// under the write lock, so two processes opening the same older file cannot
/// both add a column, and a failure leaves the table as it was.
fn add_missing_columns(
    connection: &Connection,
    table: &'static str,
    columns: &[(&'static str, &'static str)],
) -> rusqlite::Result<()> {
    if missing_columns(connection, table, columns)?.is_empty() {
        return Ok(());
    }
    let transaction =
        rusqlite::Transaction::new_unchecked(connection, rusqlite::TransactionBehavior::Immediate)?;
    for (name, definition) in missing_columns(&transaction, table, columns)? {
        transaction.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {name} {definition}"),
            [],
        )?;
    }
    transaction.commit()
}

fn missing_columns(
    connection: &Connection,
    table: &'static str,
    columns: &[(&'static str, &'static str)],
) -> rusqlite::Result<Vec<(&'static str, &'static str)>> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let existing = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns
        .iter()
        .copied()
        .filter(|(name, _)| !existing.iter().any(|column| column == name))
        .collect())
}

fn load_record_by_id(
    connection: &Connection,
    path: &Path,
    id: &str,
) -> Result<Option<TokenRecord>, TokenStoreError> {
    connection
        .query_row(
            r#"
            SELECT
                id,
                token_prefix,
                scopes_json,
                created_by,
                created_at,
                expires_at,
                last_used_at,
                revoked_at
            FROM service_tokens
            WHERE id = ?1
            "#,
            params![id],
            RawTokenRecord::from_row,
        )
        .optional()
        .map_err(|source| store_failure(path, source))?
        .map(RawTokenRecord::into_record)
        .transpose()
}

fn load_record_by_hash(
    connection: &Connection,
    path: &Path,
    token_hash: &str,
) -> Result<Option<TokenRecord>, TokenStoreError> {
    connection
        .query_row(
            r#"
            SELECT
                id,
                token_prefix,
                scopes_json,
                created_by,
                created_at,
                expires_at,
                last_used_at,
                revoked_at
            FROM service_tokens
            WHERE token_hash = ?1
            "#,
            params![token_hash],
            RawTokenRecord::from_row,
        )
        .optional()
        .map_err(|source| store_failure(path, source))?
        .map(RawTokenRecord::into_record)
        .transpose()
}

fn build_token_list_query(
    filters: &TokenListFilters,
    cursor: Option<&TokenCursor>,
) -> (String, Vec<SqlValue>) {
    let mut sql = String::from(
        r#"
        SELECT
            id,
            token_prefix,
            scopes_json,
            created_by,
            created_at,
            expires_at,
            last_used_at,
            revoked_at
        FROM service_tokens
        "#,
    );
    let mut params = Vec::new();
    if let Some(cursor) = cursor {
        sql.push_str(
            " WHERE (julianday(created_at) < julianday(?) OR (julianday(created_at) = julianday(?) AND id > ?))",
        );
        params.push(SqlValue::Text(cursor.created_at.clone()));
        params.push(SqlValue::Text(cursor.created_at.clone()));
        params.push(SqlValue::Text(cursor.id.clone()));
    }

    sql.push_str(" ORDER BY julianday(created_at) DESC, id ASC LIMIT ?");
    params.push(SqlValue::Integer(query_limit(filters.limit)));

    (sql, params)
}

pub(crate) fn generate_plaintext_token() -> Result<String, TokenStoreError> {
    let mut bytes = [0_u8; TOKEN_RANDOM_BYTES];
    getrandom::fill(&mut bytes).map_err(TokenStoreError::Random)?;
    Ok(format!("{TOKEN_MARKER}{}", hex::encode(bytes)))
}

pub(crate) fn hash_token(plaintext_token: &str) -> String {
    let digest = Sha256::digest(plaintext_token.as_bytes());
    hex::encode(digest)
}

pub(crate) fn display_prefix(plaintext_token: &str) -> String {
    let suffix = plaintext_token
        .strip_prefix(TOKEN_MARKER)
        .unwrap_or(plaintext_token);
    let visible_suffix = suffix
        .chars()
        .take(TOKEN_DISPLAY_PREFIX_HEX_CHARS)
        .collect::<String>();
    format!("{TOKEN_MARKER}{visible_suffix}")
}

pub(crate) fn new_token_id() -> String {
    format!("token_{}", uuid::Uuid::new_v4())
}

pub(crate) fn validate_optional_timestamp(
    value: Option<&str>,
    context: &'static str,
) -> Result<(), TokenStoreError> {
    if let Some(value) = value {
        parse_rfc3339(value, context)?;
    }

    Ok(())
}

/// Time left before `expires_at` by this store's clock (zero once past
/// it); `None` without an expiry.
fn remaining_lifetime(
    expires_at: Option<&str>,
    now: OffsetDateTime,
) -> Result<Option<std::time::Duration>, TokenStoreError> {
    let Some(expires_at) = expires_at else {
        return Ok(None);
    };
    let expires_at = parse_rfc3339(expires_at, "expires_at")?;
    Ok(Some((expires_at - now).try_into().unwrap_or_default()))
}

fn is_expired(expires_at: Option<&str>, now: OffsetDateTime) -> Result<bool, TokenStoreError> {
    let Some(expires_at) = expires_at else {
        return Ok(false);
    };

    Ok(parse_rfc3339(expires_at, "expires_at")? <= now)
}

fn parse_rfc3339(value: &str, context: &'static str) -> Result<OffsetDateTime, TokenStoreError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|source| TokenStoreError::TimeParse {
        context,
        value: value.to_owned(),
        source,
    })
}

pub(crate) fn encode_cursor<T: Serialize>(cursor: &T) -> Result<String, TokenStoreError> {
    let json = serde_json::to_vec(cursor).map_err(|source| TokenStoreError::Json {
        context: "cursor",
        source,
    })?;
    Ok(hex::encode(json))
}

pub(crate) fn decode_cursor<T: DeserializeOwned>(
    parameter: &'static str,
    value: &str,
) -> Result<T, TokenStoreError> {
    let bytes = hex::decode(value).map_err(|_| TokenStoreError::InvalidCursor { parameter })?;
    serde_json::from_slice(&bytes).map_err(|_| TokenStoreError::InvalidCursor { parameter })
}

pub(crate) fn query_limit(limit: usize) -> i64 {
    i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX)
}

fn utc_timestamp_rfc3339() -> Result<String, TokenStoreError> {
    format_timestamp_rfc3339(OffsetDateTime::now_utc())
}

fn format_timestamp_rfc3339(timestamp: OffsetDateTime) -> Result<String, TokenStoreError> {
    timestamp
        .format(&Rfc3339)
        .map_err(TokenStoreError::TimeFormat)
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, thread};

    use rusqlite::Connection;
    use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

    use super::*;

    #[test]
    fn create_returns_plaintext_once_and_never_exposes_hash_or_plaintext_again() {
        let db = TempDb::new("create-once");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");

        let created = store
            .create(
                create_request(&["admin"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("token should create");

        assert!(created.plaintext_token.starts_with("ggw_"));
        assert_eq!(created.record.token_prefix.len(), "ggw_".len() + 10);
        assert!(created
            .plaintext_token
            .starts_with(&created.record.token_prefix));
        assert_ne!(created.record.token_prefix, created.plaintext_token);

        let loaded = store
            .get_by_id(&created.record.id)
            .expect("token should load")
            .expect("token should exist");
        assert_eq!(loaded.id, created.record.id);
        assert_eq!(loaded.token_prefix, created.record.token_prefix);
        assert_eq!(loaded.scopes, vec!["admin"]);

        let page = store
            .list(&TokenListFilters {
                limit: 10,
                cursor: None,
            })
            .expect("tokens should list");
        assert_eq!(page.tokens.len(), 1);
        let page_json = serde_json::to_string(&page).expect("page should serialize");
        assert!(!page_json.contains(&created.plaintext_token));
        assert!(!page_json.contains("token_hash"));

        let hashes = token_hashes(&db.path);
        assert_eq!(hashes.len(), 1);
        assert_ne!(hashes[0], created.plaintext_token);
        assert_eq!(hashes[0].len(), 64);
    }

    #[test]
    fn verify_accepts_fresh_token_and_updates_last_used() {
        let db = TempDb::new("verify-fresh");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let created = store
            .create(
                create_request(&["reader", "writer"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("token should create");

        let verification = store
            .verify(&created.plaintext_token)
            .expect("verify should query");

        let verified = match verification {
            TokenVerification::Valid(verified) => verified,
            other => panic!("expected valid token, got {other:?}"),
        };
        assert_eq!(verified.id, created.record.id);
        assert_eq!(verified.scopes, vec!["reader", "writer"]);
        assert!(verified.last_used_at.is_some());

        let loaded = store
            .get_by_id(&created.record.id)
            .expect("token should load")
            .expect("token should exist");
        assert!(loaded.last_used_at.is_some());
    }

    #[test]
    fn verify_rejects_wrong_revoked_and_expired_tokens() {
        let db = TempDb::new("verify-failures");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let active = store
            .create(
                create_request(&["reader"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("active token should create");
        let revoked = store
            .create(
                create_request(&["reader"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("revoked token should create");
        let expired = store
            .create(
                create_request(
                    &["reader"],
                    "creator",
                    Some(timestamp_after(Duration::seconds(-60))),
                ),
                &ChangeActor::for_test("creator"),
            )
            .expect("expired token should create");

        assert_eq!(
            store
                .verify("ggw_not-a-real-token")
                .expect("garbage verify should query"),
            TokenVerification::Invalid(TokenVerificationFailure::NotFound)
        );

        store
            .revoke(&revoked.record.id, &ChangeActor::for_test("revoking-admin"))
            .expect("revocation should succeed")
            .expect("revoked token should exist");
        assert_eq!(
            store
                .verify(&revoked.plaintext_token)
                .expect("revoked verify should query"),
            TokenVerification::Invalid(TokenVerificationFailure::Revoked)
        );
        assert_eq!(
            store
                .verify(&expired.plaintext_token)
                .expect("expired verify should query"),
            TokenVerification::Invalid(TokenVerificationFailure::Expired)
        );
        assert!(matches!(
            store
                .verify(&active.plaintext_token)
                .expect("active verify should query"),
            TokenVerification::Valid(_)
        ));
    }

    #[test]
    fn revoke_is_idempotent_and_does_not_double_write_revoked_at() {
        let db = TempDb::new("revoke-idempotent");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let created = store
            .create(
                create_request(&["reader"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("token should create");

        let first = store
            .revoke(&created.record.id, &ChangeActor::for_test("revoking-admin"))
            .expect("first revoke should succeed")
            .expect("token should exist");
        let first_revoked_at = first.revoked_at.clone().expect("token should be revoked");
        let second = store
            .revoke(&created.record.id, &ChangeActor::for_test("revoking-admin"))
            .expect("second revoke should succeed")
            .expect("token should still exist");

        assert_eq!(
            second.revoked_at.as_deref(),
            Some(first_revoked_at.as_str())
        );
    }

    /// The change-evidence actor bound is written three times -- the
    /// SQLite table here and both tables of PostgreSQL migration 18 -- and
    /// asserted equal to the principal subject bound at compile time. Pin
    /// the SQL literals to that same constant so none can drift alone.
    #[test]
    fn change_evidence_actor_bound_matches_both_schemas() {
        let bound = format!("BETWEEN 1 AND {MAX_TOKEN_CHANGE_ACTOR_BYTES}");
        assert!(CHANGE_EVIDENCE_COLUMNS_SQL
            .contains(&format!("length(CAST(actor_user_id AS BLOB)) {bound}")));
        let migration =
            include_str!("../storage/migrations/0018_service_token_and_jwt_evidence.sql");
        assert_eq!(
            migration
                .matches(&format!("octet_length(actor_user_id) {bound}"))
                .count(),
            2
        );
    }

    /// The actor issuer bound and the kind/auth-mode pairs are written four
    /// times: the SQLite column here and the three tables of PostgreSQL
    /// migration 24. Pin the SQL to the Rust bound and keep the four CHECKs
    /// identical, so the stores cannot disagree about what is recordable.
    #[test]
    fn change_evidence_actor_metadata_matches_both_schemas() {
        let issuer_bound = format!(
            "actor_issuer IS NULL OR length(CAST(actor_issuer AS BLOB)) BETWEEN 1 AND {MAX_TOKEN_CHANGE_ACTOR_ISSUER_BYTES}"
        );
        let (_, sqlite_issuer) = CHANGE_EVIDENCE_ACTOR_COLUMNS[2];
        assert!(sqlite_issuer.contains(&issuer_bound), "{sqlite_issuer}");
        let migration =
            include_str!("../storage/migrations/0024_authority_evidence_actor_metadata.sql");
        assert_eq!(
            migration
                .matches(&format!(
                    "actor_issuer IS NULL OR octet_length(actor_issuer) BETWEEN 1 AND {MAX_TOKEN_CHANGE_ACTOR_ISSUER_BYTES}"
                ))
                .count(),
            3
        );
        // The pairing CHECK, whitespace aside, is the same text in both.
        let squeeze = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
        let pairing = squeeze(
            sqlite_issuer
                .split_once(") CHECK (")
                .map(|(_, pairing)| pairing)
                .expect("the issuer column carries the pairing CHECK"),
        );
        assert_eq!(squeeze(migration).matches(&pairing).count(), 3, "{pairing}");
    }

    /// The action vocabulary is written three times: the constants, the
    /// SQLite CHECK here and PostgreSQL migration 27's CHECK. Pin all three to
    /// each other so the stores cannot disagree about what is recordable.
    #[test]
    fn change_evidence_actions_match_both_schemas() {
        let actions = [
            TOKEN_CHANGE_ACTION_ISSUE,
            TOKEN_CHANGE_ACTION_ROTATE,
            TOKEN_CHANGE_ACTION_REVOKE,
        ]
        .map(|action| format!("'{action}'"))
        .join(", ");
        let check = format!("action IN ({actions})");
        assert!(CHANGE_EVIDENCE_COLUMNS_SQL.contains(&check), "{check}");
        let migration = include_str!("../storage/migrations/0027_service_token_issue_evidence.sql");
        assert!(migration.contains(&check), "{check}");
    }

    /// The token database as a build before token issue evidence left it:
    /// its token table and an evidence table whose action CHECK admits only
    /// rotate and revoke, created exactly as that build created it.
    fn create_pre_issue_schema(connection: &Connection) {
        connection
            .execute_batch(CREATE_SERVICE_TOKEN_SCHEMA_SQL)
            .expect("the token table should create");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS service_token_change_evidence (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE CHECK (length(event_id) = 36),
                    operation_id TEXT NOT NULL CHECK (length(operation_id) = 36),
                    actor_user_id TEXT NOT NULL CHECK (
                        length(CAST(actor_user_id AS BLOB)) BETWEEN 1 AND 4096
                    ),
                    action TEXT NOT NULL CHECK (
                        action IN ('service_token.rotate', 'service_token.revoke')
                    ),
                    token_id TEXT NOT NULL CHECK (length(CAST(token_id AS BLOB)) BETWEEN 1 AND 128),
                    committed_at TEXT NOT NULL,
                    UNIQUE (operation_id, action)
                );

                CREATE INDEX IF NOT EXISTS idx_service_token_change_evidence_token
                ON service_token_change_evidence(token_id, sequence);
                "#,
            )
            .expect("the older evidence table should create");
    }

    /// Every evidence row as text, in sequence order.
    fn evidence_text(connection: &Connection) -> Vec<String> {
        let mut statement = connection
            .prepare(
                "SELECT sequence, event_id, operation_id, actor_user_id, action, token_id, \
                        committed_at, ifnull(actor_kind, 'NULL'), \
                        ifnull(actor_auth_mode, 'NULL'), ifnull(actor_issuer, 'NULL') \
                 FROM service_token_change_evidence ORDER BY sequence",
            )
            .expect("evidence query should prepare");
        statement
            .query_map([], |row| {
                Ok(format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .expect("evidence query should run")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("evidence rows should decode")
    }

    /// An evidence table a build before token issue evidence wrote, with or
    /// without the actor columns, is rebuilt on the first open so it admits
    /// the issue, and only once. Every row keeps its sequence and every
    /// column, the AUTOINCREMENT high-water mark survives (a sequence number
    /// once handed out, even to a row since removed, is never handed out
    /// again), the index is back, no rebuild table is left, nothing is
    /// backfilled for the token issued before it, and the table still
    /// refuses an action outside the vocabulary.
    #[test]
    fn an_evidence_table_written_before_issue_evidence_is_rebuilt_once_and_keeps_its_rows() {
        for with_actor_columns in [false, true] {
            let db = TempDb::new("evidence-issue-rebuild");
            let connection = Connection::open(&db.path).expect("database should open");
            create_pre_issue_schema(&connection);
            if with_actor_columns {
                add_change_evidence_actor_columns(&connection)
                    .expect("the older binary's actor columns should add");
            }
            connection
                .execute(
                    "INSERT INTO service_tokens \
                         (id, token_hash, token_prefix, scopes_json, created_by, created_at) \
                     VALUES ('token_older', ?1, 'ggw_aaaaaaaaaa', '[\"reader\"]', \
                             'older-creator', '2026-10-01T00:00:00Z')",
                    [hash_token("older-plaintext")],
                )
                .expect("an older binary's token");
            for (action, committed_at) in [
                ("service_token.rotate", "2026-10-01T00:00:01Z"),
                ("service_token.rotate", "2026-10-01T00:00:02Z"),
                ("service_token.revoke", "2026-10-01T00:00:03Z"),
            ] {
                connection
                    .execute(
                        "INSERT INTO service_token_change_evidence \
                             (event_id, operation_id, actor_user_id, action, token_id, \
                              committed_at) \
                         VALUES (?1, ?2, 'older-admin', ?3, 'token_older', ?4)",
                        params![
                            uuid::Uuid::new_v4().to_string(),
                            uuid::Uuid::new_v4().to_string(),
                            action,
                            committed_at
                        ],
                    )
                    .expect("an older binary's evidence row");
            }
            // An operator removed the last row: the high-water mark is above
            // every remaining sequence.
            connection
                .execute(
                    "DELETE FROM service_token_change_evidence WHERE sequence = 3",
                    [],
                )
                .expect("a row should delete");
            drop(connection);
            let before = {
                let connection = Connection::open(&db.path).expect("database should open");
                add_change_evidence_actor_columns(&connection).expect("actor columns");
                evidence_text(&connection)
            };
            assert_eq!(before.len(), 2);

            for _ in 0..2 {
                drop(SqliteTokenStore::open(&db.path).expect("the store should open"));
            }
            let connection = Connection::open(&db.path).expect("database should open");
            assert!(change_evidence_admits_issue(&connection).expect("schema reads"));
            assert_eq!(
                evidence_text(&connection),
                before,
                "every row keeps its sequence and columns"
            );
            let high_water: i64 = connection
                .query_row(
                    "SELECT seq FROM sqlite_sequence WHERE name = 'service_token_change_evidence'",
                    [],
                    |row| row.get(0),
                )
                .expect("the high-water mark survives");
            assert_eq!(high_water, 3);
            let leftovers: i64 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name = ?1",
                    [CHANGE_EVIDENCE_REBUILD_TABLE],
                    |row| row.get(0),
                )
                .expect("schema reads");
            assert_eq!(leftovers, 0);
            let index: i64 = connection
                .query_row(
                    "SELECT count(*) FROM sqlite_master \
                     WHERE type = 'index' AND name = 'idx_service_token_change_evidence_token' \
                       AND tbl_name = 'service_token_change_evidence'",
                    [],
                    |row| row.get(0),
                )
                .expect("schema reads");
            assert_eq!(index, 1);
            assert!(missing_change_evidence_actor_columns(&connection)
                .expect("schema reads")
                .is_empty());
            drop(connection);

            // The token issued before the rebuild has no issue row; the next
            // issue is recorded after every sequence ever handed out.
            let store = SqliteTokenStore::open(&db.path).expect("the store should open");
            let issued = store
                .create(
                    create_request(&["reader"], "creator", None),
                    &ChangeActor::for_test("creator"),
                )
                .expect("a token issues after the rebuild");
            let connection = Connection::open(&db.path).expect("database should open");
            let after = evidence_text(&connection);
            assert_eq!(after.len(), 3);
            assert_eq!(after[..2], before[..]);
            assert!(
                after[2].starts_with("4|")
                    && after[2].contains(&format!("|service_token.issue|{}|", issued.record.id)),
                "{after:?}"
            );
            let refused = connection.execute(
                "INSERT INTO service_token_change_evidence \
                     (event_id, operation_id, actor_user_id, action, token_id, committed_at) \
                 VALUES (?1, ?2, 'admin', 'service_token.delete', 'token_older', \
                         '2026-10-01T00:00:04Z')",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string()
                ],
            );
            assert!(refused.is_err(), "the vocabulary stays closed");
        }
    }

    #[test]
    fn an_older_evidence_table_gains_the_actor_columns_once_and_keeps_its_rows() {
        let db = TempDb::new("evidence-actor-columns");
        let connection = Connection::open(&db.path).expect("database should open");
        create_pre_issue_schema(&connection);
        connection
            .execute(
                "INSERT INTO service_token_change_evidence \
                     (event_id, operation_id, actor_user_id, action, token_id, committed_at) \
                 VALUES (?1, ?2, 'older-admin', 'service_token.revoke', 'token_1', \
                         '2026-10-01T00:00:00Z')",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string()
                ],
            )
            .expect("an older binary's evidence row");
        drop(connection);

        for _ in 0..2 {
            drop(SqliteTokenStore::open(&db.path).expect("the store should open"));
        }
        let connection = Connection::open(&db.path).expect("database should open");
        assert!(missing_change_evidence_actor_columns(&connection)
            .expect("the schema should read")
            .is_empty());
        let row: (String, Option<String>, Option<String>, Option<String>) = connection
            .query_row(
                "SELECT actor_user_id, actor_issuer, actor_kind, actor_auth_mode \
                 FROM service_token_change_evidence",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("the older row should remain");
        assert_eq!(
            row,
            ("older-admin".to_owned(), None, None, None),
            "nothing is guessed into a row that did not record it"
        );

        // A row recording some of the metadata, or a pairing authentication
        // cannot produce, is refused by the table itself.
        for (issuer, kind, mode) in [
            (None, Some("principal"), None),
            (None, None, Some("bearer_token")),
            (Some("https://idp.example.test"), None, None),
            (None, Some("principal"), Some("service_token")),
            (None, Some("service_token"), Some("bearer_token")),
            (
                Some("https://idp.example.test"),
                Some("service_token"),
                Some("service_token"),
            ),
            (
                Some("https://idp.example.test"),
                Some("system"),
                Some("system"),
            ),
            (None, Some("person"), Some("bearer_token")),
            (Some(""), Some("principal"), Some("bearer_token")),
        ] {
            let refused = connection.execute(
                "INSERT INTO service_token_change_evidence \
                     (event_id, operation_id, actor_user_id, actor_issuer, actor_kind, \
                      actor_auth_mode, action, token_id, committed_at) \
                 VALUES (?1, ?2, 'admin', ?3, ?4, ?5, 'service_token.revoke', 'token_1', \
                         '2026-10-01T00:00:00Z')",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string(),
                    issuer,
                    kind,
                    mode
                ],
            );
            assert!(refused.is_err(), "{issuer:?} {kind:?} {mode:?}");
        }
    }

    /// An issue, a rotate or a revoke whose evidence cannot be inserted is
    /// refused and counted once on the standalone evidence-failure counter
    /// under the token database; the revoke recorded once evidence can be
    /// written counts nothing. The rollback itself is pinned by the repository
    /// contract tests `sqlite_failed_evidence_insert_rolls_back_rotate_and_revoke`
    /// and `sqlite_service_token_issue_evidence_satisfies_the_contract`, whose
    /// store calls run on blocking threads this thread's recorder does not
    /// see.
    #[test]
    fn a_refused_rotate_or_revoke_counts_one_evidence_failure_each() {
        let db = TempDb::new("evidence-failure-count");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let created = store
            .create(
                create_request(&["admin"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("token should create");
        let id = created.record.id;
        // The recorder is this thread's, and the store runs on this thread.
        let recorder = crate::audit::sink::tests::CountingRecorder::default();
        let _recording = ::metrics::set_default_local_recorder(&recorder);
        let evidence_failures = |store: &str| {
            recorder.count(
                crate::metrics::STANDALONE_EVIDENCE_FAILURES_TOTAL,
                &[("store", store)],
            )
        };

        // Test-only fault injection through a second connection; no
        // production hook exists for it.
        Connection::open(&db.path)
            .expect("token database should open")
            .execute_batch(
                "CREATE TRIGGER fail_token_change_evidence \
                 BEFORE INSERT ON service_token_change_evidence \
                 BEGIN SELECT RAISE(ABORT, 'injected evidence failure'); END;",
            )
            .expect("failure trigger should install");
        let faulted = ChangeActor::for_test("faulted-admin");
        assert!(matches!(
            store.rotate(&id, &faulted),
            Err(TokenStoreError::ChangeEvidence { .. })
        ));
        assert_eq!(evidence_failures("service_tokens"), 1);
        assert!(matches!(
            store.revoke(&id, &faulted),
            Err(TokenStoreError::ChangeEvidence { .. })
        ));
        assert_eq!(evidence_failures("service_tokens"), 2);
        assert!(matches!(
            store.create(create_request(&["admin"], "creator", None), &faulted),
            Err(TokenStoreError::ChangeEvidence { .. })
        ));
        assert_eq!(evidence_failures("service_tokens"), 3);
        assert_eq!(evidence_failures("connections"), 0);

        Connection::open(&db.path)
            .expect("token database should open")
            .execute_batch("DROP TRIGGER fail_token_change_evidence;")
            .expect("failure trigger should drop");
        store
            .revoke(&id, &ChangeActor::for_test("recovered-admin"))
            .expect("the revoke commits once evidence can be written")
            .expect("token should exist");
        assert_eq!(
            evidence_failures("service_tokens"),
            3,
            "a recorded change counts nothing"
        );
    }

    #[test]
    fn rotate_preserves_record_metadata_and_invalidates_old_plaintext() {
        let db = TempDb::new("rotate");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let expires_at = timestamp_after(Duration::hours(1));
        let created = store
            .create(
                create_request(&["reader", "operator"], "creator", Some(expires_at.clone())),
                &ChangeActor::for_test("creator"),
            )
            .expect("token should create");
        let original_hash = token_hashes(&db.path)
            .into_iter()
            .next()
            .expect("hash should exist");

        let rotated = store
            .rotate(&created.record.id, &ChangeActor::for_test("rotating-admin"))
            .expect("rotate should succeed")
            .expect("token should exist");
        let rotated_hash = token_hashes(&db.path)
            .into_iter()
            .next()
            .expect("rotated hash should exist");

        assert_eq!(rotated.record.id, created.record.id);
        assert_eq!(rotated.record.scopes, created.record.scopes);
        assert_eq!(rotated.record.created_by, created.record.created_by);
        assert_eq!(
            rotated.record.expires_at.as_deref(),
            Some(expires_at.as_str())
        );
        assert_ne!(rotated.plaintext_token, created.plaintext_token);
        assert_ne!(rotated_hash, original_hash);
        assert_eq!(
            store
                .verify(&created.plaintext_token)
                .expect("old token verify should query"),
            TokenVerification::Invalid(TokenVerificationFailure::NotFound)
        );
        assert!(matches!(
            store
                .verify(&rotated.plaintext_token)
                .expect("new token verify should query"),
            TokenVerification::Valid(_)
        ));
    }

    #[test]
    fn list_paginates_newest_first_without_secret_material() {
        let db = TempDb::new("list-pagination");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let first = store
            .create(
                create_request(&["one"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("first token should create");
        let second = store
            .create(
                create_request(&["two"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("second token should create");
        let third = store
            .create(
                create_request(&["three"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("third token should create");

        set_created_at(&db.path, &first.record.id, "2024-01-01T00:00:00Z");
        set_created_at(&db.path, &second.record.id, "2024-01-02T00:00:00Z");
        set_created_at(&db.path, &third.record.id, "2024-01-03T00:00:00Z");

        let first_page = store
            .list(&TokenListFilters {
                limit: 2,
                cursor: None,
            })
            .expect("first page should list");
        assert_eq!(
            first_page
                .tokens
                .iter()
                .map(|token| token.id.as_str())
                .collect::<Vec<_>>(),
            vec![third.record.id.as_str(), second.record.id.as_str()]
        );
        let cursor = first_page
            .next_cursor
            .clone()
            .expect("next cursor should exist");

        let second_page = store
            .list(&TokenListFilters {
                limit: 2,
                cursor: Some(cursor),
            })
            .expect("second page should list");
        assert_eq!(
            second_page
                .tokens
                .iter()
                .map(|token| token.id.as_str())
                .collect::<Vec<_>>(),
            vec![first.record.id.as_str()]
        );
        assert!(second_page.next_cursor.is_none());

        let serialized = serde_json::to_string(&first_page).expect("page should serialize");
        for plaintext in [
            &first.plaintext_token,
            &second.plaintext_token,
            &third.plaintext_token,
        ] {
            assert!(!serialized.contains(plaintext));
        }
        assert!(!serialized.contains("token_hash"));
    }

    #[test]
    fn recovers_from_poisoned_connection_lock() {
        let db = TempDb::new("poison");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let poisoned_store = store.clone();

        let _ = thread::spawn(move || {
            let _guard = poisoned_store
                .connection
                .lock()
                .expect("lock should not be poisoned yet");
            panic!("poison the token store connection lock");
        })
        .join();

        let created = store
            .create(
                create_request(&["reader"], "creator", None),
                &ChangeActor::for_test("creator"),
            )
            .expect("store should recover after poisoned lock");

        assert!(created.plaintext_token.starts_with("ggw_"));
    }

    /// `(operation_id, action)` rows, sorted.
    type KeyedRows = Vec<(String, String)>;

    /// Every reservation in the file, and every keyed (UUIDv7) evidence row.
    fn reservations_and_keyed_evidence(path: &PathBuf) -> (KeyedRows, KeyedRows) {
        let connection = Connection::open(path).expect("test database should open");
        let read = |sql: &str| {
            connection
                .prepare(sql)
                .expect("query should prepare")
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .expect("query should run")
                .collect::<Result<Vec<_>, _>>()
                .expect("rows should load")
        };
        let reservations = read(
            "SELECT operation_id, action FROM authority_caller_operation_ids \
             ORDER BY operation_id, action",
        );
        let keyed = read(
            "SELECT operation_id, action FROM service_token_change_evidence \
             ORDER BY operation_id, action",
        )
        .into_iter()
        .filter(|(id, _)| uuid::Uuid::parse_str(id).is_ok_and(valid_caller_operation_id))
        .collect();
        (reservations, keyed)
    }

    /// I3 over the token database: a keyed revoke reserves its key in the
    /// transaction that writes its evidence, so a reservation exists exactly
    /// when a keyed evidence row does. A replay, a conflicting reuse, an
    /// unkeyed revoke and a revoke whose evidence cannot be written reserve
    /// nothing.
    #[test]
    fn a_keyed_revoke_reserves_its_key_with_its_evidence() {
        let db = TempDb::new("keyed-revoke-reservation");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let owner = ChangeActor::for_test_with_issuer("operator", "https://issuer.example.test");
        let issue = || {
            store
                .create(create_request(&["admin"], "operator", None), &owner)
                .expect("token should create")
                .record
                .id
        };
        let (first, second, unkeyed, faulted, unreservable) =
            (issue(), issue(), issue(), issue(), issue());
        let key = test_revoke_operation_id(1);
        // The recorder is this thread's, and the store runs on this thread.
        let recorder = crate::audit::sink::tests::CountingRecorder::default();
        let _recording = ::metrics::set_default_local_recorder(&recorder);
        let evidence_failures = || {
            recorder.count(
                crate::metrics::STANDALONE_EVIDENCE_FAILURES_TOTAL,
                &[("store", "service_tokens")],
            )
        };
        let live = |id: &str| {
            store
                .get_by_id(id)
                .expect("token should load")
                .expect("token should exist")
                .revoked_at
                .is_none()
        };

        store
            .revoke_with_operation(&first, &owner, Some(key))
            .expect("the keyed revoke commits")
            .expect("token should exist");
        let (reservations, keyed) = reservations_and_keyed_evidence(&db.path);
        assert_eq!(
            reservations,
            [(key.to_string(), TOKEN_CHANGE_ACTION_REVOKE.to_owned())]
        );
        assert_eq!(reservations, keyed);
        let reserved_digest: Option<String> = Connection::open(&db.path)
            .expect("test database should open")
            .query_row(
                "SELECT binding_digest FROM authority_caller_operation_ids",
                [],
                |row| row.get(0),
            )
            .expect("the reservation reads");
        assert_eq!(reserved_digest, None, "a keyed revoke binds no digest");

        store
            .revoke_with_operation(&first, &owner, Some(key))
            .expect("the exact retry is answered")
            .expect("token should exist");
        assert!(matches!(
            store.revoke_with_operation(&second, &owner, Some(key)),
            Err(TokenStoreError::RevokeOperationConflict)
        ));
        store
            .revoke(&unkeyed, &owner)
            .expect("the unkeyed revoke commits")
            .expect("token should exist");
        assert_eq!(evidence_failures(), 0, "a recorded change counts nothing");
        let evidence_rows = || {
            Connection::open(&db.path)
                .expect("token database should open")
                .query_row(
                    "SELECT COUNT(*) FROM service_token_change_evidence",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .expect("the evidence counts")
        };
        let evidence_before = evidence_rows();

        // I2: a reservation insert that fails refuses the revoke before the
        // update, counts one evidence failure, and leaves the token live
        // with no evidence row and no reservation.
        Connection::open(&db.path)
            .expect("token database should open")
            .execute_batch(
                "CREATE TRIGGER fail_caller_operation_reservation \
                 BEFORE INSERT ON authority_caller_operation_ids \
                 BEGIN SELECT RAISE(ABORT, 'injected reservation failure'); END;",
            )
            .expect("failure trigger should install");
        assert!(matches!(
            store.revoke_with_operation(&unreservable, &owner, Some(test_revoke_operation_id(3))),
            Err(TokenStoreError::Sqlite { .. })
        ));
        assert_eq!(evidence_failures(), 1);
        assert!(live(&unreservable));
        assert_eq!(evidence_rows(), evidence_before);
        Connection::open(&db.path)
            .expect("token database should open")
            .execute_batch("DROP TRIGGER fail_caller_operation_reservation;")
            .expect("failure trigger should drop");

        Connection::open(&db.path)
            .expect("token database should open")
            .execute_batch(
                "CREATE TRIGGER fail_token_change_evidence \
                 BEFORE INSERT ON service_token_change_evidence \
                 BEGIN SELECT RAISE(ABORT, 'injected evidence failure'); END;",
            )
            .expect("failure trigger should install");
        assert!(matches!(
            store.revoke_with_operation(&faulted, &owner, Some(test_revoke_operation_id(2))),
            Err(TokenStoreError::ChangeEvidence { .. })
        ));
        assert_eq!(evidence_failures(), 2);
        let (after, keyed_after) = reservations_and_keyed_evidence(&db.path);
        assert_eq!(after, reservations, "nothing else was reserved");
        assert_eq!(after, keyed_after);
        assert!(live(&faulted));
        assert_eq!(evidence_rows(), evidence_before);
    }

    /// The token database has no version fence: an older build can open the
    /// upgraded file and commit keyed revokes without reservations, and a
    /// file it wrote before has no reservation table at all. Every open by
    /// this build reserves each such key -- only keyed (UUIDv7) revokes, never
    /// a gateway-assigned v4 ID -- and a later open changes nothing.
    #[test]
    fn reopening_reserves_keyed_revocations_an_older_build_wrote() {
        let db = TempDb::new("reservation-backfill");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let owner = ChangeActor::for_test_with_issuer("operator", "https://issuer.example.test");
        let token = store
            .create(create_request(&["admin"], "operator", None), &owner)
            .expect("token should create")
            .record
            .id;
        drop(store);

        let older = |connection: &Connection, operation_id: String, action: &str| {
            connection
                .execute(
                    "INSERT INTO service_token_change_evidence (event_id, operation_id, \
                     actor_user_id, actor_issuer, actor_kind, actor_auth_mode, action, \
                     token_id, committed_at) \
                     VALUES (?1, ?2, 'operator', 'https://issuer.example.test', 'principal', \
                     'bearer_token', ?3, ?4, '2026-11-19T00:00:00Z')",
                    params![
                        uuid::Uuid::new_v4().to_string(),
                        operation_id,
                        action,
                        token
                    ],
                )
                .expect("an older build's evidence row inserts");
        };
        let before_table = test_revoke_operation_id(3);
        let after_table = test_revoke_operation_id(4);
        {
            let connection = Connection::open(&db.path).expect("token database should open");
            connection
                .execute_batch("DROP TABLE authority_caller_operation_ids;")
                .expect("the file goes back to an older build's schema");
            older(
                &connection,
                before_table.to_string(),
                TOKEN_CHANGE_ACTION_REVOKE,
            );
            older(
                &connection,
                uuid::Uuid::new_v4().to_string(),
                TOKEN_CHANGE_ACTION_REVOKE,
            );
        }
        drop(SqliteTokenStore::open(&db.path).expect("token store should reopen"));
        let (reservations, keyed) = reservations_and_keyed_evidence(&db.path);
        assert_eq!(
            reservations,
            [(
                before_table.to_string(),
                TOKEN_CHANGE_ACTION_REVOKE.to_owned()
            )]
        );
        assert_eq!(reservations, keyed);

        // An older build serving the upgraded file never reads the table.
        older(
            &Connection::open(&db.path).expect("token database should open"),
            after_table.to_string(),
            TOKEN_CHANGE_ACTION_REVOKE,
        );
        drop(SqliteTokenStore::open(&db.path).expect("token store should reopen"));
        let (reservations, keyed) = reservations_and_keyed_evidence(&db.path);
        assert_eq!(reservations.len(), 2);
        assert_eq!(reservations, keyed);

        drop(SqliteTokenStore::open(&db.path).expect("token store should reopen"));
        assert_eq!(
            reservations_and_keyed_evidence(&db.path).0,
            reservations,
            "a later open changes nothing"
        );
    }

    /// The one exception the backfill cannot repair: an older build checks
    /// only the evidence table, so it can commit a keyed revoke whose key
    /// this file already reserved for another action. Opening leaves the
    /// key with that action, reserves nothing for the revoke, and counts
    /// the collision so it is visible; a revoke with a free key beside it is
    /// still reserved.
    #[test]
    fn reopening_counts_a_keyed_revocation_whose_key_another_action_holds() {
        let db = TempDb::new("reservation-collision");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let owner = ChangeActor::for_test_with_issuer("operator", "https://issuer.example.test");
        let token = store
            .create(create_request(&["admin"], "operator", None), &owner)
            .expect("token should create")
            .record
            .id;
        drop(store);

        let held = test_revoke_operation_id(5);
        let free = test_revoke_operation_id(6);
        let digest = "a".repeat(64);
        {
            let connection = Connection::open(&db.path).expect("token database should open");
            connection
                .execute(
                    "INSERT INTO authority_caller_operation_ids \
                     (operation_id, action, binding_digest) \
                     VALUES (?1, 'service_token.issue', ?2)",
                    params![held.to_string(), digest],
                )
                .expect("another action reserves the key");
            for key in [held, free] {
                connection
                    .execute(
                        "INSERT INTO service_token_change_evidence (event_id, operation_id, \
                         actor_user_id, actor_issuer, actor_kind, actor_auth_mode, action, \
                         token_id, committed_at) \
                         VALUES (?1, ?2, 'operator', 'https://issuer.example.test', \
                         'principal', 'bearer_token', 'service_token.revoke', ?3, \
                         '2026-11-19T00:00:00Z')",
                        params![uuid::Uuid::new_v4().to_string(), key.to_string(), token],
                    )
                    .expect("an older build's evidence row inserts");
            }
        }

        let expected = {
            let mut rows = vec![
                (held.to_string(), "service_token.issue".to_owned()),
                (free.to_string(), TOKEN_CHANGE_ACTION_REVOKE.to_owned()),
            ];
            rows.sort();
            rows
        };
        for _ in 0..2 {
            drop(SqliteTokenStore::open(&db.path).expect("token store should reopen"));
            let (reservations, _) = reservations_and_keyed_evidence(&db.path);
            assert_eq!(reservations, expected);
            let connection = Connection::open(&db.path).expect("token database should open");
            assert_eq!(
                reserve_keyed_revocations(&connection).expect("the backfill runs"),
                1,
                "the collision is counted on every open"
            );
            let kept: Option<String> = connection
                .query_row(
                    "SELECT binding_digest FROM authority_caller_operation_ids \
                     WHERE operation_id = ?1",
                    params![held.to_string()],
                    |row| row.get(0),
                )
                .expect("the held key reads");
            assert_eq!(kept.as_deref(), Some(digest.as_str()));
        }
    }

    /// The store-owned token revision and the evidence revisions (issue
    /// #425, plan P5). A file an older binary wrote -- here one from before
    /// issue evidence, so the open also rebuilds its evidence table -- gains
    /// the columns on its first open: its tokens start at revision 1, its
    /// evidence rows keep NULL revisions and `revised = 0`, and nothing is
    /// fabricated. Every change this build writes is revised: an issue NULL
    /// to 1, a rotation and a revocation one step up each. Reopening changes
    /// nothing, and the table refuses a revised row without its revision.
    #[test]
    fn standalone_token_revisions_start_at_one_and_legacy_evidence_stays_unrevised() {
        let db = TempDb::new("token-revisions");
        let connection = Connection::open(&db.path).expect("database should open");
        create_pre_issue_schema(&connection);
        connection
            .execute(
                "INSERT INTO service_tokens \
                     (id, token_hash, token_prefix, scopes_json, created_by, created_at) \
                 VALUES ('token_older', ?1, 'ggw_aaaaaaaaaa', '[\"reader\"]', \
                         'older-creator', '2026-10-01T00:00:00Z')",
                [hash_token("older-plaintext")],
            )
            .expect("an older binary's token");
        connection
            .execute(
                "INSERT INTO service_token_change_evidence \
                     (event_id, operation_id, actor_user_id, action, token_id, committed_at) \
                 VALUES (?1, ?2, 'older-admin', 'service_token.rotate', 'token_older', \
                         '2026-10-01T00:00:01Z')",
                params![
                    uuid::Uuid::new_v4().to_string(),
                    uuid::Uuid::new_v4().to_string()
                ],
            )
            .expect("an older binary's evidence row");
        drop(connection);

        type Revision = (String, String, Option<i64>, Option<i64>, i64);
        let revisions = |path: &PathBuf| -> Vec<Revision> {
            let connection = Connection::open(path).expect("database should open");
            let mut statement = connection
                .prepare(
                    "SELECT token_id, action, prior_version, new_version, revised \
                     FROM service_token_change_evidence ORDER BY sequence",
                )
                .expect("the evidence query prepares");
            statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                })
                .expect("the evidence reads")
                .collect::<Result<_, _>>()
                .expect("every row reads")
        };
        let token_revision = |path: &PathBuf, id: &str| -> i64 {
            Connection::open(path)
                .expect("database should open")
                .query_row(
                    "SELECT revision FROM service_tokens WHERE id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .expect("the token's revision reads")
        };

        let store = SqliteTokenStore::open(&db.path).expect("the store opens the older file");
        assert_eq!(token_revision(&db.path, "token_older"), 1);
        assert_eq!(
            revisions(&db.path),
            [(
                "token_older".to_owned(),
                "service_token.rotate".to_owned(),
                None,
                None,
                0
            )],
            "an older row is not revised and nothing is fabricated for it"
        );

        // The older token's next change starts its chain from revision 1.
        store
            .rotate("token_older", &ChangeActor::for_test("rotating-admin"))
            .expect("the older token rotates")
            .expect("the older token exists");
        let created = store
            .create(
                create_request(&["reader"], "creating-admin", None),
                &ChangeActor::for_test("creating-admin"),
            )
            .expect("a token issues");
        let id = created.record.id.clone();
        store
            .rotate(&id, &ChangeActor::for_test("rotating-admin"))
            .expect("the token rotates")
            .expect("the token exists");
        store
            .revoke(&id, &ChangeActor::for_test("revoking-admin"))
            .expect("the token revokes")
            .expect("the token exists");
        // A repeat revoke changes nothing and records nothing.
        store
            .revoke(&id, &ChangeActor::for_test("revoking-admin"))
            .expect("a repeat revoke answers")
            .expect("the token exists");
        assert_eq!(token_revision(&db.path, &id), 3);
        assert_eq!(token_revision(&db.path, "token_older"), 2);
        let expected = vec![
            (
                "token_older".to_owned(),
                "service_token.rotate".to_owned(),
                None,
                None,
                0,
            ),
            (
                "token_older".to_owned(),
                "service_token.rotate".to_owned(),
                Some(1),
                Some(2),
                1,
            ),
            (
                id.clone(),
                "service_token.issue".to_owned(),
                None,
                Some(1),
                1,
            ),
            (
                id.clone(),
                "service_token.rotate".to_owned(),
                Some(1),
                Some(2),
                1,
            ),
            (
                id.clone(),
                "service_token.revoke".to_owned(),
                Some(2),
                Some(3),
                1,
            ),
        ];
        assert_eq!(revisions(&db.path), expected);
        drop(store);

        // Reopening adds nothing and changes nothing.
        drop(SqliteTokenStore::open(&db.path).expect("the store reopens"));
        assert_eq!(revisions(&db.path), expected);

        // The table holds the pairing, per action as delivery projects it: a
        // revised row must carry its action's transition (an issue NULL to
        // 1, anything else one step up from a prior revision), and a legacy
        // row none.
        let connection = Connection::open(&db.path).expect("database should open");
        for (action, prior, new, revised) in [
            ("service_token.rotate", None, None, 1),
            ("service_token.rotate", Some(2), Some(2), 1),
            ("service_token.rotate", None, Some(1), 0),
            ("service_token.rotate", None, Some(2), 1),
            ("service_token.revoke", None, Some(3), 1),
            ("service_token.issue", None, Some(2), 1),
            ("service_token.issue", Some(1), Some(2), 1),
        ] {
            assert!(
                connection
                    .execute(
                        "INSERT INTO service_token_change_evidence \
                             (event_id, operation_id, actor_user_id, action, token_id, \
                              committed_at, prior_version, new_version, revised) \
                         VALUES (?1, ?2, 'fixture', ?3, ?4, \
                                 '2026-10-01T00:00:09Z', ?5, ?6, ?7)",
                        params![
                            uuid::Uuid::new_v4().to_string(),
                            uuid::Uuid::new_v4().to_string(),
                            action,
                            id,
                            prior,
                            new,
                            revised
                        ],
                    )
                    .is_err(),
                "{action} {prior:?} {new:?} {revised}"
            );
        }
    }

    fn create_request(
        scopes: &[&str],
        created_by: &str,
        expires_at: Option<String>,
    ) -> CreateTokenRequest {
        CreateTokenRequest {
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            created_by: created_by.to_owned(),
            expires_at,
        }
    }

    fn timestamp_after(duration: Duration) -> String {
        (OffsetDateTime::now_utc() + duration)
            .format(&Rfc3339)
            .expect("timestamp should format")
    }

    fn token_hashes(path: &PathBuf) -> Vec<String> {
        let connection = Connection::open(path).expect("test database should open");
        let mut statement = connection
            .prepare("SELECT token_hash FROM service_tokens ORDER BY id")
            .expect("hash query should prepare");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("hash query should run")
            .collect::<Result<Vec<_>, _>>()
            .expect("hash rows should load")
    }

    fn set_created_at(path: &PathBuf, token_id: &str, created_at: &str) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute(
                "UPDATE service_tokens SET created_at = ?1 WHERE id = ?2",
                (created_at, token_id),
            )
            .expect("created_at should update");
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-service-tokens-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            ));

            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = fs::remove_file(path);
            }
        }
    }
}
