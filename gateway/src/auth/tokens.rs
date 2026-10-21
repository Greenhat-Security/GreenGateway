#![allow(dead_code)] // Service-token storage is wired into admin APIs and validators in issue #39 PR2.

use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::metrics::LOCK_POISON_RECOVERIES_TOTAL;

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

-- Change evidence (issue #425): one append-only row per committed rotate
-- or revoke, written in the same transaction as the token change, naming
-- who made it. Created on open like the table above, so a database an
-- older binary wrote gains it on the first open by this one and an older
-- binary simply never reads it. No foreign key, so a removed token row
-- leaves its evidence; identifiers and the actor only, never the
-- plaintext, hash, prefix or scopes. The actor bound is the principal
-- subject bound (MAX_TOKEN_CHANGE_ACTOR_BYTES).
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
"#;

/// The longest actor a rotate or revoke records as its change evidence, in
/// both the SQLite table above and PostgreSQL migration 18. It is exactly
/// the principal subject bound authentication enforces, so evidence never
/// refuses a principal a validator produced; the assertion keeps the SQL
/// bounds and the Rust bound from drifting apart silently.
pub(crate) const MAX_TOKEN_CHANGE_ACTOR_BYTES: usize = 4096;
const _: () =
    assert!(MAX_TOKEN_CHANGE_ACTOR_BYTES == crate::auth::principal::MAX_PRINCIPAL_SUBJECT_BYTES);

/// The closed action vocabulary of service-token change evidence. Values are
/// the proposed authority-event operation codes
/// (`docs/schemas/authority_event.v1.schema.json`); both stores' CHECK
/// constraints refuse anything else.
pub(crate) const TOKEN_CHANGE_ACTION_ROTATE: &str = "service_token.rotate";
pub(crate) const TOKEN_CHANGE_ACTION_REVOKE: &str = "service_token.revoke";

/// An unattributable change has no evidence to record, so a store refuses
/// it before it changes anything rather than committing it anonymously. An
/// authenticated principal always satisfies this; the CHECK constraints
/// are the backstop.
pub(crate) fn is_valid_change_actor(actor_user_id: &str) -> bool {
    !actor_user_id.is_empty() && actor_user_id.len() <= MAX_TOKEN_CHANGE_ACTOR_BYTES
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

pub trait TokenStore: Send + Sync {
    fn create(&self, request: CreateTokenRequest) -> Result<CreatedToken, TokenStoreError>;

    fn list(&self, filters: &TokenListFilters) -> Result<TokenPage, TokenStoreError>;

    fn get_by_id(&self, id: &str) -> Result<Option<TokenRecord>, TokenStoreError>;

    /// Revoke on behalf of `actor_user_id`, who is recorded as the change's
    /// evidence in the same transaction. A repeat revoke changes nothing
    /// and records nothing.
    fn revoke(&self, id: &str, actor_user_id: &str)
        -> Result<Option<TokenRecord>, TokenStoreError>;

    /// Rotate on behalf of `actor_user_id`, who is recorded as the change's
    /// evidence in the same transaction. Rotating a revoked token is a
    /// conflict and records nothing.
    fn rotate(
        &self,
        id: &str,
        actor_user_id: &str,
    ) -> Result<Option<CreatedToken>, TokenStoreError>;

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
    /// A rotate or revoke named no actor, or one longer than
    /// [`MAX_TOKEN_CHANGE_ACTOR_BYTES`]; refused before anything changed.
    InvalidChangeActor,
    /// The change's evidence could not be written, so the change was
    /// rolled back with it.
    ChangeEvidence {
        path: PathBuf,
        source: rusqlite::Error,
    },
}

impl SqliteTokenStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, TokenStoreError> {
        let path = path.as_ref().to_path_buf();
        let connection = Connection::open(&path).map_err(|source| TokenStoreError::Open {
            path: path.clone(),
            source,
        })?;
        configure_connection(&connection).map_err(|source| TokenStoreError::Sqlite {
            path: path.clone(),
            source,
        })?;

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
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
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
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            });
        tokens
    }

    fn sqlite_error(&self, source: rusqlite::Error) -> TokenStoreError {
        TokenStoreError::Sqlite {
            path: self.path.clone(),
            source,
        }
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

impl TokenStore for SqliteTokenStore {
    fn create(&self, request: CreateTokenRequest) -> Result<CreatedToken, TokenStoreError> {
        validate_optional_timestamp(request.expires_at.as_deref(), "expires_at")?;

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

        let connection = self.connection_guard();
        connection
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
                    revoked_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL)
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
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        Ok(CreatedToken {
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
        })
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
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let rows = statement
            .query_map(params_from_iter(params.iter()), RawTokenRecord::from_row)
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

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

    fn revoke(
        &self,
        id: &str,
        actor_user_id: &str,
    ) -> Result<Option<TokenRecord>, TokenStoreError> {
        if !is_valid_change_actor(actor_user_id) {
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
        let Some(record) = load_record_by_id(&transaction, &self.path, id)? else {
            return Ok(None);
        };
        // Idempotent and monotonic: the first revoked_at stands, and a
        // repeat neither rewrites it nor records evidence of a change that
        // did not happen.
        if record.revoked_at.is_some() {
            return Ok(Some(record));
        }

        let changed = transaction
            .execute(
                "UPDATE service_tokens SET revoked_at = ?1 WHERE id = ?2 AND revoked_at IS NULL",
                params![revoked_at.as_str(), id],
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
                action: TOKEN_CHANGE_ACTION_REVOKE,
                token_id: id,
                actor_user_id,
                committed_at: &revoked_at,
            },
        )?;
        let record = load_record_by_id(&transaction, &self.path, id)?;
        transaction
            .commit()
            .map_err(|source| self.sqlite_error(source))?;
        Ok(record)
    }

    fn rotate(
        &self,
        id: &str,
        actor_user_id: &str,
    ) -> Result<Option<CreatedToken>, TokenStoreError> {
        if !is_valid_change_actor(actor_user_id) {
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
        let Some(record) = load_record_by_id(&transaction, &self.path, id)? else {
            return Ok(None);
        };
        if record.revoked_at.is_some() {
            return Err(TokenStoreError::RevokedToken { id: id.to_owned() });
        }

        let changed = transaction
            .execute(
                r#"
                UPDATE service_tokens
                SET token_hash = ?1,
                    token_prefix = ?2
                WHERE id = ?3 AND revoked_at IS NULL
                "#,
                params![token_hash.as_str(), token_prefix.as_str(), id],
            )
            .map_err(|source| self.sqlite_error(source))?;
        if changed != 1 {
            return Err(self.sqlite_error(rusqlite::Error::StatementChangedRows(changed)));
        }
        record_change_evidence(
            &transaction,
            &self.path,
            &ChangeEvidence {
                action: TOKEN_CHANGE_ACTION_ROTATE,
                token_id: id,
                actor_user_id,
                committed_at: &rotated_at,
            },
        )?;
        // The row was read inside this transaction, which holds the write
        // lock, so it cannot be gone; if it somehow is, nothing commits.
        let record = load_record_by_id(&transaction, &self.path, id)?
            .ok_or_else(|| self.sqlite_error(rusqlite::Error::QueryReturnedNoRows))?;
        transaction
            .commit()
            .map_err(|source| self.sqlite_error(source))?;
        Ok(Some(CreatedToken {
            record,
            plaintext_token,
        }))
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
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
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
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

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
            Self::InvalidChangeActor => {
                write!(
                    formatter,
                    "a service-token change actor must be between 1 and {MAX_TOKEN_CHANGE_ACTOR_BYTES} bytes"
                )
            }
            Self::ChangeEvidence { path, source } => {
                write!(
                    formatter,
                    "failed to record service-token change evidence at {}: {source}",
                    path.display()
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
            Self::InvalidCursor { .. } | Self::RevokedToken { .. } | Self::InvalidChangeActor => {
                None
            }
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
    action: &'static str,
    token_id: &'a str,
    actor_user_id: &'a str,
    committed_at: &'a str,
}

/// Append one evidence row inside the caller's transaction. Its event and
/// operation IDs are minted here, once per store call. Any failure is
/// returned for the caller to roll back, so the change it describes never
/// commits without it, and it is reported as an evidence failure rather
/// than as whatever constraint class SQLite gave it: a rotate whose
/// evidence failed is not a revoked-token conflict.
fn record_change_evidence(
    connection: &Connection,
    path: &Path,
    evidence: &ChangeEvidence<'_>,
) -> Result<(), TokenStoreError> {
    let event_id = uuid::Uuid::new_v4().to_string();
    let operation_id = uuid::Uuid::new_v4().to_string();
    connection
        .execute(
            r#"
            INSERT INTO service_token_change_evidence (
                event_id, operation_id, actor_user_id, action, token_id, committed_at
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![
                event_id.as_str(),
                operation_id.as_str(),
                evidence.actor_user_id,
                evidence.action,
                evidence.token_id,
                evidence.committed_at,
            ],
        )
        .map_err(|source| TokenStoreError::ChangeEvidence {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

pub fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(CREATE_SERVICE_TOKEN_SCHEMA_SQL)
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
        .map_err(|source| TokenStoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?
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
        .map_err(|source| TokenStoreError::Sqlite {
            path: path.to_path_buf(),
            source,
        })?
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
            .create(create_request(&["admin"], "creator", None))
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
            .create(create_request(&["reader", "writer"], "creator", None))
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
            .create(create_request(&["reader"], "creator", None))
            .expect("active token should create");
        let revoked = store
            .create(create_request(&["reader"], "creator", None))
            .expect("revoked token should create");
        let expired = store
            .create(create_request(
                &["reader"],
                "creator",
                Some(timestamp_after(Duration::seconds(-60))),
            ))
            .expect("expired token should create");

        assert_eq!(
            store
                .verify("ggw_not-a-real-token")
                .expect("garbage verify should query"),
            TokenVerification::Invalid(TokenVerificationFailure::NotFound)
        );

        store
            .revoke(&revoked.record.id, "revoking-admin")
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
            .create(create_request(&["reader"], "creator", None))
            .expect("token should create");

        let first = store
            .revoke(&created.record.id, "revoking-admin")
            .expect("first revoke should succeed")
            .expect("token should exist");
        let first_revoked_at = first.revoked_at.clone().expect("token should be revoked");
        let second = store
            .revoke(&created.record.id, "revoking-admin")
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
        assert!(CREATE_SERVICE_TOKEN_SCHEMA_SQL
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

    #[test]
    fn rotate_preserves_record_metadata_and_invalidates_old_plaintext() {
        let db = TempDb::new("rotate");
        let store = SqliteTokenStore::open(&db.path).expect("token store should open");
        let expires_at = timestamp_after(Duration::hours(1));
        let created = store
            .create(create_request(
                &["reader", "operator"],
                "creator",
                Some(expires_at.clone()),
            ))
            .expect("token should create");
        let original_hash = token_hashes(&db.path)
            .into_iter()
            .next()
            .expect("hash should exist");

        let rotated = store
            .rotate(&created.record.id, "rotating-admin")
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
            .create(create_request(&["one"], "creator", None))
            .expect("first token should create");
        let second = store
            .create(create_request(&["two"], "creator", None))
            .expect("second token should create");
        let third = store
            .create(create_request(&["three"], "creator", None))
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
            .create(create_request(&["reader"], "creator", None))
            .expect("store should recover after poisoned lock");

        assert!(created.plaintext_token.starts_with("ggw_"));
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
