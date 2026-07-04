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
"#;

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

    fn revoke(&self, id: &str) -> Result<Option<TokenRecord>, TokenStoreError>;

    fn rotate(&self, id: &str) -> Result<Option<CreatedToken>, TokenStoreError>;

    fn verify(&self, plaintext_token: &str) -> Result<TokenVerification, TokenStoreError>;

    fn touch_last_used(&self, id: &str) -> Result<Option<TokenRecord>, TokenStoreError>;
}

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

    fn revoke(&self, id: &str) -> Result<Option<TokenRecord>, TokenStoreError> {
        let revoked_at = utc_timestamp_rfc3339()?;
        let connection = self.connection_guard();
        let Some(record) = load_record_by_id(&connection, &self.path, id)? else {
            return Ok(None);
        };
        if record.revoked_at.is_some() {
            return Ok(Some(record));
        }

        connection
            .execute(
                "UPDATE service_tokens SET revoked_at = ?1 WHERE id = ?2",
                params![revoked_at.as_str(), id],
            )
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        load_record_by_id(&connection, &self.path, id)
    }

    fn rotate(&self, id: &str) -> Result<Option<CreatedToken>, TokenStoreError> {
        let connection = self.connection_guard();
        let Some(record) = load_record_by_id(&connection, &self.path, id)? else {
            return Ok(None);
        };
        if record.revoked_at.is_some() {
            return Err(TokenStoreError::RevokedToken { id: id.to_owned() });
        }

        let plaintext_token = generate_plaintext_token()?;
        let token_hash = hash_token(&plaintext_token);
        let token_prefix = display_prefix(&plaintext_token);

        connection
            .execute(
                r#"
                UPDATE service_tokens
                SET token_hash = ?1,
                    token_prefix = ?2
                WHERE id = ?3
                "#,
                params![token_hash.as_str(), token_prefix.as_str(), id],
            )
            .map_err(|source| TokenStoreError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        let record = load_record_by_id(&connection, &self.path, id)?
            .expect("rotated token should still exist");
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
        }
    }
}

impl Error for TokenStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Sqlite { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::TimeFormat(source) => Some(source),
            Self::TimeParse { source, .. } => Some(source),
            Self::InvalidCursor { .. } | Self::RevokedToken { .. } => None,
            Self::Random(source) => Some(source),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TokenCursor {
    created_at: String,
    id: String,
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

fn generate_plaintext_token() -> Result<String, TokenStoreError> {
    let mut bytes = [0_u8; TOKEN_RANDOM_BYTES];
    getrandom::fill(&mut bytes).map_err(TokenStoreError::Random)?;
    Ok(format!("{TOKEN_MARKER}{}", hex::encode(bytes)))
}

fn hash_token(plaintext_token: &str) -> String {
    let digest = Sha256::digest(plaintext_token.as_bytes());
    hex::encode(digest)
}

fn display_prefix(plaintext_token: &str) -> String {
    let suffix = plaintext_token
        .strip_prefix(TOKEN_MARKER)
        .unwrap_or(plaintext_token);
    let visible_suffix = suffix
        .chars()
        .take(TOKEN_DISPLAY_PREFIX_HEX_CHARS)
        .collect::<String>();
    format!("{TOKEN_MARKER}{visible_suffix}")
}

fn new_token_id() -> String {
    format!("token_{}", uuid::Uuid::new_v4())
}

fn validate_optional_timestamp(
    value: Option<&str>,
    context: &'static str,
) -> Result<(), TokenStoreError> {
    if let Some(value) = value {
        parse_rfc3339(value, context)?;
    }

    Ok(())
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

fn encode_cursor<T: Serialize>(cursor: &T) -> Result<String, TokenStoreError> {
    let json = serde_json::to_vec(cursor).map_err(|source| TokenStoreError::Json {
        context: "cursor",
        source,
    })?;
    Ok(hex::encode(json))
}

fn decode_cursor<T: DeserializeOwned>(
    parameter: &'static str,
    value: &str,
) -> Result<T, TokenStoreError> {
    let bytes = hex::decode(value).map_err(|_| TokenStoreError::InvalidCursor { parameter })?;
    serde_json::from_slice(&bytes).map_err(|_| TokenStoreError::InvalidCursor { parameter })
}

fn query_limit(limit: usize) -> i64 {
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
            .revoke(&revoked.record.id)
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
            .revoke(&created.record.id)
            .expect("first revoke should succeed")
            .expect("token should exist");
        let first_revoked_at = first.revoked_at.clone().expect("token should be revoked");
        let second = store
            .revoke(&created.record.id)
            .expect("second revoke should succeed")
            .expect("token should still exist");

        assert_eq!(
            second.revoked_at.as_deref(),
            Some(first_revoked_at.as_str())
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
            .rotate(&created.record.id)
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
