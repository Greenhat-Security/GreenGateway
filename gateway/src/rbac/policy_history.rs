use std::{
    error::Error,
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard},
};

use rusqlite::{params, types::Value as SqlValue, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::Value;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::metrics::LOCK_POISON_RECOVERIES_TOTAL;

use super::policy::{Policy, PolicyError};

const CREATE_POLICY_HISTORY_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS policy_versions (
    version INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    diff_summary_json TEXT NOT NULL,
    policy_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_policy_versions_desc
ON policy_versions(version DESC);
"#;

#[derive(Clone)]
pub struct PolicyHistoryStore {
    path: PathBuf,
    connection: Arc<Mutex<Connection>>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PolicyVersion {
    pub version: i64,
    #[serde(rename = "actor")]
    pub actor_user_id: String,
    pub created_at: String,
    pub diff_summary: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyHistoryPage {
    pub versions: Vec<PolicyVersion>,
    pub next_cursor: Option<String>,
}

pub struct PolicyHistoryListFilters {
    pub limit: usize,
    pub cursor: Option<String>,
    pub include_policy: bool,
}

#[derive(Debug)]
pub enum PolicyHistoryError {
    Sqlite {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Json {
        context: &'static str,
        source: serde_json::Error,
    },
    Policy {
        context: &'static str,
        source: PolicyError,
    },
    Time(time::error::Format),
    InvalidCursor {
        parameter: &'static str,
    },
}

impl PolicyHistoryStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PolicyHistoryError> {
        let path = path.as_ref().to_path_buf();
        let connection = Connection::open(&path).map_err(|source| PolicyHistoryError::Sqlite {
            path: path.clone(),
            source,
        })?;
        configure_connection(&connection).map_err(|source| PolicyHistoryError::Sqlite {
            path: path.clone(),
            source,
        })?;

        Ok(Self {
            path,
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn append_version(
        &self,
        actor_user_id: &str,
        diff_summary: &Value,
        policy: &Policy,
    ) -> Result<PolicyVersion, PolicyHistoryError> {
        let created_at = utc_timestamp_rfc3339()?;
        let diff_summary_json =
            serde_json::to_string(diff_summary).map_err(|source| PolicyHistoryError::Json {
                context: "diff summary",
                source,
            })?;
        let policy_json =
            serde_json::to_string(policy).map_err(|source| PolicyHistoryError::Json {
                context: "policy snapshot",
                source,
            })?;
        let connection = self.connection_guard();
        connection
            .execute(
                r#"
                INSERT INTO policy_versions (
                    actor_user_id,
                    created_at,
                    diff_summary_json,
                    policy_json
                ) VALUES (?1, ?2, ?3, ?4)
                "#,
                params![
                    actor_user_id,
                    created_at.as_str(),
                    diff_summary_json.as_str(),
                    policy_json.as_str(),
                ],
            )
            .map_err(|source| PolicyHistoryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;
        let version = connection.last_insert_rowid();

        Ok(PolicyVersion {
            version,
            actor_user_id: actor_user_id.to_owned(),
            created_at,
            diff_summary: diff_summary.clone(),
            policy: Some(policy.clone()),
        })
    }

    pub fn list_versions(
        &self,
        filters: &PolicyHistoryListFilters,
    ) -> Result<PolicyHistoryPage, PolicyHistoryError> {
        let cursor = filters
            .cursor
            .as_deref()
            .map(parse_version_cursor)
            .transpose()?;
        let mut sql = String::from(
            r#"
            SELECT
                version,
                actor_user_id,
                created_at,
                diff_summary_json,
                policy_json
            FROM policy_versions
            "#,
        );
        let mut params = Vec::new();
        if let Some(cursor) = cursor {
            sql.push_str(" WHERE version < ?");
            params.push(SqlValue::Integer(cursor));
        }
        sql.push_str(" ORDER BY version DESC LIMIT ?");
        params.push(SqlValue::Integer(query_limit(filters.limit)));

        let connection = self.connection_guard();
        let mut statement =
            connection
                .prepare(&sql)
                .map_err(|source| PolicyHistoryError::Sqlite {
                    path: self.path.clone(),
                    source,
                })?;
        let rows = statement
            .query_map(
                rusqlite::params_from_iter(params.iter()),
                RawPolicyVersion::from_row,
            )
            .map_err(|source| PolicyHistoryError::Sqlite {
                path: self.path.clone(),
                source,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| PolicyHistoryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        let mut rows = rows;
        let has_more = rows.len() > filters.limit;
        if has_more {
            rows.truncate(filters.limit);
        }

        let next_cursor = if has_more {
            rows.last().map(|row| row.version.to_string())
        } else {
            None
        };
        let versions = rows
            .into_iter()
            .map(|row| row.into_version(filters.include_policy))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(PolicyHistoryPage {
            versions,
            next_cursor,
        })
    }

    pub fn get_version(&self, version: i64) -> Result<Option<PolicyVersion>, PolicyHistoryError> {
        let connection = self.connection_guard();
        let raw = connection
            .query_row(
                r#"
                SELECT
                    version,
                    actor_user_id,
                    created_at,
                    diff_summary_json,
                    policy_json
                FROM policy_versions
                WHERE version = ?1
                "#,
                params![version],
                RawPolicyVersion::from_row,
            )
            .optional()
            .map_err(|source| PolicyHistoryError::Sqlite {
                path: self.path.clone(),
                source,
            })?;

        raw.map(|row| row.into_version(true)).transpose()
    }

    fn connection_guard(&self) -> MutexGuard<'_, Connection> {
        match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                ::metrics::counter!(
                    LOCK_POISON_RECOVERIES_TOTAL,
                    "component" => "policy_history",
                    "lock" => "connection"
                )
                .increment(1);
                tracing::error!(
                    path = %self.path.display(),
                    "SQLite policy history connection lock poisoned; recovering"
                );
                poisoned.into_inner()
            }
        }
    }
}

impl fmt::Display for PolicyHistoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite { path, source } => {
                write!(
                    formatter,
                    "failed to access policy history at {}: {source}",
                    path.display()
                )
            }
            Self::Json { context, source } => {
                write!(
                    formatter,
                    "failed to encode or decode policy history {context}: {source}"
                )
            }
            Self::Policy { context, source } => {
                write!(
                    formatter,
                    "failed to validate policy history {context}: {source}"
                )
            }
            Self::Time(source) => write!(
                formatter,
                "failed to format policy history timestamp: {source}"
            ),
            Self::InvalidCursor { parameter } => {
                write!(formatter, "invalid policy history cursor: {parameter}")
            }
        }
    }
}

impl Error for PolicyHistoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Sqlite { source, .. } => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Policy { source, .. } => Some(source),
            Self::Time(source) => Some(source),
            Self::InvalidCursor { .. } => None,
        }
    }
}

struct RawPolicyVersion {
    version: i64,
    actor_user_id: String,
    created_at: String,
    diff_summary_json: String,
    policy_json: String,
}

impl RawPolicyVersion {
    fn from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            version: row.get(0)?,
            actor_user_id: row.get(1)?,
            created_at: row.get(2)?,
            diff_summary_json: row.get(3)?,
            policy_json: row.get(4)?,
        })
    }

    fn into_version(self, include_policy: bool) -> Result<PolicyVersion, PolicyHistoryError> {
        let diff_summary =
            serde_json::from_str::<Value>(&self.diff_summary_json).map_err(|source| {
                PolicyHistoryError::Json {
                    context: "diff summary",
                    source,
                }
            })?;
        let policy = if include_policy {
            let value = serde_json::from_str::<Value>(&self.policy_json).map_err(|source| {
                PolicyHistoryError::Json {
                    context: "policy snapshot",
                    source,
                }
            })?;
            Some(Policy::validate_json_value(value).map_err(|source| {
                PolicyHistoryError::Policy {
                    context: "policy snapshot",
                    source,
                }
            })?)
        } else {
            None
        };

        Ok(PolicyVersion {
            version: self.version,
            actor_user_id: self.actor_user_id,
            created_at: self.created_at,
            diff_summary,
            policy,
        })
    }
}

pub fn configure_connection(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(CREATE_POLICY_HISTORY_SCHEMA_SQL)
}

fn parse_version_cursor(value: &str) -> Result<i64, PolicyHistoryError> {
    match value.parse::<i64>() {
        Ok(version) if version > 0 => Ok(version),
        _ => Err(PolicyHistoryError::InvalidCursor {
            parameter: "cursor",
        }),
    }
}

fn query_limit(limit: usize) -> i64 {
    limit.saturating_add(1).min(i64::MAX as usize) as i64
}

fn utc_timestamp_rfc3339() -> Result<String, PolicyHistoryError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(PolicyHistoryError::Time)
}
