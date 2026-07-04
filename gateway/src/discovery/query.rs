use std::{error::Error, fmt, path::PathBuf};

use rusqlite::Connection;
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ObservedEndpoint {
    pub method: String,
    pub endpoint_template: String,
}

#[derive(Clone, Debug)]
pub struct DiscoveryQueryStore {
    path: PathBuf,
}

#[derive(Debug)]
pub enum DiscoveryQueryError {
    Open {
        path: PathBuf,
        source: rusqlite::Error,
    },
    Query {
        path: PathBuf,
        source: rusqlite::Error,
    },
}

impl DiscoveryQueryStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, DiscoveryQueryError> {
        Ok(Self { path: path.into() })
    }

    pub fn observed_endpoints(&self) -> Result<Vec<ObservedEndpoint>, DiscoveryQueryError> {
        let connection =
            Connection::open(&self.path).map_err(|source| DiscoveryQueryError::Open {
                path: self.path.clone(),
                source,
            })?;
        let mut statement = match connection.prepare(
            r#"
            SELECT method, endpoint_template
            FROM discovery_endpoint_aggregates
            ORDER BY method, endpoint_template
            "#,
        ) {
            Ok(statement) => statement,
            Err(source) if is_missing_discovery_table(&source) => return Ok(Vec::new()),
            Err(source) => {
                return Err(DiscoveryQueryError::Query {
                    path: self.path.clone(),
                    source,
                })
            }
        };

        let rows = statement
            .query_map([], |row| {
                Ok(ObservedEndpoint {
                    method: row.get(0)?,
                    endpoint_template: row.get(1)?,
                })
            })
            .map_err(|source| DiscoveryQueryError::Query {
                path: self.path.clone(),
                source,
            })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|source| DiscoveryQueryError::Query {
                path: self.path.clone(),
                source,
            })
    }
}

impl fmt::Display for DiscoveryQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open { path, source } => write!(
                formatter,
                "failed to open SQLite discovery query store at {}: {source}",
                path.display()
            ),
            Self::Query { path, source } => write!(
                formatter,
                "failed to query SQLite discovery aggregates at {}: {source}",
                path.display()
            ),
        }
    }
}

impl Error for DiscoveryQueryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Open { source, .. } | Self::Query { source, .. } => Some(source),
        }
    }
}

fn is_missing_discovery_table(error: &rusqlite::Error) -> bool {
    match error {
        rusqlite::Error::SqliteFailure(_, Some(message)) => {
            message.contains("no such table: discovery_endpoint_aggregates")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rusqlite::{params, Connection};

    use super::*;

    #[test]
    fn loads_observed_endpoint_templates_from_discovery_aggregates() {
        let db = TempDb::new("query-observed");
        seed_endpoint(&db.path, "GET", "/users/{id}");
        seed_endpoint(&db.path, "POST", "/users");

        let store = DiscoveryQueryStore::open(&db.path).expect("discovery query store should open");
        let observed = store
            .observed_endpoints()
            .expect("observed endpoints should query");

        assert_eq!(
            observed,
            vec![
                ObservedEndpoint {
                    method: "GET".to_owned(),
                    endpoint_template: "/users/{id}".to_owned(),
                },
                ObservedEndpoint {
                    method: "POST".to_owned(),
                    endpoint_template: "/users".to_owned(),
                },
            ]
        );
    }

    fn seed_endpoint(path: &PathBuf, method: &str, endpoint_template: &str) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS discovery_endpoint_aggregates (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    call_count INTEGER NOT NULL,
                    latency_count INTEGER NOT NULL,
                    latency_p50_ms INTEGER NOT NULL,
                    latency_p95_ms INTEGER NOT NULL,
                    latency_p99_ms INTEGER NOT NULL,
                    latency_samples_json TEXT NOT NULL,
                    distinct_principal_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template)
                );
                "#,
            )
            .expect("discovery schema should create");
        connection
            .execute(
                r#"
                INSERT INTO discovery_endpoint_aggregates (
                    method,
                    endpoint_template,
                    first_seen,
                    last_seen,
                    call_count,
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', 1, 1, 1, 1, 1, '[]', 0, '2024-06-01T12:00:00Z')
                "#,
                params![method, endpoint_template],
            )
            .expect("endpoint aggregate should insert");
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-discovery-query-{test_name}-{}.sqlite",
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
