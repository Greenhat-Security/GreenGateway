//! Audit event/query repository contract and its standalone SQLite adapter.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use async_trait::async_trait;

use crate::audit::{
    query::{
        AuditQueryError, AuditQueryFilters, AuditQueryPage, AuditQueryStore, EndpointAuditActivity,
        EndpointAuditFilters, ShadowRuleWouldDenySummarySet,
    },
    sqlite_sink, AuditEvent,
};
use crate::metrics::LOCK_POISON_RECOVERIES_TOTAL;

use super::{
    classify_rusqlite, log_classified, run_blocking, RepositoryError, RepositoryErrorKind,
};

/// Contract for the durable audit event log.
///
/// Insertions are idempotent by `event_id`: an ambiguous retry is
/// at-least-once on the caller side and exactly-once in storage. Queries
/// page newest-first with a keyset cursor (`before_id` carries the last
/// seen row id), preserving the filters and ordering the admin audit API
/// exposes today.
#[async_trait]
pub trait AuditEventStore: Send + Sync {
    /// Store a batch of events in one transaction. Re-inserting an
    /// `event_id` that already exists must leave exactly one stored row and
    /// succeed.
    #[allow(dead_code)] // Production data-plane ingest stays on the sink's background flusher;
                        // this method is the backend-neutral write contract the PostgreSQL
                        // implementations (PR 5) and the import workflow satisfy, and the
                        // contract tests exercise it.
    async fn insert_events(&self, events: &[AuditEvent]) -> Result<(), RepositoryError>;

    /// Query events newest-first, keyset-paginated through
    /// `AuditQueryFilters::before_id`.
    async fn query_events(
        &self,
        filters: &AuditQueryFilters,
    ) -> Result<AuditQueryPage, RepositoryError>;
}

/// Standalone SQLite adapter for the audit event store.
///
/// Reads go through the existing [`AuditQueryStore`]. Writes use the exact
/// schema, pragmas, and insert statement the `SqliteSink` flusher uses, so
/// contract behavior and production on-disk state stay identical. This
/// adapter's write handle is a second connection to the same database; the
/// production emit path remains the sink's background flusher, unchanged.
pub struct SqliteAuditEventStore {
    query: Arc<AuditQueryStore>,
    write: Arc<Mutex<rusqlite::Connection>>,
}

/// The sink's flusher owns the audit database's only production write
/// connection and configures no busy timeout. This adapter's contract-level
/// write connection is a second writer, so it bounds its own wait on the
/// flusher's commits instead of failing fast with `SQLITE_BUSY`.
const ADAPTER_WRITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

impl SqliteAuditEventStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RepositoryError> {
        let path = path.into();
        let operation = "audit_event_store_open";
        let query = AuditQueryStore::open(path.clone()).map_err(|error| {
            let classified = match &error {
                AuditQueryError::Open { source, .. } | AuditQueryError::Sqlite { source, .. } => {
                    classify_rusqlite(operation, source)
                }
                _ => RepositoryError::new(RepositoryErrorKind::Internal, operation),
            };
            log_classified(operation, &error, classified)
        })?;

        let write = rusqlite::Connection::open(&path).map_err(rusqlite_open_error(operation))?;
        write
            .busy_timeout(ADAPTER_WRITE_BUSY_TIMEOUT)
            .map_err(rusqlite_open_error(operation))?;
        sqlite_sink::configure_connection(&write).map_err(|source| {
            log_classified(operation, &source, classify_rusqlite(operation, &source))
        })?;

        Ok(Self {
            query: Arc::new(query),
            write: Arc::new(Mutex::new(write)),
        })
    }

    /// The concrete SQLite query store backing this adapter.
    ///
    /// Transitional: call sites that stream request observations through a
    /// synchronous visitor (`scan_request_observations`) still use it
    /// directly, wrapped in `spawn_blocking` by their handlers. The backend-
    /// neutral replacement lands with the durable-cursor query contracts of
    /// PRs 5-6.
    pub fn sqlite_query_store(&self) -> &Arc<AuditQueryStore> {
        &self.query
    }

    /// Query per-endpoint activity buckets and recent events.
    ///
    /// Transitional SQLite-specific surface; it moves onto the trait when
    /// the PostgreSQL query store lands (PRs 5-6).
    pub async fn query_endpoint_activity(
        &self,
        filters: &EndpointAuditFilters,
    ) -> Result<EndpointAuditActivity, RepositoryError> {
        let query = Arc::clone(&self.query);
        let filters = filters.clone();
        run_blocking(move || {
            query
                .query_endpoint_activity(&filters)
                .map_err(|error| map_audit_query_error("audit_endpoint_activity", error))
        })
        .await
    }

    /// Count anonymous request observations in a time window.
    ///
    /// Transitional SQLite-specific surface; it moves onto the trait when
    /// the PostgreSQL query store lands (PRs 5-6).
    pub async fn anonymous_request_count(
        &self,
        from: Option<String>,
        to: Option<String>,
    ) -> Result<u64, RepositoryError> {
        let query = Arc::clone(&self.query);
        run_blocking(move || {
            query
                .anonymous_request_count(from.as_deref(), to.as_deref())
                .map_err(|error| map_audit_query_error("audit_anonymous_request_count", error))
        })
        .await
    }

    /// Aggregate matched-rule hit counts.
    ///
    /// Transitional SQLite-specific surface; it moves onto the trait when
    /// the PostgreSQL query store lands (PRs 5-6).
    pub async fn rule_hit_counts(&self) -> Result<HashMap<String, u64>, RepositoryError> {
        let query = Arc::clone(&self.query);
        run_blocking(move || {
            query
                .rule_hit_counts()
                .map_err(|error| map_audit_query_error("audit_rule_hit_counts", error))
        })
        .await
    }

    /// Summarize which traffic a shadow rule would have denied.
    ///
    /// Transitional SQLite-specific surface; it moves onto the trait when
    /// the PostgreSQL query store lands (PRs 5-6).
    pub async fn shadow_rule_would_deny_summaries(
        &self,
        rule_ids: &[String],
    ) -> Result<ShadowRuleWouldDenySummarySet, RepositoryError> {
        let query = Arc::clone(&self.query);
        let rule_ids = rule_ids.to_vec();
        run_blocking(move || {
            query
                .shadow_rule_would_deny_summaries(&rule_ids)
                .map_err(|error| map_audit_query_error("audit_shadow_review", error))
        })
        .await
    }
}

#[async_trait]
impl AuditEventStore for SqliteAuditEventStore {
    async fn insert_events(&self, events: &[AuditEvent]) -> Result<(), RepositoryError> {
        let write = Arc::clone(&self.write);
        let events = events.to_vec();
        run_blocking(move || {
            let mut connection = write_guard(&write);
            sqlite_sink::write_events(&mut connection, &events).map_err(|error| {
                let operation = "audit_event_insert";
                let classified = match &error {
                    sqlite_sink::SqliteFlushError::Sqlite(source) => {
                        classify_rusqlite(operation, source)
                    }
                    sqlite_sink::SqliteFlushError::Json(_) => {
                        RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
                    }
                };
                log_classified(operation, &error, classified)
            })
        })
        .await
    }

    async fn query_events(
        &self,
        filters: &AuditQueryFilters,
    ) -> Result<AuditQueryPage, RepositoryError> {
        let query = Arc::clone(&self.query);
        let filters = filters.clone();
        run_blocking(move || {
            query
                .query(&filters)
                .map_err(|error| map_audit_query_error("audit_event_query", error))
        })
        .await
    }
}

fn write_guard(write: &Arc<Mutex<rusqlite::Connection>>) -> MutexGuard<'_, rusqlite::Connection> {
    match write.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            ::metrics::counter!(
                LOCK_POISON_RECOVERIES_TOTAL,
                "component" => "storage",
                "lock" => "audit_write_connection"
            )
            .increment(1);
            tracing::error!("SQLite audit write connection lock poisoned; recovering");
            poisoned.into_inner()
        }
    }
}

fn map_audit_query_error(operation: &'static str, error: AuditQueryError) -> RepositoryError {
    let classified = match &error {
        AuditQueryError::Open { source, .. } | AuditQueryError::Sqlite { source, .. } => {
            classify_rusqlite(operation, source)
        }
        AuditQueryError::ActorJson { .. } | AuditQueryError::PayloadJson { .. } => {
            RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
        }
    };
    log_classified(operation, &error, classified)
}

fn rusqlite_open_error(operation: &'static str) -> impl Fn(rusqlite::Error) -> RepositoryError {
    move |source| log_classified(operation, &source, classify_rusqlite(operation, &source))
}
