//! Principal-directory repository contract and its standalone SQLite adapter.

use async_trait::async_trait;

use crate::auth::principal_directory::{
    PrincipalDirectory, PrincipalDirectoryKey, PrincipalDirectoryListFilters,
    PrincipalDirectoryListPage, PrincipalDirectoryQueryError, PrincipalDirectoryRecord,
    PrincipalObservation,
};

use super::{
    classify_rusqlite, log_classified, run_blocking, RepositoryError, RepositoryErrorKind,
};

/// Contract for the principal directory: the identity-indexed projection of
/// authenticated traffic.
///
/// Upserts are keyed by the full identity triple (subject, issuer, auth
/// method): `request_count` accumulates, `first_seen` keeps its minimum,
/// `last_seen` keeps its maximum, and mutable profile fields (email, org)
/// reflect the most recent observation. Production ingestion remains
/// asynchronous and batched; `upsert_principals` exists so the merge
/// semantics are testable against any backend and reusable for import.
#[async_trait]
pub trait PrincipalDirectoryStore: Send + Sync {
    #[allow(dead_code)] // Production ingestion stays on the queued observe/flush path;
                        // this method pins the merge semantics as part of the contract for the
                        // PostgreSQL implementations (PR 11) and the import workflow, and the
                        // contract tests exercise it.
    async fn upsert_principals(
        &self,
        observations: &[PrincipalObservation],
    ) -> Result<(), RepositoryError>;

    async fn list(
        &self,
        filters: &PrincipalDirectoryListFilters,
    ) -> Result<PrincipalDirectoryListPage, RepositoryError>;

    async fn get(
        &self,
        key: &PrincipalDirectoryKey,
    ) -> Result<Option<PrincipalDirectoryRecord>, RepositoryError>;
}

/// The standalone SQLite principal directory satisfies the contract by
/// running each synchronous operation on Tokio's blocking pool. The
/// directory, its schema, its flusher-based ingestion, and its query results
/// are unchanged.
#[async_trait]
impl PrincipalDirectoryStore for PrincipalDirectory {
    async fn upsert_principals(
        &self,
        observations: &[PrincipalObservation],
    ) -> Result<(), RepositoryError> {
        let directory = self.clone();
        let observations = observations.to_vec();
        run_blocking(move || {
            directory
                .record_observations(&observations)
                .map_err(|error| map_directory_error("principal_directory_upsert", error))
        })
        .await
    }

    async fn list(
        &self,
        filters: &PrincipalDirectoryListFilters,
    ) -> Result<PrincipalDirectoryListPage, RepositoryError> {
        let directory = self.clone();
        let filters = filters.clone();
        run_blocking(move || {
            directory
                .list(&filters)
                .map_err(|error| map_directory_error("principal_directory_list", error))
        })
        .await
    }

    async fn get(
        &self,
        key: &PrincipalDirectoryKey,
    ) -> Result<Option<PrincipalDirectoryRecord>, RepositoryError> {
        let directory = self.clone();
        let key = key.clone();
        run_blocking(move || {
            directory
                .get(&key)
                .map_err(|error| map_directory_error("principal_directory_get", error))
        })
        .await
    }
}

fn map_directory_error(
    operation: &'static str,
    error: PrincipalDirectoryQueryError,
) -> RepositoryError {
    let classified = match &error {
        PrincipalDirectoryQueryError::NotConfigured => {
            RepositoryError::new(RepositoryErrorKind::Unavailable, operation)
        }
        PrincipalDirectoryQueryError::InvalidCursor { parameter } => {
            RepositoryError::invalid_parameter(operation, parameter)
        }
        PrincipalDirectoryQueryError::Sqlite { source, .. } => classify_rusqlite(operation, source),
        PrincipalDirectoryQueryError::Json { .. } => {
            RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
        }
    };
    log_classified(operation, &error, classified)
}
