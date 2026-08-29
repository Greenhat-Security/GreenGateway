//! Policy-history repository contract and its standalone SQLite adapter.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::rbac::Policy;

use crate::rbac::policy_history::{
    PolicyHistoryError, PolicyHistoryListFilters, PolicyHistoryPage, PolicyHistoryStore,
    PolicyVersion,
};

use super::{
    classify_rusqlite, log_classified, run_blocking, RepositoryError, RepositoryErrorKind,
};

/// Contract for the append-only policy version history.
///
/// Versions are appended after a policy mutation commits; the history is the
/// rollback source of truth. Listing pages newest-first with a version
/// cursor, and each version's snapshot must validate as the exact policy
/// that was current at append time.
#[async_trait]
pub trait PolicyHistory: Send + Sync {
    async fn append_version(
        &self,
        actor_user_id: &str,
        diff_summary: &Value,
        policy: &Policy,
    ) -> Result<PolicyVersion, RepositoryError>;

    async fn list_versions(
        &self,
        filters: &PolicyHistoryListFilters,
    ) -> Result<PolicyHistoryPage, RepositoryError>;

    async fn get_version(&self, version: i64) -> Result<Option<PolicyVersion>, RepositoryError>;
}

/// The standalone SQLite history store satisfies the contract by running
/// each synchronous operation on Tokio's blocking pool. The store itself,
/// its schema, and its query results are unchanged.
#[async_trait]
impl PolicyHistory for PolicyHistoryStore {
    async fn append_version(
        &self,
        actor_user_id: &str,
        diff_summary: &Value,
        policy: &Policy,
    ) -> Result<PolicyVersion, RepositoryError> {
        let store = Arc::new(self.clone());
        let actor_user_id = actor_user_id.to_owned();
        let diff_summary = diff_summary.clone();
        let policy = policy.clone();
        run_blocking(move || {
            store
                .append_version(&actor_user_id, &diff_summary, &policy)
                .map_err(|error| map_policy_history_error("policy_history_append", error))
        })
        .await
    }

    async fn list_versions(
        &self,
        filters: &PolicyHistoryListFilters,
    ) -> Result<PolicyHistoryPage, RepositoryError> {
        let store = Arc::new(self.clone());
        let filters = filters.clone();
        run_blocking(move || {
            store
                .list_versions(&filters)
                .map_err(|error| map_policy_history_error("policy_history_list", error))
        })
        .await
    }

    async fn get_version(&self, version: i64) -> Result<Option<PolicyVersion>, RepositoryError> {
        let store = Arc::new(self.clone());
        run_blocking(move || {
            store
                .get_version(version)
                .map_err(|error| map_policy_history_error("policy_history_get", error))
        })
        .await
    }
}

fn map_policy_history_error(operation: &'static str, error: PolicyHistoryError) -> RepositoryError {
    let classified = match &error {
        PolicyHistoryError::Sqlite { source, .. } => classify_rusqlite(operation, source),
        PolicyHistoryError::Json { .. }
        | PolicyHistoryError::Policy { .. }
        | PolicyHistoryError::Time(_) => {
            RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
        }
        PolicyHistoryError::InvalidCursor { parameter } => {
            RepositoryError::invalid_parameter(operation, parameter)
        }
    };
    log_classified(operation, &error, classified)
}
