//! Policy-history repository contract and its standalone SQLite adapter.

use std::sync::Arc;

#[cfg(feature = "postgres")]
use std::fmt;

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

/// The active policy document as the control plane's authority sees it.
///
/// `security_revision` is the revision at which `version` was activated: the
/// number a replica's compiled snapshot must be keyed by to serve under this
/// document (issue #241's strict request-revision rule).
#[cfg(feature = "postgres")]
#[derive(Clone, Debug)]
pub struct ActivePolicy {
    pub policy: Policy,
    /// The immutable `policy_documents` version this document is stored as.
    /// Read by tests and (in later #241 PRs) cluster status; production
    /// wiring keys on the revision and the document itself.
    #[allow(dead_code)]
    pub version: i64,
    pub etag: String,
    pub security_revision: i64,
}

/// What a commit caller believes about the current active document. The
/// transaction re-verifies the belief against the authority; a mismatch is
/// [`PolicyCommitError::PreconditionFailed`] and nothing commits.
#[cfg(feature = "postgres")]
#[derive(Clone, Debug)]
pub enum PolicyCommitPrecondition {
    /// The caller read `etag` as the active document's ETag (an HTTP
    /// `If-Match` value). Exactly one of the writers sharing an ETag wins.
    Expected { etag: String },
    /// The caller believes no active document exists and may install the
    /// initial one. A deployment is initialized exactly once.
    #[allow(dead_code)] // Constructed by the PR 7 store tests and by the
    // standalone-to-cluster import workflow of #241 PR 15; no production
    // endpoint installs an initial document in this PR.
    Initialize,
}

/// A control-plane mutation request: everything the transaction needs to
/// write the new immutable version, advance the active pointer and the
/// security revision, append history, emit the durable outbox record, and
/// record the change's evidence (which operation, by whom).
#[cfg(feature = "postgres")]
#[derive(Clone, Debug)]
pub struct PolicyCommitRequest<'a> {
    pub precondition: PolicyCommitPrecondition,
    pub candidate: &'a Policy,
    pub change: super::DocumentChange,
    pub diff_summary: &'a Value,
}

/// Why a control-plane commit did not happen.
#[cfg(feature = "postgres")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyCommitError {
    /// The expected state no longer (or never) matched: another writer
    /// won the compare-and-swap. The caller surfaces `412`; nothing
    /// committed.
    PreconditionFailed,
    /// The authority could not be consulted or rejected the mutation for
    /// a store-level reason. Nothing committed.
    Store(RepositoryError),
    /// A tool name in the committed document is already published by
    /// another lane at the authority. The caller surfaces `409`; nothing
    /// committed.
    ToolNameTaken {
        tool_name: String,
        lane: String,
        owner_id: String,
    },
    /// The caller's operation ID (`Idempotency-Key`, issue #425) is already
    /// reserved for another action or another binding of this one. The
    /// caller surfaces `409`; nothing committed.
    CallerOperationConflict,
}

#[cfg(feature = "postgres")]
impl fmt::Display for PolicyCommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PreconditionFailed => formatter.write_str(
                "the active policy changed before the mutation committed; nothing was written",
            ),
            Self::Store(error) => write!(formatter, "policy commit failed: {error}"),
            Self::ToolNameTaken {
                tool_name,
                lane,
                owner_id,
            } => write!(
                formatter,
                "tool name '{tool_name}' is already published by the {lane} lane ({owner_id}); nothing was written"
            ),
            Self::CallerOperationConflict => formatter.write_str(
                "the caller operation ID is bound to a different request; nothing was written",
            ),
        }
    }
}

#[cfg(feature = "postgres")]
impl std::error::Error for PolicyCommitError {}

/// Contract for the authoritative, versioned policy control plane
/// (issue #241, PR 7; `docs/architecture/ha-state-model.md` section 2).
///
/// One `commit` is one transaction: lock/read the expected active revision,
/// reject a stale precondition, write the new immutable version, advance the
/// active pointer and the monotonic security revision, append the history
/// row, write the security outbox record, and commit once. Two writers with
/// the same expected state produce exactly one winner. History rows and the
/// outbox cannot fail in isolation: if any step fails, nothing commits.
#[cfg(feature = "postgres")]
#[async_trait]
pub trait PolicyControlPlane: PolicyHistory {
    /// The authoritative active document, or `None` on a deployment whose
    /// control plane has never been initialized.
    async fn active(&self) -> Result<Option<ActivePolicy>, RepositoryError>;

    /// Commit a mutation under a compare-and-swap precondition and, when
    /// `caller` is given, under the caller's operation ID (issue #425): the
    /// key is reserved with its binding digest in the commit's transaction
    /// and the evidence row carries it as `operation_id`. An exact retry of
    /// a committed key returns its receipt and changes nothing; a key bound
    /// to anything else is [`PolicyCommitError::CallerOperationConflict`].
    async fn commit_with_operation(
        &self,
        request: PolicyCommitRequest<'_>,
        caller: Option<&crate::authority_events::caller_operation::CallerOperation>,
    ) -> Result<
        crate::authority_events::caller_operation::CallerOutcome<ActivePolicy>,
        PolicyCommitError,
    >;

    /// [`Self::commit_with_operation`] without a caller key.
    async fn commit(
        &self,
        request: PolicyCommitRequest<'_>,
    ) -> Result<ActivePolicy, PolicyCommitError> {
        unkeyed_commit(self.commit_with_operation(request, None).await)
    }

    /// What the reservation table says about `caller`'s key: the read-only
    /// pre-check a handler asks before any work outside the transaction.
    /// Advisory; the commit's own transaction decides again.
    #[cfg_attr(not(test), allow(dead_code))] // Asked by the P9 handlers' pre-check.
    async fn caller_operation_state(
        &self,
        caller: &crate::authority_events::caller_operation::CallerOperation,
    ) -> Result<crate::authority_events::caller_operation::CallerKeyState, RepositoryError>;

    /// The receipt of the policy change `caller`'s key committed, read from
    /// its evidence row, or `None` when there is none.
    #[cfg_attr(not(test), allow(dead_code))] // Asked by the P9 handlers' pre-check.
    async fn caller_operation_receipt(
        &self,
        caller: &crate::authority_events::caller_operation::CallerOperation,
    ) -> Result<Option<crate::authority_events::caller_operation::OperationReceipt>, RepositoryError>;
}

/// The committed value of an unkeyed commit. A commit without a key cannot
/// be answered from a receipt; if one ever were, it fails closed rather than
/// report a change this request did not make.
#[cfg(feature = "postgres")]
pub(crate) fn unkeyed_commit<T, E: From<PolicyCommitError>>(
    outcome: Result<crate::authority_events::caller_operation::CallerOutcome<T>, E>,
) -> Result<T, E> {
    use crate::authority_events::caller_operation::CallerOutcome;
    match outcome? {
        CallerOutcome::Committed(value) => Ok(value),
        CallerOutcome::Replayed(_) => Err(E::from(PolicyCommitError::Store(RepositoryError::new(
            RepositoryErrorKind::Internal,
            "unkeyed_document_commit",
        )))),
    }
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
