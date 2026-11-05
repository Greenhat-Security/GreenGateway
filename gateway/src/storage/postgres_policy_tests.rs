//! PostgreSQL stored policy test suite (issue #243).
//!
//! Implements [`PolicyTestSuiteStore`] against migration 28's
//! `policy_test_suite_versions` and `policy_test_suite_active`, so every
//! replica of a cluster reads and replaces one suite. A write is the shared
//! versioned-document transaction ([`postgres_documents::commit_in`]), the one
//! the policy and tools documents commit through: the precondition re-checked
//! under the active pointer's row lock, a new immutable version, the next
//! shared security revision, one `security_outbox` row (`policy_tests`) and
//! one `document_change_evidence` row (`policy_tests.publish`), committed
//! together or not at all.
//!
//! Reads are plain committed reads that re-verify the stored suite against
//! its recorded ETag ([`suite_from_stored`]). No replica compiles or
//! reconciles the suite; a test run reads it here each time.
//!
//! Errors carry a stable operation label only, never SQL text, values or
//! DSN-derived material.

use async_trait::async_trait;
use serde_json::{json, Value};

use crate::auth::Principal;

use super::{
    change_evidence::{DocumentAction, DocumentChange},
    policy_history::PolicyCommitError,
    policy_tests::{
        storable_suite, suite_from_stored, PolicyTestSuiteCommitError, PolicyTestSuitePrecondition,
        PolicyTestSuiteRecord, PolicyTestSuiteStore,
    },
    postgres::{checkout, timed_operation, CheckoutClass},
    postgres_documents::{self, DocumentCommit, DocumentPrecondition, DocumentResource},
    RepositoryError, RepositoryErrorKind,
};

/// The suite's tables and outbox identity in the shared versioned-document
/// core.
pub(crate) const POLICY_TEST_SUITE_RESOURCE: DocumentResource = DocumentResource {
    documents_table: "greengateway.policy_test_suite_versions",
    active_table: "greengateway.policy_test_suite_active",
    resource_type: "policy_tests",
    operation: "policy_tests_commit",
};

const OPERATION_ACTIVE: &str = "policy_tests_active_read";
const OPERATION_COMMIT: &str = "policy_tests_commit";

/// The cluster suite store. Cheap to construct: it borrows the foundation's
/// pool and holds no per-instance state.
pub struct PostgresPolicyTestSuiteStore {
    pool: deadpool_postgres::Pool,
}

impl PostgresPolicyTestSuiteStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }
}

fn store_error(error: RepositoryError) -> PolicyTestSuiteCommitError {
    PolicyTestSuiteCommitError::Store(error)
}

#[async_trait]
impl PolicyTestSuiteStore for PostgresPolicyTestSuiteStore {
    async fn active(&self) -> Result<Option<PolicyTestSuiteRecord>, RepositoryError> {
        let client = checkout(&self.pool, CheckoutClass::SecurityStateRead).await?;
        timed_operation(OPERATION_ACTIVE, async {
            let Some((version, stored_etag, security_revision, _created_at, document_json)) =
                postgres_documents::read_active(&client, POLICY_TEST_SUITE_RESOURCE).await?
            else {
                return Ok(None);
            };
            suite_from_stored(
                &document_json,
                &stored_etag,
                version,
                Some(security_revision),
                OPERATION_ACTIVE,
            )
            .map(Some)
        })
        .await
    }

    async fn commit(
        &self,
        precondition: PolicyTestSuitePrecondition,
        document: &Value,
        actor: &Principal,
    ) -> Result<PolicyTestSuiteRecord, PolicyTestSuiteCommitError> {
        let stored = storable_suite(document, OPERATION_COMMIT).map_err(store_error)?;
        // Counts only: the version row is also the history entry, and its
        // diff summary never carries a case.
        let diff_summary_json = json!({
            "action": match precondition {
                PolicyTestSuitePrecondition::Absent => "policy_tests_created",
                PolicyTestSuitePrecondition::Expected { .. } => "policy_tests_replaced",
            },
            "case_count": stored.suite.cases.len(),
        })
        .to_string();
        let precondition = match precondition {
            PolicyTestSuitePrecondition::Expected { etag } => {
                DocumentPrecondition::Expected { etag }
            }
            PolicyTestSuitePrecondition::Absent => DocumentPrecondition::Initialize,
        };
        let client = checkout(&self.pool, CheckoutClass::ControlPlaneWrite)
            .await
            .map_err(store_error)?;
        postgres_documents::begin(&client, OPERATION_COMMIT)
            .await
            .map_err(store_error)?;
        let outcome = postgres_documents::commit_in(
            &client,
            POLICY_TEST_SUITE_RESOURCE,
            precondition,
            DocumentCommit {
                document_json: &stored.canonical_json,
                document_etag: &stored.etag,
                change: DocumentChange::by_principal(DocumentAction::PolicyTestsPublish, actor),
                diff_summary_json: &diff_summary_json,
                tool_names: None,
            },
        )
        .await;
        let committed = postgres_documents::end_transaction(
            &client,
            OPERATION_COMMIT,
            outcome,
            PolicyCommitError::Store,
        )
        .await
        .map_err(|error| match error {
            PolicyCommitError::PreconditionFailed => PolicyTestSuiteCommitError::PreconditionFailed,
            PolicyCommitError::Store(error) => PolicyTestSuiteCommitError::Store(error),
            // A suite reserves no tool names, so the core cannot refuse one;
            // fail closed rather than report a conflict that cannot be.
            PolicyCommitError::ToolNameTaken { .. } => PolicyTestSuiteCommitError::Store(
                RepositoryError::new(RepositoryErrorKind::Internal, OPERATION_COMMIT),
            ),
        })?;
        Ok(stored.into_record(committed.version, Some(committed.security_revision)))
    }
}
