//! PostgreSQL versioned tools control plane (issue #241, PR 8).
//!
//! The tools document (the TOOLS_FILE local lane: `schema_version` +
//! `tools[]`) is a singleton versioned document under the shared
//! section-2 transaction (see `postgres_documents`): immutable versions
//! doubling as history, one active pointer, the shared security revision,
//! and one outbox row per commit.
//!
//! Unlike the policy plane, an empty tools document is a valid state (it
//! is exactly what standalone mode serves without TOOLS_FILE), so a
//! cluster deployment seeds one empty document idempotently at first
//! boot ([`PostgresToolStore::seed_empty_document`]) and every later
//! mutation is an expected-ETag compare-and-swap.
//!
//! Document validation is the caller's concern (`ToolRegistry`'s file
//! loader validates the same JSON); this store only verifies the stored
//! ETag against the document body, so a tampered row fails closed rather
//! than being served or committed over.

use async_trait::async_trait;
use serde_json::Value;

use super::{
    policy_history::{PolicyCommitError, PolicyCommitPrecondition},
    postgres_documents::{self, DocumentResource},
    RepositoryError, RepositoryErrorKind,
};

/// The active tools document as the authority sees it.
#[derive(Clone, Debug)]
pub struct ActiveToolDocument {
    pub document: Value,
    #[allow(dead_code)] // Read by the PR 8 tests; cluster status arrives later.
    pub version: i64,
    pub etag: String,
    pub security_revision: i64,
}

/// Contract for the tools control plane: authoritative read plus the
/// section-2 commit. Mirrors `PolicyControlPlane`'s shape so the admin
/// wiring and tests treat the two resources uniformly.
#[async_trait]
pub trait ToolControlPlane: Send + Sync {
    /// The active document, or `None` before the deployment seeded one.
    async fn active_tools(&self) -> Result<Option<ActiveToolDocument>, RepositoryError>;

    /// Commit a new version of the document under a compare-and-swap
    /// precondition, advancing the shared security revision and writing
    /// the outbox record in the same transaction.
    async fn commit_tools(
        &self,
        precondition: PolicyCommitPrecondition,
        document: &Value,
        actor_user_id: &str,
        diff_summary: &Value,
    ) -> Result<ActiveToolDocument, PolicyCommitError>;
}

const TOOLS_DOCUMENT_RESOURCE: DocumentResource = DocumentResource {
    documents_table: "greengateway.tool_documents",
    active_table: "greengateway.tool_active",
    resource_type: "tools",
    operation: "tool_document_commit",
};

const OPERATION_TOOLS_ACTIVE: &str = "tool_document_active_read";

/// The empty document seeded at first boot. Its schema version matches
/// the tools file schema the registry validates.
fn empty_tools_document() -> Value {
    serde_json::json!({
        "schema_version": "0.1.0",
        "tools": [],
    })
}

pub struct PostgresToolStore {
    pool: deadpool_postgres::Pool,
}

/// `tools[].name` as strings, without judging the document: a value the
/// schema rejects reserves the names it does carry and fails closed at
/// the replica.
fn local_tool_names(document: &Value) -> Vec<String> {
    document["tools"]
        .as_array()
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

impl PostgresToolStore {
    pub fn new(pool: deadpool_postgres::Pool) -> Self {
        Self { pool }
    }

    /// The shared revision-counter view over this store's pool, for tests
    /// and later cluster-status surfaces. Read-only; commits advance the
    /// counter inside their own transactions.
    #[allow(dead_code)] // The PR 8 tests read it; production consumers
                        // (cluster status) arrive with #241 PR 14.
    pub fn revision_source(&self) -> super::postgres_policy::SecurityRevisionSource {
        super::postgres_policy::SecurityRevisionSource::new(self.pool.clone())
    }

    /// Idempotently seed the empty tools document. Racing first boots
    /// produce exactly one seeded document; later boots are no-ops.
    pub async fn seed_empty_document(&self) -> Result<(), PolicyCommitError> {
        let document = empty_tools_document();
        let etag = crate::tools_file_etag(&document).map_err(|_| {
            PolicyCommitError::Store(RepositoryError::new(
                RepositoryErrorKind::InvalidData,
                TOOLS_DOCUMENT_RESOURCE.operation,
            ))
        })?;
        match postgres_documents::commit(
            &self.pool,
            TOOLS_DOCUMENT_RESOURCE,
            PolicyCommitPrecondition::Initialize,
            postgres_documents::DocumentCommit {
                document_json: &document.to_string(),
                document_etag: &etag,
                actor_user_id: "bootstrap",
                diff_summary_json: r#"{"action":"tools_seeded"}"#,
                tool_names: None,
            },
        )
        .await
        {
            Ok(_) => Ok(()),
            // Another replica (or an earlier boot) already seeded the
            // document: the resource is initialized, which is all this
            // call owes the caller.
            Err(PolicyCommitError::PreconditionFailed) => Ok(()),
            Err(error) => Err(error),
        }
    }

    async fn read_active(&self) -> Result<Option<ActiveToolDocument>, RepositoryError> {
        let client = self.pool.get().await.map_err(classify_pool_error)?;
        let row = postgres_documents::read_active(&client, TOOLS_DOCUMENT_RESOURCE)
            .await?
            .map(
                |(version, stored_etag, security_revision, created_at, document_json)| {
                    ActiveToolDocumentRow {
                        version,
                        stored_etag,
                        security_revision,
                        created_at,
                        document_json,
                    }
                },
            );
        let Some(row) = row else {
            return Ok(None);
        };
        let document: Value = serde_json::from_str(&row.document_json)
            .map_err(|_| invalid_data(OPERATION_TOOLS_ACTIVE))?;
        let etag =
            crate::tools_file_etag(&document).map_err(|_| invalid_data(OPERATION_TOOLS_ACTIVE))?;
        if etag != row.stored_etag {
            tracing::error!(
                "the active tools document does not match its recorded ETag; \
                 refusing to serve an unverifiable document"
            );
            return Err(invalid_data(OPERATION_TOOLS_ACTIVE));
        }
        Ok(Some(ActiveToolDocument {
            document,
            version: row.version,
            etag,
            security_revision: row.security_revision,
        }))
    }
}

struct ActiveToolDocumentRow {
    version: i64,
    stored_etag: String,
    security_revision: i64,
    #[allow(dead_code)]
    created_at: String,
    document_json: String,
}

fn classify_pool_error(error: deadpool_postgres::PoolError) -> RepositoryError {
    super::postgres::classify_pool_error(error)
}

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

#[async_trait]
impl ToolControlPlane for PostgresToolStore {
    async fn active_tools(&self) -> Result<Option<ActiveToolDocument>, RepositoryError> {
        self.read_active().await
    }

    async fn commit_tools(
        &self,
        precondition: PolicyCommitPrecondition,
        document: &Value,
        actor_user_id: &str,
        diff_summary: &Value,
    ) -> Result<ActiveToolDocument, PolicyCommitError> {
        let etag = crate::tools_file_etag(document).map_err(|_| {
            PolicyCommitError::Store(invalid_data(TOOLS_DOCUMENT_RESOURCE.operation))
        })?;
        // The names are read from the document as the registry will name
        // the tools (`tools[].name`, verbatim), so what is reserved is
        // exactly what every replica installs. The authority does not
        // validate the document -- validation is replica-side, and the gate
        // fails closed on a document this binary cannot enforce (see
        // `tools_reconciliation_installs_and_fails_closed`); it refuses
        // only a name another lane holds.
        let tool_names = local_tool_names(document);
        let committed = postgres_documents::commit(
            &self.pool,
            TOOLS_DOCUMENT_RESOURCE,
            precondition,
            postgres_documents::DocumentCommit {
                document_json: &document.to_string(),
                document_etag: &etag,
                actor_user_id,
                diff_summary_json: &diff_summary.to_string(),
                tool_names: Some(&tool_names),
            },
        )
        .await?;
        Ok(ActiveToolDocument {
            document: document.clone(),
            version: committed.version,
            etag,
            security_revision: committed.security_revision,
        })
    }
}
