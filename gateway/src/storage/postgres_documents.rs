//! The shared versioned-document control-plane core (issue #241, PRs 7-8).
//!
//! The policy document (migration 4) and the tools document (migration 5)
//! are both singleton JSON documents under the HA state model's section 2
//! transaction: immutable versions, one active pointer, the shared
//! security-revision counter, and one outbox row per committed change.
//! The transaction below is that contract, parameterized only by table
//! names and the outbox `resource_type`; the policy and tools stores
//! delegate to it so the security-critical sequence exists once.
//!
//! Transaction steps (identical to the reviewed PR 7 policy commit):
//!
//! 1. `SELECT ... FROM <active> WHERE singleton FOR UPDATE OF a`, joining
//!    the named document row to verify the pointer's recorded ETag against
//!    the document it names -- a tampered or inconsistent pointer fails
//!    closed instead of being silently healed.
//! 2. The caller's precondition is re-verified: a stale expected ETag (or
//!    a race against another initializer) is `PreconditionFailed` and the
//!    transaction rolls back with nothing written.
//! 3. The candidate becomes a new immutable `<documents>` row (which is
//!    also the history entry).
//! 4. The next security revision is reserved from
//!    `security_revision_state` -- rollback-safe, the property a bare
//!    sequence does not have.
//! 5. The pointer advances (or is initialized under `ON CONFLICT DO
//!    NOTHING`, whose zero-row result is the initialize race's loser).
//! 6. One `security_outbox` row records the change with identifiers and
//!    revisions only.
//! 7. `COMMIT` -- once; every step rolls back together.
//!
//! Steps 1-6 are [`commit_in`], over a client whose transaction the caller
//! has already opened; [`commit`] wraps them in `BEGIN`/`COMMIT` for the
//! plain control-plane endpoints. A workflow that must commit a document
//! together with rows of its own (issue #241, PR 12: accepting a rule
//! suggestion transitions the suggestion in the same transaction as the
//! policy commit) opens the transaction itself, runs `commit_in` between
//! its own statements, and commits once -- so the seven steps still exist
//! exactly once and a failure anywhere rolls the whole workflow back.

use super::{
    log_classified, policy_history::PolicyCommitError, postgres::classify_pool_error,
    RepositoryError, RepositoryErrorKind,
};

/// The tables and identity of one versioned-document resource.
#[derive(Clone, Copy)]
pub(crate) struct DocumentResource {
    /// The immutable versions table (must follow migration 4/5's shape).
    pub documents_table: &'static str,
    /// The singleton active-pointer table.
    pub active_table: &'static str,
    /// The outbox `resource_type` label ('policy', 'tools', ...).
    pub resource_type: &'static str,
    /// The classified operation label prefix.
    pub operation: &'static str,
}

/// The caller's belief about the active state, re-verified in the
/// transaction. The same shape as `PolicyCommitPrecondition`, shared so
/// the core cannot drift from the published contract.
pub(crate) use super::policy_history::PolicyCommitPrecondition as DocumentPrecondition;

/// A fully serialized commit: the document JSON, its computed ETag, the
/// actor, and the diff summary. Validation of the document itself is the
/// caller's job before this runs; the transaction never activates a
/// candidate the caller has not validated.
pub(crate) struct DocumentCommit<'a> {
    pub document_json: &'a str,
    pub document_etag: &'a str,
    pub actor_user_id: &'a str,
    pub diff_summary_json: &'a str,
    /// The tool names this document publishes into the local lane, to be
    /// reserved at the authority in the same transaction. `None` for
    /// documents that publish no tools (policies).
    pub tool_names: Option<&'a [String]>,
}

/// The committed state, mirroring `ActivePolicy`'s facts.
pub(crate) struct DocumentCommitted {
    pub version: i64,
    pub security_revision: i64,
}

/// The active pointer's state: `(version, etag, security_revision,
/// created_at, document_json)`.
pub(crate) type ActiveDocumentRow = (i64, String, i64, String, String);

fn invalid_data(operation: &'static str) -> RepositoryError {
    RepositoryError::new(RepositoryErrorKind::InvalidData, operation)
}

fn store_error(error: RepositoryError) -> PolicyCommitError {
    PolicyCommitError::Store(error)
}

fn classify_query(error: tokio_postgres::Error, operation: &'static str) -> RepositoryError {
    let kind = super::postgres::classify_postgres_error(&error);
    log_classified(operation, &error, RepositoryError::new(kind, operation))
}

/// Read the active document row (joined for its creation timestamp), or
/// `None` on a never-initialized resource. ETag verification against the
/// stored document is the CALLER's responsibility (`document_json` is
/// returned so it can hash and validate).
pub(crate) async fn read_active(
    client: &deadpool_postgres::Object,
    resource: DocumentResource,
) -> Result<Option<ActiveDocumentRow>, RepositoryError> {
    let sql = format!(
        r#"
        SELECT a.active_version,
            a.document_etag,
            a.security_revision,
            to_char(d.created_at AT TIME ZONE 'UTC',
                    'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            d.document::text
        FROM {active} a
        JOIN {documents} d ON d.version = a.active_version
        WHERE a.singleton
        "#,
        active = resource.active_table,
        documents = resource.documents_table,
    );
    let row = client
        .query_opt(sql.as_str(), &[])
        .await
        .map_err(|error| classify_query(error, resource.operation))?;
    Ok(row.map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4))))
}

/// Open a transaction on `client`.
///
/// The transaction is driven explicitly over the simple protocol (the
/// audit store's and the migrator's pattern). A request abandoned between
/// BEGIN and COMMIT returns its connection to the pool with the transaction
/// open; the row locks it holds are reclaimed by the session's server-side
/// bounds (`lock_timeout` bounds other writers' waits,
/// `idle_in_transaction_session_timeout` closes the session), so the
/// failure mode is bounded 503s, never corruption. A drop-guarded
/// interactive transaction can harden this and the audit append together
/// if abandonment proves real.
pub(crate) async fn begin(
    client: &deadpool_postgres::Object,
    operation: &'static str,
) -> Result<(), RepositoryError> {
    client
        .batch_execute("BEGIN")
        .await
        .map_err(|error| classify_query(error, operation))
}

/// Close the transaction `begin` opened: `COMMIT` on `Ok`, `ROLLBACK` on
/// `Err` (a failed rollback is not reported; the session's bounds reclaim
/// the connection and the caller's error is the one that matters).
/// `store_error` lifts a failed COMMIT into the caller's error type.
pub(crate) async fn end_transaction<T, E>(
    client: &deadpool_postgres::Object,
    operation: &'static str,
    outcome: Result<T, E>,
    store_error: impl FnOnce(RepositoryError) -> E,
) -> Result<T, E> {
    match outcome {
        Ok(value) => client
            .batch_execute("COMMIT")
            .await
            .map_err(|error| store_error(classify_query(error, operation)))
            .map(|_| value),
        Err(error) => {
            let _ = client.batch_execute("ROLLBACK").await;
            Err(error)
        }
    }
}

/// Run the section-2 transaction for one document resource. See the module
/// documentation for the step-by-step contract.
pub(crate) async fn commit(
    pool: &deadpool_postgres::Pool,
    resource: DocumentResource,
    precondition: DocumentPrecondition,
    commit: DocumentCommit<'_>,
) -> Result<DocumentCommitted, PolicyCommitError> {
    let client = pool
        .get()
        .await
        .map_err(classify_pool_error)
        .map_err(store_error)?;
    begin(&client, resource.operation)
        .await
        .map_err(store_error)?;
    let outcome = commit_in(&client, resource, precondition, commit).await;
    end_transaction(&client, resource.operation, outcome, store_error).await
}

/// Steps 1-6 of the section-2 transaction, over a client whose transaction
/// the caller opened and will close. Returns `Err` with nothing to undo on
/// the caller's side beyond `ROLLBACK`: every write is inside the
/// transaction.
pub(crate) async fn commit_in(
    client: &deadpool_postgres::Object,
    resource: DocumentResource,
    precondition: DocumentPrecondition,
    commit: DocumentCommit<'_>,
) -> Result<DocumentCommitted, PolicyCommitError> {
    {
        // 1. Lock the pointer and verify its self-consistency.
        let lock_sql = format!(
            r#"
            SELECT a.active_version, a.document_etag, d.document_etag
            FROM {active} a
            JOIN {documents} d ON d.version = a.active_version
            WHERE a.singleton
            FOR UPDATE OF a
            "#,
            active = resource.active_table,
            documents = resource.documents_table,
        );
        let active_row = client
            .query_opt(lock_sql.as_str(), &[])
            .await
            .map_err(|error| classify_query(error, resource.operation))
            .map_err(store_error)?;
        let current = active_row.map(|row| {
            let recorded_etag: String = row.get(1);
            let document_etag: String = row.get(2);
            (row.get::<_, i64>(0), recorded_etag, document_etag)
        });

        if let Some((_, recorded_etag, document_etag)) = &current {
            if recorded_etag != document_etag {
                tracing::error!(
                    resource = resource.resource_type,
                    "the active document pointer's recorded ETag does not match the \
                     document it names; refusing to commit over an inconsistent authority"
                );
                return Err(PolicyCommitError::Store(invalid_data(resource.operation)));
            }
        }

        // 2. Re-verify the precondition against the authority.
        match (&precondition, &current) {
            (DocumentPrecondition::Expected { etag: expected }, Some((_, current_etag, _)))
                if current_etag == expected => {}
            (DocumentPrecondition::Initialize, None) => {}
            _ => return Err(PolicyCommitError::PreconditionFailed),
        }

        // 3. The new immutable version (also the history row).
        let insert_sql = format!(
            r#"
            INSERT INTO {documents} (
                actor_user_id, diff_summary, document, document_etag
            )
            VALUES ($1, $2::text::jsonb, $3::text::jsonb, $4)
            RETURNING version
            "#,
            documents = resource.documents_table,
        );
        let document_row = client
            .query_one(
                insert_sql.as_str(),
                &[
                    &commit.actor_user_id,
                    &commit.diff_summary_json,
                    &commit.document_json,
                    &commit.document_etag,
                ],
            )
            .await
            .map_err(|error| classify_query(error, resource.operation))
            .map_err(store_error)?;
        let new_version: i64 = document_row.get(0);

        // 3b. The local lane's tool names, reserved at the authority so no
        // other lane can commit one of them while this document holds it.
        if let Some(names) = commit.tool_names {
            super::postgres_tool_names::reserve_tool_names(
                client,
                super::postgres_tool_names::LANE_LOCAL,
                super::postgres_tool_names::LOCAL_OWNER,
                names.iter().cloned(),
            )
            .await
            .map_err(|error| match error {
                super::postgres_tool_names::ToolNameReservationError::Taken {
                    tool_name,
                    lane,
                    owner_id,
                } => PolicyCommitError::ToolNameTaken {
                    tool_name,
                    lane,
                    owner_id,
                },
                super::postgres_tool_names::ToolNameReservationError::Postgres(error) => {
                    store_error(classify_query(error, resource.operation))
                }
            })?;
        }

        // 4. Reserve the next security revision (rollback-safe).
        let revision_row = client
            .query_opt(
                r#"
                UPDATE greengateway.security_revision_state
                SET last_revision = last_revision + 1
                WHERE singleton
                RETURNING last_revision
                "#,
                &[],
            )
            .await
            .map_err(|error| classify_query(error, resource.operation))
            .map_err(store_error)?;
        let new_revision: i64 = revision_row
            .map(|row| row.get(0))
            .ok_or_else(|| invalid_data(resource.operation))
            .map_err(store_error)?;

        // 5. Advance (or initialize) the pointer.
        const APPEND_OUTBOX_SQL: &str = r#"
            INSERT INTO greengateway.security_outbox (
                revision, resource_type, from_version, to_version
            )
            VALUES ($1, $2, $3, $4)
            "#;
        match current {
            Some((previous_version, _, _)) => {
                let advance_sql = format!(
                    r#"
                    UPDATE {active}
                    SET active_version = $1, document_etag = $2, security_revision = $3,
                        activated_at = now()
                    WHERE singleton
                    "#,
                    active = resource.active_table,
                );
                client
                    .execute(
                        advance_sql.as_str(),
                        &[&new_version, &commit.document_etag, &new_revision],
                    )
                    .await
                    .map_err(|error| classify_query(error, resource.operation))
                    .map_err(store_error)?;
                client
                    .execute(
                        APPEND_OUTBOX_SQL,
                        &[
                            &new_revision,
                            &resource.resource_type,
                            &previous_version,
                            &new_version,
                        ],
                    )
                    .await
                    .map_err(|error| classify_query(error, resource.operation))
                    .map_err(store_error)?;
            }
            None => {
                let initialize_sql = format!(
                    r#"
                    INSERT INTO {active} (
                        singleton, active_version, document_etag, security_revision
                    )
                    VALUES (true, $1, $2, $3)
                    ON CONFLICT (singleton) DO NOTHING
                    "#,
                    active = resource.active_table,
                );
                let inserted = client
                    .execute(
                        initialize_sql.as_str(),
                        &[&new_version, &commit.document_etag, &new_revision],
                    )
                    .await
                    .map_err(|error| classify_query(error, resource.operation))
                    .map_err(store_error)?;
                if inserted == 0 {
                    // Another initializer won the race; the lock on a
                    // not-yet-existing row protected nothing, so this
                    // insert's conflict clause is the serialization point.
                    return Err(PolicyCommitError::PreconditionFailed);
                }
                client
                    .execute(
                        APPEND_OUTBOX_SQL,
                        &[
                            &new_revision,
                            &resource.resource_type,
                            &None::<i64>,
                            &new_version,
                        ],
                    )
                    .await
                    .map_err(|error| classify_query(error, resource.operation))
                    .map_err(store_error)?;
            }
        }

        Ok(DocumentCommitted {
            version: new_version,
            security_revision: new_revision,
        })
    }
}
