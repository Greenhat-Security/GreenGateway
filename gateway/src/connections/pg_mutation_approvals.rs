//! One occurrence is consumed in a transaction at the same database that owns
//! its Connection and catalog. Replicas never cache a review decision.
use super::{load_record_for_update, lock_connection_state, PostgresConnectionStore};
use crate::connections::{
    model::ConnectionId,
    mutation_approval::{
        ApprovalDecision, ApprovalError, ApprovalPrincipal, ApprovalStatus,
        ConsumedMutationApproval, MutationAction, MutationApproval, PrepareBinding, PrepareReceipt,
        APPROVAL_LIFETIME_SECS, MAX_APPROVALS, MAX_APPROVALS_PER_CALLER,
    },
};
use uuid::Uuid;

const OPERATION: &str = "connection_mutation_approval";

async fn begin(
    client: &mut deadpool_postgres::Object,
) -> Result<deadpool_postgres::Transaction<'_>, ApprovalError> {
    // RAII rolls back on cancellation. The Connection owner's existing lock
    // serializes creates against both capacity limits, catalog publication,
    // deletion (including its FK cascade), and other review transitions.
    let tx = client
        .transaction()
        .await
        .map_err(|_| ApprovalError::Unavailable)?;
    lock_connection_state(&tx, OPERATION)
        .await
        .map_err(|_| ApprovalError::Unavailable)?;
    Ok(tx)
}

async fn now(client: &impl deadpool_postgres::GenericClient) -> Result<i64, ApprovalError> {
    client
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await
        .map_err(|_| ApprovalError::Unavailable)?
        .try_get(0)
        .map_err(|_| ApprovalError::Unavailable)
}

/// Policy publication locks this same active pointer FOR UPDATE. Hold its
/// share lock through commit so a grant checked on another replica cannot
/// authorize a decision after a newer policy has become authoritative.
async fn check_policy(
    tx: &deadpool_postgres::Transaction<'_>,
    authorized_policy_revision: i64,
) -> Result<(), ApprovalError> {
    let row = tx
        .query_opt(
            "SELECT security_revision FROM greengateway.policy_active WHERE singleton FOR SHARE",
            &[],
        )
        .await
        .map_err(|_| ApprovalError::Unavailable)?
        .ok_or(ApprovalError::Unavailable)?;
    let revision: i64 = row.try_get(0).map_err(|_| ApprovalError::Unavailable)?;
    if revision <= 0 {
        return Err(ApprovalError::Unavailable);
    }
    if revision != authorized_policy_revision {
        return Err(ApprovalError::Conflict);
    }
    Ok(())
}

async fn check_current(
    tx: &deadpool_postgres::Transaction<'_>,
    action: &MutationAction,
) -> Result<(), ApprovalError> {
    let connection = load_record_for_update(tx, &action.connection_id, OPERATION)
        .await
        .map_err(|_| ApprovalError::Unavailable)?
        .ok_or(ApprovalError::Mismatch)?;
    if !connection.write.enabled || connection.etag().as_str() != action.connection_etag {
        return Err(ApprovalError::Mismatch);
    }
    let revision = i64::try_from(action.catalog_revision).map_err(|_| ApprovalError::Invalid)?;
    let row = tx
        .query_opt(
            "SELECT e.definition_json FROM greengateway.connection_openapi_catalogs c
         JOIN greengateway.connection_openapi_catalog_entries e USING (connection_id)
         WHERE c.connection_id = $1::text::uuid AND c.catalog_revision = $2
           AND c.observed_etag = $3 AND e.tool_name = $4 AND e.operation_id = $5",
            &[
                &action.connection_id.as_str(),
                &revision,
                &action.connection_etag,
                &action.tool_name,
                &action.operation,
            ],
        )
        .await
        .map_err(|_| ApprovalError::Unavailable)?
        .ok_or(ApprovalError::Mismatch)?;
    let encoded: &str = row.try_get(0).map_err(|_| ApprovalError::Unavailable)?;
    action.check_stored_definition(
        serde_json::from_str(encoded).map_err(|_| ApprovalError::Unavailable)?,
    )
}

fn field<'a, T: tokio_postgres::types::FromSql<'a>>(
    row: &'a tokio_postgres::Row,
    name: &str,
) -> Result<T, ApprovalError> {
    row.try_get(name).map_err(|_| ApprovalError::Unavailable)
}

fn principal(
    issuer: Option<String>,
    subject: Option<String>,
) -> Result<Option<ApprovalPrincipal>, ApprovalError> {
    match (issuer, subject) {
        (Some(issuer), Some(subject)) => Ok(Some(ApprovalPrincipal { issuer, subject })),
        (None, None) => Ok(None),
        _ => Err(ApprovalError::Unavailable),
    }
}

async fn read(
    client: &impl deadpool_postgres::GenericClient,
    id: Uuid,
) -> Result<(MutationApproval, i64), ApprovalError> {
    let row = client.query_opt(
        "SELECT connection_id::text, connection_etag, catalog_revision, operation, tool_name, method,
                target_sha256, body_sha256, definition_sha256, caller_issuer, caller_subject, status,
                created_at, expires_at, reviewer_issuer, reviewer_subject, reviewed_at,
                revoker_issuer, revoker_subject, revoked_at, consumed_at,
                floor(extract(epoch FROM clock_timestamp()))::bigint AS sampled_at
         FROM greengateway.connection_mutation_approvals WHERE id = $1::text::uuid",
        &[&id.to_string()],
    ).await.map_err(|_| ApprovalError::Unavailable)?.ok_or(ApprovalError::NotFound)?;
    let record = MutationApproval {
        id,
        action: MutationAction {
            connection_id: ConnectionId::parse(field::<String>(&row, "connection_id")?)
                .map_err(|_| ApprovalError::Unavailable)?,
            connection_etag: field(&row, "connection_etag")?,
            catalog_revision: u64::try_from(field::<i64>(&row, "catalog_revision")?)
                .map_err(|_| ApprovalError::Unavailable)?,
            operation: field(&row, "operation")?,
            tool_name: field(&row, "tool_name")?,
            method: field(&row, "method")?,
            definition_sha256: field(&row, "definition_sha256")?,
            target_sha256: field(&row, "target_sha256")?,
            body_sha256: field(&row, "body_sha256")?,
            caller: ApprovalPrincipal {
                issuer: field(&row, "caller_issuer")?,
                subject: field(&row, "caller_subject")?,
            },
        },
        created_at: field(&row, "created_at")?,
        expires_at: field(&row, "expires_at")?,
        status: ApprovalStatus::parse(field(&row, "status")?)
            .map_err(|_| ApprovalError::Unavailable)?,
        reviewer: principal(
            field(&row, "reviewer_issuer")?,
            field(&row, "reviewer_subject")?,
        )?,
        reviewed_at: field(&row, "reviewed_at")?,
        revoked_by: principal(
            field(&row, "revoker_issuer")?,
            field(&row, "revoker_subject")?,
        )?,
        revoked_at: field(&row, "revoked_at")?,
        consumed_at: field(&row, "consumed_at")?,
    };
    record.validate().map_err(|_| ApprovalError::Unavailable)?;
    Ok((record, field(&row, "sampled_at")?))
}

const PREPARE_ACTION: &str = "mutation_approval.prepare";

async fn read_receipt(
    client: &impl deadpool_postgres::GenericClient,
    binding: &PrepareBinding,
    action_digest: Option<&str>,
) -> Result<Option<PrepareReceipt>, ApprovalError> {
    let row = client
        .query_opt(
            "SELECT k.action, e.occurrence_id::text, e.actor_user_id, e.actor_issuer,
                e.actor_auth_mode, e.request_digest, e.action_digest, e.created_at, e.expires_at
         FROM greengateway.authority_caller_operation_ids k
         LEFT JOIN greengateway.mutation_approval_prepare_evidence e USING (operation_id)
         WHERE k.operation_id = $1::text::uuid",
            &[&binding.id.to_string()],
        )
        .await
        .map_err(|_| ApprovalError::Unavailable)?;
    let Some(row) = row else { return Ok(None) };
    if field::<&str>(&row, "action")? != PREPARE_ACTION {
        return Err(ApprovalError::Conflict);
    }
    // A reservation without its evidence is corrupt and cannot be reused.
    let occurrence_id: String = field(&row, "occurrence_id")?;
    if field::<&str>(&row, "actor_user_id")? != binding.actor.subject()
        || Some(field::<&str>(&row, "actor_issuer")?) != binding.actor.issuer()
        || field::<&str>(&row, "actor_auth_mode")? != binding.actor.auth_mode()
        || field::<&str>(&row, "request_digest")? != binding.request_digest
        || action_digest.is_some() && action_digest != Some(field::<&str>(&row, "action_digest")?)
    {
        return Err(ApprovalError::Conflict);
    }
    Ok(Some(PrepareReceipt {
        operation_id: binding.id.to_string(),
        occurrence_id,
        prepared_at: field(&row, "created_at")?,
        expires_at: field(&row, "expires_at")?,
    }))
}

async fn insert_occurrence(
    tx: &deadpool_postgres::Transaction<'_>,
    action: &MutationAction,
) -> Result<MutationApproval, ApprovalError> {
    check_current(tx, action).await?;
    let created_at = now(tx).await?;
    let expires_at = created_at
        .checked_add(APPROVAL_LIFETIME_SECS)
        .ok_or(ApprovalError::Unavailable)?;
    tx.execute(
        "DELETE FROM greengateway.connection_mutation_approvals WHERE expires_at <= $1",
        &[&created_at],
    )
    .await
    .map_err(|_| ApprovalError::Unavailable)?;
    let counts = tx
        .query_one(
            "SELECT count(*), count(*) FILTER (WHERE caller_issuer = $1 AND caller_subject = $2)
             FROM greengateway.connection_mutation_approvals",
            &[&action.caller.issuer, &action.caller.subject],
        )
        .await
        .map_err(|_| ApprovalError::Unavailable)?;
    let total: i64 = counts.try_get(0).map_err(|_| ApprovalError::Unavailable)?;
    let caller_total: i64 = counts.try_get(1).map_err(|_| ApprovalError::Unavailable)?;
    if total >= MAX_APPROVALS || caller_total >= MAX_APPROVALS_PER_CALLER {
        return Err(ApprovalError::Capacity);
    }
    let id = Uuid::new_v4();
    let revision = i64::try_from(action.catalog_revision).map_err(|_| ApprovalError::Invalid)?;
    tx.execute(
            "INSERT INTO greengateway.connection_mutation_approvals
             (id, connection_id, connection_etag, catalog_revision, tool_name, operation, method,
              definition_sha256, target_sha256, body_sha256, caller_issuer, caller_subject, status, created_at, expires_at)
             VALUES ($1::text::uuid, $2::text::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'pending', $13, $14)",
            &[&id.to_string(), &action.connection_id.as_str(), &action.connection_etag, &revision, &action.tool_name,
            &action.operation, &action.method, &action.definition_sha256, &action.target_sha256,
            &action.body_sha256, &action.caller.issuer, &action.caller.subject, &created_at, &expires_at],
        ).await.map_err(|_| ApprovalError::Unavailable)?;
    let (approval, _) = read(tx, id).await?;
    Ok(approval)
}

impl PostgresConnectionStore {
    pub(crate) async fn create_mutation_approval(
        &self,
        action: &MutationAction,
    ) -> Result<MutationApproval, ApprovalError> {
        action.validate()?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ApprovalError::Unavailable)?;
        let tx = begin(&mut client).await?;
        let approval = insert_occurrence(&tx, action).await?;
        tx.commit().await.map_err(|_| ApprovalError::Unavailable)?;
        Ok(approval)
    }

    pub(crate) async fn keyed_prepare_receipt(
        &self,
        binding: &PrepareBinding,
    ) -> Result<Option<PrepareReceipt>, ApprovalError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| ApprovalError::Unavailable)?;
        read_receipt(&client, binding, None).await
    }

    pub(crate) async fn create_keyed_mutation_approval(
        &self,
        action: &MutationAction,
        binding: &PrepareBinding,
    ) -> Result<PrepareReceipt, ApprovalError> {
        use crate::storage::postgres_authority_events::{
            append_to_journal, record_evidence_failure, reserve_caller_operation, JournalSource,
        };
        action.validate()?;
        if binding.actor.subject() != action.caller.subject
            || binding.actor.issuer() != Some(action.caller.issuer.as_str())
        {
            return Err(ApprovalError::Conflict);
        }
        let action_digest = crate::connections::caller_assertion::body_digest(
            &serde_json::to_vec(action).map_err(|_| ApprovalError::Unavailable)?,
        );
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ApprovalError::Unavailable)?;
        let tx = begin(&mut client).await?;
        if let Some(receipt) = read_receipt(&tx, binding, Some(&action_digest)).await? {
            return Ok(receipt);
        }
        if !reserve_caller_operation(tx.client(), binding.id, PREPARE_ACTION)
            .await
            .map_err(|_| {
                record_evidence_failure();
                ApprovalError::Unavailable
            })?
        {
            return Err(ApprovalError::Conflict);
        }
        let approval = insert_occurrence(&tx, action).await?;
        let event = Uuid::new_v4().to_string();
        let receipt = PrepareReceipt {
            operation_id: binding.id.to_string(),
            occurrence_id: approval.id.to_string(),
            prepared_at: approval.created_at,
            expires_at: approval.expires_at,
        };
        tx.execute(
            "INSERT INTO greengateway.mutation_approval_prepare_evidence
             (event_id,operation_id,occurrence_id,request_digest,action_digest,actor_user_id,actor_issuer,actor_auth_mode,created_at,expires_at)
             VALUES ($1::text::uuid,$2::text::uuid,$3::text::uuid,$4,$5,$6,$7,$8,$9,$10)",
            &[&event,&receipt.operation_id,&receipt.occurrence_id,&binding.request_digest,&action_digest,
              &binding.actor.subject(),&action.caller.issuer,&binding.actor.auth_mode(),&receipt.prepared_at,&receipt.expires_at],
        ).await.map_err(|_| { record_evidence_failure(); ApprovalError::Unavailable })?;
        append_to_journal(tx.client(), JournalSource::MutationApprovalPrepare, &event)
            .await
            .map_err(|_| ApprovalError::Unavailable)?;
        tx.commit().await.map_err(|_| ApprovalError::Unavailable)?;
        Ok(receipt)
    }

    pub(crate) async fn mutation_approval(
        &self,
        id: Uuid,
    ) -> Result<MutationApproval, ApprovalError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| ApprovalError::Unavailable)?;
        let (mut record, sampled_at) = read(&client, id).await?;
        record.status = record.status_at(sampled_at)?;
        Ok(record)
    }

    pub(crate) async fn decide_mutation_approval(
        &self,
        id: Uuid,
        reviewer: &ApprovalPrincipal,
        decision: ApprovalDecision,
        authorized_policy_revision: i64,
    ) -> Result<MutationApproval, ApprovalError> {
        reviewer.validate()?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ApprovalError::Unavailable)?;
        let tx = begin(&mut client).await?;
        check_policy(&tx, authorized_policy_revision).await?;
        let (record, sampled_at) = read(&tx, id).await?;
        record.check_decision(reviewer, sampled_at)?;
        if matches!(decision, ApprovalDecision::Approve) {
            check_current(&tx, &record.action).await?;
        }
        let reviewed_at = now(&tx).await?;
        record.ensure_live(reviewed_at)?;
        tx.execute(
            "UPDATE greengateway.connection_mutation_approvals
             SET status=$2, reviewer_issuer=$3, reviewer_subject=$4, reviewed_at=$5 WHERE id=$1::text::uuid",
            &[
                &id.to_string(),
                &decision.status().as_str(),
                &reviewer.issuer,
                &reviewer.subject,
                &reviewed_at,
            ],
        )
        .await
        .map_err(|_| ApprovalError::Unavailable)?;
        let (result, _) = read(&tx, id).await?;
        tx.commit().await.map_err(|_| ApprovalError::Unavailable)?;
        Ok(result)
    }

    pub(crate) async fn revoke_mutation_approval(
        &self,
        id: Uuid,
        reviewer: &ApprovalPrincipal,
        authorized_policy_revision: i64,
    ) -> Result<MutationApproval, ApprovalError> {
        reviewer.validate()?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ApprovalError::Unavailable)?;
        let tx = begin(&mut client).await?;
        check_policy(&tx, authorized_policy_revision).await?;
        let (record, revoked_at) = read(&tx, id).await?;
        record.check_revocation(reviewer, revoked_at)?;
        tx.execute(
            "UPDATE greengateway.connection_mutation_approvals
             SET status='revoked', revoker_issuer=$2, revoker_subject=$3, revoked_at=$4 WHERE id=$1::text::uuid",
            &[&id.to_string(), &reviewer.issuer, &reviewer.subject, &revoked_at],
        ).await.map_err(|_| ApprovalError::Unavailable)?;
        let (result, _) = read(&tx, id).await?;
        tx.commit().await.map_err(|_| ApprovalError::Unavailable)?;
        Ok(result)
    }

    pub(crate) async fn check_mutation_approval(
        &self,
        id: Uuid,
        action: &MutationAction,
    ) -> Result<(), ApprovalError> {
        action.validate()?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ApprovalError::Unavailable)?;
        let tx = begin(&mut client).await?;
        let (record, sampled_at) = read(&tx, id).await?;
        record.check_consumption(action, sampled_at)?;
        check_current(&tx, action).await?;
        record.ensure_live(now(&tx).await?)?;
        tx.commit().await.map_err(|_| ApprovalError::Unavailable)
    }

    pub(crate) async fn consume_mutation_approval(
        &self,
        id: Uuid,
        action: &MutationAction,
        authorized_policy_revision: i64,
    ) -> Result<ConsumedMutationApproval, ApprovalError> {
        action.validate()?;
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| ApprovalError::Unavailable)?;
        let tx = begin(&mut client).await?;
        check_policy(&tx, authorized_policy_revision).await?;
        let (record, sampled_at) = read(&tx, id).await?;
        record.check_consumption(action, sampled_at)?;
        check_current(&tx, action).await?;
        let consumed_at = now(&tx).await?;
        record.ensure_live(consumed_at)?;
        let changed = tx.execute(
            "UPDATE greengateway.connection_mutation_approvals SET status='consumed', consumed_at=$2 WHERE id=$1::text::uuid AND status='approved'",
            &[&id.to_string(), &consumed_at],
        ).await.map_err(|_| ApprovalError::Unavailable)?;
        if changed != 1 {
            return Err(ApprovalError::Conflict);
        }
        tx.commit().await.map_err(|_| ApprovalError::Unavailable)?;
        Ok(ConsumedMutationApproval::new(record, consumed_at))
    }
}
