use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use uuid::Uuid;

use super::{load_raw_by_id, SqliteConnectionStore};
use crate::connections::{
    model::ConnectionId,
    mutation_approval::{
        ApprovalDecision, ApprovalError, ApprovalPrincipal, ApprovalStatus,
        ConsumedMutationApproval, MutationAction, MutationApproval, APPROVAL_LIFETIME_SECS,
        MAX_APPROVALS, MAX_APPROVALS_PER_CALLER,
    },
};

pub(super) const MIGRATION_SQL: &str = r#"
CREATE TABLE connection_mutation_approvals (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(id) = 36),
    connection_id TEXT NOT NULL REFERENCES connection_records(id) ON DELETE CASCADE,
    connection_etag TEXT NOT NULL CHECK (length(CAST(connection_etag AS BLOB)) BETWEEN 1 AND 256),
    catalog_revision INTEGER NOT NULL CHECK (catalog_revision >= 1),
    caller_issuer TEXT NOT NULL CHECK (length(CAST(caller_issuer AS BLOB)) BETWEEN 1 AND 512),
    caller_subject TEXT NOT NULL CHECK (length(CAST(caller_subject AS BLOB)) BETWEEN 1 AND 256),
    tool_name TEXT NOT NULL CHECK (length(CAST(tool_name AS BLOB)) BETWEEN 1 AND 512),
    operation TEXT NOT NULL CHECK (length(CAST(operation AS BLOB)) BETWEEN 1 AND 1024),
    method TEXT NOT NULL CHECK (method IN ('POST','PUT','PATCH','DELETE')),
    target_sha256 TEXT NOT NULL CHECK (length(target_sha256) = 64 AND target_sha256 NOT GLOB '*[^0-9a-f]*'),
    body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64 AND body_sha256 NOT GLOB '*[^0-9a-f]*'),
    definition_sha256 TEXT NOT NULL CHECK (length(definition_sha256) = 64 AND definition_sha256 NOT GLOB '*[^0-9a-f]*'),
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','revoked','consumed')),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at - created_at = 900),
    reviewer_issuer TEXT CHECK (length(CAST(reviewer_issuer AS BLOB)) BETWEEN 1 AND 512),
    reviewer_subject TEXT CHECK (length(CAST(reviewer_subject AS BLOB)) BETWEEN 1 AND 256),
    reviewed_at INTEGER CHECK (reviewed_at >= created_at AND reviewed_at < expires_at),
    revoker_issuer TEXT CHECK (length(CAST(revoker_issuer AS BLOB)) BETWEEN 1 AND 512),
    revoker_subject TEXT CHECK (length(CAST(revoker_subject AS BLOB)) BETWEEN 1 AND 256),
    revoked_at INTEGER CHECK (revoked_at >= coalesce(reviewed_at,created_at) AND revoked_at < expires_at),
    consumed_at INTEGER CHECK (consumed_at >= reviewed_at AND consumed_at < expires_at),
    CHECK ((reviewer_issuer IS NULL) = (reviewed_at IS NULL) AND (reviewer_subject IS NULL) = (reviewed_at IS NULL)),
    CHECK ((revoker_issuer IS NULL) = (revoked_at IS NULL) AND (revoker_subject IS NULL) = (revoked_at IS NULL)),
    CHECK (reviewed_at IS NULL OR caller_issuer != reviewer_issuer OR caller_subject != reviewer_subject),
    CHECK (revoked_at IS NULL OR caller_issuer != revoker_issuer OR caller_subject != revoker_subject),
    CHECK ((status = 'pending' AND reviewed_at IS NULL AND revoked_at IS NULL AND consumed_at IS NULL)
        OR (status IN ('approved','rejected') AND reviewed_at IS NOT NULL AND revoked_at IS NULL AND consumed_at IS NULL)
        OR (status = 'revoked' AND revoked_at IS NOT NULL AND consumed_at IS NULL)
        OR (status = 'consumed' AND reviewed_at IS NOT NULL AND revoked_at IS NULL AND consumed_at IS NOT NULL))
) STRICT;
CREATE INDEX idx_mutation_approval_caller ON connection_mutation_approvals(caller_issuer,caller_subject);
CREATE INDEX idx_mutation_approval_connection ON connection_mutation_approvals(connection_id);
CREATE INDEX idx_mutation_approval_expiry ON connection_mutation_approvals(expires_at);
"#;

pub(super) const SCHEMA_QUERY: &str =
    "SELECT id,connection_id,connection_etag,catalog_revision,caller_issuer,caller_subject,tool_name,
            operation,method,target_sha256,body_sha256,definition_sha256,status,created_at,expires_at,
            reviewer_issuer,reviewer_subject,reviewed_at,revoker_issuer,revoker_subject,revoked_at,consumed_at
     FROM connection_mutation_approvals LIMIT 0";

// SQL values, including actor identities, never enter an error response or log.
impl From<rusqlite::Error> for ApprovalError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Unavailable
    }
}

fn authority_now(connection: &Connection) -> Result<i64, ApprovalError> {
    Ok(connection.query_row("SELECT unixepoch()", [], |row| row.get(0))?)
}

fn stored_actor(
    issuer: Option<String>,
    subject: Option<String>,
) -> Result<Option<ApprovalPrincipal>, ApprovalError> {
    match (issuer, subject) {
        (Some(issuer), Some(subject)) => Ok(Some(ApprovalPrincipal { issuer, subject })),
        (None, None) => Ok(None),
        _ => Err(ApprovalError::Unavailable),
    }
}

fn load_approval(connection: &Connection, id: Uuid) -> Result<MutationApproval, ApprovalError> {
    let mut statement = connection.prepare(
        "SELECT connection_id,connection_etag,catalog_revision,caller_issuer,caller_subject,
            tool_name,operation,method,target_sha256,body_sha256,definition_sha256,status,
            created_at,expires_at,reviewer_issuer,reviewer_subject,reviewed_at,
            revoker_issuer,revoker_subject,revoked_at,consumed_at
         FROM connection_mutation_approvals WHERE id=?1",
    )?;
    let mut rows = statement.query([id.to_string()])?;
    let row = rows.next()?.ok_or(ApprovalError::NotFound)?;
    let action = MutationAction {
        caller: ApprovalPrincipal {
            issuer: row.get("caller_issuer")?,
            subject: row.get("caller_subject")?,
        },
        connection_id: ConnectionId::parse(row.get::<_, String>("connection_id")?)
            .map_err(|_| ApprovalError::Unavailable)?,
        connection_etag: row.get("connection_etag")?,
        catalog_revision: u64::try_from(row.get::<_, i64>("catalog_revision")?)
            .map_err(|_| ApprovalError::Unavailable)?,
        tool_name: row.get("tool_name")?,
        operation: row.get("operation")?,
        method: row.get("method")?,
        target_sha256: row.get("target_sha256")?,
        body_sha256: row.get("body_sha256")?,
        definition_sha256: row.get("definition_sha256")?,
    };
    let record = MutationApproval {
        id,
        action,
        status: ApprovalStatus::parse(&row.get::<_, String>("status")?)?,
        created_at: row.get("created_at")?,
        expires_at: row.get("expires_at")?,
        reviewer: stored_actor(row.get("reviewer_issuer")?, row.get("reviewer_subject")?)?,
        reviewed_at: row.get("reviewed_at")?,
        revoked_by: stored_actor(row.get("revoker_issuer")?, row.get("revoker_subject")?)?,
        revoked_at: row.get("revoked_at")?,
        consumed_at: row.get("consumed_at")?,
    };
    record.validate()?;
    Ok(record)
}

impl SqliteConnectionStore {
    /// Take the writer lock before reading either the approval or authority clock. Separate
    /// handles on the same SQLite file must serialize claims just like threads on one handle.
    fn approval_transaction<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<T, ApprovalError>,
    ) -> Result<T, ApprovalError> {
        let mut connection = self.connection_guard();
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = f(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    fn check_approval_generation(
        &self,
        tx: &Transaction<'_>,
        action: &MutationAction,
    ) -> Result<(), ApprovalError> {
        let record = load_raw_by_id(tx, &self.path, &action.connection_id)
            .map_err(|_| ApprovalError::Unavailable)?
            .ok_or(ApprovalError::Mismatch)?
            .into_stored()
            .map_err(|_| ApprovalError::Unavailable)?;
        if record.etag().as_str() != action.connection_etag || !record.write.enabled {
            return Err(ApprovalError::Mismatch);
        }
        let definition: String = tx
            .query_row(
                "SELECT entry.definition_json FROM connection_openapi_catalogs AS catalog
                 JOIN connection_openapi_catalog_entries AS entry ON entry.connection_id=catalog.connection_id
                 WHERE catalog.connection_id=?1 AND catalog.observed_etag=?2 AND catalog.catalog_revision=?3
                   AND entry.tool_name=?4 AND entry.operation_id=?5",
                params![
                    action.connection_id.as_str(),
                    action.connection_etag,
                    i64::try_from(action.catalog_revision).map_err(|_| ApprovalError::Invalid)?,
                    action.tool_name,
                    action.operation
                ],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(ApprovalError::Mismatch)?;
        let definition =
            serde_json::from_str(&definition).map_err(|_| ApprovalError::Unavailable)?;
        action.check_stored_definition(definition)
    }

    pub fn create_mutation_approval(
        &self,
        action: &MutationAction,
    ) -> Result<MutationApproval, ApprovalError> {
        action.validate()?;
        self.approval_transaction(|tx| {
            self.check_approval_generation(tx, action)?;
            let now = authority_now(tx)?;
            tx.execute("DELETE FROM connection_mutation_approvals WHERE expires_at<=?1", [now])?;
            let (total, owned): (i64, i64) = tx.query_row(
                "SELECT COUNT(*),COUNT(*) FILTER (WHERE caller_issuer=?1 AND caller_subject=?2)
                 FROM connection_mutation_approvals",
                params![action.caller.issuer, action.caller.subject],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if total >= MAX_APPROVALS || owned >= MAX_APPROVALS_PER_CALLER {
                return Err(ApprovalError::Capacity);
            }
            let id = Uuid::new_v4();
            let revision = i64::try_from(action.catalog_revision).map_err(|_| ApprovalError::Invalid)?;
            let expires_at = now.checked_add(APPROVAL_LIFETIME_SECS).ok_or(ApprovalError::Unavailable)?;
            tx.execute(
                "INSERT INTO connection_mutation_approvals (id,caller_issuer,caller_subject,connection_id,connection_etag,
                    catalog_revision,tool_name,operation,method,target_sha256,body_sha256,definition_sha256,status,created_at,expires_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'pending',?13,?14)",
                params![
                    id.to_string(), action.caller.issuer, action.caller.subject, action.connection_id.as_str(),
                    action.connection_etag, revision, action.tool_name, action.operation,
                    action.method, action.target_sha256, action.body_sha256, action.definition_sha256,
                    now, expires_at
                ],
            )?;
            load_approval(tx, id)
        })
    }

    pub fn mutation_approval(&self, id: Uuid) -> Result<MutationApproval, ApprovalError> {
        let mut connection = self.connection_guard();
        let tx = connection.transaction()?;
        let mut record = load_approval(&tx, id)?;
        record.status = record.status_at(authority_now(&tx)?)?;
        tx.commit()?;
        Ok(record)
    }

    pub fn decide_mutation_approval(
        &self,
        id: Uuid,
        reviewer: &ApprovalPrincipal,
        decision: ApprovalDecision,
        check_permission: impl FnOnce() -> Result<i64, ApprovalError>,
    ) -> Result<MutationApproval, ApprovalError> {
        self.approval_transaction(|tx| {
            let record = load_approval(tx, id)?;
            record.check_decision(reviewer, authority_now(tx)?)?;
            if decision == ApprovalDecision::Approve {
                self.check_approval_generation(tx, &record.action)?;
            }
            // A reviewer can lose the grant while waiting for this writer lock.
            check_permission()?;
            let now = authority_now(tx)?;
            record.ensure_live(now)?;
            tx.execute(
                "UPDATE connection_mutation_approvals
                 SET status=?2, reviewer_issuer=?3, reviewer_subject=?4, reviewed_at=?5 WHERE id=?1",
                params![id.to_string(), decision.status().as_str(), reviewer.issuer, reviewer.subject, now],
            )?;
            load_approval(tx, id)
        })
    }

    pub fn revoke_mutation_approval(
        &self,
        id: Uuid,
        reviewer: &ApprovalPrincipal,
        check_permission: impl FnOnce() -> Result<i64, ApprovalError>,
    ) -> Result<MutationApproval, ApprovalError> {
        self.approval_transaction(|tx| {
            let record = load_approval(tx, id)?;
            check_permission()?;
            let now = authority_now(tx)?;
            record.check_revocation(reviewer, now)?;
            tx.execute(
                "UPDATE connection_mutation_approvals
                 SET status='revoked', revoker_issuer=?2, revoker_subject=?3, revoked_at=?4 WHERE id=?1",
                params![id.to_string(), reviewer.issuer, reviewer.subject, now],
            )?;
            load_approval(tx, id)
        })
    }

    pub fn consume_mutation_approval(
        &self,
        id: Uuid,
        action: &MutationAction,
    ) -> Result<ConsumedMutationApproval, ApprovalError> {
        action.validate()?;
        self.approval_transaction(|tx| {
            let record = load_approval(tx, id)?;
            record.check_consumption(action, authority_now(tx)?)?;
            self.check_approval_generation(tx, action)?;
            let now = authority_now(tx)?;
            record.ensure_live(now)?;
            let changed = tx.execute(
                "UPDATE connection_mutation_approvals
                 SET status='consumed', consumed_at=?2 WHERE id=?1 AND status='approved'",
                params![id.to_string(), now],
            )?;
            if changed != 1 {
                return Err(ApprovalError::Conflict);
            }
            Ok(ConsumedMutationApproval::new(id))
        })
    }
}
