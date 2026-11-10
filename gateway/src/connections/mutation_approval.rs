//! One review of one rendered mutation. Only the executor constructs an action from
//! the admitted caller, active catalog definition and resolved request. Persistence
//! holds digests in place of the potentially sensitive target and body.

use std::fmt;

use http::Method;
use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;

use super::{
    caller_assertion::{body_digest, AttestedCaller},
    http::ConnectionHttpTarget,
    model::ConnectionId,
    openapi::definition_digest,
};
use crate::{
    auth::principal::canonical_issuer,
    tools::definitions::{ToolDefinition, ToolSource, ToolTarget},
};

pub const APPROVAL_LIFETIME_SECS: i64 = 900;
pub const MAX_APPROVALS: i64 = 1024;
pub const MAX_APPROVALS_PER_CALLER: i64 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalError {
    Invalid,
    NotFound,
    Unavailable,
    Capacity,
    SelfReview,
    Expired,
    Conflict,
    Mismatch,
}

impl ApprovalError {
    pub fn safe_reason(self) -> &'static str {
        match self {
            Self::Invalid => "mutation_approval_invalid",
            Self::NotFound => "mutation_approval_not_found",
            Self::Unavailable => "mutation_approval_unavailable",
            Self::Capacity => "mutation_approval_capacity",
            Self::SelfReview => "mutation_approval_self_review",
            Self::Expired => "mutation_approval_expired",
            Self::Conflict => "mutation_approval_state_conflict",
            Self::Mismatch => "mutation_approval_mismatch",
        }
    }
}

fn bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalPrincipal {
    pub(super) issuer: String,
    pub(super) subject: String,
}

impl ApprovalPrincipal {
    pub fn from_caller(caller: &AttestedCaller) -> Result<Self, ApprovalError> {
        let identity = caller.identity();
        let principal = Self {
            issuer: identity.issuer.to_owned(),
            subject: identity.subject.to_owned(),
        };
        principal.validate()?;
        Ok(principal)
    }

    pub(super) fn validate(&self) -> Result<(), ApprovalError> {
        if bounded_text(&self.issuer, 512)
            && !self.issuer.contains('#')
            && canonical_issuer(&self.issuer).as_ref() == Some(&self.issuer)
            && bounded_text(&self.subject, 256)
        {
            Ok(())
        } else {
            Err(ApprovalError::Invalid)
        }
    }
}

/// Caller-owned identity for one keyed preparation. Only the bounded digest
/// enters storage; the argument bytes and execution ETag never reach the
/// receipt or journal projection.
#[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Only the PostgreSQL authority stores bindings.
#[derive(Clone)]
pub(crate) struct PrepareBinding {
    pub(crate) id: uuid::Uuid,
    pub(crate) actor: crate::auth::change_actor::ChangeActor,
    pub(crate) request_digest: String,
}

impl PrepareBinding {
    pub(crate) fn new(
        id: uuid::Uuid,
        actor: crate::auth::change_actor::ChangeActor,
        tool_id: &str,
        etag: &str,
        request_body: &[u8],
    ) -> Result<Self, ApprovalError> {
        use sha2::{Digest, Sha256};
        if !crate::auth::tokens::valid_caller_operation_id(id)
            || !actor.can_bind_operation()
            || actor.kind() != crate::auth::change_actor::ActorKind::Principal
        {
            return Err(ApprovalError::Invalid);
        }
        let mut digest = Sha256::new();
        digest.update(b"greengateway.approval.prepare.request.v1");
        for field in [tool_id.as_bytes(), etag.as_bytes(), request_body] {
            digest.update((field.len() as u64).to_be_bytes());
            digest.update(field);
        }
        Ok(Self {
            id,
            actor,
            request_digest: hex::encode(digest.finalize()),
        })
    }
}

/// Immutable result of committing a pending occurrence. The occurrence can
/// subsequently expire, be reviewed or be removed independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct PrepareReceipt {
    pub(crate) operation_id: String,
    pub(crate) occurrence_id: String,
    pub(crate) prepared_at: i64,
    pub(crate) expires_at: i64,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct MutationAction {
    pub caller: ApprovalPrincipal,
    pub connection_id: ConnectionId,
    pub connection_etag: String,
    pub catalog_revision: u64,
    pub tool_name: String,
    pub operation: String,
    pub definition_sha256: String,
    pub method: String,
    pub target_sha256: String,
    pub body_sha256: String,
}

impl fmt::Debug for MutationAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationAction")
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

impl MutationAction {
    pub fn for_http_tool(
        caller: &AttestedCaller,
        target: &ConnectionHttpTarget,
        tool: &ToolDefinition,
        method: &Method,
        body: &[u8],
    ) -> Result<Self, ApprovalError> {
        let (
            ToolSource::OpenApi {
                connection_id,
                operation_id: Some(operation),
                catalog_revision: Some(revision),
            },
            Some(ToolTarget::Http {
                connection_id: target_id,
                mapping,
            }),
        ) = (&tool.source, &tool.target)
        else {
            return Err(ApprovalError::Invalid);
        };
        if connection_id != target_id
            || target_id != target.connection_id().as_str()
            || tool.composite.is_some()
            || mapping != &tool.upstream
            || tool.upstream.method != method.as_str()
        {
            return Err(ApprovalError::Invalid);
        }
        // Parse through the same URL type as the HTTP transport, including the
        // effective origin and the final path-and-query in their wire encoding.
        let url = url::Url::parse(target.url()).map_err(|_| ApprovalError::Invalid)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(ApprovalError::Invalid);
        }
        let action = Self {
            caller: ApprovalPrincipal::from_caller(caller)?,
            connection_id: target.connection_id().clone(),
            connection_etag: target.connection_etag().to_owned(),
            catalog_revision: *revision,
            tool_name: tool.name.clone(),
            operation: operation.clone(),
            definition_sha256: hex::encode(
                definition_digest(tool).map_err(|_| ApprovalError::Invalid)?,
            ),
            method: method.as_str().to_owned(),
            target_sha256: body_digest(url.as_str().as_bytes()),
            body_sha256: body_digest(body),
        };
        action.validate()?;
        Ok(action)
    }

    pub(super) fn check_stored_definition(
        &self,
        value: serde_json::Value,
    ) -> Result<(), ApprovalError> {
        let definition: ToolDefinition =
            serde_json::from_value(value).map_err(|_| ApprovalError::Unavailable)?;
        let source_matches = matches!(&definition.source, ToolSource::OpenApi {
            connection_id, operation_id: Some(operation), catalog_revision: Some(revision)
        } if connection_id == self.connection_id.as_str() && operation == &self.operation && *revision == self.catalog_revision);
        let target_matches = matches!(&definition.target, Some(ToolTarget::Http { connection_id, mapping })
            if connection_id == self.connection_id.as_str() && mapping == &definition.upstream);
        if !source_matches
            || !target_matches
            || definition.name != self.tool_name
            || definition.upstream.method != self.method
            || definition.composite.is_some()
        {
            return Err(ApprovalError::Mismatch);
        }
        let digest = definition_digest(&definition).map_err(|_| ApprovalError::Unavailable)?;
        if hex::encode(digest) != self.definition_sha256 {
            return Err(ApprovalError::Mismatch);
        }
        Ok(())
    }

    pub(super) fn validate(&self) -> Result<(), ApprovalError> {
        self.caller.validate()?;
        let digests = [
            &self.definition_sha256,
            &self.target_sha256,
            &self.body_sha256,
        ];
        if bounded_text(&self.connection_etag, 256)
            && self.catalog_revision > 0
            && i64::try_from(self.catalog_revision).is_ok()
            && bounded_text(&self.tool_name, 512)
            && bounded_text(&self.operation, 1024)
            && matches!(self.method.as_str(), "POST" | "PATCH" | "PUT" | "DELETE")
            && digests.into_iter().all(|digest| {
                digest.len() == 64
                    && digest
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            })
        {
            Ok(())
        } else {
            Err(ApprovalError::Invalid)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Revoked,
    Consumed,
    /// Projected against the authority clock on read.
    Expired,
}

impl ApprovalStatus {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
            Self::Revoked => "revoked",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, ApprovalError> {
        match value {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "rejected" => Ok(Self::Rejected),
            "revoked" => Ok(Self::Revoked),
            "consumed" => Ok(Self::Consumed),
            _ => Err(ApprovalError::Unavailable),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

impl ApprovalDecision {
    pub(super) fn status(self) -> ApprovalStatus {
        match self {
            Self::Approve => ApprovalStatus::Approved,
            Self::Reject => ApprovalStatus::Rejected,
        }
    }
}

fn serialize_id<S: Serializer>(id: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(id)
}

#[derive(Clone, Serialize)]
pub struct MutationApproval {
    #[serde(serialize_with = "serialize_id")]
    pub id: Uuid,
    pub action: MutationAction,
    pub status: ApprovalStatus,
    pub created_at: i64,
    pub expires_at: i64,
    pub reviewer: Option<ApprovalPrincipal>,
    pub reviewed_at: Option<i64>,
    pub revoked_by: Option<ApprovalPrincipal>,
    pub revoked_at: Option<i64>,
    pub consumed_at: Option<i64>,
}

impl fmt::Debug for MutationApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MutationApproval")
            .field("id", &self.id)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl MutationApproval {
    /// Validate all persisted fields, including consistency between the review,
    /// revocation, consumption and lifetime, before trusting any row.
    pub(super) fn validate(&self) -> Result<(), ApprovalError> {
        self.action
            .validate()
            .map_err(|_| ApprovalError::Unavailable)?;
        let reviewed = self.reviewed_at.is_some();
        let revoked = self.revoked_at.is_some();
        let consumed = self.consumed_at.is_some();
        let consistent = match self.status {
            ApprovalStatus::Pending => !reviewed && !revoked && !consumed,
            ApprovalStatus::Approved | ApprovalStatus::Rejected => {
                reviewed && !revoked && !consumed
            }
            ApprovalStatus::Revoked => revoked && !consumed,
            ApprovalStatus::Consumed => reviewed && !revoked && consumed,
            ApprovalStatus::Expired => false,
        };
        if !consistent
            || self.id.is_nil()
            || self.created_at < 0
            || self.created_at.checked_add(APPROVAL_LIFETIME_SECS) != Some(self.expires_at)
            || self.reviewer.is_some() != reviewed
            || self.revoked_by.is_some() != revoked
        {
            return Err(ApprovalError::Unavailable);
        }
        for actor in [self.reviewer.as_ref(), self.revoked_by.as_ref()]
            .into_iter()
            .flatten()
        {
            actor.validate().map_err(|_| ApprovalError::Unavailable)?;
            if *actor == self.action.caller {
                return Err(ApprovalError::Unavailable);
            }
        }
        let mut previous = self.created_at;
        for time in [self.reviewed_at, self.revoked_at, self.consumed_at]
            .into_iter()
            .flatten()
        {
            if !(previous..self.expires_at).contains(&time) {
                return Err(ApprovalError::Unavailable);
            }
            previous = time;
        }
        Ok(())
    }

    pub(super) fn status_at(&self, now: i64) -> Result<ApprovalStatus, ApprovalError> {
        self.validate()?;
        if now < self.created_at
            || [self.reviewed_at, self.revoked_at, self.consumed_at]
                .into_iter()
                .flatten()
                .any(|time| now < time)
        {
            return Err(ApprovalError::Unavailable);
        }
        if now >= self.expires_at
            && matches!(
                self.status,
                ApprovalStatus::Pending | ApprovalStatus::Approved
            )
        {
            Ok(ApprovalStatus::Expired)
        } else {
            Ok(self.status)
        }
    }

    pub(super) fn ensure_live(&self, now: i64) -> Result<(), ApprovalError> {
        self.status_at(now)?;
        if now >= self.expires_at {
            Err(ApprovalError::Expired)
        } else {
            Ok(())
        }
    }

    fn independent_reviewer(
        &self,
        reviewer: &ApprovalPrincipal,
        now: i64,
    ) -> Result<(), ApprovalError> {
        self.ensure_live(now)?;
        reviewer.validate()?;
        if *reviewer == self.action.caller {
            Err(ApprovalError::SelfReview)
        } else {
            Ok(())
        }
    }

    pub(super) fn check_decision(
        &self,
        reviewer: &ApprovalPrincipal,
        now: i64,
    ) -> Result<(), ApprovalError> {
        self.independent_reviewer(reviewer, now)?;
        if self.status == ApprovalStatus::Pending {
            Ok(())
        } else {
            Err(ApprovalError::Conflict)
        }
    }

    pub(super) fn check_revocation(
        &self,
        reviewer: &ApprovalPrincipal,
        now: i64,
    ) -> Result<(), ApprovalError> {
        self.independent_reviewer(reviewer, now)?;
        if matches!(
            self.status,
            ApprovalStatus::Approved | ApprovalStatus::Pending
        ) {
            Ok(())
        } else {
            Err(ApprovalError::Conflict)
        }
    }

    pub(super) fn check_consumption(
        &self,
        action: &MutationAction,
        now: i64,
    ) -> Result<(), ApprovalError> {
        if self.action.caller != action.caller {
            return Err(ApprovalError::NotFound);
        }
        self.ensure_live(now)?;
        if &self.action != action {
            return Err(ApprovalError::Mismatch);
        }
        if self.status == ApprovalStatus::Approved {
            Ok(())
        } else {
            Err(ApprovalError::Conflict)
        }
    }
}

/// Issued only after the authority commits the one-shot transition to consumed.
#[derive(Debug)]
pub struct ConsumedMutationApproval {
    id: Uuid,
    action: MutationAction,
    consumed_at: i64,
    expires_at: i64,
}

impl ConsumedMutationApproval {
    pub(super) fn new(record: MutationApproval, consumed_at: i64) -> Self {
        Self {
            id: record.id,
            action: record.action,
            consumed_at,
            expires_at: record.expires_at,
        }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Rebind the committed decision to the actual outbound call. A clock behind
    /// the authority's consumption time cannot safely attest its lifetime.
    pub(super) fn verify_for_signing(
        &self,
        action: &MutationAction,
        issued_at: u64,
    ) -> Result<u64, ApprovalError> {
        if &self.action != action {
            return Err(ApprovalError::Mismatch);
        }
        let consumed_at =
            u64::try_from(self.consumed_at).map_err(|_| ApprovalError::Unavailable)?;
        let expires_at = u64::try_from(self.expires_at).map_err(|_| ApprovalError::Unavailable)?;
        if issued_at < consumed_at {
            return Err(ApprovalError::Unavailable);
        }
        if issued_at >= expires_at {
            return Err(ApprovalError::Expired);
        }
        Ok(expires_at)
    }
}
