//! Authenticated review of one server-prepared Connection mutation.
use super::*;

use connections::mutation_approval::{
    ApprovalDecision, ApprovalError, ApprovalPrincipal, MutationApproval,
};
use connections::permissions::ADMIN_MUTATION_APPROVAL_REVIEW;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationReview {
    decision: ApprovalDecision,
}

#[derive(Clone, Copy)]
enum ApprovalOperation {
    Read,
    Review,
    Revoke,
}

impl ApprovalOperation {
    fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Review => "review",
            Self::Revoke => "revoke",
        }
    }
}

pub(super) async fn tool_mutation_approval_get_endpoint(
    State(state): State<ToolAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(MUTATION_APPROVAL_ROUTE);
    review_operation(state, &id, request, ApprovalOperation::Read).await
}

pub(super) async fn tool_mutation_approval_review_endpoint(
    State(state): State<ToolAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(MUTATION_APPROVAL_REVIEW_ROUTE);
    review_operation(state, &id, request, ApprovalOperation::Review).await
}

pub(super) async fn tool_mutation_approval_revoke_endpoint(
    State(state): State<ToolAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(MUTATION_APPROVAL_REVOKE_ROUTE);
    review_operation(state, &id, request, ApprovalOperation::Revoke).await
}

async fn review_operation(
    state: ToolAdminState,
    raw_id: &str,
    request: AxumRequest,
    operation: ApprovalOperation,
) -> Response {
    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>() else {
        return unauthorized();
    };
    let Some(caller) = connections::caller_assertion::AttestedCaller::from_principal(principal)
    else {
        return mutation_approval_denied(&state, &parts, principal, operation.name());
    };
    let Ok(identity) = ApprovalPrincipal::from_caller(&caller) else {
        return mutation_approval_denied(&state, &parts, principal, operation.name());
    };
    let Some(rbac) = state.rbac_state.as_ref() else {
        return service_unavailable("mutation approval authorization is unavailable");
    };
    let reviewer = rbac.principal_has_permission(principal, ADMIN_MUTATION_APPROVAL_REVIEW);
    if !(reviewer
        || matches!(operation, ApprovalOperation::Read)
            && rbac.principal_has_permission(principal, ADMIN_TOOLS_EXECUTE_PERMISSION))
    {
        return mutation_approval_denied(&state, &parts, principal, operation.name());
    }
    let Ok(id) = uuid::Uuid::parse_str(raw_id) else {
        return not_found("mutation approval was not found");
    };
    let Ok(store) = state.connections.managed_store() else {
        return mutation_approval_result(
            &state,
            &parts,
            principal,
            operation.name(),
            Some(id),
            Err(ApprovalError::Unavailable),
            StatusCode::OK,
        );
    };
    let result = match operation {
        ApprovalOperation::Read => match store.mutation_approval(id).await {
            Ok(record) if !reviewer && record.action.caller != identity => {
                Err(ApprovalError::NotFound)
            }
            result => result,
        },
        ApprovalOperation::Review => {
            let body = match read_request_body(body, state.max_body_size.min(1024)).await {
                Ok(body) => body,
                Err(response) => return *response,
            };
            let Ok(review) = serde_json::from_slice::<MutationReview>(&body) else {
                return bad_request("mutation approval decision is invalid");
            };
            store
                .decide_mutation_approval(
                    id,
                    identity,
                    review.decision,
                    recheck_reviewer(rbac.clone(), principal.clone()),
                )
                .await
        }
        ApprovalOperation::Revoke => {
            match read_request_body(body, 0).await {
                Ok(_) => {}
                Err(response) => return *response,
            }
            store
                .revoke_mutation_approval(
                    id,
                    identity,
                    recheck_reviewer(rbac.clone(), principal.clone()),
                )
                .await
        }
    };
    mutation_approval_result(
        &state,
        &parts,
        principal,
        operation.name(),
        Some(id),
        result,
        StatusCode::OK,
    )
}

// SQLite invokes this under its write lock. PostgreSQL checks the returned
// policy activation again under the lock used by policy publication.
fn recheck_reviewer(
    rbac: middleware::rbac::RbacState,
    principal: auth::Principal,
) -> impl FnOnce() -> Result<i64, ApprovalError> {
    move || {
        rbac.granting_policy_revision(&principal, ADMIN_MUTATION_APPROVAL_REVIEW)
            .ok_or(ApprovalError::Conflict)
    }
}

pub(super) fn mutation_approval_denied(
    state: &ToolAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    operation: &'static str,
) -> Response {
    let payload = json!({
        "operation": operation,
        "outcome": "failure",
        "reason": "permission_denied",
    });
    audit_mutation_approval(state, parts, principal, payload);
    forbidden()
}

fn audit_mutation_approval(
    state: &ToolAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    payload: Value,
) {
    state.audit.emit(audit::AuditEvent::new(
        audit::event::CONNECTION_MUTATION_APPROVAL,
        client_ip::request_id(&parts.headers, &parts.extensions),
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy),
        Some(auth::actor_from_principal(principal)),
        payload,
    ));
}

pub(super) fn mutation_approval_result(
    state: &ToolAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    operation: &'static str,
    id: Option<uuid::Uuid>,
    result: Result<MutationApproval, ApprovalError>,
    status: StatusCode,
) -> Response {
    match result {
        Ok(record) => {
            audit_mutation_approval(
                state,
                parts,
                principal,
                json!({
                    "operation": operation,
                    "outcome": "success",
                    "approval_id": record.id.to_string(),
                    "connection_id": record.action.connection_id,
                    "status": record.status,
                }),
            );
            (
                status,
                [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
                Json(record),
            )
                .into_response()
        }
        Err(error) => {
            audit_mutation_approval(
                state,
                parts,
                principal,
                json!({
                    "operation": operation,
                    "outcome": "failure",
                    "approval_id": id.map(|id| id.to_string()),
                    "reason": error.safe_reason(),
                }),
            );
            let status = match error {
                ApprovalError::Invalid => StatusCode::BAD_REQUEST,
                ApprovalError::NotFound => StatusCode::NOT_FOUND,
                ApprovalError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                ApprovalError::Capacity => StatusCode::TOO_MANY_REQUESTS,
                ApprovalError::SelfReview => StatusCode::FORBIDDEN,
                ApprovalError::Expired => StatusCode::GONE,
                ApprovalError::Conflict | ApprovalError::Mismatch => StatusCode::CONFLICT,
            };
            (
                status,
                [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
                Json(json!({
                    "error": "mutation approval request failed",
                    "reason": error.safe_reason(),
                })),
            )
                .into_response()
        }
    }
}
