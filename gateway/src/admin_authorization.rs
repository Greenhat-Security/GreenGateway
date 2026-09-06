//! admin authorization boundary extracted from the application composition root.
use super::*;

pub(super) fn authorized_policy_state<'a>(
    state: &'a PolicyAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, PolicyAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(PolicyAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(PolicyAdminAuthzError::Forbidden(permission.to_owned()));
    }

    Ok(rbac_state)
}

pub(super) fn authorized_connection_state<'a>(
    state: &'a ConnectionAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, ConnectionAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(ConnectionAdminAuthzError::RbacNotConfigured);
    };
    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(ConnectionAdminAuthzError::Forbidden(permission.to_owned()));
    }
    Ok(rbac_state)
}

pub(super) fn connection_permissions(
    rbac_state: &middleware::rbac::RbacState,
    principal: &auth::Principal,
) -> connections::admin::ConnectionPermissions {
    connections::admin::ConnectionPermissions {
        read: rbac_state.principal_has_permission(principal, ADMIN_CONNECTIONS_READ_PERMISSION),
        write: rbac_state.principal_has_permission(principal, ADMIN_CONNECTIONS_WRITE_PERMISSION),
        secrets_write: rbac_state
            .principal_has_permission(principal, ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION),
        test: rbac_state.principal_has_permission(principal, ADMIN_CONNECTIONS_TEST_PERMISSION),
        refresh: rbac_state
            .principal_has_permission(principal, ADMIN_CONNECTIONS_REFRESH_PERMISSION),
    }
}

pub(super) fn authorized_audit_state<'a>(
    state: &'a AuditAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, AdminReadAuthzError> {
    authorized_admin_rbac_state(state.rbac_state.as_ref(), principal, permission)
}

pub(super) fn authorized_status_state<'a>(
    state: &'a StatusAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, AdminReadAuthzError> {
    authorized_admin_rbac_state(state.rbac_state.as_ref(), principal, permission)
}

pub(super) fn authorized_admin_rbac_state<'a>(
    rbac_state: Option<&'a middleware::rbac::RbacState>,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, AdminReadAuthzError> {
    let Some(rbac_state) = rbac_state else {
        return Err(AdminReadAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(AdminReadAuthzError::Forbidden(permission.to_owned()));
    }

    Ok(rbac_state)
}

pub(super) fn authorized_token_store<'a>(
    state: &'a TokenAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a Arc<dyn storage::ServiceTokenStore>, TokenAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(TokenAdminAuthzError::RbacNotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(TokenAdminAuthzError::Forbidden(permission.to_owned()));
    }

    state
        .store
        .as_ref()
        .ok_or(TokenAdminAuthzError::StoreNotConfigured)
}

/// Service-token creation and rotation may not exceed the actor's own authority.
/// An actor holding an identity-matched wildcard role may delegate any scope;
/// otherwise every scope must be a policy role the actor carries
/// and can activate under its current identity.
pub(super) fn authorize_requested_scopes(
    rbac_state: &middleware::rbac::RbacState,
    creator: &auth::Principal,
    requested_scopes: &[String],
) -> Result<(), TokenScopeAuthzError> {
    let disallowed = rbac_state.disallowed_delegated_roles(creator, requested_scopes);

    if disallowed.is_empty() {
        Ok(())
    } else {
        Err(TokenScopeAuthzError { disallowed })
    }
}

pub(super) fn authorized_tool_rbac_state<'a>(
    state: &'a ToolAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, ToolAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(ToolAdminAuthzError::RbacNotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(ToolAdminAuthzError::Forbidden(permission.to_owned()));
    }

    Ok(rbac_state)
}

pub(super) fn tool_playground_permission_forbidden(
    state: &ToolAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
) -> Response {
    state.audit.emit(audit::AuditEvent::new(
        "authz.denied",
        client_ip::request_id(&parts.headers, &parts.extensions),
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy),
        Some(auth::actor_from_principal(principal)),
        json!({
            "path": TOOL_EXECUTE_ADMIN_ROUTE,
            "method": parts.method.as_str(),
            "reason": "missing_permission",
            "permission": ADMIN_TOOLS_EXECUTE_PERMISSION,
            "authorization_layer": "tool_playground_endpoint",
            "operation": "execute",
            "invocation_source": "admin_playground",
        }),
    ));
    forbidden()
}

pub(super) fn authorized_schema_reader(
    state: &SchemaAdminState,
    principal: &auth::Principal,
) -> bool {
    state.rbac_state.as_ref().is_some_and(|rbac_state| {
        rbac_state.principal_has_permission(principal, ADMIN_SCHEMA_READ_PERMISSION)
    })
}

pub(super) fn authorized_traffic_state<'a>(
    state: &'a TrafficAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, TrafficAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(TrafficAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(TrafficAdminAuthzError::Forbidden(permission.to_owned()));
    }

    Ok(rbac_state)
}

pub(super) fn authorized_principal_state<'a>(
    state: &'a PrincipalAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, PrincipalAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(PrincipalAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(PrincipalAdminAuthzError::Forbidden(permission.to_owned()));
    }

    Ok(rbac_state)
}

pub(super) fn authorized_signals_state<'a>(
    state: &'a SignalsAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, SignalsAdminAuthzError> {
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return Err(SignalsAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(SignalsAdminAuthzError::Forbidden(permission.to_owned()));
    }

    Ok(rbac_state)
}

pub(super) fn authorized_suggestions_state<'a>(
    state: &'a SuggestionsAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> Result<&'a middleware::rbac::RbacState, SuggestionsAdminAuthzError> {
    let Some(rbac_state) = state.policy.rbac_state.as_ref() else {
        return Err(SuggestionsAdminAuthzError::NotConfigured);
    };

    if !rbac_state.principal_has_permission(principal, permission) {
        return Err(SuggestionsAdminAuthzError::Forbidden(permission.to_owned()));
    }

    Ok(rbac_state)
}

pub(super) fn policy_admin_authz_error_response(error: PolicyAdminAuthzError) -> Response {
    match error {
        PolicyAdminAuthzError::NotConfigured => policy_not_configured(),
        PolicyAdminAuthzError::Forbidden(permission) => {
            admin_permission_denied_response(permission)
        }
    }
}

pub(super) fn audit_admin_authz_error_response(error: AdminReadAuthzError) -> Response {
    match error {
        AdminReadAuthzError::NotConfigured => audit_rbac_not_configured(),
        AdminReadAuthzError::Forbidden(permission) => admin_permission_denied_response(permission),
    }
}

pub(super) fn status_admin_authz_error_response(error: AdminReadAuthzError) -> Response {
    match error {
        AdminReadAuthzError::NotConfigured => status_rbac_not_configured(),
        AdminReadAuthzError::Forbidden(permission) => admin_permission_denied_response(permission),
    }
}

pub(super) fn cluster_admin_authz_error_response(error: AdminReadAuthzError) -> Response {
    match error {
        AdminReadAuthzError::NotConfigured => cluster_rbac_not_configured(),
        AdminReadAuthzError::Forbidden(permission) => admin_permission_denied_response(permission),
    }
}

pub(super) fn token_admin_authz_error_response(error: TokenAdminAuthzError) -> Response {
    match error {
        TokenAdminAuthzError::StoreNotConfigured => token_store_not_configured(),
        TokenAdminAuthzError::RbacNotConfigured => token_rbac_not_configured(),
        TokenAdminAuthzError::Forbidden(permission) => admin_permission_denied_response(permission),
    }
}

pub(super) fn connection_admin_authz_error_response(error: ConnectionAdminAuthzError) -> Response {
    match error {
        ConnectionAdminAuthzError::RbacNotConfigured => connection_rbac_not_configured(),
        ConnectionAdminAuthzError::Forbidden(permission) => {
            admin_permission_denied_response(permission)
        }
    }
}

pub(super) fn token_scope_authz_error_response(error: TokenScopeAuthzError) -> Response {
    let mut disallowed = error.disallowed;
    disallowed.sort();
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: format!(
                "requested scopes exceed creator authority: {}",
                disallowed.join(", ")
            ),
        }),
    )
        .into_response()
}

pub(super) fn tool_admin_authz_error_response(error: ToolAdminAuthzError) -> Response {
    match error {
        ToolAdminAuthzError::RbacNotConfigured => tools_rbac_not_configured(),
        ToolAdminAuthzError::ToolsFileNotConfigured => tools_file_not_configured(),
        ToolAdminAuthzError::Forbidden(permission) => admin_permission_denied_response(permission),
    }
}

pub(super) fn capability_inventory_error_response(
    error: tools::inventory::CapabilityInventoryError,
) -> Response {
    use tools::inventory::CapabilityInventoryError;

    match error {
        CapabilityInventoryError::InvalidLimit => {
            bad_request("capability inventory limit must be between 1 and 100")
        }
        CapabilityInventoryError::InvalidFilter => {
            bad_request("capability inventory filter is invalid")
        }
        CapabilityInventoryError::InvalidCursor => {
            bad_request("capability inventory cursor is invalid")
        }
        CapabilityInventoryError::StaleCursor { current_etag } => (
            StatusCode::PRECONDITION_FAILED,
            [
                (header::ETAG, etag_header_value(&current_etag)),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            Json(ErrorResponse {
                error: "capability inventory cursor does not match the current collection"
                    .to_owned(),
            }),
        )
            .into_response(),
        CapabilityInventoryError::StoreUnavailable => {
            tracing::error!(
                reason = "store_unavailable",
                "capability inventory request failed"
            );
            service_unavailable("capability inventory is unavailable")
        }
        CapabilityInventoryError::CardinalityExceeded => {
            tracing::error!(
                reason = "cardinality_exceeded",
                "capability inventory request failed"
            );
            service_unavailable("capability inventory is unavailable")
        }
        CapabilityInventoryError::CorruptState => {
            tracing::error!(
                reason = "corrupt_state",
                "capability inventory request failed"
            );
            service_unavailable("capability inventory is unavailable")
        }
        CapabilityInventoryError::ResponseTooLarge => {
            tracing::error!(
                reason = "response_too_large",
                "capability inventory response failed"
            );
            internal_server_error("capability inventory response failed")
        }
        CapabilityInventoryError::IdentityCollision => {
            tracing::error!(
                reason = "identity_collision",
                "capability inventory response failed"
            );
            internal_server_error("capability inventory response failed")
        }
    }
}

pub(super) fn tool_playground_runtime_error_response(
    error: tools::runtime::ToolRuntimeError,
    composite_request_id: Option<&str>,
) -> Response {
    use tools::runtime::ToolRuntimeError;

    match error {
        ToolRuntimeError::UnknownTool { .. } => tool_playground_error_response(
            StatusCode::NOT_FOUND,
            "tool was not found",
            "unknown_tool",
        ),
        ToolRuntimeError::Disabled { .. } => tool_playground_error_response(
            StatusCode::CONFLICT,
            "tool execution is unavailable",
            "disabled",
        ),
        ToolRuntimeError::RoleDenied { .. } => tool_playground_error_response(
            StatusCode::FORBIDDEN,
            "tool execution was denied",
            "policy_denied",
        ),
        ToolRuntimeError::Rejected { reason, .. } => match reason.as_str() {
            "precondition_failed" => tool_playground_error_response(
                StatusCode::PRECONDITION_FAILED,
                "tool execution precondition failed",
                "precondition_failed",
            ),
            "queue_full" => tool_playground_error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "tool execution admission is full",
                "queue_full",
            ),
            "runtime_closed" => tool_playground_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "tool executor is unavailable",
                "execution_state_unavailable",
            ),
            _ => tool_playground_error_response(
                StatusCode::FORBIDDEN,
                "tool execution was denied",
                "policy_denied",
            ),
        },
        ToolRuntimeError::QueueTimeout { .. } => tool_playground_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "tool execution admission timed out",
            "queue_timeout",
        ),
        ToolRuntimeError::Timeout { .. } => tool_playground_runtime_unavailable_response(
            StatusCode::GATEWAY_TIMEOUT,
            "tool execution timed out",
            "timeout",
            composite_request_id,
        ),
        ToolRuntimeError::Cancelled { .. } => tool_playground_runtime_unavailable_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "tool execution was cancelled",
            "cancelled",
            composite_request_id,
        ),
        ToolRuntimeError::AuthorityUnavailable { .. } => tool_playground_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "tool execution admission authority is unavailable",
            "authority_unavailable",
        ),
        ToolRuntimeError::LeaseLost { .. } => tool_playground_runtime_unavailable_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "tool execution lost its execution lease",
            "lease_lost",
            composite_request_id,
        ),
        ToolRuntimeError::WorkFailed {
            reason,
            details: Some(details),
            ..
        } if matches!(
            reason.as_deref(),
            Some("composite_failed" | "composite_failed_compensation_incomplete")
        ) =>
        {
            let mut details = tools::playground::project_composite_failure_details(details);
            details["error"] = json!("tool execution failed");
            (StatusCode::BAD_GATEWAY, Json(details)).into_response()
        }
        ToolRuntimeError::WorkFailed {
            reason, details, ..
        } => match reason.as_deref() {
            Some("invalid_params") => tool_playground_error_response_with_details(
                StatusCode::UNPROCESSABLE_ENTITY,
                "tool arguments were rejected",
                "invalid_params",
                details,
            ),
            Some("unknown_tool") => tool_playground_error_response(
                StatusCode::NOT_FOUND,
                "tool was not found",
                "unknown_tool",
            ),
            Some("execution_state_unavailable") => tool_playground_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "tool execution state is unavailable",
                "execution_state_unavailable",
            ),
            Some("enum_source_unavailable") => tool_playground_error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "allowed tool values are currently unavailable",
                "enum_source_unavailable",
            ),
            Some(
                "connection_disabled"
                | "connection_not_found"
                | "connection_kind_mismatch"
                | "catalog_stale"
                | "catalog_not_registered",
            ) => tool_playground_error_response(
                StatusCode::CONFLICT,
                "tool execution is unavailable",
                "unavailable",
            ),
            _ => tool_playground_error_response(
                StatusCode::BAD_GATEWAY,
                "tool execution failed",
                "execution_failed",
            ),
        },
    }
}

pub(super) fn tool_playground_runtime_unavailable_response(
    status: StatusCode,
    error: &'static str,
    reason: &'static str,
    composite_request_id: Option<&str>,
) -> Response {
    let Some(request_id) = composite_request_id else {
        return tool_playground_error_response(status, error, reason);
    };
    (
        status,
        Json(json!({
            "error": error,
            "reason": reason,
            "request_id": request_id,
            "composite": "pending_compensation",
        })),
    )
        .into_response()
}

pub(super) fn tool_playground_error_response(
    status: StatusCode,
    error: &'static str,
    reason: &'static str,
) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "reason": reason,
        })),
    )
        .into_response()
}

pub(super) fn tool_playground_error_response_with_details(
    status: StatusCode,
    error: &'static str,
    reason: &'static str,
    details: Option<Value>,
) -> Response {
    let Some(details) = details else {
        return tool_playground_error_response(status, error, reason);
    };
    let mut body = serde_json::Map::from_iter([
        ("error".to_owned(), Value::String(error.to_owned())),
        ("reason".to_owned(), Value::String(reason.to_owned())),
    ]);
    match details {
        Value::Object(details) => {
            for (key, value) in details {
                if key != "error" && key != "reason" {
                    body.insert(key, value);
                }
            }
        }
        details => {
            body.insert("details".to_owned(), details);
        }
    }
    (status, Json(Value::Object(body))).into_response()
}

pub(super) fn traffic_admin_authz_error_response(error: TrafficAdminAuthzError) -> Response {
    match error {
        TrafficAdminAuthzError::NotConfigured => traffic_rbac_not_configured(),
        TrafficAdminAuthzError::Forbidden(permission) => {
            admin_permission_denied_response(permission)
        }
    }
}

pub(super) fn principal_admin_authz_error_response(error: PrincipalAdminAuthzError) -> Response {
    match error {
        PrincipalAdminAuthzError::NotConfigured => principal_rbac_not_configured(),
        PrincipalAdminAuthzError::Forbidden(permission) => {
            admin_permission_denied_response(permission)
        }
    }
}

pub(super) fn signals_admin_authz_error_response(error: SignalsAdminAuthzError) -> Response {
    match error {
        SignalsAdminAuthzError::NotConfigured => signals_rbac_not_configured(),
        SignalsAdminAuthzError::Forbidden(permission) => {
            admin_permission_denied_response(permission)
        }
    }
}

pub(super) fn suggestions_admin_authz_error_response(
    error: SuggestionsAdminAuthzError,
) -> Response {
    match error {
        SuggestionsAdminAuthzError::NotConfigured => suggestions_rbac_not_configured(),
        SuggestionsAdminAuthzError::Forbidden(permission) => {
            admin_permission_denied_response(permission)
        }
    }
}
