//! admin events boundary extracted from the application composition root.
use super::*;

pub(super) fn emit_policy_rule_changed(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    before: &rbac::Policy,
    after: &rbac::Policy,
    diff_summary: Value,
) {
    let mut payload = policy_change_payload(before, after);
    if let Some(payload) = payload.as_object_mut() {
        payload.insert("diff_summary".to_owned(), diff_summary);
    }

    emit_policy_changed_payload(state, parts, principal, payload);
}

pub(super) fn emit_policy_changed_payload(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    payload: Value,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let actor = Some(auth::actor_from_principal(principal));

    state.audit.emit(audit::AuditEvent::new(
        audit::event::POLICY_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

pub(super) fn emit_service_token_changed(
    state: &TokenAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    action: &'static str,
    record: &auth::tokens::TokenRecord,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let actor = Some(auth::actor_from_principal(principal));
    let mut payload = json!({
        "action": action,
        "token_id": &record.id,
        "token_prefix": &record.token_prefix,
        "scopes": &record.scopes,
        "created_by": &record.created_by,
    });
    if let Some(expires_at) = record.expires_at.as_deref() {
        payload["expires_at"] = json!(expires_at);
    }
    if let Some(revoked_at) = record.revoked_at.as_deref() {
        payload["revoked_at"] = json!(revoked_at);
    }

    state.audit.emit(audit::AuditEvent::new(
        audit::event::SERVICE_TOKEN_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

pub(super) fn emit_connection_changed(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    action: &'static str,
    record: &connections::store::StoredConnection,
    changed_fields: &[&'static str],
    credential_changed: bool,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let actor = Some(auth::actor_from_principal(principal));
    let summary = record.safe_summary(None);
    let payload = json!({
        "action": action,
        "connection_id": &record.id,
        "kind": record.write.kind,
        "source": "managed",
        "enabled": record.write.enabled,
        "authentication": summary.authentication,
        "changed_fields": changed_fields,
        "revisions": &record.revisions,
    });

    state.audit.emit(audit::AuditEvent::new(
        audit::event::CONNECTION_CHANGED,
        request_id.clone(),
        source_ip.clone(),
        actor.clone(),
        payload.clone(),
    ));
    if credential_changed {
        state.audit.emit(audit::AuditEvent::new(
            audit::event::CONNECTION_CREDENTIAL_CHANGED,
            request_id,
            source_ip,
            actor,
            payload,
        ));
    }
}

pub(super) fn emit_connection_secret_changed(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    action: &'static str,
    metadata: &connections::secret::SecretAliasMetadata,
    dependency_count: usize,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    state.audit.emit(audit::AuditEvent::new(
        audit::event::CONNECTION_SECRET_CHANGED,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        json!({
            "action": action,
            "resource": "encrypted_local_secret",
            "secret_id": metadata.id,
            "provider": metadata.provider,
            "purpose": metadata.purpose,
            "version": metadata.version,
            "dependency_count": dependency_count,
        }),
    ));
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_connection_refreshed(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    record: &connections::store::StoredConnection,
    outcome: &'static str,
    failure: Option<&ConnectionRefreshFailure>,
    elapsed: Duration,
    result: Option<&ConnectionRefreshAuditSummary>,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let mut payload = json!({
        "connection_id": &record.id,
        "kind": record.write.kind,
        "source": "managed",
        "outcome": outcome,
        "latency_ms": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
    });
    if let Some(failure) = failure {
        payload["reason"] = json!(failure.reason);
        if let Some(method) = failure.upstream_method {
            payload["upstream_method"] = json!(method);
        }
        if let Some(code) = failure.upstream_error_code {
            payload["upstream_error_code"] = json!(code);
        }
    }
    if let Some(result) = result {
        payload["catalog_revision"] = json!(result.catalog_revision);
        payload["total_count"] = json!(result.total_count);
        payload["added_count"] = json!(result.added_count);
        payload["changed_count"] = json!(result.changed_count);
        payload["removed_count"] = json!(result.removed_count);
    }
    state.audit.emit(audit::AuditEvent::new(
        audit::event::CONNECTION_REFRESHED,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        payload,
    ));
}

#[allow(clippy::too_many_arguments)]
pub(super) fn emit_connection_tested(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    record: &connections::store::StoredConnection,
    outcome: &'static str,
    reason: Option<connections::test::ConnectionTestReason>,
    latency_ms: u64,
    result: Option<&connections::test::ConnectionTestResult>,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let summary = record.safe_summary(None);
    let mut payload = json!({
        "connection_id": &record.id,
        "kind": record.write.kind,
        "source": "managed",
        "authentication": summary.authentication,
        "revisions": &record.revisions,
        "outcome": outcome,
        "latency_ms": latency_ms,
    });
    if let Some(reason) = reason {
        payload["reason"] = json!(reason);
    }
    if let Some(result) = result {
        payload["state"] = json!(result.state);
        payload["stages"] = json!(&result.stages);
    }
    state.audit.emit(audit::AuditEvent::new(
        audit::event::CONNECTION_TESTED,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        payload,
    ));
}

pub(super) fn connection_secret_authority_forbidden(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    route_pattern: &'static str,
    operation: &'static str,
) -> Response {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    state.audit.emit(audit::AuditEvent::new(
        "authz.denied",
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        json!({
            "path": route_pattern,
            "method": parts.method.as_str(),
            "reason": "missing_permission",
            "permission": ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
            "authorization_layer": "connection_secret_authority",
            "operation": operation,
        }),
    ));
    forbidden()
}

pub(super) fn connection_permission_forbidden(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    route_pattern: &'static str,
    permission: &'static str,
    operation: &'static str,
) -> Response {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    state.audit.emit(audit::AuditEvent::new(
        "authz.denied",
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        json!({
            "path": route_pattern,
            "method": parts.method.as_str(),
            "reason": "missing_permission",
            "permission": permission,
            "authorization_layer": "connection_endpoint",
            "operation": operation,
        }),
    ));
    forbidden()
}

pub(super) fn connection_test_status_persistence_reason(
    error: &connections::control_plane::ConnectionMutationError,
) -> connections::test::ConnectionTestReason {
    match error {
        connections::control_plane::ConnectionMutationError::DeadlineExceeded
        | connections::control_plane::ConnectionMutationError::Store(
            connections::store::ConnectionStoreError::DeadlineExceeded { .. },
        ) => connections::test::ConnectionTestReason::DeadlineExceeded,
        connections::control_plane::ConnectionMutationError::Store(
            connections::store::ConnectionStoreError::NotFound { .. }
            | connections::store::ConnectionStoreError::Conflict { .. },
        ) => connections::test::ConnectionTestReason::ConnectionChanged,
        _ => connections::test::ConnectionTestReason::InternalError,
    }
}

pub(super) fn connection_test_status_persistence_deadline_exceeded(
    error: &connections::control_plane::ConnectionMutationError,
) -> bool {
    matches!(
        error,
        connections::control_plane::ConnectionMutationError::DeadlineExceeded
            | connections::control_plane::ConnectionMutationError::Store(
                connections::store::ConnectionStoreError::DeadlineExceeded { .. }
            )
    )
}

pub(super) fn emit_service_token_delegation_rejected(
    state: &TokenAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    requested_scopes: &[String],
    disallowed_scopes: &[String],
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let actor = Some(auth::actor_from_principal(principal));
    let payload = json!({
        "decision": "deny",
        "reason": "requested_scopes_exceed_creator_authority",
        "requested_scopes": requested_scopes,
        "disallowed_scopes": disallowed_scopes,
    });

    state.audit.emit(audit::AuditEvent::new(
        audit::event::SERVICE_TOKEN_DELEGATION_REJECTED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

pub(super) fn emit_tool_registry_changed(
    state: &ToolAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    tools_source: &str,
    registered_tool_names: &[String],
    tool_count: usize,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let actor = Some(auth::actor_from_principal(principal));
    // The payload key keeps its historical name ("tools_file") so the
    // standalone audit shape is unchanged; in cluster mode the value
    // names the authority instead of a path.
    let payload = json!({
        "action": "openapi_tools_registered",
        "tools_file": tools_source,
        "registered_tool_names": registered_tool_names,
        "registered_tool_count": registered_tool_names.len(),
        "tool_count": tool_count,
    });

    state.audit.emit(audit::AuditEvent::new(
        audit::event::TOOL_REGISTRY_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

pub(super) fn emit_managed_openapi_catalog_changed(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    result: &connections::openapi::OpenApiCatalogPublishResult,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    state.audit.emit(audit::AuditEvent::new(
        audit::event::TOOL_REGISTRY_CHANGED,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        json!({
            "action": "managed_openapi_catalog_registered",
            "connection_id": &result.connection_id,
            "source": "managed",
            "spec_digest": &result.spec_digest,
            "spec_revision": result.spec_revision,
            "catalog_revision": result.catalog_revision,
            "registered_tool_names": &result.registered_tool_names,
            "registered_tool_count": result.registered_tool_names.len(),
            "tool_count": result.total_count,
            "added_count": result.added_count,
            "changed_count": result.changed_count,
            "removed_count": result.removed_count,
        }),
    ));
}

pub(super) fn emit_managed_openapi_catalog_rejected(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    connection_id: &connections::model::ConnectionId,
    reason: &'static str,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    state.audit.emit(audit::AuditEvent::new(
        audit::event::TOOL_REGISTRY_CHANGED,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        json!({
            "action": "managed_openapi_catalog_registration_rejected",
            "connection_id": connection_id,
            "source": "managed",
            "outcome": "failure",
            "reason": reason,
        }),
    ));
}

pub(super) fn emit_traffic_endpoint_review_changed(
    state: &TrafficAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    method: &str,
    endpoint_template: &str,
    review: &discovery::query::EndpointReviewState,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let actor = Some(auth::actor_from_principal(principal));
    let payload = json!({
        "method": method,
        "endpoint_template": endpoint_template,
        "reviewed": review.reviewed,
        "reviewed_at": review.reviewed_at,
        "reviewed_by": review.reviewed_by,
    });

    state.audit.emit(audit::AuditEvent::new(
        audit::event::TRAFFIC_ENDPOINT_REVIEW_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

pub(super) fn emit_signal_lifecycle_changed(
    state: &SignalsAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    signal: &discovery::signals::Signal,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let actor = Some(auth::actor_from_principal(principal));
    let payload = json!({
        "id": &signal.id,
        "signal_type": &signal.signal_type,
        "target": &signal.target,
        "state": signal.state.as_str(),
        "transitioned_at": &signal.transitioned_at,
        "transitioned_by": &signal.transitioned_by,
    });

    state.audit.emit(audit::AuditEvent::new(
        audit::event::SIGNAL_LIFECYCLE_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

pub(super) fn emit_suggestion_lifecycle_changed(
    state: &SuggestionsAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    suggestion: &discovery::suggestions::RuleSuggestion,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip = client_ip::canonical_client_ip(
        &parts.headers,
        &parts.extensions,
        &state.policy.client_ip_policy,
    );
    let actor = Some(auth::actor_from_principal(principal));
    let payload = json!({
        "id": &suggestion.id,
        "suggestion_type": &suggestion.suggestion_type,
        "method": &suggestion.method,
        "path_pattern": &suggestion.path_pattern,
        "proposed_rule": &suggestion.proposed_rule,
        "state": suggestion.state.as_str(),
        "transitioned_at": &suggestion.transitioned_at,
        "transitioned_by": &suggestion.transitioned_by,
        "source_signal_id": &suggestion.source_signal_id,
    });

    state.policy.audit.emit(audit::AuditEvent::new(
        audit::event::SUGGESTION_LIFECYCLE_CHANGED,
        request_id,
        source_ip,
        actor,
        payload,
    ));
}

pub(super) fn policy_change_payload(before: &rbac::Policy, after: &rbac::Policy) -> Value {
    json!({
        "before": policy_audit_summary(before),
        "after": policy_audit_summary(after),
        "changed_sections": changed_policy_sections(before, after),
    })
}

pub(super) fn policy_audit_summary(policy: &rbac::Policy) -> Value {
    json!({
        "id": policy.id,
        "roles": policy.roles.len(),
        "routes": policy.routes.len(),
        "rules": policy.rules.len(),
        "egress_hosts": policy.egress.hosts.len(),
        "egress_cidrs": policy.egress.cidrs.len(),
        "egress_ports": policy.egress.ports.len(),
        "tools": policy.tools.len(),
    })
}

pub(super) fn changed_policy_sections(
    before: &rbac::Policy,
    after: &rbac::Policy,
) -> Vec<&'static str> {
    let mut sections = Vec::new();

    if before.schema_version != after.schema_version {
        sections.push("schema_version");
    }
    if before.id != after.id {
        sections.push("id");
    }
    if before.default_action != after.default_action {
        sections.push("default_action");
    }
    if before.enforcement_mode != after.enforcement_mode {
        sections.push("enforcement_mode");
    }
    if before.roles != after.roles {
        sections.push("roles");
    }
    if before.routes != after.routes {
        sections.push("routes");
    }
    if before.rules != after.rules {
        sections.push("rules");
    }
    if before.egress != after.egress {
        sections.push("egress");
    }
    if before.tools != after.tools {
        sections.push("tools");
    }

    sections
}
