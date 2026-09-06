//! admin policy boundary extracted from the application composition root.
use super::*;

pub(super) async fn policy_get_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };

    let can_write = rbac_state.principal_has_permission(principal, ADMIN_POLICY_WRITE_PERMISSION);

    // Cluster mode serves the authoritative active document (ETag already
    // verified against the document body by `active()`), not the local
    // snapshot: an admin reading the policy sees exactly what a commit
    // would compare against.
    #[cfg(feature = "postgres")]
    if let Some(control_plane) = state.control_plane.as_ref() {
        return match control_plane.active().await {
            Ok(Some(active)) => policy_read_response(active.policy, &active.etag, can_write),
            Ok(None) => {
                tracing::error!("policy control plane has no active document");
                service_unavailable("policy control plane unavailable")
            }
            Err(error) => {
                tracing::error!(error = %error, "policy control plane read failed");
                service_unavailable("policy control plane unavailable")
            }
        };
    }

    let policy = rbac_state.current_policy();
    let etag = match policy_etag(&policy) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute policy ETag");
            return internal_server_error("policy ETag computation failed");
        }
    };

    policy_read_response(policy, &etag, can_write)
}

pub(super) fn policy_read_response(policy: rbac::Policy, etag: &str, can_write: bool) -> Response {
    // Authorization metadata belongs to this principal's response, not the
    // persisted document or its ETag. Every mutation still authorizes afresh.
    (
        StatusCode::OK,
        [
            (header::ETAG, etag_header_value(etag)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            ),
            (
                header::HeaderName::from_static("x-greengateway-policy-write"),
                HeaderValue::from_static(if can_write { "true" } else { "false" }),
            ),
        ],
        Json(policy),
    )
        .into_response()
}

pub(super) async fn policy_put_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_policy_state(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return policy_admin_authz_error_response(error),
        };
    if !policy_authority_configured(&state) {
        return policy_not_configured();
    }

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let candidate = match parse_policy_body(&body) {
        Ok(policy) => policy,
        Err(errors) => return policy_validation_failed(errors),
    };

    let _policy_write_guard = rbac_state.policy_write_guard().await;

    let (before_policy, current_etag) =
        match current_policy_and_matching_if_match(&state, rbac_state, &parts.headers).await {
            Ok(view) => view,
            Err(response) => return *response,
        };

    if candidate.egress != before_policy.egress {
        return egress_reload_unsupported();
    }

    if let Err(err) = rbac_state.validate_proxy_dispatch_policy(&candidate) {
        return policy_validation_failed(vec![policy_error_message(&err)]);
    }

    let diff_summary = json!({
        "action": "policy_replaced",
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_write_guard: &_policy_write_guard,
            parts: &parts,
            principal: &principal,
        },
        &before_policy,
        &current_etag,
        &candidate,
        diff_summary,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return *response,
    };

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(commit.after_policy),
    )
        .into_response();
    with_policy_history_append_warning(response, commit.history_append_failed)
}

pub(super) async fn policy_history_endpoint(
    State(state): State<PolicyAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<PolicyHistoryParams>,
) -> Response {
    record_request(POLICY_HISTORY_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) = authorized_policy_state(&state, &principal, ADMIN_POLICY_READ_PERMISSION) {
        return policy_admin_authz_error_response(error);
    }
    let Some(history_store) = state.history_store.as_ref() else {
        return policy_history_not_configured();
    };
    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match history_store.list_versions(&filters).await {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(err) if err.invalid_parameter_name().is_some() => bad_request(&format!(
            "invalid query parameter: {}",
            err.invalid_parameter_name()
                .expect("guard ensures a parameter")
        )),
        Err(err) => {
            tracing::error!(error = %err, "failed to query policy history");
            internal_server_error("policy history query failed")
        }
    }
}

pub(super) async fn policy_rollback_endpoint(
    State(state): State<PolicyAdminState>,
    Path(version): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_ROLLBACK_ADMIN_ROUTE);

    let target_version = match parse_policy_history_version(&version) {
        Ok(version) => version,
        Err(parameter) => return bad_request(&format!("invalid path parameter: {parameter}")),
    };
    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_policy_state(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return policy_admin_authz_error_response(error),
        };
    if !policy_authority_configured(&state) {
        return policy_not_configured();
    }
    let Some(history_store) = state.history_store.as_ref() else {
        return policy_history_not_configured();
    };

    let target = match history_store.get_version(target_version).await {
        Ok(Some(version)) => version,
        Ok(None) => return not_found("policy version was not found"),
        Err(err) => {
            tracing::error!(error = %err, version = target_version, "failed to load policy history version");
            return internal_server_error("policy history query failed");
        }
    };
    let Some(target_policy) = target.policy else {
        tracing::error!(
            version = target_version,
            "policy history detail omitted target snapshot"
        );
        return internal_server_error("policy history query failed");
    };

    let _policy_write_guard = rbac_state.policy_write_guard().await;

    // The view reads the authority (file snapshot or the active row) and
    // checks the If-Match precondition against it; in cluster mode the
    // rollback commits as a NEW immutable version of the target document.
    let (before_policy, current_etag) =
        match current_policy_and_matching_if_match(&state, rbac_state, &parts.headers).await {
            Ok(view) => view,
            Err(response) => return *response,
        };

    let diff_summary = json!({
        "action": "policy_rolled_back",
        "target_version": target.version,
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_write_guard: &_policy_write_guard,
            parts: &parts,
            principal: &principal,
        },
        &before_policy,
        &current_etag,
        &target_policy,
        diff_summary,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return *response,
    };

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(commit.after_policy),
    )
        .into_response();
    with_policy_history_append_warning(response, commit.history_append_failed)
}

pub(super) async fn policy_validate_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_VALIDATE_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };

    match parse_policy_body(&body) {
        Ok(policy) => match rbac_state.validate_proxy_dispatch_policy(&policy) {
            Ok(()) => Json(PolicyValidationResponse {
                valid: true,
                errors: Vec::new(),
            })
            .into_response(),
            Err(error) => policy_validation_failed(vec![policy_error_message(&error)]),
        },
        Err(errors) => policy_validation_failed(errors),
    }
}

pub(super) async fn policy_rule_post_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULES_ADMIN_ROUTE);

    let (parts, body, principal, rbac_state) =
        match split_authorized_policy_mutation_request(&state, request) {
            Ok(context) => context,
            Err(response) => return *response,
        };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let rule = match parse_rule_body(&body) {
        Ok(rule) => rule,
        Err(errors) => return policy_validation_failed(errors),
    };

    let created = match create_policy_rule(&state, &parts, &principal, rbac_state, rule).await {
        Ok(result) => result,
        Err(response) => return *response,
    };

    let response = (
        StatusCode::CREATED,
        [(header::ETAG, etag_header_value(&created.new_etag))],
        Json(created.rule),
    )
        .into_response();
    with_policy_history_append_warning(response, created.history_append_failed)
}

pub(super) async fn policy_rule_patch_endpoint(
    State(state): State<PolicyAdminState>,
    Path(rule_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_ADMIN_ROUTE);

    let (parts, body, principal, rbac_state) =
        match split_authorized_policy_mutation_request(&state, request) {
            Ok(context) => context,
            Err(response) => return *response,
        };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let patch = match parse_rule_patch_body(&body) {
        Ok(patch) => patch,
        Err(errors) => return policy_validation_failed(errors),
    };
    if patch.is_empty() {
        return bad_request(
            "rule patch must include at least one of enabled, methods, path, tool_name, principal, action",
        );
    }

    let _policy_write_guard = rbac_state.policy_write_guard().await;

    let (before_policy, current_etag) =
        match current_policy_and_matching_if_match(&state, rbac_state, &parts.headers).await {
            Ok(view) => view,
            Err(response) => return *response,
        };

    let rule_index = match rule_index_by_id(&before_policy, &rule_id) {
        Ok(rule_index) => rule_index,
        Err(error) => return rule_lookup_error_response(&rule_id, error),
    };

    let mut candidate = before_policy.clone();
    let before_rule = candidate.rules[rule_index].clone();
    apply_rule_patch(&mut candidate.rules[rule_index], patch);
    let changed_fields = changed_rule_fields(&before_rule, &candidate.rules[rule_index]);

    let candidate = match validate_policy_candidate(&candidate) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };
    let updated_rule = candidate.rules[rule_index].clone();

    let diff_summary = json!({
        "action": "rule_updated",
        "rule_id": rule_id,
        "changed_fields": changed_fields,
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_write_guard: &_policy_write_guard,
            parts: &parts,
            principal: &principal,
        },
        &before_policy,
        &current_etag,
        &candidate,
        diff_summary,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return *response,
    };

    let updated_rule = commit
        .after_policy
        .rules
        .get(rule_index)
        .cloned()
        .unwrap_or(updated_rule);

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(updated_rule),
    )
        .into_response();
    with_policy_history_append_warning(response, commit.history_append_failed)
}

pub(super) async fn policy_rule_delete_endpoint(
    State(state): State<PolicyAdminState>,
    Path(rule_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_ADMIN_ROUTE);

    let (parts, _body, principal, rbac_state) =
        match split_authorized_policy_mutation_request(&state, request) {
            Ok(context) => context,
            Err(response) => return *response,
        };

    let _policy_write_guard = rbac_state.policy_write_guard().await;

    let (before_policy, current_etag) =
        match current_policy_and_matching_if_match(&state, rbac_state, &parts.headers).await {
            Ok(view) => view,
            Err(response) => return *response,
        };

    let rule_index = match rule_index_by_id(&before_policy, &rule_id) {
        Ok(rule_index) => rule_index,
        Err(error) => return rule_lookup_error_response(&rule_id, error),
    };

    let mut candidate = before_policy.clone();
    candidate.rules.remove(rule_index);
    let candidate = match validate_policy_candidate(&candidate) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };

    let diff_summary = json!({
        "action": "rule_deleted",
        "rule_id": rule_id,
        "position": rule_index,
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_write_guard: &_policy_write_guard,
            parts: &parts,
            principal: &principal,
        },
        &before_policy,
        &current_etag,
        &candidate,
        diff_summary,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return *response,
    };

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(RuleDeletedResponse {
            deleted_rule_id: rule_id,
        }),
    )
        .into_response();
    with_policy_history_append_warning(response, commit.history_append_failed)
}

pub(super) async fn policy_rules_order_put_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULES_ORDER_ADMIN_ROUTE);

    let (parts, body, principal, rbac_state) =
        match split_authorized_policy_mutation_request(&state, request) {
            Ok(context) => context,
            Err(response) => return *response,
        };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let requested_order = match parse_rule_order_body(&body) {
        Ok(order) => order,
        Err(errors) => return policy_validation_failed(errors),
    };

    let _policy_write_guard = rbac_state.policy_write_guard().await;

    let (before_policy, current_etag) =
        match current_policy_and_matching_if_match(&state, rbac_state, &parts.headers).await {
            Ok(view) => view,
            Err(response) => return *response,
        };

    let current_order = policy_rule_ids(&before_policy);
    if let Err(errors) = validate_rule_order(&current_order, &requested_order) {
        return policy_validation_failed(errors);
    }

    let mut candidate = before_policy.clone();
    candidate.rules = reordered_rules(&before_policy, &requested_order);
    let candidate = match validate_policy_candidate(&candidate) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };

    let diff_summary = json!({
        "action": "rules_reordered",
        "new_order": requested_order,
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_write_guard: &_policy_write_guard,
            parts: &parts,
            principal: &principal,
        },
        &before_policy,
        &current_etag,
        &candidate,
        diff_summary,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return *response,
    };
    let order = policy_rule_ids(&commit.after_policy);

    let response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(RulesReorderedResponse { order }),
    )
        .into_response();
    with_policy_history_append_warning(response, commit.history_append_failed)
}

pub(super) async fn policy_rule_preview_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_PREVIEW_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };
    if !rbac_state.principal_has_permission(principal, ADMIN_AUDIT_READ_PERMISSION) {
        return forbidden();
    }
    let Some(query_store) = state.event_store.as_ref() else {
        return service_unavailable("policy rule preview requires an audit query store");
    };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let preview_request = match parse_rule_preview_body(&body) {
        Ok(request) => request,
        Err(errors) => return policy_validation_failed(errors),
    };

    let previewed = match preview_rule(query_store.as_ref(), preview_request).await {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(error = %err, "failed to preview policy rule");
            return internal_server_error("policy rule preview failed");
        }
    };

    (StatusCode::OK, Json(previewed)).into_response()
}

pub(super) async fn policy_rule_hits_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_HITS_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };
    let policy = rbac_state.current_policy();
    let counts = match state.query_store.as_ref() {
        Some(query_store) => match query_store.rule_hit_counts().await {
            Ok(counts) => counts,
            Err(err) => {
                tracing::error!(error = %err, "failed to query policy rule hit counts");
                return internal_server_error("policy rule hit count query failed");
            }
        },
        None => HashMap::new(),
    };

    Json(PolicyRuleHitsResponse {
        rules: policy
            .rules
            .iter()
            .enumerate()
            .map(|(rule_index, rule)| {
                let rule_id = rule.id.clone().unwrap_or_else(|| rule_index.to_string());
                let hits = counts.get(&rule_id).copied().unwrap_or(0);
                PolicyRuleHitCount { rule_id, hits }
            })
            .collect(),
    })
    .into_response()
}

pub(super) async fn policy_rule_shadow_review_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_RULE_SHADOW_REVIEW_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };
    // The response carries audit-history samples and the actor identities
    // behind them, which is the data class `admin:audit:read` gates. This is
    // the same second check the rule-preview endpoint applies for the same
    // reason; `admin:policy:read` alone covers only aggregate rule counts.
    if !rbac_state.principal_has_permission(principal, ADMIN_AUDIT_READ_PERMISSION) {
        return forbidden();
    }
    let policy = rbac_state.current_policy();
    let shadow_rules = policy
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.enabled && rule.action == rbac::RuleAction::Shadow)
        .map(|(rule_index, rule)| {
            (
                rule.id.clone().unwrap_or_else(|| rule_index.to_string()),
                rule.clone(),
            )
        })
        .collect::<Vec<_>>();
    let rule_ids = shadow_rules
        .iter()
        .map(|(rule_id, _)| rule_id.clone())
        .collect::<Vec<_>>();

    let review = match state.query_store.as_ref() {
        Some(query_store) => match query_store
            .shadow_rule_would_deny_summaries(&rule_ids)
            .await
        {
            Ok(review) => review,
            Err(err) => {
                tracing::error!(error = %err, "failed to query shadow rule review summaries");
                return internal_server_error("shadow rule review query failed");
            }
        },
        None => audit::query::ShadowRuleWouldDenySummarySet::default(),
    };

    Json(PolicyRuleShadowReviewResponse {
        scanned_event_count: review.scanned_event_count,
        scan_truncated: review.scan_truncated,
        rules: shadow_rules
            .into_iter()
            .map(|(rule_id, rule)| {
                let summary = review.summaries.get(&rule_id);
                PolicyRuleShadowReviewSummary {
                    rule_id,
                    rule,
                    would_deny_count: summary.map(|summary| summary.would_deny_count).unwrap_or(0),
                    affected_principals: summary
                        .map(|summary| summary.affected_principals.clone())
                        .unwrap_or_default(),
                    samples: summary
                        .map(|summary| summary.samples.clone())
                        .unwrap_or_default(),
                }
            })
            .collect(),
    })
    .into_response()
}

pub(super) fn split_authorized_policy_mutation_request(
    state: &PolicyAdminState,
    request: AxumRequest,
) -> ResponseResult<(
    http::request::Parts,
    Body,
    auth::Principal,
    &middleware::rbac::RbacState,
)> {
    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return Err(Box::new(unauthorized()));
    };
    let rbac_state = match authorized_policy_state(state, &principal, ADMIN_POLICY_WRITE_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return Err(Box::new(policy_admin_authz_error_response(error))),
    };
    if !policy_authority_configured(state) {
        return Err(Box::new(policy_not_configured()));
    }

    Ok((parts, body, principal, rbac_state))
}

/// Whether any policy authority is wired: the standalone file, or cluster
/// mode's PostgreSQL control plane. One of the two must exist for the
/// mutation endpoints to have anything to commit to.
pub(super) fn policy_authority_configured(state: &PolicyAdminState) -> bool {
    if state.policy_file.is_some() {
        return true;
    }
    #[cfg(feature = "postgres")]
    if state.control_plane.is_some() {
        return true;
    }
    false
}

pub(super) fn parse_create_token_body(body: &Bytes) -> ResponseResult<CreateTokenAdminRequest> {
    serde_json::from_slice::<CreateTokenAdminRequest>(body)
        .map_err(|err| Box::new(bad_request(&format!("invalid token create JSON: {err}"))))
}

pub(super) fn parse_openapi_tools_register_body(
    body: &Bytes,
) -> ResponseResult<OpenApiToolsRegisterRequest> {
    serde_json::from_slice::<OpenApiToolsRegisterRequest>(body).map_err(|err| {
        Box::new(bad_request(&format!(
            "invalid OpenAPI tools register JSON: {err}"
        )))
    })
}

pub(super) fn parse_policy_body(body: &Bytes) -> Result<rbac::Policy, Vec<String>> {
    let value = serde_json::from_slice::<Value>(body)
        .map_err(|err| vec![format!("invalid JSON: {err}")])?;

    rbac::Policy::validate_json_value(value).map_err(|err| vec![policy_error_message(&err)])
}

pub(super) fn parse_rule_body(body: &Bytes) -> Result<rbac::Rule, Vec<String>> {
    serde_json::from_slice::<rbac::Rule>(body)
        .map_err(|err| vec![format!("invalid rule JSON: {err}")])
}

pub(super) fn parse_rule_patch_body(body: &Bytes) -> Result<RulePatch, Vec<String>> {
    serde_json::from_slice::<RulePatch>(body)
        .map_err(|err| vec![format!("invalid rule patch JSON: {err}")])
}

pub(super) fn parse_rule_order_body(body: &Bytes) -> Result<Vec<String>, Vec<String>> {
    serde_json::from_slice::<Vec<String>>(body)
        .map_err(|err| vec![format!("invalid rule order JSON: {err}")])
}

pub(super) fn parse_rule_preview_body(
    body: &Bytes,
) -> Result<PolicyRulePreviewRequest, Vec<String>> {
    let mut request = serde_json::from_slice::<PolicyRulePreviewRequest>(body)
        .map_err(|err| vec![format!("invalid JSON: {err}")])?;
    rbac::policy::canonicalize_principal_matcher_issuers(&mut request.rule.principal);
    validate_rule_preview_request(&request)?;
    Ok(request)
}

pub(super) fn validate_rule_preview_request(
    request: &PolicyRulePreviewRequest,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if let Err(parameter) = validate_rfc3339("from", request.from.clone()) {
        errors.push(format!("invalid {parameter}: expected RFC 3339 timestamp"));
    }
    if let Err(parameter) = validate_rfc3339("to", request.to.clone()) {
        errors.push(format!("invalid {parameter}: expected RFC 3339 timestamp"));
    }
    let has_path = !request.rule.path.is_empty();
    let has_tool_name = request.rule.tool_name.is_some();
    if has_path == has_tool_name {
        errors.push("rule must set exactly one of path or tool_name".to_owned());
    }
    if has_tool_name {
        errors.push("rule preview currently supports HTTP path rules only".to_owned());
    }
    if has_path && !request.rule.path.starts_with('/') {
        errors.push(format!(
            "rule.path must start with '/', got '{}'",
            request.rule.path
        ));
    }
    if request
        .rule
        .principal
        .issuers
        .iter()
        .any(|issuer| issuer.is_empty())
    {
        errors.push("rule.principal.issuers must not contain empty values".to_owned());
    }
    for auth_method in &request.rule.principal.auth_methods {
        if !rbac::rule::valid_auth_method_name(auth_method) {
            errors.push(format!(
                "rule.principal.auth_methods contains unknown auth method '{auth_method}', expected 'bearer_token' or 'session_cookie'"
            ));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub(super) async fn preview_rule(
    query_store: &dyn storage::AuditEventStore,
    request: PolicyRulePreviewRequest,
) -> Result<PolicyRulePreviewResponse, storage::RepositoryError> {
    let matcher = rbac::RuleMatcher::new(std::slice::from_ref(&request.rule));
    let sample_limit = request
        .sample_limit
        .unwrap_or(DEFAULT_RULE_PREVIEW_SAMPLE_LIMIT)
        .min(MAX_RULE_PREVIEW_SAMPLE_LIMIT);
    let mut match_count = 0_u64;
    let mut scanned_event_count = 0_u64;
    let mut samples = Vec::with_capacity(sample_limit);

    let mut filters = audit::query::RequestObservationFilters {
        from: request.from,
        to: request.to,
        methods: request.rule.methods.clone(),
        path_exact: exact_preview_path_filter(&request.rule.path),
        path_prefix: prefix_preview_path_filter(&request.rule.path),
        before_id: None,
    };
    loop {
        let observations = query_store.query_request_observations(&filters).await?;
        if observations.is_empty() {
            break;
        }
        for observation in observations {
            filters.before_id = Some(observation.id);
            scanned_event_count = scanned_event_count.saturating_add(1);
            let principal = observation
                .actor
                .as_ref()
                .and_then(principal_from_audit_actor);
            let payload = serde_json::from_str::<Value>(&observation.payload_json).ok();
            let payload_string = |key: &str| {
                payload
                    .as_ref()
                    .and_then(|payload| payload.get(key))
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
            };
            let dispatch_context = if payload
                .as_ref()
                .and_then(|payload| payload.get("routing_context_known"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                rbac::RuleDispatchContext::classified_with_route_id(
                    payload_string("upstream_route_id"),
                    payload_string("upstream_route_host"),
                    payload_string("upstream_route_path_prefix"),
                    payload_string("upstream_origin"),
                )
            } else {
                rbac::RuleDispatchContext::unknown()
            };

            if matcher
                .evaluate_with_dispatch(
                    &observation.method,
                    &observation.path,
                    principal.as_ref(),
                    dispatch_context,
                )
                .is_some()
            {
                match_count = match_count.saturating_add(1);
                if samples.len() < sample_limit {
                    samples.push(preview_sample(observation));
                }
            }
        }
    }

    Ok(PolicyRulePreviewResponse {
        match_count,
        scanned_event_count,
        sample_strategy: "newest_matches",
        samples,
    })
}

pub(super) fn exact_preview_path_filter(pattern: &str) -> Option<String> {
    preview_path_filter(pattern).exact
}

pub(super) fn prefix_preview_path_filter(pattern: &str) -> Option<String> {
    preview_path_filter(pattern).prefix
}

pub(super) fn preview_path_filter(pattern: &str) -> PreviewPathFilter {
    let Some(tail) = pattern.strip_prefix('/') else {
        return PreviewPathFilter {
            exact: None,
            prefix: None,
        };
    };
    if tail.is_empty() {
        return PreviewPathFilter {
            exact: Some("/".to_owned()),
            prefix: None,
        };
    }

    let mut literal_segments = Vec::new();
    let mut first_dynamic_segment = None;
    for segment in tail.split('/') {
        if segment == "*" || segment == "**" || segment.contains('{') || segment.contains('}') {
            first_dynamic_segment = Some(segment);
            break;
        }
        literal_segments.push(segment);
    }

    let Some(first_dynamic_segment) = first_dynamic_segment else {
        return PreviewPathFilter {
            exact: Some(pattern.to_owned()),
            prefix: None,
        };
    };
    if literal_segments.is_empty() {
        return PreviewPathFilter {
            exact: None,
            prefix: None,
        };
    }

    let literal_prefix = format!("/{}", literal_segments.join("/"));
    let prefix = if first_dynamic_segment == "**" {
        literal_prefix
    } else {
        format!("{literal_prefix}/")
    };

    PreviewPathFilter {
        exact: None,
        prefix: Some(prefix),
    }
}

pub(super) fn principal_from_audit_actor(actor: &audit::Actor) -> Option<auth::Principal> {
    let auth_method = match actor.auth_mode.as_str() {
        rbac::rule::AUTH_METHOD_BEARER_TOKEN => auth::AuthMethod::Bearer,
        rbac::rule::AUTH_METHOD_SESSION_COOKIE => auth::AuthMethod::Cookie,
        rbac::rule::AUTH_METHOD_SERVICE_TOKEN => auth::AuthMethod::ServiceToken,
        _ => return None,
    };

    Some(auth::Principal {
        user_id: actor.user_id.clone(),
        issuer: actor.issuer.clone(),
        email: actor.email.clone(),
        org_id: None,
        roles: actor.roles.clone().unwrap_or_default(),
        session_id: "audit-history".to_owned(),
        auth_method,
    })
}

pub(super) fn preview_sample(
    observation: audit::query::RequestObservation,
) -> PolicyRulePreviewSample {
    let policy_decision = serde_json::from_str::<Value>(&observation.payload_json)
        .ok()
        .and_then(|payload| {
            payload
                .get("policy_decision")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });

    PolicyRulePreviewSample {
        event_id: observation.event_id,
        timestamp: observation.timestamp,
        request_id: observation.request_id,
        source_ip: observation.source_ip,
        user_agent: observation.user_agent,
        method: observation.method,
        path: observation.path,
        actor: observation.actor,
        status: observation.status,
        policy_decision,
        matched_rule_id: observation.matched_rule_id,
    }
}

pub(super) fn apply_rule_patch(rule: &mut rbac::Rule, patch: RulePatch) {
    if let Some(enabled) = patch.enabled {
        rule.enabled = enabled;
    }
    if let Some(methods) = patch.methods {
        rule.methods = methods;
    }
    if let Some(path) = patch.path {
        rule.path = match path {
            RulePathPatch::Set(value) => value,
            RulePathPatch::Clear => String::new(),
        };
    }
    if let Some(tool_name) = patch.tool_name {
        rule.tool_name = match tool_name {
            RuleToolNamePatch::Set(value) => Some(value),
            RuleToolNamePatch::Clear => None,
        };
    }
    if let Some(principal) = patch.principal {
        rule.principal = principal;
    }
    if let Some(action) = patch.action {
        rule.action = action;
    }
}

pub(super) fn changed_rule_fields(before: &rbac::Rule, after: &rbac::Rule) -> Vec<&'static str> {
    let mut fields = Vec::new();

    if before.methods != after.methods {
        fields.push("methods");
    }
    if before.enabled != after.enabled {
        fields.push("enabled");
    }
    if before.path != after.path {
        fields.push("path");
    }
    if before.tool_name != after.tool_name {
        fields.push("tool_name");
    }
    if before.principal != after.principal {
        fields.push("principal");
    }
    if before.action != after.action {
        fields.push("action");
    }

    fields
}

pub(super) fn validate_policy_candidate(candidate: &rbac::Policy) -> ResponseResult<rbac::Policy> {
    let value = match serde_json::to_value(candidate) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize candidate policy for validation");
            return Err(Box::new(internal_server_error("policy validation failed")));
        }
    };

    rbac::Policy::validate_json_value(value)
        .map_err(|err| Box::new(policy_validation_failed(vec![policy_error_message(&err)])))
}

pub(super) fn require_matching_if_match(
    headers: &HeaderMap,
    before_policy: &rbac::Policy,
) -> ResponseResult<String> {
    let current_etag = match policy_etag(before_policy) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute current policy ETag");
            return Err(Box::new(internal_server_error(
                "policy ETag computation failed",
            )));
        }
    };

    match if_match_matches(headers, &current_etag) {
        Ok(true) => Ok(current_etag),
        Ok(false) => Err(Box::new(precondition_failed(
            "If-Match does not match the current policy ETag",
        ))),
        Err(error) => Err(Box::new(if_match_error_response(error))),
    }
}

/// The current policy as its authority sees it, with no precondition:
/// cluster mode reads the active document from the control plane,
/// standalone reads the compiled snapshot, which IS the authority there.
///
/// Suggestion generation needs this rather than the local snapshot (issue
/// #241, PR 12). Generation suppresses candidates the policy already
/// covers, and a replica's snapshot converges only when the security
/// revision reconciler installs it; generating from a stale one mints
/// suggestions for rules another replica has already committed. Those
/// suggestions are stored by identity and never re-evaluated against a
/// later policy, so they would stay open until an admin dismisses them,
/// and accepting one would append a duplicate rule.
pub(super) async fn authoritative_policy(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
) -> ResponseResult<rbac::Policy> {
    #[cfg(feature = "postgres")]
    if let Some(control_plane) = state.control_plane.as_ref() {
        return match control_plane.active().await {
            Ok(Some(active)) => Ok(active.policy),
            // Startup refuses an uninitialized deployment and the pointer
            // is append-only, so both arms are defensive fail-closed paths.
            Ok(None) => {
                tracing::error!("policy control plane has no active document");
                Err(Box::new(service_unavailable(
                    "policy control plane unavailable",
                )))
            }
            Err(error) => {
                tracing::error!(error = %error, "policy control plane read failed");
                Err(Box::new(service_unavailable(
                    "policy control plane unavailable",
                )))
            }
        };
    }
    #[cfg(not(feature = "postgres"))]
    let _ = state;
    Ok(rbac_state.current_policy())
}

/// The current policy as its authority sees it, behind the request's
/// `If-Match` precondition: standalone reads the compiled snapshot and
/// hashes it; cluster mode reads the authoritative active document (whose
/// recorded ETag `active()` already verified against the document body).
///
/// The returned ETag is what a mutation must present to win its
/// compare-and-swap -- in cluster mode the commit transaction re-verifies
/// it, so a writer that raced another replica loses with `412` rather
/// than overwriting.
pub(super) async fn current_policy_and_matching_if_match(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
    headers: &HeaderMap,
) -> ResponseResult<(rbac::Policy, String)> {
    #[cfg(feature = "postgres")]
    if let Some(control_plane) = state.control_plane.as_ref() {
        return match control_plane.active().await {
            Ok(Some(active)) => match if_match_matches(headers, &active.etag) {
                Ok(true) => Ok((active.policy, active.etag)),
                Ok(false) => Err(Box::new(precondition_failed(
                    "If-Match does not match the current policy ETag",
                ))),
                Err(error) => Err(Box::new(if_match_error_response(error))),
            },
            // Startup refuses an uninitialized deployment and the pointer
            // is append-only, so both arms are defensive fail-closed paths.
            Ok(None) => {
                tracing::error!("policy control plane has no active document");
                Err(Box::new(service_unavailable(
                    "policy control plane unavailable",
                )))
            }
            Err(error) => {
                tracing::error!(error = %error, "policy control plane read failed");
                Err(Box::new(service_unavailable(
                    "policy control plane unavailable",
                )))
            }
        };
    }
    #[cfg(not(feature = "postgres"))]
    let _ = state;
    let before_policy = rbac_state.current_policy();
    let current_etag = require_matching_if_match(headers, &before_policy)?;
    Ok((before_policy, current_etag))
}

/// Build and validate the candidate that appends `rule`, behind the
/// request's `If-Match` precondition. Writes nothing. The caller holds the
/// policy write guard across preparation AND commit, so the ETag this
/// returns is still current when the commit presents it.
pub(super) async fn prepare_policy_rule_create(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
    headers: &HeaderMap,
    mut rule: rbac::Rule,
) -> ResponseResult<PreparedPolicyRuleCreate> {
    let (before_policy, current_etag) =
        current_policy_and_matching_if_match(state, rbac_state, headers).await?;

    if let Some(rule_id) = rule.id.as_deref() {
        if policy_rule_ids(&before_policy)
            .iter()
            .any(|existing_id| existing_id == rule_id)
        {
            return Err(Box::new(bad_request(&format!(
                "rule id '{rule_id}' already exists"
            ))));
        }
    } else {
        rule.id = Some(generate_unique_rule_id(&before_policy));
    }

    let rule_id = rule
        .id
        .clone()
        .unwrap_or_else(|| before_policy.rules.len().to_string());
    let position = before_policy.rules.len();
    let mut candidate = before_policy.clone();
    candidate.rules.push(rule);
    let candidate = validate_policy_candidate(&candidate)?;
    let created_rule = candidate.rules[position].clone();
    validate_policy_mutation_candidate(rbac_state, &before_policy, &candidate)?;

    let diff_summary = json!({
        "action": "rule_created",
        "rule_id": rule_id,
        "position": position,
    });

    Ok(PreparedPolicyRuleCreate {
        before_policy,
        current_etag,
        candidate,
        diff_summary,
        position,
        created_rule,
    })
}

pub(super) async fn create_policy_rule(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    rbac_state: &middleware::rbac::RbacState,
    rule: rbac::Rule,
) -> ResponseResult<PolicyRuleCreateResult> {
    let _policy_write_guard = rbac_state.policy_write_guard().await;

    let prepared = prepare_policy_rule_create(state, rbac_state, &parts.headers, rule).await?;
    let commit = persist_policy_mutation(
        PolicyMutationCommitContext {
            state,
            rbac_state,
            policy_write_guard: &_policy_write_guard,
            parts,
            principal,
        },
        &prepared.before_policy,
        &prepared.current_etag,
        &prepared.candidate,
        prepared.diff_summary,
    )
    .await?;

    debug_assert_ne!(prepared.current_etag, commit.new_etag);
    let created_rule = commit
        .after_policy
        .rules
        .get(prepared.position)
        .cloned()
        .unwrap_or(prepared.created_rule);

    Ok(PolicyRuleCreateResult {
        rule: created_rule,
        new_etag: commit.new_etag,
        history_append_failed: commit.history_append_failed,
    })
}

/// What every policy mutation must satisfy before any authority sees its
/// candidate: egress cannot change through a mutation endpoint, and the
/// candidate's proxy dispatch must be valid for this deployment. Pure --
/// shared by [`persist_policy_mutation`] and by suggestion acceptance,
/// which commits its candidate inside the suggestion's transaction.
pub(super) fn validate_policy_mutation_candidate(
    rbac_state: &middleware::rbac::RbacState,
    before_policy: &rbac::Policy,
    candidate: &rbac::Policy,
) -> ResponseResult<()> {
    if candidate.egress != before_policy.egress {
        return Err(Box::new(egress_reload_unsupported()));
    }

    if let Err(error) = rbac_state.validate_proxy_dispatch_policy(candidate) {
        return Err(Box::new(policy_validation_failed(vec![
            policy_error_message(&error),
        ])));
    }

    Ok(())
}

pub(super) async fn persist_policy_mutation(
    context: PolicyMutationCommitContext<'_, '_>,
    before_policy: &rbac::Policy,
    expected_etag: &str,
    candidate: &rbac::Policy,
    diff_summary: Value,
) -> ResponseResult<PolicyMutationCommitResult> {
    #[cfg(not(feature = "postgres"))]
    let _ = expected_etag;
    validate_policy_mutation_candidate(context.rbac_state, before_policy, candidate)?;

    // Cluster mode: one transaction through the authority -- new immutable
    // version, revision advance, history row, and outbox record commit
    // together, or nothing does. The expected ETag is the compare-and-swap;
    // a racing writer (on this replica or another) makes this a `412`.
    #[cfg(feature = "postgres")]
    if let Some(control_plane) = context.state.control_plane.as_ref() {
        let commit = control_plane
            .commit(storage::PolicyCommitRequest {
                precondition: storage::PolicyCommitPrecondition::Expected {
                    etag: expected_etag.to_owned(),
                },
                candidate,
                actor_user_id: &context.principal.user_id,
                diff_summary: &diff_summary,
            })
            .await;
        return match commit {
            Ok(active) => {
                context.rbac_state.install_revision_snapshot_locked(
                    active.policy.clone(),
                    active.security_revision,
                    context.policy_write_guard,
                );
                emit_policy_rule_changed(
                    context.state,
                    context.parts,
                    context.principal,
                    before_policy,
                    &active.policy,
                    diff_summary,
                );
                Ok(PolicyMutationCommitResult {
                    after_policy: active.policy,
                    new_etag: active.etag,
                    // History is written inside the commit transaction; a
                    // mutation cannot succeed without it.
                    history_append_failed: false,
                })
            }
            Err(storage::PolicyCommitError::PreconditionFailed) => Err(Box::new(
                precondition_failed("If-Match does not match the current policy ETag"),
            )),
            // Policies publish no tool names; the variant is unreachable
            // here and answered as the conflict it would be.
            Err(storage::PolicyCommitError::ToolNameTaken { tool_name, .. }) => {
                Err(Box::new(conflict(&format!(
                    "policy commit reported a reserved tool name '{tool_name}'"
                ))))
            }
            Err(storage::PolicyCommitError::Store(error)) => {
                tracing::error!(
                    error = %error,
                    "policy control-plane commit failed; nothing was written"
                );
                Err(Box::new(service_unavailable(
                    "policy mutation could not be committed",
                )))
            }
        };
    }

    let Some(policy_file) = context.state.policy_file.as_deref() else {
        return Err(Box::new(policy_not_configured()));
    };

    if let Err(err) = candidate.persist_to_file(policy_file) {
        tracing::error!(policy_file = %policy_file.display(), error = %err, "failed to persist policy");
        return Err(Box::new(internal_server_error("policy persist failed")));
    }

    if let Err(err) = middleware::rbac::reload_policy_from_file_locked(
        context.rbac_state,
        policy_file,
        context.policy_write_guard,
    ) {
        tracing::error!(policy_file = %policy_file.display(), error = %err, "failed to reload persisted policy");
        return Err(Box::new(internal_server_error("policy reload failed")));
    }

    let after_policy = context.rbac_state.current_policy();
    let history_append_failed = append_policy_version_after_commit(
        context.state,
        context.principal,
        &after_policy,
        &diff_summary,
    )
    .await;
    emit_policy_rule_changed(
        context.state,
        context.parts,
        context.principal,
        before_policy,
        &after_policy,
        diff_summary,
    );

    let new_etag = match policy_etag(&after_policy) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute updated policy ETag");
            return Err(Box::new(internal_server_error(
                "policy ETag computation failed",
            )));
        }
    };

    Ok(PolicyMutationCommitResult {
        after_policy,
        new_etag,
        history_append_failed,
    })
}

pub(super) async fn append_policy_version_after_commit(
    state: &PolicyAdminState,
    principal: &auth::Principal,
    policy: &rbac::Policy,
    diff_summary: &Value,
) -> bool {
    match append_policy_version(state, principal, policy, diff_summary).await {
        Ok(()) => false,
        Err(err) => {
            tracing::error!(
                error = %err,
                "failed to append policy history version after policy mutation committed; returning mutation success with warning"
            );
            true
        }
    }
}

pub(super) async fn append_policy_version(
    state: &PolicyAdminState,
    principal: &auth::Principal,
    policy: &rbac::Policy,
    diff_summary: &Value,
) -> Result<(), String> {
    let Some(history_store) = state.history_store.as_ref() else {
        return Err("policy history store is not configured".to_owned());
    };

    history_store
        .append_version(&principal.user_id, diff_summary, policy)
        .await
        .map(|_| ())
        .map_err(|err| err.to_string())
}

pub(super) fn effective_rule_id(rule: &rbac::Rule, rule_index: usize) -> String {
    rule.id.clone().unwrap_or_else(|| rule_index.to_string())
}

pub(super) fn policy_rule_ids(policy: &rbac::Policy) -> Vec<String> {
    policy
        .rules
        .iter()
        .enumerate()
        .map(|(rule_index, rule)| effective_rule_id(rule, rule_index))
        .collect()
}

pub(super) fn generate_unique_rule_id(policy: &rbac::Policy) -> String {
    let existing_ids = policy_rule_ids(policy).into_iter().collect::<HashSet<_>>();

    loop {
        let rule_id = format!("rule-{}", uuid::Uuid::new_v4());
        if !existing_ids.contains(&rule_id) {
            return rule_id;
        }
    }
}

pub(super) fn rule_index_by_id(
    policy: &rbac::Policy,
    rule_id: &str,
) -> Result<usize, RuleLookupError> {
    let mut matched_index = None;

    for (rule_index, rule) in policy.rules.iter().enumerate() {
        if effective_rule_id(rule, rule_index) == rule_id {
            if matched_index.is_some() {
                return Err(RuleLookupError::Ambiguous);
            }
            matched_index = Some(rule_index);
        }
    }

    matched_index.ok_or(RuleLookupError::NotFound)
}

pub(super) fn rule_lookup_error_response(rule_id: &str, error: RuleLookupError) -> Response {
    match error {
        RuleLookupError::NotFound => not_found(&format!("rule id '{rule_id}' was not found")),
        RuleLookupError::Ambiguous => bad_request(&format!(
            "rule id '{rule_id}' is ambiguous in the current policy"
        )),
    }
}

pub(super) fn validate_rule_order(
    current_order: &[String],
    requested_order: &[String],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let current_ids = current_order.iter().cloned().collect::<HashSet<_>>();
    if current_ids.len() != current_order.len() {
        errors.push(
            "current policy contains duplicate rule ids; cannot reorder rules safely".to_owned(),
        );
    }

    if requested_order.len() != current_order.len() {
        errors.push(format!(
            "rule order length mismatch: expected {}, got {}",
            current_order.len(),
            requested_order.len()
        ));
    }

    let mut seen = HashSet::new();
    let mut duplicate_ids = Vec::new();
    for rule_id in requested_order {
        if !seen.insert(rule_id) && !duplicate_ids.iter().any(|id| id == rule_id) {
            duplicate_ids.push(rule_id.clone());
        }
    }
    if !duplicate_ids.is_empty() {
        errors.push(format!(
            "rule order contains duplicate ids: {}",
            duplicate_ids.join(", ")
        ));
    }

    let requested_ids = requested_order.iter().cloned().collect::<HashSet<_>>();
    let missing_ids = current_order
        .iter()
        .filter(|rule_id| !requested_ids.contains(*rule_id))
        .cloned()
        .collect::<Vec<_>>();
    if !missing_ids.is_empty() {
        errors.push(format!(
            "rule order is missing ids: {}",
            missing_ids.join(", ")
        ));
    }

    let unknown_ids = requested_order
        .iter()
        .filter(|rule_id| !current_ids.contains(*rule_id))
        .cloned()
        .collect::<Vec<_>>();
    if !unknown_ids.is_empty() {
        errors.push(format!(
            "rule order contains unknown ids: {}",
            unknown_ids.join(", ")
        ));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub(super) fn reordered_rules(
    policy: &rbac::Policy,
    requested_order: &[String],
) -> Vec<rbac::Rule> {
    requested_order
        .iter()
        .filter_map(|requested_id| {
            policy
                .rules
                .iter()
                .enumerate()
                .find(|(rule_index, rule)| effective_rule_id(rule, *rule_index) == *requested_id)
                .map(|(_, rule)| rule.clone())
        })
        .collect()
}

pub(super) fn policy_etag(policy: &rbac::Policy) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(policy)?;
    sort_json_value(&mut value);
    let bytes = serde_json::to_vec(&value)?;
    let digest = Sha256::digest(&bytes);

    Ok(format!("\"sha256:{}\"", hex::encode(digest)))
}

pub(super) fn tools_file_etag(value: &Value) -> Result<String, serde_json::Error> {
    let mut value = value.clone();
    sort_json_value(&mut value);
    let bytes = serde_json::to_vec(&value)?;
    let digest = Sha256::digest(&bytes);

    Ok(format!("\"sha256:{}\"", hex::encode(digest)))
}

pub(super) fn serialized_response_etag<T: Serialize>(
    response: &T,
) -> Result<String, serde_json::Error> {
    let mut value = serde_json::to_value(response)?;
    sort_json_value(&mut value);
    let bytes = serde_json::to_vec(&value)?;
    let digest = Sha256::digest(&bytes);

    Ok(format!("\"sha256:{}\"", hex::encode(digest)))
}

pub(super) fn read_tools_file_document(
    path: &FsPath,
) -> Result<(Value, ToolsFileAdminDocument), String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read tools file {}: {err}", path.display()))?;
    let value = serde_json::from_str::<Value>(&contents).map_err(|err| {
        format!(
            "failed to parse tools file {} as JSON: {err}",
            path.display()
        )
    })?;

    tools::definitions::ToolRegistry::from_json_value(value.clone())
        .map_err(|err| err.to_string())?;
    let document = serde_json::from_value::<ToolsFileAdminDocument>(value.clone())
        .map_err(|err| format!("failed to decode tools file {}: {err}", path.display()))?;

    Ok((value, document))
}

pub(super) fn sort_json_value(value: &mut Value) {
    match value {
        Value::Array(values) => {
            for value in values {
                sort_json_value(value);
            }
        }
        Value::Object(map) => {
            let mut entries = std::mem::take(map).into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (_, value) in &mut entries {
                sort_json_value(value);
            }
            map.extend(entries);
        }
        _ => {}
    }
}

pub(super) fn etag_header_value(etag: &str) -> HeaderValue {
    HeaderValue::from_str(etag).expect("policy ETag should be a valid HTTP header value")
}

pub(super) fn with_etag(mut response: Response, etag: &str) -> Response {
    response
        .headers_mut()
        .insert(header::ETAG, etag_header_value(etag));
    response
}

pub(super) fn with_connection_collection_etag(mut response: Response, etag: &str) -> Response {
    response.headers_mut().insert(
        HeaderName::from_static(CONNECTION_COLLECTION_ETAG_HEADER),
        etag_header_value(etag),
    );
    response
}

pub(super) fn with_connection_secret_collection_etag(
    mut response: Response,
    etag: &str,
) -> Response {
    response.headers_mut().remove(header::ETAG);
    response.headers_mut().insert(
        HeaderName::from_static(CONNECTION_SECRET_COLLECTION_ETAG_HEADER),
        etag_header_value(etag),
    );
    response
}

pub(super) fn with_policy_history_append_warning(
    mut response: Response,
    history_append_failed: bool,
) -> Response {
    if history_append_failed {
        response.headers_mut().insert(
            HeaderName::from_static(POLICY_HISTORY_WARNING_HEADER),
            HeaderValue::from_static(POLICY_HISTORY_APPEND_FAILED_WARNING),
        );
    }

    response
}

pub(super) fn if_match_matches(
    headers: &HeaderMap,
    current_etag: &str,
) -> Result<bool, IfMatchError> {
    let mut saw_if_match = false;

    for value in headers.get_all(header::IF_MATCH) {
        saw_if_match = true;
        let value = value.to_str().map_err(|_| IfMatchError::InvalidHeader)?;
        if value
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == current_etag)
        {
            return Ok(true);
        }
    }

    if saw_if_match {
        Ok(false)
    } else {
        Err(IfMatchError::Missing)
    }
}

pub(super) fn exact_strong_if_match(
    headers: &HeaderMap,
) -> Result<String, ToolPlaygroundIfMatchError> {
    let mut values = headers.get_all(header::IF_MATCH).iter();
    let Some(value) = values.next() else {
        return Err(ToolPlaygroundIfMatchError::Missing);
    };
    if values.next().is_some() {
        return Err(ToolPlaygroundIfMatchError::Invalid);
    }
    let value = value
        .to_str()
        .map_err(|_| ToolPlaygroundIfMatchError::Invalid)?
        .trim();
    if value.len() > 1_024
        || value.len() < 2
        || !value.starts_with('"')
        || !value.ends_with('"')
        || !value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| *byte == b'!' || (b'#'..=b'~').contains(byte))
    {
        return Err(ToolPlaygroundIfMatchError::Invalid);
    }
    Ok(value.to_owned())
}

pub(super) fn if_match_error_response(error: IfMatchError) -> Response {
    match error {
        IfMatchError::Missing => precondition_required("If-Match header is required"),
        IfMatchError::InvalidHeader => bad_request("If-Match header must be valid ASCII"),
    }
}

pub(super) fn policy_validation_failed(errors: Vec<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(PolicyValidationResponse {
            valid: false,
            errors,
        }),
    )
        .into_response()
}
