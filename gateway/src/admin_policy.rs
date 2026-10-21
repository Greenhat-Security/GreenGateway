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
    let mut patch = match parse_rule_patch_body(&body) {
        Ok(patch) => patch,
        Err(errors) => return policy_validation_failed(errors),
    };
    if patch.is_empty() {
        return bad_request(
            "rule patch must include at least one of enabled, methods, path, tool_name, principal, action",
        );
    }
    // A patch without a binding is an ordinary rule edit, exactly as before.
    // With one, it is a promotion or disable from the shadow review, and it
    // is applied only to the policy revision and evidence that were reviewed.
    let bound = match patch.shadow_review.take() {
        None => None,
        Some(binding) => match prepare_bound_shadow_transition(
            &state, &parts, &principal, rbac_state, &rule_id, &patch, binding,
        ) {
            Ok(bound) => Some(bound),
            Err(response) => return *response,
        },
    };

    let _policy_write_guard = rbac_state.policy_write_guard().await;

    let (before_policy, current_etag) = if let Some(bound) = bound.as_ref() {
        match current_policy_matching_reviewed_revision(
            &state,
            rbac_state,
            &parts.headers,
            &bound.binding.policy_etag,
        )
        .await
        {
            Ok(view) => view,
            Err(ReviewedRevisionError::Response(response)) => return *response,
            Err(ReviewedRevisionError::Stale { current_etag }) => {
                return refuse_bound_shadow_transition(
                    BoundShadowRefusalContext {
                        state: &state,
                        parts: &parts,
                        principal: &principal,
                        rule_id: &rule_id,
                        bound,
                    },
                    ShadowReviewRefusal::RevisionStale,
                    Some(&current_etag),
                    None,
                );
            }
        }
    } else {
        match current_policy_and_matching_if_match(&state, rbac_state, &parts.headers).await {
            Ok(view) => view,
            Err(response) => return *response,
        }
    };

    let rule_index = match rule_index_by_id(&before_policy, &rule_id) {
        Ok(rule_index) => rule_index,
        Err(error) => return rule_lookup_error_response(&rule_id, error),
    };

    if let Some(bound) = bound.as_ref() {
        match verify_shadow_review_binding(bound, &before_policy, &current_etag, rule_index).await {
            Ok(()) => {}
            Err(ShadowBindingMismatch::Failed(response)) => return *response,
            Err(ShadowBindingMismatch::Refused {
                refusal,
                current_evidence_digest,
            }) => {
                return refuse_bound_shadow_transition(
                    BoundShadowRefusalContext {
                        state: &state,
                        parts: &parts,
                        principal: &principal,
                        rule_id: &rule_id,
                        bound,
                    },
                    refusal,
                    Some(&current_etag),
                    current_evidence_digest.as_deref(),
                );
            }
        }
    }

    let mut candidate = before_policy.clone();
    let before_rule = candidate.rules[rule_index].clone();
    apply_rule_patch(&mut candidate.rules[rule_index], patch);
    let changed_fields = changed_rule_fields(&before_rule, &candidate.rules[rule_index]);

    let candidate = match validate_policy_candidate(&candidate) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };
    let updated_rule = candidate.rules[rule_index].clone();

    let mut diff_summary = json!({
        "action": "rule_updated",
        "rule_id": rule_id,
        "changed_fields": changed_fields,
    });
    if let (Some(bound), Some(summary)) = (bound.as_ref(), diff_summary.as_object_mut()) {
        summary.insert("shadow_review".to_owned(), bound.diff_summary());
    }
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
        return admin_permission_denied_response(ADMIN_AUDIT_READ_PERMISSION.to_owned());
    }
    let Some(query_store) = state.event_store.as_ref() else {
        return policy_evidence_unavailable("policy rule preview requires an audit query store");
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
    // Without an audit store there are no counts to report, not counts of
    // zero: answering every rule with `hits: 0` would present unread evidence
    // as "never matched".
    let Some(query_store) = state.query_store.as_ref() else {
        return policy_evidence_unavailable("policy rule hit counts require an audit query store");
    };
    let policy = rbac_state.current_policy();
    let counts = match query_store.rule_hit_counts().await {
        Ok(counts) => counts,
        Err(err) => {
            tracing::error!(error = %err, "failed to query policy rule hit counts");
            return internal_server_error("policy rule hit count query failed");
        }
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
        return admin_permission_denied_response(ADMIN_AUDIT_READ_PERMISSION.to_owned());
    }
    // An empty summary per shadow rule would read as "this rule would deny
    // nothing" and invite promoting it to enforced deny on evidence that was
    // never read.
    let Some(query_store) = state.query_store.as_ref() else {
        return policy_evidence_unavailable("policy shadow review requires an audit query store");
    };
    // The same authority read a bound promotion compares against, so the
    // `policy_etag` reported here is exactly what that write will check.
    let (policy, policy_etag) = match authoritative_policy_and_etag(&state, rbac_state).await {
        Ok(view) => view,
        Err(response) => return *response,
    };

    match read_shadow_review(query_store, &policy, &policy_etag).await {
        Ok(review) => Json(review).into_response(),
        Err(response) => *response,
    }
}

/// Media type and schema version of the payload a shadow-review evidence
/// digest frames (ADR-0004, "Canonical digest contract"). Changing what the
/// digest covers changes the version, so a binding minted by one build is
/// never verified against a differently shaped payload by another.
const SHADOW_EVIDENCE_DIGEST_MEDIA_TYPE: &str =
    "application/vnd.greengateway.shadow-review-evidence+json";
const SHADOW_EVIDENCE_DIGEST_SCHEMA_VERSION: &str = "0.1.0";

/// Upper bounds on the strings a shadow-review binding carries. A review
/// never mints anything longer: ETags and digests are fixed-length
/// `sha256:` values and window bounds are recorded audit timestamps.
const MAX_SHADOW_REVIEW_ETAG_BYTES: usize = 256;
const MAX_SHADOW_REVIEW_TIMESTAMP_BYTES: usize = 128;

/// The shadow review of `policy`: one entry per enabled shadow rule, each
/// with the evidence window and digest a promotion or disable must later be
/// bound to.
///
/// The review endpoint and the bound rule PATCH both build the review here,
/// from the same audit query and the same policy, so a binding minted by one
/// is verified by the other against an identically computed digest.
pub(super) async fn read_shadow_review(
    query_store: &storage::SqliteAuditEventStore,
    policy: &rbac::Policy,
    policy_etag: &str,
) -> ResponseResult<PolicyRuleShadowReviewResponse> {
    let shadow_rules = policy
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.enabled && rule.action == rbac::RuleAction::Shadow)
        .map(|(rule_index, rule)| (effective_rule_id(rule, rule_index), rule.clone()))
        .collect::<Vec<_>>();
    let rule_ids = shadow_rules
        .iter()
        .map(|(rule_id, _)| rule_id.clone())
        .collect::<Vec<_>>();

    let review = match query_store
        .shadow_rule_would_deny_summaries(&rule_ids)
        .await
    {
        Ok(review) => review,
        Err(err) => {
            tracing::error!(error = %err, "failed to query shadow rule review summaries");
            return Err(Box::new(internal_server_error(
                "shadow rule review query failed",
            )));
        }
    };

    let mut rules = Vec::with_capacity(shadow_rules.len());
    for (rule_id, rule) in shadow_rules {
        let summary = review.summaries.get(&rule_id);
        let mut entry = PolicyRuleShadowReviewSummary {
            rule_id,
            rule,
            would_deny_count: summary.map(|summary| summary.would_deny_count).unwrap_or(0),
            affected_principals: summary
                .map(|summary| summary.affected_principals.clone())
                .unwrap_or_default(),
            samples: summary
                .map(|summary| summary.samples.clone())
                .unwrap_or_default(),
            evidence_window: ShadowEvidenceWindow {
                from: summary.and_then(|summary| summary.oldest_timestamp.clone()),
                to: summary.and_then(|summary| summary.newest_timestamp.clone()),
            },
            evidence_digest: String::new(),
        };
        entry.evidence_digest =
            match shadow_evidence_digest(&entry, review.scan_truncated, policy_etag) {
                Ok(digest) => digest,
                Err(err) => {
                    tracing::error!(error = %err, "failed to digest shadow rule review evidence");
                    return Err(Box::new(internal_server_error(
                        "shadow rule review evidence digest failed",
                    )));
                }
            };
        rules.push(entry);
    }

    Ok(PolicyRuleShadowReviewResponse {
        scanned_event_count: review.scanned_event_count,
        scan_truncated: review.scan_truncated,
        policy_etag: policy_etag.to_owned(),
        rules,
    })
}

/// What one shadow-review entry's digest covers: everything the operator is
/// shown about the rule, whether the scan behind it was truncated, and the
/// policy revision it was read under. The scan-wide `scanned_event_count` is
/// left out on purpose: it moves whenever any shadow rule records an event,
/// and only this rule's evidence justifies changing this rule.
#[derive(Serialize)]
struct ShadowEvidenceDigestSubject<'a> {
    policy_etag: &'a str,
    rule_id: &'a str,
    rule: &'a rbac::Rule,
    would_deny_count: u64,
    affected_principals: &'a [audit::query::ShadowRuleAffectedPrincipal],
    samples: &'a [audit::query::ShadowRuleWouldDenySample],
    evidence_window: &'a ShadowEvidenceWindow,
    scan_truncated: bool,
}

fn shadow_evidence_digest(
    entry: &PolicyRuleShadowReviewSummary,
    scan_truncated: bool,
    policy_etag: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let subject = serde_json::to_value(ShadowEvidenceDigestSubject {
        policy_etag,
        rule_id: &entry.rule_id,
        rule: &entry.rule,
        would_deny_count: entry.would_deny_count,
        affected_principals: &entry.affected_principals,
        samples: &entry.samples,
        evidence_window: &entry.evidence_window,
        scan_truncated,
    })?;
    Ok(canonical_json::semantic_digest(
        SHADOW_EVIDENCE_DIGEST_MEDIA_TYPE,
        SHADOW_EVIDENCE_DIGEST_SCHEMA_VERSION,
        &subject,
    )?)
}

/// The change a rule PATCH bound to a shadow review makes. A binding vouches
/// for exactly one of these: any other field would change the rule in a way
/// the review never showed the operator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ShadowReviewTransition {
    /// `{"action":"deny"}`: enforce what the rule only reported.
    Promote,
    /// `{"enabled":false}`: stop evaluating the rule.
    Disable,
}

impl ShadowReviewTransition {
    pub(super) fn of(patch: &RulePatch) -> Option<Self> {
        if patch.methods.is_some()
            || patch.path.is_some()
            || patch.tool_name.is_some()
            || patch.principal.is_some()
        {
            return None;
        }
        match (patch.enabled, patch.action.as_ref()) {
            (None, Some(rbac::RuleAction::Deny)) => Some(Self::Promote),
            (Some(false), None) => Some(Self::Disable),
            _ => None,
        }
    }

    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Disable => "disable",
        }
    }
}

/// Why a promotion or disable bound to a shadow review was refused. Each has
/// a stable `reason` so a client can tell them apart without parsing text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ShadowReviewRefusal {
    /// The patch is not exactly a promotion or a disable.
    TransitionUnsupported,
    /// A binding field is empty or longer than any review produces.
    BindingInvalid,
    /// The policy changed after the review was read.
    RevisionStale,
    /// The target rule is not an enabled shadow rule, so no review covers it.
    RuleNotShadow,
    /// The rule's evidence now spans different events than were reviewed.
    WindowStale,
    /// Same window, but the evidence summary differs from what was reviewed.
    DigestStale,
}

impl ShadowReviewRefusal {
    pub(super) fn status(self) -> StatusCode {
        match self {
            Self::TransitionUnsupported | Self::BindingInvalid => StatusCode::BAD_REQUEST,
            Self::RevisionStale => StatusCode::PRECONDITION_FAILED,
            Self::RuleNotShadow | Self::WindowStale | Self::DigestStale => StatusCode::CONFLICT,
        }
    }

    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::TransitionUnsupported => "shadow_review_transition_unsupported",
            Self::BindingInvalid => "shadow_review_binding_invalid",
            Self::RevisionStale => "shadow_review_revision_stale",
            Self::RuleNotShadow => "shadow_review_rule_not_shadow",
            Self::WindowStale => "shadow_evidence_window_stale",
            Self::DigestStale => "shadow_evidence_digest_stale",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::TransitionUnsupported => {
                "a shadow review binding accepts only {\"action\":\"deny\"} or {\"enabled\":false}"
            }
            Self::BindingInvalid => "shadow review binding is malformed",
            Self::RevisionStale => "policy changed after this shadow review was read",
            Self::RuleNotShadow => "rule is not an enabled shadow rule",
            Self::WindowStale => {
                "shadow evidence for this rule covers different events than were reviewed"
            }
            Self::DigestStale => "shadow evidence for this rule changed since it was reviewed",
        }
    }

    pub(super) fn response(self) -> Response {
        (
            self.status(),
            Json(json!({
                "error": self.message(),
                "reason": self.reason(),
            })),
        )
            .into_response()
    }
}

/// A rule PATCH that carries a shadow-review binding, after the checks that
/// need no policy read.
pub(super) struct BoundShadowTransition {
    pub(super) transition: ShadowReviewTransition,
    pub(super) binding: ShadowReviewBinding,
    pub(super) query_store: Arc<storage::SqliteAuditEventStore>,
}

impl BoundShadowTransition {
    /// What the policy history and `policy.changed` record about the review
    /// a successful change was bound to.
    fn diff_summary(&self) -> Value {
        json!({
            "transition": self.transition.as_str(),
            "policy_etag": self.binding.policy_etag,
            "evidence_window": self.binding.evidence_window,
            "evidence_digest": self.binding.evidence_digest,
        })
    }
}

impl ShadowReviewBinding {
    fn is_well_formed(&self) -> bool {
        let etag_ok =
            !self.policy_etag.is_empty() && self.policy_etag.len() <= MAX_SHADOW_REVIEW_ETAG_BYTES;
        let digest_ok = self
            .evidence_digest
            .strip_prefix("sha256:")
            .is_some_and(|hex| {
                hex.len() == 64
                    && hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        let window_ok = [&self.evidence_window.from, &self.evidence_window.to]
            .into_iter()
            .flatten()
            .all(|bound| !bound.is_empty() && bound.len() <= MAX_SHADOW_REVIEW_TIMESTAMP_BYTES);
        etag_ok && digest_ok && window_ok
    }
}

/// Everything a bound promotion or disable can be refused for before the
/// policy is read: `admin:audit:read` (the review it re-reads carries
/// audit-derived principals and samples, and a refusal would otherwise
/// reveal whether new events arrived), the request shape, and whether there
/// is any evidence to compare against.
pub(super) fn prepare_bound_shadow_transition(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    rbac_state: &middleware::rbac::RbacState,
    rule_id: &str,
    patch: &RulePatch,
    binding: ShadowReviewBinding,
) -> ResponseResult<BoundShadowTransition> {
    if !rbac_state.principal_has_permission(principal, ADMIN_AUDIT_READ_PERMISSION) {
        return Err(Box::new(admin_permission_denied_response(
            ADMIN_AUDIT_READ_PERMISSION.to_owned(),
        )));
    }
    let Some(transition) = ShadowReviewTransition::of(patch) else {
        return Err(Box::new(
            ShadowReviewRefusal::TransitionUnsupported.response(),
        ));
    };
    if !binding.is_well_formed() {
        return Err(Box::new(ShadowReviewRefusal::BindingInvalid.response()));
    }
    let Some(query_store) = state.query_store.clone() else {
        emit_policy_shadow_transition_refused(
            state,
            parts,
            principal,
            ShadowTransitionRefusal {
                transition,
                rule_id,
                reason: POLICY_EVIDENCE_UNAVAILABLE_REASON,
                binding: &binding,
                current_policy_etag: None,
                current_evidence_digest: None,
            },
        );
        return Err(Box::new(policy_evidence_unavailable(
            "shadow rule promotion and disable require an audit query store",
        )));
    };

    Ok(BoundShadowTransition {
        transition,
        binding,
        query_store,
    })
}

/// Compare a bound transition with the evidence as it stands now. The caller
/// holds the policy write guard and has already matched the binding's
/// revision, so `policy` is the revision that was reviewed and nothing can
/// change it before the commit.
///
/// The review is re-read in full, exactly as the review endpoint reads it,
/// rather than for this rule alone: the scan ceiling is shared across every
/// shadow rule, so only the same query reproduces the same per-rule result.
pub(super) async fn verify_shadow_review_binding(
    bound: &BoundShadowTransition,
    policy: &rbac::Policy,
    policy_etag: &str,
    rule_index: usize,
) -> Result<(), ShadowBindingMismatch> {
    let Some(rule) = policy.rules.get(rule_index) else {
        return Err(ShadowBindingMismatch::refused(
            ShadowReviewRefusal::RuleNotShadow,
        ));
    };
    if !rule.enabled || rule.action != rbac::RuleAction::Shadow {
        return Err(ShadowBindingMismatch::refused(
            ShadowReviewRefusal::RuleNotShadow,
        ));
    }
    let rule_id = effective_rule_id(rule, rule_index);

    let review = read_shadow_review(bound.query_store.as_ref(), policy, policy_etag)
        .await
        .map_err(ShadowBindingMismatch::Failed)?;
    let Some(current) = review
        .rules
        .into_iter()
        .find(|entry| entry.rule_id == rule_id)
    else {
        return Err(ShadowBindingMismatch::refused(
            ShadowReviewRefusal::RuleNotShadow,
        ));
    };

    if current.evidence_window != bound.binding.evidence_window {
        return Err(ShadowBindingMismatch::Refused {
            refusal: ShadowReviewRefusal::WindowStale,
            current_evidence_digest: Some(current.evidence_digest),
        });
    }
    if current.evidence_digest != bound.binding.evidence_digest {
        return Err(ShadowBindingMismatch::Refused {
            refusal: ShadowReviewRefusal::DigestStale,
            current_evidence_digest: Some(current.evidence_digest),
        });
    }
    Ok(())
}

pub(super) enum ShadowBindingMismatch {
    /// The binding no longer describes the current evidence.
    Refused {
        refusal: ShadowReviewRefusal,
        current_evidence_digest: Option<String>,
    },
    /// The evidence could not be re-read; the change is refused with this
    /// response, never applied on the strength of the old review.
    Failed(Box<Response>),
}

impl ShadowBindingMismatch {
    fn refused(refusal: ShadowReviewRefusal) -> Self {
        Self::Refused {
            refusal,
            current_evidence_digest: None,
        }
    }
}

/// The request a refused bound promotion or disable belongs to.
struct BoundShadowRefusalContext<'a> {
    state: &'a PolicyAdminState,
    parts: &'a http::request::Parts,
    principal: &'a auth::Principal,
    rule_id: &'a str,
    bound: &'a BoundShadowTransition,
}

/// Answer a refused bound promotion or disable, after recording it: the
/// refusal is a decision not to change enforcement, and like the change it
/// prevented it belongs in the audit stream.
fn refuse_bound_shadow_transition(
    context: BoundShadowRefusalContext<'_>,
    refusal: ShadowReviewRefusal,
    current_policy_etag: Option<&str>,
    current_evidence_digest: Option<&str>,
) -> Response {
    emit_policy_shadow_transition_refused(
        context.state,
        context.parts,
        context.principal,
        ShadowTransitionRefusal {
            transition: context.bound.transition,
            rule_id: context.rule_id,
            reason: refusal.reason(),
            binding: &context.bound.binding,
            current_policy_etag,
            current_evidence_digest,
        },
    );
    refusal.response()
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
    preview_rule_with_scan_limit(query_store, request, MAX_RULE_PREVIEW_SCAN_ROWS).await
}

/// Scan at most `max_scan_rows` observations, newest first, however wide the
/// requested window is. A window holding more rows than that answers with
/// `scan_truncated` and `complete: false`, so a count over the newest rows is
/// never presented as a count over the whole window.
pub(super) async fn preview_rule_with_scan_limit(
    query_store: &dyn storage::AuditEventStore,
    request: PolicyRulePreviewRequest,
    max_scan_rows: usize,
) -> Result<PolicyRulePreviewResponse, storage::RepositoryError> {
    let matcher = rbac::RuleMatcher::new(std::slice::from_ref(&request.rule));
    let sample_limit = request
        .sample_limit
        .unwrap_or(DEFAULT_RULE_PREVIEW_SAMPLE_LIMIT)
        .min(MAX_RULE_PREVIEW_SAMPLE_LIMIT);
    let max_scan_rows = u64::try_from(max_scan_rows).unwrap_or(u64::MAX);
    let mut match_count = 0_u64;
    let mut scanned_event_count = 0_u64;
    let mut scan_truncated = false;
    let mut samples = Vec::with_capacity(sample_limit);

    let mut filters = audit::query::RequestObservationFilters {
        from: request.from,
        to: request.to,
        methods: request.rule.methods.clone(),
        path_exact: exact_preview_path_filter(&request.rule.path),
        path_prefix: prefix_preview_path_filter(&request.rule.path),
        before_id: None,
    };
    'scan: loop {
        let observations = query_store.query_request_observations(&filters).await?;
        if observations.is_empty() {
            break;
        }
        for observation in observations {
            // Reaching one more row after the ceiling is what proves the
            // window held more than was scanned; a scan that ends exactly at
            // the ceiling with nothing left is complete.
            if scanned_event_count >= max_scan_rows {
                scan_truncated = true;
                break 'scan;
            }
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
        scan_truncated,
        complete: !scan_truncated,
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
    let (before_policy, current_etag) = authoritative_policy_and_etag(state, rbac_state).await?;
    match if_match_matches(headers, &current_etag) {
        Ok(true) => Ok((before_policy, current_etag)),
        Ok(false) => Err(Box::new(precondition_failed(
            "If-Match does not match the current policy ETag",
        ))),
        Err(error) => Err(Box::new(if_match_error_response(error))),
    }
}

/// The current policy and its ETag as the authority sees them, with no
/// precondition: cluster mode reads the authoritative active document (whose
/// recorded ETag `active()` already verified against the document body),
/// standalone reads the compiled snapshot and hashes it.
pub(super) async fn authoritative_policy_and_etag(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
) -> ResponseResult<(rbac::Policy, String)> {
    #[cfg(feature = "postgres")]
    if let Some(control_plane) = state.control_plane.as_ref() {
        return match control_plane.active().await {
            Ok(Some(active)) => Ok((active.policy, active.etag)),
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
    let policy = rbac_state.current_policy();
    match policy_etag(&policy) {
        Ok(etag) => Ok((policy, etag)),
        Err(err) => {
            tracing::error!(error = %err, "failed to compute current policy ETag");
            Err(Box::new(internal_server_error(
                "policy ETag computation failed",
            )))
        }
    }
}

pub(super) enum ReviewedRevisionError {
    /// The reviewed revision is no longer the current one.
    Stale {
        current_etag: String,
    },
    Response(Box<Response>),
}

/// [`current_policy_and_matching_if_match`] for a change bound to a shadow
/// review, which also names the revision the review was read from.
///
/// A missing `If-Match` is still `428`. A reviewed revision that is no longer
/// current is reported before an `If-Match` mismatch, so the usual stale case
/// -- both carry the reviewed ETag -- gets the binding's stable reason.
pub(super) async fn current_policy_matching_reviewed_revision(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
    headers: &HeaderMap,
    reviewed_etag: &str,
) -> Result<(rbac::Policy, String), ReviewedRevisionError> {
    let (before_policy, current_etag) = authoritative_policy_and_etag(state, rbac_state)
        .await
        .map_err(ReviewedRevisionError::Response)?;
    let if_match = if_match_matches(headers, &current_etag).map_err(|error| {
        ReviewedRevisionError::Response(Box::new(if_match_error_response(error)))
    })?;
    if reviewed_etag != current_etag {
        return Err(ReviewedRevisionError::Stale { current_etag });
    }
    if !if_match {
        return Err(ReviewedRevisionError::Response(Box::new(
            precondition_failed("If-Match does not match the current policy ETag"),
        )));
    }
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
        admit_policy_document(context.state, context.parts, context.principal, candidate).await?;
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
                let installed = context.rbac_state.install_revision_snapshot_locked(
                    active.policy.clone(),
                    active.security_revision,
                    context.policy_write_guard,
                );
                // The commit is durable either way, so the change is audited
                // either way. Returning the install failure first would leave a
                // security change that actually happened absent from the audit
                // stream, which is a worse outcome than the failure it reports.
                emit_policy_rule_changed(
                    context.state,
                    context.parts,
                    context.principal,
                    before_policy,
                    &active.policy,
                    diff_summary,
                );
                if installed.is_err() {
                    return Err(Box::new(policy_snapshot_not_installable()));
                }
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

/// Ask the cluster's operation gate before committing a document that uses
/// a feature an older member cannot read (issue #426).
///
/// A document without such a feature needs nothing beyond the schema-17
/// contract every member shares, and passes without a roster read. One that
/// gives a role a `description` is the registered operation
/// `policy.role_descriptions`: it is committed only while every live member,
/// draining ones included, advertises `policy_role_descriptions`, because a
/// member built before the field refuses the whole document. The gate reads
/// the roster for every such write, logs and audits each refusal
/// (`cluster.operation_refused`), and the refused write commits nothing.
///
/// Every cluster-mode policy commit calls this: the policy API's mutations
/// through [`persist_policy_mutation`] and a discovery suggestion's
/// acceptance, which commits the whole document with the new rule in it. A
/// control plane with no roster to read refuses rather than admits.
#[cfg(feature = "postgres")]
pub(super) async fn admit_policy_document(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    candidate: &rbac::Policy,
) -> ResponseResult<()> {
    if !candidate.uses_role_descriptions() {
        return Ok(());
    }
    let requirement = &storage::compatibility::POLICY_ROLE_DESCRIPTIONS;
    let Some(membership) = state.membership.as_ref() else {
        tracing::error!(
            operation = requirement.operation,
            "a cluster-mode policy commit has no roster to ask; the gated write is refused"
        );
        return Err(Box::new(operation_refused(
            &storage::compatibility::OperationRefusal::RosterUnavailable,
        )));
    };
    let request = cluster_membership::GatedWriteRequest {
        request_id: client_ip::request_id(&parts.headers, &parts.extensions),
        source_ip: client_ip::canonical_client_ip(
            &parts.headers,
            &parts.extensions,
            &state.client_ip_policy,
        ),
        actor: Some(auth::actor_from_principal(principal)),
    };
    membership
        .admit_operation(requirement, &state.audit, &request)
        .await
        .map(|_| ())
        .map_err(|refusal| Box::new(operation_refused(&refusal)))
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
