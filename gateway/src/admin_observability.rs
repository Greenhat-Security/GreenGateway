//! admin observability boundary extracted from the application composition root.
use super::*;

pub(super) async fn schema_coverage_endpoint(
    State(state): State<SchemaAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(SCHEMA_COVERAGE_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    if !authorized_schema_reader(&state, principal) {
        return admin_permission_denied_response(ADMIN_SCHEMA_READ_PERMISSION.to_owned());
    }
    if !state.coverage.spec_configured() {
        return schema_not_configured();
    }
    let Some(query_store) = state.query_store.as_ref() else {
        return schema_discovery_not_configured();
    };

    let observed = match query_store.observed_endpoints().await {
        Ok(observed) => observed,
        Err(error) => {
            return discovery_query_error_response(
                error,
                "failed to query schema coverage discovery inventory",
                "schema coverage discovery query failed",
            )
        }
    };

    Json(state.coverage.compare(&observed)).into_response()
}

pub(super) async fn schema_inferred_endpoint(
    State(state): State<SchemaAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<InferredSchemaParams>,
) -> Response {
    record_request(SCHEMA_INFERRED_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if !authorized_schema_reader(&state, &principal) {
        return admin_permission_denied_response(ADMIN_SCHEMA_READ_PERMISSION.to_owned());
    }
    if !state.payload_capture_enabled {
        return payload_capture_not_configured();
    }
    let Some(query_store) = state.query_store.as_ref() else {
        return schema_inference_discovery_not_configured();
    };
    let query = match params.into_query() {
        Ok(query) => query,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match query_store
        .inferred_request_schema(&query.method, &query.endpoint_template)
        .await
    {
        Ok(Some(schema)) => (StatusCode::OK, Json(schema)).into_response(),
        Ok(None) => inferred_schema_no_samples(),
        Err(error) => discovery_query_error_response(
            error,
            "failed to query inferred request schema",
            "inferred schema query failed",
        ),
    }
}

pub(super) async fn audit_query_endpoint(
    State(state): State<AuditAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<AuditQueryParams>,
) -> Response {
    record_request(AUDIT_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };

    if let Err(error) = authorized_audit_state(&state, &principal, ADMIN_AUDIT_READ_PERMISSION) {
        return audit_admin_authz_error_response(error);
    }

    let Some(query_store) = state.query_store.as_ref() else {
        return service_unavailable("audit query store not configured");
    };

    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match query_store.query_events(&filters).await {
        Ok(page) => (
            StatusCode::OK,
            Json(AuditQueryResponse {
                events: page.events,
                next_cursor: page.next_cursor,
            }),
        )
            .into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to query audit events");
            internal_server_error("audit query failed")
        }
    }
}

pub(super) async fn signals_list_endpoint(
    State(state): State<SignalsAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<SignalListParams>,
) -> Response {
    record_request(SIGNALS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) = authorized_signals_state(&state, &principal, ADMIN_SIGNALS_READ_PERMISSION)
    {
        return signals_admin_authz_error_response(error);
    }

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return signals_discovery_not_configured();
    };
    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    let signals_page = match discovery_store.list_signals(&filters).await {
        Ok(page) => page,
        Err(error) => {
            return discovery_query_error_response(
                error,
                "failed to query discovery signals",
                "signals query failed",
            )
        }
    };

    (StatusCode::OK, Json(signals_page)).into_response()
}

pub(super) async fn signal_acknowledge_endpoint(
    State(state): State<SignalsAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    signal_transition_endpoint(
        state,
        request,
        id,
        discovery::signals::SignalLifecycleState::Acknowledged,
        SIGNAL_ACKNOWLEDGE_ADMIN_ROUTE,
    )
    .await
}

pub(super) async fn signal_dismiss_endpoint(
    State(state): State<SignalsAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    signal_transition_endpoint(
        state,
        request,
        id,
        discovery::signals::SignalLifecycleState::Dismissed,
        SIGNAL_DISMISS_ADMIN_ROUTE,
    )
    .await
}

pub(super) async fn signal_transition_endpoint(
    state: SignalsAdminState,
    request: AxumRequest,
    id: String,
    lifecycle_state: discovery::signals::SignalLifecycleState,
    route: &'static str,
) -> Response {
    record_request(route);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_signals_state(&state, &principal, ADMIN_SIGNALS_WRITE_PERMISSION)
    {
        return signals_admin_authz_error_response(error);
    }

    let id = id.trim().to_owned();
    if id.is_empty() {
        return bad_request("invalid signal id");
    }

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return signals_discovery_not_configured();
    };
    let expected_revision = match expected_revision_from_if_match(&parts.headers) {
        Ok(expected_revision) => expected_revision,
        Err(response) => return *response,
    };
    // Acknowledge leaves Open; dismiss also leaves Acknowledged, so an
    // operator who acknowledged a signal can still clear it (the state it
    // cannot leave is Dismissed). Either way a signal another admin
    // already moved out of the accepted states -- on this replica or any
    // other -- is refused with its current row, never overwritten.
    let expected = discovery::lifecycle::TransitionPrecondition::from_state(
        discovery::signals::SignalLifecycleState::Open,
    );
    let expected = if lifecycle_state == discovery::signals::SignalLifecycleState::Dismissed {
        expected.or_from_state(discovery::signals::SignalLifecycleState::Acknowledged)
    } else {
        expected
    }
    .with_revision(expected_revision);
    let signal = match discovery_store
        .transition_signal(&id, lifecycle_state, Some(&principal.user_id), expected)
        .await
    {
        Ok(discovery::lifecycle::TransitionOutcome::Applied(signal)) => signal,
        Ok(discovery::lifecycle::TransitionOutcome::Refused(refused)) => {
            let current = refused.current;
            let reason = if expected.accepts(current.state) {
                "signal_revision_mismatch"
            } else {
                "signal_not_open"
            };
            return lifecycle_transition_refused(
                "signal is not in a state this transition leaves, or not at the expected revision",
                reason,
                "signal",
                &current,
            );
        }
        Ok(discovery::lifecycle::TransitionOutcome::NotFound) => {
            return not_found("signal was not found")
        }
        Err(error) => {
            return discovery_query_error_response(
                error,
                "failed to transition discovery signal",
                "signal transition failed",
            )
        }
    };
    emit_signal_lifecycle_changed(&state, &parts, &principal, &signal);

    (StatusCode::OK, Json(signal)).into_response()
}

/// The expected lifecycle revision of a signal, suggestion, or review
/// transition (issue #241, PR 12), from `If-Match`: absent is an
/// unconditional transition (the from-state predicate still applies); the
/// value is the `revision` a read returned, bare or as a quoted ETag.
pub(super) fn expected_revision_from_if_match(headers: &HeaderMap) -> ResponseResult<Option<i64>> {
    expected_revision_header(headers, header::IF_MATCH.as_str(), "If-Match")
}

/// The expected suggestion revision on the accept route, where `If-Match`
/// is already the policy ETag; see [`SUGGESTION_REVISION_HEADER`].
pub(super) fn expected_suggestion_revision(headers: &HeaderMap) -> ResponseResult<Option<i64>> {
    expected_revision_header(
        headers,
        SUGGESTION_REVISION_HEADER,
        SUGGESTION_REVISION_HEADER,
    )
}

/// One `If-Match`-style revision precondition from `name`, reported
/// against `label`.
pub(super) fn expected_revision_header(
    headers: &HeaderMap,
    name: &str,
    label: &str,
) -> ResponseResult<Option<i64>> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(Box::new(bad_request(&format!(
            "{label} must carry exactly one expected revision"
        ))));
    }
    let value = value
        .to_str()
        .map_err(|_| Box::new(bad_request(&format!("{label} header must be valid ASCII"))))?
        .trim();
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    value
        .parse::<i64>()
        .ok()
        .filter(|revision| *revision >= 0)
        .map(Some)
        .ok_or_else(|| {
            Box::new(bad_request(&format!(
                "{label} must be the revision a read returned"
            )))
        })
}

/// `409` for a refused conditional transition: a stable `reason` and the
/// row as it is now under `field`, so the caller can re-read and decide
/// rather than overwrite.
pub(super) fn lifecycle_transition_refused<T: Serialize>(
    error: &str,
    reason: &str,
    field: &str,
    current: &T,
) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": error,
            "reason": reason,
            field: current,
        })),
    )
        .into_response()
}

/// `409` for a suggestion whose lifecycle precondition failed, on every
/// route that writes one (dismiss and accept, standalone and cluster):
/// the row as it is now plus a stable reason, so a caller that lost the
/// race re-reads instead of retrying blindly. A row still Open failed on
/// its revision; any other state means another admin moved it.
pub(super) fn suggestion_transition_refused_response(
    current: &discovery::suggestions::RuleSuggestion,
) -> Response {
    if current.state == discovery::suggestions::RuleSuggestionLifecycleState::Open {
        lifecycle_transition_refused(
            "suggestion is not at the expected revision",
            "suggestion_revision_mismatch",
            "suggestion",
            current,
        )
    } else {
        lifecycle_transition_refused(
            "suggestion is not open",
            "suggestion_not_open",
            "suggestion",
            current,
        )
    }
}

pub(super) async fn rule_suggestions_list_endpoint(
    State(state): State<SuggestionsAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<RuleSuggestionListParams>,
) -> Response {
    record_request(SUGGESTIONS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_suggestions_state(&state, &principal, ADMIN_SUGGESTIONS_READ_PERMISSION)
    {
        return suggestions_admin_authz_error_response(error);
    }

    let Some(suggestion_engine) = state.suggestion_engine.as_ref() else {
        return suggestions_discovery_not_configured();
    };
    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    let suggestions_page = match suggestion_engine.list_suggestion_page(filters).await {
        Ok(page) => page,
        Err(discovery::suggestions::RuleSuggestionError::InvalidCursor { parameter }) => {
            return bad_request(&format!("invalid query parameter: {parameter}"))
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to query rule suggestions");
            return internal_server_error("suggestions query failed");
        }
    };

    (StatusCode::OK, Json(suggestions_page)).into_response()
}

pub(super) async fn rule_suggestions_generate_endpoint(
    State(state): State<SuggestionsAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(SUGGESTIONS_GENERATE_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state = match authorized_suggestions_state(
        &state,
        &principal,
        ADMIN_SUGGESTIONS_WRITE_PERMISSION,
    ) {
        Ok(rbac_state) => rbac_state,
        Err(error) => return suggestions_admin_authz_error_response(error),
    };

    let Some(suggestion_engine) = state.suggestion_engine.as_ref() else {
        return suggestions_discovery_not_configured();
    };
    // The authority's policy, not this replica's snapshot: generation
    // filters candidates the policy already covers, and a suggestion minted
    // against a stale snapshot is never re-evaluated (see
    // [`authoritative_policy`]).
    let policy = match authoritative_policy(&state.policy, rbac_state).await {
        Ok(policy) => policy,
        Err(response) => return *response,
    };

    // Suggestion generation scans the audit and discovery stores: the
    // standalone handle runs that on the blocking pool, the cluster handle
    // awaits PostgreSQL; neither sits on the executor.
    let generation = match suggestion_engine.generate(policy).await {
        Ok(run) => run,
        Err(err) => {
            tracing::error!(error = %err, "failed to generate rule suggestions");
            return internal_server_error("suggestion generation failed");
        }
    };

    (StatusCode::OK, Json(generation)).into_response()
}

pub(super) async fn rule_suggestion_accept_endpoint(
    State(state): State<SuggestionsAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(SUGGESTION_ACCEPT_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_suggestions_state(&state, &principal, ADMIN_SUGGESTIONS_WRITE_PERMISSION)
    {
        return suggestions_admin_authz_error_response(error);
    }
    let rbac_state =
        match authorized_policy_state(&state.policy, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return policy_admin_authz_error_response(error),
        };
    if !policy_authority_configured(&state.policy) {
        return policy_not_configured();
    }

    let id = id.trim();
    if id.is_empty() {
        return bad_request("invalid suggestion id");
    }
    let Some(suggestion_engine) = state.suggestion_engine.as_ref() else {
        return suggestions_discovery_not_configured();
    };
    let expected_revision = match expected_suggestion_revision(&parts.headers) {
        Ok(expected_revision) => expected_revision,
        Err(response) => return *response,
    };
    // Held until this request has both written the policy and moved the
    // suggestion (issue #241, PR 12). Every other suggestion lifecycle
    // write in this process takes the same lock, so a concurrent dismissal
    // cannot land between the two halves of an acceptance and leave the
    // rule installed for a suggestion that reads `dismissed`.
    let _lifecycle_guard = state.lifecycle_guard.lock().await;
    let suggestion = match suggestion_engine.get_suggestion(id.to_owned()).await {
        Ok(Some(suggestion)) => suggestion,
        Ok(None) => return not_found("suggestion was not found"),
        Err(err) => {
            tracing::error!(error = %err, "failed to load rule suggestion");
            return internal_server_error("suggestion query failed");
        }
    };
    // The row must still be Open, and at the revision the caller read if
    // it named one (issue #241, PR 12). This is the early answer; the
    // authoritative check is the transition's own predicate below, which
    // is what two replicas cannot both pass.
    if suggestion.state != discovery::suggestions::RuleSuggestionLifecycleState::Open
        || expected_revision.is_some_and(|expected| expected != suggestion.revision)
    {
        return suggestion_transition_refused_response(&suggestion);
    }
    if !suggestion.is_identity_bound_for_acceptance() {
        return conflict(
            "baseline suggestion is missing issuer or authentication-method constraints",
        );
    }

    let dispatch = match suggestion_engine
        .direct_rule_suggestion_safety(suggestion.clone())
        .await
    {
        Ok(discovery::suggestions::DirectRuleSuggestionSafety::Safe(dispatch)) => dispatch,
        Ok(discovery::suggestions::DirectRuleSuggestionSafety::HostRouted) => {
            return conflict(
                "suggestion targets host-routed traffic and cannot be accepted as a direct rule",
            );
        }
        Ok(discovery::suggestions::DirectRuleSuggestionSafety::PathRouted) => {
            return conflict(
                "suggestion targets path-routed traffic and cannot be accepted as a direct rule",
            );
        }
        Ok(discovery::suggestions::DirectRuleSuggestionSafety::AmbiguousRouting) => {
            return conflict(
                "suggestion spans multiple upstream routing contexts and cannot be accepted as a direct rule",
            );
        }
        Ok(discovery::suggestions::DirectRuleSuggestionSafety::UnknownRoutingContext) => {
            return conflict(
                "suggestion predates trusted routing context and cannot be accepted; dismiss it and review newly classified traffic",
            );
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to revalidate rule suggestion routing context");
            return internal_server_error("suggestion routing-context validation failed");
        }
    };

    let mut proposed_rule = suggestion.proposed_rule.clone();
    if proposed_rule.tool_name.is_none() {
        // Recompute this binding from current trusted routing state instead of
        // trusting the copy persisted with the advisory suggestion.
        proposed_rule.dispatch = Some(dispatch);
    }

    // Cluster mode commits the rule and the transition in ONE transaction
    // at the authority (issue #241, PR 12): there is no window in which a
    // crash or another replica's commit can separate them.
    #[cfg(feature = "postgres")]
    if let Some(engine) = suggestion_engine.cluster() {
        return accept_suggestion_in_cluster(
            SuggestionAcceptContext {
                state: &state,
                parts: &parts,
                principal: &principal,
                rbac_state,
            },
            engine,
            id,
            suggestion.revision,
            proposed_rule,
        )
        .await;
    }

    let created = match create_policy_rule(
        &state.policy,
        &parts,
        &principal,
        rbac_state,
        proposed_rule,
    )
    .await
    {
        Ok(result) => result,
        Err(response) => return *response,
    };

    // Standalone acceptance is policy write, then the conditional
    // transition against the revision this handler validated (issue #241,
    // PR 12). Both steps run under `lifecycle_guard`, taken above and by
    // every other suggestion lifecycle write in this process, so nothing
    // can move the row in between: the transition below is refused only if
    // the row moved before this request read it, which the check above
    // already answered. If it is ever refused anyway the rule stays and
    // the caller learns the suggestion moved.
    let expected = discovery::lifecycle::TransitionPrecondition::from_state(
        discovery::suggestions::RuleSuggestionLifecycleState::Open,
    )
    .with_revision(Some(suggestion.revision));
    let suggestion = match suggestion_engine
        .transition_suggestion(
            id.to_owned(),
            discovery::suggestions::RuleSuggestionLifecycleState::Accepted,
            Some(principal.user_id.clone()),
            expected,
        )
        .await
    {
        Ok(discovery::lifecycle::TransitionOutcome::Applied(suggestion)) => suggestion,
        Ok(discovery::lifecycle::TransitionOutcome::Refused(refused)) => {
            return with_etag(
                lifecycle_transition_refused(
                    "suggestion was transitioned concurrently; the rule was created",
                    "suggestion_transitioned_concurrently",
                    "suggestion",
                    &refused.current,
                ),
                &created.new_etag,
            );
        }
        Ok(discovery::lifecycle::TransitionOutcome::NotFound) => {
            return not_found("suggestion was not found")
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to accept rule suggestion");
            return internal_server_error("suggestion transition failed");
        }
    };
    emit_suggestion_lifecycle_changed(&state, &parts, &principal, &suggestion);

    let response = (
        StatusCode::CREATED,
        [(header::ETAG, etag_header_value(&created.new_etag))],
        Json(RuleSuggestionAcceptResponse {
            suggestion,
            rule: created.rule,
        }),
    )
        .into_response();
    with_policy_history_append_warning(response, created.history_append_failed)
}

/// Cluster mode's acceptance (issue #241, PR 12): the rule the suggestion
/// proposes and the suggestion's transition to `accepted` commit in ONE
/// transaction at the authority, so the HA state model's rule 7 holds --
/// no partial success exists. The candidate is prepared exactly as
/// [`create_policy_rule`] prepares it (same `If-Match` precondition, same
/// validation, same diff summary), then committed by
/// [`storage::postgres_discovery_lifecycle::PostgresDiscoveryLifecycleStore::accept_suggestion`]
/// alongside the transition instead of on its own.
///
/// Everything with an effect outside the transaction happens AFTER it
/// commits: the local revision snapshot install and both audit events.
/// Audit is at-least-once by design, so an event describing an acceptance
/// that rolled back must be impossible, while losing the events of a
/// committed acceptance to a crash is tolerable.
#[cfg(feature = "postgres")]
pub(super) async fn accept_suggestion_in_cluster(
    context: SuggestionAcceptContext<'_>,
    engine: &discovery::cluster_suggestions::ClusterRuleSuggestionEngine,
    suggestion_id: &str,
    expected_revision: i64,
    proposed_rule: rbac::Rule,
) -> Response {
    let SuggestionAcceptContext {
        state,
        parts,
        principal,
        rbac_state,
    } = context;
    let _policy_write_guard = rbac_state.policy_write_guard().await;

    let prepared =
        match prepare_policy_rule_create(&state.policy, rbac_state, &parts.headers, proposed_rule)
            .await
        {
            Ok(prepared) => prepared,
            Err(response) => return *response,
        };

    let accepted = engine
        .suggestion_store()
        .accept_suggestion(
            storage::postgres_discovery_lifecycle::AcceptSuggestionRequest {
                suggestion_id,
                expected_revision: Some(expected_revision),
                actor: &principal.user_id,
                policy_commit: storage::PolicyCommitRequest {
                    precondition: storage::PolicyCommitPrecondition::Expected {
                        etag: prepared.current_etag.clone(),
                    },
                    candidate: &prepared.candidate,
                    actor_user_id: &principal.user_id,
                    diff_summary: &prepared.diff_summary,
                },
            },
        )
        .await;
    let accepted = match accepted {
        Ok(accepted) => accepted,
        Err(refused) => return suggestion_acceptance_refused_response(refused),
    };

    // Committed. Install the authority's snapshot before answering, as
    // every other cluster-mode policy mutation does, then emit the two
    // changes this request made.
    rbac_state.install_revision_snapshot_locked(
        accepted.policy.policy.clone(),
        accepted.policy.security_revision,
        &_policy_write_guard,
    );
    let rule = accepted
        .policy
        .policy
        .rules
        .get(prepared.position)
        .cloned()
        .unwrap_or(prepared.created_rule);
    emit_policy_rule_changed(
        &state.policy,
        parts,
        principal,
        &prepared.before_policy,
        &accepted.policy.policy,
        prepared.diff_summary,
    );
    emit_suggestion_lifecycle_changed(state, parts, principal, &accepted.suggestion);

    // No history warning header: cluster mode writes the history row
    // inside the same transaction, so an acceptance cannot succeed
    // without it.
    (
        StatusCode::CREATED,
        [(header::ETAG, etag_header_value(&accepted.policy.etag))],
        Json(RuleSuggestionAcceptResponse {
            suggestion: accepted.suggestion,
            rule,
        }),
    )
        .into_response()
}

/// Every way an atomic acceptance can decline, answered as the standalone
/// path answers the same condition. Each variant means the rule, the
/// history row, the outbox row and the transition were all rolled back
/// together -- with one caveat carried by the store's `AcceptRefused`
/// documentation: a store failure raised by the `COMMIT` itself leaves the
/// outcome indeterminate rather than negative (the halves still never
/// separate), and the audit events are not emitted for it.
#[cfg(feature = "postgres")]
pub(super) fn suggestion_acceptance_refused_response(
    refused: storage::postgres_discovery_lifecycle::AcceptRefused,
) -> Response {
    use storage::postgres_discovery_lifecycle::AcceptRefused;

    match refused {
        AcceptRefused::Suggestion(refused) => {
            suggestion_transition_refused_response(&refused.current)
        }
        AcceptRefused::NotFound => not_found("suggestion was not found"),
        AcceptRefused::UnsafeBaselineSuggestion { .. } => {
            conflict("baseline suggestion is missing issuer or authentication-method constraints")
        }
        AcceptRefused::Policy(storage::PolicyCommitError::PreconditionFailed) => {
            precondition_failed("If-Match does not match the current policy ETag")
        }
        // Policies publish no tool names; the variant is unreachable here
        // and answered as the conflict it would be.
        AcceptRefused::Policy(storage::PolicyCommitError::ToolNameTaken { tool_name, .. }) => {
            conflict(&format!(
                "policy commit reported a reserved tool name '{tool_name}'"
            ))
        }
        AcceptRefused::Policy(storage::PolicyCommitError::Store(error)) => {
            tracing::error!(
                error = %error,
                "policy commit inside suggestion acceptance failed; both halves rolled back, unless the COMMIT acknowledgement itself was lost"
            );
            service_unavailable("policy mutation could not be committed")
        }
        AcceptRefused::Store(error) => {
            tracing::error!(
                error = %error,
                "rule suggestion acceptance failed; both halves rolled back, unless the COMMIT acknowledgement itself was lost"
            );
            internal_server_error("suggestion acceptance failed")
        }
    }
}

pub(super) async fn rule_suggestion_dismiss_endpoint(
    State(state): State<SuggestionsAdminState>,
    Path(id): Path<String>,
    request: AxumRequest,
) -> Response {
    rule_suggestion_transition_endpoint(
        state,
        request,
        id,
        discovery::suggestions::RuleSuggestionLifecycleState::Dismissed,
        SUGGESTION_DISMISS_ADMIN_ROUTE,
    )
    .await
}

pub(super) async fn rule_suggestion_transition_endpoint(
    state: SuggestionsAdminState,
    request: AxumRequest,
    id: String,
    lifecycle_state: discovery::suggestions::RuleSuggestionLifecycleState,
    route: &'static str,
) -> Response {
    record_request(route);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_suggestions_state(&state, &principal, ADMIN_SUGGESTIONS_WRITE_PERMISSION)
    {
        return suggestions_admin_authz_error_response(error);
    }

    let id = id.trim();
    if id.is_empty() {
        return bad_request("invalid suggestion id");
    }

    let Some(suggestion_engine) = state.suggestion_engine.as_ref() else {
        return suggestions_discovery_not_configured();
    };
    let expected_revision = match expected_revision_from_if_match(&parts.headers) {
        Ok(expected_revision) => expected_revision,
        Err(response) => return *response,
    };
    // The "must be Open" check is the transition's own predicate (issue
    // #241, PR 12), so two replicas cannot both pass it. The lock is the
    // one an in-flight acceptance holds across its policy write and its
    // own transition, so this dismissal either happens entirely before
    // that acceptance reads the row (which then loses on the state
    // predicate, having written nothing) or entirely after it (and is
    // refused, the rule already installed).
    let expected = discovery::lifecycle::TransitionPrecondition::from_state(
        discovery::suggestions::RuleSuggestionLifecycleState::Open,
    )
    .with_revision(expected_revision);
    let _lifecycle_guard = state.lifecycle_guard.lock().await;
    let suggestion = match suggestion_engine
        .transition_suggestion(
            id.to_owned(),
            lifecycle_state,
            Some(principal.user_id.clone()),
            expected,
        )
        .await
    {
        Ok(discovery::lifecycle::TransitionOutcome::Applied(suggestion)) => suggestion,
        Ok(discovery::lifecycle::TransitionOutcome::Refused(refused)) => {
            return suggestion_transition_refused_response(&refused.current);
        }
        Ok(discovery::lifecycle::TransitionOutcome::NotFound) => {
            return not_found("suggestion was not found")
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to transition rule suggestion");
            return internal_server_error("suggestion transition failed");
        }
    };
    emit_suggestion_lifecycle_changed(&state, &parts, &principal, &suggestion);

    (StatusCode::OK, Json(suggestion)).into_response()
}

pub(super) async fn principal_list_endpoint(
    State(state): State<PrincipalAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<PrincipalListParams>,
) -> Response {
    record_request(PRINCIPALS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_principal_state(&state, &principal, ADMIN_PRINCIPALS_READ_PERMISSION)
    {
        return principal_admin_authz_error_response(error);
    }

    if !state.directory.is_enabled() {
        return principal_directory_not_configured();
    }
    let query = match params.into_query() {
        Ok(query) => query,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    let page = match PrincipalDirectoryStore::list(&state.directory, &query.filters).await {
        Ok(page) => page,
        Err(err) if err.invalid_parameter_name().is_some() => {
            return bad_request(&format!(
                "invalid query parameter: {}",
                err.invalid_parameter_name()
                    .expect("guard ensures a parameter")
            ))
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to query principal directory");
            return internal_server_error("principal directory query failed");
        }
    };
    let anonymous_request_count = match state.audit_query_store.as_ref() {
        Some(audit_query_store) => {
            match audit_query_store
                .anonymous_request_count(
                    query.filters.last_seen_after.clone(),
                    query.filters.last_seen_before.clone(),
                )
                .await
            {
                Ok(count) => count,
                Err(err) => {
                    tracing::error!(error = %err, "failed to query anonymous request count");
                    return internal_server_error("anonymous request count query failed");
                }
            }
        }
        None => 0,
    };

    (
        StatusCode::OK,
        Json(PrincipalListResponse {
            principals: page.principals,
            next_cursor: page.next_cursor,
            anonymous_request_count,
        }),
    )
        .into_response()
}

pub(super) async fn principal_detail_endpoint(
    State(state): State<PrincipalAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<PrincipalDetailParams>,
) -> Response {
    record_request(PRINCIPAL_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_principal_state(&state, &principal, ADMIN_PRINCIPALS_READ_PERMISSION)
    {
        return principal_admin_authz_error_response(error);
    }

    if !state.directory.is_enabled() {
        return principal_directory_not_configured();
    }
    let query = match params.into_query() {
        Ok(query) => query,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    let key = query.key.clone();
    let principal_record = match PrincipalDirectoryStore::get(&state.directory, &key).await {
        Ok(Some(principal)) => principal,
        Ok(None) => return not_found("principal was not found"),
        Err(err) => {
            tracing::error!(error = %err, "failed to query principal detail");
            return internal_server_error("principal detail query failed");
        }
    };
    let (endpoints_touched, rules_hit) = match state.audit_query_store.as_ref() {
        Some(audit_query_store) => {
            let summary_store = Arc::clone(audit_query_store.sqlite_query_store());
            let subject = principal_record.subject.clone();
            let issuer = principal_record.issuer.clone();
            let auth_method = principal_record.auth_method.clone();
            match tokio::task::spawn_blocking(move || {
                principal_audit_summary(&summary_store, &subject, &issuer, &auth_method)
            })
            .await
            {
                Ok(Ok(summary)) => summary,
                Ok(Err(err)) => {
                    tracing::error!(error = %err, "failed to query principal audit summary");
                    return internal_server_error("principal audit summary query failed");
                }
                Err(err) => {
                    tracing::error!(error = %err, "principal audit summary task failed");
                    return internal_server_error("principal audit summary query failed");
                }
            }
        }
        None => (Vec::new(), Vec::new()),
    };
    let anomaly_history = match state.discovery_store.as_ref() {
        Some(discovery_store) => {
            let auth_method =
                principal_directory_audit_auth_mode(principal_record.auth_method.as_str());
            match discovery_store
                .list_principal_endpoint_signals(
                    &principal_record.subject,
                    &principal_record.issuer,
                    auth_method,
                    DEFAULT_PRINCIPAL_ANOMALY_HISTORY_LIMIT,
                )
                .await
            {
                Ok(signals) => signals,
                Err(error) => {
                    return discovery_query_error_response(
                        error,
                        "failed to query principal anomaly history",
                        "principal anomaly history query failed",
                    )
                }
            }
        }
        None => Vec::new(),
    };

    (
        StatusCode::OK,
        Json(PrincipalDetailResponse {
            principal: principal_record,
            endpoints_touched,
            rules_hit,
            anomaly_history,
            tools_called: Vec::new(),
        }),
    )
        .into_response()
}

pub(super) async fn traffic_endpoint_list_endpoint(
    State(state): State<TrafficAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<TrafficEndpointListParams>,
) -> Response {
    record_request(TRAFFIC_ENDPOINTS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_traffic_state(&state, &principal, ADMIN_TRAFFIC_READ_PERMISSION) {
            Ok(rbac_state) => rbac_state.clone(),
            Err(error) => return traffic_admin_authz_error_response(error),
        };
    let include_open_signals =
        rbac_state.principal_has_permission(&principal, ADMIN_SIGNALS_READ_PERMISSION);

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return discovery_not_configured();
    };
    let query = match params.into_query() {
        Ok(query) => query,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    // The inventory query pages the discovery store through the read
    // trait: the SQLite implementation runs on the blocking pool, so the
    // reads never sit on the executor either way.
    match list_traffic_endpoint_page(
        discovery_store.as_ref(),
        &query,
        Some(&rbac_state),
        include_open_signals,
    )
    .await
    {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(error) => discovery_query_error_response(
            error,
            "failed to query traffic endpoint inventory",
            "traffic endpoint inventory query failed",
        ),
    }
}

pub(super) async fn traffic_endpoint_detail_endpoint(
    State(state): State<TrafficAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<TrafficEndpointDetailParams>,
) -> Response {
    record_request(TRAFFIC_ENDPOINT_DETAIL_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_traffic_state(&state, &principal, ADMIN_TRAFFIC_READ_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return traffic_admin_authz_error_response(error),
        };
    let include_open_signals =
        rbac_state.principal_has_permission(&principal, ADMIN_SIGNALS_READ_PERMISSION);

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return discovery_not_configured();
    };
    let params = match params.into_query() {
        Ok(params) => params,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    let mut endpoint = match discovery_store
        .get_endpoint_with_open_signal_summaries(
            &params.method,
            &params.endpoint_template,
            params.new_since_hours,
            include_open_signals,
        )
        .await
    {
        Ok(Some(endpoint)) => endpoint,
        Ok(None) => return not_found("traffic endpoint was not found"),
        Err(error) => {
            return discovery_query_error_response(
                error,
                "failed to query traffic endpoint detail",
                "traffic endpoint detail query failed",
            )
        }
    };
    apply_endpoint_detail_rule_coverage(&mut endpoint, Some(rbac_state));
    let principal_filters = discovery::query::PrincipalPageFilters {
        limit: params.principal_limit,
        cursor: params.principal_cursor.clone(),
    };
    let principals = match discovery_store
        .list_principals(
            &params.method,
            &params.endpoint_template,
            &principal_filters,
        )
        .await
    {
        Ok(page) => page,
        Err(error) => {
            return discovery_query_error_response(
                error,
                "failed to query traffic endpoint principals",
                "traffic endpoint principal query failed",
            )
        }
    };

    let audit = match state.audit_query_store.as_ref() {
        Some(audit_query_store) => {
            let filters = audit::query::EndpointAuditFilters {
                method: params.method.clone(),
                endpoint_template: params.endpoint_template.clone(),
                from: params
                    .from
                    .clone()
                    .or_else(|| Some(endpoint.first_seen.clone())),
                to: params
                    .to
                    .clone()
                    .or_else(|| Some(endpoint.last_seen.clone())),
                bucket: params.bucket,
                recent_limit: params.events_limit,
                recent_before_id: params.events_before_id,
            };
            match audit_query_store.query_endpoint_activity(&filters).await {
                Ok(activity) => TrafficEndpointAuditEnrichment {
                    available: true,
                    match_strategy: audit::query::ENDPOINT_AUDIT_MATCH_STRATEGY,
                    match_limitations: audit::query::ENDPOINT_AUDIT_MATCH_LIMITATIONS,
                    omitted_reason: None,
                    time_series_truncated: Some(activity.time_series_truncated),
                    time_series: Some(activity.time_series),
                    recent_events: Some(activity.recent_events),
                    recent_events_next_cursor: activity.recent_events_next_cursor,
                    recent_events_scan_truncated: Some(activity.recent_events_scan_truncated),
                },
                Err(err) => {
                    tracing::error!(error = %err, "failed to query traffic endpoint audit enrichment");
                    return internal_server_error("traffic endpoint audit enrichment query failed");
                }
            }
        }
        None => TrafficEndpointAuditEnrichment {
            available: false,
            match_strategy: audit::query::ENDPOINT_AUDIT_MATCH_STRATEGY,
            match_limitations: audit::query::ENDPOINT_AUDIT_MATCH_LIMITATIONS,
            omitted_reason: Some("AUDIT_SQLITE_PATH not configured"),
            time_series_truncated: None,
            time_series: None,
            recent_events: None,
            recent_events_next_cursor: None,
            recent_events_scan_truncated: None,
        },
    };

    (
        StatusCode::OK,
        Json(TrafficEndpointDetailResponse {
            endpoint,
            principals,
            audit,
        }),
    )
        .into_response()
}

pub(super) async fn traffic_endpoint_review_endpoint(
    State(state): State<TrafficAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(TRAFFIC_ENDPOINT_REVIEW_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_traffic_state(&state, &principal, ADMIN_TRAFFIC_WRITE_PERMISSION)
    {
        return traffic_admin_authz_error_response(error);
    }

    let Some(discovery_store) = state.discovery_store.as_ref() else {
        return discovery_not_configured();
    };
    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request = match serde_json::from_slice::<TrafficEndpointReviewRequest>(&body) {
        Ok(request) => request,
        Err(err) => {
            tracing::warn!(error = %err, "traffic endpoint review request body was invalid");
            return bad_request("invalid traffic endpoint review request body");
        }
    };
    let method = request.method.trim();
    if method.is_empty() {
        return bad_request("invalid traffic endpoint review request body: method");
    }
    let endpoint_template = request.endpoint_template.trim();
    if endpoint_template.is_empty() {
        return bad_request("invalid traffic endpoint review request body: endpoint_template");
    }

    let expected_revision = match expected_revision_from_if_match(&parts.headers) {
        Ok(expected_revision) => expected_revision,
        Err(response) => return *response,
    };
    let review = match discovery_store
        .set_endpoint_review(
            method,
            endpoint_template,
            request.reviewed,
            Some(&principal.user_id),
            expected_revision,
        )
        .await
    {
        Ok(discovery::lifecycle::TransitionOutcome::Applied(review)) => review,
        Ok(discovery::lifecycle::TransitionOutcome::Refused(refused)) => {
            return lifecycle_transition_refused(
                "traffic endpoint review is not at the expected revision",
                "review_revision_mismatch",
                "review",
                &refused.current,
            );
        }
        Ok(discovery::lifecycle::TransitionOutcome::NotFound) => {
            return not_found("traffic endpoint was not found")
        }
        Err(error) => {
            return discovery_query_error_response(
                error,
                "failed to update traffic endpoint review state",
                "traffic endpoint review update failed",
            )
        }
    };
    emit_traffic_endpoint_review_changed(
        &state,
        &parts,
        &principal,
        method,
        endpoint_template,
        &review,
    );

    (StatusCode::OK, Json(review)).into_response()
}

pub(super) async fn audit_events_stream_endpoint(
    State(state): State<AuditAdminState>,
    principal: Option<Extension<auth::Principal>>,
    Query(params): Query<AuditEventStreamParams>,
    #[cfg(feature = "postgres")] headers: http::HeaderMap,
) -> Response {
    record_request(AUDIT_EVENTS_STREAM_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };

    if let Err(error) = authorized_audit_state(&state, &principal, ADMIN_AUDIT_STREAM_PERMISSION) {
        return audit_admin_authz_error_response(error);
    }

    // Cluster mode: the durable stream. Committed events from every
    // replica, replayable from a reconnecting client's Last-Event-ID (the
    // SSE standard's resume mechanism, carried on every frame's `id:`
    // field), with the in-process broadcast demoted to a wake-up between
    // polls. Standalone mode keeps the broadcast-only stream unchanged:
    // there is no durable store to replay from, and the frames carry no
    // positions.
    #[cfg(feature = "postgres")]
    if let Some(store) = state.pg_audit.clone() {
        return match durable_audit_stream_start(
            store,
            &headers,
            params,
            state.event_sender.subscribe(),
        )
        .await
        {
            Ok(stream) => Sse::new(stream)
                .keep_alive(KeepAlive::default())
                .into_response(),
            Err(DurableStreamStartError::BadCursor) => {
                bad_request("Last-Event-ID must be a stream position (an integer)")
            }
            Err(DurableStreamStartError::ExpiredCursor {
                cursor,
                first_available,
            }) => {
                tracing::info!(
                    cursor,
                    first_available,
                    "audit stream reconnect cursor expired; client must resynchronize"
                );
                (
                    StatusCode::GONE,
                    Json(ErrorResponse {
                        error: format!(
                            "audit stream cursor {cursor} is older than the earliest \
                             retained event ({first_available}); reconnect without \
                             Last-Event-ID to stream new events, or use the audit \
                             query API to read the retained window"
                        ),
                    }),
                )
                    .into_response()
            }
            Err(DurableStreamStartError::Unavailable) => {
                service_unavailable("the durable audit stream is unavailable; retry")
            }
        };
    }

    Sse::new(audit_event_sse_stream(
        state.event_sender.subscribe(),
        params,
    ))
    .keep_alive(KeepAlive::default())
    .into_response()
}

#[cfg(feature = "postgres")]
pub(super) fn record_audit_stream_outcome(outcome: &'static str) {
    ::metrics::counter!(metrics::AUDIT_STREAM_CONNECTIONS_TOTAL, "outcome" => outcome).increment(1);
}

/// How far behind a resuming client reconnected: the distribution the
/// audit retention window has to cover, since a backlog approaching the
/// retained span is a consumer about to start getting `410 Gone` instead
/// of a gapless resume.
#[cfg(feature = "postgres")]
pub(super) fn record_audit_stream_replay_backlog(events: i64) {
    ::metrics::histogram!(metrics::AUDIT_STREAM_REPLAY_BACKLOG_EVENTS).record(events.max(0) as f64);
}

/// Count stream positions delivered at or below the cursor already
/// served. An invariant violation, not a workload measure -- see
/// [`metrics::AUDIT_STREAM_DUPLICATE_POSITIONS_TOTAL`].
#[cfg(feature = "postgres")]
pub(super) fn record_audit_stream_duplicates(positions: u64) {
    ::metrics::counter!(metrics::AUDIT_STREAM_DUPLICATE_POSITIONS_TOTAL).increment(positions);
}

/// Resolve where the durable stream starts and whether it can.
#[cfg(feature = "postgres")]
pub(super) async fn durable_audit_stream_start(
    store: Arc<storage::postgres_audit::PostgresAuditEventStore>,
    headers: &http::HeaderMap,
    params: AuditEventStreamParams,
    wake: tokio::sync::broadcast::Receiver<audit::AuditEvent>,
) -> Result<impl Stream<Item = Result<Event, Infallible>> + Send + 'static, DurableStreamStartError>
{
    let cursor = match headers.get("last-event-id").map(http::HeaderValue::to_str) {
        None => None,
        Some(Ok(value)) => match value.trim().parse::<i64>() {
            Ok(position) => Some(position),
            Err(_) => {
                record_audit_stream_outcome(AUDIT_STREAM_OUTCOME_CURSOR_INVALID);
                return Err(DurableStreamStartError::BadCursor);
            }
        },
        Some(Err(_)) => {
            record_audit_stream_outcome(AUDIT_STREAM_OUTCOME_CURSOR_INVALID);
            return Err(DurableStreamStartError::BadCursor);
        }
    };

    match cursor {
        Some(last_seen) => {
            let first_available = store.stream_first_available().await.map_err(|_| {
                record_audit_stream_outcome(AUDIT_STREAM_OUTCOME_UNAVAILABLE);
                DurableStreamStartError::Unavailable
            })?;
            // Overflow-safe form of `last_seen + 1 < first_available`:
            // subtracting from first_available (always >= 1) cannot
            // underflow, while adding to last_seen could overflow at
            // i64::MAX -- a caller-reachable value via the header.
            if last_seen < first_available - 1 {
                record_audit_stream_outcome(AUDIT_STREAM_OUTCOME_CURSOR_EXPIRED);
                return Err(DurableStreamStartError::ExpiredCursor {
                    cursor: last_seen,
                    first_available,
                });
            }
            record_audit_stream_outcome(AUDIT_STREAM_OUTCOME_REPLAY);
            // How far behind this client reconnected, which is the
            // distribution the audit retention window has to cover: a
            // backlog approaching the retained span is a consumer about to
            // start getting `410 Gone` instead of a gapless resume. A head
            // that cannot be read is not worth failing the replay over --
            // the stream is about to poll for it anyway -- so the
            // observation is simply skipped.
            if let Ok(head) = store.stream_head().await {
                record_audit_stream_replay_backlog(head.saturating_sub(last_seen));
            }
            Ok(durable_audit_stream(store, last_seen, params, wake))
        }
        None => {
            // No resume cursor: start at the committed head. The stream
            // delivers events that commit from now on, matching the
            // broadcast path's live-tail semantics.
            let head = store.stream_head().await.map_err(|_| {
                record_audit_stream_outcome(AUDIT_STREAM_OUTCOME_UNAVAILABLE);
                DurableStreamStartError::Unavailable
            })?;
            record_audit_stream_outcome(AUDIT_STREAM_OUTCOME_LIVE);
            Ok(durable_audit_stream(store, head, params, wake))
        }
    }
}

/// The durable stream loop: poll `stream_after` in bounded batches and
/// emit every retained event with its position as the SSE `id:` (so
/// reconnects resume exactly after it), applying the endpoint's filters
/// the same way the broadcast path does. While caught up, the loop waits
/// on the local broadcast channel or the idle-poll deadline, whichever
/// comes first -- the wake-up only sharpens same-replica latency; the
/// poll is what makes cross-replica events arrive. Backpressure is
/// inherent: each unfold step emits at most one event and polls at most
/// one bounded batch, and the HTTP sink pulls steps only as fast as the
/// client reads.
#[cfg(feature = "postgres")]
pub(super) fn durable_audit_stream(
    store: Arc<storage::postgres_audit::PostgresAuditEventStore>,
    start_after: i64,
    params: AuditEventStreamParams,
    wake: tokio::sync::broadcast::Receiver<audit::AuditEvent>,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    stream::unfold(
        (
            store,
            start_after,
            params,
            wake,
            std::collections::VecDeque::<(i64, audit::AuditEvent)>::new(),
        ),
        |(store, mut cursor, params, mut wake, mut pending)| async move {
            loop {
                // Emit one already-fetched event per step, in position
                // order, skipping events the filters exclude (the client's
                // cursor tracks positions it received; filtered-out
                // positions simply never become frames).
                while let Some((position, event)) = pending.pop_front() {
                    if !params.matches(&event) {
                        continue;
                    }
                    let event_type = event.event_type.clone();
                    let data = match serde_json::to_string(&event) {
                        Ok(data) => data,
                        Err(error) => {
                            tracing::error!(
                                error = %error,
                                "failed to serialize audit event for durable SSE stream"
                            );
                            continue;
                        }
                    };
                    return Some((
                        Ok(Event::default()
                            .event(event_type)
                            .data(data)
                            .id(position.to_string())),
                        (store, cursor, params, wake, pending),
                    ));
                }

                match store.stream_after(cursor, DURABLE_STREAM_BATCH).await {
                    Ok(batch) if batch.is_empty() => {
                        // Caught up: wait for a local wake-up or the idle
                        // poll deadline, then poll again. A lagged or
                        // closed broadcast channel is harmless -- the poll
                        // remains the source of truth.
                        tokio::select! {
                            result = wake.recv() => {
                                if result.is_err() {
                                    tokio::time::sleep(DURABLE_STREAM_IDLE_POLL).await;
                                }
                            }
                            _ = tokio::time::sleep(DURABLE_STREAM_IDLE_POLL) => {}
                        }
                        continue;
                    }
                    Ok(batch) => {
                        // An invariant check, not a workload measure: the
                        // store reads strictly after the cursor, so a
                        // position at or below it would mean re-delivering
                        // a frame under an `id:` the client has already
                        // seen -- silently corrupting a reconnecting
                        // consumer's idea of what it has processed. It is
                        // counted rather than asserted because ending the
                        // stream would turn a store-side bug into an
                        // outage, and the count is what makes the bug
                        // visible either way.
                        let duplicates = batch
                            .iter()
                            .filter(|(position, _)| *position <= cursor)
                            .count();
                        if duplicates > 0 {
                            record_audit_stream_duplicates(duplicates as u64);
                        }
                        // The batch is ordered by position; the cursor
                        // advances past everything fetched, whether or not
                        // the filters emit it -- otherwise a fully
                        // filtered batch would be re-fetched forever.
                        // (Assignment, not shadowing: the outer `cursor`
                        // must carry into the next poll AND into the
                        // unfold state on the next emit.)
                        cursor = batch
                            .last()
                            .map(|(position, _)| *position)
                            .unwrap_or(cursor);
                        pending = batch.into();
                        continue;
                    }
                    Err(error) => {
                        // A store failure mid-stream is fail-closed: end
                        // the stream so the client reconnects (its
                        // Last-Event-ID resumes exactly where it stopped).
                        // Silently continuing on the broadcast path would
                        // hide the gap.
                        tracing::error!(
                            error = %error,
                            "durable audit stream poll failed; ending stream for reconnect"
                        );
                        return None;
                    }
                }
            }
        },
    )
}

pub(super) fn audit_event_sse_stream(
    receiver: tokio::sync::broadcast::Receiver<audit::AuditEvent>,
    params: AuditEventStreamParams,
) -> impl Stream<Item = Result<Event, Infallible>> + Send + 'static {
    stream::unfold((receiver, params), |(mut receiver, params)| async move {
        loop {
            match receiver.recv().await {
                Ok(event) => {
                    if !params.matches(&event) {
                        continue;
                    }

                    let event_type = event.event_type.clone();
                    let data = match serde_json::to_string(&event) {
                        Ok(data) => data,
                        Err(err) => {
                            tracing::error!(
                                error = %err,
                                "failed to serialize audit event for SSE stream"
                            );
                            continue;
                        }
                    };

                    return Some((
                        Ok(Event::default().event(event_type).data(data)),
                        (receiver, params),
                    ));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::debug!(
                        skipped,
                        "audit event stream receiver lagged; skipping missed events"
                    );
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    })
}

pub(super) fn validate_rfc3339(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<String>, &'static str> {
    if let Some(value) = value.as_deref() {
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| parameter)?;
    }

    Ok(value)
}

pub(super) fn parse_optional_i64(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<i64>, &'static str> {
    value
        .map(|value| value.parse::<i64>().map_err(|_| parameter))
        .transpose()
}

pub(super) fn parse_optional_non_negative_i64(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<i64>, &'static str> {
    let Some(value) = parse_optional_i64(parameter, value)? else {
        return Ok(None);
    };
    if value < 0 {
        return Err(parameter);
    }

    Ok(Some(value))
}

pub(super) fn parse_optional_non_negative_u64(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<u64>, &'static str> {
    value
        .map(|value| {
            let parsed = value.parse::<u64>().map_err(|_| parameter)?;
            Ok(parsed)
        })
        .transpose()
}

pub(super) fn parse_new_since_hours(value: Option<String>) -> Result<u64, &'static str> {
    let hours = parse_optional_non_negative_u64("new_since_hours", value)?
        .unwrap_or(discovery::query::DEFAULT_NEW_SINCE_HOURS);
    if hours > discovery::query::MAX_NEW_SINCE_HOURS {
        return Err("new_since_hours");
    }
    Ok(hours)
}

pub(super) fn parse_optional_bool(
    parameter: &'static str,
    value: Option<String>,
) -> Result<Option<bool>, &'static str> {
    value
        .map(|value| match value.as_str() {
            "true" => Ok(true),
            "false" => Ok(false),
            _ => Err(parameter),
        })
        .transpose()
}

pub(super) fn parse_principal_type(
    value: Option<String>,
) -> Result<Option<auth::principal_directory::PrincipalTypeFilter>, &'static str> {
    value
        .map(|value| match value.as_str() {
            "human" => Ok(auth::principal_directory::PrincipalTypeFilter::Human),
            "service" => Ok(auth::principal_directory::PrincipalTypeFilter::Service),
            _ => Err("principal_type"),
        })
        .transpose()
}

pub(super) fn parse_policy_history_version(value: &str) -> Result<i64, &'static str> {
    match value.parse::<i64>() {
        Ok(version) if version > 0 => Ok(version),
        _ => Err("version"),
    }
}

pub(super) fn parse_limit(value: Option<String>) -> Result<usize, &'static str> {
    parse_limit_with_default(value, DEFAULT_AUDIT_QUERY_LIMIT)
}

pub(super) fn parse_limit_with_default(
    value: Option<String>,
    default_limit: usize,
) -> Result<usize, &'static str> {
    let Some(value) = value else {
        return Ok(default_limit);
    };
    let limit = value.parse::<usize>().map_err(|_| "limit")?;
    if limit == 0 {
        return Err("limit");
    }

    Ok(limit.min(MAX_AUDIT_QUERY_LIMIT))
}

pub(super) fn required_non_empty(
    parameter: &'static str,
    value: Option<String>,
) -> Result<String, &'static str> {
    let Some(value) = value else {
        return Err(parameter);
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(parameter);
    }

    Ok(value.to_owned())
}

pub(super) fn empty_string_as_none(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_owned())
        }
    })
}

pub(super) fn parse_endpoint_audit_bucket(
    value: Option<String>,
) -> Result<audit::query::EndpointAuditBucket, &'static str> {
    match value.as_deref().unwrap_or("hour") {
        "hour" => Ok(audit::query::EndpointAuditBucket::Hour),
        "day" => Ok(audit::query::EndpointAuditBucket::Day),
        _ => Err("bucket"),
    }
}

pub(super) fn parse_before_id(value: Option<String>) -> Result<Option<i64>, &'static str> {
    let Some(value) = value else {
        return Ok(None);
    };
    let before_id = value.parse::<i64>().map_err(|_| "before_id")?;
    if before_id < 0 {
        return Err("before_id");
    }

    Ok(Some(before_id))
}

pub(super) fn enrich_endpoint_summaries_with_rule_coverage(
    endpoints: &mut [discovery::query::EndpointSummary],
    rbac_state: Option<&middleware::rbac::RbacState>,
) {
    let Some(rbac_state) = rbac_state else {
        return;
    };
    let policy = rbac_state.current_policy();

    for endpoint in endpoints {
        apply_endpoint_summary_rule_coverage(endpoint, &policy);
    }
}

pub(super) async fn list_traffic_endpoint_page(
    discovery_store: &dyn discovery::query::DiscoveryReadStore,
    query: &TrafficEndpointListQuery,
    rbac_state: Option<&middleware::rbac::RbacState>,
    include_open_signals: bool,
) -> Result<discovery::query::EndpointListPage, discovery::query::DiscoveryQueryError> {
    let Some(covered_by_rule) = query.covered_by_rule else {
        let mut page = discovery_store
            .list_endpoints_with_open_signal_summaries(&query.filters, include_open_signals)
            .await?;
        enrich_endpoint_summaries_with_rule_coverage(&mut page.endpoints, rbac_state);
        return Ok(page);
    };

    let requested_limit = query.filters.limit;
    let mut scan_filters = query.filters.clone();
    scan_filters.limit = 1;
    let mut cursor = scan_filters.cursor.clone();
    let mut endpoints = Vec::with_capacity(requested_limit);
    let mut next_cursor = None;

    loop {
        scan_filters.cursor = cursor;
        let mut page = discovery_store
            .list_endpoints_with_open_signal_summaries(&scan_filters, include_open_signals)
            .await?;
        enrich_endpoint_summaries_with_rule_coverage(&mut page.endpoints, rbac_state);

        if let Some(endpoint) = page.endpoints.into_iter().next() {
            if endpoint.covered_by_rule == covered_by_rule {
                endpoints.push(endpoint);
                if endpoints.len() == requested_limit {
                    next_cursor = page.next_cursor;
                    break;
                }
            }
        }

        let Some(cursor_after_page) = page.next_cursor else {
            break;
        };
        cursor = Some(cursor_after_page);
    }

    Ok(discovery::query::EndpointListPage {
        endpoints,
        next_cursor,
    })
}

pub(super) fn principal_audit_summary(
    audit_query_store: &audit::query::AuditQueryStore,
    subject: &str,
    issuer: &str,
    auth_method: &str,
) -> Result<(Vec<PrincipalEndpointTouch>, Vec<String>), audit::query::AuditQueryError> {
    let page = audit_query_store.query(&audit::query::AuditQueryFilters {
        from: None,
        to: None,
        event_type: Some("http.request_observed".to_owned()),
        actor: Some(subject.to_owned()),
        actor_issuer: Some(issuer.to_owned()),
        actor_auth_mode: Some(principal_directory_audit_auth_mode(auth_method).to_owned()),
        method: None,
        path: None,
        status: None,
        matched_rule_id: None,
        limit: DEFAULT_PRINCIPAL_DETAIL_AUDIT_EVENT_LIMIT,
        before_id: None,
    })?;
    let mut endpoints = BTreeMap::<(String, String), (u64, String)>::new();
    let mut rules = BTreeSet::<String>::new();

    for event in page.events {
        let method = event
            .payload
            .get("method")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let path = event
            .payload
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let (Some(method), Some(path)) = (method, path) {
            let entry = endpoints
                .entry((method, path))
                .or_insert_with(|| (0, event.timestamp.clone()));
            entry.0 = entry.0.saturating_add(1);
            if rfc3339_after(&event.timestamp, &entry.1) {
                entry.1 = event.timestamp.clone();
            }
        }

        if let Some(rule_id) = event
            .payload
            .get("matched_rule_id")
            .and_then(Value::as_str)
            .filter(|rule_id| !rule_id.is_empty())
        {
            rules.insert(rule_id.to_owned());
        }
    }

    let mut endpoints = endpoints
        .into_iter()
        .map(
            |((method, path), (request_count, last_seen))| PrincipalEndpointTouch {
                method,
                path,
                request_count,
                last_seen,
            },
        )
        .collect::<Vec<_>>();
    endpoints.sort_by(|left, right| {
        right
            .last_seen
            .cmp(&left.last_seen)
            .then_with(|| left.method.cmp(&right.method))
            .then_with(|| left.path.cmp(&right.path))
    });

    Ok((endpoints, rules.into_iter().collect()))
}

pub(super) fn principal_directory_audit_auth_mode(auth_method: &str) -> &str {
    match auth_method {
        "bearer" => rbac::rule::AUTH_METHOD_BEARER_TOKEN,
        "cookie" => rbac::rule::AUTH_METHOD_SESSION_COOKIE,
        "service_token" => rbac::rule::AUTH_METHOD_SERVICE_TOKEN,
        other => other,
    }
}

pub(super) fn rfc3339_after(left: &str, right: &str) -> bool {
    match (
        OffsetDateTime::parse(left, &Rfc3339),
        OffsetDateTime::parse(right, &Rfc3339),
    ) {
        (Ok(left), Ok(right)) => left > right,
        _ => left > right,
    }
}

pub(super) fn apply_endpoint_detail_rule_coverage(
    endpoint: &mut discovery::query::EndpointAggregateDetail,
    rbac_state: Option<&middleware::rbac::RbacState>,
) {
    let Some(rbac_state) = rbac_state else {
        return;
    };
    if !endpoint.routing_context_known {
        endpoint.coverage_scope = discovery::query::EndpointCoverageScope::Unknown;
        endpoint.covered_by_rule = false;
        return;
    }
    let policy = rbac_state.current_policy();
    let method = endpoint.method.clone();
    let endpoint_template = endpoint.endpoint_template.clone();
    apply_routing_context_coverage(
        &mut endpoint.routing_contexts,
        &policy,
        &method,
        &endpoint_template,
    );
    endpoint.coverage_scope = aggregate_coverage_scope(
        &policy,
        &method,
        &endpoint_template,
        &endpoint.routing_contexts,
    );
    endpoint.covered_by_rule =
        endpoint.coverage_scope == discovery::query::EndpointCoverageScope::Endpoint;
}

pub(super) fn apply_endpoint_summary_rule_coverage(
    endpoint: &mut discovery::query::EndpointSummary,
    policy: &rbac::Policy,
) {
    if !endpoint.routing_context_known {
        endpoint.coverage_scope = discovery::query::EndpointCoverageScope::Unknown;
        endpoint.covered_by_rule = false;
        return;
    }
    let method = endpoint.method.clone();
    let endpoint_template = endpoint.endpoint_template.clone();
    apply_routing_context_coverage(
        &mut endpoint.routing_contexts,
        policy,
        &method,
        &endpoint_template,
    );
    endpoint.coverage_scope = aggregate_coverage_scope(
        policy,
        &method,
        &endpoint_template,
        &endpoint.routing_contexts,
    );
    endpoint.covered_by_rule =
        endpoint.coverage_scope == discovery::query::EndpointCoverageScope::Endpoint;
}

pub(super) fn apply_routing_context_coverage(
    contexts: &mut [discovery::query::EndpointRoutingContext],
    policy: &rbac::Policy,
    method: &str,
    endpoint_template: &str,
) {
    for context in contexts {
        context.coverage_scope =
            endpoint_coverage_scope(policy, method, endpoint_template, Some(context));
        context.covered_by_rule =
            context.coverage_scope == discovery::query::EndpointCoverageScope::Endpoint;
    }
}

pub(super) fn aggregate_coverage_scope(
    policy: &rbac::Policy,
    method: &str,
    endpoint_template: &str,
    contexts: &[discovery::query::EndpointRoutingContext],
) -> discovery::query::EndpointCoverageScope {
    if contexts.is_empty() {
        return endpoint_coverage_scope(policy, method, endpoint_template, None);
    }

    let first = contexts[0].coverage_scope;
    if contexts
        .iter()
        .all(|context| context.coverage_scope == first)
    {
        first
    } else {
        discovery::query::EndpointCoverageScope::Mixed
    }
}

pub(super) fn endpoint_coverage_scope(
    policy: &rbac::Policy,
    method: &str,
    endpoint_template: &str,
    context: Option<&discovery::query::EndpointRoutingContext>,
) -> discovery::query::EndpointCoverageScope {
    if policy.rules.is_empty() {
        return host_route_coverage_scope(policy, method, endpoint_template, context);
    }

    let path = representative_path_from_endpoint_template(endpoint_template);
    let matcher = rbac::RuleMatcher::new(&policy.rules);
    let host_qualified = context.and_then(|context| context.route_host.as_deref());
    let dispatch_context = context.map_or_else(rbac::RuleDispatchContext::unknown, |context| {
        rbac::RuleDispatchContext::classified_with_route_id(
            context
                .upstream_origin
                .as_deref()
                .and_then(|origin| origin.strip_prefix("pool:")),
            context.route_host.as_deref(),
            context.route_path_prefix.as_deref(),
            context.upstream_origin.as_deref(),
        )
    });
    let endpoint_wide = if host_qualified.is_some() {
        matcher
            .evaluate_denies_with_dispatch(method, &path, None, dispatch_context)
            .is_some()
    } else {
        matcher
            .evaluate_with_dispatch(method, &path, None, dispatch_context)
            .is_some()
    };
    if endpoint_wide {
        return discovery::query::EndpointCoverageScope::Endpoint;
    }

    let principal_scoped = policy.rules.iter().any(|rule| {
        let Some(principal) = representative_principal_for_rule(rule) else {
            return false;
        };
        if host_qualified.is_some() {
            matcher
                .evaluate_denies_with_dispatch(method, &path, Some(&principal), dispatch_context)
                .is_some()
        } else {
            matcher
                .evaluate_with_dispatch(method, &path, Some(&principal), dispatch_context)
                .is_some()
        }
    });
    if principal_scoped {
        return discovery::query::EndpointCoverageScope::Principal;
    }

    host_route_coverage_scope(policy, method, endpoint_template, context)
}

pub(super) fn host_route_coverage_scope(
    policy: &rbac::Policy,
    method: &str,
    endpoint_template: &str,
    context: Option<&discovery::query::EndpointRoutingContext>,
) -> discovery::query::EndpointCoverageScope {
    let Some(host) = context.and_then(|context| context.route_host.as_deref()) else {
        return discovery::query::EndpointCoverageScope::None;
    };
    let path = representative_path_from_endpoint_template(endpoint_template);
    let Some(route) = policy.routes.iter().find(|route| {
        rbac::matcher::method_matches(&route.methods, method)
            && path_match::path_prefix_matches(&path, &route.path_prefix)
            && route
                .hosts
                .iter()
                .any(|route_host| route_host.eq_ignore_ascii_case(host))
    }) else {
        return discovery::query::EndpointCoverageScope::None;
    };
    let permission_granted = policy.roles.values().any(|role| {
        role.permissions
            .iter()
            .any(|permission| permission == "*" || permission == &route.permission)
    });
    if permission_granted {
        discovery::query::EndpointCoverageScope::Principal
    } else {
        discovery::query::EndpointCoverageScope::None
    }
}

pub(super) fn representative_path_from_endpoint_template(endpoint_template: &str) -> String {
    let Some(tail) = endpoint_template.strip_prefix('/') else {
        return endpoint_template.to_owned();
    };
    if tail.is_empty() {
        return "/".to_owned();
    }

    let segments = tail
        .split('/')
        .map(representative_path_segment)
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

pub(super) fn representative_path_segment(segment: &str) -> String {
    let Some(capture) = segment
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        return segment.to_owned();
    };

    if capture.eq_ignore_ascii_case("id") {
        "123".to_owned()
    } else {
        "sample".to_owned()
    }
}

pub(super) fn representative_principal_for_rule(rule: &rbac::Rule) -> Option<auth::Principal> {
    if rule.principal.is_unconstrained() {
        return None;
    }

    let auth_method = if rule
        .principal
        .auth_methods
        .iter()
        .any(|method| method == rbac::rule::AUTH_METHOD_SERVICE_TOKEN)
    {
        auth::AuthMethod::ServiceToken
    } else if rule
        .principal
        .auth_methods
        .iter()
        .any(|method| method == rbac::rule::AUTH_METHOD_SESSION_COOKIE)
    {
        auth::AuthMethod::Cookie
    } else {
        auth::AuthMethod::Bearer
    };

    Some(auth::Principal {
        user_id: rule
            .principal
            .principal_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "traffic-coverage-principal".to_owned()),
        issuer: rule.principal.issuers.first().cloned(),
        email: None,
        org_id: None,
        roles: rule.principal.roles.clone(),
        session_id: "traffic-coverage".to_owned(),
        auth_method,
    })
}

pub(super) fn policy_error_message(error: &rbac::policy::PolicyError) -> String {
    match error {
        rbac::policy::PolicyError::Invalid(message) => message.clone(),
        _ => error.to_string(),
    }
}
