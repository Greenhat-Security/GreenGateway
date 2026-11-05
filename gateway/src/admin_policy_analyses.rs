//! `POST /v1{ADMIN_PREFIX}/policy/analyses` (issue #243, slice 15): analyze
//! the structure of the active policy or a candidate -- position-aware edits
//! over it, an inline document, a server-side draft the caller owns, or a
//! version of the policy history -- and answer stable findings with advisory
//! candidate patches, as JSON or SARIF 2.1.0.
//!
//! An analysis is a read with no side effects. It needs `admin:policy:read`
//! and `admin:policy:analyze`, both checked before the body is read;
//! persists, activates and rewrites nothing -- a patch is returned, never
//! applied -- and leaves exactly one record, the `policy.analysis_run` audit
//! event, which carries digests, ETags and counts, never a finding's element
//! or any policy content. The analysis is the pure
//! [`policy_analysis::checks::analyze`] on a blocking thread, behind its own
//! [`PolicyEvaluationLimiter`] and a deadline. Running out of the deadline,
//! the comparison budget or the findings cap is an incomplete result, never
//! a clean one.
//!
//! Each finding is reported with its suppression state (issue #243, slice
//! 15): the endpoint reads the deployment's suppression records and the
//! resource snapshot once, and [`policy_analysis::suppression::apply`] marks
//! a finding suppressed only when a record binds this analysis exactly. A
//! store that cannot be read suppresses nothing, and the result says so.
use std::time::{Duration, Instant};

use super::*;

use policy_analysis::{
    checks::{analyze, AnalysisResources},
    report::AnalysisBinding,
    request::{parse_request, AnalysisFormat},
    suppression, AnalysisError,
};
use policy_simulation::request::CandidateSource;

/// Most analyses running at once across this replica. An analysis is
/// CPU-only and bounded by its comparison budget and deadline; this bounds
/// how many compete with the data plane at the same moment. Over the bound
/// is `429`, never queued.
pub(super) const MAX_CONCURRENT_POLICY_ANALYSES: usize = 2;
/// Largest analysis request body, in bytes: room for a complete inline
/// candidate at the policy compiler's 1 MiB bound.
pub(super) const MAX_POLICY_ANALYSIS_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Largest rendered result, in bytes. A result over it is refused whole,
/// never cut short.
pub(super) const MAX_POLICY_ANALYSIS_RESULT_BYTES: usize = 8 * 1024 * 1024;
/// The wall-clock bound on one analysis.
pub(super) const POLICY_ANALYSIS_DEADLINE: Duration = Duration::from_secs(2);

fn analysis_refusal(status: StatusCode, error: &str, reason: &'static str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "reason": reason,
        })),
    )
        .into_response()
}

fn analysis_invalid(diagnostics: &policy_testing::suite::Diagnostics) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "policy analysis request is invalid",
            "reason": "policy_analysis_invalid",
            "diagnostics": diagnostics.diagnostics,
            "diagnostics_truncated": diagnostics.truncated,
        })),
    )
        .into_response()
}

fn emit_policy_analysis_run(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    format: AnalysisFormat,
    binding: &AnalysisBinding<'_>,
    outcome: &policy_analysis::AnalysisOutcome,
    suppressions: &suppression::SuppressionOutcome,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let mut payload = json!({
        "request_digest": binding.request_digest,
        "base_etag": binding.base_etag,
        "candidate_source": binding.source,
        "candidate_etag": binding.analyzed_etag,
        "edits": binding.edit_count,
        "format": format.as_str(),
        "complete": outcome.complete,
        "limitations": outcome
            .limitations
            .iter()
            .map(|limitation| limitation.as_str())
            .collect::<Vec<_>>(),
        // Counts by severity, proof basis, code and suppression state only:
        // no element, pointer, fingerprint or suppression id.
        "summary": policy_analysis::report::summary(outcome, suppressions),
        "suppressions_available": suppressions.available,
        "resource_snapshot_complete": binding.resource_snapshot.is_complete(),
        "analyzer_version": policy_analysis::ANALYZER_VERSION,
        "http_semantics_version": policy_eval::HTTP_SEMANTICS_VERSION,
        "tool_semantics_version": policy_eval::tools::TOOL_SEMANTICS_VERSION,
    });
    if let Some(payload) = payload.as_object_mut() {
        if let Some(revision) = binding.security_revision {
            payload.insert("security_revision".to_owned(), json!(revision));
        }
        if let Some(digest) = binding.resource_snapshot.digest() {
            payload.insert("resource_snapshot_digest".to_owned(), json!(digest));
        }
        // Which draft or history version, never its content.
        if let Some(stored) = binding.stored {
            stored.describe("candidate_", payload);
        }
    }
    state.audit.emit(audit::AuditEvent::new(
        audit::event::POLICY_ANALYSIS_RUN,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        payload,
    ));
}

pub(super) async fn policy_analyses_endpoint(
    State(state): State<PolicyAdminState>,
    Extension(limiter): Extension<Arc<PolicyEvaluationLimiter>>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_ANALYSES_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, &principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };
    if !rbac_state.principal_has_permission(&principal, ADMIN_POLICY_ANALYZE_PERMISSION) {
        return admin_permission_denied_response(ADMIN_POLICY_ANALYZE_PERMISSION.to_owned());
    }
    let body_limit = state.max_body_size.min(MAX_POLICY_ANALYSIS_BODY_BYTES);
    let body = match read_request_body(body, body_limit).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    // Admitted once the body is in hand, so a slot bounds analyses doing
    // work rather than uploads in flight.
    let Some(slot) = limiter.try_acquire(policy_evaluation_actor(&principal)) else {
        return analysis_refusal(
            StatusCode::TOO_MANY_REQUESTS,
            "too many policy analyses are in progress; retry later",
            "policy_analysis_busy",
        );
    };
    // A repeated member is refused before anything reads the body: a JSON
    // value keeps the last of two and says nothing, so the request digested
    // and analyzed could differ from the one a reviewer read.
    if !policy_eval::input::has_unique_members(&body) {
        return analysis_refusal(
            StatusCode::BAD_REQUEST,
            "policy analysis body must be JSON with unique object members",
            "policy_analysis_request_invalid",
        );
    }
    let Ok(document) = serde_json::from_slice::<Value>(&body) else {
        return analysis_refusal(
            StatusCode::BAD_REQUEST,
            "policy analysis body must be JSON",
            "policy_analysis_request_invalid",
        );
    };
    let analysis = match parse_request(&body, &document) {
        Ok(analysis) => analysis,
        Err(diagnostics) => return analysis_invalid(&diagnostics),
    };

    let (base, base_etag, authority) = match simulation_base(&state, rbac_state).await {
        Ok(base) => base,
        Err(response) => return *response,
    };
    // The pin is required and exact: every position a finding or patch
    // names is a position in the document its author read. No rebase is
    // attempted; a stale pin is the same `412` a stale `If-Match` is.
    if analysis.base_etag != base_etag {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "error": "the active policy is no longer the one this analysis was written against",
                "reason": "policy_analysis_base_stale",
                "current_etag": base_etag,
            })),
        )
            .into_response();
    }
    let ResolvedCandidate {
        policy: candidate,
        stored,
    } = match resolve_candidate(
        &state,
        rbac_state,
        &principal,
        &base,
        &base_etag,
        &analysis.candidate,
    )
    .await
    {
        Ok(candidate) => candidate,
        Err(CandidateRefusal::Edits(diagnostics)) => return analysis_invalid(&diagnostics),
        Err(CandidateRefusal::Invalid(errors)) => return simulation_candidate_refused(errors),
        Err(CandidateRefusal::Stored(response)) => return *response,
        Err(CandidateRefusal::Internal) => return internal_server_error("policy analysis failed"),
    };
    let analyzed_etag = match candidate.as_ref().map(policy_etag) {
        None => base_etag.clone(),
        Some(Ok(etag)) => etag,
        Some(Err(error)) => {
            tracing::error!(error = %error, "failed to compute candidate policy ETag");
            return internal_server_error("policy ETag computation failed");
        }
    };
    let alias_paths = rbac_state.mcp_alias_paths();
    let alias_count = alias_paths.len();
    let analyzed = candidate.unwrap_or(base);
    let analyzed_semantic_digest = match policy_semantic_digest(&analyzed) {
        Ok(digest) => digest,
        Err(response) => return *response,
    };
    // What a suppression binds besides the policy: the resources as they
    // are now, and the records as the store reads them now. Neither changes
    // what the analyzer finds; together they decide how a finding reads.
    let resource_snapshot =
        rbac::policy_resources::PolicyResourceSnapshot::of(&rbac_state.policy_resource_view());
    let suppression_read = read_analysis_suppressions(&state).await;

    // The blocking thread owns the slot, so a request dropped mid-analysis
    // keeps its slot until the analysis it started has ended. The deadline
    // starts before compilation, so compiling counts against it.
    let outcome = match slot
        .run_blocking(move || {
            let deadline = Instant::now() + POLICY_ANALYSIS_DEADLINE;
            analyze(
                &analyzed,
                &AnalysisResources {
                    mcp_alias_paths: &alias_paths,
                },
                deadline,
            )
        })
        .await
    {
        Ok(Ok(outcome)) => outcome,
        // An evaluator refusal of a question the analyzer built, or a broken
        // invariant, is a failed analysis: no partial result and nothing that
        // could read as a clean policy.
        Ok(Err(AnalysisError::Internal(code))) => {
            tracing::error!(code, "policy analysis failed");
            return internal_server_error("policy analysis failed");
        }
        Err(error) => {
            tracing::error!(error = %error, "policy analysis did not complete");
            return internal_server_error("policy analysis failed");
        }
    };
    let binding = AnalysisBinding {
        request_digest: &analysis.digest,
        base_etag: Some(&base_etag),
        security_revision: match authority {
            policy_eval::PolicyAuthority::PostgreSql { security_revision } => {
                Some(security_revision)
            }
            policy_eval::PolicyAuthority::Standalone => None,
        },
        source: analysis.candidate.as_str(),
        analyzed_etag: &analyzed_etag,
        analyzed_semantic_digest: analyzed_semantic_digest.as_deref(),
        edit_count: match &analysis.candidate {
            CandidateSource::Edits(edits) => edits.len(),
            _ => 0,
        },
        stored: stored.as_ref(),
        mcp_alias_paths: alias_count,
        resource_snapshot: &resource_snapshot,
    };
    let suppressions = match suppression::apply(
        &outcome.findings,
        &suppression_read,
        &suppression::SuppressionBinding {
            policy_etag: &analyzed_etag,
            policy_semantic_digest: analyzed_semantic_digest.as_deref(),
            resource_snapshot_digest: resource_snapshot
                .digest()
                .filter(|_| resource_snapshot.is_complete()),
        },
    ) {
        Ok(suppressions) => suppressions,
        Err(AnalysisError::Internal(code)) => {
            tracing::error!(code, "policy analysis suppressions could not be applied");
            return internal_server_error("policy analysis failed");
        }
    };
    let (content_type, rendered) = match analysis.format {
        AnalysisFormat::Json => (
            "application/json",
            policy_analysis::report::to_json(&outcome, &binding, &suppressions),
        ),
        AnalysisFormat::Sarif => (
            "application/sarif+json",
            policy_analysis::report::to_sarif(&outcome, &binding, &suppressions),
        ),
    };
    let body = match rendered.map(|value| serde_json::to_vec(&value)) {
        Ok(Ok(body)) => body,
        Ok(Err(error)) => {
            tracing::error!(error = %error, "failed to serialize policy analysis result");
            return internal_server_error("policy analysis result could not be rendered");
        }
        Err(AnalysisError::Internal(code)) => {
            tracing::error!(code, "failed to render policy analysis result");
            return internal_server_error("policy analysis result could not be rendered");
        }
    };
    if body.len() > MAX_POLICY_ANALYSIS_RESULT_BYTES {
        return analysis_refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "the policy analysis result exceeds its size bound",
            "policy_analysis_result_too_large",
        );
    }
    emit_policy_analysis_run(
        &state,
        &parts,
        &principal,
        analysis.format,
        &binding,
        &outcome,
        &suppressions,
    );
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}
