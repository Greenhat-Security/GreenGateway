//! `POST /v1{ADMIN_PREFIX}/policy/tests/runs` (issue #243, slice 11): run a
//! `policy-tests.v1` suite against the active policy, against a candidate
//! submitted with the run, or against a stored candidate -- a server-side
//! draft the caller owns, or a version of the policy history -- and answer
//! JSON, SARIF or JUnit.
//!
//! A run is a read. It needs `admin:policy:read` and `admin:policy:simulate`,
//! both checked before the body is read, persists nothing, activates nothing,
//! and emits one `policy.tests_run` audit record that carries digests, the
//! policy ETag and counts -- never a case, fixture value or policy content.
//! The evaluation itself is the pure runner in `policy_testing`, on a blocking
//! thread so a large suite cannot stall the async workers, under a deadline,
//! and behind the same per-replica and per-actor bound simulations use
//! ([`PolicyEvaluationLimiter`]). Egress cases and isolated rate sequences
//! read the same configuration a simulation does ([`synthetic_resources`]):
//! the static egress lane and the global rate lanes' configured limits, never
//! a live bucket, resolver or connection.
use super::*;

use policy_simulation::request::CandidateSource;
use policy_testing::report::PolicySource;
use serde_json::value::RawValue;

/// Most runs evaluating at once on this replica. A run is CPU-only and
/// bounded by its body, case and deadline limits; this bounds how many of
/// those can compete with the data plane at the same moment. A run over the
/// bound is refused with `429`, never queued and never allowed to displace
/// another.
pub(super) const MAX_CONCURRENT_POLICY_TEST_RUNS: usize = 4;
/// Largest test-run request body, in bytes: room for a complete inline
/// candidate at the policy compiler's 1 MiB bound plus its suite.
pub(super) const MAX_POLICY_TEST_RUN_BODY_BYTES: usize = 2 * 1024 * 1024;
/// How long a run's body may take to arrive. A run is admitted only once its
/// body is in hand, so a trickled upload holds no slot; this also stops it
/// holding the request open indefinitely.
pub(super) const POLICY_TEST_RUN_BODY_DEADLINE: Duration = Duration::from_secs(5);
/// The wall-clock bound on one run's evaluation, compilation included.
pub(super) const POLICY_TEST_RUN_DEADLINE: Duration = Duration::from_secs(5);
/// The run's overall result, for callers that only need a gate: `passed`,
/// `failed`, `incomplete` or `error`. Present on every completed run.
pub(super) const POLICY_TESTS_STATUS_HEADER: &str = "x-greengateway-policy-tests-status";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyTestFormat {
    Json,
    Sarif,
    Junit,
}

/// The request members and what they hold, before the suite is parsed.
struct PolicyTestRunRequest {
    suite: Value,
    candidate: Option<PolicyTestCandidate>,
    format: PolicyTestFormat,
}

/// What a run judges in place of the active policy.
enum PolicyTestCandidate {
    /// The exact bytes of the `policy` member, read later by the parser a
    /// policy write reads its body with.
    Inline(Box<RawValue>),
    /// The caller's draft, at the strong draft ETag the `candidate` member
    /// names.
    Draft {
        draft_id: String,
        draft_etag: String,
    },
    /// A version of the policy history.
    Revision { version: i64 },
}

/// The request bytes' `policy` member, unread.
#[derive(Deserialize)]
struct PolicyTestRunCandidateBytes<'a> {
    #[serde(borrow)]
    policy: &'a RawValue,
}

fn policy_tests_refusal(status: StatusCode, error: &str, reason: &'static str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "reason": reason,
        })),
    )
        .into_response()
}

fn parse_policy_test_run_request(body: &Bytes) -> ResponseResult<PolicyTestRunRequest> {
    // A repeated member is refused before anything reads the body: a JSON
    // value keeps the last of two and says nothing, so the suite digested and
    // run could differ from the one a reviewer read.
    if !policy_eval::input::has_unique_members(body) {
        return Err(Box::new(policy_tests_refusal(
            StatusCode::BAD_REQUEST,
            "policy test run body must be JSON with unique object members",
            "policy_tests_request_invalid",
        )));
    }
    let Ok(Value::Object(mut members)) = serde_json::from_slice::<Value>(body) else {
        return Err(Box::new(policy_tests_refusal(
            StatusCode::BAD_REQUEST,
            "policy test run body must be a JSON object",
            "policy_tests_request_invalid",
        )));
    };
    if members
        .keys()
        .any(|key| !matches!(key.as_str(), "suite" | "policy" | "candidate" | "format"))
    {
        return Err(Box::new(policy_tests_refusal(
            StatusCode::BAD_REQUEST,
            "policy test run body accepts only suite, policy, candidate and format",
            "policy_tests_request_invalid",
        )));
    }
    let format = match members.remove("format") {
        None => PolicyTestFormat::Json,
        Some(Value::String(format)) if format == "json" => PolicyTestFormat::Json,
        Some(Value::String(format)) if format == "sarif" => PolicyTestFormat::Sarif,
        Some(Value::String(format)) if format == "junit" => PolicyTestFormat::Junit,
        Some(_) => {
            return Err(Box::new(policy_tests_refusal(
                StatusCode::BAD_REQUEST,
                "format must be \"json\", \"sarif\" or \"junit\"",
                "policy_tests_request_invalid",
            )))
        }
    };
    let Some(suite) = members.remove("suite") else {
        return Err(Box::new(policy_tests_refusal(
            StatusCode::BAD_REQUEST,
            "policy test run body requires suite",
            "policy_tests_request_invalid",
        )));
    };
    // The member is there (the body was just read with it) and named once;
    // a `null` candidate stays a candidate, and is refused as one.
    let candidate = match (members.remove("policy"), members.remove("candidate")) {
        (None, None) => None,
        (Some(_), Some(_)) => {
            return Err(Box::new(policy_tests_refusal(
                StatusCode::BAD_REQUEST,
                "a policy test run judges an inline policy or a stored candidate, not both",
                "policy_tests_request_invalid",
            )))
        }
        (Some(_), None) => match serde_json::from_slice::<PolicyTestRunCandidateBytes<'_>>(body) {
            Ok(member) => Some(PolicyTestCandidate::Inline(member.policy.to_owned())),
            Err(_) => {
                return Err(Box::new(policy_tests_refusal(
                    StatusCode::BAD_REQUEST,
                    "the candidate policy could not be read from the request",
                    "policy_tests_request_invalid",
                )))
            }
        },
        (None, Some(candidate)) => Some(stored_test_candidate(body, &candidate)?),
    };
    Ok(PolicyTestRunRequest {
        suite,
        candidate,
        format,
    })
}

/// The `candidate` member: a draft or a history version, with exactly the
/// members a simulation's candidate of the same source has, parsed by the
/// simulation's parser. An inline document is the `policy` member's, and a
/// run has no base for edits to apply to.
fn stored_test_candidate(body: &[u8], value: &Value) -> ResponseResult<PolicyTestCandidate> {
    let mut diagnostics = policy_testing::suite::Diagnostics::new();
    let source = policy_simulation::request::parse_candidate(body, value, &mut diagnostics);
    if !diagnostics.is_empty() {
        return Err(Box::new(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "the policy test run candidate is invalid",
                    "reason": "policy_tests_request_invalid",
                    "diagnostics": diagnostics.diagnostics,
                    "diagnostics_truncated": diagnostics.truncated,
                })),
            )
                .into_response(),
        ));
    }
    match source {
        Some(CandidateSource::Draft {
            draft_id,
            draft_etag,
        }) => Ok(PolicyTestCandidate::Draft {
            draft_id,
            draft_etag,
        }),
        Some(CandidateSource::Revision { version }) => {
            Ok(PolicyTestCandidate::Revision { version })
        }
        _ => Err(Box::new(policy_tests_refusal(
            StatusCode::BAD_REQUEST,
            "a policy test run candidate is a draft or a revision; send a candidate document as policy",
            "policy_tests_request_invalid",
        ))),
    }
}

/// The policy a run judges, the authority it was read under, and its binding.
type PolicyUnderTest = (
    rbac::Policy,
    policy_eval::PolicyAuthority,
    policy_testing::report::PolicyBinding,
);

/// The policy a run judges and its binding: the active document as its
/// authority holds it, or a validated candidate.
async fn policy_under_test(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
    principal: &auth::Principal,
    headers: &HeaderMap,
    candidate: Option<PolicyTestCandidate>,
) -> ResponseResult<PolicyUnderTest> {
    let Some(candidate) = candidate else {
        return active_policy_under_test(state, rbac_state, headers).await;
    };
    // `If-Match` names the live policy. Against a candidate it would be a
    // precondition nothing checks, so it is refused rather than silently
    // ignored.
    if headers.contains_key(header::IF_MATCH) {
        return Err(Box::new(policy_tests_refusal(
            StatusCode::BAD_REQUEST,
            "If-Match pins the active policy and cannot be combined with a candidate policy",
            "policy_tests_request_invalid",
        )));
    }
    let (source, resolved) = match candidate {
        PolicyTestCandidate::Inline(candidate) => {
            return inline_policy_under_test(state, rbac_state, &candidate);
        }
        PolicyTestCandidate::Draft {
            draft_id,
            draft_etag,
        } => {
            // A run has no `base_etag`: a draft is judged only while it is
            // still pinned to the live policy, the one it would be published
            // over.
            let (_, live_etag, _) = simulation_base(state, rbac_state).await?;
            let resolved = draft_candidate(
                state,
                rbac_state,
                principal,
                &draft_id,
                &draft_etag,
                &live_etag,
            )
            .await;
            (PolicySource::Draft, resolved)
        }
        PolicyTestCandidate::Revision { version } => (
            PolicySource::Revision,
            revision_candidate(state, rbac_state, version).await,
        ),
    };
    // Read and validated as a simulation reads a stored candidate, and
    // judged with no live revision, as an inline candidate is.
    let resolved = resolved.map_err(|refusal| match refusal {
        CandidateRefusal::Invalid(errors) => Box::new(policy_candidate_refused(errors)),
        CandidateRefusal::Stored(response) => response,
        CandidateRefusal::Edits(_) | CandidateRefusal::Internal => {
            Box::new(internal_server_error("policy test run failed"))
        }
    })?;
    // A stored candidate is always a document of its own, never the base.
    let Some(candidate) = resolved.policy else {
        tracing::error!("a stored policy test candidate resolved to no document");
        return Err(Box::new(internal_server_error("policy test run failed")));
    };
    let etag = candidate_etag(&candidate)?;
    Ok((
        candidate,
        policy_eval::PolicyAuthority::Standalone,
        policy_testing::report::PolicyBinding {
            source,
            etag,
            security_revision: None,
            stored: resolved.stored,
        },
    ))
}

/// The active policy, under an optional `If-Match` pin.
async fn active_policy_under_test(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
    headers: &HeaderMap,
) -> ResponseResult<PolicyUnderTest> {
    // Cluster mode judges the authoritative active document, exactly what
    // `GET /policy` serves and a commit compares against, at the revision it
    // was read.
    #[cfg(feature = "postgres")]
    if let Some(control_plane) = state.control_plane.as_ref() {
        let active = match control_plane.active().await {
            Ok(Some(active)) => active,
            Ok(None) => {
                tracing::error!("policy control plane has no active document");
                return Err(Box::new(service_unavailable(
                    "policy control plane unavailable",
                )));
            }
            Err(error) => {
                tracing::error!(error = %error, "policy control plane read failed");
                return Err(Box::new(service_unavailable(
                    "policy control plane unavailable",
                )));
            }
        };
        check_policy_test_if_match(headers, &active.etag)?;
        return Ok((
            active.policy,
            policy_eval::PolicyAuthority::PostgreSql {
                security_revision: active.security_revision,
            },
            policy_testing::report::PolicyBinding {
                source: PolicySource::Active,
                etag: active.etag,
                security_revision: Some(active.security_revision),
                stored: None,
            },
        ));
    }
    #[cfg(not(feature = "postgres"))]
    let _ = state;
    let policy = rbac_state.current_policy();
    let etag = match policy_etag(&policy) {
        Ok(etag) => etag,
        Err(error) => {
            tracing::error!(error = %error, "failed to compute current policy ETag");
            return Err(Box::new(internal_server_error(
                "policy ETag computation failed",
            )));
        }
    };
    check_policy_test_if_match(headers, &etag)?;
    Ok((
        policy,
        policy_eval::PolicyAuthority::Standalone,
        policy_testing::report::PolicyBinding {
            source: PolicySource::Active,
            etag,
            security_revision: None,
            stored: None,
        },
    ))
}

/// An inline candidate, validated as `POST /policy/validate` and
/// `PUT /policy` validate one -- read from the member's own bytes as they
/// read a body -- so it is judged as the gateway would accept it.
fn inline_policy_under_test(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
    candidate: &RawValue,
) -> ResponseResult<PolicyUnderTest> {
    let candidate = match parse_policy_body(candidate.get().as_bytes()) {
        Ok(candidate) => candidate,
        Err(errors) => return Err(Box::new(policy_candidate_refused(errors))),
    };
    if let Err(error) = rbac_state.validate_proxy_dispatch_policy(&candidate) {
        return Err(Box::new(policy_candidate_invalid(&error)));
    }
    // `POST /policy/validate` also refuses a document format replicas of
    // this build do not serve in cluster mode, so a run refuses it too
    // rather than judge a candidate the gateway would not accept. Whether
    // every live replica reads it now is a question for the commit's
    // operation gate, not for a run that commits nothing.
    if let Some(detail) = deployment_document_format_refusal(state, &candidate) {
        return Err(Box::new(policy_candidate_refused(vec![detail])));
    }
    let etag = candidate_etag(&candidate)?;
    Ok((
        candidate,
        policy_eval::PolicyAuthority::Standalone,
        policy_testing::report::PolicyBinding {
            source: PolicySource::InlineCandidate,
            etag,
            security_revision: None,
            stored: None,
        },
    ))
}

fn candidate_etag(candidate: &rbac::Policy) -> ResponseResult<String> {
    policy_etag(candidate).map_err(|error| {
        tracing::error!(error = %error, "failed to compute candidate policy ETag");
        Box::new(internal_server_error("policy ETag computation failed"))
    })
}

/// An optional pin: absent runs against whatever is active, present must
/// name exactly the active ETag. A stale pin is `412`, never a run against a
/// policy the caller did not review.
fn check_policy_test_if_match(headers: &HeaderMap, current_etag: &str) -> ResponseResult<()> {
    match if_match_matches(headers, current_etag) {
        Ok(true) | Err(IfMatchError::Missing) => Ok(()),
        Ok(false) => Err(Box::new(precondition_failed(
            "If-Match does not match the current policy ETag",
        ))),
        Err(error) => Err(Box::new(if_match_error_response(error))),
    }
}

fn policy_candidate_invalid(error: &rbac::policy::PolicyError) -> Response {
    policy_candidate_refused(vec![policy_error_message(error)])
}

fn policy_candidate_refused(errors: Vec<String>) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "candidate policy is invalid",
            "reason": "policy_candidate_invalid",
            "errors": errors,
        })),
    )
        .into_response()
}

fn emit_policy_tests_run(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    report: &policy_testing::report::RunReport,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let mut payload = json!({
        "policy_source": report.policy.source.as_str(),
        "policy_etag": report.policy.etag,
        "suite_digest": report.suite.digest,
        "status": report.status.as_str(),
        "total": report.summary.total,
        "passed": report.summary.passed,
        "failed": report.summary.failed,
        "incomplete": report.summary.incomplete,
        "errors": report.summary.errors,
        "http_semantics_version": report.evaluator.http_semantics_version,
        "tool_semantics_version": report.evaluator.tool_semantics_version,
    });
    if let Some(payload) = payload.as_object_mut() {
        if let Some(revision) = report.policy.security_revision {
            payload.insert("security_revision".to_owned(), json!(revision));
        }
        // Which draft or history version, never its content.
        if let Some(stored) = &report.policy.stored {
            stored.describe("policy_", payload);
        }
    }
    state.audit.emit(audit::AuditEvent::new(
        audit::event::POLICY_TESTS_RUN,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        payload,
    ));
}

fn policy_tests_response(
    report: &policy_testing::report::RunReport,
    format: PolicyTestFormat,
) -> Response {
    let (content_type, body) = match format {
        PolicyTestFormat::Json => match policy_testing::report::to_json(report)
            .and_then(|value| serde_json::to_vec(&value))
        {
            Ok(body) => ("application/json", body),
            Err(error) => {
                tracing::error!(error = %error, "failed to serialize policy test report");
                return internal_server_error("policy test report could not be rendered");
            }
        },
        PolicyTestFormat::Sarif => {
            match serde_json::to_vec(&policy_testing::report::to_sarif(report)) {
                Ok(body) => ("application/sarif+json", body),
                Err(error) => {
                    tracing::error!(error = %error, "failed to serialize policy test SARIF");
                    return internal_server_error("policy test report could not be rendered");
                }
            }
        }
        PolicyTestFormat::Junit => (
            "application/xml; charset=utf-8",
            policy_testing::report::to_junit(report).into_bytes(),
        ),
    };
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                HeaderName::from_static(POLICY_TESTS_STATUS_HEADER),
                HeaderValue::from_static(report.status.as_str()),
            ),
        ],
        body,
    )
        .into_response()
}

pub(super) async fn policy_test_runs_endpoint(
    State(state): State<PolicyAdminState>,
    Extension(limiter): Extension<Arc<PolicyEvaluationLimiter>>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_TEST_RUNS_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, &principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };
    if !rbac_state.principal_has_permission(&principal, ADMIN_POLICY_SIMULATE_PERMISSION) {
        return admin_permission_denied_response(ADMIN_POLICY_SIMULATE_PERMISSION.to_owned());
    }
    let body_limit = state.max_body_size.min(MAX_POLICY_TEST_RUN_BODY_BYTES);
    let body_deadline = tokio::time::Instant::now() + POLICY_TEST_RUN_BODY_DEADLINE;
    let body = match read_request_body_before(body, body_limit, body_deadline).await {
        Ok(body) => body,
        Err(TimedBodyReadError::Rejected(response)) => return *response,
        Err(TimedBodyReadError::DeadlineExceeded) => {
            return policy_tests_refusal(
                StatusCode::REQUEST_TIMEOUT,
                "the policy test run body did not arrive within its deadline",
                "policy_tests_request_timeout",
            );
        }
    };
    // Admitted once the body is in hand, so a slot bounds runs doing work
    // rather than uploads in flight, and one caller holds at most one.
    let Some(slot) = limiter.try_acquire(policy_evaluation_actor(&principal)) else {
        return policy_tests_refusal(
            StatusCode::TOO_MANY_REQUESTS,
            "too many policy test runs are in progress; retry later",
            "policy_tests_busy",
        );
    };
    let run_request = match parse_policy_test_run_request(&body) {
        Ok(run_request) => run_request,
        Err(response) => return *response,
    };
    let suite = match policy_testing::suite::parse_suite(&run_request.suite) {
        Ok(suite) => suite,
        Err(diagnostics) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "policy test suite is invalid",
                    "reason": "policy_tests_invalid",
                    "diagnostics": diagnostics.diagnostics,
                    "diagnostics_truncated": diagnostics.truncated,
                })),
            )
                .into_response();
        }
    };
    let (policy, authority, binding) = match policy_under_test(
        &state,
        rbac_state,
        &principal,
        &parts.headers,
        run_request.candidate,
    )
    .await
    {
        Ok(view) => view,
        Err(response) => return *response,
    };

    let suite_digest = suite.digest.clone();
    let resources = synthetic_resources(rbac_state);
    // The blocking thread owns the slot, so a request dropped mid-run keeps
    // its slot until the run it started has ended. The deadline starts
    // before compilation, so compiling counts against it.
    let outcome = match slot
        .run_blocking(move || {
            let deadline = Instant::now() + POLICY_TEST_RUN_DEADLINE;
            policy_testing::run_against_policy(policy, authority, &suite, &resources, deadline)
        })
        .await
    {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(policy_testing::RunError::DeadlineExceeded)) => {
            return policy_tests_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "the policy test run did not finish within its deadline; run fewer cases",
                "policy_tests_deadline_exceeded",
            );
        }
        // A policy the authority holds that the kernel will not compile, or
        // a runner that did not finish, is a failed run: no partial result
        // and nothing that could read as a pass.
        Ok(Err(policy_testing::RunError::Compile(error))) => {
            tracing::error!(error = ?error, "policy under test could not be compiled");
            return internal_server_error("policy test run failed");
        }
        Err(error) => {
            tracing::error!(error = %error, "policy test run did not complete");
            return internal_server_error("policy test run failed");
        }
    };
    let report = policy_testing::report::RunReport::new(suite_digest, binding, outcome);
    emit_policy_tests_run(&state, &parts, &principal, &report);
    policy_tests_response(&report, run_request.format)
}
