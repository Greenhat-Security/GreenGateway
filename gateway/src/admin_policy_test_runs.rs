//! `POST /v1{ADMIN_PREFIX}/policy/tests/runs` (issue #243, slice 11): run a
//! `policy-tests.v1` suite against the active policy, or against a candidate
//! submitted with the run, and answer JSON, SARIF or JUnit.
//!
//! A run is a read. It needs `admin:policy:read` and `admin:policy:simulate`,
//! both checked before the body is read, persists nothing, activates nothing,
//! and emits one `policy.tests_run` audit record that carries digests, the
//! policy ETag and counts -- never a case, fixture value or policy content.
//! The evaluation itself is the pure runner in `policy_testing`, on a blocking
//! thread so a large suite cannot stall the async workers, behind a
//! deployment-wide bound on concurrent runs.
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// Most runs evaluating at once across the process. A run is CPU-only and
/// bounded by its body and case limits; this bounds how many of those can
/// compete with the data plane at the same moment. A run over the bound is
/// refused with `429`, never queued and never allowed to displace another.
pub(super) const MAX_CONCURRENT_POLICY_TEST_RUNS: usize = 4;
/// The run's overall result, for callers that only need a gate: `passed`,
/// `failed`, `incomplete` or `error`. Present on every completed run.
pub(super) const POLICY_TESTS_STATUS_HEADER: &str = "x-greengateway-policy-tests-status";

static ACTIVE_POLICY_TEST_RUNS: AtomicUsize = AtomicUsize::new(0);

/// One admitted run. Releasing it is tied to drop, so a run that ends by any
/// path -- a refusal, a panic on the blocking thread, a cancelled request --
/// gives its slot back.
pub(super) struct PolicyTestRunSlot {
    counter: &'static AtomicUsize,
}

impl PolicyTestRunSlot {
    pub(super) fn try_acquire(counter: &'static AtomicUsize, limit: usize) -> Option<Self> {
        counter
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < limit).then_some(active + 1)
            })
            .ok()
            .map(|_| Self { counter })
    }
}

impl Drop for PolicyTestRunSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicyTestFormat {
    Json,
    Sarif,
    Junit,
}

/// The request members and what they hold, before the suite is parsed.
struct PolicyTestRunRequest {
    suite: Value,
    candidate: Option<Value>,
    format: PolicyTestFormat,
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
        .any(|key| !matches!(key.as_str(), "suite" | "policy" | "format"))
    {
        return Err(Box::new(policy_tests_refusal(
            StatusCode::BAD_REQUEST,
            "policy test run body accepts only suite, policy and format",
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
    Ok(PolicyTestRunRequest {
        suite,
        candidate: members.remove("policy"),
        format,
    })
}

/// The policy a run judges and its binding: the active document as its
/// authority holds it, or a validated candidate.
async fn policy_under_test(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
    headers: &HeaderMap,
    candidate: Option<Value>,
) -> ResponseResult<(
    rbac::Policy,
    policy_eval::PolicyAuthority,
    policy_testing::report::PolicyBinding,
)> {
    if let Some(candidate) = candidate {
        // `If-Match` names the live policy. Against a candidate it would be
        // a precondition nothing checks, so it is refused rather than
        // silently ignored.
        if headers.contains_key(header::IF_MATCH) {
            return Err(Box::new(policy_tests_refusal(
                StatusCode::BAD_REQUEST,
                "If-Match pins the active policy and cannot be combined with a candidate policy",
                "policy_tests_request_invalid",
            )));
        }
        // The validation `POST /policy/validate` and `PUT /policy` apply, so
        // a candidate is judged as the gateway would accept it.
        let candidate = match rbac::Policy::validate_json_value(candidate) {
            Ok(candidate) => candidate,
            Err(error) => return Err(Box::new(policy_candidate_invalid(&error))),
        };
        if let Err(error) = rbac_state.validate_proxy_dispatch_policy(&candidate) {
            return Err(Box::new(policy_candidate_invalid(&error)));
        }
        let etag = match policy_etag(&candidate) {
            Ok(etag) => etag,
            Err(error) => {
                tracing::error!(error = %error, "failed to compute candidate policy ETag");
                return Err(Box::new(internal_server_error(
                    "policy ETag computation failed",
                )));
            }
        };
        return Ok((
            candidate,
            policy_eval::PolicyAuthority::Standalone,
            policy_testing::report::PolicyBinding {
                source: policy_testing::report::PolicySource::InlineCandidate,
                etag,
                security_revision: None,
            },
        ));
    }

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
                source: policy_testing::report::PolicySource::Active,
                etag: active.etag,
                security_revision: Some(active.security_revision),
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
            source: policy_testing::report::PolicySource::Active,
            etag,
            security_revision: None,
        },
    ))
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
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "candidate policy is invalid",
            "reason": "policy_candidate_invalid",
            "errors": [policy_error_message(error)],
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
    if let (Some(revision), Some(payload)) =
        (report.policy.security_revision, payload.as_object_mut())
    {
        payload.insert("security_revision".to_owned(), json!(revision));
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
    let Some(_slot) =
        PolicyTestRunSlot::try_acquire(&ACTIVE_POLICY_TEST_RUNS, MAX_CONCURRENT_POLICY_TEST_RUNS)
    else {
        return policy_tests_refusal(
            StatusCode::TOO_MANY_REQUESTS,
            "too many policy test runs are in progress; retry later",
            "policy_tests_busy",
        );
    };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
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
    let (policy, authority, binding) =
        match policy_under_test(&state, rbac_state, &parts.headers, run_request.candidate).await {
            Ok(view) => view,
            Err(response) => return *response,
        };

    let suite_digest = suite.digest.clone();
    let outcome = match tokio::task::spawn_blocking(move || {
        policy_testing::run_against_policy(policy, authority, &suite)
    })
    .await
    {
        Ok(Ok(outcome)) => outcome,
        // A policy the authority holds that the kernel will not compile, or
        // a runner that did not finish, is a failed run: no partial result
        // and nothing that could read as a pass.
        Ok(Err(error)) => {
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
