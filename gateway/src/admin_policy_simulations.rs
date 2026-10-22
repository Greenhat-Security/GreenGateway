//! `POST /v1{ADMIN_PREFIX}/policy/simulations` (issue #243, slice 10):
//! evaluate synthetic cases against the active policy and a candidate --
//! the active policy itself, position-aware edits over it, or an inline
//! document -- under the `as_authored` and `enforce_all_shadow`
//! projections, at a `terminal`, `matched` or `full` trace level.
//!
//! A simulation is a read with no side effects. It needs
//! `admin:policy:read` and `admin:policy:simulate`, both checked before the
//! body is read; persists, activates and rewrites nothing; and leaves exactly
//! one record, the `policy.simulation_run` audit event, which carries digests,
//! ETags and counts -- never a case, fixture value or policy content. The
//! evaluation is the pure [`policy_simulation::run`] on a blocking thread,
//! behind a per-replica and a per-actor bound on concurrent simulations
//! and a deadline, and nothing about it touches a rate bucket, tool permit,
//! resolver or upstream.
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, PoisonError,
    },
    time::{Duration, Instant},
};

use super::*;

use policy_simulation::{
    edits::apply_edits,
    request::{parse_request, CandidateSource, SimulationRequest},
    run::{compile_pairs, simulate, SimulationError, MAX_TRACE_STAGES},
    RESULT_SCHEMA_VERSION,
};

/// Most simulations evaluating at once across this replica. A simulation is
/// CPU-only and bounded by its body, case, edit and deadline limits; this
/// bounds how many can compete with the data plane at the same moment. Over
/// the bound is `429`, never queued.
pub(super) const MAX_CONCURRENT_POLICY_SIMULATIONS: usize = 4;
/// Largest simulation request body, in bytes: room for a complete inline
/// candidate at the policy compiler's 1 MiB bound plus its cases.
pub(super) const MAX_POLICY_SIMULATION_BODY_BYTES: usize = 2 * 1024 * 1024;
/// Largest rendered result, in bytes. A result over it is refused whole,
/// never cut short.
pub(super) const MAX_POLICY_SIMULATION_RESULT_BYTES: usize = 8 * 1024 * 1024;
/// The wall-clock bound on one simulation's evaluation.
pub(super) const POLICY_SIMULATION_DEADLINE: Duration = Duration::from_secs(2);

/// The concurrency bounds of one router, shared by every request it serves:
/// at most [`MAX_CONCURRENT_POLICY_SIMULATIONS`] at once, and one at a time
/// per actor, so a single caller cannot hold every slot.
pub(super) struct PolicySimulationLimiter {
    active: AtomicUsize,
    actors: Mutex<HashSet<String>>,
}

impl PolicySimulationLimiter {
    pub(super) fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            actors: Mutex::new(HashSet::new()),
        }
    }

    /// Admit one simulation for `actor`, or `None` when either bound is
    /// reached. The slot gives both back when it drops, whatever ends the
    /// request -- a refusal, a panic on the blocking thread, a cancellation.
    pub(super) fn try_acquire(self: &Arc<Self>, actor: String) -> Option<PolicySimulationSlot> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < MAX_CONCURRENT_POLICY_SIMULATIONS).then_some(active + 1)
            })
            .ok()?;
        // The set holds owned keys only; a panic while it was held cannot
        // leave it half-updated, so a poisoned lock is still a sound set.
        let admitted = self
            .actors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(actor.clone());
        if !admitted {
            self.active.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(PolicySimulationSlot {
            limiter: Arc::clone(self),
            actor,
        })
    }
}

pub(super) struct PolicySimulationSlot {
    limiter: Arc<PolicySimulationLimiter>,
    actor: String,
}

impl Drop for PolicySimulationSlot {
    fn drop(&mut self) {
        self.limiter
            .actors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.actor);
        self.limiter.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn simulation_refusal(status: StatusCode, error: &str, reason: &'static str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "reason": reason,
        })),
    )
        .into_response()
}

fn simulation_invalid(diagnostics: &policy_testing::suite::Diagnostics) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "policy simulation request is invalid",
            "reason": "policy_simulation_invalid",
            "diagnostics": diagnostics.diagnostics,
            "diagnostics_truncated": diagnostics.truncated,
        })),
    )
        .into_response()
}

fn simulation_candidate_invalid(error: &rbac::policy::PolicyError) -> Response {
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

/// The active policy, its ETag and the authority it was read under: the
/// authoritative document in cluster mode, at the revision it was read, and
/// the installed snapshot in standalone mode.
async fn simulation_base(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
) -> ResponseResult<(rbac::Policy, String, policy_eval::PolicyAuthority)> {
    #[cfg(feature = "postgres")]
    if let Some(control_plane) = state.control_plane.as_ref() {
        return match control_plane.active().await {
            Ok(Some(active)) => Ok((
                active.policy,
                active.etag,
                policy_eval::PolicyAuthority::PostgreSql {
                    security_revision: active.security_revision,
                },
            )),
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
        Ok(etag) => Ok((policy, etag, policy_eval::PolicyAuthority::Standalone)),
        Err(error) => {
            tracing::error!(error = %error, "failed to compute current policy ETag");
            Err(Box::new(internal_server_error(
                "policy ETag computation failed",
            )))
        }
    }
}

/// The candidate the request describes, validated exactly as a policy write
/// validates one, or `None` when the candidate is the base itself.
fn simulation_candidate(
    rbac_state: &middleware::rbac::RbacState,
    base: &rbac::Policy,
    source: &CandidateSource,
) -> ResponseResult<Option<rbac::Policy>> {
    let document = match source {
        CandidateSource::Active => return Ok(None),
        CandidateSource::Inline(document) => document.clone(),
        CandidateSource::Edits(edits) => {
            let base_document = match serde_json::to_value(base) {
                Ok(document) => document,
                Err(error) => {
                    tracing::error!(error = %error, "failed to serialize the simulation base");
                    return Err(Box::new(internal_server_error("policy simulation failed")));
                }
            };
            match apply_edits(&base_document, edits, "/candidate/edits") {
                Ok(document) => document,
                Err(diagnostics) => return Err(Box::new(simulation_invalid(&diagnostics))),
            }
        }
    };
    let candidate = match rbac::Policy::validate_json_value(document) {
        Ok(candidate) => candidate,
        Err(error) => return Err(Box::new(simulation_candidate_invalid(&error))),
    };
    if let Err(error) = rbac_state.validate_proxy_dispatch_policy(&candidate) {
        return Err(Box::new(simulation_candidate_invalid(&error)));
    }
    Ok(Some(candidate))
}

struct SimulationBinding {
    base_etag: String,
    security_revision: Option<i64>,
    candidate_source: &'static str,
    candidate_etag: String,
    edit_count: usize,
}

fn simulation_report(
    request: &SimulationRequest,
    binding: &SimulationBinding,
    outcome: policy_simulation::run::SimulationOutcome,
) -> Value {
    let mut base = json!({ "source": "active", "etag": binding.base_etag });
    if let (Some(revision), Some(base)) = (binding.security_revision, base.as_object_mut()) {
        base.insert("security_revision".to_owned(), json!(revision));
    }
    let mut candidate = json!({
        "source": binding.candidate_source,
        "etag": binding.candidate_etag,
    });
    if let (CandidateSource::Edits(_), Some(candidate)) =
        (&request.candidate, candidate.as_object_mut())
    {
        candidate.insert("edits".to_owned(), json!(binding.edit_count));
    }
    json!({
        "schema_version": RESULT_SCHEMA_VERSION,
        "mode": "synthetic",
        "request_digest": request.digest,
        "evaluator": {
            "http_semantics_version": policy_eval::HTTP_SEMANTICS_VERSION,
            "http_context_version": policy_eval::CONTEXT_VERSION,
            "tool_semantics_version": policy_eval::tools::TOOL_SEMANTICS_VERSION,
            "tool_context_version": policy_eval::tools::TOOL_CONTEXT_VERSION,
            "gateway_version": env!("CARGO_PKG_VERSION"),
        },
        "base": base,
        "candidate": candidate,
        "trace": {
            "level": request.trace.as_str(),
            "max_stages": MAX_TRACE_STAGES,
            "stages_truncated": outcome.stages_truncated,
        },
        "projections": request
            .projections
            .iter()
            .map(|projection| projection.as_str())
            .collect::<Vec<_>>(),
        "not_evaluated": policy_testing::NOT_EVALUATED,
        "summary": outcome.summary,
        "cases": outcome.cases,
    })
}

fn emit_policy_simulation_run(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    request: &SimulationRequest,
    binding: &SimulationBinding,
    summary: &Value,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let mut payload = json!({
        "request_digest": request.digest,
        "base_etag": binding.base_etag,
        "candidate_source": binding.candidate_source,
        "candidate_etag": binding.candidate_etag,
        "edits": binding.edit_count,
        "trace": request.trace.as_str(),
        "projections": request
            .projections
            .iter()
            .map(|projection| projection.as_str())
            .collect::<Vec<_>>(),
        "cases": request.cases.len(),
        // Counts only: the summary holds no case id or value.
        "summary": summary,
        "http_semantics_version": policy_eval::HTTP_SEMANTICS_VERSION,
        "tool_semantics_version": policy_eval::tools::TOOL_SEMANTICS_VERSION,
    });
    if let (Some(revision), Some(payload)) = (binding.security_revision, payload.as_object_mut()) {
        payload.insert("security_revision".to_owned(), json!(revision));
    }
    state.audit.emit(audit::AuditEvent::new(
        audit::event::POLICY_SIMULATION_RUN,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        payload,
    ));
}

pub(super) async fn policy_simulations_endpoint(
    State(state): State<PolicyAdminState>,
    Extension(limiter): Extension<Arc<PolicySimulationLimiter>>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_SIMULATIONS_ADMIN_ROUTE);

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
    let body_limit = state.max_body_size.min(MAX_POLICY_SIMULATION_BODY_BYTES);
    let body = match read_request_body(body, body_limit).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    // Admitted once the body is in hand, so a slot bounds simulations doing
    // work rather than uploads in flight. The actor is the canonical identity
    // authentication established, so two credentials for one subject share
    // one bound.
    let actor = format!(
        "{}\u{0}{}",
        principal.issuer.as_deref().unwrap_or_default(),
        principal.user_id
    );
    let Some(_slot) = limiter.try_acquire(actor) else {
        return simulation_refusal(
            StatusCode::TOO_MANY_REQUESTS,
            "too many policy simulations are in progress; retry later",
            "policy_simulation_busy",
        );
    };
    // A repeated member is refused before anything reads the body: a JSON
    // value keeps the last of two and says nothing, so the request digested
    // and simulated could differ from the one a reviewer read.
    if !policy_eval::input::has_unique_members(&body) {
        return simulation_refusal(
            StatusCode::BAD_REQUEST,
            "policy simulation body must be JSON with unique object members",
            "policy_simulation_request_invalid",
        );
    }
    let Ok(document) = serde_json::from_slice::<Value>(&body) else {
        return simulation_refusal(
            StatusCode::BAD_REQUEST,
            "policy simulation body must be JSON",
            "policy_simulation_request_invalid",
        );
    };
    let simulation = match parse_request(&body, &document) {
        Ok(simulation) => simulation,
        Err(diagnostics) => return simulation_invalid(&diagnostics),
    };

    let (base, base_etag, authority) = match simulation_base(&state, rbac_state).await {
        Ok(base) => base,
        Err(response) => return *response,
    };
    // The pin is required and exact: a simulation describes the policy its
    // author read, or nothing. No rebase is attempted; a stale pin is the
    // same `412` a stale `If-Match` is.
    if simulation.base_etag != base_etag {
        return (
            StatusCode::PRECONDITION_FAILED,
            Json(json!({
                "error": "the active policy is no longer the one this simulation was written against",
                "reason": "policy_simulation_base_stale",
                "current_etag": base_etag,
            })),
        )
            .into_response();
    }
    let candidate = match simulation_candidate(rbac_state, &base, &simulation.candidate) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };
    let candidate_etag = match candidate.as_ref().map(policy_etag) {
        None => base_etag.clone(),
        Some(Ok(etag)) => etag,
        Some(Err(error)) => {
            tracing::error!(error = %error, "failed to compute candidate policy ETag");
            return internal_server_error("policy ETag computation failed");
        }
    };
    let binding = SimulationBinding {
        base_etag,
        security_revision: match authority {
            policy_eval::PolicyAuthority::PostgreSql { security_revision } => {
                Some(security_revision)
            }
            policy_eval::PolicyAuthority::Standalone => None,
        },
        candidate_source: simulation.candidate.as_str(),
        candidate_etag,
        edit_count: match &simulation.candidate {
            CandidateSource::Edits(edits) => edits.len(),
            _ => 0,
        },
    };

    let simulation = Arc::new(simulation);
    let evaluated = Arc::clone(&simulation);
    let outcome = match tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + POLICY_SIMULATION_DEADLINE;
        let pairs = compile_pairs(&base, authority, candidate.as_ref(), &evaluated.projections)
            .map_err(|error| {
                tracing::error!(error = ?error, "policy under simulation could not be compiled");
                SimulationError::Internal("compile_failed")
            })?;
        simulate(&pairs, &evaluated.cases, evaluated.trace, deadline)
    })
    .await
    {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(SimulationError::CaseRefused { pointer, code })) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "the evaluator refused a simulated case",
                    "reason": "policy_simulation_case_refused",
                    "pointer": pointer,
                    "code": code,
                })),
            )
                .into_response();
        }
        Ok(Err(SimulationError::DeadlineExceeded)) => {
            return simulation_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "the policy simulation did not finish within its deadline; simulate fewer cases",
                "policy_simulation_deadline_exceeded",
            );
        }
        // A policy the kernel will not compile, an evaluator invariant
        // failure, or a run that did not finish is a failed simulation: no
        // partial result and nothing that could read as an answer.
        Ok(Err(SimulationError::Internal(code))) => {
            tracing::error!(code, "policy simulation failed");
            return internal_server_error("policy simulation failed");
        }
        Err(error) => {
            tracing::error!(error = %error, "policy simulation did not complete");
            return internal_server_error("policy simulation failed");
        }
    };
    let summary = outcome.summary.clone();
    let report = simulation_report(&simulation, &binding, outcome);
    let body = match serde_json::to_vec(&report) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize policy simulation result");
            return internal_server_error("policy simulation result could not be rendered");
        }
    };
    if body.len() > MAX_POLICY_SIMULATION_RESULT_BYTES {
        return simulation_refusal(
            StatusCode::UNPROCESSABLE_ENTITY,
            "the policy simulation result exceeds its size bound; simulate fewer cases or a lower trace level",
            "policy_simulation_result_too_large",
        );
    }
    emit_policy_simulation_run(&state, &parts, &principal, &simulation, &binding, &summary);
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        body,
    )
        .into_response()
}
