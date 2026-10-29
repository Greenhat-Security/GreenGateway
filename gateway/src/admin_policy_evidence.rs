//! `POST /v1{ADMIN_PREFIX}/policy/evidence` (issue #243, slice 20): assemble
//! a canonical, aggregate evidence package about one policy publication.
//!
//! A publication is one version of the policy history. The handler reads it
//! and the version before it from the history authority -- never from the
//! caller -- revalidates it with this build exactly as
//! `POST .../policy/validate` would, decides the test suite and synthetic
//! cases the request carries through the shared evaluator, binds a finished
//! replay job of the caller's whose candidate is the published document, and
//! returns the `policy-evidence.v1` package [`policy_evidence::package`]
//! assembles, as RFC 8785 bytes.
//!
//! The rules it keeps:
//!
//! - **Authorization before work.** `401` and `403` are answered before the
//!   body is read: a package needs `admin:policy:read` and
//!   `admin:policy:evidence:read`. A section adds the permissions its own
//!   endpoint needs, checked before any history read or evaluation: a suite
//!   or cases need `admin:policy:simulate`, and a replay job also
//!   `admin:audit:read`. Nobody learns through a package what they could not
//!   read directly.
//! - **Server authority.** Every digest, ETag, validation result, test
//!   result and simulation outcome in a package is computed here from the
//!   history and the request's own inputs; a caller cannot supply a result or
//!   a digest. A pinned `publication.etag` that is not the stored document's
//!   is `409`, and so is a replay job whose candidate is not it.
//! - **Writes nothing.** A package is generated, served and forgotten: it is
//!   not stored, so there is nothing to expire or to fetch twice. The only
//!   record it leaves is its `policy.evidence_exported` audit event, and the
//!   package is released only once the audit authority accepts that event.
//! - **Bounded.** The body is read under a size bound and a deadline, the
//!   work under a per-replica and per-actor concurrency bound and a deadline,
//!   and a package over [`policy_evidence::MAX_PACKAGE_BYTES`] is refused
//!   whole, never cut short.
use super::*;

use policy_evidence::{
    package::{
        assemble, EvidenceInputs, PackageError, PolicyIdentity, PredecessorRecord,
        PublicationRecord, ReplayEvidence, SimulationEvidence, ValidationOutcome,
    },
    request::{parse_request, EvidenceRequest, SimulationSelection},
    PACKAGE_MEDIA_TYPE,
};
use policy_simulation::run::{compile_pairs, simulate, SimulationError};

/// Most packages being assembled at once across this replica. Assembly is
/// CPU-bound and bounded by its body, case and deadline limits; over the
/// bound is `429`, never queued.
pub(super) const MAX_CONCURRENT_POLICY_EVIDENCE: usize = 4;
/// Largest evidence request body, in bytes: room for a full test suite and a
/// full simulation, which are bounded by case count far below it.
pub(super) const MAX_POLICY_EVIDENCE_BODY_BYTES: usize = 2 * 1024 * 1024;
/// How long a request's body may take to arrive. Work is admitted only once
/// the body is in hand, so a trickled upload holds no slot.
pub(super) const POLICY_EVIDENCE_BODY_DEADLINE: Duration = Duration::from_secs(5);
/// The wall-clock bound on deciding a package's suite and cases together,
/// compilation included.
pub(super) const POLICY_EVIDENCE_DEADLINE: Duration = Duration::from_secs(5);
/// `complete` or `incomplete`: the report's completeness, for callers that
/// only need a gate. Present on every package.
pub(super) const POLICY_EVIDENCE_COMPLETENESS_HEADER: &str =
    "x-greengateway-policy-evidence-completeness";
/// The report digest the package's manifest names.
pub(super) const POLICY_EVIDENCE_DIGEST_HEADER: &str = "x-greengateway-policy-evidence-digest";
/// The one file name a package is offered for download under.
const POLICY_EVIDENCE_CONTENT_DISPOSITION: &str = "attachment; filename=\"policy-evidence.json\"";

fn evidence_refusal(status: StatusCode, error: &str, reason: &'static str) -> Response {
    (
        status,
        Json(json!({
            "error": error,
            "reason": reason,
        })),
    )
        .into_response()
}

fn evidence_invalid(diagnostics: &policy_testing::suite::Diagnostics) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "policy evidence request is invalid",
            "reason": "policy_evidence_invalid",
            "diagnostics": diagnostics.diagnostics,
            "diagnostics_truncated": diagnostics.truncated,
        })),
    )
        .into_response()
}

/// `422` for a publication this build will not evaluate: one that no longer
/// passes the checks a test run or simulation needs, or no longer compiles.
fn publication_not_evaluable(diagnostics: &[rbac::policy_document::PolicyDiagnostic]) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "the publication cannot be evaluated by this gateway build",
            "reason": "policy_evidence_publication_not_evaluable",
            "diagnostics": diagnostics,
        })),
    )
        .into_response()
}

/// The identity of a stored policy: its ETag and, for a document format
/// with a normative normalization (policy v1), its ADR-0004 semantic digest
/// -- the digest `POST .../policy/validate` reports for the same document.
fn stored_policy_identity(policy: &rbac::Policy) -> ResponseResult<PolicyIdentity> {
    let etag = policy_etag(policy).map_err(|error| {
        tracing::error!(error = %error, "failed to compute a stored policy ETag");
        Box::new(internal_server_error("policy ETag computation failed"))
    })?;
    let semantic_digest =
        match rbac::policy_document::PolicySchema::of_version(&policy.schema_version) {
            Some(rbac::policy_document::PolicySchema::V1) => {
                let normalized = serde_json::to_value(policy).map_err(|error| {
                    tracing::error!(error = %error, "failed to serialize a stored policy");
                    Box::new(internal_server_error("policy digest computation failed"))
                })?;
                Some(
                    canonical_json::semantic_digest(
                        rbac::policy_document::POLICY_MEDIA_TYPE,
                        rbac::policy_document::POLICY_V1_SCHEMA_VERSION,
                        &normalized,
                    )
                    .map_err(|error| {
                        tracing::error!(error = %error, "a stored policy has no canonical form");
                        Box::new(internal_server_error("policy digest computation failed"))
                    })?,
                )
            }
            // A 0.x document has no normative normalization, so no semantic
            // digest: the report says so rather than inventing one.
            _ => None,
        };
    Ok(PolicyIdentity {
        schema_version: policy.schema_version.clone(),
        etag,
        semantic_digest,
    })
}

/// The publication, its stored document, and the history version before it
/// with its document.
struct HistoryReading {
    publication: rbac::policy_history::PolicyVersion,
    policy: rbac::Policy,
    predecessor: Option<(i64, rbac::Policy)>,
}

async fn read_history(
    history: &dyn storage::PolicyHistory,
    version: i64,
) -> ResponseResult<HistoryReading> {
    let history_unavailable = || {
        Box::new(evidence_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "policy history is unavailable",
            "policy_evidence_history_unavailable",
        ))
    };
    let mut publication = match history.get_version(version).await {
        Ok(Some(publication)) => publication,
        Ok(None) => {
            return Err(Box::new(evidence_refusal(
                StatusCode::NOT_FOUND,
                "the policy history has no such version",
                "policy_evidence_publication_not_found",
            )))
        }
        Err(error) => {
            tracing::error!(error = %error, version, "failed to read a policy history version for evidence");
            return Err(history_unavailable());
        }
    };
    let Some(policy) = publication.policy.take() else {
        tracing::error!(version, "policy history version omitted its document");
        return Err(Box::new(internal_server_error(
            "policy history query failed",
        )));
    };
    // The newest version below this one: the cursor is exclusive.
    let filters = rbac::PolicyHistoryListFilters {
        limit: 1,
        cursor: Some(version.to_string()),
        include_policy: true,
    };
    let predecessor = match history.list_versions(&filters).await {
        Ok(page) => page.versions.into_iter().next(),
        Err(error) => {
            tracing::error!(error = %error, version, "failed to read the version before a publication");
            return Err(history_unavailable());
        }
    };
    let predecessor = match predecessor {
        None => None,
        Some(rbac::policy_history::PolicyVersion {
            version,
            policy: Some(policy),
            ..
        }) => Some((version, policy)),
        Some(_) => {
            tracing::error!(version, "policy history version omitted its document");
            return Err(Box::new(internal_server_error(
                "policy history query failed",
            )));
        }
    };
    Ok(HistoryReading {
        publication,
        policy,
        predecessor,
    })
}

/// The finished replay job a request names, bound to the publication: its
/// candidate must be the published document. Its base need not be the
/// predecessor -- a job run after publication compares the published policy
/// with itself -- but the report says whether it was.
fn bound_replay_job(
    jobs: &PolicyReplayJobs,
    principal: &auth::Principal,
    job_id: &str,
    publication_etag: &str,
    predecessor_etag: Option<&str>,
) -> ResponseResult<ReplayEvidence> {
    let job = jobs.evidence(principal, job_id).map_err(|refusal| {
        Box::new(match refusal {
            ReplayJobEvidenceRefusal::NotFound => evidence_refusal(
                StatusCode::NOT_FOUND,
                "policy replay job was not found",
                "policy_evidence_replay_job_not_found",
            ),
            ReplayJobEvidenceRefusal::Unfinished(state) => (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "the replay job holds no result to include",
                    "reason": "policy_evidence_replay_job_unfinished",
                    "state": state,
                })),
            )
                .into_response(),
        })
    })?;
    // A job's result describes the candidate it replayed. Anything but the
    // published document would be evidence about some other policy.
    if job.candidate_etag != publication_etag {
        return Err(Box::new(
            (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "the replay job's candidate is not the published policy",
                    "reason": "policy_evidence_replay_binding_stale",
                    "candidate_etag": job.candidate_etag,
                    "policy_etag": publication_etag,
                })),
            )
                .into_response(),
        ));
    }
    Ok(ReplayEvidence {
        complete: job.complete,
        compared_with_predecessor: predecessor_etag == Some(job.base_etag.as_str()),
        view: job.view,
    })
}

/// Why the synthetic sections produced nothing. None is a partial answer.
enum EvidenceRunError {
    /// The publication no longer compiles under this build.
    NotEvaluable,
    /// The evaluator refused a simulated case.
    CaseRefused { pointer: String, code: &'static str },
    /// The work passed its deadline.
    DeadlineExceeded,
    /// An evaluator invariant failed.
    Internal(&'static str),
}

/// What the synthetic sections established.
struct EvaluatedSections {
    tests: Option<policy_testing::report::RunReport>,
    simulation: Option<SimulationEvidence>,
}

/// Decide the suite against the publication, and the simulation cases
/// against it and, when it still compiles, its predecessor. Pure and
/// CPU-bound: run on a blocking thread.
fn evaluate_sections(
    publication: rbac::Policy,
    publication_etag: String,
    predecessor: Option<rbac::Policy>,
    suite: Option<policy_testing::suite::Suite>,
    simulation: Option<SimulationSelection>,
) -> Result<EvaluatedSections, EvidenceRunError> {
    let deadline = Instant::now() + POLICY_EVIDENCE_DEADLINE;
    let authority = policy_eval::PolicyAuthority::Standalone;
    let tests = match suite {
        None => None,
        Some(suite) => {
            let outcome =
                policy_testing::run_against_policy(publication.clone(), authority, &suite, deadline)
                    .map_err(|error| match error {
                        policy_testing::RunError::Compile(error) => {
                            tracing::error!(error = ?error, "a publication under evidence could not be compiled");
                            EvidenceRunError::NotEvaluable
                        }
                        policy_testing::RunError::DeadlineExceeded => {
                            EvidenceRunError::DeadlineExceeded
                        }
                    })?;
            Some(policy_testing::report::RunReport::new(
                suite.digest.clone(),
                policy_testing::report::PolicyBinding {
                    source: policy_testing::report::PolicySource::Publication,
                    etag: publication_etag,
                    security_revision: None,
                },
                outcome,
            ))
        }
    };
    let simulation = match simulation {
        None => None,
        Some(selection) => {
            // The predecessor is the base when it still compiles; one that
            // does not leaves the publication judged alone, and the report
            // says so. A historical document is bound to no live revision.
            let compared = predecessor.as_ref().and_then(|base| {
                compile_pairs(base, authority, Some(&publication), &selection.projections).ok()
            });
            let (pairs, compared_with_predecessor) = match compared {
                Some(pairs) => (pairs, true),
                None => (
                    compile_pairs(&publication, authority, None, &selection.projections).map_err(
                        |error| {
                            tracing::error!(error = ?error, "a publication under evidence could not be compiled");
                            EvidenceRunError::NotEvaluable
                        },
                    )?,
                    false,
                ),
            };
            let outcome =
                simulate(&pairs, &selection.cases, selection.trace, deadline).map_err(|error| {
                    match error {
                        SimulationError::CaseRefused { pointer, code } => {
                            EvidenceRunError::CaseRefused { pointer, code }
                        }
                        SimulationError::DeadlineExceeded => EvidenceRunError::DeadlineExceeded,
                        SimulationError::Internal(code) => EvidenceRunError::Internal(code),
                    }
                })?;
            Some(SimulationEvidence {
                trace: selection.trace,
                projections: selection.projections,
                compared_with_predecessor,
                outcome,
            })
        }
    };
    Ok(EvaluatedSections { tests, simulation })
}

fn exported_event(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    payload: Value,
) -> audit::AuditEvent {
    audit::AuditEvent::new(
        audit::event::POLICY_EVIDENCE_EXPORTED,
        client_ip::request_id(&parts.headers, &parts.extensions),
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy),
        Some(auth::actor_from_principal(principal)),
        payload,
    )
}

/// The permissions a request's sections add to the two every package needs.
fn section_permissions(request: &EvidenceRequest) -> Vec<&'static str> {
    let mut permissions = Vec::new();
    if request.evaluates_synthetic_cases() || request.replay_job_id.is_some() {
        permissions.push(ADMIN_POLICY_SIMULATE_PERMISSION);
    }
    if request.replay_job_id.is_some() {
        permissions.push(ADMIN_AUDIT_READ_PERMISSION);
    }
    permissions
}

pub(super) async fn policy_evidence_endpoint(
    State(state): State<PolicyAdminState>,
    Extension(limiter): Extension<Arc<PolicyEvaluationLimiter>>,
    Extension(replay_jobs): Extension<Arc<PolicyReplayJobs>>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_EVIDENCE_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state = match authorized_policy_state(&state, &principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(rbac_state) => rbac_state,
        Err(error) => return policy_admin_authz_error_response(error),
    };
    if !rbac_state.principal_has_permission(&principal, ADMIN_POLICY_EVIDENCE_READ_PERMISSION) {
        return admin_permission_denied_response(ADMIN_POLICY_EVIDENCE_READ_PERMISSION.to_owned());
    }
    let body_limit = state.max_body_size.min(MAX_POLICY_EVIDENCE_BODY_BYTES);
    let body_deadline = tokio::time::Instant::now() + POLICY_EVIDENCE_BODY_DEADLINE;
    let body = match read_request_body_before(body, body_limit, body_deadline).await {
        Ok(body) => body,
        Err(TimedBodyReadError::Rejected(response)) => return *response,
        Err(TimedBodyReadError::DeadlineExceeded) => {
            return evidence_refusal(
                StatusCode::REQUEST_TIMEOUT,
                "the policy evidence request body did not arrive within its deadline",
                "policy_evidence_request_timeout",
            );
        }
    };
    // Admitted once the body is in hand, so a slot bounds work being done
    // rather than uploads in flight, and one caller holds at most one.
    let Some(slot) = limiter.try_acquire(policy_evaluation_actor(&principal)) else {
        return evidence_refusal(
            StatusCode::TOO_MANY_REQUESTS,
            "too many policy evidence packages are being assembled; retry later",
            "policy_evidence_busy",
        );
    };
    // A repeated member is refused before anything reads the body: a JSON
    // value keeps the last of two and says nothing, so the request digested
    // could differ from the one a reviewer read.
    if !policy_eval::input::has_unique_members(&body) {
        return evidence_refusal(
            StatusCode::BAD_REQUEST,
            "policy evidence body must be JSON with unique object members",
            "policy_evidence_request_invalid",
        );
    }
    let Ok(document) = serde_json::from_slice::<Value>(&body) else {
        return evidence_refusal(
            StatusCode::BAD_REQUEST,
            "policy evidence body must be JSON",
            "policy_evidence_request_invalid",
        );
    };
    let mut evidence_request = match parse_request(&document) {
        Ok(evidence_request) => evidence_request,
        Err(diagnostics) => return evidence_invalid(&diagnostics),
    };
    for permission in section_permissions(&evidence_request) {
        if !rbac_state.principal_has_permission(&principal, permission) {
            return admin_permission_denied_response(permission.to_owned());
        }
    }
    // Replay jobs exist only in standalone mode; a cluster has none to bind.
    #[cfg(feature = "postgres")]
    if evidence_request.replay_job_id.is_some() && state.control_plane.is_some() {
        return evidence_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "historical policy replay is not available in cluster mode",
            "policy_evidence_replay_unsupported_in_cluster",
        );
    }
    let Some(history) = state.history_store.as_ref() else {
        return policy_history_not_configured();
    };

    let reading = match read_history(history.as_ref(), evidence_request.publication.version).await {
        Ok(reading) => reading,
        Err(response) => return *response,
    };
    let publication_identity = match stored_policy_identity(&reading.policy) {
        Ok(identity) => identity,
        Err(response) => return *response,
    };
    if let Some(pinned) = evidence_request.publication.etag.as_deref() {
        if pinned != publication_identity.etag {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "the publication is not the document the request pinned",
                    "reason": "policy_evidence_publication_mismatch",
                    "policy_etag": publication_identity.etag,
                })),
            )
                .into_response();
        }
    }
    let predecessor = match reading.predecessor.as_ref() {
        None => None,
        Some((version, policy)) => match stored_policy_identity(policy) {
            Ok(identity) => Some(PredecessorRecord {
                version: *version,
                policy: identity,
            }),
            Err(response) => return *response,
        },
    };
    let replay = match evidence_request.replay_job_id.as_deref() {
        None => None,
        Some(job_id) => {
            let predecessor_etag = predecessor
                .as_ref()
                .map(|predecessor| predecessor.policy.etag.as_str());
            match bound_replay_job(
                &replay_jobs,
                &principal,
                job_id,
                &publication_identity.etag,
                predecessor_etag,
            ) {
                Ok(replay) => Some(replay),
                Err(response) => return *response,
            }
        }
    };

    // Revalidated as `POST .../policy/validate` would judge the document now.
    // The history keeps the normalized document, not the bytes it was
    // submitted as, so this inspects that document's serialization and never
    // reports a source digest for it.
    let stored_source = match serde_json::to_vec(&reading.policy) {
        Ok(source) => source,
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize a stored policy");
            return internal_server_error("policy evidence could not be assembled");
        }
    };
    let mut inspection = inspect_policy_for_deployment(&state, rbac_state, &stored_source);
    // The cross-resource checks a publication runs, against the resources
    // current now, judging the publication as the replacement of what it
    // replaced (itself, when the history holds nothing before it). No
    // publisher is named: the caller asking for evidence is not the one who
    // published, and a package must not depend on who asks for it.
    let mut resource_snapshot = None;
    let review = inspection.policy().map(|candidate| {
        let base = reading
            .predecessor
            .as_ref()
            .map_or(&reading.policy, |(_, predecessor)| predecessor);
        rbac::policy_resources::validate_resources(
            candidate,
            base,
            &rbac_state.policy_resource_view(),
            None,
        )
    });
    if let Some(review) = review {
        let (findings, snapshot) = review.into_parts();
        for finding in findings {
            inspection.record_finding(finding.diagnostic, finding.detail);
        }
        resource_snapshot = Some(snapshot);
    }
    let blocks_requested_evaluation = inspection.diagnostics().iter().any(|diagnostic| {
        (evidence_request.suite.is_some() && diagnostic.blocks.tests)
            || (evidence_request.simulation.is_some() && diagnostic.blocks.simulation)
    });
    if blocks_requested_evaluation {
        return publication_not_evaluable(inspection.diagnostics());
    }
    let resource_snapshot = match resource_snapshot.as_ref().map(serde_json::to_value) {
        None => None,
        Some(Ok(snapshot)) => Some(snapshot),
        Some(Err(error)) => {
            tracing::error!(error = %error, "failed to serialize a resource snapshot");
            return internal_server_error("policy evidence could not be assembled");
        }
    };
    let validation = ValidationOutcome {
        valid: inspection.is_valid(),
        diagnostics: inspection.diagnostics().to_vec(),
        resource_snapshot,
    };

    let suite = evidence_request.suite.take();
    let simulation = evidence_request.simulation.take();
    let (tests_included, simulation_included) = (suite.is_some(), simulation.is_some());
    let publication_policy = reading.policy;
    let predecessor_policy = reading.predecessor.map(|(_, policy)| policy);
    let publication_etag = publication_identity.etag.clone();
    // The blocking thread owns the slot, so a request dropped mid-run keeps
    // its slot until the work it started has ended.
    let evaluated = match slot
        .run_blocking(move || {
            evaluate_sections(
                publication_policy,
                publication_etag,
                predecessor_policy,
                suite,
                simulation,
            )
        })
        .await
    {
        Ok(Ok(evaluated)) => evaluated,
        Ok(Err(EvidenceRunError::NotEvaluable)) => return publication_not_evaluable(&[]),
        Ok(Err(EvidenceRunError::CaseRefused { pointer, code })) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": "the evaluator refused a simulated case",
                    "reason": "policy_evidence_case_refused",
                    "pointer": pointer,
                    "code": code,
                })),
            )
                .into_response();
        }
        Ok(Err(EvidenceRunError::DeadlineExceeded)) => {
            return evidence_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "the evidence package's cases did not finish within their deadline; include fewer cases",
                "policy_evidence_deadline_exceeded",
            );
        }
        // An evaluator invariant failure or work that did not finish is a
        // failed package: nothing partial, nothing that could read as a pass.
        Ok(Err(EvidenceRunError::Internal(code))) => {
            tracing::error!(code, "policy evidence evaluation failed");
            return internal_server_error("policy evidence could not be assembled");
        }
        Err(error) => {
            tracing::error!(error = %error, "policy evidence evaluation did not complete");
            return internal_server_error("policy evidence could not be assembled");
        }
    };
    let EvaluatedSections { tests, simulation } = evaluated;
    let tests_status = tests.as_ref().map(|report| report.status.as_str());

    let Ok(generated_at) = OffsetDateTime::now_utc().format(&Rfc3339) else {
        return internal_server_error("policy evidence could not be assembled");
    };
    let publication_version = reading.publication.version;
    let replay_result_digest = replay
        .as_ref()
        .and_then(|replay| replay.view.get("result_digest").cloned());
    let package = match assemble(
        EvidenceInputs {
            request_digest: evidence_request.digest.clone(),
            publication: PublicationRecord {
                version: publication_version,
                recorded_at: reading.publication.created_at,
                diff_summary: reading.publication.diff_summary,
                policy: publication_identity.clone(),
            },
            predecessor,
            validation,
            tests,
            simulation,
            replay,
        },
        &generated_at,
    ) {
        Ok(package) => package,
        Err(PackageError::TooLarge) => {
            return evidence_refusal(
                StatusCode::UNPROCESSABLE_ENTITY,
                "the evidence package exceeds its size bound; include fewer cases",
                "policy_evidence_too_large",
            );
        }
        Err(PackageError::Encoding) => {
            tracing::error!("a policy evidence report had no canonical form");
            return internal_server_error("policy evidence could not be assembled");
        }
    };

    // Released only once its export is on the record: an export whose audit
    // event the authority refused never happened as far as the caller knows.
    let event = exported_event(
        &state,
        &parts,
        &principal,
        json!({
            "publication_version": publication_version,
            "policy_etag": publication_identity.etag,
            "policy_semantic_digest": publication_identity.semantic_digest,
            "request_digest": evidence_request.digest,
            "report_digest": package.report_digest,
            "completeness": if package.complete { "complete" } else { "incomplete" },
            "limitations": package.limitations,
            "tests_included": tests_included,
            "tests_status": tests_status,
            "simulation_included": simulation_included,
            "replay_result_digest": replay_result_digest,
            "package_bytes": package.bytes.len(),
        }),
    );
    let receipt = state.audit.record(event);
    if let Err(error) = state.audit.confirm(receipt).await {
        tracing::error!(error = %error, "a policy evidence export was not recorded; the package is withheld");
        return evidence_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "the evidence export could not be recorded; no package was released",
            "policy_evidence_audit_unavailable",
        );
    }

    let Ok(digest_header) = HeaderValue::from_str(&package.report_digest) else {
        return internal_server_error("policy evidence could not be assembled");
    };
    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static(PACKAGE_MEDIA_TYPE),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static(POLICY_EVIDENCE_CONTENT_DISPOSITION),
            ),
            (
                HeaderName::from_static(POLICY_EVIDENCE_COMPLETENESS_HEADER),
                HeaderValue::from_static(if package.complete {
                    "complete"
                } else {
                    "incomplete"
                }),
            ),
            (
                HeaderName::from_static(POLICY_EVIDENCE_DIGEST_HEADER),
                digest_header,
            ),
        ],
        package.bytes,
    )
        .into_response()
}
