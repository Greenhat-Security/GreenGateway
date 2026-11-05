//! `POST /v1{ADMIN_PREFIX}/policy/evidence` (issue #243): assemble a
//! canonical, aggregate evidence package about one policy candidate -- a
//! publication, which is one version of the policy history, or a server-side
//! draft the caller owns.
//!
//! The handler reads the candidate and what it replaces from their
//! authorities -- never from the caller: a publication and the history
//! version before it from the history authority, a draft at the strong draft
//! ETag the request pinned and the live policy it is pinned to through the
//! drafts store and the policy authority. It revalidates the candidate with
//! this build exactly as `POST .../policy/validate` would, decides the test
//! suite and synthetic cases the request carries through the shared
//! evaluator, runs the conservative structural analyzer over the candidate
//! when asked and applies the deployment's suppression records to its
//! findings, binds a finished replay job of the caller's whose candidate is
//! the packaged document, and returns the `policy-evidence.v1` package
//! [`policy_evidence::package`] assembles, as RFC 8785 bytes.
//!
//! The rules it keeps:
//!
//! - **Authorization before work.** `401` and `403` are answered before the
//!   body is read: a package needs `admin:policy:read` and
//!   `admin:policy:evidence:read`. A section adds the permissions its own
//!   endpoint needs, checked before any history, draft or policy read and any
//!   evaluation: a suite (inline or the stored one) or cases need
//!   `admin:policy:simulate`, a replay job also `admin:audit:read`, and the
//!   analysis `admin:policy:analyze`.
//!   Nobody learns through a package what they could not read directly.
//! - **Owner scope.** A draft is read only as its owner, exactly as a
//!   simulation reads one: another principal's draft is the same `404` as
//!   one that does not exist, a draft that moved past the pinned ETag is
//!   `412`, and one whose base is no longer the live policy is `409`.
//! - **Server authority.** Every digest, ETag, validation result, test
//!   result, simulation outcome and finding in a package is computed here
//!   from the authorities and the request's own inputs; a caller cannot
//!   supply a result or a digest. A pinned `publication.etag` that is not the
//!   stored document's is `409`, and so is a replay job whose candidate is
//!   not the packaged document.
//! - **Writes nothing.** A package is generated, served and forgotten: it is
//!   not stored, so there is nothing to expire or to fetch twice, and a draft
//!   is neither touched nor extended. The only record it leaves is its
//!   `policy.evidence_exported` audit event, and the package is released
//!   only once the audit authority accepts that event.
//! - **Bounded.** The body is read under a size bound and a deadline, the
//!   work under a per-replica and per-actor concurrency bound, a deadline on
//!   the suite and cases and the analyzer's own deadline, and a package over
//!   [`policy_evidence::MAX_PACKAGE_BYTES`] is refused whole, never cut
//!   short. It is served `Cache-Control: no-store`.
use super::*;

use policy_analysis::{
    checks::{analyze, AnalysisResources},
    report::AnalysisBinding,
    suppression, AnalysisError, AnalysisOutcome,
};
use policy_evidence::{
    package::{
        assemble, AnalysisEvidence, CandidateRecord, DraftRecord, EvidenceInputs, PackageError,
        PolicyIdentity, PredecessorRecord, PublicationRecord, ReplayEvidence, SimulationEvidence,
        ValidationOutcome,
    },
    request::{
        parse_request, CandidateSelector, DraftSelector, EvidenceRequest, PublicationSelector,
        SimulationSelection, SuiteSelection,
    },
    PACKAGE_MEDIA_TYPE,
};
use policy_simulation::{
    request::StoredCandidate,
    run::{compile_pairs, simulate, SimulationError},
};

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
/// The wall-clock bound on a package's analysis, which runs after its suite
/// and cases: the bound `POST .../policy/analyses` holds an analysis to.
/// Running out of it is an incomplete analysis, never a clean one.
pub(super) const POLICY_EVIDENCE_ANALYSIS_DEADLINE: Duration = POLICY_ANALYSIS_DEADLINE;
/// `complete` or `incomplete`: the report's completeness, for callers that
/// only need a gate. Present on every package.
pub(super) const POLICY_EVIDENCE_COMPLETENESS_HEADER: &str =
    "x-greengateway-policy-evidence-completeness";
/// The report digest the package's manifest names.
pub(super) const POLICY_EVIDENCE_DIGEST_HEADER: &str = "x-greengateway-policy-evidence-digest";
/// `publication` or `draft`: the report's `candidate_kind`, so a gate that
/// reads only headers never takes a draft's package for a publication's.
pub(super) const POLICY_EVIDENCE_CANDIDATE_KIND_HEADER: &str =
    "x-greengateway-policy-evidence-candidate-kind";
/// The one file name a publication's package is offered for download under.
const POLICY_EVIDENCE_CONTENT_DISPOSITION: &str = "attachment; filename=\"policy-evidence.json\"";
/// The one file name a draft's package is offered for download under.
const POLICY_DRAFT_EVIDENCE_CONTENT_DISPOSITION: &str =
    "attachment; filename=\"policy-draft-evidence.json\"";

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

/// `422` for a candidate this build will not evaluate: one that no longer
/// passes the checks a test run, simulation or analysis needs, or no longer
/// compiles. The reason names the candidate's kind.
fn candidate_not_evaluable(
    record: &CandidateRecord,
    diagnostics: &[rbac::policy_document::PolicyDiagnostic],
) -> Response {
    let (error, reason) = match record {
        CandidateRecord::Publication { .. } => (
            "the publication cannot be evaluated by this gateway build",
            "policy_evidence_publication_not_evaluable",
        ),
        CandidateRecord::Draft(_) => (
            "the draft cannot be evaluated by this gateway build",
            "policy_evidence_draft_not_evaluable",
        ),
    };
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": error,
            "reason": reason,
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
    Ok(PolicyIdentity {
        schema_version: policy.schema_version.clone(),
        etag,
        // A 0.x document has no normative normalization, so no semantic
        // digest: the report says so rather than inventing one.
        semantic_digest: policy_semantic_digest(policy)?,
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

/// The candidate a request names, read from its authority, and what it
/// replaces.
struct ResolvedEvidenceCandidate {
    /// How the report names the candidate and what it replaces.
    record: CandidateRecord,
    /// The candidate's document.
    policy: rbac::Policy,
    /// What it replaces: the history version before a publication (`None`
    /// when the history holds none), the live policy a draft is pinned to.
    predecessor: Option<rbac::Policy>,
    /// The stored document the analysis artifact names, as an analysis of
    /// the same candidate through `POST .../policy/analyses` names it.
    stored: StoredCandidate,
}

/// A publication: the history version the request names, pinned to the
/// ETag it names, and the version before it.
async fn resolve_publication(
    state: &PolicyAdminState,
    selector: &PublicationSelector,
) -> ResponseResult<ResolvedEvidenceCandidate> {
    let Some(history) = state.history_store.as_ref() else {
        return Err(Box::new(policy_history_not_configured()));
    };
    let reading = read_history(history.as_ref(), selector.version).await?;
    let identity = stored_policy_identity(&reading.policy)?;
    if let Some(pinned) = selector.etag.as_deref() {
        if pinned != identity.etag {
            return Err(Box::new(
                (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": "the publication is not the document the request pinned",
                        "reason": "policy_evidence_publication_mismatch",
                        "policy_etag": identity.etag,
                    })),
                )
                    .into_response(),
            ));
        }
    }
    let predecessor = match reading.predecessor.as_ref() {
        None => None,
        Some((version, policy)) => Some(PredecessorRecord {
            version: *version,
            policy: stored_policy_identity(policy)?,
        }),
    };
    let version = reading.publication.version;
    Ok(ResolvedEvidenceCandidate {
        record: CandidateRecord::Publication {
            record: PublicationRecord {
                version,
                recorded_at: reading.publication.created_at,
                diff_summary: reading.publication.diff_summary,
                policy: identity,
            },
            predecessor,
        },
        policy: reading.policy,
        predecessor: reading.predecessor.map(|(_, policy)| policy),
        stored: StoredCandidate::Revision { version },
    })
}

/// A draft of the caller's, read exactly as a simulation reads a draft
/// candidate -- owner-scoped, at the pinned draft ETag, pinned to the live
/// policy -- and never written, with the live policy it is pinned to.
async fn resolve_draft(
    state: &PolicyAdminState,
    rbac_state: &middleware::rbac::RbacState,
    principal: &auth::Principal,
    selector: &DraftSelector,
) -> ResponseResult<ResolvedEvidenceCandidate> {
    let (base, base_etag, _) = simulation_base(state, rbac_state).await?;
    let draft = draft_as_candidate(
        state,
        principal,
        &selector.draft_id,
        &selector.draft_etag,
        &base_etag,
    )
    .await?;
    let policy = stored_policy_identity(&draft.candidate)?;
    // The base is named by the ETag its authority reported, which is the one
    // the draft is pinned to and the one a replay job records as its base.
    let base_identity = PolicyIdentity {
        etag: base_etag,
        ..stored_policy_identity(&base)?
    };
    let stored = StoredCandidate::Draft {
        draft_id: draft.summary.draft_id.clone(),
        revision: draft.summary.revision,
    };
    Ok(ResolvedEvidenceCandidate {
        record: CandidateRecord::Draft(DraftRecord {
            draft_id: draft.summary.draft_id,
            revision: draft.summary.revision,
            draft_etag: selector.draft_etag.clone(),
            policy,
            base: base_identity,
        }),
        policy: draft.candidate,
        predecessor: Some(base),
        stored,
    })
}

/// The finished replay job a request names, bound to the candidate: its
/// candidate must be the packaged document. Its base need not be what the
/// candidate replaces -- a job run after publication compares the published
/// policy with itself -- but the report says whether it was.
async fn bound_replay_job(
    state: &PolicyAdminState,
    jobs: &PolicyReplayJobs,
    principal: &auth::Principal,
    job_id: &str,
    candidate_etag: &str,
    predecessor_etag: Option<&str>,
) -> ResponseResult<ReplayEvidence> {
    let job = replay_job_evidence(state, jobs, principal, job_id)
        .await
        .map_err(|refusal| {
            Box::new(match refusal {
                ReplayJobEvidenceRefusal::NotFound => evidence_refusal(
                    StatusCode::NOT_FOUND,
                    "policy replay job was not found",
                    "policy_evidence_replay_job_not_found",
                ),
                ReplayJobEvidenceRefusal::Unavailable => evidence_refusal(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the policy replay job store is unavailable; retry later",
                    "policy_replay_store_unavailable",
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
    // packaged document would be evidence about some other policy.
    if job.candidate_etag != candidate_etag {
        return Err(Box::new(
            (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "the replay job's candidate is not the packaged policy",
                    "reason": "policy_evidence_replay_binding_stale",
                    "candidate_etag": job.candidate_etag,
                    "policy_etag": candidate_etag,
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

/// Why the evaluated sections produced nothing. None is a partial answer.
enum EvidenceRunError {
    /// The candidate no longer compiles under this build.
    NotEvaluable,
    /// The evaluator refused a simulated case.
    CaseRefused { pointer: String, code: &'static str },
    /// The suite and cases passed their deadline.
    DeadlineExceeded,
    /// An evaluator or analyzer invariant failed.
    Internal(&'static str),
}

/// What the evaluated sections established.
struct EvaluatedSections {
    tests: Option<policy_testing::report::RunReport>,
    simulation: Option<SimulationEvidence>,
    analysis: Option<AnalysisOutcome>,
}

/// A suite to decide, and the stored version it is when it is the stored
/// suite.
type SuiteToDecide = (
    policy_testing::suite::Suite,
    Option<policy_testing::report::StoredSuiteBinding>,
);

/// The work one package's evaluated sections need, moved onto a blocking
/// thread.
struct EvaluationWork {
    candidate: rbac::Policy,
    candidate_etag: String,
    /// How the test results name the candidate's source.
    source: policy_testing::report::PolicySource,
    predecessor: Option<rbac::Policy>,
    suite: Option<SuiteToDecide>,
    simulation: Option<SimulationSelection>,
    /// The MCP alias paths an analysis reads, when the request asked for one.
    analysis: Option<Vec<String>>,
}

/// Decide the suite against the candidate, and the simulation cases against
/// it and, when it still compiles, what it replaces; then analyze the
/// candidate, under the analyzer's own deadline. Pure and CPU-bound: run on
/// a blocking thread.
fn evaluate_sections(work: EvaluationWork) -> Result<EvaluatedSections, EvidenceRunError> {
    let EvaluationWork {
        candidate,
        candidate_etag,
        source,
        predecessor,
        suite,
        simulation,
        analysis,
    } = work;
    let deadline = Instant::now() + POLICY_EVIDENCE_DEADLINE;
    let authority = policy_eval::PolicyAuthority::Standalone;
    // A package is a function of its candidate and its cases. This
    // process's egress controls and global rate lanes describe the gateway
    // now, not the one that served a publication or will serve a draft, so
    // an egress case or a sequence on a global lane is incomplete here
    // rather than judged by them; an override's sequence still runs, on the
    // candidate's own limits.
    let resources = policy_testing::synthetic::SyntheticResources::none();
    let tests = match suite {
        None => None,
        Some((suite, stored)) => {
            let outcome =
                policy_testing::run_against_policy(
                    candidate.clone(),
                    authority,
                    &suite,
                    &resources,
                    deadline,
                )
                    .map_err(|error| match error {
                        policy_testing::RunError::Compile(error) => {
                            tracing::error!(error = ?error, "a candidate under evidence could not be compiled");
                            EvidenceRunError::NotEvaluable
                        }
                        policy_testing::RunError::DeadlineExceeded => {
                            EvidenceRunError::DeadlineExceeded
                        }
                    })?;
            Some(
                policy_testing::report::RunReport::new(
                    suite.digest.clone(),
                    policy_testing::report::PolicyBinding {
                        source,
                        etag: candidate_etag,
                        security_revision: None,
                        // The package names the candidate it judged.
                        stored: None,
                    },
                    outcome,
                )
                .with_stored_suite(stored),
            )
        }
    };
    let simulation = match simulation {
        None => None,
        Some(selection) => {
            // What the candidate replaces is the base when it still
            // compiles; one that does not leaves the candidate judged alone,
            // and the report says so. Evidence is bound to no live revision.
            let compared = predecessor.as_ref().and_then(|base| {
                compile_pairs(base, authority, Some(&candidate), &selection.projections).ok()
            });
            let (pairs, compared_with_predecessor) = match compared {
                Some(pairs) => (pairs, true),
                None => (
                    compile_pairs(&candidate, authority, None, &selection.projections).map_err(
                        |error| {
                            tracing::error!(error = ?error, "a candidate under evidence could not be compiled");
                            EvidenceRunError::NotEvaluable
                        },
                    )?,
                    false,
                ),
            };
            let outcome = simulate(
                &pairs,
                &selection.cases,
                selection.trace,
                &resources,
                deadline,
            )
            .map_err(|error| match error {
                SimulationError::CaseRefused { pointer, code } => {
                    EvidenceRunError::CaseRefused { pointer, code }
                }
                SimulationError::DeadlineExceeded => EvidenceRunError::DeadlineExceeded,
                SimulationError::Internal(code) => EvidenceRunError::Internal(code),
            })?;
            Some(SimulationEvidence {
                trace: selection.trace,
                projections: selection.projections,
                compared_with_predecessor,
                outcome,
            })
        }
    };
    // Last, and under its own deadline, so the analysis never eats into the
    // suite's and cases' time. Running out of it is an incomplete analysis.
    let analysis = match analysis {
        None => None,
        Some(mcp_alias_paths) => Some(
            analyze(
                &candidate,
                &AnalysisResources {
                    mcp_alias_paths: &mcp_alias_paths,
                },
                Instant::now() + POLICY_EVIDENCE_ANALYSIS_DEADLINE,
            )
            .map_err(|AnalysisError::Internal(code)| EvidenceRunError::Internal(code))?,
        ),
    };
    Ok(EvaluatedSections {
        tests,
        simulation,
        analysis,
    })
}

/// What an analysis is bound to besides the candidate.
struct AnalysisContext<'a> {
    request_digest: &'a str,
    candidate: &'a PolicyIdentity,
    stored: &'a StoredCandidate,
    mcp_alias_paths: usize,
    resource_snapshot: &'a rbac::policy_resources::PolicyResourceSnapshot,
    suppressions: &'a suppression::SuppressionRead,
}

/// The analysis artifact: `outcome` with each finding's suppression state,
/// rendered as `POST .../policy/analyses` renders the same candidate's
/// analysis, but with no pinned base.
fn analysis_evidence(
    outcome: &AnalysisOutcome,
    context: &AnalysisContext<'_>,
) -> Result<AnalysisEvidence, AnalysisError> {
    let suppressions = suppression::apply(
        &outcome.findings,
        context.suppressions,
        &suppression::SuppressionBinding {
            policy_etag: &context.candidate.etag,
            policy_semantic_digest: context.candidate.semantic_digest.as_deref(),
            resource_snapshot_digest: context
                .resource_snapshot
                .digest()
                .filter(|_| context.resource_snapshot.is_complete()),
        },
    )?;
    let binding = AnalysisBinding {
        request_digest: context.request_digest,
        base_etag: None,
        security_revision: None,
        source: match context.stored {
            StoredCandidate::Draft { .. } => "draft",
            StoredCandidate::Revision { .. } => "revision",
        },
        analyzed_etag: &context.candidate.etag,
        analyzed_semantic_digest: context.candidate.semantic_digest.as_deref(),
        edit_count: 0,
        stored: Some(context.stored),
        mcp_alias_paths: context.mcp_alias_paths,
        resource_snapshot: context.resource_snapshot,
    };
    Ok(AnalysisEvidence {
        results: policy_analysis::report::to_json(outcome, &binding, &suppressions)?,
    })
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
    if request.analysis {
        permissions.push(ADMIN_POLICY_ANALYZE_PERMISSION);
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
    // The stored suite a request names is read once, here, and must still be
    // the version it pinned; the report then binds that version.
    let suite = match evidence_request.suite.take() {
        None => None,
        Some(SuiteSelection::Inline(suite)) => Some((suite, None)),
        Some(SuiteSelection::Stored { etag }) => {
            match stored_policy_test_suite(&state, Some(etag.as_str())).await {
                Ok(record) => Some((
                    record.suite,
                    Some(policy_testing::report::StoredSuiteBinding {
                        version: record.version,
                        etag: record.etag,
                    }),
                )),
                Err(StoredSuiteRefusal::EtagMismatch) => {
                    return evidence_refusal(
                        StatusCode::CONFLICT,
                        "the stored policy test suite is not the one the request pinned",
                        "policy_evidence_suite_mismatch",
                    );
                }
                Err(refusal) => return refusal.response(),
            }
        }
    };

    let resolved = match &evidence_request.candidate {
        CandidateSelector::Publication(selector) => resolve_publication(&state, selector).await,
        CandidateSelector::Draft(selector) => {
            resolve_draft(&state, rbac_state, &principal, selector).await
        }
    };
    let ResolvedEvidenceCandidate {
        record,
        policy: candidate_policy,
        predecessor: predecessor_policy,
        stored,
    } = match resolved {
        Ok(resolved) => resolved,
        Err(response) => return *response,
    };
    let candidate_identity = record.policy().clone();
    let predecessor_etag = match &record {
        CandidateRecord::Publication { predecessor, .. } => predecessor
            .as_ref()
            .map(|predecessor| predecessor.policy.etag.clone()),
        CandidateRecord::Draft(draft) => Some(draft.base.etag.clone()),
    };
    let replay = match evidence_request.replay_job_id.as_deref() {
        None => None,
        Some(job_id) => match bound_replay_job(
            &state,
            &replay_jobs,
            &principal,
            job_id,
            &candidate_identity.etag,
            predecessor_etag.as_deref(),
        )
        .await
        {
            Ok(replay) => Some(replay),
            Err(response) => return *response,
        },
    };

    // Revalidated as `POST .../policy/validate` would judge the document now.
    // The history and the drafts store keep the normalized document, not the
    // bytes it was submitted as, so this inspects that document's
    // serialization and never reports a source digest for it.
    let stored_source = match serde_json::to_vec(&candidate_policy) {
        Ok(source) => source,
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize a stored policy");
            return internal_server_error("policy evidence could not be assembled");
        }
    };
    let mut inspection = inspect_policy_for_deployment(&state, rbac_state, &stored_source);
    // The cross-resource checks a publication runs, against the resources
    // current now. A publication is judged on its own: as the replacement of
    // itself, so the checks that compare it with what it replaced (an egress
    // change, the loss of every policy-write role) find nothing to compare.
    // The history cannot say what it replaced -- a POLICY_FILE edit or a
    // restart between two publications writes no version, so the version
    // before it need not be the document that was live -- and the commit
    // already ran those checks against the policy that was. A draft is judged
    // as the replacement of the live policy it is pinned to, which is what
    // publishing it would replace. No publisher is named: the caller asking
    // for evidence is not necessarily the one who publishes, and a package
    // must not depend on who asks for it.
    let mut resource_snapshot = None;
    let review = inspection.policy().map(|candidate| {
        let base = match &record {
            CandidateRecord::Publication { .. } => candidate,
            CandidateRecord::Draft(_) => predecessor_policy.as_ref().unwrap_or(candidate),
        };
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
    // The analyzer asks the evaluator synthetic questions about a document
    // this deployment could serve, so it depends on what a simulation does.
    let blocks_requested_evaluation = (evidence_request.analysis && inspection.policy().is_none())
        || inspection.diagnostics().iter().any(|diagnostic| {
            (suite.is_some() && diagnostic.blocks.tests)
                || ((evidence_request.simulation.is_some() || evidence_request.analysis)
                    && diagnostic.blocks.simulation)
        });
    if blocks_requested_evaluation {
        return candidate_not_evaluable(&record, inspection.diagnostics());
    }
    let resource_snapshot_view = match resource_snapshot.as_ref().map(serde_json::to_value) {
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
        resource_snapshot: resource_snapshot_view,
    };
    // Read once, before the analysis, as `POST .../policy/analyses` reads
    // them: a store that cannot be read suppresses nothing, and the package
    // says so.
    let suppression_read = if evidence_request.analysis {
        Some(read_analysis_suppressions(&state).await)
    } else {
        None
    };
    let alias_paths = evidence_request
        .analysis
        .then(|| rbac_state.mcp_alias_paths());
    let alias_count = alias_paths.as_ref().map_or(0, Vec::len);

    let simulation = evidence_request.simulation.take();
    let (tests_included, simulation_included) = (suite.is_some(), simulation.is_some());
    let work = EvaluationWork {
        candidate: candidate_policy,
        candidate_etag: candidate_identity.etag.clone(),
        source: match &record {
            CandidateRecord::Publication { .. } => {
                policy_testing::report::PolicySource::Publication
            }
            CandidateRecord::Draft(_) => policy_testing::report::PolicySource::Draft,
        },
        predecessor: predecessor_policy,
        suite,
        simulation,
        analysis: alias_paths,
    };
    // The blocking thread owns the slot, so a request dropped mid-run keeps
    // its slot until the work it started has ended.
    let evaluated = match slot.run_blocking(move || evaluate_sections(work)).await {
        Ok(Ok(evaluated)) => evaluated,
        Ok(Err(EvidenceRunError::NotEvaluable)) => return candidate_not_evaluable(&record, &[]),
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
        // An evaluator or analyzer invariant failure, or work that did not
        // finish, is a failed package: nothing partial, nothing that could
        // read as a pass or a clean analysis.
        Ok(Err(EvidenceRunError::Internal(code))) => {
            tracing::error!(code, "policy evidence evaluation failed");
            return internal_server_error("policy evidence could not be assembled");
        }
        Err(error) => {
            tracing::error!(error = %error, "policy evidence evaluation did not complete");
            return internal_server_error("policy evidence could not be assembled");
        }
    };
    let EvaluatedSections {
        tests,
        simulation,
        analysis,
    } = evaluated;
    let tests_status = tests.as_ref().map(|report| report.status.as_str());
    let analysis = match (
        analysis,
        resource_snapshot.as_ref(),
        suppression_read.as_ref(),
    ) {
        (None, _, _) => None,
        (Some(outcome), Some(snapshot), Some(read)) => {
            let context = AnalysisContext {
                request_digest: &evidence_request.digest,
                candidate: &candidate_identity,
                stored: &stored,
                mcp_alias_paths: alias_count,
                resource_snapshot: snapshot,
                suppressions: read,
            };
            match analysis_evidence(&outcome, &context) {
                Ok(analysis) => Some(analysis),
                Err(AnalysisError::Internal(code)) => {
                    tracing::error!(code, "a policy evidence analysis could not be rendered");
                    return internal_server_error("policy evidence could not be assembled");
                }
            }
        }
        // An analysis runs only for a document whose resources were read
        // and whose suppressions were read.
        (Some(_), _, _) => {
            tracing::error!("a policy evidence analysis ran without its bindings");
            return internal_server_error("policy evidence could not be assembled");
        }
    };
    let analysis_included = analysis.is_some();

    let Ok(generated_at) = OffsetDateTime::now_utc().format(&Rfc3339) else {
        return internal_server_error("policy evidence could not be assembled");
    };
    let replay_result_digest = replay
        .as_ref()
        .and_then(|replay| replay.view.get("result_digest").cloned());
    let candidate_kind = record.kind();
    let mut candidate_members = serde_json::Map::new();
    match &record {
        CandidateRecord::Publication { record, .. } => {
            candidate_members.insert("publication_version".to_owned(), json!(record.version));
        }
        CandidateRecord::Draft(draft) => {
            candidate_members.insert("draft_id".to_owned(), json!(draft.draft_id));
            candidate_members.insert("draft_revision".to_owned(), json!(draft.revision));
        }
    }
    let package = match assemble(
        EvidenceInputs {
            request_digest: evidence_request.digest.clone(),
            candidate: record,
            validation,
            tests,
            simulation,
            replay,
            analysis,
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
    // Identifiers, digests, codes and counts only.
    let mut payload = json!({
        "candidate_kind": candidate_kind,
        "policy_etag": candidate_identity.etag,
        "policy_semantic_digest": candidate_identity.semantic_digest,
        "request_digest": evidence_request.digest,
        "report_digest": package.report_digest,
        "analysis_digest": package.analysis_digest,
        "markdown_digest": package.markdown_digest,
        "completeness": if package.complete { "complete" } else { "incomplete" },
        "limitations": package.limitations,
        "tests_included": tests_included,
        "tests_status": tests_status,
        "simulation_included": simulation_included,
        "analysis_included": analysis_included,
        "replay_result_digest": replay_result_digest,
        "package_bytes": package.bytes.len(),
    });
    if let Some(payload) = payload.as_object_mut() {
        payload.extend(candidate_members);
    }
    let event = exported_event(&state, &parts, &principal, payload);
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
    let content_disposition = if candidate_kind == "draft" {
        POLICY_DRAFT_EVIDENCE_CONTENT_DISPOSITION
    } else {
        POLICY_EVIDENCE_CONTENT_DISPOSITION
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
                HeaderValue::from_static(content_disposition),
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
            (
                HeaderName::from_static(POLICY_EVIDENCE_CANDIDATE_KIND_HEADER),
                HeaderValue::from_static(candidate_kind),
            ),
        ],
        package.bytes,
    )
        .into_response()
}
