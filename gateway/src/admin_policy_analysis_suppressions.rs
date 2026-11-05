//! Policy analysis suppressions (issue #243, slice 15):
//! `GET`/`POST /v1{ADMIN_PREFIX}/policy/analyses/suppressions` and
//! `DELETE .../suppressions/{id}`.
//!
//! A suppression records that a reviewer looked at one analyzer finding and
//! decided it needs no change until a stated time. It changes no policy and
//! no enforcement; it only changes how `POST .../policy/analyses` reports
//! that finding, and only while it binds the analysis exactly
//! (`policy_analysis::suppression`).
//!
//! The rules every handler here keeps:
//!
//! - **Authorization before work.** `401` and `403` are answered before any
//!   store, body or policy read. Listing needs `admin:policy:read` and
//!   `admin:policy:analyze`, the analysis permissions; creating and expiring
//!   need `admin:policy:write`.
//! - **Bound to what was reviewed.** A create names the live policy ETag in
//!   `If-Match` and the resource snapshot digest the analysis reported; a
//!   policy that has moved is `412` and resources that have moved are `409`,
//!   never re-bound silently. The record keeps the policy ETag, its semantic
//!   digest (policy v1) and the snapshot digest, so a later change to either
//!   makes it mismatched rather than letting it hide a finding it was not
//!   reviewed for.
//! - **Always expiring, never global.** A suppression names one finding by
//!   fingerprint and code and expires at most 90 days after it is created.
//!   There is no wildcard and no way to suppress a code or every finding.
//! - **Compare-and-set.** A create is admitted inside one store transaction
//!   with its duplicate check and the deployment bound; an expiry names the
//!   suppression's strong ETag in `If-Match`, and of two holding one ETag
//!   exactly one wins.
//! - **Ids and codes in audit.** `policy.analysis_suppression_created`,
//!   `policy.analysis_suppression_withdrawn` and
//!   `policy.analysis_suppression_refused` carry the suppression id, the
//!   finding code and stable reasons. The reason an operator wrote never
//!   enters an audit event, a metric or an analysis report.
use super::*;

use storage::analysis_suppressions::{
    is_analysis_suppression_id, is_analysis_suppression_reason, is_sha256_digest,
    AnalysisSuppressionActor, AnalysisSuppressionCreated, AnalysisSuppressionRecord,
    NewAnalysisSuppression, ANALYSIS_SUPPRESSION_ID_PREFIX, MAX_ANALYSIS_SUPPRESSION_REASON_BYTES,
};

/// Largest create body, in bytes: the five members at their bounds with
/// room for JSON escaping.
const MAX_SUPPRESSION_BODY_BYTES: usize = 16 * 1024;

/// `POST .../policy/analyses/suppressions`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuppressionCreateRequest {
    fingerprint: String,
    code: String,
    reason: String,
    /// RFC 3339; kept to the second.
    expires_at: String,
    resource_snapshot_digest: String,
}

/// Why a suppression request was refused. Each has a stable `reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SuppressionRefusal {
    /// No suppression store is configured, or it could not be consulted.
    Unavailable,
    /// The body is not JSON of the request's shape.
    RequestInvalid,
    /// A member is out of its bounds; `diagnostics` say which.
    Invalid,
    /// The expiry is not after now, or is more than the maximum TTL ahead,
    /// on the store's clock.
    ExpiryOutOfRange,
    /// The suppression ETag precondition is missing.
    EtagRequired,
    /// A precondition is not exactly one strong entity tag.
    EtagInvalid,
    /// The live policy is not the one `If-Match` names.
    PolicyEtagMismatch,
    /// The suppression changed since its ETag was read.
    EtagMismatch,
    /// An unended suppression of this finding under this binding exists.
    Duplicate,
    /// The deployment already holds the maximum.
    QuotaExceeded,
    /// No suppression has this identifier.
    NotFound,
    /// The suppression already ended.
    Ended,
}

impl SuppressionRefusal {
    fn status(self) -> StatusCode {
        match self {
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::RequestInvalid | Self::EtagInvalid => StatusCode::BAD_REQUEST,
            Self::Invalid | Self::ExpiryOutOfRange => StatusCode::UNPROCESSABLE_ENTITY,
            Self::EtagRequired => StatusCode::PRECONDITION_REQUIRED,
            Self::PolicyEtagMismatch | Self::EtagMismatch => StatusCode::PRECONDITION_FAILED,
            Self::Duplicate => StatusCode::CONFLICT,
            Self::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Ended => StatusCode::GONE,
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Unavailable => "policy_analysis_suppressions_unavailable",
            Self::RequestInvalid => "policy_analysis_suppression_request_invalid",
            Self::Invalid => "policy_analysis_suppression_invalid",
            Self::ExpiryOutOfRange => "policy_analysis_suppression_expiry_out_of_range",
            Self::EtagRequired => "policy_analysis_suppression_etag_required",
            Self::EtagInvalid => "policy_analysis_suppression_etag_invalid",
            Self::PolicyEtagMismatch => "policy_etag_mismatch",
            Self::EtagMismatch => "policy_analysis_suppression_etag_mismatch",
            Self::Duplicate => "policy_analysis_suppression_exists",
            Self::QuotaExceeded => "policy_analysis_suppression_quota_exceeded",
            Self::NotFound => "policy_analysis_suppression_not_found",
            Self::Ended => "policy_analysis_suppression_ended",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "policy analysis suppressions are unavailable",
            Self::RequestInvalid => "the suppression request must be JSON with exactly the documented members",
            Self::Invalid => "the suppression request is invalid",
            Self::ExpiryOutOfRange => "a suppression must expire after now and within the maximum lifetime",
            Self::EtagRequired => "If-Match is required",
            Self::EtagInvalid => "If-Match must be exactly one strong entity tag",
            Self::PolicyEtagMismatch => "the named policy ETag is not the current policy ETag; analyze the current policy again",
            Self::EtagMismatch => "the suppression changed since this ETag was read",
            Self::Duplicate => "this finding is already suppressed under the same binding",
            Self::QuotaExceeded => "the deployment already holds the maximum number of suppressions",
            Self::NotFound => "the suppression was not found",
            Self::Ended => "the suppression has already ended",
        }
    }

    fn response(self) -> Response {
        self.response_with(json!({}))
    }

    fn response_with(self, extra: Value) -> Response {
        let mut body = json!({
            "error": self.message(),
            "reason": self.reason(),
        });
        if let (Some(body), Value::Object(extra)) = (body.as_object_mut(), extra) {
            body.extend(extra);
        }
        (self.status(), Json(body)).into_response()
    }
}

/// The ADR-0004 semantic digest of a policy v1 document -- the digest `POST
/// .../policy/validate` reports for the same document -- or `None` for a
/// document format without a normative normalization (0.x).
pub(super) fn policy_semantic_digest(policy: &rbac::Policy) -> ResponseResult<Option<String>> {
    if rbac::policy_document::PolicySchema::of_version(&policy.schema_version)
        != Some(rbac::policy_document::PolicySchema::V1)
    {
        return Ok(None);
    }
    let digest = serde_json::to_value(policy).ok().and_then(|normalized| {
        canonical_json::semantic_digest(
            rbac::policy_document::POLICY_MEDIA_TYPE,
            rbac::policy_document::POLICY_V1_SCHEMA_VERSION,
            &normalized,
        )
        .ok()
    });
    match digest {
        Some(digest) => Ok(Some(digest)),
        None => {
            tracing::error!("a policy v1 document has no canonical form");
            Err(Box::new(internal_server_error(
                "policy digest computation failed",
            )))
        }
    }
}

/// The suppressions an analysis reads, as the analysis module takes them.
/// A store that is absent or fails is `Unavailable`: nothing is suppressed
/// and the report says the records were not consulted.
pub(super) async fn read_analysis_suppressions(
    state: &PolicyAdminState,
) -> policy_analysis::suppression::SuppressionRead {
    use policy_analysis::suppression::{Suppression, SuppressionRead};

    let Some(store) = state.analysis_suppression_store.as_ref() else {
        return SuppressionRead::Unavailable;
    };
    match store.list().await {
        Ok(records) => SuppressionRead::Available(
            records
                .into_iter()
                .map(|record| Suppression {
                    id: record.suppression_id,
                    fingerprint: record.fingerprint,
                    code: record.code,
                    policy_etag: record.policy_etag,
                    policy_semantic_digest: record.policy_semantic_digest,
                    resource_snapshot_digest: record.resource_snapshot_digest,
                    created_at: record.created_at,
                    ended: record.ended,
                })
                .collect(),
        ),
        Err(error) => {
            tracing::error!(error = %error, "policy analysis suppressions could not be read");
            SuppressionRead::Unavailable
        }
    }
}

/// The strong ETag of a suppression's current representation. A
/// suppression changes only once, when it is withdrawn, which advances its
/// revision; the identifier is framed in, length-prefixed, so a tag is
/// meaningful for one suppression only. Opaque to clients.
fn suppression_etag(record: &AnalysisSuppressionRecord) -> String {
    let mut digest = Sha256::new();
    digest.update(b"greengateway.policy-analysis-suppression-etag\0");
    digest.update((record.suppression_id.len() as u64).to_be_bytes());
    digest.update(record.suppression_id.as_bytes());
    digest.update(record.revision.to_be_bytes());
    format!("\"sha256:{}\"", hex::encode(digest.finalize()))
}

/// A fresh identifier from operating-system randomness, or `None` when the
/// operating system cannot supply it. Never a fallback generator.
fn new_suppression_id() -> Option<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).ok()?;
    Some(format!(
        "{ANALYSIS_SUPPRESSION_ID_PREFIX}{}",
        hex::encode(random)
    ))
}

fn rfc3339(seconds: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// A suppression as the API shows it: the reason included, for the
/// reviewers this route admits.
fn suppression_view(record: &AnalysisSuppressionRecord) -> ResponseResult<Value> {
    let (Some(created_at), Some(expires_at)) =
        (rfc3339(record.created_at), rfc3339(record.expires_at))
    else {
        tracing::error!(
            "a policy analysis suppression timestamp is outside the representable range"
        );
        return Err(Box::new(internal_server_error(
            "policy analysis suppression could not be rendered",
        )));
    };
    let state = match (record.ended, record.withdrawn_at) {
        (_, Some(_)) => "withdrawn",
        (true, None) => "expired",
        (false, None) => "active",
    };
    let mut created_by = json!({ "subject": record.actor.subject });
    if let (false, Some(created_by)) = (record.actor.issuer.is_empty(), created_by.as_object_mut())
    {
        created_by.insert("issuer".to_owned(), json!(record.actor.issuer));
    }
    let mut view = json!({
        "suppression_id": record.suppression_id,
        "etag": suppression_etag(record),
        "revision": record.revision,
        "state": state,
        "fingerprint": record.fingerprint,
        "code": record.code,
        "reason": record.reason,
        "created_by": created_by,
        "created_at": created_at,
        "expires_at": expires_at,
        "binding": {
            "policy_etag": record.policy_etag,
            "policy_semantic_digest": record.policy_semantic_digest,
            "resource_snapshot_digest": record.resource_snapshot_digest,
        },
    });
    if let (Some(withdrawn_at), Some(view)) = (record.withdrawn_at, view.as_object_mut()) {
        view.insert("withdrawn_at".to_owned(), json!(rfc3339(withdrawn_at)));
    }
    Ok(view)
}

fn suppression_response(status: StatusCode, record: &AnalysisSuppressionRecord) -> Response {
    let view = match suppression_view(record) {
        Ok(view) => view,
        Err(response) => return *response,
    };
    (
        status,
        [
            (header::ETAG, etag_header_value(&suppression_etag(record))),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(view),
    )
        .into_response()
}

fn suppression_store_failed(error: &storage::RepositoryError) -> Response {
    tracing::error!(error = %error, "policy analysis suppression store failed");
    SuppressionRefusal::Unavailable.response()
}

fn suppression_store(
    state: &PolicyAdminState,
) -> ResponseResult<&Arc<dyn storage::AnalysisSuppressionStore>> {
    if !policy_authority_configured(state) {
        return Err(Box::new(policy_not_configured()));
    }
    state
        .analysis_suppression_store
        .as_ref()
        .ok_or_else(|| Box::new(SuppressionRefusal::Unavailable.response()))
}

fn emit_suppression_event(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    event_type: &'static str,
    payload: Value,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    state.audit.emit(audit::AuditEvent::new(
        event_type,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        payload,
    ));
}

/// What a refused suppression write was: ids and codes only.
struct RefusedWrite<'a> {
    /// `create` or `withdraw`.
    operation: &'static str,
    reason: &'static str,
    code: &'a str,
    suppression_id: Option<&'a str>,
}

/// The request a suppression handler is answering, for its audit records.
struct SuppressionRequest<'a> {
    state: &'a PolicyAdminState,
    parts: &'a http::request::Parts,
    principal: &'a auth::Principal,
}

impl SuppressionRequest<'_> {
    fn emit(&self, event_type: &'static str, payload: Value) {
        emit_suppression_event(self.state, self.parts, self.principal, event_type, payload);
    }

    /// Answer a refusal decided against current state, after recording it as
    /// `policy.analysis_suppression_refused`: the operation, the stable
    /// reason, the finding code and, when there is one, the suppression id.
    /// A decision not to change how a finding reads belongs in the audit
    /// stream as much as a change does.
    fn refuse(&self, refused: RefusedWrite<'_>, response: Response) -> Response {
        self.emit(
            audit::event::POLICY_ANALYSIS_SUPPRESSION_REFUSED,
            json!({
                "operation": refused.operation,
                "reason": refused.reason,
                "code": refused.code,
                "suppression_id": refused.suppression_id,
            }),
        );
        response
    }
}

/// One problem with a create request, by RFC 6901 pointer. Value-free.
fn diagnostic(pointer: &str, code: &str, message: &str) -> Value {
    json!({ "pointer": pointer, "code": code, "message": message })
}

/// The create request's own checks, each member on its own. Returns the
/// expiry in Unix seconds when every member is in bounds.
fn check_create_request(request: &SuppressionCreateRequest) -> Result<i64, Vec<Value>> {
    let mut diagnostics = Vec::new();
    if !is_sha256_digest(&request.fingerprint) {
        diagnostics.push(diagnostic(
            "/fingerprint",
            "fingerprint_invalid",
            "fingerprint must be a finding fingerprint as an analysis reports it",
        ));
    }
    if !policy_analysis::FindingCode::ALL
        .iter()
        .any(|code| code.as_str() == request.code)
    {
        diagnostics.push(diagnostic(
            "/code",
            "code_unknown",
            "code must be a finding code this analyzer reports",
        ));
    }
    if !is_analysis_suppression_reason(&request.reason) {
        diagnostics.push(diagnostic(
            "/reason",
            "reason_invalid",
            "reason must be 1 to 512 bytes of text without control characters",
        ));
    }
    if !is_sha256_digest(&request.resource_snapshot_digest) {
        diagnostics.push(diagnostic(
            "/resource_snapshot_digest",
            "resource_snapshot_digest_invalid",
            "resource_snapshot_digest must be the resource snapshot digest an analysis reports",
        ));
    }
    let expires_at = OffsetDateTime::parse(&request.expires_at, &Rfc3339)
        .map(OffsetDateTime::unix_timestamp)
        .ok();
    if expires_at.is_none() {
        diagnostics.push(diagnostic(
            "/expires_at",
            "expires_at_invalid",
            "expires_at must be an RFC 3339 date-time",
        ));
    }
    match (expires_at, diagnostics.is_empty()) {
        (Some(expires_at), true) => Ok(expires_at),
        _ => Err(diagnostics),
    }
}

fn limits_view(store: &Arc<dyn storage::AnalysisSuppressionStore>) -> Value {
    let limits = store.limits();
    json!({
        "max_suppressions": limits.max_total,
        "max_ttl_seconds": limits.max_ttl_secs,
        "max_reason_bytes": MAX_ANALYSIS_SUPPRESSION_REASON_BYTES,
    })
}

/// `GET .../policy/analyses/suppressions`: every retained suppression,
/// ended ones included, oldest first, with the store's bounds.
pub(super) async fn policy_analysis_suppressions_list_endpoint(
    State(state): State<PolicyAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(POLICY_ANALYSIS_SUPPRESSIONS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
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
    let store = match suppression_store(&state) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    let records = match store.list().await {
        Ok(records) => records,
        Err(error) => return suppression_store_failed(&error),
    };
    let mut suppressions = Vec::with_capacity(records.len());
    for record in &records {
        match suppression_view(record) {
            Ok(view) => suppressions.push(view),
            Err(response) => return *response,
        }
    }
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(json!({
            "suppressions": suppressions,
            "limits": limits_view(store),
        })),
    )
        .into_response()
}

/// `POST .../policy/analyses/suppressions`: suppress one finding of the
/// live policy, bound to the policy `If-Match` names and the resource
/// snapshot the request names.
pub(super) async fn policy_analysis_suppression_create_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_ANALYSIS_SUPPRESSIONS_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_policy_state(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return policy_admin_authz_error_response(error),
        };
    let store = match suppression_store(&state) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    let presented_policy_etag = match exact_strong_if_match(&parts.headers) {
        Ok(etag) => etag,
        Err(ToolPlaygroundIfMatchError::Missing) => {
            return precondition_required("If-Match header is required")
        }
        Err(ToolPlaygroundIfMatchError::Invalid) => {
            return SuppressionRefusal::EtagInvalid.response()
        }
    };
    let body_limit = state.max_body_size.min(MAX_SUPPRESSION_BODY_BYTES);
    let body = match read_request_body(body, body_limit).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    // A repeated member is refused before anything reads the body: serde
    // keeps the last of two and says nothing, so the reason or finding a
    // reviewer read could differ from the one recorded.
    if !policy_eval::input::has_unique_members(&body) {
        return SuppressionRefusal::RequestInvalid.response();
    }
    let Ok(request) = serde_json::from_slice::<SuppressionCreateRequest>(&body) else {
        return SuppressionRefusal::RequestInvalid.response();
    };
    let expires_at = match check_create_request(&request) {
        Ok(expires_at) => expires_at,
        Err(diagnostics) => {
            return SuppressionRefusal::Invalid.response_with(json!({ "diagnostics": diagnostics }))
        }
    };

    let recorder = SuppressionRequest {
        state: &state,
        parts: &parts,
        principal: &principal,
    };
    let refused = |refusal: SuppressionRefusal, suppression_id: Option<&str>, response| {
        recorder.refuse(
            RefusedWrite {
                operation: "create",
                reason: refusal.reason(),
                code: &request.code,
                suppression_id,
            },
            response,
        )
    };

    let (live_policy, live_etag) = match authoritative_policy_and_etag(&state, rbac_state).await {
        Ok(view) => view,
        Err(response) => return *response,
    };
    if presented_policy_etag != live_etag {
        return refused(
            SuppressionRefusal::PolicyEtagMismatch,
            None,
            SuppressionRefusal::PolicyEtagMismatch
                .response_with(json!({ "current_etag": live_etag })),
        );
    }
    // The resources must be the ones the analysis was read against, and
    // completely read: a suppression never binds resources nobody saw.
    let snapshot =
        rbac::policy_resources::PolicyResourceSnapshot::of(&rbac_state.policy_resource_view());
    let current_snapshot = snapshot.digest().filter(|_| snapshot.is_complete());
    if current_snapshot != Some(request.resource_snapshot_digest.as_str()) {
        return recorder.refuse(
            RefusedWrite {
                operation: "create",
                reason: RESOURCE_SNAPSHOT_STALE_REASON,
                code: &request.code,
                suppression_id: None,
            },
            resource_snapshot_stale(&snapshot),
        );
    }
    let semantic_digest = match policy_semantic_digest(&live_policy) {
        Ok(digest) => digest,
        Err(response) => return *response,
    };
    let Some(suppression_id) = new_suppression_id() else {
        tracing::error!("the operating system could not supply a suppression identifier");
        return SuppressionRefusal::Unavailable.response();
    };
    let actor = AnalysisSuppressionActor {
        issuer: principal
            .issuer
            .as_deref()
            .and_then(auth::principal::canonical_issuer)
            .unwrap_or_default(),
        subject: principal.user_id.clone(),
    };
    let created = store
        .create(NewAnalysisSuppression {
            suppression_id: &suppression_id,
            fingerprint: &request.fingerprint,
            code: &request.code,
            reason: &request.reason,
            actor: &actor,
            policy_etag: &live_etag,
            policy_semantic_digest: semantic_digest.as_deref(),
            resource_snapshot_digest: &request.resource_snapshot_digest,
            expires_at,
        })
        .await;
    match created {
        Ok(AnalysisSuppressionCreated::Created(record)) => {
            recorder.emit(
                audit::event::POLICY_ANALYSIS_SUPPRESSION_CREATED,
                json!({
                    "suppression_id": record.suppression_id,
                    "code": record.code,
                }),
            );
            suppression_response(StatusCode::CREATED, &record)
        }
        Ok(AnalysisSuppressionCreated::ExpiryOutOfRange) => {
            let refusal = SuppressionRefusal::ExpiryOutOfRange;
            refused(
                refusal,
                None,
                refusal.response_with(json!({ "max_ttl_seconds": store.limits().max_ttl_secs })),
            )
        }
        Ok(AnalysisSuppressionCreated::Duplicate { suppression_id }) => {
            let refusal = SuppressionRefusal::Duplicate;
            refused(
                refusal,
                Some(&suppression_id),
                refusal.response_with(json!({ "suppression_id": suppression_id })),
            )
        }
        Ok(AnalysisSuppressionCreated::DeploymentQuotaExceeded) => {
            let refusal = SuppressionRefusal::QuotaExceeded;
            refused(
                refusal,
                None,
                refusal.response_with(json!({ "max_suppressions": store.limits().max_total })),
            )
        }
        Err(error) => suppression_store_failed(&error),
    }
}

/// `DELETE .../policy/analyses/suppressions/{id}`: end a suppression now,
/// under its strong ETag. The record stays readable as `withdrawn`, and
/// every analysis from then on reports its finding `suppression_expired`.
pub(super) async fn policy_analysis_suppression_delete_endpoint(
    State(state): State<PolicyAdminState>,
    Path(suppression_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_ANALYSIS_SUPPRESSION_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_policy_state(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
        return policy_admin_authz_error_response(error);
    }
    let store = match suppression_store(&state) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    let presented = match exact_strong_if_match(&parts.headers) {
        Ok(etag) => etag,
        Err(ToolPlaygroundIfMatchError::Missing) => {
            return SuppressionRefusal::EtagRequired.response()
        }
        Err(ToolPlaygroundIfMatchError::Invalid) => {
            return SuppressionRefusal::EtagInvalid.response()
        }
    };
    if !is_analysis_suppression_id(&suppression_id) {
        return SuppressionRefusal::NotFound.response();
    }
    let record = match store.get(&suppression_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return SuppressionRefusal::NotFound.response(),
        Err(error) => return suppression_store_failed(&error),
    };
    let recorder = SuppressionRequest {
        state: &state,
        parts: &parts,
        principal: &principal,
    };
    let refused = |refusal: SuppressionRefusal| {
        recorder.refuse(
            RefusedWrite {
                operation: "withdraw",
                reason: refusal.reason(),
                code: &record.code,
                suppression_id: Some(&record.suppression_id),
            },
            refusal.response(),
        )
    };
    if record.ended {
        return refused(SuppressionRefusal::Ended);
    }
    if suppression_etag(&record) != presented {
        return refused(SuppressionRefusal::EtagMismatch);
    }
    match store.withdraw(&suppression_id, record.revision).await {
        Ok(Some(withdrawn)) => {
            recorder.emit(
                audit::event::POLICY_ANALYSIS_SUPPRESSION_WITHDRAWN,
                json!({
                    "suppression_id": withdrawn.suppression_id,
                    "code": withdrawn.code,
                }),
            );
            suppression_response(StatusCode::OK, &withdrawn)
        }
        // Another writer, or the clock, got there first: say which.
        Ok(None) => match store.get(&suppression_id).await {
            Ok(Some(current)) if current.ended => refused(SuppressionRefusal::Ended),
            Ok(Some(_)) => refused(SuppressionRefusal::EtagMismatch),
            Ok(None) => SuppressionRefusal::NotFound.response(),
            Err(error) => suppression_store_failed(&error),
        },
        Err(error) => suppression_store_failed(&error),
    }
}
