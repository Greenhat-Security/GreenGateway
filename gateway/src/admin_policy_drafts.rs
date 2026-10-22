//! Server-side policy drafts (issue #243, slice 9): owner-scoped, expiring
//! candidate policies with strong ETags, and their conditional publication.
//!
//! A draft is a workspace, not authority. Creating, editing or deleting one
//! changes no enforcement, advances no revision and emits no
//! `policy.changed`; only `POST .../drafts/{id}/publish` can make a draft's
//! candidate live, and it does so through the same
//! [`persist_policy_mutation`] path as `PUT .../policy`, under an `If-Match`
//! that must name the live policy ETag.
//!
//! The rules every handler here keeps:
//!
//! - **Authorization before work.** `401` and `403` are answered before any
//!   store, body or policy read. Reads need `admin:policy:read`; every write,
//!   publication included, needs `admin:policy:write`.
//! - **Owner scope.** A draft is visible to the principal that created it
//!   (canonical issuer and subject) and to nobody else. Another owner's
//!   draft answers exactly like a missing one, `404`. The unpredictable
//!   identifier is defense in depth, not the authorization.
//! - **Pinned base, no silent rebase.** A draft is pinned to the live policy
//!   ETag named by `If-Match` when it was created. Publishing a draft whose
//!   base is no longer live is refused with `409 policy_draft_base_stale`
//!   and the draft is kept; re-pinning it is an explicit `PATCH` naming the
//!   current ETag as `base_etag`.
//! - **Strong ETags.** Every draft write requires the draft's current ETag
//!   (`If-Match` on `PATCH` and `DELETE`, [`POLICY_DRAFT_ETAG_HEADER`] on
//!   publish) as exactly one strong entity tag; the store applies the write
//!   as a compare-and-set on the revision that tag was computed from.
//! - **Validated like a policy write.** A candidate is parsed and checked
//!   exactly as `PUT .../policy` checks one (schema, proxy dispatch, and no
//!   egress change) when it is saved, and again against the current
//!   authority when it is published.

use super::*;

use storage::policy_drafts::{
    is_policy_draft_id, NewPolicyDraft, PolicyDraftChange, PolicyDraftCreated, PolicyDraftOwner,
    PolicyDraftRecord, PolicyDraftSummary, MAX_POLICY_DRAFT_CANDIDATE_BYTES,
    POLICY_DRAFT_ID_PREFIX,
};

/// `POST .../policy/drafts`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDraftCreateRequest {
    /// The candidate document. Absent, the draft starts as a copy of the
    /// live policy `If-Match` names.
    #[serde(default)]
    policy: Option<Value>,
}

/// `PATCH .../policy/drafts/{id}`. At least one field is required.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDraftPatchRequest {
    /// A replacement candidate document.
    #[serde(default)]
    policy: Option<Value>,
    /// Re-pin the draft to this live policy ETag. It must be the current
    /// one; this is the only way a draft's base ever moves.
    #[serde(default)]
    base_etag: Option<String>,
}

/// A draft as the API shows it. `policy` is omitted from listings.
#[derive(Serialize)]
struct PolicyDraftView<'a> {
    draft_id: &'a str,
    revision: i64,
    state: &'static str,
    base_etag: &'a str,
    candidate_etag: &'a str,
    published_etag: Option<&'a str>,
    created_at: String,
    updated_at: String,
    expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'a rbac::Policy>,
}

#[derive(Serialize)]
struct PolicyDraftListView<'a> {
    drafts: Vec<PolicyDraftView<'a>>,
    limits: PolicyDraftLimitsView,
}

/// The bounds the store enforces, so a client can say why a create was
/// refused before it is.
#[derive(Serialize)]
struct PolicyDraftLimitsView {
    ttl_seconds: i64,
    max_drafts_per_owner: usize,
    max_drafts: usize,
    max_candidate_bytes: usize,
}

/// Why a draft request was refused. Each has a stable `reason` so a client
/// can tell them apart without parsing text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PolicyDraftRefusal {
    /// No draft store is configured, or it could not be consulted.
    Unavailable,
    /// No draft with this identifier belongs to the caller.
    NotFound,
    /// The draft's TTL has passed.
    Expired,
    /// The draft was already published and accepts no further change.
    Published,
    /// The draft ETag precondition is missing.
    EtagRequired,
    /// The draft ETag precondition is not exactly one strong entity tag.
    EtagInvalid,
    /// The draft changed since the presented ETag was read.
    EtagMismatch,
    /// The live policy is no longer the one the draft was pinned to.
    BaseStale,
    /// A policy ETag the request names is not the live one.
    PolicyEtagMismatch,
    /// The serialized candidate exceeds the per-draft bound.
    TooLarge,
    /// A `PATCH` named nothing to change.
    EmptyPatch,
    /// The caller already holds the per-owner maximum.
    OwnerQuotaExceeded,
    /// The deployment already holds the deployment-wide maximum.
    DeploymentQuotaExceeded,
}

impl PolicyDraftRefusal {
    pub(super) fn status(self) -> StatusCode {
        match self {
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Expired => StatusCode::GONE,
            Self::Published | Self::BaseStale => StatusCode::CONFLICT,
            Self::EtagRequired => StatusCode::PRECONDITION_REQUIRED,
            Self::EtagInvalid | Self::EmptyPatch => StatusCode::BAD_REQUEST,
            Self::EtagMismatch | Self::PolicyEtagMismatch => StatusCode::PRECONDITION_FAILED,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::OwnerQuotaExceeded | Self::DeploymentQuotaExceeded => {
                StatusCode::TOO_MANY_REQUESTS
            }
        }
    }

    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::Unavailable => "policy_drafts_unavailable",
            Self::NotFound => "policy_draft_not_found",
            Self::Expired => "policy_draft_expired",
            Self::Published => "policy_draft_published",
            Self::EtagRequired => "policy_draft_etag_required",
            Self::EtagInvalid => "policy_draft_etag_invalid",
            Self::EtagMismatch => "policy_draft_etag_mismatch",
            Self::BaseStale => "policy_draft_base_stale",
            Self::PolicyEtagMismatch => "policy_etag_mismatch",
            Self::TooLarge => "policy_draft_too_large",
            Self::EmptyPatch => "policy_draft_patch_empty",
            Self::OwnerQuotaExceeded => "policy_draft_owner_quota_exceeded",
            Self::DeploymentQuotaExceeded => "policy_draft_deployment_quota_exceeded",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "policy drafts are unavailable",
            Self::NotFound => "policy draft was not found",
            Self::Expired => "policy draft has expired",
            Self::Published => "policy draft was already published",
            Self::EtagRequired => "the policy draft ETag precondition is required",
            Self::EtagInvalid => "the policy draft ETag must be exactly one strong entity tag",
            Self::EtagMismatch => "policy draft changed since this ETag was read",
            Self::BaseStale => {
                "the live policy changed after this draft was pinned; review the draft and rebase it explicitly"
            }
            Self::PolicyEtagMismatch => "the named policy ETag is not the current policy ETag",
            Self::TooLarge => "policy draft candidate is too large",
            Self::EmptyPatch => "a policy draft patch must name policy or base_etag",
            Self::OwnerQuotaExceeded => "this principal already holds the maximum number of policy drafts",
            Self::DeploymentQuotaExceeded => "the deployment already holds the maximum number of policy drafts",
        }
    }

    pub(super) fn response(self) -> Response {
        self.response_with(json!({}))
    }

    /// The refusal with extra fields beside `error` and `reason`.
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

/// The draft owner a principal is: its canonical issuer (empty when it has
/// none) and its subject, the identity `actor_from_principal` audits.
pub(super) fn policy_draft_owner(principal: &auth::Principal) -> PolicyDraftOwner {
    PolicyDraftOwner {
        issuer: principal
            .issuer
            .as_deref()
            .and_then(auth::principal::canonical_issuer)
            .unwrap_or_default(),
        subject: principal.user_id.clone(),
    }
}

/// The strong ETag of a draft's current representation.
///
/// Every write advances `revision` and is the only thing that changes the
/// representation, so a tag over the revision changes exactly when the
/// representation does. The draft identifier, base, candidate and
/// publication ETags are framed in as well, length-prefixed, so a tag is
/// meaningful only for the one draft state it was read from. Opaque to
/// clients: they copy it, never compute it.
pub(super) fn policy_draft_etag(summary: &PolicyDraftSummary) -> String {
    let mut digest = Sha256::new();
    digest.update(b"greengateway.policy-draft-etag\0");
    for part in [
        summary.draft_id.as_bytes(),
        summary.base_etag.as_bytes(),
        summary.candidate_etag.as_bytes(),
        summary.published_etag.as_deref().unwrap_or("").as_bytes(),
    ] {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.update(summary.revision.to_be_bytes());
    format!("\"sha256:{}\"", hex::encode(digest.finalize()))
}

/// A fresh draft identifier from operating-system randomness, or `None`
/// when the operating system cannot supply it. Never a fallback generator.
fn new_policy_draft_id() -> Option<String> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).ok()?;
    Some(format!("{POLICY_DRAFT_ID_PREFIX}{}", hex::encode(random)))
}

fn rfc3339_from_unix(seconds: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn draft_view<'a>(
    summary: &'a PolicyDraftSummary,
    policy: Option<&'a rbac::Policy>,
) -> ResponseResult<PolicyDraftView<'a>> {
    let times = (
        rfc3339_from_unix(summary.created_at),
        rfc3339_from_unix(summary.updated_at),
        rfc3339_from_unix(summary.expires_at),
    );
    let (Some(created_at), Some(updated_at), Some(expires_at)) = times else {
        tracing::error!("a policy draft timestamp is outside the representable range");
        return Err(Box::new(internal_server_error(
            "policy draft could not be rendered",
        )));
    };
    Ok(PolicyDraftView {
        draft_id: &summary.draft_id,
        revision: summary.revision,
        state: if summary.published_etag.is_some() {
            "published"
        } else {
            "open"
        },
        base_etag: &summary.base_etag,
        candidate_etag: &summary.candidate_etag,
        published_etag: summary.published_etag.as_deref(),
        created_at,
        updated_at,
        expires_at,
        policy,
    })
}

/// A draft and its strong ETag. Never cached: the body is a policy document
/// owned by one principal.
fn draft_response(status: StatusCode, record: &PolicyDraftRecord) -> Response {
    let view = match draft_view(&record.summary, Some(&record.candidate)) {
        Ok(view) => view,
        Err(response) => return *response,
    };
    (
        status,
        [
            (
                header::ETAG,
                etag_header_value(&policy_draft_etag(&record.summary)),
            ),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            ),
        ],
        Json(view),
    )
        .into_response()
}

fn policy_draft_store_failed(error: &storage::RepositoryError) -> Response {
    tracing::error!(error = %error, "policy draft store failed");
    PolicyDraftRefusal::Unavailable.response()
}

/// The RBAC state and draft store behind an authorized request. Permission
/// is decided first, so an unauthorized caller learns nothing about whether
/// drafts are configured.
fn authorized_draft_store<'a>(
    state: &'a PolicyAdminState,
    principal: &auth::Principal,
    permission: &str,
) -> ResponseResult<(
    &'a middleware::rbac::RbacState,
    &'a Arc<dyn storage::PolicyDraftStore>,
)> {
    let rbac_state = authorized_policy_state(state, principal, permission)
        .map_err(|error| Box::new(policy_admin_authz_error_response(error)))?;
    if !policy_authority_configured(state) {
        return Err(Box::new(policy_not_configured()));
    }
    let Some(store) = state.draft_store.as_ref() else {
        return Err(Box::new(PolicyDraftRefusal::Unavailable.response()));
    };
    Ok((rbac_state, store))
}

/// The caller's draft, open or published; a missing or expired one ends
/// the request.
async fn owned_draft(
    store: &Arc<dyn storage::PolicyDraftStore>,
    owner: &PolicyDraftOwner,
    draft_id: &str,
) -> ResponseResult<PolicyDraftRecord> {
    if !is_policy_draft_id(draft_id) {
        return Err(Box::new(PolicyDraftRefusal::NotFound.response()));
    }
    match store.get(owner, draft_id).await {
        Ok(Some(record)) if record.summary.expired => {
            Err(Box::new(PolicyDraftRefusal::Expired.response()))
        }
        Ok(Some(record)) => Ok(record),
        Ok(None) => Err(Box::new(PolicyDraftRefusal::NotFound.response())),
        Err(error) => Err(Box::new(policy_draft_store_failed(&error))),
    }
}

/// Why a compare-and-set write changed nothing, read back after the fact:
/// the draft is gone, expired, published, or simply moved on.
async fn lost_draft_write(
    store: &Arc<dyn storage::PolicyDraftStore>,
    owner: &PolicyDraftOwner,
    draft_id: &str,
) -> Response {
    match store.get(owner, draft_id).await {
        Ok(None) => PolicyDraftRefusal::NotFound.response(),
        Ok(Some(record)) if record.summary.expired => PolicyDraftRefusal::Expired.response(),
        Ok(Some(record)) if record.summary.published_etag.is_some() => {
            PolicyDraftRefusal::Published.response()
        }
        Ok(Some(_)) => PolicyDraftRefusal::EtagMismatch.response(),
        Err(error) => policy_draft_store_failed(&error),
    }
}

/// The draft ETag a write presents in `name`, exactly one strong tag.
fn presented_draft_etag(headers: &HeaderMap, name: &HeaderName) -> ResponseResult<String> {
    exact_strong_entity_tag(headers, name).map_err(|error| {
        Box::new(match error {
            ToolPlaygroundIfMatchError::Missing => PolicyDraftRefusal::EtagRequired.response(),
            ToolPlaygroundIfMatchError::Invalid => PolicyDraftRefusal::EtagInvalid.response(),
        })
    })
}

/// The live policy ETag a create or publish presents in `If-Match`. Exactly
/// one strong tag: a draft is pinned to one base, never to any of a list.
fn presented_policy_etag(headers: &HeaderMap) -> ResponseResult<String> {
    exact_strong_if_match(headers).map_err(|error| {
        Box::new(match error {
            ToolPlaygroundIfMatchError::Missing => {
                precondition_required("If-Match header is required")
            }
            ToolPlaygroundIfMatchError::Invalid => {
                bad_request("If-Match must be exactly one strong entity tag")
            }
        })
    })
}

fn parse_draft_candidate(value: Value) -> ResponseResult<rbac::Policy> {
    rbac::Policy::validate_json_value(value)
        .map_err(|error| Box::new(policy_validation_failed(vec![policy_error_message(&error)])))
}

/// The per-draft size bound, judged on the candidate as the store will
/// serialize it, before the store is asked.
fn within_candidate_bound(candidate: &rbac::Policy) -> ResponseResult<()> {
    match serde_json::to_vec(candidate) {
        Ok(bytes) if bytes.len() <= MAX_POLICY_DRAFT_CANDIDATE_BYTES => Ok(()),
        Ok(_) => Err(Box::new(PolicyDraftRefusal::TooLarge.response_with(
            json!({ "max_candidate_bytes": MAX_POLICY_DRAFT_CANDIDATE_BYTES }),
        ))),
        Err(error) => {
            tracing::error!(error = %error, "failed to serialize a policy draft candidate");
            Err(Box::new(internal_server_error(
                "policy draft candidate could not be serialized",
            )))
        }
    }
}

fn emit_policy_draft_event(
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

/// `policy.draft_changed`: identifiers and ETags only, never the candidate.
fn emit_policy_draft_changed(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    action: &'static str,
    summary: &PolicyDraftSummary,
    rebased: bool,
) {
    emit_policy_draft_event(
        state,
        parts,
        principal,
        audit::event::POLICY_DRAFT_CHANGED,
        json!({
            "action": action,
            "draft_id": summary.draft_id,
            "revision": summary.revision,
            "base_etag": summary.base_etag,
            "candidate_etag": summary.candidate_etag,
            "rebased": rebased,
        }),
    );
}

/// Answer a refused publication of a draft the caller holds, after
/// recording it: like the change it prevented, a decision not to change
/// enforcement belongs in the audit stream.
fn refuse_publication(
    context: &PublicationContext<'_>,
    draft: &PolicyDraftSummary,
    reason: &'static str,
    current_policy_etag: Option<&str>,
    response: Response,
) -> Response {
    emit_policy_draft_event(
        context.state,
        context.parts,
        context.principal,
        audit::event::POLICY_DRAFT_PUBLISH_REFUSED,
        json!({
            "draft_id": draft.draft_id,
            "draft_revision": draft.revision,
            "reason": reason,
            "base_etag": draft.base_etag,
            "candidate_etag": draft.candidate_etag,
            "current_policy_etag": current_policy_etag,
        }),
    );
    response
}

struct PublicationContext<'a> {
    state: &'a PolicyAdminState,
    parts: &'a http::request::Parts,
    principal: &'a auth::Principal,
}

/// `GET .../policy/drafts`: the caller's unexpired drafts, most recently
/// written first, without their candidates, and the bounds that apply.
pub(super) async fn policy_drafts_list_endpoint(
    State(state): State<PolicyAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(POLICY_DRAFTS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    let (_, store) = match authorized_draft_store(&state, &principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let summaries = match store.list(&policy_draft_owner(&principal)).await {
        Ok(summaries) => summaries,
        Err(error) => return policy_draft_store_failed(&error),
    };
    let mut drafts = Vec::with_capacity(summaries.len());
    for summary in &summaries {
        match draft_view(summary, None) {
            Ok(view) => drafts.push(view),
            Err(response) => return *response,
        }
    }
    let limits = store.limits();
    (
        StatusCode::OK,
        [(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        )],
        Json(PolicyDraftListView {
            drafts,
            limits: PolicyDraftLimitsView {
                ttl_seconds: limits.ttl_secs,
                max_drafts_per_owner: limits.max_per_owner,
                max_drafts: limits.max_total,
                max_candidate_bytes: MAX_POLICY_DRAFT_CANDIDATE_BYTES,
            },
        }),
    )
        .into_response()
}

/// `POST .../policy/drafts`: a new draft pinned to the live policy ETag that
/// `If-Match` names.
pub(super) async fn policy_draft_create_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_DRAFTS_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let (rbac_state, store) =
        match authorized_draft_store(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let base_etag = match presented_policy_etag(&parts.headers) {
        Ok(etag) => etag,
        Err(response) => return *response,
    };
    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request = match serde_json::from_slice::<PolicyDraftCreateRequest>(&body) {
        Ok(request) => request,
        Err(error) => return bad_request(&format!("invalid policy draft JSON: {error}")),
    };

    let (live_policy, live_etag) = match authoritative_policy_and_etag(&state, rbac_state).await {
        Ok(view) => view,
        Err(response) => return *response,
    };
    if base_etag != live_etag {
        return PolicyDraftRefusal::PolicyEtagMismatch.response();
    }
    let candidate = match request.policy {
        Some(value) => match parse_draft_candidate(value) {
            Ok(candidate) => candidate,
            Err(response) => return *response,
        },
        None => live_policy.clone(),
    };
    if let Err(response) = validate_policy_mutation_candidate(rbac_state, &live_policy, &candidate)
    {
        return *response;
    }
    if let Err(response) = within_candidate_bound(&candidate) {
        return *response;
    }
    let Some(draft_id) = new_policy_draft_id() else {
        tracing::error!("the operating system could not supply a policy draft identifier");
        return PolicyDraftRefusal::Unavailable.response();
    };

    let owner = policy_draft_owner(&principal);
    let created = store
        .create(NewPolicyDraft {
            draft_id: &draft_id,
            owner: &owner,
            base_etag: &live_etag,
            candidate: &candidate,
        })
        .await;
    match created {
        Ok(PolicyDraftCreated::Created(record)) => {
            emit_policy_draft_changed(
                &state,
                &parts,
                &principal,
                "created",
                &record.summary,
                false,
            );
            draft_response(StatusCode::CREATED, &record)
        }
        Ok(PolicyDraftCreated::OwnerQuotaExceeded) => PolicyDraftRefusal::OwnerQuotaExceeded
            .response_with(json!({ "max_drafts_per_owner": store.limits().max_per_owner })),
        Ok(PolicyDraftCreated::DeploymentQuotaExceeded) => {
            PolicyDraftRefusal::DeploymentQuotaExceeded
                .response_with(json!({ "max_drafts": store.limits().max_total }))
        }
        Err(error) => policy_draft_store_failed(&error),
    }
}

/// `GET .../policy/drafts/{id}`: the caller's draft and its strong ETag.
pub(super) async fn policy_draft_get_endpoint(
    State(state): State<PolicyAdminState>,
    Path(draft_id): Path<String>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(POLICY_DRAFT_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    let (_, store) = match authorized_draft_store(&state, &principal, ADMIN_POLICY_READ_PERMISSION)
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    match owned_draft(store, &policy_draft_owner(&principal), &draft_id).await {
        Ok(record) => draft_response(StatusCode::OK, &record),
        Err(response) => *response,
    }
}

/// `PATCH .../policy/drafts/{id}`: replace the candidate, re-pin the base to
/// the current live ETag, or both, under the draft's `If-Match`.
pub(super) async fn policy_draft_patch_endpoint(
    State(state): State<PolicyAdminState>,
    Path(draft_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_DRAFT_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let (rbac_state, store) =
        match authorized_draft_store(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let presented = match presented_draft_etag(&parts.headers, &header::IF_MATCH) {
        Ok(etag) => etag,
        Err(response) => return *response,
    };
    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request = match serde_json::from_slice::<PolicyDraftPatchRequest>(&body) {
        Ok(request) => request,
        Err(error) => return bad_request(&format!("invalid policy draft JSON: {error}")),
    };
    if request.policy.is_none() && request.base_etag.is_none() {
        return PolicyDraftRefusal::EmptyPatch.response();
    }

    let owner = policy_draft_owner(&principal);
    let draft = match owned_draft(store, &owner, &draft_id).await {
        Ok(record) => record,
        Err(response) => return *response,
    };
    if draft.summary.published_etag.is_some() {
        return PolicyDraftRefusal::Published.response();
    }
    if policy_draft_etag(&draft.summary) != presented {
        return PolicyDraftRefusal::EtagMismatch.response();
    }

    let (live_policy, live_etag) = match authoritative_policy_and_etag(&state, rbac_state).await {
        Ok(view) => view,
        Err(response) => return *response,
    };
    let base_etag = match request.base_etag {
        Some(requested) if requested != live_etag => {
            return PolicyDraftRefusal::PolicyEtagMismatch.response();
        }
        Some(_) => live_etag,
        None => draft.summary.base_etag.clone(),
    };
    let rebased = base_etag != draft.summary.base_etag;
    let candidate = match request.policy {
        Some(value) => match parse_draft_candidate(value) {
            Ok(candidate) => candidate,
            Err(response) => return *response,
        },
        None => draft.candidate,
    };
    if let Err(response) = validate_policy_mutation_candidate(rbac_state, &live_policy, &candidate)
    {
        return *response;
    }
    if let Err(response) = within_candidate_bound(&candidate) {
        return *response;
    }

    let updated = store
        .update(
            &owner,
            &draft_id,
            draft.summary.revision,
            PolicyDraftChange::Candidate {
                candidate: &candidate,
                base_etag: &base_etag,
            },
        )
        .await;
    match updated {
        Ok(Some(record)) => {
            emit_policy_draft_changed(
                &state,
                &parts,
                &principal,
                "updated",
                &record.summary,
                rebased,
            );
            draft_response(StatusCode::OK, &record)
        }
        Ok(None) => lost_draft_write(store, &owner, &draft_id).await,
        Err(error) => policy_draft_store_failed(&error),
    }
}

/// `DELETE .../policy/drafts/{id}`, open or published, under the draft's
/// `If-Match`.
pub(super) async fn policy_draft_delete_endpoint(
    State(state): State<PolicyAdminState>,
    Path(draft_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_DRAFT_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let (_, store) = match authorized_draft_store(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION)
    {
        Ok(context) => context,
        Err(response) => return *response,
    };
    let presented = match presented_draft_etag(&parts.headers, &header::IF_MATCH) {
        Ok(etag) => etag,
        Err(response) => return *response,
    };

    let owner = policy_draft_owner(&principal);
    let draft = match owned_draft(store, &owner, &draft_id).await {
        Ok(record) => record,
        Err(response) => return *response,
    };
    if policy_draft_etag(&draft.summary) != presented {
        return PolicyDraftRefusal::EtagMismatch.response();
    }
    match store
        .delete(&owner, &draft_id, draft.summary.revision)
        .await
    {
        Ok(true) => {
            emit_policy_draft_changed(&state, &parts, &principal, "deleted", &draft.summary, false);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => lost_draft_write(store, &owner, &draft_id).await,
        Err(error) => policy_draft_store_failed(&error),
    }
}

/// `POST .../policy/drafts/{id}/publish`: make the draft's candidate the
/// live policy.
///
/// Two preconditions, both required: [`POLICY_DRAFT_ETAG_HEADER`] names the
/// draft revision being published, and `If-Match` names the live policy
/// ETag it is published over. Under the policy write lock the handler reads
/// the draft, compares its ETag, reads the live policy from its authority,
/// refuses a draft whose pinned base is no longer live (checked before an
/// `If-Match` mismatch, so the usual stale case gets the binding's reason),
/// re-validates the candidate against the current authority, and commits it
/// through [`persist_policy_mutation`] -- the same transaction, history,
/// audit and replica install as `PUT .../policy`, whose `If-Match`
/// compare-and-swap still decides a race with another replica. Nothing is
/// written on any refusal, and the draft is kept.
///
/// After the commit the draft is marked published, which freezes it. That
/// second write is not in the policy transaction: if it fails, the response
/// still reports the committed policy and carries
/// [`POLICY_DRAFT_WARNING_HEADER`], and the draft stays open on the base it
/// was published over. The commit moved the live ETag off that base (a
/// candidate identical to its base changes nothing either way), so a second
/// publication is refused as stale until the owner explicitly re-pins it.
pub(super) async fn policy_draft_publish_endpoint(
    State(state): State<PolicyAdminState>,
    Path(draft_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_DRAFT_PUBLISH_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let (rbac_state, store) =
        match authorized_draft_store(&state, &principal, ADMIN_POLICY_WRITE_PERMISSION) {
            Ok(context) => context,
            Err(response) => return *response,
        };
    let presented_draft = match presented_draft_etag(
        &parts.headers,
        &HeaderName::from_static(POLICY_DRAFT_ETAG_HEADER),
    ) {
        Ok(etag) => etag,
        Err(response) => return *response,
    };
    let presented_policy = match presented_policy_etag(&parts.headers) {
        Ok(etag) => etag,
        Err(response) => return *response,
    };
    // Everything a publication acts on is named by the two preconditions;
    // a body could only be an option this endpoint does not have.
    match read_request_body(body, state.max_body_size).await {
        Ok(body) if body.is_empty() => {}
        Ok(_) => return bad_request("policy draft publication does not accept a request body"),
        Err(response) => return *response,
    }

    let owner = policy_draft_owner(&principal);
    let context = PublicationContext {
        state: &state,
        parts: &parts,
        principal: &principal,
    };
    let policy_write_guard = rbac_state.policy_write_guard().await;

    let draft = match owned_draft(store, &owner, &draft_id).await {
        Ok(record) => record,
        Err(response) => return *response,
    };
    if let Some(published_etag) = draft.summary.published_etag.as_deref() {
        let response = PolicyDraftRefusal::Published
            .response_with(json!({ "published_etag": published_etag }));
        return refuse_publication(
            &context,
            &draft.summary,
            PolicyDraftRefusal::Published.reason(),
            None,
            response,
        );
    }
    if policy_draft_etag(&draft.summary) != presented_draft {
        return refuse_publication(
            &context,
            &draft.summary,
            PolicyDraftRefusal::EtagMismatch.reason(),
            None,
            PolicyDraftRefusal::EtagMismatch.response(),
        );
    }

    let (live_policy, live_etag) = match authoritative_policy_and_etag(&state, rbac_state).await {
        Ok(view) => view,
        Err(response) => return *response,
    };
    if draft.summary.base_etag != live_etag {
        let response = PolicyDraftRefusal::BaseStale.response_with(json!({
            "base_etag": draft.summary.base_etag,
            "policy_etag": live_etag,
        }));
        return refuse_publication(
            &context,
            &draft.summary,
            PolicyDraftRefusal::BaseStale.reason(),
            Some(&live_etag),
            response,
        );
    }
    if presented_policy != live_etag {
        return refuse_publication(
            &context,
            &draft.summary,
            PolicyDraftRefusal::PolicyEtagMismatch.reason(),
            Some(&live_etag),
            PolicyDraftRefusal::PolicyEtagMismatch.response(),
        );
    }

    // The candidate was validated when it was saved, but publication is
    // judged against this binary and the resources current now.
    let validated = validate_policy_candidate(&draft.candidate).and_then(|candidate| {
        validate_policy_mutation_candidate(rbac_state, &live_policy, &candidate).map(|()| candidate)
    });
    let candidate = match validated {
        Ok(candidate) => candidate,
        Err(response) => {
            return refuse_publication(
                &context,
                &draft.summary,
                "policy_draft_candidate_invalid",
                Some(&live_etag),
                *response,
            );
        }
    };

    let diff_summary = json!({
        "action": "policy_draft_published",
        "draft_id": draft.summary.draft_id,
        "draft_revision": draft.summary.revision,
        "base_etag": draft.summary.base_etag,
    });
    let commit = match persist_policy_mutation(
        PolicyMutationCommitContext {
            state: &state,
            rbac_state,
            policy_write_guard: &policy_write_guard,
            parts: &parts,
            principal: &principal,
        },
        &live_policy,
        &live_etag,
        &candidate,
        diff_summary,
    )
    .await
    {
        Ok(commit) => commit,
        Err(response) => return *response,
    };

    let marked = store
        .update(
            &owner,
            &draft_id,
            draft.summary.revision,
            PolicyDraftChange::Published {
                published_etag: &commit.new_etag,
            },
        )
        .await;
    let draft_state_recorded = match marked {
        Ok(Some(_)) => true,
        Ok(None) => {
            tracing::error!(
                "a published policy draft changed before it could be marked published; it stays open on a stale base"
            );
            false
        }
        Err(error) => {
            tracing::error!(
                error = %error,
                "a published policy draft could not be marked published; it stays open on a stale base"
            );
            false
        }
    };
    emit_policy_draft_event(
        &state,
        &parts,
        &principal,
        audit::event::POLICY_DRAFT_PUBLISHED,
        json!({
            "draft_id": draft.summary.draft_id,
            "draft_revision": draft.summary.revision,
            "base_etag": draft.summary.base_etag,
            "candidate_etag": draft.summary.candidate_etag,
            "policy_etag": commit.new_etag,
            "draft_state_recorded": draft_state_recorded,
        }),
    );

    let mut response = (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&commit.new_etag))],
        Json(commit.after_policy),
    )
        .into_response();
    if !draft_state_recorded {
        response.headers_mut().insert(
            HeaderName::from_static(POLICY_DRAFT_WARNING_HEADER),
            HeaderValue::from_static(POLICY_DRAFT_STATE_NOT_RECORDED_WARNING),
        );
    }
    with_policy_history_append_warning(response, commit.history_append_failed)
}
