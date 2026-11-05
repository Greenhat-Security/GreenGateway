//! `GET`/`PUT /v1{ADMIN_PREFIX}/policy/tests` (issue #243): the stored
//! policy test suite, one exact-version `policy-tests.v1` document kept
//! beside the policy under a strong ETag.
//!
//! The suite is test input, not authority over traffic: storing one changes
//! no enforcement and activates nothing. A test run (`POST
//! .../policy/tests/runs`) and an evidence package (`POST .../policy/evidence`)
//! can name it instead of carrying a suite of their own; this module also
//! resolves that reference for them ([`stored_policy_test_suite`]).
//!
//! The rules the handlers keep:
//!
//! - **Authorization before work.** `401` and `403` are answered before any
//!   store, header or body is read. A read needs `admin:policy:read` and
//!   `admin:policy:simulate`, the permissions a run of the suite needs; a
//!   write needs `admin:policy:write`.
//! - **Strong ETag, no blind write.** The ETag is the suite's ADR-0004
//!   semantic digest in quotes. `PUT` requires exactly one of `If-Match`
//!   (one strong tag naming the stored suite) or `If-None-Match: *` (no
//!   suite stored yet): neither is `428`, and a precondition that no longer
//!   holds is `412`, decided inside the store's own transaction so two
//!   writers holding one ETag produce one winner.
//! - **Bounded and strict.** The body is read within `MAX_BODY_SIZE` or
//!   2 MiB, whichever is lower, and within five seconds; repeated member
//!   names are refused before parsing, and the suite is parsed by the same
//!   parser a run uses (at most 512 cases), so a stored suite is always one a
//!   run accepts.
//! - **Audited by digest.** Every write emits `policy.tests_changed` with the
//!   version, the old and new digests and case counts, never a case, an id or
//!   a fixture value. Standalone mode records no other evidence of the write,
//!   so `AUTHORITY_EVIDENCE_DURABILITY=required` refuses it there; cluster mode
//!   commits it with its `document_change_evidence` row.
//! - **Nothing in the browser.** The suite lives in the policy history
//!   database standalone and in migration 29's tables in cluster mode, never
//!   in client storage.
use super::*;

use storage::policy_tests::{
    contains_nul_character, PolicyTestSuiteCommitError, PolicyTestSuitePrecondition,
    PolicyTestSuiteRecord, MAX_POLICY_TEST_SUITE_BYTES,
};

/// Largest `PUT` body, in bytes: the bound a test run applies to its whole
/// request, so a stored suite always fits in one.
pub(super) const MAX_POLICY_TESTS_BODY_BYTES: usize = MAX_POLICY_TEST_SUITE_BYTES;
/// How long a `PUT` body may take to arrive.
pub(super) const POLICY_TESTS_BODY_DEADLINE: Duration = Duration::from_secs(5);
/// The stored version a response shows, beside its ETag.
pub(super) const POLICY_TESTS_VERSION_HEADER: &str = "x-greengateway-policy-tests-version";

/// Why a suite request was refused. Each has a stable `reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PolicyTestsRefusal {
    /// No suite store is configured, or it could not be consulted.
    Unavailable,
    /// No suite has been stored.
    NotFound,
    /// A write named neither `If-Match` nor `If-None-Match: *`.
    PreconditionRequired,
    /// The precondition is not exactly one strong tag or `*`, or names both.
    PreconditionInvalid,
    /// The suite named is not the stored one.
    EtagMismatch,
    /// `If-None-Match: *`, and a suite is already stored.
    AlreadyStored,
    /// The body is not one JSON value with unique member names.
    RequestInvalid,
    /// The body did not arrive within its deadline.
    RequestTimeout,
}

impl PolicyTestsRefusal {
    pub(super) fn status(self) -> StatusCode {
        match self {
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            Self::PreconditionInvalid | Self::RequestInvalid => StatusCode::BAD_REQUEST,
            Self::EtagMismatch | Self::AlreadyStored => StatusCode::PRECONDITION_FAILED,
            Self::RequestTimeout => StatusCode::REQUEST_TIMEOUT,
        }
    }

    pub(super) fn reason(self) -> &'static str {
        match self {
            Self::Unavailable => "policy_tests_unavailable",
            Self::NotFound => "policy_tests_not_found",
            Self::PreconditionRequired => "policy_tests_precondition_required",
            Self::PreconditionInvalid => "policy_tests_precondition_invalid",
            Self::EtagMismatch => "policy_tests_etag_mismatch",
            Self::AlreadyStored => "policy_tests_exist",
            Self::RequestInvalid => "policy_tests_request_invalid",
            Self::RequestTimeout => "policy_tests_request_timeout",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::Unavailable => "the stored policy test suite is unavailable",
            Self::NotFound => "no policy test suite is stored",
            Self::PreconditionRequired => {
                "If-Match naming the stored suite, or If-None-Match: * to store the first one, is required"
            }
            Self::PreconditionInvalid => {
                "the precondition must be exactly one strong entity tag in If-Match, or If-None-Match: *, not both"
            }
            Self::EtagMismatch => "the stored policy test suite is not the one this ETag names",
            Self::AlreadyStored => "a policy test suite is already stored; replace it with If-Match",
            Self::RequestInvalid => "the policy test suite must be JSON with unique object members",
            Self::RequestTimeout => "the policy test suite did not arrive within its deadline",
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

/// The store behind an authorized request. Permission is decided first, so
/// an unauthorized caller learns nothing about whether a suite is stored.
fn authorized_suite_store<'a>(
    state: &'a PolicyAdminState,
    principal: &auth::Principal,
    permissions: &[&str],
) -> ResponseResult<&'a Arc<dyn storage::PolicyTestSuiteStore>> {
    let Some((first, rest)) = permissions.split_first() else {
        return Err(Box::new(internal_server_error(
            "policy test suite permissions are not configured",
        )));
    };
    let rbac_state = authorized_policy_state(state, principal, first)
        .map_err(|error| Box::new(policy_admin_authz_error_response(error)))?;
    for permission in rest {
        if !rbac_state.principal_has_permission(principal, permission) {
            return Err(Box::new(admin_permission_denied_response(
                (*permission).to_owned(),
            )));
        }
    }
    if !policy_authority_configured(state) {
        return Err(Box::new(policy_not_configured()));
    }
    state
        .test_suite_store
        .as_ref()
        .ok_or_else(|| Box::new(PolicyTestsRefusal::Unavailable.response()))
}

/// The precondition a `PUT` presents: exactly one of `If-Match` with one
/// strong tag, or `If-None-Match: *`.
fn suite_write_precondition(
    headers: &HeaderMap,
) -> Result<PolicyTestSuitePrecondition, PolicyTestsRefusal> {
    let if_match = headers.contains_key(header::IF_MATCH);
    let mut if_none_match = headers.get_all(header::IF_NONE_MATCH).iter();
    match (if_match, if_none_match.next()) {
        (true, Some(_)) => Err(PolicyTestsRefusal::PreconditionInvalid),
        (true, None) => exact_strong_if_match(headers)
            .map(|etag| PolicyTestSuitePrecondition::Expected { etag })
            .map_err(|_| PolicyTestsRefusal::PreconditionInvalid),
        (false, Some(value)) => {
            let only = if_none_match.next().is_none();
            match value.to_str() {
                Ok(value) if only && value.trim() == "*" => Ok(PolicyTestSuitePrecondition::Absent),
                _ => Err(PolicyTestsRefusal::PreconditionInvalid),
            }
        }
        (false, None) => Err(PolicyTestsRefusal::PreconditionRequired),
    }
}

/// The stored suite as a response: its RFC 8785 bytes, its strong ETag and
/// version, never cached.
fn suite_response(status: StatusCode, record: &PolicyTestSuiteRecord) -> Response {
    let body = match canonical_json::canonical_json_bytes(&record.document) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(error = %error, "a stored policy test suite has no canonical form");
            return internal_server_error("policy test suite could not be rendered");
        }
    };
    (
        status,
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            ),
            (header::ETAG, etag_header_value(&record.etag)),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            ),
            (
                HeaderName::from_static(POLICY_TESTS_VERSION_HEADER),
                HeaderValue::from(record.version),
            ),
        ],
        body,
    )
        .into_response()
}

/// How many cases of each kind a suite declares: the shape of a change,
/// without any of its content.
fn case_kind_counts(record: &PolicyTestSuiteRecord) -> Value {
    use policy_testing::suite::CaseKind;

    let mut counts: std::collections::BTreeMap<&'static str, usize> = [
        CaseKind::Http,
        CaseKind::Tool,
        CaseKind::ToolHttp,
        CaseKind::Rate,
        CaseKind::Egress,
    ]
    .into_iter()
    .map(|kind| (kind.as_str(), 0))
    .collect();
    // Every case is counted under its own kind, so the counts always add up
    // to `case_count`.
    for case in &record.suite.cases {
        *counts.entry(case.input.kind().as_str()).or_insert(0) += 1;
    }
    json!(counts)
}

/// `policy.tests_changed`: the version, digests and counts only.
fn emit_policy_tests_changed(
    state: &PolicyAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    replaced: Option<&str>,
    record: &PolicyTestSuiteRecord,
) {
    let request_id = client_ip::request_id(&parts.headers, &parts.extensions);
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);
    let previous_digest = replaced.map(|etag| {
        etag.strip_prefix('"')
            .and_then(|etag| etag.strip_suffix('"'))
            .unwrap_or(etag)
    });
    let mut payload = json!({
        "action": if replaced.is_some() { "replaced" } else { "created" },
        "version": record.version,
        "suite_digest": record.digest,
        "previous_suite_digest": previous_digest,
        "case_count": record.case_count(),
        "case_kinds": case_kind_counts(record),
    });
    if let (Some(revision), Some(payload)) = (record.security_revision, payload.as_object_mut()) {
        payload.insert("security_revision".to_owned(), json!(revision));
    }
    state.audit.emit(audit::AuditEvent::new(
        audit::event::POLICY_TESTS_CHANGED,
        request_id,
        source_ip,
        Some(auth::actor_from_principal(principal)),
        payload,
    ));
}

fn suite_invalid(diagnostics: &policy_testing::suite::Diagnostics) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "policy test suite is invalid",
            "reason": "policy_tests_invalid",
            "diagnostics": diagnostics.diagnostics,
            "diagnostics_truncated": diagnostics.truncated,
        })),
    )
        .into_response()
}

fn suite_store_failed(error: &dyn std::fmt::Display) -> Response {
    tracing::error!(error = %error, "policy test suite store failed");
    PolicyTestsRefusal::Unavailable.response()
}

/// Why the stored suite a run or evidence package names cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StoredSuiteRefusal {
    /// No suite store is configured, or it could not be consulted.
    Unavailable,
    /// No suite is stored.
    NotFound,
    /// The stored suite is not the one the reference pinned.
    EtagMismatch,
}

impl StoredSuiteRefusal {
    /// The refusal a test run answers with.
    pub(super) fn response(self) -> Response {
        match self {
            Self::Unavailable => PolicyTestsRefusal::Unavailable.response(),
            Self::NotFound => PolicyTestsRefusal::NotFound.response(),
            Self::EtagMismatch => PolicyTestsRefusal::EtagMismatch.response(),
        }
    }
}

/// The stored suite a run or evidence package names, pinned to
/// `expected_etag` when the reference names one. The caller has already
/// decided the permissions a run of it needs.
pub(super) async fn stored_policy_test_suite(
    state: &PolicyAdminState,
    expected_etag: Option<&str>,
) -> Result<PolicyTestSuiteRecord, StoredSuiteRefusal> {
    let Some(store) = state.test_suite_store.as_ref() else {
        return Err(StoredSuiteRefusal::Unavailable);
    };
    let record = match store.active().await {
        Ok(Some(record)) => record,
        Ok(None) => return Err(StoredSuiteRefusal::NotFound),
        Err(error) => {
            tracing::error!(error = %error, "the stored policy test suite could not be read");
            return Err(StoredSuiteRefusal::Unavailable);
        }
    };
    match expected_etag {
        Some(expected) if expected != record.etag => Err(StoredSuiteRefusal::EtagMismatch),
        _ => Ok(record),
    }
}

/// `GET .../policy/tests`: the stored suite and its strong ETag.
pub(super) async fn policy_tests_get_endpoint(
    State(state): State<PolicyAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(POLICY_TESTS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    let store = match authorized_suite_store(
        &state,
        &principal,
        &[
            ADMIN_POLICY_READ_PERMISSION,
            ADMIN_POLICY_SIMULATE_PERMISSION,
        ],
    ) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    match store.active().await {
        Ok(Some(record)) => suite_response(StatusCode::OK, &record),
        Ok(None) => PolicyTestsRefusal::NotFound.response(),
        Err(error) => suite_store_failed(&error),
    }
}

/// `PUT .../policy/tests`: store the next version of the suite, under
/// `If-Match` naming the stored one or `If-None-Match: *` for the first.
pub(super) async fn policy_tests_put_endpoint(
    State(state): State<PolicyAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(POLICY_TESTS_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let store = match authorized_suite_store(&state, &principal, &[ADMIN_POLICY_WRITE_PERMISSION]) {
        Ok(store) => store,
        Err(response) => return *response,
    };
    let precondition = match suite_write_precondition(&parts.headers) {
        Ok(precondition) => precondition,
        Err(refusal) => return refusal.response(),
    };
    // Standalone mode records no evidence of the write beyond the writer's
    // subject on the version row, so required evidence refuses it here,
    // before anything is read or written.
    if let Err(response) = admit_authority_change(
        &state.authority_evidence,
        authority_events::required::AuthorityOperation::PolicyTestsPublish,
        &state.audit,
        &parts,
        &principal,
        &state.client_ip_policy,
    ) {
        return *response;
    }
    let body_limit = state.max_body_size.min(MAX_POLICY_TESTS_BODY_BYTES);
    let body_deadline = tokio::time::Instant::now() + POLICY_TESTS_BODY_DEADLINE;
    let body = match read_request_body_before(body, body_limit, body_deadline).await {
        Ok(body) => body,
        Err(TimedBodyReadError::Rejected(response)) => return *response,
        Err(TimedBodyReadError::DeadlineExceeded) => {
            return PolicyTestsRefusal::RequestTimeout.response();
        }
    };
    // A repeated member is refused before anything reads the body: a JSON
    // value keeps the last of two and says nothing, so the suite stored
    // could differ from the one a reviewer read.
    if !policy_eval::input::has_unique_members(&body) {
        return PolicyTestsRefusal::RequestInvalid.response();
    }
    let Ok(document) = serde_json::from_slice::<Value>(&body) else {
        return PolicyTestsRefusal::RequestInvalid.response();
    };
    if let Err(diagnostics) = policy_testing::suite::parse_suite(&document) {
        return suite_invalid(&diagnostics);
    }
    // PostgreSQL's jsonb cannot hold U+0000, so neither mode stores one and
    // a suite means the same thing in both.
    if contains_nul_character(&document) {
        let mut diagnostics = policy_testing::suite::Diagnostics::new();
        diagnostics.push(
            "invalid_value",
            "",
            "a stored suite may not contain the character U+0000 in any string",
        );
        return suite_invalid(&diagnostics);
    }

    let replaced = match &precondition {
        PolicyTestSuitePrecondition::Expected { etag } => Some(etag.clone()),
        PolicyTestSuitePrecondition::Absent => None,
    };
    match store.commit(precondition, &document, &principal).await {
        Ok(record) => {
            emit_policy_tests_changed(&state, &parts, &principal, replaced.as_deref(), &record);
            let status = if replaced.is_some() {
                StatusCode::OK
            } else {
                StatusCode::CREATED
            };
            suite_response(status, &record)
        }
        Err(PolicyTestSuiteCommitError::PreconditionFailed) => {
            if replaced.is_some() {
                PolicyTestsRefusal::EtagMismatch.response()
            } else {
                PolicyTestsRefusal::AlreadyStored.response()
            }
        }
        Err(PolicyTestSuiteCommitError::Store(error)) => suite_store_failed(&error),
    }
}
