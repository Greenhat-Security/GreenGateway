//! admin responses boundary extracted from the application composition root.
use super::*;

pub(super) fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        Json(ErrorResponse {
            error: "unauthorized".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn forbidden() -> Response {
    let mut response = (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            error: "forbidden".to_owned(),
        }),
    )
        .into_response();
    response
        .extensions_mut()
        .insert(middleware::decision::PolicyDecision {
            outcome: middleware::decision::PolicyDecisionOutcome::Denied,
            reason: "admin_endpoint_denied",
            permission: None,
            path_prefix: None,
            matched_rule_id: None,
            facts: None,
        });
    response
}

pub(super) fn bad_request(error: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn not_found(error: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

/// The authority committed the policy, but this replica could not compile the
/// snapshot it just wrote -- a security revision that cannot exist.
///
/// The write stands; what failed is this replica's ability to serve under it. A
/// 503 rather than a 200 because answering success would report a snapshot that
/// is not installed, and rather than a 500 because the revision gate already
/// answers 503 for exactly this state: the replica is behind the authority.
#[cfg(feature = "postgres")]
pub(super) fn policy_snapshot_not_installable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: "policy was committed but its snapshot could not be installed on this replica"
                .to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn policy_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "policy API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn policy_history_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error:
                "policy history requires POLICY_FILE or POLICY_HISTORY_SQLITE_PATH to be configured"
                    .to_owned(),
        }),
    )
        .into_response()
}

/// The stable `reason` of [`policy_evidence_unavailable`], which a bound
/// shadow-rule promotion also records when it is refused for that cause.
pub(super) const POLICY_EVIDENCE_UNAVAILABLE_REASON: &str = "audit_evidence_unavailable";

/// A policy evidence endpoint (rule preview, hit counts, shadow review) has
/// no audit store to read.
///
/// A `503` with a stable `reason` rather than a successful empty result: a
/// zero hit count or an empty shadow summary reads exactly like "this rule
/// never matched", and an operator could delete or promote a rule on
/// evidence that was never read.
pub(super) fn policy_evidence_unavailable(error: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "error": error,
            "reason": POLICY_EVIDENCE_UNAVAILABLE_REASON,
        })),
    )
        .into_response()
}

pub(super) fn token_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "token API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn audit_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "audit API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn config_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "configuration API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn mcp_clients_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "MCP client configuration API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn status_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "status API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn cluster_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "cluster status API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn token_store_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "token API requires SERVICE_TOKEN_SQLITE_PATH to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn connection_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "connection API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn connection_store_not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: "connection mutations require CONNECTIONS_SQLITE_PATH to be configured"
                .to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn connection_secret_store_not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: "encrypted local connection-secret mutations are not configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn tools_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "tools API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn tools_file_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "tools API requires TOOLS_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn schema_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(SchemaNotConfiguredResponse {
            error: "schema coverage requires OPENAPI_SPEC_PATH or UPSTREAM_ROUTES[].openapi_spec_path to be configured".to_owned(),
            spec_configured: false,
        }),
    )
        .into_response()
}

pub(super) fn traffic_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "traffic endpoint inventory requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn principal_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "principal directory requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn signals_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "signals API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn suggestions_rbac_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "suggestions API requires POLICY_FILE to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn schema_discovery_not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(DiscoveryNotConfiguredResponse {
            error: "schema coverage requires DISCOVERY_SQLITE_PATH to be configured".to_owned(),
            discovery_configured: false,
        }),
    )
        .into_response()
}

pub(super) fn schema_inference_discovery_not_configured() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(DiscoveryNotConfiguredResponse {
            error: "inferred schema requires DISCOVERY_SQLITE_PATH to be configured".to_owned(),
            discovery_configured: false,
        }),
    )
        .into_response()
}

pub(super) fn payload_capture_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(PayloadCaptureNotConfiguredResponse {
            error: "inferred schema requires PAYLOAD_CAPTURE_ENABLED=true".to_owned(),
            payload_capture_configured: false,
        }),
    )
        .into_response()
}

pub(super) fn inferred_schema_no_samples() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(InferredSchemaNoSamplesResponse {
            error:
                "inferred schema has no captured payload samples for method and endpoint_template"
                    .to_owned(),
            schema_inferred: false,
        }),
    )
        .into_response()
}

pub(super) fn discovery_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "traffic endpoint inventory requires DISCOVERY_SQLITE_PATH to be configured"
                .to_owned(),
        }),
    )
        .into_response()
}

/// Map a discovery read-store failure for the admin surfaces. An invalid
/// cursor is the caller's `400`. A store that cannot be reached, or that
/// could not answer inside its contention budget (cluster mode's authority
/// down), is a dependency failure: `503`. Everything else is logged under
/// `context` and answered `500` with `failure`, which is what every
/// discovery handler answered before the read trait existed.
pub(super) fn discovery_query_error_response(
    error: discovery::query::DiscoveryQueryError,
    context: &'static str,
    failure: &str,
) -> Response {
    match error {
        discovery::query::DiscoveryQueryError::InvalidCursor { parameter } => {
            bad_request(&format!("invalid query parameter: {parameter}"))
        }
        discovery::query::DiscoveryQueryError::Repository(repository)
            if matches!(
                repository.kind(),
                storage::RepositoryErrorKind::Unavailable | storage::RepositoryErrorKind::Timeout
            ) =>
        {
            tracing::error!(error = %repository, context, "discovery store is unavailable");
            service_unavailable("discovery store is unavailable")
        }
        error => {
            tracing::error!(error = %error, "{context}");
            internal_server_error(failure)
        }
    }
}

pub(super) fn principal_directory_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "principal directory requires PRINCIPAL_SQLITE_PATH to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn signals_discovery_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "signals API requires DISCOVERY_SQLITE_PATH to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn suggestions_discovery_not_configured() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            error: "suggestions API requires DISCOVERY_SQLITE_PATH to be configured".to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn precondition_required(error: &str) -> Response {
    (
        StatusCode::PRECONDITION_REQUIRED,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn precondition_failed(error: &str) -> Response {
    (
        StatusCode::PRECONDITION_FAILED,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn conflict(error: &str) -> Response {
    (
        StatusCode::CONFLICT,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn connection_catalog_lifecycle_error_response(
    error: connections::control_plane::CatalogLifecycleError,
) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": "connection catalog operation is already in progress",
            "reason": error.safe_reason(),
        })),
    )
        .into_response()
}

pub(super) fn connection_refresh_error_response(
    error: connections::mcp::McpCatalogRefreshError,
) -> Response {
    let status = match error {
        connections::mcp::McpCatalogRefreshError::InvalidConnectionId
        | connections::mcp::McpCatalogRefreshError::ConnectionNotFound => StatusCode::NOT_FOUND,
        connections::mcp::McpCatalogRefreshError::PreconditionFailed => {
            StatusCode::PRECONDITION_FAILED
        }
        connections::mcp::McpCatalogRefreshError::ToolNameConflict
        | connections::mcp::McpCatalogRefreshError::RefreshInProgress
        | connections::mcp::McpCatalogRefreshError::ConnectionDisabled
        | connections::mcp::McpCatalogRefreshError::ConnectionKindMismatch
        | connections::mcp::McpCatalogRefreshError::DiscoveryNotConfigured
        | connections::mcp::McpCatalogRefreshError::CallerAssertionNotEnforced => {
            StatusCode::CONFLICT
        }
        connections::mcp::McpCatalogRefreshError::StoreUnavailable
        | connections::mcp::McpCatalogRefreshError::StorageUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        connections::mcp::McpCatalogRefreshError::EgressDenied
        | connections::mcp::McpCatalogRefreshError::SecretUnavailable
        | connections::mcp::McpCatalogRefreshError::AuthenticationFailed
        | connections::mcp::McpCatalogRefreshError::UpstreamMethodNotFound { .. }
        | connections::mcp::McpCatalogRefreshError::UpstreamError { .. }
        | connections::mcp::McpCatalogRefreshError::UpstreamTransport { .. }
        | connections::mcp::McpCatalogRefreshError::RequestFailed
        | connections::mcp::McpCatalogRefreshError::InvalidResponse => StatusCode::BAD_GATEWAY,
    };
    let mut body = json!({
        "error": "MCP connection refresh failed",
        "reason": error.safe_reason(),
    });
    if let Some(method) = error.upstream_method() {
        body["upstream_method"] = json!(method);
    }
    if let Some(code) = error.upstream_error_code() {
        body["upstream_error_code"] = json!(code);
    }
    (status, Json(body)).into_response()
}

pub(super) fn openapi_catalog_error_response(
    error: connections::openapi::OpenApiCatalogError,
    operation: &'static str,
) -> Response {
    use connections::openapi::OpenApiCatalogError;

    let status = match error {
        OpenApiCatalogError::InvalidConnectionId | OpenApiCatalogError::ConnectionNotFound => {
            StatusCode::NOT_FOUND
        }
        OpenApiCatalogError::PreconditionFailed => StatusCode::PRECONDITION_FAILED,
        OpenApiCatalogError::StalePreview
        | OpenApiCatalogError::CatalogNotRegistered
        | OpenApiCatalogError::OperationInProgress
        | OpenApiCatalogError::ConnectionDisabled
        | OpenApiCatalogError::ConnectionKindMismatch
        | OpenApiCatalogError::DiscoveryNotConfigured
        | OpenApiCatalogError::CallerAssertionNotEnforced
        | OpenApiCatalogError::AuthenticationNotSupported
        | OpenApiCatalogError::ToolConflict => StatusCode::CONFLICT,
        OpenApiCatalogError::SpecTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        OpenApiCatalogError::InvalidSpec
        | OpenApiCatalogError::InvalidSelection
        | OpenApiCatalogError::AuthenticationMismatch => StatusCode::BAD_REQUEST,
        // The endpoints ask the operation gate on this answer and never
        // return it; reaching here means nothing asked, so nothing is stored.
        OpenApiCatalogError::StoreUnavailable
        | OpenApiCatalogError::StorageUnavailable
        | OpenApiCatalogError::ConvertedCatalogNeedsAdmission { .. } => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        OpenApiCatalogError::EgressDenied
        | OpenApiCatalogError::SecretUnavailable
        | OpenApiCatalogError::AuthenticationFailed
        | OpenApiCatalogError::RequestFailed
        | OpenApiCatalogError::InvalidResponse => StatusCode::BAD_GATEWAY,
    };
    (
        status,
        Json(json!({
            "error": format!("managed OpenAPI {operation} failed"),
            "reason": error.safe_reason(),
        })),
    )
        .into_response()
}

pub(super) fn openapi_overlay_operation_error_response(
    error: connections::openapi::OpenApiOverlayOperationError,
    operation: &'static str,
) -> Response {
    match error {
        connections::openapi::OpenApiOverlayOperationError::Catalog(error) => {
            openapi_catalog_error_response(error, operation)
        }
        connections::openapi::OpenApiOverlayOperationError::Rejected(error) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({
                "problems": error.problems,
                "warnings": [],
            })),
        )
            .into_response(),
        connections::openapi::OpenApiOverlayOperationError::PreconditionFailed(current) => {
            with_etag(
                precondition_failed("If-Match does not match the current overlay ETag"),
                current.as_str(),
            )
        }
        connections::openapi::OpenApiOverlayOperationError::SecretsWriteRequired => {
            admin_permission_denied_response(ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION.to_owned())
        }
    }
}

pub(super) fn egress_reload_unsupported() -> Response {
    conflict(
        "egress allowlist changes cannot be applied via the policy API; edit POLICY_FILE and restart the gateway to change egress rules",
    )
}

/// A write the cluster's operation gate refused (issue #426). Nothing was
/// written. A live member that does not advertise what the write needs is a
/// conflict with the deployment's current membership -- finish the rollout,
/// or wait for departed members to go stale -- so it is a `409`; every other
/// refusal means the gate could not decide, or that this replica cannot
/// perform the write right now (a backfill not yet verified, a migration in
/// progress, a contract fence that excludes its build), so it is a `503`.
/// The body carries the refusal's stable reason and its member counts,
/// never a member identifier.
#[cfg(feature = "postgres")]
pub(super) fn operation_refused(refusal: &storage::compatibility::OperationRefusal) -> Response {
    let status = match refusal {
        storage::compatibility::OperationRefusal::MembersLackRequirement { .. } => {
            StatusCode::CONFLICT
        }
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        Json(json!({
            "error": refusal.to_string(),
            "reason": refusal.reason(),
        })),
    )
        .into_response()
}

/// A change `AUTHORITY_EVIDENCE_DURABILITY=required` refused because this
/// deployment mode records no evidence of it (issue #425, PR 4). It
/// conflicts with how the deployment is configured and will until that
/// changes, so it is a `409`, not a `503`. Nothing was read from or written
/// to the authority. The body names the refused operation and the stable
/// reason, never anything from the request.
pub(super) fn authority_evidence_unsupported(
    refusal: &authority_events::required::EvidenceRefusal,
) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": refusal.message(),
            "reason": authority_events::required::REFUSAL_REASON,
            "operation": refusal.operation().code(),
        })),
    )
        .into_response()
}

/// A caller-owned operation is one canonical RFC UUIDv7 header.
pub(super) fn caller_operation_id(headers: &HeaderMap) -> Result<uuid::Uuid, &'static str> {
    let mut values = headers.get_all("idempotency-key").iter();
    let raw = values.next().and_then(|v| v.to_str().ok());
    let id = raw
        .and_then(|raw| {
            uuid::Uuid::parse_str(raw).ok().filter(|id| {
                auth::tokens::valid_caller_operation_id(*id) && id.hyphenated().to_string() == raw
            })
        })
        .ok_or("Idempotency-Key must be one canonical lowercase UUIDv7")?;
    if values.next().is_some() {
        return Err("Idempotency-Key must occur exactly once");
    }
    Ok(id)
}

/// Ask the authority-evidence gate before an admin change made without a
/// caller key, and record a refusal against the caller and the request that
/// asked.
pub(super) fn admit_authority_change(
    gate: &authority_events::required::AuthorityEvidenceGate,
    operation: authority_events::required::AuthorityOperation,
    audit: &audit::AuditLog,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    client_ip_policy: &client_ip::ClientIpPolicy,
) -> ResponseResult<()> {
    admit_authority_change_for(
        gate,
        operation,
        authority_events::required::RequestForm::UNKEYED,
        audit,
        parts,
        principal,
        client_ip_policy,
    )
}

/// [`admit_authority_change`] for a request in `form`: keyed or not, by an
/// issuer-bound principal or not. Only a `caller_key_required` change looks
/// at the form.
pub(super) fn admit_authority_change_for(
    gate: &authority_events::required::AuthorityEvidenceGate,
    operation: authority_events::required::AuthorityOperation,
    form: authority_events::required::RequestForm,
    audit: &audit::AuditLog,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    client_ip_policy: &client_ip::ClientIpPolicy,
) -> ResponseResult<()> {
    gate.admit_for(
        operation,
        form,
        audit,
        authority_events::required::RefusalOrigin::Request {
            request_id: client_ip::request_id(&parts.headers, &parts.extensions),
            source_ip: client_ip::canonical_client_ip(
                &parts.headers,
                &parts.extensions,
                client_ip_policy,
            ),
            actor: Some(auth::actor_from_principal(principal)),
        },
    )
    .map_err(|refusal| Box::new(authority_evidence_unsupported(&refusal)))
}

// --- keyed authority changes (issue #425) -----------------------------------
//
// Every admin change that binds an `Idempotency-Key` through these helpers
// follows one contract (docs/authority-evidence.md, "Keyed authority
// changes"). The keyed revoke and the keyed preparation predate it and keep
// their own receipts and conflict answers. A handler, in this order:
//
// 0. authorizes the caller for the change and validates the request, as it
//    does today, before any of the steps below. Admission can raise the
//    durable contract fence, which is irreversible, fleet-wide and the
//    rollback cutoff for builds without `caller_operation_keys`; admin
//    routes are exempt from the data-plane RBAC layer and authorize
//    themselves, so a handler that asked the gates first would let any
//    authenticated caller, a service token without admin permission
//    included, raise the fence with one keyed request answered `403`;
// 1. binds the header to its request with [`caller_operation`], before it
//    reads anything: `None` for a request without the header;
// 2. asks [`admit_keyed_authority_change`]: the evidence gate, then, for a
//    keyed request in cluster mode, the operation gate for
//    `caller_operation_keys`;
// 3. answers an exact retry with [`replayed_receipt`], the read-only
//    pre-check, before any external I/O or post-commit side effect;
// 4. calls its store with the `CallerOperation`, which reserves the key in
//    the change's own transaction, and answers a `CallerOutcome::Replayed`
//    with [`operation_receipt`] and a key bound to something else with
//    [`caller_operation_conflict`].
//
// The gates come before the pre-check, an exact retry included, because the
// pre-check reads the authority: required mode refuses a form it does not
// admit before anything is read (I4), and a key is answered only while the
// whole fleet honours keys. Both gates are cheap on a retry: the evidence
// gate reads configuration only, and once the fence carries the capability
// the operation gate answers from an unlocked read that takes no exclusive
// lock, so concurrent keyed requests and retries admit each other.
//
// The route must also be listed in `routing::KEYED_ROUTES`; everywhere else
// the router refuses the header with [`idempotency_key_unsupported`] before
// the handler runs. Connection create, replace and delete bind keys through
// these helpers (`admin_connections::admit_keyed_connection_change`); each
// other operation family does so in its own change.

/// The caller key a request carries, bound to that request: `Ok(None)` when
/// it carries no `Idempotency-Key`. `action` is the operation code the key is
/// reserved for; `target` the resource identifier (empty for a create);
/// `precondition` the `If-Match` value as received (empty where the route
/// takes none); `request` the canonical request bytes with every secret value
/// removed (credential aliases and provider locators stay in). A malformed or
/// repeated header is `400`; an actor that cannot own a key -- a principal
/// without a canonical issuer -- is `403`, as for the keyed revoke. Reads
/// nothing and writes nothing.
#[cfg_attr(not(test), allow(dead_code))] // Called by the operation families that bind keys.
pub(super) fn caller_operation(
    headers: &HeaderMap,
    actor: &auth::change_actor::ChangeActor,
    action: &'static str,
    target: &str,
    precondition: &str,
    request: &[u8],
) -> ResponseResult<Option<authority_events::caller_operation::CallerOperation>> {
    use authority_events::caller_operation::{
        BindingRefusal, CallerOperation, CallerOperationBinding,
    };

    if !headers.contains_key("idempotency-key") {
        return Ok(None);
    }
    let id = caller_operation_id(headers).map_err(|reason| Box::new(bad_request(reason)))?;
    let binding = CallerOperationBinding {
        action,
        actor,
        target,
        precondition,
        request,
    };
    match CallerOperation::bind(id, &binding) {
        Ok(operation) => Ok(Some(operation)),
        Err(BindingRefusal::ActorCannotBind) => Err(Box::new(forbidden())),
        Err(BindingRefusal::NotCallerAssigned) => Err(Box::new(bad_request(
            "Idempotency-Key must be one canonical lowercase UUIDv7",
        ))),
        Err(BindingRefusal::MissingAction) => {
            tracing::error!("a keyed admin route bound a caller key to no action");
            Err(Box::new(internal_server_error(
                "the caller operation could not be bound",
            )))
        }
    }
}

/// What a keyed admin change asks before its store is called: the
/// authority-evidence gate, and in cluster mode the replica's membership,
/// whose operation gate admits `caller_operation_keys`. The audit log and
/// client-address policy name the request in a refusal's audit event.
#[cfg_attr(not(test), allow(dead_code))] // Built by the operation families that bind keys.
pub(super) struct KeyedChangeGates<'a> {
    pub(super) evidence: &'a authority_events::required::AuthorityEvidenceGate,
    /// `None` outside cluster mode. In cluster mode a keyed request with no
    /// membership to ask is refused, never admitted.
    #[cfg(feature = "postgres")]
    pub(super) membership: Option<&'a cluster_membership::ClusterMembership>,
    pub(super) audit: &'a audit::AuditLog,
    pub(super) client_ip_policy: &'a client_ip::ClientIpPolicy,
}

/// What a keyed admin change is, for the evidence gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))] // Named by the operation families that bind keys.
pub(super) enum KeyedChange {
    /// A change the evidence gate decides on.
    Gated(authority_events::required::AuthorityOperation),
    /// A change that only removes authority, which never asks the evidence
    /// gate: every form of it stays admitted (owner ruling 4 on issue #425).
    /// The set is closed ([`Withdrawal`]), and a key bound to any other
    /// action is not accepted as one.
    ///
    /// [`Withdrawal`]: authority_events::required::Withdrawal
    Withdrawal(authority_events::required::Withdrawal),
}

/// Admit a keyed admin change, or answer why not. Nothing is read from or
/// written to the authority before this admits. Call it only after the
/// handler has authorized the caller for the change and validated the
/// request: admitting a keyed request in cluster mode can raise the durable
/// contract fence, which never comes down.
///
/// - `change` names the change for the evidence gate: a
///   [`KeyedChange::Gated`] operation asks it, a [`KeyedChange::Withdrawal`]
///   never does. A refusal is `409 authority_evidence_unsupported`, audited.
///   A key reserved for a withdrawal's action on a gated change, or for
///   another action on a withdrawal, is a handler defect: `500`, and
///   nothing is asked or read.
/// - A keyed request (`caller` is `Some`) in cluster mode then asks the
///   operation gate for [`storage::compatibility::CALLER_OPERATION_KEYS`]:
///   the key is honoured only while every live member advertises
///   `caller_operation_keys`, and the first admission raises the durable
///   contract fence, so a build that would ignore the key can no longer
///   start or rejoin. A refusal is `409` when a live member lacks the
///   capability and `503` when the gate cannot answer, audited as
///   `cluster.operation_refused`. A request without a key does not ask.
///
/// [`AuthorityOperation`]: authority_events::required::AuthorityOperation
#[cfg_attr(not(test), allow(dead_code))] // Called by the operation families that bind keys.
pub(super) async fn admit_keyed_authority_change(
    gates: &KeyedChangeGates<'_>,
    change: KeyedChange,
    caller: Option<&authority_events::caller_operation::CallerOperation>,
    actor: &auth::change_actor::ChangeActor,
    parts: &http::request::Parts,
    principal: &auth::Principal,
) -> ResponseResult<()> {
    use authority_events::required::Withdrawal;

    if let Some(caller) = caller {
        let bound_withdrawal = Withdrawal::from_code(caller.action());
        let consistent = match change {
            KeyedChange::Gated(_) => bound_withdrawal.is_none(),
            KeyedChange::Withdrawal(withdrawal) => bound_withdrawal == Some(withdrawal),
        };
        if !consistent {
            tracing::error!(
                action = caller.action(),
                "a keyed admin change named a withdrawal its caller key is not bound to, or a gated change bound to a withdrawal; it is refused"
            );
            return Err(Box::new(internal_server_error(
                "the keyed change could not be admitted",
            )));
        }
    }
    if let KeyedChange::Gated(operation) = change {
        admit_authority_change_for(
            gates.evidence,
            operation,
            authority_events::required::RequestForm::of(caller.is_some(), actor),
            gates.audit,
            parts,
            principal,
            gates.client_ip_policy,
        )?;
    }
    if caller.is_none() || gates.evidence.backend() != config::StateBackend::Postgres {
        return Ok(());
    }
    #[cfg(feature = "postgres")]
    {
        let Some(membership) = gates.membership else {
            tracing::error!(
                "cluster mode: a keyed admin change has no cluster membership to ask; it is refused"
            );
            return Err(Box::new(operation_refused(
                &storage::compatibility::OperationRefusal::RosterUnavailable,
            )));
        };
        let request = cluster_membership::GatedWriteRequest {
            request_id: client_ip::request_id(&parts.headers, &parts.extensions),
            source_ip: client_ip::canonical_client_ip(
                &parts.headers,
                &parts.extensions,
                gates.client_ip_policy,
            ),
            actor: Some(auth::actor_from_principal(principal)),
        };
        membership
            .admit_operation(
                &storage::compatibility::CALLER_OPERATION_KEYS,
                gates.audit,
                &request,
            )
            .await
            .map(|_| ())
            .map_err(|refusal| Box::new(operation_refused(&refusal)))
    }
    #[cfg(not(feature = "postgres"))]
    {
        // Cluster mode cannot be configured without the feature; refuse
        // rather than honour a key no operation gate admitted.
        Err(Box::new(service_unavailable(
            "keyed admin changes in cluster mode need the postgres feature",
        )))
    }
}

/// The read-only pre-check of a keyed request (step 0 of the keyed
/// contract), run before any external I/O and any post-commit side effect.
/// `key` is the store's `read_caller_operation` for the request's
/// `CallerOperation`, and `receipt` its read of the committed evidence row
/// by that key; both are futures, so `receipt` runs only for an exact retry.
/// `Ok(())` means the key is unused: go on. Otherwise the answer is the
/// receipt (`200`) for the same action and binding, `409` for a key bound to
/// anything else, and `503` when either read fails or a reservation has no
/// evidence row. The answer is advisory: the change's own transaction
/// decides again.
#[cfg_attr(not(test), allow(dead_code))] // Called by the operation families that bind keys.
pub(super) async fn replayed_receipt(
    key: impl std::future::Future<
        Output = Result<
            authority_events::caller_operation::CallerKeyState,
            storage::RepositoryError,
        >,
    >,
    receipt: impl std::future::Future<
        Output = Result<
            Option<authority_events::caller_operation::OperationReceipt>,
            storage::RepositoryError,
        >,
    >,
) -> ResponseResult<()> {
    use authority_events::caller_operation::CallerKeyState;

    let unavailable = |error: Option<storage::RepositoryError>| {
        match error {
            Some(error) => {
                tracing::error!(error = %error, "a caller operation could not be read")
            }
            None => tracing::error!(
                "a caller operation is reserved without its evidence row; the request is refused"
            ),
        }
        Box::new(service_unavailable(
            "the caller operation could not be read",
        ))
    };
    match key.await.map_err(|error| unavailable(Some(error)))? {
        CallerKeyState::Unused => Ok(()),
        CallerKeyState::OtherBinding => Err(Box::new(caller_operation_conflict())),
        CallerKeyState::SameBinding => {
            match receipt.await.map_err(|error| unavailable(Some(error)))? {
                Some(receipt) => Err(Box::new(operation_receipt(&receipt))),
                None => Err(unavailable(None)),
            }
        }
    }
}

/// An exact retry's answer: `200` with the receipt read from the committed
/// evidence row, never a secret, a binding digest or a raw request field.
#[cfg_attr(not(test), allow(dead_code))] // Called by the operation families that bind keys.
pub(super) fn operation_receipt(
    receipt: &authority_events::caller_operation::OperationReceipt,
) -> Response {
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(receipt),
    )
        .into_response()
}

/// The stable reason of [`caller_operation_conflict`].
pub(super) const CALLER_OPERATION_CONFLICT_REASON: &str = "caller_operation_conflict";

/// A key already reserved for another action, another binding, or without a
/// binding (a keyed revoke or prepare): `409`, and nothing changed.
#[cfg_attr(not(test), allow(dead_code))] // Called by the operation families that bind keys.
pub(super) fn caller_operation_conflict() -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "error": "Idempotency-Key is bound to a different request; nothing was changed",
            "reason": CALLER_OPERATION_CONFLICT_REASON,
        })),
    )
        .into_response()
}

/// The stable reason of [`idempotency_key_unsupported`].
pub(super) const IDEMPOTENCY_KEY_UNSUPPORTED_REASON: &str = "idempotency_key_unsupported";

/// An `Idempotency-Key` on an admin mutation route that does not honour one
/// (`routing::KEYED_ROUTES`): `400`, answered by the router before the
/// handler runs, so nothing was read or written. A key is honoured or
/// refused, never ignored: ignoring it would apply a retry a second time.
pub(super) fn idempotency_key_unsupported() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": "this route does not honour an Idempotency-Key; nothing was changed",
            "reason": IDEMPOTENCY_KEY_UNSUPPORTED_REASON,
        })),
    )
        .into_response()
}

pub(super) fn service_unavailable(error: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn internal_server_error(error: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: error.to_owned(),
        }),
    )
        .into_response()
}

pub(super) fn token_store_error_response(error: storage::RepositoryError) -> Response {
    if let Some(parameter) = error.invalid_parameter_name() {
        return bad_request(&format!("invalid query parameter: {parameter}"));
    }
    // The rotate and keyed-revoke endpoints translate their known conflicts
    // into 409 responses. A storage uniqueness violation or another
    // unexpected conflict is an internal failure.
    // A store that cannot be reached, or that could not answer inside its
    // contention budget, is a dependency failure: `503`, so a load
    // balancer and an operator see "the authority is unavailable" rather
    // than "the gateway is broken". Everything else stays `500`.
    match error.kind() {
        storage::RepositoryErrorKind::Unavailable | storage::RepositoryErrorKind::Timeout => {
            tracing::error!(error = %error, "service-token store is unavailable");
            service_unavailable("service-token store is unavailable")
        }
        _ => {
            tracing::error!(error = %error, "service-token store operation failed");
            internal_server_error("service-token store operation failed")
        }
    }
}
