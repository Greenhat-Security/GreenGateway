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
        | connections::mcp::McpCatalogRefreshError::DiscoveryNotConfigured => StatusCode::CONFLICT,
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
        | OpenApiCatalogError::ToolConflict => StatusCode::CONFLICT,
        OpenApiCatalogError::SpecTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        OpenApiCatalogError::InvalidSpec
        | OpenApiCatalogError::InvalidSelection
        | OpenApiCatalogError::AuthenticationMismatch => StatusCode::BAD_REQUEST,
        OpenApiCatalogError::StoreUnavailable | OpenApiCatalogError::StorageUnavailable => {
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
        connections::openapi::OpenApiOverlayOperationError::SecretsWriteRequired => forbidden(),
    }
}

pub(super) fn egress_reload_unsupported() -> Response {
    conflict(
        "egress allowlist changes cannot be applied via the policy API; edit POLICY_FILE and restart the gateway to change egress rules",
    )
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
    // A `Conflict` is not translated here. The only store conflict an
    // endpoint can reach is the rotate endpoint's revoked-token case, and
    // that endpoint answers it with its own `409` before falling through to
    // this shared mapping; any other conflict (a store-level uniqueness
    // violation, for instance) is a store failure this responder logs and
    // answers `500`, which is the pre-#340 behavior the async-contract
    // refactor's blanket translation had broadened to every operation.
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
