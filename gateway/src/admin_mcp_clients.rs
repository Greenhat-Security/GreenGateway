//! MCP client configuration templates (issue #242, ADR-0008 "MCP client
//! templates").
//!
//! `GET /v1{ADMIN_PREFIX}/mcp/client-configs` serves the `McpClientConfigs`
//! document the shared `gateway-config` crate renders, which `ggctl
//! mcp-config` reads with the same crate. Every template names the gateway's
//! MCP resource identifier, computed from `GATEWAY_PUBLIC_URL` exactly as the
//! protected-resource metadata computes it. The handler reads nothing from
//! the request but the principal and the optional server entry `name`, so no
//! `Host`, forwarding header or query parameter can move the URL, and no
//! template can point at an upstream.
//!
//! The route has its own read permission, `admin:mcp:clients:read`, so a role
//! that hands out client templates needs neither `admin:config:read` nor a
//! token permission. Minting the token a token template reads stays a
//! separate `admin:tokens:write` action under the existing delegation rules.
use gateway_config::mcp_client_configs::{McpClientConfigs, McpUrl, ServerName};

use super::*;

/// The query this route accepts: an optional server entry name.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct McpClientConfigParams {
    name: Option<String>,
}

/// `GET /v1{ADMIN_PREFIX}/mcp/client-configs`: `admin:mcp:clients:read`,
/// behind the admin authentication and RBAC layers like every admin read
/// route.
pub(super) async fn mcp_client_configs_endpoint(
    State(state): State<StatusAdminState>,
    principal: Option<Extension<auth::Principal>>,
    params: Result<Query<McpClientConfigParams>, axum::extract::rejection::QueryRejection>,
) -> Response {
    record_request(MCP_CLIENT_CONFIGS_ADMIN_ROUTE);
    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    match authorized_status_state(&state, &principal, ADMIN_MCP_CLIENTS_READ_PERMISSION) {
        Ok(_) => {}
        Err(AdminReadAuthzError::NotConfigured) => return mcp_clients_rbac_not_configured(),
        Err(AdminReadAuthzError::Forbidden(permission)) => {
            return admin_permission_denied_response(permission)
        }
    }
    // Checked only once the caller is authorized, and never echoed: a
    // refused query or name is answered with fixed text and a stable reason.
    let Ok(Query(params)) = params else {
        return refusal(
            StatusCode::BAD_REQUEST,
            "the only query parameter is name, at most once",
            "invalid_query",
        );
    };
    let server_name = match params.name.as_deref().map(ServerName::new) {
        None => ServerName::default(),
        Some(Some(name)) => name,
        Some(None) => {
            return refusal(
                StatusCode::BAD_REQUEST,
                "name must be 1 to 64 ASCII letters, digits, '-' or '_', starting with a letter or digit",
                "invalid_server_name",
            )
        }
    };
    // The gateway has no other source for its public origin, and guesses
    // none: without GATEWAY_PUBLIC_URL there is no URL to template.
    let Some(metadata) =
        auth::protected_resource::ProtectedResourceMetadataConfig::from_config(&state.config)
    else {
        return refusal(
            StatusCode::CONFLICT,
            "MCP client configuration templates require GATEWAY_PUBLIC_URL",
            "public_url_not_configured",
        );
    };
    let Ok(mcp_url) = McpUrl::new(&metadata.mcp_resource()) else {
        return refusal(
            StatusCode::CONFLICT,
            "the MCP endpoint derived from GATEWAY_PUBLIC_URL cannot be written into a client configuration",
            "public_url_not_templatable",
        );
    };
    match McpClientConfigs::render(
        &mcp_url,
        &server_name,
        metadata.advertises_authorization_server(),
    ) {
        Ok(document) => {
            let mut response = Json(document).into_response();
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        Err(_) => internal_server_error("MCP client configuration templates could not be rendered"),
    }
}

/// A refusal with a stable `reason`. Nothing was rendered.
fn refusal(status: StatusCode, error: &'static str, reason: &'static str) -> Response {
    (status, Json(json!({ "error": error, "reason": reason }))).into_response()
}
