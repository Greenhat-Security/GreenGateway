//! The configuration admin API (issue #242, ADR-0008).
//!
//! Only the version handshake exists so far:
//! `GET /v1{ADMIN_PREFIX}/config/capabilities` serves the
//! `GatewayCapabilities` document that `ggctl` reads before any
//! configuration operation. The document is built by the shared
//! `gateway-config` crate, the same one `ggctl` reads it with, so the two
//! binaries cannot disagree about its shape. It reports environment mode, no
//! accepted configuration document and no enabled configuration operation,
//! because nothing in this API accepts configuration yet; the later #242
//! slices that add validate, plan and apply extend those lists.
use super::*;

/// `GET /v1{ADMIN_PREFIX}/config/capabilities`: `admin:config:read`, behind
/// the admin authentication and RBAC layers like every admin read route.
pub(super) async fn config_capabilities_endpoint(
    State(state): State<StatusAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(CONFIG_CAPABILITIES_ADMIN_ROUTE);
    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    match authorized_status_state(&state, &principal, ADMIN_CONFIG_READ_PERMISSION) {
        Ok(_) => {}
        Err(AdminReadAuthzError::NotConfigured) => return config_rbac_not_configured(),
        Err(AdminReadAuthzError::Forbidden(permission)) => {
            return admin_permission_denied_response(permission)
        }
    }
    let capabilities =
        gateway_config::capabilities::GatewayCapabilities::environment(env!("CARGO_PKG_VERSION"));
    let mut response = Json(capabilities).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
