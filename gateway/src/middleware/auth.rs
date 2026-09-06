//! Global authentication middleware.
//!
//! This ports the issue #5 request-path auth scope and folds in the planned
//! auth audit events scope now that the audit pipeline is available.

use std::sync::Arc;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use http::{
    header::{COOKIE, RETRY_AFTER, USER_AGENT, WWW_AUTHENTICATE},
    HeaderMap, HeaderValue, StatusCode,
};
use serde::Serialize;
use serde_json::json;

use crate::{
    audit::{AuditEvent, AuditLog},
    auth::{
        actor_from_principal, protected_resource, AuthError, Principal, PrincipalDirectory,
        SessionCredential, SessionValidator, VerifiedClientIdentity,
    },
    client_ip::{canonical_client_ip, request_id, ClientIpPolicy},
    config::{AuthMode, Config},
    path_match::exempt_path_matches,
};

use super::{bearer::bearer_token, decision::AuthOutcome};

const AUTH_SUCCESS: &str = "auth.success";
const AUTH_FAILURE: &str = "auth.failure";

#[derive(Clone)]
pub struct AuthState {
    pub validator: Option<Arc<dyn SessionValidator>>,
    pub mode: AuthMode,
    pub cookie_name: String,
    pub exempt_paths: Vec<String>,
    pub audit: AuditLog,
    pub principal_directory: PrincipalDirectory,
    pub client_ip_policy: ClientIpPolicy,
    pub mcp_route_paths: Vec<String>,
    pub mcp_resource: Option<String>,
    pub mcp_resource_metadata_url: Option<String>,
}

#[derive(Serialize)]
struct UnauthorizedBody {
    error: &'static str,
}

#[derive(Serialize)]
struct ServiceUnavailableBody {
    error: &'static str,
}

/// Why authentication did not produce a principal.
///
/// The validators separate a credential that was judged and not accepted from
/// one that could not be judged at all, and `ChainValidator` carries that
/// distinction through the chain. These are different answers and they need
/// different wire encodings: a rejected credential is the caller's problem and
/// permanent, an identity dependency that failed is the gateway's and
/// transient.
#[derive(Clone, Copy)]
enum AuthFailureKind {
    /// The credential was evaluated and not accepted.
    Rejected,
    /// An identity dependency failed, so the credential was never judged.
    Unverifiable,
}

struct AuditContext {
    request_id: String,
    source_ip: String,
    user_agent: Option<String>,
    path: String,
}

impl AuthState {
    pub fn from_config(
        config: &Config,
        validator: Option<Arc<dyn SessionValidator>>,
        audit: AuditLog,
        principal_directory: PrincipalDirectory,
    ) -> Self {
        let protected_resource_metadata =
            protected_resource::ProtectedResourceMetadataConfig::from_config(config);
        Self {
            validator,
            mode: config.auth_mode,
            cookie_name: config.auth_cookie_name.clone(),
            exempt_paths: config.auth_exempt_paths.clone(),
            audit,
            principal_directory,
            client_ip_policy: ClientIpPolicy::from_config(config),
            mcp_route_paths: protected_resource::mcp_route_paths(config),
            mcp_resource: protected_resource_metadata
                .as_ref()
                .map(protected_resource::ProtectedResourceMetadataConfig::mcp_resource),
            mcp_resource_metadata_url: protected_resource_metadata
                .as_ref()
                .map(protected_resource::ProtectedResourceMetadataConfig::metadata_url),
        }
    }
}

impl AuthState {
    fn is_mcp_route_path(&self, path: &str) -> bool {
        self.mcp_route_paths
            .iter()
            .any(|route_path| path == route_path)
    }

    fn mcp_resource_for_path(&self, path: &str) -> Option<String> {
        self.is_mcp_route_path(path)
            .then(|| self.mcp_resource.clone())
            .flatten()
    }

    fn mcp_resource_metadata_url_for_path(&self, path: &str) -> Option<&str> {
        self.mcp_route_paths
            .iter()
            .any(|route_path| path == route_path)
            .then_some(self.mcp_resource_metadata_url.as_deref())
            .flatten()
    }
}

pub async fn auth_middleware(
    State(state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_owned();
    if protected_resource::is_well_known_path(&path) {
        return next.run(req).await;
    }

    let is_mcp_route = state.is_mcp_route_path(&path);
    if !is_mcp_route
        && state
            .exempt_paths
            .iter()
            .any(|exempt_path| exempt_path_matches(&path, exempt_path))
    {
        return next.run(req).await;
    }

    let resource = state.mcp_resource_for_path(&path);
    let audit = audit_context(&req, path, &state.client_ip_policy);
    let Some(credential) = request_credential(&req, &state.cookie_name) else {
        return auth_failure_response(
            &state,
            &audit,
            AuthFailureKind::Rejected,
            "missing_credential",
            req,
            next,
        )
        .await;
    };

    let Some(validator) = state.validator.as_ref().map(Arc::clone) else {
        return auth_failure_response(
            &state,
            &audit,
            AuthFailureKind::Rejected,
            "no_validator_configured",
            req,
            next,
        )
        .await;
    };

    match &credential {
        SessionCredential::Cookie(_) if !validator.supports_cookie() => {
            return auth_failure_response(
                &state,
                &audit,
                AuthFailureKind::Rejected,
                "cookie_auth_unsupported",
                req,
                next,
            )
            .await;
        }
        SessionCredential::Bearer(_) if !validator.supports_bearer() => {
            return auth_failure_response(
                &state,
                &audit,
                AuthFailureKind::Rejected,
                "bearer_auth_unsupported",
                req,
                next,
            )
            .await;
        }
        SessionCredential::ClientCertificate(_) if !validator.supports_client_certificate() => {
            return auth_failure_response(
                &state,
                &audit,
                AuthFailureKind::Rejected,
                "client_certificate_auth_unsupported",
                req,
                next,
            )
            .await;
        }
        _ => {}
    }

    match validator
        .validate_session_for_resource(&credential, resource.as_deref())
        .await
    {
        Ok(principal) => {
            emit_success(&state, &audit, &credential, &principal);
            req.extensions_mut().insert(principal.clone());
            state.principal_directory.observe(&principal);
            let mut response = next.run(req).await;
            response.extensions_mut().insert(AuthOutcome {
                principal: Some(principal),
                authenticated: true,
                reason: None,
            });
            response
        }
        Err(AuthError::InvalidSession(reason)) => {
            auth_failure_response(&state, &audit, AuthFailureKind::Rejected, reason, req, next)
                .await
        }
        Err(AuthError::Upstream(reason)) => {
            let reason = format!("upstream_error: {reason}");
            auth_failure_response(
                &state,
                &audit,
                AuthFailureKind::Unverifiable,
                reason,
                req,
                next,
            )
            .await
        }
    }
}

fn audit_context(req: &Request, path: String, client_ip_policy: &ClientIpPolicy) -> AuditContext {
    AuditContext {
        request_id: request_id(req.headers(), req.extensions()),
        source_ip: canonical_client_ip(req.headers(), req.extensions(), client_ip_policy),
        user_agent: header_to_trimmed_string(req.headers().get(USER_AGENT)),
        path,
    }
}

/// The credential this request is judged on.
///
/// A credential the caller *sent* wins over the certificate their connection
/// was established with, and that order is deliberate. A caller who presents a
/// bearer token is asking to be judged as that token's subject; preferring the
/// certificate would mean an expired or revoked token silently succeeded as
/// somebody else, which is a worse surprise than a 401. The certificate is what
/// authenticates a caller who sends no other credential.
///
/// This is also the only place a client-certificate credential can come from.
/// It is read from a request extension that only the inbound TLS listener
/// writes, never from a header, so there is no header a caller can set to
/// produce one -- and the mTLS assertion headers a fronting proxy would use for
/// exactly this purpose are stripped by `crate::middleware::headers` before any
/// upstream sees them.
fn request_credential(req: &Request, cookie_name: &str) -> Option<SessionCredential> {
    extract_credential(req.headers(), cookie_name).or_else(|| {
        req.extensions()
            .get::<VerifiedClientIdentity>()
            .cloned()
            .map(SessionCredential::ClientCertificate)
    })
}

pub fn extract_credential(headers: &HeaderMap, cookie_name: &str) -> Option<SessionCredential> {
    bearer_token(headers)
        .map(|token| SessionCredential::Bearer(token.to_owned()))
        .or_else(|| {
            session_cookie(headers, cookie_name)
                .map(|cookie| SessionCredential::Cookie(cookie.to_owned()))
        })
}

fn session_cookie<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    if cookie_name.is_empty() {
        return None;
    }

    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(header_value_to_str)
        .flat_map(|value| value.split(';'))
        .filter_map(|cookie| cookie.trim().split_once('='))
        .find_map(|(name, value)| {
            let value = value.trim();
            (name.trim() == cookie_name && !value.is_empty()).then_some(value)
        })
}

fn emit_success(
    state: &AuthState,
    context: &AuditContext,
    credential: &SessionCredential,
    principal: &Principal,
) {
    state.audit.emit(with_optional_user_agent(
        AuditEvent::new(
            AUTH_SUCCESS,
            &context.request_id,
            &context.source_ip,
            Some(actor_from_principal(principal)),
            json!({
                "path": &context.path,
                "auth_mode": auth_mode(credential),
                "user_id": &principal.user_id,
            }),
        ),
        context.user_agent.as_deref(),
    ));
}

fn emit_failure(state: &AuthState, context: &AuditContext, reason: &str) {
    state.audit.emit(with_optional_user_agent(
        AuditEvent::new(
            AUTH_FAILURE,
            &context.request_id,
            &context.source_ip,
            None,
            json!({
                "path": &context.path,
                "reason": reason,
            }),
        ),
        context.user_agent.as_deref(),
    ));
}

async fn auth_failure_response(
    state: &AuthState,
    context: &AuditContext,
    kind: AuthFailureKind,
    reason: impl Into<String>,
    req: Request,
    next: Next,
) -> Response {
    let reason = reason.into();
    emit_failure(state, context, &reason);

    match (state.mode, kind) {
        (AuthMode::Required, AuthFailureKind::Rejected) => unauthorized_with_auth_outcome(
            reason,
            state.mcp_resource_metadata_url_for_path(&context.path),
        ),
        // No credential was judged, so no bearer challenge is sent: telling a
        // caller to re-authenticate would make it discard a token that may well
        // be valid and re-mint it against the identity provider that is already
        // failing. The response carries no reason and no credential-derived
        // detail, and every `AuthError::Upstream` producer raises this on a
        // dependency fault evaluated without consulting who the credential
        // belongs to, so it cannot report whether a credential exists, is
        // known, or is correctly signed.
        (AuthMode::Required, AuthFailureKind::Unverifiable) => {
            identity_unavailable_with_auth_outcome(reason)
        }
        (AuthMode::Observe, _) => forward_with_auth_outcome(req, next, reason).await,
    }
}

async fn forward_with_auth_outcome(req: Request, next: Next, reason: String) -> Response {
    let mut response = next.run(req).await;
    response.extensions_mut().insert(AuthOutcome {
        principal: None,
        authenticated: false,
        reason: Some(reason),
    });
    response
}

fn auth_mode(credential: &SessionCredential) -> &'static str {
    match credential {
        SessionCredential::Cookie(_) => "session_cookie",
        SessionCredential::Bearer(_) => "bearer_token",
        SessionCredential::ClientCertificate(_) => "client_certificate",
    }
}

fn with_optional_user_agent(event: AuditEvent, user_agent: Option<&str>) -> AuditEvent {
    match user_agent {
        Some(user_agent) => event.with_user_agent(user_agent),
        None => event,
    }
}

fn unauthorized(resource_metadata_url: Option<&str>) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(UnauthorizedBody {
            error: "unauthorized",
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, bearer_challenge(resource_metadata_url));
    response
}

/// `503` for a credential the gateway could not verify.
///
/// Deliberately not a `401`: `401` plus `WWW-Authenticate` is the wire encoding
/// of "your credential is bad, get a new one", which inverts the caller's
/// recovery path when the truth is that the identity provider is unreachable.
fn identity_unavailable() -> Response {
    let mut response = (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ServiceUnavailableBody {
            error: "service unavailable",
        }),
    )
        .into_response();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("5"));
    response
}

fn identity_unavailable_with_auth_outcome(reason: impl Into<String>) -> Response {
    let mut response = identity_unavailable();
    response.extensions_mut().insert(AuthOutcome {
        principal: None,
        authenticated: false,
        reason: Some(reason.into()),
    });
    response
}

fn unauthorized_with_auth_outcome(
    reason: impl Into<String>,
    resource_metadata_url: Option<&str>,
) -> Response {
    let mut response = unauthorized(resource_metadata_url);
    response.extensions_mut().insert(AuthOutcome {
        principal: None,
        authenticated: false,
        reason: Some(reason.into()),
    });
    response
}

fn bearer_challenge(resource_metadata_url: Option<&str>) -> HeaderValue {
    let Some(resource_metadata_url) = resource_metadata_url else {
        return HeaderValue::from_static("Bearer");
    };

    HeaderValue::from_str(&format!(
        "Bearer realm=\"mcp\", resource_metadata=\"{resource_metadata_url}\""
    ))
    .unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
}

fn header_to_trimmed_string(value: Option<&HeaderValue>) -> Option<String> {
    value
        .and_then(header_value_to_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn header_value_to_str(value: &HeaderValue) -> Option<&str> {
    value.to_str().ok()
}

#[cfg(test)]
#[path = "auth_tests.rs"]
mod tests;
