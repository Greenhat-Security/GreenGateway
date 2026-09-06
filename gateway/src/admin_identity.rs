//! admin identity boundary extracted from the application composition root.
use super::*;

pub(super) async fn admin_auth_login_endpoint(
    State(state): State<AdminAuthState>,
    request: AxumRequest,
) -> Response {
    record_request(ADMIN_AUTH_LOGIN_ROUTE);
    let (parts, _) = request.into_parts();
    let source_ip =
        client_ip::canonical_client_ip(&parts.headers, &parts.extensions, &state.client_ip_policy);

    match state.login.begin_login(&source_ip).await {
        Ok(start) => {
            state.record(&parts, "start", "accepted", "transaction_created");
            let mut response = found_redirect(start.authorization_url);
            state.set_browser_cookie(&mut response, &start.browser_binding, state.cookie_max_age);
            response
        }
        Err(err) if err.is_store_unavailable() => {
            state.record(&parts, "start", "unavailable", "store_unavailable");
            tracing::error!(error = %err, "admin OIDC login state store is unavailable");
            service_unavailable("login state store is unavailable")
        }
        Err(err) => {
            state.record(&parts, "start", "denied", "login_start_failed");
            tracing::warn!(error = %err, "failed to start admin OIDC login");
            found_redirect(admin_auth_error_url(
                &state.admin_prefix,
                "login_start_failed",
            ))
        }
    }
}

pub(super) async fn admin_auth_callback_endpoint(
    State(state): State<AdminAuthState>,
    Query(params): Query<AdminAuthCallbackParams>,
    parts: http::request::Parts,
) -> Response {
    record_request(ADMIN_AUTH_CALLBACK_ROUTE);

    if params.error.is_some() {
        state.record(&parts, "callback", "denied", "provider_error");
        return found_redirect(admin_auth_error_url(&state.admin_prefix, "provider_error"));
    }

    let Some(code) = params
        .code
        .as_deref()
        .map(str::trim)
        .filter(|code| !code.is_empty())
    else {
        state.record(&parts, "callback", "denied", "missing_code");
        return found_redirect(admin_auth_error_url(&state.admin_prefix, "missing_code"));
    };
    let Some(oauth_state) = params
        .state
        .as_deref()
        .map(str::trim)
        .filter(|state| !state.is_empty())
    else {
        state.record(&parts, "callback", "denied", "invalid_state");
        return found_redirect(admin_auth_error_url(&state.admin_prefix, "invalid_state"));
    };

    let binding = state.browser_binding(&parts.headers).unwrap_or_default();
    if !auth::OidcLoginState::browser_binding_matches(oauth_state, &binding) {
        state.record(&parts, "callback", "denied", "browser_binding_mismatch");
        tracing::warn!(
            reason = "browser_binding_mismatch",
            "admin OIDC callback rejected"
        );
        return found_redirect(admin_auth_error_url(&state.admin_prefix, "invalid_state"));
    }

    // The fragment contains only a PKCE-protected authorization code and
    // state. The browser must POST them with its HttpOnly binding cookie;
    // only that exchange consumes the pending login and returns a token.
    state.record(&parts, "callback", "accepted", "browser_bound");
    found_redirect(admin_auth_complete_url(
        &state.admin_prefix,
        code,
        oauth_state,
    ))
}

pub(super) async fn admin_auth_completion_endpoint(
    State(state): State<AdminAuthState>,
    parts: http::request::Parts,
    Json(params): Json<AdminAuthCompletionParams>,
) -> Response {
    record_request(ADMIN_AUTH_CALLBACK_ROUTE);
    let origin = state.login.redirect_origin();
    if origin.is_empty()
        || parts
            .headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            != Some(origin.as_str())
    {
        state.record(&parts, "completion", "denied", "origin_mismatch");
        tracing::warn!(reason = "origin_mismatch", "admin OIDC completion rejected");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "invalid_origin"})),
        )
            .into_response();
    }
    let binding = state.browser_binding(&parts.headers).unwrap_or_default();
    if params.code.trim().is_empty()
        || params.code.len() > 8192
        || !auth::OidcLoginState::browser_binding_matches(&params.state, &binding)
    {
        state.record(&parts, "completion", "denied", "browser_binding_mismatch");
        tracing::warn!(
            reason = "browser_binding_mismatch",
            "admin OIDC completion rejected"
        );
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_state"})),
        )
            .into_response();
    }

    let mut response = match state
        .login
        .exchange_code(&params.code, &params.state, &binding)
        .await
    {
        Ok(exchange) => {
            state.record(&parts, "completion", "accepted", "token_exchanged");
            tracing::info!(outcome = "success", "admin OIDC completion exchanged");
            Json(json!({"access_token": exchange.access_token})).into_response()
        }
        // A store that cannot be consulted is a dependency failure: 503,
        // never "unknown state" -- "cannot check" is not "checked and
        // denied", and no code is exchanged at the IdP.
        Err(err) if err.is_store_unavailable() => {
            state.record(&parts, "completion", "unavailable", "store_unavailable");
            tracing::error!(error = %err, "admin OIDC login state store is unavailable");
            return service_unavailable("login state store is unavailable");
        }
        Err(err) if err.is_invalid_state() => {
            state.record(&parts, "completion", "denied", "invalid_state");
            tracing::warn!("admin OIDC callback rejected unknown or expired state");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_state"})),
            )
                .into_response()
        }
        Err(err) => {
            state.record(&parts, "completion", "denied", "token_exchange_failed");
            tracing::warn!(error = %err, "admin OIDC token exchange failed");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "token_exchange_failed"})),
            )
                .into_response()
        }
    };
    state.set_browser_cookie(&mut response, "", 0);
    response
}

pub(super) fn found_redirect(location: String) -> Response {
    match HeaderValue::from_str(&location) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "failed to build redirect Location header");
            internal_server_error("redirect location was invalid")
        }
    }
}

pub(super) fn admin_auth_complete_url(admin_prefix: &str, code: &str, state: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer
        .append_pair("code", code)
        .append_pair("state", state);
    format!(
        "{}/#/auth/complete?{}",
        admin_prefix.trim_end_matches('/'),
        serializer.finish()
    )
}

pub(super) fn admin_auth_error_url(admin_prefix: &str, error: &str) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("error", error);
    format!(
        "{}/#/auth/error?{}",
        admin_prefix.trim_end_matches('/'),
        serializer.finish()
    )
}

pub(super) async fn admin_capabilities_endpoint(
    State(state): State<StatusAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(ADMIN_CAPABILITIES_ROUTE);
    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    let Some(rbac) = state.rbac_state.as_ref() else {
        return service_unavailable("policy state unavailable");
    };
    let permissions: Vec<&str> = [
        ADMIN_AUDIT_READ_PERMISSION,
        ADMIN_AUDIT_STREAM_PERMISSION,
        ADMIN_STATUS_READ_PERMISSION,
        ADMIN_CLUSTER_READ_PERMISSION,
        ADMIN_POLICY_READ_PERMISSION,
        ADMIN_POLICY_WRITE_PERMISSION,
        ADMIN_TOKENS_READ_PERMISSION,
        ADMIN_TOKENS_WRITE_PERMISSION,
        ADMIN_CONNECTIONS_READ_PERMISSION,
        ADMIN_CONNECTIONS_WRITE_PERMISSION,
        ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
        ADMIN_CONNECTIONS_TEST_PERMISSION,
        ADMIN_CONNECTIONS_REFRESH_PERMISSION,
        ADMIN_TOOLS_READ_PERMISSION,
        ADMIN_TOOLS_WRITE_PERMISSION,
        ADMIN_TOOLS_EXECUTE_PERMISSION,
        ADMIN_SCHEMA_READ_PERMISSION,
        ADMIN_SIGNALS_READ_PERMISSION,
        ADMIN_SIGNALS_WRITE_PERMISSION,
        ADMIN_SUGGESTIONS_READ_PERMISSION,
        ADMIN_SUGGESTIONS_WRITE_PERMISSION,
        ADMIN_TRAFFIC_READ_PERMISSION,
        ADMIN_TRAFFIC_WRITE_PERMISSION,
        ADMIN_PRINCIPALS_READ_PERMISSION,
    ]
    .into_iter()
    .filter(|permission| rbac.principal_has_permission(&principal, permission))
    .collect();
    let mut response = Json(json!({ "permissions": permissions })).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub(super) async fn admin_decision_audit_middleware(
    State((audit, ip_policy)): State<(audit::AuditLog, client_ip::ClientIpPolicy)>,
    request: AxumRequest,
    next: axum::middleware::Next,
) -> Response {
    let principal = request.extensions().get::<auth::Principal>().cloned();
    let request_id = client_ip::request_id(request.headers(), request.extensions());
    let source_ip =
        client_ip::canonical_client_ip(request.headers(), request.extensions(), &ip_policy);
    let method = request.method().clone();
    // MatchedPath is a bounded route template, never a raw URL/query.
    let path = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|path| path.as_str().to_owned())
        .unwrap_or_else(|| "admin".to_owned());
    let response = next.run(request).await;
    if let Some(decision) = response
        .extensions()
        .get::<middleware::decision::PolicyDecision>()
    {
        if decision.outcome == middleware::decision::PolicyDecisionOutcome::Denied
            && decision.permission.is_some()
        {
            audit.emit(audit::AuditEvent::new(
                "authz.denied",
                request_id,
                source_ip,
                principal.as_ref().map(auth::actor_from_principal),
                json!({
                    "path": path, "method": method.as_str(),
                    "reason": decision.reason, "permission": decision.permission,
                    "authorization_layer": "admin_endpoint",
                }),
            ));
        }
    }
    response
}

pub(super) fn admin_permission_denied_response(permission: String) -> Response {
    let mut response = forbidden();
    if let Some(decision) = response
        .extensions_mut()
        .get_mut::<middleware::decision::PolicyDecision>()
    {
        decision.permission = Some(permission);
        decision.reason = "missing_permission";
    }
    response
}

pub(super) async fn status_endpoint(
    State(state): State<StatusAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(STATUS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };

    if let Err(error) = authorized_status_state(&state, &principal, ADMIN_STATUS_READ_PERMISSION) {
        return status_admin_authz_error_response(error);
    }

    Json(StatusResponse::from_state(&state).await).into_response()
}

/// `GET /v1{ADMIN_PREFIX}/cluster` (issue #241, PR 14).
pub(super) async fn cluster_endpoint(
    State(state): State<ClusterAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(CLUSTER_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) = authorized_cluster_state(&state, &principal) {
        return cluster_admin_authz_error_response(error);
    }

    let (local, readout) = state.read_facts().await;
    Json(cluster_status::cluster_status(&local, &readout)).into_response()
}

/// `GET /v1{ADMIN_PREFIX}/cluster/replicas` (issue #241, PR 14).
pub(super) async fn cluster_replicas_endpoint(
    State(state): State<ClusterAdminState>,
    principal: Option<Extension<auth::Principal>>,
) -> Response {
    record_request(CLUSTER_REPLICAS_ADMIN_ROUTE);

    let Some(Extension(principal)) = principal else {
        return unauthorized();
    };
    if let Err(error) = authorized_cluster_state(&state, &principal) {
        return cluster_admin_authz_error_response(error);
    }

    let (local, readout) = state.read_facts().await;
    Json(cluster_status::cluster_replicas(&local, &readout)).into_response()
}

/// The migration-manifest range this binary serves on. A build without
/// the PostgreSQL client carries no manifest, and reports the empty range
/// it can honestly claim.
pub(super) fn schema_version_range_for_status() -> (i32, i32) {
    #[cfg(feature = "postgres")]
    {
        storage::migrations::schema_version_range()
    }
    #[cfg(not(feature = "postgres"))]
    {
        (0, 0)
    }
}

/// The policy/tools document major range this binary enforces, which is
/// the same constant the membership registration advertises.
pub(super) fn document_version_range_for_status() -> (i32, i32) {
    #[cfg(feature = "postgres")]
    {
        cluster_membership::DOCUMENT_VERSION_RANGE
    }
    #[cfg(not(feature = "postgres"))]
    {
        (0, 0)
    }
}

/// This process's hostname, for `local.hostname` when
/// `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`.
///
/// Read from the environment rather than through a syscall crate because
/// the deployments this field exists for already publish it there: a
/// Kubernetes pod and a Docker container both get `HOSTNAME` set to the
/// name the operator is trying to match a roster UUID against, which is
/// more useful than whatever `gethostname(2)` would return inside the
/// container anyway. `COMPUTERNAME` is the Windows spelling. Neither set
/// means no hostname is reported, which is the same answer as the flag
/// being off -- this never guesses.
///
/// Called once at startup; the value is then stored on the state, so a
/// status request performs no environment read of its own.
pub(super) fn local_hostname() -> Option<String> {
    ["HOSTNAME", "COMPUTERNAME"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|value| !value.trim().is_empty())
}

/// The cluster status API's one authorization check, applied identically
/// on both routes: the same shape `admin:audit:read` is enforced with.
pub(super) fn authorized_cluster_state<'a>(
    state: &'a ClusterAdminState,
    principal: &auth::Principal,
) -> Result<&'a middleware::rbac::RbacState, AdminReadAuthzError> {
    authorized_admin_rbac_state(
        state.rbac_state.as_ref(),
        principal,
        ADMIN_CLUSTER_READ_PERMISSION,
    )
}
