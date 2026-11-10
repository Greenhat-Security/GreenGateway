//! admin tokens boundary extracted from the application composition root.
use super::*;

pub(super) async fn token_create_endpoint(
    State(state): State<TokenAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(TOKENS_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, &principal, ADMIN_TOKENS_WRITE_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };
    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let requested = match parse_create_token_body(&body) {
        Ok(requested) => requested,
        Err(response) => return *response,
    };
    // The store bounds the serialized scope list (the PostgreSQL column's
    // check constraint); judge it here, before delegation is even
    // considered, so an oversized list is the client's error rather than a
    // store failure.
    if serde_json::to_string(&requested.scopes)
        .map(|scopes| scopes.len() > auth::tokens::MAX_SERVICE_TOKEN_SCOPES_JSON_BYTES)
        .unwrap_or(true)
    {
        return bad_request("service-token scopes exceed the maximum serialized size");
    }
    // Scopes become the token's roles at authentication, so they are held to
    // the principal role bounds when written: a token the validator would
    // refuse must not be creatable.
    if let Err(problem) = auth::principal::check_roles_shape(&requested.scopes) {
        return bad_request(&format!("service-token scopes out of bounds: {problem}"));
    }

    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return token_rbac_not_configured();
    };
    if let Err(error) = authorize_requested_scopes(rbac_state, &principal, &requested.scopes) {
        emit_service_token_delegation_rejected(
            &state,
            &parts,
            &principal,
            &requested.scopes,
            &error.disallowed,
        );
        return token_scope_authz_error_response(error);
    }

    // Issue #425: the authenticated principal is the issue's actor, recorded
    // as its evidence in the create's own transaction. `created_by` keeps
    // naming the creator on the token row as before.
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    let request = auth::tokens::CreateTokenRequest {
        scopes: requested.scopes,
        created_by: principal.user_id.clone(),
        expires_at: requested.expires_at,
    };
    let created = match store.create(request, &actor).await {
        Ok(created) => created,
        // The one request-reachable invalid input on create: a malformed
        // `expires_at` (scopes are validated before the store is called, and
        // the adapter marks exactly this parse failure with its field name).
        // Every other store failure -- including other `InvalidData` such as a
        // serialization error -- is the shared `500` path, restoring the
        // pre-#340 mapping the async-contract refactor broadened.
        Err(error) if error.invalid_parameter_name() == Some("expires_at") => {
            return bad_request("invalid service-token expires_at timestamp");
        }
        Err(error) if error.invalid_parameter_name() == Some("created_by") => {
            return bad_request("principal identifier exceeds the service-token record bound");
        }
        Err(error) => return token_store_error_response(error),
    };

    emit_service_token_changed(&state, &parts, &principal, "token_created", &created.record);

    (
        StatusCode::CREATED,
        Json(CreatedTokenAdminResponse::from_created(created)),
    )
        .into_response()
}

pub(super) async fn token_list_endpoint(
    State(state): State<TokenAdminState>,
    Query(params): Query<TokenListParams>,
    request: AxumRequest,
) -> Response {
    record_request(TOKENS_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, principal, ADMIN_TOKENS_READ_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };
    let filters = match params.into_filters() {
        Ok(filters) => filters,
        Err(parameter) => return bad_request(&format!("invalid query parameter: {parameter}")),
    };

    match store.list(&filters).await {
        Ok(page) => (StatusCode::OK, Json(page)).into_response(),
        Err(error) => token_store_error_response(error),
    }
}

pub(super) async fn token_get_endpoint(
    State(state): State<TokenAdminState>,
    Path(token_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(TOKEN_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, principal, ADMIN_TOKENS_READ_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };

    match store.get_by_id(&token_id).await {
        Ok(Some(record)) => (StatusCode::OK, Json(record)).into_response(),
        Ok(None) => not_found("service token was not found"),
        Err(error) => token_store_error_response(error),
    }
}

pub(super) async fn token_revoke_endpoint(
    State(state): State<TokenAdminState>,
    Path(token_id): Path<String>,
    request: AxumRequest,
) -> Response {
    let keyed = request.method() == Method::POST;
    record_request(if keyed {
        TOKEN_KEYED_REVOKE_ADMIN_ROUTE
    } else {
        TOKEN_ADMIN_ROUTE
    });

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, &principal, ADMIN_TOKENS_WRITE_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };

    // The revoking principal -- subject, issuer, kind and auth mode -- is
    // recorded as the change's evidence in the revoke's own transaction; the
    // audit event below stays post-commit telemetry.
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    let (result, operation_id) = if keyed {
        if !actor.can_bind_operation() {
            return forbidden();
        }
        let mut keys = parts.headers.get_all("idempotency-key").iter();
        let key = keys.next().and_then(|value| value.to_str().ok());
        let Some(operation_id) = key.and_then(|raw| {
            uuid::Uuid::parse_str(raw).ok().filter(|id| {
                auth::tokens::valid_revoke_operation_id(*id) && id.hyphenated().to_string() == raw
            })
        }) else {
            return bad_request("Idempotency-Key must be one canonical lowercase UUIDv7");
        };
        if keys.next().is_some() {
            return bad_request("Idempotency-Key must occur exactly once");
        }
        if parts.uri.query().is_some()
            || parts
                .headers
                .keys()
                .any(|name| name.as_str().starts_with("if-"))
        {
            return bad_request(
                "keyed service-token revocation accepts no query or conditional headers",
            );
        }
        match tokio::time::timeout(Duration::from_secs(5), axum::body::to_bytes(body, 0)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {
                return bad_request("keyed service-token revocation requires an empty body")
            }
            Err(_) => {
                return (
                    StatusCode::REQUEST_TIMEOUT,
                    Json(json!({"error": "revocation request timed out"})),
                )
                    .into_response()
            }
        }
        (
            store
                .revoke_with_operation(&token_id, &actor, Some(operation_id))
                .await,
            Some(operation_id),
        )
    } else {
        (store.revoke(&token_id, &actor).await, None)
    };
    match result {
        Ok(Some(record)) => {
            if let Some(validator) = state.validator.as_ref() {
                validator.invalidate_token_id(&token_id);
            }
            emit_service_token_changed(&state, &parts, &principal, "token_revoked", &record);
            if let Some(operation_id) = operation_id {
                return Json(json!({
                    "operation_id": operation_id.to_string(),
                    "token_id": record.id,
                    "revoked_at": record.revoked_at
                }))
                .into_response();
            }
            (StatusCode::OK, Json(record)).into_response()
        }
        Ok(None) => not_found("service token was not found"),
        Err(error)
            if keyed
                && error.kind() == storage::RepositoryErrorKind::Conflict
                && error.operation() == auth::tokens::REVOKE_OPERATION_BINDING =>
        {
            conflict("revocation conflicts with an already committed operation")
        }
        Err(error) => token_store_error_response(error),
    }
}

pub(super) async fn token_rotate_endpoint(
    State(state): State<TokenAdminState>,
    Path(token_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(TOKEN_ROTATE_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, &principal, ADMIN_TOKENS_WRITE_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };

    let record = match store.get_by_id(&token_id).await {
        Ok(Some(record)) => record,
        Ok(None) => return not_found("service token was not found"),
        Err(error) => return token_store_error_response(error),
    };
    // Scopes are immutable through rotation, so a record outside the principal
    // bounds -- written before the bound existed, or around the admin API --
    // would be re-minted into a credential the validator refuses on first use.
    // Refuse the rotation instead: the token is unusable as stored, and the
    // remedy is to revoke it and create a new one.
    if let Err(problem) = auth::principal::check_roles_shape(&record.scopes) {
        return conflict(&format!(
            "cannot rotate service token whose scopes are out of bounds: {problem}; revoke it and create a new token"
        ));
    }
    let Some(rbac_state) = state.rbac_state.as_ref() else {
        return token_rbac_not_configured();
    };
    // Rotation returns a new credential carrying the existing scopes, so it
    // requires the same delegation authority as creation. Scopes are immutable
    // through the token store contract; each store still checks revocation
    // when rotating.
    if let Err(error) = authorize_requested_scopes(rbac_state, &principal, &record.scopes) {
        emit_service_token_delegation_rejected(
            &state,
            &parts,
            &principal,
            &record.scopes,
            &error.disallowed,
        );
        return token_scope_authz_error_response(error);
    }

    // As with revoke: the rotating principal is the change's evidence,
    // committed with the rotation or not at all.
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    match store.rotate(&token_id, &actor).await {
        Ok(Some(created)) => {
            if let Some(validator) = state.validator.as_ref() {
                validator.invalidate_token_id(&token_id);
            }
            emit_service_token_changed(
                &state,
                &parts,
                &principal,
                "token_rotated",
                &created.record,
            );
            (
                StatusCode::OK,
                Json(CreatedTokenAdminResponse::from_created(created)),
            )
                .into_response()
        }
        Ok(None) => not_found("service token was not found"),
        // The revoked-token rejection is the only conflict this store's
        // rotate path produces (the adapter maps `RevokedToken` to exactly
        // this kind, and the statement it guards updates no unique column),
        // so the `409` here means "cannot rotate a revoked token" and nothing
        // else; conflicts from every other operation stay on the shared
        // responder's `500` path.
        Err(error) if error.kind() == storage::RepositoryErrorKind::Conflict => {
            conflict("cannot rotate revoked service token")
        }
        Err(error) => token_store_error_response(error),
    }
}
