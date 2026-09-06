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

    let created = match store
        .create(auth::tokens::CreateTokenRequest {
            scopes: requested.scopes,
            created_by: principal.user_id.clone(),
            expires_at: requested.expires_at,
        })
        .await
    {
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
    record_request(TOKEN_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, &principal, ADMIN_TOKENS_WRITE_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };

    match store.revoke(&token_id).await {
        Ok(Some(record)) => {
            if let Some(validator) = state.validator.as_ref() {
                validator.invalidate_token_id(&token_id);
            }
            emit_service_token_changed(&state, &parts, &principal, "token_revoked", &record);
            (StatusCode::OK, Json(record)).into_response()
        }
        Ok(None) => not_found("service token was not found"),
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

    match store.rotate(&token_id).await {
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
