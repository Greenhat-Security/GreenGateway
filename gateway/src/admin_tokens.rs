//! admin tokens boundary extracted from the application composition root.
use super::*;

pub(super) async fn token_create_endpoint(
    State(state): State<TokenAdminState>,
    request: AxumRequest,
) -> Response {
    let pins = request.extensions().clone();
    token_change_to_completion(pins, Box::pin(token_create(state, request))).await
}

/// Runs a service-token issue or rotation on a task of its own, so it
/// finishes whether or not anyone is still waiting for the response (issue
/// #425), as `admin_connections` runs a Connection change. axum drops a
/// handler's future when the client disconnects, while a store call already
/// under way still commits: the SQLite transaction runs on the blocking pool,
/// and a PostgreSQL `COMMIT` already sent completes. Dropped there, an issue
/// or rotation would be committed but never audited, and a rotation would
/// never drop the replaced plaintext from this process's validator cache --
/// while a keyed retry is answered from the receipt of the committed change
/// and repeats no audit event. The request's pinned snapshots are re-entered
/// on the task and its span carried over. A panic is resumed here, as if the
/// handler had panicked itself. The change arrives boxed: a handler's state
/// machine is large, and moving it by value through the spawn would grow
/// every stack it passes through.
async fn token_change_to_completion(
    pins: http::Extensions,
    change: std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>,
) -> Response {
    use tracing::Instrument as _;

    let task = tokio::spawn(
        async move { crate::middleware::rbac::with_request_pins(Some(&pins), change).await }
            .instrument(tracing::Span::current()),
    );
    match task.await {
        Ok(response) => response,
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(error) => {
            tracing::error!(error = %error, "a service-token change task was cancelled");
            service_unavailable("service-token state is unavailable")
        }
    }
}

async fn token_create(state: TokenAdminState, request: AxumRequest) -> Response {
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
    // The rest of the request is validated here too, before the gates
    // below: admitting a keyed request in cluster mode can raise the
    // durable contract fence, so a request the store would refuse as
    // malformed must be answered before it is admitted ("Keyed authority
    // changes" in docs/authority-evidence.md). The store checks both again.
    if auth::tokens::validate_optional_timestamp(requested.expires_at.as_deref(), "expires_at")
        .is_err()
    {
        return bad_request("invalid service-token expires_at timestamp");
    }
    if principal.user_id.len() > auth::tokens::MAX_SERVICE_TOKEN_CREATED_BY_BYTES {
        return bad_request("principal identifier exceeds the service-token record bound");
    }

    // Issue #425: the authenticated principal is the issue's actor, recorded
    // as its evidence in the create's own transaction. `created_by` keeps
    // naming the creator on the token row as before.
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    // Authorized and validated: bind the caller key to what the token will
    // be (its scopes and expiry; an issue has no target), ask the gates, and
    // answer an exact retry from its receipt (issue #425).
    let bound_request = match canonical_token_request(&requested) {
        Ok(bound) => bound,
        Err(response) => return *response,
    };
    let caller = match admit_keyed_token_change(
        &state,
        store.as_ref(),
        &parts,
        &principal,
        &actor,
        KeyedTokenChange::Issue,
        "",
        &bound_request,
    )
    .await
    {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    let request = auth::tokens::CreateTokenRequest {
        scopes: requested.scopes,
        created_by: principal.user_id.clone(),
        expires_at: requested.expires_at,
    };
    let created = match store
        .create_with_operation(request, &actor, caller.as_ref())
        .await
    {
        Ok(authority_events::caller_operation::CallerOutcome::Committed(created)) => created,
        // An exact retry: no second token, no audit event, and never the
        // plaintext, which only the first response carried.
        Ok(authority_events::caller_operation::CallerOutcome::Replayed(receipt)) => {
            return token_operation_receipt(&receipt)
        }
        Err(error) if is_caller_operation_conflict(&error) => return caller_operation_conflict(),
        // The backstop for the two inputs judged above, before the gates: a
        // malformed `expires_at` (the adapter marks exactly this parse
        // failure with its field name) and an oversized creator.
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
        let operation_id = match caller_operation_id(&parts.headers) {
            Ok(id) => id,
            Err(reason) => return bad_request(reason),
        };
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
    let pins = request.extensions().clone();
    token_change_to_completion(pins, Box::pin(token_rotate(state, token_id, request))).await
}

async fn token_rotate(state: TokenAdminState, token_id: String, request: AxumRequest) -> Response {
    record_request(TOKEN_ROTATE_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let store = match authorized_token_store(&state, &principal, ADMIN_TOKENS_WRITE_PERMISSION) {
        Ok(store) => store,
        Err(error) => return token_admin_authz_error_response(error),
    };
    // As with revoke: the rotating principal is the change's evidence,
    // committed with the rotation or not at all.
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    // Required mode refuses a form of the rotation it does not admit before
    // anything is read (I4), so the evidence gate is asked before the token
    // is read for the delegation check below. It reads configuration only
    // and cannot raise the contract fence, so it may come before that
    // check; the operation gate, which can, is asked only after it, by
    // `admit_keyed_token_change`, which asks this gate again.
    if let Err(response) = admit_authority_change_for(
        &state.authority_evidence,
        KeyedTokenChange::Rotate.operation(),
        authority_events::required::RequestForm::of(
            parts.headers.contains_key("idempotency-key"),
            &actor,
        ),
        &state.audit,
        &parts,
        &principal,
        &state.client_ip_policy,
    ) {
        return *response;
    }

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

    // Authorized: bind the caller key to the token it rotates (a rotation
    // has no body), ask the gates, and answer an exact retry from its
    // receipt (issue #425).
    let caller = match admit_keyed_token_change(
        &state,
        store.as_ref(),
        &parts,
        &principal,
        &actor,
        KeyedTokenChange::Rotate,
        &token_id,
        &[],
    )
    .await
    {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    match store
        .rotate_with_operation(&token_id, &actor, caller.as_ref())
        .await
    {
        // An exact retry: no second rotation, no audit event, and never a
        // plaintext. The replaced plaintext is still dropped from this
        // process's validator cache, which is idempotent and reads nothing:
        // a first attempt that committed without finishing its handler, or
        // that another process sharing the token file committed, may have
        // left it cached here.
        Ok(Some(authority_events::caller_operation::CallerOutcome::Replayed(receipt))) => {
            if let Some(validator) = state.validator.as_ref() {
                validator.invalidate_token_id(&token_id);
            }
            token_operation_receipt(&receipt)
        }
        Ok(Some(authority_events::caller_operation::CallerOutcome::Committed(created))) => {
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
        Err(error) if is_caller_operation_conflict(&error) => caller_operation_conflict(),
        // Apart from a caller key bound to another request (above), the
        // revoked-token rejection is the only conflict this store's rotate
        // path produces (the adapter maps `RevokedToken` to exactly this
        // kind, and the statement it guards updates no unique column), so
        // the `409` here means "cannot rotate a revoked token" and nothing
        // else; conflicts from every other operation stay on the shared
        // responder's `500` path.
        Err(error) if error.kind() == storage::RepositoryErrorKind::Conflict => {
            conflict("cannot rotate revoked service token")
        }
        Err(error) => token_store_error_response(error),
    }
}

/// A service-token change that binds a caller key (issue #425). Revocation
/// keeps its own keyed route and replay check (issue #765).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyedTokenChange {
    Issue,
    Rotate,
}

impl KeyedTokenChange {
    /// The operation the evidence gate is asked about. Its code is the action
    /// the caller key is bound to and the evidence row records, so the key
    /// and the gate always name the same change.
    pub(super) const fn operation(self) -> authority_events::required::AuthorityOperation {
        match self {
            Self::Issue => authority_events::required::AuthorityOperation::ServiceTokenIssue,
            Self::Rotate => authority_events::required::AuthorityOperation::ServiceTokenRotate,
        }
    }
}

/// The request an issue's caller key is bound to: what the token will be,
/// its scopes in the order given and its expiry as given, as canonical JSON.
/// The body is parsed with unknown fields refused, so this is the body
/// whatever its whitespace or key order. It holds no secret: the plaintext
/// does not exist until the store mints it.
pub(super) fn canonical_token_request(
    requested: &CreateTokenAdminRequest,
) -> ResponseResult<Vec<u8>> {
    #[derive(Serialize)]
    struct Bound<'a> {
        expires_at: Option<&'a str>,
        scopes: &'a [String],
    }
    serde_json::to_vec(&Bound {
        expires_at: requested.expires_at.as_deref(),
        scopes: &requested.scopes,
    })
    .map_err(|error| {
        tracing::error!(error = %error, "a token request could not be encoded for its caller key");
        Box::new(internal_server_error(
            "the caller operation could not be bound",
        ))
    })
}

/// Bind a service-token issue's or rotation's caller key and admit it (issue
/// #425). Called once the handler has authorized the caller and validated
/// the request, and before the store is asked to change anything: the key
/// is bound to the action, the recorded actor, the token ID (empty for an
/// issue), no precondition (these routes take none) and the canonical
/// request; the evidence gate and, for a keyed request in cluster mode, the
/// operation gate are asked; and an exact retry of a committed change is
/// answered with its receipt, a key bound to anything else with `409`.
/// `Ok(None)` is an unkeyed request the gates admitted; `Ok(Some(_))` a keyed
/// one whose key is unused.
#[allow(clippy::too_many_arguments)]
pub(super) async fn admit_keyed_token_change(
    state: &TokenAdminState,
    store: &dyn storage::ServiceTokenStore,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    actor: &auth::change_actor::ChangeActor,
    change: KeyedTokenChange,
    target: &str,
    request: &[u8],
) -> ResponseResult<Option<authority_events::caller_operation::CallerOperation>> {
    let caller = caller_operation(
        &parts.headers,
        actor,
        change.operation().code(),
        target,
        "",
        request,
    )?;
    let gates = KeyedChangeGates {
        evidence: &state.authority_evidence,
        #[cfg(feature = "postgres")]
        membership: state.membership.as_deref(),
        audit: &state.audit,
        client_ip_policy: &state.client_ip_policy,
    };
    admit_keyed_authority_change(
        &gates,
        KeyedChange::Gated(change.operation()),
        caller.as_ref(),
        actor,
        parts,
        principal,
    )
    .await?;
    if let Some(caller) = &caller {
        // An exact retry of a rotation drops the replaced plaintext from
        // this process's validator cache, as the store's own replay does in
        // `token_rotate`.
        let on_replay = || {
            if change == KeyedTokenChange::Rotate {
                if let Some(validator) = state.validator.as_ref() {
                    validator.invalidate_token_id(target);
                }
            }
        };
        replayed_token_receipt(
            store.caller_operation_state(caller),
            store.caller_operation_receipt(caller),
            on_replay,
        )
        .await?;
    }
    Ok(caller)
}

/// The read-only pre-check of a keyed issue or rotation (step 0 of the keyed
/// contract), answered as `admin_responses::replayed_receipt` answers it but
/// with the token receipt: `Ok(())` for an unused key; the receipt (`200`)
/// for the same action and binding, `409` for a key bound to anything else,
/// and `503` when either read fails or a reservation has no evidence row.
/// `on_replay` runs once, just before an exact retry is answered.
async fn replayed_token_receipt(
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
    on_replay: impl FnOnce(),
) -> ResponseResult<()> {
    use authority_events::caller_operation::CallerKeyState;

    let unavailable = |error: Option<storage::RepositoryError>| {
        match error {
            Some(error) => {
                tracing::error!(error = %error, "a service-token caller operation could not be read")
            }
            None => tracing::error!(
                "a service-token caller operation is reserved without its evidence row; the request is refused"
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
                Some(receipt) => {
                    on_replay();
                    Err(Box::new(token_operation_receipt(&receipt)))
                }
                None => Err(unavailable(None)),
            }
        }
    }
}

/// An exact retry of a keyed issue or rotation: `200`, `Cache-Control:
/// no-store`, the receipt read from the committed evidence row --
/// `{operation_id, operation, resource_id, revision, committed_at}`, where
/// `resource_id` is the token ID -- and `secret_returned: false`. The
/// plaintext was returned once, by the first response, and is never stored,
/// so a retry cannot carry it. A caller whose first response was lost holds
/// a live token whose secret it never received: it revokes that token by the
/// ID in the receipt and issues again with a new key.
pub(super) fn token_operation_receipt(
    receipt: &authority_events::caller_operation::OperationReceipt,
) -> Response {
    #[derive(Serialize)]
    struct TokenReceipt<'a> {
        #[serde(flatten)]
        receipt: &'a authority_events::caller_operation::OperationReceipt,
        secret_returned: bool,
    }
    (
        StatusCode::OK,
        [(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(TokenReceipt {
            receipt,
            secret_returned: false,
        }),
    )
        .into_response()
}

/// Whether a store error is a keyed issue's or rotation's caller key bound
/// to another request.
fn is_caller_operation_conflict(error: &storage::RepositoryError) -> bool {
    error.kind() == storage::RepositoryErrorKind::Conflict
        && error.operation() == auth::tokens::CALLER_OPERATION_BINDING
}
