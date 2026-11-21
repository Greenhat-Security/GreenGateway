//! admin connections boundary extracted from the application composition root.
use super::*;

pub(super) async fn connection_secret_list_endpoint(
    State(state): State<ConnectionAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_SECRETS_ADMIN_ROUTE);

    let (parts, _body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_connection_state(
        &state,
        &principal,
        ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
    ) {
        return match error {
            ConnectionAdminAuthzError::Forbidden(_) => connection_permission_forbidden(
                &state,
                &parts,
                &principal,
                CONNECTION_SECRETS_ADMIN_ROUTE,
                ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
                "list",
            ),
            error => connection_admin_authz_error_response(error),
        };
    }

    let metadata = state.control_plane.secret_alias_metadata();
    let dependency_counts =
        connection_secret_dependency_counts(&state.control_plane.runtime_snapshot());
    let local_encrypted = state.control_plane.is_local_secret_manager_configured();
    let operator_aliases = metadata
        .iter()
        .any(|item| item.provider != connections::secret::SecretProviderKind::LocalEncrypted);
    let collection_etag = connections::admin::secret_collection_etag(&metadata);
    let secrets = metadata
        .iter()
        .cloned()
        .map(|item| {
            let dependency_count = dependency_counts
                .get(item.id.as_str())
                .copied()
                .unwrap_or_default();
            connections::admin::SafeSecretAliasView::from_metadata(item, true, dependency_count)
        })
        .collect();
    let response_body = connections::admin::SecretAliasListResponse {
        secrets,
        actions: connections::admin::SecretCollectionActions {
            can_create: local_encrypted,
        },
        providers: connections::admin::SecretProviderAvailability {
            operator_aliases,
            local_encrypted,
        },
    };
    let response_etag = match serialized_response_etag(&response_body) {
        Ok(etag) => etag,
        Err(error) => {
            tracing::error!(error = %error, "failed to hash connection-secret list response");
            return internal_server_error("connection-secret list response could not be encoded");
        }
    };
    (
        StatusCode::OK,
        [
            (header::ETAG, etag_header_value(&response_etag)),
            (
                HeaderName::from_static(CONNECTION_SECRET_COLLECTION_ETAG_HEADER),
                etag_header_value(&collection_etag),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(response_body),
    )
        .into_response()
}

pub(super) async fn connection_secret_create_endpoint(
    State(state): State<ConnectionAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_SECRETS_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_connection_state(
        &state,
        &principal,
        ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
    ) {
        return match error {
            ConnectionAdminAuthzError::Forbidden(_) => connection_permission_forbidden(
                &state,
                &parts,
                &principal,
                CONNECTION_SECRETS_ADMIN_ROUTE,
                ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
                "create",
            ),
            error => connection_admin_authz_error_response(error),
        };
    }

    let current_metadata = state.control_plane.secret_alias_metadata();
    let current_collection_etag = connections::admin::secret_collection_etag(&current_metadata);
    match if_match_matches(&parts.headers, &current_collection_etag) {
        Ok(true) => {}
        Ok(false) => {
            return with_connection_secret_collection_etag(
                precondition_failed(
                    "If-Match does not match the current connection-secret collection ETag",
                ),
                &current_collection_etag,
            );
        }
        Err(error) => {
            return with_connection_secret_collection_etag(
                if_match_error_response(error),
                &current_collection_etag,
            );
        }
    }
    if !state.control_plane.is_local_secret_manager_configured() {
        return connection_secret_store_not_configured();
    }

    let body =
        match read_connection_secret_body(body, connection_secret_admin_body_limit(&state)).await {
            Ok(body) => body,
            Err(response) => return *response,
        };
    let ConnectionSecretCreateRequest {
        label,
        purpose,
        mut value,
    } = match serde_json::from_slice::<ConnectionSecretCreateRequest>(&body) {
        Ok(requested) => requested,
        Err(_) => return bad_request("invalid connection-secret JSON"),
    };
    drop(body);
    let secret_value = std::mem::take(&mut *value).into_bytes();
    let secret = match connections::secret::ResolvedSecret::new(purpose, secret_value) {
        Ok(secret) => secret,
        Err(_) => return connection_secret_validation_error(),
    };
    // The precondition lock, the collection re-check, and the encrypted
    // SQLite write run together on the blocking pool: the guard never spans
    // an await, and the write never sits on the request executor.
    let created = {
        let lock = Arc::clone(&state.secret_precondition_lock);
        let control_plane = state.control_plane.clone();
        let current_collection_etag = current_collection_etag.clone();
        let actor = auth::change_actor::ChangeActor::from_principal(&principal);
        match tokio::task::spawn_blocking(move || -> ResponseResult<_> {
            let mutation_guard = match lock_connection_secret_mutations(&lock) {
                Ok(guard) => guard,
                Err(response) => return Err(response),
            };
            let locked_metadata = control_plane.secret_alias_metadata();
            let locked_collection_etag =
                connections::admin::secret_collection_etag(&locked_metadata);
            if locked_collection_etag != current_collection_etag {
                drop(mutation_guard);
                return Err(Box::new(with_connection_secret_collection_etag(
                    precondition_failed(
                        "If-Match does not match the current connection-secret collection ETag",
                    ),
                    &locked_collection_etag,
                )));
            }
            let manager = match control_plane.local_secret_manager() {
                Ok(manager) => manager,
                Err(_) => {
                    drop(mutation_guard);
                    return Err(Box::new(connection_secret_store_not_configured()));
                }
            };
            match manager.create(&label, secret, &actor) {
                Ok(created) => {
                    let new_collection_etag = connections::admin::secret_collection_etag(
                        &control_plane.secret_alias_metadata(),
                    );
                    Ok((created, new_collection_etag))
                }
                Err(error) => Err(Box::new(connection_secret_error_response(error))),
            }
        })
        .await
        {
            Ok(Ok((created, new_collection_etag))) => (created, new_collection_etag),
            Ok(Err(response)) => return *response,
            Err(error) => {
                tracing::error!(error = %error, "connection-secret mutation task failed");
                return internal_server_error("connection-secret mutation failed");
            }
        }
    };
    let (created, new_collection_etag) = created;
    let item_etag = connections::admin::secret_metadata_etag(&created);
    emit_connection_secret_changed(&state, &parts, &principal, "created", &created, 0);
    (
        StatusCode::CREATED,
        [
            (header::ETAG, etag_header_value(&item_etag)),
            (
                HeaderName::from_static(CONNECTION_SECRET_COLLECTION_ETAG_HEADER),
                etag_header_value(&new_collection_etag),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(connections::admin::SafeSecretAliasView::from_metadata(
            created, true, 0,
        )),
    )
        .into_response()
}

pub(super) async fn connection_secret_rotate_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_SECRET_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_connection_state(
        &state,
        &principal,
        ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
    ) {
        return match error {
            ConnectionAdminAuthzError::Forbidden(_) => connection_permission_forbidden(
                &state,
                &parts,
                &principal,
                CONNECTION_SECRET_ADMIN_ROUTE,
                ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
                "rotate",
            ),
            error => connection_admin_authz_error_response(error),
        };
    }

    let current = match local_secret_metadata(&state.control_plane, &raw_id) {
        Ok(current) => current,
        Err(response) if response.status() == StatusCode::NOT_FOUND => {
            if let Err(error) =
                if_match_matches(&parts.headers, "\"connection-secret:no-current-version\"")
            {
                return if_match_error_response(error);
            }
            let current_collection_etag = connections::admin::secret_collection_etag(
                &state.control_plane.secret_alias_metadata(),
            );
            return with_connection_secret_collection_etag(
                precondition_failed("If-Match does not match an existing connection secret"),
                &current_collection_etag,
            );
        }
        Err(response) => return *response,
    };
    let current_etag = connections::admin::secret_metadata_etag(&current);
    match if_match_matches(&parts.headers, &current_etag) {
        Ok(true) => {}
        Ok(false) => {
            return with_etag(
                precondition_failed("If-Match does not match the current connection-secret ETag"),
                &current_etag,
            );
        }
        Err(error) => return with_etag(if_match_error_response(error), &current_etag),
    }
    let body =
        match read_connection_secret_body(body, connection_secret_admin_body_limit(&state)).await {
            Ok(body) => body,
            Err(response) => return *response,
        };
    let ConnectionSecretRotateRequest { purpose, mut value } =
        match serde_json::from_slice::<ConnectionSecretRotateRequest>(&body) {
            Ok(requested) => requested,
            Err(_) => return bad_request("invalid connection-secret JSON"),
        };
    drop(body);
    let secret_value = std::mem::take(&mut *value).into_bytes();
    let replacement = match connections::secret::ResolvedSecret::new(purpose, secret_value) {
        Ok(replacement) => replacement,
        Err(_) => return connection_secret_validation_error(),
    };
    // When this secret is one half of a client identity whose other half lives
    // behind a network provider, the synchronous preflight inside rotate cannot
    // fetch that half to match the pair. Do it here, before the mutation guard,
    // so the network I/O happens outside the lock.
    if let Err(error) = state
        .control_plane
        .ensure_rotated_identity_pairs_resolvable(&raw_id, &replacement)
        .await
    {
        return connection_mutation_error_response(error);
    }
    // See the create handler: the guard, the re-check, and the encrypted
    // SQLite write run together on the blocking pool.
    let rotated = {
        let lock = Arc::clone(&state.secret_precondition_lock);
        let control_plane = state.control_plane.clone();
        let raw_id_for_mutation = raw_id.clone();
        let current_etag_for_mutation = current_etag.clone();
        let actor = auth::change_actor::ChangeActor::from_principal(&principal);
        match tokio::task::spawn_blocking(move || -> ResponseResult<_> {
            let mutation_guard = match lock_connection_secret_mutations(&lock) {
                Ok(guard) => guard,
                Err(response) => return Err(response),
            };
            let locked_current = match local_secret_metadata(&control_plane, &raw_id_for_mutation) {
                Ok(current) => current,
                Err(_) => {
                    let current_collection_etag = connections::admin::secret_collection_etag(
                        &control_plane.secret_alias_metadata(),
                    );
                    drop(mutation_guard);
                    return Err(Box::new(with_connection_secret_collection_etag(
                        precondition_failed("connection secret changed during rotation"),
                        &current_collection_etag,
                    )));
                }
            };
            let locked_etag = connections::admin::secret_metadata_etag(&locked_current);
            if locked_etag != current_etag_for_mutation {
                drop(mutation_guard);
                return Err(Box::new(with_etag(
                    precondition_failed(
                        "If-Match does not match the current connection-secret ETag",
                    ),
                    &locked_etag,
                )));
            }
            let manager = match control_plane.local_secret_manager() {
                Ok(manager) => manager,
                Err(_) => {
                    drop(mutation_guard);
                    return Err(Box::new(connection_secret_store_not_configured()));
                }
            };
            match manager.rotate(&raw_id_for_mutation, replacement, &actor) {
                Ok(rotated) => {
                    let dependency_count =
                        connection_secret_dependency_counts(&control_plane.runtime_snapshot())
                            .get(raw_id_for_mutation.as_str())
                            .copied()
                            .unwrap_or_default();
                    let new_collection_etag = connections::admin::secret_collection_etag(
                        &control_plane.secret_alias_metadata(),
                    );
                    Ok((rotated, dependency_count, new_collection_etag))
                }
                Err(error) => Err(Box::new(connection_secret_error_response(error))),
            }
        })
        .await
        {
            Ok(Ok(rotation)) => rotation,
            Ok(Err(response)) => return *response,
            Err(error) => {
                tracing::error!(error = %error, "connection-secret mutation task failed");
                return internal_server_error("connection-secret mutation failed");
            }
        }
    };
    let (rotated, dependency_count, new_collection_etag) = rotated;
    let item_etag = connections::admin::secret_metadata_etag(&rotated);
    emit_connection_secret_changed(
        &state,
        &parts,
        &principal,
        "rotated",
        &rotated,
        dependency_count,
    );
    (
        StatusCode::OK,
        [
            (header::ETAG, etag_header_value(&item_etag)),
            (
                HeaderName::from_static(CONNECTION_SECRET_COLLECTION_ETAG_HEADER),
                etag_header_value(&new_collection_etag),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(connections::admin::SafeSecretAliasView::from_metadata(
            rotated,
            true,
            dependency_count,
        )),
    )
        .into_response()
}

pub(super) async fn connection_secret_delete_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_SECRET_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_connection_state(
        &state,
        &principal,
        ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
    ) {
        return match error {
            ConnectionAdminAuthzError::Forbidden(_) => connection_permission_forbidden(
                &state,
                &parts,
                &principal,
                CONNECTION_SECRET_ADMIN_ROUTE,
                ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
                "delete",
            ),
            error => connection_admin_authz_error_response(error),
        };
    }

    let current = match local_secret_metadata(&state.control_plane, &raw_id) {
        Ok(current) => current,
        Err(response) if response.status() == StatusCode::NOT_FOUND => {
            if let Err(error) =
                if_match_matches(&parts.headers, "\"connection-secret:no-current-version\"")
            {
                return if_match_error_response(error);
            }
            let current_collection_etag = connections::admin::secret_collection_etag(
                &state.control_plane.secret_alias_metadata(),
            );
            return with_connection_secret_collection_etag(
                precondition_failed("If-Match does not match an existing connection secret"),
                &current_collection_etag,
            );
        }
        Err(response) => return *response,
    };
    let current_etag = connections::admin::secret_metadata_etag(&current);
    match if_match_matches(&parts.headers, &current_etag) {
        Ok(true) => {}
        Ok(false) => {
            return with_etag(
                precondition_failed("If-Match does not match the current connection-secret ETag"),
                &current_etag,
            );
        }
        Err(error) => return with_etag(if_match_error_response(error), &current_etag),
    }
    let body = match read_connection_secret_body(body, state.max_body_size.min(1024)).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if !body.is_empty() {
        return bad_request("connection-secret delete does not accept a request body");
    }
    drop(body);
    // See the create handler: the guard, the re-check, and the encrypted
    // SQLite delete run together on the blocking pool.
    let deletion = {
        let lock = Arc::clone(&state.secret_precondition_lock);
        let control_plane = state.control_plane.clone();
        let raw_id_for_mutation = raw_id.clone();
        let current_etag_for_mutation = current_etag.clone();
        let actor = auth::change_actor::ChangeActor::from_principal(&principal);
        tokio::task::spawn_blocking(move || -> ResponseResult<String> {
            let mutation_guard = match lock_connection_secret_mutations(&lock) {
                Ok(guard) => guard,
                Err(response) => return Err(response),
            };
            let locked_current = match local_secret_metadata(&control_plane, &raw_id_for_mutation) {
                Ok(current) => current,
                Err(_) => {
                    let current_collection_etag = connections::admin::secret_collection_etag(
                        &control_plane.secret_alias_metadata(),
                    );
                    drop(mutation_guard);
                    return Err(Box::new(with_connection_secret_collection_etag(
                        precondition_failed("connection secret changed during deletion"),
                        &current_collection_etag,
                    )));
                }
            };
            let locked_etag = connections::admin::secret_metadata_etag(&locked_current);
            if locked_etag != current_etag_for_mutation {
                drop(mutation_guard);
                return Err(Box::new(with_etag(
                    precondition_failed(
                        "If-Match does not match the current connection-secret ETag",
                    ),
                    &locked_etag,
                )));
            }
            let manager = match control_plane.local_secret_manager() {
                Ok(manager) => manager,
                Err(_) => {
                    drop(mutation_guard);
                    return Err(Box::new(connection_secret_store_not_configured()));
                }
            };
            if let Err(error) = manager.delete(&raw_id_for_mutation, &actor) {
                return Err(Box::new(connection_secret_error_response(error)));
            }
            let new_collection_etag =
                connections::admin::secret_collection_etag(&control_plane.secret_alias_metadata());
            Ok(new_collection_etag)
        })
        .await
    };
    let new_collection_etag = match deletion {
        Ok(Ok(new_collection_etag)) => new_collection_etag,
        Ok(Err(response)) => return *response,
        Err(error) => {
            tracing::error!(error = %error, "connection-secret mutation task failed");
            return internal_server_error("connection-secret mutation failed");
        }
    };
    emit_connection_secret_changed(&state, &parts, &principal, "deleted", &current, 0);
    (
        StatusCode::OK,
        [
            (
                HeaderName::from_static(CONNECTION_SECRET_COLLECTION_ETAG_HEADER),
                etag_header_value(&new_collection_etag),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(ConnectionSecretDeletedResponse {
            deleted_secret_id: raw_id,
        }),
    )
        .into_response()
}

pub(super) async fn connection_list_endpoint(
    State(state): State<ConnectionAdminState>,
    Query(params): Query<connections::admin::ConnectionListParams>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTIONS_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_connection_state(&state, principal, ADMIN_CONNECTIONS_READ_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return connection_admin_authz_error_response(error),
        };
    let permissions = connection_permissions(rbac_state, principal);
    let snapshot = state.control_plane.runtime_snapshot();
    let runtime =
        match connection_collection_runtime_data(&state, &snapshot, rbac_state, principal).await {
            Ok(data) => data,
            Err(response) => return *response,
        };
    let page = match connections::admin::build_connection_list_page(
        &snapshot,
        connections::admin::ConnectionListRuntimeData {
            statuses: &runtime.statuses,
            status_revisions: &runtime.status_revisions,
            dependency_counts: &runtime.dependency_counts,
            capability_counts: &runtime.capability_counts,
            activity_times: &runtime.activity_times,
        },
        &params,
        permissions,
        state.control_plane.is_managed_store_configured(),
        state.control_plane.is_local_secret_manager_configured(),
    ) {
        Ok(page) => page,
        Err(connections::admin::ConnectionListError::InvalidLimit) => {
            return bad_request("limit must be between 1 and 100");
        }
        Err(connections::admin::ConnectionListError::InvalidCursor) => {
            return bad_request("connection list cursor is invalid");
        }
        Err(connections::admin::ConnectionListError::StaleCursor) => {
            return with_connection_collection_etag(
                precondition_failed("connection list cursor does not match the current collection"),
                snapshot.collection_etag(),
            );
        }
    };

    let response_etag = match serialized_response_etag(&page) {
        Ok(etag) => etag,
        Err(error) => {
            tracing::error!(error = %error, "failed to hash connection list response");
            return internal_server_error("connection list response could not be encoded");
        }
    };
    with_connection_collection_etag(
        (
            StatusCode::OK,
            [
                (header::ETAG, etag_header_value(&response_etag)),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            Json(page),
        )
            .into_response(),
        snapshot.collection_etag(),
    )
}

pub(super) async fn connection_get_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_connection_state(&state, principal, ADMIN_CONNECTIONS_READ_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return connection_admin_authz_error_response(error),
        };
    let permissions = connection_permissions(rbac_state, principal);
    let id = match connections::model::ConnectionId::parse(raw_id) {
        Ok(id) => id,
        Err(_) => return not_found("connection was not found"),
    };
    let snapshot = state.control_plane.runtime_snapshot();

    if let Some(record) = snapshot.managed().get(&id) {
        let (status, dependencies, status_revision) =
            match connection_detail_runtime_data(&state, &id).await {
                Ok(data) => data,
                Err(response) => return *response,
            };
        let record =
            connections::admin::with_authoritative_status_revision(record, status_revision);
        let etag = record.etag();
        return (
            StatusCode::OK,
            [
                (header::ETAG, etag_header_value(etag.as_str())),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            Json(connections::admin::managed_detail_view(
                &record,
                status,
                dependencies,
                permissions,
                state.control_plane.is_local_secret_manager_configured(),
                state.control_plane.caller_assertion_key_problem(&record),
            )),
        )
            .into_response();
    }

    if let Some(projection) = snapshot
        .legacy()
        .iter()
        .find(|projection| projection.id() == &id)
    {
        return (
            StatusCode::OK,
            [
                (header::ETAG, etag_header_value(snapshot.collection_etag())),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            Json(connections::admin::legacy_detail_view(
                projection.safe_summary(),
                permissions.secrets_write
                    && state.control_plane.is_local_secret_manager_configured(),
            )),
        )
            .into_response();
    }

    not_found("connection was not found")
}

pub(super) async fn connection_create_endpoint(
    State(state): State<ConnectionAdminState>,
    request: AxumRequest,
) -> Response {
    let pins = request.extensions().clone();
    connection_change_to_completion(pins, Box::pin(connection_create(state, request))).await
}

/// Runs a Connection create, replace or delete on a task of its own, so it
/// finishes whether or not anyone is still waiting for the response (issue
/// #425). axum drops a handler's future when the client disconnects, while
/// a store call already under way still commits: the SQLite transaction runs
/// on the blocking pool, and a PostgreSQL `COMMIT` already sent completes.
/// Dropped there, a change would be committed but never published to this
/// replica's runtime snapshot, its catalogs never reconciled or removed and
/// its audit event never emitted, and in standalone mode nothing would heal
/// that before a restart -- while a keyed retry is answered from the receipt
/// of the committed change. The request's pinned snapshots are re-entered on
/// the task and its span carried over. A panic is resumed here, as if the
/// handler had panicked itself. The change arrives boxed: a handler's state
/// machine is large, and moving it by value through the spawn would grow
/// every stack it passes through.
async fn connection_change_to_completion(
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
            tracing::error!(error = %error, "a Connection change task was cancelled");
            service_unavailable("managed connection state is unavailable")
        }
    }
}

async fn connection_create(state: ConnectionAdminState, request: AxumRequest) -> Response {
    record_request(CONNECTIONS_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_connection_state(&state, &principal, ADMIN_CONNECTIONS_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return connection_admin_authz_error_response(error),
        };
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }

    let body = match read_request_body(body, connection_admin_body_limit(&state)).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let candidate = match parse_connection_create_body(&body) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };
    let credential_changed = candidate.requires_secrets_write_to_create();
    if credential_changed
        && !rbac_state
            .principal_has_permission(&principal, ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION)
    {
        return connection_secret_authority_forbidden(
            &state,
            &parts,
            &principal,
            CONNECTIONS_ADMIN_ROUTE,
            "create",
        );
    }

    // Authorized and validated: bind the caller key, ask the gates, and
    // answer an exact retry before the collection precondition, which a
    // committed create has since moved (issue #425). The snapshot is read
    // first: one older than a racing first attempt's commit passes `If-Match`
    // and the control plane answers the retry from the key under its lock,
    // while a snapshot that already shows the commit means the pre-check
    // below sees the key too.
    let snapshot = state.control_plane.runtime_snapshot();
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    let caller = match admit_keyed_connection_change(
        &state,
        &parts,
        &principal,
        &actor,
        KeyedConnectionChange::Create,
        &body,
        "",
    )
    .await
    {
        Ok(caller) => caller,
        Err(response) => return *response,
    };

    match if_match_matches(&parts.headers, snapshot.collection_etag()) {
        Ok(true) => {}
        Ok(false) => {
            return with_connection_collection_etag(
                precondition_failed(
                    "If-Match does not match the current connection collection ETag",
                ),
                snapshot.collection_etag(),
            );
        }
        Err(error) => {
            return with_connection_collection_etag(
                if_match_error_response(error),
                snapshot.collection_etag(),
            );
        }
    }

    // Bindings owned by a network secret provider cannot be resolved on the
    // synchronous path inside create_managed, so they are validated here, before
    // the mutation lock is taken and before anything is persisted.
    if let Err(error) = state
        .control_plane
        .ensure_deferred_bindings_resolvable(&candidate)
        .await
    {
        return connection_mutation_error_response(error);
    }
    // Managed mutations transact inside the control plane. The store
    // dispatch owns keeping that work off the request executor: standalone
    // mode runs its SQLite transaction on the blocking pool, cluster mode
    // awaits the PostgreSQL authority.
    if let Err(response) =
        admit_mutation_approval_enrollment(&state, &parts, &principal, &candidate).await
    {
        return *response;
    }
    let created = match state
        .control_plane
        .create_managed_with_operation(
            snapshot.collection_etag(),
            candidate,
            &actor,
            caller.as_ref(),
        )
        .await
    {
        Ok(authority_events::caller_operation::CallerOutcome::Committed(created)) => created,
        // An exact retry: no change, no audit event, no reload.
        Ok(authority_events::caller_operation::CallerOutcome::Replayed(receipt)) => {
            return operation_receipt(&receipt)
        }
        Err(error) => return connection_mutation_error_response(error),
    };
    let permissions = connection_permissions(rbac_state, &principal);
    let changed_fields = connections::admin::changed_connection_fields(None, Some(&created.write));
    emit_connection_changed(
        &state,
        &parts,
        &principal,
        "created",
        &created,
        &changed_fields,
        credential_changed,
    );
    let new_snapshot = state.control_plane.runtime_snapshot();
    let etag = created.etag();
    with_connection_collection_etag(
        (
            StatusCode::CREATED,
            [
                (header::ETAG, etag_header_value(etag.as_str())),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            Json(connections::admin::managed_detail_view(
                &created,
                None,
                Vec::new(),
                permissions,
                state.control_plane.is_local_secret_manager_configured(),
                state.control_plane.caller_assertion_key_problem(&created),
            )),
        )
            .into_response(),
        new_snapshot.collection_etag(),
    )
}

pub(super) async fn connection_put_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    let pins = request.extensions().clone();
    connection_change_to_completion(pins, Box::pin(connection_put(state, raw_id, request))).await
}

async fn connection_put(
    state: ConnectionAdminState,
    raw_id: String,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_connection_state(&state, &principal, ADMIN_CONNECTIONS_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return connection_admin_authz_error_response(error),
        };
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }
    let id = match connections::model::ConnectionId::parse(raw_id) {
        Ok(id) => id,
        Err(_) => return not_found("connection was not found"),
    };
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    let snapshot = state.control_plane.runtime_snapshot();
    let Some(current) = snapshot.managed().get(&id).cloned() else {
        if snapshot
            .legacy()
            .iter()
            .any(|projection| projection.id() == &id)
        {
            return conflict("legacy connection projections are read-only");
        }
        // A keyed replacement that committed is answered from its evidence
        // even once the Connection has since been deleted, as a keyed delete
        // is (issue #425). The caller is authorized for what the body says
        // and the body is validated before the key is bound; with the record
        // gone, the body is bound as received and judged as a replacement in
        // its own right, not against the record. An unkeyed request for a
        // missing record is `404`, as before.
        if parts.headers.contains_key("idempotency-key") {
            let body = match read_request_body(body, connection_admin_body_limit(&state)).await {
                Ok(body) => body,
                Err(response) => return *response,
            };
            match explicit_connection_binding_intent_from_body(&body) {
                Ok(true)
                    if !rbac_state.principal_has_permission(
                        &principal,
                        ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
                    ) =>
                {
                    return connection_secret_authority_forbidden(
                        &state,
                        &parts,
                        &principal,
                        CONNECTION_ADMIN_ROUTE,
                        "replace",
                    );
                }
                Ok(_) => {}
                Err(response) => return *response,
            }
            // Validated before admission, which can raise the cluster's
            // contract fence: the body must be a Connection replacement in
            // its own right, whatever record it would have been judged
            // against.
            if let Err(response) = validate_connection_replacement_without_record(&body) {
                return *response;
            }
            if let Err(response) = admit_keyed_connection_change(
                &state,
                &parts,
                &principal,
                &actor,
                KeyedConnectionChange::Replace,
                &body,
                id.as_str(),
            )
            .await
            {
                return *response;
            }
        }
        return not_found("connection was not found");
    };

    let body = match read_request_body(body, connection_admin_body_limit(&state)).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let has_secrets_write =
        rbac_state.principal_has_permission(&principal, ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION);
    let explicit_binding_intent = match explicit_connection_binding_intent_from_body(&body) {
        Ok(intent) => intent,
        Err(response) => return *response,
    };
    if explicit_binding_intent && !has_secrets_write {
        return connection_secret_authority_forbidden(
            &state,
            &parts,
            &principal,
            CONNECTION_ADMIN_ROUTE,
            "replace",
        );
    }
    let candidate = match parse_connection_write_body(&body, &current.write) {
        Ok(candidate) => candidate,
        Err(response) => return *response,
    };
    let credential_changed = current.write.requires_secrets_write_to_replace(&candidate);
    if credential_changed && !has_secrets_write {
        return connection_secret_authority_forbidden(
            &state,
            &parts,
            &principal,
            CONNECTION_ADMIN_ROUTE,
            "replace",
        );
    }

    // Authorized and validated: bind the caller key, ask the gates, and
    // answer an exact retry before the ETag precondition, which a committed
    // replacement has since moved (issue #425).
    let current_etag = current.etag();
    let caller = match admit_keyed_connection_change(
        &state,
        &parts,
        &principal,
        &actor,
        KeyedConnectionChange::Replace,
        &body,
        id.as_str(),
    )
    .await
    {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    match if_match_matches(&parts.headers, current_etag.as_str()) {
        Ok(true) => {}
        Ok(false) => {
            return with_etag(
                precondition_failed("If-Match does not match the current connection ETag"),
                current_etag.as_str(),
            );
        }
        Err(error) => return with_etag(if_match_error_response(error), current_etag.as_str()),
    }
    let _catalog_lifecycle = match state.control_plane.begin_catalog_mutation(&id) {
        Ok(guard) => guard,
        Err(error) => return connection_catalog_lifecycle_error_response(error),
    };

    let changed_fields =
        connections::admin::changed_connection_fields(Some(&current.write), Some(&candidate));
    let (current_status, dependencies, _status_revision) =
        match connection_detail_runtime_data(&state, &id).await {
            Ok(data) => data,
            Err(response) => return *response,
        };
    // See the create handler: deferred bindings are resolved before the lock.
    if let Err(error) = state
        .control_plane
        .ensure_deferred_bindings_resolvable(&candidate)
        .await
    {
        return connection_mutation_error_response(error);
    }
    if let Err(response) =
        admit_mutation_approval_enrollment(&state, &parts, &principal, &candidate).await
    {
        return *response;
    }
    let updated = match state
        .control_plane
        .replace_managed_with_operation(&id, &current_etag, candidate, &actor, caller.as_ref())
        .await
    {
        Ok(authority_events::caller_operation::CallerOutcome::Committed(updated)) => updated,
        // An exact retry: no change, no audit event, no catalog reconcile.
        Ok(authority_events::caller_operation::CallerOutcome::Replayed(receipt)) => {
            return operation_receipt(&receipt)
        }
        Err(error) => return connection_mutation_error_response(error),
    };
    state.mcp_catalogs.reconcile_connection(&updated);
    let withdrawn_openapi_catalog = state.openapi_catalogs.reconcile_connection(&updated);
    if !changed_fields.is_empty() {
        emit_connection_changed(
            &state,
            &parts,
            &principal,
            "updated",
            &updated,
            &changed_fields,
            credential_changed,
        );
    }
    if let Some(withdrawal) = &withdrawn_openapi_catalog {
        emit_managed_openapi_catalog_withdrawn(&state, &parts, &principal, withdrawal);
    }
    let status = if changed_fields.is_empty() {
        current_status
    } else {
        None
    };
    let permissions = connection_permissions(rbac_state, &principal);
    let etag = updated.etag();
    let new_snapshot = state.control_plane.runtime_snapshot();
    with_connection_collection_etag(
        (
            StatusCode::OK,
            [
                (header::ETAG, etag_header_value(etag.as_str())),
                (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
            ],
            Json(connections::admin::managed_detail_view(
                &updated,
                status,
                dependencies,
                permissions,
                state.control_plane.is_local_secret_manager_configured(),
                state.control_plane.caller_assertion_key_problem(&updated),
            )),
        )
            .into_response(),
        new_snapshot.collection_etag(),
    )
}

pub(super) async fn connection_delete_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    let pins = request.extensions().clone();
    connection_change_to_completion(pins, Box::pin(connection_delete(state, raw_id, request))).await
}

async fn connection_delete(
    state: ConnectionAdminState,
    raw_id: String,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_connection_state(&state, &principal, ADMIN_CONNECTIONS_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return connection_admin_authz_error_response(error),
        };
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }
    let body = match read_request_body(body, connection_admin_body_limit(&state)).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if !body.is_empty() {
        return bad_request("connection delete does not accept a request body");
    }
    let id = match connections::model::ConnectionId::parse(raw_id) {
        Ok(id) => id,
        Err(_) => return not_found("connection was not found"),
    };
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    let snapshot = state.control_plane.runtime_snapshot();
    let Some(current) = snapshot.managed().get(&id).cloned() else {
        if snapshot
            .legacy()
            .iter()
            .any(|projection| projection.id() == &id)
        {
            return conflict("legacy connection projections are read-only");
        }
        // A keyed delete that committed is answered from its evidence,
        // which outlives the record (issue #425); any other request for a
        // missing record is `404`.
        if let Err(response) = admit_keyed_connection_change(
            &state,
            &parts,
            &principal,
            &actor,
            KeyedConnectionChange::Delete,
            &body,
            id.as_str(),
        )
        .await
        {
            return *response;
        }
        return not_found("connection was not found");
    };
    let credential_changed = current.write.requires_secrets_write_to_delete();
    if credential_changed
        && !rbac_state
            .principal_has_permission(&principal, ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION)
    {
        return connection_secret_authority_forbidden(
            &state,
            &parts,
            &principal,
            CONNECTION_ADMIN_ROUTE,
            "delete",
        );
    }
    let current_etag = current.etag();
    // Authorized and validated: bind the caller key, ask the operation gate
    // (a withdrawal never asks the evidence gate), and answer an exact
    // retry before the ETag precondition.
    let caller = match admit_keyed_connection_change(
        &state,
        &parts,
        &principal,
        &actor,
        KeyedConnectionChange::Delete,
        &body,
        id.as_str(),
    )
    .await
    {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    match if_match_matches(&parts.headers, current_etag.as_str()) {
        Ok(true) => {}
        Ok(false) => {
            return with_etag(
                precondition_failed("If-Match does not match the current connection ETag"),
                current_etag.as_str(),
            );
        }
        Err(error) => return with_etag(if_match_error_response(error), current_etag.as_str()),
    }
    let _catalog_lifecycle = match state.control_plane.begin_catalog_mutation(&id) {
        Ok(guard) => guard,
        Err(error) => return connection_catalog_lifecycle_error_response(error),
    };

    // The catalog-lifecycle guard stays held across the delete. The deleting
    // principal -- subject, issuer, kind and auth mode -- is the deletion's
    // evidence, committed with it or not at all; the audit event below stays
    // post-commit telemetry.
    match state
        .control_plane
        .delete_managed_with_operation(&id, &current_etag, &actor, caller.as_ref())
        .await
    {
        Ok(authority_events::caller_operation::CallerOutcome::Committed(())) => {}
        // An exact retry: no change, no audit event, no catalog removal.
        Ok(authority_events::caller_operation::CallerOutcome::Replayed(receipt)) => {
            return operation_receipt(&receipt)
        }
        Err(error) => return connection_mutation_error_response(error),
    }
    state.mcp_catalogs.remove_connection(&id);
    state.openapi_catalogs.remove_connection(&id);
    let changed_fields = connections::admin::changed_connection_fields(Some(&current.write), None);
    emit_connection_changed(
        &state,
        &parts,
        &principal,
        "deleted",
        &current,
        &changed_fields,
        credential_changed,
    );
    let new_snapshot = state.control_plane.runtime_snapshot();
    with_connection_collection_etag(
        (
            StatusCode::OK,
            Json(ConnectionDeletedResponse {
                deleted_connection_id: id,
            }),
        )
            .into_response(),
        new_snapshot.collection_etag(),
    )
}

/// A Connection change, or a publication of a Connection's managed catalog,
/// that binds a caller key (issue #425).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum KeyedConnectionChange {
    Create,
    Replace,
    Delete,
    /// A refresh of a managed MCP Connection's catalog.
    CatalogMcpPublish,
    /// An OpenAPI registration, or a refresh of a managed OpenAPI
    /// Connection's catalog.
    CatalogOpenApiPublish,
    /// An OpenAPI overlay stored, with its catalog.
    CatalogOverlayReplace,
    /// An OpenAPI overlay removed, with its catalog published without it.
    CatalogOverlayDelete,
}

impl KeyedConnectionChange {
    /// The operation code the key is reserved for and the evidence records.
    pub(super) const fn action(self) -> &'static str {
        match self {
            Self::Create => "connection.create",
            Self::Replace => "connection.replace",
            Self::Delete => "connection.delete",
            Self::CatalogMcpPublish => "catalog.mcp.publish",
            Self::CatalogOpenApiPublish => "catalog.openapi.publish",
            Self::CatalogOverlayReplace => "catalog.overlay.replace",
            Self::CatalogOverlayDelete => "catalog.overlay.delete",
        }
    }

    /// What the change is to the evidence gate. Its operation's code is
    /// [`Self::action`], so the key bound here is the one the gate is asked
    /// about.
    fn keyed_change(self) -> KeyedChange {
        match self {
            Self::Create => {
                KeyedChange::Gated(authority_events::required::AuthorityOperation::ConnectionCreate)
            }
            Self::Replace => KeyedChange::Gated(
                authority_events::required::AuthorityOperation::ConnectionReplace,
            ),
            Self::Delete => {
                KeyedChange::Withdrawal(authority_events::required::Withdrawal::ConnectionDelete)
            }
            Self::CatalogMcpPublish => KeyedChange::Gated(
                authority_events::required::AuthorityOperation::CatalogMcpPublish,
            ),
            Self::CatalogOpenApiPublish => KeyedChange::Gated(
                authority_events::required::AuthorityOperation::CatalogOpenapiPublish,
            ),
            Self::CatalogOverlayReplace => KeyedChange::Gated(
                authority_events::required::AuthorityOperation::CatalogOverlayReplace,
            ),
            Self::CatalogOverlayDelete => KeyedChange::Gated(
                authority_events::required::AuthorityOperation::CatalogOverlayDelete,
            ),
        }
    }
}

/// The request a Connection change's key is bound to: the body as canonical
/// JSON, object keys sorted, so a retry is the same request whatever its
/// whitespace or key order. A Connection body holds no secret value -- only
/// credential aliases and provider locators, which decide which credential
/// the Connection uses and so stay in -- and a delete has no body. Nor does
/// a catalog request: an OpenAPI registration carries the specification
/// and its selection, an overlay put the overlay document, and a refresh or
/// an overlay delete nothing.
pub(super) fn canonical_connection_request(body: &[u8]) -> ResponseResult<Vec<u8>> {
    fn sorted(value: Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut entries: Vec<(String, Value)> = object.into_iter().collect();
                entries.sort_by(|left, right| left.0.cmp(&right.0));
                Value::Object(
                    entries
                        .into_iter()
                        .map(|(key, value)| (key, sorted(value)))
                        .collect(),
                )
            }
            Value::Array(values) => Value::Array(values.into_iter().map(sorted).collect()),
            other => other,
        }
    }
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let value = serde_json::from_slice::<Value>(body)
        .map_err(|_| Box::new(bad_request("invalid connection JSON")))?;
    serde_json::to_vec(&sorted(value)).map_err(|error| {
        tracing::error!(error = %error, "a Connection request could not be encoded for its caller key");
        Box::new(internal_server_error("the caller operation could not be bound"))
    })
}

/// The `If-Match` values a request carries, as received, for its key's
/// binding: missing is `428` and a value that is not ASCII is `400`, as the
/// precondition check itself answers.
fn if_match_precondition(headers: &HeaderMap) -> ResponseResult<String> {
    let mut values = Vec::new();
    for value in headers.get_all(header::IF_MATCH) {
        values.push(
            value
                .to_str()
                .map_err(|_| Box::new(if_match_error_response(IfMatchError::InvalidHeader)))?,
        );
    }
    if values.is_empty() {
        return Err(Box::new(if_match_error_response(IfMatchError::Missing)));
    }
    Ok(values.join(", "))
}

/// Bind a Connection change's caller key and admit it (issue #425). Called
/// once the handler has authorized the caller and validated the request, and
/// before the precondition check and any external I/O: the key is bound to
/// the action, the recorded actor, the target, the `If-Match` value and the
/// canonical body; the evidence gate (create and replace) and, for a keyed
/// request in cluster mode, the operation gate are asked; and an exact retry
/// of a committed change is answered with its receipt, a key bound to
/// anything else with `409`. `Ok(None)` is an unkeyed request the gates
/// admitted; `Ok(Some(_))` a keyed one whose key is unused.
pub(super) async fn admit_keyed_connection_change(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    actor: &auth::change_actor::ChangeActor,
    change: KeyedConnectionChange,
    body: &[u8],
    target: &str,
) -> ResponseResult<Option<authority_events::caller_operation::CallerOperation>> {
    let caller = if parts.headers.contains_key("idempotency-key") {
        caller_operation(
            &parts.headers,
            actor,
            change.action(),
            target,
            &if_match_precondition(&parts.headers)?,
            &canonical_connection_request(body)?,
        )?
    } else {
        None
    };
    let gates = KeyedChangeGates {
        evidence: &state.authority_evidence,
        #[cfg(feature = "postgres")]
        membership: state.membership.as_deref(),
        audit: &state.audit,
        client_ip_policy: &state.client_ip_policy,
    };
    admit_keyed_authority_change(
        &gates,
        change.keyed_change(),
        caller.as_ref(),
        actor,
        parts,
        principal,
    )
    .await?;
    if let Some(caller) = &caller {
        replayed_receipt(
            state.control_plane.caller_operation_state(caller),
            state.control_plane.caller_operation_receipt(caller),
        )
        .await?;
    }
    Ok(caller)
}

/// Refresh a managed OpenAPI catalog, asking the operation gate when the
/// refreshed document turns out to be converted. Whether it is converted is
/// known only once it is fetched, so an admitted refresh fetches it again;
/// the service stopped the first pass before writing or recording anything.
/// Both passes carry the refresh's caller key, if any (issue #425).
async fn refresh_managed_openapi_catalog(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    id: &connections::model::ConnectionId,
    current_etag: &str,
    caller: Option<&authority_events::caller_operation::CallerOperation>,
) -> Result<
    authority_events::caller_operation::CallerOutcome<
        connections::openapi::OpenApiCatalogPublishResult,
    >,
    Box<(ConnectionRefreshFailure, Response)>,
> {
    let actor = auth::change_actor::ChangeActor::from_principal(principal);
    let mut converted_catalog = connections::openapi::ConvertedCatalogAdmission::NotAsked;
    loop {
        let result = state
            .openapi_catalogs
            .refresh_with_operation(id.as_str(), current_etag, converted_catalog, &actor, caller)
            .await;
        match result {
            Err(connections::openapi::OpenApiCatalogError::ConvertedCatalogNeedsAdmission {
                requirement,
            }) if converted_catalog
                == connections::openapi::ConvertedCatalogAdmission::NotAsked =>
            {
                admit_converted_openapi_catalog(state, parts, principal, requirement)
                    .await
                    .map_err(|refusal| {
                        Box::new((
                            ConnectionRefreshFailure::plain(refusal.reason),
                            *refusal.response,
                        ))
                    })?;
                converted_catalog =
                    connections::openapi::ConvertedCatalogAdmission::Admitted(requirement);
            }
            result => {
                return result.map_err(|error| {
                    Box::new((
                        ConnectionRefreshFailure::plain(error.safe_reason()),
                        openapi_catalog_error_response(error, "refresh"),
                    ))
                });
            }
        }
    }
}

pub(super) async fn connection_refresh_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_REFRESH_ADMIN_ROUTE);

    let started = Instant::now();
    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_connection_state(&state, &principal, ADMIN_CONNECTIONS_REFRESH_PERMISSION)
    {
        return connection_admin_authz_error_response(error);
    }
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }
    let body = match read_request_body(body, connection_admin_body_limit(&state)).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    if !body.is_empty() {
        return bad_request("connection refresh does not accept a request body");
    }
    let id = match connections::model::ConnectionId::parse(raw_id) {
        Ok(id) => id,
        Err(_) => return not_found("connection was not found"),
    };
    let snapshot = state.control_plane.runtime_snapshot();
    let Some(record) = snapshot.managed().get(&id) else {
        if snapshot
            .legacy()
            .iter()
            .any(|projection| projection.id() == &id)
        {
            return conflict("legacy connection projections are read-only");
        }
        return not_found("connection was not found");
    };
    let current_etag = record.etag();
    match if_match_matches(&parts.headers, current_etag.as_str()) {
        Ok(true) => {}
        Ok(false) => {
            return with_etag(
                precondition_failed("If-Match does not match the current connection ETag"),
                current_etag.as_str(),
            );
        }
        Err(error) => return with_etag(if_match_error_response(error), current_etag.as_str()),
    }

    // Authorized and validated: bind the caller key to the publication the
    // Connection's discovery makes, ask the gates, and answer an exact retry
    // from its receipt before the upstream is contacted again (issue #425).
    // A refresh publishes a catalog revision and leaves the Connection's
    // ETag where it was, so the precondition above still holds on a retry.
    // A Connection without discovery publishes nothing and is refused below.
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    let publication = match &record.write.discovery {
        Some(connections::model::DiscoveryConfig::ManagedMcp { .. }) => {
            Some(KeyedConnectionChange::CatalogMcpPublish)
        }
        Some(connections::model::DiscoveryConfig::ManagedOpenapi { .. }) => {
            Some(KeyedConnectionChange::CatalogOpenApiPublish)
        }
        None => None,
    };
    let caller = match publication {
        Some(publication) => match admit_keyed_connection_change(
            &state,
            &parts,
            &principal,
            &actor,
            publication,
            &body,
            id.as_str(),
        )
        .await
        {
            Ok(caller) => caller,
            Err(response) => return *response,
        },
        None => None,
    };

    let refreshed = match &record.write.discovery {
        Some(connections::model::DiscoveryConfig::ManagedMcp { .. }) => match state
            .mcp_catalogs
            .refresh_with_operation(id.as_str(), current_etag.as_str(), &actor, caller.as_ref())
            .await
        {
            Ok(authority_events::caller_operation::CallerOutcome::Committed(result)) => {
                Ok(ConnectionCatalogRefreshResponse::Mcp(result))
            }
            // An exact retry: no publication, no audit event.
            Ok(authority_events::caller_operation::CallerOutcome::Replayed(receipt)) => {
                return operation_receipt(&receipt)
            }
            Err(error) => Err((
                ConnectionRefreshFailure::mcp(error),
                connection_refresh_error_response(error),
            )),
        },
        Some(connections::model::DiscoveryConfig::ManagedOpenapi { .. }) => {
            match refresh_managed_openapi_catalog(
                &state,
                &parts,
                &principal,
                &id,
                current_etag.as_str(),
                caller.as_ref(),
            )
            .await
            {
                Ok(authority_events::caller_operation::CallerOutcome::Committed(result)) => {
                    Ok(ConnectionCatalogRefreshResponse::OpenApi(result))
                }
                // An exact retry: no publication, no audit event.
                Ok(authority_events::caller_operation::CallerOutcome::Replayed(receipt)) => {
                    return operation_receipt(&receipt)
                }
                Err(failure) => Err(*failure),
            }
        }
        None => Err((
            ConnectionRefreshFailure::plain("discovery_not_configured"),
            (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "connection discovery is not configured",
                    "reason": "discovery_not_configured",
                })),
            )
                .into_response(),
        )),
    };
    match refreshed {
        Ok(result) => {
            let audit_summary = result.audit_summary();
            emit_connection_refreshed(
                &state,
                &parts,
                &principal,
                record,
                "success",
                None,
                started.elapsed(),
                Some(&audit_summary),
            );
            (
                StatusCode::OK,
                [
                    (header::ETAG, etag_header_value(current_etag.as_str())),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
                Json(result),
            )
                .into_response()
        }
        Err((failure, response)) => {
            emit_connection_refreshed(
                &state,
                &parts,
                &principal,
                record,
                "failure",
                Some(&failure),
                started.elapsed(),
                None,
            );
            with_etag(response, current_etag.as_str())
        }
    }
}

pub(super) async fn connection_test_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_TEST_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_connection_state(&state, &principal, ADMIN_CONNECTIONS_TEST_PERMISSION)
    {
        return match error {
            ConnectionAdminAuthzError::Forbidden(_) => connection_permission_forbidden(
                &state,
                &parts,
                &principal,
                CONNECTION_TEST_ADMIN_ROUTE,
                ADMIN_CONNECTIONS_TEST_PERMISSION,
                "test",
            ),
            error => connection_admin_authz_error_response(error),
        };
    }
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }
    let id = match connections::model::ConnectionId::parse(raw_id) {
        Ok(id) => id,
        Err(_) => return not_found("connection was not found"),
    };
    let snapshot = state.control_plane.runtime_snapshot();
    let Some(record) = snapshot.managed().get(&id) else {
        if snapshot
            .legacy()
            .iter()
            .any(|projection| projection.id() == &id)
        {
            return conflict("legacy connection projections are read-only");
        }
        return not_found("connection was not found");
    };
    let current_etag = record.etag();
    match if_match_matches(&parts.headers, current_etag.as_str()) {
        Ok(true) => {}
        Ok(false) => {
            return with_etag(
                precondition_failed("If-Match does not match the current connection ETag"),
                current_etag.as_str(),
            );
        }
        Err(error) => return with_etag(if_match_error_response(error), current_etag.as_str()),
    }

    let permit = match state.tests.admit(&principal, &id) {
        Ok(permit) => permit,
        Err(error) => {
            emit_connection_tested(
                &state,
                &parts,
                &principal,
                record,
                "rejected",
                Some(error.safe_reason()),
                0,
                None,
            );
            let status = if error == connections::test::ConnectionTestAdmissionError::Unavailable {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::TOO_MANY_REQUESTS
            };
            return (
                status,
                [
                    (header::ETAG, etag_header_value(current_etag.as_str())),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
                Json(json!({
                    "error": "connection test was not admitted",
                    "reason": error.safe_reason(),
                })),
            )
                .into_response();
        }
    };

    let probe_started = Instant::now();
    let probe_deadline = tokio::time::Instant::now() + state.tests.deadline();
    let body =
        match read_request_body_before(body, state.max_body_size.min(1024), probe_deadline).await {
            Ok(body) => body,
            Err(TimedBodyReadError::DeadlineExceeded) => {
                emit_connection_tested(
                    &state,
                    &parts,
                    &principal,
                    record,
                    "rejected",
                    Some(connections::test::ConnectionTestReason::DeadlineExceeded),
                    duration_millis(probe_started.elapsed()),
                    None,
                );
                return (
                    StatusCode::REQUEST_TIMEOUT,
                    [
                        (header::ETAG, etag_header_value(current_etag.as_str())),
                        (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                    ],
                    Json(json!({
                        "error": "connection test request timed out",
                        "reason": connections::test::ConnectionTestReason::DeadlineExceeded,
                    })),
                )
                    .into_response();
            }
            Err(TimedBodyReadError::Rejected(response)) => {
                emit_connection_tested(
                    &state,
                    &parts,
                    &principal,
                    record,
                    "rejected",
                    Some(connections::test::ConnectionTestReason::RequestBodyTooLarge),
                    duration_millis(probe_started.elapsed()),
                    None,
                );
                return with_etag(*response, current_etag.as_str());
            }
        };
    if !body.is_empty() {
        emit_connection_tested(
            &state,
            &parts,
            &principal,
            record,
            "rejected",
            None,
            duration_millis(probe_started.elapsed()),
            None,
        );
        return with_etag(
            bad_request("connection test does not accept a request body"),
            current_etag.as_str(),
        );
    }

    // The test runs as the principal who asked for it: a delegated Connection
    // is tested with that principal's own token, exactly as the admin tool
    // playground calls tools as them. Every other credential ignores it.
    let tester = connections::caller_assertion::AttestedCaller::from_principal(&principal);
    let execution = state
        .tests
        .execute_before(
            record,
            current_etag.as_str(),
            tester.as_ref(),
            probe_deadline,
        )
        .await;
    let persistence = state
        .control_plane
        .append_status_before(
            &id,
            &current_etag,
            execution.status_update(),
            probe_deadline.into_std(),
        )
        .await;
    drop(permit);

    if let Err(error) = persistence {
        let reason = connection_test_status_persistence_reason(&error);
        emit_connection_tested(
            &state,
            &parts,
            &principal,
            record,
            "failure",
            Some(reason),
            execution.result.latency_ms,
            Some(&execution.result),
        );
        if connection_test_status_persistence_deadline_exceeded(&error) {
            return (
                StatusCode::REQUEST_TIMEOUT,
                [
                    (header::ETAG, etag_header_value(current_etag.as_str())),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
                Json(json!({
                    "error": "connection test request timed out",
                    "reason": connections::test::ConnectionTestReason::DeadlineExceeded,
                })),
            )
                .into_response();
        }
        return with_etag(
            connection_mutation_error_response(error),
            current_etag.as_str(),
        );
    }

    let outcome = if execution.result.ok {
        "success"
    } else {
        "failure"
    };
    let reason = execution
        .result
        .stages
        .iter()
        .rev()
        .find_map(|stage| stage.reason);
    emit_connection_tested(
        &state,
        &parts,
        &principal,
        record,
        outcome,
        reason,
        execution.result.latency_ms,
        Some(&execution.result),
    );

    (
        StatusCode::OK,
        [
            (header::ETAG, etag_header_value(current_etag.as_str())),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(execution.result),
    )
        .into_response()
}

pub(super) async fn connection_openapi_preview_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_OPENAPI_PREVIEW_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_connection_state(&state, principal, ADMIN_TOOLS_READ_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return connection_admin_authz_error_response(error),
        };
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }
    let body = match read_request_body(body, managed_openapi_admin_body_limit(&state)).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let requested = match serde_json::from_slice::<ManagedOpenApiPreviewRequest>(&body) {
        Ok(requested) => requested,
        Err(error) => {
            return bad_request(&format!("invalid managed OpenAPI preview JSON: {error}"));
        }
    };
    if requested.spec.is_empty() {
        return bad_request("spec must not be empty");
    }
    let secrets_write_authorized =
        rbac_state.principal_has_permission(principal, ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION);

    // Preview validates the candidate spec against the stored catalog; the
    // SQLite read and spec binding run on the blocking pool.
    match state
        .openapi_catalogs
        .preview_with_overlay_authorization(
            &raw_id,
            &requested.spec,
            requested.overlay.as_ref(),
            secrets_write_authorized,
        )
        .await
    {
        Ok(preview) => {
            let connection_etag = preview.connection_etag.as_str().to_owned();
            (
                StatusCode::OK,
                [
                    (header::ETAG, etag_header_value(&connection_etag)),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
                Json(managed_openapi_preview_response(preview)),
            )
                .into_response()
        }
        Err(error) => openapi_overlay_operation_error_response(error, "preview"),
    }
}

pub(super) async fn connection_openapi_overlay_get_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_OPENAPI_OVERLAY_ADMIN_ROUTE);
    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_connection_state(&state, principal, ADMIN_CONNECTIONS_READ_PERMISSION)
    {
        return connection_admin_authz_error_response(error);
    }
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }

    match state.openapi_catalogs.openapi_overlay(&raw_id).await {
        Ok((stored, etag, applied_catalog_revision)) => {
            let (document, sources, updated_at, overlay_revision) = match stored {
                Some(stored) => {
                    let document = match serde_json::from_str::<Value>(&stored.overlay_json) {
                        Ok(document) => Some(document),
                        Err(error) => {
                            tracing::error!(error = %error, connection_id = %raw_id, "stored overlay JSON could not be decoded");
                            return service_unavailable("stored OpenAPI overlay is unavailable");
                        }
                    };
                    let sources = match stored_overlay_sources(&stored) {
                        Ok(sources) => sources,
                        Err(response) => return response,
                    };
                    (
                        document,
                        sources,
                        Some(stored.updated_at),
                        stored.overlay_revision,
                    )
                }
                None => (None, Vec::new(), None, 0),
            };
            (
                StatusCode::OK,
                [
                    (header::ETAG, etag_header_value(etag.as_str())),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
                Json(ConnectionOpenApiOverlayGetResponse {
                    connection_id: match connections::model::ConnectionId::parse(raw_id) {
                        Ok(id) => id,
                        Err(_) => return not_found("connection was not found"),
                    },
                    etag: etag.as_str().to_owned(),
                    overlay_revision,
                    applied_catalog_revision: applied_catalog_revision.unwrap_or(0),
                    document,
                    sources,
                    updated_at,
                }),
            )
                .into_response()
        }
        Err(error) => openapi_catalog_error_response(error, "overlay read"),
    }
}

pub(super) async fn connection_openapi_overlay_put_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    Query(params): Query<OpenApiOverlayPutParams>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_OPENAPI_OVERLAY_ADMIN_ROUTE);
    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_connection_state(&state, &principal, ADMIN_CONNECTIONS_WRITE_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return connection_admin_authz_error_response(error),
        };
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }
    let expected_etag = match exact_strong_if_match(&parts.headers) {
        Ok(etag) => etag,
        Err(ToolPlaygroundIfMatchError::Missing) => {
            return precondition_required("If-Match header is required");
        }
        Err(ToolPlaygroundIfMatchError::Invalid) => {
            return bad_request("If-Match must contain exactly one strong entity tag");
        }
    };
    let body = match read_request_body(body, tools::overlay::MAX_OVERLAY_BYTES).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let document = match serde_json::from_slice::<Value>(&body) {
        Ok(document) => document,
        Err(error) => return bad_request(&format!("invalid OpenAPI overlay JSON: {error}")),
    };
    let secrets_write_authorized =
        rbac_state.principal_has_permission(&principal, ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION);
    // The document's own validity and the secret authority it needs are
    // judged before its caller key is bound and the gates are asked (issue
    // #425): admission can raise the cluster's contract fence. The catalog
    // service judges both again under its lifecycle guard.
    match tools::overlay::validate(&document) {
        Ok(validated) if validated.has_raw_path_sources() && !secrets_write_authorized => {
            return openapi_overlay_operation_error_response(
                connections::openapi::OpenApiOverlayOperationError::SecretsWriteRequired,
                "overlay update",
            );
        }
        Ok(_) => {}
        Err(error) => {
            return openapi_overlay_operation_error_response(
                connections::openapi::OpenApiOverlayOperationError::Rejected(error),
                "overlay update",
            );
        }
    }
    if let Err(response) = managed_overlay_target(&state, &raw_id, "overlay update") {
        return *response;
    }
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    let caller = match admit_keyed_connection_change(
        &state,
        &parts,
        &principal,
        &actor,
        KeyedConnectionChange::CatalogOverlayReplace,
        &body,
        &raw_id,
    )
    .await
    {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    mutate_openapi_overlay(&state, &parts, &principal, "overlay update", |admission| {
        state.openapi_catalogs.put_overlay_with_operation(
            &raw_id,
            &expected_etag,
            &document,
            params.allow_unresolved_enum_sources,
            secrets_write_authorized,
            admission,
            &actor,
            caller.as_ref(),
        )
    })
    .await
}

/// The Connection an overlay change names, judged before its caller key is
/// bound (issue #425): an identifier that does not parse, or a Connection
/// that is not managed, is answered as the catalog service answers it, and
/// nothing is admitted. The catalog service judges it again.
fn managed_overlay_target(
    state: &ConnectionAdminState,
    raw_id: &str,
    operation: &'static str,
) -> ResponseResult<()> {
    let refused = |error| {
        Box::new(openapi_overlay_operation_error_response(
            connections::openapi::OpenApiOverlayOperationError::Catalog(error),
            operation,
        ))
    };
    let id = connections::model::ConnectionId::parse(raw_id.to_owned())
        .map_err(|_| refused(connections::openapi::OpenApiCatalogError::InvalidConnectionId))?;
    if state
        .control_plane
        .runtime_snapshot()
        .managed()
        .contains_key(&id)
    {
        Ok(())
    } else {
        Err(refused(
            connections::openapi::OpenApiCatalogError::ConnectionNotFound,
        ))
    }
}

pub(super) async fn connection_openapi_overlay_delete_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_OPENAPI_OVERLAY_ADMIN_ROUTE);
    let (parts, _) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_connection_state(&state, &principal, ADMIN_CONNECTIONS_WRITE_PERMISSION)
    {
        return connection_admin_authz_error_response(error);
    }
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }
    let expected_etag = match exact_strong_if_match(&parts.headers) {
        Ok(etag) => etag,
        Err(ToolPlaygroundIfMatchError::Missing) => {
            return precondition_required("If-Match header is required");
        }
        Err(ToolPlaygroundIfMatchError::Invalid) => {
            return bad_request("If-Match must contain exactly one strong entity tag");
        }
    };
    if let Err(response) = managed_overlay_target(&state, &raw_id, "overlay delete") {
        return *response;
    }
    // Removing the overlay publishes a new catalog revision: it binds its
    // caller key as a publication, not as a withdrawal (issue #425).
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    let caller = match admit_keyed_connection_change(
        &state,
        &parts,
        &principal,
        &actor,
        KeyedConnectionChange::CatalogOverlayDelete,
        b"",
        &raw_id,
    )
    .await
    {
        Ok(caller) => caller,
        Err(response) => return *response,
    };
    mutate_openapi_overlay(&state, &parts, &principal, "overlay delete", |admission| {
        state.openapi_catalogs.delete_overlay_with_operation(
            &raw_id,
            &expected_etag,
            admission,
            &actor,
            caller.as_ref(),
        )
    })
    .await
}

async fn mutate_openapi_overlay<Fut>(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    operation: &'static str,
    apply: impl Fn(connections::openapi::ConvertedCatalogAdmission) -> Fut,
) -> Response
where
    Fut: std::future::Future<
            Output = Result<
                authority_events::caller_operation::CallerOutcome<
                    connections::openapi::OpenApiOverlayMutationResult,
                >,
                connections::openapi::OpenApiOverlayOperationError,
            >,
        > + Send,
{
    use authority_events::caller_operation::CallerOutcome;
    use connections::openapi::{
        ConvertedCatalogAdmission, OpenApiCatalogError, OpenApiOverlayOperationError,
    };
    let mut updated = apply(ConvertedCatalogAdmission::NotAsked).await;
    if let Err(OpenApiOverlayOperationError::Catalog(
        OpenApiCatalogError::ConvertedCatalogNeedsAdmission { requirement },
    )) = &updated
    {
        if let Err(refusal) =
            admit_converted_openapi_catalog(state, parts, principal, *requirement).await
        {
            return *refusal.response;
        }
        updated = apply(ConvertedCatalogAdmission::Admitted(*requirement)).await;
    }
    match updated {
        Ok(CallerOutcome::Committed(result)) => {
            emit_managed_openapi_catalog_changed(state, parts, principal, &result.catalog);
            overlay_mutation_response(result)
        }
        // An exact retry: no publication, no audit event.
        Ok(CallerOutcome::Replayed(receipt)) => operation_receipt(&receipt),
        Err(error) => openapi_overlay_operation_error_response(error, operation),
    }
}

/// The operation gate refused to store a converted managed OpenAPI catalog.
/// Nothing was written; `reason` is the refusal's stable code.
pub(super) struct ConvertedCatalogRefusal {
    pub(super) reason: &'static str,
    pub(super) response: Box<Response>,
}

/// An enrolled Connection is durable. Fence older replicas out before the
/// first PostgreSQL write so they cannot join later and serve the profile.
async fn admit_mutation_approval_enrollment(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    candidate: &connections::model::ConnectionWrite,
) -> ResponseResult<()> {
    if !candidate.uses_managed_mutation_approval() {
        return Ok(());
    }
    #[cfg(feature = "postgres")]
    {
        let refusal = storage::compatibility::OperationRefusal::RosterUnavailable;
        let store = state
            .control_plane
            .managed_store()
            .map_err(|_| Box::new(operation_refused(&refusal)))?;
        if store.sqlite().is_none() {
            let membership = state
                .membership
                .as_ref()
                .ok_or_else(|| Box::new(operation_refused(&refusal)))?;
            let request = cluster_membership::GatedWriteRequest {
                request_id: client_ip::request_id(&parts.headers, &parts.extensions),
                source_ip: client_ip::canonical_client_ip(
                    &parts.headers,
                    &parts.extensions,
                    &state.client_ip_policy,
                ),
                actor: Some(auth::actor_from_principal(principal)),
            };
            membership
                .admit_operation(
                    &storage::compatibility::MANAGED_HTTP_MUTATION_V1,
                    &state.audit,
                    &request,
                )
                .await
                .map_err(|error| Box::new(operation_refused(&error)))?;
        }
    }
    #[cfg(not(feature = "postgres"))]
    let _ = (state, parts, principal);
    Ok(())
}

/// Ask the cluster's operation gate before storing a managed OpenAPI catalog
/// generated from a Swagger 2.0 or Google Discovery document (issue #443).
///
/// The catalog service answers `ConvertedCatalogNeedsAdmission`, before it
/// writes or records anything, only when it gates converted catalogs
/// (cluster mode) and only for a converted document, so an OpenAPI 3.x
/// document asks only when it generates repeated query mappings. The write is the registered operation for its
/// source format, `connections.openapi_swagger2_catalog` or
/// `connections.openapi_discovery_catalog`: it proceeds only while every
/// live member, draining ones included, advertises that format's capability
/// (`openapi_swagger2_catalogs` or `openapi_discovery_catalogs`), because a
/// member built before the conversion cannot regenerate from the stored
/// document. The gate reads the roster for every such write and logs and
/// audits each refusal (`cluster.operation_refused`). A deployment with no
/// roster to ask refuses rather than admits.
pub(super) async fn admit_converted_openapi_catalog(
    state: &ConnectionAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    requirement: connections::openapi::CatalogWriteRequirement,
) -> Result<(), ConvertedCatalogRefusal> {
    #[cfg(feature = "postgres")]
    {
        use connections::openapi::CatalogWriteRequirement;

        let (format, repeated) = match requirement {
            CatalogWriteRequirement::Converted(format) => (Some(format), false),
            CatalogWriteRequirement::RepeatedQuery { source_format } => (source_format, true),
        };
        let format_requirement = format.map(|format| match format {
            tools::openapi::OpenApiSourceFormat::Swagger2 => {
                &storage::compatibility::OPENAPI_SWAGGER2_CATALOGS
            }
            tools::openapi::OpenApiSourceFormat::GoogleDiscovery => {
                &storage::compatibility::OPENAPI_DISCOVERY_CATALOGS
            }
        });
        let repeated_requirement =
            repeated.then_some(&storage::compatibility::OPENAPI_REPEATED_QUERY);
        let Some(membership) = state.membership.as_ref() else {
            tracing::error!(
                "a gated managed OpenAPI write has no roster to ask; the write is refused"
            );
            let refusal = storage::compatibility::OperationRefusal::RosterUnavailable;
            return Err(ConvertedCatalogRefusal {
                reason: refusal.reason(),
                response: Box::new(operation_refused(&refusal)),
            });
        };
        let request = cluster_membership::GatedWriteRequest {
            request_id: client_ip::request_id(&parts.headers, &parts.extensions),
            source_ip: client_ip::canonical_client_ip(
                &parts.headers,
                &parts.extensions,
                &state.client_ip_policy,
            ),
            actor: Some(auth::actor_from_principal(principal)),
        };
        for requirement in format_requirement.into_iter().chain(repeated_requirement) {
            membership
                .admit_operation(requirement, &state.audit, &request)
                .await
                .map_err(|refusal| ConvertedCatalogRefusal {
                    reason: refusal.reason(),
                    response: Box::new(operation_refused(&refusal)),
                })?;
        }
        Ok(())
    }
    // A build without cluster mode has no roster, and its catalog service
    // never gates outside tests; refuse exactly as a roster-less cluster
    // deployment does.
    #[cfg(not(feature = "postgres"))]
    {
        let _ = (state, parts, principal, requirement);
        tracing::error!("a gated managed OpenAPI write has no roster to ask; the write is refused");
        Err(ConvertedCatalogRefusal {
            reason: "roster_unavailable",
            response: Box::new(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": "no cluster roster can be read, so no live member can be shown to \
                                  support the operation; nothing was written",
                        "reason": "roster_unavailable",
                    })),
                )
                    .into_response(),
            ),
        })
    }
}

pub(super) async fn connection_openapi_register_endpoint(
    State(state): State<ConnectionAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(CONNECTION_OPENAPI_REGISTER_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) =
        authorized_connection_state(&state, &principal, ADMIN_TOOLS_WRITE_PERMISSION)
    {
        return connection_admin_authz_error_response(error);
    }
    if !state.control_plane.is_managed_store_configured() {
        return connection_store_not_configured();
    }
    let id = match connections::model::ConnectionId::parse(raw_id.clone()) {
        Ok(id) => id,
        Err(_) => return not_found("connection was not found"),
    };
    let snapshot = state.control_plane.runtime_snapshot();
    let Some(record) = snapshot.managed().get(&id) else {
        if snapshot
            .legacy()
            .iter()
            .any(|projection| projection.id() == &id)
        {
            return conflict("legacy connection projections are read-only");
        }
        return not_found("connection was not found");
    };
    let current_etag = record.etag();
    match if_match_matches(&parts.headers, current_etag.as_str()) {
        Ok(true) => {}
        Ok(false) => {
            return with_etag(
                precondition_failed("If-Match does not match the current connection ETag"),
                current_etag.as_str(),
            );
        }
        Err(error) => return with_etag(if_match_error_response(error), current_etag.as_str()),
    }
    let body = match read_request_body(body, managed_openapi_admin_body_limit(&state)).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let requested = match serde_json::from_slice::<ManagedOpenApiRegisterRequest>(&body) {
        Ok(requested) => requested,
        Err(error) => {
            return bad_request(&format!("invalid managed OpenAPI register JSON: {error}"));
        }
    };
    // The specification's size and its preview digest are the request's own
    // to get right: judged before its caller key is bound (issue #425), and
    // again by the catalog service.
    if let Err(error) =
        connections::openapi::check_registration_spec(&requested.spec, &requested.spec_digest)
    {
        emit_managed_openapi_catalog_rejected(&state, &parts, &principal, &id, error.safe_reason());
        return with_etag(
            openapi_catalog_error_response(error, "register"),
            current_etag.as_str(),
        );
    }
    let confirmations = requested
        .security_confirmations
        .into_iter()
        .map(|selection| tools::openapi::OpenApiToolSecuritySelection {
            tool_name: selection.tool_name,
            selected_scheme_names: selection.selected_scheme_names,
        })
        .collect::<Vec<_>>();

    // Authorized and validated: bind the caller key, ask the gates, and
    // answer an exact retry from its receipt before anything is generated or
    // resolved (issue #425). A registration publishes a catalog revision and
    // leaves the Connection's ETag where it was.
    let actor = auth::change_actor::ChangeActor::from_principal(&principal);
    let caller = match admit_keyed_connection_change(
        &state,
        &parts,
        &principal,
        &actor,
        KeyedConnectionChange::CatalogOpenApiPublish,
        &body,
        id.as_str(),
    )
    .await
    {
        Ok(caller) => caller,
        Err(response) => return *response,
    };

    // At most two passes: the second only after the operation gate admitted
    // a converted document the first pass stopped at, before writing.
    let mut converted_catalog = connections::openapi::ConvertedCatalogAdmission::NotAsked;
    let registered = loop {
        let result = state
            .openapi_catalogs
            .register_with_operation(
                id.as_str(),
                current_etag.as_str(),
                requested.expected_spec_revision,
                requested.expected_catalog_revision,
                &requested.spec_digest,
                &requested.spec,
                &requested.selected_tool_names,
                &confirmations,
                converted_catalog,
                &actor,
                caller.as_ref(),
            )
            .await;
        if let (
            connections::openapi::ConvertedCatalogAdmission::NotAsked,
            Err(connections::openapi::OpenApiCatalogError::ConvertedCatalogNeedsAdmission {
                requirement,
            }),
        ) = (converted_catalog, &result)
        {
            let requirement = *requirement;
            if let Err(refusal) =
                admit_converted_openapi_catalog(&state, &parts, &principal, requirement).await
            {
                emit_managed_openapi_catalog_rejected(
                    &state,
                    &parts,
                    &principal,
                    &id,
                    refusal.reason,
                );
                return with_etag(*refusal.response, current_etag.as_str());
            }
            converted_catalog =
                connections::openapi::ConvertedCatalogAdmission::Admitted(requirement);
            continue;
        }
        break result;
    };
    match registered {
        // An exact retry: no publication, no audit event.
        Ok(authority_events::caller_operation::CallerOutcome::Replayed(receipt)) => {
            operation_receipt(&receipt)
        }
        Ok(authority_events::caller_operation::CallerOutcome::Committed(result)) => {
            emit_managed_openapi_catalog_changed(&state, &parts, &principal, &result);
            (
                StatusCode::CREATED,
                [
                    (header::ETAG, etag_header_value(current_etag.as_str())),
                    (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
                ],
                Json(result),
            )
                .into_response()
        }
        Err(error) => {
            emit_managed_openapi_catalog_rejected(
                &state,
                &parts,
                &principal,
                &id,
                error.safe_reason(),
            );
            with_etag(
                openapi_catalog_error_response(error, "register"),
                current_etag.as_str(),
            )
        }
    }
}

pub(super) async fn read_request_body(body: Body, max_body_size: usize) -> ResponseResult<Bytes> {
    axum::body::to_bytes(body, max_body_size)
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "request body exceeded the configured limit or could not be read");
            Box::new(payload_too_large(max_body_size))
        })
}

pub(super) async fn read_connection_secret_body(
    body: Body,
    max_body_size: usize,
) -> ResponseResult<Zeroizing<Vec<u8>>> {
    let bytes = axum::body::to_bytes(body, max_body_size)
        .await
        .map_err(|_| {
            tracing::warn!(
                reason = "body_rejected",
                maximum_bytes = max_body_size,
                "connection-secret request body exceeded its limit or could not be read"
            );
            Box::new(payload_too_large(max_body_size))
        })?;
    match bytes.try_into_mut() {
        Ok(mut mutable) => {
            let owned = Zeroizing::new(mutable.to_vec());
            mutable.as_mut().zeroize();
            Ok(owned)
        }
        Err(bytes) => Ok(Zeroizing::new(bytes.as_ref().to_vec())),
    }
}

pub(super) async fn read_request_body_before(
    body: Body,
    max_body_size: usize,
    deadline: tokio::time::Instant,
) -> Result<Bytes, TimedBodyReadError> {
    match tokio::time::timeout_at(deadline, read_request_body(body, max_body_size)).await {
        Ok(Ok(body)) => Ok(body),
        Ok(Err(response)) => Err(TimedBodyReadError::Rejected(response)),
        Err(_) => Err(TimedBodyReadError::DeadlineExceeded),
    }
}

pub(super) fn connection_admin_body_limit(state: &ConnectionAdminState) -> usize {
    state
        .max_body_size
        .min(connections::admin::MAX_CONNECTION_ADMIN_BODY_BYTES)
}

pub(super) fn connection_secret_admin_body_limit(state: &ConnectionAdminState) -> usize {
    state
        .max_body_size
        .min(connections::secret::MAX_TLS_CERTIFICATE_BYTES.saturating_add(16 * 1024))
}

pub(super) fn managed_openapi_admin_body_limit(state: &ConnectionAdminState) -> usize {
    state.max_body_size.min(
        connections::model::MAX_MANAGED_SPEC_BYTES
            .saturating_mul(6)
            .saturating_add(MANAGED_OPENAPI_JSON_ENVELOPE_OVERHEAD_BYTES),
    )
}

pub(super) fn parse_connection_write_body(
    body: &Bytes,
    current: &connections::model::ConnectionWrite,
) -> ResponseResult<connections::model::ConnectionWrite> {
    let mut candidate = serde_json::from_slice::<Value>(body)
        .map_err(|_| Box::new(bad_request("invalid connection JSON")))?;
    retain_hidden_connection_bindings(&mut candidate, current)?;
    // The admin UI sends `caller_assertion` only when the operator edits the
    // block, so a routine edit (a display name, the enabled flag, a secret
    // rotation) leaves it out. Reading that omission as removal would quietly
    // stop attesting the caller and serve the Connection's calls unattested.
    // An omitted block is therefore kept, and removing it takes an explicit
    // `"caller_assertion": null`. The body is known to be an object here, so a
    // missing key and an explicit `null` are distinct.
    let caller_assertion_omitted = candidate.get("caller_assertion").is_none();
    let mut candidate = serde_json::from_value::<connections::model::ConnectionWrite>(candidate)
        .map_err(|_| Box::new(bad_request("invalid connection JSON")))?;
    if caller_assertion_omitted {
        candidate.caller_assertion = current.caller_assertion.clone();
    }
    validate_connection_write(candidate)
}

/// A Connection replacement body judged without the record it names: what a
/// keyed `PUT` for a Connection that is no longer in the snapshot checks
/// before its caller key is bound (issue #425). Everything that does not
/// need the stored record is checked as a replacement is: the body is a
/// JSON object, every redacted-binding marker is a boolean that is not
/// combined with an explicit binding and does not clear a caller-assertion
/// key, and the result is a valid Connection specification. A marker that
/// keeps a hidden binding stands for one that passes validation, because
/// only the stored record could say which binding it keeps and whether it
/// matches. Nothing is read or written.
pub(super) fn validate_connection_replacement_without_record(body: &Bytes) -> ResponseResult<()> {
    /// The binding a replacement keeps by marker, as far as validation
    /// sees it. It is never stored or bound: the caller key binds the body
    /// as received.
    const KEPT_BINDING: &str = "kept-binding";

    fn keep(
        object: &mut serde_json::Map<String, Value>,
        marker_field: &'static str,
        binding_field: &'static str,
    ) -> ResponseResult<()> {
        let marker = take_redacted_marker(object, marker_field)?;
        if object.contains_key(binding_field) && marker.is_some() {
            return Err(Box::new(bad_request(
                "redacted connection binding markers cannot be combined with explicit binding IDs",
            )));
        }
        if marker == Some(true) {
            object.insert(
                binding_field.to_owned(),
                Value::String(KEPT_BINDING.to_owned()),
            );
        }
        Ok(())
    }

    fn keep_caller_assertion_key(key: &mut serde_json::Map<String, Value>) -> ResponseResult<()> {
        if key.get("signing_key_configured") == Some(&Value::Bool(false)) {
            return Err(Box::new(bad_request(
                "a caller assertion key cannot be cleared; leave the key out instead",
            )));
        }
        keep(key, "signing_key_configured", "signing_key_id")
    }

    let mut candidate = serde_json::from_slice::<Value>(body)
        .map_err(|_| Box::new(bad_request("invalid connection JSON")))?;
    let object = candidate
        .as_object_mut()
        .ok_or_else(|| Box::new(bad_request("connection JSON must be an object")))?;
    if let Some(authentication) = object
        .get_mut("authentication")
        .and_then(Value::as_object_mut)
    {
        keep(authentication, "secret_configured", "secret_id")?;
        keep(
            authentication,
            "client_secret_configured",
            "client_secret_id",
        )?;
    }
    if let Some(headers) = object
        .get_mut("additional_headers")
        .and_then(Value::as_array_mut)
    {
        for header in headers.iter_mut().filter_map(Value::as_object_mut) {
            keep(header, "secret_configured", "secret_id")?;
        }
    }
    if let Some(assertion) = object
        .get_mut("caller_assertion")
        .and_then(Value::as_object_mut)
    {
        keep_caller_assertion_key(assertion)?;
        if let Some(keys) = assertion
            .get_mut("published_keys")
            .and_then(Value::as_array_mut)
        {
            for key in keys.iter_mut().filter_map(Value::as_object_mut) {
                keep_caller_assertion_key(key)?;
            }
        }
    }
    if let Some(tls) = object.get_mut("tls").and_then(Value::as_object_mut) {
        keep(tls, "ca_bundle_configured", "ca_bundle_alias")?;
        keep(
            tls,
            "client_certificate_configured",
            "client_certificate_id",
        )?;
        keep(
            tls,
            "client_private_key_configured",
            "client_private_key_id",
        )?;
    }
    let candidate = serde_json::from_value::<connections::model::ConnectionWrite>(candidate)
        .map_err(|_| Box::new(bad_request("invalid connection JSON")))?;
    validate_connection_write(candidate).map(|_| ())
}

pub(super) fn explicit_connection_binding_intent_from_body(body: &Bytes) -> ResponseResult<bool> {
    let candidate = serde_json::from_slice::<Value>(body)
        .map_err(|_| Box::new(bad_request("invalid connection JSON")))?;
    Ok(has_explicit_connection_binding_intent(&candidate))
}

pub(super) fn has_explicit_connection_binding_intent(candidate: &Value) -> bool {
    candidate
        .get("authentication")
        .and_then(Value::as_object)
        .is_some_and(|authentication| {
            authentication.contains_key("secret_id")
                || authentication.contains_key("client_secret_id")
        })
        || candidate
            .get("additional_headers")
            .and_then(Value::as_array)
            .is_some_and(|headers| {
                headers.iter().any(|header| {
                    header
                        .as_object()
                        .is_some_and(|header| header.contains_key("secret_id"))
                })
            })
        || candidate
            .get("tls")
            .and_then(Value::as_object)
            .is_some_and(|tls| {
                tls.contains_key("ca_bundle_alias")
                    || tls.contains_key("client_certificate_id")
                    || tls.contains_key("client_private_key_id")
            })
        // A caller assertion's key aliases are hidden like every other
        // binding. Naming one is secret authority even when it matches what is
        // stored, or a principal without it could learn a hidden alias by
        // sending guesses and seeing which save goes through unchanged.
        || candidate
            .get("caller_assertion")
            .and_then(Value::as_object)
            .is_some_and(|assertion| {
                assertion.contains_key("signing_key_id")
                    || assertion
                        .get("published_keys")
                        .and_then(Value::as_array)
                        .is_some_and(|keys| {
                            keys.iter().any(|key| {
                                key.as_object()
                                    .is_some_and(|key| key.contains_key("signing_key_id"))
                            })
                        })
            })
}

pub(super) fn retain_hidden_connection_bindings(
    candidate: &mut Value,
    current: &connections::model::ConnectionWrite,
) -> ResponseResult<()> {
    let object = candidate
        .as_object_mut()
        .ok_or_else(|| Box::new(bad_request("connection JSON must be an object")))?;
    let authentication = object
        .get_mut("authentication")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Box::new(bad_request("connection authentication must be an object")))?;
    let authentication_type = authentication
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| Box::new(bad_request("connection authentication type is required")))?;

    match (&current.authentication, authentication_type) {
        (
            connections::model::ConnectionAuthentication::HeaderApiKey { secret_id, .. },
            "header_api_key",
        )
        | (
            connections::model::ConnectionAuthentication::StaticBearer { secret_id },
            "static_bearer",
        ) => retain_hidden_binding(
            authentication,
            "secret_id",
            "secret_configured",
            secret_id.as_deref(),
            true,
        )?,
        (
            connections::model::ConnectionAuthentication::OAuth2ClientCredentials {
                client_secret_id,
                ..
            },
            "oauth2_client_credentials",
        )
        | (
            connections::model::ConnectionAuthentication::DelegatedIssuerToken {
                client_secret_id,
                ..
            },
            "delegated_issuer_token",
        ) => retain_hidden_binding(
            authentication,
            "client_secret_id",
            "client_secret_configured",
            client_secret_id.as_deref(),
            true,
        )?,
        _ => {
            reject_redacted_marker(authentication, "secret_configured")?;
            reject_redacted_marker(authentication, "client_secret_configured")?;
        }
    }

    // Additional headers are matched to the current document by header name
    // (case-insensitively; the model lowercases on validation). A marker on
    // a header the current document does not carry has nothing to retain.
    if let Some(headers) = object
        .get_mut("additional_headers")
        .and_then(Value::as_array_mut)
    {
        for header in headers.iter_mut() {
            let header = header.as_object_mut().ok_or_else(|| {
                Box::new(bad_request(
                    "connection additional_headers entries must be objects",
                ))
            })?;
            let header_name = header
                .get("header_name")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                .ok_or_else(|| {
                    Box::new(bad_request(
                        "connection additional_headers entries require a header_name",
                    ))
                })?;
            let current_secret = current
                .additional_headers
                .iter()
                .find(|current| current.header_name.eq_ignore_ascii_case(&header_name));
            match current_secret {
                Some(current) => retain_hidden_binding(
                    header,
                    "secret_id",
                    "secret_configured",
                    current.secret_id.as_deref(),
                    true,
                )?,
                None => reject_redacted_marker(header, "secret_configured")?,
            }
        }
    }

    if let Some(assertion) = object
        .get_mut("caller_assertion")
        .and_then(Value::as_object_mut)
    {
        retain_hidden_caller_assertion_keys(assertion, current.caller_assertion.as_ref())?;
    }

    let tls = object
        .entry("tls")
        .or_insert_with(|| Value::Object(serde_json::Map::new()))
        .as_object_mut()
        .ok_or_else(|| {
            Box::new(bad_request(
                "connection TLS configuration must be an object",
            ))
        })?;
    retain_hidden_binding(
        tls,
        "ca_bundle_alias",
        "ca_bundle_configured",
        current.tls.ca_bundle_alias.as_deref(),
        true,
    )?;
    retain_hidden_binding(
        tls,
        "client_certificate_id",
        "client_certificate_configured",
        current.tls.client_certificate_id.as_deref(),
        true,
    )?;
    retain_hidden_binding(
        tls,
        "client_private_key_id",
        "client_private_key_configured",
        current.tls.client_private_key_id.as_deref(),
        true,
    )
}

/// Keeps the hidden alias of each caller-assertion key a replacement marks
/// `"signing_key_configured": true`: the signing key and every entry in
/// `published_keys`.
///
/// A marked key is matched to the stored key with the same `kid` and
/// algorithm, wherever that key is in the stored block, rather than to the key
/// in the same position. A rotation moves a key between `signing_key_id` and
/// `published_keys` in one `PUT` (see the operator guide), and a `kid` names
/// exactly one key, so keeping the alias stored under it is the only reading
/// that cannot put other key material behind a published `kid`. A marker that
/// matches no stored key is refused rather than ignored, and `false` is
/// refused because a key cannot be unbound: leave the key out, or remove the
/// block, instead.
fn retain_hidden_caller_assertion_keys(
    assertion: &mut serde_json::Map<String, Value>,
    current: Option<&connections::model::CallerAssertionSettings>,
) -> ResponseResult<()> {
    retain_hidden_caller_assertion_key(assertion, current)?;
    if let Some(keys) = assertion
        .get_mut("published_keys")
        .and_then(Value::as_array_mut)
    {
        for key in keys.iter_mut() {
            let key = key.as_object_mut().ok_or_else(|| {
                Box::new(bad_request(
                    "caller_assertion published_keys entries must be objects",
                ))
            })?;
            retain_hidden_caller_assertion_key(key, current)?;
        }
    }
    Ok(())
}

fn retain_hidden_caller_assertion_key(
    key: &mut serde_json::Map<String, Value>,
    current: Option<&connections::model::CallerAssertionSettings>,
) -> ResponseResult<()> {
    let Some(marker) = take_redacted_marker(key, "signing_key_configured")? else {
        return Ok(());
    };
    if key.contains_key("signing_key_id") {
        return Err(Box::new(bad_request(
            "redacted connection binding markers cannot be combined with explicit binding IDs",
        )));
    }
    if !marker {
        return Err(Box::new(bad_request(
            "a caller assertion key cannot be cleared; leave the key out instead",
        )));
    }
    let kid = key.get("kid").and_then(Value::as_str);
    let algorithm = key.get("algorithm").cloned().and_then(|algorithm| {
        serde_json::from_value::<connections::model::CallerAssertionAlgorithm>(algorithm).ok()
    });
    let stored = current.and_then(|current| {
        current
            .keys()
            .find(|stored| Some(stored.kid) == kid && Some(stored.algorithm) == algorithm)
    });
    let Some(stored) = stored else {
        return Err(Box::new(bad_request(
            "redacted connection binding marker does not match the current resource",
        )));
    };
    key.insert(
        "signing_key_id".to_owned(),
        Value::String(stored.signing_key_id.to_owned()),
    );
    Ok(())
}

pub(super) fn retain_hidden_binding(
    object: &mut serde_json::Map<String, Value>,
    binding_field: &'static str,
    marker_field: &'static str,
    current: Option<&str>,
    allow_preserve: bool,
) -> ResponseResult<()> {
    let marker = take_redacted_marker(object, marker_field)?;
    retain_hidden_binding_with_marker(object, binding_field, current, marker, allow_preserve)
}

pub(super) fn retain_hidden_binding_with_marker(
    object: &mut serde_json::Map<String, Value>,
    binding_field: &'static str,
    current: Option<&str>,
    marker: Option<bool>,
    allow_preserve: bool,
) -> ResponseResult<()> {
    if object.contains_key(binding_field) {
        if marker.is_some() {
            return Err(Box::new(bad_request(
                "redacted connection binding markers cannot be combined with explicit binding IDs",
            )));
        }
        return Ok(());
    }
    if !allow_preserve {
        if marker.is_some() {
            return Err(Box::new(bad_request(
                "redacted connection binding marker cannot be used for a different authentication type",
            )));
        }
        return Ok(());
    }
    if marker == Some(false) {
        return Ok(());
    }
    if let Some(current) = current {
        object.insert(binding_field.to_owned(), Value::String(current.to_owned()));
        Ok(())
    } else if marker == Some(true) {
        Err(Box::new(bad_request(
            "redacted connection binding marker does not match the current resource",
        )))
    } else {
        Ok(())
    }
}

pub(super) fn take_redacted_marker(
    object: &mut serde_json::Map<String, Value>,
    marker_field: &'static str,
) -> ResponseResult<Option<bool>> {
    object
        .remove(marker_field)
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                Box::new(bad_request(
                    "redacted connection binding marker must be a boolean",
                ))
            })
        })
        .transpose()
}

pub(super) fn reject_redacted_marker(
    object: &mut serde_json::Map<String, Value>,
    marker_field: &'static str,
) -> ResponseResult<()> {
    if object.contains_key(marker_field) {
        Err(Box::new(bad_request(
            "redacted connection binding marker cannot be used for a different authentication type",
        )))
    } else {
        Ok(())
    }
}

pub(super) fn parse_connection_create_body(
    body: &Bytes,
) -> ResponseResult<connections::model::ConnectionWrite> {
    let mut candidate = serde_json::from_slice::<Value>(body)
        .map_err(|_| Box::new(bad_request("invalid connection JSON")))?;
    let object = candidate
        .as_object_mut()
        .ok_or_else(|| Box::new(bad_request("connection JSON must be an object")))?;
    object.entry("enabled").or_insert(Value::Bool(false));
    let candidate = serde_json::from_value::<connections::model::ConnectionWrite>(candidate)
        .map_err(|_| Box::new(bad_request("invalid connection JSON")))?;
    validate_connection_write(candidate)
}

pub(super) fn validate_connection_write(
    candidate: connections::model::ConnectionWrite,
) -> ResponseResult<connections::model::ConnectionWrite> {
    candidate.validated().map_err(|problems| {
        Box::new(
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ConnectionValidationResponse {
                    error: "connection validation failed",
                    problems: problems
                        .into_iter()
                        .map(|problem| ConnectionValidationProblem {
                            field: problem.field,
                            code: problem.code,
                        })
                        .collect(),
                }),
            )
                .into_response(),
        )
    })
}

pub(super) fn connection_secret_dependency_counts(
    snapshot: &connections::control_plane::ConnectionRuntimeSnapshot,
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for record in snapshot.managed().values() {
        let authentication_id = match &record.write.authentication {
            connections::model::ConnectionAuthentication::HeaderApiKey { secret_id, .. }
            | connections::model::ConnectionAuthentication::StaticBearer { secret_id } => {
                secret_id.as_deref()
            }
            connections::model::ConnectionAuthentication::OAuth2ClientCredentials {
                client_secret_id,
                ..
            }
            | connections::model::ConnectionAuthentication::DelegatedIssuerToken {
                client_secret_id,
                ..
            } => client_secret_id.as_deref(),
            connections::model::ConnectionAuthentication::None
            | connections::model::ConnectionAuthentication::GoogleDomainWideDelegation { .. } => {
                None
            }
        };
        for id in [
            authentication_id,
            record.write.tls.ca_bundle_alias.as_deref(),
            record.write.tls.client_certificate_id.as_deref(),
            record.write.tls.client_private_key_id.as_deref(),
        ]
        .into_iter()
        .chain(
            record
                .write
                .additional_headers
                .iter()
                .map(|header| header.secret_id.as_deref()),
        )
        .flatten()
        {
            *counts.entry(id.to_owned()).or_default() += 1;
        }
    }
    counts
}

pub(super) fn lock_connection_secret_mutations(
    lock: &std::sync::Mutex<()>,
) -> ResponseResult<std::sync::MutexGuard<'_, ()>> {
    match lock.lock() {
        Ok(guard) => Ok(guard),
        Err(_) => {
            tracing::error!(
                "connection-secret endpoint mutation lock poisoned; rejecting ambiguous mutation"
            );
            Err(Box::new(service_unavailable(
                "connection-secret mutation coordination is unavailable",
            )))
        }
    }
}

pub(super) fn local_secret_metadata(
    control_plane: &connections::control_plane::ConnectionControlPlane,
    id: &str,
) -> ResponseResult<connections::secret::SecretAliasMetadata> {
    let Some(metadata) = control_plane
        .secret_alias_metadata()
        .into_iter()
        .find(|metadata| metadata.id == id)
    else {
        return Err(Box::new(not_found("connection secret was not found")));
    };
    if metadata.provider != connections::secret::SecretProviderKind::LocalEncrypted {
        return Err(Box::new(conflict(
            "operator-provisioned secret aliases are read-only",
        )));
    }
    Ok(metadata)
}

pub(super) fn connection_secret_validation_error() -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({
            "error": "connection-secret validation failed",
        })),
    )
        .into_response()
}

pub(super) fn connection_secret_error_response(
    error: connections::local_secret::LocalSecretError,
) -> Response {
    match error {
        connections::local_secret::LocalSecretError::InvalidLabel
        | connections::local_secret::LocalSecretError::InvalidSecret => {
            connection_secret_validation_error()
        }
        connections::local_secret::LocalSecretError::NotFound => {
            not_found("connection secret was not found")
        }
        connections::local_secret::LocalSecretError::LimitExceeded { .. }
        | connections::local_secret::LocalSecretError::IdentifierCollision => {
            conflict("connection-secret capacity has been reached")
        }
        connections::local_secret::LocalSecretError::DependencyConflict {
            connection_ids,
            count,
        } => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": "connection secret is referenced by managed connections",
                "dependency_count": count,
                "connection_ids": connection_ids,
            })),
        )
            .into_response(),
        other => {
            tracing::error!(
                reason = %other,
                "encrypted local connection-secret operation failed"
            );
            service_unavailable("encrypted local connection-secret storage is unavailable")
        }
    }
}

pub(super) async fn connection_capability_counts(
    state: &ConnectionAdminState,
    rbac_state: &middleware::rbac::RbacState,
    principal: &auth::Principal,
) -> ResponseResult<BTreeMap<connections::model::ConnectionId, usize>> {
    state
        .inventory
        .connection_counts(rbac_state, principal)
        .await
        .map_err(|error| {
            tracing::error!(
                reason = ?error,
                "failed to build bounded connection capability counts"
            );
            Box::new(service_unavailable(
                "connection capability inventory is unavailable",
            ))
        })
}

pub(super) async fn connection_collection_runtime_data(
    state: &ConnectionAdminState,
    snapshot: &connections::control_plane::ConnectionRuntimeSnapshot,
    rbac_state: &middleware::rbac::RbacState,
    principal: &auth::Principal,
) -> ResponseResult<ConnectionCollectionRuntimeData> {
    let capability_counts = connection_capability_counts(state, rbac_state, principal).await?;
    if snapshot.managed().is_empty() {
        return Ok(ConnectionCollectionRuntimeData {
            statuses: BTreeMap::new(),
            status_revisions: BTreeMap::new(),
            dependency_counts: BTreeMap::new(),
            capability_counts,
            activity_times: BTreeMap::new(),
        });
    }
    let store = state
        .control_plane
        .managed_store()
        .map_err(|_| {
            Box::new(service_unavailable(
                "managed connection state is unavailable",
            ))
        })?
        .clone();
    let ids = snapshot.managed().keys().cloned().collect::<Vec<_>>();
    // The store dispatch keeps these reads off the request executor.
    let (dependency_counts, activity_times, stored_statuses, status_revisions) = {
        let dependency_counts = store.dependency_counts().await.map_err(|error| {
            tracing::error!(error = %error, "failed to load connection dependency counts");
            Box::new(service_unavailable(
                "managed connection state is unavailable",
            ))
        })?;
        let activity_times = store.activity_times().await.map_err(|error| {
            tracing::error!(error = %error, "failed to load connection activity timestamps");
            Box::new(service_unavailable(
                "managed connection state is unavailable",
            ))
        })?;
        // One read for every status rather than one per Connection: in
        // cluster mode each call is a pool checkout and a round trip.
        let stored_statuses = store.latest_statuses(&ids).await.map_err(|error| {
            tracing::error!(error = %error, "failed to load connection statuses");
            Box::new(service_unavailable(
                "managed connection state is unavailable",
            ))
        })?;
        // The authority's status revisions: a status write on another
        // replica moves no security revision, so the runtime records here
        // may still carry the revision they last reconciled.
        let status_revisions = store.status_revisions(&ids).await.map_err(|error| {
            tracing::error!(error = %error, "failed to load connection status revisions");
            Box::new(service_unavailable(
                "managed connection state is unavailable",
            ))
        })?;
        (
            dependency_counts,
            activity_times,
            stored_statuses,
            status_revisions,
        )
    };
    let mut statuses = BTreeMap::new();
    for (id, record) in snapshot.managed() {
        let stored_status = stored_statuses.get(id).cloned();
        let status = state
            .mcp_catalogs
            .status_fallback(id, &record.etag(), stored_status);
        if let Some(status) = state
            .openapi_catalogs
            .status_fallback(id, &record.etag(), status)
        {
            statuses.insert(id.clone(), status);
        }
    }
    Ok(ConnectionCollectionRuntimeData {
        statuses,
        status_revisions,
        dependency_counts,
        capability_counts,
        activity_times,
    })
}

pub(super) async fn connection_detail_runtime_data(
    state: &ConnectionAdminState,
    id: &connections::model::ConnectionId,
) -> ResponseResult<(
    Option<connections::status::SafeConnectionStatus>,
    Vec<connections::store::ConnectionDependency>,
    Option<u64>,
)> {
    let store = state
        .control_plane
        .managed_store()
        .map_err(|_| {
            Box::new(service_unavailable(
                "managed connection state is unavailable",
            ))
        })?
        .clone();
    let stored_status = store.latest_status(id).await.map_err(|error| {
        tracing::error!(connection_id = %id, error = %error, "failed to load connection status");
        Box::new(service_unavailable(
            "managed connection state is unavailable",
        ))
    })?;
    let snapshot = state.control_plane.runtime_snapshot();
    let status = snapshot.managed().get(id).and_then(|record| {
        let status = state
            .mcp_catalogs
            .status_fallback(id, &record.etag(), stored_status);
        state
            .openapi_catalogs
            .status_fallback(id, &record.etag(), status)
    });
    let dependencies = store.dependencies(id).await.map_err(|error| {
        tracing::error!(connection_id = %id, error = %error, "failed to load connection dependencies");
        Box::new(connection_store_error_response(error))
    })?;
    let status_revision = store
        .status_revisions(std::slice::from_ref(id))
        .await
        .map_err(|error| {
            tracing::error!(connection_id = %id, error = %error, "failed to load connection status revision");
            Box::new(service_unavailable(
                "managed connection state is unavailable",
            ))
        })?
        .get(id)
        .copied();
    Ok((status, dependencies, status_revision))
}

pub(super) fn connection_mutation_error_response(
    error: connections::control_plane::ConnectionMutationError,
) -> Response {
    match error {
        connections::control_plane::ConnectionMutationError::Unavailable(_) => {
            connection_store_not_configured()
        }
        connections::control_plane::ConnectionMutationError::CollectionConflict { current } => {
            with_connection_collection_etag(
                precondition_failed("connection collection changed during the mutation"),
                &current,
            )
        }
        connections::control_plane::ConnectionMutationError::UnresolvableBindings { fields } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ConnectionValidationResponse {
                error: "connection validation failed",
                problems: fields
                    .into_iter()
                    .map(|field| ConnectionValidationProblem {
                        field,
                        code: "unresolvable_binding",
                    })
                    .collect(),
            }),
        )
            .into_response(),
        // The field and a fixed code (`algorithm_mismatch`, `invalid_signing_key`,
        // `unusable_signing_key`, `duplicate_kid`): enough to fix the
        // configuration, and nothing about the key material.
        connections::control_plane::ConnectionMutationError::CallerAssertionKeyRejected {
            field,
            code,
        } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ConnectionValidationResponse {
                error: "connection validation failed",
                problems: vec![ConnectionValidationProblem { field, code }],
            }),
        )
            .into_response(),
        connections::control_plane::ConnectionMutationError::BindingUnavailable => {
            service_unavailable("connection binding validation is unavailable")
        }
        connections::control_plane::ConnectionMutationError::Busy => {
            service_unavailable("managed connection state is busy")
        }
        connections::control_plane::ConnectionMutationError::DeadlineExceeded => (
            StatusCode::REQUEST_TIMEOUT,
            Json(json!({
                "error": "managed connection mutation timed out",
            })),
        )
            .into_response(),
        connections::control_plane::ConnectionMutationError::Store(error) => {
            connection_store_error_response(error)
        }
    }
}

pub(super) fn connection_store_error_response(
    error: connections::store::ConnectionStoreError,
) -> Response {
    match error {
        connections::store::ConnectionStoreError::Validation { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ConnectionValidationResponse {
                error: "connection validation failed",
                problems: vec![ConnectionValidationProblem {
                    field: "connection",
                    code: "invalid",
                }],
            }),
        )
            .into_response(),
        // The candidate's field and a fixed code. Which other Connection, or
        // which alias, is not said: the field is enough to fix the write.
        connections::store::ConnectionStoreError::SecretPurposeConflict { field } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ConnectionValidationResponse {
                error: "connection validation failed",
                problems: vec![ConnectionValidationProblem {
                    field,
                    code: connections::model::SECRET_PURPOSE_CONFLICT_CODE,
                }],
            }),
        )
            .into_response(),
        connections::store::ConnectionStoreError::NotFound { .. } => {
            not_found("connection was not found")
        }
        connections::store::ConnectionStoreError::Conflict { current, .. } => with_etag(
            precondition_failed("connection changed during the mutation"),
            current.as_str(),
        ),
        connections::store::ConnectionStoreError::ToolNameConflict {
            tool_name,
            lane,
            owner_id,
            ..
        } => conflict(&format!(
            "tool name '{tool_name}' is already published by the {lane} lane ({owner_id})"
        )),
        connections::store::ConnectionStoreError::DependencyConflict { count, .. } => conflict(
            &format!("connection is referenced by {count} retained control-plane records"),
        ),
        connections::store::ConnectionStoreError::LimitExceeded { .. } => {
            conflict("managed connection capacity has been reached")
        }
        connections::store::ConnectionStoreError::CallerOperationConflict => {
            caller_operation_conflict()
        }
        other => {
            tracing::error!(error = %other, "managed connection operation failed");
            service_unavailable("managed connection state is unavailable")
        }
    }
}
