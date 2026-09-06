//! admin tools boundary extracted from the application composition root.
use super::*;

pub(super) async fn tool_inventory_list_endpoint(
    State(state): State<ToolAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(TOOLS_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_tool_rbac_state(&state, principal, ADMIN_TOOLS_READ_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return tool_admin_authz_error_response(error),
        };
    let params = match Query::<tools::inventory::CapabilityListParams>::try_from_uri(request.uri())
    {
        Ok(Query(params)) => params,
        Err(_) => return bad_request("capability inventory query is invalid"),
    };

    let page = match state.inventory.list(rbac_state, principal, &params).await {
        Ok(page) => page,
        Err(error) => return capability_inventory_error_response(error),
    };
    let etag = match serialized_response_etag(&page) {
        Ok(etag) => etag,
        Err(error) => {
            tracing::error!(
                error = %error,
                "failed to hash capability inventory list response"
            );
            return internal_server_error("capability inventory response failed");
        }
    };

    (
        StatusCode::OK,
        [
            (header::ETAG, etag_header_value(&etag)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(page),
    )
        .into_response()
}

pub(super) async fn tool_inventory_detail_endpoint(
    State(state): State<ToolAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(TOOL_ADMIN_ROUTE);

    let Some(principal) = request.extensions().get::<auth::Principal>() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_tool_rbac_state(&state, principal, ADMIN_TOOLS_READ_PERMISSION) {
            Ok(rbac_state) => rbac_state,
            Err(error) => return tool_admin_authz_error_response(error),
        };
    let detail = match state
        .inventory
        .detail(
            rbac_state,
            principal,
            &raw_id,
            rbac_state.principal_has_permission(principal, ADMIN_TOOLS_EXECUTE_PERMISSION),
            true,
        )
        .await
    {
        Ok(Some(detail)) => detail,
        Ok(None) => return not_found("capability was not found"),
        Err(error) => return capability_inventory_error_response(error),
    };
    let etag = detail.execution_etag().to_owned();

    (
        StatusCode::OK,
        [
            (header::ETAG, etag_header_value(&etag)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(detail.detail),
    )
        .into_response()
}

pub(super) async fn tool_playground_execute_endpoint(
    State(state): State<ToolAdminState>,
    Path(raw_id): Path<String>,
    request: AxumRequest,
) -> Response {
    record_request(TOOL_EXECUTE_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    let rbac_state =
        match authorized_tool_rbac_state(&state, &principal, ADMIN_TOOLS_EXECUTE_PERMISSION) {
            Ok(rbac_state) => rbac_state.clone(),
            Err(ToolAdminAuthzError::Forbidden(_)) => {
                return tool_playground_permission_forbidden(&state, &parts, &principal);
            }
            Err(error) => return tool_admin_authz_error_response(error),
        };

    let supplied_etag = match exact_strong_if_match(&parts.headers) {
        Ok(etag) => etag,
        Err(ToolPlaygroundIfMatchError::Missing) => {
            return precondition_required("If-Match header is required");
        }
        Err(ToolPlaygroundIfMatchError::Invalid) => {
            return bad_request("If-Match must contain exactly one strong entity tag");
        }
    };
    // Opaque IDs are resolved only against the active registry. This does not
    // inspect connection/catalog/provider/DNS state.
    let Some(definition) = state.inventory.registered_tool(&raw_id) else {
        return not_found("capability was not found");
    };
    let body = match read_request_body(
        body,
        state
            .max_body_size
            .min(tools::playground::TOOL_PLAYGROUND_REQUEST_LIMIT_BYTES),
    )
    .await
    {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let request = match serde_json::from_slice::<tools::playground::ToolPlaygroundRequest>(&body) {
        Ok(request) => request,
        Err(_) => return bad_request("tool execution request is invalid"),
    };

    let inventory = state.inventory.clone();
    let precondition_rbac_state = rbac_state.clone();
    let precondition_principal = principal.clone();
    let expected_etag = supplied_etag.clone();
    // The inventory read behind this precondition awaits the Connection
    // store, so the checker is registered as an asynchronous one; the
    // executor awaits it in place rather than blocking an executor thread.
    let precondition =
        tools::executor::ToolExecutionPrecondition::new_async(move |current_definition| {
            let inventory = inventory.clone();
            let rbac_state = precondition_rbac_state.clone();
            let principal = precondition_principal.clone();
            let expected_etag = expected_etag.clone();
            Box::pin(async move {
                if !rbac_state.principal_has_permission(&principal, ADMIN_TOOLS_EXECUTE_PERMISSION)
                {
                    return Err(tools::executor::ToolExecutionPreconditionError::Failed);
                }
                match inventory
                    .execution_etag_for_definition(&rbac_state, &principal, &current_definition)
                    .await
                {
                    Ok(Some(current_etag)) if current_etag == expected_etag => Ok(()),
                    Ok(_) => Err(tools::executor::ToolExecutionPreconditionError::Failed),
                    Err(_) => Err(tools::executor::ToolExecutionPreconditionError::Unavailable),
                }
            })
        });
    let context = tools::runtime::ToolInvocationContext {
        request_id: client_ip::request_id(&parts.headers, &parts.extensions),
        source_ip: client_ip::canonical_client_ip(
            &parts.headers,
            &parts.extensions,
            &state.client_ip_policy,
        ),
        actor: Some(auth::actor_from_principal(&principal)),
        source: tools::runtime::ToolInvocationSource::AdminPlayground,
        admitted_deadline: None,
    };
    let composite_request_id = definition
        .composite
        .is_some()
        .then(|| context.request_id.clone());

    let result = match state
        .executor
        .execute_with_precondition(
            &definition.name,
            Value::Object(request.arguments),
            context,
            tokio_util::sync::CancellationToken::new(),
            precondition,
        )
        .await
    {
        Ok(result) => result,
        Err(error) => {
            return tool_playground_runtime_error_response(error, composite_request_id.as_deref())
        }
    };
    let projected = match tools::playground::project_tool_execution_result(result) {
        Ok(projected) => projected,
        Err(error) => {
            state.audit.emit(audit::AuditEvent::new(
                audit::event::TOOL_PLAYGROUND_OUTPUT_REJECTED,
                client_ip::request_id(&parts.headers, &parts.extensions),
                client_ip::canonical_client_ip(
                    &parts.headers,
                    &parts.extensions,
                    &state.client_ip_policy,
                ),
                Some(auth::actor_from_principal(&principal)),
                json!({
                    "tool_name": definition.name.as_str(),
                    "reason": error.reason(),
                    "invocation_source": "admin_playground",
                }),
            ));
            return tool_playground_error_response(
                StatusCode::BAD_GATEWAY,
                "tool execution output was rejected",
                error.reason(),
            );
        }
    };

    (
        StatusCode::OK,
        [
            (header::ETAG, etag_header_value(&supplied_etag)),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(projected),
    )
        .into_response()
}

pub(super) async fn tools_openapi_preview_endpoint(
    State(state): State<ToolAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(TOOLS_OPENAPI_PREVIEW_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>() else {
        return unauthorized();
    };
    if let Err(error) = authorized_tool_rbac_state(&state, principal, ADMIN_TOOLS_READ_PERMISSION) {
        return tool_admin_authz_error_response(error);
    }
    let authority = match tools_authority(&state) {
        Ok(authority) => authority,
        Err(response) => return *response,
    };
    let (_tools_file_value, _current_document, current_etag) =
        match current_tools_document(&authority).await {
            Ok(current) => current,
            Err(response) => return *response,
        };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let spec = match std::str::from_utf8(&body) {
        Ok(spec) => spec,
        Err(err) => return bad_request(&format!("invalid OpenAPI spec UTF-8: {err}")),
    };
    let generation =
        match tools::openapi::generate_tools_from_openapi_str("admin-openapi-preview", spec) {
            Ok(generation) => generation,
            Err(err) => return bad_request(&format!("invalid OpenAPI spec: {err}")),
        };

    (
        StatusCode::OK,
        [(header::ETAG, etag_header_value(&current_etag))],
        Json(openapi_tools_preview_response(generation)),
    )
        .into_response()
}

pub(super) async fn tools_openapi_register_endpoint(
    State(state): State<ToolAdminState>,
    request: AxumRequest,
) -> Response {
    record_request(TOOLS_OPENAPI_REGISTER_ADMIN_ROUTE);

    let (parts, body) = request.into_parts();
    let Some(principal) = parts.extensions.get::<auth::Principal>().cloned() else {
        return unauthorized();
    };
    if let Err(error) = authorized_tool_rbac_state(&state, &principal, ADMIN_TOOLS_WRITE_PERMISSION)
    {
        return tool_admin_authz_error_response(error);
    }
    let authority = match tools_authority(&state) {
        Ok(authority) => authority,
        Err(response) => return *response,
    };

    let body = match read_request_body(body, state.max_body_size).await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    let requested = match parse_openapi_tools_register_body(&body) {
        Ok(requested) => requested,
        Err(response) => return *response,
    };
    if requested.selected_tool_names.is_empty() {
        return bad_request("selected_tool_names must include at least one tool name");
    }

    let generation = match tools::openapi::generate_tools_from_openapi_str(
        "admin-openapi-register",
        &requested.spec,
    ) {
        Ok(generation) => generation,
        Err(err) => return bad_request(&format!("invalid OpenAPI spec: {err}")),
    };
    let selected = match selected_generated_tools(&generation, &requested) {
        Ok(selected) => selected,
        Err(response) => return *response,
    };

    // Each authority owns its whole flow. Standalone holds the write guard
    // across its local read-modify-write (nothing else serializes it);
    // cluster mode serializes at the authority's compare-and-swap and holds
    // no process-local lock across its awaits.
    match &authority {
        ToolsAuthority::File(tools_file) => {
            // Standalone: the write guard spans the local read-modify-write
            // (there is no authority to serialize it). Validate, write the
            // file, swap; the restore-on-reject path re-installs the
            // previous lane so the connection dependency validator sees the
            // pre-rejection state again.
            let _tools_write_guard = match state.write_lock.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            // Sync read under the guard: the file branch never awaits
            // between its read and its write.
            let (current_value, current_document) = match read_tools_file_document(tools_file) {
                Ok(document) => document,
                Err(error) => {
                    tracing::error!(tools_file = %tools_file.display(), error = %error, "failed to read current tools file for OpenAPI registration");
                    return internal_server_error("tools file read failed");
                }
            };
            let current_etag = match tools_file_etag(&current_value) {
                Ok(etag) => etag,
                Err(err) => {
                    tracing::error!(error = %err, "failed to compute current tools file ETag");
                    return internal_server_error("tools file ETag computation failed");
                }
            };
            let merged = match merge_tools_candidate(
                &parts.headers,
                &current_etag,
                current_document,
                selected,
            ) {
                Ok(merged) => merged,
                Err(response) => return *response,
            };
            if let Err(error) = state.registry.replace_local_definitions_with_persist(
                merged.candidate_local_tools.clone(),
                || fs::write(tools_file, &merged.candidate_contents),
            ) {
                if let Err(restore_error) = state
                    .registry
                    .replace_local_definitions_with_persist(merged.previous_local_tools, || {
                        Ok::<(), Infallible>(())
                    })
                {
                    tracing::error!(
                        tools_file = %tools_file.display(),
                        error = ?restore_error,
                        "failed to restore Connection dependency validation after rejected tools update"
                    );
                }
                return match error {
                    tools::definitions::McpCatalogPublishError::Registry(error) => {
                        tracing::warn!(
                            tools_file = %tools_file.display(),
                            error = %error,
                            "merged OpenAPI tools conflicted with the active tool registry"
                        );
                        conflict("OpenAPI tools conflict with the active tool registry")
                    }
                    tools::definitions::McpCatalogPublishError::Persist(error) => {
                        tracing::error!(
                            tools_file = %tools_file.display(),
                            error = %error,
                            "failed to persist merged tools file"
                        );
                        internal_server_error("tools file persist failed")
                    }
                };
            }
            tools_register_response(
                &state,
                &parts,
                &principal,
                &authority.audit_source_label(),
                merged,
            )
        }
        #[cfg(feature = "postgres")]
        ToolsAuthority::Postgres(control_plane) => {
            let (_current_value, current_document, current_etag) =
                match current_tools_document(&authority).await {
                    Ok(current) => current,
                    Err(response) => return *response,
                };
            let merged = match merge_tools_candidate(
                &parts.headers,
                &current_etag,
                current_document,
                selected,
            ) {
                Ok(merged) => merged,
                Err(response) => return *response,
            };
            match register_tools_via_control_plane(
                control_plane,
                state.tools_resource.as_ref(),
                &state.registry,
                &current_etag,
                &principal,
                merged,
            )
            .await
            {
                Ok(merged) => tools_register_response(
                    &state,
                    &parts,
                    &principal,
                    &authority.audit_source_label(),
                    merged,
                ),
                Err(response) => *response,
            }
        }
    }
}

/// The cluster-mode register flow: validate the merged candidate against
/// the current lanes, commit the new immutable version through the
/// authority's compare-and-swap (advancing the shared security revision
/// and writing the outbox row in one transaction), then install the local
/// lane. A racing writer loses at the CAS with `412` and writes nothing.
#[cfg(feature = "postgres")]
pub(super) async fn register_tools_via_control_plane(
    control_plane: &Arc<dyn storage::ToolControlPlane>,
    tools_resource: Option<&Arc<security_cluster::ToolsResource>>,
    registry: &tools::definitions::ToolRegistry,
    current_etag: &str,
    principal: &auth::Principal,
    merged: MergedToolsCandidate,
) -> Result<MergedToolsCandidate, Box<Response>> {
    if let Err(error) = registry.validate_local_definitions(&merged.candidate_local_tools) {
        tracing::warn!(
            error = %error,
            "merged OpenAPI tools conflicted with the active tool registry"
        );
        return Err(Box::new(conflict(
            "OpenAPI tools conflict with the active tool registry",
        )));
    }
    let diff_summary = json!({
        "action": "openapi_tools_registered",
        "registered_tool_names": merged.registered_tool_names,
    });
    match control_plane
        .commit_tools(
            storage::PolicyCommitPrecondition::Expected {
                etag: current_etag.to_owned(),
            },
            &merged.candidate_value,
            &principal.user_id,
            &diff_summary,
        )
        .await
    {
        Ok(committed) => {
            // Through the gate's adapter when there is one: the install is
            // then a compare-and-swap on the security revision, so a
            // commit that paused here while another replica's newer commit
            // was reconciled cannot roll the live lane back. A skipped
            // install is success -- the document is durable and the lane
            // already serves something newer.
            let installed = match tools_resource {
                Some(resource) => resource
                    .install_committed(
                        merged.candidate_local_tools.clone(),
                        committed.security_revision,
                    )
                    .await
                    .map(|_| ()),
                None => registry.install_local_definitions(merged.candidate_local_tools.clone()),
            };
            if let Err(error) = installed {
                // The mutation is durable at the authority; this replica's
                // managed lanes moved under it and the local compile
                // failed. Fail closed for this response and let
                // reconciliation converge (or surface the conflict through
                // the revision gate).
                tracing::error!(
                    error = %error,
                    revision = committed.security_revision,
                    "committed tools document could not be activated locally; \
                     reconciliation will retry"
                );
                return Err(Box::new(service_unavailable(
                    "tools document committed but not activated locally",
                )));
            }
            Ok(merged)
        }
        Err(storage::PolicyCommitError::PreconditionFailed) => Err(Box::new(precondition_failed(
            "If-Match does not match the current tools ETag",
        ))),
        // The authority refused a name another lane holds: a verdict on
        // this document, not a storage failure, and nothing was written.
        Err(storage::PolicyCommitError::ToolNameTaken {
            tool_name,
            lane,
            owner_id,
        }) => Err(Box::new(conflict(&format!(
            "tool name '{tool_name}' is already published by the {lane} lane ({owner_id})"
        )))),
        Err(storage::PolicyCommitError::Store(error)) => {
            tracing::error!(
                error = %error,
                "tools control-plane commit failed; nothing was written"
            );
            Err(Box::new(service_unavailable(
                "tools mutation could not be committed",
            )))
        }
    }
}

pub(super) fn merge_tools_candidate(
    headers: &HeaderMap,
    current_etag: &str,
    mut current_document: ToolsFileAdminDocument,
    selected: Vec<tools::definitions::ToolDefinition>,
) -> Result<MergedToolsCandidate, Box<Response>> {
    match if_match_matches(headers, current_etag) {
        Ok(true) => {}
        Ok(false) => {
            return Err(Box::new(precondition_failed(
                "If-Match does not match the current tools ETag",
            )));
        }
        Err(error) => return Err(Box::new(if_match_error_response(error))),
    }

    let conflicts = conflicting_tool_names(&current_document.tools, &selected);
    if !conflicts.is_empty() {
        return Err(Box::new(
            (
                StatusCode::CONFLICT,
                Json(ToolNameConflictResponse {
                    error: "tool name collision",
                    conflicts,
                }),
            )
                .into_response(),
        ));
    }

    let registered_tool_names = selected
        .iter()
        .map(|tool| tool.name.clone())
        .collect::<Vec<_>>();
    let previous_local_tools = current_document.tools.clone();
    current_document.tools.extend(selected);
    let candidate_value = match serde_json::to_value(&current_document) {
        Ok(value) => value,
        Err(err) => {
            tracing::error!(error = %err, "failed to serialize merged tools file");
            return Err(Box::new(internal_server_error("tools file merge failed")));
        }
    };
    let candidate_contents = match serde_json::to_string_pretty(&candidate_value) {
        Ok(contents) => contents,
        Err(err) => {
            tracing::error!(error = %err, "failed to render merged tools file");
            return Err(Box::new(internal_server_error("tools file merge failed")));
        }
    };
    let tool_count = current_document.tools.len();
    Ok(MergedToolsCandidate {
        registered_tool_names,
        previous_local_tools,
        candidate_value,
        candidate_contents,
        candidate_local_tools: current_document.tools,
        tool_count,
    })
}

pub(super) fn tools_register_response(
    state: &ToolAdminState,
    parts: &http::request::Parts,
    principal: &auth::Principal,
    source_label: &str,
    merged: MergedToolsCandidate,
) -> Response {
    emit_tool_registry_changed(
        state,
        parts,
        principal,
        source_label,
        &merged.registered_tool_names,
        merged.tool_count,
    );
    let new_etag = match tools_file_etag(&merged.candidate_value) {
        Ok(etag) => etag,
        Err(err) => {
            tracing::error!(error = %err, "failed to compute updated tools file ETag");
            return internal_server_error("tools file ETag computation failed");
        }
    };

    (
        StatusCode::CREATED,
        [(header::ETAG, etag_header_value(&new_etag))],
        Json(OpenApiToolsRegisterResponse {
            registered_tool_names: merged.registered_tool_names,
            tool_count: merged.tool_count,
        }),
    )
        .into_response()
}

/// Resolve the configured tools authority, or the not-configured response
/// when neither the file nor the control plane is wired.
pub(super) fn tools_authority(state: &ToolAdminState) -> Result<ToolsAuthority<'_>, Box<Response>> {
    if let Some(tools_file) = state.tools_file.as_deref() {
        return Ok(ToolsAuthority::File(tools_file));
    }
    #[cfg(feature = "postgres")]
    if let Some(control_plane) = state.tool_control_plane.as_ref() {
        return Ok(ToolsAuthority::Postgres(control_plane));
    }
    Err(Box::new(tool_admin_authz_error_response(
        ToolAdminAuthzError::ToolsFileNotConfigured,
    )))
}

/// The current tools document plus its verified ETag from the authority:
/// the file (re-read and re-validated) or the active cluster document.
pub(super) async fn current_tools_document(
    authority: &ToolsAuthority<'_>,
) -> Result<(Value, ToolsFileAdminDocument, String), Box<Response>> {
    match authority {
        ToolsAuthority::File(tools_file) => {
            let (current_value, current_document) = match read_tools_file_document(tools_file) {
                Ok(document) => document,
                Err(error) => {
                    tracing::error!(tools_file = %tools_file.display(), error = %error, "failed to read current tools file");
                    return Err(Box::new(internal_server_error("tools file read failed")));
                }
            };
            let current_etag = match tools_file_etag(&current_value) {
                Ok(etag) => etag,
                Err(err) => {
                    tracing::error!(error = %err, "failed to compute current tools file ETag");
                    return Err(Box::new(internal_server_error(
                        "tools file ETag computation failed",
                    )));
                }
            };
            Ok((current_value, current_document, current_etag))
        }
        #[cfg(feature = "postgres")]
        ToolsAuthority::Postgres(control_plane) => {
            let active = match control_plane.active_tools().await {
                Ok(Some(active)) => active,
                Ok(None) => {
                    tracing::error!("tools control plane has no active document");
                    return Err(Box::new(service_unavailable(
                        "tools control plane unavailable",
                    )));
                }
                Err(error) => {
                    tracing::error!(error = %error, "tools control plane read failed");
                    return Err(Box::new(service_unavailable(
                        "tools control plane unavailable",
                    )));
                }
            };
            let document =
                match serde_json::from_value::<ToolsFileAdminDocument>(active.document.clone()) {
                    Ok(document) => document,
                    Err(error) => {
                        tracing::error!(
                            error = %error,
                            "the active tools document does not match the admin schema"
                        );
                        return Err(Box::new(service_unavailable(
                            "tools control plane unavailable",
                        )));
                    }
                };
            Ok((active.document, document, active.etag))
        }
    }
}

pub(super) fn openapi_tools_preview_response(
    generation: tools::openapi::OpenApiToolGeneration,
) -> OpenApiToolsPreviewResponse {
    OpenApiToolsPreviewResponse {
        tools: generation.definitions,
        operation_id_fallbacks: generation
            .operation_id_fallbacks
            .into_iter()
            .map(openapi_tool_name_fallback_response)
            .collect(),
        skipped_operations: generation
            .skipped_operations
            .into_iter()
            .map(openapi_skipped_operation_response)
            .collect(),
        api_key_header_auth_requirements: generation
            .api_key_header_auth_requirements
            .into_iter()
            .map(|requirement| OpenApiApiKeyHeaderAuthRequirementResponse {
                tool_name: requirement.tool_name,
                method: requirement.method,
                path_template: requirement.path_template,
                scheme_name: requirement.scheme_name,
                header_name: requirement.header_name,
            })
            .collect(),
    }
}

pub(super) fn managed_openapi_preview_response(
    preview: connections::openapi::OpenApiCatalogPreview,
) -> ManagedOpenApiPreviewResponse {
    let connection_etag = preview.connection_etag.as_str().to_owned();
    let security_confirmations = preview
        .registration_security_selections
        .into_iter()
        .map(|selection| ManagedOpenApiSecuritySelectionResponse {
            tool_name: selection.tool_name,
            selected_scheme_names: selection.selected_scheme_names,
        })
        .collect();
    let incompatibilities = preview
        .binding
        .incompatibilities
        .into_iter()
        .map(managed_openapi_incompatibility_response)
        .collect();
    let overlay = managed_openapi_overlay_report_response(preview.overlay_report);
    ManagedOpenApiPreviewResponse {
        connection_id: preview.connection_id,
        connection_etag,
        spec_digest: preview.spec_digest,
        spec_revision: preview.spec_revision,
        catalog_revision: preview.catalog_revision,
        tools: preview.binding.definitions,
        security_confirmations,
        incompatibilities,
        operation_id_fallbacks: preview
            .generation
            .operation_id_fallbacks
            .into_iter()
            .map(openapi_tool_name_fallback_response)
            .collect(),
        skipped_operations: preview
            .generation
            .skipped_operations
            .into_iter()
            .map(openapi_skipped_operation_response)
            .collect(),
        overlay,
    }
}

pub(super) fn managed_openapi_overlay_report_response(
    report: Option<connections::openapi::OpenApiOverlayCompileReport>,
) -> ManagedOpenApiOverlayReportResponse {
    let (applied, warnings, sources, tools, composites) = report
        .map(|report| {
            (
                true,
                report.warnings,
                report.sources,
                report.tools,
                report.composites,
            )
        })
        .unwrap_or_else(|| (false, Vec::new(), Vec::new(), Vec::new(), Vec::new()));
    ManagedOpenApiOverlayReportResponse {
        applied,
        problems: Vec::new(),
        warnings,
        sources,
        tools,
        composites,
    }
}

#[allow(clippy::result_large_err)] // Axum's complete safe HTTP failure is the useful error here.
pub(super) fn stored_overlay_sources(
    stored: &connections::store::StoredOpenApiOverlay,
) -> Result<Vec<connections::store::StoredOpenApiSourceReport>, Response> {
    let Some(encoded) = stored.source_reports_json.as_deref() else {
        tracing::error!(connection_id = %stored.connection_id, "stored overlay is missing its source report snapshot");
        return Err(service_unavailable(
            "stored OpenAPI overlay source reports are unavailable",
        ));
    };
    let report = connections::store::decode_openapi_source_reports(encoded).map_err(|()| {
        tracing::error!(connection_id = %stored.connection_id, "stored overlay source reports failed strict validation");
        service_unavailable("stored OpenAPI overlay source reports are unavailable")
    })?;
    Ok(report.sources)
}

pub(super) fn overlay_mutation_response(
    result: connections::openapi::OpenApiOverlayMutationResult,
) -> Response {
    let connection_id = result.catalog.connection_id.clone();
    let catalog_revision = result.catalog.catalog_revision;
    let etag = result.etag;
    let (overlay_revision, sources) = match result.stored.as_ref() {
        Some(stored) => {
            let sources = match stored_overlay_sources(stored) {
                Ok(sources) => sources,
                Err(response) => return response,
            };
            (stored.overlay_revision, sources)
        }
        None => (0, Vec::new()),
    };
    let (warnings, tools, composites) = result
        .report
        .map(|report| (report.warnings, report.tools, report.composites))
        .unwrap_or_else(|| (Vec::new(), Vec::new(), Vec::new()));
    (
        StatusCode::OK,
        [
            (header::ETAG, etag_header_value(etag.as_str())),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        Json(ConnectionOpenApiOverlayMutationResponse {
            connection_id,
            overlay_revision,
            catalog_revision,
            warnings,
            sources,
            tools,
            composites,
        }),
    )
        .into_response()
}

pub(super) fn managed_openapi_incompatibility_response(
    incompatibility: tools::openapi::OpenApiToolIncompatibility,
) -> ManagedOpenApiIncompatibilityResponse {
    use tools::openapi::OpenApiToolIncompatibilityReason;

    let (reason, path_template, detail) = match incompatibility.reason {
        OpenApiToolIncompatibilityReason::MissingSecurityMetadata => {
            ("missing_security_metadata", None, None)
        }
        OpenApiToolIncompatibilityReason::NoCompatibleSecurityAlternative => {
            ("no_compatible_security_alternative", None, None)
        }
        OpenApiToolIncompatibilityReason::InvalidMappingPath {
            path_template,
            message,
        } => ("invalid_mapping_path", Some(path_template), Some(message)),
    };
    ManagedOpenApiIncompatibilityResponse {
        tool_name: incompatibility.tool_name,
        reason,
        path_template,
        detail,
    }
}

pub(super) fn openapi_tool_name_fallback_response(
    fallback: tools::openapi::OpenApiToolNameFallback,
) -> OpenApiToolNameFallbackResponse {
    OpenApiToolNameFallbackResponse {
        method: fallback.method,
        path_template: fallback.path_template,
        original_operation_id: fallback.original_operation_id,
        generated_name: fallback.generated_name,
        reason: match fallback.reason {
            tools::openapi::OpenApiToolNameFallbackReason::MissingOperationId => {
                "missing_operation_id"
            }
            tools::openapi::OpenApiToolNameFallbackReason::InvalidOperationId => {
                "invalid_operation_id"
            }
            tools::openapi::OpenApiToolNameFallbackReason::DuplicateToolName => {
                "duplicate_tool_name"
            }
        },
    }
}

pub(super) fn openapi_skipped_operation_response(
    skipped: tools::openapi::OpenApiSkippedOperation,
) -> OpenApiSkippedOperationResponse {
    match skipped.reason {
        tools::openapi::OpenApiSkippedOperationReason::BodyPropertyParameterNameCollision {
            property_name,
        } => OpenApiSkippedOperationResponse {
            method: skipped.method,
            path_template: skipped.path_template,
            original_operation_id: skipped.original_operation_id,
            reason: "body_property_parameter_name_collision",
            property_name: Some(property_name),
        },
        tools::openapi::OpenApiSkippedOperationReason::UnsafeTraceMethod => {
            OpenApiSkippedOperationResponse {
                method: skipped.method,
                path_template: skipped.path_template,
                original_operation_id: skipped.original_operation_id,
                reason: "unsafe_trace_method",
                property_name: None,
            }
        }
    }
}

pub(super) fn selected_generated_tools(
    generation: &tools::openapi::OpenApiToolGeneration,
    request: &OpenApiToolsRegisterRequest,
) -> ResponseResult<Vec<tools::definitions::ToolDefinition>> {
    let duplicates = duplicate_strings(&request.selected_tool_names);
    if !duplicates.is_empty() {
        return Err(Box::new(bad_request(&format!(
            "selected_tool_names contains duplicate names: {}",
            duplicates.join(", ")
        ))));
    }

    let generated_names = generation
        .definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();
    let selected_names = request
        .selected_tool_names
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let unknown = selected_names
        .iter()
        .filter(|name| !generated_names.contains(**name))
        .copied()
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(Box::new(bad_request(&format!(
            "selected tool names were not generated: {}",
            unknown.join(", ")
        ))));
    }

    let unsupported_tool_names = generation
        .api_key_header_auth_requirements
        .iter()
        .filter(|requirement| selected_names.contains(requirement.tool_name.as_str()))
        .map(|requirement| requirement.tool_name.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    if !unsupported_tool_names.is_empty() {
        return Err(Box::new(
            unsupported_openapi_tool_auth_requirements_response(unsupported_tool_names),
        ));
    }

    Ok(generation
        .definitions
        .iter()
        .filter(|definition| selected_names.contains(definition.name.as_str()))
        .cloned()
        .collect())
}

pub(super) fn unsupported_openapi_tool_auth_requirements_response(
    unsupported_tool_names: Vec<String>,
) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(UnsupportedOpenApiToolAuthRequirementsResponse {
            error: OPENAPI_TOOLS_UNSUPPORTED_AUTH_REQUIREMENTS_ERROR,
            unsupported_tool_names,
        }),
    )
        .into_response()
}

pub(super) fn duplicate_strings(values: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut duplicates = BTreeSet::new();

    for value in values {
        if !seen.insert(value.as_str()) {
            duplicates.insert(value.clone());
        }
    }

    duplicates.into_iter().collect()
}

pub(super) fn conflicting_tool_names(
    existing: &[tools::definitions::ToolDefinition],
    selected: &[tools::definitions::ToolDefinition],
) -> Vec<String> {
    let existing_names = existing
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<BTreeSet<_>>();

    selected
        .iter()
        .filter(|definition| existing_names.contains(definition.name.as_str()))
        .map(|definition| definition.name.clone())
        .collect()
}
