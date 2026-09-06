//! routing boundary extracted from the application composition root.
use super::*;

/// Builds the gRPC listener's router, or `None` when `GRPC_LISTEN_ADDR` is unset.
///
/// Returning `None` is what makes "no HTTP/2 server is ever constructed by
/// default" a fact rather than a claim: `lifecycle` binds and serves a listener
/// only when this is `Some`, and nothing else in the tree can reach
/// `hyper::server::conn::http2`.
///
/// The router goes through the SAME `apply_middleware` function, over the same
/// middleware state values, as the data listener: the same audit log, rate
/// limiter, observation state, RBAC state, auth state, CSRF configuration, and
/// proxy dispatch state. That is the whole structural argument for the
/// zero-bytes invariant -- authentication, rate limiting, CSRF, request
/// validation, route classification, RBAC and direct policy are the same
/// layers, in the same order, so a gRPC call is subject to exactly the
/// decisions an HTTP request is.
///
/// Three things differ, and all three are narrowings:
///
/// * Request validation is given the gRPC media types as its allow-list instead
///   of the deployment's HTTP list. This listener serves one protocol, so
///   `application/json` has no business being accepted on it.
/// * The router carries NO admin routes and no gateway-owned probe routes. Its
///   only route is a fallback into the gRPC proxy, which refuses any route
///   without an explicit `grpc` policy block.
/// * `AUTH_EXEMPT_PATHS` and `RBAC_EXEMPT_PATHS` do not apply here at all. See
///   below -- this one is a security property, not a convenience.
///
/// One layer is added, outermost, so it wraps everything above: the middleware
/// stack answers in HTTP, and a gRPC client needs a gRPC status.
///
/// # Why the exempt lists are dropped on this listener
///
/// The exempt lists exist to let gateway-owned surfaces through without a
/// credential: the admin UI and its assets, the admin login callback, the fixed
/// probe routes. #306 settled the rule that makes them safe -- *a gateway-owned
/// exempt entry can only grant exemptions inside gateway-owned space* -- and
/// the startup warning at [`GatewayRoutes::unowned_exempt_paths`] filters
/// gateway-owned entries out on exactly that reasoning.
///
/// None of it holds here. This listener serves ONE thing, a fallback into the
/// gRPC proxy; there is no gateway-owned space on it for an exemption to land
/// in. So every exemption that matches on this listener, without exception, is
/// an unauthenticated and unauthorized call proxied to an upstream:
///
/// * `default_admin_exempt_paths` puts `ADMIN_PREFIX` in both lists by default,
///   and entries are segment-boundary prefixes, so the default configuration
///   exempts `/admin/<Method>` -- which is a well-formed gRPC method path,
///   because `admin` and `Method` are both valid protobuf identifiers. The
///   operator gets no warning, because the entry IS gateway-owned and the
///   warning's premise is that a gateway-owned entry cannot be forwarded.
/// * An operator-added entry such as `/public`, written about HTTP paths on the
///   data listener, silently reads on this listener as "the gRPC service named
///   `public` needs no credential". One decision, two protocols, two listeners.
///
/// An exemption mechanism whose every match is a bypass is not a mechanism with
/// a bug in it. So the lists are emptied for this router, explicitly and in one
/// place, rather than each hole being patched as it is found. A deployment that
/// genuinely needs an unauthenticated gRPC method -- a load balancer calling
/// `grpc.health.v1.Health/Check`, say -- needs a setting that names canonical
/// method paths and is matched exactly, on this listener only; that is a
/// deliberate follow-up, not something to reach by leaving an HTTP path list
/// applying here.
///
/// `CSRF_EXEMPT_PATHS` is deliberately NOT emptied. CSRF exemption grants
/// nothing on its own -- an exempt call still has to authenticate and still has
/// to pass policy -- so it is not the same defect class, and it is the
/// documented way an operator relieves gRPC clients of the CSRF rule.
pub(super) fn grpc_app(
    config: &config::Config,
    app_state: &AppState,
    middleware_stack: &MiddlewareStack,
) -> Option<GrpcApp> {
    let address = config.grpc_listen_addr?;
    let mut grpc_config = middleware_stack.config.clone();
    grpc_config.validation_allowed_content_types = proxy::grpc::protocol::GRPC_CONTENT_TYPES
        .iter()
        .map(|content_type| (*content_type).to_owned())
        .collect();
    let grpc_stack = MiddlewareStack {
        config: grpc_config,
        audit_log: middleware_stack.audit_log.clone(),
        csrf_config: middleware_stack.csrf_config.clone(),
        rate_limit_state: middleware_stack.rate_limit_state.clone(),
        observation_state: middleware_stack.observation_state.clone(),
        rbac_state: middleware_stack.rbac_state.clone().map(|mut state| {
            state.exempt_paths = Vec::new();
            state
        }),
        auth_state: middleware_stack.auth_state.clone().map(|mut state| {
            state.exempt_paths = Vec::new();
            state
        }),
        proxy_dispatch_state: middleware_stack.proxy_dispatch_state.clone(),
    };

    let router = Router::new()
        .fallback(any(grpc_endpoint))
        .with_state(app_state.clone());

    Some(GrpcApp {
        address,
        router: apply_middleware(router, &grpc_stack, true)
            .layer(axum::middleware::from_fn(proxy::grpc::shape_response)),
        limits: proxy::grpc::GrpcListenerLimits {
            max_concurrent_streams: config.grpc_max_concurrent_streams,
            max_metadata_bytes: config.grpc_max_metadata_bytes,
        },
    })
}

pub(super) async fn grpc_endpoint(State(state): State<AppState>, request: AxumRequest) -> Response {
    record_request(GRPC_FALLBACK_ROUTE);

    // The same pair of refusals `proxy_fallback` makes, for the same reasons,
    // and stated here rather than inherited because this is a different router
    // with a different fallback. `grpc_app` also empties the auth and RBAC
    // exempt lists for this listener, which is the primary fix; this is the
    // defence in depth behind it, and it holds even if some future caller
    // reaches `handle_call` by another route.
    //
    // `is_gateway_owned_path` matters here for a reason that is easy to miss:
    // a gateway-owned path on THIS listener is not gateway-owned by anything.
    // The router serves no admin, probe or well-known routes, so without this
    // the gateway's own reserved namespace is simply proxy space -- and
    // `proxy_dispatch_context_middleware` skips route classification for those
    // paths on the premise that they never reach a proxy.
    let path = request.uri().path();
    if path_match::is_unsafe_request_path(path) {
        return proxy::grpc::not_proxyable_response("unsafe_path");
    }
    if state.routes.is_gateway_owned_path(path) {
        return proxy::grpc::not_proxyable_response("gateway_owned_path");
    }

    let Some(proxy) = state.proxy.as_ref() else {
        // No proxy configured at all. Answered as a gRPC status rather than a
        // 404 so the client sees a protocol-correct refusal.
        return proxy::grpc::unimplemented_response();
    };

    let source_ip = client_ip::canonical_client_ip(
        request.headers(),
        request.extensions(),
        &state.client_ip_policy,
    );

    proxy.handle_grpc_call(request, &source_ip).await
}

pub(super) fn unified_router(
    routes: &GatewayRoutes,
    app_state: AppState,
    admin_api_states: AdminApiStates,
) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/livez", get(livez))
        .route("/startupz", get(startupz))
        .route("/readyz", get(readyz))
        .route("/version", get(version))
        .route("/metrics", get(metrics_endpoint))
        .route(
            auth::protected_resource::WELL_KNOWN_PATH,
            get(oauth_protected_resource_metadata_endpoint),
        )
        .route(
            auth::protected_resource::WELL_KNOWN_SUFFIX_ROUTE,
            get(oauth_protected_resource_metadata_endpoint),
        )
        .route(routes.admin.ui_prefix.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_slash_route.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_asset_route.as_str(), get(admin_ui_asset));
    let router = add_mcp_routes(router, routes);

    let router = with_proxy_fallback_if_configured(router, &app_state).with_state(app_state);
    let router = add_admin_api_routes(router, routes, admin_api_states);

    #[cfg(test)]
    let router = router.route(
        "/__test/principal",
        get(principal_probe).options(principal_probe),
    );

    router
}

pub(super) fn data_router(app_state: AppState) -> Router {
    let router = Router::new()
        .route("/health", get(health))
        .route("/livez", get(livez))
        .route("/startupz", get(startupz))
        .route("/readyz", get(readyz))
        .route("/version", get(version))
        .route("/metrics", get(metrics_endpoint))
        .route(
            auth::protected_resource::WELL_KNOWN_PATH,
            get(oauth_protected_resource_metadata_endpoint),
        )
        .route(
            auth::protected_resource::WELL_KNOWN_SUFFIX_ROUTE,
            get(oauth_protected_resource_metadata_endpoint),
        );
    let router = add_mcp_routes(router, &app_state.routes);

    with_proxy_fallback_if_configured(router, &app_state).with_state(app_state)
}

pub(super) fn add_mcp_routes(
    mut router: Router<AppState>,
    routes: &GatewayRoutes,
) -> Router<AppState> {
    for route_path in &routes.mcp_route_paths {
        router = router.route(route_path.as_str(), any(mcp::mcp_endpoint));
    }
    router
}

pub(super) fn admin_router(
    routes: &GatewayRoutes,
    app_state: AppState,
    admin_api_states: AdminApiStates,
) -> Router {
    let router = Router::new()
        .route(routes.admin.ui_prefix.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_slash_route.as_str(), get(admin_ui_index))
        .route(routes.admin.ui_asset_route.as_str(), get(admin_ui_asset))
        .with_state(app_state);

    add_admin_api_routes(router, routes, admin_api_states)
}

pub(super) fn with_proxy_fallback_if_configured(
    router: Router<AppState>,
    app_state: &AppState,
) -> Router<AppState> {
    if app_state.proxy.is_some() {
        router.fallback(any(proxy_fallback))
    } else {
        router
    }
}

pub(super) fn add_admin_api_routes(
    router: Router,
    routes: &GatewayRoutes,
    admin_api_states: AdminApiStates,
) -> Router {
    let decision_audit = (
        admin_api_states.policy.audit.clone(),
        admin_api_states.policy.client_ip_policy.clone(),
    );
    // The admin API (minus the pre-authorization auth routes, merged
    // separately below) is one router so cluster mode can gate all of it
    // with one layer: every endpoint here authorizes against the compiled
    // policy snapshot, and that check must never see a stale revision.
    #[cfg_attr(not(feature = "postgres"), allow(unused_mut))]
    let mut api = Router::new()
        .merge(
            Router::new()
                .route(routes.admin.audit_route.as_str(), get(audit_query_endpoint))
                .route(
                    routes.admin.events_stream_route.as_str(),
                    get(audit_events_stream_endpoint),
                )
                .with_state(admin_api_states.audit),
        )
        .merge(
            Router::new()
                .route(routes.admin.status_route.as_str(), get(status_endpoint))
                .route(
                    &format!("{}/capabilities", routes.admin.api_prefix),
                    get(admin_capabilities_endpoint),
                )
                .with_state(admin_api_states.status),
        )
        .merge(
            Router::new()
                .route(routes.admin.cluster_route.as_str(), get(cluster_endpoint))
                .route(
                    routes.admin.cluster_replicas_route.as_str(),
                    get(cluster_replicas_endpoint),
                )
                .with_state(admin_api_states.cluster),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.schema_coverage_route.as_str(),
                    get(schema_coverage_endpoint),
                )
                .route(
                    routes.admin.schema_inferred_route.as_str(),
                    get(schema_inferred_endpoint),
                )
                .with_state(admin_api_states.schema),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.signals_route.as_str(),
                    get(signals_list_endpoint),
                )
                .route(
                    routes.admin.signal_acknowledge_route.as_str(),
                    post(signal_acknowledge_endpoint),
                )
                .route(
                    routes.admin.signal_dismiss_route.as_str(),
                    post(signal_dismiss_endpoint),
                )
                .with_state(admin_api_states.signals),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.suggestions_route.as_str(),
                    get(rule_suggestions_list_endpoint),
                )
                .route(
                    routes.admin.suggestions_generate_route.as_str(),
                    post(rule_suggestions_generate_endpoint),
                )
                .route(
                    routes.admin.suggestion_accept_route.as_str(),
                    post(rule_suggestion_accept_endpoint),
                )
                .route(
                    routes.admin.suggestion_dismiss_route.as_str(),
                    post(rule_suggestion_dismiss_endpoint),
                )
                .with_state(admin_api_states.suggestions),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.policy_route.as_str(),
                    get(policy_get_endpoint).put(policy_put_endpoint),
                )
                .route(
                    routes.admin.policy_history_route.as_str(),
                    get(policy_history_endpoint),
                )
                .route(
                    routes.admin.policy_rollback_route.as_str(),
                    post(policy_rollback_endpoint),
                )
                .route(
                    routes.admin.policy_rule_preview_route.as_str(),
                    post(policy_rule_preview_endpoint),
                )
                .route(
                    routes.admin.policy_rule_hits_route.as_str(),
                    get(policy_rule_hits_endpoint),
                )
                .route(
                    routes.admin.policy_rule_shadow_review_route.as_str(),
                    get(policy_rule_shadow_review_endpoint),
                )
                .route(
                    routes.admin.policy_validate_route.as_str(),
                    post(policy_validate_endpoint),
                )
                .route(
                    routes.admin.policy_rules_route.as_str(),
                    post(policy_rule_post_endpoint),
                )
                .route(
                    routes.admin.policy_rule_route.as_str(),
                    patch(policy_rule_patch_endpoint).delete(policy_rule_delete_endpoint),
                )
                .route(
                    routes.admin.policy_rules_order_route.as_str(),
                    put(policy_rules_order_put_endpoint),
                )
                .with_state(admin_api_states.policy),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.tokens_route.as_str(),
                    get(token_list_endpoint).post(token_create_endpoint),
                )
                .route(
                    routes.admin.token_route.as_str(),
                    get(token_get_endpoint).delete(token_revoke_endpoint),
                )
                .route(
                    routes.admin.token_rotate_route.as_str(),
                    post(token_rotate_endpoint),
                )
                .with_state(admin_api_states.tokens),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.connections_route.as_str(),
                    get(connection_list_endpoint).post(connection_create_endpoint),
                )
                .route(
                    routes.admin.connection_route.as_str(),
                    get(connection_get_endpoint)
                        .put(connection_put_endpoint)
                        .delete(connection_delete_endpoint),
                )
                .route(
                    routes.admin.connection_refresh_route.as_str(),
                    post(connection_refresh_endpoint),
                )
                .route(
                    routes.admin.connection_test_route.as_str(),
                    post(connection_test_endpoint),
                )
                .route(
                    routes.admin.connection_openapi_preview_route.as_str(),
                    post(connection_openapi_preview_endpoint),
                )
                .route(
                    routes.admin.connection_openapi_register_route.as_str(),
                    post(connection_openapi_register_endpoint),
                )
                .route(
                    routes.admin.connection_openapi_overlay_route.as_str(),
                    get(connection_openapi_overlay_get_endpoint)
                        .put(connection_openapi_overlay_put_endpoint)
                        .delete(connection_openapi_overlay_delete_endpoint),
                )
                .route(
                    routes.admin.connection_secrets_route.as_str(),
                    get(connection_secret_list_endpoint).post(connection_secret_create_endpoint),
                )
                .route(
                    routes.admin.connection_secret_route.as_str(),
                    put(connection_secret_rotate_endpoint)
                        .delete(connection_secret_delete_endpoint),
                )
                .with_state(admin_api_states.connections),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.tools_route.as_str(),
                    get(tool_inventory_list_endpoint),
                )
                .route(
                    routes.admin.tool_route.as_str(),
                    get(tool_inventory_detail_endpoint),
                )
                .route(
                    routes.admin.tool_execute_route.as_str(),
                    post(tool_playground_execute_endpoint),
                )
                .route(
                    routes.admin.tools_openapi_preview_route.as_str(),
                    post(tools_openapi_preview_endpoint),
                )
                .route(
                    routes.admin.tools_openapi_register_route.as_str(),
                    post(tools_openapi_register_endpoint),
                )
                .with_state(admin_api_states.tools),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.principals_route.as_str(),
                    get(principal_list_endpoint),
                )
                .route(
                    routes.admin.principal_detail_route.as_str(),
                    get(principal_detail_endpoint),
                )
                .with_state(admin_api_states.principals),
        )
        .merge(
            Router::new()
                .route(
                    routes.admin.traffic_endpoints_route.as_str(),
                    get(traffic_endpoint_list_endpoint),
                )
                .route(
                    routes.admin.traffic_endpoint_detail_route.as_str(),
                    get(traffic_endpoint_detail_endpoint),
                )
                .route(
                    routes.admin.traffic_endpoint_review_route.as_str(),
                    post(traffic_endpoint_review_endpoint),
                )
                .with_state(admin_api_states.traffic),
        );

    api = api.layer(axum::middleware::from_fn_with_state(
        decision_audit,
        admin_decision_audit_middleware,
    ));

    // Cluster mode's strict revision check for the admin plane: an admin
    // request whose replica cannot prove a current compiled snapshot fails
    // closed with 503, exactly like a protected data-plane request, and is
    // never authorized under a stale allow.
    #[cfg(feature = "postgres")]
    if let Some(gate) = admin_api_states.revision_gate.clone() {
        api = api.layer(axum::middleware::from_fn_with_state(
            gate,
            admin_revision_gate_middleware,
        ));
    }

    router
        .merge(api)
        .merge(admin_auth_router(routes, admin_api_states.auth))
}

/// The admin API's revision gate (issue #241, PR 7): one bound-checked read
/// of the authority before any admin endpoint runs. Without this layer the
/// admin routes -- which the RBAC middleware exempts and which authorize
/// through `RbacState`'s local snapshot -- would accept `admin:*` decisions
/// from a stale revision for as long as the replica lags the authority.
#[cfg(feature = "postgres")]
pub(super) async fn admin_revision_gate_middleware(
    State(gate): State<Arc<dyn middleware::rbac::SecurityRevisionGate>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    match gate.ensure_current_revision().await {
        Ok(_) => next.run(request).await,
        Err(_) => service_unavailable("policy state unavailable"),
    }
}

pub(super) fn admin_auth_router(routes: &GatewayRoutes, state: Option<AdminAuthState>) -> Router {
    let Some(state) = state else {
        return Router::new();
    };

    Router::new()
        .route(
            routes.admin.auth_login_route.as_str(),
            get(admin_auth_login_endpoint),
        )
        .route(
            routes.admin.auth_callback_route.as_str(),
            get(admin_auth_callback_endpoint).post(admin_auth_completion_endpoint),
        )
        .layer(axum::middleware::map_response(admin_auth_no_store))
        .with_state(state)
}

pub(super) async fn admin_auth_no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

pub(super) fn apply_middleware(
    router: Router,
    stack: &MiddlewareStack,
    proxy_fallback_enabled: bool,
) -> Router {
    let request_id_header = request_id_header();

    // Later axum layers run earlier at runtime. Observation wraps proxy dispatch
    // classification, which must complete before any validation, rate limiting,
    // auth, or RBAC layer can short-circuit the request.
    let router = if let Some(rbac_state) = stack.rbac_state.clone() {
        router.layer(axum::middleware::from_fn_with_state(
            rbac_state,
            middleware::rbac::rbac_middleware,
        ))
    } else {
        router
    };

    let router = router.layer(axum::middleware::from_fn_with_state(
        stack.rate_limit_state.clone(),
        middleware::rate_limit::policy_rate_limit_request,
    ));

    let router = if let Some(auth_state) = stack.auth_state.clone() {
        router.layer(axum::middleware::from_fn_with_state(
            auth_state,
            middleware::auth::auth_middleware,
        ))
    } else {
        router
    };

    let router = router
        .layer(axum::middleware::from_fn_with_state(
            stack.csrf_config.clone(),
            middleware::csrf::csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            stack.config.clone(),
            middleware::validate::validate_request,
        ))
        .layer(axum::middleware::from_fn_with_state(
            stack.rate_limit_state.clone(),
            middleware::rate_limit::rate_limit_request,
        ));

    // Classification runs immediately inside observation and stamps every
    // observed request, including gateway-owned and contextless requests. This
    // keeps early auth/rate-limit/validation rejections route-aware while still
    // preventing proxy policy from replacing local route policy.
    let router = router.layer(axum::middleware::from_fn_with_state(
        ProxyDispatchState {
            routes: stack.proxy_dispatch_state.routes.clone(),
            classifier: proxy_fallback_enabled
                .then(|| stack.proxy_dispatch_state.classifier.clone())
                .flatten(),
        },
        proxy_dispatch_context_middleware,
    ));

    let router = router
        .layer(axum::middleware::from_fn_with_state(
            stack.observation_state.clone(),
            middleware::observation::observation_middleware,
        ))
        .layer(axum::middleware::from_fn(
            middleware::headers::header_hardening_middleware,
        ))
        .layer(cors_layer(&stack.config))
        .layer(PropagateRequestIdLayer::new(request_id_header.clone()))
        .layer(TraceLayer::new_for_http())
        .layer(SetRequestIdLayer::new(request_id_header, MakeRequestUuid));

    #[cfg(test)]
    let router = router.layer(axum::middleware::from_fn(audit_extension_probe_middleware));

    let router = router.layer(Extension(stack.audit_log.clone()));
    let admin_routes = AdminRoutes::from_prefix(&stack.config.admin_prefix);
    router.layer(axum::middleware::from_fn_with_state(
        ManagedAdminCacheControlState {
            connections_route: admin_routes.connections_route,
            connection_secrets_route: admin_routes.connection_secrets_route,
            tools_route: admin_routes.tools_route,
        },
        managed_admin_cache_control_middleware,
    ))
}

pub(super) async fn managed_admin_cache_control_middleware(
    State(state): State<ManagedAdminCacheControlState>,
    request: AxumRequest,
    next: axum::middleware::Next,
) -> Response {
    let no_store = is_managed_admin_path(request.uri().path(), &state);
    let mut response = next.run(request).await;
    if no_store {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}

pub(super) fn is_managed_admin_path(path: &str, state: &ManagedAdminCacheControlState) -> bool {
    is_managed_connection_path(path, &state.connections_route)
        || is_connection_secret_path(path, &state.connection_secrets_route)
        || is_managed_tools_path(path, &state.tools_route)
}

pub(super) fn is_managed_connection_path(path: &str, collection_route: &str) -> bool {
    if path == collection_route {
        return true;
    }

    let Some(remainder) = path
        .strip_prefix(collection_route)
        .and_then(|remainder| remainder.strip_prefix('/'))
    else {
        return false;
    };
    let mut segments = remainder.split('/');
    match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some(id), None, None, None) => !id.is_empty(),
        (Some(id), Some("refresh" | "test"), None, None) => !id.is_empty(),
        (Some(id), Some("openapi"), Some("preview" | "register"), None) => !id.is_empty(),
        _ => false,
    }
}

pub(super) fn is_connection_secret_path(path: &str, collection_route: &str) -> bool {
    if path == collection_route {
        return true;
    }

    let Some(remainder) = path
        .strip_prefix(collection_route)
        .and_then(|remainder| remainder.strip_prefix('/'))
    else {
        return false;
    };
    !remainder.is_empty() && !remainder.contains('/')
}

pub(super) fn is_managed_tools_path(path: &str, collection_route: &str) -> bool {
    if is_capability_inventory_path(path, collection_route) {
        return true;
    }

    let Some(remainder) = path
        .strip_prefix(collection_route)
        .and_then(|remainder| remainder.strip_prefix('/'))
    else {
        return false;
    };
    let mut segments = remainder.split('/');
    matches!(
        (segments.next(), segments.next(), segments.next()),
        (Some("openapi"), Some("preview" | "register"), None)
    )
}

pub(super) fn is_capability_inventory_path(path: &str, collection_route: &str) -> bool {
    if path == collection_route {
        return true;
    }

    let Some(remainder) = path
        .strip_prefix(collection_route)
        .and_then(|remainder| remainder.strip_prefix('/'))
    else {
        return false;
    };
    if !remainder.is_empty() && !remainder.contains('/') {
        return true;
    }
    let mut segments = remainder.split('/');
    matches!(
        (segments.next(), segments.next(), segments.next()),
        (Some(id), Some("execute"), None) if !id.is_empty()
    )
}

pub(super) async fn proxy_dispatch_context_middleware(
    State(state): State<ProxyDispatchState>,
    mut request: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    request
        .extensions_mut()
        .insert(upstream_route::ProxyRouteClassificationCompleted);
    let path = request.uri().path();
    let observation_context = if !state.routes.is_gateway_owned_path(path) {
        state.classifier.as_ref().and_then(|classifier| {
            classifier.observation_context_for_request(path, request.headers())
        })
    } else {
        None
    };
    if let Some(context) = observation_context.as_ref() {
        request.extensions_mut().insert(context.clone());
        if let Some(authorization_context) = context.authorization_context() {
            request.extensions_mut().insert(authorization_context);
        }
    }

    let mut response = next.run(request).await;
    response
        .extensions_mut()
        .insert(upstream_route::ProxyRouteClassificationCompleted);
    if let Some(context) = observation_context {
        response.extensions_mut().insert(context);
    }
    response
}

pub(super) fn install_metrics_recorder(
) -> Result<PrometheusHandle, metrics_exporter_prometheus::BuildError> {
    let handle = PrometheusBuilder::new()
        .with_recommended_naming(true)
        .install_recorder()?;

    ::metrics::describe_counter!(REQUEST_COUNTER, "HTTP requests served by GreenGateway");
    ::metrics::describe_counter!(
        audit::AUDIT_EVENTS_DROPPED_TOTAL,
        "Audit events dropped by the bounded asynchronous audit channel"
    );
    ::metrics::describe_counter!(
        audit::AUDIT_SQLITE_FLUSH_ERRORS_TOTAL,
        "SQLite audit sink flush or retention prune errors"
    );
    ::metrics::describe_counter!(
        auth::principal_directory::PRINCIPAL_DIRECTORY_EVENTS_DROPPED_TOTAL,
        "Principal directory observations dropped by the bounded asynchronous channel"
    );
    ::metrics::describe_counter!(
        auth::principal_directory::PRINCIPAL_DIRECTORY_SQLITE_FLUSH_ERRORS_TOTAL,
        "SQLite principal directory flush errors"
    );
    ::metrics::describe_counter!(
        metrics::LOCK_POISON_RECOVERIES_TOTAL,
        "Lock poison recoveries by component and lock"
    );
    ::metrics::describe_counter!(
        metrics::EGRESS_CLIENT_CACHE_REQUESTS_TOTAL,
        "Exact-pinned egress client cache lookups by bounded result category"
    );
    ::metrics::describe_counter!(
        metrics::EGRESS_CLIENT_CACHE_EVICTIONS_TOTAL,
        "Exact-pinned egress client cache evictions by bounded reason"
    );
    ::metrics::describe_gauge!(
        metrics::EGRESS_CLIENT_CACHE_ENTRIES,
        "Exact-pinned egress clients currently retained across process caches"
    );

    Ok(handle)
}

pub(super) fn cors_layer(config: &config::Config) -> CorsLayer {
    let allowed_origins: Vec<HeaderValue> = config
        .cors_allow_origins
        .iter()
        .map(|origin| {
            origin
                .parse::<HeaderValue>()
                .expect("validated CORS origin should be a valid HTTP header value")
        })
        .collect();
    let allowed_headers = vec![
        header::CONTENT_TYPE,
        header::AUTHORIZATION,
        header::COOKIE,
        header::ACCEPT,
        config
            .csrf_header_name
            .parse::<HeaderName>()
            .expect("validated CSRF header name should be a valid HTTP header name"),
        request_id_header(),
    ];

    CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(allowed_headers)
        .allow_credentials(true)
}

pub(super) fn request_id_header() -> HeaderName {
    HeaderName::from_static(REQUEST_ID_HEADER)
}
