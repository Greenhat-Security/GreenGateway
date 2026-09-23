//! Frozen pre-cutover middleware from 167cc5e, only for differential tests.
//! Never compiled into the serving binary; do not update its decision semantics.

use super::*;
use crate::{path_match::path_prefix_matches, rbac::RuleDecision};
use http::Method;

pub(crate) async fn rbac_middleware(
    State(state): State<RbacState>,
    req: Request,
    next: Next,
) -> Response {
    // Pinned for the whole request once the gate admits it (cluster mode):
    // the proxy and the tool executor resolve every Connection target from
    // this snapshot, never from one a later reconcile installed mid-flight.
    #[cfg(feature = "postgres")]
    #[cfg(feature = "postgres")]
    let mut admitted_bundle: Option<Arc<crate::security_cluster::SecurityBundle>> = None;
    #[cfg(not(feature = "postgres"))]
    let admitted_bundle: Option<Arc<()>> = None;
    #[cfg(feature = "postgres")]
    let mut pinned_connections: Option<
        Arc<crate::connections::control_plane::ConnectionRuntimeSnapshot>,
    > = None;
    #[cfg(not(feature = "postgres"))]
    let pinned_connections: Option<Arc<()>> = None;
    let path = req.uri().path();
    let proxy_context = req
        .extensions()
        .get::<ProxyRouteAuthorizationContext>()
        .cloned();

    // Conservative fail-closed guard for the current local-handler stage. When
    // the Phase 3 reverse proxy lands, upgrade this to proper path
    // normalization (percent-decode plus dot-segment resolution) before route
    // matching so legitimate percent-encoded upstream paths can be supported.
    // Until then, rejecting unsafe raw paths is the safe default.
    if is_unsafe_request_path(path) {
        let context = audit_context(&req, &state.client_ip_policy);
        let principal = req.extensions().get::<auth::Principal>().cloned();
        emit_denied(&state, &context, principal.as_ref(), "unsafe_path", None);
        return with_policy_decision(
            forbidden(),
            PolicyDecision {
                outcome: PolicyDecisionOutcome::Denied,
                reason: "unsafe_path",
                permission: None,
                path_prefix: None,
                matched_rule_id: None,
            },
        );
    }

    if proxy_context.is_none() && auth::protected_resource::is_well_known_path(path) {
        return next.run(req).await;
    }

    if proxy_context.is_none()
        && !state.is_mcp_route_path(path)
        && state
            .exempt_paths
            .iter()
            .any(|exempt_path| exempt_path_matches(path, exempt_path))
    {
        return next.run(req).await;
    }

    #[cfg_attr(not(feature = "postgres"), allow(unused_mut))]
    let mut context = audit_context(&req, &state.client_ip_policy);
    let principal = req.extensions().get::<auth::Principal>().cloned();
    let policy_path = state.policy_path_for_request(path);
    let request_host = upstream_route::request_host_without_port(req.uri(), req.headers());
    let required_upstream_host = proxy_context.as_ref().map(|context| context.host.as_str());
    let dispatch_context = if req
        .extensions()
        .get::<ProxyRouteClassificationCompleted>()
        .is_none()
    {
        RuleDispatchContext::unknown()
    } else if let Some(context) = req.extensions().get::<ProxyRouteObservationContext>() {
        RuleDispatchContext::classified_with_route_id(
            context.route_id.as_deref(),
            context.route_host.as_deref(),
            context.route_path_prefix.as_deref(),
            Some(context.upstream_origin.as_str()),
        )
    } else {
        RuleDispatchContext::contextless()
    };

    // Cluster mode's strict revision check (issue #241): this request may
    // consult the local compiled snapshot only if it is keyed by the
    // authority's current security revision. A failed check is `503` with
    // zero upstream attempts -- never a `401`/`403` (a dependency failure
    // is not a policy decision), and never a stale allow.
    #[cfg(feature = "postgres")]
    let mut served_security_revision: Option<i64> = None;
    #[cfg(feature = "postgres")]
    if let Some(gate) = state.revision_gate.as_ref() {
        match gate.admit().await {
            Ok(admission) => {
                served_security_revision = Some(admission.revision);
                admitted_bundle = admission.bundle;
            }
            Err(error) => {
                emit_revision_check_failed(&state, &context, principal.as_ref(), error);
                return with_policy_decision(
                    service_unavailable_response(),
                    PolicyDecision {
                        outcome: PolicyDecisionOutcome::Denied,
                        reason: error.as_str(),
                        permission: None,
                        path_prefix: None,
                        matched_rule_id: None,
                    },
                );
            }
        }
    }

    #[cfg(feature = "postgres")]
    if served_security_revision.is_some() {
        // The bundle's Connection snapshot when the gate published one:
        // the same cut the policy below comes from. A gate without
        // bundle sources pins the live snapshot, as before.
        pinned_connections = admitted_bundle
            .as_ref()
            .map(|bundle| Arc::clone(&bundle.connections))
            .or_else(|| {
                state
                    .connections
                    .as_ref()
                    .map(|control_plane| control_plane.runtime_snapshot())
            });
    }
    // The policy this request is judged by: the bundle's, published with
    // the watermark the gate admitted at -- never a lane a concurrent
    // reconcile may have swapped since.
    #[cfg(feature = "postgres")]
    let policy: Arc<RbacPolicyState> = match admitted_bundle.as_ref() {
        Some(bundle) => Arc::clone(&bundle.policy),
        None => state.policy.load_full(),
    };
    #[cfg(not(feature = "postgres"))]
    let policy = state.policy.load();
    // Record the revision this request actually serves under: the compiled
    // watermark the gate proved current for this request, covering every
    // shared-security resource (policy, tools, ...), not just this
    // snapshot's own key.
    #[cfg(feature = "postgres")]
    {
        context.security_revision = served_security_revision;
    }
    // Direct firewall rules run before route-to-permission rules. A direct deny
    // remains global, but host-qualified upstreams require an explicit host-bound
    // route permission. Direct allow cannot authorize them, while first-match
    // shadow telemetry is retained before route evaluation. MCP aliases evaluate
    // their raw and canonical policy identities together so a deny or shadow on
    // either identity cannot be suppressed by an allow on the other.
    let first_direct_rule = matching_direct_rule(
        &policy.rule_matcher,
        req.method().as_str(),
        path,
        policy_path,
        principal.as_ref(),
        dispatch_context,
        false,
    );
    let direct_rule_decision = if required_upstream_host.is_some() {
        matching_direct_rule(
            &policy.rule_matcher,
            req.method().as_str(),
            path,
            policy_path,
            principal.as_ref(),
            dispatch_context,
            true,
        )
    } else {
        first_direct_rule.clone()
    };
    if required_upstream_host.is_some() {
        if let Some(rule_decision) = first_direct_rule.as_ref() {
            if rule_decision.action == RuleAction::Shadow {
                let matched_rule_id = policy.rule_id(rule_decision.rule_index);
                emit_rule_would_deny(&state, &context, principal.as_ref(), &matched_rule_id);
            }
        }
    }
    if let Some(rule_decision) = direct_rule_decision {
        let matched_rule_id = policy.rule_id(rule_decision.rule_index);
        return match rule_decision.action {
            RuleAction::Allow => {
                emit_rule_allowed(&state, &context, principal.as_ref(), &matched_rule_id);
                let decision = decision_for_direct_rule(
                    PolicyDecisionOutcome::Allowed,
                    "matched_rule",
                    matched_rule_id,
                );
                drop(policy);
                let response = run_pinned(
                    pinned_connections.clone(),
                    admitted_bundle.clone(),
                    next,
                    req,
                )
                .await;
                with_policy_decision(response, decision)
            }
            RuleAction::Deny => {
                emit_rule_denied(&state, &context, principal.as_ref(), &matched_rule_id);
                with_policy_decision(
                    forbidden(),
                    decision_for_direct_rule(
                        PolicyDecisionOutcome::Denied,
                        "matched_rule",
                        matched_rule_id,
                    ),
                )
            }
            RuleAction::Shadow => {
                emit_rule_would_deny(&state, &context, principal.as_ref(), &matched_rule_id);
                let decision = decision_for_direct_rule(
                    PolicyDecisionOutcome::WouldDeny,
                    "matched_rule",
                    matched_rule_id,
                );
                drop(policy);
                let response = run_pinned(
                    pinned_connections.clone(),
                    admitted_bundle.clone(),
                    next,
                    req,
                )
                .await;
                with_policy_decision(response, decision)
            }
        };
    }

    let matching_policy_route = matching_route_for_request(
        &policy.routes,
        req.method(),
        path,
        policy_path,
        required_upstream_host.or(request_host.as_deref()),
        required_upstream_host.is_some(),
    );

    if let Some(rule) = matching_policy_route {
        if principal.as_ref().is_some_and(|principal| {
            policy
                .engine
                .principal_has_permission(principal, &rule.permission)
        }) {
            emit_allowed(&state, &context, principal.as_ref(), Some(rule), None);
            let decision = decision_for_rule(PolicyDecisionOutcome::Allowed, "matched_rule", rule);
            drop(policy);
            let response = run_pinned(
                pinned_connections.clone(),
                admitted_bundle.clone(),
                next,
                req,
            )
            .await;
            return with_policy_decision(response, decision);
        }

        let reason = if principal.is_some() {
            "missing_permission"
        } else {
            "missing_principal"
        };
        return match effective_enforcement_mode(&policy, rule) {
            EnforcementMode::Enforce => {
                emit_denied(&state, &context, principal.as_ref(), reason, Some(rule));
                with_policy_decision(
                    forbidden(),
                    decision_for_rule(PolicyDecisionOutcome::Denied, reason, rule),
                )
            }
            EnforcementMode::Shadow => {
                emit_would_deny(&state, &context, principal.as_ref(), reason, Some(rule));
                let decision = decision_for_rule(PolicyDecisionOutcome::WouldDeny, reason, rule);
                drop(policy);
                let response = run_pinned(
                    pinned_connections.clone(),
                    admitted_bundle.clone(),
                    next,
                    req,
                )
                .await;
                with_policy_decision(response, decision)
            }
        };
    }

    if required_upstream_host.is_some() {
        emit_host_policy_required(
            &state,
            &context,
            principal.as_ref(),
            proxy_context
                .as_ref()
                .expect("host binding requires proxy dispatch context"),
        );
        return with_policy_decision(
            forbidden(),
            PolicyDecision {
                outcome: PolicyDecisionOutcome::Denied,
                reason: "host_policy_required",
                permission: None,
                path_prefix: None,
                matched_rule_id: None,
            },
        );
    }

    let default_action = policy.default_action.clone();
    let enforcement_mode = policy.enforcement_mode;
    drop(policy);

    match default_action {
        DefaultAction::Allow => {
            let decision = PolicyDecision {
                outcome: PolicyDecisionOutcome::Allowed,
                reason: "default_allow",
                permission: None,
                path_prefix: None,
                matched_rule_id: None,
            };
            emit_allowed(
                &state,
                &context,
                principal.as_ref(),
                None,
                Some("default_allow"),
            );
            let response = run_pinned(
                pinned_connections.clone(),
                admitted_bundle.clone(),
                next,
                req,
            )
            .await;
            with_policy_decision(response, decision)
        }
        DefaultAction::Deny => match enforcement_mode {
            EnforcementMode::Enforce => {
                emit_denied(&state, &context, principal.as_ref(), "default_deny", None);
                with_policy_decision(
                    forbidden(),
                    PolicyDecision {
                        outcome: PolicyDecisionOutcome::Denied,
                        reason: "default_deny",
                        permission: None,
                        path_prefix: None,
                        matched_rule_id: None,
                    },
                )
            }
            EnforcementMode::Shadow => {
                emit_would_deny(&state, &context, principal.as_ref(), "default_deny", None);
                let response = run_pinned(
                    pinned_connections.clone(),
                    admitted_bundle.clone(),
                    next,
                    req,
                )
                .await;
                with_policy_decision(
                    response,
                    PolicyDecision {
                        outcome: PolicyDecisionOutcome::WouldDeny,
                        reason: "default_deny",
                        permission: None,
                        path_prefix: None,
                        matched_rule_id: None,
                    },
                )
            }
        },
    }
}

fn effective_enforcement_mode(policy: &RbacPolicyState, rule: &RouteRule) -> EnforcementMode {
    rule.enforcement_mode.unwrap_or(policy.enforcement_mode)
}

fn matching_direct_rule(
    matcher: &RuleMatcher,
    method: &str,
    path: &str,
    policy_path: &str,
    principal: Option<&auth::Principal>,
    dispatch_context: RuleDispatchContext<'_>,
    denies_only: bool,
) -> Option<RuleDecision> {
    if policy_path != path {
        return matcher.evaluate_equivalent_paths_with_dispatch(
            method,
            &[policy_path, path],
            principal,
            dispatch_context,
            denies_only,
        );
    }

    if denies_only {
        matcher.evaluate_denies_with_dispatch(method, path, principal, dispatch_context)
    } else {
        matcher.evaluate_with_dispatch(method, path, principal, dispatch_context)
    }
}

#[cfg(test)]
pub(super) fn matching_route<'a>(
    routes: &'a [RouteRule],
    method: &Method,
    path: &str,
) -> Option<&'a RouteRule> {
    matching_route_with_host(routes, method, path, None, false)
}

fn matching_route_with_host<'a>(
    routes: &'a [RouteRule],
    method: &Method,
    path: &str,
    request_host: Option<&str>,
    host_binding_required: bool,
) -> Option<&'a RouteRule> {
    routes.iter().find(|rule| {
        path_prefix_matches(path, &rule.path_prefix)
            && method_matches(&rule.methods, method)
            && route_host_matches(rule, request_host, host_binding_required)
    })
}

fn matching_route_for_request<'a>(
    routes: &'a [RouteRule],
    method: &Method,
    path: &str,
    policy_path: &str,
    request_host: Option<&str>,
    host_binding_required: bool,
) -> Option<&'a RouteRule> {
    if policy_path != path {
        matching_exact_route(routes, method, path, request_host, host_binding_required).or_else(
            || {
                matching_route_with_host(
                    routes,
                    method,
                    policy_path,
                    request_host,
                    host_binding_required,
                )
            },
        )
    } else {
        matching_route_with_host(routes, method, path, request_host, host_binding_required)
    }
}

fn matching_exact_route<'a>(
    routes: &'a [RouteRule],
    method: &Method,
    path: &str,
    request_host: Option<&str>,
    host_binding_required: bool,
) -> Option<&'a RouteRule> {
    routes.iter().find(|rule| {
        rule.path_prefix == path
            && method_matches(&rule.methods, method)
            && route_host_matches(rule, request_host, host_binding_required)
    })
}

fn route_host_matches(
    rule: &RouteRule,
    request_host: Option<&str>,
    host_binding_required: bool,
) -> bool {
    if rule.hosts.is_empty() {
        return !host_binding_required;
    }

    request_host.is_some_and(|request_host| {
        rule.hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case(request_host))
    })
}

fn method_matches(methods: &[String], method: &Method) -> bool {
    methods.is_empty()
        || methods.iter().any(|configured| {
            let configured = configured.trim();
            configured == "*" || configured.eq_ignore_ascii_case(method.as_str())
        })
}
