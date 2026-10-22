//! Frozen pre-cutover analysis consumers from 6fc83e9, only for differential
//! tests: the historical rule preview's per-observation match and the traffic
//! inventory's endpoint coverage, each with the helpers it called. Never
//! compiled into the serving binary; do not update their decision semantics.
//!
//! The live consumers now ask the shared evaluator (#422 PR 4). These are the
//! implementations they replaced, so comparing the two cannot make the
//! evaluator its own oracle.

use super::*;

/// Whether the pre-cutover preview counted `observation` as a match for
/// `rule`: the body of its scan loop, for one row.
pub(crate) fn legacy_preview_matches(
    rule: &rbac::Rule,
    observation: &audit::query::RequestObservation,
) -> bool {
    let matcher = rbac::RuleMatcher::new(std::slice::from_ref(rule));
    let principal = observation
        .actor
        .as_ref()
        .and_then(legacy_principal_from_audit_actor);
    let payload = serde_json::from_str::<Value>(&observation.payload_json).ok();
    let payload_string = |key: &str| {
        payload
            .as_ref()
            .and_then(|payload| payload.get(key))
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
    };
    let dispatch_context = if payload
        .as_ref()
        .and_then(|payload| payload.get("routing_context_known"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        rbac::RuleDispatchContext::classified_with_route_id(
            payload_string("upstream_route_id"),
            payload_string("upstream_route_host"),
            payload_string("upstream_route_path_prefix"),
            payload_string("upstream_origin"),
        )
    } else {
        rbac::RuleDispatchContext::unknown()
    };

    matcher
        .evaluate_with_dispatch(
            &observation.method,
            &observation.path,
            principal.as_ref(),
            dispatch_context,
        )
        .is_some()
}

fn legacy_principal_from_audit_actor(actor: &audit::Actor) -> Option<auth::Principal> {
    let auth_method = match actor.auth_mode.as_str() {
        rbac::rule::AUTH_METHOD_BEARER_TOKEN => auth::AuthMethod::Bearer,
        rbac::rule::AUTH_METHOD_SESSION_COOKIE => auth::AuthMethod::Cookie,
        rbac::rule::AUTH_METHOD_SERVICE_TOKEN => auth::AuthMethod::ServiceToken,
        _ => return None,
    };

    Some(auth::Principal {
        user_id: actor.user_id.clone(),
        issuer: actor.issuer.clone(),
        email: actor.email.clone(),
        org_id: None,
        roles: actor.roles.clone().unwrap_or_default(),
        session_id: "audit-history".to_owned(),
        auth_method,
    })
}

pub(crate) fn legacy_endpoint_coverage_scope(
    policy: &rbac::Policy,
    method: &str,
    endpoint_template: &str,
    context: Option<&discovery::query::EndpointRoutingContext>,
) -> discovery::query::EndpointCoverageScope {
    if policy.rules.is_empty() {
        return legacy_host_route_coverage_scope(policy, method, endpoint_template, context);
    }

    let path = legacy_representative_path_from_endpoint_template(endpoint_template);
    let matcher = rbac::RuleMatcher::new(&policy.rules);
    let host_qualified = context.and_then(|context| context.route_host.as_deref());
    let dispatch_context = context.map_or_else(rbac::RuleDispatchContext::unknown, |context| {
        rbac::RuleDispatchContext::classified_with_route_id(
            context
                .upstream_origin
                .as_deref()
                .and_then(|origin| origin.strip_prefix("pool:")),
            context.route_host.as_deref(),
            context.route_path_prefix.as_deref(),
            context.upstream_origin.as_deref(),
        )
    });
    let endpoint_wide = if host_qualified.is_some() {
        matcher
            .evaluate_denies_with_dispatch(method, &path, None, dispatch_context)
            .is_some()
    } else {
        matcher
            .evaluate_with_dispatch(method, &path, None, dispatch_context)
            .is_some()
    };
    if endpoint_wide {
        return discovery::query::EndpointCoverageScope::Endpoint;
    }

    let principal_scoped = policy.rules.iter().any(|rule| {
        let Some(principal) = legacy_representative_principal_for_rule(rule) else {
            return false;
        };
        if host_qualified.is_some() {
            matcher
                .evaluate_denies_with_dispatch(method, &path, Some(&principal), dispatch_context)
                .is_some()
        } else {
            matcher
                .evaluate_with_dispatch(method, &path, Some(&principal), dispatch_context)
                .is_some()
        }
    });
    if principal_scoped {
        return discovery::query::EndpointCoverageScope::Principal;
    }

    legacy_host_route_coverage_scope(policy, method, endpoint_template, context)
}

fn legacy_host_route_coverage_scope(
    policy: &rbac::Policy,
    method: &str,
    endpoint_template: &str,
    context: Option<&discovery::query::EndpointRoutingContext>,
) -> discovery::query::EndpointCoverageScope {
    let Some(host) = context.and_then(|context| context.route_host.as_deref()) else {
        return discovery::query::EndpointCoverageScope::None;
    };
    let path = legacy_representative_path_from_endpoint_template(endpoint_template);
    let Some(route) = policy.routes.iter().find(|route| {
        rbac::matcher::method_matches(&route.methods, method)
            && path_match::path_prefix_matches(&path, &route.path_prefix)
            && route
                .hosts
                .iter()
                .any(|route_host| route_host.eq_ignore_ascii_case(host))
    }) else {
        return discovery::query::EndpointCoverageScope::None;
    };
    let permission_granted = policy.roles.values().any(|role| {
        role.permissions
            .iter()
            .any(|permission| permission == "*" || permission == &route.permission)
    });
    if permission_granted {
        discovery::query::EndpointCoverageScope::Principal
    } else {
        discovery::query::EndpointCoverageScope::None
    }
}

fn legacy_representative_path_from_endpoint_template(endpoint_template: &str) -> String {
    let Some(tail) = endpoint_template.strip_prefix('/') else {
        return endpoint_template.to_owned();
    };
    if tail.is_empty() {
        return "/".to_owned();
    }

    let segments = tail
        .split('/')
        .map(legacy_representative_path_segment)
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn legacy_representative_path_segment(segment: &str) -> String {
    let Some(capture) = segment
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        return segment.to_owned();
    };

    if capture.eq_ignore_ascii_case("id") {
        "123".to_owned()
    } else {
        "sample".to_owned()
    }
}

fn legacy_representative_principal_for_rule(rule: &rbac::Rule) -> Option<auth::Principal> {
    if rule.principal.is_unconstrained() {
        return None;
    }

    let auth_method = if rule
        .principal
        .auth_methods
        .iter()
        .any(|method| method == rbac::rule::AUTH_METHOD_SERVICE_TOKEN)
    {
        auth::AuthMethod::ServiceToken
    } else if rule
        .principal
        .auth_methods
        .iter()
        .any(|method| method == rbac::rule::AUTH_METHOD_SESSION_COOKIE)
    {
        auth::AuthMethod::Cookie
    } else {
        auth::AuthMethod::Bearer
    };

    Some(auth::Principal {
        user_id: rule
            .principal
            .principal_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "traffic-coverage-principal".to_owned()),
        issuer: rule.principal.issuers.first().cloned(),
        email: None,
        org_id: None,
        roles: rule.principal.roles.clone(),
        session_id: "traffic-coverage".to_owned(),
        auth_method,
    })
}
