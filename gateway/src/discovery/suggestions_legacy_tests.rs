//! Frozen pre-cutover suggestion coverage from 6fc83e9, only for differential
//! tests: `policy_has_covering_action` and the host-route check it used, with
//! the helpers they called. Never compiled into the serving binary; do not
//! update their decision semantics.
//!
//! Generation now asks the shared evaluator whether the policy already covers
//! a candidate (#422 PR 4). This is the check it replaced.

use crate::{
    auth::{AuthMethod, Principal},
    rbac::{Policy, PrincipalMatcher, RuleAction, RuleDispatchContext, RuleMatcher},
};

pub(crate) fn legacy_policy_has_covering_action(
    policy: &Policy,
    method: &str,
    path_pattern: &str,
    principal: &PrincipalMatcher,
    covering_actions: &[RuleAction],
    route_host: Option<&str>,
    dispatch_context: RuleDispatchContext<'_>,
) -> bool {
    if let Some(route_host) = route_host {
        return covering_actions
            .iter()
            .any(|action| matches!(action, RuleAction::Allow | RuleAction::Shadow))
            && legacy_host_route_covers_principal(
                policy,
                method,
                path_pattern,
                route_host,
                principal,
            );
    }
    if policy.rules.is_empty() {
        return false;
    }

    let matcher = RuleMatcher::new(&policy.rules);
    let principal = legacy_representative_principal_for_matcher(principal);

    if let Some(tool_name) = legacy_tool_name_from_mcp_endpoint(method, path_pattern) {
        matcher
            .evaluate_tool(tool_name, principal.as_ref())
            .is_some_and(|decision| covering_actions.contains(&decision.action))
    } else {
        let path = legacy_representative_path_from_endpoint_template(path_pattern);
        matcher
            .evaluate_with_dispatch(method, &path, principal.as_ref(), dispatch_context)
            .is_some_and(|decision| covering_actions.contains(&decision.action))
    }
}

fn legacy_host_route_covers_principal(
    policy: &Policy,
    method: &str,
    path_pattern: &str,
    route_host: &str,
    principal: &PrincipalMatcher,
) -> bool {
    let path = legacy_representative_path_from_endpoint_template(path_pattern);
    let Some(route) = policy.routes.iter().find(|route| {
        crate::rbac::matcher::method_matches(&route.methods, method)
            && crate::path_match::path_prefix_matches(&path, &route.path_prefix)
            && route
                .hosts
                .iter()
                .any(|host| host.eq_ignore_ascii_case(route_host))
    }) else {
        return false;
    };

    principal.roles.iter().any(|role| {
        policy.roles.get(role).is_some_and(|entry| {
            entry
                .permissions
                .iter()
                .any(|permission| permission == "*" || permission == &route.permission)
        })
    })
}

fn legacy_tool_name_from_mcp_endpoint<'a>(method: &str, path_pattern: &'a str) -> Option<&'a str> {
    if !method.eq_ignore_ascii_case("MCP") {
        return None;
    }

    let tool_name = path_pattern.strip_prefix("/mcp/tools/")?;
    if tool_name.is_empty() || tool_name.contains('/') {
        return None;
    }

    Some(tool_name)
}

pub(crate) fn legacy_representative_path_from_endpoint_template(endpoint_template: &str) -> String {
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

pub(crate) fn legacy_representative_principal_for_matcher(
    matcher: &PrincipalMatcher,
) -> Option<Principal> {
    if matcher.is_unconstrained() {
        return None;
    }

    let auth_method = if matcher
        .auth_methods
        .iter()
        .any(|method| method == crate::rbac::rule::AUTH_METHOD_SERVICE_TOKEN)
    {
        AuthMethod::ServiceToken
    } else if matcher
        .auth_methods
        .iter()
        .any(|method| method == crate::rbac::rule::AUTH_METHOD_SESSION_COOKIE)
    {
        AuthMethod::Cookie
    } else {
        AuthMethod::Bearer
    };

    Some(Principal {
        user_id: matcher
            .principal_ids
            .first()
            .cloned()
            .unwrap_or_else(|| "rule-suggestion-principal".to_owned()),
        issuer: matcher.issuers.first().cloned(),
        email: None,
        org_id: None,
        roles: matcher.roles.clone(),
        session_id: "rule-suggestion".to_owned(),
        auth_method,
    })
}
