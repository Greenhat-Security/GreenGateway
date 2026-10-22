//! The tool runtime's frozen pre-cutover RBAC consumers from 05c295a, only for
//! the differential tests in `policy_eval::tools`. Never compiled into the
//! serving binary; do not update their decision semantics.
//!
//! Each `legacy_*` method is the RBAC branch of the same-named live method as
//! it stood before the shared evaluator decided the tool lane, reading the
//! frozen `RbacState` helpers in `middleware::rbac::legacy`. The audit
//! emission and limiter bookkeeping they share with the live path are the
//! runtime's own, unchanged.
//!
//! `legacy_authorize_source_request` is the enum-source precheck's policy
//! branch as it stood at ff33fbc, before the shared evaluator decided it
//! (#422 legacy retirement): the enable bit read from the policy's tool
//! entries and the deny rules matched by a `RuleMatcher` built per call.

use super::*;
use crate::{
    middleware::rbac::legacy::{ToolAuthorizationSnapshot, ToolPolicySnapshot},
    rbac::{RuleDispatchContext, RuleMatcher},
};

impl ToolRuntime {
    /// The live policy half of admission, for comparison: the admitted limits,
    /// or the error the caller would see. Audits exactly as a served call.
    pub(crate) fn admit_for_differential(
        &self,
        tool_name: &str,
        context: &ToolInvocationContext,
    ) -> Result<ToolRuntimeToolConfig, ToolRuntimeError> {
        self.admit_invocation(tool_name, context)
            .map(|state| state.config)
    }

    /// The pre-cutover policy half of admission.
    pub(crate) fn legacy_admit(
        &self,
        tool_name: &str,
        context: &ToolInvocationContext,
    ) -> Result<ToolRuntimeToolConfig, ToolRuntimeError> {
        let authorization = match self.legacy_authorize_tool_call(tool_name, context) {
            Ok(authorization) => authorization,
            Err(error) => {
                self.emit_rejected_error(context, tool_name, &error);
                return Err(error);
            }
        };
        self.enforce_tool_rule(tool_name, context, authorization)
            .map(|state| state.config)
    }

    fn legacy_authorize_tool_call(
        &self,
        tool_name: &str,
        context: &ToolInvocationContext,
    ) -> Result<AuthorizedToolInvocation, ToolRuntimeError> {
        let principal = principal_from_tool_context(context);
        let rbac_state = self
            .inner
            .rbac_state
            .as_ref()
            .expect("the oracle covers the policy-backed branch only");
        rbac_state.legacy_evaluate_tool_authorization(
            tool_name,
            principal.as_ref(),
            |authorization| {
                self.prune_idle_limiters(authorization.tools.keys());
                let config = authorize_tool_snapshot(tool_name, context, &authorization)?;
                let limiter = self.limiter_for_tool(tool_name, config.max_concurrent);
                Ok(AuthorizedToolInvocation {
                    state: ToolExecutionState {
                        config,
                        limiter: Some(limiter),
                    },
                    rule_decision: authorization.rule_decision,
                })
            },
        )
    }

    pub(crate) fn legacy_authorize_http_operation(
        &self,
        tool_name: &str,
        method: &str,
        path: &str,
        context: &ToolInvocationContext,
    ) -> bool {
        let principal = principal_from_tool_context(context);
        let rbac_state = self
            .inner
            .rbac_state
            .as_ref()
            .expect("the oracle covers the policy-backed branch only");
        let decision = rbac_state.legacy_evaluate_tool_http_rule(method, path, principal.as_ref());

        let Some(decision) = decision else {
            return true;
        };

        let event_type = match decision.action {
            RuleAction::Allow => AUTHZ_ALLOWED,
            RuleAction::Shadow => AUTHZ_WOULD_DENY,
            RuleAction::Deny => AUTHZ_DENIED,
        };
        self.emit_http_rule_event(
            event_type,
            context,
            principal.as_ref(),
            HttpRuleAudit {
                tool_name,
                method,
                path,
                reason: "matched_rule",
                matched_rule_id: Some(&decision.matched_rule_id),
            },
        );

        decision.action != RuleAction::Deny
    }

    pub(crate) fn legacy_composite_leaf_enabled(&self, tool_name: &str) -> bool {
        let rbac_state = self
            .inner
            .rbac_state
            .as_ref()
            .expect("the oracle covers the policy-backed branch only");
        rbac_state.legacy_evaluate_tool_authorization(tool_name, None, |authorization| {
            authorization.tool.is_some_and(|tool| tool.enabled)
        })
    }

    /// The pre-cutover enum-source precheck over one policy snapshot.
    pub(crate) fn legacy_authorize_source_request(
        &self,
        policy: &Policy,
        connection_id: &ConnectionId,
        source_id: &str,
        tool: Option<&str>,
        rendered_path_and_query: &str,
        audit_path_template: &str,
    ) -> Result<(), EnumSourceFailureReason> {
        let rendered_path = rendered_path_and_query
            .split_once('?')
            .map_or(rendered_path_and_query, |(path, _)| path);
        let audit_path = audit_path_template
            .split_once('?')
            .map_or(audit_path_template, |(path, _)| path);
        if let Some(tool_name) = tool {
            let enabled = policy
                .tools
                .get(tool_name)
                .is_some_and(|entry| entry.enabled);
            if !enabled {
                self.emit_enum_source_denial(
                    connection_id,
                    source_id,
                    tool,
                    audit_path,
                    "tool_disabled",
                    None,
                );
                return Err(EnumSourceFailureReason::ToolDisabled);
            }
        }

        let matched_rule_id = RuleMatcher::new(&policy.rules)
            .evaluate_denies_with_dispatch(
                "GET",
                rendered_path,
                None,
                RuleDispatchContext::contextless(),
            )
            .map(|decision| {
                policy
                    .rules
                    .get(decision.rule_index)
                    .and_then(|rule| rule.id.clone())
                    .unwrap_or_else(|| decision.rule_index.to_string())
            });
        if let Some(matched_rule_id) = matched_rule_id {
            self.emit_enum_source_denial(
                connection_id,
                source_id,
                tool,
                audit_path,
                "http_rule_denied",
                Some(&matched_rule_id),
            );
            return Err(EnumSourceFailureReason::HttpRuleDenied);
        }
        Ok(())
    }

    pub(crate) fn legacy_tool_visible_to_context(
        &self,
        tool_name: &str,
        context: &ToolInvocationContext,
    ) -> bool {
        let rbac_state = self
            .inner
            .rbac_state
            .as_ref()
            .expect("the oracle covers the policy-backed branch only");
        let principal = principal_from_tool_context(context);
        rbac_state.legacy_evaluate_tool_authorization(
            tool_name,
            principal.as_ref(),
            |authorization| tool_visible_for_snapshot(context, &authorization),
        )
    }
}

fn tool_config_from_policy_snapshot(tool: ToolPolicySnapshot<'_>) -> ToolRuntimeToolConfig {
    ToolRuntimeToolConfig {
        enabled: tool.enabled,
        allowed_roles: tool.allowed_roles.to_vec(),
        issuers: tool.issuers.to_vec(),
        auth_methods: tool.auth_methods.to_vec(),
        timeout: Duration::from_millis(tool.timeout_ms),
        max_concurrent: tool.max_concurrent as usize,
    }
}

fn authorize_tool_snapshot(
    tool_name: &str,
    context: &ToolInvocationContext,
    authorization: &ToolAuthorizationSnapshot<'_>,
) -> Result<ToolRuntimeToolConfig, ToolRuntimeError> {
    let Some(tool) = authorization.tool else {
        return Err(ToolRuntimeError::UnknownTool {
            tool_name: tool_name.to_owned(),
        });
    };

    if !tool.enabled {
        return Err(ToolRuntimeError::Disabled {
            tool_name: tool_name.to_owned(),
        });
    }

    if !tool_principal_matches(tool.allowed_roles, tool.issuers, tool.auth_methods, context) {
        return Err(ToolRuntimeError::RoleDenied {
            tool_name: tool_name.to_owned(),
            allowed_roles: tool.allowed_roles.to_vec(),
        });
    }

    Ok(tool_config_from_policy_snapshot(tool))
}

fn tool_visible_for_snapshot(
    context: &ToolInvocationContext,
    authorization: &ToolAuthorizationSnapshot<'_>,
) -> bool {
    authorization.tool.is_some_and(|tool| {
        tool.enabled
            && tool_principal_matches(tool.allowed_roles, tool.issuers, tool.auth_methods, context)
    }) && tool_rule_allows_visibility(
        authorization
            .rule_decision
            .as_ref()
            .map(|decision| &decision.action),
    )
}

fn tool_rule_allows_visibility(rule_action: Option<&RuleAction>) -> bool {
    !matches!(rule_action, Some(RuleAction::Deny))
}
