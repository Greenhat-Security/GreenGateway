use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    future::Future,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use serde_json::{json, Value};
use tokio::{
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
    time,
};
use tokio_util::sync::CancellationToken;

use crate::{
    audit::{self, Actor, AuditEvent, AuditLog},
    auth::{AuthMethod, Principal},
    config::{
        Config, DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS, DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
        DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH, DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
    },
    middleware::rbac::{
        RbacState, ToolAuthorizationSnapshot, ToolPolicySnapshot, ToolRuleDecision,
    },
    rbac::{policy, rule::principal_identity_matches, Policy, Rule, RuleAction, RuleMatcher},
};

const AUTHZ_ALLOWED: &str = "authz.allowed";
const AUTHZ_DENIED: &str = "authz.denied";
const AUTHZ_WOULD_DENY: &str = "authz.would_deny";
const MCP_TOOL_OBSERVATION_METHOD: &str = "MCP";

#[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRuntimeToolConfig {
    pub enabled: bool,
    pub allowed_roles: Vec<String>,
    pub issuers: Vec<String>,
    pub auth_methods: Vec<String>,
    pub timeout: Duration,
    pub max_concurrent: usize,
}

#[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultToolPolicy {
    Deny,
    Allow,
}

#[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRuntimeConfig {
    pub max_queue: usize,
    pub queue_timeout: Duration,
    pub max_concurrent_global: usize,
    pub default_policy: DefaultToolPolicy,
    pub default_timeout: Duration,
    pub rules: Vec<Rule>,
    pub tools: HashMap<String, ToolRuntimeToolConfig>,
}

impl Default for ToolRuntimeConfig {
    fn default() -> Self {
        Self {
            max_queue: DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH,
            queue_timeout: Duration::from_millis(DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS),
            max_concurrent_global: DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
            default_policy: DefaultToolPolicy::Deny,
            default_timeout: Duration::from_millis(DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS),
            rules: Vec::new(),
            tools: HashMap::new(),
        }
    }
}

impl ToolRuntimeConfig {
    #[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
    pub fn from_env_defaults(config: &Config) -> Self {
        Self {
            max_queue: config.tool_runtime_queue_depth,
            queue_timeout: Duration::from_millis(config.tool_runtime_queue_timeout_ms),
            max_concurrent_global: config.tool_runtime_global_concurrency,
            default_timeout: Duration::from_millis(config.tool_runtime_default_timeout_ms),
            ..Self::default()
        }
    }

    #[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
    pub fn from_policy(policy: &Policy) -> Option<Self> {
        if policy.tools.is_empty() && !policy.rules.iter().any(|rule| rule.tool_name.is_some()) {
            return None;
        }

        Some(Self {
            rules: policy.rules.clone(),
            tools: policy
                .tools
                .iter()
                .map(|(name, entry)| (name.clone(), tool_config_from_policy(entry)))
                .collect(),
            ..Self::default()
        })
    }

    #[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
    pub fn with_policy_tools(mut self, policy: &Policy) -> Self {
        self.rules = policy.rules.clone();
        self.tools = policy
            .tools
            .iter()
            .map(|(name, entry)| (name.clone(), tool_config_from_policy(entry)))
            .collect();
        self
    }
}

#[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
#[derive(Debug, Clone)]
pub struct ToolInvocationContext {
    pub request_id: String,
    pub source_ip: String,
    pub actor: Option<Actor>,
}

impl Default for ToolInvocationContext {
    fn default() -> Self {
        // The runtime is request-agnostic. Future HTTP/MCP callers should pass
        // real attribution with execute_with_context; this default is for
        // non-request-triggered or transitional callers.
        Self {
            request_id: "tool-runtime".to_owned(),
            source_ip: "127.0.0.1".to_owned(),
            actor: None,
        }
    }
}

#[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolRuntimeError {
    UnknownTool {
        tool_name: String,
    },
    Disabled {
        tool_name: String,
    },
    RoleDenied {
        tool_name: String,
        allowed_roles: Vec<String>,
    },
    Rejected {
        tool_name: String,
        reason: String,
    },
    QueueTimeout {
        tool_name: String,
    },
    Timeout {
        tool_name: String,
    },
    Cancelled {
        tool_name: String,
    },
    WorkFailed {
        tool_name: String,
        message: String,
        reason: Option<String>,
    },
}

impl fmt::Display for ToolRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTool { tool_name } => {
                write!(formatter, "tool '{tool_name}' is not configured")
            }
            Self::Disabled { tool_name } => write!(formatter, "tool '{tool_name}' is disabled"),
            Self::RoleDenied {
                tool_name,
                allowed_roles,
            } => write!(
                formatter,
                "tool '{tool_name}' requires one of the allowed roles: {}",
                allowed_roles.join(", ")
            ),
            Self::Rejected { tool_name, reason } => {
                write!(formatter, "tool '{tool_name}' was rejected: {reason}")
            }
            Self::QueueTimeout { tool_name } => {
                write!(
                    formatter,
                    "tool '{tool_name}' timed out while waiting for runtime admission"
                )
            }
            Self::Timeout { tool_name } => {
                write!(formatter, "tool '{tool_name}' timed out during execution")
            }
            Self::Cancelled { tool_name } => {
                write!(formatter, "tool '{tool_name}' invocation was cancelled")
            }
            Self::WorkFailed {
                tool_name, message, ..
            } => {
                write!(formatter, "tool '{tool_name}' failed: {message}")
            }
        }
    }
}

impl Error for ToolRuntimeError {}

#[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
#[derive(Clone)]
pub struct ToolRuntime {
    inner: Arc<ToolRuntimeInner>,
}

struct ToolRuntimeInner {
    config: ToolRuntimeConfig,
    audit: AuditLog,
    queue: Arc<Semaphore>,
    global: Arc<Semaphore>,
    per_tool: Mutex<HashMap<String, Arc<ToolLimiter>>>,
    rbac_state: Option<RbacState>,
    rule_matcher: RuleMatcher,
    rule_ids: Vec<String>,
}

struct ToolExecutionState {
    config: ToolRuntimeToolConfig,
    limiter: Option<Arc<ToolLimiter>>,
}

struct AdmittedInvocation {
    config: ToolRuntimeToolConfig,
    _permits: ExecutionPermits,
}

struct AuthorizedToolInvocation {
    state: ToolExecutionState,
    rule_decision: Option<ToolRuleDecision>,
}

struct ExecutionPermits {
    _queue: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
    _tool: Option<ToolPermit>,
}

struct ToolLimiter {
    state: Mutex<ToolLimiterState>,
    notify: Notify,
}

struct ToolLimiterState {
    max_concurrent: usize,
    running: usize,
}

struct ToolPermit {
    limiter: Arc<ToolLimiter>,
}

impl ToolLimiter {
    fn new(max_concurrent: usize) -> Self {
        Self {
            state: Mutex::new(ToolLimiterState {
                max_concurrent: normalized_tool_limit(max_concurrent),
                running: 0,
            }),
            notify: Notify::new(),
        }
    }

    fn set_limit(&self, max_concurrent: usize) {
        let should_notify = {
            let mut state = lock_unpoisoned(&self.state);
            let max_concurrent = normalized_tool_limit(max_concurrent);
            let increased = max_concurrent > state.max_concurrent;
            state.max_concurrent = max_concurrent;

            increased && state.running < state.max_concurrent
        };

        if should_notify {
            self.notify.notify_waiters();
        }
    }

    async fn acquire(self: Arc<Self>) -> ToolPermit {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = lock_unpoisoned(&self.state);
                if state.running < state.max_concurrent {
                    state.running += 1;
                    return ToolPermit {
                        limiter: Arc::clone(&self),
                    };
                }
            }

            notified.await;
        }
    }

    fn is_idle(&self) -> bool {
        lock_unpoisoned(&self.state).running == 0
    }
}

impl Drop for ToolPermit {
    fn drop(&mut self) {
        let should_notify = {
            let mut state = lock_unpoisoned(&self.limiter.state);
            debug_assert!(state.running > 0);
            state.running = state.running.saturating_sub(1);
            state.running < state.max_concurrent
        };

        if should_notify {
            self.limiter.notify.notify_one();
        }
    }
}

fn normalized_tool_limit(max_concurrent: usize) -> usize {
    max_concurrent.max(1)
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl ToolRuntime {
    #[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
    pub fn new(config: ToolRuntimeConfig, audit: AuditLog) -> Self {
        Self::new_with_rbac_state(config, audit, None)
    }

    #[allow(dead_code)] // Main runtime wiring uses this once RBAC is configured.
    pub(crate) fn new_with_rbac_state(
        config: ToolRuntimeConfig,
        audit: AuditLog,
        rbac_state: Option<RbacState>,
    ) -> Self {
        let per_tool = config
            .tools
            .iter()
            .map(|(name, tool_config)| {
                (
                    name.clone(),
                    Arc::new(ToolLimiter::new(tool_config.max_concurrent)),
                )
            })
            .collect();
        let rule_matcher = RuleMatcher::new(&config.rules);
        let rule_ids = config
            .rules
            .iter()
            .enumerate()
            .map(|(rule_index, rule)| rule.id.clone().unwrap_or_else(|| rule_index.to_string()))
            .collect();

        Self {
            inner: Arc::new(ToolRuntimeInner {
                queue: Arc::new(Semaphore::new(config.max_queue.max(1))),
                global: Arc::new(Semaphore::new(config.max_concurrent_global.max(1))),
                per_tool: Mutex::new(per_tool),
                config,
                audit,
                rbac_state,
                rule_matcher,
                rule_ids,
            }),
        }
    }

    #[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
    pub async fn execute<F, Fut, T>(
        &self,
        tool_name: &str,
        cancel: CancellationToken,
        work: F,
    ) -> Result<T, ToolRuntimeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        self.execute_with_context(tool_name, ToolInvocationContext::default(), cancel, work)
            .await
    }

    #[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
    pub async fn execute_with_context<F, Fut, T>(
        &self,
        tool_name: &str,
        context: ToolInvocationContext,
        cancel: CancellationToken,
        work: F,
    ) -> Result<T, ToolRuntimeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
    {
        let admitted = self
            .prepare_invocation(tool_name, &context, &cancel)
            .await?;

        self.emit(
            audit::event::TOOL_INVOKE_START,
            &context,
            tool_name,
            "started",
            None,
        );

        tokio::select! {
            _ = cancel.cancelled() => {
                self.emit(
                    audit::event::TOOL_INVOKE_FAILURE,
                    &context,
                    tool_name,
                    "failure",
                    Some("cancelled"),
                );
                Err(ToolRuntimeError::Cancelled {
                    tool_name: tool_name.to_owned(),
                })
            }
            result = time::timeout(admitted.config.timeout, work()) => {
                match result {
                    Ok(value) => {
                        self.emit(
                            audit::event::TOOL_INVOKE_SUCCESS,
                            &context,
                            tool_name,
                            "success",
                            None,
                        );
                        Ok(value)
                    }
                    Err(_) => {
                        self.emit(
                            audit::event::TOOL_INVOKE_FAILURE,
                            &context,
                            tool_name,
                            "failure",
                            Some("timeout"),
                        );
                        Err(ToolRuntimeError::Timeout {
                            tool_name: tool_name.to_owned(),
                        })
                    }
                }
            }
        }
    }

    #[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
    pub async fn execute_result<F, Fut, T, E>(
        &self,
        tool_name: &str,
        cancel: CancellationToken,
        work: F,
    ) -> Result<T, ToolRuntimeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: fmt::Display,
    {
        self.execute_result_with_context(tool_name, ToolInvocationContext::default(), cancel, work)
            .await
    }

    #[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
    pub async fn execute_result_with_context<F, Fut, T, E>(
        &self,
        tool_name: &str,
        context: ToolInvocationContext,
        cancel: CancellationToken,
        work: F,
    ) -> Result<T, ToolRuntimeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: fmt::Display,
    {
        self.execute_result_with_context_and_reason(tool_name, context, cancel, work, |_| None)
            .await
    }

    pub(crate) async fn execute_result_with_context_and_reason<F, Fut, T, E, R>(
        &self,
        tool_name: &str,
        context: ToolInvocationContext,
        cancel: CancellationToken,
        work: F,
        failure_reason: R,
    ) -> Result<T, ToolRuntimeError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: fmt::Display,
        R: Fn(&E) -> Option<String>,
    {
        let admitted = self
            .prepare_invocation(tool_name, &context, &cancel)
            .await?;

        self.emit(
            audit::event::TOOL_INVOKE_START,
            &context,
            tool_name,
            "started",
            None,
        );

        tokio::select! {
            _ = cancel.cancelled() => {
                self.emit(
                    audit::event::TOOL_INVOKE_FAILURE,
                    &context,
                    tool_name,
                    "failure",
                    Some("cancelled"),
                );
                Err(ToolRuntimeError::Cancelled {
                    tool_name: tool_name.to_owned(),
                })
            }
            result = time::timeout(admitted.config.timeout, work()) => {
                match result {
                    Ok(Ok(value)) => {
                        self.emit(
                            audit::event::TOOL_INVOKE_SUCCESS,
                            &context,
                            tool_name,
                            "success",
                            None,
                        );
                        Ok(value)
                    }
                    Ok(Err(err)) => {
                        let reason = failure_reason(&err);
                        let message = err.to_string();
                        self.emit(
                            audit::event::TOOL_INVOKE_FAILURE,
                            &context,
                            tool_name,
                            "failure",
                            Some("work_error"),
                        );
                        Err(ToolRuntimeError::WorkFailed {
                            tool_name: tool_name.to_owned(),
                            message,
                            reason,
                        })
                    }
                    Err(_) => {
                        self.emit(
                            audit::event::TOOL_INVOKE_FAILURE,
                            &context,
                            tool_name,
                            "failure",
                            Some("timeout"),
                        );
                        Err(ToolRuntimeError::Timeout {
                            tool_name: tool_name.to_owned(),
                        })
                    }
                }
            }
        }
    }

    async fn prepare_invocation(
        &self,
        tool_name: &str,
        context: &ToolInvocationContext,
        cancel: &CancellationToken,
    ) -> Result<AdmittedInvocation, ToolRuntimeError> {
        let authorization = match self.authorize_tool_call(tool_name, context) {
            Ok(authorization) => authorization,
            Err(error) => {
                self.emit_rejected_error(context, tool_name, &error);
                return Err(error);
            }
        };
        let state = authorization.state;

        let principal = principal_from_tool_context(context);
        if let Some(rule_decision) = authorization.rule_decision {
            let matched_rule_id = rule_decision.matched_rule_id;
            match rule_decision.action {
                RuleAction::Allow => {
                    self.emit_tool_rule_event(
                        AUTHZ_ALLOWED,
                        context,
                        tool_name,
                        principal.as_ref(),
                        &matched_rule_id,
                    );
                }
                RuleAction::Shadow => {
                    self.emit_tool_rule_event(
                        AUTHZ_WOULD_DENY,
                        context,
                        tool_name,
                        principal.as_ref(),
                        &matched_rule_id,
                    );
                }
                RuleAction::Deny => {
                    self.emit_tool_rule_event(
                        AUTHZ_DENIED,
                        context,
                        tool_name,
                        principal.as_ref(),
                        &matched_rule_id,
                    );
                    self.emit_rejected(context, tool_name, "matched_rule");
                    return Err(ToolRuntimeError::Rejected {
                        tool_name: tool_name.to_owned(),
                        reason: "matched_rule".to_owned(),
                    });
                }
            }
        }

        let queue_permit = match Arc::clone(&self.inner.queue).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.emit_rejected(context, tool_name, "queue_full");
                return Err(ToolRuntimeError::Rejected {
                    tool_name: tool_name.to_owned(),
                    reason: "queue_full".to_owned(),
                });
            }
        };

        let acquire = Self::acquire_execution_permits(
            queue_permit,
            Arc::clone(&self.inner.global),
            state.limiter.clone(),
            tool_name.to_owned(),
        );

        let permits = tokio::select! {
            _ = cancel.cancelled() => {
                self.emit_rejected(context, tool_name, "cancelled");
                return Err(ToolRuntimeError::Cancelled {
                    tool_name: tool_name.to_owned(),
                });
            }
            result = time::timeout(self.inner.config.queue_timeout, acquire) => {
                match result {
                    Ok(Ok(permits)) => permits,
                    Ok(Err(error)) => {
                        self.emit_rejected_error(context, tool_name, &error);
                        return Err(error);
                    }
                    Err(_) => {
                        self.emit_rejected(context, tool_name, "queue_timeout");
                        return Err(ToolRuntimeError::QueueTimeout {
                            tool_name: tool_name.to_owned(),
                        });
                    }
                }
            }
        };

        Ok(AdmittedInvocation {
            config: state.config,
            _permits: permits,
        })
    }

    fn authorize_tool_call(
        &self,
        tool_name: &str,
        context: &ToolInvocationContext,
    ) -> Result<AuthorizedToolInvocation, ToolRuntimeError> {
        let principal = principal_from_tool_context(context);
        if let Some(rbac_state) = &self.inner.rbac_state {
            return rbac_state.evaluate_tool_authorization(
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
            );
        }

        let state = self.lookup_tool(tool_name)?;
        if !state.config.enabled {
            return Err(ToolRuntimeError::Disabled {
                tool_name: tool_name.to_owned(),
            });
        }

        let rule_decision = self
            .inner
            .rule_matcher
            .evaluate_tool(tool_name, principal.as_ref())
            .map(|decision| ToolRuleDecision {
                action: decision.action,
                matched_rule_id: self.rule_id(decision.rule_index),
            });

        if !tool_principal_matches(
            &state.config.allowed_roles,
            &state.config.issuers,
            &state.config.auth_methods,
            context,
        ) {
            return Err(ToolRuntimeError::RoleDenied {
                tool_name: tool_name.to_owned(),
                allowed_roles: state.config.allowed_roles.clone(),
            });
        }

        Ok(AuthorizedToolInvocation {
            state,
            rule_decision,
        })
    }

    fn rule_id(&self, rule_index: usize) -> String {
        self.inner
            .rule_ids
            .get(rule_index)
            .cloned()
            .unwrap_or_else(|| rule_index.to_string())
    }

    pub(crate) fn tool_visible_to_context(
        &self,
        tool_name: &str,
        context: &ToolInvocationContext,
    ) -> bool {
        if let Some(rbac_state) = &self.inner.rbac_state {
            let principal = principal_from_tool_context(context);
            return rbac_state.evaluate_tool_authorization(
                tool_name,
                principal.as_ref(),
                |authorization| tool_visible_for_snapshot(context, &authorization),
            );
        }

        let Ok(state) = self.lookup_tool(tool_name) else {
            return false;
        };

        if !state.config.enabled {
            return false;
        }

        let principal = principal_from_tool_context(context);
        let rule_action = self
            .inner
            .rule_matcher
            .evaluate_tool(tool_name, principal.as_ref())
            .map(|decision| decision.action);
        if !tool_rule_allows_visibility(rule_action.as_ref()) {
            return false;
        }

        tool_principal_matches(
            &state.config.allowed_roles,
            &state.config.issuers,
            &state.config.auth_methods,
            context,
        )
    }

    async fn acquire_execution_permits(
        queue: OwnedSemaphorePermit,
        global: Arc<Semaphore>,
        tool: Option<Arc<ToolLimiter>>,
        tool_name: String,
    ) -> Result<ExecutionPermits, ToolRuntimeError> {
        let global = global
            .acquire_owned()
            .await
            .map_err(|_| ToolRuntimeError::Rejected {
                tool_name: tool_name.clone(),
                reason: "runtime_closed".to_owned(),
            })?;
        let tool = match tool {
            Some(tool) => Some(tool.acquire().await),
            None => None,
        };

        Ok(ExecutionPermits {
            _queue: queue,
            _global: global,
            _tool: tool,
        })
    }

    fn lookup_tool(&self, tool_name: &str) -> Result<ToolExecutionState, ToolRuntimeError> {
        if let Some(tool_config) = self.inner.config.tools.get(tool_name).cloned() {
            let limiter = self.limiter_for_tool(tool_name, tool_config.max_concurrent);
            return Ok(ToolExecutionState {
                config: tool_config,
                limiter: Some(limiter),
            });
        }

        match self.inner.config.default_policy {
            DefaultToolPolicy::Deny => Err(ToolRuntimeError::UnknownTool {
                tool_name: tool_name.to_owned(),
            }),
            DefaultToolPolicy::Allow => Ok(ToolExecutionState {
                config: ToolRuntimeToolConfig {
                    enabled: true,
                    allowed_roles: Vec::new(),
                    issuers: Vec::new(),
                    auth_methods: Vec::new(),
                    timeout: self.inner.config.default_timeout,
                    max_concurrent: self.inner.config.max_concurrent_global,
                },
                limiter: None,
            }),
        }
    }

    fn limiter_for_tool(&self, tool_name: &str, max_concurrent: usize) -> Arc<ToolLimiter> {
        let limiter = {
            let mut per_tool = lock_unpoisoned(&self.inner.per_tool);
            per_tool
                .entry(tool_name.to_owned())
                .or_insert_with(|| Arc::new(ToolLimiter::new(max_concurrent)))
                .clone()
        };
        limiter.set_limit(max_concurrent);
        limiter
    }

    fn prune_idle_limiters<'a>(&self, active_tool_names: impl IntoIterator<Item = &'a String>) {
        let active_tool_names = active_tool_names
            .into_iter()
            .cloned()
            .collect::<HashSet<_>>();
        let mut per_tool = lock_unpoisoned(&self.inner.per_tool);
        per_tool.retain(|tool_name, limiter| {
            active_tool_names.contains(tool_name)
                || Arc::strong_count(limiter) > 1
                || !limiter.is_idle()
        });
    }

    fn emit_rejected_error(
        &self,
        context: &ToolInvocationContext,
        tool_name: &str,
        error: &ToolRuntimeError,
    ) {
        let reason = match error {
            ToolRuntimeError::UnknownTool { .. } => "unknown_tool",
            ToolRuntimeError::Disabled { .. } => "disabled",
            ToolRuntimeError::RoleDenied { .. } => "role_not_allowed",
            ToolRuntimeError::Rejected { reason, .. } => reason,
            ToolRuntimeError::QueueTimeout { .. } => "queue_timeout",
            ToolRuntimeError::Timeout { .. } => "timeout",
            ToolRuntimeError::Cancelled { .. } => "cancelled",
            ToolRuntimeError::WorkFailed { .. } => "work_error",
        };
        self.emit_rejected(context, tool_name, reason);
    }

    fn emit_rejected(&self, context: &ToolInvocationContext, tool_name: &str, reason: &str) {
        self.emit(
            audit::event::TOOL_INVOKE_REJECTED,
            context,
            tool_name,
            "rejected",
            Some(reason),
        );
    }

    fn emit_tool_rule_event(
        &self,
        event_type: &'static str,
        context: &ToolInvocationContext,
        tool_name: &str,
        principal: Option<&Principal>,
        matched_rule_id: &str,
    ) {
        self.inner.audit.emit(AuditEvent::new(
            event_type,
            &context.request_id,
            &context.source_ip,
            principal.map(crate::auth::actor_from_principal),
            json!({
                "tool_name": tool_name,
                "path": tool_observation_path(tool_name),
                "method": MCP_TOOL_OBSERVATION_METHOD,
                "reason": "matched_rule",
                "matched_rule_id": matched_rule_id,
            }),
        ));
    }

    fn emit(
        &self,
        event_type: &'static str,
        context: &ToolInvocationContext,
        tool_name: &str,
        outcome: &'static str,
        reason: Option<&str>,
    ) {
        self.inner.audit.emit(AuditEvent::new(
            event_type,
            &context.request_id,
            &context.source_ip,
            context.actor.clone(),
            tool_audit_payload(tool_name, outcome, reason),
        ));
    }
}

fn tool_config_from_policy(entry: &policy::ToolPolicyEntry) -> ToolRuntimeToolConfig {
    ToolRuntimeToolConfig {
        enabled: entry.enabled,
        allowed_roles: entry.allowed_roles.clone(),
        issuers: entry.issuers.clone(),
        auth_methods: entry.auth_methods.clone(),
        timeout: Duration::from_millis(entry.timeout_ms),
        max_concurrent: entry.max_concurrent as usize,
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

fn tool_principal_matches(
    allowed_roles: &[String],
    issuers: &[String],
    auth_methods: &[String],
    context: &ToolInvocationContext,
) -> bool {
    if allowed_roles.is_empty() && issuers.is_empty() && auth_methods.is_empty() {
        return true;
    }

    let Some(principal) = principal_from_tool_context(context) else {
        return false;
    };

    principal_identity_matches(issuers, auth_methods, &principal)
        && (allowed_roles.is_empty()
            || allowed_roles
                .iter()
                .any(|allowed_role| principal.roles.iter().any(|role| role == allowed_role)))
}

fn principal_from_tool_context(context: &ToolInvocationContext) -> Option<Principal> {
    let actor = context.actor.as_ref()?;
    let auth_method = auth_method_from_audit_mode(&actor.auth_mode)?;

    Some(Principal {
        user_id: actor.user_id.clone(),
        issuer: actor.issuer.clone(),
        email: actor.email.clone(),
        org_id: None,
        roles: actor.roles.clone().unwrap_or_default(),
        session_id: context.request_id.clone(),
        auth_method,
    })
}

fn auth_method_from_audit_mode(auth_mode: &str) -> Option<AuthMethod> {
    match auth_mode {
        crate::rbac::rule::AUTH_METHOD_BEARER_TOKEN => Some(AuthMethod::Bearer),
        crate::rbac::rule::AUTH_METHOD_SESSION_COOKIE => Some(AuthMethod::Cookie),
        crate::rbac::rule::AUTH_METHOD_SERVICE_TOKEN => Some(AuthMethod::ServiceToken),
        _ => None,
    }
}

fn tool_audit_payload(tool_name: &str, outcome: &'static str, reason: Option<&str>) -> Value {
    let mut payload = json!({
        "tool_name": tool_name,
        "outcome": outcome,
    });

    if let Some(reason) = reason {
        payload["reason"] = json!(reason);
    }

    payload
}

fn tool_observation_path(tool_name: &str) -> String {
    format!("/mcp/tools/{tool_name}")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use serde_json::json;
    use tokio::sync::Notify;
    use tokio_util::sync::CancellationToken;

    use super::*;
    use crate::audit::{
        sink::{tests::CaptureSink, AuditSink},
        Actor, AuditEvent, AuditLog,
    };
    use crate::rbac::{Policy, PrincipalMatcher, Rule, RuleAction};

    #[tokio::test]
    async fn unknown_tool_is_rejected_and_audited_once() {
        let (runtime, capture) = runtime_with_tools([("known", enabled_tool(100, 1))], 2, 1, 100);

        let error = runtime
            .execute_with_context("missing", context(), CancellationToken::new(), || async {
                "should not run"
            })
            .await
            .expect_err("unknown tool should be rejected");

        assert!(matches!(error, ToolRuntimeError::UnknownTool { .. }));
        assert_rejected_events(&capture, "missing", "unknown_tool", 1).await;
    }

    #[tokio::test]
    async fn disabled_tool_is_rejected_and_audited_once() {
        let (runtime, capture) =
            runtime_with_tools([("disabled", disabled_tool(100, 1))], 2, 1, 100);

        let error = runtime
            .execute_with_context("disabled", context(), CancellationToken::new(), || async {
                "should not run"
            })
            .await
            .expect_err("disabled tool should be rejected");

        assert!(matches!(error, ToolRuntimeError::Disabled { .. }));
        assert_rejected_events(&capture, "disabled", "disabled", 1).await;
    }

    #[tokio::test]
    async fn role_restricted_tool_requires_any_allowed_role_and_audits_rejection() {
        let (runtime, capture) = runtime_with_tools(
            [("tool", role_restricted_tool(100, 1, &["operator"]))],
            2,
            1,
            100,
        );

        let denied = runtime
            .execute_with_context(
                "tool",
                context_with_roles(&["viewer"]),
                CancellationToken::new(),
                || async { "should not run" },
            )
            .await
            .expect_err("viewer should not satisfy operator role policy");

        assert!(matches!(
            denied,
            ToolRuntimeError::RoleDenied {
                ref allowed_roles,
                ..
            } if allowed_roles.as_slice() == ["operator"]
        ));
        assert_rejected_events(&capture, "tool", "role_not_allowed", 1).await;

        let allowed = runtime
            .execute_with_context(
                "tool",
                context_with_roles(&["viewer", "operator"]),
                CancellationToken::new(),
                || async { "allowed" },
            )
            .await
            .expect("any overlapping role should allow invocation");

        assert_eq!(allowed, "allowed");
    }

    #[tokio::test]
    async fn tool_policy_separates_colliding_roles_by_issuer_and_auth_method() {
        let mut tool = role_restricted_tool(100, 1, &["operator"]);
        tool.issuers = vec!["https://idp-a.example/".to_owned()];
        tool.auth_methods = vec!["bearer_token".to_owned()];
        let (runtime, _capture) = runtime_with_tools([("tool", tool)], 2, 1, 100);

        let denied = runtime
            .execute_with_context(
                "tool",
                context_with_identity(
                    &["operator"],
                    Some("https://idp-b.example/"),
                    "bearer_token",
                ),
                CancellationToken::new(),
                || async { "should not run" },
            )
            .await
            .expect_err("same role from another issuer must not invoke the tool");
        assert!(matches!(denied, ToolRuntimeError::RoleDenied { .. }));

        let allowed = runtime
            .execute_with_context(
                "tool",
                context_with_identity(
                    &["operator"],
                    Some("https://idp-a.example/"),
                    "bearer_token",
                ),
                CancellationToken::new(),
                || async { "allowed" },
            )
            .await
            .expect("matching issuer and auth method should allow invocation");

        assert_eq!(allowed, "allowed");
    }

    #[tokio::test]
    async fn empty_allowed_roles_do_not_constrain_actor_roles() {
        let (runtime, _capture) = runtime_with_tools([("tool", enabled_tool(100, 1))], 2, 1, 100);

        let empty_roles_actor = runtime
            .execute_with_context(
                "tool",
                context_with_roles(&[]),
                CancellationToken::new(),
                || async { "empty-roles" },
            )
            .await
            .expect("empty allowed_roles should accept an actor with no roles");
        let unauthenticated = runtime
            .execute_with_context("tool", context(), CancellationToken::new(), || async {
                "unauthenticated"
            })
            .await
            .expect("empty allowed_roles should not require authentication");

        assert_eq!(empty_roles_actor, "empty-roles");
        assert_eq!(unauthenticated, "unauthenticated");
    }

    #[tokio::test]
    async fn tool_name_deny_rule_blocks_tool_allowed_by_empty_allowed_roles() {
        let (runtime, capture) = runtime_with_tools_and_rules(
            [("tool", enabled_tool(100, 1))],
            vec![tool_rule(
                Some("deny-tool-for-viewers"),
                "tool",
                &["viewer"],
                RuleAction::Deny,
            )],
            2,
            1,
            100,
        );

        let denied = runtime
            .execute_with_context(
                "tool",
                context_with_roles(&["viewer"]),
                CancellationToken::new(),
                || async { "should not run" },
            )
            .await
            .expect_err("matching Deny rule should block even with empty allowed_roles");

        assert!(matches!(
            denied,
            ToolRuntimeError::Rejected { ref reason, .. } if reason == "matched_rule"
        ));
        assert_rejected_events(&capture, "tool", "matched_rule", 1).await;
        let events = audit_events(&capture, 2).await;
        assert!(
            events.iter().any(|event| {
                event.event_type == "authz.denied"
                    && event.payload["method"] == json!("MCP")
                    && event.payload["path"] == json!("/mcp/tools/tool")
                    && event.payload["matched_rule_id"] == json!("deny-tool-for-viewers")
            }),
            "tool Deny rule should emit an authz.denied direct-rule event: {events:#?}"
        );
    }

    #[tokio::test]
    async fn tool_name_deny_rule_hides_tool_from_matching_context() {
        let (runtime, _capture) = runtime_with_tools_and_rules(
            [("tool", enabled_tool(100, 1))],
            vec![tool_rule(
                Some("deny-tool-for-viewers"),
                "tool",
                &["viewer"],
                RuleAction::Deny,
            )],
            2,
            1,
            100,
        );

        assert!(
            !runtime.tool_visible_to_context("tool", &context_with_roles(&["viewer"])),
            "matching deny rule should hide tool from discovery"
        );
        assert!(
            runtime.tool_visible_to_context("tool", &context_with_roles(&["operator"])),
            "non-matching context should still see the tool"
        );
    }

    #[tokio::test]
    async fn tool_name_shadow_rule_emits_would_deny_and_allows_execution() {
        let (runtime, capture) = runtime_with_tools_and_rules(
            [("tool", enabled_tool(100, 1))],
            vec![tool_rule(
                Some("shadow-tool-for-viewers"),
                "tool",
                &["viewer"],
                RuleAction::Shadow,
            )],
            2,
            1,
            100,
        );
        let work_ran = Arc::new(AtomicBool::new(false));
        let work_ran_in_closure = Arc::clone(&work_ran);

        let result = runtime
            .execute_with_context(
                "tool",
                context_with_roles(&["viewer"]),
                CancellationToken::new(),
                || async move {
                    work_ran_in_closure.store(true, Ordering::SeqCst);
                    "allowed"
                },
            )
            .await
            .expect("shadow tool_name rule should not block execution");

        assert_eq!(result, "allowed");
        assert!(
            work_ran.load(Ordering::SeqCst),
            "work closure should run under shadow tool_name rule"
        );

        let events = audit_events(&capture, 3).await;
        let would_deny: Vec<_> = events
            .iter()
            .filter(|event| event.event_type == "authz.would_deny")
            .collect();
        assert_eq!(would_deny.len(), 1, "{events:#?}");
        let event = would_deny[0];
        assert_eq!(event.payload["tool_name"], json!("tool"));
        assert_eq!(event.payload["method"], json!("MCP"));
        assert_eq!(event.payload["path"], json!("/mcp/tools/tool"));
        assert_eq!(
            event.payload["matched_rule_id"],
            json!("shadow-tool-for-viewers")
        );
    }

    #[tokio::test]
    async fn policy_reload_updates_live_tool_name_rules_for_same_runtime() {
        let file = TempPolicyFile::new(&tool_policy_document_without_rules());
        let initial_policy =
            Policy::from_file(file.path()).expect("initial tool policy should parse");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture) as Arc<dyn AuditSink>);
        let rbac_state = crate::middleware::rbac::RbacState::new(
            initial_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        let runtime_config = ToolRuntimeConfig::from_policy(&initial_policy)
            .expect("initial tool policy should configure runtime");
        let runtime =
            ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state.clone()));

        let allowed = runtime
            .execute_with_context(
                "echo",
                context_with_roles(&["admin"]),
                CancellationToken::new(),
                || async { "allowed-before-reload" },
            )
            .await
            .expect("tool call should be allowed before rule reload");
        assert_eq!(allowed, "allowed-before-reload");

        file.write(&tool_policy_document_with_deny_rule());
        crate::middleware::rbac::reload_policy_from_file(&rbac_state, file.path())
            .expect("valid tool policy reload should succeed");

        let denied = runtime
            .execute_with_context(
                "echo",
                context_with_roles(&["admin"]),
                CancellationToken::new(),
                || async { "should not run after reload" },
            )
            .await
            .expect_err("same runtime should use reloaded tool-name Deny rule");

        assert!(matches!(
            denied,
            ToolRuntimeError::Rejected { ref reason, .. } if reason == "matched_rule"
        ));
    }

    #[tokio::test]
    async fn policy_reload_updates_live_allowed_roles_for_same_runtime() {
        let file = TempPolicyFile::new(&tool_policy_document_with_allowed_roles(&["operator"]));
        let initial_policy =
            Policy::from_file(file.path()).expect("initial tool policy should parse");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let rbac_state = crate::middleware::rbac::RbacState::new(
            initial_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        let runtime_config = ToolRuntimeConfig::from_policy(&initial_policy)
            .expect("initial tool policy should configure runtime");
        let runtime =
            ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state.clone()));

        let allowed = runtime
            .execute_with_context(
                "echo",
                context_with_roles(&["operator"]),
                CancellationToken::new(),
                || async { "allowed-before-reload" },
            )
            .await
            .expect("initial allowed_roles should admit operator");
        assert_eq!(allowed, "allowed-before-reload");

        file.write(&tool_policy_document_with_allowed_roles(&["admin"]));
        crate::middleware::rbac::reload_policy_from_file(&rbac_state, file.path())
            .expect("valid tool policy reload should succeed");

        let denied = runtime
            .execute_with_context(
                "echo",
                context_with_roles(&["operator"]),
                CancellationToken::new(),
                || async { "should not run after reload" },
            )
            .await
            .expect_err("same runtime should use reloaded allowed_roles");

        assert!(matches!(
            denied,
            ToolRuntimeError::RoleDenied {
                ref allowed_roles,
                ..
            } if allowed_roles.as_slice() == ["admin"]
        ));
        assert_rejected_events(&capture, "echo", "role_not_allowed", 1).await;

        let allowed = runtime
            .execute_with_context(
                "echo",
                context_with_roles(&["admin"]),
                CancellationToken::new(),
                || async { "allowed-after-reload" },
            )
            .await
            .expect("reloaded allowed_roles should admit admin");
        assert_eq!(allowed, "allowed-after-reload");
    }

    #[tokio::test]
    async fn policy_reload_disables_tool_for_same_runtime() {
        let file = TempPolicyFile::new(&tool_policy_document_without_rules());
        let initial_policy =
            Policy::from_file(file.path()).expect("initial tool policy should parse");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let rbac_state = crate::middleware::rbac::RbacState::new(
            initial_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        let runtime_config = ToolRuntimeConfig::from_policy(&initial_policy)
            .expect("initial tool policy should configure runtime");
        let runtime =
            ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state.clone()));

        let allowed = runtime
            .execute_with_context("echo", context(), CancellationToken::new(), || async {
                "allowed-before-reload"
            })
            .await
            .expect("tool call should be allowed before disabling reload");
        assert_eq!(allowed, "allowed-before-reload");

        file.write(&tool_policy_document_with_echo_enabled(false));
        crate::middleware::rbac::reload_policy_from_file(&rbac_state, file.path())
            .expect("valid tool policy reload should succeed");

        let disabled = runtime
            .execute_with_context("echo", context(), CancellationToken::new(), || async {
                "should not run after reload"
            })
            .await
            .expect_err("same runtime should use reloaded enabled=false state");

        assert!(matches!(disabled, ToolRuntimeError::Disabled { .. }));
        assert_rejected_events(&capture, "echo", "disabled", 1).await;
    }

    #[tokio::test]
    async fn policy_reload_removes_tool_membership_for_same_runtime() {
        let file = TempPolicyFile::new(&tool_policy_document_without_rules());
        let initial_policy =
            Policy::from_file(file.path()).expect("initial tool policy should parse");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let rbac_state = crate::middleware::rbac::RbacState::new(
            initial_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        let runtime_config = ToolRuntimeConfig::from_policy(&initial_policy)
            .expect("initial tool policy should configure runtime");
        let runtime =
            ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state.clone()));

        let allowed = runtime
            .execute_with_context("echo", context(), CancellationToken::new(), || async {
                "allowed-before-reload"
            })
            .await
            .expect("tool call should be allowed before removal reload");
        assert_eq!(allowed, "allowed-before-reload");
        assert!(
            lock_unpoisoned(&runtime.inner.per_tool).contains_key("echo"),
            "initial call should populate an echo limiter"
        );

        file.write(&tool_policy_document_without_tools());
        crate::middleware::rbac::reload_policy_from_file(&rbac_state, file.path())
            .expect("valid tool policy reload should succeed");

        let removed = runtime
            .execute_with_context("echo", context(), CancellationToken::new(), || async {
                "should not run after reload"
            })
            .await
            .expect_err("same runtime should use reloaded tool membership");

        assert!(matches!(removed, ToolRuntimeError::UnknownTool { .. }));
        assert_rejected_events(&capture, "echo", "unknown_tool", 1).await;
        assert!(
            !lock_unpoisoned(&runtime.inner.per_tool).contains_key("echo"),
            "idle limiter for removed tool should be pruned"
        );
    }

    #[tokio::test]
    async fn policy_reload_updates_live_max_concurrent_for_same_runtime() {
        let file = TempPolicyFile::new(&tool_policy_document_with_echo_max_concurrent(1));
        let initial_policy =
            Policy::from_file(file.path()).expect("initial tool policy should parse");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture) as Arc<dyn AuditSink>);
        let rbac_state = crate::middleware::rbac::RbacState::new(
            initial_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        let mut runtime_config = ToolRuntimeConfig::from_policy(&initial_policy)
            .expect("initial tool policy should configure runtime");
        runtime_config.max_queue = 4;
        runtime_config.max_concurrent_global = 2;
        runtime_config.queue_timeout = Duration::from_secs(1);
        let runtime =
            ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state.clone()));

        file.write(&tool_policy_document_with_echo_max_concurrent(2));
        crate::middleware::rbac::reload_policy_from_file(&rbac_state, file.path())
            .expect("valid tool policy reload should succeed");

        let tracker = Arc::new(ConcurrencyTracker::default());
        let release = ReleaseGate::new();
        let handles = vec![
            spawn_tracked_invocation(
                runtime.clone(),
                "echo",
                Arc::clone(&tracker),
                release.clone(),
            ),
            spawn_tracked_invocation(
                runtime.clone(),
                "echo",
                Arc::clone(&tracker),
                release.clone(),
            ),
        ];

        tracker.wait_for_started(2).await;
        release.release();

        for handle in handles {
            handle
                .await
                .expect("invocation task should join")
                .expect("invocation should succeed");
        }
        assert_eq!(tracker.max_running.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn policy_reload_readd_keeps_limiter_owned_by_globally_queued_call() {
        let file = TempPolicyFile::new(&tool_policy_document_with_echo_max_concurrent(1));
        let initial_policy =
            Policy::from_file(file.path()).expect("initial tool policy should parse");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture) as Arc<dyn AuditSink>);
        let rbac_state = crate::middleware::rbac::RbacState::new(
            initial_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        let mut runtime_config = ToolRuntimeConfig::from_policy(&initial_policy)
            .expect("initial tool policy should configure runtime");
        runtime_config.max_queue = 4;
        runtime_config.max_concurrent_global = 1;
        runtime_config.queue_timeout = Duration::from_secs(2);
        let runtime =
            ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state.clone()));

        let blocker_release = ReleaseGate::new();
        let blocker = spawn_blocking_invocation(runtime.clone(), "echo", blocker_release.clone());
        wait_until(Duration::from_secs(1), || {
            runtime.inner.global.available_permits() == 0
        })
        .await;

        let tracker = Arc::new(ConcurrencyTracker::default());
        let queued_release = ReleaseGate::new();
        let queued_before_reload = spawn_tracked_invocation(
            runtime.clone(),
            "echo",
            Arc::clone(&tracker),
            queued_release.clone(),
        );
        wait_until(Duration::from_secs(1), || {
            lock_unpoisoned(&runtime.inner.per_tool)
                .get("echo")
                .is_some_and(|limiter| Arc::strong_count(limiter) > 1)
        })
        .await;

        file.write(&tool_policy_document_without_tools());
        crate::middleware::rbac::reload_policy_from_file(&rbac_state, file.path())
            .expect("valid tool removal reload should succeed");
        let _ = runtime
            .execute_with_context("missing", context(), CancellationToken::new(), || async {
                "trigger-prune"
            })
            .await
            .expect_err("unknown tool should be rejected");
        assert!(
            lock_unpoisoned(&runtime.inner.per_tool).contains_key("echo"),
            "queued call's limiter should not be pruned while it has outside owners"
        );

        file.write(&tool_policy_document_with_echo_max_concurrent(1));
        crate::middleware::rbac::reload_policy_from_file(&rbac_state, file.path())
            .expect("valid tool re-add reload should succeed");

        let after_readd_release = ReleaseGate::new();
        let after_readd = spawn_tracked_invocation(
            runtime.clone(),
            "echo",
            Arc::clone(&tracker),
            after_readd_release.clone(),
        );

        blocker_release.release();
        blocker
            .await
            .expect("blocker task should join")
            .expect("blocker invocation should succeed");
        tracker.wait_for_started(1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            tracker.started.load(Ordering::SeqCst),
            1,
            "re-added tool should reuse the limiter owned by the queued call"
        );

        queued_release.release();
        queued_before_reload
            .await
            .expect("queued invocation task should join")
            .expect("queued invocation should succeed");

        tracker.wait_for_started(2).await;
        after_readd_release.release();
        after_readd
            .await
            .expect("post-readd invocation task should join")
            .expect("post-readd invocation should succeed");
        assert_eq!(tracker.max_running.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn policy_reload_added_tool_uses_reloaded_max_concurrent() {
        let file = TempPolicyFile::new(&tool_policy_document_with_echo_max_concurrent(2));
        let initial_policy =
            Policy::from_file(file.path()).expect("initial tool policy should parse");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture) as Arc<dyn AuditSink>);
        let rbac_state = crate::middleware::rbac::RbacState::new(
            initial_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        let mut runtime_config = ToolRuntimeConfig::from_policy(&initial_policy)
            .expect("initial tool policy should configure runtime");
        runtime_config.max_queue = 4;
        runtime_config.max_concurrent_global = 4;
        runtime_config.queue_timeout = Duration::from_secs(1);
        let runtime =
            ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state.clone()));

        file.write(&tool_policy_document_with_echo_and_search_max_concurrent(
            2, 1,
        ));
        crate::middleware::rbac::reload_policy_from_file(&rbac_state, file.path())
            .expect("valid tool policy reload should succeed");

        let tracker = Arc::new(ConcurrencyTracker::default());
        let release = ReleaseGate::new();
        let handles = vec![
            spawn_tracked_invocation(
                runtime.clone(),
                "search",
                Arc::clone(&tracker),
                release.clone(),
            ),
            spawn_tracked_invocation(
                runtime.clone(),
                "search",
                Arc::clone(&tracker),
                release.clone(),
            ),
        ];

        tracker.wait_for_started(1).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            tracker.started.load(Ordering::SeqCst),
            1,
            "the reloaded tool should enforce its per-tool limit instead of falling back to the global limit"
        );
        release.release();

        for handle in handles {
            handle
                .await
                .expect("invocation task should join")
                .expect("invocation should succeed");
        }
        assert!(tracker.max_running.load(Ordering::SeqCst) <= 1);
    }

    #[tokio::test]
    async fn policy_reload_updates_allowed_roles_and_tool_name_rules_from_same_snapshot() {
        let file = TempPolicyFile::new(&tool_policy_document_with_allowed_roles_and_deny_rule(
            &["operator"],
            "deny-operator-before",
            "operator",
        ));
        let initial_policy =
            Policy::from_file(file.path()).expect("initial tool policy should parse");
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let rbac_state = crate::middleware::rbac::RbacState::new(
            initial_policy.clone(),
            Vec::new(),
            false,
            audit.clone(),
        );
        let runtime_config = ToolRuntimeConfig::from_policy(&initial_policy)
            .expect("initial tool policy should configure runtime");
        let runtime =
            ToolRuntime::new_with_rbac_state(runtime_config, audit, Some(rbac_state.clone()));

        file.write(&tool_policy_document_with_allowed_roles_and_deny_rule(
            &["admin"],
            "deny-admin-after",
            "admin",
        ));
        crate::middleware::rbac::reload_policy_from_file(&rbac_state, file.path())
            .expect("valid tool policy reload should succeed");

        let denied = runtime
            .execute_with_context(
                "echo",
                context_with_roles(&["admin"]),
                CancellationToken::new(),
                || async { "should not run after reload" },
            )
            .await
            .expect_err("same runtime should use reloaded role gate and rule matcher");

        assert!(matches!(
            denied,
            ToolRuntimeError::Rejected { ref reason, .. } if reason == "matched_rule"
        ));
        let events = audit_events(&capture, 2).await;
        assert!(
            events.iter().any(|event| {
                event.event_type == "authz.denied"
                    && event.payload["matched_rule_id"] == json!("deny-admin-after")
            }),
            "tool authorization should use the reloaded rule after passing reloaded allowed_roles: {events:#?}"
        );
        assert!(
            events.iter().all(|event| {
                event.event_type != "tool.invoke_rejected"
                    || event.payload["reason"] != json!("role_not_allowed")
            }),
            "admin should pass the reloaded allowed_roles gate before the reloaded rule denies: {events:#?}"
        );
    }

    #[tokio::test]
    async fn allowed_roles_still_blocks_tool_call_even_when_tool_rule_allows() {
        let (runtime, capture) = runtime_with_tools_and_rules(
            [("tool", role_restricted_tool(100, 1, &["operator"]))],
            vec![tool_rule(
                Some("allow-viewer-tool"),
                "tool",
                &["viewer"],
                RuleAction::Allow,
            )],
            2,
            1,
            100,
        );

        let denied = runtime
            .execute_with_context(
                "tool",
                context_with_roles(&["viewer"]),
                CancellationToken::new(),
                || async { "should not run" },
            )
            .await
            .expect_err("allowed_roles should remain an independent restriction");

        assert!(matches!(denied, ToolRuntimeError::RoleDenied { .. }));
        assert_rejected_events(&capture, "tool", "role_not_allowed", 1).await;
        assert!(
            capture
                .events()
                .iter()
                .all(|event| event.event_type != "authz.allowed"),
            "allowed_roles denial should not be overridden by a matching Allow rule"
        );
    }

    #[tokio::test]
    async fn unauthenticated_call_to_role_restricted_tool_is_rejected() {
        let (runtime, capture) = runtime_with_tools(
            [("tool", role_restricted_tool(100, 1, &["operator"]))],
            2,
            1,
            100,
        );

        let error = runtime
            .execute_with_context("tool", context(), CancellationToken::new(), || async {
                "should not run"
            })
            .await
            .expect_err("actor-less invocation should not satisfy role policy");

        assert!(matches!(error, ToolRuntimeError::RoleDenied { .. }));
        assert_rejected_events(&capture, "tool", "role_not_allowed", 1).await;
    }

    #[tokio::test]
    async fn default_policy_controls_unlisted_tools() {
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let deny_runtime = ToolRuntime::new(
            ToolRuntimeConfig {
                default_policy: DefaultToolPolicy::Deny,
                tools: HashMap::new(),
                ..runtime_base_config()
            },
            audit,
        );

        let denied = deny_runtime
            .execute_with_context("unlisted", context(), CancellationToken::new(), || async {
                "should not run"
            })
            .await
            .expect_err("default deny should reject unlisted tools");

        assert!(matches!(denied, ToolRuntimeError::UnknownTool { .. }));
        assert_rejected_events(&capture, "unlisted", "unknown_tool", 1).await;

        let allow_runtime = ToolRuntime::new(
            ToolRuntimeConfig {
                default_policy: DefaultToolPolicy::Allow,
                tools: HashMap::new(),
                ..runtime_base_config()
            },
            AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>),
        );
        let allowed = allow_runtime
            .execute_with_context("unlisted", context(), CancellationToken::new(), || async {
                "allowed"
            })
            .await
            .expect("default allow should admit unlisted tools");

        assert_eq!(allowed, "allowed");
    }

    #[tokio::test]
    async fn exhausted_queue_rejects_immediately_and_audits_once() {
        let (runtime, capture) = runtime_with_tools([("tool", enabled_tool(500, 1))], 1, 1, 500);
        let release = Arc::new(Notify::new());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let running_release = Arc::clone(&release);
        let running = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                runtime
                    .execute_with_context("tool", context(), CancellationToken::new(), || async {
                        let _ = started_tx.send(());
                        running_release.notified().await;
                        "first"
                    })
                    .await
            }
        });
        started_rx
            .await
            .expect("first invocation should start before queue exhaustion check");

        let started = Instant::now();
        let error = runtime
            .execute_with_context("tool", context(), CancellationToken::new(), || async {
                "second"
            })
            .await
            .expect_err("queue should reject immediately");

        assert!(
            started.elapsed() < Duration::from_millis(50),
            "queue-full rejection should not wait: {:?}",
            started.elapsed()
        );
        assert!(matches!(
            error,
            ToolRuntimeError::Rejected { ref reason, .. } if reason == "queue_full"
        ));
        assert_rejected_events(&capture, "tool", "queue_full", 1).await;

        release.notify_waiters();
        let result = running.await.expect("task should join");
        assert_eq!(result.expect("first invocation should finish"), "first");
    }

    #[tokio::test]
    async fn queue_timeout_is_distinct_from_execution_timeout() {
        let (runtime, capture) = runtime_with_tools([("tool", enabled_tool(500, 1))], 2, 1, 25);
        let release = Arc::new(Notify::new());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let running_release = Arc::clone(&release);
        let running = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                runtime
                    .execute_with_context("tool", context(), CancellationToken::new(), || async {
                        let _ = started_tx.send(());
                        running_release.notified().await;
                        "first"
                    })
                    .await
            }
        });
        started_rx
            .await
            .expect("first invocation should occupy global concurrency");

        let error = runtime
            .execute_with_context("tool", context(), CancellationToken::new(), || async {
                "second"
            })
            .await
            .expect_err("second invocation should time out waiting for permits");

        assert!(matches!(error, ToolRuntimeError::QueueTimeout { .. }));
        assert_rejected_events(&capture, "tool", "queue_timeout", 1).await;

        release.notify_waiters();
        let _ = running.await.expect("task should join");
    }

    #[tokio::test]
    async fn queue_timeout_after_partial_acquire_releases_global_permit() {
        let (runtime, _capture) = runtime_with_tools(
            [
                ("alpha", enabled_tool(500, 1)),
                ("beta", enabled_tool(500, 2)),
            ],
            4,
            2,
            25,
        );
        let release_alpha = Arc::new(Notify::new());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let running_release = Arc::clone(&release_alpha);
        let running = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                runtime
                    .execute_with_context("alpha", context(), CancellationToken::new(), || async {
                        let _ = started_tx.send(());
                        running_release.notified().await;
                    })
                    .await
            }
        });
        started_rx
            .await
            .expect("alpha should occupy its per-tool permit");

        let error = runtime
            .execute_with_context("alpha", context(), CancellationToken::new(), || async {})
            .await
            .expect_err("second alpha should time out waiting for the per-tool permit");
        assert!(matches!(error, ToolRuntimeError::QueueTimeout { .. }));

        release_alpha.notify_waiters();
        running
            .await
            .expect("alpha task should join")
            .expect("alpha should finish");

        let tracker = Arc::new(ConcurrencyTracker::default());
        let release_beta = ReleaseGate::new();
        let first = spawn_tracked_invocation(
            runtime.clone(),
            "beta",
            Arc::clone(&tracker),
            release_beta.clone(),
        );
        let second =
            spawn_tracked_invocation(runtime, "beta", Arc::clone(&tracker), release_beta.clone());

        tracker.wait_for_started(2).await;
        release_beta.release();

        first
            .await
            .expect("first beta task should join")
            .expect("first beta should succeed");
        second
            .await
            .expect("second beta task should join")
            .expect("second beta should succeed");
    }

    #[tokio::test]
    async fn execution_timeout_aborts_work_and_releases_permits_for_next_call() {
        let (runtime, _capture) = runtime_with_tools([("tool", enabled_tool(20, 1))], 1, 1, 100);

        let error = runtime
            .execute_with_context("tool", context(), CancellationToken::new(), || async {
                tokio::time::sleep(Duration::from_secs(5)).await;
                "late"
            })
            .await
            .expect_err("long-running work should time out");

        assert!(matches!(error, ToolRuntimeError::Timeout { .. }));

        let retry = runtime
            .execute_with_context("tool", context(), CancellationToken::new(), || async {
                "retry"
            })
            .await
            .expect("timeout should release queue/global/per-tool permits");
        assert_eq!(retry, "retry");
    }

    #[tokio::test]
    async fn cancelled_waiter_releases_queue_slot_for_retry() {
        let (runtime, _capture) = runtime_with_tools(
            [
                ("alpha", enabled_tool(500, 1)),
                ("beta", enabled_tool(500, 1)),
            ],
            2,
            1,
            500,
        );
        let release = Arc::new(Notify::new());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let running_release = Arc::clone(&release);
        let running = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                runtime
                    .execute_with_context("alpha", context(), CancellationToken::new(), || async {
                        let _ = started_tx.send(());
                        running_release.notified().await;
                        "alpha"
                    })
                    .await
            }
        });
        started_rx
            .await
            .expect("alpha should occupy the global permit");

        let cancel = CancellationToken::new();
        let waiting = tokio::spawn({
            let runtime = runtime.clone();
            let cancel = cancel.clone();
            async move {
                runtime
                    .execute_with_context("beta", context(), cancel, || async { "cancelled" })
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
        let error = waiting
            .await
            .expect("waiting task should join")
            .expect_err("cancelled waiter should return cancelled");
        assert!(matches!(error, ToolRuntimeError::Cancelled { .. }));

        let retry = tokio::spawn({
            let runtime = runtime.clone();
            async move {
                runtime
                    .execute_with_context("beta", context(), CancellationToken::new(), || async {
                        "retry"
                    })
                    .await
            }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        release.notify_waiters();

        assert_eq!(
            running
                .await
                .expect("alpha task should join")
                .expect("alpha should finish"),
            "alpha"
        );
        assert_eq!(
            retry
                .await
                .expect("retry task should join")
                .expect("retry should proceed after cancellation"),
            "retry"
        );
    }

    #[tokio::test]
    async fn cancellation_during_execution_releases_permits_for_next_call() {
        let (runtime, _capture) = runtime_with_tools([("tool", enabled_tool(500, 1))], 1, 1, 100);
        let cancel = CancellationToken::new();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let running = tokio::spawn({
            let runtime = runtime.clone();
            let cancel = cancel.clone();
            async move {
                runtime
                    .execute_with_context("tool", context(), cancel, || async {
                        let _ = started_tx.send(());
                        std::future::pending::<()>().await;
                        "never"
                    })
                    .await
            }
        });
        started_rx
            .await
            .expect("tool work should start before cancellation");
        cancel.cancel();

        let error = running
            .await
            .expect("running task should join")
            .expect_err("cancelled execution should return cancelled");
        assert!(matches!(error, ToolRuntimeError::Cancelled { .. }));

        let retry = runtime
            .execute_with_context("tool", context(), CancellationToken::new(), || async {
                "retry"
            })
            .await
            .expect("cancelled execution should release permits");
        assert_eq!(retry, "retry");
    }

    #[tokio::test]
    async fn global_concurrency_is_enforced_across_tools() {
        let (runtime, _capture) = runtime_with_tools(
            [
                ("alpha", enabled_tool(500, 4)),
                ("beta", enabled_tool(500, 4)),
            ],
            8,
            2,
            500,
        );
        let tracker = Arc::new(ConcurrencyTracker::default());
        let release = ReleaseGate::new();
        let mut handles = Vec::new();

        for tool_name in ["alpha", "beta", "alpha", "beta"] {
            handles.push(spawn_tracked_invocation(
                runtime.clone(),
                tool_name,
                Arc::clone(&tracker),
                release.clone(),
            ));
        }

        tracker.wait_for_started(2).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            tracker.started.load(Ordering::SeqCst),
            2,
            "only two invocations should start before the global gate opens"
        );
        release.release();

        for handle in handles {
            handle
                .await
                .expect("invocation task should join")
                .expect("invocation should succeed");
        }
        assert_eq!(tracker.started.load(Ordering::SeqCst), 4);
        assert!(
            tracker.max_running.load(Ordering::SeqCst) <= 2,
            "global concurrency exceeded: {}",
            tracker.max_running.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn per_tool_concurrency_is_independent_between_tools() {
        let (runtime, _capture) = runtime_with_tools(
            [
                ("alpha", enabled_tool(500, 1)),
                ("beta", enabled_tool(500, 1)),
            ],
            8,
            4,
            500,
        );
        let alpha = Arc::new(ConcurrencyTracker::default());
        let beta = Arc::new(ConcurrencyTracker::default());
        let release = ReleaseGate::new();
        let handles = vec![
            spawn_tracked_invocation(
                runtime.clone(),
                "alpha",
                Arc::clone(&alpha),
                release.clone(),
            ),
            spawn_tracked_invocation(
                runtime.clone(),
                "alpha",
                Arc::clone(&alpha),
                release.clone(),
            ),
            spawn_tracked_invocation(runtime.clone(), "beta", Arc::clone(&beta), release.clone()),
            spawn_tracked_invocation(runtime.clone(), "beta", Arc::clone(&beta), release.clone()),
        ];

        wait_until(Duration::from_secs(1), || {
            alpha.started.load(Ordering::SeqCst) + beta.started.load(Ordering::SeqCst) == 2
        })
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(alpha.started.load(Ordering::SeqCst), 1);
        assert_eq!(beta.started.load(Ordering::SeqCst), 1);

        release.release();
        for handle in handles {
            handle
                .await
                .expect("invocation task should join")
                .expect("invocation should succeed");
        }

        assert_eq!(alpha.started.load(Ordering::SeqCst), 2);
        assert_eq!(beta.started.load(Ordering::SeqCst), 2);
        assert!(alpha.max_running.load(Ordering::SeqCst) <= 1);
        assert!(beta.max_running.load(Ordering::SeqCst) <= 1);
    }

    #[tokio::test]
    async fn successful_call_emits_start_then_success_with_context_and_payload() {
        let (runtime, capture) = runtime_with_tools([("tool", enabled_tool(100, 1))], 2, 1, 100);

        let result = runtime
            .execute_with_context(
                "tool",
                ToolInvocationContext {
                    request_id: "request-tool-1".to_owned(),
                    source_ip: "203.0.113.24".to_owned(),
                    actor: Some(Actor {
                        user_id: "user-123".to_owned(),
                        issuer: None,
                        email: None,
                        roles: Some(vec!["operator".to_owned()]),
                        auth_mode: "bearer_token".to_owned(),
                    }),
                },
                CancellationToken::new(),
                || async { 42 },
            )
            .await
            .expect("tool invocation should succeed");

        assert_eq!(result, 42);
        let events = audit_events(&capture, 2).await;
        assert_eq!(events[0].event_type, "tool.invoke_start");
        assert_eq!(events[1].event_type, "tool.invoke_success");
        for event in &events {
            assert_eq!(event.request_id, "request-tool-1");
            assert_eq!(event.source_ip, "203.0.113.24");
            assert_eq!(
                event.actor.as_ref().map(|actor| actor.user_id.as_str()),
                Some("user-123")
            );
            assert_eq!(event.payload["tool_name"], json!("tool"));
        }
        assert_eq!(events[0].payload["outcome"], json!("started"));
        assert_eq!(events[1].payload["outcome"], json!("success"));
    }

    #[test]
    fn runtime_config_from_policy_reads_tools_and_returns_none_when_absent() {
        let policy_without_tools =
            Policy::validate_json_value(json!({ "schema_version": "0.1.0" }))
                .expect("policy without tools should parse");
        assert!(
            ToolRuntimeConfig::from_policy(&policy_without_tools).is_none(),
            "missing tools section should not force runtime configuration"
        );

        let policy_with_tools = Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "tools": {
                "lookup": {},
                "report": {
                    "enabled": false,
                    "allowed_roles": ["operator"],
                    "timeout_ms": 1500,
                    "max_concurrent": 3
                }
            }
        }))
        .expect("policy with tools should parse");

        let runtime_config = ToolRuntimeConfig::from_policy(&policy_with_tools)
            .expect("tools section should map into runtime config");

        assert_eq!(runtime_config.tools.len(), 2);
        assert_eq!(
            runtime_config.tools["lookup"],
            ToolRuntimeToolConfig {
                enabled: true,
                allowed_roles: Vec::new(),
                issuers: Vec::new(),
                auth_methods: Vec::new(),
                timeout: Duration::from_millis(30_000),
                max_concurrent: 8,
            }
        );
        assert_eq!(
            runtime_config.tools["report"],
            ToolRuntimeToolConfig {
                enabled: false,
                allowed_roles: vec!["operator".to_owned()],
                issuers: Vec::new(),
                auth_methods: Vec::new(),
                timeout: Duration::from_millis(1500),
                max_concurrent: 3,
            }
        );
    }

    fn runtime_with_tools<const N: usize>(
        tools: [(&str, ToolRuntimeToolConfig); N],
        max_queue: usize,
        max_concurrent_global: usize,
        queue_timeout_ms: u64,
    ) -> (ToolRuntime, CaptureSink) {
        runtime_with_tools_and_rules(
            tools,
            Vec::new(),
            max_queue,
            max_concurrent_global,
            queue_timeout_ms,
        )
    }

    fn runtime_with_tools_and_rules<const N: usize>(
        tools: [(&str, ToolRuntimeToolConfig); N],
        rules: Vec<Rule>,
        max_queue: usize,
        max_concurrent_global: usize,
        queue_timeout_ms: u64,
    ) -> (ToolRuntime, CaptureSink) {
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            ToolRuntimeConfig {
                max_queue,
                queue_timeout: Duration::from_millis(queue_timeout_ms),
                max_concurrent_global,
                default_policy: DefaultToolPolicy::Deny,
                default_timeout: Duration::from_millis(100),
                rules,
                tools: tools
                    .into_iter()
                    .map(|(name, config)| (name.to_owned(), config))
                    .collect::<HashMap<_, _>>(),
            },
            audit,
        );

        (runtime, capture)
    }

    fn enabled_tool(timeout_ms: u64, max_concurrent: usize) -> ToolRuntimeToolConfig {
        ToolRuntimeToolConfig {
            enabled: true,
            allowed_roles: Vec::new(),
            issuers: Vec::new(),
            auth_methods: Vec::new(),
            timeout: Duration::from_millis(timeout_ms),
            max_concurrent,
        }
    }

    fn disabled_tool(timeout_ms: u64, max_concurrent: usize) -> ToolRuntimeToolConfig {
        ToolRuntimeToolConfig {
            enabled: false,
            allowed_roles: Vec::new(),
            issuers: Vec::new(),
            auth_methods: Vec::new(),
            timeout: Duration::from_millis(timeout_ms),
            max_concurrent,
        }
    }

    fn role_restricted_tool(
        timeout_ms: u64,
        max_concurrent: usize,
        allowed_roles: &[&str],
    ) -> ToolRuntimeToolConfig {
        ToolRuntimeToolConfig {
            enabled: true,
            allowed_roles: allowed_roles
                .iter()
                .map(|role| (*role).to_owned())
                .collect(),
            issuers: Vec::new(),
            auth_methods: Vec::new(),
            timeout: Duration::from_millis(timeout_ms),
            max_concurrent,
        }
    }

    fn runtime_base_config() -> ToolRuntimeConfig {
        ToolRuntimeConfig {
            max_queue: 2,
            queue_timeout: Duration::from_millis(100),
            max_concurrent_global: 1,
            default_policy: DefaultToolPolicy::Deny,
            default_timeout: Duration::from_millis(100),
            rules: Vec::new(),
            tools: HashMap::new(),
        }
    }

    fn tool_rule(id: Option<&str>, tool_name: &str, roles: &[&str], action: RuleAction) -> Rule {
        Rule {
            id: id.map(str::to_owned),
            enabled: true,
            methods: Vec::new(),
            path: String::new(),
            tool_name: Some(tool_name.to_owned()),
            dispatch: None,
            principal: PrincipalMatcher {
                roles: roles.iter().map(|role| (*role).to_owned()).collect(),
                issuers: Vec::new(),
                auth_methods: Vec::new(),
                principal_ids: Vec::new(),
            },
            action,
        }
    }

    fn tool_policy_document_without_rules() -> String {
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "echo": {
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            }
        })
        .to_string()
    }

    fn tool_policy_document_with_echo_max_concurrent(max_concurrent: u32) -> String {
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "echo": {
                    "timeout_ms": 5000,
                    "max_concurrent": max_concurrent
                }
            }
        })
        .to_string()
    }

    fn tool_policy_document_with_echo_and_search_max_concurrent(
        echo_max_concurrent: u32,
        search_max_concurrent: u32,
    ) -> String {
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "echo": {
                    "timeout_ms": 5000,
                    "max_concurrent": echo_max_concurrent
                },
                "search": {
                    "timeout_ms": 5000,
                    "max_concurrent": search_max_concurrent
                }
            }
        })
        .to_string()
    }

    fn tool_policy_document_with_allowed_roles(allowed_roles: &[&str]) -> String {
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "echo": {
                    "allowed_roles": allowed_roles,
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            }
        })
        .to_string()
    }

    fn tool_policy_document_with_echo_enabled(enabled: bool) -> String {
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "echo": {
                    "enabled": enabled,
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            }
        })
        .to_string()
    }

    fn tool_policy_document_without_tools() -> String {
        json!({
            "schema_version": "0.1.0"
        })
        .to_string()
    }

    fn tool_policy_document_with_allowed_roles_and_deny_rule(
        allowed_roles: &[&str],
        rule_id: &str,
        rule_role: &str,
    ) -> String {
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "echo": {
                    "allowed_roles": allowed_roles,
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            },
            "rules": [
                {
                    "id": rule_id,
                    "tool_name": "echo",
                    "principal": {
                        "roles": [rule_role]
                    },
                    "action": "deny"
                }
            ]
        })
        .to_string()
    }

    fn tool_policy_document_with_deny_rule() -> String {
        json!({
            "schema_version": "0.1.0",
            "tools": {
                "echo": {
                    "timeout_ms": 5000,
                    "max_concurrent": 2
                }
            },
            "rules": [
                {
                    "id": "deny-echo-after-reload",
                    "tool_name": "echo",
                    "principal": {
                        "roles": ["admin"]
                    },
                    "action": "deny"
                }
            ]
        })
        .to_string()
    }

    fn context() -> ToolInvocationContext {
        ToolInvocationContext {
            request_id: "request-test".to_owned(),
            source_ip: "127.0.0.1".to_owned(),
            actor: None,
        }
    }

    fn context_with_roles(roles: &[&str]) -> ToolInvocationContext {
        context_with_identity(roles, None, "bearer_token")
    }

    fn context_with_identity(
        roles: &[&str],
        issuer: Option<&str>,
        auth_mode: &str,
    ) -> ToolInvocationContext {
        ToolInvocationContext {
            request_id: "request-test".to_owned(),
            source_ip: "127.0.0.1".to_owned(),
            actor: Some(Actor {
                user_id: "user-123".to_owned(),
                issuer: issuer.map(str::to_owned),
                email: None,
                roles: Some(roles.iter().map(|role| (*role).to_owned()).collect()),
                auth_mode: auth_mode.to_owned(),
            }),
        }
    }

    async fn assert_rejected_events(
        capture: &CaptureSink,
        tool_name: &str,
        reason: &str,
        count: usize,
    ) {
        wait_until(Duration::from_secs(1), || {
            capture
                .events()
                .iter()
                .filter(|event| event.event_type == "tool.invoke_rejected")
                .count()
                >= count
        })
        .await;
        let events = capture.events();
        let rejected: Vec<_> = events
            .iter()
            .filter(|event| event.event_type == "tool.invoke_rejected")
            .collect();
        assert_eq!(rejected.len(), count, "{events:#?}");
        for event in rejected {
            assert_eq!(event.payload["tool_name"], json!(tool_name));
            assert_eq!(event.payload["reason"], json!(reason));
            assert_eq!(event.payload["outcome"], json!("rejected"));
        }
    }

    async fn audit_events(capture: &CaptureSink, expected_count: usize) -> Vec<AuditEvent> {
        wait_until(Duration::from_secs(1), || capture.len() >= expected_count).await;
        capture.events()
    }

    async fn wait_until(timeout: Duration, condition: impl Fn() -> bool) {
        let started = Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }

    #[derive(Default)]
    struct ConcurrencyTracker {
        started: AtomicUsize,
        running: AtomicUsize,
        max_running: AtomicUsize,
    }

    impl ConcurrencyTracker {
        async fn wait_for_started(&self, expected: usize) {
            wait_until(Duration::from_secs(1), || {
                self.started.load(Ordering::SeqCst) >= expected
            })
            .await;
        }

        fn enter(&self) -> RunningGuard<'_> {
            self.started.fetch_add(1, Ordering::SeqCst);
            let current = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_running.fetch_max(current, Ordering::SeqCst);
            RunningGuard { tracker: self }
        }
    }

    struct RunningGuard<'a> {
        tracker: &'a ConcurrencyTracker,
    }

    impl Drop for RunningGuard<'_> {
        fn drop(&mut self) {
            self.tracker.running.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn spawn_tracked_invocation(
        runtime: ToolRuntime,
        tool_name: &'static str,
        tracker: Arc<ConcurrencyTracker>,
        release: ReleaseGate,
    ) -> tokio::task::JoinHandle<Result<(), ToolRuntimeError>> {
        tokio::spawn(async move {
            runtime
                .execute_with_context(tool_name, context(), CancellationToken::new(), || async {
                    let _guard = tracker.enter();
                    release.wait().await;
                })
                .await
        })
    }

    fn spawn_blocking_invocation(
        runtime: ToolRuntime,
        tool_name: &'static str,
        release: ReleaseGate,
    ) -> tokio::task::JoinHandle<Result<(), ToolRuntimeError>> {
        tokio::spawn(async move {
            runtime
                .execute_with_context(tool_name, context(), CancellationToken::new(), || async {
                    release.wait().await;
                })
                .await
        })
    }

    #[derive(Clone)]
    struct ReleaseGate {
        released: Arc<AtomicBool>,
        notify: Arc<Notify>,
    }

    impl ReleaseGate {
        fn new() -> Self {
            Self {
                released: Arc::new(AtomicBool::new(false)),
                notify: Arc::new(Notify::new()),
            }
        }

        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            self.notify.notify_waiters();
        }

        async fn wait(&self) {
            while !self.released.load(Ordering::SeqCst) {
                self.notify.notified().await;
            }
        }
    }

    struct TempPolicyFile {
        path: PathBuf,
    }

    impl TempPolicyFile {
        fn new(contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-tool-runtime-policy-test-{}.json",
                uuid::Uuid::new_v4()
            ));
            fs::write(&path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));

            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn write(&self, contents: &str) {
            fs::write(&self.path, contents)
                .unwrap_or_else(|err| panic!("failed to write {}: {err}", self.path.display()));
        }
    }

    impl Drop for TempPolicyFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
