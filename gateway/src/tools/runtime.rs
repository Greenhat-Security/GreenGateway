use std::{collections::HashMap, error::Error, fmt, future::Future, sync::Arc, time::Duration};

use serde_json::{json, Value};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time,
};
use tokio_util::sync::CancellationToken;

use crate::{
    audit::{self, Actor, AuditEvent, AuditLog},
    config::{
        Config, DEFAULT_TOOL_RUNTIME_DEFAULT_TIMEOUT_MS, DEFAULT_TOOL_RUNTIME_GLOBAL_CONCURRENCY,
        DEFAULT_TOOL_RUNTIME_QUEUE_DEPTH, DEFAULT_TOOL_RUNTIME_QUEUE_TIMEOUT_MS,
    },
    rbac::{policy, Policy},
};

#[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRuntimeToolConfig {
    pub enabled: bool,
    pub allowed_roles: Vec<String>,
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
        if policy.tools.is_empty() {
            return None;
        }

        Some(Self {
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
    per_tool: HashMap<String, Arc<Semaphore>>,
}

struct ToolExecutionState {
    config: ToolRuntimeToolConfig,
    semaphore: Option<Arc<Semaphore>>,
}

struct AdmittedInvocation {
    config: ToolRuntimeToolConfig,
    _permits: ExecutionPermits,
}

struct ExecutionPermits {
    _queue: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
    _tool: Option<OwnedSemaphorePermit>,
}

impl ToolRuntime {
    #[allow(dead_code)] // Issue #32's tool registry and issue #33's MCP endpoint will invoke this.
    pub fn new(config: ToolRuntimeConfig, audit: AuditLog) -> Self {
        let per_tool = config
            .tools
            .iter()
            .map(|(name, tool_config)| {
                // Never create a zero-permit per-tool semaphore: a configured
                // zero would otherwise wait forever instead of behaving as the
                // documented minimum of one concurrent execution.
                let permits = tool_config.max_concurrent.max(1);
                (name.clone(), Arc::new(Semaphore::new(permits)))
            })
            .collect();

        Self {
            inner: Arc::new(ToolRuntimeInner {
                queue: Arc::new(Semaphore::new(config.max_queue.max(1))),
                global: Arc::new(Semaphore::new(config.max_concurrent_global.max(1))),
                per_tool,
                config,
                audit,
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
        let state = self.lookup_tool(tool_name);

        let state = match state {
            Ok(state) => state,
            Err(error) => {
                self.emit_rejected_error(context, tool_name, &error);
                return Err(error);
            }
        };

        if !state.config.enabled {
            self.emit_rejected(context, tool_name, "disabled");
            return Err(ToolRuntimeError::Disabled {
                tool_name: tool_name.to_owned(),
            });
        }

        if !allowed_roles_match(&state.config.allowed_roles, context) {
            self.emit_rejected(context, tool_name, "role_not_allowed");
            return Err(ToolRuntimeError::RoleDenied {
                tool_name: tool_name.to_owned(),
                allowed_roles: state.config.allowed_roles.clone(),
            });
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
            state.semaphore.clone(),
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

    pub(crate) fn tool_visible_to_context(
        &self,
        tool_name: &str,
        context: &ToolInvocationContext,
    ) -> bool {
        let Ok(state) = self.lookup_tool(tool_name) else {
            return false;
        };

        state.config.enabled && allowed_roles_match(&state.config.allowed_roles, context)
    }

    async fn acquire_execution_permits(
        queue: OwnedSemaphorePermit,
        global: Arc<Semaphore>,
        tool: Option<Arc<Semaphore>>,
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
            Some(tool) => {
                Some(
                    tool.acquire_owned()
                        .await
                        .map_err(|_| ToolRuntimeError::Rejected {
                            tool_name,
                            reason: "runtime_closed".to_owned(),
                        })?,
                )
            }
            None => None,
        };

        Ok(ExecutionPermits {
            _queue: queue,
            _global: global,
            _tool: tool,
        })
    }

    fn lookup_tool(&self, tool_name: &str) -> Result<ToolExecutionState, ToolRuntimeError> {
        if let Some(tool_config) = self.inner.config.tools.get(tool_name) {
            return Ok(ToolExecutionState {
                config: tool_config.clone(),
                semaphore: self.inner.per_tool.get(tool_name).cloned(),
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
                    timeout: self.inner.config.default_timeout,
                    max_concurrent: self.inner.config.max_concurrent_global,
                },
                semaphore: None,
            }),
        }
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
        timeout: Duration::from_millis(entry.timeout_ms),
        max_concurrent: entry.max_concurrent as usize,
    }
}

fn allowed_roles_match(allowed_roles: &[String], context: &ToolInvocationContext) -> bool {
    if allowed_roles.is_empty() {
        return true;
    }

    context
        .actor
        .as_ref()
        .and_then(|actor| actor.roles.as_ref())
        .is_some_and(|actor_roles| {
            allowed_roles
                .iter()
                .any(|allowed_role| actor_roles.iter().any(|role| role == allowed_role))
        })
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

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
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
    use crate::rbac::Policy;

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
                timeout: Duration::from_millis(30_000),
                max_concurrent: 8,
            }
        );
        assert_eq!(
            runtime_config.tools["report"],
            ToolRuntimeToolConfig {
                enabled: false,
                allowed_roles: vec!["operator".to_owned()],
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
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        let runtime = ToolRuntime::new(
            ToolRuntimeConfig {
                max_queue,
                queue_timeout: Duration::from_millis(queue_timeout_ms),
                max_concurrent_global,
                default_policy: DefaultToolPolicy::Deny,
                default_timeout: Duration::from_millis(100),
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
            timeout: Duration::from_millis(timeout_ms),
            max_concurrent,
        }
    }

    fn disabled_tool(timeout_ms: u64, max_concurrent: usize) -> ToolRuntimeToolConfig {
        ToolRuntimeToolConfig {
            enabled: false,
            allowed_roles: Vec::new(),
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
            tools: HashMap::new(),
        }
    }

    fn context() -> ToolInvocationContext {
        ToolInvocationContext {
            request_id: "request-test".to_owned(),
            source_ip: "127.0.0.1".to_owned(),
            actor: None,
        }
    }

    fn context_with_roles(roles: &[&str]) -> ToolInvocationContext {
        ToolInvocationContext {
            request_id: "request-test".to_owned(),
            source_ip: "127.0.0.1".to_owned(),
            actor: Some(Actor {
                user_id: "user-123".to_owned(),
                email: None,
                roles: Some(roles.iter().map(|role| (*role).to_owned()).collect()),
                auth_mode: "bearer_token".to_owned(),
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
}
