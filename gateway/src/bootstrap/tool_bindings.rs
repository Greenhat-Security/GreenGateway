//! The tool registry's startup bindings: the check that every
//! Connection-bound tool names a Connection that can serve it, and the
//! MCP upstream rediscovery a tools-file reload runs.
use super::*;

pub(crate) fn validate_connection_bound_tools(
    runtime: &connections::http::ConnectionHttpRuntime,
    definitions: &[tools::definitions::ToolDefinition],
) -> Result<(), Vec<String>> {
    use connections::store::ConnectionDependencyKind;
    use tools::definitions::{ToolSource, ToolTarget};

    let mut problems = Vec::new();
    let mut dependencies = Vec::new();
    for definition in definitions {
        match (&definition.source, definition.target.as_ref()) {
            (ToolSource::Manual, Some(ToolTarget::Http { connection_id, .. })) => {
                // A manual tool may be bound to a Connection that attests its
                // caller, delegated ones included: its calls sign the
                // assertion.
                if let Err(error) = runtime.validate_tool_binding(connection_id) {
                    problems.push(format!(
                        "tool '{}' Connection target is unavailable: {}",
                        definition.name,
                        error.safe_reason()
                    ));
                    continue;
                }
                dependencies.push((connection_id.clone(), definition.name.clone()));
            }
            (
                ToolSource::OpenApi {
                    connection_id: source_connection_id,
                    catalog_revision,
                    ..
                },
                Some(ToolTarget::Http {
                    connection_id: target_connection_id,
                    ..
                })
                | Some(ToolTarget::Composite {
                    connection_id: target_connection_id,
                }),
            ) => {
                if source_connection_id != target_connection_id {
                    problems.push(format!(
                        "OpenAPI tool '{}' source and target Connection IDs do not match",
                        definition.name
                    ));
                    continue;
                }
                if catalog_revision.is_none() {
                    problems.push(format!(
                        "managed OpenAPI tool '{}' is missing its catalog revision",
                        definition.name
                    ));
                    continue;
                }
                // Its calls sign a caller assertion as a manual tool's do, so
                // an attesting Connection is accepted, delegated ones
                // included; a composite's steps still refuse a delegated one
                // when they run.
                if let Err(error) = runtime.validate_openapi_tool_binding(target_connection_id) {
                    problems.push(format!(
                        "OpenAPI tool '{}' Connection target is unavailable: {}",
                        definition.name,
                        error.safe_reason()
                    ));
                }
            }
            (ToolSource::OpenApi { .. }, _) => {
                problems.push(format!(
                    "managed OpenAPI tool '{}' must use a Connection HTTP or composite target",
                    definition.name
                ));
            }
            (_, Some(ToolTarget::Http { .. }) | Some(ToolTarget::Composite { .. })) => {
                problems.push(format!(
                    "tool '{}' uses a Connection HTTP or composite target with an unsupported source",
                    definition.name
                ));
            }
            _ => {}
        }
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    runtime
        .replace_dependencies(ConnectionDependencyKind::ManualTool, &dependencies)
        .map_err(|error| {
            vec![format!(
                "manual tool Connection dependencies could not be reconciled: {}",
                error.safe_reason()
            )]
        })
}

pub(crate) fn mcp_proxy_definitions_provider(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
) -> Option<tools::definitions::McpProxyDefinitionsProvider> {
    let config = config.clone();
    Some(Arc::new(
        move || match tools::mcp_upstream::discover_upstream_tools_strict_blocking(
            &config,
            Arc::clone(&egress_client),
        ) {
            Ok(definitions) => Some(definitions),
            Err(err) => {
                tracing::error!(
                    error = %err,
                    "MCP upstream rediscovery failed during tool registry reload; preserving existing MCP proxy tools"
                );
                None
            }
        },
    ))
}
