//! The pure parts of saga execution over a compiled composite-tool mapping.
//!
//! The mapping itself -- steps, bindings, limits and the closed binding
//! grammar -- is `gateway_config::tools::composite` (issue #242), re-exported
//! here so call sites keep their paths. The overlay compiler owns proving
//! that references are well formed and that step tools belong to the same
//! OpenAPI catalog. This module deliberately repeats the inexpensive runtime
//! bounds and reference checks: persisted definitions are an authority
//! boundary, and the executor must fail closed if a corrupt definition
//! reaches it.

use std::collections::BTreeMap;

use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub use gateway_config::tools::composite::*;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CompositeStepOutput {
    /// Only a successfully parsed JSON response is referenceable by `$step`.
    pub json_body: Option<Value>,
    /// The safe agent-facing value used by the default composite result.
    pub result_body: Value,
}

pub(crate) type CompositeOutputs = BTreeMap<String, Vec<CompositeStepOutput>>;

pub(crate) struct BindingScope<'a> {
    pub input: &'a Map<String, Value>,
    pub steps: &'a CompositeOutputs,
    pub item: Option<(&'a str, &'a Value)>,
    pub self_body: Option<&'a Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BindingResolutionError {
    PointerUnresolved,
    ForEachNotArray,
}

impl BindingResolutionError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::PointerUnresolved => "pointer_unresolved",
            Self::ForEachNotArray => "for_each_not_array",
        }
    }
}

pub(crate) fn resolve_binding(
    binding: &CompositeBinding,
    scope: &BindingScope<'_>,
) -> Result<Value, BindingResolutionError> {
    match binding {
        CompositeBinding::Literal(value) => Ok(value.clone()),
        CompositeBinding::Input { input, pointer } => scope
            .input
            .get(input)
            .and_then(|value| value_at_pointer(value, pointer.as_deref()))
            .cloned()
            .ok_or(BindingResolutionError::PointerUnresolved),
        CompositeBinding::Step {
            step,
            pointer,
            collect,
        } => {
            let outputs = scope
                .steps
                .get(step)
                .ok_or(BindingResolutionError::PointerUnresolved)?;
            if *collect {
                outputs
                    .iter()
                    .map(|output| {
                        output
                            .json_body
                            .as_ref()
                            .and_then(|body| value_at_pointer(body, pointer.as_deref()))
                            .cloned()
                            .ok_or(BindingResolutionError::PointerUnresolved)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Value::Array)
            } else {
                let [output] = outputs.as_slice() else {
                    return Err(BindingResolutionError::PointerUnresolved);
                };
                output
                    .json_body
                    .as_ref()
                    .and_then(|body| value_at_pointer(body, pointer.as_deref()))
                    .cloned()
                    .ok_or(BindingResolutionError::PointerUnresolved)
            }
        }
        CompositeBinding::Item { item, pointer } => scope
            .item
            .filter(|(name, _)| *name == item)
            .and_then(|(_, value)| value_at_pointer(value, pointer.as_deref()))
            .cloned()
            .ok_or(BindingResolutionError::PointerUnresolved),
        CompositeBinding::SelfValue { pointer } => scope
            .self_body
            .and_then(|body| value_at_pointer(body, Some(pointer)))
            .cloned()
            .ok_or(BindingResolutionError::PointerUnresolved),
    }
}

pub(crate) fn resolve_arguments(
    bindings: &BTreeMap<String, CompositeBinding>,
    scope: &BindingScope<'_>,
) -> Result<Value, BindingResolutionError> {
    bindings
        .iter()
        .map(|(name, binding)| resolve_binding(binding, scope).map(|value| (name.clone(), value)))
        .collect::<Result<Map<_, _>, _>>()
        .map(Value::Object)
}

pub(crate) fn resolve_for_each(
    binding: &CompositeBinding,
    scope: &BindingScope<'_>,
) -> Result<Vec<Value>, BindingResolutionError> {
    match resolve_binding(binding, scope)? {
        Value::Array(items) => Ok(items),
        _ => Err(BindingResolutionError::ForEachNotArray),
    }
}

fn value_at_pointer<'a>(value: &'a Value, pointer: Option<&str>) -> Option<&'a Value> {
    match pointer {
        None | Some("") => Some(value),
        Some(pointer) => value.pointer(pointer),
    }
}

pub(crate) fn status_is_success(step: &CompositeStep, status: u16) -> bool {
    step.success_statuses
        .as_ref()
        .map_or((200..=299).contains(&status), |statuses| {
            statuses.contains(&status)
        })
}

pub(crate) fn status_is_ambiguous(step: &CompositeStep, method: &Method, status: u16) -> bool {
    step.ambiguous_statuses.as_ref().map_or_else(
        || {
            method != Method::GET
                && method != Method::HEAD
                && matches!(status, 500 | 502 | 503 | 504)
        },
        |statuses| statuses.contains(&status),
    )
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeResult {
    pub body: Value,
    pub steps_summary: Vec<CompositeStepSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeStepOutcome {
    Succeeded,
    Failed,
    Ambiguous,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeStepSummary {
    pub index: usize,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<usize>,
    pub tool: String,
    pub method: String,
    pub path_template: String,
    pub outcome: CompositeStepOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeCompensationOutcome {
    Succeeded,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeCompensationSummary {
    pub for_step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<usize>,
    pub tool: String,
    pub outcome: CompositeCompensationOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeOrphanCertainty {
    Confirmed,
    Possible,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeOrphan {
    pub step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<usize>,
    pub tool: String,
    pub certainty: CompositeOrphanCertainty,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeCompensationState {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingCompensation {
    pub step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iteration: Option<usize>,
    pub tool: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompositeCompletionAudit {
    pub tool_name: String,
    pub request_id: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_step: Option<String>,
    pub steps: Vec<CompositeStepSummary>,
    pub compensations: Vec<CompositeCompensationSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pending_compensation: Vec<PendingCompensation>,
    pub invocation_source: String,
    pub connection_id: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn bindings_round_trip_and_unknown_dollar_keys_fail_closed() {
        let cases = [
            json!(7),
            json!({"literal": true}),
            json!({"$input":"ids","pointer":"/0"}),
            json!({"$step":"create","pointer":"/data/id","collect":true}),
            json!({"$item":"company","pointer":"/id"}),
            json!({"$self":"/data/id"}),
        ];
        for value in cases {
            let binding: CompositeBinding =
                serde_json::from_value(value.clone()).expect("binding should deserialize");
            assert_eq!(serde_json::to_value(binding).expect("serialize"), value);
        }
        assert!(serde_json::from_value::<CompositeBinding>(json!({"$future":"unsafe"})).is_err());
        assert!(serde_json::from_value::<CompositeBinding>(
            json!({"$input":"ids","unexpected":true})
        )
        .is_err());
    }

    #[test]
    fn omitted_and_explicit_empty_results_remain_distinct() {
        let omitted: CompositeMapping = serde_json::from_value(json!({
            "steps": [{"id":"read","tool":"read","arguments":{}}]
        }))
        .expect("mapping without result should deserialize");
        assert_eq!(omitted.result, None);

        let explicit: CompositeMapping = serde_json::from_value(json!({
            "steps": [{"id":"read","tool":"read","arguments":{}}],
            "result": {}
        }))
        .expect("mapping with an explicit empty result should deserialize");
        assert_eq!(explicit.result, Some(BTreeMap::new()));
        assert!(serde_json::to_value(explicit)
            .expect("mapping should serialize")
            .get("result")
            .is_some());
    }

    #[test]
    fn step_collect_and_item_bindings_resolve_without_exposing_wire_state() {
        let input = json!({"ids":["one","two"]});
        let input = input.as_object().expect("object");
        let outputs = BTreeMap::from([(
            "create".to_owned(),
            vec![
                CompositeStepOutput {
                    json_body: Some(json!({"data":{"id":"a"}})),
                    result_body: json!({"data":{"id":"a"}}),
                },
                CompositeStepOutput {
                    json_body: Some(json!({"data":{"id":"b"}})),
                    result_body: json!({"data":{"id":"b"}}),
                },
            ],
        )]);
        let item = json!({"id":"company"});
        let scope = BindingScope {
            input,
            steps: &outputs,
            item: Some(("record", &item)),
            self_body: None,
        };
        assert_eq!(
            resolve_binding(
                &CompositeBinding::Step {
                    step: "create".to_owned(),
                    pointer: Some("/data/id".to_owned()),
                    collect: true,
                },
                &scope,
            ),
            Ok(json!(["a", "b"]))
        );
        assert_eq!(
            resolve_binding(
                &CompositeBinding::Item {
                    item: "record".to_owned(),
                    pointer: Some("/id".to_owned()),
                },
                &scope,
            ),
            Ok(json!("company"))
        );
    }

    #[test]
    fn write_status_defaults_are_ambiguous_but_read_statuses_are_not() {
        let step = CompositeStep {
            id: "write".to_owned(),
            tool: "create".to_owned(),
            arguments: BTreeMap::new(),
            for_each: None,
            success_statuses: None,
            ambiguous_statuses: None,
            compensate: None,
        };
        assert!(status_is_success(&step, 201));
        assert!(status_is_ambiguous(&step, &Method::POST, 502));
        assert!(!status_is_ambiguous(&step, &Method::GET, 502));
        assert!(!status_is_ambiguous(&step, &Method::POST, 400));
    }
}
