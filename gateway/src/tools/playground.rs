use std::{error::Error, fmt};

use http::{header, HeaderMap};
use rmcp::model::{CallToolResult, ContentBlock, Resource, ResourceContents};
use serde::Deserialize;
use serde_json::{json, Map, Value};

#[cfg(test)]
use crate::egress::EgressResponse;
use crate::tools::executor::{HttpToolExecutionResult, ToolExecutionResult};

pub const TOOL_PLAYGROUND_REQUEST_LIMIT_BYTES: usize = 64 * 1024;
pub const TOOL_PLAYGROUND_OUTPUT_LIMIT_BYTES: usize = 64 * 1024;
const HTTP_NON_SUCCESS_BODY_MESSAGE: &str =
    "Upstream returned a non-success status; response body was withheld.";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPlaygroundRequest {
    pub arguments: Map<String, Value>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ToolPlaygroundOutputError {
    UnsupportedOutput,
    OutputLimitExceeded,
}

impl ToolPlaygroundOutputError {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::UnsupportedOutput => "unsupported_output",
            Self::OutputLimitExceeded => "output_limit_exceeded",
        }
    }
}

impl fmt::Display for ToolPlaygroundOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedOutput => {
                write!(formatter, "tool output cannot be represented safely")
            }
            Self::OutputLimitExceeded => write!(
                formatter,
                "projected tool output exceeds the {TOOL_PLAYGROUND_OUTPUT_LIMIT_BYTES}-byte limit"
            ),
        }
    }
}

impl Error for ToolPlaygroundOutputError {}

pub fn project_tool_execution_result(
    result: ToolExecutionResult,
) -> Result<Value, ToolPlaygroundOutputError> {
    let projected = match result {
        ToolExecutionResult::Http(result) => project_http_response(result)?,
        ToolExecutionResult::McpCallToolResult(result) => project_mcp_result(result)?,
    };

    let encoded =
        serde_json::to_vec(&projected).map_err(|_| ToolPlaygroundOutputError::UnsupportedOutput)?;
    if encoded.len() > TOOL_PLAYGROUND_OUTPUT_LIMIT_BYTES {
        return Err(ToolPlaygroundOutputError::OutputLimitExceeded);
    }

    Ok(projected)
}

fn project_http_response(
    result: HttpToolExecutionResult,
) -> Result<Value, ToolPlaygroundOutputError> {
    let HttpToolExecutionResult { response, warnings } = result;
    if !response.status.is_success() {
        let mut projected = json!({
            "kind": "http",
            "status": response.status.as_u16(),
            "body": {
                "type": "text",
                "value": HTTP_NON_SUCCESS_BODY_MESSAGE,
            },
        });
        if !warnings.is_empty() {
            projected["warnings"] = json!(warnings);
        }
        return Ok(projected);
    }

    let body = if response_is_json(&response.headers) {
        match serde_json::from_slice::<Value>(&response.body) {
            Ok(value) => json!({
                "type": "json",
                "value": value,
            }),
            Err(_) => project_http_text(response.body)?,
        }
    } else {
        project_http_text(response.body)?
    };

    let mut projected = json!({
        "kind": "http",
        "status": response.status.as_u16(),
        "body": body,
    });
    if !warnings.is_empty() {
        projected["warnings"] = json!(warnings);
    }
    Ok(projected)
}

fn project_http_text(body: Vec<u8>) -> Result<Value, ToolPlaygroundOutputError> {
    let value =
        String::from_utf8(body).map_err(|_| ToolPlaygroundOutputError::UnsupportedOutput)?;
    Ok(json!({
        "type": "text",
        "value": value,
    }))
}

fn response_is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            let media_type = value.split(';').next().map(str::trim).unwrap_or_default();
            if media_type.eq_ignore_ascii_case("application/json") {
                return true;
            }
            media_type
                .split_once('/')
                .is_some_and(|(_, subtype)| subtype.to_ascii_lowercase().ends_with("+json"))
        })
}

fn project_mcp_result(result: CallToolResult) -> Result<Value, ToolPlaygroundOutputError> {
    let CallToolResult {
        content,
        structured_content,
        is_error,
        ..
    } = result;
    let content = content
        .into_iter()
        .map(project_mcp_content)
        .collect::<Result<Vec<_>, _>>()?;

    let mut projected = json!({
        "kind": "mcp",
        "content": content,
        "is_error": is_error.unwrap_or(false),
    });
    if let Some(structured_content) = structured_content {
        projected["structured_content"] = structured_content;
    }

    Ok(projected)
}

fn project_mcp_content(content: ContentBlock) -> Result<Value, ToolPlaygroundOutputError> {
    match content {
        ContentBlock::Text(content) => Ok(json!({
            "type": "text",
            "text": content.text,
        })),
        ContentBlock::Image(content) => Ok(json!({
            "type": "image",
            "data": content.data,
            "mime_type": content.mime_type,
        })),
        ContentBlock::Audio(content) => Ok(json!({
            "type": "audio",
            "data": content.data,
            "mime_type": content.mime_type,
        })),
        ContentBlock::Resource(content) => project_mcp_resource(content.resource),
        ContentBlock::ResourceLink(resource) => Ok(project_mcp_resource_link(resource)),
        _ => Err(ToolPlaygroundOutputError::UnsupportedOutput),
    }
}

fn project_mcp_resource(resource: ResourceContents) -> Result<Value, ToolPlaygroundOutputError> {
    let resource = match resource {
        ResourceContents::TextResourceContents {
            uri,
            mime_type,
            text,
            ..
        } => {
            let mut projected = resource_base(uri, mime_type);
            projected.insert("text".to_owned(), Value::String(text));
            projected
        }
        ResourceContents::BlobResourceContents {
            uri,
            mime_type,
            blob,
            ..
        } => {
            let mut projected = resource_base(uri, mime_type);
            projected.insert("blob".to_owned(), Value::String(blob));
            projected
        }
        _ => return Err(ToolPlaygroundOutputError::UnsupportedOutput),
    };

    Ok(json!({
        "type": "resource",
        "resource": resource,
    }))
}

fn resource_base(uri: String, mime_type: Option<String>) -> Map<String, Value> {
    let mut resource = Map::new();
    resource.insert("uri".to_owned(), Value::String(uri));
    if let Some(mime_type) = mime_type {
        resource.insert("mime_type".to_owned(), Value::String(mime_type));
    }
    resource
}

fn project_mcp_resource_link(resource: Resource) -> Value {
    let Resource {
        uri,
        name,
        title,
        description,
        mime_type,
        size,
        ..
    } = resource;
    let mut projected = Map::new();
    projected.insert("type".to_owned(), Value::String("resource_link".to_owned()));
    projected.insert("uri".to_owned(), Value::String(uri));
    projected.insert("name".to_owned(), Value::String(name));
    insert_optional_string(&mut projected, "title", title);
    insert_optional_string(&mut projected, "description", description);
    insert_optional_string(&mut projected, "mime_type", mime_type);
    if let Some(size) = size {
        projected.insert("size".to_owned(), json!(size));
    }
    Value::Object(projected)
}

fn insert_optional_string(
    object: &mut Map<String, Value>,
    key: &'static str,
    value: Option<String>,
) {
    if let Some(value) = value {
        object.insert(key.to_owned(), Value::String(value));
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderValue, StatusCode};
    use rmcp::model::CallToolResult;
    use serde_json::json;

    use super::*;

    #[test]
    fn request_requires_object_arguments_and_rejects_unknown_fields() {
        let request: ToolPlaygroundRequest = serde_json::from_value(json!({
            "arguments": {
                "widget_id": "widget-123"
            }
        }))
        .expect("object arguments should deserialize");
        assert_eq!(
            request.arguments["widget_id"],
            json!("widget-123"),
            "arguments should remain an object"
        );

        assert!(serde_json::from_value::<ToolPlaygroundRequest>(json!({})).is_err());
        assert!(serde_json::from_value::<ToolPlaygroundRequest>(json!({
            "arguments": []
        }))
        .is_err());
        assert!(serde_json::from_value::<ToolPlaygroundRequest>(json!({
            "arguments": {},
            "url": "https://forbidden.example/"
        }))
        .is_err());
    }

    #[test]
    fn request_preserves_arbitrary_precision_numbers_for_executor_mapping() {
        let request: ToolPlaygroundRequest = serde_json::from_str(
            r#"{"arguments":{"beyond_u64":18446744073709551616,"high_precision_decimal":0.123456789012345678901234567890123456789,"huge_exponent":1e400}}"#,
        )
        .expect("valid arbitrary-precision JSON numbers should deserialize");

        assert_eq!(
            request.arguments["beyond_u64"].to_string(),
            "18446744073709551616"
        );
        assert_eq!(
            request.arguments["high_precision_decimal"].to_string(),
            "0.123456789012345678901234567890123456789"
        );
        assert_eq!(request.arguments["huge_exponent"].to_string(), "1e+400");
        let serialized = serde_json::to_string(&request.arguments)
            .expect("arbitrary-precision arguments should reserialize");
        assert!(serialized.contains("18446744073709551616"));
        assert!(serialized.contains("0.123456789012345678901234567890123456789"));
        assert!(serialized.contains("1e+400"));
    }

    #[test]
    fn http_projection_exposes_only_status_and_json_body() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json; charset=utf-8"),
        );
        headers.insert(
            header::SET_COOKIE,
            HeaderValue::from_static("session=header-secret"),
        );
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header-secret"),
        );
        headers.insert(
            "x-upstream-metadata",
            HeaderValue::from_static("header-secret"),
        );

        let projected =
            project_tool_execution_result(ToolExecutionResult::Http(HttpToolExecutionResult {
                response: EgressResponse {
                    status: StatusCode::CREATED,
                    headers,
                    body: br#"{"ok":true}"#.to_vec(),
                },
                warnings: Vec::new(),
            }))
            .expect("safe JSON response should project");

        assert_eq!(
            projected,
            json!({
                "kind": "http",
                "status": 201,
                "body": {
                    "type": "json",
                    "value": {
                        "ok": true
                    }
                }
            })
        );
        assert!(
            !projected.to_string().contains("header-secret"),
            "headers, cookies, and upstream metadata must be stripped"
        );
    }

    #[test]
    fn http_transform_warnings_match_the_mcp_warning_shape() {
        let projected =
            project_tool_execution_result(ToolExecutionResult::Http(HttpToolExecutionResult {
                response: EgressResponse {
                    status: StatusCode::OK,
                    headers: HeaderMap::from_iter([(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    )]),
                    body: br#"{"amount":"invalid"}"#.to_vec(),
                },
                warnings: vec![crate::tools::transforms::TransformWarning {
                    path: "/data/company/annualRecurringRevenue".to_owned(),
                    reason: "wire value must match the canonical integer grammar".to_owned(),
                }],
            }))
            .expect("a transform warning is caller-safe output metadata");

        assert_eq!(
            projected["warnings"],
            json!([{
                "path": "/data/company/annualRecurringRevenue",
                "reason": "wire value must match the canonical integer grammar",
            }])
        );
    }

    #[test]
    fn invalid_json_content_type_body_falls_back_to_utf8_text() {
        let projected = project_tool_execution_result(http_result(
            Some("application/json"),
            b"not-json".to_vec(),
        ))
        .expect("valid UTF-8 should remain displayable");

        assert_eq!(
            projected["body"],
            json!({
                "type": "text",
                "value": "not-json"
            })
        );
    }

    #[test]
    fn non_success_json_http_projection_withholds_credential_reflecting_body() {
        let authorization_canary = "Bearer reflected-authorization-canary";
        let api_key_canary = "reflected-api-key-canary";
        let projected = project_tool_execution_result(http_result_with_status(
            StatusCode::UNAUTHORIZED,
            Some("application/problem+json"),
            serde_json::to_vec(&json!({
                "authorization": authorization_canary,
                "api_key": api_key_canary,
            }))
            .expect("credential canary fixture should serialize"),
        ))
        .expect("non-success JSON output should use the safe projection");

        assert_eq!(
            projected,
            json!({
                "kind": "http",
                "status": 401,
                "body": {
                    "type": "text",
                    "value": HTTP_NON_SUCCESS_BODY_MESSAGE,
                }
            })
        );
        let serialized = projected.to_string();
        assert!(!serialized.contains(authorization_canary));
        assert!(!serialized.contains(api_key_canary));
    }

    #[test]
    fn non_success_text_http_projection_withholds_credential_reflecting_body() {
        let authorization_canary = "Basic reflected-authorization-canary";
        let api_key_canary = "reflected-api-key-canary";
        let projected = project_tool_execution_result(http_result_with_status(
            StatusCode::BAD_GATEWAY,
            Some("text/plain"),
            format!("authorization={authorization_canary}; api_key={api_key_canary}").into_bytes(),
        ))
        .expect("non-success text output should use the safe projection");

        assert_eq!(
            projected,
            json!({
                "kind": "http",
                "status": 502,
                "body": {
                    "type": "text",
                    "value": HTTP_NON_SUCCESS_BODY_MESSAGE,
                }
            })
        );
        let serialized = projected.to_string();
        assert!(!serialized.contains(authorization_canary));
        assert!(!serialized.contains(api_key_canary));
    }

    #[test]
    fn binary_http_output_is_rejected_with_stable_reason() {
        let error = project_tool_execution_result(http_result(None, vec![0xff, 0xfe, 0xfd]))
            .expect_err("non-UTF-8 HTTP output must fail closed");

        assert_eq!(error, ToolPlaygroundOutputError::UnsupportedOutput);
        assert_eq!(error.reason(), "unsupported_output");
    }

    #[test]
    fn mcp_projection_allowlists_content_and_strips_metadata() {
        let result: CallToolResult = serde_json::from_value(json!({
            "content": [
                {
                    "type": "text",
                    "text": "hello",
                    "annotations": { "priority": 0.5 },
                    "_meta": { "secret": "metadata-secret" }
                },
                {
                    "type": "image",
                    "data": "aW1hZ2U=",
                    "mimeType": "image/png",
                    "annotations": { "priority": 0.5 },
                    "_meta": { "secret": "metadata-secret" }
                },
                {
                    "type": "audio",
                    "data": "YXVkaW8=",
                    "mimeType": "audio/wav",
                    "_meta": { "secret": "metadata-secret" }
                },
                {
                    "type": "resource",
                    "resource": {
                        "uri": "file:///safe.txt",
                        "mimeType": "text/plain",
                        "text": "safe text",
                        "_meta": { "secret": "metadata-secret" }
                    },
                    "_meta": { "secret": "metadata-secret" }
                },
                {
                    "type": "resource",
                    "resource": {
                        "uri": "file:///safe.bin",
                        "blob": "AAEC",
                        "_meta": { "secret": "metadata-secret" }
                    }
                },
                {
                    "type": "resource_link",
                    "uri": "file:///linked.txt",
                    "name": "linked",
                    "title": "Linked resource",
                    "description": "Safe description",
                    "mimeType": "text/plain",
                    "size": 12,
                    "icons": [
                        { "src": "https://icon-secret.example/icon.png" }
                    ],
                    "annotations": { "priority": 0.5 },
                    "_meta": { "secret": "metadata-secret" }
                }
            ],
            "structuredContent": {
                "answer": 42
            },
            "isError": false,
            "_meta": {
                "secret": "metadata-secret"
            }
        }))
        .expect("MCP fixture should deserialize");

        let projected =
            project_tool_execution_result(ToolExecutionResult::McpCallToolResult(result))
                .expect("allowlisted MCP output should project");

        assert_eq!(
            projected,
            json!({
                "kind": "mcp",
                "content": [
                    {
                        "type": "text",
                        "text": "hello"
                    },
                    {
                        "type": "image",
                        "data": "aW1hZ2U=",
                        "mime_type": "image/png"
                    },
                    {
                        "type": "audio",
                        "data": "YXVkaW8=",
                        "mime_type": "audio/wav"
                    },
                    {
                        "type": "resource",
                        "resource": {
                            "uri": "file:///safe.txt",
                            "mime_type": "text/plain",
                            "text": "safe text"
                        }
                    },
                    {
                        "type": "resource",
                        "resource": {
                            "uri": "file:///safe.bin",
                            "blob": "AAEC"
                        }
                    },
                    {
                        "type": "resource_link",
                        "uri": "file:///linked.txt",
                        "name": "linked",
                        "title": "Linked resource",
                        "description": "Safe description",
                        "mime_type": "text/plain",
                        "size": 12
                    }
                ],
                "structured_content": {
                    "answer": 42
                },
                "is_error": false
            })
        );
        let serialized = projected.to_string();
        assert!(!serialized.contains("metadata-secret"));
        assert!(!serialized.contains("icon-secret"));
        assert!(!serialized.contains("annotations"));
        assert!(!serialized.contains("_meta"));
    }

    #[test]
    fn mcp_projection_defaults_missing_error_flag_and_omits_missing_structure() {
        let result: CallToolResult = serde_json::from_value(json!({
            "content": []
        }))
        .expect("minimal MCP fixture should deserialize");

        let projected =
            project_tool_execution_result(ToolExecutionResult::McpCallToolResult(result))
                .expect("minimal MCP result should project");

        assert_eq!(
            projected,
            json!({
                "kind": "mcp",
                "content": [],
                "is_error": false
            })
        );
        assert!(projected.get("structured_content").is_none());
    }

    #[test]
    fn oversized_projected_output_is_rejected_without_truncation() {
        let error = project_tool_execution_result(http_result(
            Some("text/plain"),
            vec![b'x'; TOOL_PLAYGROUND_OUTPUT_LIMIT_BYTES],
        ))
        .expect_err("serialized envelope overhead must count toward the limit");

        assert_eq!(error, ToolPlaygroundOutputError::OutputLimitExceeded);
        assert_eq!(error.reason(), "output_limit_exceeded");
    }

    fn http_result(content_type: Option<&str>, body: Vec<u8>) -> ToolExecutionResult {
        http_result_with_status(StatusCode::OK, content_type, body)
    }

    fn http_result_with_status(
        status: StatusCode,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> ToolExecutionResult {
        let mut headers = HeaderMap::new();
        if let Some(content_type) = content_type {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(content_type)
                    .expect("test content type should be a valid header value"),
            );
        }
        ToolExecutionResult::Http(HttpToolExecutionResult {
            response: EgressResponse {
                status,
                headers,
                body,
            },
            warnings: Vec::new(),
        })
    }
}
