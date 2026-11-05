use serde_json::{json, Value};

use super::*;
use crate::documents::published_schema;

const PREFIXED: &str = "https://gateway.example.test/base/mcp";

fn url(text: &str) -> McpUrl {
    McpUrl::new(text).unwrap_or_else(|error| panic!("{text}: {error:?}"))
}

fn rendered(text: &str, oauth: bool) -> McpClientConfigs {
    McpClientConfigs::render(&url(text), &ServerName::default(), oauth).expect("renders")
}

fn schema_validator() -> jsonschema::Validator {
    let schema = published_schema(API_VERSION_V1ALPHA1, MCP_CLIENT_CONFIGS_KIND)
        .expect("the MCP client configs schema should be published");
    let schema: Value = serde_json::from_str(schema.json).expect("schema should be JSON");
    jsonschema::validator_for(&schema).expect("schema should compile")
}

fn kinds(document: &McpClientConfigs) -> Vec<(&'static str, &'static str)> {
    document
        .templates
        .iter()
        .map(|template| (template.client.as_str(), template.auth.as_str()))
        .collect()
}

/// Parses one template the way its client reads it and returns the server
/// entry, holding the template to its client's file shape.
fn parsed_entry(template: &Template, name: &str) -> Value {
    match template.format {
        Format::Url => {
            let line = template
                .content
                .strip_suffix('\n')
                .expect("one line ending in a line feed");
            assert!(!line.contains('\n'));
            let parsed = Url::parse(line).expect("the line is a URL");
            json!({ "url": parsed.as_str() })
        }
        Format::Json => {
            let value: Value =
                serde_json::from_str(&template.content).expect("the template is JSON");
            let object = value.as_object().expect("a JSON object");
            match template.client {
                ClientKind::Generic => value.clone(),
                ClientKind::Cursor => {
                    assert_eq!(object.len(), 1);
                    let servers = object["mcpServers"].as_object().expect("mcpServers");
                    assert_eq!(servers.len(), 1);
                    servers[name].clone()
                }
                ClientKind::Vscode => {
                    assert_eq!(object.len(), 1);
                    let servers = object["servers"].as_object().expect("servers");
                    assert_eq!(servers.len(), 1);
                    servers[name].clone()
                }
                ClientKind::ClaudeDesktop => panic!("Claude Desktop takes a URL"),
            }
        }
    }
}

#[test]
fn every_client_gets_the_gateway_url_and_only_token_templates_name_the_variable() {
    let document = rendered(PREFIXED, true);
    assert_eq!(
        kinds(&document),
        [
            ("generic", "oauth"),
            ("generic", "token"),
            ("claude-desktop", "oauth"),
            ("cursor", "oauth"),
            ("cursor", "token"),
            ("vscode", "oauth"),
            ("vscode", "token"),
        ]
    );
    for template in &document.templates {
        let entry = parsed_entry(template, DEFAULT_SERVER_NAME);
        let expected = match (template.client, template.auth) {
            (ClientKind::Generic, Auth::Oauth) => {
                json!({"transport": "streamable-http", "url": PREFIXED})
            }
            (ClientKind::Generic, Auth::Token) => json!({
                "transport": "streamable-http",
                "url": PREFIXED,
                "headers": {"Authorization": "Bearer ${GREENGATEWAY_MCP_TOKEN}"}
            }),
            (ClientKind::ClaudeDesktop, _) => json!({"url": PREFIXED}),
            (ClientKind::Cursor, Auth::Oauth) => json!({"url": PREFIXED}),
            (ClientKind::Cursor, Auth::Token) => json!({
                "url": PREFIXED,
                "headers": {"Authorization": "Bearer ${env:GREENGATEWAY_MCP_TOKEN}"}
            }),
            (ClientKind::Vscode, Auth::Oauth) => json!({"type": "http", "url": PREFIXED}),
            (ClientKind::Vscode, Auth::Token) => json!({
                "type": "http",
                "url": PREFIXED,
                "headers": {"Authorization": "Bearer ${env:GREENGATEWAY_MCP_TOKEN}"}
            }),
        };
        assert_eq!(
            entry,
            expected,
            "{} {}",
            template.client.as_str(),
            template.auth.as_str()
        );
        // An OAuth template is the URL and nothing that authenticates.
        if template.auth == Auth::Oauth {
            for word in ["Authorization", "Bearer", "headers", TOKEN_VARIABLE] {
                assert!(!template.content.contains(word), "{}", template.content);
            }
        }
        assert!(template.content.ends_with('\n'));
        assert!(!template.content.contains('\r'));
    }
    assert_eq!(document.mcp_url, PREFIXED);
    assert_eq!(document.server_name, DEFAULT_SERVER_NAME);
    assert_eq!(document.token_variable, TOKEN_VARIABLE);
    assert!(schema_validator().is_valid(&serde_json::to_value(&document).expect("serializes")));
}

#[test]
fn the_files_are_exactly_these_bytes() {
    let document = rendered("https://gateway.example.test/mcp", true);
    let content = |client, auth| {
        document
            .template(client, auth)
            .expect("rendered")
            .content
            .as_str()
    };
    assert_eq!(
        content(ClientKind::Cursor, Auth::Token),
        "{\n  \"mcpServers\": {\n    \"greengateway\": {\n      \"url\": \"https://gateway.example.test/mcp\",\n      \"headers\": {\n        \"Authorization\": \"Bearer ${env:GREENGATEWAY_MCP_TOKEN}\"\n      }\n    }\n  }\n}\n"
    );
    assert_eq!(
        content(ClientKind::Vscode, Auth::Oauth),
        "{\n  \"servers\": {\n    \"greengateway\": {\n      \"type\": \"http\",\n      \"url\": \"https://gateway.example.test/mcp\"\n    }\n  }\n}\n"
    );
    assert_eq!(
        content(ClientKind::ClaudeDesktop, Auth::Oauth),
        "https://gateway.example.test/mcp\n"
    );
    assert_eq!(
        content(ClientKind::Generic, Auth::Oauth),
        "{\n  \"transport\": \"streamable-http\",\n  \"url\": \"https://gateway.example.test/mcp\"\n}\n"
    );
}

#[test]
fn without_an_authorization_server_only_token_templates_are_offered() {
    let document = rendered(PREFIXED, false);
    assert!(!document.oauth);
    assert_eq!(
        kinds(&document),
        [
            ("generic", "token"),
            ("cursor", "token"),
            ("vscode", "token")
        ]
    );
    assert!(document
        .template(ClientKind::ClaudeDesktop, Auth::Oauth)
        .is_none());
    assert!(!ClientKind::ClaudeDesktop.supports(Auth::Token));
    assert!(schema_validator().is_valid(&serde_json::to_value(&document).expect("serializes")));
}

#[test]
fn locations_round_trip_with_windows_separators_escaped() {
    let document = rendered(PREFIXED, true);
    let cursor = document
        .template(ClientKind::Cursor, Auth::Oauth)
        .expect("rendered");
    assert_eq!(
        cursor.locations,
        [
            ".cursor/mcp.json",
            "~/.cursor/mcp.json",
            "%USERPROFILE%\\.cursor\\mcp.json"
        ]
    );
    let text = serde_json::to_string(&document).expect("serializes");
    assert!(
        text.contains(r#""%USERPROFILE%\\.cursor\\mcp.json""#),
        "{text}"
    );
    assert_eq!(read(text.as_bytes()), Ok(document.clone()));
    let vscode = document
        .template(ClientKind::Vscode, Auth::Token)
        .expect("rendered");
    assert_eq!(vscode.locations, [".vscode/mcp.json"]);
    for client in [ClientKind::Generic, ClientKind::ClaudeDesktop] {
        let template = document.template(client, Auth::Oauth).expect("rendered");
        assert!(template.locations.is_empty());
    }
}

#[test]
fn hostile_server_names_are_refused_never_escaped() {
    for valid in [
        "greengateway",
        "gg",
        "0",
        "prod-gateway_2",
        "GreenGateway",
        &"a".repeat(MAX_SERVER_NAME_BYTES),
    ] {
        let name = ServerName::new(valid).unwrap_or_else(|| panic!("{valid}"));
        let document = McpClientConfigs::render(&url(PREFIXED), &name, true).expect("renders");
        assert_eq!(document.server_name, valid);
        for template in &document.templates {
            if template.format == Format::Json && template.client != ClientKind::Generic {
                let entry = parsed_entry(template, valid);
                assert_eq!(entry["url"], PREFIXED);
            }
        }
        assert_eq!(
            read(&serde_json::to_vec(&document).expect("serializes")),
            Ok(document)
        );
    }
    for hostile in [
        "",
        " ",
        "a b",
        "a\"b",
        "a\\b",
        "a'b",
        "${env:HOME}",
        "$HOME",
        "{x}",
        "__proto__",
        "-leading",
        "_leading",
        "a/b",
        "..",
        "a.b",
        "a:b",
        "a\nb",
        "a\u{0}",
        "<script>",
        "caf\u{e9}",
        "\u{ff47}g",
        &"a".repeat(MAX_SERVER_NAME_BYTES + 1),
    ] {
        assert_eq!(ServerName::new(hostile), None, "{hostile:?}");
    }
}

#[test]
fn only_a_canonical_gateway_mcp_endpoint_is_templated() {
    for valid in [
        "https://gateway.example.test/mcp",
        "https://gateway.example.test/base/mcp",
        "https://gateway.example.test/a/b/c/mcp",
        "https://gateway.example.test:8443/mcp",
        "https://gateway.example.test/base/mcp?tenant=a",
        "https://[2001:db8::1]/mcp",
        "https://xn--bcher-kva.example.test/mcp",
        "https://gateway.example.test/caf%C3%A9%20%22q%22/mcp",
        "http://localhost:8080/mcp",
        "http://127.0.0.1:8080/base/mcp",
        "http://[::1]:8080/mcp",
        "http://[::ffff:7f00:1]/mcp",
    ] {
        assert_eq!(url(valid).as_str(), valid);
    }
    for invalid in [
        "",
        "/mcp",
        "gateway.example.test/mcp",
        "ftp://gateway.example.test/mcp",
        "http://gateway.example.test/mcp",
        "http://10.0.0.1/mcp",
        "https://operator@gateway.example.test/mcp",
        "https://gateway.example.test/mcp#fragment",
        "https://gateway.example.test/",
        "https://gateway.example.test/mcp/",
        "https://gateway.example.test/mcp/tools",
        "https://gateway.example.test/mcpx",
        "https://gateway.example.test/upstream?next=/mcp",
        // Not canonical: the URL parser would change each of these, so it is
        // not the identifier the gateway computed.
        "HTTPS://gateway.example.test/mcp",
        "https://GATEWAY.example.test/mcp",
        "https://gateway.example.test:443/mcp",
        "https://gateway.example.test/a/../mcp",
        "https://gateway.example.test\\mcp",
        "https://gateway.example.test/caf\u{e9}/mcp",
        " https://gateway.example.test/mcp",
        "https://gateway.example.test/mcp\n",
        "https://b\u{fc}cher.example.test/mcp",
        "http://[::ffff:127.0.0.1]/mcp",
        "http://[::ffff:10.0.0.1]/mcp",
        "http://[::ffff:a00:1]/mcp",
    ] {
        assert_eq!(
            McpUrl::new(invalid),
            Err(McpUrlError::Invalid),
            "{invalid:?}"
        );
    }
    for untemplatable in [
        "https://gateway.example.test/$base/mcp",
        "https://gateway.example.test/mcp?a=${env:HOME}",
        "https://gateway.example.test/mcp?a={x}",
        "https://gateway.example.test/mcp?a=\\b",
        &format!(
            "https://gateway.example.test/{}/mcp",
            "a".repeat(MAX_MCP_URL_BYTES)
        ),
    ] {
        assert_eq!(
            McpUrl::new(untemplatable),
            Err(McpUrlError::NotTemplatable),
            "{untemplatable:?}"
        );
    }
}

#[test]
fn escaped_paths_and_queries_reach_every_client_byte_for_byte() {
    for text in [
        "https://gateway.example.test/caf%C3%A9%20%22q%22/mcp",
        "https://gateway.example.test/base/mcp?tenant=a&x=%26%22",
        "https://gateway.example.test/%3Cscript%3E/mcp",
    ] {
        let document = rendered(text, true);
        for template in &document.templates {
            assert_eq!(
                parsed_entry(template, DEFAULT_SERVER_NAME)["url"],
                text,
                "{}",
                template.client.as_str()
            );
        }
    }
}

fn document_value() -> Value {
    serde_json::to_value(rendered(PREFIXED, true)).expect("serializes")
}

fn read_value(value: &Value) -> Result<McpClientConfigs, ReadError> {
    read(value.to_string().as_bytes())
}

#[test]
fn a_rendered_document_reads_back_and_matches_the_published_schema() {
    for oauth in [true, false] {
        let document = rendered(PREFIXED, oauth);
        let value = serde_json::to_value(&document).expect("serializes");
        assert!(schema_validator().is_valid(&value));
        assert_eq!(read_value(&value), Ok(document));
    }
}

#[test]
fn a_document_that_is_not_exactly_a_rendering_is_refused_whole() {
    let canary = "gg-canary-mcp-5e4d3c2b";
    let mut cases = Vec::new();
    let mut unknown = document_value();
    unknown["token"] = json!(canary);
    cases.push(unknown);
    for member in [
        "mcpUrl",
        "serverName",
        "oauth",
        "tokenVariable",
        "templates",
    ] {
        let mut missing = document_value();
        missing.as_object_mut().expect("object").remove(member);
        cases.push(missing);
    }
    let mut token_in_content = document_value();
    token_in_content["templates"][4]["content"] = json!(token_in_content["templates"][4]
        ["content"]
        .as_str()
        .expect("content")
        .replace("${env:GREENGATEWAY_MCP_TOKEN}", canary));
    cases.push(token_in_content);
    let mut header_in_oauth = document_value();
    header_in_oauth["templates"][3]["content"] = header_in_oauth["templates"][4]["content"].clone();
    cases.push(header_in_oauth);
    let mut other_url = document_value();
    other_url["mcpUrl"] = json!("https://elsewhere.example.test/mcp");
    cases.push(other_url);
    let mut upstream = document_value();
    upstream["mcpUrl"] = json!("https://upstream.example.test/v1/tools");
    cases.push(upstream);
    let mut variable = document_value();
    variable["tokenVariable"] = json!("HOME");
    cases.push(variable);
    let mut flipped = document_value();
    flipped["oauth"] = json!(false);
    cases.push(flipped);
    let mut extra = document_value();
    extra["templates"]
        .as_array_mut()
        .expect("templates")
        .push(json!({
            "client": "claude-desktop",
            "auth": "token",
            "format": "url",
            "locations": [],
            "content": "https://gateway.example.test/base/mcp\n"
        }));
    cases.push(extra);
    let mut reordered = document_value();
    reordered["templates"]
        .as_array_mut()
        .expect("templates")
        .swap(0, 1);
    cases.push(reordered);
    let mut location = document_value();
    location["templates"][3]["locations"][0] = json!("../../.ssh/config");
    cases.push(location);
    let mut template_member = document_value();
    template_member["templates"][0]["note"] = json!("x");
    cases.push(template_member);
    let mut name = document_value();
    name["serverName"] = json!("a\"b");
    cases.push(name);
    for case in cases {
        assert_eq!(read_value(&case), Err(ReadError::Invalid), "{case}");
    }
}

#[test]
fn a_duplicate_member_is_refused_rather_than_last_one_wins() {
    let text = serde_json::to_string(&rendered(PREFIXED, true)).expect("serializes");
    let duplicated = text.replacen(
        "\"oauth\":true",
        "\"oauth\":true,\"mcpUrl\":\"https://elsewhere.example.test/mcp\"",
        1,
    );
    assert_ne!(duplicated, text);
    assert_eq!(read(duplicated.as_bytes()), Err(ReadError::Invalid));
}

#[test]
fn another_version_oversized_or_non_document_input_is_refused_before_interpretation() {
    for (api_version, kind) in [
        ("greengateway.dev/v1alpha2", MCP_CLIENT_CONFIGS_KIND),
        ("greengateway.dev/v1", MCP_CLIENT_CONFIGS_KIND),
        (API_VERSION_V1ALPHA1, "GatewayCapabilities"),
        (API_VERSION_V1ALPHA1, "mcpClientConfigs"),
    ] {
        let mut value = document_value();
        value["apiVersion"] = json!(api_version);
        value["kind"] = json!(kind);
        value["newMember"] = json!(true);
        assert_eq!(
            read_value(&value),
            Err(ReadError::UnsupportedVersion),
            "{api_version} {kind}"
        );
    }
    let mut large = document_value();
    large["padding"] = json!("x".repeat(MAX_MCP_CLIENT_CONFIGS_BYTES));
    assert_eq!(read_value(&large), Err(ReadError::TooLarge));
    for text in ["", "null", "[]", "{", "{\"kind\":1}", "{}", "\"text\""] {
        assert_eq!(
            read(text.as_bytes()),
            Err(ReadError::NotADocument),
            "{text}"
        );
    }
}

#[test]
fn names_parse_exactly() {
    for client in ClientKind::ALL {
        assert_eq!(ClientKind::parse(client.as_str()), Some(client));
        assert_eq!(
            serde_json::to_value(client).expect("serializes"),
            json!(client.as_str())
        );
    }
    for auth in Auth::ALL {
        assert_eq!(Auth::parse(auth.as_str()), Some(auth));
        assert_eq!(
            serde_json::to_value(auth).expect("serializes"),
            json!(auth.as_str())
        );
    }
    for unknown in ["", "Cursor", "vs-code", "claude_desktop", "claude"] {
        assert_eq!(ClientKind::parse(unknown), None, "{unknown}");
    }
    for unknown in ["", "OAuth", "bearer"] {
        assert_eq!(Auth::parse(unknown), None, "{unknown}");
    }
}
