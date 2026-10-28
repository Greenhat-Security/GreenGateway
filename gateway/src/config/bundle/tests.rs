use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::{json, Value as JsonValue};
use sha2::{Digest, Sha256};

use super::{
    diagnostic::{BundleDiagnostic, Code, Position, Severity},
    document::{
        self, ApiVersion, Profile, ResourceSource, POLICY_SCHEMA_VERSIONS, TOOLS_SCHEMA_VERSIONS,
    },
    json, read_bundle, resource,
    source::{
        is_portable_file_name, owner_is_trusted, BundleDirectory, FileName, MAX_BUNDLE_BYTES,
        MAX_DIRECTORY_ENTRIES,
    },
    syntax::{
        decode_text, Limits, Node, Numbers, TextRules, Value, DOCUMENT_LIMITS, MAX_ARRAY_ELEMENTS,
        MAX_DEPTH, MAX_KEY_BYTES, MAX_OBJECT_MEMBERS, MAX_STRING_BYTES, RESOURCE_LIMITS,
    },
    value::{Decimal, SecretReference, Unresolved, UnresolvedReason},
    yaml, BundledResource, ReadOptions, MANIFEST_MEDIA_TYPE, MAX_DEPLOYMENT_BYTES,
    MAX_MANIFEST_BYTES,
};
use crate::canonical_json;

const CANARY: &str = "zqcanary";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway crate should live under the repository root")
        .to_path_buf()
}

/// A repository file with line endings normalized: a Windows checkout with
/// `core.autocrlf` turns them into CRLF, which the bundle reader refuses.
fn repository_text(path: &str) -> String {
    fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|error| panic!("{path} should be readable: {error}"))
        .replace("\r\n", "\n")
}

fn parse_yaml(text: &str) -> Node {
    yaml::parse(text, DOCUMENT_LIMITS)
        .unwrap_or_else(|error| panic!("{text:?} should parse: {error:?}"))
}

fn yaml_error(text: &str) -> (Code, Position) {
    match yaml::parse(text, DOCUMENT_LIMITS) {
        Ok(node) => panic!("{text:?} should be refused, parsed {:?}", node.to_json()),
        Err(error) => (error.code, error.position),
    }
}

fn json_error(text: &str, limits: Limits) -> (Code, Position) {
    match json::parse(text, limits) {
        Ok(node) => panic!("{text:?} should be refused, parsed {:?}", node.to_json()),
        Err(error) => (error.code, error.position),
    }
}

fn at(line: u32, column: u32) -> Position {
    Position::new(line, column)
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn codes(diagnostics: &[BundleDiagnostic]) -> Vec<Code> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code)
        .collect()
}

// --- the YAML subset --------------------------------------------------------

#[test]
fn yaml_reads_the_supported_subset() {
    let node = parse_yaml(concat!(
        "--- # a leading document marker is allowed\n",
        "# comment line\n",
        "plain: some text # trailing comment\n",
        "url: https://idp.example.com/realms/a#fragment\n",
        "path: /admin\n",
        "quoted: \"0.0.0.0:8080\"\n",
        "single: 'it''s'\n",
        "escapes: \"tab\\t quote\\\" slash\\/ \\u00e9 \\ud83d\\ude00\"\n",
        "integer: 42\n",
        "negative: -7\n",
        "zero: 0\n",
        "flag: true\n",
        "off_flag: false\n",
        "nothing: null\n",
        "unicode: \u{e9}t\u{e9}\n",
        "\"quoted key\": 1\n",
        "nested:\n",
        "  inner:\n",
        "    deep: value\n",
        "  sibling: 2\n",
        "list:\n",
        "- first\n",
        "- second\n",
        "indented_list:\n",
        "  - key: value\n",
        "    other: 3\n",
        "  - - nested\n",
        "    - items\n",
        "  -\n",
        "    after_dash: true\n",
        "flow_map: { secret: idp-client, port: 8443 }\n",
        "flow_list: [a, \"b, c\", 1, [], {}]\n",
        "json_style: {\"a\":1, \"b\": [true, null]}\n",
        "last: end\n",
    ));

    assert_eq!(
        node.to_json(),
        json!({
            "plain": "some text",
            "url": "https://idp.example.com/realms/a#fragment",
            "path": "/admin",
            "quoted": "0.0.0.0:8080",
            "single": "it's",
            "escapes": "tab\t quote\" slash/ \u{e9} \u{1f600}",
            "integer": 42,
            "negative": -7,
            "zero": 0,
            "flag": true,
            "off_flag": false,
            "nothing": null,
            "unicode": "\u{e9}t\u{e9}",
            "quoted key": 1,
            "nested": {"inner": {"deep": "value"}, "sibling": 2},
            "list": ["first", "second"],
            "indented_list": [
                {"key": "value", "other": 3},
                ["nested", "items"],
                {"after_dash": true}
            ],
            "flow_map": {"secret": "idp-client", "port": 8443},
            "flow_list": ["a", "b, c", 1, [], {}],
            "json_style": {"a": 1, "b": [true, null]},
            "last": "end"
        })
    );
}

#[test]
fn yaml_keeps_positions_for_diagnostics() {
    let node = parse_yaml("a:\n  b: [x, {c: 1}]\n");
    let Value::Object(members) = &node.value else {
        panic!("root should be a mapping");
    };
    assert_eq!(members[0].key_position, at(1, 1));
    let Value::Object(inner) = &members[0].value.value else {
        panic!("a should be a mapping");
    };
    assert_eq!(inner[0].key_position, at(2, 3));
    assert_eq!(inner[0].value.position, at(2, 6));
    let Value::Array(items) = &inner[0].value.value else {
        panic!("b should be a sequence");
    };
    assert_eq!(items[1].position, at(2, 10));
}

#[test]
fn yaml_refuses_everything_outside_the_subset() {
    let cases: &[(&str, Code, Option<Position>)] = &[
        ("a: &x 1\n", Code::AnchorForbidden, Some(at(1, 4))),
        ("&x a: 1\n", Code::AnchorForbidden, Some(at(1, 1))),
        ("a: *x\n", Code::AliasForbidden, Some(at(1, 4))),
        ("- *x\n", Code::AliasForbidden, Some(at(1, 3))),
        ("a: !!str 1\n", Code::TagForbidden, Some(at(1, 4))),
        ("a: [!t x]\n", Code::TagForbidden, Some(at(1, 5))),
        ("<<: {a: 1}\n", Code::MergeKeyForbidden, Some(at(1, 1))),
        ("a: {<<: b}\n", Code::MergeKeyForbidden, Some(at(1, 5))),
        (
            "%YAML 1.2\n---\na: 1\n",
            Code::DirectiveForbidden,
            Some(at(1, 1)),
        ),
        ("a: 1\n---\nb: 2\n", Code::MultipleDocuments, Some(at(2, 1))),
        ("a: 1\n...\n", Code::MultipleDocuments, Some(at(2, 1))),
        ("--- a: 1\n", Code::YamlSyntax, Some(at(1, 1))),
        ("? a\n: 1\n", Code::ComplexKeyForbidden, Some(at(1, 1))),
        ("[a]: 1\n", Code::ComplexKeyForbidden, Some(at(1, 4))),
        ("a: {[b]: 1}\n", Code::ComplexKeyForbidden, Some(at(1, 5))),
        ("1: a\n", Code::NonStringKey, Some(at(1, 1))),
        ("yes: a\n", Code::NonStringKey, Some(at(1, 1))),
        ("on: a\n", Code::NonStringKey, Some(at(1, 1))),
        ("Null: a\n", Code::NonStringKey, Some(at(1, 1))),
        ("~: a\n", Code::NonStringKey, Some(at(1, 1))),
        ("a b: 1\n", Code::KeyMustBeQuoted, Some(at(1, 1))),
        ("/admin: 1\n", Code::KeyMustBeQuoted, Some(at(1, 1))),
        ("a: |\n  text\n", Code::BlockScalarForbidden, Some(at(1, 4))),
        (
            "a: >-\n  text\n",
            Code::BlockScalarForbidden,
            Some(at(1, 4)),
        ),
        ("a: b\n  c\n", Code::MultilineValueForbidden, Some(at(2, 3))),
        ("- b\n  c\n", Code::MultilineValueForbidden, Some(at(2, 3))),
        (
            "a: \"b\n  c\"\n",
            Code::MultilineValueForbidden,
            Some(at(1, 4)),
        ),
        ("a: 'b\n", Code::MultilineValueForbidden, Some(at(1, 4))),
        (
            "a: [b,\n  c]\n",
            Code::MultilineValueForbidden,
            Some(at(1, 4)),
        ),
        (
            "a: {b: 1 # c\n",
            Code::MultilineValueForbidden,
            Some(at(1, 4)),
        ),
        ("a: \"\\x41\"\n", Code::UnsupportedEscape, Some(at(1, 5))),
        ("a: \"\\0\"\n", Code::UnsupportedEscape, Some(at(1, 5))),
        ("a: \"\\N\"\n", Code::UnsupportedEscape, Some(at(1, 5))),
        ("a: \"\\ud800\"\n", Code::UnsupportedEscape, Some(at(1, 5))),
        ("a: \"\\udc00\"\n", Code::UnsupportedEscape, Some(at(1, 5))),
        ("a:\n\tb: 1\n", Code::TabForbidden, Some(at(2, 1))),
        ("a:\tb\n", Code::TabForbidden, Some(at(1, 3))),
        ("a: b\tc\n", Code::TabForbidden, Some(at(1, 5))),
        ("a: \"b\"\tc\n", Code::TabForbidden, Some(at(1, 7))),
        ("-\tb\n", Code::TabForbidden, Some(at(1, 2))),
        ("a:\n  b: 1\n c: 2\n", Code::BadIndentation, Some(at(3, 2))),
        (
            "a: 1\n  b: 2\n",
            Code::MultilineValueForbidden,
            Some(at(2, 3)),
        ),
        ("a: \"x\"\n  b: 2\n", Code::BadIndentation, Some(at(2, 3))),
        ("a: 1\n- b\n", Code::BadIndentation, Some(at(2, 1))),
        ("- a\nb: 1\n", Code::BadIndentation, Some(at(2, 1))),
        ("a:\nb: 1\n", Code::EmptyValue, Some(at(1, 1))),
        ("a:\n", Code::EmptyValue, Some(at(1, 1))),
        ("a: # nothing\n", Code::EmptyValue, Some(at(1, 1))),
        ("-\n", Code::EmptyValue, Some(at(1, 1))),
        ("a: {b: }\n", Code::EmptyValue, Some(at(1, 5))),
        ("a: 1\na: 2\n", Code::YamlDuplicateKey, Some(at(2, 1))),
        ("a: 1\n\"a\": 2\n", Code::YamlDuplicateKey, Some(at(2, 1))),
        ("a: {b: 1, b: 2}\n", Code::YamlDuplicateKey, Some(at(1, 11))),
        ("a: b: c\n", Code::YamlSyntax, Some(at(1, 5))),
        ("a: value:\n", Code::YamlSyntax, Some(at(1, 9))),
        ("a: [1, 2,]\n", Code::YamlSyntax, Some(at(1, 10))),
        ("a: {b: 1,}\n", Code::YamlSyntax, Some(at(1, 10))),
        ("a: [b c: d]\n", Code::YamlSyntax, Some(at(1, 8))),
        ("a: {b}\n", Code::YamlSyntax, Some(at(1, 6))),
        ("a: \"b\" c\n", Code::YamlSyntax, Some(at(1, 8))),
        ("a: \"b\"# c\n", Code::YamlSyntax, Some(at(1, 7))),
        ("a: - b\n", Code::YamlSyntax, Some(at(1, 4))),
        ("a: %b\n", Code::YamlSyntax, Some(at(1, 4))),
        ("a: @b\n", Code::YamlSyntax, Some(at(1, 4))),
        ("a: `b\n", Code::YamlSyntax, Some(at(1, 4))),
        ("", Code::EmptyDocument, Some(at(1, 1))),
        ("# only a comment\n\n", Code::EmptyDocument, Some(at(1, 1))),
        ("---\n", Code::EmptyDocument, Some(at(1, 1))),
        (
            "a: 9007199254740992\n",
            Code::IntegerOutOfRange,
            Some(at(1, 4)),
        ),
        (
            "a: -9007199254740992\n",
            Code::IntegerOutOfRange,
            Some(at(1, 4)),
        ),
    ];
    for (text, code, position) in cases {
        let (found, found_position) = yaml_error(text);
        assert_eq!(found, *code, "{text:?}");
        if let Some(position) = position {
            assert_eq!(found_position, *position, "{text:?}");
        }
    }
}

#[test]
fn yaml_refuses_plain_scalars_another_reader_could_type_differently() {
    for scalar in [
        "yes",
        "Yes",
        "YES",
        "no",
        "No",
        "NO",
        "y",
        "Y",
        "n",
        "N",
        "on",
        "On",
        "ON",
        "off",
        "Off",
        "OFF",
        "True",
        "TRUE",
        "False",
        "FALSE",
        "Null",
        "NULL",
        "~",
        "0x1F",
        "0o17",
        "017",
        "00",
        "1_000",
        "+1",
        "-1.5",
        "1.5",
        "1e3",
        "1E3",
        "1.",
        ".5",
        "12:30",
        "1:30:00",
        "2026-10-21",
        "2026-10-21T10:00:00Z",
        ".inf",
        "-.inf",
        "+.inf",
        ".Inf",
        ".nan",
        ".NaN",
        "=",
        "<<",
        "-foo",
        ".hidden",
        "0.0.0.0:8080",
        "1.2.3",
        "$HOME",
        "?x",
        ":x",
    ] {
        let text = format!("a: {scalar}\n");
        assert_eq!(yaml_error(&text).0, Code::AmbiguousScalar, "{text:?}");
        let quoted = format!("a: \"{scalar}\"\n");
        assert_eq!(
            parse_yaml(&quoted).to_json(),
            json!({"a": scalar}),
            "{quoted:?}"
        );
        let flow = format!("a: [{scalar}]\n");
        assert_eq!(yaml_error(&flow).0, Code::AmbiguousScalar, "{flow:?}");
    }
    for (scalar, value) in [
        ("true", json!(true)),
        ("false", json!(false)),
        ("null", json!(null)),
        ("0", json!(0)),
        ("-0", json!(0)),
        ("9007199254740991", json!(9_007_199_254_740_991_i64)),
        ("-9007199254740991", json!(-9_007_199_254_740_991_i64)),
        ("production", json!("production")),
        ("_private", json!("_private")),
        ("/v1/admin", json!("/v1/admin")),
        ("\u{e9}t\u{e9}", json!("\u{e9}t\u{e9}")),
        ("a#b", json!("a#b")),
        ("a:b", json!("a:b")),
        ("x y  z", json!("x y  z")),
    ] {
        assert_eq!(
            parse_yaml(&format!("a: {scalar}\n")).to_json(),
            json!({ "a": value }),
            "{scalar:?}"
        );
    }
}

#[test]
fn yaml_and_json_spellings_canonicalize_identically() {
    let yaml_node = parse_yaml(concat!(
        "apiVersion: greengateway.dev/v1alpha1\n",
        "kind: GatewayDeployment\n",
        "spec:\n",
        "  profile: production\n",
        "  values: [1, -2, \"\u{e9}\", {b: true, a: null}]\n",
    ));
    let json_node = json::parse(
        r#"{
            "spec": {"values": [1, -2, "\u00e9", {"a": null, "b": true}], "profile": "production"},
            "kind": "GatewayDeployment",
            "apiVersion": "greengateway.dev/v1alpha1"
        }"#,
        DOCUMENT_LIMITS,
    )
    .expect("JSON spelling should parse");

    let canonical = |node: &Node| {
        String::from_utf8(
            canonical_json::canonical_json_bytes(&node.to_json())
                .expect("document should canonicalize"),
        )
        .expect("canonical JSON is UTF-8")
    };
    assert_eq!(canonical(&yaml_node), canonical(&json_node));
    assert_eq!(
        canonical(&yaml_node),
        concat!(
            "{\"apiVersion\":\"greengateway.dev/v1alpha1\",\"kind\":\"GatewayDeployment\",",
            "\"spec\":{\"profile\":\"production\",\"values\":[1,-2,\"\u{e9}\",{\"a\":null,\"b\":true}]}}"
        )
    );
}

// --- strict JSON --------------------------------------------------------------

#[test]
fn json_reads_rfc_8259_strictly() {
    let node = json::parse(
        " {\"a\": [1, -0, \"\\u00e9\\ud83d\\ude00\\n\\/\"], \"b\": {}, \"c\": [], \"d\": false}\n",
        DOCUMENT_LIMITS,
    )
    .expect("document should parse");
    assert_eq!(
        node.to_json(),
        json!({"a": [1, 0, "\u{e9}\u{1f600}\n/"], "b": {}, "c": [], "d": false})
    );

    let cases: &[(&str, Code, Position)] = &[
        ("{\"a\": 1, \"a\": 2}", Code::JsonDuplicateKey, at(1, 10)),
        (
            "{\"a\": {\"b\": 1, \"b\": 1}}",
            Code::JsonDuplicateKey,
            at(1, 16),
        ),
        ("{\"a\": 1,}", Code::JsonSyntax, at(1, 9)),
        ("[1, 2,]", Code::JsonSyntax, at(1, 7)),
        ("{} {}", Code::JsonSyntax, at(1, 4)),
        ("[01]", Code::JsonSyntax, at(1, 3)),
        ("[1.5]", Code::NumberNotInteger, at(1, 2)),
        ("[1e3]", Code::NumberNotInteger, at(1, 2)),
        ("[1.0]", Code::NumberNotInteger, at(1, 2)),
        ("[9007199254740992]", Code::IntegerOutOfRange, at(1, 2)),
        ("[-9007199254740992]", Code::IntegerOutOfRange, at(1, 2)),
        ("[99999999999999999999]", Code::IntegerOutOfRange, at(1, 2)),
        ("[NaN]", Code::JsonSyntax, at(1, 2)),
        ("[Infinity]", Code::JsonSyntax, at(1, 2)),
        ("[\"a\u{1}\"]", Code::JsonSyntax, at(1, 4)),
        ("[\"\\udc00\"]", Code::JsonSyntax, at(1, 3)),
        ("[\"\\ud800x\"]", Code::JsonSyntax, at(1, 3)),
        ("[\"\\x41\"]", Code::JsonSyntax, at(1, 3)),
        ("['a']", Code::JsonSyntax, at(1, 2)),
        ("{a: 1}", Code::JsonSyntax, at(1, 2)),
        ("// comment\n{}", Code::JsonSyntax, at(1, 1)),
        ("[1,\n 2", Code::JsonSyntax, at(2, 3)),
        ("", Code::EmptyDocument, at(1, 1)),
        ("  \n ", Code::EmptyDocument, at(2, 2)),
    ];
    for (text, code, position) in cases {
        assert_eq!(
            json_error(text, DOCUMENT_LIMITS),
            (*code, *position),
            "{text:?}"
        );
    }
}

#[test]
fn resource_json_keeps_exact_numbers_and_still_refuses_duplicates() {
    let node = json::parse(
        "{\"rps\": 1.50, \"big\": 1e400, \"int\": 7}",
        RESOURCE_LIMITS,
    )
    .expect("resource numbers should parse");
    let Value::Object(members) = &node.value else {
        panic!("root should be an object");
    };
    assert_eq!(members[0].value.value, Value::Number("1.50".to_owned()));
    assert_eq!(members[1].value.value, Value::Number("1e400".to_owned()));
    assert_eq!(members[2].value.value, Value::Number("7".to_owned()));
    assert_eq!(
        json_error("{\"a\": 1, \"a\": 1}", RESOURCE_LIMITS).0,
        Code::JsonDuplicateKey
    );
}

// --- bounds -------------------------------------------------------------------

fn nested_json_arrays(depth: usize) -> String {
    format!("{}{}", "[".repeat(depth), "]".repeat(depth))
}

#[test]
fn nesting_is_bounded_in_both_syntaxes() {
    assert!(json::parse(&nested_json_arrays(MAX_DEPTH), DOCUMENT_LIMITS).is_ok());
    assert_eq!(
        json_error(&nested_json_arrays(MAX_DEPTH + 1), DOCUMENT_LIMITS).0,
        Code::TooDeep
    );
    // Resources keep the depth bound too.
    assert_eq!(
        json_error(&nested_json_arrays(MAX_DEPTH + 1), RESOURCE_LIMITS).0,
        Code::TooDeep
    );
    // Far past the bound fails the same way, without exhausting the stack.
    assert_eq!(
        json_error(&nested_json_arrays(100_000), DOCUMENT_LIMITS).0,
        Code::TooDeep
    );

    assert!(yaml::parse(&nested_json_arrays(MAX_DEPTH), DOCUMENT_LIMITS).is_ok());
    assert_eq!(
        yaml_error(&nested_json_arrays(MAX_DEPTH + 1)).0,
        Code::TooDeep
    );

    let block = |depth: usize| {
        (0..depth)
            .map(|level| format!("{}k{level}:\n", "  ".repeat(level)))
            .collect::<String>()
            + &format!("{}leaf: 1\n", "  ".repeat(depth))
    };
    // `depth` keys nest `depth + 1` mappings.
    assert!(yaml::parse(&block(MAX_DEPTH - 1), DOCUMENT_LIMITS).is_ok());
    assert_eq!(yaml_error(&block(MAX_DEPTH)).0, Code::TooDeep);
}

#[test]
fn members_elements_and_nodes_are_bounded() {
    let object = |count: usize| {
        let members: Vec<String> = (0..count)
            .map(|index| format!("\"k{index}\": {index}"))
            .collect();
        format!("{{{}}}", members.join(","))
    };
    assert!(json::parse(&object(MAX_OBJECT_MEMBERS), DOCUMENT_LIMITS).is_ok());
    assert_eq!(
        json_error(&object(MAX_OBJECT_MEMBERS + 1), DOCUMENT_LIMITS).0,
        Code::TooManyMembers
    );
    let block_mapping: String = (0..=MAX_OBJECT_MEMBERS)
        .map(|index| format!("k{index}: 1\n"))
        .collect();
    assert_eq!(yaml_error(&block_mapping).0, Code::TooManyMembers);

    let array = |count: usize| format!("[{}]", vec!["0"; count].join(","));
    assert!(json::parse(&array(MAX_ARRAY_ELEMENTS), DOCUMENT_LIMITS).is_ok());
    assert_eq!(
        json_error(&array(MAX_ARRAY_ELEMENTS + 1), DOCUMENT_LIMITS).0,
        Code::TooManyElements
    );
    let block_sequence: String = (0..=MAX_ARRAY_ELEMENTS).map(|_| "- 0\n").collect();
    assert_eq!(yaml_error(&block_sequence).0, Code::TooManyElements);

    // 16 arrays of `width` elements: 1 + 16 + 16 * width values.
    let nodes = |width: usize| {
        let arrays: Vec<String> = (0..16).map(|_| array(width)).collect();
        format!("[{}]", arrays.join(","))
    };
    assert!(json::parse(&nodes(4_094), DOCUMENT_LIMITS).is_ok());
    assert_eq!(
        json_error(&nodes(4_095), DOCUMENT_LIMITS).0,
        Code::TooManyNodes
    );
}

#[test]
fn strings_and_keys_are_bounded() {
    let string = |length: usize| format!("[\"{}\"]", "x".repeat(length));
    assert!(json::parse(&string(MAX_STRING_BYTES), DOCUMENT_LIMITS).is_ok());
    assert_eq!(
        json_error(&string(MAX_STRING_BYTES + 1), DOCUMENT_LIMITS).0,
        Code::StringTooLong
    );
    assert!(yaml::parse(
        &format!("a: \"{}\"\n", "x".repeat(MAX_STRING_BYTES)),
        DOCUMENT_LIMITS
    )
    .is_ok());
    assert_eq!(
        yaml_error(&format!("a: \"{}\"\n", "x".repeat(MAX_STRING_BYTES + 1))).0,
        Code::StringTooLong
    );
    assert_eq!(
        yaml_error(&format!("a: '{}'\n", "x".repeat(MAX_STRING_BYTES + 1))).0,
        Code::StringTooLong
    );
    assert_eq!(
        yaml_error(&format!("a: x{}\n", "x".repeat(MAX_STRING_BYTES))).0,
        Code::StringTooLong
    );

    let key = |length: usize| format!("{{\"{}\": 1}}", "k".repeat(length));
    assert!(json::parse(&key(MAX_KEY_BYTES), DOCUMENT_LIMITS).is_ok());
    assert_eq!(
        json_error(&key(MAX_KEY_BYTES + 1), DOCUMENT_LIMITS).0,
        Code::KeyTooLong
    );
    assert!(yaml::parse(
        &format!("{}: 1\n", "k".repeat(MAX_KEY_BYTES)),
        DOCUMENT_LIMITS
    )
    .is_ok());
    assert_eq!(
        yaml_error(&format!("{}: 1\n", "k".repeat(MAX_KEY_BYTES + 1))).0,
        Code::KeyTooLong
    );
}

// --- text rules ---------------------------------------------------------------

#[test]
fn bundle_text_is_utf8_lf_and_free_of_control_and_bidi_characters() {
    fn decoded(bytes: &[u8], rules: TextRules) -> Result<&str, (Code, Position)> {
        decode_text(bytes, rules).map_err(|error| (error.code, error.position))
    }
    assert_eq!(decoded(b"a: 1\n", TextRules::Document), Ok("a: 1\n"));
    assert_eq!(
        decoded(b"\xef\xbb\xbfa: 1\n", TextRules::Document),
        Err((Code::ByteOrderMark, at(1, 1)))
    );
    assert_eq!(
        decoded(b"a: 1\r\nb: 2\r\n", TextRules::Resource),
        Err((Code::CarriageReturn, at(1, 5)))
    );
    assert_eq!(
        decoded(b"a: 1\nb: \xff\n", TextRules::Document),
        Err((Code::NotUtf8, at(2, 4)))
    );
    for forbidden in [
        '\u{0}', '\u{7}', '\u{1b}', '\u{7f}', '\u{85}', '\u{200f}', '\u{2028}', '\u{2029}',
        '\u{202e}', '\u{2066}', '\u{feff}',
    ] {
        // In a comment too: a reviewer reads comments.
        let text = format!("a: 1 # {forbidden}\n");
        assert_eq!(
            decoded(text.as_bytes(), TextRules::Document),
            Err((Code::ForbiddenCharacter, at(1, 8))),
            "{forbidden:?}"
        );
        assert!(
            decoded(text.as_bytes(), TextRules::Resource).is_ok(),
            "{forbidden:?}"
        );
    }
    // Escapes cannot smuggle what the raw text may not contain.
    for escaped in ["\\u0000", "\\u202e", "\\u001b", "\\u2028"] {
        assert_eq!(
            yaml_error(&format!("a: \"{escaped}\"\n")).0,
            Code::ForbiddenCharacter
        );
        assert_eq!(
            json_error(&format!("[\"{escaped}\"]"), DOCUMENT_LIMITS).0,
            Code::ForbiddenCharacter
        );
        assert_eq!(
            json_error(&format!("{{\"{escaped}\": 1}}"), DOCUMENT_LIMITS).0,
            Code::ForbiddenCharacter
        );
        assert!(json::parse(&format!("[\"{escaped}\"]"), RESOURCE_LIMITS).is_ok());
    }
    // Tab and line feed stay expressible inside strings.
    assert_eq!(
        parse_yaml("a: \"x\\ty\\nz\"\n").to_json(),
        json!({"a": "x\ty\nz"})
    );
}

// --- documents ----------------------------------------------------------------

const DEPLOYMENT_DIGEST: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
const POLICY_DIGEST: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
const TOOLS_DIGEST: &str = "c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2";

fn manifest_text(deployment: &str, policy: &str, tools: &str) -> String {
    format!(
        concat!(
            "apiVersion: greengateway.dev/v1alpha1\n",
            "kind: GatewayBundle\n",
            "metadata:\n",
            "  name: payments-production\n",
            "spec:\n",
            "  deployment:\n",
            "    path: deployment.yaml\n",
            "    sha256: \"{deployment}\"\n",
            "  resources:\n",
            "    policy:\n",
            "      source: bundle\n",
            "      path: policy.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{policy}\"\n",
            "    tools:\n",
            "      source: bundle\n",
            "      path: tools.json\n",
            "      schema_version: \"0.1.0\"\n",
            "      sha256: \"{tools}\"\n",
            "    connections:\n",
            "      source: server\n",
        ),
        deployment = deployment,
        policy = policy,
        tools = tools,
    )
}

fn manifest_diagnostics(text: &str) -> Vec<BundleDiagnostic> {
    let mut diagnostics = Vec::new();
    let node = parse_yaml(text);
    assert!(
        document::manifest(&node, &mut diagnostics).is_none(),
        "{text}"
    );
    diagnostics
}

#[test]
fn a_complete_manifest_is_typed() {
    let mut diagnostics = Vec::new();
    let manifest = document::manifest(
        &parse_yaml(&manifest_text(
            DEPLOYMENT_DIGEST,
            POLICY_DIGEST,
            TOOLS_DIGEST,
        )),
        &mut diagnostics,
    )
    .expect("manifest should validate");
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(manifest.api_version, ApiVersion::V1Alpha1);
    assert_eq!(manifest.name, "payments-production");
    assert_eq!(manifest.deployment.file.as_str(), "deployment.yaml");
    assert_eq!(manifest.deployment.sha256, DEPLOYMENT_DIGEST);
    let Some(ResourceSource::Bundle {
        reference,
        schema_version,
    }) = &manifest.policy
    else {
        panic!("policy should come from the bundle");
    };
    assert_eq!(reference.file.as_str(), "policy.json");
    assert_eq!(reference.sha256, POLICY_DIGEST);
    assert_eq!(*schema_version, "0.1.0");
    assert!(manifest.connections_from_server);
    assert_eq!(
        manifest
            .files()
            .iter()
            .map(FileName::as_str)
            .collect::<Vec<_>>(),
        [
            "bundle.yaml",
            "deployment.yaml",
            "policy.json",
            "tools.json"
        ]
    );

    // Resources are optional, and the server may own policy and tools.
    let minimal = concat!(
        "apiVersion: greengateway.dev/v1alpha1\n",
        "kind: GatewayBundle\n",
        "metadata: {name: a}\n",
        "spec:\n",
        "  deployment: {path: deployment.json, sha256: \"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\"}\n",
        "  resources: {policy: {source: server}, tools: {source: server}}\n",
    );
    let manifest =
        document::manifest(&parse_yaml(minimal), &mut diagnostics).expect("minimal manifest");
    assert_eq!(manifest.policy, Some(ResourceSource::Server));
    assert!(!manifest.connections_from_server);
    assert_eq!(manifest.files().len(), 2);
}

#[test]
fn an_unknown_api_version_is_refused_before_any_member_is_read() {
    for version in [
        "greengateway.dev/v1alpha2",
        "greengateway.dev/v1",
        "greengateway.dev/v1alpha1 ",
        "v1alpha1",
        "greengateway.dev/V1alpha1",
    ] {
        let text =
            format!("apiVersion: \"{version}\"\nkind: GatewayBundle\nunknown_future_member: 1\n");
        let diagnostics = manifest_diagnostics(&text);
        assert_eq!(
            codes(&diagnostics),
            [Code::UnsupportedApiVersion],
            "{version:?}"
        );
        assert_eq!(diagnostics[0].pointer.to_string(), "/apiVersion");
    }
    assert_eq!(
        codes(&manifest_diagnostics(
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\n"
        )),
        [Code::UnsupportedKind]
    );
    assert_eq!(
        codes(&manifest_diagnostics("kind: GatewayBundle\n")),
        [Code::MissingMember]
    );
    assert_eq!(codes(&manifest_diagnostics("[1]\n")), [Code::WrongType]);
}

#[test]
fn manifest_structure_is_closed_and_every_problem_is_reported() {
    let valid = manifest_text(DEPLOYMENT_DIGEST, POLICY_DIGEST, TOOLS_DIGEST);
    let cases: &[(String, &[Code], &str)] = &[
        (
            valid.replace("kind: GatewayBundle\n", "kind: GatewayBundle\nextra: 1\n"),
            &[Code::UnknownMember],
            "",
        ),
        (
            valid.replace(
                "  name: payments-production\n",
                "  name: payments-production\n  labels: {}\n",
            ),
            &[Code::UnknownMember],
            "/metadata",
        ),
        (
            valid.replace(
                "    path: deployment.yaml\n",
                "    path: deployment.yaml\n    format: yaml\n",
            ),
            &[Code::UnknownMember],
            "/spec/deployment",
        ),
        (
            valid.replace(
                "    connections:\n",
                "    openapi:\n      source: server\n    connections:\n",
            ),
            &[Code::UnknownMember],
            "/spec/resources",
        ),
        (
            valid.replace("  name: payments-production\n", "  name: Payments\n"),
            &[Code::InvalidName],
            "/metadata/name",
        ),
        (
            valid.replace("  name: payments-production\n", "  name: \"-payments\"\n"),
            &[Code::InvalidName],
            "/metadata/name",
        ),
        (
            valid.replace(
                "  name: payments-production\n",
                &format!("  name: {}\n", "a".repeat(64)),
            ),
            &[Code::InvalidName],
            "/metadata/name",
        ),
        (
            valid.replace("    path: deployment.yaml\n", "    path: deployment.yml\n"),
            &[Code::InvalidPath],
            "/spec/deployment/path",
        ),
        (
            valid.replace(
                "      path: policy.json\n",
                "      path: \"../policy.json\"\n",
            ),
            &[Code::InvalidPath],
            "/spec/resources/policy/path",
        ),
        (
            valid.replace(
                "      path: policy.json\n",
                "      path: /etc/policy.json\n",
            ),
            &[Code::InvalidPath],
            "/spec/resources/policy/path",
        ),
        (
            valid.replace("      path: policy.json\n", "      path: Policy.json\n"),
            &[Code::InvalidPath],
            "/spec/resources/policy/path",
        ),
        (
            valid.replace("      path: policy.json\n", "      path: policy.yaml\n"),
            &[Code::InvalidPath],
            "/spec/resources/policy/path",
        ),
        (
            valid.replace("      path: policy.json\n", "      path: con.json\n"),
            &[Code::InvalidPath],
            "/spec/resources/policy/path",
        ),
        (
            valid.replace(
                "      path: policy.json\n",
                "      path: \"policy.json:stream\"\n",
            ),
            &[Code::InvalidPath],
            "/spec/resources/policy/path",
        ),
        (
            valid.replace("      path: policy.json\n", "      path: bundle.yaml\n"),
            &[Code::ReservedPath],
            "/spec/resources/policy/path",
        ),
        (
            valid.replace("      path: tools.json\n", "      path: policy.json\n"),
            &[Code::DuplicatePath],
            "/spec/resources/tools/path",
        ),
        (
            valid.replace(DEPLOYMENT_DIGEST, &DEPLOYMENT_DIGEST.to_uppercase()),
            &[Code::InvalidDigest],
            "/spec/deployment/sha256",
        ),
        (
            valid.replace(POLICY_DIGEST, &POLICY_DIGEST[..63]),
            &[Code::InvalidDigest],
            "/spec/resources/policy/sha256",
        ),
        (
            valid.replace(
                "      schema_version: \"0.1.0\"\n      sha256: \"a1",
                "      schema_version: \"0.2.0\"\n      sha256: \"a1",
            ),
            &[Code::UnsupportedSchemaVersion],
            "/spec/resources/policy/schema_version",
        ),
        (
            valid.replace("      source: server\n", "      source: bundle\n"),
            &[Code::SourceUnsupported],
            "/spec/resources/connections/source",
        ),
        (
            valid.replace(
                "    policy:\n      source: bundle\n",
                "    policy:\n      source: git\n",
            ),
            &[Code::InvalidValue],
            "/spec/resources/policy/source",
        ),
        (
            valid.replace("    sha256: \"0b0b", "    digest: \"0b0b"),
            &[Code::UnknownMember, Code::MissingMember],
            "/spec/deployment",
        ),
        (
            valid.replace("metadata:\n  name: payments-production\n", ""),
            &[Code::MissingMember],
            "/metadata",
        ),
        (
            valid.replace("  name: payments-production\n", "  name: 7\n"),
            &[Code::WrongType],
            "/metadata/name",
        ),
    ];
    for (text, expected, pointer) in cases {
        let diagnostics = manifest_diagnostics(text);
        assert_eq!(codes(&diagnostics), *expected, "{text}");
        if !pointer.is_empty() {
            assert_eq!(diagnostics[0].pointer.to_string(), *pointer, "{text}");
        }
        for diagnostic in &diagnostics {
            assert_eq!(diagnostic.severity, Severity::Error);
            assert_eq!(
                diagnostic.file.as_ref().map(FileName::as_str),
                Some("bundle.yaml")
            );
        }
    }

    // A server-owned resource takes nothing but its source.
    let server_with_path = valid.replace(
        "    tools:\n      source: bundle\n",
        "    tools:\n      source: server\n",
    );
    assert_eq!(
        codes(&manifest_diagnostics(&server_with_path)),
        [
            Code::UnknownMember,
            Code::UnknownMember,
            Code::UnknownMember
        ]
    );

    // Several independent problems are all reported.
    let many = valid
        .replace("  name: payments-production\n", "  name: Payments\n")
        .replace("    path: deployment.yaml\n", "    path: deployment.txt\n")
        .replace("      source: server\n", "      source: bundle\n");
    assert_eq!(
        codes(&manifest_diagnostics(&many)),
        [
            Code::InvalidName,
            Code::InvalidPath,
            Code::SourceUnsupported
        ]
    );
}

#[test]
fn the_deployment_document_carries_only_its_profile_in_this_alpha() {
    let deployment = |spec: &str| {
        format!("apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n{spec}")
    };
    let file = FileName::parse("deployment.yaml").expect("valid name");
    for profile in Profile::ALL {
        let mut diagnostics = Vec::new();
        let parsed = document::deployment(
            &parse_yaml(&deployment(&format!("  profile: {}\n", profile.as_str()))),
            &file,
            &mut diagnostics,
        )
        .expect("deployment should validate");
        assert_eq!(parsed.profile, *profile);
        assert_eq!(parsed.api_version, ApiVersion::V1Alpha1);
    }
    let cases: [(&str, &[Code]); 4] = [
        ("  profile: staging\n", &[Code::InvalidValue]),
        (
            "  profile: production\n  listeners: {}\n",
            &[Code::UnknownMember],
        ),
        ("  profile: [production]\n", &[Code::WrongType]),
        ("  other: 1\n", &[Code::UnknownMember, Code::MissingMember]),
    ];
    for (spec, expected) in cases {
        let mut diagnostics = Vec::new();
        assert!(
            document::deployment(&parse_yaml(&deployment(spec)), &file, &mut diagnostics).is_none()
        );
        assert_eq!(codes(&diagnostics), expected, "{spec}");
    }
    let mut diagnostics = Vec::new();
    let wrong_kind =
        parse_yaml("apiVersion: greengateway.dev/v1alpha1\nkind: GatewayBundle\nspec: {}\n");
    assert!(document::deployment(&wrong_kind, &file, &mut diagnostics).is_none());
    assert_eq!(codes(&diagnostics), [Code::UnsupportedKind]);
}

// --- typed values -------------------------------------------------------------

#[test]
fn sensitive_values_accept_only_secret_references() {
    let reference = parse_yaml("{ secret: idp-client.v2_A }\n");
    assert_eq!(
        SecretReference::from_node(&reference).map(|reference| reference.alias_id().to_owned()),
        Ok("idp-client.v2_A".to_owned())
    );
    for (text, code) in [
        (
            format!("\"{CANARY}-literal-secret\"\n"),
            Code::InlineSecretValue,
        ),
        ("12345\n".to_owned(), Code::InlineSecretValue),
        ("true\n".to_owned(), Code::InlineSecretValue),
        ("null\n".to_owned(), Code::InvalidSecretReference),
        ("[a]\n".to_owned(), Code::InvalidSecretReference),
        (
            "{ secret: \"../file\" }\n".to_owned(),
            Code::InvalidSecretReference,
        ),
        (
            "{ secret: \"env:TOKEN\" }\n".to_owned(),
            Code::InvalidSecretReference,
        ),
        (
            "{ secret: _leading }\n".to_owned(),
            Code::InvalidSecretReference,
        ),
        (
            format!("{{ secret: {} }}\n", "a".repeat(129)),
            Code::InvalidSecretReference,
        ),
        (
            "{ secret: a, purpose: b }\n".to_owned(),
            Code::InvalidSecretReference,
        ),
        ("{ secret: 7 }\n".to_owned(), Code::InvalidSecretReference),
        ("{ value: a }\n".to_owned(), Code::InvalidSecretReference),
        (
            "{ unresolved: legacy_inline_secret }\n".to_owned(),
            Code::Unresolved,
        ),
    ] {
        assert_eq!(
            SecretReference::from_node(&parse_yaml(&text)),
            Err(code),
            "{text}"
        );
    }
}

#[test]
fn unresolved_placeholders_are_recognized_and_never_accepted() {
    for reason in UnresolvedReason::ALL {
        let node = parse_yaml(&format!("{{ unresolved: {} }}\n", reason.as_str()));
        assert_eq!(Unresolved::from_node(&node), Some(Ok(*reason)));
    }
    assert_eq!(
        Unresolved::from_node(&parse_yaml("{ unresolved: something_else }\n")),
        Some(Err(Code::Unresolved))
    );
    assert_eq!(
        Unresolved::from_node(&parse_yaml("{ unresolved: a, b: c }\n")),
        None
    );
    assert_eq!(Unresolved::from_node(&parse_yaml("unresolved\n")), None);
}

#[test]
fn decimals_are_exact_strings_with_one_canonical_spelling() {
    for (text, canonical) in [
        ("0", "0"),
        ("0.10", "0.1"),
        ("0.000001", "0.000001"),
        ("2.0", "2"),
        ("50", "50"),
        ("10.500", "10.5"),
        ("9999999999999999.999999", "9999999999999999.999999"),
    ] {
        let decimal = Decimal::from_node(&parse_yaml(&format!("\"{text}\"\n"))).expect("decimal");
        assert_eq!(decimal.canonical(), canonical);
        // Exactly what the same text yields from an environment variable.
        assert_eq!(
            decimal.as_f64(),
            text.parse::<f64>().expect("float"),
            "{text}"
        );
    }
    for text in [
        "",
        "01",
        "1.",
        ".5",
        "-1",
        "+1",
        "1e3",
        "1.1234567",
        "10000000000000000",
        "1,5",
        " 1",
        "0x1",
        "NaN",
        "inf",
    ] {
        assert!(Decimal::parse(text).is_none(), "{text:?}");
    }
    assert_eq!(
        Decimal::from_node(&parse_yaml("1\n")),
        Err(Code::InvalidDecimal)
    );
}

// --- referenced resources -----------------------------------------------------

fn policy_file() -> FileName {
    FileName::parse("policy.json").expect("valid name")
}

fn tools_file() -> FileName {
    FileName::parse("tools.json").expect("valid name")
}

#[test]
fn referenced_policies_pass_their_schema_and_production_validator() {
    assert!(resource::policy_schema_compiles());
    let mut diagnostics = Vec::new();
    let starter = repository_text("docs/examples/policy.starter.json");
    let policy = resource::policy(&starter, "0.1.0", &policy_file(), &mut diagnostics)
        .expect("the starter policy should validate");
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(policy.id.as_deref(), Some("starter"));

    for (text, code) in [
        (
            format!("{{\"schema_version\": \"0.1.0\", \"{CANARY}\": true}}"),
            Code::ResourceUnknownMember,
        ),
        ("{\"schema_version\": \"0.2.0\"}".to_owned(), Code::SchemaVersionMismatch),
        ("{\"schema_version\": \"0.1\"}".to_owned(), Code::SchemaVersionMismatch),
        ("{\"default_action\": \"deny\"}".to_owned(), Code::MissingMember),
        (
            "{\"schema_version\": \"0.1.0\", \"schema_version\": \"0.1.0\"}".to_owned(),
            Code::JsonDuplicateKey,
        ),
        (
            format!("{{\"schema_version\": \"0.1.0\", \"default_action\": \"{CANARY}\"}}"),
            Code::ResourceInvalid,
        ),
        (
            format!(
                "{{\"schema_version\": \"0.1.0\", \"routes\": [{{\"path_prefix\": \"{CANARY}\", \"permission\": \"p\"}}]}}"
            ),
            Code::ResourceInvalid,
        ),
        ("[]".to_owned(), Code::WrongType),
    ] {
        let mut diagnostics = Vec::new();
        assert!(resource::policy(&text, "0.1.0", &policy_file(), &mut diagnostics).is_none(), "{text}");
        assert_eq!(codes(&diagnostics), [code], "{text}");
        assert_value_free(&diagnostics);
    }
}

#[test]
fn referenced_tools_pass_their_production_validator() {
    let mut diagnostics = Vec::new();
    let starter = repository_text("docs/examples/tools.starter.json");
    let tools = resource::tools(&starter, "0.1.0", &tools_file(), &mut diagnostics)
        .expect("the starter tools should validate");
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(tools.len(), 1);

    for (text, code) in [
        (
            format!("{{\"schema_version\": \"0.1.0\", \"tools\": [], \"{CANARY}\": 1}}"),
            Code::ResourceInvalid,
        ),
        (
            format!("{{\"schema_version\": \"0.1.0\", \"tools\": [{{\"name\": \"{CANARY}\"}}]}}"),
            Code::ResourceInvalid,
        ),
        (
            "{\"schema_version\": \"0.9.9\", \"tools\": []}".to_owned(),
            Code::SchemaVersionMismatch,
        ),
    ] {
        let mut diagnostics = Vec::new();
        assert!(
            resource::tools(&text, "0.1.0", &tools_file(), &mut diagnostics).is_none(),
            "{text}"
        );
        assert_eq!(codes(&diagnostics), [code], "{text}");
        assert_value_free(&diagnostics);
    }
}

// --- reading bundle directories -----------------------------------------------

struct TempBundle {
    root: PathBuf,
}

impl Drop for TempBundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl TempBundle {
    fn empty(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "greengateway-bundle-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&root).expect("temporary bundle directory should create");
        #[cfg(unix)]
        set_mode(&root, 0o755);
        Self { root }
    }

    fn write(&self, name: &str, contents: &[u8]) {
        let path = self.root.join(name);
        fs::write(&path, contents).expect("bundle file should write");
        #[cfg(unix)]
        set_mode(&path, 0o644);
    }

    /// A complete, valid bundle: YAML deployment, policy and tools.
    fn complete(label: &str) -> Self {
        let bundle = Self::empty(label);
        bundle.write("deployment.yaml", DEPLOYMENT_YAML.as_bytes());
        bundle.write("policy.json", POLICY_JSON.as_bytes());
        bundle.write("tools.json", TOOLS_JSON.as_bytes());
        bundle.write("bundle.yaml", bundle.manifest().as_bytes());
        bundle
    }

    fn digest_of(&self, name: &str) -> String {
        sha256_hex(&fs::read(self.root.join(name)).expect("bundle file should read"))
    }

    /// The manifest pinning the files currently in the bundle.
    fn manifest(&self) -> String {
        manifest_text(
            &self.digest_of("deployment.yaml"),
            &self.digest_of("policy.json"),
            &self.digest_of("tools.json"),
        )
    }

    fn read(&self) -> super::BundleReport {
        read_bundle(&self.root, ReadOptions::default())
    }

    fn read_strict(&self) -> super::BundleReport {
        read_bundle(&self.root, ReadOptions { strict: true })
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("permissions should set");
}

const DEPLOYMENT_YAML: &str = concat!(
    "apiVersion: greengateway.dev/v1alpha1\n",
    "kind: GatewayDeployment\n",
    "spec:\n",
    "  profile: production\n",
);
const POLICY_JSON: &str =
    "{\n  \"schema_version\": \"0.1.0\",\n  \"default_action\": \"deny\"\n}\n";
const TOOLS_JSON: &str = "{\n  \"schema_version\": \"0.1.0\",\n  \"tools\": []\n}\n";

fn only_codes(report: &super::BundleReport) -> Vec<Code> {
    codes(&report.diagnostics)
}

#[test]
fn a_complete_bundle_is_read_with_its_digests() {
    let bundle = TempBundle::complete("complete");
    let report = bundle.read();
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    let read = report.bundle.expect("bundle should be read");

    let manifest_bytes = fs::read(bundle.root.join("bundle.yaml")).expect("manifest");
    assert_eq!(read.api_version, ApiVersion::V1Alpha1);
    assert_eq!(read.name, "payments-production");
    assert_eq!(
        read.source_digest,
        canonical_json::source_digest(
            MANIFEST_MEDIA_TYPE,
            "greengateway.dev/v1alpha1",
            &manifest_bytes
        )
    );
    assert_eq!(read.deployment.profile, Profile::Production);
    assert_eq!(read.deployment.file.as_str(), "deployment.yaml");
    assert_eq!(read.deployment.sha256, bundle.digest_of("deployment.yaml"));
    assert_eq!(
        String::from_utf8(read.deployment.canonical_json.clone()).expect("UTF-8"),
        "{\"apiVersion\":\"greengateway.dev/v1alpha1\",\"kind\":\"GatewayDeployment\",\"spec\":{\"profile\":\"production\"}}"
    );
    let Some(BundledResource::Bundle {
        file,
        schema_version,
        sha256,
        document,
    }) = &read.policy
    else {
        panic!("policy should come from the bundle");
    };
    assert_eq!(file.as_str(), "policy.json");
    assert_eq!(*schema_version, "0.1.0");
    assert_eq!(*sha256, bundle.digest_of("policy.json"));
    assert_eq!(document.default_action, crate::rbac::DefaultAction::Deny);
    assert!(
        matches!(&read.tools, Some(BundledResource::Bundle { document, .. }) if document.is_empty())
    );
    assert!(read.connections_from_server);
}

#[test]
fn a_json_deployment_reads_to_the_same_canonical_form() {
    let bundle = TempBundle::complete("json-deployment");
    let yaml_canonical = bundle
        .read()
        .bundle
        .expect("YAML bundle")
        .deployment
        .canonical_json;

    bundle.write(
        "deployment.json",
        b"{\"spec\": {\"profile\": \"production\"}, \"kind\": \"GatewayDeployment\", \"apiVersion\": \"greengateway.dev/v1alpha1\"}\n",
    );
    let manifest = bundle
        .manifest()
        .replace(
            &bundle.digest_of("deployment.yaml"),
            &bundle.digest_of("deployment.json"),
        )
        .replace("path: deployment.yaml", "path: deployment.json");
    fs::remove_file(bundle.root.join("deployment.yaml")).expect("remove YAML spelling");
    bundle.write("bundle.yaml", manifest.as_bytes());

    let report = bundle.read();
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert_eq!(
        report
            .bundle
            .expect("JSON bundle")
            .deployment
            .canonical_json,
        yaml_canonical
    );
}

#[test]
fn the_bundle_root_must_be_an_openable_directory() {
    let missing = std::env::temp_dir().join(format!(
        "greengateway-bundle-missing-{}",
        uuid::Uuid::new_v4()
    ));
    let report = read_bundle(&missing, ReadOptions::default());
    assert_eq!(only_codes(&report), [Code::RootUnavailable]);

    let bundle = TempBundle::empty("root-file");
    bundle.write("not-a-directory", b"x");
    let report = read_bundle(&bundle.root.join("not-a-directory"), ReadOptions::default());
    assert_eq!(only_codes(&report), [Code::RootNotDirectory]);

    let empty = TempBundle::empty("no-manifest");
    assert_eq!(only_codes(&empty.read()), [Code::ManifestMissing]);
}

#[test]
fn only_root_or_the_directory_owner_may_own_what_is_read() {
    assert!(owner_is_trusted(Some(1000), Some(1000)));
    assert!(owner_is_trusted(Some(0), Some(1000)));
    assert!(owner_is_trusted(Some(0), Some(0)));
    // Another account could rewrite the file whatever its mode says.
    assert!(!owner_is_trusted(Some(1001), Some(1000)));
    assert!(!owner_is_trusted(Some(1000), Some(0)));
    assert!(!owner_is_trusted(Some(1000), None));
    assert!(!owner_is_trusted(None, Some(1000)));
    // A platform that records no owner (Windows) leaves it to ACLs.
    assert!(owner_is_trusted(None, None));
}

#[test]
fn file_names_must_match_exactly_whatever_the_filesystem_folds() {
    let bundle = TempBundle::empty("case");
    bundle.write("BUNDLE.YAML", b"apiVersion: greengateway.dev/v1alpha1\n");
    let report = bundle.read();
    assert_eq!(codes(&report.diagnostics), [Code::ManifestMissing]);

    let bundle = TempBundle::complete("case-resource");
    fs::rename(
        bundle.root.join("policy.json"),
        bundle.root.join("POLICY.JSON"),
    )
    .expect("rename");
    let report = bundle.read();
    assert!(report.bundle.is_none());
    assert_eq!(
        codes(&report.diagnostics),
        [Code::FileMissing, Code::UnreferencedEntry]
    );
    assert_eq!(
        report.diagnostics[0].file.as_ref().map(FileName::as_str),
        Some("policy.json")
    );
    // The uppercase name fails the grammar, so it is not reported by name.
    assert_eq!(report.diagnostics[1].file, None);
    assert_eq!(report.diagnostics[1].severity, Severity::Warning);
}

#[test]
fn a_digest_mismatch_refuses_the_file_before_it_is_parsed() {
    let bundle = TempBundle::complete("digest");
    // Unparseable on purpose: only the pin may be reported.
    bundle.write("policy.json", b"{{{ not json");
    let report = bundle.read();
    assert!(report.bundle.is_none());
    assert_eq!(only_codes(&report), [Code::DigestMismatch]);
    assert_eq!(
        report.diagnostics[0].file.as_ref().map(FileName::as_str),
        Some("policy.json")
    );
}

#[test]
fn problems_across_files_are_aggregated() {
    let bundle = TempBundle::empty("aggregate");
    bundle.write("deployment.yaml", b"apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: staging\n");
    bundle.write(
        "policy.json",
        b"{\"schema_version\": \"0.1.0\", \"extra\": 1}\n",
    );
    bundle.write("tools.json", TOOLS_JSON.as_bytes());
    bundle.write("bundle.yaml", bundle.manifest().as_bytes());
    let report = bundle.read();
    assert!(report.bundle.is_none());
    assert_eq!(
        only_codes(&report),
        [Code::InvalidValue, Code::ResourceUnknownMember]
    );
    assert_eq!(
        report.diagnostics[0].file.as_ref().map(FileName::as_str),
        Some("deployment.yaml")
    );
    assert_eq!(report.diagnostics[0].pointer.to_string(), "/spec/profile");
    assert_eq!(report.diagnostics[0].position, Some(at(4, 12)));
}

#[test]
fn unreferenced_entries_warn_and_strict_reading_refuses_them() {
    let bundle = TempBundle::complete("unreferenced");
    bundle.write("notes.txt", b"operator notes\n");
    bundle.write("README.md", b"# readme\n");
    // Dot entries are ignored entirely.
    bundle.write(".gitattributes", b"* text eol=lf\n");
    fs::create_dir(bundle.root.join(".git")).expect("dot directory");

    let report = bundle.read();
    assert!(report.bundle.is_some(), "warnings do not refuse a bundle");
    let mut warnings: Vec<_> = report
        .diagnostics
        .iter()
        .map(|diagnostic| {
            (
                diagnostic.code,
                diagnostic.severity,
                diagnostic
                    .file
                    .as_ref()
                    .map(|file| file.as_str().to_owned()),
            )
        })
        .collect();
    warnings.sort_by(|left, right| left.2.cmp(&right.2));
    assert_eq!(
        warnings,
        [
            (Code::UnreferencedEntry, Severity::Warning, None),
            (
                Code::UnreferencedEntry,
                Severity::Warning,
                Some("notes.txt".to_owned())
            ),
        ]
    );

    let strict = bundle.read_strict();
    assert!(strict.bundle.is_none());
    assert!(strict
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.severity == Severity::Error));
    assert_eq!(strict.diagnostics.len(), 2);
}

#[test]
fn a_bundle_is_flat_and_holds_regular_files_only() {
    let bundle = TempBundle::complete("flat");
    fs::create_dir(bundle.root.join("nested")).expect("subdirectory");
    let report = bundle.read();
    assert!(report.bundle.is_none());
    assert_eq!(only_codes(&report), [Code::NotRegularFile]);
    assert_eq!(
        report.diagnostics[0].file.as_ref().map(FileName::as_str),
        Some("nested")
    );

    let bundle = TempBundle::complete("referenced-directory");
    fs::remove_file(bundle.root.join("policy.json")).expect("remove policy");
    fs::create_dir(bundle.root.join("policy.json")).expect("directory named like the policy");
    assert_eq!(only_codes(&bundle.read()), [Code::NotRegularFile]);
}

#[test]
fn hard_linked_files_are_refused() {
    let bundle = TempBundle::complete("hard-link");
    fs::hard_link(
        bundle.root.join("policy.json"),
        bundle.root.join("elsewhere.json"),
    )
    .expect("hard link");
    let report = bundle.read();
    assert!(report.bundle.is_none());
    assert_eq!(
        codes(&report.diagnostics),
        [Code::HardLinkForbidden, Code::UnreferencedEntry]
    );
}

#[test]
fn file_and_bundle_sizes_are_bounded_before_reading() {
    let bundle = TempBundle::complete("large-deployment");
    let mut large = DEPLOYMENT_YAML.as_bytes().to_vec();
    large.resize(MAX_DEPLOYMENT_BYTES + 1, b'\n');
    bundle.write("deployment.yaml", &large);
    bundle.write("bundle.yaml", bundle.manifest().as_bytes());
    assert_eq!(only_codes(&bundle.read()), [Code::FileTooLarge]);

    let bundle = TempBundle::complete("large-manifest");
    let mut manifest = bundle.manifest().into_bytes();
    manifest.resize(MAX_MANIFEST_BYTES + 1, b'\n');
    bundle.write("bundle.yaml", &manifest);
    assert_eq!(only_codes(&bundle.read()), [Code::FileTooLarge]);

    // The total bound is checked across every read of one directory.
    let bundle = TempBundle::empty("total");
    let chunk = MAX_BUNDLE_BYTES / 4;
    for index in 0..5 {
        bundle.write(&format!("part{index}.bin"), &vec![b'x'; chunk]);
    }
    let mut directory = BundleDirectory::open(&bundle.root).expect("directory should open");
    for index in 0..4 {
        let name = FileName::parse(&format!("part{index}.bin")).expect("valid name");
        assert_eq!(
            directory.read(&name, chunk).map(|bytes| bytes.len()),
            Ok(chunk)
        );
    }
    let name = FileName::parse("part4.bin").expect("valid name");
    assert_eq!(
        directory
            .read(&name, chunk)
            .map_err(|diagnostic| diagnostic.code),
        Err(Code::BundleTooLarge)
    );
}

#[test]
fn directory_listings_are_bounded() {
    let bundle = TempBundle::complete("entries");
    for index in 0..MAX_DIRECTORY_ENTRIES {
        bundle.write(&format!("extra{index}.txt"), b"");
    }
    let report = bundle.read();
    assert_eq!(only_codes(&report), [Code::TooManyEntries]);
}

#[test]
fn line_endings_and_byte_order_marks_are_refused_in_every_file() {
    let bundle = TempBundle::complete("crlf");
    bundle.write("policy.json", POLICY_JSON.replace('\n', "\r\n").as_bytes());
    bundle.write("bundle.yaml", bundle.manifest().as_bytes());
    assert_eq!(only_codes(&bundle.read()), [Code::CarriageReturn]);

    let bundle = TempBundle::complete("bom");
    let mut manifest = b"\xef\xbb\xbf".to_vec();
    manifest.extend_from_slice(bundle.manifest().as_bytes());
    bundle.write("bundle.yaml", &manifest);
    assert_eq!(only_codes(&bundle.read()), [Code::ByteOrderMark]);
}

#[cfg(unix)]
mod unix {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn symbolic_links_are_refused_referenced_or_not() {
        let bundle = TempBundle::complete("symlink-referenced");
        fs::rename(
            bundle.root.join("policy.json"),
            bundle.root.join("real.json"),
        )
        .expect("rename");
        symlink("real.json", bundle.root.join("policy.json")).expect("symlink");
        let report = bundle.read();
        assert!(report.bundle.is_none());
        assert_eq!(
            codes(&report.diagnostics),
            [Code::SymlinkForbidden, Code::UnreferencedEntry]
        );

        let bundle = TempBundle::complete("symlink-unreferenced");
        symlink("/etc/passwd", bundle.root.join("escape.json")).expect("symlink");
        let report = bundle.read();
        assert!(report.bundle.is_none());
        assert_eq!(only_codes(&report), [Code::SymlinkForbidden]);
    }

    #[test]
    fn writable_files_and_directories_are_refused() {
        let bundle = TempBundle::complete("writable-file");
        set_mode(&bundle.root.join("policy.json"), 0o666);
        assert_eq!(only_codes(&bundle.read()), [Code::UnsafePermissions]);

        for mode in [0o777, 0o775, 0o757] {
            let bundle = TempBundle::complete(&format!("writable-root-{mode:o}"));
            set_mode(&bundle.root, mode);
            assert_eq!(
                only_codes(&bundle.read()),
                [Code::UnsafePermissions],
                "{mode:o}"
            );
        }
    }

    /// The sticky bit stops another account replacing a file, not adding
    /// one, so in a flat root it could add the unpinned manifest.
    #[test]
    fn a_flat_root_is_never_writable_by_others_even_with_the_sticky_bit() {
        for mode in [0o1777, 0o1775, 0o1757] {
            let bundle = TempBundle::complete(&format!("sticky-root-{mode:o}"));
            set_mode(&bundle.root, mode);
            assert_eq!(
                only_codes(&bundle.read()),
                [Code::UnsafePermissions],
                "{mode:o}"
            );
        }
        let bundle = TempBundle::complete("sticky-owner-only-root");
        set_mode(&bundle.root, 0o1755);
        assert!(bundle.read().bundle.is_some());
    }

    /// Only root or the directory's owner may own a file read from it.
    #[test]
    fn a_file_or_generation_another_account_owns_is_refused() {
        use std::os::unix::fs::{chown, MetadataExt};

        let bundle = TempBundle::complete("foreign-file");
        let directory_owner = fs::metadata(&bundle.root).expect("metadata").uid();
        // Neither root nor the directory's owner.
        let other = if directory_owner == 1 { 2 } else { 1 };
        // Giving a file away needs privilege. An unprivileged run checks the
        // rule itself in `only_root_or_the_directory_owner_may_own_what_is_read`.
        if chown(bundle.root.join("policy.json"), Some(other), None).is_ok() {
            assert_eq!(only_codes(&bundle.read()), [Code::UntrustedOwner]);

            let bundle = atomic_writer("foreign-generation");
            chown(
                bundle.root.join("..2026_10_21_10_00_00.000000001"),
                Some(other),
                None,
            )
            .expect("a privileged run can give the generation away");
            assert_eq!(only_codes(&bundle.read()), [Code::UntrustedOwner]);

            // Root may own what another account's directory holds.
            let bundle = TempBundle::complete("root-owned-file");
            chown(&bundle.root, Some(other), None).expect("give the root away");
            chown(bundle.root.join("policy.json"), Some(0), None).expect("root owns");
            for name in ["bundle.yaml", "deployment.yaml", "tools.json"] {
                chown(bundle.root.join(name), Some(other), None).expect("same owner");
            }
            assert!(bundle.read().bundle.is_some());
        }
    }

    #[test]
    fn the_atomic_writer_volume_root_alone_may_be_sticky_and_world_writable() {
        let bundle = atomic_writer("atomic-sticky-root");
        set_mode(&bundle.root, 0o1777);
        let report = bundle.read();
        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
        assert!(report.bundle.is_some());

        // Without the sticky bit anyone could repoint `..data`.
        let bundle = atomic_writer("atomic-open-root");
        set_mode(&bundle.root, 0o777);
        assert_eq!(only_codes(&bundle.read()), [Code::UnsafePermissions]);

        // The generation is the volume owner's alone, sticky or not.
        for mode in [0o1777, 0o775, 0o777] {
            let bundle = atomic_writer(&format!("atomic-writable-generation-{mode:o}"));
            set_mode(&bundle.root.join("..2026_10_21_10_00_00.000000001"), mode);
            assert_eq!(
                only_codes(&bundle.read()),
                [Code::UnsafePermissions],
                "{mode:o}"
            );
        }
    }

    /// The kubelet's layout: `..data -> ..<timestamp>`, files inside the
    /// generation, and one top-level link per key.
    fn atomic_writer(label: &str) -> TempBundle {
        let bundle = TempBundle::empty(label);
        let generation = bundle.root.join("..2026_10_21_10_00_00.000000001");
        fs::create_dir(&generation).expect("generation directory");
        set_mode(&generation, 0o755);
        let staged = TempBundle::complete(&format!("{label}-staged"));
        for name in [
            "bundle.yaml",
            "deployment.yaml",
            "policy.json",
            "tools.json",
        ] {
            let target = generation.join(name);
            fs::copy(staged.root.join(name), &target).expect("copy into generation");
            set_mode(&target, 0o644);
            symlink(format!("..data/{name}"), bundle.root.join(name)).expect("per-key link");
        }
        symlink(
            "..2026_10_21_10_00_00.000000001",
            bundle.root.join("..data"),
        )
        .expect("..data link");
        bundle
    }

    #[test]
    fn the_atomic_writer_layout_is_read_from_one_generation() {
        let bundle = atomic_writer("atomic");
        let report = bundle.read();
        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
        assert!(report.bundle.is_some());
    }

    #[test]
    fn a_malformed_atomic_writer_layout_is_refused() {
        let bundle = atomic_writer("atomic-absolute");
        fs::remove_file(bundle.root.join("..data")).expect("remove ..data");
        symlink("/tmp", bundle.root.join("..data")).expect("absolute ..data");
        assert_eq!(only_codes(&bundle.read()), [Code::AtomicWriterInvalid]);

        let bundle = atomic_writer("atomic-nested");
        fs::remove_file(bundle.root.join("..data")).expect("remove ..data");
        symlink(
            "..2026_10_21_10_00_00.000000001/.",
            bundle.root.join("..data"),
        )
        .expect("nested ..data");
        assert_eq!(only_codes(&bundle.read()), [Code::AtomicWriterInvalid]);

        let bundle = atomic_writer("atomic-plain-target");
        fs::create_dir(bundle.root.join(".plain")).expect("dot directory");
        fs::remove_file(bundle.root.join("..data")).expect("remove ..data");
        symlink(".plain", bundle.root.join("..data")).expect("non-generation target");
        assert_eq!(only_codes(&bundle.read()), [Code::AtomicWriterInvalid]);

        let bundle = atomic_writer("atomic-mixed");
        fs::write(bundle.root.join("stray.json"), b"{}").expect("regular file beside ..data");
        assert_eq!(only_codes(&bundle.read()), [Code::AtomicWriterInvalid]);

        let bundle = atomic_writer("atomic-data-directory");
        fs::remove_file(bundle.root.join("..data")).expect("remove ..data");
        fs::create_dir(bundle.root.join("..data")).expect("..data directory");
        assert_eq!(only_codes(&bundle.read()), [Code::AtomicWriterInvalid]);

        let bundle = atomic_writer("atomic-inner-link");
        let generation = bundle.root.join("..2026_10_21_10_00_00.000000001");
        fs::remove_file(generation.join("policy.json")).expect("remove policy");
        symlink("/etc/passwd", generation.join("policy.json")).expect("link inside generation");
        assert_eq!(only_codes(&bundle.read()), [Code::SymlinkForbidden]);
    }
}

#[cfg(windows)]
#[test]
#[ignore = "requires Windows Developer Mode or SeCreateSymbolicLinkPrivilege"]
fn windows_symbolic_links_are_refused() {
    let bundle = TempBundle::complete("windows-symlink");
    fs::rename(
        bundle.root.join("policy.json"),
        bundle.root.join("real.json"),
    )
    .expect("rename");
    std::os::windows::fs::symlink_file(
        bundle.root.join("real.json"),
        bundle.root.join("policy.json"),
    )
    .expect("Windows symbolic-link privilege is required for this ignored test");
    let report = bundle.read();
    assert!(report.bundle.is_none());
    assert_eq!(codes(&report.diagnostics)[0], Code::SymlinkForbidden);
}

// --- file names ---------------------------------------------------------------

#[test]
fn file_names_are_portable_lowercase_and_contained() {
    for name in [
        "bundle.yaml",
        "policy.json",
        "a",
        "0",
        "a-b_c.d.json",
        &"a".repeat(63),
        "console.json",
        "com10.json",
        "nul-x.json",
    ] {
        assert!(is_portable_file_name(name), "{name:?}");
    }
    for name in [
        "",
        ".",
        "..",
        ".hidden",
        "-lead",
        "_lead",
        "Policy.json",
        "policy.json.",
        "policy json",
        "a/b",
        "a\\b",
        "../a",
        "c:policy",
        "policy.json:stream",
        "\u{e9}.json",
        &"a".repeat(64),
        "con",
        "con.json",
        "nul.yaml",
        "prn",
        "aux.txt",
        "com1",
        "com9.json",
        "lpt1",
        "lpt0.x",
    ] {
        assert!(!is_portable_file_name(name), "{name:?}");
    }
    let file = FileName::parse("deployment.yaml").expect("valid");
    assert!(file.has_extension("yaml"));
    assert!(!file.has_extension("json"));
    assert!(!FileName::parse("json")
        .expect("valid")
        .has_extension("json"));
}

// --- diagnostics --------------------------------------------------------------

fn assert_value_free(diagnostics: &[BundleDiagnostic]) {
    for diagnostic in diagnostics {
        let rendered = format!("{diagnostic} {diagnostic:?}");
        assert!(!rendered.contains(CANARY), "{rendered}");
    }
}

#[test]
fn every_code_is_stable_unique_and_documented() {
    let reference = repository_text("docs/configuration-bundles.md");
    let mut seen = std::collections::BTreeSet::new();
    for code in Code::ALL {
        let text = code.as_str();
        let (family, reason) = text.split_once('.').expect("family.reason");
        // Lowercase snake segments; a word starts with a letter (`not_utf8`).
        let snake = |part: &str| {
            !part.is_empty()
                && part.split('_').all(|word| {
                    word.as_bytes()
                        .first()
                        .is_some_and(|first| first.is_ascii_lowercase())
                        && word
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                })
        };
        assert!(snake(family) && snake(reason), "{text}");
        assert!(seen.insert(text), "{text} is used twice");
        assert!(
            !code.message().is_empty() && !code.message().ends_with('.'),
            "{text}"
        );
        assert!(
            reference.contains(&format!("`{text}`")),
            "{text} is not documented"
        );
    }
    // Every `family.reason` the reference spells in code is a real code.
    let families = [
        "bundle",
        "syntax",
        "json",
        "yaml",
        "compat",
        "schema",
        "reference",
        "secret",
        "resource",
    ];
    for spelled in reference.split('`').skip(1).step_by(2) {
        let Some((family, reason)) = spelled.split_once('.') else {
            continue;
        };
        let code_shaped = families.contains(&family)
            && !reason.is_empty()
            && reason
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
        if code_shaped && spelled != "bundle.yaml" {
            assert!(
                seen.contains(spelled),
                "{spelled} is documented but not a code"
            );
        }
    }
}

#[test]
fn diagnostics_never_echo_document_values() {
    let bundle = TempBundle::empty("canary");
    bundle.write(
        "deployment.yaml",
        format!(
            "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: {CANARY}\n  {CANARY}_key: \"{CANARY}\"\n"
        )
        .as_bytes(),
    );
    bundle.write(
        "policy.json",
        format!("{{\"schema_version\": \"0.1.0\", \"default_action\": \"{CANARY}\"}}\n").as_bytes(),
    );
    bundle.write(
        "tools.json",
        format!("{{\"schema_version\": \"0.1.0\", \"tools\": [{{\"name\": \"{CANARY}\"}}]}}\n")
            .as_bytes(),
    );
    bundle.write("bundle.yaml", bundle.manifest().as_bytes());
    let report = bundle.read();
    assert!(report.bundle.is_none());
    assert_eq!(
        only_codes(&report),
        [
            Code::UnknownMember,
            Code::InvalidValue,
            Code::ResourceInvalid,
            Code::ResourceInvalid
        ]
    );
    assert_value_free(&report.diagnostics);

    let manifest = bundle.manifest().replace(
        "  name: payments-production\n",
        &format!("  name: {CANARY}_Name\n  {CANARY}: 1\n"),
    );
    bundle.write("bundle.yaml", manifest.as_bytes());
    let report = bundle.read();
    assert_eq!(
        only_codes(&report),
        [Code::UnknownMember, Code::InvalidName]
    );
    assert_value_free(&report.diagnostics);

    // Each stage, with the canary placed where it would be echoed.
    let file = FileName::parse("deployment.yaml").expect("valid");
    for text in [
        format!("a: \"{CANARY}\\x\"\n"),
        format!("a: {CANARY}: b\n"),
        format!("{CANARY} key: 1\n"),
        format!("a: yes{CANARY}\n"),
        format!("apiVersion: \"{CANARY}\"\nkind: GatewayDeployment\n"),
        format!("apiVersion: greengateway.dev/v1alpha1\nkind: {CANARY}\n"),
    ] {
        let mut diagnostics = Vec::new();
        match yaml::parse(&text, DOCUMENT_LIMITS) {
            Ok(node) => {
                let _ = document::deployment(&node, &file, &mut diagnostics);
            }
            Err(error) => diagnostics.push(BundleDiagnostic::at(
                error.code,
                &file,
                super::diagnostic::Pointer::root(),
                Some(error.position),
            )),
        }
        assert!(!diagnostics.is_empty(), "{text}");
        assert_value_free(&diagnostics);
    }
}

#[test]
fn diagnostics_render_file_position_code_and_pointer() {
    let file = FileName::parse("bundle.yaml").expect("valid");
    let diagnostic = BundleDiagnostic::at(
        Code::InvalidDigest,
        &file,
        super::diagnostic::Pointer::root()
            .member("spec")
            .member("deployment")
            .member("sha256"),
        Some(at(8, 13)),
    );
    assert_eq!(
        diagnostic.to_string(),
        "bundle.yaml:8:13: error[reference.invalid_digest]: a pinned digest is not 64 lowercase hexadecimal digits (at /spec/deployment/sha256)"
    );
    assert_eq!(
        BundleDiagnostic::bundle(Code::TooManyEntries).warning().to_string(),
        "warning[bundle.too_many_entries]: the bundle directory holds more entries than a bundle may"
    );
    assert_eq!(
        super::diagnostic::Pointer::root()
            .member("a")
            .index(3)
            .to_string(),
        "/a/3"
    );
}

// --- published schemas --------------------------------------------------------

fn schema(name: &str) -> JsonValue {
    let schema: JsonValue = serde_json::from_str(&repository_text(&format!("docs/schemas/{name}")))
        .unwrap_or_else(|error| panic!("{name} should be JSON: {error}"));
    assert_eq!(
        schema["$schema"], "https://json-schema.org/draft/2020-12/schema",
        "{name}"
    );
    assert_eq!(
        schema["$id"],
        format!("https://greengateway.dev/schemas/{name}"),
        "{name}"
    );
    schema
}

fn validator(schema: &JsonValue) -> jsonschema::Validator {
    jsonschema::validator_for(schema).expect("schema should compile")
}

/// A `$defs` entry compiled on its own.
fn definition(schema: &JsonValue, name: &str) -> jsonschema::Validator {
    let mut standalone = schema["$defs"][name].clone();
    standalone["$defs"] = schema["$defs"].clone();
    standalone["$schema"] = schema["$schema"].clone();
    validator(&standalone)
}

#[test]
fn the_manifest_schema_agrees_with_the_reader() {
    let schema = schema("gateway-bundle.v1alpha1.schema.json");
    let validator = validator(&schema);
    assert_eq!(
        schema["properties"]["apiVersion"]["const"],
        ApiVersion::V1Alpha1.as_str()
    );
    assert_eq!(schema["properties"]["kind"]["const"], document::BUNDLE_KIND);
    assert_eq!(
        schema["$defs"]["policyResource"]["oneOf"][0]["properties"]["schema_version"]["enum"],
        json!(POLICY_SCHEMA_VERSIONS)
    );
    assert_eq!(
        schema["$defs"]["toolsResource"]["oneOf"][0]["properties"]["schema_version"]["enum"],
        json!(TOOLS_SCHEMA_VERSIONS)
    );

    let valid = manifest_text(DEPLOYMENT_DIGEST, POLICY_DIGEST, TOOLS_DIGEST);
    let cases = [
        valid.clone(),
        valid.replace("kind: GatewayBundle\n", "kind: GatewayBundle\nextra: 1\n"),
        valid.replace("kind: GatewayBundle\n", "kind: GatewayDeployment\n"),
        valid.replace(
            "apiVersion: greengateway.dev/v1alpha1\n",
            "apiVersion: greengateway.dev/v1alpha2\n",
        ),
        valid.replace("metadata:\n  name: payments-production\n", ""),
        valid.replace("  name: payments-production\n", "  name: Payments\n"),
        valid.replace("  name: payments-production\n", "  name: payments-\n"),
        valid.replace("  name: payments-production\n", "  name: a\n"),
        valid.replace("    path: deployment.yaml\n", "    path: deployment.json\n"),
        valid.replace("    path: deployment.yaml\n", "    path: deployment.yml\n"),
        valid.replace("      path: policy.json\n", "      path: Policy.json\n"),
        valid.replace("      path: policy.json\n", "      path: policy.json.\n"),
        valid.replace("      path: policy.json\n", "      path: con.json\n"),
        valid.replace("      path: policy.json\n", "      path: console.json\n"),
        valid.replace("      path: policy.json\n", "      path: bundle.yaml\n"),
        valid.replace(
            "      path: policy.json\n",
            "      path: \"../policy.json\"\n",
        ),
        valid.replace(DEPLOYMENT_DIGEST, &DEPLOYMENT_DIGEST.to_uppercase()),
        valid.replace(
            "      schema_version: \"0.1.0\"\n      sha256: \"a1",
            "      schema_version: \"0.2.0\"\n      sha256: \"a1",
        ),
        valid.replace(
            "    tools:\n      source: bundle\n",
            "    tools:\n      source: server\n",
        ),
        valid.replace("    sha256: \"0b0b", "    digest: \"0b0b"),
        valid.replace("      source: server\n", "      source: bundle\n"),
        valid.replace("    connections:\n      source: server\n", ""),
        valid.replace("  resources:\n", "  ignored:\n"),
        valid.replace(
            "    policy:\n      source: bundle\n",
            "    policy:\n      source: git\n",
        ),
    ];
    for text in cases {
        let node = parse_yaml(&text);
        let mut diagnostics = Vec::new();
        let reader = document::manifest(&node, &mut diagnostics).is_some();
        assert_eq!(
            validator.is_valid(&node.to_json()),
            reader,
            "{text}\n{diagnostics:?}"
        );
    }
}

#[test]
fn the_deployment_schema_agrees_with_the_reader() {
    let schema = schema("gateway-deployment.v1alpha1.schema.json");
    let validator = validator(&schema);
    assert_eq!(
        schema["properties"]["kind"]["const"],
        document::DEPLOYMENT_KIND
    );
    assert_eq!(
        schema["properties"]["spec"]["properties"]["profile"]["enum"],
        json!(Profile::ALL
            .iter()
            .map(|profile| profile.as_str())
            .collect::<Vec<_>>())
    );
    assert_eq!(
        schema["$defs"]["unresolved"]["properties"]["unresolved"]["enum"],
        json!(UnresolvedReason::ALL
            .iter()
            .map(|reason| reason.as_str())
            .collect::<Vec<_>>())
    );

    let file = FileName::parse("deployment.yaml").expect("valid");
    for text in [
        DEPLOYMENT_YAML.to_owned(),
        DEPLOYMENT_YAML.replace("production", "development"),
        DEPLOYMENT_YAML.replace("production", "staging"),
        DEPLOYMENT_YAML.replace(
            "  profile: production\n",
            "  profile: production\n  listeners: {}\n",
        ),
        DEPLOYMENT_YAML.replace(
            "kind: GatewayDeployment\n",
            "kind: GatewayDeployment\nmetadata: {name: a}\n",
        ),
        DEPLOYMENT_YAML.replace("kind: GatewayDeployment\n", "kind: GatewayBundle\n"),
        DEPLOYMENT_YAML.replace("spec:\n  profile: production\n", "spec: {}\n"),
    ] {
        let node = parse_yaml(&text);
        let mut diagnostics = Vec::new();
        let reader = document::deployment(&node, &file, &mut diagnostics).is_some();
        assert_eq!(
            validator.is_valid(&node.to_json()),
            reader,
            "{text}\n{diagnostics:?}"
        );
    }

    let secret_reference = definition(&schema, "secretReference");
    let decimal = definition(&schema, "decimal");
    let unresolved = definition(&schema, "unresolved");
    for text in [
        "{ secret: idp-client }",
        "{ secret: a.b_c-D9 }",
        "{ secret: \"../x\" }",
        "{ secret: _a }",
        "{ secret: a, b: c }",
        "{ secret: 1 }",
        "\"literal\"",
        "{ unresolved: template_value }",
    ] {
        let node = parse_yaml(text);
        assert_eq!(
            secret_reference.is_valid(&node.to_json()),
            SecretReference::from_node(&node).is_ok(),
            "{text}"
        );
        assert_eq!(
            unresolved.is_valid(&node.to_json()),
            matches!(Unresolved::from_node(&node), Some(Ok(_))),
            "{text}"
        );
    }
    let long_alias = format!("{{ secret: {} }}", "a".repeat(129));
    assert!(!secret_reference.is_valid(&parse_yaml(&long_alias).to_json()));
    for text in [
        "0",
        "0.10",
        "2.0",
        "01",
        "1.",
        ".5",
        "-1",
        "1e3",
        "1.1234567",
        "10000000000000000",
    ] {
        assert_eq!(
            decimal.is_valid(&json!(text)),
            Decimal::parse(text).is_some(),
            "{text:?}"
        );
    }
    assert!(!decimal.is_valid(&json!(1)));
}

#[test]
fn number_domains_and_byte_bounds_are_fixed() {
    // Bundle documents are safe integers; resources keep exact number text.
    assert_eq!(DOCUMENT_LIMITS.numbers, Numbers::SafeIntegers);
    assert_eq!(RESOURCE_LIMITS.numbers, Numbers::Any);
    assert_eq!(MAX_MANIFEST_BYTES, 64 * 1024);
    assert_eq!(resource::MAX_RESOURCE_BYTES, 1024 * 1024);
}
