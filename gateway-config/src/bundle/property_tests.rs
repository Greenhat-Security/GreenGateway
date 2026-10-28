//! Bounded, seeded fuzz-style properties of the bundle readers.
//!
//! Each property runs a fixed number of cases from a fixed seed, so a failure
//! reproduces exactly and the suite's cost is bounded. They cover what the
//! example tables cannot enumerate: hostile input never panics and never
//! escapes a bound, generated documents round-trip through both syntaxes to
//! the same value, and the published file-name pattern agrees with the
//! reader's grammar.

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};
use serde_json::{Map, Value as JsonValue};

use super::{
    document, json,
    source::is_portable_file_name,
    syntax::{Node, Value, DOCUMENT_LIMITS, MAX_DEPTH, RESOURCE_LIMITS},
    value::Decimal,
    yaml,
};

fn property_config() -> Config {
    Config {
        cases: 256,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(242_004),
        max_shrink_iters: 2_048,
        ..Config::default()
    }
}

/// Characters that mean something to YAML or JSON, plus ordinary ones.
const HOSTILE: &[char] = &[
    '-', '?', ':', ',', '[', ']', '{', '}', '#', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`',
    '\\', '<', '=', '~', '.', '+', '_', '/', ' ', ' ', ' ', '\n', '\n', '\t', 'a', 'b', 'y', 'n',
    'o', 'e', 's', 'x', '0', '1', '9', 'u', '\u{e9}', '\u{202e}', '\u{2028}', '\u{0}',
];

fn hostile_text(maximum: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::sample::select(HOSTILE), 0..maximum)
        .prop_map(|characters| characters.into_iter().collect())
}

/// The deepest collection nesting in a parsed tree.
fn depth(node: &Node) -> usize {
    match &node.value {
        Value::Array(items) => 1 + items.iter().map(depth).max().unwrap_or(0),
        Value::Object(members) => {
            1 + members
                .iter()
                .map(|member| depth(&member.value))
                .max()
                .unwrap_or(0)
        }
        _ => 0,
    }
}

/// JSON values in the bundle document domain: safe integers, printable
/// strings without forbidden characters, and objects with unique keys.
fn document_value() -> impl Strategy<Value = JsonValue> {
    let leaf = prop_oneof![
        Just(JsonValue::Null),
        any::<bool>().prop_map(JsonValue::Bool),
        (-9_007_199_254_740_991_i64..=9_007_199_254_740_991_i64).prop_map(JsonValue::from),
        "[ -~\u{e9}\u{4e2d}\t\n]{0,24}".prop_map(JsonValue::String),
    ];
    leaf.prop_recursive(6, 64, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(JsonValue::Array),
            proptest::collection::btree_map("[ -~\u{e9}]{0,12}", inner, 0..6)
                .prop_map(|map| JsonValue::Object(map.into_iter().collect::<Map<_, _>>())),
        ]
    })
}

/// A block-style YAML rendering in the safe subset: every string and key
/// double-quoted with JSON escapes, every non-empty collection as a block.
fn block_yaml(value: &JsonValue) -> String {
    let mut out = String::new();
    match value {
        JsonValue::Array(items) if !items.is_empty() => emit_sequence(items, 0, &mut out),
        JsonValue::Object(map) if !map.is_empty() => emit_mapping(map, 0, &mut out),
        scalar => {
            out.push_str(&inline(scalar));
            out.push('\n');
        }
    }
    out
}

fn inline(value: &JsonValue) -> String {
    match value {
        JsonValue::Array(items) if items.is_empty() => "[]".to_owned(),
        JsonValue::Object(map) if map.is_empty() => "{}".to_owned(),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

fn is_block(value: &JsonValue) -> bool {
    match value {
        JsonValue::Array(items) => !items.is_empty(),
        JsonValue::Object(map) => !map.is_empty(),
        _ => false,
    }
}

fn emit_mapping(map: &Map<String, JsonValue>, indent: usize, out: &mut String) {
    for (key, value) in map {
        out.push_str(&" ".repeat(indent));
        out.push_str(&serde_json::to_string(key).unwrap_or_default());
        out.push(':');
        emit_value(value, indent, out);
    }
}

fn emit_sequence(items: &[JsonValue], indent: usize, out: &mut String) {
    for item in items {
        out.push_str(&" ".repeat(indent));
        out.push('-');
        emit_value(item, indent, out);
    }
}

fn emit_value(value: &JsonValue, indent: usize, out: &mut String) {
    if is_block(value) {
        out.push('\n');
        match value {
            JsonValue::Array(items) => emit_sequence(items, indent + 2, out),
            JsonValue::Object(map) => emit_mapping(map, indent + 2, out),
            _ => {}
        }
    } else {
        out.push(' ');
        out.push_str(&inline(value));
        out.push('\n');
    }
}

/// A valid manifest to mutate.
const MANIFEST: &str = concat!(
    "apiVersion: greengateway.dev/v1alpha1\n",
    "kind: GatewayBundle\n",
    "metadata:\n",
    "  name: payments-production\n",
    "spec:\n",
    "  deployment: {path: deployment.yaml, sha256: \"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\"}\n",
    "  resources:\n",
    "    policy:\n",
    "      source: bundle\n",
    "      path: policy.json\n",
    "      schema_version: \"0.1.0\"\n",
    "      sha256: \"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"\n",
    "    connections: {source: server}\n",
);

#[derive(Clone, Debug)]
enum Edit {
    Insert(usize, char),
    Delete(usize),
    Replace(usize, char),
}

fn edits() -> impl Strategy<Value = Vec<Edit>> {
    let edit = prop_oneof![
        (any::<usize>(), proptest::sample::select(HOSTILE))
            .prop_map(|(at, character)| Edit::Insert(at, character)),
        any::<usize>().prop_map(Edit::Delete),
        (any::<usize>(), proptest::sample::select(HOSTILE))
            .prop_map(|(at, character)| Edit::Replace(at, character)),
    ];
    proptest::collection::vec(edit, 1..8)
}

fn apply(text: &str, edits: &[Edit]) -> String {
    let mut characters: Vec<char> = text.chars().collect();
    for edit in edits {
        match *edit {
            Edit::Insert(at, character) => {
                let at = at % (characters.len() + 1);
                characters.insert(at, character);
            }
            Edit::Delete(at) if !characters.is_empty() => {
                let at = at % characters.len();
                characters.remove(at);
            }
            Edit::Replace(at, character) if !characters.is_empty() => {
                let at = at % characters.len();
                characters[at] = character;
            }
            _ => {}
        }
    }
    characters.into_iter().collect()
}

/// A manifest's outcome, rendered for comparison.
fn manifest_outcome(text: &str) -> String {
    match yaml::parse(text, DOCUMENT_LIMITS) {
        Err(error) => format!("syntax {error:?}"),
        Ok(node) => {
            let mut diagnostics = Vec::new();
            let manifest = document::manifest(&node, &mut diagnostics);
            format!("{manifest:?} {diagnostics:?}")
        }
    }
}

proptest! {
    #![proptest_config(property_config())]

    #[test]
    fn the_yaml_reader_never_panics_and_keeps_its_bounds(text in hostile_text(256)) {
        if let Ok(node) = yaml::parse(&text, DOCUMENT_LIMITS) {
            prop_assert!(depth(&node) <= MAX_DEPTH);
            // What the reader accepted denotes a JSON value that strictly
            // reparses to the same thing.
            let json_text = serde_json::to_string(&node.to_json()).unwrap_or_default();
            let reparsed = json::parse(&json_text, DOCUMENT_LIMITS).map(|node| node.to_json());
            prop_assert_eq!(reparsed.ok(), Some(node.to_json()));
        }
    }

    #[test]
    fn the_json_reader_never_panics_and_keeps_its_bounds(text in hostile_text(256)) {
        for limits in [DOCUMENT_LIMITS, RESOURCE_LIMITS] {
            if let Ok(node) = json::parse(&text, limits) {
                prop_assert!(depth(&node) <= MAX_DEPTH);
            }
        }
    }

    #[test]
    fn generated_documents_round_trip_through_strict_json(value in document_value()) {
        for text in [
            serde_json::to_string(&value).unwrap_or_default(),
            serde_json::to_string_pretty(&value).unwrap_or_default(),
        ] {
            let parsed = json::parse(&text, DOCUMENT_LIMITS).map(|node| node.to_json());
            prop_assert_eq!(parsed.ok(), Some(value.clone()), "{}", text);
        }
    }

    #[test]
    fn generated_documents_round_trip_through_block_and_flow_yaml(value in document_value()) {
        let block = block_yaml(&value);
        let parsed = yaml::parse(&block, DOCUMENT_LIMITS).map(|node| node.to_json());
        prop_assert_eq!(parsed.ok(), Some(value.clone()), "{}", block);

        // Single-line JSON is a flow collection in the subset.
        let flow = serde_json::to_string(&value).unwrap_or_default();
        let parsed = yaml::parse(&flow, DOCUMENT_LIMITS).map(|node| node.to_json());
        prop_assert_eq!(parsed.ok(), Some(value), "{}", flow);
    }

    #[test]
    fn mutated_manifests_never_panic_and_are_judged_deterministically(edits in edits()) {
        let mutated = apply(MANIFEST, &edits);
        prop_assert_eq!(manifest_outcome(&mutated), manifest_outcome(&mutated));
    }

    #[test]
    fn boolean_and_null_words_must_be_quoted_in_any_case(
        word in proptest::sample::select(&["y", "yes", "n", "no", "true", "false", "on", "off", "null"][..]),
        mask in any::<u16>(),
    ) {
        let cased: String = word
            .chars()
            .enumerate()
            .map(|(index, character)| {
                if mask & (1 << index) != 0 { character.to_ascii_uppercase() } else { character }
            })
            .collect();
        let as_value = yaml::parse(&format!("a: {cased}\n"), DOCUMENT_LIMITS);
        let as_key = yaml::parse(&format!("{cased}: a\n"), DOCUMENT_LIMITS);
        prop_assert!(as_key.is_err(), "{cased}");
        if matches!(cased.as_str(), "true" | "false" | "null") {
            prop_assert!(as_value.is_ok(), "{cased}");
        } else {
            prop_assert!(as_value.is_err(), "{cased}");
        }
    }

    #[test]
    fn the_published_file_name_pattern_matches_the_reader(
        name in prop_oneof![
            "[a-zA-Z0-9._:/\\\\ -]{0,66}",
            "[a-z0-9._-]{0,66}",
            "(con|prn|aux|nul|com[0-9]|lpt[0-9]|console|com|lpt1x)(\\.[a-z]{0,4})?",
        ],
    ) {
        prop_assert_eq!(is_portable_file_name(&name), published_file_name(&name), "{}", name);
    }

    #[test]
    fn decimal_canonical_forms_parse_to_the_same_float(
        integer in "0|[1-9][0-9]{0,15}",
        fraction in proptest::option::of("[0-9]{1,6}"),
    ) {
        let text = match &fraction {
            Some(fraction) => format!("{integer}.{fraction}"),
            None => integer.clone(),
        };
        let decimal = Decimal::parse(&text);
        prop_assert!(decimal.is_some(), "{text}");
        let Some(decimal) = decimal else {
            return Ok(());
        };
        prop_assert_eq!(decimal.as_f64(), text.parse::<f64>().unwrap_or(f64::NAN));
        prop_assert!(!decimal.canonical().ends_with('0') || !decimal.canonical().contains('.'));
        prop_assert!(!decimal.canonical().ends_with('.'));
        let reparsed = Decimal::parse(decimal.canonical()).map(|again| again.canonical().to_owned());
        prop_assert_eq!(reparsed.as_deref(), Some(decimal.canonical()));
    }
}

/// The schema's `fileName` definition, compiled once.
fn published_file_name(name: &str) -> bool {
    static VALIDATOR: std::sync::LazyLock<jsonschema::Validator> = std::sync::LazyLock::new(|| {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../docs/schemas/gateway-bundle.v1alpha1.schema.json");
        let schema: JsonValue = serde_json::from_str(
            &std::fs::read_to_string(path).expect("the manifest schema should be readable"),
        )
        .expect("the manifest schema should be JSON");
        let mut definition = schema["$defs"]["fileName"].clone();
        definition["$schema"] = schema["$schema"].clone();
        jsonschema::validator_for(&definition).expect("the fileName definition should compile")
    });
    VALIDATOR.is_valid(&JsonValue::String(name.to_owned()))
}
