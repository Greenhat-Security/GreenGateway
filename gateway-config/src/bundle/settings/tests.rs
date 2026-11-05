//! The deployment settings reader, held to the field catalog, to the
//! published schema and to the reference it renders.
//!
//! What the catalog says about each bound is proved against the compiler by
//! `compiler::catalog_tests`; these tests prove that the document reader
//! enforces exactly the catalog's types and bounds, refuses every member the
//! catalog's paths do not name, canonicalizes decimals and the store list,
//! never echoes a value, and that the committed schema and reference are what
//! the catalog renders.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};
use serde_json::{json, Map, Value as JsonValue};

use super::{
    check, children, document_maximum, document_paths, member_names, render::DECIMAL_PATTERN,
    render_deployment_reference, render_deployment_schema, Child, SettingValue,
    DEPLOYMENT_SCHEMA_DOCUMENT, SECTIONS, STANDALONE_STORES, STORES_PATH,
};
use crate::{
    bundle::{
        diagnostic::{BundleDiagnostic, Code},
        document, json,
        source::FileName,
        syntax::{Node, Value, DOCUMENT_LIMITS, MAX_SAFE_INTEGER},
        yaml, PublishedSchemasOnly, ReadOptions,
    },
    catalog::{
        self, BundleMapping, DecimalBound, DefaultValue, Field, FieldType, Sensitivity, FIELDS,
    },
};

const CANARY: &str = "zqcanary";
const SAFE: u64 = MAX_SAFE_INTEGER.unsigned_abs();
/// Where the settings reference sits in `docs/configuration-bundles.md`.
const REFERENCE_DOCUMENT: &str = "docs/configuration-bundles.md";
const REFERENCE_BEGIN: &str = "<!-- deployment-settings:begin -->";
const REFERENCE_END: &str = "<!-- deployment-settings:end -->";

fn repository_path(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(relative)
}

fn repository_text(relative: &str) -> String {
    let path = repository_path(relative);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
        .replace("\r\n", "\n")
}

/// Every field a document can set.
fn settable() -> impl Iterator<Item = &'static Field> {
    FIELDS
        .iter()
        .filter(|field| field.document_path().is_some())
}

fn field(environment: &str) -> &'static Field {
    catalog::field(environment).unwrap_or_else(|| panic!("{environment} is a field"))
}

/// A value the document accepts for `field`.
fn valid(field: &Field) -> JsonValue {
    if field.sensitivity != Sensitivity::Public {
        return json!({ "secret": "settings-probe" });
    }
    match field.field_type {
        FieldType::Boolean => json!(true),
        FieldType::Integer(range) => json!(range.minimum),
        FieldType::Decimal(_) => match field.default {
            DefaultValue::Literal(value) => json!(value),
            DefaultValue::Unset | DefaultValue::Derived(_) => {
                panic!("{} has a literal default", field.environment)
            }
        },
        FieldType::Choice(words) => json!(words[0]),
        FieldType::SocketAddress => json!("127.0.0.1:9099"),
        FieldType::Url => json!("https://settings-probe.example.test"),
        FieldType::Text => json!("settings-probe"),
        FieldType::List => json!(["settings-probe", "/second"]),
        FieldType::Path | FieldType::PathList | FieldType::Json => {
            panic!("{} has no document form", field.environment)
        }
    }
}

/// Sets the member at `path` (a JSON Pointer of plain names) in `document`,
/// creating the sections above it.
fn set(document: &mut JsonValue, path: &str, value: JsonValue) {
    let mut segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let last = segments.pop().expect("a path has a member");
    let mut current = document;
    for segment in segments {
        current = current
            .as_object_mut()
            .expect("sections are objects")
            .entry(segment)
            .or_insert_with(|| JsonValue::Object(Map::new()));
    }
    current
        .as_object_mut()
        .expect("sections are objects")
        .insert(last.to_owned(), value);
}

fn envelope() -> JsonValue {
    json!({
        "apiVersion": "greengateway.dev/v1alpha1",
        "kind": "GatewayDeployment",
        "spec": { "profile": "production" },
    })
}

fn with(path: &str, value: JsonValue) -> JsonValue {
    let mut document = envelope();
    set(&mut document, path, value);
    document
}

fn node(document: &JsonValue) -> Node {
    let text = serde_json::to_string(document).expect("documents serialize");
    json::parse(&text, DOCUMENT_LIMITS)
        .unwrap_or_else(|error| panic!("{text} should parse: {error:?}"))
}

fn file() -> FileName {
    FileName::parse("deployment.json").expect("a valid name")
}

fn read(document: &JsonValue) -> (Option<document::Deployment>, Vec<BundleDiagnostic>) {
    let mut diagnostics = Vec::new();
    let deployment = document::deployment(&node(document), &file(), &mut diagnostics);
    (deployment, diagnostics)
}

/// The codes and pointers of a refused document.
fn refusals(document: &JsonValue) -> Vec<(Code, String)> {
    let (deployment, diagnostics) = read(document);
    assert_eq!(
        deployment.is_none(),
        !diagnostics.is_empty(),
        "a document is refused exactly when it has diagnostics: {diagnostics:?}"
    );
    diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code, diagnostic.pointer.to_string()))
        .collect()
}

fn schema() -> JsonValue {
    serde_json::from_str(&repository_text(DEPLOYMENT_SCHEMA_DOCUMENT))
        .expect("the deployment schema is JSON")
}

fn validator() -> &'static jsonschema::Validator {
    static VALIDATOR: std::sync::LazyLock<jsonschema::Validator> = std::sync::LazyLock::new(|| {
        jsonschema::validator_for(&schema()).expect("the deployment schema compiles")
    });
    &VALIDATOR
}

// --- the document's shape -----------------------------------------------------

#[test]
fn document_paths_are_unique_snake_case_and_never_a_section() {
    let paths: Vec<&str> = document_paths().map(|(path, _)| path).collect();
    let unique: BTreeSet<&str> = paths.iter().copied().collect();
    assert_eq!(unique.len(), paths.len(), "no two settings share a path");
    for path in &paths {
        let segments: Vec<&str> = path
            .strip_prefix("/spec/")
            .unwrap_or_else(|| panic!("{path} is beneath /spec"))
            .split('/')
            .collect();
        for segment in &segments {
            assert!(
                segment
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_lowercase())
                    && segment.bytes().all(|byte| byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'_'),
                "{path}: {segment} is a snake_case name"
            );
        }
        assert_ne!(*path, "/spec/profile", "the profile is the document's own");
        for other in &paths {
            assert!(
                !other.starts_with(&format!("{path}/")),
                "{path} is a setting, so nothing lies beneath it"
            );
        }
    }
}

#[test]
fn every_section_the_paths_imply_is_described_once() {
    let mut implied = BTreeSet::new();
    for (path, _) in document_paths() {
        let mut end = "/spec".len();
        while let Some(next) = path[end + 1..].find('/') {
            end += 1 + next;
            implied.insert(&path[..end]);
        }
    }
    let described: Vec<&str> = SECTIONS.iter().map(|section| section.path).collect();
    let unique: BTreeSet<&str> = described.iter().copied().collect();
    assert_eq!(unique.len(), described.len(), "a section is described once");
    assert_eq!(unique, implied);
    for section in SECTIONS {
        assert!(
            section.description.ends_with('.') && !section.description.contains('|'),
            "{}: one or more sentences that fit a table",
            section.path
        );
    }
}

#[test]
fn the_document_has_a_path_for_every_scalar_and_list_deployment_field() {
    for field in FIELDS {
        let BundleMapping::Deployment { path } = field.bundle else {
            continue;
        };
        assert_eq!(
            path.is_some(),
            field.field_type != FieldType::Json,
            "{}: every deployment field but the JSON documents has a path",
            field.environment
        );
    }
}

#[test]
fn the_standalone_stores_are_the_catalogs_store_resources() {
    let listed: BTreeSet<&str> = STANDALONE_STORES
        .iter()
        .map(|store| store.environment)
        .collect();
    assert_eq!(listed.len(), STANDALONE_STORES.len());
    let resources: BTreeSet<&str> = FIELDS
        .iter()
        .filter(|field| field.bundle == BundleMapping::Resource)
        .map(|field| field.environment)
        .filter(|name| name.ends_with("_SQLITE_PATH") && *name != "POLICY_HISTORY_SQLITE_PATH")
        .collect();
    assert_eq!(
        listed, resources,
        "every standalone store the catalog replaces with a bundle resource can be enabled, \
         except the policy history ADR-0008 has not placed"
    );
    for store in STANDALONE_STORES {
        assert!(
            store
                .name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "{}",
            store.name
        );
    }
}

// --- reading -------------------------------------------------------------------

#[test]
fn a_document_may_set_every_setting_and_each_is_typed_by_its_entry() {
    let mut document = envelope();
    for field in settable() {
        set(
            &mut document,
            field.document_path().expect("settable"),
            valid(field),
        );
    }
    set(
        &mut document,
        STORES_PATH,
        json!(["service_tokens", "audit"]),
    );
    let (deployment, diagnostics) = read(&document);
    let deployment = deployment.unwrap_or_else(|| panic!("{diagnostics:?}"));
    assert_eq!(deployment.settings.values.len(), settable().count());
    for setting in &deployment.settings.values {
        let field = setting.field;
        let typed = match (&setting.value, field.field_type) {
            _ if field.sensitivity != Sensitivity::Public => {
                matches!(setting.value, SettingValue::Secret(_))
            }
            (SettingValue::Boolean(true), FieldType::Boolean) => true,
            (SettingValue::Integer(value), FieldType::Integer(range)) => *value == range.minimum,
            (SettingValue::Decimal(_), FieldType::Decimal(_)) => true,
            (SettingValue::Word(word), FieldType::Choice(words)) => *word == words[0],
            (
                SettingValue::Text(_),
                FieldType::SocketAddress | FieldType::Url | FieldType::Text,
            ) => true,
            (SettingValue::List(entries), FieldType::List) => {
                entries == &["settings-probe", "/second"]
            }
            _ => false,
        };
        assert!(typed, "{}: {:?}", field.environment, setting.value);
    }
    assert_eq!(
        deployment.settings.stores,
        Some(vec!["audit", "service_tokens"]),
        "stores are kept in canonical order"
    );

    // An empty section and an absent one both set nothing.
    let (deployment, _) = read(&with("/spec/listeners", json!({})));
    assert_eq!(
        deployment.expect("an empty section is valid").settings,
        super::Settings::default()
    );
}

#[test]
fn every_object_refuses_a_member_its_paths_do_not_name() {
    let mut objects: Vec<&str> = vec!["/spec"];
    objects.extend(SECTIONS.iter().map(|section| section.path));
    for path in objects {
        let mut document = envelope();
        set(&mut document, &format!("{path}/{CANARY}_member"), json!(1));
        assert_eq!(
            refusals(&document),
            [(Code::UnknownMember, path.to_owned())],
            "{path}"
        );
        // The names it does allow are exactly the next segments of the paths.
        let names: BTreeSet<&str> = member_names(path).into_iter().collect();
        let expected: BTreeSet<&str> = document_paths()
            .filter_map(|(full, _)| full.strip_prefix(path)?.strip_prefix('/'))
            .map(|rest| rest.split('/').next().unwrap_or(rest))
            .collect();
        assert_eq!(names, expected, "{path}");
    }
    // A section is an object; a setting is not one.
    assert_eq!(
        refusals(&with("/spec/egress", json!(true))),
        [(Code::WrongType, "/spec/egress".to_owned())]
    );
    assert_eq!(
        refusals(&with(
            "/spec/egress",
            json!({ "unresolved": "template_value" })
        )),
        [(Code::Unresolved, "/spec/egress".to_owned())]
    );
    assert_eq!(
        refusals(&with("/spec/public_url", json!({ "url": "x" }))),
        [(Code::WrongType, "/spec/public_url".to_owned())]
    );
    // The profile stays required beside the settings.
    let mut document = envelope();
    document["spec"] = json!({ "cors": {} });
    assert_eq!(
        refusals(&document),
        [(Code::MissingMember, "/spec/profile".to_owned())]
    );
}

/// The values a field's catalog entry puts at its edges, each with the code
/// the reader refuses it with, or `None` when it accepts it.
fn edges(field: &Field) -> Vec<(JsonValue, Option<Code>)> {
    let mut cases = vec![
        (
            json!({ "unresolved": "template_value" }),
            Some(Code::Unresolved),
        ),
        (json!({ "unresolved": "other" }), Some(Code::Unresolved)),
    ];
    // `null` is never a value: leaving the member out is how a setting is
    // left unset.
    let null = if field.sensitivity != Sensitivity::Public {
        Code::InvalidSecretReference
    } else if matches!(field.field_type, FieldType::Decimal(_)) {
        Code::InvalidDecimal
    } else {
        Code::WrongType
    };
    cases.push((json!(null), Some(null)));
    if field.sensitivity != Sensitivity::Public {
        cases.extend([
            (json!({ "secret": "settings-probe.v2" }), None),
            (
                json!(format!("{CANARY}-literal")),
                Some(Code::InlineSecretValue),
            ),
            (json!(1), Some(Code::InlineSecretValue)),
            (
                json!({ "secret": format!("../{CANARY}") }),
                Some(Code::InvalidSecretReference),
            ),
            (json!([]), Some(Code::InvalidSecretReference)),
        ]);
        return cases;
    }
    match field.field_type {
        FieldType::Boolean => cases.extend([
            (json!(true), None),
            (json!(false), None),
            (json!("true"), Some(Code::WrongType)),
            (json!(1), Some(Code::WrongType)),
        ]),
        FieldType::Integer(range) => {
            let maximum = document_maximum(range.maximum);
            cases.extend([
                (json!(range.minimum), None),
                (json!(maximum), None),
                (json!(-1), Some(Code::InvalidValue)),
                (json!("1"), Some(Code::WrongType)),
                (json!(true), Some(Code::WrongType)),
            ]);
            if let Some(below) = range.minimum.checked_sub(1) {
                cases.push((json!(below), Some(Code::InvalidValue)));
            }
            if maximum < SAFE {
                cases.push((json!(maximum + 1), Some(Code::InvalidValue)));
            }
        }
        FieldType::Decimal(range) => {
            let minimum = range.minimum;
            cases.extend([
                (
                    json!(minimum.value),
                    (!minimum.inclusive).then_some(Code::InvalidValue),
                ),
                (json!(stepped(minimum, true)), None),
                (json!(1), Some(Code::InvalidDecimal)),
                (json!("1e3"), Some(Code::InvalidDecimal)),
                (json!("-0.5"), Some(Code::InvalidDecimal)),
                (json!("0.1234567"), Some(Code::InvalidDecimal)),
            ]);
            if let Some(below) = stepped_below(minimum) {
                cases.push((json!(below), Some(Code::InvalidValue)));
            }
            match range.maximum {
                Some(maximum) => cases.extend([
                    (
                        json!(maximum.value),
                        (!maximum.inclusive).then_some(Code::InvalidValue),
                    ),
                    (json!(stepped(maximum, false)), None),
                    (json!(stepped(maximum, true)), Some(Code::InvalidValue)),
                ]),
                None => cases.push((json!("9999999999999999.999999"), None)),
            }
        }
        FieldType::Choice(words) => {
            cases.extend(words.iter().map(|word| (json!(word), None)));
            cases.extend([
                (
                    json!(words[0].to_ascii_uppercase() + "X"),
                    Some(Code::InvalidValue),
                ),
                (json!(format!(" {}", words[0])), Some(Code::InvalidValue)),
                (json!(""), Some(Code::InvalidValue)),
                (json!([words[0]]), Some(Code::WrongType)),
            ]);
        }
        FieldType::SocketAddress | FieldType::Url | FieldType::Text => cases.extend([
            (valid(field), None),
            (json!("a"), None),
            (json!("a b"), None),
            (json!(""), Some(Code::InvalidValue)),
            (json!(" a"), Some(Code::InvalidValue)),
            (json!("a\u{a0}"), Some(Code::InvalidValue)),
            (json!(1), Some(Code::WrongType)),
            (json!(["a"]), Some(Code::WrongType)),
        ]),
        FieldType::List => cases.extend([
            (json!([]), None),
            (json!(["a", "b c", "/x"]), None),
            (json!("a"), Some(Code::WrongType)),
            (json!(["a", ""]), Some(Code::InvalidValue)),
            (json!(["a,b"]), Some(Code::InvalidValue)),
            (json!(["a "]), Some(Code::InvalidValue)),
            (json!([1]), Some(Code::WrongType)),
            (
                json!([{ "unresolved": "template_value" }]),
                Some(Code::Unresolved),
            ),
        ]),
        FieldType::Path | FieldType::PathList | FieldType::Json => {}
    }
    cases
}

/// `bound` moved by the smallest step the decimal grammar can write.
fn stepped(bound: DecimalBound, up: bool) -> String {
    let value: f64 = bound.value.parse().expect("catalog bounds are decimals");
    let step = if up { 0.000_001 } else { -0.000_001 };
    format!("{:.6}", value + step)
}

/// The decimal just below `bound`, unless that is negative, which the
/// grammar cannot write.
fn stepped_below(bound: DecimalBound) -> Option<String> {
    let value: f64 = bound.value.parse().expect("catalog bounds are decimals");
    (value >= 0.000_001).then(|| stepped(bound, false))
}

#[test]
fn every_catalog_bound_is_accepted_and_refused_at_its_edges() {
    for field in settable() {
        let path = field.document_path().expect("settable");
        for (value, expected) in edges(field) {
            let document = with(path, value.clone());
            let refused = refusals(&document);
            let label = format!("{} = {value}", field.environment);
            match expected {
                None => assert!(refused.is_empty(), "{label}: {refused:?}"),
                Some(code) => {
                    let [(found, at)] = refused.as_slice() else {
                        panic!("{label}: one refusal, not {refused:?}");
                    };
                    assert_eq!(*found, code, "{label}");
                    // A list entry is reported at its index.
                    let entry = matches!(value, JsonValue::Array(_))
                        && field.field_type == FieldType::List
                        && field.sensitivity == Sensitivity::Public;
                    if entry {
                        assert!(at.starts_with(&format!("{path}/")), "{label} at {at}");
                    } else {
                        assert_eq!(at, path, "{label}");
                    }
                }
            }
        }
    }
}

/// Integers beyond the I-JSON safe range never reach a setting: the syntax
/// reader refuses them before a value is built, so a field with no bound of
/// its own is bounded by the document.
#[test]
fn integers_beyond_the_safe_range_are_refused_by_the_syntax_reader() {
    let text = format!(
        "{{\"apiVersion\":\"greengateway.dev/v1alpha1\",\"kind\":\"GatewayDeployment\",\
         \"spec\":{{\"profile\":\"production\",\"limits\":{{\"max_body_bytes\":{}}}}}}}",
        SAFE + 1
    );
    let error = json::parse(&text, DOCUMENT_LIMITS).expect_err("beyond the safe range");
    assert_eq!(error.code, Code::IntegerOutOfRange);
    let text = "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayDeployment\nspec:\n  profile: production\n  limits:\n    max_body_bytes: 9007199254740992\n";
    let error = yaml::parse(text, DOCUMENT_LIMITS).expect_err("beyond the safe range");
    assert_eq!(error.code, Code::IntegerOutOfRange);
    assert_eq!(document_maximum(u64::MAX), SAFE);
    assert_eq!(document_maximum(10), 10);
}

#[test]
fn the_store_list_names_distinct_known_stores() {
    for (value, expected) in [
        (json!([]), vec![]),
        (json!(["connections"]), vec![]),
        (
            json!([
                "audit",
                "discovery",
                "principals",
                "connections",
                "service_tokens"
            ]),
            vec![],
        ),
        (
            json!(["audit", "audit"]),
            vec![(Code::InvalidValue, "/spec/state/stores/1")],
        ),
        (
            json!(["policy_history"]),
            vec![(Code::InvalidValue, "/spec/state/stores/0")],
        ),
        (json!([1]), vec![(Code::WrongType, "/spec/state/stores/0")]),
        (
            json!("audit"),
            vec![(Code::WrongType, "/spec/state/stores")],
        ),
        (
            json!({ "unresolved": "template_value" }),
            vec![(Code::Unresolved, "/spec/state/stores")],
        ),
    ] {
        let document = with(STORES_PATH, value.clone());
        let expected: Vec<(Code, String)> = expected
            .into_iter()
            .map(|(code, at)| (code, at.to_owned()))
            .collect();
        assert_eq!(refusals(&document), expected, "{value}");
        assert_eq!(
            validator().is_valid(&document),
            expected.is_empty(),
            "the schema agrees on {value}"
        );
    }
}

#[test]
fn every_problem_is_reported_in_document_order() {
    let text = concat!(
        "apiVersion: greengateway.dev/v1alpha1\n",
        "kind: GatewayDeployment\n",
        "spec:\n",
        "  profile: production\n",
        "  listeners:\n",
        "    grpc:\n",
        "      max_concurrent_streams: 0\n",
        "  egress:\n",
        "    deny_private_addresses: \"no\"\n",
        "  upstream:\n",
        "    url: https://upstream.example.test\n",
    );
    let node = yaml::parse(text, DOCUMENT_LIMITS).expect("the subset");
    let mut diagnostics = Vec::new();
    assert!(document::deployment(&node, &file(), &mut diagnostics).is_none());
    let found: Vec<(Code, String)> = diagnostics
        .iter()
        .map(|diagnostic| (diagnostic.code, diagnostic.pointer.to_string()))
        .collect();
    assert_eq!(
        found,
        [
            (
                Code::InvalidValue,
                "/spec/listeners/grpc/max_concurrent_streams".to_owned()
            ),
            (
                Code::WrongType,
                "/spec/egress/deny_private_addresses".to_owned()
            ),
            (Code::InlineSecretValue, "/spec/upstream/url".to_owned()),
        ]
    );
}

#[test]
fn diagnostics_never_echo_a_setting_or_member() {
    let mut document = envelope();
    set(
        &mut document,
        "/spec/csrf/cookie_name",
        json!(format!(" {CANARY}")),
    );
    set(
        &mut document,
        "/spec/cors/allowed_origins",
        json!([format!("{CANARY},x")]),
    );
    set(
        &mut document,
        "/spec/upstream/url",
        json!(format!("https://{CANARY}.example.test")),
    );
    set(&mut document, "/spec/state/backend", json!(CANARY));
    set(
        &mut document,
        &format!("/spec/egress/{CANARY}"),
        json!(CANARY),
    );
    set(&mut document, "/spec/state/stores", json!([CANARY]));
    let (deployment, diagnostics) = read(&document);
    assert!(deployment.is_none());
    assert_eq!(diagnostics.len(), 6, "{diagnostics:?}");
    for diagnostic in &diagnostics {
        let rendered = format!("{diagnostic} {diagnostic:?}");
        assert!(!rendered.contains(CANARY), "{rendered}");
    }
}

// --- the canonical form ----------------------------------------------------------

fn manifest(deployment: &[u8]) -> String {
    format!(
        "apiVersion: greengateway.dev/v1alpha1\nkind: GatewayBundle\nmetadata:\n  name: settings\nspec:\n  deployment:\n    path: deployment.yaml\n    sha256: \"{}\"\n",
        crate::bundle::sha256_pin(deployment)
    )
}

/// The canonical JSON a bundle with this deployment document is read with.
fn canonical(deployment: &str) -> String {
    let files = BTreeMap::from([
        (
            FileName::manifest(),
            manifest(deployment.as_bytes()).into_bytes(),
        ),
        (
            FileName::parse("deployment.yaml").expect("a valid name"),
            deployment.as_bytes().to_vec(),
        ),
    ]);
    let report =
        crate::bundle::read_bundle_files(files, ReadOptions::default(), &PublishedSchemasOnly);
    let bundle = report
        .bundle
        .unwrap_or_else(|| panic!("{deployment} should be read: {:?}", report.diagnostics));
    String::from_utf8(bundle.deployment.canonical_json).expect("UTF-8")
}

#[test]
fn decimals_and_the_store_list_take_their_canonical_form() {
    let written = concat!(
        "apiVersion: greengateway.dev/v1alpha1\n",
        "kind: GatewayDeployment\n",
        "spec:\n",
        "  profile: production\n",
        "  discovery:\n",
        "    payload_capture: { sample_rate: \"0.100\" }\n",
        "    signals: { volume_outlier_threshold: \"3.0\", error_rate_spike_threshold: \"1.000000\" }\n",
        "  rate_limits:\n",
        "    read: { requests_per_second: \"50.250\" }\n",
        "  state:\n",
        "    stores: [service_tokens, audit]\n",
    );
    let canonical_form = concat!(
        "apiVersion: greengateway.dev/v1alpha1\n",
        "kind: GatewayDeployment\n",
        "spec:\n",
        "  profile: production\n",
        "  state:\n",
        "    stores: [audit, service_tokens]\n",
        "  rate_limits:\n",
        "    read: { requests_per_second: \"50.25\" }\n",
        "  discovery:\n",
        "    signals: { error_rate_spike_threshold: \"1\", volume_outlier_threshold: \"3\" }\n",
        "    payload_capture: { sample_rate: \"0.1\" }\n",
    );
    let bytes = canonical(written);
    assert_eq!(bytes, canonical(canonical_form));
    let value: JsonValue = serde_json::from_str(&bytes).expect("canonical JSON");
    assert_eq!(
        value.pointer("/spec/discovery/payload_capture/sample_rate"),
        Some(&json!("0.1"))
    );
    assert_eq!(
        value.pointer("/spec/discovery/signals/volume_outlier_threshold"),
        Some(&json!("3"))
    );
    assert_eq!(
        value.pointer(STORES_PATH),
        Some(&json!(["audit", "service_tokens"]))
    );
    // Integers and other strings are kept as written.
    let integers = concat!(
        "apiVersion: greengateway.dev/v1alpha1\n",
        "kind: GatewayDeployment\n",
        "spec:\n",
        "  profile: production\n",
        "  listeners:\n",
        "    public:\n",
        "      address: \"0.0.0.0:8080\"\n",
        "  limits:\n",
        "    max_body_bytes: 1048576\n",
        "    allowed_content_types:\n",
        "      - application/json\n",
        "      - text/plain\n",
    );
    let value: JsonValue = serde_json::from_str(&canonical(integers)).expect("canonical JSON");
    assert_eq!(
        value["spec"]["limits"],
        json!({ "max_body_bytes": 1_048_576, "allowed_content_types": ["application/json", "text/plain"] })
    );
}

// --- the published schema and the reference -----------------------------------

#[test]
fn the_committed_schema_is_the_rendered_schema() {
    assert!(
        repository_text(DEPLOYMENT_SCHEMA_DOCUMENT) == render_deployment_schema(),
        "{DEPLOYMENT_SCHEMA_DOCUMENT} is not the rendered schema; regenerate it with \
         `cargo test -p gateway-config --lib bundle::settings::tests::regenerate_the_committed_schema_and_reference -- --ignored` \
         and review the difference"
    );
    let schema = schema();
    assert_eq!(
        schema["$defs"]["decimal"]["pattern"], DECIMAL_PATTERN,
        "the schema's decimal grammar is the reader's"
    );
}

fn committed_reference(text: &str) -> Option<(usize, usize)> {
    let start = text.find(REFERENCE_BEGIN)? + REFERENCE_BEGIN.len();
    let end = start + text[start..].find(REFERENCE_END)?;
    Some((start, end))
}

#[test]
fn the_committed_reference_is_the_rendered_reference() {
    let text = repository_text(REFERENCE_DOCUMENT);
    let (start, end) = committed_reference(&text)
        .unwrap_or_else(|| panic!("{REFERENCE_DOCUMENT} has the settings reference markers"));
    assert!(
        text[start..end] == format!("\n{}\n", render_deployment_reference()),
        "{REFERENCE_DOCUMENT}'s settings reference is not the rendered one; regenerate it with \
         `cargo test -p gateway-config --lib bundle::settings::tests::regenerate_the_committed_schema_and_reference -- --ignored` \
         and review the difference"
    );
    // Every setting has one row, and every row links its variable's entry.
    let reference = render_deployment_reference();
    for (path, child) in document_paths() {
        let member = path.trim_start_matches("/spec/").replace('/', ".");
        assert_eq!(
            reference.matches(&format!("| `{member}` |")).count(),
            1,
            "{member}"
        );
        if let Child::Setting(field) = child {
            assert!(
                reference.contains(&format!(
                    "[`{}`](configuration.md#{})",
                    field.environment, field.id
                )),
                "{member}"
            );
        }
    }
}

/// Writes the rendered schema and reference over the committed ones. Run it
/// deliberately, after changing the catalog's document paths, and review the
/// difference it makes.
#[test]
#[ignore = "rewrites the deployment schema and the reference in docs/configuration-bundles.md"]
fn regenerate_the_committed_schema_and_reference() {
    std::fs::write(
        repository_path(DEPLOYMENT_SCHEMA_DOCUMENT),
        render_deployment_schema(),
    )
    .expect("the schema is writable");
    let text = repository_text(REFERENCE_DOCUMENT);
    let (start, end) = committed_reference(&text).expect("the reference markers");
    let updated = format!(
        "{}\n{}\n{}",
        &text[..start],
        render_deployment_reference(),
        &text[end..]
    );
    std::fs::write(repository_path(REFERENCE_DOCUMENT), updated)
        .expect("the reference is writable");
}

#[test]
fn the_schema_agrees_with_the_reader_at_every_edge() {
    for field in settable() {
        let path = field.document_path().expect("settable");
        for (value, expected) in edges(field) {
            let document = with(path, value.clone());
            let reader = refusals(&document).is_empty();
            assert_eq!(reader, expected.is_none());
            // The schema can state a decimal's bounds, not check them.
            let decimal_bound = matches!(field.field_type, FieldType::Decimal(_))
                && field.sensitivity == Sensitivity::Public
                && expected == Some(Code::InvalidValue);
            assert_eq!(
                validator().is_valid(&document),
                reader || decimal_bound,
                "{} = {value}",
                field.environment
            );
        }
    }
    for document in [
        envelope(),
        with(&format!("/spec/listeners/{CANARY}"), json!(1)),
        with("/spec/listeners", json!([])),
    ] {
        assert_eq!(
            validator().is_valid(&document),
            refusals(&document).is_empty(),
            "{document}"
        );
    }
}

#[test]
fn the_schema_states_each_settings_type_and_bounds() {
    let schema = schema();
    for field in settable() {
        let path = field.document_path().expect("settable");
        let pointer = path
            .trim_start_matches('/')
            .split('/')
            .fold(String::from("/properties"), |pointer, segment| {
                format!("{pointer}/{segment}/properties")
            });
        let definition = schema
            .pointer(pointer.trim_end_matches("/properties"))
            .unwrap_or_else(|| panic!("{path} is in the schema"));
        assert!(
            definition["description"]
                .as_str()
                .is_some_and(|text| text.starts_with(field.environment)),
            "{path}"
        );
        if field.sensitivity != Sensitivity::Public {
            assert_eq!(definition["$ref"], "#/$defs/secretReference", "{path}");
            continue;
        }
        match field.field_type {
            FieldType::Integer(range) => {
                assert_eq!(definition["minimum"], range.minimum, "{path}");
                assert_eq!(
                    definition["maximum"],
                    document_maximum(range.maximum),
                    "{path}"
                );
            }
            FieldType::Choice(words) => assert_eq!(definition["enum"], json!(words), "{path}"),
            FieldType::Decimal(_) => assert_eq!(definition["$ref"], "#/$defs/decimal", "{path}"),
            FieldType::Boolean => assert_eq!(definition["type"], "boolean", "{path}"),
            _ => {}
        }
    }
    // Every object is closed.
    fn closed(schema: &JsonValue, at: &str) {
        if let Some(properties) = schema.get("properties").and_then(JsonValue::as_object) {
            assert_eq!(schema["additionalProperties"], false, "{at}");
            for (name, member) in properties {
                closed(member, &format!("{at}/{name}"));
            }
        }
    }
    closed(&schema, "");
}

// --- properties --------------------------------------------------------------------

fn property_config() -> Config {
    Config {
        cases: 256,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(242_116),
        max_shrink_iters: 1_024,
        ..Config::default()
    }
}

fn settable_of(predicate: fn(&Field) -> bool) -> Vec<&'static Field> {
    settable()
        .filter(|field| field.sensitivity == Sensitivity::Public && predicate(field))
        .collect()
}

/// Integers near each end of `range`, and anywhere in the safe range.
fn integer_near(minimum: u64, maximum: u64) -> impl Strategy<Value = i64> {
    let signed = |value: u64| i64::try_from(value).unwrap_or(MAX_SAFE_INTEGER);
    let low = signed(minimum);
    let high = signed(maximum);
    prop_oneof![
        (-3_i64..=3).prop_map(move |offset| low.saturating_add(offset)),
        (-3_i64..=3).prop_map(move |offset| high.saturating_add(offset)),
        -MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER,
    ]
    .prop_map(|value| value.clamp(-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER))
}

fn decimal_text() -> impl Strategy<Value = String> {
    (
        prop_oneof!["0", "1", "[1-9][0-9]{0,15}"],
        proptest::option::of("[0-9]{1,6}"),
    )
        .prop_map(|(integer, fraction)| match fraction {
            Some(fraction) => format!("{integer}.{fraction}"),
            None => integer,
        })
}

proptest! {
    #![proptest_config(property_config())]

    #[test]
    fn integer_settings_are_accepted_exactly_within_their_bounds(
        (field, value) in proptest::sample::select(settable_of(|field| matches!(field.field_type, FieldType::Integer(_))))
            .prop_flat_map(|field| {
                let FieldType::Integer(range) = field.field_type else {
                    unreachable!("integer fields only");
                };
                (Just(field), integer_near(range.minimum, document_maximum(range.maximum)))
            })
    ) {
        let FieldType::Integer(range) = field.field_type else {
            unreachable!("integer fields only");
        };
        let within = u64::try_from(value)
            .is_ok_and(|value| (range.minimum..=range.maximum).contains(&value));
        let document = with(field.document_path().expect("settable"), json!(value));
        prop_assert_eq!(refusals(&document).is_empty(), within, "{} = {}", field.environment, value);
        prop_assert_eq!(validator().is_valid(&document), within);
    }

    #[test]
    fn decimal_settings_are_bounded_and_canonicalized_as_the_environment_float(
        field in proptest::sample::select(settable_of(|field| matches!(field.field_type, FieldType::Decimal(_)))),
        text in decimal_text(),
    ) {
        let FieldType::Decimal(range) = field.field_type else {
            unreachable!("decimal fields only");
        };
        let float: f64 = text.parse().expect("the grammar is a float's");
        let minimum: f64 = range.minimum.value.parse().expect("a bound");
        let above = float > minimum || (range.minimum.inclusive && float == minimum);
        let below = range.maximum.is_none_or(|maximum| {
            let bound: f64 = maximum.value.parse().expect("a bound");
            float < bound || (maximum.inclusive && float == bound)
        });
        let node = Node::new(Value::String(text.clone()), Default::default());
        match check(field, &node) {
            Ok(SettingValue::Decimal(decimal)) => {
                prop_assert!(above && below, "{} accepted {}", field.environment, text);
                prop_assert_eq!(decimal.as_f64(), float);
                let canonical: f64 = decimal.canonical().parse().expect("canonical decimals parse");
                prop_assert_eq!(canonical, float);
                prop_assert!(decimal.canonical().len() <= text.len());
            }
            Ok(other) => prop_assert!(false, "{} typed {:?}", field.environment, other),
            Err(refused) => {
                prop_assert_eq!(refused.code, Code::InvalidValue);
                prop_assert!(!(above && below), "{} refused {}", field.environment, text);
            }
        }
    }

    #[test]
    fn text_and_list_settings_refuse_exactly_padded_or_comma_entries(
        text in "[ ,a\u{a0}\u{3000}]{0,6}",
    ) {
        let trimmed = !text.is_empty() && text.trim() == text;
        let node = Node::new(Value::String(text.clone()), Default::default());
        prop_assert_eq!(check(field("CSRF_COOKIE_NAME"), &node).is_ok(), trimmed);
        let list = with("/spec/cors/allowed_origins", json!([text.clone()]));
        prop_assert_eq!(refusals(&list).is_empty(), trimmed && !text.contains(','));
        prop_assert_eq!(validator().is_valid(&list), trimmed && !text.contains(','));
        let single = with("/spec/csrf/cookie_name", json!(text));
        prop_assert_eq!(validator().is_valid(&single), trimmed);
    }
}

#[test]
fn the_children_of_spec_start_with_the_listeners() {
    let names: Vec<&str> = children("/spec")
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(names.first(), Some(&"listeners"));
    assert!(names.contains(&"public_url"));
    assert!(names.contains(&"state"));
}

/// The example in the reference is a document the reader accepts.
#[test]
fn the_documented_example_is_a_valid_deployment_document() {
    let text = repository_text(REFERENCE_DOCUMENT);
    let section = &text[text
        .find("## The deployment document\n")
        .expect("the deployment document section")..];
    let start = section.find("```yaml\n").expect("an example") + "```yaml\n".len();
    let end = start + section[start..].find("```\n").expect("the example ends");
    let node = yaml::parse(&section[start..end], DOCUMENT_LIMITS).expect("the example parses");
    let mut diagnostics = Vec::new();
    let deployment = document::deployment(&node, &file(), &mut diagnostics);
    assert!(deployment.is_some(), "{diagnostics:?}");
    assert!(validator().is_valid(&node.to_json()));
}
