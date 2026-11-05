//! The published deployment schema and the settings reference in
//! `docs/configuration-bundles.md`, rendered from the same document paths the
//! reader walks.
//!
//! Both are committed; `bundle::settings::tests` hold the committed files to
//! what these functions render, so the schema and the reference change only
//! with the catalog. The schema is written by a small ordered writer rather
//! than `serde_json`, so its member order, and so its bytes, are the same
//! whatever `serde_json` features a build unifies.

use crate::{
    catalog::{DecimalBound, DecimalRange, DefaultValue, Field, FieldType, Sensitivity, Unit},
    documents::{API_VERSION_V1ALPHA1, DEPLOYMENT_KIND},
};

use super::{
    super::{
        document::Profile,
        value::{Decimal, UnresolvedReason},
    },
    children, document_maximum, Child, StandaloneStore, SECTIONS, STANDALONE_STORES, STORES_PATH,
};

/// The secret reference grammar: an ADR-0006 opaque alias ID.
const SECRET_ALIAS_PATTERN: &str = "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$";
/// ADR-0008's decimal grammar.
pub(crate) const DECIMAL_PATTERN: &str = r"^(0|[1-9][0-9]{0,15})(\.[0-9]{1,6})?$";
/// A non-empty string with no whitespace at either end.
const TEXT_PATTERN: &str = r"^\S([\s\S]*\S)?$";
/// A list entry: a text without a comma.
const LIST_ENTRY_PATTERN: &str = r"^[^,\s]([^,]*[^,\s])?$";

/// A JSON value whose object members keep the order they are written in.
enum Json {
    Object(Vec<(&'static str, Json)>),
    Array(Vec<Json>),
    String(String),
    Integer(u64),
    Bool(bool),
}

fn text(value: &str) -> Json {
    Json::String(value.to_owned())
}

fn words(values: impl IntoIterator<Item = &'static str>) -> Json {
    Json::Array(values.into_iter().map(text).collect())
}

fn reference(definition: &str) -> (&'static str, Json) {
    ("$ref", Json::String(format!("#/$defs/{definition}")))
}

impl Json {
    fn is_scalar(&self) -> bool {
        !matches!(self, Self::Object(_) | Self::Array(_))
    }

    fn write(&self, out: &mut String, indent: usize) {
        match self {
            Self::Object(members) if members.is_empty() => out.push_str("{}"),
            Self::Object(members) => {
                out.push_str("{\n");
                for (index, (key, value)) in members.iter().enumerate() {
                    if index > 0 {
                        out.push_str(",\n");
                    }
                    pad(out, indent + 2);
                    write_string(out, key);
                    out.push_str(": ");
                    value.write(out, indent + 2);
                }
                out.push('\n');
                pad(out, indent);
                out.push('}');
            }
            Self::Array(items) if items.iter().all(Self::is_scalar) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    item.write(out, indent);
                }
                out.push(']');
            }
            Self::Array(items) => {
                out.push_str("[\n");
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push_str(",\n");
                    }
                    pad(out, indent + 2);
                    item.write(out, indent + 2);
                }
                out.push('\n');
                pad(out, indent);
                out.push(']');
            }
            Self::String(value) => write_string(out, value),
            Self::Integer(value) => out.push_str(&value.to_string()),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        }
    }
}

fn pad(out: &mut String, indent: usize) {
    out.extend(std::iter::repeat_n(' ', indent));
}

/// A JSON string literal. The rendered text is the module's own, so only
/// the characters JSON requires are escaped.
fn write_string(out: &mut String, value: &str) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            character if u32::from(character) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", u32::from(character)));
            }
            character => out.push(character),
        }
    }
    out.push('"');
}

/// The published `GatewayDeployment` schema, committed as
/// [`super::DEPLOYMENT_SCHEMA_DOCUMENT`]: Draft 2020-12, with `\n` line
/// endings.
pub fn render_deployment_schema() -> String {
    let mut spec_properties = vec![(
        "profile",
        Json::Object(vec![
            (
                "description",
                text("The deployment profile. Its invariants are enforced by the configuration compiler, not by this schema."),
            ),
            ("enum", words(Profile::ALL.iter().map(|profile| profile.as_str()))),
        ]),
    )];
    spec_properties.extend(section_properties("/spec"));
    let schema = Json::Object(vec![
        ("$schema", text("https://json-schema.org/draft/2020-12/schema")),
        (
            "$id",
            text("https://greengateway.dev/schemas/gateway-deployment.v1alpha1.schema.json"),
        ),
        ("title", text("GreenGateway Deployment Configuration")),
        (
            "description",
            text(concat!(
                "The deployment document of a greengateway.dev/v1alpha1 configuration bundle, generated from the configuration field catalog. ",
                "Each setting under spec is one catalog field at its document path, typed and bounded as the catalog says, and every object is closed. ",
                "Integers lie within the I-JSON safe range, a fractional setting is a decimal string, a setting whose value may carry a secret accepts only a secretReference, and no setting accepts an unresolved placeholder. ",
                "A decimal setting's bounds are stated in its description and enforced by the reader. ",
                "No gateway starts from a deployment document yet. ",
                "This schema is necessary but not sufficient: the gateway's reader is authoritative, and rules that relate settings are the configuration compiler's."
            )),
        ),
        ("type", text("object")),
        ("additionalProperties", Json::Bool(false)),
        ("required", words(["apiVersion", "kind", "spec"])),
        (
            "properties",
            Json::Object(vec![
                (
                    "apiVersion",
                    Json::Object(vec![
                        (
                            "description",
                            text("Exact document version. No other version, prefix, or spelling is accepted."),
                        ),
                        ("const", text(API_VERSION_V1ALPHA1)),
                    ]),
                ),
                ("kind", Json::Object(vec![("const", text(DEPLOYMENT_KIND))])),
                (
                    "spec",
                    Json::Object(vec![
                        ("description", text("The deployment profile and the deployment settings.")),
                        ("type", text("object")),
                        ("additionalProperties", Json::Bool(false)),
                        ("required", words(["profile"])),
                        ("properties", Json::Object(spec_properties)),
                    ]),
                ),
            ]),
        ),
        ("$defs", definitions()),
    ]);
    let mut out = String::new();
    schema.write(&mut out, 0);
    out.push('\n');
    out
}

fn definitions() -> Json {
    Json::Object(vec![
        (
            "secretReference",
            Json::Object(vec![
                (
                    "description",
                    text("An opaque secret alias ID resolved by the gateway's secret providers. It is never a secret value, an environment-variable name, a file path, a provider locator, or ciphertext."),
                ),
                ("type", text("object")),
                ("additionalProperties", Json::Bool(false)),
                ("required", words(["secret"])),
                (
                    "properties",
                    Json::Object(vec![(
                        "secret",
                        Json::Object(vec![
                            ("type", text("string")),
                            ("pattern", text(SECRET_ALIAS_PATTERN)),
                        ]),
                    )]),
                ),
            ]),
        ),
        (
            "unresolved",
            Json::Object(vec![
                (
                    "description",
                    text("A placeholder an export, conversion, or template writes where it could not or would not supply a value. No setting accepts one, so a document that contains one never validates."),
                ),
                ("type", text("object")),
                ("additionalProperties", Json::Bool(false)),
                ("required", words(["unresolved"])),
                (
                    "properties",
                    Json::Object(vec![(
                        "unresolved",
                        Json::Object(vec![(
                            "enum",
                            words(UnresolvedReason::ALL.iter().map(|reason| reason.as_str())),
                        )]),
                    )]),
                ),
            ]),
        ),
        (
            "decimal",
            Json::Object(vec![
                (
                    "description",
                    text("A fractional setting written as a string; JSON numbers in bundle documents are integers only. The canonical form is the shortest exact spelling."),
                ),
                ("type", text("string")),
                ("pattern", text(DECIMAL_PATTERN)),
            ]),
        ),
        (
            "text",
            Json::Object(vec![
                (
                    "description",
                    text("A non-empty string with no whitespace at either end. Its own grammar is the configuration compiler's."),
                ),
                ("type", text("string")),
                ("pattern", text(TEXT_PATTERN)),
            ]),
        ),
        (
            "list",
            Json::Object(vec![
                (
                    "description",
                    text("The entries of an environment variable's comma-separated list: non-empty strings with no comma and no whitespace at either end."),
                ),
                ("type", text("array")),
                (
                    "items",
                    Json::Object(vec![
                        ("type", text("string")),
                        ("pattern", text(LIST_ENTRY_PATTERN)),
                    ]),
                ),
            ]),
        ),
    ])
}

/// The schema properties of the object at `path`.
fn section_properties(path: &str) -> Vec<(&'static str, Json)> {
    children(path)
        .into_iter()
        .map(|(name, child)| {
            let schema = match child {
                Child::Setting(field) => setting_schema(field),
                Child::Section(section) => Json::Object(vec![
                    ("description", text(section_description(section))),
                    ("type", text("object")),
                    ("additionalProperties", Json::Bool(false)),
                    ("properties", Json::Object(section_properties(section))),
                ]),
                Child::Stores => Json::Object(vec![
                    (
                        "description",
                        text(concat!(
                            "The standalone stores kept beneath the state directory, each named once; ",
                            "in environment mode, which of their *_SQLITE_PATH variables are set."
                        )),
                    ),
                    ("type", text("array")),
                    ("uniqueItems", Json::Bool(true)),
                    (
                        "items",
                        Json::Object(vec![(
                            "enum",
                            words(STANDALONE_STORES.iter().map(|store| store.name)),
                        )]),
                    ),
                ]),
            };
            (name, schema)
        })
        .collect()
}

fn section_description(path: &str) -> &'static str {
    SECTIONS
        .iter()
        .find(|section| section.path == path)
        .map_or("", |section| section.description)
}

fn setting_schema(field: &Field) -> Json {
    let mut description = format!(
        "{} in environment mode: {}.",
        field.environment,
        field.documentation()
    );
    let mut members = Vec::new();
    if field.sensitivity != Sensitivity::Public {
        description.push_str(" Its value may carry a secret, so it is a secret reference.");
        members.push(reference("secretReference"));
    } else {
        match field.field_type {
            FieldType::Boolean => members.push(("type", text("boolean"))),
            FieldType::Integer(range) => {
                if range.unit != Unit::Count {
                    description.push_str(&format!(" In {}.", range.unit.code()));
                }
                members.push(("type", text("integer")));
                members.push(("minimum", Json::Integer(range.minimum)));
                members.push(("maximum", Json::Integer(document_maximum(range.maximum))));
            }
            FieldType::Decimal(range) => {
                description.push_str(&format!(" A decimal {}.", decimal_bounds(range)));
                members.push(reference("decimal"));
            }
            FieldType::Choice(values) => members.push(("enum", words(values.iter().copied()))),
            FieldType::SocketAddress | FieldType::Url | FieldType::Text => {
                members.push(reference("text"));
            }
            FieldType::List => members.push(reference("list")),
            // No such field has a document path (see `check`).
            FieldType::Path | FieldType::PathList | FieldType::Json => {}
        }
    }
    members.insert(0, ("description", Json::String(description)));
    Json::Object(members)
}

/// "at least 0 and below 1", "above 1".
fn decimal_bounds(range: DecimalRange) -> String {
    let bound = |bound: DecimalBound, inclusive: &str, exclusive: &str| {
        let word = if bound.inclusive {
            inclusive
        } else {
            exclusive
        };
        format!("{word} {}", bound.value)
    };
    let minimum = bound(range.minimum, "at least", "above");
    match range.maximum {
        Some(maximum) => format!("{minimum} and {}", bound(maximum, "at most", "below")),
        None => minimum,
    }
}

/// The settings reference between the markers in
/// `docs/configuration-bundles.md`: one table per member of `spec`, in
/// schema order, with `\n` line endings.
pub fn render_deployment_reference() -> String {
    let mut out = String::new();
    for (name, child) in children("/spec") {
        let (description, rows) = match child {
            Child::Section(section) => (section_description(section), leaves(section)),
            Child::Setting(field) => ("", vec![(field.document_path().unwrap_or_default(), child)]),
            Child::Stores => ("", vec![(STORES_PATH, child)]),
        };
        out.push_str(&format!("\n#### `spec.{name}`\n\n"));
        if !description.is_empty() {
            out.push_str(description);
            out.push_str("\n\n");
        }
        out.push_str("| Member | Value | Default | Environment mode |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for (path, leaf) in rows {
            let member = dotted(path);
            let (value, default, environment) = match leaf {
                Child::Setting(field) => (
                    value_text(field),
                    default_text(field),
                    format!("[`{}`](configuration.md#{})", field.environment, field.id),
                ),
                Child::Stores => (
                    format!(
                        "array of distinct {}",
                        join_words(STANDALONE_STORES.iter().map(|store| store.name), "and")
                    ),
                    "unset".to_owned(),
                    format!(
                        "which of {} are set",
                        join_words(
                            STANDALONE_STORES
                                .iter()
                                .filter_map(StandaloneStore::environment),
                            "and"
                        )
                    ),
                ),
                Child::Section(_) => continue,
            };
            out.push_str(&format!(
                "| `{member}` | {value} | {default} | {environment} |\n"
            ));
        }
    }
    out
}

/// Every setting beneath the section at `path`, depth first, in schema order.
fn leaves(path: &'static str) -> Vec<(&'static str, Child)> {
    let mut found = Vec::new();
    for (_, child) in children(path) {
        match child {
            Child::Section(section) => found.extend(leaves(section)),
            Child::Setting(field) => {
                found.push((field.document_path().unwrap_or_default(), child));
            }
            Child::Stores => found.push((STORES_PATH, child)),
        }
    }
    found
}

/// `/spec/listeners/public/address` as `listeners.public.address`.
fn dotted(path: &str) -> String {
    path.strip_prefix("/spec/")
        .unwrap_or(path)
        .replace('/', ".")
}

/// `` `a`, `b` and `c` ``.
fn join_words(values: impl Iterator<Item = &'static str>, last: &str) -> String {
    let values: Vec<String> = values.map(|value| format!("`{value}`")).collect();
    match values.as_slice() {
        [] => String::new(),
        [only] => only.clone(),
        [rest @ .., final_value] => format!("{} {last} {final_value}", rest.join(", ")),
    }
}

fn value_text(field: &Field) -> String {
    if field.sensitivity != Sensitivity::Public {
        return "secret reference".to_owned();
    }
    match field.field_type {
        FieldType::Boolean => "`true` or `false`".to_owned(),
        FieldType::Integer(range) => {
            let unit = match range.unit {
                Unit::Count => String::new(),
                unit => format!(" {}", unit.code()),
            };
            let maximum = document_maximum(range.maximum);
            if maximum < range.maximum {
                format!("integer{unit}, at least {}", range.minimum)
            } else {
                format!("integer{unit}, {} to {maximum}", range.minimum)
            }
        }
        FieldType::Decimal(range) => format!("decimal string, {}", decimal_bounds(range)),
        FieldType::Choice(values) => join_words(values.iter().copied(), "or"),
        FieldType::SocketAddress => "socket address string".to_owned(),
        FieldType::Url => "URL string".to_owned(),
        FieldType::Text => "string".to_owned(),
        FieldType::List => "array of strings".to_owned(),
        FieldType::Path | FieldType::PathList | FieldType::Json => String::new(),
    }
}

/// The default as the document would spell it.
fn default_text(field: &Field) -> String {
    match field.default {
        DefaultValue::Unset => "unset".to_owned(),
        DefaultValue::Derived(from) => {
            let names: Vec<String> = from
                .iter()
                .map(|environment| {
                    crate::catalog::field(environment)
                        .and_then(Field::document_path)
                        .map_or_else(
                            || format!("`{environment}`"),
                            |path| format!("`{}`", dotted(path)),
                        )
                })
                .collect();
            format!("follows {}", names.join(", "))
        }
        DefaultValue::Literal(value) => {
            let mut out = String::from("`");
            match field.field_type {
                FieldType::Boolean | FieldType::Integer(_) => out.push_str(value),
                FieldType::Decimal(_) => {
                    let canonical = Decimal::parse(value).map_or_else(
                        || value.to_owned(),
                        |decimal| decimal.canonical().to_owned(),
                    );
                    write_string(&mut out, &canonical);
                }
                FieldType::List => {
                    Json::Array(value.split(',').map(str::trim).map(text).collect())
                        .write(&mut out, 0);
                }
                FieldType::Choice(_)
                | FieldType::SocketAddress
                | FieldType::Url
                | FieldType::Text
                | FieldType::Path
                | FieldType::PathList
                | FieldType::Json => write_string(&mut out, value),
            }
            out.push('`');
            out
        }
    }
}
