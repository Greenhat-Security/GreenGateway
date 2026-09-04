use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

const MAX_SELECTOR_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonPointer(String);

impl JsonPointer {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for JsonPointer {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        validate_json_pointer(value)?;
        Ok(Self(value.to_owned()))
    }
}

impl TryFrom<String> for JsonPointer {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_json_pointer(&value)?;
        Ok(Self(value))
    }
}

impl Serialize for JsonPointer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for JsonPointer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    source: String,
    pub(crate) segments: Vec<SelectorSegment>,
}

impl Selector {
    pub fn as_str(&self) -> &str {
        &self.source
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.source)
    }
}

impl FromStr for Selector {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let segments = parse_selector(value)?;
        Ok(Self {
            source: value.to_owned(),
            segments,
        })
    }
}

impl TryFrom<String> for Selector {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let segments = parse_selector(&value)?;
        Ok(Self {
            source: value,
            segments,
        })
    }
}

impl Serialize for Selector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.source)
    }
}

impl<'de> Deserialize<'de> for Selector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelectorSegment {
    Key(String),
    Wildcard,
    Filter {
        key: String,
        field: String,
        value: Value,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum SchemaResolution {
    Verified(Vec<Value>),
    Unverifiable,
    Missing,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SelectionStats {
    pub selected: usize,
    pub objects: usize,
}

pub fn resolve_pointer_schemas(_roots: &[Value], _pointer: &JsonPointer) -> SchemaResolution {
    let segments = pointer_tokens(_pointer.as_str());
    resolve_schema_segments(_roots.to_vec(), &segments, false)
}

pub fn select_object_schemas(roots: &[Value], selector: &Selector) -> SchemaResolution {
    let mut candidates = roots.to_vec();
    let mut unverifiable = false;
    for segment in &selector.segments {
        let mut next = Vec::new();
        for candidate in candidates {
            match schema_selector_step(&candidate, segment) {
                SchemaStep::Known(values) => next.extend(values),
                SchemaStep::Unverifiable => unverifiable = true,
                SchemaStep::Missing => {}
            }
        }
        candidates = deduplicate_schemas(next);
        if candidates.is_empty() {
            return if unverifiable {
                SchemaResolution::Unverifiable
            } else {
                SchemaResolution::Missing
            };
        }
    }

    let mut objects = Vec::new();
    for candidate in candidates {
        match schema_kind(&candidate) {
            SchemaKind::Object => objects.push(candidate),
            SchemaKind::Unknown => unverifiable = true,
            SchemaKind::Array | SchemaKind::Scalar | SchemaKind::Never => {}
        }
    }
    if unverifiable {
        SchemaResolution::Unverifiable
    } else if objects.is_empty() {
        SchemaResolution::Missing
    } else {
        SchemaResolution::Verified(deduplicate_schemas(objects))
    }
}

pub fn visit_selected_objects_mut(
    root: &mut Value,
    selector: &Selector,
    mut visitor: impl FnMut(&str, &mut Map<String, Value>),
) -> SelectionStats {
    let mut stats = SelectionStats::default();
    visit_selected_value_mut(
        root,
        &selector.segments,
        0,
        String::new(),
        &mut visitor,
        &mut stats,
    );
    stats
}

fn visit_selected_value_mut(
    value: &mut Value,
    segments: &[SelectorSegment],
    index: usize,
    path: String,
    visitor: &mut impl FnMut(&str, &mut Map<String, Value>),
    stats: &mut SelectionStats,
) {
    if index == segments.len() {
        stats.selected = stats.selected.saturating_add(1);
        if let Value::Object(object) = value {
            stats.objects = stats.objects.saturating_add(1);
            visitor(if path.is_empty() { "/" } else { &path }, object);
        }
        return;
    }

    match &segments[index] {
        SelectorSegment::Key(key) => {
            let Value::Object(object) = value else {
                return;
            };
            if let Some(child) = object.get_mut(key) {
                visit_selected_value_mut(
                    child,
                    segments,
                    index + 1,
                    append_pointer_path(&path, key),
                    visitor,
                    stats,
                );
            }
        }
        SelectorSegment::Wildcard => match value {
            Value::Array(values) => {
                for (child_index, child) in values.iter_mut().enumerate() {
                    visit_selected_value_mut(
                        child,
                        segments,
                        index + 1,
                        append_pointer_path(&path, &child_index.to_string()),
                        visitor,
                        stats,
                    );
                }
            }
            Value::Object(object) => {
                for (key, child) in object.iter_mut() {
                    visit_selected_value_mut(
                        child,
                        segments,
                        index + 1,
                        append_pointer_path(&path, key),
                        visitor,
                        stats,
                    );
                }
            }
            _ => {}
        },
        SelectorSegment::Filter {
            key,
            field,
            value: expected,
        } => {
            let Value::Object(object) = value else {
                return;
            };
            let Some(Value::Array(values)) = object.get_mut(key) else {
                return;
            };
            let array_path = append_pointer_path(&path, key);
            for (child_index, child) in values.iter_mut().enumerate() {
                let matches = child
                    .as_object()
                    .and_then(|object| object.get(field))
                    .is_some_and(|actual| actual == expected);
                if matches {
                    visit_selected_value_mut(
                        child,
                        segments,
                        index + 1,
                        append_pointer_path(&array_path, &child_index.to_string()),
                        visitor,
                        stats,
                    );
                }
            }
        }
    }
}

fn append_pointer_path(base: &str, token: &str) -> String {
    let escaped = token.replace('~', "~0").replace('/', "~1");
    format!("{base}/{escaped}")
}

fn pointer_tokens(pointer: &str) -> Vec<String> {
    if pointer.is_empty() {
        return Vec::new();
    }
    pointer[1..]
        .split('/')
        .map(|token| token.replace("~1", "/").replace("~0", "~"))
        .collect()
}

fn resolve_schema_segments(
    mut candidates: Vec<Value>,
    segments: &[String],
    mut unverifiable: bool,
) -> SchemaResolution {
    for segment in segments {
        let mut next = Vec::new();
        for candidate in candidates {
            match schema_pointer_step(&candidate, segment) {
                SchemaStep::Known(values) => next.extend(values),
                SchemaStep::Unverifiable => unverifiable = true,
                SchemaStep::Missing => {}
            }
        }
        candidates = deduplicate_schemas(next);
        if candidates.is_empty() {
            return if unverifiable {
                SchemaResolution::Unverifiable
            } else {
                SchemaResolution::Missing
            };
        }
    }
    if unverifiable {
        SchemaResolution::Unverifiable
    } else if candidates.is_empty() {
        SchemaResolution::Missing
    } else {
        SchemaResolution::Verified(deduplicate_schemas(candidates))
    }
}

enum SchemaStep {
    Known(Vec<Value>),
    Unverifiable,
    Missing,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SchemaKind {
    Object,
    Array,
    Scalar,
    Unknown,
    Never,
}

fn schema_kind(schema: &Value) -> SchemaKind {
    match schema {
        Value::Bool(true) => SchemaKind::Unknown,
        Value::Bool(false) => SchemaKind::Never,
        Value::Object(object) => {
            if object.contains_key("properties") {
                return SchemaKind::Object;
            }
            if object.contains_key("items") {
                return SchemaKind::Array;
            }
            match object.get("type") {
                Some(Value::String(kind)) if kind == "object" => SchemaKind::Object,
                Some(Value::String(kind)) if kind == "array" => SchemaKind::Array,
                Some(Value::String(_)) => SchemaKind::Scalar,
                Some(Value::Array(kinds)) => {
                    let object = kinds.iter().any(|kind| kind.as_str() == Some("object"));
                    let array = kinds.iter().any(|kind| kind.as_str() == Some("array"));
                    if object && !array {
                        SchemaKind::Object
                    } else if array && !object {
                        SchemaKind::Array
                    } else {
                        SchemaKind::Unknown
                    }
                }
                _ => SchemaKind::Unknown,
            }
        }
        _ => SchemaKind::Unknown,
    }
}

fn schema_pointer_step(schema: &Value, token: &str) -> SchemaStep {
    if let Some(alternatives) = schema_alternatives(schema) {
        return combine_steps(
            alternatives
                .iter()
                .map(|alternative| schema_pointer_step(alternative, token)),
        );
    }

    let Value::Object(object) = schema else {
        return match schema_kind(schema) {
            SchemaKind::Unknown => SchemaStep::Unverifiable,
            _ => SchemaStep::Missing,
        };
    };
    match schema_kind(schema) {
        SchemaKind::Object => object_property_step(object, token),
        SchemaKind::Array if is_json_pointer_array_index(token) => object
            .get("items")
            .map_or(SchemaStep::Unverifiable, |items| {
                SchemaStep::Known(vec![items.clone()])
            }),
        SchemaKind::Unknown => SchemaStep::Unverifiable,
        SchemaKind::Array | SchemaKind::Scalar | SchemaKind::Never => SchemaStep::Missing,
    }
}

fn schema_selector_step(schema: &Value, segment: &SelectorSegment) -> SchemaStep {
    if let Some(alternatives) = schema_alternatives(schema) {
        return combine_steps(
            alternatives
                .iter()
                .map(|alternative| schema_selector_step(alternative, segment)),
        );
    }
    let Value::Object(object) = schema else {
        return match schema_kind(schema) {
            SchemaKind::Unknown => SchemaStep::Unverifiable,
            _ => SchemaStep::Missing,
        };
    };

    match segment {
        SelectorSegment::Key(key) => match schema_kind(schema) {
            SchemaKind::Object => object_property_step(object, key),
            SchemaKind::Unknown => SchemaStep::Unverifiable,
            _ => SchemaStep::Missing,
        },
        SelectorSegment::Wildcard => match schema_kind(schema) {
            SchemaKind::Array => object
                .get("items")
                .map_or(SchemaStep::Unverifiable, |items| {
                    SchemaStep::Known(vec![items.clone()])
                }),
            SchemaKind::Object => object_wildcard_step(object),
            SchemaKind::Unknown => SchemaStep::Unverifiable,
            _ => SchemaStep::Missing,
        },
        SelectorSegment::Filter { key, field, .. } => {
            let array_step = match schema_kind(schema) {
                SchemaKind::Object => object_property_step(object, key),
                SchemaKind::Unknown => SchemaStep::Unverifiable,
                _ => SchemaStep::Missing,
            };
            match array_step {
                SchemaStep::Known(arrays) => combine_steps(arrays.iter().map(|array| {
                    let Value::Object(array_object) = array else {
                        return SchemaStep::Missing;
                    };
                    if schema_kind(array) != SchemaKind::Array {
                        return if schema_kind(array) == SchemaKind::Unknown {
                            SchemaStep::Unverifiable
                        } else {
                            SchemaStep::Missing
                        };
                    }
                    let Some(items) = array_object.get("items") else {
                        return SchemaStep::Unverifiable;
                    };
                    match schema_pointer_step(items, field) {
                        SchemaStep::Missing => SchemaStep::Missing,
                        SchemaStep::Unverifiable => SchemaStep::Unverifiable,
                        SchemaStep::Known(_) => SchemaStep::Known(vec![items.clone()]),
                    }
                })),
                other => other,
            }
        }
    }
}

fn object_property_step(object: &Map<String, Value>, key: &str) -> SchemaStep {
    if let Some(property) = object
        .get("properties")
        .and_then(Value::as_object)
        .and_then(|properties| properties.get(key))
    {
        return SchemaStep::Known(vec![property.clone()]);
    }
    match object.get("additionalProperties") {
        Some(Value::Bool(false)) => SchemaStep::Missing,
        Some(Value::Bool(true)) => SchemaStep::Unverifiable,
        Some(schema @ Value::Object(_)) => SchemaStep::Known(vec![schema.clone()]),
        Some(_) => SchemaStep::Unverifiable,
        None if object.contains_key("properties") => SchemaStep::Missing,
        None => SchemaStep::Unverifiable,
    }
}

fn object_wildcard_step(object: &Map<String, Value>) -> SchemaStep {
    let has_declared_properties = object.contains_key("properties");
    let mut values = object
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.values().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    match object.get("additionalProperties") {
        Some(Value::Bool(true)) => return SchemaStep::Unverifiable,
        Some(schema @ Value::Object(_)) => values.push(schema.clone()),
        Some(Value::Bool(false)) | None => {}
        Some(_) => return SchemaStep::Unverifiable,
    }
    if values.is_empty() && !has_declared_properties {
        SchemaStep::Unverifiable
    } else if values.is_empty() {
        SchemaStep::Missing
    } else {
        SchemaStep::Known(values)
    }
}

fn is_json_pointer_array_index(token: &str) -> bool {
    !token.is_empty()
        && (token == "0" || !token.starts_with('0'))
        && token.bytes().all(|byte| byte.is_ascii_digit())
        && token.parse::<usize>().is_ok()
}

fn schema_alternatives(schema: &Value) -> Option<&Vec<Value>> {
    let object = schema.as_object()?;
    object
        .get("oneOf")
        .or_else(|| object.get("anyOf"))
        .and_then(Value::as_array)
}

fn combine_steps(steps: impl IntoIterator<Item = SchemaStep>) -> SchemaStep {
    let mut values = Vec::new();
    let mut unverifiable = false;
    for step in steps {
        match step {
            SchemaStep::Known(step_values) => values.extend(step_values),
            SchemaStep::Unverifiable => unverifiable = true,
            SchemaStep::Missing => {}
        }
    }
    if unverifiable {
        SchemaStep::Unverifiable
    } else if values.is_empty() {
        SchemaStep::Missing
    } else {
        SchemaStep::Known(deduplicate_schemas(values))
    }
}

fn deduplicate_schemas(values: Vec<Value>) -> Vec<Value> {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    unique
}

fn validate_json_pointer(value: &str) -> Result<(), String> {
    if value.len() > 512 {
        return Err("JSON pointer exceeds 512 bytes".to_owned());
    }
    if !value.is_empty() && !value.starts_with('/') {
        return Err("JSON pointer must be empty or start with '/'".to_owned());
    }
    for segment in value.split('/').skip(1) {
        let bytes = segment.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            if bytes[index] == b'~' {
                if index + 1 >= bytes.len() || !matches!(bytes[index + 1], b'0' | b'1') {
                    return Err("JSON pointer contains an invalid '~' escape".to_owned());
                }
                index += 2;
            } else {
                index += 1;
            }
        }
    }
    Ok(())
}

fn parse_selector(value: &str) -> Result<Vec<SelectorSegment>, String> {
    if value.is_empty() || !value.starts_with('/') {
        return Err("selector must start with '/'".to_owned());
    }
    if value.len() > 1_024 {
        return Err("selector exceeds 1024 bytes".to_owned());
    }
    let raw_segments = value[1..].split('/').collect::<Vec<_>>();
    if raw_segments.len() > MAX_SELECTOR_DEPTH {
        return Err(format!(
            "selector exceeds maximum depth {MAX_SELECTOR_DEPTH}"
        ));
    }
    raw_segments
        .into_iter()
        .map(parse_selector_segment)
        .collect()
}

fn parse_selector_segment(segment: &str) -> Result<SelectorSegment, String> {
    if segment == "*" {
        return Ok(SelectorSegment::Wildcard);
    }
    if segment.is_empty() {
        return Err("selector segments must be non-empty".to_owned());
    }
    if let Some((key, suffix)) = segment.split_once('[') {
        let filter = suffix
            .strip_suffix(']')
            .ok_or_else(|| "selector filter must end with ']'".to_owned())?;
        let (field, literal) = filter
            .split_once('=')
            .ok_or_else(|| "selector filter must contain '='".to_owned())?;
        validate_selector_name(key)?;
        validate_selector_name(field)?;
        let value = if let Some(integer) = literal.strip_prefix("int:") {
            validate_selector_integer(integer)?;
            serde_json::from_str::<Value>(integer)
                .map_err(|_| "selector int literal is invalid".to_owned())?
        } else if let Some(boolean) = literal.strip_prefix("bool:") {
            match boolean {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                _ => return Err("selector bool literal must be true or false".to_owned()),
            }
        } else {
            if literal.is_empty()
                || literal.len() > 128
                || literal
                    .bytes()
                    .any(|byte| matches!(byte, b']' | b'\\' | b'/'))
            {
                return Err("selector string literals must contain 1-128 bytes".to_owned());
            }
            Value::String(literal.to_owned())
        };
        return Ok(SelectorSegment::Filter {
            key: key.to_owned(),
            field: field.to_owned(),
            value,
        });
    }
    validate_selector_name(segment)?;
    Ok(SelectorSegment::Key(segment.to_owned()))
}

fn validate_selector_integer(value: &str) -> Result<(), String> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty()
        || digits.len() > 18
        || (digits.len() > 1 && digits.starts_with('0'))
        || (value.starts_with('-') && digits == "0")
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(
            "selector int literals must be canonical integers of at most 18 digits".to_owned(),
        );
    }
    Ok(())
}

fn validate_selector_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err("selector keys must contain only letters, digits, '.', '_' or '-'".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn typed_filters_and_wildcards_select_in_deterministic_order() {
        let selector: Selector = "/data[name=company]/fields/enabled[active=bool:true]/options/*"
            .parse()
            .expect("selector should parse");
        let mut document = json!({
            "data": [
                {"name":"person","fields":{}},
                {"name":"company","fields": {
                    "enabled": [
                        {"active":false,"options":[{"value":"NO"}]},
                        {"active":true,"options":[{"value":"A"},{"value":"B"}]}
                    ]
                }}
            ]
        });
        let mut paths = Vec::new();
        let stats = visit_selected_objects_mut(&mut document, &selector, |path, object| {
            paths.push(path.to_owned());
            object.insert("selected".to_owned(), Value::Bool(true));
        });
        assert_eq!(
            stats,
            SelectionStats {
                selected: 2,
                objects: 2
            }
        );
        assert_eq!(
            paths,
            [
                "/data/1/fields/enabled/1/options/0",
                "/data/1/fields/enabled/1/options/1"
            ]
        );
    }

    #[test]
    fn filters_are_type_strict_and_wrong_kinds_select_nothing() {
        let mut document = json!({"items":[{"value":"5"},{"value":5},{"value":true}]});
        for (selector, expected) in [
            ("/items[value=5]", 1),
            ("/items[value=int:5]", 1),
            ("/items[value=bool:true]", 1),
            ("/items/*/missing", 0),
        ] {
            let selector: Selector = selector.parse().expect("selector should parse");
            let stats = visit_selected_objects_mut(&mut document, &selector, |_, _| {});
            assert_eq!(stats.selected, expected, "{selector}");
        }
    }

    #[test]
    fn parser_rejects_noncanonical_literals_and_excess_depth() {
        for selector in [
            "/items[value=int:01]",
            "/items[value=int:-0]",
            "/items[value=int:1.0]",
            "/items[value=]",
            "/items[value=bad]]",
            "/items[value=bad\\value]",
        ] {
            assert!(selector.parse::<Selector>().is_err(), "{selector}");
        }
        let deep = format!("/{}", vec!["x"; 33].join("/"));
        assert!(deep.parse::<Selector>().is_err());
    }

    #[test]
    fn rfc6901_pointer_parsing_and_schema_resolution_are_bounded() {
        assert!("/a~1b/~0key".parse::<JsonPointer>().is_ok());
        assert!("/bad~2escape".parse::<JsonPointer>().is_err());
        assert!("not/a/pointer".parse::<JsonPointer>().is_err());

        let roots = vec![json!({
            "type":"object",
            "properties": {
                "a/b": {
                    "type":"object",
                    "properties":{"~key":{"type":"string"}}
                }
            }
        })];
        let pointer = "/a~1b/~0key".parse().expect("pointer");
        assert!(matches!(
            resolve_pointer_schemas(&roots, &pointer),
            SchemaResolution::Verified(values) if values == vec![json!({"type":"string"})]
        ));
        let missing = "/a~1b/missing".parse().expect("pointer");
        assert_eq!(
            resolve_pointer_schemas(&roots, &missing),
            SchemaResolution::Missing
        );
        let free_form = vec![json!({"type":"object","additionalProperties":true})];
        assert_eq!(
            resolve_pointer_schemas(&free_form, &"/anything".parse().expect("pointer")),
            SchemaResolution::Unverifiable
        );

        let array = vec![json!({"type":"array","items":{"type":"string"}})];
        assert!(matches!(
            resolve_pointer_schemas(&array, &"/0".parse().expect("pointer")),
            SchemaResolution::Verified(values) if values == vec![json!({"type":"string"})]
        ));
        for noncanonical in ["/", "/01", "/999999999999999999999999999999999"] {
            assert_eq!(
                resolve_pointer_schemas(&array, &noncanonical.parse().expect("pointer")),
                SchemaResolution::Missing,
                "{noncanonical}"
            );
        }

        let closed_empty = json!({
            "type":"object",
            "properties":{"data":{"type":"object","properties":{}}}
        });
        assert_eq!(
            select_object_schemas(&[closed_empty], &"/data/*".parse().expect("selector")),
            SchemaResolution::Missing
        );
    }
}
