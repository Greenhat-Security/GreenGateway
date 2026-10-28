//! Explicit, position-aware candidate edits over the pinned base policy.
//!
//! An edit says exactly where it lands. `insert` names the position the new
//! element will occupy (the section's length appends, and must be said);
//! `replace` and `delete` name the position they change; `move` names the
//! position it takes an element from and the position the element ends at;
//! `set` names the scalar it changes. Edits apply in order, each to the
//! result of the ones before it, against the base the request pinned by ETag,
//! so a position always means what the author read.
//!
//! An element may additionally be named by its stable `id` (`expect_id`):
//! the element at the position must carry exactly that identifier, or the
//! edit is refused. Policy v1 gives every direct rule, route and rate-limit
//! override an id; a 0.x document gives one only to the rules that set it,
//! and never to a route or override, so an `expect_id` naming one of those
//! is refused as a mismatch rather than ignored.
//!
//! Edits produce a JSON document; the caller validates it exactly as a policy
//! write would before anything compiles it. Diagnostics name the edit by
//! JSON Pointer and never repeat a value from it.

use serde_json::{Map, Value};

use crate::policy_testing::suite::{
    bounded_string, check_members, index, object, required, Diagnostics,
};

/// Most edits one simulation may carry.
pub(crate) const MAX_EDITS: usize = 64;
/// Longest element identifier an `expect_id` may name, in bytes.
pub(crate) const MAX_EXPECT_ID_BYTES: usize = 256;

/// An ordered policy section an edit addresses by position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Section {
    Rules,
    Routes,
    RateLimits,
}

impl Section {
    fn key(self) -> &'static str {
        match self {
            Self::Rules => "rules",
            Self::Routes => "routes",
            Self::RateLimits => "rate_limits",
        }
    }
}

/// A top-level scalar an edit may set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scalar {
    DefaultAction,
    EnforcementMode,
}

impl Scalar {
    fn key(self) -> &'static str {
        match self {
            Self::DefaultAction => "default_action",
            Self::EnforcementMode => "enforcement_mode",
        }
    }
}

/// One accepted edit. Only [`parse_edits`] builds one, so every position is
/// bounded and every value has the right JSON type; whether an element is a
/// valid rule, route or override is the policy validator's question.
pub(crate) enum PolicyEdit {
    Insert {
        section: Section,
        position: usize,
        value: Value,
    },
    Replace {
        section: Section,
        position: usize,
        expect_id: Option<String>,
        value: Value,
    },
    Move {
        section: Section,
        from: usize,
        to: usize,
        expect_id: Option<String>,
    },
    Delete {
        section: Section,
        position: usize,
        expect_id: Option<String>,
    },
    Set {
        scalar: Scalar,
        value: &'static str,
    },
}

/// Parse the `edits` array at `pointer`: 1 to [`MAX_EDITS`] edits.
pub(crate) fn parse_edits(
    value: Option<&Value>,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Vec<PolicyEdit> {
    let items = match value {
        None => {
            diagnostics.push("missing_field", pointer, "edits is required");
            return Vec::new();
        }
        Some(Value::Array(items)) if items.is_empty() => {
            diagnostics.push(
                "empty_edits",
                pointer,
                "an edits candidate needs at least one edit; use the active source to simulate the base unchanged",
            );
            return Vec::new();
        }
        Some(Value::Array(items)) if items.len() > MAX_EDITS => {
            diagnostics.push(
                "too_many_edits",
                pointer,
                format!("at most {MAX_EDITS} edits may be declared"),
            );
            return Vec::new();
        }
        Some(Value::Array(items)) => items,
        Some(_) => {
            diagnostics.push("invalid_type", pointer, "edits must be an array");
            return Vec::new();
        }
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| parse_edit(item, &format!("{pointer}/{index}"), diagnostics))
        .collect()
}

fn parse_edit(value: &Value, pointer: &str, diagnostics: &mut Diagnostics) -> Option<PolicyEdit> {
    let map = object(value, pointer, diagnostics)?;
    let op_pointer = format!("{pointer}/op");
    let op = required(map, "op", pointer, diagnostics)?;
    let op = match op.as_str() {
        Some(op @ ("insert" | "replace" | "move" | "delete" | "set")) => op,
        _ => {
            diagnostics.push(
                "invalid_value",
                &op_pointer,
                "op must be one of \"insert\", \"replace\", \"move\", \"delete\" or \"set\"",
            );
            return None;
        }
    };
    let members: &[&str] = match op {
        "insert" => &["op", "section", "position", "value"],
        "replace" => &["op", "section", "position", "expect_id", "value"],
        "move" => &["op", "section", "from", "to", "expect_id"],
        "delete" => &["op", "section", "position", "expect_id"],
        _ => &["op", "field", "value"],
    };
    let before = diagnostics.diagnostics.len();
    check_members(map, pointer, members, diagnostics);
    if op == "set" {
        let edit = parse_set(map, pointer, diagnostics);
        return (diagnostics.diagnostics.len() == before).then_some(edit?);
    }
    let section = required(map, "section", pointer, diagnostics).and_then(|value| {
        let section = match value.as_str() {
            Some("rules") => Some(Section::Rules),
            Some("routes") => Some(Section::Routes),
            Some("rate_limits") => Some(Section::RateLimits),
            _ => None,
        };
        if section.is_none() {
            diagnostics.push(
                "invalid_value",
                &format!("{pointer}/section"),
                "section must be one of \"rules\", \"routes\" or \"rate_limits\"",
            );
        }
        section
    });
    let position = |key: &str, diagnostics: &mut Diagnostics| {
        required(map, key, pointer, diagnostics)
            .and_then(|value| index(value, &format!("{pointer}/{key}"), diagnostics))
    };
    let element = |diagnostics: &mut Diagnostics| {
        required(map, "value", pointer, diagnostics).and_then(|value| {
            if value.is_object() {
                Some(value.clone())
            } else {
                diagnostics.push(
                    "invalid_type",
                    &format!("{pointer}/value"),
                    "value must be the complete element as an object",
                );
                None
            }
        })
    };
    let edit = match op {
        "insert" => {
            let position = position("position", diagnostics);
            let value = element(diagnostics);
            Some(PolicyEdit::Insert {
                section: section?,
                position: position?,
                value: value?,
            })
        }
        "replace" => {
            let position = position("position", diagnostics);
            let expect_id = parse_expect_id(map, pointer, diagnostics);
            let value = element(diagnostics);
            Some(PolicyEdit::Replace {
                section: section?,
                position: position?,
                expect_id: expect_id?,
                value: value?,
            })
        }
        "move" => {
            let from = position("from", diagnostics);
            let to = position("to", diagnostics);
            let expect_id = parse_expect_id(map, pointer, diagnostics);
            Some(PolicyEdit::Move {
                section: section?,
                from: from?,
                to: to?,
                expect_id: expect_id?,
            })
        }
        _ => {
            let position = position("position", diagnostics);
            let expect_id = parse_expect_id(map, pointer, diagnostics);
            Some(PolicyEdit::Delete {
                section: section?,
                position: position?,
                expect_id: expect_id?,
            })
        }
    };
    (diagnostics.diagnostics.len() == before).then_some(edit?)
}

/// `Some(None)` when absent.
fn parse_expect_id(
    map: &Map<String, Value>,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<Option<String>> {
    let Some(value) = map.get("expect_id") else {
        return Some(None);
    };
    bounded_string(
        value,
        &format!("{pointer}/expect_id"),
        MAX_EXPECT_ID_BYTES,
        diagnostics,
    )
    .map(Some)
}

fn parse_set(
    map: &Map<String, Value>,
    pointer: &str,
    diagnostics: &mut Diagnostics,
) -> Option<PolicyEdit> {
    let scalar = required(map, "field", pointer, diagnostics).and_then(|value| {
        let scalar = match value.as_str() {
            Some("default_action") => Some(Scalar::DefaultAction),
            Some("enforcement_mode") => Some(Scalar::EnforcementMode),
            _ => None,
        };
        if scalar.is_none() {
            diagnostics.push(
                "invalid_value",
                &format!("{pointer}/field"),
                "field must be \"default_action\" or \"enforcement_mode\"",
            );
        }
        scalar
    })?;
    let value = required(map, "value", pointer, diagnostics)?;
    let accepted = match (scalar, value.as_str()) {
        (Scalar::DefaultAction, Some("allow")) => Some("allow"),
        (Scalar::DefaultAction, Some("deny")) => Some("deny"),
        (Scalar::EnforcementMode, Some("enforce")) => Some("enforce"),
        (Scalar::EnforcementMode, Some("shadow")) => Some("shadow"),
        _ => None,
    };
    let Some(value) = accepted else {
        diagnostics.push(
            "invalid_value",
            &format!("{pointer}/value"),
            match scalar {
                Scalar::DefaultAction => "default_action must be \"allow\" or \"deny\"",
                Scalar::EnforcementMode => "enforcement_mode must be \"enforce\" or \"shadow\"",
            },
        );
        return None;
    };
    Some(PolicyEdit::Set { scalar, value })
}

/// Apply `edits`, in order, to `base` (a policy document as JSON). Each edit
/// sees the result of the ones before it. The first edit that cannot apply
/// refuses the whole candidate, with its pointer; nothing is half-applied
/// because the result is a new value the caller only uses on success.
pub(crate) fn apply_edits(
    base: &Value,
    edits: &[PolicyEdit],
    pointer: &str,
) -> Result<Value, Diagnostics> {
    let mut candidate = base.clone();
    let mut diagnostics = Diagnostics::new();
    let Some(document) = candidate.as_object_mut() else {
        diagnostics.push("internal_error", "", "the base policy is not an object");
        return Err(diagnostics);
    };
    for (index, edit) in edits.iter().enumerate() {
        let edit_pointer = format!("{pointer}/{index}");
        if let Err((member, code, message)) = apply_edit(document, edit) {
            diagnostics.push(code, &format!("{edit_pointer}/{member}"), message);
            return Err(diagnostics);
        }
    }
    Ok(candidate)
}

type EditRefusal = (&'static str, &'static str, &'static str);

fn apply_edit(document: &mut Map<String, Value>, edit: &PolicyEdit) -> Result<(), EditRefusal> {
    match edit {
        PolicyEdit::Set { scalar, value } => {
            document.insert(scalar.key().to_owned(), Value::String((*value).to_owned()));
            Ok(())
        }
        PolicyEdit::Insert {
            section,
            position,
            value,
        } => {
            let items = section_items(document, *section)?;
            if *position > items.len() {
                return Err((
                    "position",
                    "position_out_of_range",
                    "an insert position may be at most the section's length, which appends",
                ));
            }
            items.insert(*position, value.clone());
            Ok(())
        }
        PolicyEdit::Replace {
            section,
            position,
            expect_id,
            value,
        } => {
            let items = section_items(document, *section)?;
            let slot = existing(items, *position, "position")?;
            check_expected_id(slot, expect_id.as_deref())?;
            *slot = value.clone();
            Ok(())
        }
        PolicyEdit::Delete {
            section,
            position,
            expect_id,
        } => {
            let items = section_items(document, *section)?;
            check_expected_id(
                existing(items, *position, "position")?,
                expect_id.as_deref(),
            )?;
            items.remove(*position);
            Ok(())
        }
        PolicyEdit::Move {
            section,
            from,
            to,
            expect_id,
        } => {
            let items = section_items(document, *section)?;
            check_expected_id(existing(items, *from, "from")?, expect_id.as_deref())?;
            if *to >= items.len() {
                return Err((
                    "to",
                    "position_out_of_range",
                    "a move destination must be an existing position in the section",
                ));
            }
            let element = items.remove(*from);
            items.insert(*to, element);
            Ok(())
        }
    }
}

/// The section's array, created empty when the base omits it (an empty
/// `rate_limits` is not serialized).
fn section_items(
    document: &mut Map<String, Value>,
    section: Section,
) -> Result<&mut Vec<Value>, EditRefusal> {
    match document
        .entry(section.key())
        .or_insert_with(|| Value::Array(Vec::new()))
    {
        Value::Array(items) => Ok(items),
        _ => Err((
            "section",
            "internal_error",
            "the base policy section is not an array",
        )),
    }
}

fn existing<'a>(
    items: &'a mut [Value],
    position: usize,
    member: &'static str,
) -> Result<&'a mut Value, EditRefusal> {
    items.get_mut(position).ok_or((
        member,
        "position_out_of_range",
        "no element is at this position in the section as edited so far",
    ))
}

fn check_expected_id(element: &Value, expect_id: Option<&str>) -> Result<(), EditRefusal> {
    let Some(expected) = expect_id else {
        return Ok(());
    };
    if element.get("id").and_then(Value::as_str) == Some(expected) {
        Ok(())
    } else {
        Err((
            "expect_id",
            "edit_target_mismatch",
            "the element at this position does not carry the expected id",
        ))
    }
}
