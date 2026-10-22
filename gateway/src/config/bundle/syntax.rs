//! The value tree both bundle syntaxes parse into, and the bounds they share.
//!
//! The JSON and YAML readers produce the same [`Node`] tree, with duplicate
//! keys already refused and every bound already applied while parsing, so
//! everything after them works on one representation whatever the operator
//! wrote. Each node keeps the line and column it started at, for diagnostics.

use std::collections::HashSet;

use serde_json::{Map, Number};

use super::diagnostic::{Code, Position};

/// The largest integer magnitude I-JSON exchanges exactly.
pub(crate) const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// Which numbers a document may contain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Numbers {
    /// Integers within the I-JSON safe range only: bundle documents, whose
    /// fractional settings are decimal strings.
    SafeIntegers,
    /// Any RFC 8259 number, kept as its exact text: referenced policy and
    /// tools documents, which keep their own validators' number rules.
    Any,
}

/// The structural bounds one document is parsed under.
///
/// A bound of `None` is not checked by the reader; it is left to the
/// document's own validator.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub(crate) depth: usize,
    pub(crate) members: Option<usize>,
    pub(crate) elements: Option<usize>,
    pub(crate) nodes: Option<usize>,
    pub(crate) string_bytes: Option<usize>,
    pub(crate) key_bytes: Option<usize>,
    pub(crate) numbers: Numbers,
    /// Whether decoded strings and keys are held to the same character rule
    /// as the raw text of a bundle document.
    pub(crate) text_characters: bool,
}

pub(crate) const MAX_DEPTH: usize = 32;
pub(crate) const MAX_OBJECT_MEMBERS: usize = 1_024;
pub(crate) const MAX_ARRAY_ELEMENTS: usize = 4_096;
pub(crate) const MAX_DOCUMENT_NODES: usize = 65_536;
pub(crate) const MAX_STRING_BYTES: usize = 64 * 1024;
pub(crate) const MAX_KEY_BYTES: usize = 128;

/// `GatewayBundle` and `GatewayDeployment` documents.
pub(crate) const DOCUMENT_LIMITS: Limits = Limits {
    depth: MAX_DEPTH,
    members: Some(MAX_OBJECT_MEMBERS),
    elements: Some(MAX_ARRAY_ELEMENTS),
    nodes: Some(MAX_DOCUMENT_NODES),
    string_bytes: Some(MAX_STRING_BYTES),
    key_bytes: Some(MAX_KEY_BYTES),
    numbers: Numbers::SafeIntegers,
    text_characters: true,
};

/// Referenced policy and tools documents keep their own validators' limits;
/// the reader adds only the depth bound (and the byte bound, applied when the
/// file is read).
pub(crate) const RESOURCE_LIMITS: Limits = Limits {
    depth: MAX_DEPTH,
    members: None,
    elements: None,
    nodes: None,
    string_bytes: None,
    key_bytes: None,
    numbers: Numbers::Any,
    text_characters: false,
};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    /// The exact text of a number, under [`Numbers::Any`] only.
    Number(String),
    String(String),
    Array(Vec<Node>),
    Object(Vec<Member>),
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Node {
    pub(crate) value: Value,
    pub(crate) position: Position,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Member {
    pub(crate) key: String,
    pub(crate) key_position: Position,
    pub(crate) value: Node,
}

impl Node {
    pub(crate) fn new(value: Value, position: Position) -> Self {
        Self { value, position }
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        match &self.value {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    pub(crate) fn as_object(&self) -> Option<&[Member]> {
        match &self.value {
            Value::Object(members) => Some(members),
            _ => None,
        }
    }

    /// The JSON value this node denotes.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        match &self.value {
            Value::Null => serde_json::Value::Null,
            Value::Bool(value) => serde_json::Value::Bool(*value),
            Value::Integer(value) => serde_json::Value::Number(Number::from(*value)),
            // The reader validated the RFC 8259 grammar, which is exactly what
            // `Number` parses; `Null` is unreachable but keeps the conversion
            // total without a panic path.
            Value::Number(text) => text
                .parse::<Number>()
                .map_or(serde_json::Value::Null, serde_json::Value::Number),
            Value::String(text) => serde_json::Value::String(text.clone()),
            Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(Node::to_json).collect())
            }
            Value::Object(members) => {
                let mut map = Map::new();
                for member in members {
                    map.insert(member.key.clone(), member.value.to_json());
                }
                serde_json::Value::Object(map)
            }
        }
    }
}

/// Why a document could not be parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SyntaxError {
    pub(crate) code: Code,
    pub(crate) position: Position,
}

impl SyntaxError {
    pub(crate) fn new(code: Code, position: Position) -> Self {
        Self { code, position }
    }
}

/// The running bounds of one parse.
pub(crate) struct Budget {
    limits: Limits,
    nodes: usize,
}

impl Budget {
    pub(crate) fn new(limits: Limits) -> Self {
        Self { limits, nodes: 0 }
    }

    pub(crate) fn numbers(&self) -> Numbers {
        self.limits.numbers
    }

    /// Counts one value.
    pub(crate) fn node(&mut self, position: Position) -> Result<(), SyntaxError> {
        self.nodes += 1;
        match self.limits.nodes {
            Some(maximum) if self.nodes > maximum => {
                Err(SyntaxError::new(Code::TooManyNodes, position))
            }
            _ => Ok(()),
        }
    }

    /// Refuses opening a collection inside `open` already-open collections
    /// when that would exceed the depth bound.
    pub(crate) fn open_collection(
        &self,
        open: usize,
        position: Position,
    ) -> Result<(), SyntaxError> {
        if open + 1 > self.limits.depth {
            Err(SyntaxError::new(Code::TooDeep, position))
        } else {
            Ok(())
        }
    }

    pub(crate) fn members(&self, count: usize, position: Position) -> Result<(), SyntaxError> {
        bound(self.limits.members, count, Code::TooManyMembers, position)
    }

    pub(crate) fn elements(&self, count: usize, position: Position) -> Result<(), SyntaxError> {
        bound(self.limits.elements, count, Code::TooManyElements, position)
    }

    pub(crate) fn string(&self, text: &str, position: Position) -> Result<(), SyntaxError> {
        bound(
            self.limits.string_bytes,
            text.len(),
            Code::StringTooLong,
            position,
        )?;
        self.characters(text, position)
    }

    pub(crate) fn key(&self, text: &str, position: Position) -> Result<(), SyntaxError> {
        bound(
            self.limits.key_bytes,
            text.len(),
            Code::KeyTooLong,
            position,
        )?;
        self.characters(text, position)
    }

    /// Whether a string being decoded has already passed the byte bound, so
    /// a reader can stop before allocating further.
    pub(crate) fn string_overflows(&self, bytes: usize) -> bool {
        self.limits
            .string_bytes
            .is_some_and(|maximum| bytes > maximum)
    }

    pub(crate) fn string_limit(&self) -> Option<usize> {
        self.limits.string_bytes
    }

    fn characters(&self, text: &str, position: Position) -> Result<(), SyntaxError> {
        if self.limits.text_characters && text.chars().any(is_forbidden_character) {
            Err(SyntaxError::new(Code::ForbiddenCharacter, position))
        } else {
            Ok(())
        }
    }
}

fn bound(
    maximum: Option<usize>,
    count: usize,
    code: Code,
    position: Position,
) -> Result<(), SyntaxError> {
    match maximum {
        Some(maximum) if count > maximum => Err(SyntaxError::new(code, position)),
        _ => Ok(()),
    }
}

/// Tracks the keys of one object so a duplicate is refused before a later
/// value could replace an earlier one.
#[derive(Default)]
pub(crate) struct KeySet(HashSet<String>);

impl KeySet {
    /// Whether `key` is new.
    pub(crate) fn insert(&mut self, key: &str) -> bool {
        self.0.insert(key.to_owned())
    }
}

/// Characters a bundle document may not contain anywhere, comments
/// included: C0 controls other than tab and line feed, DEL, C1 controls, the
/// byte-order mark, the bidirectional formatting characters, and the line
/// and paragraph separators, which YAML 1.1 readers (like NEL, a C1 control)
/// treat as line breaks. Each lets a reviewer, another YAML reader and this
/// reader see different lines or text in the same bytes.
pub(crate) fn is_forbidden_character(character: char) -> bool {
    matches!(
        character,
        '\u{0}'..='\u{8}'
            | '\u{b}'..='\u{1f}'
            | '\u{7f}'..='\u{9f}'
            | '\u{61c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// Which text rules a file is held to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TextRules {
    /// A bundle document: UTF-8, no byte-order mark, LF only, and no
    /// [forbidden character](is_forbidden_character).
    Document,
    /// A referenced resource: UTF-8, no byte-order mark, LF only.
    Resource,
}

/// Decodes a file's bytes under the bundle's text rules.
pub(crate) fn decode_text(bytes: &[u8], rules: TextRules) -> Result<&str, SyntaxError> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err(SyntaxError::new(Code::ByteOrderMark, Position::new(1, 1)));
    }
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(error) => {
            let valid = &bytes[..error.valid_up_to()];
            // The prefix is valid UTF-8 by construction.
            let prefix = std::str::from_utf8(valid).unwrap_or_default();
            return Err(SyntaxError::new(Code::NotUtf8, end_position(prefix)));
        }
    };
    if let Some(index) = text.find('\r') {
        return Err(SyntaxError::new(
            Code::CarriageReturn,
            end_position(&text[..index]),
        ));
    }
    if rules == TextRules::Document {
        if let Some((index, _)) = text
            .char_indices()
            .find(|(_, character)| is_forbidden_character(*character))
        {
            return Err(SyntaxError::new(
                Code::ForbiddenCharacter,
                end_position(&text[..index]),
            ));
        }
    }
    Ok(text)
}

/// The position just after `prefix`.
fn end_position(prefix: &str) -> Position {
    let line = prefix.matches('\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, last)| last)
        .chars()
        .count()
        + 1;
    Position::new(
        u32::try_from(line).unwrap_or(u32::MAX),
        u32::try_from(column).unwrap_or(u32::MAX),
    )
}

/// The RFC 8259 integer grammar: `-?(0|[1-9][0-9]*)`.
pub(crate) fn is_json_integer(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    match digits.as_bytes() {
        [b'0'] => true,
        [first, rest @ ..] => (b'1'..=b'9').contains(first) && rest.iter().all(u8::is_ascii_digit),
        [] => false,
    }
}

/// An integer in the RFC 8259 grammar, held to the I-JSON safe range.
pub(crate) fn safe_integer(text: &str, position: Position) -> Result<i64, SyntaxError> {
    text.parse::<i64>()
        .ok()
        .filter(|value| value.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs())
        .ok_or_else(|| SyntaxError::new(Code::IntegerOutOfRange, position))
}
