//! The safe YAML subset bundle documents may be written in.
//!
//! This is a reader for a deliberately small subset of YAML 1.2, written for
//! the bundle rather than borrowed from a general YAML library, because the
//! subset's whole point is what it refuses before any value is built:
//!
//! - one document, with at most a leading `---`; no `...`, no directives;
//! - block mappings and block sequences indented with spaces, including a
//!   sequence written at its key's indentation and a mapping or sequence
//!   that starts on a `- ` line;
//! - flow sequences and mappings (`[a, b]`, `{ a: b }`) that close on the
//!   line they open, without trailing commas;
//! - double-quoted scalars with exactly the JSON escapes, single-quoted
//!   scalars, and plain scalars, each ending on the line it starts;
//! - `#` comments.
//!
//! Anchors, aliases, tags, merge keys, explicit (`? `) and collection keys,
//! block scalars (`|`, `>`), multi-line scalars, tabs outside quoted strings
//! and comments, empty values and duplicate keys are refused. So is any plain
//! scalar another YAML reader could type differently: a plain scalar is
//! `true`, `false`, `null`, an RFC 8259 integer, or a string that starts with
//! an ASCII letter, `_`, `/` or a non-ASCII character and is not one of the
//! YAML 1.1 boolean or null words in any case (`yes`, `No`, `ON`, `~`, ...).
//! Everything else -- `0x1F`, `017`, `1_000`, `12:30`, `2026-10-21`, `1.5`,
//! `.inf`, `-foo` -- must be quoted, so a reviewer and the gateway can never
//! read the same file differently. Plain keys follow the same idea: an
//! identifier (`[A-Za-z_][A-Za-z0-9_.-]*`) that is not a boolean or null word,
//! or a quoted string.
//!
//! Every bound in [`Limits`] is charged while parsing, and recursion is bounded
//! by the depth limit.

use super::{
    diagnostic::{Code, Position},
    syntax::{
        is_json_integer, safe_integer, Budget, KeySet, Limits, Member, Node, SyntaxError, Value,
    },
};

/// Plain words YAML 1.1 or 1.2 reads as booleans or null, compared without
/// case.
const BOOLEAN_AND_NULL_WORDS: &[&str] = &[
    "y", "yes", "n", "no", "true", "false", "on", "off", "null", "~",
];

/// Parses one document in the safe subset.
pub(crate) fn parse(text: &str, limits: Limits) -> Result<Node, SyntaxError> {
    let lines = content_lines(text)?;
    let mut parser = Parser {
        lines,
        index: 0,
        budget: Budget::new(limits),
    };
    if parser.current().is_none() {
        return Err(SyntaxError::new(Code::EmptyDocument, Position::new(1, 1)));
    }
    let node = parser.block(0)?;
    if let Some(line) = parser.current() {
        return Err(SyntaxError::new(Code::BadIndentation, line.position(0)));
    }
    Ok(node)
}

/// One line with content, after its indentation.
#[derive(Clone, Copy, Debug)]
struct Line<'a> {
    number: u32,
    /// Leading spaces; for the rest of a `- ` line re-read as a line of its
    /// own, the column it starts at less one.
    indent: usize,
    /// The content, without indentation or trailing spaces.
    text: &'a str,
}

impl Line<'_> {
    /// The position of byte `offset` of `text`. Everything before `text` is
    /// ASCII, so `indent` counts characters.
    fn position(&self, offset: usize) -> Position {
        let before = self.text.get(..offset).unwrap_or(self.text).chars().count();
        Position::new(
            self.number,
            u32::try_from(self.indent + before + 1).unwrap_or(u32::MAX),
        )
    }

    fn byte(&self, offset: usize) -> Option<u8> {
        self.text.as_bytes().get(offset).copied()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Context {
    Block,
    Flow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InlineKind {
    Plain,
    Quoted,
    Flow,
}

/// A mapping key found at the start of a line.
struct KeyToken {
    key: String,
    position: Position,
    /// The byte just after the `:`.
    value_offset: usize,
}

/// Splits a document into its content lines, refusing what is decided per
/// line: tab indentation, directives, and document markers after the first.
fn content_lines(text: &str) -> Result<Vec<Line<'_>>, SyntaxError> {
    let mut lines = Vec::new();
    for (index, raw) in text.split('\n').enumerate() {
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let indent = raw.bytes().take_while(|byte| *byte == b' ').count();
        let rest = &raw[indent..];
        let after_whitespace = rest.trim_start_matches([' ', '\t']);
        if after_whitespace.is_empty() || after_whitespace.starts_with('#') {
            continue;
        }
        if rest.starts_with('\t') {
            return Err(SyntaxError::new(
                Code::TabForbidden,
                Position::new(number, u32::try_from(indent + 1).unwrap_or(u32::MAX)),
            ));
        }
        let content = rest.trim_end_matches(' ');
        if indent == 0 && content.starts_with('%') {
            return Err(SyntaxError::new(
                Code::DirectiveForbidden,
                Position::new(number, 1),
            ));
        }
        let line = Line {
            number,
            indent,
            text: content,
        };
        if indent == 0 && is_marker(content, "---") {
            if !lines.is_empty() {
                return Err(SyntaxError::new(Code::MultipleDocuments, line.position(0)));
            }
            if !marker_is_alone(content) {
                return Err(SyntaxError::new(Code::YamlSyntax, line.position(0)));
            }
            continue;
        }
        if indent == 0 && is_marker(content, "...") {
            return Err(SyntaxError::new(Code::MultipleDocuments, line.position(0)));
        }
        lines.push(line);
    }
    Ok(lines)
}

fn is_marker(text: &str, marker: &str) -> bool {
    text == marker
        || text
            .strip_prefix(marker)
            .is_some_and(|rest| rest.starts_with([' ', '\t']))
}

/// A `---` followed by nothing but a comment.
fn marker_is_alone(text: &str) -> bool {
    let rest = text[3..].trim_start_matches(' ');
    rest.is_empty() || rest.starts_with('#')
}

fn is_sequence_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ") || text.starts_with("-\t")
}

struct Parser<'a> {
    lines: Vec<Line<'a>>,
    index: usize,
    budget: Budget,
}

impl<'a> Parser<'a> {
    fn current(&self) -> Option<Line<'a>> {
        self.lines.get(self.index).copied()
    }

    /// The block node starting on the current line, inside `open` collections.
    fn block(&mut self, open: usize) -> Result<Node, SyntaxError> {
        let Some(line) = self.current() else {
            return Err(SyntaxError::new(Code::EmptyDocument, Position::new(1, 1)));
        };
        if is_sequence_item(line.text) {
            return self.sequence(open);
        }
        if key_token(&line)?.is_some() {
            return self.mapping(open);
        }
        let (node, end, kind) = self.inline(line, 0, open, Context::Block)?;
        finish_line(&line, end)?;
        self.index += 1;
        self.no_continuation(line.indent, kind)?;
        Ok(node)
    }

    fn mapping(&mut self, open: usize) -> Result<Node, SyntaxError> {
        let Some(first) = self.current() else {
            return Err(SyntaxError::new(Code::EmptyDocument, Position::new(1, 1)));
        };
        let indent = first.indent;
        let position = first.position(0);
        self.budget.open_collection(open, position)?;
        self.budget.node(position)?;
        let mut members = Vec::new();
        let mut keys = KeySet::default();
        while let Some(line) = self.current() {
            if is_sequence_item(line.text) {
                return Err(SyntaxError::new(Code::BadIndentation, line.position(0)));
            }
            let Some(token) = key_token(&line)? else {
                return Err(SyntaxError::new(Code::YamlSyntax, line.position(0)));
            };
            self.budget.key(&token.key, token.position)?;
            if !keys.insert(&token.key) {
                return Err(SyntaxError::new(Code::YamlDuplicateKey, token.position));
            }
            self.budget.members(members.len() + 1, token.position)?;

            let value_start = skip_spaces(&line, token.value_offset)?;
            let rest = &line.text[value_start..];
            let value = if rest.is_empty() || rest.starts_with('#') {
                self.index += 1;
                match self.current() {
                    Some(next) if next.indent > indent => self.block(open + 1)?,
                    Some(next) if next.indent == indent && is_sequence_item(next.text) => {
                        self.sequence(open + 1)?
                    }
                    _ => return Err(SyntaxError::new(Code::EmptyValue, token.position)),
                }
            } else {
                let (node, end, kind) = self.inline(line, value_start, open + 1, Context::Block)?;
                finish_line(&line, end)?;
                self.index += 1;
                self.no_continuation(indent, kind)?;
                node
            };
            members.push(Member {
                key: token.key,
                key_position: token.position,
                value,
            });

            match self.current() {
                Some(next) if next.indent == indent => continue,
                Some(next) if next.indent > indent => {
                    return Err(SyntaxError::new(Code::BadIndentation, next.position(0)));
                }
                _ => break,
            }
        }
        Ok(Node::new(Value::Object(members), position))
    }

    fn sequence(&mut self, open: usize) -> Result<Node, SyntaxError> {
        let Some(first) = self.current() else {
            return Err(SyntaxError::new(Code::EmptyDocument, Position::new(1, 1)));
        };
        let indent = first.indent;
        let position = first.position(0);
        self.budget.open_collection(open, position)?;
        self.budget.node(position)?;
        let mut items = Vec::new();
        while let Some(line) = self.current() {
            let item_position = line.position(0);
            self.budget.elements(items.len() + 1, item_position)?;
            let value_start = skip_spaces(&line, 1)?;
            let rest = &line.text[value_start..];
            let compact = Line {
                number: line.number,
                indent: line.indent + value_start,
                text: rest,
            };
            let item = if rest.is_empty() || rest.starts_with('#') {
                self.index += 1;
                match self.current() {
                    Some(next) if next.indent > indent => self.block(open + 1)?,
                    _ => return Err(SyntaxError::new(Code::EmptyValue, item_position)),
                }
            } else if is_sequence_item(rest) || key_token(&compact)?.is_some() {
                // A mapping or sequence that starts on the `- ` line: re-read
                // the rest of the line as a line of its own, indented to where
                // it starts.
                self.lines[self.index] = compact;
                self.block(open + 1)?
            } else {
                let (node, end, kind) = self.inline(line, value_start, open + 1, Context::Block)?;
                finish_line(&line, end)?;
                self.index += 1;
                self.no_continuation(indent, kind)?;
                node
            };
            items.push(item);

            match self.current() {
                Some(next) if next.indent == indent && is_sequence_item(next.text) => continue,
                Some(next) if next.indent > indent => {
                    return Err(SyntaxError::new(Code::BadIndentation, next.position(0)));
                }
                // Less indented, or the parent mapping's next key at this
                // indentation.
                _ => break,
            }
        }
        Ok(Node::new(Value::Array(items), position))
    }

    /// Refuses a line more indented than the inline value just read, which
    /// YAML would fold into a multi-line scalar or reject.
    fn no_continuation(&self, indent: usize, kind: InlineKind) -> Result<(), SyntaxError> {
        match self.current() {
            Some(next) if next.indent > indent => Err(SyntaxError::new(
                if kind == InlineKind::Plain {
                    Code::MultilineValueForbidden
                } else {
                    Code::BadIndentation
                },
                next.position(0),
            )),
            _ => Ok(()),
        }
    }

    /// One scalar or flow collection starting at byte `start` of `line`.
    /// Returns the node, the byte after it, and what kind of value it was.
    fn inline(
        &mut self,
        line: Line<'a>,
        start: usize,
        open: usize,
        context: Context,
    ) -> Result<(Node, usize, InlineKind), SyntaxError> {
        let position = line.position(start);
        let Some(first) = line.text[start..].chars().next() else {
            return Err(SyntaxError::new(Code::EmptyValue, position));
        };
        let next = line.byte(start + first.len_utf8());
        let indicator_ends = |byte: Option<u8>| match byte {
            None | Some(b' ' | b'\t') => true,
            Some(b',' | b']' | b'}') => context == Context::Flow,
            _ => false,
        };
        match first {
            '"' => {
                let (text, end) = double_quoted(&line, start, self.budget.string_limit())?;
                self.scalar_string(text, position, end, InlineKind::Quoted)
            }
            '\'' => {
                let (text, end) = single_quoted(&line, start, self.budget.string_limit())?;
                self.scalar_string(text, position, end, InlineKind::Quoted)
            }
            '[' => {
                let (node, end) = self.flow_sequence(line, start, open)?;
                Ok((node, end, InlineKind::Flow))
            }
            '{' => {
                let (node, end) = self.flow_mapping(line, start, open)?;
                Ok((node, end, InlineKind::Flow))
            }
            '&' => Err(SyntaxError::new(Code::AnchorForbidden, position)),
            '*' => Err(SyntaxError::new(Code::AliasForbidden, position)),
            '!' => Err(SyntaxError::new(Code::TagForbidden, position)),
            '|' | '>' => Err(SyntaxError::new(Code::BlockScalarForbidden, position)),
            '?' if indicator_ends(next) => {
                Err(SyntaxError::new(Code::ComplexKeyForbidden, position))
            }
            '-' | ':' if indicator_ends(next) => Err(SyntaxError::new(Code::YamlSyntax, position)),
            '%' | '@' | '`' | ',' | ']' | '}' | '#' => {
                Err(SyntaxError::new(Code::YamlSyntax, position))
            }
            '\t' => Err(SyntaxError::new(Code::TabForbidden, position)),
            _ => self.plain(line, start, context),
        }
    }

    fn scalar_string(
        &mut self,
        text: String,
        position: Position,
        end: usize,
        kind: InlineKind,
    ) -> Result<(Node, usize, InlineKind), SyntaxError> {
        self.budget.node(position)?;
        self.budget.string(&text, position)?;
        Ok((Node::new(Value::String(text), position), end, kind))
    }

    fn plain(
        &mut self,
        line: Line<'a>,
        start: usize,
        context: Context,
    ) -> Result<(Node, usize, InlineKind), SyntaxError> {
        let position = line.position(start);
        let bytes = line.text.as_bytes();
        let mut end = start;
        while end < bytes.len() {
            match bytes[end] {
                b'\t' => return Err(SyntaxError::new(Code::TabForbidden, line.position(end))),
                b' ' if bytes.get(end + 1) == Some(&b'#') => break,
                b':' if matches!(bytes.get(end + 1), None | Some(b' '))
                    || (context == Context::Flow
                        && matches!(bytes.get(end + 1), Some(b',' | b']' | b'}'))) =>
                {
                    if context == Context::Flow {
                        // The collection then refuses the stray indicator.
                        break;
                    }
                    // `key: a: b` and `key: value:` are mapping indicators
                    // YAML refuses inside a value.
                    return Err(SyntaxError::new(Code::YamlSyntax, line.position(end)));
                }
                b',' | b']' | b'}' if context == Context::Flow => break,
                b'[' | b'{' if context == Context::Flow => {
                    return Err(SyntaxError::new(Code::YamlSyntax, line.position(end)));
                }
                _ => end += 1,
            }
        }
        let text = line.text[start..end].trim_end_matches(' ');
        let value = resolve_plain(text).map_err(|code| SyntaxError::new(code, position))?;
        self.budget.node(position)?;
        if let Value::String(text) = &value {
            self.budget.string(text, position)?;
        }
        Ok((Node::new(value, position), end, InlineKind::Plain))
    }

    fn flow_sequence(
        &mut self,
        line: Line<'a>,
        start: usize,
        open: usize,
    ) -> Result<(Node, usize), SyntaxError> {
        let position = line.position(start);
        self.budget.open_collection(open, position)?;
        self.budget.node(position)?;
        let mut items = Vec::new();
        let mut index = skip_spaces(&line, start + 1)?;
        if line.byte(index) == Some(b']') {
            return Ok((Node::new(Value::Array(items), position), index + 1));
        }
        loop {
            if flow_ends_here(&line, index) {
                return Err(SyntaxError::new(Code::MultilineValueForbidden, position));
            }
            self.budget
                .elements(items.len() + 1, line.position(index))?;
            let (node, end, _) = self.inline(line, index, open + 1, Context::Flow)?;
            items.push(node);
            index = skip_spaces(&line, end)?;
            match line.byte(index) {
                Some(b',') => {
                    index = skip_spaces(&line, index + 1)?;
                    if line.byte(index) == Some(b']') {
                        return Err(SyntaxError::new(Code::YamlSyntax, line.position(index)));
                    }
                }
                Some(b']') => return Ok((Node::new(Value::Array(items), position), index + 1)),
                _ if flow_ends_here(&line, index) => {
                    return Err(SyntaxError::new(Code::MultilineValueForbidden, position));
                }
                _ => return Err(SyntaxError::new(Code::YamlSyntax, line.position(index))),
            }
        }
    }

    fn flow_mapping(
        &mut self,
        line: Line<'a>,
        start: usize,
        open: usize,
    ) -> Result<(Node, usize), SyntaxError> {
        let position = line.position(start);
        self.budget.open_collection(open, position)?;
        self.budget.node(position)?;
        let mut members = Vec::new();
        let mut keys = KeySet::default();
        let mut index = skip_spaces(&line, start + 1)?;
        if line.byte(index) == Some(b'}') {
            return Ok((Node::new(Value::Object(members), position), index + 1));
        }
        loop {
            if flow_ends_here(&line, index) {
                return Err(SyntaxError::new(Code::MultilineValueForbidden, position));
            }
            let key_position = line.position(index);
            let (key, after_key) = flow_key(&line, index, self.budget.string_limit())?;
            self.budget.key(&key, key_position)?;
            if !keys.insert(&key) {
                return Err(SyntaxError::new(Code::YamlDuplicateKey, key_position));
            }
            self.budget.members(members.len() + 1, key_position)?;
            index = skip_spaces(&line, after_key)?;
            if matches!(line.byte(index), Some(b',' | b'}')) {
                return Err(SyntaxError::new(Code::EmptyValue, key_position));
            }
            if flow_ends_here(&line, index) {
                return Err(SyntaxError::new(Code::MultilineValueForbidden, position));
            }
            let (value, end, _) = self.inline(line, index, open + 1, Context::Flow)?;
            members.push(Member {
                key,
                key_position,
                value,
            });
            index = skip_spaces(&line, end)?;
            match line.byte(index) {
                Some(b',') => {
                    index = skip_spaces(&line, index + 1)?;
                    if line.byte(index) == Some(b'}') {
                        return Err(SyntaxError::new(Code::YamlSyntax, line.position(index)));
                    }
                }
                Some(b'}') => return Ok((Node::new(Value::Object(members), position), index + 1)),
                _ if flow_ends_here(&line, index) => {
                    return Err(SyntaxError::new(Code::MultilineValueForbidden, position));
                }
                _ => return Err(SyntaxError::new(Code::YamlSyntax, line.position(index))),
            }
        }
    }
}

/// Whether a flow collection reaches the end of its line (or a comment)
/// at `index` without closing.
fn flow_ends_here(line: &Line<'_>, index: usize) -> bool {
    index >= line.text.len()
        || (line.byte(index) == Some(b'#') && index > 0 && line.byte(index - 1) == Some(b' '))
}

/// The key that starts `line`, if the line is a mapping entry.
fn key_token(line: &Line<'_>) -> Result<Option<KeyToken>, SyntaxError> {
    let text = line.text;
    let position = line.position(0);
    match text.as_bytes().first() {
        Some(b'"' | b'\'') => {
            // Unbounded here: the key's own bound is charged when the
            // mapping reads it, and the line is already bounded by the file.
            let quoted = if text.starts_with('"') {
                double_quoted(line, 0, None)
            } else {
                single_quoted(line, 0, None)
            };
            // An unterminated quote is reported when the value is read.
            let Ok((key, end)) = quoted else {
                return Ok(None);
            };
            let colon = skip_spaces(line, end)?;
            if line.byte(colon) == Some(b':') && matches!(line.byte(colon + 1), None | Some(b' ')) {
                return Ok(Some(KeyToken {
                    key,
                    position,
                    value_offset: colon + 1,
                }));
            }
            if line.byte(colon) == Some(b':') && line.byte(colon + 1) == Some(b'\t') {
                return Err(SyntaxError::new(
                    Code::TabForbidden,
                    line.position(colon + 1),
                ));
            }
            Ok(None)
        }
        Some(b'?') if matches!(line.byte(1), None | Some(b' ' | b'\t')) => {
            Err(SyntaxError::new(Code::ComplexKeyForbidden, position))
        }
        Some(b'[' | b'{') | None => Ok(None),
        Some(_) if is_sequence_item(text) => Ok(None),
        Some(_) => {
            let bytes = text.as_bytes();
            for (index, byte) in bytes.iter().enumerate() {
                match byte {
                    b' ' if bytes.get(index + 1) == Some(&b'#') => return Ok(None),
                    b':' => match bytes.get(index + 1) {
                        None | Some(b' ') => {
                            let key = &text[..index];
                            if key.ends_with('\t') {
                                return Err(SyntaxError::new(Code::TabForbidden, position));
                            }
                            let key = key.trim_end_matches(' ');
                            validate_plain_key(key)
                                .map_err(|code| SyntaxError::new(code, position))?;
                            return Ok(Some(KeyToken {
                                key: key.to_owned(),
                                position,
                                value_offset: index + 1,
                            }));
                        }
                        Some(b'\t') => {
                            return Err(SyntaxError::new(
                                Code::TabForbidden,
                                line.position(index + 1),
                            ));
                        }
                        Some(_) => {}
                    },
                    _ => {}
                }
            }
            Ok(None)
        }
    }
}

/// The key of a flow mapping entry starting at `start`, and the byte after
/// its `:`.
fn flow_key(
    line: &Line<'_>,
    start: usize,
    maximum: Option<usize>,
) -> Result<(String, usize), SyntaxError> {
    let position = line.position(start);
    match line.byte(start) {
        Some(b'"' | b'\'') => {
            let (key, end) = if line.byte(start) == Some(b'"') {
                double_quoted(line, start, maximum)?
            } else {
                single_quoted(line, start, maximum)?
            };
            let colon = skip_spaces(line, end)?;
            if line.byte(colon) != Some(b':') {
                return Err(SyntaxError::new(Code::YamlSyntax, line.position(colon)));
            }
            Ok((key, colon + 1))
        }
        Some(b'?') if matches!(line.byte(start + 1), None | Some(b' ' | b'\t')) => {
            Err(SyntaxError::new(Code::ComplexKeyForbidden, position))
        }
        Some(b'[' | b'{') => Err(SyntaxError::new(Code::ComplexKeyForbidden, position)),
        _ => {
            let bytes = line.text.as_bytes();
            let mut index = start;
            while index < bytes.len() {
                match bytes[index] {
                    b':' if matches!(bytes.get(index + 1), Some(b' ')) => {
                        let key = line.text[start..index].trim_end_matches(' ');
                        validate_plain_key(key).map_err(|code| SyntaxError::new(code, position))?;
                        return Ok((key.to_owned(), index + 1));
                    }
                    b'\t' => {
                        return Err(SyntaxError::new(Code::TabForbidden, line.position(index)))
                    }
                    b',' | b'}' | b']' | b'{' | b'[' | b'#' => break,
                    _ => index += 1,
                }
            }
            if index >= bytes.len() {
                Err(SyntaxError::new(Code::MultilineValueForbidden, position))
            } else {
                Err(SyntaxError::new(Code::YamlSyntax, line.position(index)))
            }
        }
    }
}

/// Refuses a plain key outside the identifier form, or one another reader
/// would type as a boolean, null or number.
fn validate_plain_key(key: &str) -> Result<(), Code> {
    let Some(first) = key.chars().next() else {
        return Err(Code::KeyMustBeQuoted);
    };
    match first {
        '&' => return Err(Code::AnchorForbidden),
        '*' => return Err(Code::AliasForbidden),
        '!' => return Err(Code::TagForbidden),
        _ => {}
    }
    if key == "<<" {
        return Err(Code::MergeKeyForbidden);
    }
    if is_boolean_or_null_word(key) || is_json_integer(key) {
        return Err(Code::NonStringKey);
    }
    let mut characters = key.chars();
    let identifier = characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        });
    if identifier {
        Ok(())
    } else {
        Err(Code::KeyMustBeQuoted)
    }
}

fn is_boolean_or_null_word(text: &str) -> bool {
    BOOLEAN_AND_NULL_WORDS
        .iter()
        .any(|word| word.eq_ignore_ascii_case(text))
}

/// What a plain scalar denotes, or why it must be quoted.
fn resolve_plain(text: &str) -> Result<Value, Code> {
    match text {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        "null" => return Ok(Value::Null),
        _ => {}
    }
    if is_json_integer(text) {
        return safe_integer(text, Position::default())
            .map(Value::Integer)
            .map_err(|error| error.code);
    }
    let Some(first) = text.chars().next() else {
        return Err(Code::EmptyValue);
    };
    let starts_safely =
        first.is_ascii_alphabetic() || first == '_' || first == '/' || !first.is_ascii();
    if !starts_safely || is_boolean_or_null_word(text) {
        return Err(Code::AmbiguousScalar);
    }
    Ok(Value::String(text.to_owned()))
}

/// Skips spaces from `offset`; a tab is refused.
fn skip_spaces(line: &Line<'_>, offset: usize) -> Result<usize, SyntaxError> {
    let mut index = offset;
    loop {
        match line.byte(index) {
            Some(b' ') => index += 1,
            Some(b'\t') => return Err(SyntaxError::new(Code::TabForbidden, line.position(index))),
            _ => return Ok(index),
        }
    }
}

/// After an inline value ending at `end`, only spaces and a comment may
/// follow on the line.
fn finish_line(line: &Line<'_>, end: usize) -> Result<(), SyntaxError> {
    let rest = &line.text[end..];
    let trimmed = rest.trim_start_matches(' ');
    if trimmed.is_empty() || (trimmed.starts_with('#') && trimmed.len() < rest.len()) {
        return Ok(());
    }
    let offset = end + (rest.len() - trimmed.len());
    let code = if trimmed.starts_with('\t') {
        Code::TabForbidden
    } else if trimmed.starts_with(':') {
        Code::ComplexKeyForbidden
    } else {
        Code::YamlSyntax
    };
    Err(SyntaxError::new(code, line.position(offset)))
}

/// A double-quoted scalar at `start`, decoded with exactly the JSON escape
/// set, and the byte after its closing quote.
fn double_quoted(
    line: &Line<'_>,
    start: usize,
    maximum: Option<usize>,
) -> Result<(String, usize), SyntaxError> {
    let position = line.position(start);
    let mut out = String::new();
    let mut characters = line.text[start + 1..].char_indices();
    while let Some((offset, character)) = characters.next() {
        if maximum.is_some_and(|maximum| out.len() > maximum) {
            return Err(SyntaxError::new(Code::StringTooLong, position));
        }
        match character {
            '"' => return Ok((out, start + 1 + offset + 1)),
            '\\' => {
                let escape_position = line.position(start + 1 + offset);
                let Some((_, escape)) = characters.next() else {
                    return Err(SyntaxError::new(Code::MultilineValueForbidden, position));
                };
                let decoded = match escape {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'u' => {
                        let first = hex4(&mut characters).ok_or_else(|| {
                            SyntaxError::new(Code::UnsupportedEscape, escape_position)
                        })?;
                        decode_unicode_escape(first, &mut characters).ok_or_else(|| {
                            SyntaxError::new(Code::UnsupportedEscape, escape_position)
                        })?
                    }
                    _ => return Err(SyntaxError::new(Code::UnsupportedEscape, escape_position)),
                };
                out.push(decoded);
            }
            other => out.push(other),
        }
    }
    Err(SyntaxError::new(Code::MultilineValueForbidden, position))
}

fn hex4(characters: &mut std::str::CharIndices<'_>) -> Option<u32> {
    let mut value = 0_u32;
    for _ in 0..4 {
        let (_, character) = characters.next()?;
        value = value * 16 + character.to_digit(16)?;
    }
    Some(value)
}

/// A `\u` escape, joining a UTF-16 surrogate pair written as two escapes.
/// A lone surrogate is refused.
fn decode_unicode_escape(first: u32, characters: &mut std::str::CharIndices<'_>) -> Option<char> {
    match first {
        0xd800..=0xdbff => {
            let (_, backslash) = characters.next()?;
            let (_, letter) = characters.next()?;
            if backslash != '\\' || letter != 'u' {
                return None;
            }
            let second = hex4(characters)?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return None;
            }
            char::from_u32(0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00))
        }
        0xdc00..=0xdfff => None,
        scalar => char::from_u32(scalar),
    }
}

/// A single-quoted scalar at `start` (`''` is one quote), and the byte after
/// its closing quote.
fn single_quoted(
    line: &Line<'_>,
    start: usize,
    maximum: Option<usize>,
) -> Result<(String, usize), SyntaxError> {
    let position = line.position(start);
    let mut out = String::new();
    let mut characters = line.text[start + 1..].char_indices().peekable();
    while let Some((offset, character)) = characters.next() {
        if maximum.is_some_and(|maximum| out.len() > maximum) {
            return Err(SyntaxError::new(Code::StringTooLong, position));
        }
        if character == '\'' {
            if characters.peek().is_some_and(|(_, next)| *next == '\'') {
                characters.next();
                out.push('\'');
                continue;
            }
            return Ok((out, start + 1 + offset + 1));
        }
        out.push(character);
    }
    Err(SyntaxError::new(Code::MultilineValueForbidden, position))
}
