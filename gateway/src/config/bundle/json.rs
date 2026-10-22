//! A strict RFC 8259 JSON reader.
//!
//! `serde_json` keeps the last of two members with the same name, which is
//! exactly the silent field loss a bundle must not have, and it cannot apply
//! the bundle's structural bounds while it parses. This reader refuses a
//! duplicate member when it meets the second one, refuses trailing content,
//! and charges every bound before the value it limits is built. Its recursion
//! is bounded by the depth limit.

use super::{
    diagnostic::{Code, Position},
    syntax::{
        is_json_integer, safe_integer, Budget, KeySet, Limits, Member, Node, Numbers, SyntaxError,
        Value,
    },
};

/// Parses one JSON document.
pub(crate) fn parse(text: &str, limits: Limits) -> Result<Node, SyntaxError> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        index: 0,
        line: 1,
        column: 1,
        budget: Budget::new(limits),
    };
    parser.skip_whitespace();
    if parser.at_end() {
        return Err(SyntaxError::new(Code::EmptyDocument, parser.position()));
    }
    let node = parser.value(0)?;
    parser.skip_whitespace();
    if !parser.at_end() {
        return Err(parser.error(Code::JsonSyntax));
    }
    Ok(node)
}

struct Parser<'a> {
    bytes: &'a [u8],
    index: usize,
    line: u32,
    column: u32,
    budget: Budget,
}

impl Parser<'_> {
    fn position(&self) -> Position {
        Position::new(self.line, self.column)
    }

    fn error(&self, code: Code) -> SyntaxError {
        SyntaxError::new(code, self.position())
    }

    fn at_end(&self) -> bool {
        self.index >= self.bytes.len()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    /// Advances one byte, counting columns in characters: a UTF-8
    /// continuation byte does not start a new column.
    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.index += 1;
        if byte == b'\n' {
            self.line = self.line.saturating_add(1);
            self.column = 1;
        } else if byte & 0b1100_0000 != 0b1000_0000 {
            self.column = self.column.saturating_add(1);
        }
        Some(byte)
    }

    fn expect(&mut self, expected: u8) -> Result<(), SyntaxError> {
        if self.peek() == Some(expected) {
            self.bump();
            Ok(())
        } else {
            Err(self.error(Code::JsonSyntax))
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.bump();
        }
    }

    /// One value, inside `open` already-open collections.
    fn value(&mut self, open: usize) -> Result<Node, SyntaxError> {
        let position = self.position();
        self.budget.node(position)?;
        let value = match self.peek() {
            Some(b'{') => self.object(open, position)?,
            Some(b'[') => self.array(open, position)?,
            Some(b'"') => {
                let text = self.string()?;
                self.budget.string(&text, position)?;
                Value::String(text)
            }
            Some(b't') => self.literal(b"true", Value::Bool(true))?,
            Some(b'f') => self.literal(b"false", Value::Bool(false))?,
            Some(b'n') => self.literal(b"null", Value::Null)?,
            Some(b'-' | b'0'..=b'9') => self.number(position)?,
            _ => return Err(self.error(Code::JsonSyntax)),
        };
        Ok(Node::new(value, position))
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Result<Value, SyntaxError> {
        if self.bytes[self.index..].starts_with(word) {
            for _ in word {
                self.bump();
            }
            Ok(value)
        } else {
            Err(self.error(Code::JsonSyntax))
        }
    }

    fn object(&mut self, open: usize, position: Position) -> Result<Value, SyntaxError> {
        self.budget.open_collection(open, position)?;
        self.expect(b'{')?;
        let mut members = Vec::new();
        let mut keys = KeySet::default();
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.bump();
            return Ok(Value::Object(members));
        }
        loop {
            self.skip_whitespace();
            let key_position = self.position();
            if self.peek() != Some(b'"') {
                return Err(self.error(Code::JsonSyntax));
            }
            let key = self.string()?;
            self.budget.key(&key, key_position)?;
            if !keys.insert(&key) {
                return Err(SyntaxError::new(Code::JsonDuplicateKey, key_position));
            }
            self.budget.members(members.len() + 1, key_position)?;
            self.skip_whitespace();
            self.expect(b':')?;
            self.skip_whitespace();
            let value = self.value(open + 1)?;
            members.push(Member {
                key,
                key_position,
                value,
            });
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                }
                Some(b'}') => {
                    self.bump();
                    return Ok(Value::Object(members));
                }
                _ => return Err(self.error(Code::JsonSyntax)),
            }
        }
    }

    fn array(&mut self, open: usize, position: Position) -> Result<Value, SyntaxError> {
        self.budget.open_collection(open, position)?;
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.bump();
            return Ok(Value::Array(items));
        }
        loop {
            self.skip_whitespace();
            let item_position = self.position();
            self.budget.elements(items.len() + 1, item_position)?;
            items.push(self.value(open + 1)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => {
                    self.bump();
                }
                Some(b']') => {
                    self.bump();
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.error(Code::JsonSyntax)),
            }
        }
    }

    fn number(&mut self, position: Position) -> Result<Value, SyntaxError> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => {
                self.bump();
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.bump();
                }
            }
            _ => return Err(self.error(Code::JsonSyntax)),
        }
        let mut integer = true;
        if self.peek() == Some(b'.') {
            integer = false;
            self.bump();
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            integer = false;
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            self.digits()?;
        }
        // The scanned bytes are ASCII digits and signs.
        let text = std::str::from_utf8(&self.bytes[start..self.index])
            .map_err(|_| SyntaxError::new(Code::JsonSyntax, position))?;
        match self.budget.numbers() {
            Numbers::Any => Ok(Value::Number(text.to_owned())),
            Numbers::SafeIntegers if integer && is_json_integer(text) => {
                safe_integer(text, position).map(Value::Integer)
            }
            Numbers::SafeIntegers => Err(SyntaxError::new(Code::NumberNotInteger, position)),
        }
    }

    fn digits(&mut self) -> Result<(), SyntaxError> {
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(self.error(Code::JsonSyntax));
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.bump();
        }
        Ok(())
    }

    /// A string, decoded. The caller charges the byte bound; this stops as
    /// soon as the decoded text passes it.
    fn string(&mut self) -> Result<String, SyntaxError> {
        let start = self.position();
        self.expect(b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            if self.budget.string_overflows(out.len()) {
                return Err(SyntaxError::new(Code::StringTooLong, start));
            }
            match self.peek() {
                None => return Err(self.error(Code::JsonSyntax)),
                Some(b'"') => {
                    self.bump();
                    break;
                }
                Some(b'\\') => {
                    let escape_position = self.position();
                    self.bump();
                    let character = self.escape(escape_position)?;
                    let mut buffer = [0_u8; 4];
                    out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                }
                Some(byte) if byte < 0x20 => return Err(self.error(Code::JsonSyntax)),
                Some(byte) => {
                    self.bump();
                    out.push(byte);
                }
            }
        }
        // Raw bytes came from a `&str` and escapes were encoded as UTF-8.
        String::from_utf8(out).map_err(|_| SyntaxError::new(Code::JsonSyntax, start))
    }

    /// The escape after a backslash at `position`.
    fn escape(&mut self, position: Position) -> Result<char, SyntaxError> {
        let character = match self.bump() {
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                let first = self.hex4()?;
                match first {
                    0xd800..=0xdbff => {
                        if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                            return Err(SyntaxError::new(Code::JsonSyntax, position));
                        }
                        let second = self.hex4()?;
                        if !(0xdc00..=0xdfff).contains(&second) {
                            return Err(SyntaxError::new(Code::JsonSyntax, position));
                        }
                        let combined = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
                        char::from_u32(combined)
                            .ok_or_else(|| SyntaxError::new(Code::JsonSyntax, position))?
                    }
                    0xdc00..=0xdfff => return Err(SyntaxError::new(Code::JsonSyntax, position)),
                    scalar => char::from_u32(scalar)
                        .ok_or_else(|| SyntaxError::new(Code::JsonSyntax, position))?,
                }
            }
            _ => return Err(SyntaxError::new(Code::JsonSyntax, position)),
        };
        Ok(character)
    }

    fn hex4(&mut self) -> Result<u32, SyntaxError> {
        let mut value = 0_u32;
        for _ in 0..4 {
            let digit = self
                .peek()
                .and_then(|byte| char::from(byte).to_digit(16))
                .ok_or_else(|| self.error(Code::JsonSyntax))?;
            self.bump();
            value = value * 16 + digit;
        }
        Ok(value)
    }
}
