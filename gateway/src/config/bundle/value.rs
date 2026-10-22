//! The typed value forms bundle documents use where a plain JSON value is not
//! safe or not exact: secret references, unresolved placeholders, and
//! decimals.
//!
//! In `v1alpha1` the deployment document's settings come from the field
//! catalog (issue #242, PR 3), which attaches these forms to the fields that
//! need them: every sensitive field accepts only a [`SecretReference`], and
//! every fractional field only a [`Decimal`]. The forms are fixed here, with
//! the reader, so the published schema and the canonical form can define them
//! before any field uses them.

use crate::connections::{model::MAX_SECRET_ID_BYTES, secret::is_valid_opaque_id};

use super::{
    diagnostic::Code,
    syntax::{Node, Value},
};

/// The member of a secret reference object.
pub(crate) const SECRET_MEMBER: &str = "secret";
/// The member of an unresolved placeholder object.
pub(crate) const UNRESOLVED_MEMBER: &str = "unresolved";

/// `{ secret: <alias-id> }`: an opaque #240 alias ID in a sensitive field.
///
/// The form cannot express a value, an environment-variable name, a file
/// path, a provider locator or ciphertext: the ID follows ADR-0006's opaque
/// grammar and lives in the one alias namespace #240 maintains. Resolving it
/// is never the reader's job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SecretReference {
    alias_id: String,
}

impl SecretReference {
    /// Reads a sensitive field.
    ///
    /// A plain string is refused as an inline value without being kept or
    /// echoed; an unresolved placeholder is refused as unresolved.
    pub(crate) fn from_node(node: &Node) -> Result<Self, Code> {
        let members = match &node.value {
            Value::String(_) | Value::Integer(_) | Value::Number(_) | Value::Bool(_) => {
                return Err(Code::InlineSecretValue)
            }
            Value::Object(members) => members,
            Value::Null | Value::Array(_) => return Err(Code::InvalidSecretReference),
        };
        if Unresolved::from_node(node).is_some() {
            return Err(Code::Unresolved);
        }
        match members.as_slice() {
            [member] if member.key == SECRET_MEMBER => match member.value.as_str() {
                Some(alias_id) if is_valid_opaque_id(alias_id, MAX_SECRET_ID_BYTES) => Ok(Self {
                    alias_id: alias_id.to_owned(),
                }),
                _ => Err(Code::InvalidSecretReference),
            },
            _ => Err(Code::InvalidSecretReference),
        }
    }

    pub(crate) fn alias_id(&self) -> &str {
        &self.alias_id
    }
}

/// Why an export, conversion or template could not or would not supply a
/// value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UnresolvedReason {
    LegacyInlineSecret,
    TemplateValue,
    NotRepresentable,
}

impl UnresolvedReason {
    pub(crate) const ALL: &'static [Self] = &[
        Self::LegacyInlineSecret,
        Self::TemplateValue,
        Self::NotRepresentable,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::LegacyInlineSecret => "legacy_inline_secret",
            Self::TemplateValue => "template_value",
            Self::NotRepresentable => "not_representable",
        }
    }
}

/// `{ unresolved: <reason> }`: a placeholder that marks a value as missing.
///
/// No field accepts one. Validation always fails on it with
/// `reference.unresolved`, so an output that contains one can never be
/// mistaken for a deployable bundle.
pub(crate) struct Unresolved;

impl Unresolved {
    /// The placeholder's reason, when `node` has the placeholder's shape.
    /// `Some(Err(_))` is the shape with an unknown reason, which is refused
    /// the same way.
    pub(crate) fn from_node(node: &Node) -> Option<Result<UnresolvedReason, Code>> {
        let members = node.as_object()?;
        let [member] = members else {
            return None;
        };
        if member.key != UNRESOLVED_MEMBER {
            return None;
        }
        let reason = member.value.as_str().and_then(|reason| {
            UnresolvedReason::ALL
                .iter()
                .copied()
                .find(|known| known.as_str() == reason)
        });
        Some(reason.ok_or(Code::Unresolved))
    }
}

/// The longest integer part of a decimal.
const MAX_DECIMAL_INTEGER_DIGITS: usize = 16;
/// The longest fraction of a decimal.
const MAX_DECIMAL_FRACTION_DIGITS: usize = 6;

/// A fractional setting, written as a string in the grammar
/// `^(0|[1-9][0-9]{0,15})(\.[0-9]{1,6})?$`.
///
/// JSON numbers in bundle documents are integers only, so a fraction is
/// never parsed as a floating-point number from JSON. The canonical form is
/// the shortest exact spelling (`"0.10"` becomes `"0.1"`, `"2.0"` becomes
/// `"2"`), and [`Decimal::as_f64`] is exactly what parsing the same text from
/// an environment variable produces.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Decimal {
    canonical: String,
    value: f64,
}

impl Decimal {
    pub(crate) fn from_node(node: &Node) -> Result<Self, Code> {
        let Some(text) = node.as_str() else {
            return Err(Code::InvalidDecimal);
        };
        Self::parse(text).ok_or(Code::InvalidDecimal)
    }

    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (integer, fraction) = match text.split_once('.') {
            Some((integer, fraction)) => (integer, Some(fraction)),
            None => (text, None),
        };
        let integer_ok = match integer.as_bytes() {
            [b'0'] => true,
            [first, rest @ ..] => {
                (b'1'..=b'9').contains(first)
                    && rest.len() < MAX_DECIMAL_INTEGER_DIGITS
                    && rest.iter().all(u8::is_ascii_digit)
            }
            [] => false,
        };
        let fraction_ok = fraction.is_none_or(|fraction| {
            (1..=MAX_DECIMAL_FRACTION_DIGITS).contains(&fraction.len())
                && fraction.bytes().all(|byte| byte.is_ascii_digit())
        });
        if !integer_ok || !fraction_ok {
            return None;
        }
        let canonical = match fraction.map(|fraction| fraction.trim_end_matches('0')) {
            Some(fraction) if !fraction.is_empty() => format!("{integer}.{fraction}"),
            _ => integer.to_owned(),
        };
        let value = canonical.parse::<f64>().ok()?;
        Some(Self { canonical, value })
    }

    /// The shortest exact spelling, which is what the canonical form holds.
    pub(crate) fn canonical(&self) -> &str {
        &self.canonical
    }

    pub(crate) fn as_f64(&self) -> f64 {
        self.value
    }
}
