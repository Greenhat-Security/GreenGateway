//! A replay run's partial aggregate as a lossless document (issue #243): what
//! a cluster job stores after every page, under its lease's fence, together
//! with the stream position it has read through, so a replica that takes the
//! job over resumes from exactly that page and counts no record twice.
//!
//! The document is the `policy-replay-checkpoint.v1` dump the tallies of
//! [`super::job`] and [`super::impact`] write of themselves. It is not a
//! result: it holds every count a run keeps, by stable code and element
//! position, with none of a result's row caps, and it is read only by the
//! run that resumes from it. Nothing renders it.
//!
//! Reading one back is strict, because a resumed run's result must be the
//! one an uninterrupted run would have produced: every object has exactly
//! its members, every code is a stable code (lowercase ASCII letters, digits
//! and underscores, at most [`MAX_CHECKPOINT_CODE_BYTES`]), every closed code
//! names a member of its set, every count is positive -- a tally never holds
//! a zero -- and no key appears twice. Anything else is a [`CheckpointError`]
//! and the run does not resume.
//!
//! The codes a restored tally holds are borrowed from the document, which
//! outlives the run; new ones are the evaluator's own `'static` codes. Both
//! compare by content, so a resumed tally keys a count exactly as a fresh one
//! does.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

/// The schema of a run's checkpoint.
pub(crate) const CHECKPOINT_SCHEMA_VERSION: &str = "policy-replay-checkpoint.v1";
/// Longest stable code a checkpoint may hold.
pub(crate) const MAX_CHECKPOINT_CODE_BYTES: usize = 128;

/// A checkpoint this build cannot read back as a tally. Opaque: it says
/// nothing about where the document went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CheckpointError;

pub(crate) type Restored<T> = Result<T, CheckpointError>;

/// `value` as an object with exactly `members`.
pub(crate) fn exact_object<'a>(
    value: &'a Value,
    members: &[&str],
) -> Restored<&'a Map<String, Value>> {
    let Value::Object(object) = value else {
        return Err(CheckpointError);
    };
    if object.len() != members.len() || members.iter().any(|name| !object.contains_key(*name)) {
        return Err(CheckpointError);
    }
    Ok(object)
}

/// One member of an object [`exact_object`] accepted.
pub(crate) fn member<'a>(object: &'a Map<String, Value>, name: &str) -> Restored<&'a Value> {
    object.get(name).ok_or(CheckpointError)
}

pub(crate) fn array(value: &Value) -> Restored<&[Value]> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(CheckpointError),
    }
}

/// `value` as an array of exactly `N` items.
pub(crate) fn tuple<const N: usize>(value: &Value) -> Restored<&[Value; N]> {
    array(value)?.try_into().map_err(|_| CheckpointError)
}

/// A stable code: what every `&str` a tally keys is.
pub(crate) fn code(value: &Value) -> Restored<&str> {
    match value {
        Value::String(text) if is_code(text) => Ok(text),
        _ => Err(CheckpointError),
    }
}

fn is_code(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_CHECKPOINT_CODE_BYTES
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// A non-negative total: a record count that may be zero.
pub(crate) fn total(value: &Value) -> Restored<u64> {
    value.as_u64().ok_or(CheckpointError)
}

/// A map entry's count: never zero, since a tally only holds a key it
/// counted.
pub(crate) fn count(value: &Value) -> Restored<u64> {
    match value.as_u64() {
        Some(count) if count > 0 => Ok(count),
        _ => Err(CheckpointError),
    }
}

/// A policy element's position.
pub(crate) fn position(value: &Value) -> Restored<usize> {
    value
        .as_u64()
        .and_then(|position| usize::try_from(position).ok())
        .ok_or(CheckpointError)
}

pub(crate) fn optional_position(value: &Value) -> Restored<Option<usize>> {
    match value {
        Value::Null => Ok(None),
        value => position(value).map(Some),
    }
}

/// The member of `all` whose code `value` is.
pub(crate) fn closed<T: Copy>(
    all: &[T],
    name: fn(T) -> &'static str,
    value: &Value,
) -> Restored<T> {
    let text = code(value)?;
    all.iter()
        .copied()
        .find(|item| name(*item) == text)
        .ok_or(CheckpointError)
}

/// Add one restored entry, refusing a repeated key.
pub(crate) fn insert<K: Ord>(map: &mut BTreeMap<K, u64>, key: K, value: &Value) -> Restored<()> {
    let count = count(value)?;
    match map.insert(key, count) {
        None => Ok(()),
        Some(_) => Err(CheckpointError),
    }
}

/// A map keyed by codes of a closed set, as `{code: count}`.
pub(crate) fn dump_closed<T: Copy + Ord>(
    counts: &BTreeMap<T, u64>,
    name: fn(T) -> &'static str,
) -> Value {
    Value::Object(
        counts
            .iter()
            .map(|(item, count)| (name(*item).to_owned(), Value::from(*count)))
            .collect(),
    )
}

pub(crate) fn restore_closed<T: Copy + Ord>(
    all: &[T],
    name: fn(T) -> &'static str,
    value: &Value,
) -> Restored<BTreeMap<T, u64>> {
    let Value::Object(object) = value else {
        return Err(CheckpointError);
    };
    let mut counts = BTreeMap::new();
    for (key, count) in object {
        let item = all
            .iter()
            .copied()
            .find(|item| name(*item) == key)
            .ok_or(CheckpointError)?;
        insert(&mut counts, item, count)?;
    }
    Ok(counts)
}

/// A map keyed by stable codes, written as the `{code: count}` object its
/// `Serialize` renders.
pub(crate) fn restore_codes(value: &Value) -> Restored<BTreeMap<&str, u64>> {
    let Value::Object(object) = value else {
        return Err(CheckpointError);
    };
    let mut counts = BTreeMap::new();
    for (key, count) in object {
        if !is_code(key) {
            return Err(CheckpointError);
        }
        insert(&mut counts, key.as_str(), count)?;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn a_checkpoint_is_read_back_strictly() {
        assert_eq!(code(&json!("matched_rule")), Ok("matched_rule"));
        for bad in [
            json!(""),
            json!("Matched"),
            json!("has space"),
            json!("dash-ed"),
            json!(7),
            json!("a".repeat(MAX_CHECKPOINT_CODE_BYTES + 1)),
        ] {
            assert_eq!(code(&bad), Err(CheckpointError), "{bad}");
        }
        assert_eq!(
            count(&json!(0)),
            Err(CheckpointError),
            "a tally holds no zero"
        );
        assert_eq!(count(&json!(-1)), Err(CheckpointError));
        assert_eq!(count(&json!(3)), Ok(3));
        assert_eq!(total(&json!(0)), Ok(0));
        assert_eq!(
            restore_codes(&json!({ "missing_identity": 2 })).map(|map| map.len()),
            Ok(1)
        );
        assert_eq!(
            restore_codes(&json!({ "Bad Code": 2 })),
            Err(CheckpointError)
        );
        assert_eq!(
            exact_object(&json!({ "a": 1 }), &["a", "b"]).map(|_| ()),
            Err(CheckpointError),
            "a missing member is refused"
        );
        assert_eq!(
            exact_object(&json!({ "a": 1, "b": 2, "c": 3 }), &["a", "b"]).map(|_| ()),
            Err(CheckpointError),
            "an unknown member is refused"
        );
        let mut map = BTreeMap::new();
        assert_eq!(insert(&mut map, "x", &json!(1)), Ok(()));
        assert_eq!(
            insert(&mut map, "x", &json!(1)),
            Err(CheckpointError),
            "a repeated key is refused, never summed"
        );
        assert_eq!(tuple::<2>(&json!([1, 2])).map(|items| items.len()), Ok(2));
        assert_eq!(tuple::<2>(&json!([1])).map(|_| ()), Err(CheckpointError));
    }
}
