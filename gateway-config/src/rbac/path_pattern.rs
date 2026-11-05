//! The capture-segment grammar of a rule or rate-override path pattern, as
//! the policy's validating parse checks it.
//!
//! A path pattern is anchored and segment-based: `*` matches one segment,
//! `**` any number, and `{name}` one segment it names. The gateway's rule
//! matcher (`gateway/src/rbac/matcher.rs`) compiles a segment that looks
//! like a capture but is not one to a segment that never matches, so
//! validation refuses such a pattern up front instead of accepting a rule
//! that can never fire.
//!
//! The matcher keeps its own copy of the three grammar functions below: the
//! pure-path microbenchmark compiles them from that file, alone, and so pins
//! them there. A gateway test (`rbac::matcher::tests`) holds this copy to the
//! matcher's: a segment is refused here exactly when the matcher would
//! compile it to its never-matching segment.

/// Returns the first path segment that looks like a capture (contains `{`
/// or `}`) but does not parse as a valid one, if any.
pub fn find_malformed_capture_segment(pattern: &str) -> Option<&str> {
    let tail = pattern.strip_prefix('/')?;
    if tail.is_empty() {
        return None;
    }

    tail.split('/').find(|segment| {
        *segment != "*"
            && *segment != "**"
            && has_capture_delimiter(segment)
            && !is_capture_segment(segment)
    })
}

fn is_capture_segment(segment: &str) -> bool {
    let Some(name) = segment
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        return false;
    };

    is_valid_capture_name(name)
}

fn has_capture_delimiter(segment: &str) -> bool {
    segment.bytes().any(|byte| matches!(byte, b'{' | b'}'))
}

fn is_valid_capture_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    (first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}
