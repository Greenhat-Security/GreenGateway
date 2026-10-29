//! Sound inclusion between policy element predicates.
//!
//! Each function here answers one question: does every request the `covered`
//! element's predicate accepts also satisfy the `covering` element's? A `true`
//! is a proof, derived from the matcher's own reading of both predicates; a
//! `false` means only that no proof was found. Several answers are exact, and
//! the path-pattern one is not: it may miss an inclusion, and never invents
//! one. Every claim built on these is also checked against the canonical
//! evaluator on a witness request (see [`super::checks`]), and the
//! brute-force tests check them over small universes.

use crate::{
    path_match::path_prefix_matches,
    rbac::{
        matcher::{pattern_segments, PatternSegment},
        PrincipalMatcher, RuleDispatchMatcher,
    },
};

/// The pattern that matches every absolute path.
pub(crate) const EVERY_PATH: &str = "/**";

/// The segments of a pattern, read once, for repeated inclusion checks.
pub(crate) type Segments<'a> = Option<Vec<PatternSegment<'a>>>;

/// Read `pattern` with the matcher's segment parser.
pub(crate) fn segments(pattern: &str) -> Segments<'_> {
    pattern_segments(pattern)
}

/// Whether every path `covered` matches is a path `covering` matches.
///
/// It looks for one alignment of the two patterns that works for every path
/// `covered` accepts: a deep wildcard in `covering` may absorb any run of
/// `covered`'s segments, wildcards included, and every other `covering`
/// segment must accept everything the `covered` segment it faces accepts.
/// That is sound, because the alignment builds a match of `covering` for each
/// such path, but not complete: an inclusion that needs different alignments
/// for different paths is not found, and is not reported.
///
/// A pattern that is not absolute, or that holds a segment that never
/// matches, takes part in no inclusion: no claim is made about a pattern the
/// matcher would never let match.
pub(crate) fn pattern_covers(covering: &Segments<'_>, covered: &Segments<'_>) -> bool {
    let (Some(covering), Some(covered)) = (covering.as_deref(), covered.as_deref()) else {
        return false;
    };
    let never = |segments: &[PatternSegment<'_>]| segments.contains(&PatternSegment::Never);
    if never(covering) || never(covered) {
        return false;
    }
    // covers[i][j]: covering[i..] accepts everything covered[j..] accepts.
    // Filled from the ends, so each cell reads only cells already computed.
    let (rows, columns) = (covering.len(), covered.len());
    let mut covers = vec![vec![false; columns + 1]; rows + 1];
    for i in (0..=rows).rev() {
        for j in (0..=columns).rev() {
            covers[i][j] = if i == rows {
                // Only the empty sequence remains on the covering side.
                j == columns
            } else if j == columns {
                // Only the empty path remains to be accepted.
                covering[i..]
                    .iter()
                    .all(|segment| *segment == PatternSegment::Any)
            } else {
                match (covering[i], covered[j]) {
                    // Absorb nothing more, or absorb the covered segment and
                    // keep the deep wildcard for what follows.
                    (PatternSegment::Any, _) => covers[i + 1][j] || covers[i][j + 1],
                    (PatternSegment::Literal(left), PatternSegment::Literal(right)) => {
                        left == right && covers[i + 1][j + 1]
                    }
                    (PatternSegment::One, PatternSegment::One) => covers[i + 1][j + 1],
                    (PatternSegment::One, PatternSegment::Literal(literal)) => {
                        !literal.is_empty() && covers[i + 1][j + 1]
                    }
                    // A literal accepts one value and a single wildcard one
                    // non-empty segment; neither accepts every value, or every
                    // run of segments, the other side may produce.
                    _ => false,
                }
            };
        }
    }
    covers[0][0]
}

/// Whether a pattern matches every path.
pub(crate) fn matches_every_path(pattern: &Segments<'_>) -> bool {
    pattern_covers(pattern, &segments(EVERY_PATH))
}

/// The pattern that matches at least every path `path_prefix` selects a
/// route for, or `None` when the prefix holds a segment the pattern syntax
/// would read as a wildcard or capture, which the prefix compares literally.
///
/// A prefix `P` selects `P` itself and every path below it at a segment
/// boundary, and a prefix ending in `/` every path starting with it, so
/// `P/**` (with any trailing `/` of `P` removed) matches everything it
/// selects: a pattern that covers this one covers the route's paths.
pub(crate) fn prefix_pattern(path_prefix: &str) -> Option<String> {
    let trimmed = path_prefix.strip_suffix('/').unwrap_or(path_prefix);
    if !path_prefix.starts_with('/') {
        return None;
    }
    let literal_only = trimmed
        .split('/')
        .skip(1)
        .all(|segment| segment != "*" && segment != "**" && !segment.contains(['{', '}']));
    literal_only.then(|| format!("{trimmed}{EVERY_PATH}"))
}

/// Whether every request path the `covered` route prefix selects is one the
/// `covering` prefix selects, by the route matcher itself: the covered prefix,
/// read as a path, must be selected by the covering one, and everything below
/// a selected path is selected too. Exact.
pub(crate) fn prefix_covers(covering: &str, covered: &str) -> bool {
    covered.starts_with('/') && path_prefix_matches(covered, covering)
}

/// Whether a route with `covering` hosts admits every request a route with
/// `covered` hosts admits. Exact: an unbound route serves any host but never
/// a selected virtual upstream, and a bound one only its own hosts, compared
/// ASCII-case-insensitively.
pub(crate) fn hosts_cover(covering: &[String], covered: &[String]) -> bool {
    match (covering.is_empty(), covered.is_empty()) {
        (true, true) => true,
        (false, false) => covered.iter().all(|host| {
            covering
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(host))
        }),
        _ => false,
    }
}

/// Whether every caller the `covered` principal matcher accepts is one the
/// `covering` matcher accepts. Exact: an unconstrained matcher accepts every
/// caller, an anonymous one included, and is covered only by another; each
/// constrained field must be at least as permissive as the covered one's.
pub(crate) fn principal_covers(covering: &PrincipalMatcher, covered: &PrincipalMatcher) -> bool {
    if covering.is_unconstrained() {
        return true;
    }
    if covered.is_unconstrained() {
        return false;
    }
    let field = |covering: &[String], covered: &[String]| {
        covering.is_empty()
            || (!covered.is_empty() && covered.iter().all(|value| covering.contains(value)))
    };
    field(&covering.roles, &covered.roles)
        && field(&covering.issuers, &covered.issuers)
        && field(&covering.auth_methods, &covered.auth_methods)
        && field(&covering.principal_ids, &covered.principal_ids)
}

/// Whether a rule bound to `covering` matches in every dispatch context a
/// rule bound to `covered` does: an unbound rule matches in every context,
/// and two identical bindings compile to the same matcher. Sound, not
/// complete: two spellings of one legacy origin are not recognized as one.
pub(crate) fn dispatch_covers(
    covering: Option<&RuleDispatchMatcher>,
    covered: Option<&RuleDispatchMatcher>,
) -> bool {
    match (covering, covered) {
        (None, _) => true,
        (Some(covering), Some(covered)) => covering == covered,
        (Some(_), None) => false,
    }
}
