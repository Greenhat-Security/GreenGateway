//! Request path templating for discovery inventory.
//!
//! The templater has two complementary mechanisms:
//!
//! - Stateless ID recognition templates unambiguous identifier-looking segments on
//!   the first observation. It recognizes ASCII decimal numbers, UUIDs in
//!   canonical hyphenated form, compact 32-character hex UUID/hash forms, common
//!   hex hash lengths of 32, 40, and 64 characters, and ULIDs. Hex recognition is
//!   intentionally limited to those long lengths so short literal words such as
//!   `deadbeef` remain literal.
//! - Stateful learning tracks distinct non-ID values at varying positions within
//!   same-shaped paths. A position is learned as `{param}` after four distinct
//!   values by default. Low-cardinality enum-like paths such as
//!   `/status/active`, `/status/pending`, and `/status/closed` therefore remain
//!   literal unless more evidence arrives. Once a position exceeds the distinct
//!   value cap, the learner drops the set and keeps only a lightweight learned
//!   marker, bounding memory for high-cardinality positions.
//!
//! Base64url-looking segments are not recognized by alphabet alone because that
//! alphabet overlaps too heavily with ordinary slugs and tokens. They can still
//! become `{param}` through cardinality learning.

use std::collections::HashSet;

const ID_PLACEHOLDER: &str = "{id}";
const PARAM_PLACEHOLDER: &str = "{param}";
const DEFAULT_DISTINCT_VALUE_CAP: usize = 64;
const DEFAULT_LEARNED_TEMPLATE_THRESHOLD: usize = 4;
const DEFAULT_PATH_TEMPLATE_MAX_GROUPS: usize = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PathTemplateConfig {
    pub distinct_value_cap: usize,
    pub learned_template_threshold: usize,
    /// Maximum number of learned path-shape groups. Zero keeps the learner
    /// unbounded for standalone callers that have not opted into a cap.
    pub max_groups: usize,
}

impl Default for PathTemplateConfig {
    fn default() -> Self {
        Self {
            distinct_value_cap: DEFAULT_DISTINCT_VALUE_CAP,
            learned_template_threshold: DEFAULT_LEARNED_TEMPLATE_THRESHOLD,
            max_groups: DEFAULT_PATH_TEMPLATE_MAX_GROUPS,
        }
    }
}

impl PathTemplateConfig {
    fn learned_reason(self, distinct_count: usize) -> Option<LearnedReason> {
        if distinct_count > self.distinct_value_cap {
            Some(LearnedReason::Overflow)
        } else if self.learned_template_threshold > 0
            && distinct_count >= self.learned_template_threshold
        {
            Some(LearnedReason::Cardinality)
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct PathTemplateLearner {
    config: PathTemplateConfig,
    groups: Vec<ShapeGroup>,
}

impl PathTemplateLearner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: PathTemplateConfig) -> Self {
        Self {
            config,
            groups: Vec::new(),
        }
    }

    pub fn observe(&mut self, path: &str) -> String {
        let segments = split_path(path);
        if segments.is_empty() {
            return "/".to_owned();
        }

        let group_index = match self.find_group_index(&segments) {
            Some(index) => index,
            None => {
                if self.config.max_groups != 0 && self.groups.len() >= self.config.max_groups {
                    return template_stateless_segments(&segments);
                }
                self.groups.push(ShapeGroup::from_segments(&segments));
                self.groups.len() - 1
            }
        };

        let group = &mut self.groups[group_index];
        group.observe(&segments, self.config);
        group.template(&segments)
    }

    pub fn template(&self, path: &str) -> String {
        let segments = split_path(path);
        if segments.is_empty() {
            return "/".to_owned();
        }

        self.find_group_index(&segments).map_or_else(
            || template_stateless_segments(&segments),
            |index| self.groups[index].template(&segments),
        )
    }

    fn find_group_index(&self, segments: &[&str]) -> Option<usize> {
        let mut best_match = None;

        for (index, group) in self.groups.iter().enumerate() {
            let Some(score) = group.match_score(segments) else {
                continue;
            };

            if best_match
                .map(|(_, best_score)| score.is_better_than(best_score))
                .unwrap_or(true)
            {
                best_match = Some((index, score));
            }
        }

        best_match.map(|(index, _)| index)
    }
}

pub fn template_stateless(path: &str) -> String {
    template_stateless_segments(&split_path(path))
}

#[derive(Clone, Debug)]
struct ShapeGroup {
    positions: Vec<SegmentPosition>,
}

impl ShapeGroup {
    fn from_segments(segments: &[&str]) -> Self {
        Self {
            positions: segments
                .iter()
                .map(|segment| SegmentPosition::from_segment(segment))
                .collect(),
        }
    }

    fn match_score(&self, segments: &[&str]) -> Option<MatchScore> {
        if segments.len() != self.positions.len() {
            return None;
        }

        let mut score = MatchScore::default();

        for (position, segment) in self.positions.iter().zip(segments.iter()) {
            position.score_match(segment, &mut score)?;
        }

        if score.exact_matches == 0 || (score.literal_matches == 0 && score.new_variations > 0) {
            return None;
        }

        Some(score)
    }

    fn observe(&mut self, segments: &[&str], config: PathTemplateConfig) {
        for (position, segment) in self.positions.iter_mut().zip(segments.iter()) {
            position.observe(segment, config);
        }
    }

    fn template(&self, segments: &[&str]) -> String {
        join_template_segments(
            self.positions
                .iter()
                .zip(segments.iter())
                .map(|(position, segment)| position.template_segment(segment))
                .collect(),
        )
    }
}

#[derive(Clone, Debug)]
enum SegmentPosition {
    Literal(String),
    Varying { values: HashSet<String> },
    Learned { reason: LearnedReason },
    ImmediateId,
}

impl SegmentPosition {
    fn from_segment(segment: &str) -> Self {
        if is_well_known_identifier(segment) {
            Self::ImmediateId
        } else {
            Self::Literal(segment.to_owned())
        }
    }

    fn score_match(&self, segment: &str, score: &mut MatchScore) -> Option<()> {
        match self {
            Self::Literal(value) if value == segment => {
                score.exact_matches += 1;
                score.literal_matches += 1;
                Some(())
            }
            Self::Literal(_) if !is_well_known_identifier(segment) => {
                score.new_variations += 1;
                Some(())
            }
            Self::Varying { .. } if !is_well_known_identifier(segment) => Some(()),
            Self::Learned { .. } => Some(()),
            Self::ImmediateId if is_well_known_identifier(segment) => {
                score.exact_matches += 1;
                Some(())
            }
            _ => None,
        }
    }

    fn observe(&mut self, segment: &str, config: PathTemplateConfig) {
        match self {
            Self::Literal(value) if value == segment => {}
            Self::Literal(value) => {
                debug_assert!(!is_well_known_identifier(segment));
                let mut values = HashSet::new();
                values.insert(value.clone());
                values.insert(segment.to_owned());
                *self = Self::from_values(values, config);
            }
            Self::Varying { values } => {
                debug_assert!(!is_well_known_identifier(segment));
                let learned_reason = if values.insert(segment.to_owned()) {
                    config.learned_reason(values.len())
                } else {
                    None
                };

                if let Some(reason) = learned_reason {
                    *self = Self::Learned { reason };
                }
            }
            Self::Learned { .. } | Self::ImmediateId => {}
        }
    }

    fn from_values(values: HashSet<String>, config: PathTemplateConfig) -> Self {
        if let Some(reason) = config.learned_reason(values.len()) {
            Self::Learned { reason }
        } else {
            Self::Varying { values }
        }
    }

    fn template_segment(&self, segment: &str) -> String {
        match self {
            Self::Learned {
                reason: LearnedReason::Cardinality | LearnedReason::Overflow,
            } => PARAM_PLACEHOLDER.to_owned(),
            _ if is_well_known_identifier(segment) => ID_PLACEHOLDER.to_owned(),
            _ => segment.to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LearnedReason {
    Cardinality,
    Overflow,
}

#[derive(Clone, Copy, Debug, Default)]
struct MatchScore {
    exact_matches: usize,
    literal_matches: usize,
    new_variations: usize,
}

impl MatchScore {
    fn is_better_than(self, other: Self) -> bool {
        self.exact_matches > other.exact_matches
            || (self.exact_matches == other.exact_matches
                && self.literal_matches > other.literal_matches)
            || (self.exact_matches == other.exact_matches
                && self.literal_matches == other.literal_matches
                && self.new_variations < other.new_variations)
    }
}

fn template_stateless_segments(segments: &[&str]) -> String {
    join_template_segments(
        segments
            .iter()
            .map(|segment| {
                if is_well_known_identifier(segment) {
                    ID_PLACEHOLDER.to_owned()
                } else {
                    (*segment).to_owned()
                }
            })
            .collect(),
    )
}

fn split_path(path: &str) -> Vec<&str> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let path = path.strip_prefix('/').unwrap_or(path);

    if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    }
}

fn join_template_segments(segments: Vec<String>) -> String {
    if segments.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn is_well_known_identifier(segment: &str) -> bool {
    is_decimal_number(segment)
        || is_hyphenated_uuid(segment)
        || is_long_hex_identifier(segment)
        || is_ulid(segment)
}

fn is_decimal_number(segment: &str) -> bool {
    !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_hyphenated_uuid(segment: &str) -> bool {
    const HYPHEN_POSITIONS: [usize; 4] = [8, 13, 18, 23];

    segment.len() == 36
        && segment.bytes().enumerate().all(|(index, byte)| {
            if HYPHEN_POSITIONS.contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn is_long_hex_identifier(segment: &str) -> bool {
    matches!(segment.len(), 32 | 40 | 64) && segment.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_ulid(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    bytes.len() == 26
        && matches!(bytes[0], b'0'..=b'7')
        && bytes.iter().all(|byte| is_crockford_base32(*byte))
}

fn is_crockford_base32(byte: u8) -> bool {
    matches!(
        byte.to_ascii_uppercase(),
        b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_well_known_identifiers_on_first_observation() {
        let mut learner = PathTemplateLearner::new();
        let cases = [
            ("/users/123", "/users/{id}"),
            ("/users/999999999", "/users/{id}"),
            (
                "/sessions/550e8400-e29b-41d4-a716-446655440000",
                "/sessions/{id}",
            ),
            (
                "/sessions/550E8400E29B41D4A716446655440000",
                "/sessions/{id}",
            ),
            ("/files/d41d8cd98f00b204e9800998ecf8427e", "/files/{id}"),
            (
                "/files/da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "/files/{id}",
            ),
            (
                "/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "/files/{id}",
            ),
            ("/events/01ARZ3NDEKTSV4RRFFQ69G5FAV", "/events/{id}"),
        ];

        for (path, expected) in cases {
            assert_eq!(learner.observe(path), expected);
        }
    }

    #[test]
    fn does_not_template_messy_literal_segments_too_early() {
        let mut learner = PathTemplateLearner::new();
        let cases = [
            ("/v2/users", "/v2/users"),
            ("/reports/api-2024/summary", "/reports/api-2024/summary"),
            ("/assets/deadbeef/logo", "/assets/deadbeef/logo"),
            ("/skus/AB12CD34/details", "/skus/AB12CD34/details"),
            ("/posts/hello-world-2024", "/posts/hello-world-2024"),
            (
                "/tokens/abcDEF123_-abcDEF123_-",
                "/tokens/abcDEF123_-abcDEF123_-",
            ),
        ];

        for (path, expected) in cases {
            assert_eq!(learner.observe(path), expected);
        }
    }

    #[test]
    fn keeps_low_cardinality_status_values_literal() {
        let mut learner = PathTemplateLearner::new();

        assert_eq!(learner.observe("/status/active"), "/status/active");
        assert_eq!(learner.observe("/status/pending"), "/status/pending");
        assert_eq!(learner.observe("/status/closed"), "/status/closed");
        assert_eq!(learner.template("/status/active"), "/status/active");
    }

    #[test]
    fn learns_slug_parameters_after_distinct_threshold() {
        let mut learner = PathTemplateLearner::new();

        assert_eq!(learner.observe("/products/apple"), "/products/apple");
        assert_eq!(learner.observe("/products/banana"), "/products/banana");
        assert_eq!(learner.observe("/products/cherry"), "/products/cherry");
        assert_eq!(learner.observe("/products/date"), "/products/{param}");
        assert_eq!(learner.template("/products/apple"), "/products/{param}");
    }

    #[test]
    fn learned_templates_apply_to_future_paths() {
        let mut learner = PathTemplateLearner::new();

        for slug in ["apple", "banana", "cherry", "date"] {
            learner.observe(&format!("/products/{slug}"));
        }

        assert_eq!(learner.observe("/products/elderberry"), "/products/{param}");
        assert_eq!(learner.template("/products/fig"), "/products/{param}");
    }

    #[test]
    fn cardinality_overflow_drops_distinct_value_set() {
        let mut learner = PathTemplateLearner::with_config(PathTemplateConfig {
            distinct_value_cap: 3,
            learned_template_threshold: 100,
            max_groups: 0,
        });

        assert_eq!(learner.observe("/tenants/acme"), "/tenants/acme");
        assert_eq!(learner.observe("/tenants/beta"), "/tenants/beta");
        assert_eq!(learner.observe("/tenants/charlie"), "/tenants/charlie");
        assert_eq!(tracked_value_count(&learner, "tenants", 1), Some(3));

        assert_eq!(learner.observe("/tenants/delta"), "/tenants/{param}");
        assert_eq!(
            learned_reason(&learner, "tenants", 1),
            Some(LearnedReason::Overflow)
        );
        assert_eq!(tracked_value_count(&learner, "tenants", 1), None);

        for index in 0..100 {
            assert_eq!(
                learner.observe(&format!("/tenants/customer-{index}")),
                "/tenants/{param}"
            );
        }

        assert_eq!(
            learned_reason(&learner, "tenants", 1),
            Some(LearnedReason::Overflow)
        );
        assert_eq!(tracked_value_count(&learner, "tenants", 1), None);
        assert_eq!(learner.groups.len(), 1);
    }

    #[test]
    fn templating_is_stable_for_repeated_paths() {
        let mut learner = PathTemplateLearner::new();

        let path = "/users/550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(learner.observe(path), "/users/{id}");
        assert_eq!(learner.observe(path), "/users/{id}");

        for slug in ["apple", "banana", "cherry", "date"] {
            learner.observe(&format!("/products/{slug}"));
        }

        assert_eq!(learner.template("/products/apple"), "/products/{param}");
        assert_eq!(learner.observe("/products/apple"), "/products/{param}");
    }

    #[test]
    fn stateless_template_preserves_slash_shape_and_strips_query() {
        assert_eq!(template_stateless("/users/123/"), "/users/{id}/");
        assert_eq!(template_stateless("/users//123"), "/users//{id}");
        assert_eq!(template_stateless("/users/123?verbose=true"), "/users/{id}");
    }

    fn tracked_value_count(
        learner: &PathTemplateLearner,
        leading_literal: &str,
        position: usize,
    ) -> Option<usize> {
        let group = shape_group(learner, leading_literal);

        match &group.positions[position] {
            SegmentPosition::Varying { values } => Some(values.len()),
            SegmentPosition::Learned { .. } => None,
            SegmentPosition::Literal(_) | SegmentPosition::ImmediateId => Some(0),
        }
    }

    #[test]
    fn groups_are_capped_and_fall_back_to_stateless() {
        let mut learner = PathTemplateLearner::with_config(PathTemplateConfig {
            max_groups: 2,
            ..PathTemplateConfig::default()
        });

        assert_eq!(learner.observe("/a"), "/a");
        assert_eq!(learner.observe("/b"), "/b");
        assert_eq!(learner.groups.len(), 2);

        assert_eq!(learner.observe("/c"), "/c");
        assert_eq!(learner.groups.len(), 2);
        assert_eq!(learner.observe("/c"), "/c");
        assert_eq!(learner.groups.len(), 2);
    }

    fn learned_reason(
        learner: &PathTemplateLearner,
        leading_literal: &str,
        position: usize,
    ) -> Option<LearnedReason> {
        let group = shape_group(learner, leading_literal);

        match &group.positions[position] {
            SegmentPosition::Learned { reason } => Some(*reason),
            _ => None,
        }
    }

    fn shape_group<'a>(learner: &'a PathTemplateLearner, leading_literal: &str) -> &'a ShapeGroup {
        learner
            .groups
            .iter()
            .find(|group| {
                matches!(
                    group.positions.first(),
                    Some(SegmentPosition::Literal(value)) if value == leading_literal
                )
            })
            .expect("shape group should exist")
    }
}
