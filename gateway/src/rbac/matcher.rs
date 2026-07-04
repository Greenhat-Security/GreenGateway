use crate::auth::Principal;

use super::rule::{PrincipalMatcher, Rule, RuleAction};

/// Precompiled first-match-wins evaluator for direct firewall rules.
#[derive(Debug, Clone)]
pub struct RuleMatcher {
    rules: Vec<CompiledRule>,
}

/// Decision returned by the first matching direct firewall rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDecision {
    pub rule_index: usize,
    pub action: RuleAction,
}

impl RuleMatcher {
    #[allow(dead_code)]
    pub fn new(rules: &[Rule]) -> Self {
        Self {
            rules: rules
                .iter()
                .enumerate()
                .map(|(rule_index, rule)| CompiledRule::new(rule_index, rule))
                .collect(),
        }
    }

    #[allow(dead_code)]
    pub fn evaluate(
        &self,
        method: &str,
        path: &str,
        principal: Option<&Principal>,
    ) -> Option<RuleDecision> {
        self.rules
            .iter()
            .find(|rule| rule.matches(method, path, principal))
            .map(|rule| RuleDecision {
                rule_index: rule.rule_index,
                action: rule.action.clone(),
            })
    }
}

pub(super) fn rule_matches(
    rule: &Rule,
    method: &str,
    path: &str,
    principal: Option<&Principal>,
) -> bool {
    CompiledRule::new(0, rule).matches(method, path, principal)
}

/// Standalone method matcher reusing the hardened, anchored implementation
/// backing `RuleMatcher`, for callers (e.g. rate-limit overrides) that need
/// the same semantics without a full `Rule`.
pub(crate) fn method_matches(methods: &[String], method: &str) -> bool {
    MethodMatcher::new(methods).matches(method)
}

/// Standalone path-pattern matcher reusing the hardened, anchored
/// implementation backing `RuleMatcher`, for callers (e.g. rate-limit
/// overrides) that need the same semantics without a full `Rule`.
pub(crate) fn path_pattern_matches(pattern: &str, path: &str) -> bool {
    PathPattern::new(pattern).matches(path)
}

/// Returns the first path segment that looks like a capture (contains `{`
/// or `}`) but does not parse as a valid one, if any. `PathSegment::new`
/// silently compiles such a segment to `PathSegment::Never`, which never
/// matches any request — reused here so policy validation can reject a
/// malformed pattern up front instead of persisting a rule that can never
/// fire.
pub(crate) fn find_malformed_capture_segment(pattern: &str) -> Option<&str> {
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

#[derive(Debug, Clone)]
struct CompiledRule {
    rule_index: usize,
    enabled: bool,
    methods: MethodMatcher,
    path: PathPattern,
    principal: PrincipalMatcher,
    action: RuleAction,
}

impl CompiledRule {
    fn new(rule_index: usize, rule: &Rule) -> Self {
        Self {
            rule_index,
            enabled: rule.enabled,
            methods: MethodMatcher::new(&rule.methods),
            path: PathPattern::new(&rule.path),
            principal: rule.principal.clone(),
            action: rule.action.clone(),
        }
    }

    fn matches(&self, method: &str, path: &str, principal: Option<&Principal>) -> bool {
        self.enabled
            && self.methods.matches(method)
            && self.path.matches(path)
            && self.principal.matches(principal)
    }
}

#[derive(Debug, Clone)]
enum MethodMatcher {
    Any,
    Exact(Vec<String>),
}

impl MethodMatcher {
    fn new(methods: &[String]) -> Self {
        if methods.is_empty() {
            return Self::Any;
        }

        let mut exact_methods = Vec::with_capacity(methods.len());
        for method in methods {
            let method = method.trim();
            if method == "*" {
                return Self::Any;
            }
            exact_methods.push(method.to_owned());
        }

        Self::Exact(exact_methods)
    }

    fn matches(&self, method: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(methods) => methods
                .iter()
                .any(|configured| configured.eq_ignore_ascii_case(method)),
        }
    }
}

#[derive(Debug, Clone)]
struct PathPattern {
    segments: Option<Vec<PathSegment>>,
}

impl PathPattern {
    fn new(pattern: &str) -> Self {
        let segments = absolute_path_segments(pattern).map(|segments| {
            segments
                .iter()
                .map(|segment| PathSegment::new(segment))
                .collect()
        });

        Self { segments }
    }

    fn matches(&self, path: &str) -> bool {
        let Some(pattern_segments) = self.segments.as_deref() else {
            return false;
        };
        let Some(path_segments) = absolute_path_segments(path) else {
            return false;
        };

        path_segments_match(pattern_segments, &path_segments)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PathSegment {
    Literal(String),
    SingleWildcard,
    DeepWildcard,
    Capture,
    Never,
}

impl PathSegment {
    fn new(segment: &str) -> Self {
        match segment {
            "*" => Self::SingleWildcard,
            "**" => Self::DeepWildcard,
            _ if is_capture_segment(segment) => Self::Capture,
            _ if has_capture_delimiter(segment) => Self::Never,
            _ => Self::Literal(segment.to_owned()),
        }
    }

    fn matches(&self, path_segment: &str) -> bool {
        match self {
            Self::Literal(literal) => literal == path_segment,
            Self::SingleWildcard | Self::Capture => !path_segment.is_empty(),
            Self::DeepWildcard | Self::Never => false,
        }
    }
}

fn absolute_path_segments(value: &str) -> Option<Vec<&str>> {
    let tail = value.strip_prefix('/')?;

    if tail.is_empty() {
        return Some(Vec::new());
    }

    Some(tail.split('/').collect())
}

fn path_segments_match(pattern: &[PathSegment], path: &[&str]) -> bool {
    let mut reachable = vec![false; path.len() + 1];
    reachable[0] = true;

    for segment in pattern {
        let mut next_reachable = vec![false; path.len() + 1];

        if *segment == PathSegment::DeepWildcard {
            let mut can_reach_here = false;
            for index in 0..=path.len() {
                can_reach_here |= reachable[index];
                next_reachable[index] = can_reach_here;
            }
        } else {
            for (index, path_segment) in path.iter().enumerate() {
                if reachable[index] && segment.matches(path_segment) {
                    next_reachable[index + 1] = true;
                }
            }
        }

        reachable = next_reachable;
    }

    reachable[path.len()]
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::{Config as ProptestConfig, TestRunner};

    use super::*;
    use crate::auth::{AuthMethod, Principal};

    #[test]
    fn example_rule_matches_one_user_segment_for_role() {
        let matcher = RuleMatcher::new(&[Rule {
            id: None,
            enabled: true,
            methods: vec!["GET".to_owned()],
            path: "/api/users/*".to_owned(),
            principal: PrincipalMatcher {
                roles: vec!["support".to_owned()],
                auth_methods: Vec::new(),
                principal_ids: Vec::new(),
            },
            action: RuleAction::Allow,
        }]);
        let principal = test_principal("user-123", &["support"], AuthMethod::Bearer);

        assert_eq!(
            matcher.evaluate("GET", "/api/users/42", Some(&principal)),
            Some(RuleDecision {
                rule_index: 0,
                action: RuleAction::Allow,
            })
        );
        assert_eq!(
            matcher.evaluate("GET", "/api/users/42/sessions", Some(&principal)),
            None
        );
        assert_eq!(
            matcher.evaluate("GET", "/api/users", Some(&principal)),
            None
        );
        assert_eq!(matcher.evaluate("GET", "/api/users/42", None), None);
    }

    #[test]
    fn path_patterns_are_anchored_to_whole_segments() {
        let user_matcher = RuleMatcher::new(&[rule(&[], "/api/users/*", RuleAction::Allow)]);

        assert_eq!(
            user_matcher.evaluate("GET", "/api/users/42", None),
            Some(RuleDecision {
                rule_index: 0,
                action: RuleAction::Allow,
            })
        );
        assert_eq!(
            user_matcher.evaluate("GET", "/api/users/42/extra", None),
            None
        );
        assert_eq!(user_matcher.evaluate("GET", "/api/usersXYZ", None), None);

        let deep_matcher = RuleMatcher::new(&[rule(&[], "/api/**", RuleAction::Deny)]);
        assert_eq!(deep_matcher.evaluate("GET", "/apiFOO", None), None);
    }

    #[test]
    fn deep_wildcard_matches_zero_or_more_complete_segments() {
        let matcher = RuleMatcher::new(&[rule(&[], "/api/**", RuleAction::Allow)]);

        assert_eq!(
            matcher.evaluate("GET", "/api", None),
            Some(RuleDecision {
                rule_index: 0,
                action: RuleAction::Allow,
            })
        );
        assert_eq!(
            matcher.evaluate("GET", "/api/a/b/c", None),
            Some(RuleDecision {
                rule_index: 0,
                action: RuleAction::Allow,
            })
        );
        assert_eq!(matcher.evaluate("GET", "/apiFOO", None), None);
    }

    #[test]
    fn capture_matches_exactly_one_non_empty_segment() {
        let matcher = RuleMatcher::new(&[rule(&[], "/api/{name}/profile", RuleAction::Allow)]);

        assert_eq!(
            matcher.evaluate("GET", "/api/alice/profile", None),
            Some(RuleDecision {
                rule_index: 0,
                action: RuleAction::Allow,
            })
        );
        assert_eq!(matcher.evaluate("GET", "/api//profile", None), None);
        assert_eq!(
            matcher.evaluate("GET", "/api/alice/photos/profile", None),
            None
        );
    }

    #[test]
    fn method_matching_is_exact_case_insensitive_token_matching() {
        let matcher = RuleMatcher::new(&[rule(&["GET"], "/data", RuleAction::Allow)]);

        assert_eq!(
            matcher.evaluate("get", "/data", None),
            Some(RuleDecision {
                rule_index: 0,
                action: RuleAction::Allow,
            })
        );
        assert_eq!(matcher.evaluate("GETX", "/data", None), None);
        assert_eq!(matcher.evaluate("POST", "/data", None), None);
    }

    #[test]
    fn first_matching_rule_wins() {
        let matcher = RuleMatcher::new(&[
            rule(&["GET"], "/admin/**", RuleAction::Deny),
            rule(&["GET"], "/admin/settings", RuleAction::Allow),
        ]);

        assert_eq!(
            matcher.evaluate("GET", "/admin/settings", None),
            Some(RuleDecision {
                rule_index: 0,
                action: RuleAction::Deny,
            })
        );
    }

    #[test]
    fn disabled_rules_are_skipped_by_first_match_evaluation() {
        let mut disabled_deny = rule(&["GET"], "/admin/**", RuleAction::Deny);
        disabled_deny.enabled = false;
        let matcher = RuleMatcher::new(&[
            disabled_deny,
            rule(&["GET"], "/admin/settings", RuleAction::Allow),
        ]);

        assert_eq!(
            matcher.evaluate("GET", "/admin/settings", None),
            Some(RuleDecision {
                rule_index: 1,
                action: RuleAction::Allow,
            })
        );
    }

    #[test]
    fn malformed_capture_segments_never_match() {
        let matcher = RuleMatcher::new(&[rule(&[], "/api/{bad-name}", RuleAction::Allow)]);

        assert_eq!(matcher.evaluate("GET", "/api/alice", None), None);
    }

    #[test]
    fn find_malformed_capture_segment_flags_capture_like_but_invalid_segments() {
        let malformed = [
            "/api/{bad-name}",
            "/api/{}",
            "/api/{id}extra",
            "/api/{123}",
            "/api/prefix{id}",
        ];
        for pattern in malformed {
            assert!(
                find_malformed_capture_segment(pattern).is_some(),
                "expected {pattern:?} to be flagged as malformed"
            );
        }

        let valid = ["/api/{id}", "/api/*", "/api/**", "/api/{_id}", "/", "/api"];
        for pattern in valid {
            assert_eq!(
                find_malformed_capture_segment(pattern),
                None,
                "expected {pattern:?} to be accepted"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(160))]

        #[test]
        fn path_pattern_matching_matches_reference(
            pattern in path_pattern_strategy(),
            path in request_path_strategy(),
        ) {
            let actual = PathPattern::new(&pattern).matches(&path);
            let expected = reference_pattern_matches(&pattern, &path);

            prop_assert_eq!(actual, expected, "pattern={:?} path={:?}", pattern, path);
        }

        #[test]
        fn generated_negative_path_cases_are_rejected(
            (pattern, path) in non_matching_pattern_path_strategy(),
        ) {
            prop_assert!(
                !reference_pattern_matches(&pattern, &path),
                "negative generator produced a matching case: pattern={pattern:?} path={path:?}"
            );
            prop_assert!(!PathPattern::new(&pattern).matches(&path));
        }

        #[test]
        fn optimized_rule_matcher_matches_naive_first_match_scan(
            rules in rule_list_strategy(),
            method in method_strategy(),
            path in request_path_strategy(),
            principal in optional_principal_strategy(),
        ) {
            let matcher = RuleMatcher::new(&rules);
            let actual = matcher.evaluate(&method, &path, principal.as_ref());
            let expected = reference_first_match(&rules, &method, &path, principal.as_ref());

            prop_assert_eq!(actual, expected);
        }
    }

    #[test]
    fn pattern_generator_exercises_negative_space() {
        let mut runner = TestRunner::new(ProptestConfig::with_cases(64));
        let strategy = (path_pattern_strategy(), request_path_strategy());
        let mut saw_negative = false;

        for _ in 0..64 {
            let (pattern, path) = strategy
                .new_tree(&mut runner)
                .expect("path strategy should generate values")
                .current();

            if !reference_pattern_matches(&pattern, &path) {
                saw_negative = true;
                assert!(!PathPattern::new(&pattern).matches(&path));
            }
        }

        assert!(
            saw_negative,
            "path generator produced no non-matching cases"
        );
    }

    fn reference_first_match(
        rules: &[Rule],
        method: &str,
        path: &str,
        principal: Option<&Principal>,
    ) -> Option<RuleDecision> {
        rules
            .iter()
            .enumerate()
            .find(|(_, rule)| reference_rule_matches(rule, method, path, principal))
            .map(|(rule_index, rule)| RuleDecision {
                rule_index,
                action: rule.action.clone(),
            })
    }

    fn reference_rule_matches(
        rule: &Rule,
        method: &str,
        path: &str,
        principal: Option<&Principal>,
    ) -> bool {
        reference_method_matches(&rule.methods, method)
            && rule.enabled
            && reference_pattern_matches(&rule.path, path)
            && rule.principal.matches(principal)
    }

    fn reference_method_matches(methods: &[String], method: &str) -> bool {
        methods.is_empty()
            || methods.iter().any(|configured| {
                let configured = configured.trim();
                configured == "*" || configured.eq_ignore_ascii_case(method)
            })
    }

    fn reference_pattern_matches(pattern: &str, path: &str) -> bool {
        let Some(pattern_segments) = reference_absolute_segments(pattern) else {
            return false;
        };
        let Some(path_segments) = reference_absolute_segments(path) else {
            return false;
        };

        reference_segments_match(&pattern_segments, &path_segments)
    }

    fn reference_absolute_segments(value: &str) -> Option<Vec<&str>> {
        let tail = value.strip_prefix('/')?;

        if tail.is_empty() {
            return Some(Vec::new());
        }

        Some(tail.split('/').collect())
    }

    fn reference_segments_match(pattern: &[&str], path: &[&str]) -> bool {
        let Some((head, pattern_tail)) = pattern.split_first() else {
            return path.is_empty();
        };

        if *head == "**" {
            return reference_segments_match(pattern_tail, path)
                || path
                    .split_first()
                    .is_some_and(|(_, path_tail)| reference_segments_match(pattern, path_tail));
        }

        path.split_first().is_some_and(|(path_head, path_tail)| {
            reference_segment_matches(head, path_head)
                && reference_segments_match(pattern_tail, path_tail)
        })
    }

    fn reference_segment_matches(pattern: &str, path: &str) -> bool {
        match pattern {
            "*" => !path.is_empty(),
            _ if reference_is_capture_segment(pattern) => !path.is_empty(),
            _ if pattern.bytes().any(|byte| matches!(byte, b'{' | b'}')) => false,
            _ => pattern == path,
        }
    }

    fn reference_is_capture_segment(segment: &str) -> bool {
        let Some(name) = segment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        else {
            return false;
        };

        reference_is_valid_capture_name(name)
    }

    fn reference_is_valid_capture_name(name: &str) -> bool {
        let mut chars = name.chars();
        let Some(first) = chars.next() else {
            return false;
        };

        (first.is_ascii_alphabetic() || first == '_')
            && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    }

    fn path_pattern_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(pattern_segment_strategy(), 0..7)
            .prop_map(|segments| absolute_path_from_segments(&segments))
    }

    fn request_path_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(path_segment_strategy(), 0..7)
            .prop_map(|segments| absolute_path_from_segments(&segments))
    }

    fn non_matching_pattern_path_strategy() -> impl Strategy<Value = (String, String)> {
        prop_oneof![
            Just(("/api/users/*".to_owned(), "/api/users".to_owned())),
            Just(("/api/users/*".to_owned(), "/api/users/42/extra".to_owned())),
            Just(("/api/users/*".to_owned(), "/api/usersXYZ".to_owned())),
            Just(("/api/**".to_owned(), "/apiFOO".to_owned())),
            Just(("/api/{name}/profile".to_owned(), "/api//profile".to_owned())),
            Just((
                "/api/{name}/profile".to_owned(),
                "/api/alice/photos/profile".to_owned()
            )),
            path_segment_strategy().prop_map(|segment| {
                (
                    format!("/root/{segment}/leaf"),
                    format!("/root/{segment}/leaf/extra"),
                )
            }),
        ]
    }

    fn pattern_segment_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            5 => path_segment_strategy(),
            2 => Just("*".to_owned()),
            2 => Just("**".to_owned()),
            2 => capture_name_strategy().prop_map(|name| format!("{{{name}}}")),
            1 => Just("{bad-name}".to_owned()),
            1 => Just("prefix{bad}".to_owned()),
            1 => Just("bad}".to_owned()),
        ]
    }

    fn path_segment_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            2 => Just(String::new()),
            3 => Just("api".to_owned()),
            3 => Just("users".to_owned()),
            2 => Just("42".to_owned()),
            2 => Just("alice".to_owned()),
            1 => Just("GET".to_owned()),
            1 => Just("*".to_owned()),
            1 => Just("**".to_owned()),
            1 => Just("{id}".to_owned()),
            2 => "[a-z0-9_-]{1,5}".prop_map(|value| value),
        ]
    }

    fn capture_name_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("id".to_owned()),
            Just("_name".to_owned()),
            Just("v2".to_owned()),
            "[A-Za-z_][A-Za-z0-9_]{0,4}".prop_map(|value| value),
        ]
    }

    fn rule_list_strategy() -> impl Strategy<Value = Vec<Rule>> {
        prop::collection::vec(rule_strategy(), 0..16)
    }

    fn rule_strategy() -> impl Strategy<Value = Rule> {
        (
            any::<bool>(),
            prop::collection::vec(configured_method_strategy(), 0..4),
            path_pattern_strategy(),
            principal_matcher_strategy(),
            action_strategy(),
        )
            .prop_map(|(enabled, methods, path, principal, action)| Rule {
                id: None,
                enabled,
                methods,
                path,
                principal,
                action,
            })
    }

    fn configured_method_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("*".to_owned()),
            Just("GET".to_owned()),
            Just("get".to_owned()),
            Just(" GET ".to_owned()),
            Just("POST".to_owned()),
            Just("HEAD".to_owned()),
            Just("GETX".to_owned()),
        ]
    }

    fn method_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("GET".to_owned()),
            Just("get".to_owned()),
            Just("POST".to_owned()),
            Just("HEAD".to_owned()),
            Just("DELETE".to_owned()),
            Just("GETX".to_owned()),
            Just(String::new()),
        ]
    }

    fn principal_matcher_strategy() -> impl Strategy<Value = PrincipalMatcher> {
        (
            prop::collection::vec(role_strategy(), 0..3),
            prop::collection::vec(auth_method_name_strategy(), 0..2),
            prop::collection::vec(principal_id_strategy(), 0..2),
        )
            .prop_map(|(roles, auth_methods, principal_ids)| PrincipalMatcher {
                roles,
                auth_methods,
                principal_ids,
            })
    }

    fn optional_principal_strategy() -> impl Strategy<Value = Option<Principal>> {
        prop_oneof![Just(None), principal_strategy().prop_map(Some)]
    }

    fn principal_strategy() -> impl Strategy<Value = Principal> {
        (
            principal_id_strategy(),
            prop::collection::vec(role_strategy(), 0..3),
            prop_oneof![Just(AuthMethod::Bearer), Just(AuthMethod::Cookie)],
        )
            .prop_map(|(user_id, roles, auth_method)| Principal {
                user_id,
                email: Some("user@example.test".to_owned()),
                org_id: None,
                roles,
                session_id: "session-123".to_owned(),
                auth_method,
            })
    }

    fn auth_method_name_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("bearer_token".to_owned()),
            Just("session_cookie".to_owned()),
        ]
    }

    fn role_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("admin".to_owned()),
            Just("support".to_owned()),
            Just("reader".to_owned()),
            Just("writer".to_owned()),
        ]
    }

    fn principal_id_strategy() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("user-123".to_owned()),
            Just("user-999".to_owned()),
            Just("service-account".to_owned()),
        ]
    }

    fn action_strategy() -> impl Strategy<Value = RuleAction> {
        prop_oneof![
            Just(RuleAction::Allow),
            Just(RuleAction::Deny),
            Just(RuleAction::Shadow),
        ]
    }

    fn absolute_path_from_segments(segments: &[String]) -> String {
        if segments.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", segments.join("/"))
        }
    }

    fn rule(methods: &[&str], path: &str, action: RuleAction) -> Rule {
        Rule {
            id: None,
            enabled: true,
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            path: path.to_owned(),
            principal: PrincipalMatcher::default(),
            action,
        }
    }

    fn test_principal(user_id: &str, roles: &[&str], auth_method: AuthMethod) -> Principal {
        Principal {
            user_id: user_id.to_owned(),
            email: Some("user@example.test".to_owned()),
            org_id: None,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            session_id: "session-123".to_owned(),
            auth_method,
        }
    }
}
