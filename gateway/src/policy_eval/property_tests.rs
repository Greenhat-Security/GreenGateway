//! Bounded generated contracts for the pure evaluator, without a runtime or I/O.

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, RngSeed};
use serde_json::json;

use super::*;

fn property_config() -> Config {
    Config {
        cases: 128,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(435_004),
        max_shrink_iters: 2_048,
        ..Config::default()
    }
}

fn compile(value: &Value, authority: PolicyAuthority) -> CompiledPolicy {
    CompiledPolicy::compile(&serde_json::to_vec(value).unwrap(), authority).unwrap()
}

fn principal(suffix: &str) -> Principal {
    Principal {
        user_id: format!("synthetic-subject-{suffix}"),
        issuer: Some(format!("https://{suffix}.example.test")),
        roles: vec![
            format!("synthetic-role-{suffix}"),
            "synthetic-other-role".to_owned(),
        ],
        auth_method: AuthMethod::Bearer,
        email: None,
        org_id: None,
        session_id: String::new(),
    }
}

fn context(compiled: &CompiledPolicy, suffix: &str) -> PolicyEvaluationContext {
    PolicyEvaluationContext {
        version: CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        method: Some(Method::GET),
        path: Some(format!("/synthetic/{suffix}")),
        principal: PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&principal(
            suffix,
        ))),
        target: HttpTarget::Contextless,
        request_host: HostFact::Absent,
        dispatch: None,
    }
}

// A table independent of the production matcher's decision conversion. The
// ordinal is also the alias lane's documented restrictiveness order.
fn action(code: u8) -> (&'static str, LogicalDecision, PolicyEffect) {
    match code {
        0 => ("deny", LogicalDecision::Deny, PolicyEffect::Block),
        1 => ("shadow", LogicalDecision::Deny, PolicyEffect::Observe),
        2 => ("allow", LogicalDecision::Allow, PolicyEffect::Allow),
        _ => unreachable!("bounded generated action"),
    }
}

proptest! {
    #![proptest_config(property_config())]

    #[test]
    fn generated_direct_rules_are_deterministic_and_keep_source_order(
        suffix in "[a-z]{1,24}",
        entries in proptest::collection::vec((0u8..3, any::<bool>(), any::<bool>()), 0..9),
        default_allow in any::<bool>(), shadow in any::<bool>(),
    ) {
        let path = format!("/synthetic/{suffix}");
        let other_path = format!("/unmatched/{suffix}");
        let rules: Vec<Value> = entries.iter().enumerate().map(|(index, (code, enabled, matches))| {
            json!({"id":format!("synthetic-{index}"),"enabled":enabled,
                "path":if *matches { &path } else { &other_path },"action":action(*code).0})
        }).collect();
        let value = json!({"schema_version":"0.1.0","rules":rules,
            "default_action":if default_allow { "allow" } else { "deny" },
            "enforcement_mode":if shadow { "shadow" } else { "enforce" }});
        let compiled = compile(&value, PolicyAuthority::Standalone);
        let independently_compiled = compile(&value, PolicyAuthority::Standalone);
        let input = context(&compiled, &suffix);
        let result = compiled.evaluate(&input).unwrap();
        prop_assert_eq!(&result, &compiled.evaluate(&input).unwrap());
        prop_assert_eq!(&result, &independently_compiled.evaluate(&input).unwrap());
        prop_assert_eq!(result.canonical_trace_bytes().unwrap(),
            independently_compiled.evaluate(&input).unwrap().canonical_trace_bytes().unwrap());
        prop_assert!(result.is_complete());
        prop_assert!(result.reusable_for(&input));
        prop_assert_eq!(result.limitation(), None);
        let expected = entries.iter().enumerate().find(|(_, (_, enabled, matches))| *enabled && *matches);
        if let Some((index, (code, _, _))) = expected {
            let (_, logical, effect) = action(*code);
            prop_assert_eq!(result.logical(), logical);
            prop_assert_eq!(result.effect(), effect);
            prop_assert_eq!(result.matched(), Some(RuleReference::Direct(index)));
            prop_assert_eq!(result.reason(), Reason::MatchedRule);
        } else {
            prop_assert_eq!(result.logical(), if default_allow { LogicalDecision::Allow } else { LogicalDecision::Deny });
            let effect = if default_allow { PolicyEffect::Allow } else if shadow { PolicyEffect::Observe } else { PolicyEffect::Block };
            prop_assert_eq!(result.effect(), effect);
            prop_assert_eq!(result.matched(), None);
            prop_assert_eq!(result.reason(), if default_allow { Reason::DefaultAllow } else { Reason::DefaultDeny });
        }
    }

    #[test]
    fn alias_pairs_choose_the_most_restrictive_action_across_both_identities(
        suffix in "[a-z]{1,24}",
        entries in proptest::collection::vec((0u8..3, any::<bool>()), 1..9),
    ) {
        let path = format!("/synthetic/{suffix}");
        let canonical = format!("/canonical/{suffix}");
        let rules: Vec<Value> = entries.iter().map(|(code, request_path)| {
            json!({"path":if *request_path { &path } else { &canonical },"action":action(*code).0})
        }).collect();
        let compiled = compile(&json!({"schema_version":"0.1.0","rules":rules}), PolicyAuthority::Standalone);
        let mut input = context(&compiled, &suffix);
        input.target = HttpTarget::McpAlias { canonical_path: canonical };
        let result = compiled.evaluate(&input).unwrap();
        let (expected_index, (code, _)) = entries.iter().enumerate().min_by_key(|(_, (code, _))| *code).unwrap();
        let (_, logical, effect) = action(*code);
        prop_assert_eq!(result.logical(), logical);
        prop_assert_eq!(result.effect(), effect);
        prop_assert_eq!(result.matched(), Some(RuleReference::Direct(expected_index)));
        prop_assert!(result.is_complete());
        prop_assert!(result.reusable_for(&input));
    }

    #[test]
    fn every_required_missing_fact_blocks_even_a_permissive_policy(
        suffix in "[a-z]{1,24}", shadow in any::<bool>(),
    ) {
        let compiled = compile(&json!({"schema_version":"0.1.0","default_action":"allow",
            "enforcement_mode":if shadow { "shadow" } else { "enforce" },
            "rules":[{"path":"/**","action":"allow"}],
            "routes":[{"path_prefix":"/","hosts":[format!("{suffix}.example.test")],"permission":"synthetic-read"}]}),
            PolicyAuthority::Standalone);
        let baseline = context(&compiled, &suffix);
        prop_assert_eq!(compiled.evaluate(&baseline).unwrap().logical(), LogicalDecision::Allow);
        // Force all required gaps for every generated case, rather than hoping
        // a random selector reaches a rare missing-fact branch.
        for (mutate, limitation) in [
            ((|input: &mut PolicyEvaluationContext| input.method = None) as fn(&mut _), Limitation::MissingMethod),
            (|input: &mut PolicyEvaluationContext| input.path = None, Limitation::MissingPath),
            (|input: &mut PolicyEvaluationContext| input.principal = PrincipalFact::Missing, Limitation::MissingPrincipalFact),
            (|input: &mut PolicyEvaluationContext| input.target = HttpTarget::Missing, Limitation::MissingDispatchFact),
            (|input: &mut PolicyEvaluationContext| input.target = HttpTarget::ProxyDispatch, Limitation::MissingDispatchFact),
            (|input: &mut PolicyEvaluationContext| input.request_host = HostFact::Missing, Limitation::MissingHostFact),
        ] {
            let mut input = baseline.clone();
            mutate(&mut input);
            let result = compiled.evaluate(&input).unwrap();
            prop_assert_eq!(result.logical(), LogicalDecision::Indeterminate);
            prop_assert_eq!(result.effect(), PolicyEffect::Block);
            prop_assert_eq!(result.reason(), Reason::Incomplete);
            prop_assert_eq!(result.limitation(), Some(limitation));
            prop_assert_eq!(result.matched(), None);
            prop_assert_eq!(result.observation(), None);
            prop_assert!(!result.is_complete());
            prop_assert!(!result.reusable_for(&input));
            prop_assert!(!result.reusable_for(&baseline));
            prop_assert!(result.canonical_trace_bytes().unwrap().len() <= MAX_TRACE_BYTES);
            if matches!(limitation, Limitation::MissingMethod | Limitation::MissingPath | Limitation::MissingPrincipalFact) {
                let selection = compiled.select_rate_lane(&input).unwrap();
                prop_assert_eq!(selection.limitation(), Some(limitation));
                prop_assert!(!selection.reusable_for(&input));
                prop_assert!(!selection.reusable_for(&baseline));
            }
        }
        // An uncaptured host is not required when no route depends on it.
        let unbound = compile(&json!({"schema_version":"0.1.0","default_action":"allow"}), PolicyAuthority::Standalone);
        let mut no_host = context(&unbound, &suffix);
        no_host.request_host = HostFact::Missing;
        let result = unbound.evaluate(&no_host).unwrap();
        prop_assert!(result.is_complete());
        prop_assert_eq!(result.logical(), LogicalDecision::Allow);
    }

    #[test]
    fn exact_source_digest_kind_and_authority_prevent_cross_snapshot_replay(
        suffix in "[a-z]{1,24}", revision in 0i64..i64::MAX,
        whitespace in 1usize..17, default_allow in any::<bool>(), negative in i64::MIN..0i64,
    ) {
        let value = json!({"schema_version":"0.1.0","id":format!("synthetic-{suffix}"),
            "default_action":if default_allow { "allow" } else { "deny" }});
        let source = serde_json::to_vec(&value).unwrap();
        let mut formatted = source.clone();
        formatted.extend(std::iter::repeat_n(b' ', whitespace));
        let original = CompiledPolicy::compile(&source, PolicyAuthority::Standalone).unwrap();
        let reformatted = CompiledPolicy::compile(&formatted, PolicyAuthority::Standalone).unwrap();
        let installed = CompiledPolicy::from_validated_policy(Policy::validate_json_value(value).unwrap(), PolicyAuthority::Standalone).unwrap();
        let at_revision = CompiledPolicy::compile(&source, PolicyAuthority::PostgreSql { security_revision: revision }).unwrap();
        let next_revision = CompiledPolicy::compile(&source, PolicyAuthority::PostgreSql { security_revision: revision + 1 }).unwrap();
        let variants = [&original, &reformatted, &installed, &at_revision, &next_revision];
        prop_assert!(matches!(original.snapshot().digest, PolicyDigest::Source(_)));
        prop_assert!(matches!(installed.snapshot().digest, PolicyDigest::ValidatedPolicy(_)));
        for (left_index, left) in variants.iter().enumerate() {
            let input = context(left, &suffix);
            let result = left.evaluate(&input).unwrap();
            let selection = left.select_rate_lane(&input).unwrap();
            prop_assert!(result.reusable_for(&input));
            prop_assert!(selection.reusable_for(&input));
            for (right_index, right) in variants.iter().enumerate() {
                if left_index == right_index { continue; }
                let changed = context(right, &suffix);
                prop_assert_ne!(left.snapshot(), right.snapshot());
                prop_assert_eq!(right.evaluate(&input), Err(EvaluationError::SnapshotMismatch));
                prop_assert_eq!(right.select_rate_lane(&input), Err(EvaluationError::SnapshotMismatch));
                prop_assert!(!result.reusable_for(&changed));
                prop_assert!(!selection.reusable_for(&changed));
                // Formatting and authority do not change the logical answer,
                // but equal answers still cannot be reused across identities.
                prop_assert_eq!(right.evaluate(&changed).unwrap().logical(), result.logical());
            }
        }
        let invalid = PolicyAuthority::PostgreSql { security_revision: negative };
        prop_assert_eq!(CompiledPolicy::compile(&source, invalid).unwrap_err(), CompileError::InvalidRevision);
        let policy = Policy::validate_json_value(serde_json::from_slice(&source).unwrap()).unwrap();
        prop_assert_eq!(CompiledPolicy::from_validated_policy(policy, invalid).unwrap_err(), CompileError::InvalidRevision);
    }

    #[test]
    fn context_and_semantics_versions_cannot_reuse_a_complete_result(
        suffix in "[a-z]{1,24}", delta in 1u16..=u16::MAX,
    ) {
        let compiled = compile(&json!({"schema_version":"0.1.0","default_action":"allow"}), PolicyAuthority::Standalone);
        let baseline = context(&compiled, &suffix);
        let result = compiled.evaluate(&baseline).unwrap();
        let selection = compiled.select_rate_lane(&baseline).unwrap();
        let mut wrong_context_version = baseline.clone();
        wrong_context_version.version = CONTEXT_VERSION.wrapping_add(delta);
        let mut wrong_snapshot_version = baseline.clone();
        wrong_snapshot_version.snapshot.context_version = CONTEXT_VERSION.wrapping_add(delta);
        let mut wrong_semantics = baseline.clone();
        wrong_semantics.snapshot.semantics_version = "synthetic-future-semantics";
        for (input, expected) in [
            (wrong_context_version, EvaluationError::UnsupportedContextVersion),
            (wrong_snapshot_version, EvaluationError::SnapshotMismatch),
            (wrong_semantics, EvaluationError::SnapshotMismatch),
        ] {
            prop_assert_eq!(compiled.evaluate(&input), Err(expected));
            prop_assert_eq!(compiled.select_rate_lane(&input), Err(expected));
            prop_assert!(!result.reusable_for(&input));
            prop_assert!(!selection.reusable_for(&input));
        }
    }

    #[test]
    fn every_captured_policy_fact_changes_the_replay_binding(
        suffix in "[a-z]{1,24}",
    ) {
        let compiled = compile(&json!({"schema_version":"0.1.0","default_action":"allow"}), PolicyAuthority::Standalone);
        let mut baseline = context(&compiled, &suffix);
        baseline.target = HttpTarget::ProxyDispatch;
        baseline.request_host = HostFact::Present(format!("request-{suffix}.example.test"));
        baseline.dispatch = Some(DispatchFacts {
            route_id: Some(format!("synthetic-route-{suffix}")),
            route_host: Some(format!("upstream-{suffix}.example.test")),
            route_path_prefix: Some(format!("/synthetic/{suffix}")),
            upstream_origin: format!("https://origin-{suffix}.example.test"),
        });
        let result = compiled.evaluate(&baseline).unwrap();
        let selection = compiled.select_rate_lane(&baseline).unwrap();
        prop_assert!(result.is_complete());
        prop_assert!(result.reusable_for(&baseline));
        prop_assert!(selection.reusable_for(&baseline));
        for mutate in [
            (|input: &mut PolicyEvaluationContext| input.method = Some(Method::POST)) as fn(&mut _),
            |input| input.path.as_mut().unwrap().push_str("/changed"),
            |input| { if let PrincipalFact::Authenticated(identity) = &mut input.principal { identity.0.user_id.push_str("-changed"); } },
            |input| { if let PrincipalFact::Authenticated(identity) = &mut input.principal { identity.0.issuer = None; } },
            |input| { if let PrincipalFact::Authenticated(identity) = &mut input.principal { identity.0.roles.reverse(); } },
            |input| { if let PrincipalFact::Authenticated(identity) = &mut input.principal { identity.0.auth_method = AuthMethod::Cookie; } },
            |input| input.principal = PrincipalFact::Anonymous,
            |input| input.request_host = HostFact::Absent,
            |input| input.request_host = HostFact::Missing,
            |input| input.request_host = HostFact::Present("changed.example.test".to_owned()),
            |input| input.dispatch.as_mut().unwrap().route_id = None,
            |input| input.dispatch.as_mut().unwrap().route_id.as_mut().unwrap().push_str("-changed"),
            |input| input.dispatch.as_mut().unwrap().route_host = None,
            |input| input.dispatch.as_mut().unwrap().route_host = Some("changed.example.test".to_owned()),
            |input| input.dispatch.as_mut().unwrap().route_path_prefix = None,
            |input| input.dispatch.as_mut().unwrap().route_path_prefix.as_mut().unwrap().push_str("/changed"),
            |input| input.dispatch.as_mut().unwrap().upstream_origin = "https://changed.example.test".to_owned(),
            |input| { input.target = HttpTarget::Contextless; input.dispatch = None; },
        ] {
            let mut changed = baseline.clone();
            mutate(&mut changed);
            prop_assert!(compiled.evaluate(&changed).unwrap().is_complete());
            prop_assert!(!result.reusable_for(&changed));
            prop_assert!(!selection.reusable_for(&changed));
            prop_assert_ne!(result.binding, compiled.evaluate(&changed).unwrap().binding);
        }
        // The second path identity is part of the context even when no rule
        // examines either path and the logical result therefore stays allow.
        let mut alias = context(&compiled, &suffix);
        alias.target = HttpTarget::McpAlias { canonical_path: format!("/canonical/{suffix}") };
        let alias_result = compiled.evaluate(&alias).unwrap();
        let alias_selection = compiled.select_rate_lane(&alias).unwrap();
        let mut changed = alias.clone();
        if let HttpTarget::McpAlias { canonical_path } = &mut changed.target { canonical_path.push_str("/changed"); }
        prop_assert_eq!(compiled.evaluate(&changed).unwrap().logical(), alias_result.logical());
        prop_assert!(!alias_result.reusable_for(&changed));
        prop_assert!(!alias_selection.reusable_for(&changed));
        changed.target = HttpTarget::Contextless;
        prop_assert!(!alias_result.reusable_for(&changed));
        prop_assert!(!alias_selection.reusable_for(&changed));
    }

    #[test]
    fn generated_traces_are_bounded_redacted_and_ignore_non_policy_identity_metadata(
        suffix in "[a-z]{1,24}", code in 0u8..3, use_route in any::<bool>(),
        revision in 0i64..=i64::MAX,
    ) {
        let marker = format!("synthetic-private-{suffix}");
        let path = format!("/{marker}");
        let mut value = json!({"schema_version":"0.1.0","id":marker,
            "roles":{marker.clone():{"permissions":[marker.clone()]}},
            "routes":[{"path_prefix":path,"permission":marker}]});
        if !use_route {
            value["rules"] = json!([{"id":marker,"path":path,"action":action(code).0}]);
        }
        let compiled = compile(&value, PolicyAuthority::PostgreSql { security_revision: revision });
        let mut identity = principal(&suffix);
        identity.user_id = marker.clone();
        identity.issuer = Some(format!("https://{marker}.example.test"));
        identity.roles = vec![marker.clone()];
        identity.email = Some(format!("{marker}@example.test"));
        identity.org_id = Some(marker.clone());
        identity.session_id = marker.clone();
        let mut input = context(&compiled, &suffix);
        input.path = Some(path);
        input.principal = PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&identity));
        input.request_host = HostFact::Present(format!("{marker}.example.test"));
        input.target = HttpTarget::McpAlias { canonical_path: format!("/canonical/{marker}") };
        let result = compiled.evaluate(&input).unwrap();
        prop_assert!(result.is_complete());
        prop_assert_eq!(result.matched(), Some(if use_route { RuleReference::Route(0) } else { RuleReference::Direct(0) }));
        let bytes = result.canonical_trace_bytes().unwrap();
        prop_assert!(bytes.len() <= MAX_TRACE_BYTES);
        prop_assert!(!String::from_utf8(bytes.clone()).unwrap().contains(&marker));
        let debug = format!("{compiled:?} {input:?} {result:?}");
        prop_assert!(!debug.contains(&marker));
        let trace: Value = serde_json::from_slice(&bytes).unwrap();
        prop_assert_eq!(&trace["domain"], &json!(HTTP_DOMAIN));
        prop_assert_eq!(&trace["not_evaluated"], &json!(NOT_EVALUATED));
        prop_assert_eq!(trace.as_object().unwrap().len(), 10);
        // Session/email/organization never reach the policy projection. Their
        // changes must not turn an otherwise identical replay into a new input.
        identity.session_id.push_str("-changed");
        identity.email = None;
        identity.org_id = None;
        let projected = PrincipalIdentity::from_principal(&identity);
        prop_assert!(projected.0.session_id.is_empty());
        prop_assert!(projected.0.email.is_none());
        prop_assert!(projected.0.org_id.is_none());
        input.principal = PrincipalFact::Authenticated(projected);
        prop_assert!(result.reusable_for(&input));
        prop_assert_eq!(compiled.evaluate(&input).unwrap().canonical_trace_bytes().unwrap(), bytes);
    }

    #[test]
    fn generated_rate_selection_keeps_first_match_and_anonymous_bypass(
        suffix in "[a-z]{1,24}",
        limits in proptest::collection::vec((1u16..=1_000, 1u32..=10_000), 1..9),
    ) {
        let path = format!("/synthetic/{suffix}");
        let rules: Vec<Value> = limits.iter().map(|(rate, burst)| {
            json!({"methods":["GET"],"path":path,"requests_per_second":rate,"burst":burst})
        }).collect();
        let compiled = compile(&json!({"schema_version":"0.1.0","rate_limits":rules}), PolicyAuthority::Standalone);
        let input = context(&compiled, &suffix);
        let selection = compiled.select_rate_lane(&input).unwrap();
        prop_assert_eq!(selection, compiled.select_rate_lane(&input).unwrap());
        prop_assert_eq!(selection.matched(), Some(0));
        prop_assert_eq!(selection.limit().unwrap().requests_per_second(), f64::from(limits[0].0));
        prop_assert_eq!(selection.limit().unwrap().burst(), limits[0].1);
        prop_assert!(selection.reusable_for(&input));
        let mut anonymous = input.clone();
        anonymous.principal = PrincipalFact::Anonymous;
        let bypassed = compiled.select_rate_lane(&anonymous).unwrap();
        prop_assert_eq!(bypassed.outcome(), RateLaneOutcome::NoOverride);
        prop_assert!(bypassed.reusable_for(&anonymous));
        prop_assert!(!selection.reusable_for(&anonymous));
        let mut missing = input.clone();
        missing.principal = PrincipalFact::Missing;
        let incomplete = compiled.select_rate_lane(&missing).unwrap();
        prop_assert_eq!(incomplete.limitation(), Some(Limitation::MissingPrincipalFact));
        prop_assert!(!incomplete.reusable_for(&missing));
        prop_assert!(!incomplete.reusable_for(&input));
    }
}
