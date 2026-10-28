//! Differential evidence for the rate-lane cutover (#422 PR 3a).
//!
//! The frozen pre-cutover policy stage (`legacy`) and the live one are each
//! driven as middleware, over their own buckets, with the same requests in the
//! same order, and compared request by request: what each selector picked
//! (rule fingerprint and declared limit), the status, the policy decision on the
//! response, every override bucket's remaining tokens for the caller, whether
//! downstream work ran, and the audit each side emitted. The oracle is the
//! original middleware, never a hand-written expectation.
//!
//! The one designed disagreement is a path the evaluator does not accept: the
//! live stage refuses it, charging nothing, where the frozen stage selected on
//! the raw path, charged a bucket and passed the request to the authorization
//! stage -- which refused it with the same answer. Both halves are pinned.

use axum::{body::Body, middleware::from_fn_with_state, Router};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngAlgorithm, RngSeed};
use serde_json::{json, Value};
use tower::ServiceExt;

use super::{legacy, *};
use crate::{
    audit::{
        sink::tests::{CaptureSink, DurableBehaviour, DurableCaptureSink},
        AuditSink,
    },
    auth::{AuthMethod, Principal},
    middleware::{
        decision::{PolicyDecision, PolicyDecisionOutcome},
        rbac::{rbac_middleware, reload_policy_from_file, with_pinned_policy, RbacState},
    },
    rbac::Policy,
    upstream_route::ProxyRouteClassificationCompleted,
};

/// Paths the evaluator accepts, so both stages must answer them alike.
const SERVED_PATHS: &[&str] = &[
    "/",
    "/data",
    "/data/",
    "/data/42",
    "/data/42/detail",
    "/other/n/x",
    "/elsewhere",
];

/// Paths the evaluator refuses: four the authorization stage's unsafe-path
/// guard refuses first, and an asterisk-form target, which is not a path.
const REFUSED_PATHS: &[&str] = &["/data/%34%32", "//data", "/data/./x", "/data/../x", "*"];

/// Override path patterns the corpus draws from; `None` omits `path`.
const PATTERNS: &[Option<&str>] = &[
    None,
    Some("/data"),
    Some("/data/*"),
    Some("/data/**"),
    Some("/data/{id}"),
    Some("/"),
    Some("/**"),
    Some("/other/{name}/x"),
];

/// Refill is negligible over a test run, so buckets compare as whole tokens on
/// both sides however long each side took. Distinct values still tell the
/// overrides' limits apart.
const RATES: &[f64] = &[0.000_001, 0.000_002, 0.000_003];

fn methods() -> Vec<Method> {
    vec![
        Method::GET,
        Method::POST,
        Method::DELETE,
        Method::from_bytes(b"PURGE").expect("an extension method"),
    ]
}

fn principal(user_id: &str, issuer: &str, roles: &[&str], auth_method: AuthMethod) -> Principal {
    Principal {
        user_id: user_id.to_owned(),
        issuer: Some(issuer.to_owned()),
        email: Some("synthetic@example.test".to_owned()),
        org_id: Some("synthetic-organization".to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: "synthetic-session".to_owned(),
        auth_method,
    }
}

/// Anonymous, each authentication method, a subject shared across two issuers,
/// and a principal at the role-count bound.
fn identities() -> Vec<Option<Principal>> {
    let mut many_roles = principal(
        "subject-many",
        "https://idp-a.example.test",
        &[],
        AuthMethod::Bearer,
    );
    many_roles.roles = (0..255).map(|index| format!("role-{index}")).collect();
    many_roles.roles.push("reader".to_owned());
    vec![
        None,
        Some(principal(
            "subject-a",
            "https://idp-a.example.test",
            &["reader"],
            AuthMethod::Bearer,
        )),
        Some(principal(
            "subject-b",
            "https://idp-a.example.test",
            &["writer"],
            AuthMethod::Cookie,
        )),
        Some(principal(
            "service-c",
            "provider:synthetic",
            &[],
            AuthMethod::ServiceToken,
        )),
        Some(principal(
            "certificate-d",
            "provider:synthetic-mtls",
            &[],
            AuthMethod::ClientCertificate,
        )),
        Some(principal(
            "subject-a",
            "https://idp-b.example.test",
            &["reader", "writer"],
            AuthMethod::Bearer,
        )),
        Some(many_roles),
    ]
}

/// One generated override: principal constraint, methods, path pattern, burst
/// and rate, each an index into a fixed table.
type GeneratedRule = (u8, u8, usize, u32, usize);

fn generated_policy(shadow: bool, default_allow: bool, rules: &[GeneratedRule]) -> Policy {
    let rate_limits: Vec<Value> = rules
        .iter()
        .map(|&(principal, methods, pattern, burst, rate)| {
            let mut rule = json!({"requests_per_second": RATES[rate], "burst": burst});
            match principal {
                1 => rule["principal"] = json!({"roles": ["reader"]}),
                2 => rule["principal"] = json!({"issuers": ["https://idp-a.example.test"]}),
                3 => rule["principal"] = json!({"auth_methods": ["session_cookie"]}),
                4 => rule["principal"] = json!({"principal_ids": ["subject-a"]}),
                5 => {
                    rule["principal"] =
                        json!({"roles": ["writer"], "auth_methods": ["bearer_token"]})
                }
                _ => {}
            }
            match methods {
                1 => rule["methods"] = json!(["GET"]),
                2 => rule["methods"] = json!(["POST"]),
                3 => rule["methods"] = json!(["*"]),
                4 => rule["methods"] = json!(["get", "DELETE"]),
                5 => rule["methods"] = json!(["purge"]),
                _ => {}
            }
            if let Some(pattern) = PATTERNS[pattern] {
                rule["path"] = json!(pattern);
            }
            rule
        })
        .collect();
    Policy::validate_json_value(json!({
        "schema_version": "0.1.0",
        "default_action": if default_allow { "allow" } else { "deny" },
        "enforcement_mode": if shadow { "shadow" } else { "enforce" },
        "roles": {"reader": {"permissions": []}, "writer": {"permissions": []}},
        // Rate selection never reads routes, rules or the default; they are
        // here so a stage that started to would be caught disagreeing.
        "routes": [{"path_prefix": "/data", "permission": "unavailable"}],
        "rules": [{"id": "deny-data", "path": "/data/**", "action": "deny"}],
        "rate_limits": rate_limits
    }))
    .expect("generated policies are valid")
}

/// One side of the comparison: a policy stage attached to its own RBAC state,
/// so each side has its own buckets, driven as middleware in front of a
/// handler that counts the requests it was reached by.
struct Side {
    state: RateLimitState,
    rbac: RbacState,
    router: Router,
    audit: AuditLog,
    capture: CaptureSink,
    downstream: Arc<AtomicUsize>,
}

fn unattached_state() -> RateLimitState {
    RateLimitState::from_config(&crate::config::Config::test_defaults())
}

fn side(policy: &Policy, frozen: bool) -> Side {
    side_with_authorization(policy, frozen, false)
}

/// A side, optionally with the live authorization stage behind the policy
/// stage, layered as `routing::apply_middleware` layers the two.
fn side_with_authorization(policy: &Policy, frozen: bool, authorization: bool) -> Side {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let state = unattached_state();
    let rbac = RbacState::new(policy.clone(), Vec::new(), false, audit.clone())
        .with_rate_limit_state(state.clone());
    let downstream = Arc::new(AtomicUsize::new(0));
    let reached = Arc::clone(&downstream);
    let router = Router::new().fallback(axum::routing::any(move || {
        let reached = Arc::clone(&reached);
        async move {
            reached.fetch_add(1, Ordering::SeqCst);
            "downstream"
        }
    }));
    let router = if authorization {
        router.layer(from_fn_with_state(rbac.clone(), rbac_middleware))
    } else {
        router
    };
    let router = if frozen {
        router.layer(from_fn_with_state(
            state.clone(),
            legacy::legacy_policy_rate_limit_request,
        ))
    } else {
        router.layer(from_fn_with_state(state.clone(), policy_rate_limit_request))
    };
    Side {
        state,
        rbac,
        router,
        audit,
        capture,
        downstream,
    }
}

async fn send(
    side: &Side,
    method: &Method,
    path: &str,
    principal: Option<&Principal>,
) -> (StatusCode, Option<PolicyDecision>) {
    let mut request = Request::builder()
        .method(method.clone())
        .uri(path)
        .body(Body::empty())
        .expect("request should build");
    // Classified, as `proxy_dispatch_context_middleware` marks every request
    // before either stage runs.
    request
        .extensions_mut()
        .insert(ProxyRouteClassificationCompleted);
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal.clone());
    }
    let response = side
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("request should complete");
    (
        response.status(),
        response.extensions().get::<PolicyDecision>().cloned(),
    )
}

/// Every override bucket's whole tokens left for `key`, or `None` where the
/// key was never charged.
fn charged(state: &RateLimitState, key: &str) -> Vec<Option<f64>> {
    state
        .policy
        .load()
        .overrides
        .iter()
        .map(|selected| {
            let buckets = selected.limiter.buckets.lock().expect("bucket lock");
            let hashed = buckets.hash_of(key);
            buckets.map.get(&hashed).map(|bucket| bucket.tokens.floor())
        })
        .collect()
}

/// What the live stage selects for a request, as the stage consults it: the
/// guard first, then the evaluator.
fn live_selection(
    state: &RateLimitState,
    method: &Method,
    path: &str,
    principal: Option<&Principal>,
) -> Result<Option<(Arc<str>, f64, u32)>, RateLaneRefusal> {
    let Some(principal) = principal else {
        return Ok(None);
    };
    state
        .policy
        .load()
        .select(method, path, principal)
        .map(|selected| {
            selected.map(|selected| {
                (
                    selected.fingerprint,
                    selected.limit.requests_per_second,
                    selected.limit.burst,
                )
            })
        })
        .map_err(|refused| refused.refusal)
}

async fn drained(side: &Side) -> Vec<crate::audit::AuditEvent> {
    side.audit
        .close_and_drain(Duration::from_secs(5))
        .await
        .expect("the audit log drains");
    side.capture.events()
}

/// Every served request is answered alike: the same selection, status and
/// decision, the same bucket charged by the same amount, the same downstream
/// work, and no audit record from either stage. Returns how many of the
/// requests selected an override, so a caller can require that the comparison
/// reached one.
async fn assert_old_and_new_agree(policy: &Policy) -> usize {
    let old = side(policy, true);
    let new = side(policy, false);
    let mut selected = 0;
    for identity in identities() {
        let key = identity.as_ref().map(principal_rate_limit_key);
        for method in methods() {
            for path in SERVED_PATHS {
                let label = format!(
                    "{method} {path} as {:?}",
                    identity
                        .as_ref()
                        .map(|identity| (&identity.user_id, &identity.issuer))
                );
                let expected =
                    legacy::legacy_selection(&old.state, &method, path, identity.as_ref());
                let actual = live_selection(&new.state, &method, path, identity.as_ref());
                selected += usize::from(expected.is_some());
                assert_eq!(actual, Ok(expected), "selection for {label}");
                // Twice, so a burst of one is spent and the second answer
                // shows which bucket the first one charged.
                for attempt in 0..2 {
                    let old_answer = send(&old, &method, path, identity.as_ref()).await;
                    let new_answer = send(&new, &method, path, identity.as_ref()).await;
                    assert_eq!(new_answer, old_answer, "answer {attempt} for {label}");
                    if let Some(key) = &key {
                        assert_eq!(
                            charged(&new.state, key),
                            charged(&old.state, key),
                            "buckets after answer {attempt} for {label}"
                        );
                    }
                }
            }
        }
    }
    assert_eq!(
        new.downstream.load(Ordering::SeqCst),
        old.downstream.load(Ordering::SeqCst),
        "downstream work"
    );
    assert!(
        drained(&old).await.is_empty(),
        "the frozen stage audits nothing"
    );
    assert!(
        drained(&new).await.is_empty(),
        "the live stage audits nothing it serves"
    );
    selected
}

/// The designed disagreement: a path the evaluator refuses is refused by the
/// live stage, with the authorization stage's reason, before any bucket or
/// downstream work, and audited once. The frozen stage selected on the raw path
/// instead, and the authorization stage behind it refused the request;
/// `a_refused_path_is_answered_and_audited_as_the_authorization_stage_answered_it`
/// compares the two answers with that stage in place.
async fn assert_refused_paths_are_refused_and_charge_nothing(policy: &Policy) {
    let new = side(policy, false);
    let mut expected_reasons = Vec::new();
    for identity in identities().into_iter().flatten() {
        let key = principal_rate_limit_key(&identity);
        for method in methods() {
            for path in REFUSED_PATHS {
                let reason = if is_unsafe_request_path(path) {
                    "unsafe_path"
                } else {
                    "policy_evaluation_error"
                };
                let selection = live_selection(&new.state, &method, path, Some(&identity));
                assert!(
                    matches!(
                        selection,
                        Err(RateLaneRefusal::UnsafePath)
                            | Err(RateLaneRefusal::Error(EvaluationError::MalformedPath))
                    ),
                    "{method} {path}: {selection:?}"
                );
                assert_eq!(
                    send(&new, &method, path, Some(&identity)).await,
                    (
                        StatusCode::FORBIDDEN,
                        Some(PolicyDecision {
                            outcome: PolicyDecisionOutcome::Denied,
                            reason,
                            permission: None,
                            path_prefix: None,
                            matched_rule_id: None,
                        })
                    ),
                    "{method} {path}"
                );
                expected_reasons.push(reason);
            }
        }
        assert!(
            charged(&new.state, &key).iter().all(Option::is_none),
            "a refused request charges no bucket"
        );
    }
    assert_eq!(
        new.downstream.load(Ordering::SeqCst),
        0,
        "a refused request does no downstream work"
    );
    let events = drained(&new).await;
    let reasons: Vec<_> = events
        .iter()
        .map(|event| {
            assert_eq!(event.event_type, "authz.denied");
            assert!(event.payload.get("matched_rule_id").is_none());
            assert!(event.payload.get("security_revision").is_none());
            event.payload["reason"]
                .as_str()
                .expect("a reason")
                .to_owned()
        })
        .collect();
    assert_eq!(reasons, expected_reasons);
}

fn differential_config() -> ProptestConfig {
    ProptestConfig {
        cases: 128,
        rng_algorithm: RngAlgorithm::ChaCha,
        rng_seed: RngSeed::Fixed(422_003),
        max_shrink_iters: 1_024,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(differential_config())]

    #[test]
    fn generated_policies_select_and_charge_alike_in_the_frozen_and_live_stages(
        shadow in any::<bool>(),
        default_allow in any::<bool>(),
        rules in proptest::collection::vec(
            (0u8..6, 0u8..6, 0usize..PATTERNS.len(), 1u32..4, 0usize..RATES.len()),
            0..6,
        ),
    ) {
        let policy = generated_policy(shadow, default_allow, &rules);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a test runtime")
            .block_on(async {
                let _ = assert_old_and_new_agree(&policy).await;
                assert_refused_paths_are_refused_and_charge_nothing(&policy).await;
            });
    }
}

#[tokio::test]
async fn the_frozen_and_live_stages_agree_across_the_named_matrix() {
    // The cases the corpus reaches only by chance, each written out.
    let any_caller = (0, 0, 0, 1, 0);
    let matrix: Vec<(&str, Vec<GeneratedRule>)> = vec![
        ("no overrides", vec![]),
        // Matches every authenticated request; anonymous still reaches none.
        ("an unconstrained override", vec![any_caller]),
        // Same predicates, later in source order: only the first is charged.
        ("first match wins", vec![(0, 1, 3, 1, 0), (0, 1, 3, 3, 1)]),
        // A rule before the deciding one that does not match, and one after
        // it that would.
        (
            "rules around the deciding one",
            vec![(0, 2, 3, 1, 0), (1, 1, 3, 2, 1), (0, 0, 6, 3, 2)],
        ),
        ("roles alone", vec![(1, 0, 0, 1, 0)]),
        ("issuers alone", vec![(2, 0, 0, 1, 0)]),
        ("auth methods alone", vec![(3, 0, 0, 1, 0)]),
        ("principal ids alone", vec![(4, 0, 0, 1, 0)]),
        ("roles and auth methods together", vec![(5, 0, 0, 1, 0)]),
        ("wildcard method", vec![(0, 3, 1, 1, 0)]),
        (
            "lower-case and mixed methods",
            vec![(0, 4, 3, 1, 0), (0, 5, 0, 2, 1)],
        ),
        ("one-segment wildcard", vec![(0, 0, 2, 1, 0)]),
        ("capture", vec![(0, 0, 4, 1, 0), (0, 0, 7, 2, 1)]),
        ("root only", vec![(0, 0, 5, 1, 0)]),
        ("everything below the root", vec![(0, 0, 6, 1, 0)]),
    ];
    for (name, rules) in matrix {
        for (shadow, default_allow) in [(false, false), (true, false), (false, true), (true, true)]
        {
            let policy = generated_policy(shadow, default_allow, &rules);
            println!("{name}, shadow {shadow}, default allow {default_allow}");
            let selected = assert_old_and_new_agree(&policy).await;
            // Every named override matches some request in the matrix, so a
            // comparison that never selected one would be comparing nothing.
            assert_eq!(
                selected == 0,
                rules.is_empty(),
                "{name}: {selected} selected"
            );
            assert_refused_paths_are_refused_and_charge_nothing(&policy).await;
        }
    }
}

/// With the authorization stage behind it, a path the evaluator refuses gets
/// the same answer and the same audit record from both policy stages: the
/// frozen stage passed it on to be refused, the live stage refuses it itself.
#[tokio::test]
async fn a_refused_path_is_answered_and_audited_as_the_authorization_stage_answered_it() {
    // Generous enough that the frozen stage never spends the bucket, so the
    // authorization stage decides every frozen-side answer.
    let policy = generated_policy(false, true, &[(0, 0, 0, 10, 0)]);
    let old = side_with_authorization(&policy, true, true);
    let new = side_with_authorization(&policy, false, true);
    let identity = principal(
        "subject-a",
        "https://idp-a.example.test",
        &["reader"],
        AuthMethod::Bearer,
    );
    for path in REFUSED_PATHS {
        let old_answer = send(&old, &Method::GET, path, Some(&identity)).await;
        let new_answer = send(&new, &Method::GET, path, Some(&identity)).await;
        assert_eq!(new_answer, old_answer, "{path}");
        assert_eq!(new_answer.0, StatusCode::FORBIDDEN, "{path}");
    }
    let summary = |events: Vec<crate::audit::AuditEvent>| -> Vec<(String, Value, Option<String>)> {
        events
            .into_iter()
            .map(|event| {
                (
                    event.event_type,
                    event.payload,
                    event.actor.map(|actor| actor.user_id),
                )
            })
            .collect()
    };
    let old_events = summary(drained(&old).await);
    let new_events = summary(drained(&new).await);
    assert_eq!(new_events.len(), REFUSED_PATHS.len());
    assert_eq!(new_events, old_events);
    assert_eq!(old.downstream.load(Ordering::SeqCst), 0);
    assert_eq!(new.downstream.load(Ordering::SeqCst), 0);
    // The frozen stage charged a bucket for each; the live stage none.
    let key = principal_rate_limit_key(&identity);
    assert_eq!(
        charged(&old.state, &key),
        vec![Some(f64::from(10 - REFUSED_PATHS.len() as u32))]
    );
    assert_eq!(charged(&new.state, &key), vec![None]);
}

/// Required audit durability (issue #425): the live stage's own refusal of a
/// path the evaluator does not accept is answered `403` only once its record
/// has committed, and as the audit outage while it cannot be. Neither answer
/// lets the request past the stage.
#[tokio::test]
async fn a_refused_path_is_answered_only_once_its_record_commits_under_required_durability() {
    let policy = generated_policy(false, true, &[(0, 0, 0, 10, 0)]);
    let durable = DurableCaptureSink::new();
    let audit = AuditLog::new_required(
        Arc::new(durable.clone()) as Arc<dyn AuditSink>,
        Duration::from_secs(5),
    );
    let state = unattached_state();
    let rbac = RbacState::new(policy, Vec::new(), false, audit.clone())
        .with_rate_limit_state(state.clone());
    let downstream = Arc::new(AtomicUsize::new(0));
    let reached = Arc::clone(&downstream);
    let router = Router::new()
        .fallback(axum::routing::any(move || {
            let reached = Arc::clone(&reached);
            async move {
                reached.fetch_add(1, Ordering::SeqCst);
                "downstream"
            }
        }))
        .layer(from_fn_with_state(state.clone(), policy_rate_limit_request));
    let live = Side {
        state,
        rbac,
        router,
        audit,
        capture: CaptureSink::new(),
        downstream,
    };
    let identity = principal(
        "subject-a",
        "https://idp-a.example.test",
        &["reader"],
        AuthMethod::Bearer,
    );

    durable.set(DurableBehaviour::Refuse);
    let (status, decision) = send(&live, &Method::GET, "/data/../x", Some(&identity)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        decision.map(|decision| decision.reason),
        Some("audit_unavailable")
    );

    durable.set(DurableBehaviour::Store);
    let (status, decision) = send(&live, &Method::GET, "/data/../x", Some(&identity)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        decision.map(|decision| decision.reason),
        Some("unsafe_path")
    );
    let stored = durable.events();
    assert_eq!(stored.len(), 1, "only the committed refusal is stored");
    assert_eq!(stored[0].event_type, "authz.denied");
    assert_eq!(stored[0].payload["reason"], json!("unsafe_path"));
    assert_eq!(live.downstream.load(Ordering::SeqCst), 0);
}

/// The stage selects with the snapshot the RBAC lane installed, the same
/// instance, after every install path; and an index always names the bucket
/// built for the rule it came from, never the bucket at that position in
/// another policy.
#[tokio::test]
async fn every_install_hands_the_rate_stage_the_installed_snapshot_with_its_own_buckets() {
    let first = generated_policy(false, true, &[(0, 1, 1, 1, 0)]);
    // `/data` moves from index 0 to index 1, behind a rule for another path.
    let second = generated_policy(false, true, &[(0, 1, 7, 3, 1), (0, 1, 1, 1, 0)]);
    let file = TempPolicyFile::new(&first);
    let live = side(&first, false);
    let installed = |side: &Side| {
        let lane = side.state.policy.load();
        let selector = lane.selector.as_ref().expect("attached");
        Arc::ptr_eq(&selector.snapshot, &side.rbac.installed_compiled_policy())
    };
    assert!(
        installed(&live),
        "attaching hands over the installed snapshot"
    );

    let identity = principal(
        "subject-a",
        "https://idp-a.example.test",
        &["reader"],
        AuthMethod::Bearer,
    );
    let key = principal_rate_limit_key(&identity);
    assert_eq!(
        send(&live, &Method::GET, "/data", Some(&identity)).await.0,
        StatusCode::OK
    );
    assert_eq!(charged(&live.state, &key), vec![Some(0.0)]);

    file.write(&second);
    reload_policy_from_file(&live.rbac, file.path())
        .await
        .expect("the reload is valid");
    assert!(
        installed(&live),
        "a reload hands over the snapshot it installed"
    );
    // Fresh buckets for the new policy, and `/data` charges index 1.
    assert_eq!(charged(&live.state, &key), vec![None, None]);
    assert_eq!(
        send(&live, &Method::GET, "/data", Some(&identity)).await.0,
        StatusCode::OK
    );
    assert_eq!(charged(&live.state, &key), vec![None, Some(0.0)]);
    assert_eq!(
        send(&live, &Method::GET, "/data", Some(&identity)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );

    #[cfg(feature = "postgres")]
    {
        live.rbac
            .install_revision_snapshot(first.clone(), 3)
            .await
            .expect("the revision installs");
        assert!(
            installed(&live),
            "a revision install hands over the snapshot it installed"
        );
        assert_eq!(
            send(&live, &Method::GET, "/data", Some(&identity)).await.0,
            StatusCode::OK
        );
        assert_eq!(charged(&live.state, &key), vec![Some(0.0)]);
        // A duplicate of an installed revision installs nothing, so it
        // neither swaps the snapshot nor resets the buckets.
        live.rbac
            .install_revision_snapshot(second.clone(), 3)
            .await
            .expect("a duplicate revision is a no-op");
        assert!(installed(&live));
        assert_eq!(charged(&live.state, &key), vec![Some(0.0)]);
        assert_eq!(
            send(&live, &Method::GET, "/data", Some(&identity)).await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}

/// A request pinned to a snapshot is selected for that snapshot. When the
/// buckets were built for another one, the evaluator refuses the question and
/// the request is refused, charging nothing; a snapshot of the same policy
/// content is the same question and is answered.
#[tokio::test]
async fn a_request_pinned_to_another_snapshot_is_refused_rather_than_charged_against_this_one() {
    let older = generated_policy(false, true, &[(0, 1, 1, 1, 0)]);
    let newer = generated_policy(false, true, &[(0, 1, 1, 2, 1)]);
    let live = side(&newer, false);
    let identity = principal(
        "subject-a",
        "https://idp-a.example.test",
        &["reader"],
        AuthMethod::Bearer,
    );
    let key = principal_rate_limit_key(&identity);
    let other_audit = AuditLog::new(Arc::new(CaptureSink::new()) as Arc<dyn AuditSink>);
    let older_snapshot =
        RbacState::new(older, Vec::new(), false, other_audit.clone()).installed_compiled_policy();
    let same_content =
        RbacState::new(newer, Vec::new(), false, other_audit).installed_compiled_policy();

    let pinned_to_older = with_pinned_policy(
        older_snapshot,
        send(&live, &Method::GET, "/data", Some(&identity)),
    )
    .await;
    assert_eq!(
        pinned_to_older,
        (
            StatusCode::FORBIDDEN,
            Some(PolicyDecision {
                outcome: PolicyDecisionOutcome::Denied,
                reason: "policy_evaluation_error",
                permission: None,
                path_prefix: None,
                matched_rule_id: None,
            })
        )
    );
    assert_eq!(charged(&live.state, &key), vec![None]);

    let pinned_to_same_content = with_pinned_policy(
        same_content,
        send(&live, &Method::GET, "/data", Some(&identity)),
    )
    .await;
    assert_eq!(pinned_to_same_content.0, StatusCode::OK);
    assert_eq!(charged(&live.state, &key), vec![Some(1.0)]);
    assert_eq!(live.downstream.load(Ordering::SeqCst), 1);

    let events = drained(&live).await;
    assert_eq!(events.len(), 1, "only the refusal is audited");
    assert_eq!(events[0].event_type, "authz.denied");
    assert_eq!(events[0].payload["reason"], "policy_evaluation_error");
}

/// The stage enforces only a bucket built for the rule the evaluator read. An
/// index past the buckets, or a bucket declaring another limit, is refused --
/// unreachable while the buckets are built from the evaluator's own rule
/// vector, and pinned so it stays refused if that ever changes.
#[tokio::test]
async fn a_selection_that_names_no_bucket_of_its_rule_is_refused() {
    let selector_policy = generated_policy(false, true, &[(0, 1, 7, 1, 0), (0, 1, 1, 1, 0)]);
    let bucket_policy = generated_policy(false, true, &[(0, 1, 7, 1, 0), (0, 1, 1, 2, 0)]);
    let identity = principal(
        "subject-a",
        "https://idp-a.example.test",
        &["reader"],
        AuthMethod::Bearer,
    );
    for buckets in [
        // One bucket short of the selector's rules.
        vec![bucket_policy.rate_limits[0].clone()],
        // The right count, but index 1 declares another burst.
        bucket_policy.rate_limits.clone(),
    ] {
        let live = side(&selector_policy, false);
        let selector = {
            let lane = live.state.policy.load();
            let selector = lane.selector.as_ref().expect("attached");
            RateLaneSelector {
                snapshot: Arc::clone(&selector.snapshot),
                audit: selector.audit.clone(),
            }
        };
        let live_buckets = Arc::new(AtomicUsize::new(0));
        live.state.policy.store(Arc::new(RateLimitPolicyState {
            selector: Some(selector),
            overrides: buckets
                .into_iter()
                .map(|rule| {
                    RateLimitOverride::new(
                        rule,
                        16,
                        Duration::from_secs(60),
                        Arc::clone(&live_buckets),
                    )
                })
                .collect(),
        }));
        assert_eq!(
            live_selection(&live.state, &Method::GET, "/data", Some(&identity)),
            Err(RateLaneRefusal::Error(EvaluationError::InternalInvariant))
        );
        let (status, decision) = send(&live, &Method::GET, "/data", Some(&identity)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            decision.map(|decision| decision.reason),
            Some("policy_evaluation_error")
        );
        assert_eq!(live.downstream.load(Ordering::SeqCst), 0);
        // A path the first rule governs still selects normally.
        assert!(matches!(
            live_selection(&live.state, &Method::GET, "/other/n/x", Some(&identity)),
            Ok(Some(_))
        ));
    }
}

/// Anonymous traffic reaches no override, however permissive the rules: the
/// stage returns before selecting, charges nothing and audits nothing, and the
/// evaluator would have answered `NoOverride` had it been asked.
#[tokio::test]
async fn anonymous_requests_pass_the_policy_stage_unselected_and_uncharged() {
    let policy = generated_policy(true, false, &[(0, 0, 0, 1, 0), (0, 0, 6, 1, 1)]);
    let live = side(&policy, false);
    for path in SERVED_PATHS.iter().chain(REFUSED_PATHS) {
        for attempt in 0..3 {
            let (status, decision) = send(&live, &Method::GET, path, None).await;
            assert_eq!(status, StatusCode::OK, "{path} attempt {attempt}");
            assert_eq!(decision, None);
        }
    }
    assert_eq!(
        live.downstream.load(Ordering::SeqCst),
        (SERVED_PATHS.len() + REFUSED_PATHS.len()) * 3
    );
    assert!(drained(&live).await.is_empty());

    let installed = live.rbac.installed_compiled_policy();
    let compiled = installed.compiled();
    let selection = compiled
        .select_rate_lane(&PolicyEvaluationContext {
            version: CONTEXT_VERSION,
            snapshot: compiled.snapshot(),
            method: Some(Method::GET),
            path: Some("/data".to_owned()),
            principal: PrincipalFact::Anonymous,
            target: HttpTarget::Missing,
            request_host: HostFact::Missing,
            dispatch: None,
        })
        .expect("selects");
    assert_eq!(selection.outcome(), RateLaneOutcome::NoOverride);
}

/// A stage no RBAC state attached -- a gateway with no policy -- selects
/// nothing and charges nothing, as before.
#[tokio::test]
async fn an_unattached_stage_selects_nothing() {
    let state = unattached_state();
    let router = Router::new()
        .fallback(axum::routing::any(|| async { "downstream" }))
        .layer(from_fn_with_state(state.clone(), policy_rate_limit_request));
    let identity = principal(
        "subject-a",
        "https://idp-a.example.test",
        &["reader"],
        AuthMethod::Bearer,
    );
    for path in SERVED_PATHS.iter().chain(REFUSED_PATHS) {
        let mut request = Request::builder()
            .uri(*path)
            .body(Body::empty())
            .expect("request should build");
        request.extensions_mut().insert(identity.clone());
        let response = router
            .clone()
            .oneshot(request)
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK, "{path}");
    }
    assert!(state.policy.load().selector.is_none());
    assert!(state.policy.load().overrides.is_empty());
}

struct TempPolicyFile {
    path: std::path::PathBuf,
}

impl TempPolicyFile {
    fn new(policy: &Policy) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-rate-lane-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        let file = Self { path };
        file.write(policy);
        file
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn write(&self, policy: &Policy) {
        let contents = serde_json::to_string(policy).expect("policy should serialize");
        std::fs::write(&self.path, contents)
            .unwrap_or_else(|err| panic!("failed to write {}: {err}", self.path.display()));
    }
}

impl Drop for TempPolicyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
