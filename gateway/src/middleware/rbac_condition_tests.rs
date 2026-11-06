//! Rule conditions on the live lanes (issue #243).
//!
//! The HTTP stage and the tool lanes answer exactly what the shared evaluator
//! answers when it is handed the facts the request carried, built here by
//! hand: the canonical client address under the trust boundary, the
//! referenced headers with every occurrence, the strictly decoded query and
//! the injected clock. A lane that read a forwarding header from an untrusted
//! peer, dropped an occurrence, decoded the query leniently or read the wall
//! clock would disagree. A fact the lane could not capture is never a guess:
//! the request is refused as incomplete, and no fact value reaches an audit
//! record, a decision or a log.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;

use super::*;
use crate::{
    middleware::policy_facts::PolicyClock,
    policy_eval::{
        tools::{ToolEvaluationContext, TOOL_CONTEXT_VERSION},
        Evaluation, Fact, HostFact, HttpTarget, LogicalDecision, PolicyEvaluationContext,
        PolicyFacts, PrincipalFact, PrincipalIdentity, CONTEXT_VERSION,
    },
};

const ISSUER: &str = "https://idp.example.test";
/// 2026-06-01T00:00:00Z, when the maintenance window opens.
const WINDOW_FROM: i64 = 1_780_272_000;
/// 2026-06-01T02:00:00Z, the first instant after it.
const WINDOW_UNTIL: i64 = WINDOW_FROM + 7_200;
/// Values no condition lists, that must never leave the request.
const HEADER_CANARY: &str = "hdr-canary-5d1e";
const QUERY_CANARY: &str = "qry-canary-9b42";

fn conditions_document() -> Value {
    json!({
        "schema_version": "1.0.0",
        "id": "conditioned-lanes",
        "default_action": "allow",
        "rules": [
            {
                "id": "canary-only",
                "path": "/canary/**",
                "action": "deny",
                "conditions": { "not": { "header": { "name": "x-environment", "in": ["canary"] } } }
            },
            {
                "id": "office-csv-exports",
                "path": "/exports/**",
                "action": "allow",
                "conditions": { "all": [
                    { "source_network": { "cidrs": ["10.0.0.0/8", "fd00::/8"] } },
                    { "query": { "name": "format", "in": ["csv"] } }
                ] }
            },
            { "id": "exports-closed", "path": "/exports/**", "action": "deny" },
            {
                "id": "maintenance",
                "path": "/maintenance/**",
                "action": "deny",
                "conditions": { "time_window": {
                    "from": "2026-06-01T00:00:00Z",
                    "until": "2026-06-01T02:00:00Z"
                } }
            },
            {
                "id": "watch-partner-reports",
                "path": "/reports/**",
                "action": "shadow",
                "conditions": { "organization": { "issuer": ISSUER, "in": ["acme"] } }
            },
            {
                "id": "exports-from-the-office",
                "tool_name": "reports.export",
                "action": "deny",
                "conditions": { "not": { "source_network": { "cidrs": ["10.0.0.0/8"] } } }
            },
            {
                "id": "no-exports-in-maintenance",
                "tool_name": "reports.export",
                "action": "deny",
                "conditions": { "time_window": {
                    "from": "2026-06-01T00:00:00Z",
                    "until": "2026-06-01T02:00:00Z"
                } }
            },
            {
                "id": "rendered-canary-only",
                "path": "/render/**",
                "action": "deny",
                "conditions": { "header": { "name": "x-environment", "in": ["prod"] } }
            }
        ],
        "tools": { "reports.export": { "allowed_roles": ["reader"] } }
    })
}

fn conditioned_state(client_ip_policy: ClientIpPolicy, now: i64) -> (RbacState, CaptureSink) {
    let capture = CaptureSink::new();
    let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
    let policy = Policy::validate_json_value(conditions_document()).expect("the fixture validates");
    let state = RbacState::new_with_mcp_route_paths(
        policy,
        Vec::new(),
        client_ip_policy,
        audit,
        vec![protected_resource::MCP_RESOURCE_PATH.to_owned()],
    )
    .with_policy_clock(PolicyClock::fixed(now));
    (state, capture)
}

fn trusted_proxies() -> ClientIpPolicy {
    ClientIpPolicy::from_trusted_proxy_cidrs(vec!["192.0.2.0/24".parse().expect("a CIDR")])
}

fn person(organization: Option<&str>) -> Principal {
    Principal {
        user_id: "synthetic-subject".to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: None,
        org_id: organization.map(str::to_owned),
        roles: vec!["reader".to_owned()],
        session_id: "synthetic-session".to_owned(),
        auth_method: AuthMethod::Bearer,
        scopes: None,
        verified_claims: Vec::new(),
    }
}

/// One request the HTTP stage judges: target, header lines, connection peer.
struct Probe {
    target: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    peer: Option<&'static str>,
}

fn probe(
    target: &'static str,
    headers: &[(&'static str, &'static str)],
    peer: Option<&'static str>,
) -> Probe {
    Probe {
        target,
        headers: headers.to_vec(),
        peer,
    }
}

impl Probe {
    fn request(&self) -> Request<Body> {
        let mut builder = Request::builder().method(Method::GET).uri(self.target);
        for (name, value) in &self.headers {
            builder = builder.header(*name, *value);
        }
        let mut request = builder.body(Body::empty()).expect("request should build");
        if let Some(peer) = self.peer {
            request.extensions_mut().insert(ConnectInfo(
                peer.parse::<SocketAddr>().expect("a socket address"),
            ));
        }
        request
    }
}

/// The facts the request carries, built by hand from what this suite knows
/// about it: the address the trust boundary admits, every occurrence of the
/// one header and the one query parameter the policy reads, and the clock.
fn hand_built_facts(
    probe: &Probe,
    principal: Option<&Principal>,
    trusted_proxy: bool,
    now: i64,
) -> PolicyFacts {
    let mut facts = PolicyFacts::uncaptured();
    facts.organization = Fact::Captured(principal.and_then(|principal| principal.org_id.clone()));
    let forwarded = probe
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-forwarded-for"))
        .map(|(_, value)| *value);
    facts.source_ip = match (probe.peer, forwarded) {
        (None, _) => Fact::Uncaptured,
        (Some(peer), Some(forwarded)) if trusted_proxy && peer.starts_with("192.0.2.") => {
            Fact::Captured(forwarded.parse::<IpAddr>().expect("a forwarded address"))
        }
        (Some(peer), _) => Fact::Captured(
            peer.parse::<SocketAddr>()
                .expect("a socket address")
                .ip()
                .to_canonical(),
        ),
    };
    facts.headers = Fact::Captured(
        probe
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("x-environment"))
            .map(|(_, value)| ("x-environment".to_owned(), (*value).to_owned()))
            .collect(),
    );
    let query = probe.target.split_once('?').map_or("", |(_, query)| query);
    facts.query = Fact::Captured(
        query
            .split('&')
            .filter_map(|piece| piece.split_once('='))
            .filter(|(name, _)| *name == "format")
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect(),
    );
    facts.now = Fact::Captured(now);
    facts
}

fn kernel_http(
    state: &RbacState,
    probe: &Probe,
    principal: Option<&Principal>,
    facts: &PolicyFacts,
) -> Evaluation {
    let snapshot = state.installed_compiled_policy();
    let compiled = snapshot.compiled();
    let context = PolicyEvaluationContext {
        version: CONTEXT_VERSION,
        snapshot: compiled.snapshot(),
        method: Some(Method::GET),
        path: Some(
            probe
                .target
                .split_once('?')
                .map_or(probe.target, |(path, _)| path)
                .to_owned(),
        ),
        principal: principal.map_or(PrincipalFact::Anonymous, |principal| {
            PrincipalFact::Authenticated(PrincipalIdentity::from_principal(principal))
        }),
        target: HttpTarget::Contextless,
        request_host: HostFact::Absent,
        dispatch: None,
    };
    compiled
        .evaluate_with_facts(&context, facts)
        .expect("the kernel answers")
}

fn probes() -> Vec<Probe> {
    vec![
        probe("/canary/x", &[("x-environment", "canary")], None),
        probe("/canary/x", &[("X-Environment", "canary")], None),
        probe("/canary/x", &[("x-environment", "Canary")], None),
        probe("/canary/x", &[("x-environment", "prod, canary")], None),
        probe(
            "/canary/x",
            &[("x-environment", "prod"), ("x-environment", "canary")],
            None,
        ),
        probe("/canary/x", &[], None),
        probe("/exports/x?format=csv", &[], Some("10.1.2.3:5000")),
        probe(
            "/exports/x?format=csv&format=pdf",
            &[],
            Some("10.1.2.3:5000"),
        ),
        probe("/exports/x?format=pdf", &[], Some("10.1.2.3:5000")),
        probe("/exports/x?format=csv", &[], Some("[fd00::7]:5000")),
        probe("/exports/x?format=csv", &[], Some("[::ffff:10.1.2.3]:5000")),
        probe("/exports/x?format=csv", &[], Some("203.0.113.9:5000")),
        probe(
            "/exports/x?format=csv",
            &[("x-forwarded-for", "10.1.2.3")],
            Some("203.0.113.9:5000"),
        ),
        probe(
            "/exports/x?format=csv",
            &[("x-forwarded-for", "10.1.2.3")],
            Some("192.0.2.10:5000"),
        ),
        probe("/maintenance/x", &[], None),
        probe("/reports/x", &[], None),
        probe(
            "/elsewhere",
            &[("x-environment", "canary")],
            Some("10.1.2.3:5000"),
        ),
    ]
}

/// Every settled condition decides on the live HTTP stage exactly as the
/// kernel decides it with the facts built by hand, for each principal, each
/// trust boundary and either side of the time window.
#[tokio::test]
async fn the_http_stage_decides_settled_conditions_exactly_as_the_kernel() {
    let acme = person(Some("acme"));
    let globex = person(Some("globex"));
    let principals = [None, Some(&acme), Some(&globex)];
    for trusted_proxy in [false, true] {
        for now in [WINDOW_FROM - 1, WINDOW_FROM, WINDOW_UNTIL - 1, WINDOW_UNTIL] {
            for principal in principals {
                for probe in probes() {
                    let client_ip_policy = if trusted_proxy {
                        trusted_proxies()
                    } else {
                        ClientIpPolicy::default()
                    };
                    let (state, capture) = conditioned_state(client_ip_policy, now);
                    let facts = hand_built_facts(&probe, principal, trusted_proxy, now);
                    let expected = kernel_http(&state, &probe, principal, &facts);
                    let case = format!(
                        "{} {:?}, peer {:?}, trusted {trusted_proxy}, now {now}, org {:?}",
                        probe.target,
                        probe.headers,
                        probe.peer,
                        principal.and_then(|principal| principal.org_id.as_deref())
                    );
                    if expected.logical() == LogicalDecision::Indeterminate {
                        // Only the address can be missing here; the stage
                        // refuses rather than guess, as the next test shows.
                        assert!(probe.peer.is_none(), "{case}");
                    }
                    let response = test_router(state.clone(), principal.cloned())
                        .oneshot(probe.request())
                        .await
                        .expect("the request completes");
                    let decision = response
                        .extensions()
                        .get::<PolicyDecision>()
                        .expect("a decision is attached");
                    if expected.logical() == LogicalDecision::Indeterminate {
                        assert_eq!(response.status(), StatusCode::FORBIDDEN, "{case}");
                        assert_eq!(decision.reason, "policy_evaluation_incomplete", "{case}");
                        continue;
                    }
                    assert_eq!(
                        response.status() == StatusCode::FORBIDDEN,
                        expected.effect() == PolicyEffect::Block,
                        "{case}: {expected:?}"
                    );
                    assert_eq!(
                        decision.reason,
                        expected.reason().as_str(),
                        "{case}: {expected:?}"
                    );
                    let expected_rule = match expected.matched() {
                        Some(RuleReference::Direct(index)) => {
                            Some(state.installed_compiled_policy().rule_ids()[index].clone())
                        }
                        _ => None,
                    };
                    assert_eq!(decision.matched_rule_id, expected_rule, "{case}");
                    if expected.effect() == PolicyEffect::Observe {
                        captured_event(&capture, AUTHZ_WOULD_DENY).await;
                    }
                }
            }
        }
    }
}

async fn decide(
    state: &RbacState,
    principal: Option<Principal>,
    probe: &Probe,
) -> (StatusCode, PolicyDecision) {
    let response = test_router(state.clone(), principal)
        .oneshot(probe.request())
        .await
        .expect("the request completes");
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .cloned()
        .expect("a decision is attached");
    (response.status(), decision)
}

/// Header names are case-insensitive and values are not; every occurrence
/// counts, and a comma-separated field line is one value, never split.
#[tokio::test]
async fn header_conditions_read_every_occurrence_and_compare_field_lines_whole() {
    let (state, _capture) = conditioned_state(ClientIpPolicy::default(), WINDOW_FROM - 1);
    for (headers, admitted) in [
        (vec![("x-environment", "canary")], true),
        (vec![("X-ENVIRONMENT", "canary")], true),
        (vec![("x-environment", "CANARY")], false),
        (vec![("x-environment", "prod, canary")], false),
        (vec![("x-environment", "canary, prod")], false),
        (
            vec![("x-environment", "prod"), ("x-environment", "canary")],
            true,
        ),
        (
            vec![("x-environment", "canary"), ("x-environment", "prod")],
            true,
        ),
        (vec![("x-environments", "canary")], false),
        (vec![], false),
    ] {
        let (status, decision) = decide(&state, None, &probe("/canary/x", &headers, None)).await;
        assert_eq!(status == StatusCode::OK, admitted, "{headers:?}");
        if !admitted {
            assert_eq!(
                decision.matched_rule_id.as_deref(),
                Some("canary-only"),
                "{headers:?}"
            );
        }
    }
}

/// A forwarding header moves the source address only when the connection
/// peer is a configured trusted proxy; from anyone else it is ignored, and a
/// request without a peer has no address, which is refused rather than
/// guessed -- under `not` too.
#[tokio::test]
async fn a_client_cannot_spoof_its_source_network() {
    for (client_ip_policy, peer, forwarded, office) in [
        (
            ClientIpPolicy::default(),
            "203.0.113.9:5000",
            Some("10.1.2.3"),
            false,
        ),
        (
            trusted_proxies(),
            "203.0.113.9:5000",
            Some("10.1.2.3"),
            false,
        ),
        (trusted_proxies(), "192.0.2.10:5000", Some("10.1.2.3"), true),
        (
            trusted_proxies(),
            "192.0.2.10:5000",
            Some("203.0.113.9"),
            false,
        ),
        // The nearest address a trusted proxy did not append decides.
        (
            trusted_proxies(),
            "192.0.2.10:5000",
            Some("10.1.2.3, 203.0.113.9"),
            false,
        ),
        (ClientIpPolicy::default(), "10.1.2.3:5000", None, true),
    ] {
        let (state, _capture) = conditioned_state(client_ip_policy, WINDOW_FROM - 1);
        let mut headers = vec![("x-real-ip", "10.9.9.9")];
        headers.extend(forwarded.map(|forwarded| ("x-forwarded-for", forwarded)));
        let mut spoofing = probe("/exports/x?format=csv", &headers, None);
        spoofing.peer = Some(peer);
        let (status, decision) = decide(&state, None, &spoofing).await;
        assert_eq!(status == StatusCode::OK, office, "{peer} {forwarded:?}");
        let expected = if office {
            "office-csv-exports"
        } else {
            "exports-closed"
        };
        assert_eq!(
            decision.matched_rule_id.as_deref(),
            Some(expected),
            "{peer} {forwarded:?}"
        );
    }

    // No peer: the address cannot be told, so neither the allow nor the
    // `not` over it is decided, and both requests are refused as incomplete.
    let (state, capture) = conditioned_state(trusted_proxies(), WINDOW_FROM - 1);
    let (status, decision) = decide(
        &state,
        None,
        &probe(
            "/exports/x?format=csv",
            &[("x-forwarded-for", "10.1.2.3")],
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(decision.reason, "policy_evaluation_incomplete");
    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(
        event.payload["reason"],
        json!("policy_evaluation_incomplete")
    );

    let principal = person(Some("acme"));
    let allowed = state.evaluate_tool_authorization_without_arguments(
        "reports.export",
        Some(&principal),
        None,
        |authorization| matches!(authorization.verdict, ToolInvocationVerdict::Entry { .. }),
    );
    assert!(!allowed, "a tool call without an address is not admitted");
}

/// `[from, until)`: the window opens at `from` and is shut at `until`.
#[tokio::test]
async fn a_time_window_includes_from_and_excludes_until() {
    let clock = PolicyClock::fixed(WINDOW_FROM - 1);
    let (state, _capture) = conditioned_state(ClientIpPolicy::default(), 0);
    let state = state.with_policy_clock(clock.clone());
    let principal = person(Some("acme"));
    for (now, in_window) in [
        (WINDOW_FROM - 1, false),
        (WINDOW_FROM, true),
        (WINDOW_UNTIL - 1, true),
        (WINDOW_UNTIL, false),
    ] {
        clock.set(now);
        let (status, _) = decide(&state, None, &probe("/maintenance/x", &[], None)).await;
        assert_eq!(status == StatusCode::FORBIDDEN, in_window, "HTTP at {now}");
        // The tool lane reads the same clock, through the state's clone.
        let admitted = state.evaluate_tool_authorization_without_arguments(
            "reports.export",
            Some(&principal),
            Some("10.1.2.3".parse().expect("an address")),
            |authorization| match authorization.verdict {
                ToolInvocationVerdict::Entry { rule_decision, .. } => {
                    rule_decision.map(|decision| decision.matched_rule_id)
                }
                _ => Some("refused".to_owned()),
            },
        );
        assert_eq!(
            admitted.as_deref(),
            in_window.then_some("no-exports-in-maintenance"),
            "tool at {now}"
        );
    }
}

/// A query that does not decode strictly is refused before any rule is
/// read, with its own stable reason; a policy whose conditions read no query
/// parameter does not decode the query at all.
#[tokio::test]
async fn an_undecodable_query_is_refused_with_its_own_reason() {
    let (state, capture) = conditioned_state(ClientIpPolicy::default(), WINDOW_FROM - 1);
    for target in ["/elsewhere?format=%zz", "/exports/x?format=csv&q=%FF"] {
        let (status, decision) =
            decide(&state, None, &probe(target, &[], Some("10.1.2.3:5000"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{target}");
        assert_eq!(decision.reason, "policy_query_undecodable", "{target}");
        assert_eq!(decision.matched_rule_id, None, "{target}");
    }
    let event = captured_event(&capture, AUTHZ_DENIED).await;
    assert_eq!(event.payload["reason"], json!("policy_query_undecodable"));

    // Past the fact bounds the request is refused, never truncated: one
    // occurrence too many of the one header a condition reads.
    let mut request = probe("/canary/x", &[], None).request();
    for _ in 0..=crate::policy_eval::MAX_FACT_ENTRIES {
        request
            .headers_mut()
            .append("x-environment", http::HeaderValue::from_static("canary"));
    }
    let response = test_router(state.clone(), None)
        .oneshot(request)
        .await
        .expect("the request completes");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let decision = response
        .extensions()
        .get::<PolicyDecision>()
        .expect("a decision is attached");
    assert_eq!(decision.reason, "policy_evaluation_error");

    let plain = Policy::validate_json_value(json!({
        "schema_version": "1.0.0",
        "default_action": "allow",
        "rules": [{
            "id": "canary-only",
            "path": "/canary/**",
            "action": "deny",
            "conditions": { "header": { "name": "x-environment", "in": ["prod"] } }
        }]
    }))
    .expect("the fixture validates");
    let (state, _capture) = test_state(plain, &[]);
    let (status, _) = decide(&state, None, &probe("/canary/x?format=%zz", &[], None)).await;
    assert_eq!(status, StatusCode::OK);
}

/// The tool lanes read the address the call entered with and the injected
/// clock. A rendered tool request has no headers of its own, so an HTTP rule
/// whose conditions read one cannot be decided for it, and refuses it.
#[test]
fn the_tool_lanes_decide_conditions_from_the_call_context() {
    let (state, _capture) = conditioned_state(ClientIpPolicy::default(), WINDOW_FROM - 1);
    let principal = person(None);
    let office: IpAddr = "10.1.2.3".parse().expect("an address");
    let outside: IpAddr = "203.0.113.9".parse().expect("an address");
    let snapshot = state.installed_compiled_policy();
    let compiled = snapshot.compiled();
    for (address, operation) in [office, outside].into_iter().flat_map(|address| {
        [ToolOperation::Invocation, ToolOperation::Visibility]
            .into_iter()
            .map(move |operation| (address, operation))
    }) {
        let mut facts = PolicyFacts::uncaptured();
        // The policy reads an organization (on an HTTP rule), so the lane
        // captures the principal's: none.
        facts.organization = Fact::Captured(None);
        facts.source_ip = Fact::Captured(address);
        facts.now = Fact::Captured(WINDOW_FROM - 1);
        let context = ToolEvaluationContext {
            version: TOOL_CONTEXT_VERSION,
            snapshot: compiled.snapshot(),
            operation,
            tool_name: Some("reports.export".to_owned()),
            principal: PrincipalFact::Authenticated(PrincipalIdentity::from_principal(&principal)),
            method: None,
            path: None,
        };
        let expected = compiled
            .evaluate_tool_with_facts(&context, &facts, &mut NoStages)
            .expect("the kernel answers");
        let live = match operation {
            ToolOperation::Visibility => {
                state.tool_visible("reports.export", Some(&principal), Some(address))
            }
            _ => state.evaluate_tool_authorization_without_arguments(
                "reports.export",
                Some(&principal),
                Some(address),
                |authorization| match authorization.verdict {
                    ToolInvocationVerdict::Entry { rule_decision, .. } => {
                        rule_decision.is_none_or(|decision| decision.action != RuleAction::Deny)
                    }
                    _ => false,
                },
            ),
        };
        assert_eq!(
            live,
            expected.effect() == PolicyEffect::Allow,
            "{address} {operation:?}: {expected:?}"
        );
        assert_eq!(address == office, live, "{address} {operation:?}");
    }

    // The rendered request reaches a rule over a header it does not carry.
    let refusal = state
        .evaluate_tool_http_rule(
            "reports.export",
            "GET",
            "/render/report",
            Some(&principal),
            Some(office),
        )
        .expect_err("a header condition cannot be decided for a rendered request");
    assert_eq!(refusal.reason(), "policy_evaluation_incomplete");
    // Inventory eligibility previews a call it has no address for.
    let eligibility = state.tool_policy_eligibility("reports.export", &principal);
    assert!(!eligibility.eligible);
    assert_eq!(eligibility.reason, "policy_evaluation_incomplete");
}

/// No header or query value the conditions read, matched or not, reaches an
/// audit record, the policy decision the response carries, or the response.
#[tokio::test]
async fn no_fact_value_reaches_audit_the_decision_or_the_response() {
    let (state, capture) = conditioned_state(ClientIpPolicy::default(), WINDOW_FROM);
    let principal = person(Some("acme"));
    let requests = [
        probe("/canary/x", &[("x-environment", HEADER_CANARY)], None),
        probe(
            "/exports/x?format=qry-canary-9b42",
            &[("x-environment", HEADER_CANARY)],
            Some("10.1.2.3:5000"),
        ),
        probe("/reports/x?format=qry-canary-9b42", &[], None),
        probe(
            "/maintenance/x?format=%zz-qry-canary-9b42",
            &[],
            Some("10.1.2.3:5000"),
        ),
    ];
    for probe in &requests {
        let response = test_router(state.clone(), Some(principal.clone()))
            .oneshot(probe.request())
            .await
            .expect("the request completes");
        let decision = format!("{:?}", response.extensions().get::<PolicyDecision>());
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("the body reads");
        for rendered in [decision, String::from_utf8_lossy(&body).into_owned()] {
            assert!(!rendered.contains(HEADER_CANARY), "{rendered}");
            assert!(!rendered.contains(QUERY_CANARY), "{rendered}");
        }
    }
    assert_eventually(Duration::from_secs(1), || {
        capture.events().len() >= requests.len()
    });
    let audited = serde_json::to_string(&capture.events()).expect("events serialize");
    assert!(!audited.contains(HEADER_CANARY));
    assert!(!audited.contains(QUERY_CANARY));
    // The organization a condition read is not audited either (the audit
    // actor carries none).
    assert!(!audited.contains("acme"));
}
