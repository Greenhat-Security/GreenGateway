//! The live fact builder (issue #243): what it captures for each policy, and
//! what it refuses.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::extract::ConnectInfo;
use http::{HeaderMap, HeaderValue};
use serde_json::{json, Value};

use super::*;
use crate::{
    auth::AuthMethod,
    policy_eval::{PolicyAuthority, UNCAPTURED_FACTS},
    rbac::Policy,
};

/// 2026-01-01T00:00:00Z.
const NOW: i64 = 1_767_225_600;

fn compile(document: Value) -> CompiledPolicy {
    let policy = Policy::validate_json_value(document).expect("the fixture validates");
    CompiledPolicy::from_validated_policy(policy, PolicyAuthority::Standalone)
        .expect("a standalone authority is valid")
}

/// A v1 policy with one HTTP rule carrying `conditions`.
fn conditioned(conditions: Value) -> CompiledPolicy {
    compile(json!({
        "schema_version": "1.0.0",
        "rules": [{ "id": "conditioned", "path": "/**", "action": "deny", "conditions": conditions }]
    }))
}

fn headers(lines: &[(&str, &[u8])]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in lines {
        map.append(
            http::header::HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            HeaderValue::from_bytes(value).expect("a header value"),
        );
    }
    map
}

fn peer(address: &str) -> Extensions {
    let mut extensions = Extensions::new();
    extensions.insert(ConnectInfo(
        address.parse::<SocketAddr>().expect("a socket address"),
    ));
    extensions
}

fn uri(target: &str) -> Uri {
    target.parse().expect("a request target")
}

fn build(
    compiled: &CompiledPolicy,
    headers: &HeaderMap,
    target: &str,
    extensions: &Extensions,
    client_ip_policy: &ClientIpPolicy,
) -> Result<PolicyFacts, FactsRefusal> {
    http_request_facts(
        compiled,
        None,
        headers,
        &uri(target),
        extensions,
        client_ip_policy,
        &PolicyClock::fixed(NOW),
    )
}

fn query_of(
    compiled: &CompiledPolicy,
    target: &str,
) -> Result<Vec<(String, String)>, FactsRefusal> {
    match build(
        compiled,
        &HeaderMap::new(),
        target,
        &Extensions::new(),
        &ClientIpPolicy::default(),
    )?
    .query
    {
        Fact::Captured(pairs) => Ok(pairs),
        Fact::Uncaptured => panic!("a query condition captures the query"),
    }
}

fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

/// A policy that reads no fact gets none, whatever the request carries, so it
/// decides and binds exactly as before conditions were served.
#[test]
fn a_policy_without_conditions_captures_nothing() {
    let compiled = compile(json!({
        "schema_version": "1.0.0",
        "rules": [{ "id": "plain", "path": "/**", "action": "deny" }]
    }));
    let facts = build(
        &compiled,
        &headers(&[("x-environment", b"prod")]),
        "/x?mode=%zz",
        &peer("203.0.113.9:443"),
        &ClientIpPolicy::default(),
    )
    .expect("an unread query is not decoded");
    assert_eq!(facts, UNCAPTURED_FACTS);
    let call = ToolCallFacts {
        source_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        clock: &PolicyClock::fixed(NOW),
    };
    assert_eq!(tool_call_facts(&compiled, None, call), UNCAPTURED_FACTS);
}

/// Only the headers a condition names are copied, every occurrence in the
/// order received and each field line whole.
#[test]
fn only_referenced_headers_are_copied_with_every_occurrence_in_order() {
    let compiled = conditioned(json!({ "any": [
        { "header": { "name": "x-environment", "in": ["canary"] } },
        { "header": { "name": "x-region", "in": ["eu"] } }
    ] }));
    assert_eq!(
        compiled.fact_needs().headers,
        vec!["x-environment".to_owned(), "x-region".to_owned()]
    );
    let request = headers(&[
        ("x-environment", b"prod, canary"),
        ("x-unrelated", b"left out"),
        ("X-Environment", b"canary"),
        ("x-region", b"eu"),
    ]);
    let facts = build(
        &compiled,
        &request,
        "/x",
        &Extensions::new(),
        &ClientIpPolicy::default(),
    )
    .expect("the headers are within bounds");
    assert_eq!(
        facts.headers,
        Fact::Captured(pairs(&[
            ("x-environment", "prod, canary"),
            ("x-environment", "canary"),
            ("x-region", "eu"),
        ]))
    );
    // Nothing else is read for a policy that reads headers only.
    assert_eq!(facts.query, Fact::Uncaptured);
    assert_eq!(facts.source_ip, Fact::Uncaptured);
    assert_eq!(facts.now, Fact::Uncaptured);

    // A request without the header carried none: a certain absence.
    let facts = build(
        &compiled,
        &HeaderMap::new(),
        "/x",
        &Extensions::new(),
        &ClientIpPolicy::default(),
    )
    .expect("no headers");
    assert_eq!(facts.headers, Fact::Captured(Vec::new()));
}

/// A value that is not UTF-8 still counts as an occurrence, and can never
/// equal an authored value.
#[test]
fn an_opaque_header_value_is_an_occurrence_that_matches_nothing() {
    let compiled = conditioned(json!({ "header": { "name": "x-environment", "in": ["prod"] } }));
    let facts = build(
        &compiled,
        &headers(&[("x-environment", b"pro\xffd")]),
        "/x",
        &Extensions::new(),
        &ClientIpPolicy::default(),
    )
    .expect("within bounds");
    let Fact::Captured(lines) = &facts.headers else {
        panic!("headers are captured");
    };
    assert_eq!(lines.len(), 1);
    assert_ne!(lines[0].1, "prod");
}

/// Past the evaluator's bounds the request is refused, never truncated.
#[test]
fn headers_past_the_fact_bounds_are_refused() {
    let compiled = conditioned(json!({ "header": { "name": "x-environment", "in": ["prod"] } }));
    let mut many = HeaderMap::new();
    for _ in 0..=MAX_FACT_ENTRIES {
        many.append("x-environment", HeaderValue::from_static("prod"));
    }
    let long = "a".repeat(MAX_FACT_VALUE_BYTES + 1);
    let long = headers(&[("x-environment", long.as_bytes())]);
    for request in [many, long] {
        assert_eq!(
            build(
                &compiled,
                &request,
                "/x",
                &Extensions::new(),
                &ClientIpPolicy::default()
            ),
            Err(FactsRefusal::TooLarge)
        );
    }
    // Exactly at the bound is accepted.
    let mut bounded = HeaderMap::new();
    for _ in 0..MAX_FACT_ENTRIES {
        bounded.append("x-environment", HeaderValue::from_static("prod"));
    }
    assert!(build(
        &compiled,
        &bounded,
        "/x",
        &Extensions::new(),
        &ClientIpPolicy::default()
    )
    .is_ok());
}

/// The query is decoded as a form is, strictly, with repeated keys kept in
/// order and only the parameters a condition reads retained.
#[test]
fn the_query_is_decoded_strictly_and_repeated_keys_are_preserved() {
    let compiled = conditioned(json!({ "any": [
        { "query": { "name": "mode", "in": ["read"] } },
        { "query": { "name": "two words", "in": [""] } }
    ] }));
    for (target, expected) in [
        ("/x", Vec::new()),
        ("/x?", Vec::new()),
        (
            "/x?mode=read&other=1&mode=write&mode",
            pairs(&[("mode", "read"), ("mode", "write"), ("mode", "")]),
        ),
        ("/x?mo%64e=re%61d", pairs(&[("mode", "read")])),
        ("/x?two+words=a+b%2Bc", pairs(&[("two words", "a b+c")])),
        ("/x?two%20words", pairs(&[("two words", "")])),
        ("/x?mode=a=b", pairs(&[("mode", "a=b")])),
        ("/x?&&mode=read&", pairs(&[("mode", "read")])),
        ("/x?mode=caf%C3%A9", pairs(&[("mode", "caf\u{e9}")])),
        // `;` is not a separator, and case is part of the name.
        (
            "/x?mode=read;mode=write&MODE=read",
            pairs(&[("mode", "read;mode=write")]),
        ),
    ] {
        assert_eq!(query_of(&compiled, target), Ok(expected), "{target}");
    }
}

/// An escape lenient decoders disagree about refuses the whole query, even
/// in a parameter no condition reads.
#[test]
fn a_query_that_does_not_decode_strictly_is_refused() {
    let compiled = conditioned(json!({ "query": { "name": "mode", "in": ["read"] } }));
    for target in [
        "/x?mode=%zz",
        "/x?mode=%4",
        "/x?mode=read%",
        "/x?mode=%FF",
        "/x?mode=%C3",
        "/x?mode=read%00",
        "/x?mode=read%0Aextra",
        "/x?mode=read&other=%G0",
        "/x?mo%de=read",
    ] {
        assert_eq!(
            query_of(&compiled, target),
            Err(FactsRefusal::QueryUndecodable),
            "{target}"
        );
    }
    let many = format!("/x?{}", vec!["mode=read"; MAX_FACT_ENTRIES + 1].join("&"));
    assert_eq!(query_of(&compiled, &many), Err(FactsRefusal::TooLarge));
}

/// The source address is the canonical client address under the trust
/// boundary: a forwarding header counts only from a trusted proxy, and a
/// request without a connection peer has no address at all.
#[test]
fn the_source_address_is_the_canonical_client_address() {
    let compiled = conditioned(json!({ "source_network": { "cidrs": ["10.0.0.0/8"] } }));
    let forwarded = headers(&[("x-forwarded-for", b"10.1.2.3"), ("x-real-ip", b"10.1.2.4")]);
    let trusted =
        ClientIpPolicy::from_trusted_proxy_cidrs(vec!["192.0.2.0/24".parse().expect("a CIDR")]);
    let address = |headers: &HeaderMap, extensions: &Extensions, policy: &ClientIpPolicy| {
        build(&compiled, headers, "/x", extensions, policy)
            .expect("no bounded fact")
            .source_ip
    };
    let ip = |text: &str| Fact::Captured(text.parse::<IpAddr>().expect("an address"));
    // An untrusted peer's forwarding headers are ignored.
    assert_eq!(
        address(&forwarded, &peer("203.0.113.9:443"), &trusted),
        ip("203.0.113.9")
    );
    assert_eq!(
        address(
            &forwarded,
            &peer("203.0.113.9:443"),
            &ClientIpPolicy::default()
        ),
        ip("203.0.113.9")
    );
    // A trusted proxy's are honored.
    assert_eq!(
        address(&forwarded, &peer("192.0.2.10:443"), &trusted),
        ip("10.1.2.3")
    );
    // An IPv4-mapped peer is the IPv4 address.
    assert_eq!(
        address(
            &HeaderMap::new(),
            &peer("[::ffff:10.9.8.7]:443"),
            &ClientIpPolicy::default()
        ),
        ip("10.9.8.7")
    );
    // No peer, no address: undetermined rather than guessed.
    assert_eq!(
        address(&forwarded, &Extensions::new(), &trusted),
        Fact::Uncaptured
    );
}

/// The instant comes from the injected clock, and only for a policy with a
/// time window.
#[test]
fn the_instant_comes_from_the_injected_clock() {
    let compiled = conditioned(json!({ "time_window": { "until": "2027-01-01T00:00:00Z" } }));
    let clock = PolicyClock::fixed(NOW);
    let now = |clock: &PolicyClock| {
        http_request_facts(
            &compiled,
            None,
            &HeaderMap::new(),
            &uri("/x"),
            &Extensions::new(),
            &ClientIpPolicy::default(),
            clock,
        )
        .expect("no bounded fact")
        .now
    };
    assert_eq!(now(&clock), Fact::Captured(NOW));
    clock.set(NOW + 1);
    assert_eq!(now(&clock), Fact::Captured(NOW + 1));
    assert!(matches!(now(&PolicyClock::System), Fact::Captured(seconds) if seconds > NOW));
}

/// A tool lane captures the organization, the address the call entered with
/// and the instant; a tool call has no headers or query.
#[test]
fn a_tool_call_captures_the_organization_address_and_instant_only() {
    const ISSUER: &str = "https://idp.example.test";
    let compiled = compile(json!({
        "schema_version": "1.0.0",
        "rules": [{
            "id": "conditioned",
            "path": "/**",
            "action": "deny",
            "conditions": { "all": [
                { "organization": { "issuer": ISSUER, "in": ["acme"] } },
                { "source_network": { "cidrs": ["10.0.0.0/8"] } },
                { "header": { "name": "x-environment", "in": ["prod"] } },
                { "query": { "name": "mode", "in": ["read"] } },
                { "time_window": { "until": "2027-01-01T00:00:00Z" } }
            ] }
        }]
    }));
    let principal = Principal {
        user_id: "synthetic-subject".to_owned(),
        issuer: Some(ISSUER.to_owned()),
        email: None,
        org_id: Some("acme".to_owned()),
        roles: Vec::new(),
        session_id: String::new(),
        auth_method: AuthMethod::Bearer,
        scopes: None,
        verified_claims: Vec::new(),
    };
    let clock = PolicyClock::fixed(NOW);
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let facts = tool_call_facts(
        &compiled,
        Some(&principal),
        ToolCallFacts {
            source_address: Some(address),
            clock: &clock,
        },
    );
    assert_eq!(facts.organization, Fact::Captured(Some("acme".to_owned())));
    assert_eq!(facts.source_ip, Fact::Captured(address));
    assert_eq!(facts.now, Fact::Captured(NOW));
    assert_eq!(facts.headers, Fact::Uncaptured);
    assert_eq!(facts.query, Fact::Uncaptured);
    assert_eq!(facts.tool_arguments, Fact::Uncaptured);
    // An internal call has no address, so the network leaf cannot be told.
    let internal = tool_call_facts(
        &compiled,
        Some(&principal),
        ToolCallFacts {
            source_address: None,
            clock: &clock,
        },
    );
    assert_eq!(internal.source_ip, Fact::Uncaptured);
}

/// The argument fact is the eligible scalars the pointers read and nothing
/// else; one ineligible pointer captures none at all.
#[test]
fn tool_argument_facts_carry_only_eligible_referenced_scalars() {
    let schema = json!({
        "type": "object",
        "properties": {
            "region": { "type": "string" },
            "limit": { "type": "integer" },
            "password": { "type": "string", "format": "password" },
            "note": { "type": "string" }
        }
    });
    let arguments = json!({
        "region": "eu",
        "limit": 10,
        "password": "fact-password-canary",
        "note": "fact-note-canary"
    });
    let eligible = ["/limit".to_owned(), "/region".to_owned()];
    assert_eq!(
        tool_argument_facts(&schema, &arguments, &eligible),
        Fact::Captured(json!({ "region": "eu", "limit": 10 }))
    );
    // An argument the call did not pass is simply absent from the fact.
    assert_eq!(
        tool_argument_facts(&schema, &json!({ "limit": 10 }), &eligible),
        Fact::Captured(json!({ "limit": 10 }))
    );
    // A secret-marked or undeclared pointer makes the whole fact uncaptured,
    // so a rule over it is undetermined rather than a no-match.
    for ineligible in ["/password", "/undeclared"] {
        let pointers = ["/region".to_owned(), ineligible.to_owned()];
        assert_eq!(
            tool_argument_facts(&schema, &arguments, &pointers),
            Fact::Uncaptured,
            "{ineligible}"
        );
    }
}
