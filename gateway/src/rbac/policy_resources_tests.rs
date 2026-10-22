use std::{
    collections::{BTreeSet, HashSet},
    sync::Arc,
};

use serde_json::{json, Value};

use super::*;
use crate::{
    auth::{AuthMethod, Principal},
    policy_eval::egress::{CompiledEgressPolicy, EgressControls},
    rbac::policy_document::{DiagnosticBlocks, DiagnosticSeverity},
};

const POLICY_ROUTE: &str = "/v1/admin/policy";

fn policy(document: Value) -> Policy {
    Policy::validate_json_value(document).expect("fixture policy should validate")
}

/// A live policy its `admin` role can replace: write permission, and a
/// route that admits the publisher's `PUT` under a default deny.
fn administered(extra: Value) -> Value {
    let mut document = json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "roles": {
            "admin": { "permissions": ["admin:policy:read", "admin:policy:write"] },
            "reader": { "permissions": ["admin:policy:read"] }
        },
        "routes": [
            { "methods": ["PUT"], "path_prefix": POLICY_ROUTE, "permission": "admin:policy:write" }
        ]
    });
    if let (Some(document), Some(extra)) = (document.as_object_mut(), extra.as_object()) {
        for (name, value) in extra {
            document.insert(name.clone(), value.clone());
        }
    }
    document
}

fn principal(roles: &[&str]) -> Principal {
    Principal {
        user_id: "synthetic-publisher".to_owned(),
        issuer: Some("https://idp.example.test".to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        auth_method: AuthMethod::Bearer,
        email: None,
        org_id: None,
        session_id: "synthetic-session".to_owned(),
    }
}

fn egress(hosts: &[&str], ports: &[u16]) -> Arc<CompiledEgressPolicy> {
    Arc::new(CompiledEgressPolicy::new(EgressControls {
        allowed_hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        allowed_host_globs: Vec::new(),
        allowed_ports: ports.iter().copied().collect::<HashSet<u16>>(),
        deny_private_ips: true,
        nat64_prefixes: Vec::new(),
        private_ip_allow_cidrs: Vec::new(),
    }))
}

/// Every resource read, nothing refused by egress, no tool registered.
fn complete_view() -> PolicyResourceView {
    PolicyResourceView {
        configuration: Some(format!("sha256:{}", "c".repeat(64))),
        egress: Some(egress(&["api.example.test"], &[])),
        tools: Some(ToolInventory {
            names: BTreeSet::new(),
            digest: format!("sha256:{}", "t".repeat(64)),
        }),
        connections: Some(ConnectionInventory {
            etag: "\"connections:sha256:0\"".to_owned(),
            endpoints: vec!["https://api.example.test/v1".to_owned()],
        }),
        admin: Some(AdminSurface {
            policy_route: POLICY_ROUTE.to_owned(),
            policy_route_exempt: false,
        }),
        security_revision: None,
    }
}

fn validate(candidate: &Policy, live: &Policy, view: &PolicyResourceView) -> ResourceValidation {
    validate_resources(candidate, live, view, None)
}

fn validate_as(
    candidate: &Policy,
    live: &Policy,
    view: &PolicyResourceView,
    publisher: &Principal,
    host: Option<&str>,
) -> ResourceValidation {
    validate_resources(
        candidate,
        live,
        view,
        Some(&Publisher {
            principal: publisher,
            request_host: host.map(str::to_owned),
        }),
    )
}

fn codes(validation: &ResourceValidation) -> Vec<(&'static str, String)> {
    validation
        .findings()
        .iter()
        .map(|finding| (finding.diagnostic.code, finding.diagnostic.pointer.clone()))
        .collect()
}

fn finding(validation: &ResourceValidation, code: IssueCode) -> &ResourceFinding {
    validation
        .findings()
        .iter()
        .find(|finding| finding.diagnostic.code == code.as_str())
        .unwrap_or_else(|| panic!("expected {code} in {:?}", codes(validation)))
}

fn has(validation: &ResourceValidation, code: IssueCode) -> bool {
    validation
        .findings()
        .iter()
        .any(|finding| finding.diagnostic.code == code.as_str())
}

const PUBLICATION_ONLY: DiagnosticBlocks = DiagnosticBlocks {
    simulation: false,
    tests: false,
    publication: true,
    evidence: false,
};

const BLOCKS_NOTHING: DiagnosticBlocks = DiagnosticBlocks {
    simulation: false,
    tests: false,
    publication: false,
    evidence: false,
};

#[test]
fn a_policy_that_grants_no_role_policy_write_cannot_be_published() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({
        "roles": { "admin": { "permissions": ["admin:policy:read"] } }
    })));

    let validation = validate(&candidate, &live, &complete_view());

    let refusal = finding(&validation, IssueCode::PolicyWriteUnreachable);
    assert_eq!(refusal.diagnostic.pointer, "/roles");
    assert_eq!(refusal.diagnostic.severity, DiagnosticSeverity::Error);
    assert_eq!(refusal.diagnostic.blocks, PUBLICATION_ONLY);
    assert!(refusal
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("admin:policy:write")));
    assert!(validation.blocks_publication());
    assert_eq!(
        validation.blocking_codes(),
        vec!["policy_write_unreachable"]
    );

    for grant in [json!(["admin:policy:write"]), json!(["*"])] {
        let candidate = policy(administered(json!({
            "roles": { "operator": { "permissions": grant } }
        })));
        let validation = validate(&candidate, &live, &complete_view());
        assert!(!has(&validation, IssueCode::PolicyWriteUnreachable));
    }

    // A live policy that already grants it to nobody is managed another way,
    // and a successor is not refused for staying that way.
    let unmanaged = policy(administered(json!({
        "roles": { "reader": { "permissions": ["admin:policy:read"] } }
    })));
    let validation = validate(&unmanaged, &unmanaged, &complete_view());
    assert!(!has(&validation, IssueCode::PolicyWriteUnreachable));
    assert!(!validation.blocks_publication());
}

#[test]
fn a_publisher_who_would_lose_policy_write_is_told_what_refuses_it() {
    let live = policy(administered(json!({})));
    let publisher = principal(&["admin"]);
    let view = complete_view();
    let lost = |candidate: Value| {
        let validation = validate_as(&policy(candidate), &live, &view, &publisher, None);
        assert!(validation.blocks_publication(), "{:?}", codes(&validation));
        let finding = finding(&validation, IssueCode::PublisherPolicyWriteLost).clone();
        assert_eq!(finding.diagnostic.blocks, PUBLICATION_ONLY);
        finding
    };

    // Its role no longer grants the permission; another role still does, so
    // this is the publisher's lockout, not everyone's.
    let finding = lost(administered(json!({
        "roles": {
            "admin": { "permissions": ["admin:policy:read"] },
            "operator": { "permissions": ["admin:policy:write"] }
        }
    })));
    assert_eq!(finding.diagnostic.pointer, "/roles");

    // A direct rule refuses its PUT, and is named by its stable id.
    let finding = lost(administered(json!({
        "rules": [{ "id": "lock-admin", "path": "/v1/admin/**", "action": "deny" }]
    })));
    assert_eq!(finding.diagnostic.pointer, "/rules/0");
    assert_eq!(finding.diagnostic.element_id.as_deref(), Some("lock-admin"));
    assert!(finding
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("rules[0]")));

    // The route that admitted it now requires a permission it lacks.
    let finding = lost(administered(json!({
        "roles": {
            "admin": { "permissions": ["admin:policy:read", "admin:policy:write"] }
        },
        "routes": [
            { "methods": ["PUT"], "path_prefix": POLICY_ROUTE, "permission": "admin:root" }
        ]
    })));
    assert_eq!(finding.diagnostic.pointer, "/routes/0");

    // No route admits it any more, and the default denies.
    let finding = lost(administered(json!({ "routes": [] })));
    assert_eq!(finding.diagnostic.pointer, "/default_action");
}

#[test]
fn the_publisher_check_asks_the_http_lane_only_where_rbac_applies() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({ "routes": [] })));
    let publisher = principal(&["admin"]);

    let mut exempt = complete_view();
    if let Some(admin) = exempt.admin.as_mut() {
        admin.policy_route_exempt = true;
    }
    let validation = validate_as(&candidate, &live, &exempt, &publisher, None);
    assert!(!has(&validation, IssueCode::PublisherPolicyWriteLost));

    // Shadow enforcement observes the default deny and forwards the request.
    let shadow = policy(administered(
        json!({ "routes": [], "enforcement_mode": "shadow" }),
    ));
    let validation = validate_as(&shadow, &live, &complete_view(), &publisher, None);
    assert!(!has(&validation, IssueCode::PublisherPolicyWriteLost));
    assert!(has(&validation, IssueCode::EnforcementModeShadow));

    // Without the admin surface only the permission can be judged, and the
    // snapshot says so.
    let mut unknown = complete_view();
    unknown.admin = None;
    let validation = validate_as(&candidate, &live, &unknown, &publisher, None);
    assert!(!has(&validation, IssueCode::PublisherPolicyWriteLost));
    assert!(has(&validation, IssueCode::ResourceUnavailable));
    assert!(!validation.snapshot().is_complete());
}

#[test]
fn only_a_publisher_who_can_replace_the_live_policy_has_anything_to_lose() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({ "routes": [] })));

    let validation = validate_as(
        &candidate,
        &live,
        &complete_view(),
        &principal(&["reader"]),
        None,
    );
    assert!(!has(&validation, IssueCode::PublisherPolicyWriteLost));
    assert!(!validation.blocks_publication());
}

#[test]
fn the_publisher_check_judges_the_host_the_publisher_used() {
    let host_bound = |host: &str| {
        policy(json!({
            "schema_version": "0.1.0",
            "default_action": "deny",
            "roles": { "admin": { "permissions": ["admin:policy:write"] } },
            "routes": [{
                "methods": ["PUT"],
                "hosts": [host],
                "path_prefix": POLICY_ROUTE,
                "permission": "admin:policy:write"
            }]
        }))
    };
    let live = host_bound("admin.example.test");
    let publisher = principal(&["admin"]);
    let view = complete_view();

    let same = validate_as(&live, &live, &view, &publisher, Some("admin.example.test"));
    assert!(!same.blocks_publication(), "{:?}", codes(&same));

    let moved = host_bound("ops.example.test");
    let validation = validate_as(&moved, &live, &view, &publisher, Some("admin.example.test"));
    assert_eq!(
        finding(&validation, IssueCode::PublisherPolicyWriteLost)
            .diagnostic
            .pointer,
        "/default_action"
    );

    // A publisher who reached the gateway by another host could not replace
    // the live policy either, so the move takes nothing from it.
    let elsewhere = validate_as(&moved, &live, &view, &publisher, Some("ops.example.test"));
    assert!(!has(&elsewhere, IssueCode::PublisherPolicyWriteLost));
}

#[test]
fn an_egress_change_is_refused_for_publication_only() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({
        "egress": { "hosts": ["*.example.test"] }
    })));

    let validation = validate(&candidate, &live, &complete_view());

    let refusal = finding(&validation, IssueCode::EgressChangeRequiresRestart);
    assert_eq!(refusal.diagnostic.pointer, "/egress");
    assert_eq!(refusal.diagnostic.blocks, PUBLICATION_ONLY);
    assert!(!has(
        &validate(&live, &live, &complete_view()),
        IssueCode::EgressChangeRequiresRestart
    ));
}

#[test]
fn references_to_undefined_roles_are_located_in_every_section() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({
        "tools": { "search": { "allowed_roles": ["admin", "analyst"] } },
        "rules": [{
            "id": "r1",
            "tool_name": "search",
            "principal": { "roles": ["auditor"] },
            "action": "allow"
        }],
        "rate_limits": [{
            "principal": { "roles": ["batch"] },
            "requests_per_second": 1.0,
            "burst": 1
        }]
    })));

    let validation = validate(&candidate, &live, &complete_view());
    let undefined: Vec<(String, Option<String>)> = validation
        .findings()
        .iter()
        .filter(|finding| finding.diagnostic.code == "role_not_defined")
        .map(|finding| {
            assert_eq!(finding.diagnostic.severity, DiagnosticSeverity::Warning);
            assert_eq!(finding.diagnostic.blocks, BLOCKS_NOTHING);
            assert!(finding.detail.is_none());
            (
                finding.diagnostic.pointer.clone(),
                finding.diagnostic.element_id.clone(),
            )
        })
        .collect();
    assert_eq!(
        undefined,
        vec![
            ("/tools/search/allowed_roles/1".to_owned(), None),
            (
                "/rules/0/principal/roles/0".to_owned(),
                Some("r1".to_owned())
            ),
            ("/rate_limits/0/principal/roles/0".to_owned(), None),
        ]
    );
    assert!(!validation.blocks_publication());
}

#[test]
fn a_route_whose_permission_no_role_grants_is_reported() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({
        "routes": [
            { "methods": ["PUT"], "path_prefix": POLICY_ROUTE, "permission": "admin:policy:write" },
            { "path_prefix": "/reports", "permission": "reports:raed" }
        ]
    })));

    let validation = validate(&candidate, &live, &complete_view());
    assert_eq!(
        finding(&validation, IssueCode::RoutePermissionUngranted)
            .diagnostic
            .pointer,
        "/routes/1/permission"
    );

    // A wildcard grant grants it.
    let granted = policy(administered(json!({
        "roles": { "admin": { "permissions": ["*"] } },
        "routes": [{ "path_prefix": "/reports", "permission": "reports:raed" }]
    })));
    assert!(!has(
        &validate(&granted, &live, &complete_view()),
        IssueCode::RoutePermissionUngranted
    ));
}

#[test]
fn a_tool_rule_the_tool_lane_never_reaches_is_reported() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({
        "tools": {
            "enabled": {},
            "disabled": { "enabled": false }
        },
        "rules": [
            { "id": "t0", "tool_name": "enabled", "action": "deny" },
            { "id": "t1", "tool_name": "disabled", "action": "allow" },
            { "id": "t2", "tool_name": "absent", "action": "shadow" },
            { "id": "t3", "tool_name": "absent", "action": "allow", "enabled": false }
        ]
    })));

    let validation = validate(&candidate, &live, &complete_view());
    let never: Vec<(String, Option<String>)> = validation
        .findings()
        .iter()
        .filter(|finding| finding.diagnostic.code == "tool_rule_never_decides")
        .map(|finding| {
            (
                finding.diagnostic.pointer.clone(),
                finding.diagnostic.element_id.clone(),
            )
        })
        .collect();
    assert_eq!(
        never,
        vec![
            ("/rules/1/tool_name".to_owned(), Some("t1".to_owned())),
            ("/rules/2/tool_name".to_owned(), Some("t2".to_owned())),
        ]
    );
}

#[test]
fn tool_names_the_registry_does_not_hold_are_reported_only_when_it_was_read() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({
        "tools": { "search": {}, "a/b~c": {} },
        "rules": [{ "tool_name": "fetch", "action": "deny" }]
    })));
    let mut view = complete_view();
    view.tools = Some(ToolInventory {
        names: ["search".to_owned()].into_iter().collect(),
        digest: format!("sha256:{}", "1".repeat(64)),
    });

    let validation = validate(&candidate, &live, &view);
    let unregistered: Vec<String> = validation
        .findings()
        .iter()
        .filter(|finding| finding.diagnostic.code == "tool_not_registered")
        .map(|finding| finding.diagnostic.pointer.clone())
        .collect();
    assert_eq!(unregistered, vec!["/tools/a~1b~0c", "/rules/0/tool_name"]);
    assert!(validation.snapshot().is_complete());

    // An unread registry is not an empty one: nothing is reported against
    // it, and the snapshot says it was not read.
    view.tools = None;
    let validation = validate(&candidate, &live, &view);
    assert!(!has(&validation, IssueCode::ToolNotRegistered));
    let unavailable = finding(&validation, IssueCode::ResourceUnavailable);
    assert_eq!(unavailable.diagnostic.pointer, "");
    assert_eq!(
        unavailable.diagnostic.blocks,
        DiagnosticBlocks {
            simulation: false,
            tests: false,
            publication: false,
            evidence: true
        }
    );
    let snapshot = serde_json::to_value(validation.snapshot()).expect("serialize");
    assert_eq!(snapshot["complete"], json!(false));
    assert_eq!(snapshot["unavailable"], json!(["tools"]));
    assert_eq!(snapshot["components"]["tools"], Value::Null);
}

#[test]
fn connection_endpoints_the_egress_lane_refuses_are_reported_without_naming_them() {
    let live = policy(administered(json!({})));
    let check = |endpoints: &[&str], hosts: &[&str], ports: &[u16]| {
        let mut view = complete_view();
        view.egress = Some(egress(hosts, ports));
        view.connections = Some(ConnectionInventory {
            etag: "\"connections:sha256:0\"".to_owned(),
            endpoints: endpoints.iter().map(|url| (*url).to_owned()).collect(),
        });
        validate(&live, &live, &view)
    };

    let admitted = check(
        &["https://api.example.test/v1", "not a url"],
        &["api.example.test"],
        &[],
    );
    assert!(!has(&admitted, IssueCode::ConnectionEndpointEgressDenied));

    let refused = check(
        &[
            "https://api.example.test/v1",
            "https://other.example.test",
            "https://third.example.test",
        ],
        &["api.example.test"],
        &[],
    );
    let warnings: Vec<&ResourceFinding> = refused
        .findings()
        .iter()
        .filter(|finding| finding.diagnostic.code == "connection_endpoint_egress_denied")
        .collect();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].diagnostic.pointer, "/egress");
    assert_eq!(warnings[0].diagnostic.blocks, BLOCKS_NOTHING);
    let serialized = serde_json::to_string(&warnings[0].diagnostic).expect("serialize");
    assert!(!serialized.contains("example.test"));

    let wrong_port = check(
        &["http://api.example.test:8080"],
        &["api.example.test"],
        &[443],
    );
    assert!(has(&wrong_port, IssueCode::ConnectionEndpointEgressDenied));
}

#[test]
fn names_that_differ_only_in_case_are_reported() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({
        "roles": {
            "admin": { "permissions": ["admin:policy:write"] },
            "Admin": { "permissions": [] }
        },
        "tools": { "Search": {}, "search": {} }
    })));

    let validation = validate(&candidate, &live, &complete_view());
    let collisions: Vec<String> = validation
        .findings()
        .iter()
        .filter(|finding| finding.diagnostic.code == "name_case_collision")
        .map(|finding| finding.diagnostic.pointer.clone())
        .collect();
    assert_eq!(collisions, vec!["/roles/admin", "/tools/search"]);
}

#[test]
fn risks_are_reported_and_block_nothing() {
    let live = policy(administered(json!({})));
    let candidate = policy(administered(json!({
        "default_action": "allow",
        "enforcement_mode": "shadow",
        "roles": {
            "admin": { "permissions": ["admin:policy:read", "*"] },
            "reader": { "permissions": ["admin:policy:read"] }
        }
    })));

    let validation = validate(&candidate, &live, &complete_view());
    let risks: Vec<(&'static str, String)> = validation
        .findings()
        .iter()
        .filter(|finding| finding.diagnostic.severity == DiagnosticSeverity::Risk)
        .map(|finding| {
            assert_eq!(finding.diagnostic.blocks, BLOCKS_NOTHING);
            assert!(finding.detail.is_none());
            (finding.diagnostic.code, finding.diagnostic.pointer.clone())
        })
        .collect();
    assert_eq!(
        risks,
        vec![
            ("default_action_allow", "/default_action".to_owned()),
            ("enforcement_mode_shadow", "/enforcement_mode".to_owned()),
            (
                "wildcard_permission",
                "/roles/admin/permissions/1".to_owned()
            ),
        ]
    );
    assert_eq!(
        validation.risk_codes(),
        vec![
            "default_action_allow",
            "enforcement_mode_shadow",
            "wildcard_permission"
        ]
    );
    assert!(!validation.blocks_publication());
    assert_eq!(
        serde_json::to_value(&finding(&validation, IssueCode::WildcardPermission).diagnostic)
            .expect("serialize")["severity"],
        json!("risk")
    );
}

#[test]
fn a_sound_publication_finds_nothing_and_binds_a_complete_snapshot() {
    let live = policy(administered(json!({})));

    let validation = validate_as(&live, &live, &complete_view(), &principal(&["admin"]), None);

    assert!(validation.findings().is_empty(), "{:?}", codes(&validation));
    assert!(validation.snapshot().is_complete());
    let snapshot = serde_json::to_value(validation.snapshot()).expect("serialize");
    assert_eq!(snapshot["schema_version"], json!("1.0.0"));
    assert_eq!(
        snapshot["components"]["evaluator"],
        json!({
            "http": "gg-http-alias-v1",
            "http_context": 3,
            "tools": "gg-tool-policy-v1",
            "tool_context": 1,
            "egress": "gg-static-egress-v1",
            "egress_context": 1
        })
    );
    assert_eq!(
        snapshot["components"]["gateway_build"],
        json!(env!("CARGO_PKG_VERSION"))
    );
    assert!(snapshot.get("unavailable").is_none());
    assert!(snapshot["components"].get("security_revision").is_none());
}

#[test]
fn the_snapshot_digest_binds_every_component_and_nothing_else() {
    let live = policy(administered(json!({})));
    let digest = |view: &PolicyResourceView| {
        validate(&live, &live, view)
            .snapshot()
            .digest()
            .expect("a snapshot of strings always has a digest")
            .to_owned()
    };
    let base = digest(&complete_view());
    assert!(base.starts_with("sha256:") && base.len() == 71);

    // The same resources read twice, or validated for another candidate,
    // bind the same snapshot.
    assert_eq!(digest(&complete_view()), base);
    let other_candidate = policy(administered(json!({ "default_action": "allow" })));
    assert_eq!(
        validate(&other_candidate, &live, &complete_view())
            .snapshot()
            .digest()
            .map(str::to_owned),
        Some(base.clone())
    );

    let mut changed = Vec::new();
    let mut view = complete_view();
    view.configuration = Some(format!("sha256:{}", "d".repeat(64)));
    changed.push(digest(&view));
    let mut view = complete_view();
    view.egress = Some(egress(&["api.example.test", "more.example.test"], &[]));
    changed.push(digest(&view));
    let mut view = complete_view();
    if let Some(tools) = view.tools.as_mut() {
        tools.digest = format!("sha256:{}", "u".repeat(64));
    }
    changed.push(digest(&view));
    let mut view = complete_view();
    if let Some(connections) = view.connections.as_mut() {
        connections.etag = "\"connections:sha256:1\"".to_owned();
    }
    changed.push(digest(&view));
    let mut view = complete_view();
    view.security_revision = Some(7);
    changed.push(digest(&view));
    let mut view = complete_view();
    view.tools = None;
    changed.push(digest(&view));

    let distinct: BTreeSet<&String> = changed.iter().chain([&base]).collect();
    assert_eq!(distinct.len(), changed.len() + 1, "{changed:?}");

    // Endpoints are judged, not bound: the collection ETag identifies them.
    let mut view = complete_view();
    if let Some(connections) = view.connections.as_mut() {
        connections
            .endpoints
            .push("https://api.example.test/v2".to_owned());
    }
    assert_eq!(digest(&view), base);
}

#[test]
fn a_cluster_snapshot_records_its_security_revision_in_decimal() {
    let live = policy(administered(json!({})));
    let mut view = complete_view();
    view.security_revision = Some(9_007_199_254_740_993);

    let validation = validate(&live, &live, &view);

    assert!(validation.snapshot().is_complete());
    let snapshot = serde_json::to_value(validation.snapshot()).expect("serialize");
    assert_eq!(
        snapshot["components"]["security_revision"],
        json!("9007199254740993")
    );
}

#[test]
fn an_empty_view_reads_nothing_and_says_so() {
    let live = policy(administered(json!({})));

    let validation = validate(&live, &live, &PolicyResourceView::default());

    let snapshot = serde_json::to_value(validation.snapshot()).expect("serialize");
    assert_eq!(
        snapshot["unavailable"],
        json!([
            "configuration",
            "egress",
            "tools",
            "connections",
            "admin_routes"
        ])
    );
    assert!(!validation.snapshot().is_complete());
    assert_eq!(
        codes(&validation),
        vec![("resource_unavailable", String::new())]
    );
}

#[test]
fn the_rbac_state_reports_its_own_exemption_and_no_resources_it_was_not_given() {
    let state = |exempt: &[&str]| {
        crate::middleware::rbac::RbacState::new(
            policy(administered(json!({}))),
            exempt.iter().map(|path| (*path).to_owned()).collect(),
            false,
            crate::audit::AuditLog::new(Arc::new(crate::audit::sink::tests::CaptureSink::new())),
        )
    };

    let admin = state(&["/v1/admin"]);
    assert!(admin.rbac_exempts_path(POLICY_ROUTE));
    // Prefixes match whole segments, as the RBAC stage matches them.
    assert!(!admin.rbac_exempts_path("/v1/administrators"));
    assert!(!state(&["/v1/admin/policy/validate"]).rbac_exempts_path(POLICY_ROUTE));
    // An exact MCP route is judged whatever encloses it.
    let everything = state(&["/"]);
    assert!(everything.rbac_exempts_path(POLICY_ROUTE));
    assert!(!everything.rbac_exempts_path("/mcp"));

    let view = admin.policy_resource_view();
    assert!(view.configuration.is_none() && view.tools.is_none() && view.admin.is_none());
    assert!(view.security_revision.is_none());
}
