use std::{
    collections::{BTreeSet, HashSet},
    fs,
    path::PathBuf,
};

use jsonschema::Validator;
use serde_json::{json, Value};

use super::*;
use crate::{
    auth::{AuthMethod, Principal},
    policy_eval::{
        CompiledPolicy, HostFact, HttpTarget, PolicyAuthority, PolicyEvaluationContext,
        PrincipalFact, PrincipalIdentity, CONTEXT_VERSION,
    },
    rbac::{
        policy::{DEFAULT_TOOL_POLICY_MAX_CONCURRENT, DEFAULT_TOOL_POLICY_TIMEOUT_MS},
        PrincipalMatcher, RuleAction, RuleDispatchMatcher,
    },
};

fn inspect(document: &Value) -> PolicyInspection {
    inspect_source(&serde_json::to_vec(document).expect("fixture should serialize"))
}

fn codes_and_pointers(inspection: &PolicyInspection) -> Vec<(&'static str, String)> {
    inspection
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code, diagnostic.pointer.clone()))
        .collect()
}

fn diagnostic(inspection: &PolicyInspection, code: IssueCode) -> &PolicyDiagnostic {
    inspection
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == code.as_str())
        .unwrap_or_else(|| {
            panic!(
                "expected a {code} diagnostic: {:?}",
                inspection.diagnostics()
            )
        })
}

/// A v1 document exercising every section.
fn golden_v1() -> Value {
    json!({
        "schema_version": "1.0.0",
        "id": "golden",
        "roles": {
            "reader": { "permissions": ["data:read"], "issuers": ["https://idp.example.test/"] }
        },
        "routes": [
            { "id": "data-read", "methods": ["GET"], "path_prefix": "/data", "permission": "data:read" }
        ],
        "rules": [
            { "id": "deny-admin", "path": "/admin/**", "action": "deny" }
        ],
        "rate_limits": [
            {
                "id": "reader-burst",
                "principal": { "roles": ["reader"] },
                "requests_per_second": 2.5,
                "burst": 5
            }
        ],
        "tools": { "lookup": { "allowed_roles": ["reader"] } }
    })
}

#[test]
fn only_exactly_1_0_0_dispatches_to_v1() {
    assert_eq!(PolicySchema::of_version("1.0.0"), Some(PolicySchema::V1));
    for v0 in ["0.1.0", "0.2", "0.", "0.99.0-rc.1"] {
        assert_eq!(PolicySchema::of_version(v0), Some(PolicySchema::V0), "{v0}");
    }
    for unsupported in [
        "1",
        "1.0",
        "1.0.1",
        "1.1.0",
        "1.0.0 ",
        " 1.0.0",
        "01.0.0",
        "1.0.0-rc.1",
        "v1",
        "2.0.0",
        "",
    ] {
        assert_eq!(
            PolicySchema::of_version(unsupported),
            None,
            "{unsupported:?}"
        );
    }
    assert_eq!(PolicySchema::V0.document_format_major(), 0);
    assert_eq!(PolicySchema::V1.document_format_major(), 1);

    // A near miss is not read as v1, and not as v0 either.
    let inspection = inspect(&json!({ "schema_version": "1.0.1" }));
    assert!(!inspection.is_valid());
    assert_eq!(inspection.schema_version(), None);
    assert_eq!(
        codes_and_pointers(&inspection),
        vec![("schema_version_unsupported", "/schema_version".to_owned())]
    );
    assert!(
        inspection.error_details()[0].contains("schema_version must start with"),
        "{:?}",
        inspection.error_details()
    );
}

#[test]
fn a_minimal_v1_document_is_valid_and_digests_its_normalized_form() {
    let source = br#"{"schema_version":"1.0.0"}"#;
    let inspection = inspect_source(source);

    assert!(inspection.is_valid(), "{:?}", inspection.diagnostics());
    assert_eq!(inspection.schema_version(), Some("1.0.0"));
    assert!(inspection.diagnostics().is_empty());
    // The normalized form is the gateway's own serialization of the parsed
    // policy, written in JCS. Derived by hand from the field defaults.
    let normalized = serde_json::to_value(inspection.policy().expect("policy")).expect("serialize");
    assert_eq!(
        String::from_utf8(canonical_json::canonical_json_bytes(&normalized).expect("canonical"))
            .expect("utf-8"),
        r#"{"default_action":"deny","enforcement_mode":"enforce","roles":{},"routes":[],"rules":[],"schema_version":"1.0.0"}"#
    );
    // Computed independently from the ADR-0004 frame over those bytes.
    assert_eq!(
        inspection.semantic_digest(),
        Some(MINIMAL_V1_SEMANTIC_DIGEST)
    );
    assert_eq!(
        inspection.source_digest(),
        Some(canonical_json::source_digest("application/json", "1.0.0", source).as_str())
    );
}

#[test]
fn the_v1_semantic_digest_is_pinned_by_an_independent_vector() {
    let inspection = inspect(&golden_v1());
    assert!(inspection.is_valid(), "{:?}", inspection.diagnostics());

    // The issuer lost its trailing slash, every defaulted member is written
    // the way the gateway writes it, and the members are in JCS order. Both
    // the text and the digest were derived without this code.
    let normalized = serde_json::to_value(inspection.policy().expect("policy")).expect("serialize");
    assert_eq!(
        String::from_utf8(canonical_json::canonical_json_bytes(&normalized).expect("canonical"))
            .expect("utf-8"),
        GOLDEN_V1_CANONICAL
    );
    assert_eq!(
        inspection.semantic_digest(),
        Some(GOLDEN_V1_SEMANTIC_DIGEST)
    );
}

#[test]
fn the_semantic_digest_ignores_representation_and_binds_meaning() {
    let golden = inspect(&golden_v1());
    // Same policy, spelled differently: other member order and whitespace,
    // explicit defaults, and an issuer the gateway canonicalizes.
    let respelled = br#"{
        "tools": { "lookup": { "timeout_ms": 30000, "allowed_roles": ["reader"], "enabled": true } },
        "rate_limits": [ { "burst": 5, "requests_per_second": 2.50, "methods": [],
                           "principal": { "roles": ["reader"], "issuers": [] }, "id": "reader-burst" } ],
        "rules": [ { "action": "deny", "enabled": true, "path": "/admin/**", "methods": [],
                     "principal": {}, "id": "deny-admin" } ],
        "routes": [ { "permission": "data:read", "path_prefix": "/data", "methods": ["GET"],
                      "hosts": [], "id": "data-read" } ],
        "roles": { "reader": { "issuers": ["https://idp.example.test///"], "permissions": ["data:read"] } },
        "enforcement_mode": "enforce",
        "default_action": "deny",
        "id": "golden",
        "schema_version": "1.0.0"
    }"#;
    let respelled = inspect_source(respelled);
    assert!(respelled.is_valid(), "{:?}", respelled.diagnostics());
    assert_eq!(respelled.semantic_digest(), golden.semantic_digest());
    assert_ne!(respelled.source_digest(), golden.source_digest());

    // A change in meaning is a change in digest: order, ids and values all
    // count, because each changes what the policy names or decides.
    let mut reordered = golden_v1();
    reordered["routes"] = json!([
        { "id": "data-read", "methods": ["GET"], "path_prefix": "/data", "permission": "data:read" },
        { "id": "data-all", "path_prefix": "/data", "permission": "data:all" }
    ]);
    let mut swapped = reordered.clone();
    swapped["routes"] = json!([
        { "id": "data-all", "path_prefix": "/data", "permission": "data:all" },
        { "id": "data-read", "methods": ["GET"], "path_prefix": "/data", "permission": "data:read" }
    ]);
    let mut renamed = golden_v1();
    renamed["rules"][0]["id"] = json!("deny-admin-2");
    let mut faster = golden_v1();
    faster["rate_limits"][0]["requests_per_second"] = json!(2.6);
    let digests: HashSet<String> = [golden_v1(), reordered, swapped, renamed, faster]
        .iter()
        .map(|document| {
            inspect(document)
                .semantic_digest()
                .expect("semantic digest")
                .to_owned()
        })
        .collect();
    assert_eq!(digests.len(), 5, "every variant must have its own digest");
}

/// The gateway writes a v1 policy back out -- to `POLICY_FILE`, into its
/// ETag, and as the semantic payload -- through its own serialization. That
/// serialization must itself be a v1 document that reads back as the same
/// policy with the same digests, or a replace would persist a file the next
/// reload refuses, and normalizing twice would name a second policy.
#[test]
fn the_normalized_form_of_a_v1_policy_reads_back_as_itself() {
    let document = json!({
        "schema_version": "1.0.0",
        "id": "every-member",
        "default_action": "allow",
        "enforcement_mode": "shadow",
        "roles": {
            "reader": {
                "permissions": ["data:read"],
                "issuers": ["https://idp.example.test/"],
                "auth_methods": ["bearer_token"],
                "description": "Reads data"
            }
        },
        "routes": [{
            "id": "data-read",
            "methods": ["GET"],
            "hosts": ["api.example.test"],
            "path_prefix": "/data",
            "permission": "data:read",
            "enforcement_mode": "enforce"
        }],
        "rules": [
            {
                "id": "routed",
                "enabled": false,
                "methods": ["POST"],
                "path": "/orders/{id}",
                "dispatch": { "kind": "route", "route_id": "orders" },
                "principal": {
                    "roles": ["reader"],
                    "issuers": ["https://idp.example.test"],
                    "auth_methods": ["session_cookie"],
                    "principal_ids": ["synthetic-user"]
                },
                "action": "deny"
            },
            {
                "id": "legacy",
                "path": "/legacy/**",
                "dispatch": { "kind": "legacy", "upstream_origin": "https://upstream.example.test" },
                "action": "allow"
            },
            { "id": "local", "path": "/local", "dispatch": { "kind": "contextless" }, "action": "allow" },
            { "id": "tool", "tool_name": "lookup", "action": "deny" }
        ],
        "egress": { "hosts": ["*.example.test"], "cidrs": ["192.0.2.0/24"], "ports": [443] },
        "rate_limits": [{
            "id": "reader-burst",
            "principal": { "roles": ["reader"] },
            "methods": ["GET"],
            "path": "/data/**",
            "requests_per_second": 0.5,
            "burst": 3
        }],
        "tools": {
            "lookup": {
                "enabled": false,
                "allowed_roles": ["reader"],
                "issuers": ["https://idp.example.test"],
                "auth_methods": ["service_token"],
                "timeout_ms": 1500,
                "max_concurrent": 2
            }
        }
    });
    let first = inspect(&document);
    assert!(first.is_valid(), "{:?}", first.diagnostics());

    let written = serde_json::to_vec(first.policy().expect("policy")).expect("serialize");
    let second = inspect_source(&written);
    assert!(second.is_valid(), "{:?}", second.diagnostics());
    assert!(
        second.diagnostics().is_empty(),
        "{:?}",
        second.diagnostics()
    );
    assert_eq!(second.policy(), first.policy());
    assert_eq!(second.semantic_digest(), first.semantic_digest());
    // And the file loader, which a reload uses, reads it the same way.
    let reloaded = Policy::from_source(&written, None).expect("reload");
    assert_eq!(Some(&reloaded), first.policy());
}

#[test]
fn v1_requires_a_unique_stable_id_on_every_rule_route_and_rate_override() {
    let inspection = inspect(&json!({
        "schema_version": "1.0.0",
        "routes": [
            { "path_prefix": "/data", "permission": "data:read" },
            { "id": "shared", "path_prefix": "/reports", "permission": "reports:read" }
        ],
        "rules": [
            { "id": "bad id", "path": "/x", "action": "deny" },
            { "id": 7, "path": "/y", "action": "deny" },
            { "id": null, "path": "/z", "action": "deny" },
            { "id": "", "path": "/w", "action": "deny" },
            { "id": "x".repeat(65), "path": "/v", "action": "deny" }
        ],
        "rate_limits": [
            { "id": "shared", "requests_per_second": 1, "burst": 1 }
        ]
    }));

    assert!(!inspection.is_valid());
    assert!(inspection.policy().is_none());
    assert_eq!(
        codes_and_pointers(&inspection),
        vec![
            ("element_id_missing", "/routes/0/id".to_owned()),
            ("element_id_invalid", "/rules/0/id".to_owned()),
            ("element_id_invalid", "/rules/1/id".to_owned()),
            ("element_id_invalid", "/rules/2/id".to_owned()),
            ("element_id_invalid", "/rules/3/id".to_owned()),
            ("element_id_invalid", "/rules/4/id".to_owned()),
            ("element_id_duplicate", "/rate_limits/0/id".to_owned()),
        ]
    );
    let duplicate = diagnostic(&inspection, IssueCode::ElementIdDuplicate);
    assert_eq!(duplicate.element_id.as_deref(), Some("shared"));
    assert_eq!(duplicate.severity, DiagnosticSeverity::Error);
    assert_eq!(
        duplicate.blocks,
        DiagnosticBlocks {
            simulation: true,
            tests: true,
            publication: true,
            evidence: true
        }
    );
    // An id that is not a valid stable id is never reported as the element's.
    assert_eq!(
        diagnostic(&inspection, IssueCode::ElementIdInvalid).element_id,
        None
    );
    assert_eq!(inspection.error_details().len(), 7);

    // The same document through the loaders that run before serving a
    // policy refuses with every problem named.
    let error = Policy::validate_json_value(json!({
        "schema_version": "1.0.0",
        "routes": [{ "path_prefix": "/data", "permission": "data:read" }]
    }))
    .expect_err("an id-less v1 route must be refused");
    assert!(
        error.to_string().contains("/routes/0/id"),
        "unexpected error: {error}"
    );
}

#[test]
fn ids_need_only_be_unique_ids_not_unique_elements() {
    let inspection = inspect(&json!({
        "schema_version": "1.0.0",
        "rules": [
            { "id": "a.b_c-1", "path": "/x", "action": "deny" },
            { "id": "A.B_C-1", "path": "/x", "action": "deny" },
            { "id": "x".repeat(64), "tool_name": "lookup", "action": "deny" }
        ]
    }));

    assert!(inspection.is_valid(), "{:?}", inspection.diagnostics());
}

#[test]
fn v1_refuses_members_it_does_not_define_at_every_level() {
    let inspection = inspect(&json!({
        "schema_version": "1.0.0",
        "future": true,
        "roles": { "reader": { "permissions": [], "grants": [] } },
        "routes": [{ "id": "r", "path_prefix": "/", "permission": "p", "weight": 1 }],
        "rules": [{
            "id": "x",
            "path": "/x",
            "action": "deny",
            "comment": "",
            "principal": { "group": [] },
            "dispatch": { "kind": "contextless", "region": "eu" }
        }],
        "egress": { "hosts": [], "dns": [] },
        "rate_limits": [{ "id": "l", "requests_per_second": 1, "burst": 1, "key": "ip" }],
        "tools": { "lookup": { "enabled": true, "retries": 1 }, "a/b~c": { "x": 1 } }
    }));

    assert_eq!(
        codes_and_pointers(&inspection),
        vec![
            ("unknown_member", "/future".to_owned()),
            ("unknown_member", "/roles/reader/grants".to_owned()),
            ("unknown_member", "/routes/0/weight".to_owned()),
            ("unknown_member", "/rules/0/comment".to_owned()),
            ("unknown_member", "/rules/0/principal/group".to_owned()),
            ("unknown_member", "/rules/0/dispatch/region".to_owned()),
            ("unknown_member", "/rate_limits/0/key".to_owned()),
            ("unknown_member", "/egress/dns".to_owned()),
            ("unknown_member", "/tools/a~1b~0c/x".to_owned()),
            ("unknown_member", "/tools/lookup/retries".to_owned()),
        ]
    );
    let rule_member = &inspection.diagnostics()[3];
    assert_eq!(rule_member.element_id.as_deref(), Some("x"));
    // The message never quotes the document; the pointer locates the member.
    for diagnostic in inspection.diagnostics() {
        assert_eq!(diagnostic.message, IssueCode::UnknownMember.message());
    }
}

#[test]
fn v1_reports_missing_required_members_and_wrong_container_types() {
    let inspection = inspect(&json!({
        "schema_version": "1.0.0",
        "roles": [],
        "routes": [{ "id": "r", "path_prefix": "/" }, "not an object"],
        "rules": [{ "id": "x", "path": "/x", "dispatch": {} }],
        "rate_limits": { "id": "l" },
        "egress": [],
        "tools": { "lookup": 1 }
    }));

    assert_eq!(
        codes_and_pointers(&inspection),
        vec![
            ("invalid_type", "/roles".to_owned()),
            ("required_member_missing", "/routes/0/permission".to_owned()),
            ("invalid_type", "/routes/1".to_owned()),
            ("required_member_missing", "/rules/0/action".to_owned()),
            (
                "required_member_missing",
                "/rules/0/dispatch/kind".to_owned()
            ),
            ("invalid_type", "/rate_limits".to_owned()),
            ("invalid_type", "/egress".to_owned()),
            ("invalid_type", "/tools/lookup".to_owned()),
        ]
    );
    assert_eq!(
        inspect(&json!([{ "schema_version": "1.0.0" }])).schema_version(),
        None,
        "a document that is not an object declares no schema"
    );
}

#[test]
fn v1_refuses_a_repeated_member_name_and_names_where() {
    let source = br#"{"schema_version":"1.0.0","rules":[{"id":"a","path":"/x","action":"allow","action":"deny"}]}"#;
    let inspection = inspect_source(source);

    assert!(!inspection.is_valid());
    assert_eq!(
        codes_and_pointers(&inspection),
        vec![("duplicate_member", "/rules/0/action".to_owned())]
    );
    assert_eq!(
        diagnostic(&inspection, IssueCode::DuplicateMember)
            .element_id
            .as_deref(),
        Some("a")
    );
    // Escapes are decoded first: these two names are one name.
    let escaped = br#"{"schema_version":"1.0.0","id":"a","id":"b"}"#;
    assert_eq!(
        codes_and_pointers(&inspect_source(escaped)),
        vec![("duplicate_member", "/id".to_owned())]
    );
    // Every byte-level reader refuses it, the file loader included.
    let error = Policy::from_source(source, None).expect_err("a repeated member must be refused");
    assert!(
        error.to_string().contains("/rules/0/action"),
        "unexpected error: {error}"
    );
}

#[test]
fn v0_keeps_reading_a_repeated_member_name_and_warns_that_evidence_cannot_rely_on_it() {
    let source = br#"{"schema_version":"0.1.0","rules":[{"id":"a","path":"/x","action":"allow","action":"deny"}]}"#;
    let inspection = inspect_source(source);

    assert!(inspection.is_valid(), "{:?}", inspection.diagnostics());
    // The 0.x reading is unchanged: the last copy wins.
    assert_eq!(
        inspection.policy().expect("policy").rules[0].action,
        RuleAction::Deny
    );
    let warning = diagnostic(&inspection, IssueCode::DuplicateMember);
    assert_eq!(warning.severity, DiagnosticSeverity::Warning);
    assert_eq!(warning.pointer, "/rules/0/action");
    assert_eq!(
        warning.blocks,
        DiagnosticBlocks {
            simulation: false,
            tests: false,
            publication: false,
            evidence: true
        }
    );
    assert!(inspection.error_details().is_empty());
}

#[test]
fn v1_refuses_numbers_without_a_canonical_form() {
    let source = br#"{
        "schema_version": "1.0.0",
        "rate_limits": [{ "id": "l", "requests_per_second": 1e300, "burst": 1 }],
        "tools": { "lookup": { "timeout_ms": 9007199254740992 } }
    }"#;
    let inspection = inspect_source(source);

    assert_eq!(
        codes_and_pointers(&inspection),
        vec![
            (
                "number_out_of_range",
                "/rate_limits/0/requests_per_second".to_owned()
            ),
            ("number_out_of_range", "/tools/lookup/timeout_ms".to_owned()),
        ]
    );
    // The same values are still accepted in a 0.x document, as they were.
    let v0 = br#"{
        "schema_version": "0.1.0",
        "tools": { "lookup": { "timeout_ms": 9007199254740992 } }
    }"#;
    assert!(inspect_source(v0).is_valid());
}

#[test]
fn v1_refuses_a_number_spelled_through_serde_jsons_private_tag() {
    // Read through `Value` this object is the number 0.5; read straight from
    // the bytes it is an object where a number belongs. A document must mean
    // the same to both readings.
    let source = br#"{"schema_version":"1.0.0","rate_limits":[{"id":"l","requests_per_second":{"$serde_json::private::Number":"0.5"},"burst":1}]}"#;
    let inspection = inspect_source(source);

    assert!(!inspection.is_valid());
    assert!(
        inspection
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error),
        "{:?}",
        inspection.diagnostics()
    );
}

#[test]
fn v1_refuses_a_document_larger_than_a_policy_file_may_be() {
    let padding = " ".repeat(MAX_POLICY_FILE_BYTES as usize);
    let source = format!(r#"{{"schema_version":"1.0.0"}}{padding}"#);
    let inspection = inspect_source(source.as_bytes());

    assert_eq!(
        codes_and_pointers(&inspection),
        vec![("document_too_large", String::new())]
    );
}

#[test]
fn v1_semantic_problems_carry_code_pointer_element_id_and_the_original_detail() {
    let inspection = inspect(&json!({
        "schema_version": "1.0.0",
        "rules": [
            { "id": "ok", "path": "/fine", "action": "allow" },
            { "id": "relative", "path": "relative", "action": "deny" }
        ]
    }));

    assert_eq!(
        codes_and_pointers(&inspection),
        vec![("path_not_absolute", "/rules/1/path".to_owned())]
    );
    assert_eq!(
        inspection.diagnostics()[0].element_id.as_deref(),
        Some("relative")
    );
    assert_eq!(
        inspection.error_details(),
        ["rules[1].path must start with '/', got 'relative'".to_owned()]
    );
    // The diagnostic itself quotes nothing from the document.
    assert!(!inspection.diagnostics()[0].message.contains("relative"));
}

#[test]
fn semantic_problems_point_into_every_section() {
    for (document, expected) in [
        (
            json!({"schema_version":"1.0.0","routes":[{"id":"r","path_prefix":"/","permission":"p","hosts":["a.test","A.test"]}]}),
            ("route_host_duplicate", "/routes/0/hosts/1"),
        ),
        (
            json!({"schema_version":"1.0.0","rules":[{"id":"t","tool_name":"lookup","methods":["GET"],"action":"deny"}]}),
            ("tool_rule_methods_present", "/rules/0/methods"),
        ),
        (
            json!({"schema_version":"1.0.0","rules":[{"id":"d","path":"/x","action":"deny","dispatch":{"kind":"legacy"}}]}),
            (
                "dispatch_member_missing",
                "/rules/0/dispatch/upstream_origin",
            ),
        ),
        (
            json!({"schema_version":"1.0.0","rules":[{"id":"d","path":"/x","action":"deny","dispatch":{"kind":"legacy","upstream_origin":"https://user@host.test"}}]}),
            (
                "dispatch_origin_invalid",
                "/rules/0/dispatch/upstream_origin",
            ),
        ),
        (
            json!({"schema_version":"1.0.0","rules":[{"id":"p","path":"/x","action":"deny","principal":{"issuers":[" "]}}]}),
            ("issuer_empty", "/rules/0/principal/issuers/0"),
        ),
        (
            json!({"schema_version":"1.0.0","rate_limits":[{"id":"l","requests_per_second":1,"burst":0}]}),
            ("rate_limit_burst_invalid", "/rate_limits/0/burst"),
        ),
        (
            json!({"schema_version":"1.0.0","roles":{"a/b":{"auth_methods":["password"]}}}),
            ("auth_method_unknown", "/roles/a~1b/auth_methods/0"),
        ),
        (
            json!({"schema_version":"1.0.0","roles":{"reader":{"description":" "}}}),
            ("role_description_invalid", "/roles/reader/description"),
        ),
        (
            json!({"schema_version":"1.0.0","tools":{"lookup":{"timeout_ms":0}}}),
            ("tool_timeout_invalid", "/tools/lookup/timeout_ms"),
        ),
        (
            json!({"schema_version":"1.0.0","egress":{"cidrs":["10.0.0.0/8","nope"]}}),
            ("egress_cidr_invalid", "/egress/cidrs/1"),
        ),
        (
            json!({"schema_version":"1.0.0","egress":{"ports":[443,0]}}),
            ("egress_port_invalid", "/egress/ports/1"),
        ),
        (
            json!({"schema_version":"1.0.0","rules":[{"id":"b","path":"/x","tool_name":"y","action":"deny"}]}),
            ("rule_target_invalid", "/rules/0"),
        ),
    ] {
        let inspection = inspect(&document);
        assert_eq!(
            codes_and_pointers(&inspection),
            vec![(expected.0, expected.1.to_owned())],
            "{document}"
        );
    }
}

#[test]
fn an_over_long_tool_name_is_located_without_being_echoed() {
    let long_name = "t".repeat(MAX_TOOL_NAME_BYTES + 1);
    // Whatever the entry holds -- an unknown member, a number without a
    // canonical form, nothing -- the one finding is the name, at the map.
    for entry in [
        json!({ "retries": 1 }),
        json!({ "timeout_ms": 9_007_199_254_740_992_u64 }),
        json!({}),
    ] {
        let inspection = inspect(&json!({
            "schema_version": "1.0.0",
            "tools": { long_name.clone(): entry, "other": {} }
        }));
        assert_eq!(
            codes_and_pointers(&inspection),
            vec![("tool_name_too_long", "/tools".to_owned())],
            "{entry}"
        );
        assert!(inspection
            .error_details()
            .iter()
            .all(|detail| !detail.contains(&long_name)));
    }
    // The 0.x reading refuses the same name the same way, from its semantic
    // validation.
    let v0 = inspect(&json!({
        "schema_version": "0.1.0",
        "tools": { long_name.clone(): {} }
    }));
    assert_eq!(
        codes_and_pointers(&v0),
        vec![("tool_name_too_long", "/tools".to_owned())]
    );
    assert!(v0
        .error_details()
        .iter()
        .all(|detail| !detail.contains(&long_name)));
}

#[test]
fn v1_gives_null_no_reading_where_0x_takes_it_for_absent() {
    // Each of these reads as an omitted member in a 0.x document. v1 defines
    // no member that takes null, so each is refused where it stands.
    let v0 = json!({
        "schema_version": "0.1.0",
        "id": null,
        "roles": { "reader": { "permissions": [], "description": null } },
        "routes": [{ "path_prefix": "/", "permission": "p", "enforcement_mode": null }],
        "rate_limits": [{ "path": null, "requests_per_second": 1, "burst": 1 }]
    });
    assert!(inspect(&v0).is_valid(), "{:?}", inspect(&v0).diagnostics());

    let mut v1 = v0.clone();
    v1["schema_version"] = json!("1.0.0");
    v1["routes"][0]["id"] = json!("root");
    v1["rate_limits"][0]["id"] = json!("everyone");
    let inspection = inspect(&v1);
    assert_eq!(
        codes_and_pointers(&inspection),
        vec![
            ("invalid_type", "/id".to_owned()),
            ("invalid_type", "/rate_limits/0/path".to_owned()),
            ("invalid_type", "/roles/reader/description".to_owned()),
            ("invalid_type", "/routes/0/enforcement_mode".to_owned()),
        ]
    );
    assert_eq!(
        inspection.diagnostics()[1].element_id.as_deref(),
        Some("everyone")
    );
    assert!(!v1_schema_validator().is_valid(&v1));

    // A null element id is reported once, as the invalid id it is.
    let inspection = inspect(&json!({
        "schema_version": "1.0.0",
        "routes": [{ "id": null, "path_prefix": "/", "permission": "p" }]
    }));
    assert_eq!(
        codes_and_pointers(&inspection),
        vec![("element_id_invalid", "/routes/0/id".to_owned())]
    );
}

#[test]
fn a_flood_of_problems_is_reported_up_to_the_bound() {
    let routes: Vec<Value> = (0..MAX_REPORTED_ISSUES + 50)
        .map(|_| json!({ "path_prefix": "/", "permission": "p" }))
        .collect();
    let inspection = inspect(&json!({ "schema_version": "1.0.0", "routes": routes }));

    assert_eq!(inspection.diagnostics().len(), MAX_REPORTED_ISSUES + 1);
    assert_eq!(
        inspection
            .diagnostics()
            .last()
            .map(|diagnostic| diagnostic.code),
        Some("too_many_problems")
    );
    assert_eq!(inspection.error_details().len(), MAX_REPORTED_ISSUES + 1);
}

#[test]
fn a_v0_document_reads_as_before_with_a_source_digest_and_stated_limitations() {
    let source = br#"{
        "schema_version": "0.1.0",
        "comment": "ignored by 0.x readers",
        "routes": [{ "path_prefix": "/data", "permission": "data:read" }],
        "rules": [{ "path": "/admin/**", "action": "deny" }]
    }"#;
    let inspection = inspect_source(source);

    assert!(inspection.is_valid(), "{:?}", inspection.diagnostics());
    assert_eq!(inspection.schema_version(), Some("0.1.0"));
    assert_eq!(
        codes_and_pointers(&inspection),
        vec![
            ("unknown_top_level_member", "/comment".to_owned()),
            ("stable_ids_unavailable", String::new()),
        ]
    );
    assert!(inspection
        .diagnostics()
        .iter()
        .all(
            |diagnostic| diagnostic.severity == DiagnosticSeverity::Warning
                && !diagnostic.blocks.publication
                && diagnostic.blocks.evidence
        ));
    assert_eq!(
        inspection.source_digest(),
        Some(canonical_json::source_digest("application/json", "0.1.0", source).as_str())
    );
    // 0.x defines no normalization, so no semantic digest is claimed for it.
    assert_eq!(inspection.semantic_digest(), None);

    // A 0.x document whose every element is already named states no
    // identity limitation.
    let named = inspect(&json!({
        "schema_version": "0.1.0",
        "rules": [{ "id": "deny-admin", "path": "/admin/**", "action": "deny" }]
    }));
    assert!(named.diagnostics().is_empty(), "{:?}", named.diagnostics());
}

#[test]
fn a_v0_document_cannot_carry_the_ids_v1_adds() {
    for (document, pointer, detail) in [
        (
            json!({"schema_version":"0.1.0","routes":[{"id":"r","path_prefix":"/","permission":"p"}]}),
            "/routes/0/id",
            "routes[0].id requires schema_version \"1.0.0\"",
        ),
        (
            json!({"schema_version":"0.1.0","rate_limits":[{"id":"l","requests_per_second":1,"burst":1}]}),
            "/rate_limits/0/id",
            "rate_limits[0].id requires schema_version \"1.0.0\"",
        ),
    ] {
        let inspection = inspect(&document);
        assert_eq!(
            codes_and_pointers(&inspection),
            vec![("member_requires_v1", pointer.to_owned())]
        );
        let error = Policy::validate_json_value(document).expect_err("0.x ids must be refused");
        assert!(
            error.to_string().contains(detail),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn v0_errors_keep_the_words_the_policy_api_has_always_returned() {
    let invalid_json = inspect_source(b"{\"schema_version\":");
    assert_eq!(
        codes_and_pointers(&invalid_json),
        vec![("invalid_json", String::new())]
    );
    assert!(invalid_json.error_details()[0].starts_with("invalid JSON: "));

    let bom = inspect_source(b"\xEF\xBB\xBF{\"schema_version\":\"0.1.0\"}");
    assert_eq!(
        codes_and_pointers(&bom),
        vec![("invalid_json", String::new())]
    );

    let wrong_type = inspect(&json!({
        "schema_version": "0.1.0",
        "rules": [{ "path": "/ok", "action": "deny" }, { "path": "/x", "action": "maybe" }]
    }));
    assert_eq!(
        codes_and_pointers(&wrong_type),
        vec![("invalid_value", "/rules/1".to_owned())]
    );
    assert!(
        wrong_type.error_details()[0].starts_with("failed to parse policy JSON: "),
        "{:?}",
        wrong_type.error_details()
    );

    let semantic = inspect(&json!({
        "schema_version": "0.1.0",
        "routes": [{ "path_prefix": "relative", "permission": "p" }]
    }));
    assert_eq!(
        semantic.error_details(),
        ["routes[0].path_prefix must start with '/'".to_owned()]
    );
}

#[test]
fn a_v1_document_authorizes_exactly_as_the_v0_document_with_the_same_members() {
    let v0 = json!({
        "schema_version": "0.1.0",
        "default_action": "deny",
        "roles": {
            "reader": { "permissions": ["data:read"], "issuers": ["https://idp.example.test"] },
            "admin": { "permissions": ["*"] }
        },
        "routes": [
            { "methods": ["GET"], "path_prefix": "/data", "permission": "data:read" },
            { "path_prefix": "/data", "permission": "data:write", "enforcement_mode": "shadow" },
            { "path_prefix": "/admin", "permission": "admin:all" }
        ],
        "rules": [
            { "id": "deny-secret", "path": "/data/secret/**", "action": "deny" },
            { "id": "shadow-export", "methods": ["POST"], "path": "/data/export", "action": "shadow" },
            { "id": "public", "path": "/public/**", "action": "allow" }
        ],
        "rate_limits": [
            { "principal": { "roles": ["reader"] }, "path": "/data/**", "requests_per_second": 2.5, "burst": 5 },
            { "requests_per_second": 10, "burst": 20 }
        ]
    });
    let mut v1 = v0.clone();
    v1["schema_version"] = json!("1.0.0");
    for (index, id) in ["data-read", "data-write", "admin"].iter().enumerate() {
        v1["routes"][index]["id"] = json!(id);
    }
    for (index, id) in ["reader-data", "everyone"].iter().enumerate() {
        v1["rate_limits"][index]["id"] = json!(id);
    }

    let v0_policy = Policy::validate_json_value(v0).expect("v0 fixture should parse");
    let v1_policy = Policy::validate_json_value(v1).expect("v1 fixture should parse");

    // Structurally, the only differences are the version and the new ids.
    let mut projected = v1_policy.clone();
    projected.schema_version = v0_policy.schema_version.clone();
    for route in &mut projected.routes {
        route.id = None;
    }
    for rule in &mut projected.rate_limits {
        rule.id = None;
    }
    assert_eq!(projected, v0_policy);

    // And through the evaluator the live gateway uses, every decision and
    // every rate-lane selection agrees.
    let v0_compiled = CompiledPolicy::from_validated_policy(v0_policy, PolicyAuthority::Standalone)
        .expect("v0 compiles");
    let v1_compiled = CompiledPolicy::from_validated_policy(v1_policy, PolicyAuthority::Standalone)
        .expect("v1 compiles");
    let reader = principal(&["reader"]);
    let admin = principal(&["admin"]);
    let mut compared = 0;
    for method in [http::Method::GET, http::Method::POST, http::Method::DELETE] {
        for path in [
            "/data",
            "/data/item",
            "/data/secret/key",
            "/data/export",
            "/admin/users",
            "/public/page",
            "/other",
        ] {
            for who in [None, Some(&reader), Some(&admin)] {
                let decide = |compiled: &CompiledPolicy| {
                    let context = PolicyEvaluationContext {
                        version: CONTEXT_VERSION,
                        snapshot: compiled.snapshot(),
                        method: Some(method.clone()),
                        path: Some(path.to_owned()),
                        principal: who.map_or(PrincipalFact::Anonymous, |principal| {
                            PrincipalFact::Authenticated(PrincipalIdentity::from_principal(
                                principal,
                            ))
                        }),
                        target: HttpTarget::Contextless,
                        request_host: HostFact::Absent,
                        dispatch: None,
                    };
                    let evaluation = compiled.evaluate(&context).expect("evaluates");
                    let lane = compiled.select_rate_lane(&context).expect("selects");
                    (
                        evaluation.logical(),
                        evaluation.effect(),
                        evaluation.reason(),
                        evaluation.matched(),
                        evaluation.observation(),
                        format!("{:?}", lane.outcome()),
                    )
                };
                assert_eq!(
                    decide(&v1_compiled),
                    decide(&v0_compiled),
                    "{method} {path} as {:?}",
                    who.map(|principal| &principal.roles)
                );
                compared += 1;
            }
        }
    }
    assert_eq!(compared, 63);
}

#[test]
fn every_repository_v0_document_still_reads_unchanged() {
    for relative_path in ["docs/examples/policy.starter.json", "dev/policy.json"] {
        let path = repo_root().join(relative_path);
        let source = fs::read(&path).unwrap_or_else(|err| panic!("{relative_path}: {err}"));
        let inspection = inspect_source(&source);
        assert!(
            inspection.is_valid(),
            "{relative_path}: {:?}",
            inspection.diagnostics()
        );
        assert!(inspection
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.severity == DiagnosticSeverity::Warning));
        // A 0.x policy serializes exactly as before v1: no route or rate
        // override gains an `id` member, so its ETag and every stored copy
        // are unchanged.
        let policy = Policy::from_file(&path).expect("example should parse");
        let serialized = serde_json::to_value(&policy).expect("serialize");
        for section in ["routes", "rate_limits"] {
            for element in serialized
                .get(section)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                assert!(element.get("id").is_none(), "{relative_path} {section}");
            }
        }
        assert_eq!(inspection.policy(), Some(&policy));
    }
}

#[test]
fn a_deployment_refusal_blocks_publication_without_hiding_the_document() {
    let mut inspection = inspect(&golden_v1());
    assert!(inspection.is_valid());

    inspection.refuse(
        IssueCode::DocumentFormatUnsupportedInCluster,
        "/schema_version",
        "cluster mode reads only 0.x documents".to_owned(),
    );

    assert!(!inspection.is_valid());
    assert!(inspection.policy().is_some());
    assert!(inspection.semantic_digest().is_some());
    let refusal = diagnostic(&inspection, IssueCode::DocumentFormatUnsupportedInCluster);
    assert_eq!(
        refusal.blocks,
        DiagnosticBlocks {
            simulation: false,
            tests: false,
            publication: true,
            evidence: false
        }
    );
    assert_eq!(
        inspection.into_policy().expect_err("refused"),
        vec!["cluster mode reads only 0.x documents".to_owned()]
    );
}

#[test]
fn diagnostics_serialize_to_the_documented_shape() {
    let inspection = inspect(&json!({
        "schema_version": "1.0.0",
        "rules": [{ "id": "x", "path": "relative", "action": "deny" }]
    }));

    assert_eq!(
        serde_json::to_value(inspection.diagnostics()).expect("serialize"),
        json!([{
            "code": "path_not_absolute",
            "severity": "error",
            "pointer": "/rules/0/path",
            "element_id": "x",
            "message": "the path does not start with '/'",
            "remediation": "Write the path as an absolute path beginning with '/'.",
            "blocks": { "simulation": true, "tests": true, "publication": true, "evidence": true }
        }])
    );
}

#[test]
fn the_code_vocabulary_is_closed_unique_and_stable_text() {
    let mut seen = HashSet::new();
    for code in IssueCode::ALL {
        let name = code.as_str();
        assert!(seen.insert(name), "{name} is listed twice");
        assert!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_' || byte.is_ascii_digit()),
            "{name} is not a snake_case code"
        );
        assert!(!code.message().is_empty() && !code.message().contains('{'));
        assert!(code.remediation().ends_with('.'), "{name}");
    }
}

#[test]
fn json_pointer_tokens_escape_tilde_before_slash() {
    assert_eq!(pointer_token("a/b~c"), "a~1b~0c");
    assert_eq!(pointer_token("~1"), "~01");
    assert_eq!(pointer_token("plain"), "plain");
}

#[test]
fn the_member_vocabularies_match_the_parser() {
    // Every member the gateway writes for a fully populated element is in its
    // v1 vocabulary, and nothing else is: a field added to a struct without
    // its vocabulary entry fails here rather than being refused in v1.
    let rule = Rule {
        id: Some("x".to_owned()),
        enabled: false,
        methods: vec!["GET".to_owned()],
        path: "/x".to_owned(),
        tool_name: Some("t".to_owned()),
        dispatch: Some(RuleDispatchMatcher::legacy("https://a.test".to_owned())),
        principal: full_principal(),
        action: RuleAction::Deny,
    };
    let mut dispatch = RuleDispatchMatcher::legacy("https://a.test".to_owned());
    dispatch.route_id = Some("r".to_owned());
    let route = RouteRule {
        id: Some("r".to_owned()),
        methods: vec!["GET".to_owned()],
        hosts: vec!["a.test".to_owned()],
        path_prefix: "/".to_owned(),
        permission: "p".to_owned(),
        enforcement_mode: Some(EnforcementMode::Shadow),
    };
    let rate_limit = RateLimitRule {
        id: Some("l".to_owned()),
        principal: full_principal(),
        methods: vec!["GET".to_owned()],
        path: Some("/".to_owned()),
        requests_per_second: 1.0,
        burst: 1,
    };
    let role = RoleEntry {
        permissions: vec!["p".to_owned()],
        issuers: vec!["i".to_owned()],
        auth_methods: vec!["bearer_token".to_owned()],
        description: Some("d".to_owned()),
    };
    let tool = ToolPolicyEntry {
        enabled: true,
        allowed_roles: vec!["r".to_owned()],
        issuers: vec!["i".to_owned()],
        auth_methods: vec!["bearer_token".to_owned()],
        timeout_ms: DEFAULT_TOOL_POLICY_TIMEOUT_MS,
        max_concurrent: DEFAULT_TOOL_POLICY_MAX_CONCURRENT,
    };
    let egress = EgressPolicy {
        hosts: vec!["a.test".to_owned()],
        cidrs: vec!["10.0.0.0/8".to_owned()],
        ports: vec![443],
    };
    for (value, members) in [
        (serde_json::to_value(&rule), &RULE_MEMBERS),
        (serde_json::to_value(&dispatch), &DISPATCH_MEMBERS),
        (serde_json::to_value(full_principal()), &PRINCIPAL_MEMBERS),
        (serde_json::to_value(&route), &ROUTE_MEMBERS),
        (serde_json::to_value(&rate_limit), &RATE_LIMIT_MEMBERS),
        (serde_json::to_value(&role), &ROLE_MEMBERS),
        (serde_json::to_value(&tool), &TOOL_MEMBERS),
        (serde_json::to_value(&egress), &EGRESS_MEMBERS),
    ] {
        let value = value.expect("serialize");
        let written: BTreeSet<&str> = value
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect();
        let allowed: BTreeSet<&str> = members.allowed.iter().copied().collect();
        assert_eq!(written, allowed);
    }

    let policy = Policy::validate_json_value(json!({
        "schema_version": "1.0.0",
        "id": "p",
        "egress": { "hosts": ["a.test"] },
        "rate_limits": [{ "id": "l", "requests_per_second": 1, "burst": 1 }],
        "tools": { "t": {} }
    }))
    .expect("policy");
    let written: BTreeSet<String> = serde_json::to_value(&policy)
        .expect("serialize")
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect();
    let known: BTreeSet<String> = KNOWN_TOP_LEVEL_KEYS
        .iter()
        .map(|key| (*key).to_owned())
        .collect();
    assert_eq!(written, known);
}

#[test]
fn the_published_v1_schema_matches_the_member_vocabularies() {
    let schema = published_v1_schema();
    let definitions = &schema["$defs"];
    for (definition, members, required) in [
        ("rule", &RULE_MEMBERS, vec!["id", "action"]),
        ("rule_dispatch_matcher", &DISPATCH_MEMBERS, vec!["kind"]),
        ("principal_matcher", &PRINCIPAL_MEMBERS, vec![]),
        (
            "route_rule",
            &ROUTE_MEMBERS,
            vec!["id", "path_prefix", "permission"],
        ),
        (
            "rate_limit_rule",
            &RATE_LIMIT_MEMBERS,
            vec!["id", "requests_per_second", "burst"],
        ),
        ("role_entry", &ROLE_MEMBERS, vec![]),
        ("tool_policy_entry", &TOOL_MEMBERS, vec![]),
        ("egress_policy", &EGRESS_MEMBERS, vec![]),
    ] {
        let schema_members: BTreeSet<&str> = definitions[definition]["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{definition} has properties"))
            .keys()
            .map(String::as_str)
            .collect();
        let allowed: BTreeSet<&str> = members.allowed.iter().copied().collect();
        assert_eq!(schema_members, allowed, "{definition}");
        assert_eq!(
            definitions[definition]["additionalProperties"],
            json!(false),
            "{definition}"
        );
        let schema_required: BTreeSet<&str> = definitions[definition]["required"]
            .as_array()
            .map(|required| required.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        assert_eq!(
            schema_required,
            required.into_iter().collect::<BTreeSet<_>>(),
            "{definition}"
        );
    }
    let top_level: BTreeSet<&str> = schema["properties"]
        .as_object()
        .expect("top-level properties")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        top_level,
        KNOWN_TOP_LEVEL_KEYS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );
    assert_eq!(schema["additionalProperties"], json!(false));
    assert_eq!(
        schema["properties"]["schema_version"]["const"],
        json!(POLICY_V1_SCHEMA_VERSION)
    );
    // The schema's id syntax is the gateway's.
    let id_pattern = definitions["element_id"]["pattern"]
        .as_str()
        .expect("element_id pattern");
    assert_eq!(id_pattern, "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$");
}

#[test]
fn the_published_v1_schema_accepts_and_refuses_what_the_gateway_does() {
    let validator = v1_schema_validator();
    assert_schema_accepts(&validator, &golden_v1());
    assert_schema_accepts(&validator, &json!({ "schema_version": "1.0.0" }));

    let mut missing_id = golden_v1();
    missing_id["routes"][0]
        .as_object_mut()
        .expect("route")
        .remove("id");
    let mut bad_id = golden_v1();
    bad_id["rules"][0]["id"] = json!("bad id");
    let mut unknown_top = golden_v1();
    unknown_top["future"] = json!(true);
    let mut unknown_nested = golden_v1();
    unknown_nested["rate_limits"][0]["key"] = json!("ip");
    let mut too_fast = golden_v1();
    too_fast["rate_limits"][0]["requests_per_second"] = json!(9_007_199_254_740_992_u64);
    // A 0.x document is not a v1 document: the v1 schema refuses it, and the
    // gateway reads it under the 0.x rules instead.
    let v0 = json!({ "schema_version": "0.1.0" });
    assert!(!validator.is_valid(&v0));
    let v0_inspection = inspect(&v0);
    assert!(v0_inspection.is_valid());
    assert_eq!(v0_inspection.schema_version(), Some("0.1.0"));
    assert_eq!(v0_inspection.semantic_digest(), None);

    for (name, document) in [
        ("near-miss version", json!({ "schema_version": "1.0.1" })),
        ("route without id", missing_id),
        ("invalid id", bad_id),
        ("unknown top-level member", unknown_top),
        ("unknown element member", unknown_nested),
        ("number past the safe range", too_fast),
    ] {
        assert!(
            !validator.is_valid(&document),
            "the published schema should refuse a {name}"
        );
        assert!(
            !inspect(&document).is_valid(),
            "the gateway should refuse a {name}"
        );
    }
}

fn full_principal() -> PrincipalMatcher {
    PrincipalMatcher {
        roles: vec!["r".to_owned()],
        issuers: vec!["i".to_owned()],
        auth_methods: vec!["bearer_token".to_owned()],
        principal_ids: vec!["u".to_owned()],
    }
}

fn principal(roles: &[&str]) -> Principal {
    Principal {
        user_id: "synthetic-user".to_owned(),
        issuer: Some("https://idp.example.test".to_owned()),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        auth_method: AuthMethod::Bearer,
        email: None,
        org_id: None,
        session_id: "synthetic-session".to_owned(),
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("gateway crate should live directly under the repo root")
        .to_owned()
}

fn published_v1_schema() -> Value {
    let path = repo_root().join("docs/schemas/policy.v1.schema.json");
    let schema = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    serde_json::from_str(&schema)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()))
}

fn v1_schema_validator() -> Validator {
    jsonschema::validator_for(&published_v1_schema())
        .unwrap_or_else(|err| panic!("failed to compile the v1 schema: {err}"))
}

fn assert_schema_accepts(validator: &Validator, document: &Value) {
    if let Err(error) = validator.validate(document) {
        panic!("published v1 schema should accept {document}: {error}");
    }
}

/// `{"schema_version":"1.0.0"}` normalized: the ADR-0004 semantic frame over
/// its JCS bytes, computed outside this code.
const MINIMAL_V1_SEMANTIC_DIGEST: &str =
    "sha256:987420945ae0ff782ebfcfaea81528a8292568ce6b76d61300139a475e786ba7";

/// [`golden_v1`] normalized and canonicalized, written out by hand from the
/// field defaults and RFC 8785's member order.
const GOLDEN_V1_CANONICAL: &str = concat!(
    r#"{"default_action":"deny","enforcement_mode":"enforce","id":"golden","#,
    r#""rate_limits":[{"burst":5,"id":"reader-burst","methods":[],"#,
    r#""principal":{"auth_methods":[],"issuers":[],"principal_ids":[],"roles":["reader"]},"#,
    r#""requests_per_second":2.5}],"#,
    r#""roles":{"reader":{"issuers":["https://idp.example.test"],"permissions":["data:read"]}},"#,
    r#""routes":[{"id":"data-read","methods":["GET"],"path_prefix":"/data","permission":"data:read"}],"#,
    r#""rules":[{"action":"deny","id":"deny-admin","methods":[],"path":"/admin/**","#,
    r#""principal":{"auth_methods":[],"issuers":[],"principal_ids":[],"roles":[]}}],"#,
    r#""schema_version":"1.0.0","#,
    r#""tools":{"lookup":{"allowed_roles":["reader"],"enabled":true,"max_concurrent":8,"timeout_ms":30000}}}"#
);

/// The ADR-0004 semantic frame over [`GOLDEN_V1_CANONICAL`], computed
/// outside this code.
const GOLDEN_V1_SEMANTIC_DIGEST: &str =
    "sha256:ea0ee24587a50ccc33a6b42eed021227fd8a3237b00602665af61745d83d78c4";
