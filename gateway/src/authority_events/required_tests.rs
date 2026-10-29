use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use serde_json::Value;

use super::*;
use crate::audit::sink::tests::CaptureSink;

const EVERY_OPERATION: [AuthorityOperation; 14] = [
    AuthorityOperation::PolicyPublish,
    AuthorityOperation::PolicyRollback,
    AuthorityOperation::PolicyRuleCreate,
    AuthorityOperation::PolicyRuleUpdate,
    AuthorityOperation::PolicyRuleDelete,
    AuthorityOperation::PolicyRuleReorder,
    AuthorityOperation::PolicySuggestionAccept,
    AuthorityOperation::PolicyFileReload,
    AuthorityOperation::ToolsPublish,
    AuthorityOperation::CatalogMcpPublish,
    AuthorityOperation::CatalogOpenapiPublish,
    AuthorityOperation::CatalogOverlayReplace,
    AuthorityOperation::CatalogOverlayDelete,
    AuthorityOperation::ConfigurationImport,
];

/// The operation whose gate covers an inventory operation code, or `None`
/// for one no gate asks about.
fn gated_operation(code: &str) -> Option<AuthorityOperation> {
    EVERY_OPERATION
        .into_iter()
        .find(|operation| operation.code() == code)
}

fn capture_log() -> (AuditLog, CaptureSink) {
    let capture = CaptureSink::new();
    (AuditLog::new(Arc::new(capture.clone())), capture)
}

/// Every event emitted before this call, once the audit writer, which
/// delivers in order, has delivered a marker emitted after them.
fn delivered_events(audit: &AuditLog, capture: &CaptureSink) -> Vec<AuditEvent> {
    audit.emit(AuditEvent::new(
        "test.marker",
        "marker",
        "internal",
        None,
        json!({}),
    ));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let mut events = capture.events();
        if events
            .last()
            .is_some_and(|event| event.event_type == "test.marker")
        {
            events.pop();
            return events;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the audit writer delivers the marker"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn best_effort_admits_every_operation_in_both_modes() {
    for backend in [StateBackend::Sqlite, StateBackend::Postgres] {
        let gate = AuthorityEvidenceGate::new(AuthorityEvidenceDurability::BestEffort, backend);
        for operation in EVERY_OPERATION {
            assert_eq!(gate.refusal(operation), None, "{operation:?} {backend:?}");
        }
    }
    assert_eq!(
        AuthorityEvidenceGate::best_effort().refusal(AuthorityOperation::PolicyPublish),
        None
    );
}

#[test]
fn required_refuses_every_standalone_operation_and_what_cluster_mode_cannot_perform() {
    let standalone =
        AuthorityEvidenceGate::new(AuthorityEvidenceDurability::Required, StateBackend::Sqlite);
    let cluster = AuthorityEvidenceGate::new(
        AuthorityEvidenceDurability::Required,
        StateBackend::Postgres,
    );
    for operation in EVERY_OPERATION {
        let refusal = standalone
            .refusal(operation)
            .unwrap_or_else(|| panic!("standalone mode does not evidence {operation:?}"));
        assert_eq!(refusal.operation(), operation);
        let why = if operation == AuthorityOperation::ConfigurationImport {
            "does not perform it"
        } else {
            "records no durable evidence of it"
        };
        assert_eq!(
            refusal.message(),
            format!(
                "AUTHORITY_EVIDENCE_DURABILITY=required refuses {}: standalone mode {why}; nothing was changed",
                operation.code()
            )
        );
    }
    assert_eq!(
        AuthorityOperation::ConfigurationImport.required_mode(StateBackend::Sqlite),
        RequiredMode::Unavailable,
        "standalone mode has no import to refuse"
    );

    let refused_in_cluster: Vec<_> = EVERY_OPERATION
        .into_iter()
        .filter(|operation| cluster.refusal(*operation).is_some())
        .collect();
    assert_eq!(
        refused_in_cluster,
        [AuthorityOperation::PolicyFileReload],
        "cluster mode refuses only what it cannot perform anyway"
    );
    for operation in refused_in_cluster {
        assert_eq!(
            operation.required_mode(StateBackend::Postgres),
            RequiredMode::Unavailable
        );
        assert_eq!(
            cluster.refusal(operation).map(|refusal| refusal.message()),
            Some(format!(
                "AUTHORITY_EVIDENCE_DURABILITY=required refuses {}: cluster mode does not perform it; nothing was changed",
                operation.code()
            ))
        );
    }
}

#[test]
fn an_admitted_operation_records_nothing() {
    let (audit, capture) = capture_log();
    let gate = AuthorityEvidenceGate::new(
        AuthorityEvidenceDurability::Required,
        StateBackend::Postgres,
    );
    gate.admit(
        AuthorityOperation::PolicyPublish,
        &audit,
        RefusalOrigin::Background("signal"),
    )
    .expect("cluster mode evidences a policy publication");
    BackgroundEvidenceGate::new(AuthorityEvidenceGate::best_effort(), audit.clone())
        .admits(AuthorityOperation::PolicyFileReload, "file_watch")
        .then_some(())
        .expect("best effort admits a reload");
    assert!(delivered_events(&audit, &capture).is_empty());
}

#[test]
fn a_refusal_is_audited_with_its_operation_mode_and_origin_and_nothing_else() {
    let (audit, capture) = capture_log();
    let gate =
        AuthorityEvidenceGate::new(AuthorityEvidenceDurability::Required, StateBackend::Sqlite);
    let refusal = gate
        .admit(
            AuthorityOperation::CatalogOverlayDelete,
            &audit,
            RefusalOrigin::Request {
                request_id: "request-1".to_owned(),
                source_ip: "192.0.2.10".to_owned(),
                actor: Some(audit::Actor {
                    user_id: "operator@example.test".to_owned(),
                    issuer: Some("https://issuer.example.test".to_owned()),
                    email: None,
                    roles: None,
                    auth_mode: "bearer_token".to_owned(),
                }),
            },
        )
        .expect_err("standalone mode records no overlay evidence");
    assert_eq!(
        refusal.operation(),
        AuthorityOperation::CatalogOverlayDelete
    );
    assert!(!BackgroundEvidenceGate::new(gate, audit.clone())
        .admits(AuthorityOperation::PolicyFileReload, "signal"));

    let events = delivered_events(&audit, &capture);
    assert_eq!(events.len(), 2, "{events:?}");
    let request = &events[0];
    assert_eq!(
        request.event_type,
        audit::event::AUTHORITY_EVIDENCE_OPERATION_REFUSED
    );
    assert_eq!(request.request_id, "request-1");
    assert_eq!(request.source_ip, "192.0.2.10");
    assert_eq!(
        request.actor.as_ref().map(|actor| actor.user_id.as_str()),
        Some("operator@example.test")
    );
    assert_eq!(
        request.payload,
        json!({
            "operation": "catalog.overlay.delete",
            "deployment_mode": "standalone",
            "trigger": "admin_api",
            "reason": "authority_evidence_unsupported",
        })
    );
    let background = &events[1];
    assert_eq!(background.request_id, "authority-evidence");
    assert_eq!(background.source_ip, "internal");
    assert!(background.actor.is_none());
    assert_eq!(
        background.payload,
        json!({
            "operation": "policy.file_reload",
            "deployment_mode": "standalone",
            "trigger": "signal",
            "reason": "authority_evidence_unsupported",
        })
    );
}

fn inventory() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/authority-evidence-inventory.json"
    );
    let text = std::fs::read_to_string(path).expect("the evidence inventory is readable");
    serde_json::from_str(&text).expect("the evidence inventory is JSON")
}

fn backend_of(mode: &str) -> StateBackend {
    match mode {
        "standalone" => StateBackend::Sqlite,
        "postgres" => StateBackend::Postgres,
        other => panic!("unknown storage mode {other}"),
    }
}

/// The inventory's `required_mode` is the contract and this module's table
/// enforces it: every operation a row refuses has a gate that refuses it in
/// that mode, every operation a gate covers agrees with its row, and the
/// only operations required mode refuses at startup are the ones the
/// configuration compiler refuses.
#[test]
fn the_gate_enforces_exactly_what_the_evidence_inventory_says() {
    let inventory = inventory();
    assert_eq!(
        inventory["required_durability_mode"], "refuses_unsupported",
        "the inventory describes the mode this module implements"
    );

    let mut seen = BTreeSet::new();
    let mut refused_at_startup = BTreeSet::new();
    let mut by_mode: BTreeMap<(&str, &str), &str> = BTreeMap::new();
    let groups = inventory["groups"].as_array().expect("groups");
    for group in groups {
        let id = group["id"].as_str().expect("group id");
        let required_mode = group["required_mode"]
            .as_str()
            .unwrap_or_else(|| panic!("{id} has a required_mode"));
        for mode in group["modes"].as_array().expect("modes") {
            let mode = mode.as_str().expect("mode");
            for operation in group["operations"].as_array().expect("operations") {
                let code = operation.as_str().expect("operation code");
                assert!(
                    by_mode.insert((code, mode), required_mode).is_none(),
                    "{code} in {mode} is listed once"
                );
                match gated_operation(code) {
                    Some(gated) => {
                        seen.insert(gated.code());
                        assert_eq!(
                            gated.required_mode(backend_of(mode)).as_str(),
                            required_mode,
                            "{id}: {code} in {mode}"
                        );
                    }
                    None => {
                        assert!(
                            matches!(
                                required_mode,
                                "admitted"
                                    | "refused_at_startup"
                                    | "unavailable"
                                    | "outside_gateway"
                                    | "not_refused"
                            ),
                            "{id}: {code} in {mode} is {required_mode} and no gate asks about it"
                        );
                        if required_mode == "refused_at_startup" {
                            refused_at_startup.insert((code, mode));
                        }
                    }
                }
            }
        }
    }

    let gated: BTreeSet<_> = EVERY_OPERATION
        .into_iter()
        .map(AuthorityOperation::code)
        .collect();
    assert_eq!(
        seen, gated,
        "every gated operation is an inventory operation"
    );
    assert_eq!(
        refused_at_startup,
        BTreeSet::from([
            ("admin_session.grant", "standalone"),
            ("admin_session.withdraw", "standalone"),
        ]),
        "config_tests covers each refusal at startup"
    );
    // The standalone Connections database records these in the change's own
    // transaction, so required mode admits them and no gate asks.
    for code in [
        "connection.create",
        "connection.replace",
        "credential.binding_change",
        "connection.delete",
        "secret.create",
        "secret.rotate",
        "secret.delete",
        "secret.reencrypt",
    ] {
        assert_eq!(
            by_mode.get(&(code, "standalone")),
            Some(&"admitted"),
            "{code}"
        );
        assert!(gated_operation(code).is_none(), "{code} is not gated");
    }
    // The one unsupported operation required mode runs is the activation
    // that starts it.
    let not_refused: Vec<_> = by_mode
        .iter()
        .filter(|(_, required_mode)| **required_mode == "not_refused")
        .map(|((code, mode), _)| (*code, *mode))
        .collect();
    assert_eq!(
        not_refused,
        [
            ("configuration.activate", "postgres"),
            ("configuration.activate", "standalone"),
        ]
    );
}
