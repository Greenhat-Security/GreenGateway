use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use serde_json::Value;

use super::*;
use crate::audit::sink::tests::CaptureSink;

const EVERY_OPERATION: [AuthorityOperation; 17] = [
    AuthorityOperation::PolicyPublish,
    AuthorityOperation::PolicyRollback,
    AuthorityOperation::PolicyRuleCreate,
    AuthorityOperation::PolicyRuleUpdate,
    AuthorityOperation::PolicyRuleDelete,
    AuthorityOperation::PolicyRuleReorder,
    AuthorityOperation::PolicySuggestionAccept,
    AuthorityOperation::PolicyFileReload,
    AuthorityOperation::ToolsPublish,
    AuthorityOperation::ConfigurationImport,
    AuthorityOperation::PolicyTestsPublish,
    AuthorityOperation::MutationApprovalPrepare,
    AuthorityOperation::MutationApprovalConsume,
    AuthorityOperation::MutationApprovalReview,
    AuthorityOperation::MutationApprovalRevoke,
    AuthorityOperation::ConnectionCreate,
    AuthorityOperation::ConnectionReplace,
];

/// The operations both modes admit only in their keyed form (issue #425).
const KEYED_CONNECTION_OPERATIONS: [AuthorityOperation; 2] = [
    AuthorityOperation::ConnectionCreate,
    AuthorityOperation::ConnectionReplace,
];

/// The operation whose gate covers an inventory operation code, or `None`
/// for one no gate asks about. A credential binding change is never asked on
/// its own: the Connection replacement that makes it is.
fn gated_operation(code: &str) -> Option<AuthorityOperation> {
    if code == "credential.binding_change" {
        return Some(AuthorityOperation::ConnectionReplace);
    }
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
        } else if KEYED_CONNECTION_OPERATIONS.contains(&operation) {
            "admits it only with an Idempotency-Key, on a route that honours one"
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
        [
            AuthorityOperation::PolicyFileReload,
            AuthorityOperation::ConfigurationImport,
            AuthorityOperation::MutationApprovalPrepare,
            AuthorityOperation::MutationApprovalConsume,
            AuthorityOperation::MutationApprovalReview,
            AuthorityOperation::MutationApprovalRevoke,
            AuthorityOperation::ConnectionCreate,
            AuthorityOperation::ConnectionReplace,
        ],
        "cluster mode refuses operations without durable authority evidence, and the unkeyed form of keyed ones"
    );
    for operation in refused_in_cluster {
        let why = match operation {
            AuthorityOperation::PolicyFileReload => "does not perform it",
            AuthorityOperation::ConfigurationImport => "records evidence for only part of it",
            // The ordinary preparation POST refuses a key: the message names
            // the keyed route instead.
            AuthorityOperation::MutationApprovalPrepare => {
                "admits it only as a keyed preparation, PUT .../tools/{id}/mutation-approvals with an Idempotency-Key"
            }
            AuthorityOperation::ConnectionCreate | AuthorityOperation::ConnectionReplace => {
                "admits it only with an Idempotency-Key, on a route that honours one"
            }
            _ => "records no durable evidence of it",
        };
        assert_eq!(
            cluster.refusal(operation).map(|refusal| refusal.message()),
            Some(format!(
                "AUTHORITY_EVIDENCE_DURABILITY=required refuses {}: cluster mode {why}; nothing was changed",
                operation.code()
            ))
        );
    }
}

/// The offline import's writing form records evidence for its policy and
/// tools activations only; its Connections, audit, discovery and token
/// sections commit without any. Required mode therefore refuses it in
/// cluster mode (owner ruling 7 on issue #425, 2026-11-20), with a reason
/// that says so rather than claiming no evidence at all. Standalone mode
/// still has no import to refuse, and `best_effort` admits it as before.
#[test]
fn required_refuses_the_offline_import_in_cluster_mode() {
    let operation = AuthorityOperation::ConfigurationImport;
    assert_eq!(
        operation.required_mode(StateBackend::Postgres),
        RequiredMode::Refused
    );
    assert_eq!(
        operation.required_mode(StateBackend::Sqlite),
        RequiredMode::Unavailable
    );
    let refusal = AuthorityEvidenceGate::new(
        AuthorityEvidenceDurability::Required,
        StateBackend::Postgres,
    )
    .refusal(operation)
    .expect("required mode refuses the import in cluster mode");
    assert_eq!(refusal.operation(), operation);
    assert_eq!(
        refusal.message(),
        "AUTHORITY_EVIDENCE_DURABILITY=required refuses configuration.import: cluster mode records evidence for only part of it; nothing was changed"
    );
    assert_eq!(
        AuthorityEvidenceGate::new(
            AuthorityEvidenceDurability::BestEffort,
            StateBackend::Postgres,
        )
        .refusal(operation),
        None,
        "best_effort imports as before"
    );
}

/// A required gate in cluster mode, where preparation is the one
/// `caller_key_required` operation, with every delivery criterion met unless
/// a case changes it.
fn keyed_cluster_gate() -> AuthorityEvidenceGate {
    AuthorityEvidenceGate::new(
        AuthorityEvidenceDurability::Required,
        StateBackend::Postgres,
    )
    .with_delivery(crate::config::AuthorityEventFormat::QualifiedV1, true, true)
}

fn issuer_bound_principal() -> crate::auth::change_actor::ChangeActor {
    crate::auth::change_actor::ChangeActor::for_test_with_issuer(
        "operator@example.test",
        "https://issuer.example.test",
    )
}

/// The general gate (issue #425, plan section 3.3): a `caller_key_required`
/// change is admitted only keyed, by a provider-authenticated principal with
/// a canonical issuer, under `qualified_v1`, with the file sink, on a build
/// that syncs the file and its directory. One case per criterion: each
/// refusal names exactly the criterion that failed, the first in that order.
#[test]
fn caller_key_required_admits_only_a_keyed_issuer_bound_principal_under_qualified_v1_with_the_file_sink(
) {
    use crate::auth::change_actor::ChangeActor;
    use crate::config::AuthorityEventFormat;

    let operation = AuthorityOperation::MutationApprovalPrepare;
    assert_eq!(
        operation.required_mode(StateBackend::Postgres),
        RequiredMode::CallerKeyRequired
    );
    let principal = issuer_bound_principal();
    let keyed = RequestForm::of(true, &principal);
    assert_eq!(
        keyed,
        RequestForm {
            keyed: true,
            issuer_bound_principal: true
        }
    );
    assert_eq!(keyed_cluster_gate().refusal_for(operation, keyed), None);

    let unmet = |gate: AuthorityEvidenceGate, form: RequestForm| {
        gate.refusal_for(operation, form)
            .map(|refusal| refusal.unmet())
            .expect("refused")
    };
    let cases = [
        (
            keyed_cluster_gate(),
            RequestForm::of(false, &principal),
            KeyedAdmission::CallerKey,
        ),
        (
            keyed_cluster_gate(),
            RequestForm::UNKEYED,
            KeyedAdmission::CallerKey,
        ),
        (
            keyed_cluster_gate(),
            RequestForm::of(
                true,
                &ChangeActor::service_token_for_test("service-token:1"),
            ),
            KeyedAdmission::IssuerBoundPrincipal,
        ),
        (
            keyed_cluster_gate(),
            RequestForm::of(true, &ChangeActor::for_test("no-issuer")),
            KeyedAdmission::IssuerBoundPrincipal,
        ),
        (
            keyed_cluster_gate(),
            RequestForm::of(true, &ChangeActor::system("operator:revoke-jwt")),
            KeyedAdmission::IssuerBoundPrincipal,
        ),
        (
            keyed_cluster_gate().with_delivery(AuthorityEventFormat::DeliveryV1, true, true),
            keyed,
            KeyedAdmission::QualifiedFormat,
        ),
        (
            keyed_cluster_gate().with_delivery(AuthorityEventFormat::QualifiedV1, false, true),
            keyed,
            KeyedAdmission::FileSink,
        ),
        (
            keyed_cluster_gate().with_delivery(AuthorityEventFormat::QualifiedV1, true, false),
            keyed,
            KeyedAdmission::SyncedFilesystem,
        ),
        // Two unmet criteria: the earlier one is named.
        (
            keyed_cluster_gate().with_delivery(AuthorityEventFormat::DeliveryV1, false, false),
            RequestForm::of(true, &ChangeActor::for_test("no-issuer")),
            KeyedAdmission::IssuerBoundPrincipal,
        ),
    ];
    for (gate, form, expected) in cases {
        assert_eq!(unmet(gate, form), Some(expected), "{form:?} {gate:?}");
    }

    // The form never changes what the mode decides for any other operation:
    // an admitted operation stays admitted unkeyed, and a refused one stays
    // refused keyed by an issuer-bound principal with every criterion met.
    let gate = keyed_cluster_gate();
    assert_eq!(
        gate.refusal_for(AuthorityOperation::PolicyPublish, RequestForm::UNKEYED),
        None
    );
    let refused = gate
        .refusal_for(AuthorityOperation::MutationApprovalReview, keyed)
        .expect("review is refused in every form");
    assert_eq!(refused.unmet(), None);
    // And best_effort admits every form.
    let best_effort = AuthorityEvidenceGate::new(
        AuthorityEvidenceDurability::BestEffort,
        StateBackend::Postgres,
    );
    assert_eq!(
        best_effort.refusal_for(operation, RequestForm::UNKEYED),
        None
    );
    // `refusal` is the unkeyed form.
    assert_eq!(
        gate.refusal(operation),
        gate.refusal_for(operation, RequestForm::UNKEYED)
    );
}

/// The log sink only hands an event to the log writer, which is not a
/// durable store, while every qualified path records the synced file sink.
/// So a keyed, issuer-bound preparation under `qualified_v1` is refused with
/// the log sink, and the refusal says the sink is why. This tightens keyed
/// preparation, which before this change was admitted with any sink.
#[test]
fn a_keyed_request_with_the_log_sink_is_refused_and_the_refusal_names_the_sink() {
    let (audit, capture) = capture_log();
    let gate = keyed_cluster_gate().with_delivery(
        crate::config::AuthorityEventFormat::QualifiedV1,
        false,
        true,
    );
    let refusal = gate
        .admit_for(
            AuthorityOperation::MutationApprovalPrepare,
            RequestForm::of(true, &issuer_bound_principal()),
            &audit,
            RefusalOrigin::Background("signal"),
        )
        .expect_err("the log sink is not durable");
    assert_eq!(refusal.unmet(), Some(KeyedAdmission::FileSink));
    assert_eq!(
        refusal.message(),
        "AUTHORITY_EVIDENCE_DURABILITY=required refuses mutation_approval.prepare: cluster mode admits it only with AUTHORITY_EVENT_SINK=file; nothing was changed"
    );
    let events = delivered_events(&audit, &capture);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(
        events[0].payload["operation"], "mutation_approval.prepare",
        "the refusal is audited like every other"
    );
    assert_eq!(events[0].payload["reason"], REFUSAL_REASON);
}

/// A change that only removes authority and that a remote caller starts --
/// token revocation, Connection deletion, local-secret deletion -- never
/// asks the evidence gate: refusing one fails open (owner ruling 4 on issue
/// #425). None is an operation the gate knows, and the inventory admits
/// every form of each in every mode that performs it.
#[test]
fn withdrawals_never_ask_the_evidence_gate() {
    let withdrawals = Withdrawal::ALL.map(Withdrawal::code);
    assert_eq!(
        withdrawals,
        ["service_token.revoke", "connection.delete", "secret.delete"]
    );
    for code in withdrawals {
        assert!(gated_operation(code).is_none(), "{code} is not gated");
        assert_eq!(
            Withdrawal::from_code(code).map(Withdrawal::code),
            Some(code)
        );
    }
    for operation in EVERY_OPERATION {
        assert_eq!(
            Withdrawal::from_code(operation.code()),
            None,
            "{operation:?}"
        );
    }
    let inventory = inventory();
    let mut admitted = BTreeSet::new();
    for group in inventory["groups"].as_array().expect("groups") {
        for operation in group["operations"].as_array().expect("operations") {
            let code = operation.as_str().expect("code");
            if !withdrawals.contains(&code) {
                continue;
            }
            for mode in group["modes"].as_array().expect("modes") {
                let required_mode = group["required_mode"].as_str().expect("required mode");
                assert!(
                    matches!(required_mode, "admitted" | "unavailable"),
                    "{code} in {mode} is {required_mode}"
                );
                if required_mode == "admitted" {
                    admitted.insert((code, mode.as_str().expect("mode")));
                }
            }
        }
    }
    assert_eq!(
        admitted,
        BTreeSet::from([
            ("connection.delete", "postgres"),
            ("connection.delete", "standalone"),
            ("secret.delete", "standalone"),
            ("service_token.revoke", "postgres"),
            ("service_token.revoke", "standalone"),
        ])
    );
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
            AuthorityOperation::ToolsPublish,
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
        .expect_err("standalone mode records no tools evidence");
    assert_eq!(refusal.operation(), AuthorityOperation::ToolsPublish);
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
            "operation": "tools.publish",
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
/// configuration compiler refuses and the activation that starts the
/// gateway, which [`startup_refusal`] refuses.
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
            ("configuration.activate", "postgres"),
            ("configuration.activate", "standalone"),
        ]),
        "config_tests covers the session refusal and bootstrap_tests the activation refusal"
    );
    // The standalone Connections database records these in the change's own
    // transaction, so required mode admits them and no gate asks: Connection
    // deletion and local-secret changes since its migration 12, and managed
    // catalog and overlay publication since its migration 13.
    for code in [
        "connection.delete",
        "secret.create",
        "secret.rotate",
        "secret.delete",
        "secret.reencrypt",
        "catalog.mcp.publish",
        "catalog.openapi.publish",
        "catalog.overlay.replace",
        "catalog.overlay.delete",
    ] {
        assert_eq!(
            by_mode.get(&(code, "standalone")),
            Some(&"admitted"),
            "{code}"
        );
        assert!(gated_operation(code).is_none(), "{code} is not gated");
    }
    // Connection create and replace, with the credential binding change a
    // replacement makes, bind caller keys in both modes (issue #425): only
    // their keyed form is admitted.
    for code in [
        "connection.create",
        "connection.replace",
        "credential.binding_change",
    ] {
        for mode in ["postgres", "standalone"] {
            assert_eq!(
                by_mode.get(&(code, mode)),
                Some(&"caller_key_required"),
                "{code} in {mode}"
            );
        }
    }
}

/// Connection create and replace (issue #425): in both modes required mode
/// admits only the keyed request of an issuer-bound principal under
/// `qualified_v1` with the file sink on a Unix build, and the refusal of
/// every other form names the first criterion it misses. Connection deletion
/// is a withdrawal and never asks.
#[test]
fn connection_create_and_replace_admit_only_their_keyed_issuer_bound_form_in_both_modes() {
    use crate::auth::change_actor::ChangeActor;
    use crate::config::AuthorityEventFormat;

    let principal = issuer_bound_principal();
    let keyed = RequestForm::of(true, &principal);
    let service_token = ChangeActor::service_token_for_test("service-token:1");
    for backend in [StateBackend::Sqlite, StateBackend::Postgres] {
        let gate = AuthorityEvidenceGate::new(AuthorityEvidenceDurability::Required, backend)
            .with_delivery(AuthorityEventFormat::QualifiedV1, true, true);
        for operation in KEYED_CONNECTION_OPERATIONS {
            assert_eq!(
                operation.required_mode(backend),
                RequiredMode::CallerKeyRequired,
                "{operation:?} {backend:?}"
            );
            assert_eq!(gate.refusal_for(operation, keyed), None, "{operation:?}");
            for (gate, form, expected) in [
                (gate, RequestForm::UNKEYED, KeyedAdmission::CallerKey),
                (
                    gate,
                    RequestForm::of(true, &service_token),
                    KeyedAdmission::IssuerBoundPrincipal,
                ),
                (
                    gate.with_delivery(AuthorityEventFormat::DeliveryV1, true, true),
                    keyed,
                    KeyedAdmission::QualifiedFormat,
                ),
                (
                    gate.with_delivery(AuthorityEventFormat::QualifiedV1, false, true),
                    keyed,
                    KeyedAdmission::FileSink,
                ),
                (
                    gate.with_delivery(AuthorityEventFormat::QualifiedV1, true, false),
                    keyed,
                    KeyedAdmission::SyncedFilesystem,
                ),
            ] {
                assert_eq!(
                    gate.refusal_for(operation, form)
                        .and_then(|refusal| refusal.unmet()),
                    Some(expected),
                    "{operation:?} {backend:?} {form:?}"
                );
            }
            assert_eq!(
                AuthorityEvidenceGate::new(AuthorityEvidenceDurability::BestEffort, backend)
                    .refusal(operation),
                None,
                "best_effort admits the unkeyed form"
            );
        }
    }
    assert_eq!(
        Withdrawal::from_code("connection.delete"),
        Some(Withdrawal::ConnectionDelete)
    );
    assert_eq!(gated_operation("connection.delete"), None);
}

/// No proof of a configuration activation exists, so required mode refuses
/// every start in both modes (owner decision 2 of issue #425, 2026-11-19).
/// This asserts a constant on purpose: the evidence inventory's checker is
/// what stops the proof type from gaining a value without the inventory row
/// and this hook changing with it (issue #242).
#[test]
fn no_activation_proof_exists_for_any_candidate() {
    for backend in [StateBackend::Sqlite, StateBackend::Postgres] {
        assert!(
            activation_proof(&ActivationCandidate { backend }).is_none(),
            "{backend:?}"
        );
        let refusal = StartupEvidenceRefusal { backend };
        assert_eq!(refusal.code(), "authority_evidence_activation_unevidenced");
        assert_eq!(
            refusal.message(),
            format!(
                "authority_evidence_activation_unevidenced: AUTHORITY_EVIDENCE_DURABILITY=required refuses configuration.activate: {} mode records no durable evidence of the configuration it would activate (issue #242); nothing was activated",
                mode_name(backend)
            )
        );
    }
}
