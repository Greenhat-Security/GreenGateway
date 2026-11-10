use std::sync::{Arc, Barrier};

use super::*;
use crate::connections::mutation_approval::{
    ApprovalDecision, ApprovalError, ApprovalPrincipal, ApprovalStatus, MutationAction,
    MAX_APPROVALS_PER_CALLER,
};

fn actor(issuer: &str, subject: &str) -> ApprovalPrincipal {
    ApprovalPrincipal {
        issuer: issuer.to_owned(),
        subject: subject.to_owned(),
    }
}

fn install_action(store: &SqliteConnectionStore) -> MutationAction {
    let mut write = candidate();
    write.enabled = true;
    let admin = ChangeActor::for_test("operator");
    let connection = store.create(write, &admin).expect("create Connection");
    let mut entry = openapi_catalog_entry("create_invoice");
    let mapping = json!({"method":"POST","path_template":"/invoices"});
    entry.definition["upstream"] = mapping.clone();
    entry.definition["target"] =
        json!({"type":"http","connection_id":connection.id,"mapping":mapping});
    entry.definition["source"] = json!({"type":"open_api","connection_id":connection.id,
        "operation_id":entry.operation_id,"catalog_revision":1});
    let tool: ToolDefinition =
        serde_json::from_value(entry.definition.clone()).expect("typed catalog definition");
    let spec = r#"{"openapi":"3.1.0","info":{"title":"Invoices","version":"1"}}"#;
    let catalog = store
        .replace_openapi_catalog(
            &connection.id,
            &connection.etag(),
            0,
            0,
            spec,
            &spec_digest(spec),
            std::slice::from_ref(&entry),
            &admin,
        )
        .expect("publish catalog");
    MutationAction {
        caller: actor("https://first.example", "same-subject"),
        connection_id: connection.id,
        connection_etag: catalog.observed_etag.as_str().to_owned(),
        catalog_revision: catalog.catalog_revision,
        tool_name: tool.name.clone(),
        operation: entry.operation_id.expect("named operation"),
        method: "POST".to_owned(),
        target_sha256: spec_digest("https://billing.example.test/v1/invoices"),
        body_sha256: spec_digest("{}"),
        definition_sha256: hex::encode(
            crate::connections::openapi::definition_digest(&tool).expect("digest"),
        ),
    }
}

#[test]
fn mutation_approval_survives_restart_and_only_one_database_handle_can_consume_it() {
    let (_temp, path, first) = temporary_store("mutation-approval-race");
    let action = install_action(&first);
    let id = first.create_mutation_approval(&action).unwrap().id;
    let second_occurrence = first.create_mutation_approval(&action).unwrap().id;
    assert_ne!(id, second_occurrence);
    assert_eq!(
        first.consume_mutation_approval(id, &action).unwrap_err(),
        ApprovalError::Conflict
    );
    assert_eq!(
        first
            .decide_mutation_approval(id, &action.caller, ApprovalDecision::Approve, || Ok(0))
            .unwrap_err(),
        ApprovalError::SelfReview
    );
    // A provider scopes the subject. Identical subject values from different providers are distinct principals.
    let reviewer = actor("https://second.example", "same-subject");
    first
        .decide_mutation_approval(id, &reviewer, ApprovalDecision::Approve, || Ok(0))
        .unwrap();
    drop(first);
    let first = SqliteConnectionStore::open(&path).unwrap();
    let second = SqliteConnectionStore::open(&path).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    std::thread::scope(|scope| {
        let handles = [&first, &second].map(|store| {
            let barrier = Arc::clone(&barrier);
            let action = &action;
            scope.spawn(move || {
                barrier.wait();
                store.consume_mutation_approval(id, action)
            })
        });
        let results = handles.map(|handle| handle.join().unwrap());
        assert_eq!(
            results
                .iter()
                .filter(|result| result.as_ref().is_ok_and(|receipt| receipt.id() == id))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ApprovalError::Conflict)))
                .count(),
            1
        );
    });
    let used = first.mutation_approval(id).unwrap();
    assert_eq!(used.status, ApprovalStatus::Consumed);
    assert!(used.reviewer.as_ref() == Some(&reviewer));
    assert!(used.consumed_at.is_some());
    assert_eq!(
        second.mutation_approval(second_occurrence).unwrap().status,
        ApprovalStatus::Pending
    );
}

#[test]
fn mutation_approval_checks_each_action_field_and_rejects_stale_catalogs() {
    let (_temp, _path, store) = temporary_store("mutation-approval-mismatch");
    let action = install_action(&store);
    let id = store.create_mutation_approval(&action).unwrap().id;
    let reviewer = actor("https://first.example", "reviewer");
    store
        .decide_mutation_approval(id, &reviewer, ApprovalDecision::Approve, || Ok(0))
        .unwrap();
    let mut changed = action.clone();
    changed.caller.subject.push('2');
    let mut issuer = action.clone();
    issuer.caller.issuer.push('2');
    let mut operation = action.clone();
    operation.operation.push('2');
    let mut tool = action.clone();
    tool.tool_name.push('2');
    let mut method = action.clone();
    method.method = "DELETE".to_owned();
    let mut body = action.clone();
    body.body_sha256 = spec_digest("{ }");
    let mut target = action.clone();
    target.target_sha256 = spec_digest("https://elsewhere.example/v1/invoices");
    let mut revision = action.clone();
    revision.catalog_revision += 1;
    let mut definition = action.clone();
    definition.definition_sha256 = spec_digest("changed tool");
    let mut version = action.clone();
    version.connection_etag.push('2');
    let mut connection = action.clone();
    connection.connection_id = ConnectionId::new_managed();
    for incompatible in [
        changed, issuer, operation, tool, method, body, target, revision, definition, version,
        connection,
    ] {
        assert_eq!(
            store
                .consume_mutation_approval(id, &incompatible)
                .unwrap_err(),
            ApprovalError::Mismatch
        );
    }
    store
        .connection_guard()
        .execute(
            "UPDATE connection_openapi_catalogs SET catalog_revision=catalog_revision+1",
            [],
        )
        .unwrap();
    assert_eq!(
        store.consume_mutation_approval(id, &action).unwrap_err(),
        ApprovalError::Mismatch
    );
    assert_eq!(
        store.create_mutation_approval(&action).unwrap_err(),
        ApprovalError::Mismatch
    );
    let revoked = store
        .revoke_mutation_approval(id, &reviewer, || Ok(0))
        .unwrap();
    assert_eq!(revoked.status, ApprovalStatus::Revoked);
    assert!(revoked.reviewer == revoked.revoked_by);
    assert_eq!(
        store.consume_mutation_approval(id, &action).unwrap_err(),
        ApprovalError::Conflict
    );
}

#[test]
fn mutation_approval_holds_rejections_revocations_expiry_and_connection_deletion() {
    let (_temp, _path, store) = temporary_store("mutation-approval-lifecycle");
    let action = install_action(&store);
    let reviewer = actor("https://second.example", "reviewer");
    let id = store.create_mutation_approval(&action).unwrap().id;
    let rejected = store
        .decide_mutation_approval(id, &reviewer, ApprovalDecision::Reject, || Ok(0))
        .unwrap();
    assert_eq!(rejected.status, ApprovalStatus::Rejected);
    assert_eq!(
        store
            .decide_mutation_approval(id, &reviewer, ApprovalDecision::Approve, || Ok(0))
            .unwrap_err(),
        ApprovalError::Conflict
    );
    assert_eq!(
        store.consume_mutation_approval(id, &action).unwrap_err(),
        ApprovalError::Conflict
    );
    let pending = store.create_mutation_approval(&action).unwrap();
    assert_eq!(
        store
            .revoke_mutation_approval(pending.id, &action.caller, || Ok(0))
            .unwrap_err(),
        ApprovalError::SelfReview
    );
    let revoked = store
        .revoke_mutation_approval(pending.id, &reviewer, || Ok(0))
        .unwrap();
    assert_eq!(revoked.status, ApprovalStatus::Revoked);
    assert!(revoked.reviewer.is_none());
    let expiring = store.create_mutation_approval(&action).unwrap();
    store
        .decide_mutation_approval(expiring.id, &reviewer, ApprovalDecision::Approve, || Ok(0))
        .unwrap();
    store.connection_guard().execute("UPDATE connection_mutation_approvals SET created_at=unixepoch()-900,expires_at=unixepoch(),reviewed_at=unixepoch()-1 WHERE id=?1",[expiring.id.to_string()]).unwrap();
    assert_eq!(
        store.mutation_approval(expiring.id).unwrap().status,
        ApprovalStatus::Expired
    );
    assert_eq!(
        store
            .consume_mutation_approval(expiring.id, &action)
            .unwrap_err(),
        ApprovalError::Expired
    );
    let fresh = store.create_mutation_approval(&action).unwrap().id;
    assert_eq!(
        store.mutation_approval(expiring.id).unwrap_err(),
        ApprovalError::NotFound
    );

    // The catalog registers a managed HTTP tool dependency. Unregistering it
    // permits Connection deletion, which cascades even unexpired approvals.
    store
        .remove_dependency(
            &action.connection_id,
            ConnectionDependencyKind::ManagedTool,
            &action.tool_name,
        )
        .unwrap();
    let connection = store.get(&action.connection_id).unwrap().unwrap();
    store
        .delete(
            &connection.id,
            &connection.etag(),
            &ChangeActor::for_test("deleting-admin"),
        )
        .unwrap();
    assert_eq!(
        store.mutation_approval(fresh).unwrap_err(),
        ApprovalError::NotFound
    );
    assert_eq!(
        store.mutation_approval(id).unwrap_err(),
        ApprovalError::NotFound
    );
}

#[test]
fn mutation_approval_rechecks_the_reviewer_grant_under_the_write_lock() {
    let (_file, path, store) = temporary_store("mutation-approval-reviewer-withdrawal");
    let action = install_action(&store);
    let reviewer = actor("https://second.example", "reviewer");
    let id = store.create_mutation_approval(&action).unwrap().id;
    let probe = Connection::open(path).unwrap();
    probe.busy_timeout(Duration::ZERO).unwrap();
    let withdrawn = || {
        let locked = probe.execute_batch("BEGIN IMMEDIATE").unwrap_err();
        assert_eq!(
            locked.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        Err(ApprovalError::Conflict)
    };
    for decision in [ApprovalDecision::Approve, ApprovalDecision::Reject] {
        assert_eq!(
            store
                .decide_mutation_approval(id, &reviewer, decision, withdrawn)
                .unwrap_err(),
            ApprovalError::Conflict
        );
    }
    let pending = store.mutation_approval(id).unwrap();
    assert_eq!(pending.status, ApprovalStatus::Pending);
    assert!(pending.reviewer.is_none() && pending.reviewed_at.is_none());

    store
        .decide_mutation_approval(id, &reviewer, ApprovalDecision::Approve, || Ok(0))
        .unwrap();
    assert_eq!(
        store
            .revoke_mutation_approval(id, &reviewer, withdrawn)
            .unwrap_err(),
        ApprovalError::Conflict
    );
    let approved = store.mutation_approval(id).unwrap();
    assert_eq!(approved.status, ApprovalStatus::Approved);
    assert!(approved.reviewer.as_ref() == Some(&reviewer));
    assert!(approved.revoked_by.is_none() && approved.revoked_at.is_none());
}

#[test]
fn mutation_approval_bounds_retained_rows_per_caller_and_reclaims_expired_capacity() {
    let (_temp, _path, store) = temporary_store("mutation-approval-capacity");
    let action = install_action(&store);
    for _ in 0..MAX_APPROVALS_PER_CALLER {
        store.create_mutation_approval(&action).unwrap();
    }
    assert_eq!(
        store.create_mutation_approval(&action).unwrap_err(),
        ApprovalError::Capacity
    );
    let mut other = action.clone();
    other.caller.issuer = "https://other.example".to_owned();
    store.create_mutation_approval(&other).unwrap();
    store.connection_guard().execute("UPDATE connection_mutation_approvals SET created_at=unixepoch()-901,expires_at=unixepoch()-1 WHERE caller_issuer=?1",[&action.caller.issuer]).unwrap();
    store.create_mutation_approval(&action).unwrap();
    let count: i64 = store
        .connection_guard()
        .query_row(
            "SELECT COUNT(*) FROM connection_mutation_approvals",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
}
