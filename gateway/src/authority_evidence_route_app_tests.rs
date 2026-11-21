//! Every keyed admin route under `AUTHORITY_EVIDENCE_DURABILITY=required`,
//! driven from the router's own table (issue #425, plan P10). The handlers
//! name their change to `admit_keyed_authority_change` as a gated operation
//! or as a withdrawal, and only a gated operation asks the evidence gate. A
//! keyed request is held to that name by its key's action, but an unkeyed
//! one is not (#838): a handler that labelled a gated change a withdrawal
//! would admit it unkeyed. This test walks `KEYED_ROUTES`, so a keyed route
//! cannot be added without saying here what its unkeyed form must get.

use super::*;

use crate::routing::{KeyedRoute, KEYED_ROUTES};

/// What an unkeyed request on one keyed route must get in required mode.
#[derive(Clone, Copy, Debug)]
enum Unkeyed {
    /// `409 authority_evidence_unsupported` naming this operation, before
    /// anything is read or written.
    Refused(&'static str),
    /// Admitted in every form: a withdrawal (owner decision, plan section 8
    /// item 4). The named test proves it still records its evidence.
    Withdrawal(&'static str),
    /// `400` naming the missing key, before any gate, before the tool is
    /// looked up and before the body is read: the route takes no request
    /// without a key, in any mode (issue #794).
    KeyRequired,
}

/// The targets the routes with a path parameter name: each exists, so a
/// refusal cannot be mistaken for a `404`.
struct Targets {
    connection_id: String,
    connection_etag: String,
    registration: String,
    overlay_etag: String,
    connection_collection_etag: String,
    secret_id: String,
    secret_etag: String,
    secret_collection_etag: String,
    token_id: String,
}

/// Every route in one policy: the HTTP layer allows every route and
/// `keyed-route-admin` may do anything, so each answer below is the
/// handler's own. The Connection roles the target helpers use are kept.
fn keyed_route_policy(id: &str) -> String {
    let mut policy: Value = serde_json::from_str(&connection_policy_document_string())
        .expect("the Connection policy is JSON");
    policy["id"] = json!(id);
    policy["default_action"] = json!("allow");
    policy["roles"]["keyed-route-admin"] = json!({ "permissions": ["*"] });
    policy["roles"]["probe-reader"] = json!({ "permissions": ["test:read"] });
    policy["rules"] = json!([
        { "id": "first-rule", "path": "/first", "action": "allow" },
        { "id": "second-rule", "path": "/second", "action": "deny" }
    ]);
    policy.to_string()
}

fn suite_document() -> String {
    json!({
        "schema_version": "policy-tests.v1",
        "cases": [{
            "id": "anonymous-is-allowed",
            "kind": "http",
            "request": { "method": "GET", "path": "/elsewhere" },
            "principal": "anonymous",
            "expect": { "logical": "allow" }
        }]
    })
    .to_string()
}

/// The unkeyed request for `route` and what it must get. A route this test
/// does not know fails it: add the route here in the change that keys it.
fn unkeyed_case(
    route: &KeyedRoute,
    targets: &Targets,
) -> (Unkeyed, String, Option<String>, Vec<(&'static str, String)>) {
    let uri = |suffix: &str| format!("/v1{}{suffix}", config::DEFAULT_ADMIN_PREFIX);
    let connection = |rest: &str| uri(&format!("/connections/{}{rest}", targets.connection_id));
    let if_match = |etag: &str| vec![("if-match", etag.to_owned())];
    let policy_etag = || if_match("\"keyed-route-policy\"");
    let suffix = route
        .route
        .strip_prefix(crate::routing::KEYED_ROUTE_PREFIX)
        .expect("every keyed route starts with the admin API prefix");
    match (route.method, suffix) {
        ("POST", "/tokens") => (
            Unkeyed::Refused("service_token.issue"),
            uri("/tokens"),
            Some(json!({ "scopes": ["probe-reader"] }).to_string()),
            Vec::new(),
        ),
        ("POST", "/tokens/{id}/rotate") => (
            Unkeyed::Refused("service_token.rotate"),
            uri(&format!("/tokens/{}/rotate", targets.token_id)),
            None,
            Vec::new(),
        ),
        ("POST", "/tokens/{id}/revoke") => (
            Unkeyed::Withdrawal("required_mode_admits_every_form_of_token_revocation"),
            String::new(),
            None,
            Vec::new(),
        ),
        ("PUT", "/tools/{id}/mutation-approvals") => (
            Unkeyed::KeyRequired,
            uri("/tools/widget-tool/mutation-approvals"),
            Some(json!({}).to_string()),
            if_match("\"keyed-route-tool\""),
        ),
        ("POST", "/connections") => (
            Unkeyed::Refused("connection.create"),
            uri("/connections"),
            Some(aliased_connection_body("Unkeyed API", "unkeyed-alias", "unkeyed-header")),
            if_match(&targets.connection_collection_etag),
        ),
        ("PUT", "/connections/{id}") => (
            Unkeyed::Refused("connection.replace"),
            connection(""),
            Some(aliased_connection_body("Unkeyed API renamed", "unkeyed-alias", "unkeyed-header")),
            if_match(&targets.connection_etag),
        ),
        ("DELETE", "/connections/{id}") => (
            Unkeyed::Withdrawal("required_mode_admits_every_form_of_connection_delete"),
            String::new(),
            None,
            Vec::new(),
        ),
        // The target was registered from an OpenAPI document, so its refresh
        // publishes an OpenAPI catalog.
        ("POST", "/connections/{id}/refresh") => (
            Unkeyed::Refused("catalog.openapi.publish"),
            connection("/refresh"),
            None,
            if_match(&targets.connection_etag),
        ),
        ("POST", "/connections/{id}/openapi/register") => (
            Unkeyed::Refused("catalog.openapi.publish"),
            connection("/openapi/register"),
            Some(targets.registration.clone()),
            if_match(&targets.connection_etag),
        ),
        ("PUT", "/connections/{id}/overlay") => (
            Unkeyed::Refused("catalog.overlay.replace"),
            connection("/overlay"),
            Some(catalog_overlay_document()),
            if_match(&targets.overlay_etag),
        ),
        ("DELETE", "/connections/{id}/overlay") => (
            Unkeyed::Refused("catalog.overlay.delete"),
            connection("/overlay"),
            None,
            if_match(&targets.overlay_etag),
        ),
        ("POST", "/connection-secrets") => (
            Unkeyed::Refused("secret.create"),
            uri("/connection-secrets"),
            Some(json!({ "label": "Unkeyed secret", "purpose": "static_bearer", "value": "unkeyed-value" }).to_string()),
            if_match(&targets.secret_collection_etag),
        ),
        ("PUT", "/connection-secrets/{id}") => (
            Unkeyed::Refused("secret.rotate"),
            uri(&format!("/connection-secrets/{}", targets.secret_id)),
            Some(json!({ "purpose": "static_bearer", "value": "unkeyed-value-next" }).to_string()),
            if_match(&targets.secret_etag),
        ),
        ("DELETE", "/connection-secrets/{id}") => (
            Unkeyed::Withdrawal("required_mode_admits_every_form_of_secret_delete"),
            String::new(),
            None,
            Vec::new(),
        ),
        ("PUT", "/policy") => (
            Unkeyed::Refused("policy.publish"),
            uri("/policy"),
            Some(keyed_route_policy("unkeyed-policy")),
            policy_etag(),
        ),
        ("POST", "/policy/rollback/{version}") => (
            Unkeyed::Refused("policy.rollback"),
            uri("/policy/rollback/1"),
            None,
            policy_etag(),
        ),
        ("POST", "/policy/rules") => (
            Unkeyed::Refused("policy.rule.create"),
            uri("/policy/rules"),
            Some(json!({ "id": "unkeyed-rule", "path": "/unkeyed", "action": "allow" }).to_string()),
            policy_etag(),
        ),
        ("PATCH", "/policy/rules/{id}") => (
            Unkeyed::Refused("policy.rule.update"),
            uri("/policy/rules/first-rule"),
            Some(json!({ "action": "deny" }).to_string()),
            policy_etag(),
        ),
        ("DELETE", "/policy/rules/{id}") => (
            Unkeyed::Refused("policy.rule.delete"),
            uri("/policy/rules/first-rule"),
            None,
            policy_etag(),
        ),
        ("PUT", "/policy/rules/order") => (
            Unkeyed::Refused("policy.rule.reorder"),
            uri("/policy/rules/order"),
            Some(json!(["second-rule", "first-rule"]).to_string()),
            policy_etag(),
        ),
        // A suggestion or draft that does not exist gets the refusal too:
        // the gate is asked before either is read.
        ("POST", "/suggestions/{id}/accept") => (
            Unkeyed::Refused("policy.suggestion.accept"),
            uri("/suggestions/sug-missing/accept"),
            None,
            policy_etag(),
        ),
        ("POST", "/policy/drafts/{id}/publish") => (
            Unkeyed::Refused("policy.publish"),
            uri("/policy/drafts/draft-missing/publish"),
            None,
            vec![
                ("if-match", "\"keyed-route-policy\"".to_owned()),
                (POLICY_DRAFT_ETAG_HEADER, "\"keyed-route-draft\"".to_owned()),
            ],
        ),
        ("POST", "/tools/openapi/register") => (
            Unkeyed::Refused("tools.publish"),
            uri("/tools/openapi/register"),
            Some(json!({ "spec": widget_openapi_spec(), "selected_tool_names": ["createWidget"] }).to_string()),
            if_match("\"keyed-route-tools\""),
        ),
        ("PUT", "/policy/tests") => (
            Unkeyed::Refused("policy_tests.publish"),
            uri("/policy/tests"),
            Some(suite_document()),
            policy_etag(),
        ),
        (method, route) => panic!(
            "{method} {route} honours an Idempotency-Key but this test does not say what its unkeyed form gets in required mode; add it to `unkeyed_case`"
        ),
    }
}

/// One admin request by `principal`; a write declares a JSON body, as the
/// admin API requires, even when it sends none.
fn route_request(
    method: &str,
    uri: &str,
    principal: auth::Principal,
    body: Option<String>,
    headers: &[(&'static str, String)],
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::from_bytes(method.as_bytes()).expect("a method"))
        .uri(uri)
        .header(header::AUTHORIZATION, "Bearer test-token");
    if body.is_some() || matches!(method, "POST" | "PUT" | "PATCH") {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let mut request = builder
        .body(Body::from(body.unwrap_or_default()))
        .expect("the request builds");
    request.extensions_mut().insert(principal);
    request
}

/// Every table of a standalone SQLite database with its row count: equal
/// before and after means nothing was written to it.
fn rows_by_table(path: &FsPath) -> Vec<(String, i64)> {
    let connection = rusqlite::Connection::open(path).expect("the database opens");
    let tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .expect("the table list prepares")
        .query_map([], |row| row.get::<_, String>(0))
        .expect("the tables list")
        .collect::<Result<Vec<_>, _>>()
        .expect("the table names read");
    tables
        .into_iter()
        .map(|table| {
            let rows = connection
                .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("the table counts");
            (table, rows)
        })
        .collect()
}

/// Every reservation in a standalone SQLite database.
fn reservations_in(path: &FsPath) -> usize {
    rusqlite::Connection::open(path)
        .expect("the database opens")
        .query_row(
            "SELECT COUNT(*) FROM authority_caller_operation_ids",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("the reservations count") as usize
}

/// Required mode refuses the unkeyed form of every gated keyed route with
/// `409 authority_evidence_unsupported` naming its operation, audited once,
/// and reserves nothing; a withdrawal route is named with the test that
/// proves it stays admitted. The deployment meets every keyed criterion
/// (an issuer-bound principal, `qualified_v1`, the file sink), so the only
/// thing each request lacks is its key.
#[tokio::test]
async fn required_mode_refuses_the_unkeyed_form_of_every_gated_keyed_route() {
    let connection_db = TempDb::new("keyed-routes-connections");
    let token_db = TempDb::new("keyed-routes-tokens");
    let history_db = TempDb::new("keyed-routes-history");
    let discovery_db = TempDb::new("keyed-routes-discovery");
    let events = TempDb::new("keyed-routes-events");
    create_rule_suggestion_schema(&discovery_db.path);
    let policy = TempPolicyFile::new(&keyed_route_policy("keyed-routes"));
    let tools = TempToolsFile::new(&empty_tools_document());
    let mut config = connection_admin_config(&connection_db, &policy, config::DEFAULT_ADMIN_PREFIX);
    config.rate_limit_write_burst = 1_000;
    config.service_token_sqlite_path = Some(token_db.path.to_string_lossy().into_owned());
    config.policy_history_sqlite_path = Some(history_db.path.to_string_lossy().into_owned());
    config.discovery_sqlite_path = Some(discovery_db.path.to_string_lossy().into_owned());
    config.tools_file = Some(tools.path.to_string_lossy().into_owned());
    let admin = keyed_admin(&["keyed-route-admin"]);

    // Required mode admits a create only keyed, so every target is made
    // before it is on.
    let best_effort = router_with(config.clone(), test_audit_log());
    let (connection_id, connection_etag) =
        create_managed_openapi_connection(&best_effort, "Keyed route target").await;
    let registration =
        openapi_registration_body(&best_effort, &connection_id, &["createWidget"]).await;
    let overlay_etag = overlay_etag(&best_effort, &connection_id).await;
    let connection_collection_etag = connection_collection_etag(&best_effort).await;
    let secret_collection_etag = {
        let response = best_effort
            .clone()
            .oneshot(route_request(
                "GET",
                CONNECTION_SECRETS_ADMIN_ROUTE,
                admin.clone(),
                None,
                &[],
            ))
            .await
            .expect("the secret list completes");
        assert_eq!(response.status(), StatusCode::OK);
        response.headers()[CONNECTION_SECRET_COLLECTION_ETAG_HEADER]
            .to_str()
            .expect("an ETag")
            .to_owned()
    };
    let (status, secret_etag, secret) = exchange(
        &best_effort,
        route_request(
            "POST",
            CONNECTION_SECRETS_ADMIN_ROUTE,
            admin.clone(),
            Some(json!({ "label": "Target secret", "purpose": "static_bearer", "value": "target-value" }).to_string()),
            &[("if-match", secret_collection_etag.clone())],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{secret}");
    let (status, _, token) = exchange(
        &best_effort,
        route_request(
            "POST",
            TOKENS_ADMIN_ROUTE,
            admin.clone(),
            Some(json!({ "scopes": ["probe-reader"] }).to_string()),
            &[],
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{token}");
    drop(best_effort);
    let targets = Targets {
        connection_id,
        connection_etag,
        registration,
        overlay_etag,
        connection_collection_etag,
        secret_id: secret["id"].as_str().expect("a secret ID").to_owned(),
        secret_etag: secret_etag.expect("a secret ETag"),
        secret_collection_etag,
        token_id: token["token"]["id"]
            .as_str()
            .expect("a token ID")
            .to_owned(),
    };
    let reserved_before = (
        reservations_in(&connection_db.path),
        reservations_in(&token_db.path),
    );
    let policy_before = fs::read(&policy.path).expect("the policy file reads");
    let tools_before = fs::read(&tools.path).expect("the tools file reads");

    let (audit_log, capture) = captured_audit();
    let mut required = config;
    qualified_required(&mut required, &events);
    let router = router_with(required, audit_log);
    let databases = [
        &connection_db.path,
        &token_db.path,
        &history_db.path,
        &discovery_db.path,
    ];
    let stored_before = databases.map(|path| rows_by_table(path));
    let mut refused = Vec::new();
    let mut withdrawals = Vec::new();
    for route in KEYED_ROUTES {
        let (expected, uri, body, headers) = unkeyed_case(route, &targets);
        let label = format!("{} {}", route.method, route.route);
        match expected {
            Unkeyed::Withdrawal(covered_by) => {
                withdrawals.push((label, covered_by));
                continue;
            }
            Unkeyed::KeyRequired => {
                let (status, _, answer) = exchange(
                    &router,
                    route_request(route.method, &uri, admin.clone(), body, &headers),
                )
                .await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {answer}");
                // The key is checked before the tool or the body, so this
                // answer cannot come from the body or the unknown tool.
                assert_eq!(
                    answer["error"],
                    json!("Idempotency-Key must be one canonical lowercase UUIDv7"),
                    "{label}: {answer}"
                );
            }
            Unkeyed::Refused(operation) => {
                let (status, _, answer) = exchange(
                    &router,
                    route_request(route.method, &uri, admin.clone(), body, &headers),
                )
                .await;
                assert_eq!(status, StatusCode::CONFLICT, "{label}: {answer}");
                assert_eq!(
                    answer["reason"],
                    json!("authority_evidence_unsupported"),
                    "{label}: {answer}"
                );
                assert_eq!(answer["operation"], json!(operation), "{label}: {answer}");
                refused.push(operation.to_owned());
            }
        }
    }
    // Nothing is reserved or written, and each refusal is audited once: no
    // table of any store (Connections, catalogs, overlays, local secrets,
    // evidence, tokens, policy history, suggestions) gained or lost a row,
    // and neither document file changed.
    assert_eq!(databases.map(|path| rows_by_table(path)), stored_before);
    assert_eq!(
        (
            reservations_in(&connection_db.path),
            reservations_in(&token_db.path)
        ),
        reserved_before
    );
    assert_eq!(
        fs::read(&policy.path).expect("the policy file reads"),
        policy_before
    );
    assert_eq!(
        fs::read(&tools.path).expect("the tools file reads"),
        tools_before
    );
    assert_eq!(refused_operations(&capture, refused.len()), refused);
    // The three withdrawals, each covered by its own test, and nothing else
    // is left out.
    assert_eq!(
        withdrawals
            .iter()
            .map(|(_, test)| *test)
            .collect::<Vec<_>>(),
        [
            "required_mode_admits_every_form_of_token_revocation",
            "required_mode_admits_every_form_of_connection_delete",
            "required_mode_admits_every_form_of_secret_delete",
        ]
    );
    assert_eq!(refused.len() + withdrawals.len() + 1, KEYED_ROUTES.len());
}
