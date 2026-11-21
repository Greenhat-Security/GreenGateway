//! Crash-consistent suggestion acceptance in standalone mode (issue #243):
//! the durable intent an acceptance records beside the suggestion before it
//! writes the policy file, the reconciler that settles an intent at startup
//! and before every suggestion request, and a draft publication bound to the
//! suggestion whose rule it holds. Crashes are injected at each boundary of
//! the real handlers with `acceptance_crash`, and a "restart" is a fresh
//! application over the same files. Cluster mode's single-transaction
//! acceptance is in `admin_observability_app_tests`.
use super::*;

fn draft_uri(draft_id: &str) -> String {
    format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}")
}

fn admin_request(
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> Request<Body> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        builder = builder
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, "Bearer test-token");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
    let mut request = builder.body(body).expect("request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }
    request
}

fn reviewer() -> Option<auth::Principal> {
    Some(test_principal(&["suggestions-policy-writer"]))
}

async fn send(router: &Router, request: Request<Body>) -> Response {
    router
        .clone()
        .oneshot(request)
        .await
        .expect("request should complete")
}

async fn refusal(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    (status, json_body(response).await)
}

fn seed_suggestion(
    path: &PathBuf,
    id: &'static str,
    path_pattern: &'static str,
    action: &'static str,
    source_signal_id: Option<&'static str>,
) {
    insert_rule_suggestion(
        path,
        RuleSuggestionSeed {
            id,
            suggestion_type: if source_signal_id.is_some() {
                "signal_shadow_new_endpoint"
            } else {
                "baseline_allow"
            },
            method: "GET",
            path_pattern,
            role: Some("review-reader"),
            action,
            rationale: "Observed review-reader calls.",
            evidence: json!({ "observation_count": 3 }),
            state: "open",
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id,
        },
    );
}

/// The gateway over `discovery_path` and `policy`, with an audit capture.
/// Building a second one over the same files is a restart: it loads the
/// policy file and runs the startup reconciler.
fn gateway(
    discovery_path: &PathBuf,
    policy: &TempPolicyFile,
) -> (Router, audit::sink::tests::CaptureSink) {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let mut config = suggestions_admin_config(Some(discovery_path), None, policy);
    config.rate_limit_write_burst = 1_000;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build");
    (router, capture)
}

fn events_of(capture: &audit::sink::tests::CaptureSink, event_type: &str) -> Vec<Value> {
    capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == event_type)
        .map(|event| event.payload)
        .collect()
}

/// A suggestion row read straight from SQLite, so the read itself runs no
/// reconciliation: `(state, revision, transitioned_by)`.
fn stored_suggestion(discovery_path: &PathBuf, id: &str) -> (String, i64, Option<String>) {
    let connection = Connection::open(discovery_path).expect("discovery database should open");
    connection
        .query_row(
            "SELECT state, revision, transitioned_by FROM discovery_rule_suggestions WHERE id = ?1",
            params![id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("suggestion should read")
}

/// The pending acceptance intents, read straight from SQLite:
/// `(suggestion_id, origin)`.
fn stored_intents(discovery_path: &PathBuf) -> Vec<(String, String)> {
    let connection = Connection::open(discovery_path).expect("discovery database should open");
    let mut statement = connection
        .prepare(
            "SELECT suggestion_id, origin FROM discovery_suggestion_acceptance_intents
             ORDER BY suggestion_id",
        )
        .expect("intent query should prepare");
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .expect("intents should read")
        .collect::<Result<Vec<_>, _>>()
        .expect("intents should decode")
}

/// Wait, yielding to the runtime, until the startup reconciler a fresh
/// gateway spawned has run.
async fn until(condition: impl Fn() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(condition(), "condition did not become true within 5s");
}

/// How many rules of the policy file match `path`.
fn rules_for(policy: &TempPolicyFile, path: &str) -> usize {
    let document: Value =
        serde_json::from_str(&fs::read_to_string(&policy.path).expect("policy file should read"))
            .expect("policy file should parse");
    document["rules"].as_array().map_or(0, |rules| {
        rules.iter().filter(|rule| rule["path"] == path).count()
    })
}

async fn accept(router: &Router, suggestion_id: &str, policy_etag: &str) -> Response {
    send(
        router,
        admin_request(
            Method::POST,
            &format!("{SUGGESTIONS_ADMIN_ROUTE}/{suggestion_id}/accept"),
            reviewer(),
            None,
            &[("if-match", policy_etag)],
        ),
    )
    .await
}

async fn live_etag(router: &Router) -> String {
    let response = send(
        router,
        admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            None,
            &[],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    policy_etag_header(&response)
}

/// Open `suggestion_id` in a new draft: `(draft_id, draft_etag, rule)`.
async fn open_in_draft(router: &Router, suggestion_id: &str) -> (String, String, Value) {
    let policy_etag = live_etag(router).await;
    let opened = send(
        router,
        admin_request(
            Method::POST,
            &format!("{SUGGESTIONS_ADMIN_ROUTE}/{suggestion_id}/draft"),
            reviewer(),
            None,
            &[("if-match", &policy_etag)],
        ),
    )
    .await;
    assert_eq!(opened.status(), StatusCode::CREATED);
    let draft_etag = policy_etag_header(&opened);
    let opened = json_body(opened).await;
    (
        opened["draft"]["draft_id"]
            .as_str()
            .expect("the draft names its id")
            .to_owned(),
        draft_etag,
        opened["rule"].clone(),
    )
}

async fn publish(
    router: &Router,
    principal: Option<auth::Principal>,
    draft: (&str, &str),
    policy_etag: &str,
    body: Option<Value>,
) -> Response {
    send(
        router,
        admin_request(
            Method::POST,
            &format!("{}/publish", draft_uri(draft.0)),
            principal,
            body,
            &[
                (POLICY_DRAFT_ETAG_HEADER, draft.1),
                ("if-match", policy_etag),
            ],
        ),
    )
    .await
}

fn binding(suggestion_id: &str, revision: i64) -> Option<Value> {
    Some(json!({ "suggestion": { "id": suggestion_id, "revision": revision } }))
}

#[tokio::test]
async fn an_acceptance_clears_the_intent_it_records_before_the_policy_write() {
    let discovery_db = TempDb::new("acceptance-intent-cleared");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-clean",
        "/clean/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;

    let accepted = accept(&router, "sug-clean", &live_etag(&router).await).await;
    assert_eq!(accepted.status(), StatusCode::CREATED);
    assert_eq!(rules_for(&policy, "/clean/{id}"), 1);
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-clean"),
        ("accepted".to_owned(), 2, Some("user-123".to_owned()))
    );
    assert!(stored_intents(&discovery_db.path).is_empty());

    // A retry is refused by the suggestion's own state and writes nothing.
    let (status, body) =
        refusal(accept(&router, "sug-clean", &live_etag(&router).await).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_not_open");
    assert_eq!(rules_for(&policy, "/clean/{id}"), 1);
}

#[tokio::test]
async fn an_acceptance_that_dies_before_its_policy_write_leaves_the_suggestion_open() {
    let discovery_db = TempDb::new("acceptance-crash-intent");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-crash-intent",
        "/intent/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;
    let disk_before = fs::read_to_string(&policy.path).expect("policy file should read");

    acceptance_crash::arm("sug-crash-intent", AcceptanceBoundary::IntentRecorded);
    let crashed = accept(&router, "sug-crash-intent", &live_etag(&router).await).await;
    assert_eq!(crashed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        stored_intents(&discovery_db.path),
        vec![("sug-crash-intent".to_owned(), "accept".to_owned())]
    );
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        disk_before
    );

    // The restart's reconciler finds the candidate never committed and
    // drops the intent: the suggestion is open, at the revision it had.
    drop(router);
    let (restarted, capture) = gateway(&discovery_db.path, &policy);
    until(|| stored_intents(&discovery_db.path).is_empty()).await;
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-crash-intent"),
        ("open".to_owned(), 1, None)
    );
    assert!(events_of(&capture, audit::event::SUGGESTION_LIFECYCLE_CHANGED).is_empty());

    // The operator retries, and that acceptance completes.
    let retried = accept(&restarted, "sug-crash-intent", &live_etag(&restarted).await).await;
    assert_eq!(retried.status(), StatusCode::CREATED);
    assert_eq!(rules_for(&policy, "/intent/{id}"), 1);
}

#[tokio::test]
async fn an_acceptance_that_dies_after_its_policy_write_is_accepted_at_restart() {
    let discovery_db = TempDb::new("acceptance-crash-committed");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-crash-commit",
        "/commit/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;

    acceptance_crash::arm("sug-crash-commit", AcceptanceBoundary::PolicyCommitted);
    let crashed = accept(&router, "sug-crash-commit", &live_etag(&router).await).await;
    assert_eq!(crashed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    // The rule is live and the suggestion has not moved: exactly the state
    // the intent exists to repair.
    assert_eq!(rules_for(&policy, "/commit/{id}"), 1);
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-crash-commit"),
        ("open".to_owned(), 1, None)
    );
    assert_eq!(stored_intents(&discovery_db.path).len(), 1);

    drop(router);
    let (restarted, capture) = gateway(&discovery_db.path, &policy);
    until(|| stored_intents(&discovery_db.path).is_empty()).await;
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-crash-commit"),
        ("accepted".to_owned(), 2, Some("user-123".to_owned()))
    );
    until(|| !events_of(&capture, audit::event::SUGGESTION_LIFECYCLE_CHANGED).is_empty()).await;
    let reconciled = events_of(&capture, audit::event::SUGGESTION_LIFECYCLE_CHANGED);
    assert_eq!(reconciled.len(), 1);
    assert_eq!(reconciled[0]["state"], "accepted");
    assert_eq!(reconciled[0]["transitioned_by"], "user-123");
    assert_eq!(reconciled[0]["reconciled"]["origin"], "accept");
    assert_eq!(
        reconciled[0]["reconciled"]["candidate_etag"],
        json!(live_etag(&restarted).await)
    );

    // Retrying the lost request is refused by the suggestion's state; the
    // rule is never added twice.
    let (status, body) =
        refusal(accept(&restarted, "sug-crash-commit", &live_etag(&restarted).await).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_not_open");
    assert_eq!(rules_for(&policy, "/commit/{id}"), 1);
}

#[tokio::test]
async fn the_next_suggestion_request_settles_an_acceptance_the_running_process_left() {
    let discovery_db = TempDb::new("acceptance-crash-in-process");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-crash-live",
        "/live/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;

    acceptance_crash::arm("sug-crash-live", AcceptanceBoundary::PolicyCommitted);
    let crashed = accept(&router, "sug-crash-live", &live_etag(&router).await).await;
    assert_eq!(crashed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(stored_intents(&discovery_db.path).len(), 1);

    // A listing never shows the suggestion open while its rule is live: it
    // settles the intent first.
    let listed = suggestions_json(
        &router,
        "/v1/admin/suggestions?state=accepted",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    assert_eq!(suggestion_ids(&listed), vec!["sug-crash-live".to_owned()]);
    assert!(stored_intents(&discovery_db.path).is_empty());

    // A dismissal arriving after the lost acceptance is refused, never
    // applied to a suggestion whose rule is already live.
    let dismissed = send(
        &router,
        admin_request(
            Method::POST,
            &format!("{SUGGESTIONS_ADMIN_ROUTE}/sug-crash-live/dismiss"),
            Some(test_principal(&["suggestions-writer"])),
            None,
            &[],
        ),
    )
    .await;
    assert_eq!(dismissed.status(), StatusCode::CONFLICT);
}

/// The policy file is the authority a restart loads, but committed history
/// is a witness too: an acceptance whose rule was committed (and recorded
/// in history) before the process died is accepted even when the file was
/// replaced while the gateway was down.
#[tokio::test]
async fn committed_history_settles_an_acceptance_whose_file_was_replaced() {
    let discovery_db = TempDb::new("acceptance-crash-history");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-crash-history",
        "/history/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;

    acceptance_crash::arm("sug-crash-history", AcceptanceBoundary::PolicyCommitted);
    let crashed = accept(&router, "sug-crash-history", &live_etag(&router).await).await;
    assert_eq!(crashed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    drop(router);
    fs::write(&policy.path, suggestions_policy_document_string())
        .expect("policy file should be replaced");

    let (_restarted, _capture) = gateway(&discovery_db.path, &policy);
    until(|| stored_intents(&discovery_db.path).is_empty()).await;
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-crash-history").0,
        "accepted"
    );
    assert_eq!(rules_for(&policy, "/history/{id}"), 0);
}

#[tokio::test]
async fn a_publication_bound_to_its_suggestion_accepts_it_with_the_draft() {
    let discovery_db = TempDb::new("bound-publication");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-bound",
        "/bound/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, capture) = gateway(&discovery_db.path, &policy);
    let (draft_id, draft_etag, rule) = open_in_draft(&router, "sug-bound").await;
    let base = live_etag(&router).await;

    let published = publish(
        &router,
        reviewer(),
        (&draft_id, &draft_etag),
        &base,
        binding("sug-bound", 1),
    )
    .await;
    assert_eq!(published.status(), StatusCode::OK);
    let policy_etag = policy_etag_header(&published);
    assert_eq!(json_body(published).await["rules"], json!([rule]));
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-bound"),
        ("accepted".to_owned(), 2, Some("user-123".to_owned()))
    );
    assert!(stored_intents(&discovery_db.path).is_empty());

    until(|| !events_of(&capture, audit::event::POLICY_DRAFT_PUBLISHED).is_empty()).await;
    let suggestion_binding = json!({
        "id": "sug-bound",
        "revision": 1,
        "rule_id": rule["id"],
        "position": 0,
        "operator_edit": null,
    });
    let published_events = events_of(&capture, audit::event::POLICY_DRAFT_PUBLISHED);
    assert_eq!(published_events[0]["suggestion"], suggestion_binding);
    assert_eq!(published_events[0]["policy_etag"], json!(policy_etag));
    let changed = events_of(&capture, audit::event::POLICY_CHANGED);
    assert_eq!(changed[0]["diff_summary"]["suggestion"], suggestion_binding);
    let lifecycle = events_of(&capture, audit::event::SUGGESTION_LIFECYCLE_CHANGED);
    assert_eq!(lifecycle.len(), 1);
    assert_eq!(lifecycle[0]["state"], "accepted");

    // An exact retry writes nothing: the draft is published, and the
    // suggestion stays accepted at the revision the publication gave it.
    let (status, body) = refusal(
        publish(
            &router,
            reviewer(),
            (&draft_id, &draft_etag),
            &base,
            binding("sug-bound", 1),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "policy_draft_published");
    assert_eq!(body["published_etag"], json!(policy_etag));
    assert_eq!(stored_suggestion(&discovery_db.path, "sug-bound").1, 2);
    assert_eq!(rules_for(&policy, "/bound/{id}"), 1);
}

#[tokio::test]
async fn a_bound_publication_is_refused_unless_the_suggestion_and_its_rule_still_hold() {
    let discovery_db = TempDb::new("bound-publication-refusals");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(&discovery_db.path, "sug-held", "/held/{id}", "allow", None);
    seed_suggestion(
        &discovery_db.path,
        "sug-elsewhere",
        "/elsewhere/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, capture) = gateway(&discovery_db.path, &policy);
    let (draft_id, draft_etag, _rule) = open_in_draft(&router, "sug-held").await;
    let base = live_etag(&router).await;
    let draft = (draft_id.as_str(), draft_etag.as_str());

    // Malformed bindings are the request's fault, and a policy writer
    // without the suggestion write permission cannot accept one.
    for body in [
        json!({ "suggestion": { "id": "sug-held" } }),
        json!({ "suggestion": { "id": "sug-held", "revision": 0 } }),
        json!({ "suggestion": { "id": " ", "revision": 1 } }),
        json!({ "suggestion": { "id": "sug-held", "revision": 1, "force": true } }),
        json!({ "force": true }),
    ] {
        let response = publish(&router, reviewer(), draft, &base, Some(body.clone())).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{body}");
    }
    let forbidden = publish(
        &router,
        Some(test_principal(&["policy-writer"])),
        draft,
        &base,
        binding("sug-held", 1),
    )
    .await;
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    // A revision the suggestion is not at is stale, and so is another
    // suggestion's rule the draft does not hold.
    let (status, body) =
        refusal(publish(&router, reviewer(), draft, &base, binding("sug-held", 2)).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_stale");
    assert_eq!(body["suggestion"]["revision"], 1);
    let (status, body) = refusal(
        publish(
            &router,
            reviewer(),
            draft,
            &base,
            binding("sug-elsewhere", 1),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_rule_absent");

    // Dismissed first, the suggestion cannot be accepted by a publication:
    // one compare-and-set winner.
    let dismissed = send(
        &router,
        admin_request(
            Method::POST,
            &format!("{SUGGESTIONS_ADMIN_ROUTE}/sug-held/dismiss"),
            Some(test_principal(&["suggestions-writer"])),
            None,
            &[],
        ),
    )
    .await;
    assert_eq!(dismissed.status(), StatusCode::OK);
    let (status, body) =
        refusal(publish(&router, reviewer(), draft, &base, binding("sug-held", 1)).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_stale");
    assert_eq!(body["suggestion"]["state"], "dismissed");

    // Nothing was written by any refusal, and each one that reached the
    // draft was audited with its reason.
    assert_eq!(live_etag(&router).await, base);
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-elsewhere"),
        ("open".to_owned(), 1, None)
    );
    assert!(stored_intents(&discovery_db.path).is_empty());
    until(|| events_of(&capture, audit::event::POLICY_DRAFT_PUBLISH_REFUSED).len() == 3).await;
    let reasons = events_of(&capture, audit::event::POLICY_DRAFT_PUBLISH_REFUSED)
        .into_iter()
        .map(|event| event["reason"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        vec![
            json!("suggestion_stale"),
            json!("suggestion_rule_absent"),
            json!("suggestion_stale")
        ]
    );

    // The draft is still open and still publishes on its own.
    let unbound = publish(&router, reviewer(), draft, &base, None).await;
    assert_eq!(unbound.status(), StatusCode::OK);
}

/// A shadow proposal published as an enforced deny is the operator's
/// explicit edit: accepted, and recorded with the publication. Any other
/// change to the rule means the draft no longer holds the proposal.
#[tokio::test]
async fn enforcing_a_shadow_proposal_is_an_operator_edit_the_publication_records() {
    let discovery_db = TempDb::new("bound-publication-edit");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-signal-edit",
        "/signal/{id}",
        "deny",
        Some("sig-new-endpoint"),
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, capture) = gateway(&discovery_db.path, &policy);
    let (draft_id, draft_etag, rule) = open_in_draft(&router, "sug-signal-edit").await;
    assert_eq!(rule["action"], "shadow");
    let base = live_etag(&router).await;

    let patch = |draft_etag: String, action: &'static str| {
        let mut edited = rule.clone();
        edited["action"] = json!(action);
        let mut document: Value =
            serde_json::from_str(&suggestions_policy_document_string()).expect("policy parses");
        document["rules"] = json!([edited]);
        let router = router.clone();
        let draft_id = draft_id.clone();
        async move {
            let patched = send(
                &router,
                admin_request(
                    Method::PATCH,
                    &draft_uri(&draft_id),
                    reviewer(),
                    Some(json!({ "policy": document })),
                    &[("if-match", &draft_etag)],
                ),
            )
            .await;
            assert_eq!(patched.status(), StatusCode::OK);
            policy_etag_header(&patched)
        }
    };

    let allowed_etag = patch(draft_etag, "allow").await;
    let (status, body) = refusal(
        publish(
            &router,
            reviewer(),
            (&draft_id, &allowed_etag),
            &base,
            binding("sug-signal-edit", 1),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_rule_absent");

    let enforced_etag = patch(allowed_etag, "deny").await;
    let published = publish(
        &router,
        reviewer(),
        (&draft_id, &enforced_etag),
        &base,
        binding("sug-signal-edit", 1),
    )
    .await;
    assert_eq!(published.status(), StatusCode::OK);
    assert_eq!(json_body(published).await["rules"][0]["action"], "deny");
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-signal-edit").0,
        "accepted"
    );
    until(|| !events_of(&capture, audit::event::POLICY_DRAFT_PUBLISHED).is_empty()).await;
    assert_eq!(
        events_of(&capture, audit::event::POLICY_DRAFT_PUBLISHED)[0]["suggestion"]["operator_edit"],
        "shadow_enforced_as_deny"
    );
    assert_eq!(
        events_of(&capture, audit::event::POLICY_CHANGED)[0]["diff_summary"]["suggestion"]
            ["operator_edit"],
        "shadow_enforced_as_deny"
    );
}

/// An acceptance and a bound publication of the same suggestion racing in
/// one process: exactly one wins, the rule is added once, and the
/// suggestion moves once.
#[tokio::test]
async fn an_acceptance_and_a_bound_publication_of_one_suggestion_have_one_winner() {
    let discovery_db = TempDb::new("bound-publication-race");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-raced",
        "/raced/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    let (draft_id, draft_etag, _rule) = open_in_draft(&router, "sug-raced").await;
    let base = live_etag(&router).await;

    let (accepted, published) = tokio::join!(
        accept(&router, "sug-raced", &base),
        publish(
            &router,
            reviewer(),
            (&draft_id, &draft_etag),
            &base,
            binding("sug-raced", 1),
        ),
    );
    let statuses = [accepted.status(), published.status()];
    assert_eq!(
        statuses.iter().filter(|status| status.is_success()).count(),
        1,
        "{statuses:?}"
    );
    assert!(
        statuses
            .iter()
            .any(|status| *status == StatusCode::CONFLICT
                || *status == StatusCode::PRECONDITION_FAILED),
        "{statuses:?}"
    );
    assert_eq!(rules_for(&policy, "/raced/{id}"), 1);
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-raced"),
        ("accepted".to_owned(), 2, Some("user-123".to_owned()))
    );
}

/// The bound publication's own boundaries: dying after the policy commit
/// is settled like an acceptance, and dying after the suggestion moved
/// leaves only the draft's mark, which a retry cannot repeat the commit
/// around.
#[tokio::test]
async fn a_bound_publication_that_dies_at_either_boundary_never_splits_the_rule_and_suggestion() {
    let discovery_db = TempDb::new("bound-publication-crash");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-publish-commit",
        "/one/{id}",
        "allow",
        None,
    );
    seed_suggestion(
        &discovery_db.path,
        "sug-publish-mark",
        "/two/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);

    let (draft_id, draft_etag, _rule) = open_in_draft(&router, "sug-publish-commit").await;
    acceptance_crash::arm("sug-publish-commit", AcceptanceBoundary::PolicyCommitted);
    let crashed = publish(
        &router,
        reviewer(),
        (&draft_id, &draft_etag),
        &live_etag(&router).await,
        binding("sug-publish-commit", 1),
    )
    .await;
    assert_eq!(crashed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        stored_intents(&discovery_db.path),
        vec![("sug-publish-commit".to_owned(), "draft_publish".to_owned())]
    );
    drop(router);
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    until(|| stored_intents(&discovery_db.path).is_empty()).await;
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-publish-commit").0,
        "accepted"
    );
    assert_eq!(rules_for(&policy, "/one/{id}"), 1);
    // The draft was never marked published, and its base is no longer
    // live: a retry is refused rather than committed again.
    let (status, body) = refusal(
        publish(
            &router,
            reviewer(),
            (&draft_id, &draft_etag),
            &live_etag(&router).await,
            binding("sug-publish-commit", 1),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "policy_draft_base_stale");

    let (draft_id, draft_etag, _rule) = open_in_draft(&router, "sug-publish-mark").await;
    acceptance_crash::arm("sug-publish-mark", AcceptanceBoundary::SuggestionAccepted);
    let crashed = publish(
        &router,
        reviewer(),
        (&draft_id, &draft_etag),
        &live_etag(&router).await,
        binding("sug-publish-mark", 1),
    )
    .await;
    assert_eq!(crashed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert!(stored_intents(&discovery_db.path).is_empty());
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-publish-mark").0,
        "accepted"
    );
    assert_eq!(rules_for(&policy, "/two/{id}"), 1);
    let read = send(
        &router,
        admin_request(Method::GET, &draft_uri(&draft_id), reviewer(), None, &[]),
    )
    .await;
    assert_eq!(json_body(read).await["state"], "open");
}

// ---------------------------------------------------------------------
// Generation bindings and freshness on the accept, draft and list routes
// (issue #243, checklist item 19; owner rulings 2 and 3 of 2026-11-20).
// ---------------------------------------------------------------------

/// Replace the live policy with one that also has an unrelated role: a
/// policy change that touches no suggestion. Returns the new ETag.
async fn change_policy(router: &Router) -> String {
    let current = send(
        router,
        admin_request(
            Method::GET,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["policy-reader"])),
            None,
            &[],
        ),
    )
    .await;
    assert_eq!(current.status(), StatusCode::OK);
    let etag = policy_etag_header(&current);
    let mut document = json_body(current).await;
    document["roles"]["unrelated-role"] = json!({ "permissions": [] });
    let replaced = send(
        router,
        admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            Some(test_principal(&["policy-writer"])),
            Some(document),
            &[("if-match", &etag)],
        ),
    )
    .await;
    assert_eq!(replaced.status(), StatusCode::OK);
    let replaced_etag = policy_etag_header(&replaced);
    assert_ne!(replaced_etag, etag);
    replaced_etag
}

async fn accept_with(router: &Router, suggestion_id: &str, headers: &[(&str, &str)]) -> Response {
    send(
        router,
        admin_request(
            Method::POST,
            &format!("{SUGGESTIONS_ADMIN_ROUTE}/{suggestion_id}/accept"),
            reviewer(),
            None,
            headers,
        ),
    )
    .await
}

async fn listed(router: &Router, principal: &[&str]) -> Value {
    suggestions_json(
        router,
        "/v1/admin/suggestions",
        Some(test_principal(principal)),
    )
    .await
}

fn listed_row<'a>(page: &'a Value, id: &str) -> &'a Value {
    page["suggestions"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["id"] == id))
        .unwrap_or_else(|| panic!("{id} is listed: {page}"))
}

#[tokio::test]
async fn suggestion_list_reports_server_computed_freshness() {
    let discovery_db = TempDb::new("freshness-list");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-bound",
        "/bound/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;
    // Seeded after the fixture ran: no binding was recorded for it.
    seed_suggestion(
        &discovery_db.path,
        "sug-unbound",
        "/unbound/{id}",
        "allow",
        None,
    );
    seed_suggestion(&discovery_db.path, "sug-done", "/done/{id}", "allow", None);
    let dismissed = send(
        &router,
        admin_request(
            Method::POST,
            &format!("{SUGGESTIONS_ADMIN_ROUTE}/sug-done/dismiss"),
            Some(test_principal(&["suggestions-writer"])),
            None,
            &[],
        ),
    )
    .await;
    assert_eq!(dismissed.status(), StatusCode::OK);

    let page = listed(&router, &["suggestions-reader"]).await;
    let bound = listed_row(&page, "sug-bound");
    assert_eq!(
        bound["freshness"],
        json!({ "status": "current", "reasons": [] })
    );
    assert_eq!(
        bound["generation"]["generator_version"],
        json!("rule-suggestions.v1")
    );
    assert_eq!(
        bound["generation"]["evidence_schema_version"],
        json!("rule-suggestion-evidence.v1")
    );
    assert_eq!(
        bound["generation"]["evidence_cutoff"],
        json!("2024-06-01T00:00:00Z")
    );
    assert_eq!(
        bound["generation"]["resource_snapshot_complete"],
        json!(true)
    );
    assert!(bound["generation"]["resource_snapshot_digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));
    let unbound = listed_row(&page, "sug-unbound");
    assert_eq!(unbound["generation"], Value::Null);
    assert_eq!(
        unbound["freshness"],
        json!({ "status": "unbound", "reasons": ["binding_not_recorded"] })
    );
    // A row that is not open has no freshness; its state says what it is.
    assert_eq!(
        listed_row(&page, "sug-done")["freshness"],
        json!({ "status": null, "reasons": [] })
    );

    // A policy change makes the bound row stale, and says why.
    change_policy(&router).await;
    let page = listed(&router, &["suggestions-reader"]).await;
    assert_eq!(
        listed_row(&page, "sug-bound")["freshness"],
        json!({ "status": "stale", "reasons": ["policy_changed"] })
    );
}

#[tokio::test]
async fn freshness_never_reveals_the_live_policy_etag_to_a_suggestions_reader_without_policy_read()
{
    let discovery_db = TempDb::new("freshness-privacy");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-private",
        "/private/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;
    let live = live_etag(&router).await;
    let live_digest = live
        .trim_matches('"')
        .trim_start_matches("sha256:")
        .to_owned();
    let context = current_generation_context(&router).await;

    // The `current` case is the one where the stored binding equals the
    // live state, so it is the one that could leak it.
    let page = listed(&router, &["suggestions-reader"]).await;
    assert_eq!(
        listed_row(&page, "sug-private")["freshness"]["status"],
        json!("current")
    );
    let text = page.to_string();
    assert!(!text.contains(&live_digest), "the live ETag leaked: {text}");
    assert!(
        !text.contains(&context.resource_components),
        "the resource components leaked: {text}"
    );
    if let Some(semantic) = &context.policy_semantic_digest {
        assert!(!text.contains(semantic.as_str()), "{text}");
    }
}

#[tokio::test]
async fn accept_refuses_a_stale_binding_with_409_and_writes_nothing() {
    let discovery_db = TempDb::new("accept-stale-binding");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-stale",
        "/stale/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;
    let changed = change_policy(&router).await;
    let disk_before = fs::read(&policy.path).expect("policy file should read");
    // The policy change's own event, once it has arrived.
    assert_eventually(Duration::from_secs(1), || {
        events_of(&capture, audit::event::POLICY_CHANGED).len() == 1
    });
    let changes_before = 1;

    let (status, body) = refusal(accept(&router, "sug-stale", &changed).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_binding_stale");
    assert_eq!(
        body["freshness"],
        json!({ "status": "stale", "reasons": ["policy_changed"] })
    );
    assert_eq!(body["suggestion"]["id"], "sug-stale");
    assert_eq!(body["suggestion"]["state"], "open");

    // Nothing was written: not the policy, not the suggestion, no intent,
    // no event.
    assert_eq!(
        fs::read(&policy.path).expect("policy file should read"),
        disk_before
    );
    assert_eq!(live_etag(&router).await, changed);
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-stale"),
        ("open".to_owned(), 1, None)
    );
    assert!(stored_intents(&discovery_db.path).is_empty());
    // Long enough for an event the refusal emitted to have arrived.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        events_of(&capture, audit::event::POLICY_CHANGED).len(),
        changes_before
    );
    assert!(events_of(&capture, audit::event::SUGGESTION_LIFECYCLE_CHANGED).is_empty());
}

/// A resource component change, not a policy change: the gateway restarts
/// over the same files with a different static configuration, so its
/// configuration fingerprint moves while the policy ETag does not. A
/// suggestion bound before the restart is refused on accept with that
/// component's code, and nothing is written.
#[tokio::test]
async fn accept_refuses_a_suggestion_bound_before_a_configuration_change() {
    let discovery_db = TempDb::new("accept-stale-configuration");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-stale-config",
        "/stale-config/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (before_restart, _) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&before_restart, &discovery_db.path).await;
    let etag = live_etag(&before_restart).await;

    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let mut config = suggestions_admin_config(Some(&discovery_db.path), None, &policy);
    config.rate_limit_write_burst = 2_000;
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("app should build");
    assert_eq!(live_etag(&router).await, etag, "the policy did not change");
    let disk_before = fs::read(&policy.path).expect("policy file should read");

    let (status, body) = refusal(accept(&router, "sug-stale-config", &etag).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_binding_stale");
    assert_eq!(
        body["freshness"],
        json!({ "status": "stale", "reasons": ["configuration_changed"] })
    );
    assert_eq!(
        fs::read(&policy.path).expect("policy file should read"),
        disk_before
    );
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-stale-config"),
        ("open".to_owned(), 1, None)
    );
    assert!(stored_intents(&discovery_db.path).is_empty());
    assert!(events_of(&capture, audit::event::SUGGESTION_LIFECYCLE_CHANGED).is_empty());
}

#[tokio::test]
async fn accept_refuses_an_unbound_suggestion_while_review_in_draft_still_opens_it() {
    let discovery_db = TempDb::new("accept-unbound");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-unbound",
        "/unbound/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);

    let (status, body) =
        refusal(accept(&router, "sug-unbound", &live_etag(&router).await).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_binding_unrecorded");
    assert_eq!(
        body["freshness"],
        json!({ "status": "unbound", "reasons": ["binding_not_recorded"] })
    );
    assert_eq!(rules_for(&policy, "/unbound/{id}"), 0);
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-unbound"),
        ("open".to_owned(), 1, None)
    );

    // Review in draft is the way through: drafting re-checks the proposal
    // against the live policy, and says the binding was not recorded.
    let opened = send(
        &router,
        admin_request(
            Method::POST,
            &format!("{SUGGESTIONS_ADMIN_ROUTE}/sug-unbound/draft"),
            reviewer(),
            None,
            &[("if-match", &live_etag(&router).await)],
        ),
    )
    .await;
    assert_eq!(opened.status(), StatusCode::CREATED);
    assert_eq!(
        json_body(opened).await["freshness"],
        json!({ "status": "unbound", "reasons": ["binding_not_recorded"] })
    );
}

#[tokio::test]
async fn accept_refuses_a_suggestion_whose_rule_is_already_live() {
    let discovery_db = TempDb::new("accept-superseded");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(&discovery_db.path, "sug-live", "/live/{id}", "allow", None);
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;

    // The same rule goes live without the suggestion: its draft is
    // published unbound, so the suggestion stays open.
    let (draft_id, draft_etag, _rule) = open_in_draft(&router, "sug-live").await;
    let published = publish(
        &router,
        reviewer(),
        (&draft_id, &draft_etag),
        &live_etag(&router).await,
        None,
    )
    .await;
    assert_eq!(published.status(), StatusCode::OK);
    assert_eq!(rules_for(&policy, "/live/{id}"), 1);

    // The listing judges the stored proposal, which this seeded row holds
    // without the dispatch review recomputes, so it reports only that the
    // policy changed; the accept route judges the rule it would install.
    let page = listed(&router, &["suggestions-reader"]).await;
    assert_eq!(
        listed_row(&page, "sug-live")["freshness"]["status"],
        json!("stale")
    );
    let (status, body) =
        refusal(accept(&router, "sug-live", &live_etag(&router).await).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_rule_already_present");
    assert_eq!(body["freshness"]["status"], "superseded");
    assert_eq!(rules_for(&policy, "/live/{id}"), 1, "never a second copy");
}

#[tokio::test]
async fn accept_installs_a_signal_derived_deny_as_shadow() {
    let discovery_db = TempDb::new("accept-shadow-first");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-deny",
        "/deny/{id}",
        "deny",
        Some("sig-deny"),
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;

    let accepted = accept(&router, "sug-deny", &live_etag(&router).await).await;
    assert_eq!(accepted.status(), StatusCode::CREATED);
    assert_eq!(json_body(accepted).await["rule"]["action"], "shadow");
    let document: Value =
        serde_json::from_str(&fs::read_to_string(&policy.path).expect("policy file should read"))
            .expect("policy file should parse");
    assert_eq!(document["rules"][0]["action"], "shadow");
}

#[tokio::test]
async fn a_repeated_accept_of_an_accepted_suggestion_is_409_not_open_whatever_its_preconditions_and_writes_nothing(
) {
    let discovery_db = TempDb::new("accept-repeat");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-repeat",
        "/repeat/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;
    let original = live_etag(&router).await;
    let accepted = accept(&router, "sug-repeat", &original).await;
    assert_eq!(accepted.status(), StatusCode::CREATED);
    let after = live_etag(&router).await;
    let disk_after = fs::read(&policy.path).expect("policy file should read");
    // The acceptance's own events, once they have arrived.
    assert_eventually(Duration::from_secs(1), || {
        events_of(&capture, audit::event::POLICY_CHANGED).len() == 1
            && events_of(&capture, audit::event::SUGGESTION_LIFECYCLE_CHANGED).len() == 1
    });
    let changes_after = 1;
    let transitions_after = 1;

    for headers in [
        vec![("if-match", original.as_str())],
        vec![("if-match", after.as_str())],
        vec![
            ("if-match", after.as_str()),
            (SUGGESTION_REVISION_HEADER, "1"),
        ],
        vec![],
    ] {
        let (status, body) = refusal(accept_with(&router, "sug-repeat", &headers).await).await;
        assert_eq!(status, StatusCode::CONFLICT, "{headers:?}");
        assert_eq!(body["reason"], "suggestion_not_open", "{headers:?}");
        assert_eq!(body["suggestion"]["state"], "accepted", "{headers:?}");
        assert_eq!(body["suggestion"]["revision"], 2, "{headers:?}");
        assert_eq!(
            body["suggestion"]["transitioned_by"], "user-123",
            "{headers:?}"
        );
    }
    // Long enough for an event a repeat emitted to have arrived.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(rules_for(&policy, "/repeat/{id}"), 1);
    assert_eq!(
        fs::read(&policy.path).expect("policy file should read"),
        disk_after
    );
    assert_eq!(live_etag(&router).await, after);
    assert!(stored_intents(&discovery_db.path).is_empty());
    assert_eq!(
        events_of(&capture, audit::event::POLICY_CHANGED).len(),
        changes_after
    );
    assert_eq!(
        events_of(&capture, audit::event::SUGGESTION_LIFECYCLE_CHANGED).len(),
        transitions_after
    );
}

#[tokio::test]
async fn a_repeated_accept_while_its_intent_is_pending_settles_it_and_answers_not_open() {
    let discovery_db = TempDb::new("accept-repeat-pending");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-pending",
        "/pending/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;

    acceptance_crash::arm("sug-pending", AcceptanceBoundary::PolicyCommitted);
    let crashed = accept(&router, "sug-pending", &live_etag(&router).await).await;
    assert_eq!(crashed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(stored_intents(&discovery_db.path).len(), 1);

    // The repeat settles the pending intent first, then answers from the
    // row as it now stands: accepted, the rule installed once.
    let (status, body) =
        refusal(accept(&router, "sug-pending", &live_etag(&router).await).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_not_open");
    assert_eq!(body["suggestion"]["state"], "accepted");
    assert!(stored_intents(&discovery_db.path).is_empty());
    assert_eq!(rules_for(&policy, "/pending/{id}"), 1);
}

#[tokio::test]
async fn the_binding_check_runs_after_the_policy_precondition_and_before_any_write() {
    let discovery_db = TempDb::new("accept-binding-precedence");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-order",
        "/order/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;
    let original = live_etag(&router).await;
    let changed = change_policy(&router).await;

    // A stale If-Match and a stale binding: the policy precondition
    // answers first.
    let stale_both = accept(&router, "sug-order", &original).await;
    assert_eq!(stale_both.status(), StatusCode::PRECONDITION_FAILED);
    // No If-Match at all: still the precondition's answer.
    let missing = accept_with(&router, "sug-order", &[]).await;
    assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);
    // A current If-Match and a stale binding: the binding's 409.
    let (status, body) = refusal(accept(&router, "sug-order", &changed).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_binding_stale");
    // The suggestion's own revision precedes both.
    let (status, body) = refusal(
        accept_with(
            &router,
            "sug-order",
            &[("if-match", &original), (SUGGESTION_REVISION_HEADER, "7")],
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_revision_mismatch");
    assert_eq!(rules_for(&policy, "/order/{id}"), 0);
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-order"),
        ("open".to_owned(), 1, None)
    );
}

#[tokio::test]
async fn drafting_reports_generation_freshness_and_audits_codes_only() {
    let discovery_db = TempDb::new("draft-freshness");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-drafted",
        "/drafted/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;
    change_policy(&router).await;

    // A stale suggestion still opens: drafting is the review that
    // re-checks it, and the answer says what changed.
    let opened = send(
        &router,
        admin_request(
            Method::POST,
            &format!("{SUGGESTIONS_ADMIN_ROUTE}/sug-drafted/draft"),
            reviewer(),
            None,
            &[("if-match", &live_etag(&router).await)],
        ),
    )
    .await;
    assert_eq!(opened.status(), StatusCode::CREATED);
    let opened = json_body(opened).await;
    assert_eq!(
        opened["freshness"],
        json!({ "status": "stale", "reasons": ["policy_changed"] })
    );
    assert_eq!(
        opened["suggestion"]["generation"]["generator_version"],
        "rule-suggestions.v1"
    );

    assert_eventually(Duration::from_secs(1), || {
        !events_of(&capture, audit::event::POLICY_SUGGESTION_DRAFTED).is_empty()
    });
    let drafted = events_of(&capture, audit::event::POLICY_SUGGESTION_DRAFTED);
    assert_eq!(drafted[0]["generation_freshness"], "stale");
    assert_eq!(
        drafted[0]["generation_freshness_reasons"],
        json!(["policy_changed"])
    );
    // Codes only: no policy content, path or principal joins the event.
    let mut keys = drafted[0]
        .as_object()
        .expect("the payload is an object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        [
            "base_etag",
            "candidate_etag",
            "draft_created",
            "draft_id",
            "draft_revision",
            "generation_freshness",
            "generation_freshness_reasons",
            "position",
            "rule_id",
            "suggestion_id",
            "suggestion_revision",
            "suggestion_type",
        ]
    );
    let text = drafted[0].to_string();
    assert!(!text.contains("/drafted/"), "{text}");
    assert!(!text.contains("review-reader"), "{text}");
}

#[tokio::test]
async fn a_publication_bound_to_a_revision_that_regeneration_moved_is_refused_as_stale_and_writes_nothing(
) {
    let discovery_db = TempDb::new("publish-after-rebind");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-moved",
        "/moved/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    let (draft_id, draft_etag, _rule) = open_in_draft(&router, "sug-moved").await;

    // A rebind moves the revision the draft's publication names: here the
    // generation fixture binds the unbound row, as a run would.
    let connection = Connection::open(&discovery_db.path).expect("discovery database should open");
    connection
        .execute(
            "UPDATE discovery_rule_suggestions SET revision = revision + 1 WHERE id = 'sug-moved'",
            [],
        )
        .expect("the rebind's revision move should apply");
    drop(connection);
    bind_seeded_suggestions(&router, &discovery_db.path).await;
    let disk_before = fs::read(&policy.path).expect("policy file should read");

    let (status, body) = refusal(
        publish(
            &router,
            reviewer(),
            (&draft_id, &draft_etag),
            &live_etag(&router).await,
            binding("sug-moved", 1),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_stale");
    assert_eq!(
        fs::read(&policy.path).expect("policy file should read"),
        disk_before
    );
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-moved"),
        ("open".to_owned(), 2, None)
    );
}

#[tokio::test]
async fn generation_settles_a_pending_acceptance_before_it_writes() {
    let discovery_db = TempDb::new("generation-settles-intent");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-inflight",
        "/inflight/{id}",
        "allow",
        None,
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = gateway(&discovery_db.path, &policy);
    bind_seeded_suggestions(&router, &discovery_db.path).await;

    acceptance_crash::arm("sug-inflight", AcceptanceBoundary::PolicyCommitted);
    let crashed = accept(&router, "sug-inflight", &live_etag(&router).await).await;
    assert_eq!(crashed.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(stored_intents(&discovery_db.path).len(), 1);

    // Generation now rebinds rows, so its writes take the lifecycle lock,
    // which settles the acceptance first: the policy commit and the
    // transition both stand, and nothing rebinds the row in between.
    let generated = send(
        &router,
        admin_request(
            Method::POST,
            &format!("{SUGGESTIONS_ADMIN_ROUTE}/generate"),
            Some(test_principal(&["suggestions-writer"])),
            None,
            &[],
        ),
    )
    .await;
    assert_eq!(generated.status(), StatusCode::OK);
    assert!(stored_intents(&discovery_db.path).is_empty());
    assert_eq!(
        stored_suggestion(&discovery_db.path, "sug-inflight"),
        ("accepted".to_owned(), 2, Some("user-123".to_owned()))
    );
    assert_eq!(rules_for(&policy, "/inflight/{id}"), 1);
}
