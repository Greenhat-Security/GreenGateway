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
