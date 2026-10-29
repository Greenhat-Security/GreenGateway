//! Opening a discovery suggestion into a server-side policy draft (issue
//! #243, slice 19), in standalone mode: the SQLite discovery store, the
//! draft store beside the policy history database, and the file authority.
//! The draft routes themselves are in `admin_policy_drafts_tests`, and
//! acceptance, which still applies a suggestion directly, beside the other
//! suggestion routes in `app_tests`.
use super::*;

fn suggestion_draft_uri(suggestion_id: &str) -> String {
    format!("{SUGGESTIONS_ADMIN_ROUTE}/{suggestion_id}/draft")
}

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

/// Open `suggestion_id` in a draft: a new one, or `draft` (its id and
/// current ETag) when named.
async fn draft_suggestion(
    router: &Router,
    suggestion_id: &str,
    policy_etag: &str,
    draft: Option<(&str, &str)>,
) -> Response {
    let mut headers = vec![("if-match", policy_etag)];
    let body = draft.map(|(draft_id, draft_etag)| {
        headers.push((POLICY_DRAFT_ETAG_HEADER, draft_etag));
        json!({ "draft_id": draft_id })
    });
    send(
        router,
        admin_request(
            Method::POST,
            &suggestion_draft_uri(suggestion_id),
            reviewer(),
            body,
            &headers,
        ),
    )
    .await
}

fn seed_suggestion(
    path: &PathBuf,
    id: &'static str,
    path_pattern: &'static str,
    action: &'static str,
    source_signal_id: Option<&'static str>,
    state: &'static str,
) {
    insert_rule_suggestion(
        path,
        RuleSuggestionSeed {
            id,
            suggestion_type: if source_signal_id.is_some() {
                "signal_shadow_deny"
            } else {
                "baseline_allow"
            },
            method: "GET",
            path_pattern,
            role: Some("review-reader"),
            action,
            rationale: "Observed review-reader calls.",
            evidence: json!({ "observation_count": 3 }),
            state,
            created_at: "2024-06-01T00:00:00Z",
            transitioned_at: None,
            transitioned_by: None,
            source_signal_id,
        },
    );
}

/// The suggestions router with an audit capture and a write lane wide
/// enough for every request these tests send.
fn captured_router(
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

async fn live_policy(router: &Router) -> (String, Value) {
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
    let etag = policy_etag_header(&response);
    (etag, json_body(response).await)
}

async fn owned_drafts(router: &Router) -> Vec<Value> {
    let response = send(
        router,
        admin_request(
            Method::GET,
            POLICY_DRAFTS_ADMIN_ROUTE,
            reviewer(),
            None,
            &[],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    json_body(response).await["drafts"]
        .as_array()
        .cloned()
        .expect("a listing names its drafts")
}

async fn open_suggestion(router: &Router, suggestion_id: &str) -> Value {
    let page = suggestions_json(
        router,
        "/v1/admin/suggestions?state=open",
        Some(test_principal(&["suggestions-reader"])),
    )
    .await;
    page["suggestions"]
        .as_array()
        .and_then(|suggestions| {
            suggestions
                .iter()
                .find(|suggestion| suggestion["id"] == suggestion_id)
        })
        .cloned()
        .unwrap_or_else(|| panic!("{suggestion_id} should still be open"))
}

#[tokio::test]
async fn a_suggestion_opens_as_an_inactive_draft_pinned_to_the_live_policy() {
    let discovery_db = TempDb::new("suggestion-draft-review");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-review",
        "/review/{id}",
        "allow",
        None,
        "open",
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, capture) = captured_router(&discovery_db.path, &policy);
    let (live_etag, live) = live_policy(&router).await;
    let disk_before = fs::read_to_string(&policy.path).expect("policy file should read");

    let opened = draft_suggestion(&router, "sug-review", &live_etag, None).await;
    assert_eq!(opened.status(), StatusCode::CREATED);
    assert_eq!(
        opened
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
    let draft_etag = policy_etag_header(&opened);
    let opened = json_body(opened).await;
    let draft = &opened["draft"];
    let draft_id = draft["draft_id"]
        .as_str()
        .expect("the draft names its id")
        .to_owned();
    assert!(draft_id.starts_with("pd_"), "{draft_id}");
    assert_eq!(draft["state"], "open");
    assert_eq!(draft["revision"], 1);
    assert_eq!(draft["base_etag"], json!(live_etag));
    assert_eq!(opened["position"], 0);
    assert_eq!(draft["policy"]["rules"].as_array().map(Vec::len), Some(1));
    assert_eq!(draft["policy"]["rules"][0], opened["rule"]);
    let rule = &opened["rule"];
    assert!(
        rule["id"]
            .as_str()
            .is_some_and(|id| id.starts_with("rule-")),
        "a drafted rule gets a stable id: {rule}"
    );
    assert_eq!(rule["action"], "allow");
    assert_eq!(rule["path"], "/review/{id}");
    assert_eq!(rule["principal"]["roles"], json!(["review-reader"]));
    assert_eq!(rule["principal"]["issuers"], json!(["provider:test"]));
    // Bound to routing as it is now, exactly as acceptance binds it.
    assert_eq!(rule["dispatch"], json!({ "kind": "contextless" }));
    assert_eq!(opened["suggestion"]["id"], "sug-review");
    assert_eq!(opened["suggestion"]["state"], "open");
    assert_eq!(opened["suggestion"]["revision"], 1);

    // Nothing live moved: not the policy, not the suggestion.
    assert_eq!(live_policy(&router).await, (live_etag.clone(), live));
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        disk_before
    );
    let still_open = open_suggestion(&router, "sug-review").await;
    assert_eq!(still_open["revision"], 1);
    assert_eq!(still_open["transitioned_by"], Value::Null);

    // The draft is an ordinary draft of its owner's.
    let read = send(
        &router,
        admin_request(Method::GET, &draft_uri(&draft_id), reviewer(), None, &[]),
    )
    .await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(policy_etag_header(&read), draft_etag);
    assert_eq!(json_body(read).await["policy"], draft["policy"]);

    // Audit: the draft write and the suggestion it came from, by
    // identifiers and ETags only.
    assert_eventually(Duration::from_secs(1), || {
        !events_of(&capture, audit::event::POLICY_SUGGESTION_DRAFTED).is_empty()
    });
    let changes = events_of(&capture, audit::event::POLICY_DRAFT_CHANGED);
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["action"], "created");
    assert_eq!(changes[0]["draft_id"], json!(draft_id));
    let drafted = events_of(&capture, audit::event::POLICY_SUGGESTION_DRAFTED);
    assert_eq!(
        drafted,
        vec![json!({
            "suggestion_id": "sug-review",
            "suggestion_revision": 1,
            "suggestion_type": "baseline_allow",
            "draft_id": draft_id,
            "draft_revision": 1,
            "draft_created": true,
            "base_etag": live_etag,
            "candidate_etag": draft["candidate_etag"],
            "rule_id": rule["id"],
            "position": 0,
        })]
    );
    assert!(events_of(&capture, audit::event::POLICY_CHANGED).is_empty());
    assert!(events_of(&capture, audit::event::SUGGESTION_LIFECYCLE_CHANGED).is_empty());

    // The rule goes live only through the draft's own publication, which
    // leaves the suggestion where it was.
    let published = send(
        &router,
        admin_request(
            Method::POST,
            &format!("{}/publish", draft_uri(&draft_id)),
            reviewer(),
            None,
            &[
                (POLICY_DRAFT_ETAG_HEADER, &draft_etag),
                ("if-match", &live_etag),
            ],
        ),
    )
    .await;
    assert_eq!(published.status(), StatusCode::OK);
    let (published_etag, published_policy) = live_policy(&router).await;
    assert_eq!(json!(published_etag), draft["candidate_etag"]);
    assert_eq!(published_policy["rules"], json!([rule]));
    assert_eq!(open_suggestion(&router, "sug-review").await["revision"], 1);

    // Its rule is now live, so opening it again would only add it twice.
    let (status, body) =
        refusal(draft_suggestion(&router, "sug-review", &published_etag, None).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_rule_already_present");
    assert_eq!(owned_drafts(&router).await.len(), 1);
}

#[tokio::test]
async fn opening_a_suggestion_in_a_draft_is_refused_without_its_permissions_or_preconditions() {
    let discovery_db = TempDb::new("suggestion-draft-refusals");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-open",
        "/open/{id}",
        "allow",
        None,
        "open",
    );
    seed_suggestion(
        &discovery_db.path,
        "sug-dismissed",
        "/dismissed/{id}",
        "allow",
        None,
        "dismissed",
    );
    seed_suggestion(
        &discovery_db.path,
        "sug-unclassified",
        "/unclassified/{id}",
        "allow",
        None,
        "open",
    );
    clear_discovery_routing_classification(&discovery_db.path, "GET", "/unclassified/{id}");
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, capture) = captured_router(&discovery_db.path, &policy);
    let (live_etag, _) = live_policy(&router).await;
    let uri = suggestion_draft_uri("sug-open");

    let unauthenticated = send(
        &router,
        admin_request(Method::POST, &uri, None, None, &[("if-match", &live_etag)]),
    )
    .await;
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    // Reading suggestions is not writing policy, and writing policy is not
    // reading suggestions: both are needed.
    for role in ["suggestions-writer", "policy-writer"] {
        let forbidden = send(
            &router,
            admin_request(
                Method::POST,
                &uri,
                Some(test_principal(&[role])),
                None,
                &[("if-match", &live_etag)],
            ),
        )
        .await;
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN, "{role}");
    }

    let missing_if_match = send(
        &router,
        admin_request(Method::POST, &uri, reviewer(), None, &[]),
    )
    .await;
    assert_eq!(missing_if_match.status(), StatusCode::PRECONDITION_REQUIRED);
    let weak = send(
        &router,
        admin_request(
            Method::POST,
            &uri,
            reviewer(),
            None,
            &[("if-match", &format!("W/{live_etag}"))],
        ),
    )
    .await;
    assert_eq!(weak.status(), StatusCode::BAD_REQUEST);
    let (status, body) =
        refusal(draft_suggestion(&router, "sug-open", "\"sha256:stale\"", None).await).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["reason"], "policy_etag_mismatch");

    let (status, body) = refusal(
        send(
            &router,
            admin_request(
                Method::POST,
                &uri,
                reviewer(),
                None,
                &[("if-match", &live_etag), (SUGGESTION_REVISION_HEADER, "7")],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_revision_mismatch");
    assert_eq!(body["suggestion"]["revision"], 1);
    let (status, body) =
        refusal(draft_suggestion(&router, "sug-dismissed", &live_etag, None).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_not_open");
    let unknown = draft_suggestion(&router, "sug-missing", &live_etag, None).await;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    let (status, body) =
        refusal(draft_suggestion(&router, "sug-unclassified", &live_etag, None).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body["error"],
        "suggestion predates trusted routing context and cannot be accepted; dismiss it and review newly classified traffic"
    );

    // No option this route does not have, and no draft ETag without the
    // draft it would describe.
    let unknown_field = send(
        &router,
        admin_request(
            Method::POST,
            &uri,
            reviewer(),
            Some(json!({ "force": true })),
            &[("if-match", &live_etag)],
        ),
    )
    .await;
    assert_eq!(unknown_field.status(), StatusCode::BAD_REQUEST);
    let stray_draft_etag = send(
        &router,
        admin_request(
            Method::POST,
            &uri,
            reviewer(),
            None,
            &[
                ("if-match", &live_etag),
                (POLICY_DRAFT_ETAG_HEADER, "\"sha256:draft\""),
            ],
        ),
    )
    .await;
    assert_eq!(stray_draft_etag.status(), StatusCode::BAD_REQUEST);
    let (status, body) = refusal(
        send(
            &router,
            admin_request(
                Method::POST,
                &uri,
                reviewer(),
                Some(json!({ "draft_id": "pd_00000000000000000000000000000000" })),
                &[("if-match", &live_etag)],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(body["reason"], "policy_draft_etag_required");

    // Every refusal wrote nothing: no draft, no suggestion transition, no
    // event.
    assert!(owned_drafts(&router).await.is_empty());
    assert_eq!(open_suggestion(&router, "sug-open").await["revision"], 1);
    assert!(events_of(&capture, audit::event::POLICY_DRAFT_CHANGED).is_empty());
    assert!(events_of(&capture, audit::event::POLICY_SUGGESTION_DRAFTED).is_empty());
}

#[tokio::test]
async fn suggestions_add_their_rules_to_an_open_draft_under_its_etag_without_rebasing_it() {
    let discovery_db = TempDb::new("suggestion-draft-existing");
    create_rule_suggestion_schema(&discovery_db.path);
    for (id, path) in [
        ("sug-first", "/first/{id}"),
        ("sug-second", "/second/{id}"),
        ("sug-third", "/third/{id}"),
    ] {
        seed_suggestion(&discovery_db.path, id, path, "allow", None, "open");
    }
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, capture) = captured_router(&discovery_db.path, &policy);
    let (live_etag, _) = live_policy(&router).await;

    let created = send(
        &router,
        admin_request(
            Method::POST,
            POLICY_DRAFTS_ADMIN_ROUTE,
            reviewer(),
            Some(json!({})),
            &[("if-match", &live_etag)],
        ),
    )
    .await;
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_etag = policy_etag_header(&created);
    let draft_id = json_body(created).await["draft_id"]
        .as_str()
        .expect("a created draft names its id")
        .to_owned();

    let first = draft_suggestion(
        &router,
        "sug-first",
        &live_etag,
        Some((&draft_id, &created_etag)),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_etag = policy_etag_header(&first);
    assert_ne!(first_etag, created_etag);
    let first = json_body(first).await;
    assert_eq!(first["draft"]["draft_id"], json!(draft_id));
    assert_eq!(first["draft"]["revision"], 2);
    assert_eq!(first["draft"]["base_etag"], json!(live_etag));
    assert_eq!(first["position"], 0);

    // The draft moved on, so its old ETag no longer names it.
    let (status, body) = refusal(
        draft_suggestion(
            &router,
            "sug-second",
            &live_etag,
            Some((&draft_id, &created_etag)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["reason"], "policy_draft_etag_mismatch");

    let second = draft_suggestion(
        &router,
        "sug-second",
        &live_etag,
        Some((&draft_id, &first_etag)),
    )
    .await;
    assert_eq!(second.status(), StatusCode::OK);
    let second_etag = policy_etag_header(&second);
    let second = json_body(second).await;
    assert_eq!(second["draft"]["revision"], 3);
    assert_eq!(second["position"], 1);
    let rules = second["draft"]["policy"]["rules"]
        .as_array()
        .expect("the candidate has rules");
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0], first["rule"]);
    assert_eq!(rules[1], second["rule"]);

    // The same suggestion twice would only repeat its rule.
    let (status, body) = refusal(
        draft_suggestion(
            &router,
            "sug-first",
            &live_etag,
            Some((&draft_id, &second_etag)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "suggestion_rule_already_present");

    // Another principal's draft is not there at all.
    let mut other = test_principal(&["suggestions-policy-writer"]);
    other.user_id = "user-456".to_owned();
    let (status, body) = refusal(
        send(
            &router,
            admin_request(
                Method::POST,
                &suggestion_draft_uri("sug-third"),
                Some(other),
                Some(json!({ "draft_id": draft_id })),
                &[
                    ("if-match", &live_etag),
                    (POLICY_DRAFT_ETAG_HEADER, &second_etag),
                ],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["reason"], "policy_draft_not_found");

    // Once the live policy moves, the draft is stale and is not rebased to
    // take another rule.
    let rule_created = send(
        &router,
        admin_request(
            Method::POST,
            POLICY_RULES_ADMIN_ROUTE,
            reviewer(),
            Some(json!({ "methods": ["GET"], "path": "/unrelated", "action": "deny" })),
            &[("if-match", &live_etag)],
        ),
    )
    .await;
    assert_eq!(rule_created.status(), StatusCode::CREATED);
    let moved_etag = policy_etag_header(&rule_created);
    let (status, body) = refusal(
        draft_suggestion(
            &router,
            "sug-third",
            &moved_etag,
            Some((&draft_id, &second_etag)),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "policy_draft_base_stale");
    assert_eq!(body["base_etag"], json!(live_etag));
    assert_eq!(body["policy_etag"], json!(moved_etag));

    let read = send(
        &router,
        admin_request(Method::GET, &draft_uri(&draft_id), reviewer(), None, &[]),
    )
    .await;
    assert_eq!(policy_etag_header(&read), second_etag);
    assert_eq!(json_body(read).await["revision"], 3);

    assert_eventually(Duration::from_secs(1), || {
        events_of(&capture, audit::event::POLICY_SUGGESTION_DRAFTED).len() == 2
    });
    let drafted = events_of(&capture, audit::event::POLICY_SUGGESTION_DRAFTED);
    assert_eq!(drafted[0]["suggestion_id"], "sug-first");
    assert_eq!(drafted[0]["draft_revision"], 2);
    assert_eq!(drafted[0]["draft_created"], false);
    assert_eq!(drafted[1]["suggestion_id"], "sug-second");
    assert_eq!(drafted[1]["position"], 1);
    let updates = events_of(&capture, audit::event::POLICY_DRAFT_CHANGED)
        .into_iter()
        .filter(|event| event["action"] == "updated")
        .count();
    assert_eq!(updates, 2);
}

#[tokio::test]
async fn a_signal_derived_deny_suggestion_is_drafted_as_shadow() {
    let discovery_db = TempDb::new("suggestion-draft-signal");
    create_rule_suggestion_schema(&discovery_db.path);
    seed_suggestion(
        &discovery_db.path,
        "sug-signal",
        "/signal/{id}",
        "deny",
        Some("sig-new-endpoint"),
        "open",
    );
    let policy = TempPolicyFile::new(&suggestions_policy_document_string());
    let (router, _capture) = captured_router(&discovery_db.path, &policy);
    let (live_etag, live) = live_policy(&router).await;

    let opened = draft_suggestion(&router, "sug-signal", &live_etag, None).await;
    assert_eq!(opened.status(), StatusCode::CREATED);
    let opened = json_body(opened).await;
    assert_eq!(opened["rule"]["action"], "shadow");
    assert_eq!(opened["draft"]["policy"]["rules"][0]["action"], "shadow");
    // The suggestion itself is shown as it was read.
    assert_eq!(opened["suggestion"]["proposed_rule"]["action"], "deny");
    assert_eq!(live_policy(&router).await, (live_etag, live));
}
