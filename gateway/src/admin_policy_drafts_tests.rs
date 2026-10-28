//! Server-side policy drafts (issue #243, slice 9) through the admin API, in
//! standalone mode: the SQLite store beside the policy history database and
//! the file authority. The store contract itself, for both backends, is in
//! `storage::contract_tests`; cluster-mode publication is in
//! `cluster_policy_tests`.
use super::*;

fn draft_uri(draft_id: &str) -> String {
    format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}")
}

fn draft_publish_uri(draft_id: &str) -> String {
    format!("{POLICY_DRAFTS_ADMIN_ROUTE}/{draft_id}/publish")
}

fn draft_request(
    method: Method,
    uri: &str,
    principal: Option<auth::Principal>,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> Request<Body> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    // Request validation wants an allowed media type on every POST, PUT
    // and PATCH, a body-less publication included.
    if matches!(method, Method::POST | Method::PUT | Method::PATCH) {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if matches!(
        method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    ) {
        builder = builder.header(header::AUTHORIZATION, "Bearer test-token");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
    let mut request = builder.body(body).expect("draft request should build");
    if let Some(principal) = principal {
        request.extensions_mut().insert(principal);
    }
    request
}

fn admin() -> Option<auth::Principal> {
    Some(test_principal(&["admin"]))
}

fn other_admin(user_id: &str, issuer: Option<&str>) -> Option<auth::Principal> {
    let mut principal = test_principal(&["admin"]);
    principal.user_id = user_id.to_owned();
    principal.issuer = issuer.map(str::to_owned);
    Some(principal)
}

async fn send(router: &Router, request: Request<Body>) -> Response {
    router
        .clone()
        .oneshot(request)
        .await
        .expect("draft request should complete")
}

async fn refusal(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    (status, json_body(response).await)
}

/// Create a draft of `candidate` (or a copy of the live policy) on `base`.
async fn create_draft(
    router: &Router,
    base: &str,
    candidate: Option<Value>,
) -> (String, String, Value) {
    let body = match candidate {
        Some(policy) => json!({ "policy": policy }),
        None => json!({}),
    };
    let response = send(
        router,
        draft_request(
            Method::POST,
            POLICY_DRAFTS_ADMIN_ROUTE,
            admin(),
            Some(body),
            &[("if-match", base)],
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let etag = policy_etag_header(&response);
    let body = json_body(response).await;
    let draft_id = body["draft_id"]
        .as_str()
        .expect("a created draft names its id")
        .to_owned();
    (draft_id, etag, body)
}

async fn publish(router: &Router, draft_id: &str, draft_etag: &str, policy_etag: &str) -> Response {
    send(
        router,
        draft_request(
            Method::POST,
            &draft_publish_uri(draft_id),
            admin(),
            None,
            &[
                (POLICY_DRAFT_ETAG_HEADER, draft_etag),
                ("if-match", policy_etag),
            ],
        ),
    )
    .await
}

fn captured_router(policy: &TempPolicyFile) -> (Router, audit::sink::tests::CaptureSink) {
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let mut config = policy_admin_config_with_sqlite(Some(policy), None);
    // These tests send more writes than the global write lane's default
    // burst admits, faster than it refills; that lane is not what they test.
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

#[tokio::test]
async fn a_policy_draft_is_inactive_until_published_under_both_preconditions() {
    let policy = TempPolicyFile::new(&policy_document_string("live-policy", "test:old"));
    let (router, capture) = captured_router(&policy);
    let (live_etag, live) = current_policy(&router).await;
    let disk_before = fs::read_to_string(&policy.path).expect("policy file should read");

    let candidate = policy_document("draft-candidate", "test:new");
    let (draft_id, created_etag, created) =
        create_draft(&router, &live_etag, Some(candidate.clone())).await;
    assert!(
        draft_id.starts_with("pd_") && draft_id.len() == 35,
        "{draft_id}"
    );
    assert_eq!(created["revision"], 1);
    assert_eq!(created["state"], "open");
    assert_eq!(created["base_etag"], json!(live_etag));
    assert_eq!(created["published_etag"], Value::Null);
    assert_eq!(created["policy"]["id"], "draft-candidate");
    let expires = OffsetDateTime::parse(created["expires_at"].as_str().unwrap(), &Rfc3339)
        .expect("expires_at is RFC 3339");
    let updated = OffsetDateTime::parse(created["updated_at"].as_str().unwrap(), &Rfc3339)
        .expect("updated_at is RFC 3339");
    assert_eq!(
        (expires - updated).whole_seconds(),
        storage::policy_drafts::POLICY_DRAFT_TTL_SECS
    );

    // Saving a draft changes nothing live.
    assert_eq!(current_policy(&router).await, (live_etag.clone(), live));
    assert_eq!(
        fs::read_to_string(&policy.path).expect("policy file should read"),
        disk_before
    );
    assert!(events_of(&capture, audit::event::POLICY_CHANGED).is_empty());

    // Read back: the same strong ETag, never cached.
    let read = send(
        &router,
        draft_request(Method::GET, &draft_uri(&draft_id), admin(), None, &[]),
    )
    .await;
    assert_eq!(read.status(), StatusCode::OK);
    assert_eq!(policy_etag_header(&read), created_etag);
    assert_eq!(
        read.headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("private, no-store")
    );
    let listed = json_body(
        send(
            &router,
            draft_request(Method::GET, POLICY_DRAFTS_ADMIN_ROUTE, admin(), None, &[]),
        )
        .await,
    )
    .await;
    assert_eq!(listed["drafts"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["drafts"][0]["draft_id"], json!(draft_id));
    assert!(
        listed["drafts"][0].get("policy").is_none(),
        "a listing carries no candidates"
    );
    assert_eq!(
        listed["limits"],
        json!({
            "ttl_seconds": storage::policy_drafts::POLICY_DRAFT_TTL_SECS,
            "max_drafts_per_owner": storage::policy_drafts::MAX_POLICY_DRAFTS_PER_OWNER,
            "max_drafts": storage::policy_drafts::MAX_POLICY_DRAFTS,
            "max_candidate_bytes": storage::policy_drafts::MAX_POLICY_DRAFT_CANDIDATE_BYTES,
        })
    );

    // Edit under the draft's strong ETag; the old one is then stale.
    let edited = policy_document("draft-edited", "test:new");
    let patched = send(
        &router,
        draft_request(
            Method::PATCH,
            &draft_uri(&draft_id),
            admin(),
            Some(json!({ "policy": edited })),
            &[("if-match", &created_etag)],
        ),
    )
    .await;
    assert_eq!(patched.status(), StatusCode::OK);
    let edited_etag = policy_etag_header(&patched);
    assert_ne!(edited_etag, created_etag);
    let patched = json_body(patched).await;
    assert_eq!(patched["revision"], 2);
    assert_eq!(patched["policy"]["id"], "draft-edited");
    let (status, body) = refusal(
        send(
            &router,
            draft_request(
                Method::PATCH,
                &draft_uri(&draft_id),
                admin(),
                Some(json!({ "policy": candidate })),
                &[("if-match", &created_etag)],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["reason"], "policy_draft_etag_mismatch");

    // Publication needs the current draft ETag as well as the live one.
    let (status, body) =
        refusal(publish(&router, &draft_id, &created_etag, &live_etag).await).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["reason"], "policy_draft_etag_mismatch");
    assert_eq!(current_policy(&router).await.0, live_etag);

    let published = publish(&router, &draft_id, &edited_etag, &live_etag).await;
    assert_eq!(published.status(), StatusCode::OK);
    assert!(published
        .headers()
        .get(POLICY_DRAFT_WARNING_HEADER)
        .is_none());
    let new_etag = policy_etag_header(&published);
    assert_ne!(new_etag, live_etag);
    assert_eq!(
        json!(new_etag),
        patched["candidate_etag"],
        "the committed policy is exactly the candidate the draft recorded"
    );
    assert_eq!(json_body(published).await["id"], "draft-edited");
    let (now_etag, now_live) = current_policy(&router).await;
    assert_eq!(now_etag, new_etag);
    assert_eq!(now_live["id"], "draft-edited");

    // The draft is frozen as published and cannot publish or change again.
    let frozen = send(
        &router,
        draft_request(Method::GET, &draft_uri(&draft_id), admin(), None, &[]),
    )
    .await;
    let frozen_etag = policy_etag_header(&frozen);
    let frozen = json_body(frozen).await;
    assert_eq!(frozen["state"], "published");
    assert_eq!(frozen["revision"], 3);
    assert_eq!(frozen["published_etag"], json!(new_etag));
    let (status, body) = refusal(publish(&router, &draft_id, &frozen_etag, &new_etag).await).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "policy_draft_published");
    assert_eq!(body["published_etag"], json!(new_etag));
    let (status, body) = refusal(
        send(
            &router,
            draft_request(
                Method::PATCH,
                &draft_uri(&draft_id),
                admin(),
                Some(json!({ "policy": candidate })),
                &[("if-match", &frozen_etag)],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["reason"], "policy_draft_published");

    // Audit: workspace changes, one publication, one policy change, and the
    // refusals -- identifiers and ETags only, never the candidate.
    // The publish-after-publish refusal is the last event this test causes;
    // the audit writer delivers in order, so once it lands every earlier one
    // has too.
    assert_eventually(Duration::from_secs(1), || {
        events_of(&capture, audit::event::POLICY_DRAFT_PUBLISH_REFUSED).len() == 2
    });
    let changes = events_of(&capture, audit::event::POLICY_DRAFT_CHANGED);
    assert_eq!(
        changes
            .iter()
            .map(|payload| payload["action"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        ["created", "updated"]
    );
    let publications = events_of(&capture, audit::event::POLICY_DRAFT_PUBLISHED);
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0]["draft_id"], json!(draft_id));
    assert_eq!(publications[0]["policy_etag"], json!(new_etag));
    assert_eq!(publications[0]["draft_state_recorded"], true);
    let policy_changes = events_of(&capture, audit::event::POLICY_CHANGED);
    assert_eq!(policy_changes.len(), 1);
    assert_eq!(
        policy_changes[0]["diff_summary"]["action"],
        "policy_draft_published"
    );
    assert_eq!(
        policy_changes[0]["diff_summary"]["draft_id"],
        json!(draft_id)
    );
    let refusals = events_of(&capture, audit::event::POLICY_DRAFT_PUBLISH_REFUSED);
    assert_eq!(
        refusals
            .iter()
            .map(|payload| payload["reason"].as_str().unwrap_or_default())
            .collect::<Vec<_>>(),
        ["policy_draft_etag_mismatch", "policy_draft_published"]
    );
    for payload in changes.iter().chain(&publications).chain(&refusals) {
        assert!(payload.get("policy").is_none(), "{payload}");
        assert!(!payload.to_string().contains("draft-edited"), "{payload}");
    }

    // History records the publication like any other policy write.
    let history = policy_history_entries(&router, Some(1)).await;
    assert_eq!(
        history[0]["diff_summary"]["action"],
        "policy_draft_published"
    );
    assert_eq!(history[0]["diff_summary"]["draft_revision"], 2);
}

#[tokio::test]
async fn a_draft_without_a_candidate_starts_as_a_copy_of_its_base() {
    let policy = TempPolicyFile::new(&policy_document_string("copied-policy", "test:old"));
    let (router, _capture) = captured_router(&policy);
    let (live_etag, live) = current_policy(&router).await;

    let (_, _, created) = create_draft(&router, &live_etag, None).await;
    assert_eq!(created["policy"], live);
    assert_eq!(
        created["candidate_etag"],
        json!(live_etag),
        "an unedited copy carries the live policy's own ETag"
    );
}

#[tokio::test]
async fn publishing_a_draft_whose_base_moved_is_refused_until_it_is_rebased() {
    let policy = TempPolicyFile::new(&policy_document_string("base-policy", "test:old"));
    let (router, capture) = captured_router(&policy);
    let (base_etag, _) = current_policy(&router).await;
    let (draft_id, draft_etag, _) = create_draft(
        &router,
        &base_etag,
        Some(policy_document("draft-over-base", "test:new")),
    )
    .await;

    // Someone else changes the live policy.
    let moved = send(
        &router,
        policy_admin_request(
            Method::PUT,
            POLICY_ADMIN_ROUTE,
            admin(),
            Some(policy_document_string("moved-policy", "test:old")),
            Some(&base_etag),
        ),
    )
    .await;
    assert_eq!(moved.status(), StatusCode::OK);
    let moved_etag = policy_etag_header(&moved);

    // Stale base is the binding's conflict whichever live ETag is presented;
    // nothing changes and the draft is kept.
    for presented in [&base_etag, &moved_etag] {
        let (status, body) =
            refusal(publish(&router, &draft_id, &draft_etag, presented).await).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "policy_draft_base_stale");
        assert_eq!(body["base_etag"], json!(base_etag));
        assert_eq!(body["policy_etag"], json!(moved_etag));
    }
    let (live_etag, live) = current_policy(&router).await;
    assert_eq!(live_etag, moved_etag);
    assert_eq!(live["id"], "moved-policy");
    let kept = json_body(
        send(
            &router,
            draft_request(Method::GET, &draft_uri(&draft_id), admin(), None, &[]),
        )
        .await,
    )
    .await;
    assert_eq!(kept["revision"], 1);
    assert_eq!(kept["base_etag"], json!(base_etag));
    assert_eventually(Duration::from_secs(1), || {
        events_of(&capture, audit::event::POLICY_DRAFT_PUBLISH_REFUSED).len() == 2
    });
    let refusals = events_of(&capture, audit::event::POLICY_DRAFT_PUBLISH_REFUSED);
    assert!(refusals.iter().all(|payload| {
        payload["reason"] == "policy_draft_base_stale"
            && payload["current_policy_etag"] == json!(moved_etag)
    }));

    // A rebase must name the current live ETag; only then does it move.
    let (status, body) = refusal(
        send(
            &router,
            draft_request(
                Method::PATCH,
                &draft_uri(&draft_id),
                admin(),
                Some(json!({ "base_etag": base_etag })),
                &[("if-match", &draft_etag)],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["reason"], "policy_etag_mismatch");
    let rebased = send(
        &router,
        draft_request(
            Method::PATCH,
            &draft_uri(&draft_id),
            admin(),
            Some(json!({ "base_etag": moved_etag })),
            &[("if-match", &draft_etag)],
        ),
    )
    .await;
    assert_eq!(rebased.status(), StatusCode::OK);
    let rebased_etag = policy_etag_header(&rebased);
    let rebased = json_body(rebased).await;
    assert_eq!(rebased["base_etag"], json!(moved_etag));
    assert_eq!(rebased["policy"]["id"], "draft-over-base");
    assert_eventually(Duration::from_secs(1), || {
        events_of(&capture, audit::event::POLICY_DRAFT_CHANGED)
            .iter()
            .any(|payload| payload["rebased"] == true)
    });

    // A live If-Match that is not current is still refused.
    let (status, body) =
        refusal(publish(&router, &draft_id, &rebased_etag, &base_etag).await).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["reason"], "policy_etag_mismatch");
    let published = publish(&router, &draft_id, &rebased_etag, &moved_etag).await;
    assert_eq!(published.status(), StatusCode::OK);
    assert_eq!(current_policy(&router).await.1["id"], "draft-over-base");
}

#[tokio::test]
async fn publishing_a_draft_runs_the_cross_resource_checks_of_every_policy_write() {
    let policy = TempPolicyFile::new(&policy_document_string("base-policy", "test:old"));
    let (router, capture) = captured_router(&policy);
    let (base_etag, _) = current_policy(&router).await;

    // Saving a candidate that leaves nobody able to write the policy is
    // allowed: a draft is a workspace, and only publication is blocked.
    let mut locked_out = policy_document("locked-out", "test:new");
    locked_out["roles"]["admin"]["permissions"] = json!([ADMIN_POLICY_READ_PERMISSION]);
    let (locked_id, locked_etag, _) = create_draft(&router, &base_etag, Some(locked_out)).await;

    let (status, body) =
        refusal(publish(&router, &locked_id, &locked_etag, &base_etag).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["valid"], json!(false));
    let codes: Vec<&str> = body["diagnostics"]
        .as_array()
        .expect("a refusal carries its diagnostics")
        .iter()
        .filter(|diagnostic| diagnostic["blocks"]["publication"] == json!(true))
        .filter_map(|diagnostic| diagnostic["code"].as_str())
        .collect();
    assert_eq!(
        codes,
        ["policy_write_unreachable", "publisher_policy_write_lost"],
        "{body}"
    );
    let reviewed = body["resource_snapshot"]["digest"]
        .as_str()
        .expect("a refusal names the snapshot it read")
        .to_owned();
    assert_eq!(body["resource_snapshot"]["complete"], json!(true));

    // Nothing was written and the draft is kept, still open on its base.
    let (live_etag, live) = current_policy(&router).await;
    assert_eq!(live_etag, base_etag);
    assert_eq!(live["id"], "base-policy");
    let kept = json_body(
        send(
            &router,
            draft_request(Method::GET, &draft_uri(&locked_id), admin(), None, &[]),
        )
        .await,
    )
    .await;
    assert_eq!(kept["revision"], 1);
    assert_eq!(kept["state"], "open");
    assert_eq!(kept["published_etag"], Value::Null);
    assert_eventually(Duration::from_secs(1), || {
        !events_of(&capture, audit::event::POLICY_PUBLICATION_REFUSED).is_empty()
    });
    assert_eq!(
        events_of(&capture, audit::event::POLICY_PUBLICATION_REFUSED),
        [json!({
            "action": "policy_draft_published",
            "codes": ["policy_write_unreachable", "publisher_policy_write_lost"],
            "policy_etag": base_etag,
            "resource_snapshot_digest": reviewed,
        })]
    );
    assert!(events_of(&capture, audit::event::POLICY_DRAFT_PUBLISHED).is_empty());
    assert!(events_of(&capture, audit::event::POLICY_CHANGED).is_empty());

    // A sound draft published against a resource snapshot that is not the
    // current one is refused as stale, and kept.
    let (sound_id, sound_etag, _) = create_draft(
        &router,
        &base_etag,
        Some(policy_document("sound-draft", "test:new")),
    )
    .await;
    let bound_publish = |snapshot: &str| {
        draft_request(
            Method::POST,
            &draft_publish_uri(&sound_id),
            admin(),
            None,
            &[
                (POLICY_DRAFT_ETAG_HEADER, sound_etag.as_str()),
                ("if-match", base_etag.as_str()),
                ("x-greengateway-resource-snapshot", snapshot),
            ],
        )
    };
    let stale = format!("sha256:{}", "0".repeat(64));
    let (status, body) = refusal(send(&router, bound_publish(&stale)).await).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "resource_snapshot_stale");
    assert_eq!(body["resource_snapshot"]["digest"], json!(reviewed));
    assert_eq!(current_policy(&router).await.0, base_etag);

    // Bound to the snapshot that is current, it publishes, and the commit's
    // policy.changed names that snapshot.
    let published = send(&router, bound_publish(&reviewed)).await;
    assert_eq!(published.status(), StatusCode::OK);
    assert_eq!(current_policy(&router).await.1["id"], "sound-draft");
    assert_eventually(Duration::from_secs(1), || {
        events_of(&capture, audit::event::POLICY_CHANGED)
            .iter()
            .any(|payload| payload["resource_snapshot_digest"] == json!(reviewed))
    });
}

#[tokio::test]
async fn policy_drafts_belong_to_their_owner_alone() {
    let policy = TempPolicyFile::new(&policy_document_string("owned-policy", "test:old"));
    let (router, _capture) = captured_router(&policy);
    let (live_etag, _) = current_policy(&router).await;
    let (draft_id, draft_etag, _) = create_draft(&router, &live_etag, None).await;

    // Another subject, and the same subject from another issuer, are
    // strangers: every route answers as if the draft did not exist.
    for stranger in [
        other_admin("someone-else", None),
        other_admin("user-123", Some("https://other-issuer.example")),
    ] {
        let listed = json_body(
            send(
                &router,
                draft_request(
                    Method::GET,
                    POLICY_DRAFTS_ADMIN_ROUTE,
                    stranger.clone(),
                    None,
                    &[],
                ),
            )
            .await,
        )
        .await;
        assert_eq!(listed["drafts"], json!([]));
        for request in [
            draft_request(
                Method::GET,
                &draft_uri(&draft_id),
                stranger.clone(),
                None,
                &[],
            ),
            draft_request(
                Method::PATCH,
                &draft_uri(&draft_id),
                stranger.clone(),
                Some(json!({ "base_etag": live_etag })),
                &[("if-match", &draft_etag)],
            ),
            draft_request(
                Method::DELETE,
                &draft_uri(&draft_id),
                stranger.clone(),
                None,
                &[("if-match", &draft_etag)],
            ),
            draft_request(
                Method::POST,
                &draft_publish_uri(&draft_id),
                stranger.clone(),
                None,
                &[
                    (POLICY_DRAFT_ETAG_HEADER, &draft_etag),
                    ("if-match", &live_etag),
                ],
            ),
        ] {
            let (status, body) = refusal(send(&router, request).await).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
            assert_eq!(body["reason"], "policy_draft_not_found");
        }
    }
    // The owner still has it, untouched.
    let kept = send(
        &router,
        draft_request(Method::GET, &draft_uri(&draft_id), admin(), None, &[]),
    )
    .await;
    assert_eq!(kept.status(), StatusCode::OK);
    assert_eq!(policy_etag_header(&kept), draft_etag);
    assert_eq!(current_policy(&router).await.0, live_etag);
}

#[tokio::test]
async fn policy_draft_routes_authorize_before_any_work_and_require_preconditions() {
    let policy = TempPolicyFile::new(&policy_document_string("authz-policy", "test:old"));
    let (router, _capture) = captured_router(&policy);
    let (live_etag, _) = current_policy(&router).await;
    let (draft_id, draft_etag, _) = create_draft(&router, &live_etag, None).await;
    let routes = |principal: Option<auth::Principal>| {
        [
            draft_request(
                Method::GET,
                POLICY_DRAFTS_ADMIN_ROUTE,
                principal.clone(),
                None,
                &[],
            ),
            draft_request(
                Method::POST,
                POLICY_DRAFTS_ADMIN_ROUTE,
                principal.clone(),
                Some(json!({})),
                &[("if-match", &live_etag)],
            ),
            draft_request(
                Method::GET,
                &draft_uri(&draft_id),
                principal.clone(),
                None,
                &[],
            ),
            draft_request(
                Method::PATCH,
                &draft_uri(&draft_id),
                principal.clone(),
                Some(json!({ "base_etag": live_etag })),
                &[("if-match", &draft_etag)],
            ),
            draft_request(
                Method::DELETE,
                &draft_uri(&draft_id),
                principal.clone(),
                None,
                &[("if-match", &draft_etag)],
            ),
            draft_request(
                Method::POST,
                &draft_publish_uri(&draft_id),
                principal.clone(),
                None,
                &[
                    (POLICY_DRAFT_ETAG_HEADER, &draft_etag),
                    ("if-match", &live_etag),
                ],
            ),
        ]
    };
    for request in routes(None) {
        assert_eq!(
            send(&router, request).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    for request in routes(Some(test_principal(&["reader"]))) {
        assert_eq!(send(&router, request).await.status(), StatusCode::FORBIDDEN);
    }
    // A policy reader may read its drafts but change nothing.
    let reader = Some(test_principal(&["policy-reader"]));
    let statuses = {
        let mut statuses = Vec::new();
        for request in routes(reader) {
            statuses.push(send(&router, request).await.status());
        }
        statuses
    };
    assert_eq!(
        statuses,
        [
            StatusCode::OK,
            StatusCode::FORBIDDEN,
            StatusCode::OK,
            StatusCode::FORBIDDEN,
            StatusCode::FORBIDDEN,
            StatusCode::FORBIDDEN,
        ]
    );

    // Preconditions are required and must be exactly one strong tag.
    let create = |headers: &[(&str, &str)]| {
        draft_request(
            Method::POST,
            POLICY_DRAFTS_ADMIN_ROUTE,
            admin(),
            Some(json!({})),
            headers,
        )
    };
    assert_eq!(
        send(&router, create(&[])).await.status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let list = format!("{live_etag}, \"sha256:other\"");
    assert_eq!(
        send(&router, create(&[("if-match", &list)])).await.status(),
        StatusCode::BAD_REQUEST
    );
    let weak = format!("W/{live_etag}");
    assert_eq!(
        send(&router, create(&[("if-match", &weak)])).await.status(),
        StatusCode::BAD_REQUEST
    );
    let (status, body) =
        refusal(send(&router, create(&[("if-match", "\"sha256:stale\"")])).await).await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["reason"], "policy_etag_mismatch");

    let patch = |body: Value, headers: &[(&str, &str)]| {
        draft_request(
            Method::PATCH,
            &draft_uri(&draft_id),
            admin(),
            Some(body),
            headers,
        )
    };
    let (status, body) =
        refusal(send(&router, patch(json!({ "base_etag": live_etag }), &[])).await).await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(body["reason"], "policy_draft_etag_required");
    let (status, body) =
        refusal(send(&router, patch(json!({}), &[("if-match", &draft_etag)])).await).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["reason"], "policy_draft_patch_empty");
    assert_eq!(
        send(
            &router,
            patch(json!({ "force": true }), &[("if-match", &draft_etag)])
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST,
        "unknown fields are rejected: there is no force flag"
    );
    let (status, body) = refusal(
        send(
            &router,
            draft_request(Method::DELETE, &draft_uri(&draft_id), admin(), None, &[]),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(body["reason"], "policy_draft_etag_required");

    let publish_with = |headers: &[(&str, &str)]| {
        draft_request(
            Method::POST,
            &draft_publish_uri(&draft_id),
            admin(),
            None,
            headers,
        )
    };
    let (status, body) =
        refusal(send(&router, publish_with(&[("if-match", &live_etag)])).await).await;
    assert_eq!(status, StatusCode::PRECONDITION_REQUIRED);
    assert_eq!(body["reason"], "policy_draft_etag_required");
    assert_eq!(
        send(
            &router,
            publish_with(&[(POLICY_DRAFT_ETAG_HEADER, &draft_etag)])
        )
        .await
        .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    // Publication has no options: a body is refused, not ignored.
    let with_body = draft_request(
        Method::POST,
        &draft_publish_uri(&draft_id),
        admin(),
        Some(json!({ "force": true })),
        &[
            (POLICY_DRAFT_ETAG_HEADER, &draft_etag),
            ("if-match", &live_etag),
        ],
    );
    assert_eq!(
        send(&router, with_body).await.status(),
        StatusCode::BAD_REQUEST
    );

    // An identifier of the wrong shape names no draft.
    for malformed in [
        "not-a-draft",
        "pd_ABC",
        "pd_00000000000000000000000000000000x",
    ] {
        let (status, body) = refusal(
            send(
                &router,
                draft_request(Method::GET, &draft_uri(malformed), admin(), None, &[]),
            )
            .await,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["reason"], "policy_draft_not_found");
    }

    // None of it touched the live policy or the draft.
    assert_eq!(current_policy(&router).await.0, live_etag);
    let kept = send(
        &router,
        draft_request(Method::GET, &draft_uri(&draft_id), admin(), None, &[]),
    )
    .await;
    assert_eq!(policy_etag_header(&kept), draft_etag);
}

#[tokio::test]
async fn a_draft_candidate_is_validated_like_a_policy_write() {
    let policy = TempPolicyFile::new(&policy_document_string("validated-policy", "test:old"));
    let (router, _capture) = captured_router(&policy);
    let (live_etag, _) = current_policy(&router).await;
    let (draft_id, draft_etag, _) = create_draft(&router, &live_etag, None).await;

    let invalid = json!({ "schema_version": "0.1.0", "default_action": "sometimes" });
    let mut egress_change = policy_document("egress-policy", "test:old");
    egress_change["egress"] = json!({ "hosts": ["upstream.example.test"] });
    for (candidate, expected) in [
        (invalid, StatusCode::BAD_REQUEST),
        (egress_change, StatusCode::CONFLICT),
    ] {
        let created = send(
            &router,
            draft_request(
                Method::POST,
                POLICY_DRAFTS_ADMIN_ROUTE,
                admin(),
                Some(json!({ "policy": candidate })),
                &[("if-match", &live_etag)],
            ),
        )
        .await;
        assert_eq!(created.status(), expected);
        let patched = send(
            &router,
            draft_request(
                Method::PATCH,
                &draft_uri(&draft_id),
                admin(),
                Some(json!({ "policy": candidate })),
                &[("if-match", &draft_etag)],
            ),
        )
        .await;
        assert_eq!(patched.status(), expected);
    }
    let listed = json_body(
        send(
            &router,
            draft_request(Method::GET, POLICY_DRAFTS_ADMIN_ROUTE, admin(), None, &[]),
        )
        .await,
    )
    .await;
    assert_eq!(
        listed["drafts"].as_array().map(Vec::len),
        Some(1),
        "no refused candidate was saved"
    );
    assert_eq!(listed["drafts"][0]["revision"], 1);
}

#[tokio::test]
async fn an_owner_holds_a_bounded_number_of_drafts_and_deleting_frees_one() {
    let policy = TempPolicyFile::new(&policy_document_string("quota-policy", "test:old"));
    let (router, capture) = captured_router(&policy);
    let (live_etag, _) = current_policy(&router).await;
    let mut drafts = Vec::new();
    for _ in 0..storage::policy_drafts::MAX_POLICY_DRAFTS_PER_OWNER {
        let (draft_id, draft_etag, _) = create_draft(&router, &live_etag, None).await;
        drafts.push((draft_id, draft_etag));
    }
    let over = send(
        &router,
        draft_request(
            Method::POST,
            POLICY_DRAFTS_ADMIN_ROUTE,
            admin(),
            Some(json!({})),
            &[("if-match", &live_etag)],
        ),
    )
    .await;
    let (status, body) = refusal(over).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["reason"], "policy_draft_owner_quota_exceeded");
    assert_eq!(
        body["max_drafts_per_owner"],
        storage::policy_drafts::MAX_POLICY_DRAFTS_PER_OWNER
    );

    // Another owner is not held to this owner's quota.
    let other = send(
        &router,
        draft_request(
            Method::POST,
            POLICY_DRAFTS_ADMIN_ROUTE,
            other_admin("second-owner", None),
            Some(json!({})),
            &[("if-match", &live_etag)],
        ),
    )
    .await;
    assert_eq!(other.status(), StatusCode::CREATED);

    // A stale ETag deletes nothing; the current one frees the slot.
    let (draft_id, draft_etag) = &drafts[0];
    let (status, body) = refusal(
        send(
            &router,
            draft_request(
                Method::DELETE,
                &draft_uri(draft_id),
                admin(),
                None,
                &[("if-match", "\"sha256:stale\"")],
            ),
        )
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["reason"], "policy_draft_etag_mismatch");
    let deleted = send(
        &router,
        draft_request(
            Method::DELETE,
            &draft_uri(draft_id),
            admin(),
            None,
            &[("if-match", draft_etag)],
        ),
    )
    .await;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        send(
            &router,
            draft_request(Method::GET, &draft_uri(draft_id), admin(), None, &[]),
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    create_draft(&router, &live_etag, None).await;
    assert_eventually(Duration::from_secs(1), || {
        events_of(&capture, audit::event::POLICY_DRAFT_CHANGED)
            .iter()
            .any(|payload| payload["action"] == "deleted" && payload["draft_id"] == json!(draft_id))
    });
}

#[tokio::test]
async fn an_expired_draft_is_gone_for_every_route() {
    let policy = TempPolicyFile::new(&policy_document_string("expiry-policy", "test:old"));
    let (router, _capture) = captured_router(&policy);
    let (live_etag, _) = current_policy(&router).await;
    let (draft_id, draft_etag, _) = create_draft(&router, &live_etag, None).await;

    // Age the row on the store's own clock, in the history database the
    // standalone store shares.
    let history = default_policy_history_sqlite_path(&policy.path.to_string_lossy());
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let changed = rusqlite::Connection::open(&history)
        .expect("history database should open")
        .execute(
            "UPDATE policy_drafts
             SET created_at = ?1 - 7200, updated_at = ?1 - 7200, expires_at = ?1 - 1
             WHERE draft_id = ?2",
            rusqlite::params![now, draft_id],
        )
        .expect("draft should age");
    assert_eq!(changed, 1);

    for request in [
        draft_request(Method::GET, &draft_uri(&draft_id), admin(), None, &[]),
        draft_request(
            Method::PATCH,
            &draft_uri(&draft_id),
            admin(),
            Some(json!({ "base_etag": live_etag })),
            &[("if-match", &draft_etag)],
        ),
        draft_request(
            Method::DELETE,
            &draft_uri(&draft_id),
            admin(),
            None,
            &[("if-match", &draft_etag)],
        ),
        draft_request(
            Method::POST,
            &draft_publish_uri(&draft_id),
            admin(),
            None,
            &[
                (POLICY_DRAFT_ETAG_HEADER, &draft_etag),
                ("if-match", &live_etag),
            ],
        ),
    ] {
        let (status, body) = refusal(send(&router, request).await).await;
        assert_eq!(status, StatusCode::GONE, "{body}");
        assert_eq!(body["reason"], "policy_draft_expired");
    }
    let listed = json_body(
        send(
            &router,
            draft_request(Method::GET, POLICY_DRAFTS_ADMIN_ROUTE, admin(), None, &[]),
        )
        .await,
    )
    .await;
    assert_eq!(listed["drafts"], json!([]));
    assert_eq!(current_policy(&router).await.0, live_etag);
}

#[tokio::test]
async fn draft_routes_without_a_policy_authority_answer_like_the_policy_api() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app should build");
    // No POLICY_FILE: there is no policy authority to draft against, and
    // the draft routes say so exactly as the policy API does.
    for uri in [POLICY_ADMIN_ROUTE, POLICY_DRAFTS_ADMIN_ROUTE] {
        let (status, body) =
            refusal(send(&router, draft_request(Method::GET, uri, admin(), None, &[])).await).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{uri}: {body}");
        assert_eq!(
            body["error"],
            "policy API requires POLICY_FILE to be configured"
        );
    }
}

/// A draft store that cannot record a publication, standing in for one that
/// fails, or loses a race with its owner's edit, after the policy committed.
struct UnmarkableDraftStore(storage::SqlitePolicyDraftStore);

#[async_trait::async_trait]
impl storage::PolicyDraftStore for UnmarkableDraftStore {
    fn limits(&self) -> storage::policy_drafts::PolicyDraftLimits {
        self.0.limits()
    }

    async fn create(
        &self,
        draft: storage::policy_drafts::NewPolicyDraft<'_>,
    ) -> Result<storage::policy_drafts::PolicyDraftCreated, storage::RepositoryError> {
        self.0.create(draft).await
    }

    async fn get(
        &self,
        owner: &storage::policy_drafts::PolicyDraftOwner,
        draft_id: &str,
    ) -> Result<Option<storage::policy_drafts::PolicyDraftRecord>, storage::RepositoryError> {
        self.0.get(owner, draft_id).await
    }

    async fn list(
        &self,
        owner: &storage::policy_drafts::PolicyDraftOwner,
    ) -> Result<Vec<storage::policy_drafts::PolicyDraftSummary>, storage::RepositoryError> {
        self.0.list(owner).await
    }

    async fn update(
        &self,
        owner: &storage::policy_drafts::PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
        change: storage::policy_drafts::PolicyDraftChange<'_>,
    ) -> Result<Option<storage::policy_drafts::PolicyDraftRecord>, storage::RepositoryError> {
        match change {
            storage::policy_drafts::PolicyDraftChange::Published { .. } => {
                Err(storage::RepositoryError::new(
                    storage::RepositoryErrorKind::Unavailable,
                    "policy_draft_update",
                ))
            }
            change => {
                self.0
                    .update(owner, draft_id, expected_revision, change)
                    .await
            }
        }
    }

    async fn delete(
        &self,
        owner: &storage::policy_drafts::PolicyDraftOwner,
        draft_id: &str,
        expected_revision: i64,
    ) -> Result<bool, storage::RepositoryError> {
        self.0.delete(owner, draft_id, expected_revision).await
    }
}

/// The policy commit and the draft's published mark are two writes. When
/// the second fails, the response still reports the committed policy, says
/// the draft state was not recorded, and the draft -- left open on the base
/// it was published over -- cannot publish a second time.
#[tokio::test]
async fn a_publication_whose_draft_cannot_be_marked_still_reports_the_commit() {
    let policy = TempPolicyFile::new(&policy_document_string("unmarked-policy", "test:old"));
    let drafts_db = TempDb::new("policy-drafts-unmarkable");
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let live_policy = parse_policy_body(&axum::body::Bytes::from(policy_document_string(
        "unmarked-policy",
        "test:old",
    )))
    .expect("policy should parse");
    let rbac_state =
        middleware::rbac::RbacState::new(live_policy, Vec::new(), false, audit_log.clone());
    let store =
        storage::SqlitePolicyDraftStore::open(&drafts_db.path).expect("draft store should open");
    let router = Router::new()
        .route(POLICY_ADMIN_ROUTE, get(policy_get_endpoint))
        .route(
            POLICY_DRAFTS_ADMIN_ROUTE,
            post(policy_draft_create_endpoint),
        )
        .route(POLICY_DRAFT_ADMIN_ROUTE, get(policy_draft_get_endpoint))
        .route(
            POLICY_DRAFT_PUBLISH_ADMIN_ROUTE,
            post(policy_draft_publish_endpoint),
        )
        .with_state(PolicyAdminState {
            policy_file: Some(policy.path.clone()),
            rbac_state: Some(rbac_state),
            history_store: None,
            draft_store: Some(
                Arc::new(UnmarkableDraftStore(store)) as Arc<dyn storage::PolicyDraftStore>
            ),
            #[cfg(feature = "postgres")]
            control_plane: None,
            #[cfg(feature = "postgres")]
            membership: None,
            event_store: None,
            query_store: None,
            audit: audit_log,
            client_ip_policy: client_ip::ClientIpPolicy::default(),
            max_body_size: 1024 * 1024,
        });
    let (base_etag, _) = current_policy(&router).await;
    let (draft_id, draft_etag, created) = create_draft(
        &router,
        &base_etag,
        Some(policy_document("unmarked-candidate", "test:new")),
    )
    .await;

    let published = publish(&router, &draft_id, &draft_etag, &base_etag).await;
    assert_eq!(published.status(), StatusCode::OK);
    assert_eq!(
        published
            .headers()
            .get(POLICY_DRAFT_WARNING_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(POLICY_DRAFT_STATE_NOT_RECORDED_WARNING)
    );
    let new_etag = policy_etag_header(&published);
    assert_eq!(json!(new_etag), created["candidate_etag"]);
    let (live_etag, live) = current_policy(&router).await;
    assert_eq!(live_etag, new_etag);
    assert_eq!(live["id"], "unmarked-candidate");

    // The draft is still open on the old base, so it cannot publish again.
    let kept = send(
        &router,
        draft_request(Method::GET, &draft_uri(&draft_id), admin(), None, &[]),
    )
    .await;
    assert_eq!(policy_etag_header(&kept), draft_etag);
    let kept = json_body(kept).await;
    assert_eq!(kept["state"], "open");
    assert_eq!(kept["base_etag"], json!(base_etag));
    let (status, body) = refusal(publish(&router, &draft_id, &draft_etag, &new_etag).await).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "policy_draft_base_stale");
    assert_eq!(current_policy(&router).await.0, new_etag);

    assert_eventually(Duration::from_secs(1), || {
        events_of(&capture, audit::event::POLICY_DRAFT_PUBLISH_REFUSED).len() == 1
    });
    let publications = events_of(&capture, audit::event::POLICY_DRAFT_PUBLISHED);
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0]["draft_state_recorded"], false);
    assert_eq!(publications[0]["policy_etag"], json!(new_etag));
    assert_eq!(events_of(&capture, audit::event::POLICY_CHANGED).len(), 1);
}
