use super::*;

fn testable_connection_body(display_name: &str, enabled: bool) -> String {
    json!({
        "display_name": display_name,
        "enabled": enabled,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://blocked-test-target.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "none"
        },
        "test_profile": {
            "method": "HEAD",
            "path": "/ready",
            "expected_statuses": [200, 204]
        }
    })
    .to_string()
}

fn credentialed_connection_body() -> String {
    json!({
        "display_name": "Credentialed billing API",
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://credentialed.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "static_bearer",
            "secret_id": "credential-secret-id-canary"
        }
    })
    .to_string()
}

#[test]
fn explicit_hidden_binding_fields_are_secret_authority_intent() {
    for candidate in [
        json!({"authentication": {"secret_id": "alias"}}),
        json!({"authentication": {"client_secret_id": null}}),
        json!({"additional_headers": [{"header_name": "x-proxy-token", "secret_id": "alias"}]}),
        json!({"additional_headers": [{"header_name": "x-proxy-token", "secret_id": null}]}),
        json!({"tls": {"ca_bundle_alias": "ca"}}),
        json!({"tls": {"client_certificate_id": "certificate"}}),
        json!({"tls": {"client_private_key_id": null}}),
        json!({"caller_assertion": {"signing_key_id": "alias"}}),
        json!({"caller_assertion": {"published_keys": [{"signing_key_id": "alias"}]}}),
    ] {
        assert!(has_explicit_connection_binding_intent(&candidate));
    }
    assert!(!has_explicit_connection_binding_intent(&json!({
        "authentication": {"secret_configured": true},
        "caller_assertion": {
            "signing_key_configured": true,
            "published_keys": [{"signing_key_configured": true}]
        },
        "tls": {
            "ca_bundle_configured": true,
            "client_certificate_configured": true,
            "client_private_key_configured": true
        }
    })));
    assert!(!has_explicit_connection_binding_intent(&json!({
        "caller_assertion": null
    })));
}

#[test]
fn redacted_additional_header_bindings_round_trip_clear_and_reject_false_markers() {
    let current: connections::model::ConnectionWrite = serde_json::from_value(json!({
        "display_name": "Access-fronted API",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://access.example.test",
            "base_path": "/"
        },
        "authentication": {"type": "none"},
        "additional_headers": [
            {
                "header_name": "cf-access-client-id",
                "secret_id": "additional-header-secret-id-canary"
            },
            {
                "header_name": "cf-access-client-secret"
            }
        ],
        "tls": {}
    }))
    .expect("additional-header draft should deserialize");

    let redacted_edit = json!({
        "display_name": "Access-fronted API renamed",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://access.example.test",
            "base_path": "/"
        },
        "authentication": {"type": "none"},
        "additional_headers": [
            {
                "header_name": "CF-Access-Client-Id",
                "secret_configured": true
            },
            {
                "header_name": "cf-access-client-secret",
                "secret_configured": false
            }
        ],
        "tls": {}
    });
    assert!(!has_explicit_connection_binding_intent(&redacted_edit));
    let candidate = parse_connection_write_body(&Bytes::from(redacted_edit.to_string()), &current)
        .expect("redacted additional headers should retain matching hidden bindings");
    assert_eq!(
        candidate.additional_headers[0].secret_id.as_deref(),
        Some("additional-header-secret-id-canary")
    );
    assert!(candidate.additional_headers[1].secret_id.is_none());
    assert_eq!(
        candidate.additional_headers[0].header_name,
        "cf-access-client-id"
    );
    assert!(!current.requires_secrets_write_to_replace(&candidate));

    let mut cleared = redacted_edit.clone();
    cleared["additional_headers"][0]["secret_configured"] = json!(false);
    let cleared = parse_connection_write_body(&Bytes::from(cleared.to_string()), &current)
        .expect("a false marker should explicitly clear the hidden binding");
    assert!(cleared.additional_headers[0].secret_id.is_none());
    assert!(current.requires_secrets_write_to_replace(&cleared));

    for invalid in [
        json!({
            "display_name": "Access-fronted API",
            "enabled": false,
            "kind": "http_api",
            "endpoint": {"base_url": "https://access.example.test", "base_path": "/"},
            "authentication": {"type": "none"},
            "additional_headers": [{
                "header_name": "x-not-current",
                "secret_configured": true
            }],
            "tls": {}
        }),
        json!({
            "display_name": "Access-fronted API",
            "enabled": false,
            "kind": "http_api",
            "endpoint": {"base_url": "https://access.example.test", "base_path": "/"},
            "authentication": {"type": "none"},
            "additional_headers": [{
                "header_name": "cf-access-client-id",
                "secret_id": "replacement-secret",
                "secret_configured": true
            }],
            "tls": {}
        }),
    ] {
        let error = parse_connection_write_body(&Bytes::from(invalid.to_string()), &current)
            .expect_err("forged or contradictory redaction markers must fail closed");
        let rendered = format!("{error:?}");
        assert!(!rendered.contains("additional-header-secret-id-canary"));
    }
}

#[test]
fn redacted_partial_mtls_draft_round_trips_each_hidden_binding_independently() {
    let current: connections::model::ConnectionWrite = serde_json::from_value(json!({
        "display_name": "Partial mTLS draft",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://partial.example.test",
            "base_path": "/"
        },
        "authentication": {
            "type": "none"
        },
        "tls": {
            "client_certificate_id": "certificate-only-binding-canary"
        }
    }))
    .expect("partial disabled draft should deserialize");
    let redacted_edit = json!({
        "display_name": "Partial mTLS draft renamed",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://partial.example.test",
            "base_path": "/"
        },
        "authentication": {
            "type": "none"
        },
        "tls": {
            "ca_bundle_configured": false,
            "client_certificate_configured": true,
            "client_private_key_configured": false
        }
    });

    let candidate = parse_connection_write_body(&Bytes::from(redacted_edit.to_string()), &current)
        .expect("redacted partial draft should retain its lone certificate binding");

    assert_eq!(
        candidate.tls.client_certificate_id.as_deref(),
        Some("certificate-only-binding-canary")
    );
    assert!(candidate.tls.client_private_key_id.is_none());
    assert!(!current.requires_secrets_write_to_replace(&candidate));

    let mut private_key_only = current.clone();
    private_key_only.tls.client_certificate_id = None;
    private_key_only.tls.client_private_key_id = Some("private-key-only-binding-canary".to_owned());
    let private_key_edit = json!({
        "display_name": "Private-key-only mTLS draft renamed",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://partial.example.test",
            "base_path": "/"
        },
        "authentication": {
            "type": "none"
        },
        "tls": {
            "ca_bundle_configured": false,
            "client_certificate_configured": false,
            "client_private_key_configured": true
        }
    });
    let private_key_candidate = parse_connection_write_body(
        &Bytes::from(private_key_edit.to_string()),
        &private_key_only,
    )
    .expect("redacted partial draft should retain its lone private-key binding");
    assert!(private_key_candidate.tls.client_certificate_id.is_none());
    assert_eq!(
        private_key_candidate.tls.client_private_key_id.as_deref(),
        Some("private-key-only-binding-canary")
    );
    assert!(!private_key_only.requires_secrets_write_to_replace(&private_key_candidate));
}

#[test]
fn replacement_keeps_an_omitted_caller_assertion_and_removes_it_only_on_null() {
    // The admin UI does not edit the block, so a routine edit omits it. Reading
    // that as removal would put a Connection that cannot yet attest its caller
    // back into service without the assertion.
    let current: connections::model::ConnectionWrite = serde_json::from_value(json!({
        "display_name": "Attested API",
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/"
        },
        "authentication": {"type": "none"},
        "caller_assertion": {
            "signing_key_id": "assertion-signing-key",
            "kid": "gw-test-1",
            "algorithm": "es256",
            "issuer": "https://gateway.example.test",
            "audience": "https://billing.example.test",
            "token_type": "at+jwt",
            "header_name": "x-caller-assertion",
            "lifetime_seconds": 60
        },
        "tls": {}
    }))
    .expect("attested Connection should deserialize");
    let current = current
        .validated()
        .expect("attested Connection should validate");
    let mut routine_edit = json!({
        "display_name": "Attested API renamed",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/"
        },
        "authentication": {"type": "none"},
        "tls": {}
    });

    let kept = parse_connection_write_body(&Bytes::from(routine_edit.to_string()), &current)
        .expect("an edit that omits the assertion should keep it");
    assert_eq!(kept.caller_assertion, current.caller_assertion);
    assert_eq!(kept.display_name, "Attested API renamed");
    assert!(!kept.enabled);
    assert_eq!(
        connections::admin::changed_connection_fields(Some(&current), Some(&kept)),
        vec!["display_name", "enabled"]
    );

    routine_edit["caller_assertion"] = Value::Null;
    let removed = parse_connection_write_body(&Bytes::from(routine_edit.to_string()), &current)
        .expect("an explicit null should remove the assertion");
    assert!(removed.caller_assertion.is_none());
    assert!(
        connections::admin::changed_connection_fields(Some(&current), Some(&removed))
            .contains(&"caller_assertion")
    );

    // With no current block there is nothing to keep.
    let mut unattested = current.clone();
    unattested.caller_assertion = None;
    let plain_edit = json!({
        "display_name": "Plain API",
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/"
        },
        "authentication": {"type": "none"},
        "tls": {}
    });
    let plain = parse_connection_write_body(&Bytes::from(plain_edit.to_string()), &unattested)
        .expect("an edit of an unattested Connection should parse");
    assert!(plain.caller_assertion.is_none());
}

fn rotating_caller_assertion_connection() -> connections::model::ConnectionWrite {
    let current: connections::model::ConnectionWrite = serde_json::from_value(json!({
        "display_name": "Attested API",
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/"
        },
        "authentication": {"type": "none"},
        "caller_assertion": {
            "signing_key_id": "assertion-key-current-canary",
            "kid": "gw-test-1",
            "algorithm": "es256",
            "issuer": "https://gateway.example.test",
            "audience": "https://billing.example.test",
            "token_type": "caller-assertion+jwt",
            "header_name": "x-caller-assertion",
            "lifetime_seconds": 60,
            "published_keys": [{
                "signing_key_id": "assertion-key-next-canary",
                "kid": "gw-test-2",
                "algorithm": "rs256"
            }]
        },
        "tls": {}
    }))
    .expect("attested Connection should deserialize");
    current
        .validated()
        .expect("attested Connection should validate")
}

fn caller_assertion_edit(assertion: Value) -> Value {
    json!({
        "display_name": "Attested API",
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/"
        },
        "authentication": {"type": "none"},
        "caller_assertion": assertion,
        "tls": {}
    })
}

#[test]
fn replacement_keeps_caller_assertion_key_aliases_by_kid_through_a_rotation() {
    // The admin UI edits the block without ever seeing its aliases: it marks
    // each key it keeps, and the gateway keeps the alias stored under that
    // key's `kid` and algorithm.
    let current = rotating_caller_assertion_connection();
    let unchanged = caller_assertion_edit(json!({
        "signing_key_configured": true,
        "kid": "gw-test-1",
        "algorithm": "es256",
        "issuer": "https://gateway.example.test",
        "audience": "https://billing.example.test",
        "token_type": "caller-assertion+jwt",
        "header_name": "X-Caller-Assertion",
        "lifetime_seconds": 60,
        "published_keys": [{
            "signing_key_configured": true,
            "kid": "gw-test-2",
            "algorithm": "rs256"
        }]
    }));
    assert!(!has_explicit_connection_binding_intent(&unchanged));
    let kept = parse_connection_write_body(&Bytes::from(unchanged.to_string()), &current)
        .expect("marked keys should keep their stored aliases");
    assert_eq!(kept.caller_assertion, current.caller_assertion);
    assert!(!current.requires_secrets_write_to_replace(&kept));

    let mut longer = unchanged.clone();
    longer["caller_assertion"]["lifetime_seconds"] = json!(120);
    let longer = parse_connection_write_body(&Bytes::from(longer.to_string()), &current)
        .expect("an edit of another field should keep both aliases");
    let assertion = longer.caller_assertion.as_ref().expect("block kept");
    assert_eq!(assertion.lifetime_seconds, 120);
    assert_eq!(assertion.signing_key_id, "assertion-key-current-canary");
    assert_eq!(
        assertion.published_keys[0].signing_key_id,
        "assertion-key-next-canary"
    );
    assert!(current.requires_secrets_write_to_replace(&longer));

    // Rotation step 3: the next key signs and the previous one stays published.
    let promoted = caller_assertion_edit(json!({
        "signing_key_configured": true,
        "kid": "gw-test-2",
        "algorithm": "rs256",
        "issuer": "https://gateway.example.test",
        "audience": "https://billing.example.test",
        "token_type": "caller-assertion+jwt",
        "header_name": "x-caller-assertion",
        "lifetime_seconds": 60,
        "published_keys": [{
            "signing_key_configured": true,
            "kid": "gw-test-1",
            "algorithm": "es256"
        }]
    }));
    let promoted = parse_connection_write_body(&Bytes::from(promoted.to_string()), &current)
        .expect("a promotion should move each alias with its kid");
    let assertion = promoted.caller_assertion.as_ref().expect("block kept");
    assert_eq!(assertion.kid, "gw-test-2");
    assert_eq!(assertion.signing_key_id, "assertion-key-next-canary");
    assert_eq!(assertion.published_keys[0].kid, "gw-test-1");
    assert_eq!(
        assertion.published_keys[0].signing_key_id,
        "assertion-key-current-canary"
    );

    // A marked key next to a newly named one: only the new alias is explicit.
    let mut added = unchanged.clone();
    added["caller_assertion"]["published_keys"] = json!([{
        "signing_key_id": "assertion-key-third",
        "kid": "gw-test-3",
        "algorithm": "es256"
    }]);
    assert!(has_explicit_connection_binding_intent(&added));
    let added = parse_connection_write_body(&Bytes::from(added.to_string()), &current)
        .expect("a newly named key should be accepted beside a marked one");
    let assertion = added.caller_assertion.as_ref().expect("block kept");
    assert_eq!(assertion.signing_key_id, "assertion-key-current-canary");
    assert_eq!(
        assertion.published_keys[0].signing_key_id,
        "assertion-key-third"
    );
}

#[test]
fn caller_assertion_key_markers_that_match_no_stored_key_fail_closed() {
    let current = rotating_caller_assertion_connection();
    let signing = |overrides: Value| {
        let mut assertion = json!({
            "signing_key_configured": true,
            "kid": "gw-test-1",
            "algorithm": "es256",
            "issuer": "https://gateway.example.test",
            "audience": "https://billing.example.test",
            "token_type": "caller-assertion+jwt",
            "header_name": "x-caller-assertion",
            "lifetime_seconds": 60
        });
        for (field, value) in overrides.as_object().expect("overrides are an object") {
            assertion[field] = value.clone();
        }
        caller_assertion_edit(assertion)
    };

    for (invalid, reason) in [
        (signing(json!({"kid": "gw-test-9"})), "a kid nothing stores"),
        (
            signing(json!({"algorithm": "rs256"})),
            "a stored kid under the other algorithm",
        ),
        (
            signing(json!({"signing_key_configured": false})),
            "a cleared key",
        ),
        (
            signing(json!({"signing_key_id": "assertion-key-guess"})),
            "a marker beside an explicit alias",
        ),
        (
            signing(json!({"signing_key_configured": "yes"})),
            "a non-boolean marker",
        ),
        (
            signing(json!({"published_keys": [{
                "signing_key_configured": true,
                "kid": "gw-test-2",
                "algorithm": "es256"
            }]})),
            "a published key under the other algorithm",
        ),
        (
            signing(json!({"published_keys": ["gw-test-2"]})),
            "a published key that is not an object",
        ),
    ] {
        let error = parse_connection_write_body(&Bytes::from(invalid.to_string()), &current)
            .expect_err(reason);
        assert_eq!(error.status(), StatusCode::BAD_REQUEST, "{reason}");
        let rendered = format!("{error:?}");
        assert!(
            !rendered.contains("assertion-key-current-canary"),
            "{reason}"
        );
        assert!(!rendered.contains("assertion-key-next-canary"), "{reason}");
    }

    // With no stored block there is no alias to keep.
    let mut unattested = current.clone();
    unattested.caller_assertion = None;
    let error =
        parse_connection_write_body(&Bytes::from(signing(json!({})).to_string()), &unattested)
            .expect_err("a marker with nothing stored must fail closed");
    assert_eq!(error.status(), StatusCode::BAD_REQUEST);

    // A create never retains anything, so a marker is an unknown field there.
    assert!(parse_connection_create_body(&Bytes::from(signing(json!({})).to_string())).is_err());
}

#[tokio::test]
async fn managed_openapi_preview_and_register_enforce_permissions_and_revisions() {
    let connection_db = TempDb::new("connection-openapi-admin-guards");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = connection_admin_router(&connection_db, &policy, test_audit_log());

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let collection_etag = list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include collection ETag")
        .to_owned();
    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-editor"])),
            Some(managed_openapi_connection_body("Managed OpenAPI")),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("managed OpenAPI connection create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let connection_etag = created
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("created connection should include ETag")
        .to_owned();
    let connection_id = json_body(created).await["id"]
        .as_str()
        .expect("created connection should include ID")
        .to_owned();
    let preview_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview");
    let register_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/register");
    let preview_request_body = json!({ "spec": widget_openapi_spec() }).to_string();

    let forbidden_preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &preview_uri,
            Some(test_principal(&["connections-editor"])),
            Some(preview_request_body.clone()),
            None,
            true,
        ))
        .await
        .expect("preview permission denial should complete");
    assert_eq!(forbidden_preview.status(), StatusCode::FORBIDDEN);

    let large_spec = json!({
        "openapi": "3.0.3",
        "info": {
            "title": "Large managed preview",
            "version": "1.0.0",
            "description": "x".repeat(70 * 1024)
        },
        "paths": {
            "/widgets": {
                "get": {
                    "operationId": "listWidgets",
                    "responses": {
                        "200": { "description": "ok" }
                    }
                }
            }
        }
    })
    .to_string();
    let large_preview_body = json!({ "spec": large_spec }).to_string();
    assert!(
        large_preview_body.len() > connections::admin::MAX_CONNECTION_ADMIN_BODY_BYTES,
        "regression body must exceed the normal Connection admin limit"
    );
    let large_preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &preview_uri,
            Some(test_principal(&["openapi-tools-reader"])),
            Some(large_preview_body),
            None,
            true,
        ))
        .await
        .expect("large managed OpenAPI preview should complete");
    assert_eq!(large_preview.status(), StatusCode::OK);

    let preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &preview_uri,
            Some(test_principal(&["openapi-tools-reader"])),
            Some(preview_request_body),
            None,
            true,
        ))
        .await
        .expect("managed OpenAPI preview should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    assert_eq!(
        preview
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(connection_etag.as_str())
    );
    let preview = json_body(preview).await;
    assert_eq!(preview["connection_id"], json!(connection_id));
    assert_eq!(preview["connection_etag"], json!(connection_etag));
    assert_eq!(preview["spec_revision"], json!(0));
    assert_eq!(preview["catalog_revision"], json!(0));
    assert!(preview["spec_digest"].as_str().is_some_and(
        |digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    ));
    let selected_tool_name = preview["tools"][0]["name"]
        .as_str()
        .expect("preview should include a generated tool")
        .to_owned();
    let selected_security_confirmation = preview["security_confirmations"]
        .as_array()
        .and_then(|confirmations| {
            confirmations.iter().find(|confirmation| {
                confirmation["tool_name"].as_str() == Some(selected_tool_name.as_str())
            })
        })
        .cloned()
        .expect("selected tool should include an exact security confirmation");
    let register_body = json!({
        "spec": widget_openapi_spec(),
        "spec_digest": preview["spec_digest"],
        "expected_spec_revision": preview["spec_revision"],
        "expected_catalog_revision": preview["catalog_revision"],
        "selected_tool_names": [selected_tool_name],
        "security_confirmations": [selected_security_confirmation],
    })
    .to_string();

    let forbidden_register = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &register_uri,
            Some(test_principal(&["openapi-tools-reader"])),
            Some(register_body.clone()),
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("register permission denial should complete");
    assert_eq!(forbidden_register.status(), StatusCode::FORBIDDEN);

    let missing_if_match = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &register_uri,
            Some(test_principal(&["openapi-tools-writer"])),
            Some(register_body.clone()),
            None,
            true,
        ))
        .await
        .expect("missing register precondition should complete");
    assert_eq!(missing_if_match.status(), StatusCode::PRECONDITION_REQUIRED);

    let stale_if_match = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &register_uri,
            Some(test_principal(&["openapi-tools-writer"])),
            Some(register_body.clone()),
            Some("\"connection:stale\""),
            true,
        ))
        .await
        .expect("stale register precondition should complete");
    assert_eq!(stale_if_match.status(), StatusCode::PRECONDITION_FAILED);

    let registered = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &register_uri,
            Some(test_principal(&["openapi-tools-writer"])),
            Some(register_body),
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("one-tool managed OpenAPI registration should complete");
    assert_eq!(registered.status(), StatusCode::CREATED);
    let registered = json_body(registered).await;
    assert_eq!(registered["total_count"], json!(1));
    assert_eq!(registered["added_count"], json!(1));

    let clear_body = json!({
        "spec": widget_openapi_spec(),
        "spec_digest": registered["spec_digest"],
        "expected_spec_revision": registered["spec_revision"],
        "expected_catalog_revision": registered["catalog_revision"],
        "selected_tool_names": [],
        "security_confirmations": [],
    })
    .to_string();
    let cleared = router
        .oneshot(connection_admin_request(
            Method::POST,
            &register_uri,
            Some(test_principal(&["openapi-tools-writer"])),
            Some(clear_body),
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("empty managed OpenAPI catalog registration should complete");
    assert_eq!(cleared.status(), StatusCode::CREATED);
    let cleared = json_body(cleared).await;
    assert_eq!(cleared["registered_tool_names"], json!([]));
    assert_eq!(cleared["total_count"], json!(0));
    assert_eq!(cleared["removed_count"], json!(1));
}

#[tokio::test]
async fn managed_openapi_preview_reports_swagger2_conversion_and_registers_converted_tools() {
    let connection_db = TempDb::new("connection-openapi-swagger2-preview");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = connection_admin_router(&connection_db, &policy, test_audit_log());
    let (connection_id, connection_etag) =
        create_managed_openapi_connection(&router, "Managed Swagger").await;
    let preview_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview");
    let register_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/register");

    let openapi_preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &preview_uri,
            Some(test_principal(&["openapi-tools-reader"])),
            Some(json!({ "spec": widget_openapi_spec() }).to_string()),
            None,
            true,
        ))
        .await
        .expect("OpenAPI 3.x preview should complete");
    assert_eq!(openapi_preview.status(), StatusCode::OK);
    assert!(
        json_body(openapi_preview).await.get("conversion").is_none(),
        "an OpenAPI 3.x preview keeps its previous shape"
    );

    let swagger_spec = json!({
        "swagger": "2.0",
        "info": { "title": "Widget API", "version": "1.0.0" },
        "basePath": "/v1",
        "paths": {
            "/widgets/{widgetId}": {
                "get": {
                    "operationId": "getWidget",
                    "summary": "Fetch a widget",
                    "parameters": [
                        { "name": "widgetId", "in": "path", "required": true, "type": "string" }
                    ]
                }
            },
            "/widgets": {
                "post": {
                    "operationId": "createWidgets",
                    "parameters": [
                        { "name": "a", "in": "body", "schema": { "type": "object" } },
                        { "name": "b", "in": "body", "schema": { "type": "object" } }
                    ]
                }
            }
        }
    })
    .to_string();
    let preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &preview_uri,
            Some(test_principal(&["openapi-tools-reader"])),
            Some(json!({ "spec": swagger_spec }).to_string()),
            None,
            true,
        ))
        .await
        .expect("Swagger 2.0 preview should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = json_body(preview).await;
    assert_eq!(
        preview["conversion"],
        json!({
            "source_format": "swagger_2_0",
            "warnings": [
                {
                    "code": "base_path_not_in_paths",
                    "message": "basePath is not part of generated path templates; include it in the Connection base path",
                    "operation_omitted": false,
                    "subject": "/v1"
                },
                {
                    "code": "multiple_body_parameters",
                    "message": "the operation has more than one body parameter; it was left out",
                    "operation_omitted": true,
                    "method": "POST",
                    "path_template": "/widgets"
                }
            ]
        })
    );
    assert_eq!(
        preview["tools"]
            .as_array()
            .expect("preview should list tools")
            .iter()
            .map(|tool| tool["name"].clone())
            .collect::<Vec<_>>(),
        vec![json!("getWidget")],
        "the omitted operation generates no tool"
    );

    let registered = router
        .oneshot(connection_admin_request(
            Method::POST,
            &register_uri,
            Some(test_principal(&["openapi-tools-writer"])),
            Some(
                json!({
                    "spec": swagger_spec,
                    "spec_digest": preview["spec_digest"],
                    "expected_spec_revision": preview["spec_revision"],
                    "expected_catalog_revision": preview["catalog_revision"],
                    "selected_tool_names": ["getWidget"],
                    "security_confirmations": preview["security_confirmations"],
                })
                .to_string(),
            ),
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("Swagger 2.0 registration should complete");
    assert_eq!(registered.status(), StatusCode::CREATED);
    let registered = json_body(registered).await;
    assert_eq!(registered["registered_tool_names"], json!(["getWidget"]));
}

/// Converted managed OpenAPI catalogs gated as cluster mode gates them
/// (issue #443), with no roster to ask: every write that would store one --
/// registering it, an overlay over it, refreshing to it -- is refused with
/// `503 roster_unavailable` and changes nothing, while preview and an
/// OpenAPI 3.x registration never ask.
#[tokio::test]
async fn managed_openapi_gated_swagger2_writes_fail_closed_without_a_roster() {
    let connection_db = TempDb::new("connection-openapi-swagger2-gated");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let swagger_spec = json!({
        "swagger": "2.0",
        "info": { "title": "Widget API", "version": "1.0.0" },
        "paths": {
            "/widgets": {
                "get": {
                    "operationId": "listWidgets",
                    "responses": { "200": { "description": "Widgets" } }
                }
            }
        }
    })
    .to_string();

    // A replica that does not gate stores the converted catalog first.
    let ungated = connection_admin_router(&connection_db, &policy, test_audit_log());
    let (connection_id, connection_etag) =
        create_managed_openapi_connection(&ungated, "Gated Swagger").await;
    let registered = preview_and_register_managed_openapi(
        &ungated,
        &connection_id,
        &connection_etag,
        &swagger_spec,
        &["listWidgets"],
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let catalog_revision = json_body(registered).await["catalog_revision"]
        .as_u64()
        .expect("registration should return the catalog revision");
    drop(ungated);

    let router = gated_connection_admin_router(
        &connection_db,
        &policy,
        test_audit_log(),
        GatewayAppBuildOverrides::default(),
    );
    let assert_refused = |status: StatusCode, body: &Value, write: &str| {
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{write}: {body}");
        assert_eq!(
            body["reason"],
            json!("roster_unavailable"),
            "{write}: {body}"
        );
    };

    let refused = preview_and_register_managed_openapi(
        &router,
        &connection_id,
        &connection_etag,
        &swagger_spec,
        &["listWidgets"],
    )
    .await;
    let status = refused.status();
    assert_refused(status, &json_body(refused).await, "registration");

    let overlay_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/overlay");
    let overlay_etag = format!("\"overlay:{connection_id}:c1:r{catalog_revision}:o0\"");
    let refused = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            Some(
                json!({
                    "schema_version": "0.1.0",
                    "tools": { "listWidgets": { "description": "List every widget" } }
                })
                .to_string(),
            ),
            Some(&overlay_etag),
            true,
        ))
        .await
        .expect("overlay PUT should complete");
    let status = refused.status();
    assert_refused(status, &json_body(refused).await, "overlay");

    let refused = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/refresh"),
            Some(test_principal(&["connections-refresher"])),
            None,
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("refresh should complete");
    let status = refused.status();
    assert_refused(status, &json_body(refused).await, "refresh");

    // Nothing was written: the overlay is still absent at the catalog
    // revision the ungated replica registered.
    let current = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &overlay_uri,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("overlay read should complete");
    assert_eq!(current.status(), StatusCode::OK);
    assert_eq!(
        current
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(overlay_etag.as_str())
    );
    assert_eq!(json_body(current).await["document"], Value::Null);

    let openapi = preview_and_register_managed_openapi(
        &router,
        &connection_id,
        &connection_etag,
        widget_openapi_spec(),
        &["createWidget"],
    )
    .await;
    assert_eq!(
        openapi.status(),
        StatusCode::CREATED,
        "an OpenAPI 3.x document never asks the gate"
    );
}

#[tokio::test]
async fn managed_openapi_preview_reports_google_discovery_conversion_and_registers_converted_tools()
{
    let connection_db = TempDb::new("connection-openapi-discovery-preview");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = connection_admin_router(&connection_db, &policy, test_audit_log());
    let (connection_id, connection_etag) =
        create_managed_openapi_connection(&router, "Managed Discovery").await;
    let spec = widget_discovery_document();
    let preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview"),
            Some(test_principal(&["openapi-tools-reader"])),
            Some(json!({ "spec": spec }).to_string()),
            None,
            true,
        ))
        .await
        .expect("Discovery preview should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = json_body(preview).await;
    assert_eq!(
        preview["conversion"],
        json!({
            "source_format": "google_discovery_v1",
            "warnings": [
                {
                    "code": "base_path_not_in_paths",
                    "message": "basePath is not part of generated path templates; include it in the Connection base path",
                    "operation_omitted": false,
                    "subject": "/widgets/v1"
                },
                {
                    "code": "global_parameter_not_mapped",
                    "message": "this document-level parameter is not a tool argument, and generated tools never send it",
                    "operation_omitted": false,
                    "subject": "key"
                },
                {
                    "code": "unsupported_path_expansion",
                    "message": "the method path uses a URI template expansion other than a plain {name}, such as {+name}, which has no OpenAPI 3.0 form; it was left out",
                    "operation_omitted": true,
                    "method": "POST",
                    "path_template": "/{+name}:move",
                    "subject": "+name"
                }
            ]
        })
    );
    assert_eq!(
        preview["tools"]
            .as_array()
            .expect("preview should list tools")
            .iter()
            .map(|tool| tool["name"].clone())
            .collect::<Vec<_>>(),
        vec![json!("widgets.widgets.get")],
        "tools are named by their Discovery method IDs; the omitted method generates none"
    );
    // A scoped method needs a token for the user, which this Connection's
    // shared credential is not, and the preview says so per alternative.
    let incompatibilities = preview["incompatibilities"]
        .as_array()
        .expect("preview should list incompatibilities");
    assert_eq!(
        incompatibilities
            .iter()
            .find(|incompatibility| incompatibility["tool_name"] == json!("widgets.widgets.list")),
        Some(&json!({
            "tool_name": "widgets.widgets.list",
            "reason": "no_compatible_security_alternative",
            "security_alternatives": [{
                "scheme_names": ["Oauth2"],
                "reason": "oauth2_without_client_credentials",
                "message": "the OAuth 2.0 scheme has no clientCredentials flow, so it needs a token for the user; bind it with a per-caller Connection such as delegated_issuer_token"
            }]
        })),
        "{preview}"
    );
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../docs/schemas/connection-admin.v1.schema.json"),
        )
        .expect("the admin schema should read"),
    )
    .expect("the admin schema should parse");
    let incompatibility_schema = jsonschema::validator_for(&json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": schema["$defs"].clone(),
        "$ref": "#/$defs/OpenApiIncompatibility"
    }))
    .expect("the incompatibility schema should compile");
    for incompatibility in incompatibilities {
        assert!(
            incompatibility_schema.is_valid(incompatibility),
            "{incompatibility} should match the published schema"
        );
    }

    let registered = preview_and_register_managed_openapi(
        &router,
        &connection_id,
        &connection_etag,
        &spec,
        &["widgets.widgets.get"],
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    assert_eq!(
        json_body(registered).await["registered_tool_names"],
        json!(["widgets.widgets.get"])
    );
}

/// A Discovery catalog is a gated converted catalog like a Swagger 2.0 one:
/// without a roster its registration is refused and stores nothing.
#[tokio::test]
async fn managed_openapi_gated_discovery_registration_fails_closed_without_a_roster() {
    let connection_db = TempDb::new("connection-openapi-discovery-gated");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = gated_connection_admin_router(
        &connection_db,
        &policy,
        test_audit_log(),
        GatewayAppBuildOverrides::default(),
    );
    let (connection_id, connection_etag) =
        create_managed_openapi_connection(&router, "Gated Discovery").await;
    let refused = preview_and_register_managed_openapi(
        &router,
        &connection_id,
        &connection_etag,
        &widget_discovery_document(),
        &["widgets.widgets.get"],
    )
    .await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        json_body(refused).await["reason"],
        json!("roster_unavailable")
    );
    let preview = router
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview"),
            Some(test_principal(&["openapi-tools-reader"])),
            Some(json!({ "spec": widget_discovery_document() }).to_string()),
            None,
            true,
        ))
        .await
        .expect("Discovery preview should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    assert_eq!(
        json_body(preview).await["catalog_revision"],
        json!(0),
        "a refused registration stores no catalog"
    );
}

#[test]
fn stored_overlay_source_response_projects_only_a_strict_typed_envelope() {
    let mut reports = connections::store::StoredOpenApiSourceReports::empty();
    reports
        .sources
        .push(connections::store::StoredOpenApiSourceReport {
            id: "statuses".to_owned(),
            kind: connections::store::StoredOpenApiSourceKind::Enum,
            state: "resolved".to_owned(),
            item_count: 3,
            resolved_at: Some("2026-09-03T12:00:00Z".to_owned()),
        });
    let stored = connections::store::StoredOpenApiOverlay {
        connection_id: connections::model::ConnectionId::parse(
            "00000000-0000-0000-0000-000000000360",
        )
        .expect("test connection ID should parse"),
        schema_version: "0.1.0".to_owned(),
        overlay_revision: 1,
        overlay_json: r#"{"schema_version":"0.1.0"}"#.to_owned(),
        source_reports_json: Some(
            reports
                .canonical_json()
                .expect("typed source reports should serialize"),
        ),
        updated_at: "2026-09-03T12:00:00Z".to_owned(),
    };

    let sources = stored_overlay_sources(&stored).expect("strict source reports should decode");
    assert_eq!(
        serde_json::to_value(sources).expect("source response should serialize"),
        json!([{
            "id": "statuses",
            "kind": "enum",
            "state": "resolved",
            "item_count": 3,
            "resolved_at": "2026-09-03T12:00:00Z"
        }])
    );
}

#[test]
fn stored_overlay_source_response_fails_closed_on_invalid_envelopes() {
    for encoded in [
        None,
        Some(r#"{"schema_version":"0.1.0"}"#),
        Some(r#"{"schema_version":"future","sources":[]}"#),
        Some(r#"{"schema_version":"0.1.0","sources":[],"future":true}"#),
    ] {
        let stored = connections::store::StoredOpenApiOverlay {
            connection_id: connections::model::ConnectionId::parse(
                "00000000-0000-0000-0000-000000000360",
            )
            .expect("test connection ID should parse"),
            schema_version: "0.1.0".to_owned(),
            overlay_revision: 1,
            overlay_json: r#"{"schema_version":"0.1.0"}"#.to_owned(),
            source_reports_json: encoded.map(str::to_owned),
            updated_at: "2026-09-03T12:00:00Z".to_owned(),
        };

        let response = stored_overlay_sources(&stored)
            .expect_err("invalid source report envelope must fail closed");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[tokio::test]
async fn managed_openapi_overlay_api_enforces_permissions_etags_and_atomic_validation() {
    let connection_db = TempDb::new("connection-openapi-overlay-api");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = connection_admin_router(&connection_db, &policy, test_audit_log());

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let collection_etag = list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include collection ETag")
        .to_owned();
    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-editor"])),
            Some(managed_openapi_connection_body("Overlay API")),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("managed OpenAPI connection create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let connection_etag = created
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("created connection should include ETag")
        .to_owned();
    let connection_id = json_body(created).await["id"]
        .as_str()
        .expect("created connection should include ID")
        .to_owned();

    let preview_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview");
    let register_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/register");
    let overlay_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/overlay");
    let preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &preview_uri,
            Some(test_principal(&["openapi-tools-reader"])),
            Some(json!({ "spec": widget_openapi_spec() }).to_string()),
            None,
            true,
        ))
        .await
        .expect("managed OpenAPI preview should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = json_body(preview).await;
    let selected_tool_name = preview["tools"][0]["name"]
        .as_str()
        .expect("preview should include a generated tool")
        .to_owned();
    let selected_security_confirmation = preview["security_confirmations"]
        .as_array()
        .and_then(|confirmations| {
            confirmations.iter().find(|confirmation| {
                confirmation["tool_name"].as_str() == Some(selected_tool_name.as_str())
            })
        })
        .cloned()
        .expect("selected tool should include its security confirmation");
    let registered = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &register_uri,
            Some(test_principal(&["openapi-tools-writer"])),
            Some(
                json!({
                    "spec": widget_openapi_spec(),
                    "spec_digest": preview["spec_digest"],
                    "expected_spec_revision": preview["spec_revision"],
                    "expected_catalog_revision": preview["catalog_revision"],
                    "selected_tool_names": [selected_tool_name.clone()],
                    "security_confirmations": [selected_security_confirmation],
                })
                .to_string(),
            ),
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("managed OpenAPI registration should complete");
    assert_eq!(registered.status(), StatusCode::CREATED);
    let registered = json_body(registered).await;
    let registered_catalog_revision = registered["catalog_revision"]
        .as_u64()
        .expect("registration must return the catalog revision");
    let initial_expected_etag =
        format!("\"overlay:{connection_id}:c1:r{registered_catalog_revision}:o0\"");

    let forbidden = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &overlay_uri,
            Some(test_principal(&["connections-observer"])),
            None,
            None,
            false,
        ))
        .await
        .expect("overlay read permission denial should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let initial = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &overlay_uri,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("initial overlay read should complete");
    assert_eq!(initial.status(), StatusCode::OK);
    assert_eq!(
        initial
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(initial_expected_etag.as_str())
    );
    assert_eq!(
        initial
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let initial_etag = initial
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("initial overlay read should include ETag")
        .to_owned();
    let initial = json_body(initial).await;
    assert_eq!(initial["connection_id"], json!(connection_id));
    assert_eq!(initial["overlay_revision"], json!(0));
    assert_eq!(initial["document"], Value::Null);
    assert_eq!(
        initial["applied_catalog_revision"],
        registered["catalog_revision"]
    );
    assert_eq!(initial["sources"], json!([]));

    let missing_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            Some(json!({ "schema_version": "0.1.0" }).to_string()),
            None,
            true,
        ))
        .await
        .expect("missing overlay precondition should complete");
    assert_eq!(
        missing_precondition.status(),
        StatusCode::PRECONDITION_REQUIRED
    );

    let weak_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            Some(json!({ "schema_version": "0.1.0" }).to_string()),
            Some(&format!("W/{initial_etag}")),
            true,
        ))
        .await
        .expect("weak overlay precondition should complete");
    assert_eq!(weak_precondition.status(), StatusCode::BAD_REQUEST);

    let rejected = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            Some(
                json!({
                    "schema_version": "0.1.0",
                    "tools": { "missingGeneratedTool": {} }
                })
                .to_string(),
            ),
            Some(&initial_etag),
            true,
        ))
        .await
        .expect("invalid overlay should complete");
    assert_eq!(rejected.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let rejected = json_body(rejected).await;
    assert_eq!(rejected["warnings"], json!([]));
    assert!(rejected["problems"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));

    // The rejected compile must not have moved either durable resource.
    let after_rejection = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &overlay_uri,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("overlay read after rejection should complete");
    assert_eq!(
        after_rejection
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(initial_etag.as_str())
    );
    assert_eq!(json_body(after_rejection).await["document"], Value::Null);

    let mut tool_overlays = serde_json::Map::new();
    tool_overlays.insert(
        selected_tool_name.clone(),
        json!({
            "rename": "overlay_widget",
            "description": "Widget operation compiled from the overlay.",
            "visibility": "listed"
        }),
    );
    let document = json!({
        "schema_version": "0.1.0",
        "tools": tool_overlays
    });
    let stored = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            Some(document.to_string()),
            Some(&initial_etag),
            true,
        ))
        .await
        .expect("valid overlay should publish");
    assert_eq!(stored.status(), StatusCode::OK);
    assert_eq!(
        stored
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let stored_etag = stored
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("overlay mutation should include ETag")
        .to_owned();
    let stored_catalog_revision = registered_catalog_revision + 1;
    assert_eq!(
        stored_etag,
        format!("\"overlay:{connection_id}:c1:r{stored_catalog_revision}:o1\"")
    );
    let stored = json_body(stored).await;
    assert_eq!(stored["overlay_revision"], json!(1));
    assert_eq!(
        stored["tools"][0]["generated_name"],
        json!(selected_tool_name)
    );
    assert_eq!(stored["tools"][0]["served_name"], json!("overlay_widget"));
    assert_eq!(stored["tools"][0]["visibility"], json!("listed"));
    assert!(stored["catalog_revision"]
        .as_u64()
        .is_some_and(|revision| { revision == stored_catalog_revision }));

    let read_back = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &overlay_uri,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("stored overlay read should complete");
    assert_eq!(
        read_back
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(stored_etag.as_str())
    );
    let read_back = json_body(read_back).await;
    assert_eq!(read_back["overlay_revision"], json!(1));
    assert_eq!(read_back["document"], document);
    assert_eq!(
        read_back["applied_catalog_revision"],
        stored["catalog_revision"]
    );

    let stale = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            Some(json!({ "schema_version": "0.1.0" }).to_string()),
            Some(&initial_etag),
            true,
        ))
        .await
        .expect("stale overlay write should complete");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        stale
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(stored_etag.as_str())
    );

    let missing_delete_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            None,
            None,
            true,
        ))
        .await
        .expect("missing overlay delete precondition should complete");
    assert_eq!(
        missing_delete_precondition.status(),
        StatusCode::PRECONDITION_REQUIRED
    );

    let deleted = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &overlay_uri,
            Some(test_principal(&["connections-editor"])),
            None,
            Some(&stored_etag),
            true,
        ))
        .await
        .expect("overlay delete should complete");
    assert_eq!(deleted.status(), StatusCode::OK);
    let deleted_catalog_revision = stored_catalog_revision + 1;
    let deleted_etag = format!("\"overlay:{connection_id}:c1:r{deleted_catalog_revision}:o0\"");
    assert_eq!(
        deleted
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(deleted_etag.as_str())
    );
    let deleted = json_body(deleted).await;
    assert_eq!(deleted["overlay_revision"], json!(0));
    assert_eq!(deleted["tools"], json!([]));

    let final_read = router
        .oneshot(connection_admin_request(
            Method::GET,
            &overlay_uri,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("deleted overlay read should complete");
    assert_eq!(final_read.status(), StatusCode::OK);
    let final_read = json_body(final_read).await;
    assert_eq!(final_read["overlay_revision"], json!(0));
    assert_eq!(final_read["document"], Value::Null);
    assert_eq!(
        final_read["applied_catalog_revision"],
        deleted["catalog_revision"]
    );
}

#[tokio::test]
async fn mcp_refresh_errors_expose_bounded_upstream_diagnostics() {
    for (error, reason, method, code) in [
        (
            connections::mcp::McpCatalogRefreshError::UpstreamMethodNotFound {
                method: "tools/list",
            },
            "upstream_method_not_found",
            "tools/list",
            -32601,
        ),
        (
            connections::mcp::McpCatalogRefreshError::UpstreamError {
                method: "resources/list",
                code: -32000,
            },
            "upstream_error",
            "resources/list",
            -32000,
        ),
    ] {
        let failure = ConnectionRefreshFailure::mcp(error);
        assert_eq!(failure.reason, reason);
        assert_eq!(failure.upstream_method, Some(method));
        assert_eq!(failure.upstream_error_code, Some(code));

        let response = connection_refresh_error_response(error);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = json_body(response).await;
        assert_eq!(body["reason"], json!(reason));
        assert_eq!(body["upstream_method"], json!(method));
        assert_eq!(body["upstream_error_code"], json!(code));
        assert!(
            !body.to_string().contains("bounded upstream error"),
            "upstream messages must not cross the safe response boundary"
        );
    }
}

#[tokio::test]
async fn caller_assertion_refusals_are_conflicts_with_their_own_reason() {
    // A Connection that cannot yet attest its caller is a state the operator
    // must change, like a disabled one, not an upstream failure to retry.
    let response = connection_refresh_error_response(
        connections::mcp::McpCatalogRefreshError::CallerAssertionNotEnforced,
    );
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = json_body(response).await;
    assert_eq!(body["reason"], json!("caller_assertion_not_enforced"));

    for operation in ["preview", "register", "refresh"] {
        let response = openapi_catalog_error_response(
            connections::openapi::OpenApiCatalogError::CallerAssertionNotEnforced,
            operation,
        );
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = json_body(response).await;
        assert_eq!(body["reason"], json!("caller_assertion_not_enforced"));
    }
}

/// A caller assertion as an operator would send one. Saving it loads the key
/// behind its alias, which [`attested_connection_admin_router`] provides;
/// nothing these tests drive signs with it: a catalog operation makes no
/// call for a caller, and the discovery ones refuse the Connection first.
fn admin_caller_assertion_json() -> Value {
    json!({
        "signing_key_id": "assertion-signing-key",
        "kid": "gw-test-1",
        "algorithm": "es256",
        "issuer": "https://gateway.example.test",
        "audience": "https://openapi.example.test",
        "token_type": "at+jwt",
        "header_name": "x-caller-assertion",
        "lifetime_seconds": 60,
        "claims": ["email"],
        "bind_request": true
    })
}

/// Create `body` with a caller assertion through the admin API, returning
/// the new Connection's ID and ETag. Binding a caller assertion binds secret
/// material, so the creator holds secrets-write as well.
async fn create_attested_connection(router: &Router, mut body: Value) -> (String, String) {
    body["caller_assertion"] = admin_caller_assertion_json();
    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let collection_etag = list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include collection ETag")
        .to_owned();
    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-secrets-editor"])),
            Some(body.to_string()),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("attested connection create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let etag = created
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("created connection should include ETag")
        .to_owned();
    let id = json_body(created).await["id"]
        .as_str()
        .expect("created connection should include ID")
        .to_owned();
    (id, etag)
}

#[tokio::test]
async fn attested_connection_catalog_discovery_is_a_conflict_over_http() {
    // A catalog registered from an uploaded specification is served on an
    // attested Connection, because its tools sign the assertion. Discovery,
    // which has no caller to attest, reaches an admin client as a 409 naming
    // the reason and is audited with it, through the real handlers rather
    // than only the error mappers.
    let connection_db = TempDb::new("connection-caller-assertion-catalogs");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = attested_connection_admin_router(&connection_db, &policy, audit_log);

    let mut openapi_body: Value =
        serde_json::from_str(&managed_openapi_connection_body("Attested OpenAPI"))
            .expect("managed OpenAPI body should parse");
    // A refresh fetches the specification from this path: discovery.
    openapi_body["discovery"]["path"] = json!("/openapi.json");
    let (openapi_id, openapi_etag) = create_attested_connection(&router, openapi_body).await;
    let spec = widget_openapi_spec();

    let preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{openapi_id}/openapi/preview"),
            Some(test_principal(&["openapi-tools-reader"])),
            Some(json!({ "spec": spec }).to_string()),
            None,
            true,
        ))
        .await
        .expect("attested preview should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = json_body(preview).await;
    let selected_tool_name = preview["tools"][0]["name"]
        .as_str()
        .expect("preview should include a generated tool")
        .to_owned();
    let selected_security_confirmation = preview["security_confirmations"]
        .as_array()
        .and_then(|confirmations| {
            confirmations.iter().find(|confirmation| {
                confirmation["tool_name"].as_str() == Some(selected_tool_name.as_str())
            })
        })
        .cloned()
        .expect("selected tool should include an exact security confirmation");

    let register = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{openapi_id}/openapi/register"),
            Some(test_principal(&["openapi-tools-writer"])),
            Some(
                json!({
                    "spec": spec,
                    "spec_digest": preview["spec_digest"],
                    "expected_spec_revision": preview["spec_revision"],
                    "expected_catalog_revision": preview["catalog_revision"],
                    "selected_tool_names": [selected_tool_name],
                    "security_confirmations": [selected_security_confirmation],
                })
                .to_string(),
            ),
            Some(&openapi_etag),
            true,
        ))
        .await
        .expect("attested register should complete");
    assert_eq!(register.status(), StatusCode::CREATED);
    assert_eq!(json_body(register).await["total_count"], json!(1));

    let openapi_refresh = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{openapi_id}/refresh"),
            Some(test_principal(&["connections-refresher"])),
            None,
            Some(&openapi_etag),
            true,
        ))
        .await
        .expect("attested OpenAPI refresh should complete");
    assert_eq!(openapi_refresh.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(openapi_refresh).await["reason"],
        json!("caller_assertion_not_enforced")
    );

    let (mcp_id, mcp_etag) = create_attested_connection(
        &router,
        json!({
            "display_name": "Attested MCP",
            "enabled": true,
            "kind": "mcp_streamable_http",
            "endpoint": {
                "base_url": "https://mcp.example.test",
                "base_path": "/mcp"
            },
            "authentication": { "type": "none" },
            "discovery": {
                "type": "managed_mcp",
                "use_connection_authentication": false
            }
        }),
    )
    .await;
    let mcp_refresh = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{mcp_id}/refresh"),
            Some(test_principal(&["connections-refresher"])),
            None,
            Some(&mcp_etag),
            true,
        ))
        .await
        .expect("attested MCP refresh should complete");
    assert_eq!(mcp_refresh.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(mcp_refresh).await["reason"],
        json!("caller_assertion_not_enforced")
    );

    let refused = |event: &audit::AuditEvent, id: &str| {
        event.payload["connection_id"] == json!(id)
            && event.payload["outcome"] == json!("failure")
            && event.payload["reason"] == json!("caller_assertion_not_enforced")
    };
    assert_eventually(Duration::from_secs(1), || {
        let events = capture.events();
        [&openapi_id, &mcp_id].into_iter().all(|id| {
            events.iter().any(|event| {
                event.event_type == audit::event::CONNECTION_REFRESHED
                    && refused(event, id.as_str())
            })
        })
    });
    assert!(capture.events().iter().all(|event| {
        event.payload["action"] != json!("managed_openapi_catalog_registration_rejected")
    }));
}

#[tokio::test]
async fn a_save_to_domain_wide_delegation_withdraws_the_openapi_catalog_and_audits_it() {
    // Through the real handlers: a save that switches a managed OpenAPI
    // Connection to domain-wide delegation takes its live catalog off the
    // tool list and records why, and registering a catalog on it is a 409
    // naming the reason, audited, rather than the binding mismatch it used
    // to look like.
    let connection_db = TempDb::new("connection-openapi-domain-wide-delegation");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let mut config = connection_admin_config(&connection_db, &policy, config::DEFAULT_ADMIN_PREFIX);
    // Saving an enabled delegating Connection checks only that the profile
    // is configured; nothing here reads its token file.
    config.connection_gcp_provider.profiles = vec![connections::gcp_secret::GcpProfileConfig {
        id: "gateway-wif".to_owned(),
        audience: "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gateway-pool/providers/gateway-provider".to_owned(),
        token_root: connection_db
            .path
            .with_extension("secrets")
            .display()
            .to_string(),
        token_file: "gcp-token".to_owned(),
        service_account: None,
    }];
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("delegation connection admin app should build");

    let display_name = "Workspace widgets";
    let (connection_id, connection_etag) =
        create_managed_openapi_connection(&router, display_name).await;
    let spec = widget_openapi_spec();
    let registered = preview_and_register_managed_openapi(
        &router,
        &connection_id,
        &connection_etag,
        spec,
        &["createWidget"],
    )
    .await;
    assert_eq!(registered.status(), StatusCode::CREATED);
    let preview_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview");
    let preview = |router: Router| {
        let request = connection_admin_request(
            Method::POST,
            &preview_uri,
            Some(test_principal(&["openapi-tools-reader"])),
            Some(json!({ "spec": spec }).to_string()),
            None,
            true,
        );
        async move {
            router
                .oneshot(request)
                .await
                .expect("managed OpenAPI preview should complete")
        }
    };
    let previewed = preview(router.clone()).await;
    assert_eq!(previewed.status(), StatusCode::OK);
    let previewed = json_body(previewed).await;

    let mut delegating: Value =
        serde_json::from_str(&managed_openapi_connection_body(display_name))
            .expect("managed OpenAPI body should parse");
    delegating["authentication"] = json!({
        "type": "google_domain_wide_delegation",
        "service_account_email": "gateway-delegate@example-project.iam.gserviceaccount.com",
        "workload_identity_profile": "gateway-wif",
        "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
        "subject_claim": "email",
        "subject_issuers": ["https://idp.example.test/"]
    });
    let saved = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}"),
            Some(test_principal(&["connections-secrets-editor"])),
            Some(delegating.to_string()),
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("delegation save should complete");
    assert_eq!(saved.status(), StatusCode::OK);
    let saved_etag = saved
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("saved connection should include ETag")
        .to_owned();

    let withdrawn = captured_tool_registry_change(&capture, "managed_openapi_catalog_withdrawn");
    assert_eq!(withdrawn.payload["connection_id"], json!(connection_id));
    assert_eq!(withdrawn.payload["source"], json!("managed"));
    assert_eq!(withdrawn.payload["outcome"], json!("success"));
    assert_eq!(
        withdrawn.payload["reason"],
        json!("authentication_not_supported")
    );
    assert_eq!(
        withdrawn.payload["withdrawn_tool_names"],
        json!(["createWidget"])
    );
    assert_eq!(withdrawn.payload["withdrawn_tool_count"], json!(1));
    assert_eq!(
        withdrawn.actor.as_ref().map(|actor| actor.user_id.as_str()),
        Some("user-123")
    );

    let assert_refused = |status: StatusCode, body: &Value, write: &str| {
        assert_eq!(status, StatusCode::CONFLICT, "{write}: {body}");
        assert_eq!(
            body["reason"],
            json!("authentication_not_supported"),
            "{write}: {body}"
        );
    };
    let refused = preview(router.clone()).await;
    let status = refused.status();
    assert_refused(status, &json_body(refused).await, "preview");

    let refused = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/register"),
            Some(test_principal(&["openapi-tools-writer"])),
            Some(
                json!({
                    "spec": spec,
                    "spec_digest": previewed["spec_digest"],
                    "expected_spec_revision": previewed["spec_revision"],
                    "expected_catalog_revision": previewed["catalog_revision"],
                    "selected_tool_names": ["createWidget"],
                    "security_confirmations": [],
                })
                .to_string(),
            ),
            Some(&saved_etag),
            true,
        ))
        .await
        .expect("delegation registration should complete");
    let status = refused.status();
    assert_refused(status, &json_body(refused).await, "registration");
    let rejected =
        captured_tool_registry_change(&capture, "managed_openapi_catalog_registration_rejected");
    assert_eq!(rejected.payload["connection_id"], json!(connection_id));
    assert_eq!(rejected.payload["outcome"], json!("failure"));
    assert_eq!(
        rejected.payload["reason"],
        json!("authentication_not_supported")
    );

    let refused = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/refresh"),
            Some(test_principal(&["connections-refresher"])),
            None,
            Some(&saved_etag),
            true,
        ))
        .await
        .expect("delegation refresh should complete");
    let status = refused.status();
    assert_refused(status, &json_body(refused).await, "refresh");
}

#[tokio::test]
async fn a_routine_admin_ui_save_keeps_the_caller_assertion_byte_for_byte() {
    // The admin UI shows the block read only and never sends it. Its save is
    // the safe read written back without `caller_assertion`; the gateway has
    // to come back with the same block, byte for byte.
    let connection_db = TempDb::new("connection-caller-assertion-ui-save");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = attested_connection_admin_router(&connection_db, &policy, test_audit_log());
    let connection_body: Value =
        serde_json::from_str(&managed_openapi_connection_body("Attested API"))
            .expect("managed OpenAPI body should parse");
    let (id, etag) = create_attested_connection(&router, connection_body).await;
    let uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{id}");

    let read = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &uri,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("attested connection read should complete");
    assert_eq!(read.status(), StatusCode::OK);
    let read = json_body(read).await;
    let stored = read["configuration"]["caller_assertion"].clone();
    assert_eq!(stored["signing_key_configured"], json!(true));
    assert_eq!(stored["kid"], json!("gw-test-1"));
    assert!(
        !read.to_string().contains("assertion-signing-key"),
        "the safe read must not name the signing key alias"
    );

    // Exactly what the editor's `writeFromForm` sends for this Connection
    // after a rename.
    let mut ui_save = json!({
        "display_name": "Attested API renamed",
        "enabled": read["enabled"],
        "kind": read["kind"],
        "endpoint": read["configuration"]["endpoint"],
        "authentication": read["configuration"]["authentication"],
        "tls": {},
        "discovery": read["configuration"]["discovery"],
    });
    assert!(ui_save.get("caller_assertion").is_none());
    let saved = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &uri,
            Some(test_principal(&["connections-editor"])),
            Some(ui_save.to_string()),
            Some(&etag),
            true,
        ))
        .await
        .expect("admin UI save should complete");
    assert_eq!(saved.status(), StatusCode::OK);
    let saved_etag = saved
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("saved connection should include ETag")
        .to_owned();
    let saved = json_body(saved).await;
    assert_eq!(saved["display_name"], json!("Attested API renamed"));
    assert_eq!(
        serde_json::to_string(&saved["configuration"]["caller_assertion"])
            .expect("saved block should serialize"),
        serde_json::to_string(&stored).expect("stored block should serialize"),
    );

    let reread = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &uri,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("attested connection reread should complete");
    let reread = json_body(reread).await;
    assert_eq!(
        serde_json::to_string(&reread["configuration"]["caller_assertion"])
            .expect("reread block should serialize"),
        serde_json::to_string(&stored).expect("stored block should serialize"),
    );

    // The same body with an explicit `null` is the deliberate removal the
    // admin UI never sends. It withdraws the Connection's keys from the JWKS
    // and lifts its refusal, so like any change to the block it needs
    // secrets-write: the editor that could rename the Connection cannot.
    ui_save["caller_assertion"] = Value::Null;
    let refused = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &uri,
            Some(test_principal(&["connections-editor"])),
            Some(ui_save.to_string()),
            Some(&saved_etag),
            true,
        ))
        .await
        .expect("explicit removal without secrets-write should complete");
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let removed = router
        .oneshot(connection_admin_request(
            Method::PUT,
            &uri,
            Some(test_principal(&["connections-secrets-editor"])),
            Some(ui_save.to_string()),
            Some(&saved_etag),
            true,
        ))
        .await
        .expect("explicit removal should complete");
    assert_eq!(removed.status(), StatusCode::OK);
    assert!(json_body(removed).await["configuration"]
        .get("caller_assertion")
        .is_none());
}

#[tokio::test]
async fn connection_refresh_requires_permission_empty_body_and_exact_etag() {
    let connection_db = TempDb::new("connection-refresh-guards");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = connection_admin_router(&connection_db, &policy, audit_log);

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let collection_etag = list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include collection ETag")
        .to_owned();
    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-editor"])),
            Some(plain_connection_body("Refresh guard target")),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("connection create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let connection_etag = created
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("created connection should include ETag")
        .to_owned();
    let connection_id = json_body(created).await["id"]
        .as_str()
        .expect("created connection should include ID")
        .to_owned();
    let refresh_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/refresh");

    let forbidden = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &refresh_uri,
            Some(test_principal(&["connections-editor"])),
            None,
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("refresh permission denial should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let missing = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &refresh_uri,
            Some(test_principal(&["connections-refresher"])),
            None,
            None,
            true,
        ))
        .await
        .expect("missing refresh precondition should complete");
    assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);

    let stale = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &refresh_uri,
            Some(test_principal(&["connections-refresher"])),
            None,
            Some("\"connection:stale\""),
            true,
        ))
        .await
        .expect("stale refresh precondition should complete");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);

    let non_empty = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &refresh_uri,
            Some(test_principal(&["connections-refresher"])),
            Some("{}".to_owned()),
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("non-empty refresh request should complete");
    assert_eq!(non_empty.status(), StatusCode::BAD_REQUEST);

    let wrong_kind = router
        .oneshot(connection_admin_request(
            Method::POST,
            &refresh_uri,
            Some(test_principal(&["connections-refresher"])),
            None,
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("wrong-kind refresh should complete");
    assert_eq!(wrong_kind.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(wrong_kind).await["reason"],
        json!("discovery_not_configured")
    );
    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::CONNECTION_REFRESHED
                && event.payload["outcome"] == json!("failure")
                && event.payload["reason"] == json!("discovery_not_configured")
        })
    });
}

#[tokio::test]
async fn connection_test_requires_permission_saved_profile_and_exact_etag() {
    let connection_db = TempDb::new("connection-test-guards");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = connection_admin_router(&connection_db, &policy, audit_log);

    let unauthorized = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            "/v1/admin/connections/00000000-0000-0000-0000-000000000001/test",
            None,
            None,
            Some("\"connection:unknown\""),
            true,
        ))
        .await
        .expect("unauthorized connection test should complete");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let forbidden_unknown = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            "/v1/admin/connections/00000000-0000-0000-0000-000000000001/test",
            Some(test_principal(&["connections-editor"])),
            None,
            Some("\"connection:unknown\""),
            true,
        ))
        .await
        .expect("forbidden connection test should complete");
    assert_eq!(
        forbidden_unknown.status(),
        StatusCode::FORBIDDEN,
        "authorization must run before connection lookup"
    );

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let collection_etag = list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include collection ETag")
        .to_owned();
    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-editor"])),
            Some(testable_connection_body("Disabled test target", false)),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("testable connection create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let connection_etag = created
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("created connection should include ETag")
        .to_owned();
    let connection_id = json_body(created).await["id"]
        .as_str()
        .expect("created connection should include ID")
        .to_owned();
    let test_uri = format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/test");

    let forbidden = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &test_uri,
            Some(test_principal(&["connections-editor"])),
            None,
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("connection test permission denial should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let missing = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &test_uri,
            Some(test_principal(&["connections-tester"])),
            None,
            None,
            true,
        ))
        .await
        .expect("missing connection test precondition should complete");
    assert_eq!(missing.status(), StatusCode::PRECONDITION_REQUIRED);

    let stale = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &test_uri,
            Some(test_principal(&["connections-tester"])),
            None,
            Some("\"connection:stale\""),
            true,
        ))
        .await
        .expect("stale connection test precondition should complete");
    assert_eq!(stale.status(), StatusCode::PRECONDITION_FAILED);

    let non_empty = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &test_uri,
            Some(test_principal(&["connections-tester"])),
            Some("{}".to_owned()),
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("non-empty connection test should complete");
    assert_eq!(non_empty.status(), StatusCode::BAD_REQUEST);
    let router = connection_admin_router(
        &connection_db,
        &policy,
        audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>),
    );

    let tested = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &test_uri,
            Some(test_principal(&["connections-tester"])),
            None,
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("saved-profile connection test should complete");
    assert_eq!(tested.status(), StatusCode::OK);
    let tested_etag = tested
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("tested connection should return its post-status ETag")
        .to_owned();
    assert_eq!(
        tested_etag, connection_etag,
        "test status persistence must not advance the config mutation ETag"
    );
    assert_eq!(
        tested
            .headers()
            .get(header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let tested = json_body(tested).await;
    assert_eq!(tested["ok"], json!(false));
    assert_eq!(tested["state"], json!("unavailable"));
    assert_eq!(tested["stages"][0]["name"], json!("egress_policy"));
    assert_eq!(tested["stages"][0]["outcome"], json!("failure"));
    assert_eq!(tested["stages"][0]["reason"], json!("host_not_allowed"));
    assert!(
        !tested.to_string().contains("blocked-test-target"),
        "test response must not expose the saved destination"
    );

    let rate_limited = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &test_uri,
            Some(test_principal(&["connections-tester"])),
            None,
            Some(&tested_etag),
            true,
        ))
        .await
        .expect("rate-limited connection test should complete");
    assert_eq!(rate_limited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        json_body(rate_limited).await["reason"],
        json!("test_rate_limited")
    );

    let detail = router
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}"),
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("tested connection detail should complete");
    assert_eq!(detail.status(), StatusCode::OK);
    assert_eq!(
        detail
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(tested_etag.as_str())
    );
    let detail = json_body(detail).await;
    assert_eq!(detail["status"]["state"], json!("unavailable"));
    assert_eq!(detail["status"]["reason"], json!("egress_denied"));

    assert_eventually(Duration::from_secs(1), || {
        let events = capture.events();
        events.iter().any(|event| {
            event.event_type == audit::event::CONNECTION_TESTED
                && event.payload["outcome"] == json!("failure")
                && event.payload["reason"] == json!("host_not_allowed")
                && !event.payload.to_string().contains("blocked-test-target")
        }) && events.iter().any(|event| {
            event.event_type == audit::event::CONNECTION_TESTED
                && event.payload["outcome"] == json!("rejected")
                && event.payload["reason"] == json!("test_rate_limited")
        }) && events.iter().any(|event| {
            event.event_type == "authz.denied"
                && event.payload["permission"] == json!(ADMIN_CONNECTIONS_TEST_PERMISSION)
                && event.payload["operation"] == json!("test")
        })
    });
}

/// A stored test of a `delegated_issuer_token` Connection runs as the
/// principal who asks for it (issue #441): the endpoint attests that
/// principal, so one an issuer could not look up is refused as naming nobody,
/// and an attestable one gets as far as the key check, which refuses a
/// disabled Connection because its keys are not published. Both are refused
/// before any network or secret I/O.
#[tokio::test]
async fn a_delegated_connection_test_runs_as_the_requesting_principal() {
    let connection_db = TempDb::new("connection-test-delegated");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = connection_admin_router(&connection_db, &policy, audit_log);
    let secrets_editor = test_principal(&["connections-secrets-editor"]);
    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(secrets_editor.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let mut collection_etag = list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include collection ETag")
        .to_owned();
    let mut assertion = admin_caller_assertion_json();
    assertion["bind_request"] = json!(false);
    assertion["audience"] = json!("https://issuer.example.test");
    // One Connection per tester: the per-Connection test budget admits one
    // test at a time.
    let mut created_connections = Vec::new();
    for display_name in ["Mail for nobody", "Mail for alice"] {
        let created = router
            .clone()
            .oneshot(connection_admin_request(
                Method::POST,
                CONNECTIONS_ADMIN_ROUTE,
                Some(secrets_editor.clone()),
                Some(
                    json!({
                        "display_name": display_name,
                        "enabled": false,
                        "kind": "http_api",
                        "endpoint": {
                            "base_url": "https://mail.example.test",
                            "base_path": "/v1"
                        },
                        "authentication": {
                            "type": "delegated_issuer_token",
                            "token_exchange_url": "https://issuer.example.test/oauth2/token-exchange",
                            "client_id": "greengateway",
                            "client_secret_id": "issuer-exchange-secret",
                            "subject_token_source": "caller_assertion"
                        },
                        "caller_assertion": assertion,
                        "test_profile": {
                            "method": "GET",
                            "path": "/messages",
                            "expected_statuses": [200]
                        }
                    })
                    .to_string(),
                ),
                Some(&collection_etag),
                true,
            ))
            .await
            .expect("delegated create should complete");
        assert_eq!(created.status(), StatusCode::CREATED);
        collection_etag = created
            .headers()
            .get(CONNECTION_COLLECTION_ETAG_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("created connection should include collection ETag")
            .to_owned();
        let etag = created
            .headers()
            .get(header::ETAG)
            .and_then(|value| value.to_str().ok())
            .expect("created connection should include ETag")
            .to_owned();
        let id = json_body(created).await["id"]
            .as_str()
            .expect("created connection should include ID")
            .to_owned();
        created_connections.push((id, etag));
    }

    // `test_principal` has no identity-provider issuer, so no issuer could
    // look its subject up; the same principal with one is attestable.
    let nobody = test_principal(&["connections-tester"]);
    let alice = auth::Principal {
        issuer: Some("https://idp.example.test".to_owned()),
        ..test_principal(&["connections-tester"])
    };
    for ((id, etag), tester, stage, reason) in [
        (
            &created_connections[0],
            nobody,
            "secret_available",
            "delegated_token_no_principal",
        ),
        (
            &created_connections[1],
            alice,
            "authenticated",
            "caller_assertion_key_not_published",
        ),
    ] {
        let tested = router
            .clone()
            .oneshot(connection_admin_request(
                Method::POST,
                &format!("{CONNECTIONS_ADMIN_ROUTE}/{id}/test"),
                Some(tester),
                None,
                Some(etag),
                true,
            ))
            .await
            .expect("delegated connection test should complete");
        assert_eq!(tested.status(), StatusCode::OK);
        let tested = json_body(tested).await;
        assert_eq!(tested["ok"], json!(false));
        assert_eq!(
            tested["stages"],
            json!([{ "name": stage, "outcome": "failure", "reason": reason }])
        );
    }

    assert_eventually(Duration::from_secs(1), || {
        let events = capture.events();
        [
            "delegated_token_no_principal",
            "caller_assertion_key_not_published",
        ]
        .iter()
        .all(|reason| {
            events.iter().any(|event| {
                event.event_type == audit::event::CONNECTION_TESTED
                    && event.payload["outcome"] == json!("failure")
                    && event.payload["reason"] == json!(reason)
                    && event.payload["authentication"] == json!("delegated_issuer_token")
            })
        })
    });
    // Nothing was exchanged: both tests stopped before the issuer.
    assert!(!capture
        .events()
        .iter()
        .any(|event| event.event_type == audit::event::CONNECTION_DELEGATED_TOKEN_EXCHANGE));
}

#[tokio::test]
async fn connection_test_body_reader_deadline_bounds_slow_clients() {
    let body = Body::from_stream(stream::pending::<Result<Bytes, Infallible>>());
    let result = read_request_body_before(
        body,
        1024,
        tokio::time::Instant::now() + Duration::from_millis(10),
    )
    .await;

    assert!(matches!(result, Err(TimedBodyReadError::DeadlineExceeded)));
}

#[test]
fn connection_test_status_persistence_errors_use_closed_accurate_reasons() {
    let changed = connections::control_plane::ConnectionMutationError::Store(
        connections::store::ConnectionStoreError::NotFound {
            id: "opaque-connection".to_owned(),
        },
    );
    assert_eq!(
        connection_test_status_persistence_reason(&changed),
        connections::test::ConnectionTestReason::ConnectionChanged
    );

    let unavailable = connections::control_plane::ConnectionMutationError::Unavailable(
        connections::control_plane::ManagedConnectionMutationUnavailable,
    );
    assert_eq!(
        connection_test_status_persistence_reason(&unavailable),
        connections::test::ConnectionTestReason::InternalError
    );

    let deadline = connections::control_plane::ConnectionMutationError::Store(
        connections::store::ConnectionStoreError::DeadlineExceeded {
            operation: "connection status persistence",
        },
    );
    assert_eq!(
        connection_test_status_persistence_reason(&deadline),
        connections::test::ConnectionTestReason::DeadlineExceeded
    );
    assert!(connection_test_status_persistence_deadline_exceeded(
        &deadline
    ));
    assert!(!connection_test_status_persistence_deadline_exceeded(
        &unavailable
    ));
}

#[tokio::test]
async fn connection_admin_crud_enforces_etags_secret_authority_and_redaction() {
    let connection_db = TempDb::new("connection-admin-crud");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let router = connection_admin_router(&connection_db, &policy, audit_log);
    let reader = test_principal(&["connections-reader"]);
    let editor = test_principal(&["connections-editor"]);
    // Vouched for by an issuer, written the way a token may carry it, so the
    // change evidence below shows the endpoints pass the whole principal.
    let secrets_editor = auth::Principal {
        issuer: Some(" https://idp.example.test/ ".to_owned()),
        ..test_principal(&["connections-secrets-editor"])
    };

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(reader.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    assert_eq!(list.status(), StatusCode::OK);
    let collection_etag = list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("collection response should include an ETag")
        .to_owned();
    assert_eq!(json_body(list).await["connections"], json!([]));

    let missing_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(editor.clone()),
            Some(plain_connection_body("Billing API")),
            None,
            true,
        ))
        .await
        .expect("missing precondition request should complete");
    assert_eq!(
        missing_precondition.status(),
        StatusCode::PRECONDITION_REQUIRED
    );

    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(editor.clone()),
            Some(plain_connection_body("Billing API")),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("connection create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let plain_etag = created
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("created connection should include an ETag")
        .to_owned();
    let after_create_etag = created
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("create should include the new collection ETag")
        .to_owned();
    assert_ne!(collection_etag, after_create_etag);
    let created_body = json_body(created).await;
    let plain_id = created_body["id"]
        .as_str()
        .expect("created connection should include an ID")
        .to_owned();
    assert_eq!(
        created_body["configuration"]["authentication"]["type"],
        json!("none")
    );

    let stale_create = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(editor.clone()),
            Some(plain_connection_body("Stale create")),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("stale create should complete");
    assert_eq!(stale_create.status(), StatusCode::PRECONDITION_FAILED);
    assert_managed_admin_no_store(&stale_create);

    let detail = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{plain_id}"),
            Some(reader.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("connection detail should complete");
    assert_eq!(detail.status(), StatusCode::OK);
    let detail_body = json_body(detail).await;
    assert_eq!(detail_body["actions"]["can_update"], json!(false));
    assert_eq!(detail_body["actions"]["can_bind_secret"], json!(false));

    let updated = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{plain_id}"),
            Some(editor.clone()),
            Some(plain_connection_body("Billing API renamed")),
            Some(&plain_etag),
            true,
        ))
        .await
        .expect("connection update should complete");
    assert_eq!(updated.status(), StatusCode::OK);
    let updated_etag = updated
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("updated connection should include an ETag")
        .to_owned();
    let after_update_collection_etag = updated
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("update should include the collection ETag")
        .to_owned();
    assert_ne!(plain_etag, updated_etag);
    assert_eq!(
        json_body(updated).await["display_name"],
        json!("Billing API renamed")
    );

    let forbidden_credential_create = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(editor.clone()),
            Some(credentialed_connection_body()),
            Some(&after_update_collection_etag),
            true,
        ))
        .await
        .expect("credential create denial should complete");
    assert_eq!(forbidden_credential_create.status(), StatusCode::FORBIDDEN);
    assert!(!body_string(forbidden_credential_create)
        .await
        .contains("credential-secret-id-canary"));

    let credentialed = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(secrets_editor.clone()),
            Some(credentialed_connection_body()),
            Some(&after_update_collection_etag),
            true,
        ))
        .await
        .expect("credentialed connection create should complete");
    assert_eq!(credentialed.status(), StatusCode::CREATED);
    let mut credentialed_etag = credentialed
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("credentialed connection should include an ETag")
        .to_owned();
    let credentialed_body_string = body_string(credentialed).await;
    assert!(!credentialed_body_string.contains("credential-secret-id-canary"));
    let credentialed_body: Value = serde_json::from_str(&credentialed_body_string)
        .expect("credentialed response should be JSON");
    assert_eq!(
        credentialed_body["configuration"]["authentication"]["secret_configured"],
        json!(true)
    );
    let credentialed_id = credentialed_body["id"]
        .as_str()
        .expect("credentialed connection should include an ID")
        .to_owned();
    let initial_credential_revision = credentialed_body["revisions"]["credential"]
        .as_u64()
        .expect("credentialed connection should include a credential revision");

    let explicit_current_binding = credentialed_connection_body();
    let mut explicit_wrong_binding: Value =
        serde_json::from_str(&explicit_current_binding).expect("credentialed body should parse");
    explicit_wrong_binding["authentication"]["secret_id"] = json!("different-secret-id-canary");
    let explicit_wrong_binding = explicit_wrong_binding.to_string();
    let mut explicit_null_binding: Value =
        serde_json::from_str(&explicit_current_binding).expect("credentialed body should parse");
    explicit_null_binding["authentication"]["secret_id"] = Value::Null;
    let explicit_null_binding = explicit_null_binding.to_string();
    let mut explicit_binding_denial_bodies = Vec::new();
    for explicit_binding in [
        explicit_current_binding,
        explicit_wrong_binding,
        explicit_null_binding,
    ] {
        let response = router
            .clone()
            .oneshot(connection_admin_request(
                Method::PUT,
                &format!("{CONNECTIONS_ADMIN_ROUTE}/{credentialed_id}"),
                Some(editor.clone()),
                Some(explicit_binding),
                Some(&credentialed_etag),
                true,
            ))
            .await
            .expect("explicit hidden-binding denial should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        explicit_binding_denial_bodies.push(body_string(response).await);
    }
    assert!(explicit_binding_denial_bodies
        .iter()
        .all(|body| body == &explicit_binding_denial_bodies[0]));

    let credentialed_detail = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{credentialed_id}"),
            Some(editor.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("credentialed detail should complete");
    assert_eq!(credentialed_detail.status(), StatusCode::OK);
    let credentialed_detail = json_body(credentialed_detail).await;
    assert_eq!(credentialed_detail["actions"]["can_update"], json!(true));
    assert_eq!(
        credentialed_detail["actions"]["can_bind_secret"],
        json!(false)
    );
    let presentation_update = json!({
        "display_name": "Credentialed billing API renamed",
        "enabled": credentialed_detail["enabled"].clone(),
        "kind": credentialed_detail["kind"].clone(),
        "endpoint": credentialed_detail["configuration"]["endpoint"].clone(),
        "authentication": credentialed_detail["configuration"]["authentication"].clone(),
        "tls": credentialed_detail["configuration"]["tls"].clone()
    })
    .to_string();
    let presentation_updated = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{credentialed_id}"),
            Some(editor.clone()),
            Some(presentation_update),
            Some(&credentialed_etag),
            true,
        ))
        .await
        .expect("presentation-only credentialed update should complete");
    assert_eq!(presentation_updated.status(), StatusCode::OK);
    credentialed_etag = presentation_updated
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("presentation update should include an ETag")
        .to_owned();
    let presentation_updated_body = body_string(presentation_updated).await;
    assert!(!presentation_updated_body.contains("credential-secret-id-canary"));
    assert!(!presentation_updated_body.contains("credential-material-value-canary"));
    let presentation_updated_body: Value = serde_json::from_str(&presentation_updated_body)
        .expect("presentation update should return JSON");
    assert_eq!(
        presentation_updated_body["revisions"]["credential"],
        json!(initial_credential_revision)
    );

    let test_target_update = json!({
        "display_name": presentation_updated_body["display_name"].clone(),
        "enabled": presentation_updated_body["enabled"].clone(),
        "kind": presentation_updated_body["kind"].clone(),
        "endpoint": presentation_updated_body["configuration"]["endpoint"].clone(),
        "authentication": presentation_updated_body["configuration"]["authentication"].clone(),
        "tls": presentation_updated_body["configuration"]["tls"].clone(),
        "test_profile": {
            "method": "GET",
            "path": "/credentialed-health",
            "expected_statuses": [200]
        }
    })
    .to_string();
    let forbidden_test_target_update = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{credentialed_id}"),
            Some(editor.clone()),
            Some(test_target_update.clone()),
            Some(&credentialed_etag),
            true,
        ))
        .await
        .expect("credentialed test-target denial should complete");
    assert_eq!(forbidden_test_target_update.status(), StatusCode::FORBIDDEN);

    let allowed_test_target_update = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{credentialed_id}"),
            Some(secrets_editor.clone()),
            Some(test_target_update),
            Some(&credentialed_etag),
            true,
        ))
        .await
        .expect("credentialed test-target update should complete");
    assert_eq!(allowed_test_target_update.status(), StatusCode::OK);
    credentialed_etag = allowed_test_target_update
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("test-target update should include an ETag")
        .to_owned();
    let allowed_test_target_update = json_body(allowed_test_target_update).await;
    assert_eq!(
        allowed_test_target_update["revisions"]["credential"],
        json!(initial_credential_revision + 1)
    );

    let first_page = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}?limit=1&enabled=true&source=managed"),
            Some(secrets_editor.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("first connection page should complete");
    assert_eq!(first_page.status(), StatusCode::OK);
    let first_page = json_body(first_page).await;
    assert_eq!(
        first_page["connections"]
            .as_array()
            .expect("connections should be an array")
            .len(),
        1
    );
    let cursor = first_page["next_cursor"]
        .as_str()
        .expect("first page should include a cursor");
    let second_page = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &format!(
                "{CONNECTIONS_ADMIN_ROUTE}?limit=1&enabled=true&source=managed&cursor={cursor}"
            ),
            Some(secrets_editor.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("second connection page should complete");
    assert_eq!(second_page.status(), StatusCode::OK);
    let second_page = json_body(second_page).await;
    assert_eq!(
        second_page["connections"]
            .as_array()
            .expect("connections should be an array")
            .len(),
        1
    );
    assert!(second_page.get("next_cursor").is_none());

    let credential_delete_without_secret_authority = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{credentialed_id}"),
            Some(editor.clone()),
            None,
            Some(&credentialed_etag),
            true,
        ))
        .await
        .expect("credential delete denial should complete");
    assert_eq!(
        credential_delete_without_secret_authority.status(),
        StatusCode::FORBIDDEN
    );

    let dependency_store = connections::store::SqliteConnectionStore::open(&connection_db.path)
        .expect("dependency store should open");
    let plain_connection_id =
        connections::model::ConnectionId::parse(plain_id.clone()).expect("ID should parse");
    dependency_store
        .add_dependency(
            &plain_connection_id,
            connections::store::ConnectionDependencyKind::ManualTool,
            "billing.get",
        )
        .expect("dependency should insert");
    let dependent_detail = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{plain_id}"),
            Some(test_principal(&["connections-editor"])),
            None,
            None,
            false,
        ))
        .await
        .expect("dependent detail should complete");
    assert_eq!(dependent_detail.status(), StatusCode::OK);
    let dependent_detail = json_body(dependent_detail).await;
    assert_eq!(dependent_detail["actions"]["can_delete"], json!(false));
    assert_eq!(
        dependent_detail["dependencies"][0]["consumer_id"],
        json!("billing.get")
    );
    let dependency_conflict = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{plain_id}"),
            Some(editor.clone()),
            None,
            Some(&updated_etag),
            true,
        ))
        .await
        .expect("dependency conflict should complete");
    assert_eq!(dependency_conflict.status(), StatusCode::CONFLICT);
    dependency_store
        .remove_dependency(
            &plain_connection_id,
            connections::store::ConnectionDependencyKind::ManualTool,
            "billing.get",
        )
        .expect("dependency should remove");
    drop(dependency_store);

    let plain_delete = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{plain_id}"),
            Some(editor),
            None,
            Some(&updated_etag),
            true,
        ))
        .await
        .expect("plain delete should complete");
    assert_eq!(plain_delete.status(), StatusCode::OK);

    let credential_delete = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{credentialed_id}"),
            Some(secrets_editor),
            None,
            Some(&credentialed_etag),
            true,
        ))
        .await
        .expect("credential delete should complete");
    assert_eq!(credential_delete.status(), StatusCode::OK);

    assert_eventually(Duration::from_secs(1), || {
        let events = capture.events();
        events
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_CHANGED)
            .count()
            == 7
            && events
                .iter()
                .filter(|event| event.event_type == audit::event::CONNECTION_CREDENTIAL_CHANGED)
                .count()
                == 3
            && events
                .iter()
                .filter(|event| {
                    event.event_type == "authz.denied"
                        && event.payload["permission"]
                            == json!(ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION)
                })
                .count()
                == 6
    });
    let events = capture.events();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_CHANGED)
            .count(),
        7
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| { event.event_type == audit::event::CONNECTION_CREDENTIAL_CHANGED })
            .count(),
        3
    );
    assert!(events.iter().any(|event| {
        event.event_type == audit::event::CONNECTION_CREDENTIAL_CHANGED
            && event.payload["action"] == json!("updated")
            && event.payload["changed_fields"]
                .as_array()
                .is_some_and(|fields| fields.contains(&json!("test_profile")))
    }));
    let secret_authority_denials = events
        .iter()
        .filter(|event| {
            event.event_type == "authz.denied"
                && event.payload["permission"] == json!(ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION)
        })
        .collect::<Vec<_>>();
    assert_eq!(secret_authority_denials.len(), 6);
    assert_eq!(
        secret_authority_denials
            .iter()
            .filter(|event| event.payload["operation"] == json!("create"))
            .count(),
        1
    );
    assert_eq!(
        secret_authority_denials
            .iter()
            .filter(|event| event.payload["operation"] == json!("replace"))
            .count(),
        4
    );
    assert_eq!(
        secret_authority_denials
            .iter()
            .filter(|event| event.payload["operation"] == json!("delete"))
            .count(),
        1
    );
    assert!(secret_authority_denials.iter().all(|event| {
        event.payload["reason"] == json!("missing_permission")
            && event.payload["authorization_layer"] == json!("connection_secret_authority")
    }));
    let serialized_events = serde_json::to_string(&events).expect("audit events should serialize");
    assert!(!serialized_events.contains("credential-secret-id-canary"));
    assert!(!serialized_events.contains("different-secret-id-canary"));
    assert!(!serialized_events.contains("credential-material-value-canary"));
    assert!(!serialized_events.contains("credentialed.example.test"));
    assert!(!serialized_events.contains("/credentialed-health"));

    // Every committed change recorded the authenticated principal -- its
    // subject, canonical issuer, kind and auth mode -- as its actor in the
    // Connections database's own transaction (issue #425), and no binding
    // ID, material or destination reached a row.
    let (changes, stored) =
        standalone_change_evidence(&connection_db.path, "connection_change_evidence");
    let editor_actor = (None, "principal".to_owned(), "bearer_token".to_owned());
    let secrets_editor_actor = (
        Some("https://idp.example.test".to_owned()),
        "principal".to_owned(),
        "bearer_token".to_owned(),
    );
    assert!(
        changes.iter().all(|change| change.subject == "user-123"
            && [&editor_actor, &secrets_editor_actor].contains(&&change.metadata())),
        "{changes:?}"
    );
    for action in [
        "connection.create",
        "connection.replace",
        "connection.delete",
    ] {
        assert!(
            changes.iter().any(|change| change.action == action),
            "{action} was not recorded: {changes:?}"
        );
    }
    let last = changes.last().expect("the deletes were recorded");
    assert_eq!(
        (last.action.as_str(), last.metadata()),
        ("connection.delete", secrets_editor_actor),
        "the credentialed Connection's delete names the principal that deleted it"
    );
    for canary in [
        "credential-secret-id-canary",
        "different-secret-id-canary",
        "credential-material-value-canary",
        "credentialed.example.test",
        "/credentialed-health",
    ] {
        assert!(!stored.contains(canary), "{canary} reached the evidence");
    }
}

#[tokio::test]
async fn connection_secret_admin_crud_is_safe_permissioned_and_preconditioned() {
    let connection_db = TempDb::new("connection-secret-admin-crud");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let audit_drain = audit_log.clone();
    let router = connection_admin_router(&connection_db, &policy, audit_log);
    let secret_manager = test_principal(&["connections-secret-manager"]);

    let unauthorized = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            None,
            None,
            None,
            false,
        ))
        .await
        .expect("unauthorized secret list should complete");
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let forbidden = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/invalid@id"),
            Some(test_principal(&["connections-observer"])),
            Some("secret-body-canary".repeat(100_000)),
            Some("\"untrusted-etag\""),
            true,
        ))
        .await
        .expect("forbidden secret mutation should complete before lookup or body parsing");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);

    let initial = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(secret_manager.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("secret list should complete");
    assert_eq!(initial.status(), StatusCode::OK);
    assert_eq!(initial.headers()[header::CACHE_CONTROL], "no-store");
    let initial_representation_etag = initial
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("secret list should include a representation ETag")
        .to_owned();
    let initial_collection_etag = initial
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("secret list should include a mutation collection ETag")
        .to_owned();
    assert_ne!(initial_representation_etag, initial_collection_etag);
    let initial_body = json_body(initial).await;
    assert_eq!(initial_body["actions"]["can_create"], json!(true));
    assert_eq!(
        initial_body["providers"],
        json!({"operator_aliases": true, "local_encrypted": true})
    );
    let operator = initial_body["secrets"]
        .as_array()
        .and_then(|secrets| {
            secrets
                .iter()
                .find(|secret| secret["id"] == json!("credential-secret-id-canary"))
        })
        .expect("operator secret alias should be listed");
    assert_eq!(operator["provider"], json!("operator_file"));
    assert_eq!(operator["actions"]["can_rotate"], json!(false));
    assert_eq!(operator["actions"]["can_delete"], json!(false));
    assert_eq!(
        operator["compatible_purposes"].as_array().map(Vec::len),
        Some(8)
    );
    let operator_etag = operator["etag"]
        .as_str()
        .expect("operator alias should include a safe ETag")
        .to_owned();
    let initial_serialized =
        serde_json::to_string(&initial_body).expect("initial secret list should serialize");
    assert!(!initial_serialized.contains("credential-material-value-canary"));
    assert!(!initial_serialized.contains("credential-token"));
    assert!(!initial_serialized.contains("local-master-key"));
    assert!(!initial_serialized.contains("\"value\""));

    let wildcard = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(test_principal(&["connections-superadmin"])),
            None,
            None,
            false,
        ))
        .await
        .expect("wildcard secret list should complete");
    assert_eq!(wildcard.status(), StatusCode::OK);

    let create_body = json!({
        "label": "Webhook bearer",
        "purpose": "static_bearer",
        "value": "created-secret-value-canary"
    })
    .to_string();
    let missing_create_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(secret_manager.clone()),
            Some(create_body.clone()),
            None,
            true,
        ))
        .await
        .expect("missing create precondition should complete");
    assert_eq!(
        missing_create_precondition.status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    assert!(
        !missing_create_precondition
            .headers()
            .contains_key(header::ETAG),
        "a collection precondition failure must not use the representation ETag header"
    );
    assert_eq!(
        missing_create_precondition
            .headers()
            .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(initial_collection_etag.as_str())
    );
    let stale_create_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(secret_manager.clone()),
            Some(create_body.clone()),
            Some("\"connection-secrets:stale\""),
            true,
        ))
        .await
        .expect("stale create precondition should complete");
    assert_eq!(
        stale_create_precondition.status(),
        StatusCode::PRECONDITION_FAILED
    );
    assert!(
        !stale_create_precondition
            .headers()
            .contains_key(header::ETAG),
        "a stale collection mutation has no item representation validator"
    );
    assert_eq!(
        stale_create_precondition
            .headers()
            .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(initial_collection_etag.as_str())
    );

    let csrf_denied = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(secret_manager.clone()),
            Some(create_body.clone()),
            Some(&initial_collection_etag),
            false,
        ))
        .await
        .expect("CSRF-denied secret create should complete");
    assert_eq!(csrf_denied.status(), StatusCode::FORBIDDEN);

    let mut csrf_create = connection_admin_request(
        Method::POST,
        CONNECTION_SECRETS_ADMIN_ROUTE,
        Some(secret_manager.clone()),
        Some(create_body),
        Some(&initial_collection_etag),
        false,
    );
    csrf_create.headers_mut().insert(
        header::COOKIE,
        HeaderValue::from_static("csrf_token=secret-admin-csrf"),
    );
    csrf_create.headers_mut().insert(
        HeaderName::from_static("x-csrf-token"),
        HeaderValue::from_static("secret-admin-csrf"),
    );
    let created = router
        .clone()
        .oneshot(csrf_create)
        .await
        .expect("CSRF-protected secret create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_etag = created
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("created secret should include an item ETag")
        .to_owned();
    let created_collection_etag = created
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("created secret should include the new collection ETag")
        .to_owned();
    assert_ne!(created_collection_etag, initial_collection_etag);
    let created_body = json_body(created).await;
    let secret_id = created_body["id"]
        .as_str()
        .expect("created secret should include its opaque ID")
        .to_owned();
    assert_eq!(created_body["provider"], json!("local_encrypted"));
    assert_eq!(
        created_body["compatible_purposes"],
        json!(["static_bearer"])
    );
    assert_eq!(created_body["version"], json!(1));
    assert!(created_body.get("value").is_none());
    assert!(!created_body
        .to_string()
        .contains("created-secret-value-canary"));

    let operator_rotate = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/credential-secret-id-canary"),
            Some(secret_manager.clone()),
            Some(
                json!({
                    "purpose": "static_bearer",
                    "value": "operator-replacement-canary"
                })
                .to_string(),
            ),
            Some(&operator_etag),
            true,
        ))
        .await
        .expect("operator alias rotation should complete safely");
    assert_eq!(operator_rotate.status(), StatusCode::CONFLICT);

    let local_uri = format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/{secret_id}");
    let missing_rotate_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &local_uri,
            Some(secret_manager.clone()),
            Some(
                json!({
                    "purpose": "static_bearer",
                    "value": "missing-rotate-precondition-canary"
                })
                .to_string(),
            ),
            None,
            true,
        ))
        .await
        .expect("missing rotate precondition should complete");
    assert_eq!(
        missing_rotate_precondition.status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let stale_rotate_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &local_uri,
            Some(secret_manager.clone()),
            Some(
                json!({
                    "purpose": "static_bearer",
                    "value": "stale-rotate-precondition-canary"
                })
                .to_string(),
            ),
            Some("\"connection-secret:stale\""),
            true,
        ))
        .await
        .expect("stale rotate precondition should complete");
    assert_eq!(
        stale_rotate_precondition.status(),
        StatusCode::PRECONDITION_FAILED
    );
    let wrong_purpose = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &local_uri,
            Some(secret_manager.clone()),
            Some(
                json!({
                    "purpose": "tls_certificate",
                    "value": "wrong-purpose-value-canary"
                })
                .to_string(),
            ),
            Some(&created_etag),
            true,
        ))
        .await
        .expect("wrong-purpose rotation should complete");
    assert_eq!(wrong_purpose.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let oversized_value = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &local_uri,
            Some(secret_manager.clone()),
            Some(
                json!({
                    "purpose": "static_bearer",
                    "value": "x".repeat(connections::secret::MAX_HTTP_CREDENTIAL_BYTES + 1)
                })
                .to_string(),
            ),
            Some(&created_etag),
            true,
        ))
        .await
        .expect("oversized secret value should complete");
    assert_eq!(oversized_value.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let rotated = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &local_uri,
            Some(secret_manager.clone()),
            Some(
                json!({
                    "purpose": "static_bearer",
                    "value": "rotated-secret-value-canary"
                })
                .to_string(),
            ),
            Some(&created_etag),
            true,
        ))
        .await
        .expect("secret rotation should complete");
    assert_eq!(rotated.status(), StatusCode::OK);
    let rotated_etag = rotated
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("rotated secret should include a new item ETag")
        .to_owned();
    let rotated_collection_etag = rotated
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("rotated secret should include a new collection ETag")
        .to_owned();
    assert_ne!(rotated_etag, created_etag);
    let rotated_body = json_body(rotated).await;
    assert_eq!(rotated_body["version"], json!(2));
    assert!(!rotated_body
        .to_string()
        .contains("rotated-secret-value-canary"));

    let oversized_request = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(secret_manager.clone()),
            Some("x".repeat(connections::secret::MAX_TLS_CERTIFICATE_BYTES + (16 * 1024) + 1)),
            Some(&rotated_collection_etag),
            true,
        ))
        .await
        .expect("oversized secret request should complete");
    assert_eq!(oversized_request.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let secrets_before_binding = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(secret_manager.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("secret list before binding should complete");
    let pre_binding_representation_etag = secrets_before_binding
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("pre-binding secret list should include a representation ETag")
        .to_owned();
    assert_eq!(
        secrets_before_binding
            .headers()
            .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(rotated_collection_etag.as_str())
    );

    let connection_list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(secret_manager.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let connection_collection_etag = connection_list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection list should include its mutation ETag")
        .to_owned();
    let connection_actions = json_body(connection_list).await["actions"].clone();
    assert_eq!(connection_actions["can_create"], json!(false));
    assert_eq!(connection_actions["can_bind_secret"], json!(false));
    assert_eq!(connection_actions["can_manage_secrets"], json!(true));

    let mut credentialed: Value = serde_json::from_str(&credentialed_connection_body())
        .expect("credentialed connection should parse");
    credentialed["authentication"]["secret_id"] = json!(secret_id);
    let bound_connection = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-superadmin"])),
            Some(credentialed.to_string()),
            Some(&connection_collection_etag),
            true,
        ))
        .await
        .expect("secret-bound connection create should complete");
    assert_eq!(bound_connection.status(), StatusCode::CREATED);
    let bound_connection_etag = bound_connection
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("bound connection should include an item ETag")
        .to_owned();
    let bound_connection_body = json_body(bound_connection).await;
    let bound_connection_id = bound_connection_body["id"]
        .as_str()
        .expect("bound connection should include an ID")
        .to_owned();

    let secrets_after_binding = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(secret_manager.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("secret list after binding should complete");
    let bound_representation_etag = secrets_after_binding
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("bound secret list should include a representation ETag")
        .to_owned();
    assert_ne!(
        bound_representation_etag, pre_binding_representation_etag,
        "dependency-derived representation changes must change the standard HTTP ETag"
    );
    assert_eq!(
        secrets_after_binding
            .headers()
            .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(rotated_collection_etag.as_str())
    );
    let bound_secrets = json_body(secrets_after_binding).await;
    let bound_secret = bound_secrets["secrets"]
        .as_array()
        .and_then(|secrets| {
            secrets
                .iter()
                .find(|secret| secret["id"] == json!(secret_id))
        })
        .expect("bound local secret should remain listed");
    assert_eq!(bound_secret["dependency_count"], json!(1));
    assert_eq!(bound_secret["actions"]["can_delete"], json!(false));

    let secret_only_detail = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{bound_connection_id}"),
            Some(secret_manager.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("secret-manager detail should complete");
    assert_eq!(secret_only_detail.status(), StatusCode::OK);
    let detail_actions = json_body(secret_only_detail).await["actions"].clone();
    assert_eq!(detail_actions["can_update"], json!(false));
    assert_eq!(detail_actions["can_bind_secret"], json!(false));
    assert_eq!(detail_actions["can_manage_secrets"], json!(true));

    let missing_delete_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &local_uri,
            Some(secret_manager.clone()),
            None,
            None,
            true,
        ))
        .await
        .expect("missing delete precondition should complete");
    assert_eq!(
        missing_delete_precondition.status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    let stale_delete_precondition = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &local_uri,
            Some(secret_manager.clone()),
            None,
            Some("\"connection-secret:stale\""),
            true,
        ))
        .await
        .expect("stale delete precondition should complete");
    assert_eq!(
        stale_delete_precondition.status(),
        StatusCode::PRECONDITION_FAILED
    );
    let dependency_conflict = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &local_uri,
            Some(secret_manager.clone()),
            None,
            Some(&rotated_etag),
            true,
        ))
        .await
        .expect("referenced secret delete should complete");
    assert_eq!(dependency_conflict.status(), StatusCode::CONFLICT);
    let dependency_conflict = json_body(dependency_conflict).await;
    assert_eq!(dependency_conflict["dependency_count"], json!(1));
    assert_eq!(
        dependency_conflict["connection_ids"],
        json!([bound_connection_id])
    );

    let deleted_connection = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{bound_connection_id}"),
            Some(test_principal(&["connections-superadmin"])),
            None,
            Some(&bound_connection_etag),
            true,
        ))
        .await
        .expect("bound connection delete should complete");
    assert_eq!(deleted_connection.status(), StatusCode::OK);

    let nonempty_delete = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &local_uri,
            Some(secret_manager.clone()),
            Some("{}".to_owned()),
            Some(&rotated_etag),
            true,
        ))
        .await
        .expect("non-empty secret delete should complete");
    assert_eq!(nonempty_delete.status(), StatusCode::BAD_REQUEST);
    let oversized_delete = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &local_uri,
            Some(secret_manager.clone()),
            Some("x".repeat(1025)),
            Some(&rotated_etag),
            true,
        ))
        .await
        .expect("oversized secret delete should complete");
    assert_eq!(oversized_delete.status(), StatusCode::PAYLOAD_TOO_LARGE);

    let deleted = router
        .clone()
        .oneshot(connection_admin_request(
            Method::DELETE,
            &local_uri,
            Some(secret_manager),
            None,
            Some(&rotated_etag),
            true,
        ))
        .await
        .expect("secret delete should complete");
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_eq!(
        json_body(deleted).await["deleted_secret_id"],
        json!(secret_id)
    );

    audit_drain
        .close_and_drain(Duration::from_secs(5))
        .await
        .expect("connection-secret CRUD audit events should drain");
    let secret_events = capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == audit::event::CONNECTION_SECRET_CHANGED)
        .collect::<Vec<_>>();
    assert_eq!(secret_events.len(), 3);
    assert_eq!(
        secret_events
            .iter()
            .map(|event| event.payload["action"].as_str())
            .collect::<Vec<_>>(),
        vec![Some("created"), Some("rotated"), Some("deleted")]
    );
    for event in &secret_events {
        let mut fields = event
            .payload
            .as_object()
            .expect("secret audit payload should be an object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        fields.sort_unstable();
        assert_eq!(
            fields,
            vec![
                "action",
                "dependency_count",
                "provider",
                "purpose",
                "resource",
                "secret_id",
                "version",
            ]
        );
        assert_eq!(event.payload["secret_id"], json!(secret_id));
        assert_eq!(event.payload["provider"], json!("local_encrypted"));
        assert_eq!(event.payload["purpose"], json!("static_bearer"));
    }
    let serialized_events =
        serde_json::to_string(&secret_events).expect("secret events should serialize");
    for forbidden_value in [
        "created-secret-value-canary",
        "rotated-secret-value-canary",
        "wrong-purpose-value-canary",
        "operator-replacement-canary",
        "missing-rotate-precondition-canary",
        "stale-rotate-precondition-canary",
        "credential-material-value-canary",
        "credential-token",
        "local-master-key",
        "Webhook bearer",
    ] {
        assert!(
            !serialized_events.contains(forbidden_value),
            "secret audit events must not contain {forbidden_value}"
        );
    }

    // Every committed secret change recorded the authenticated principal in
    // the Connections database's own transaction (issue #425), and no
    // material or label reached a row.
    let (changes, stored) = standalone_change_evidence(
        &connection_db.path,
        "connection_local_secret_change_evidence",
    );
    assert!(
        changes.iter().all(|change| change.subject == "user-123"
            && change.metadata() == (None, "principal".to_owned(), "bearer_token".to_owned())),
        "{changes:?}"
    );
    for action in ["secret.create", "secret.rotate", "secret.delete"] {
        assert!(
            changes.iter().any(|change| change.action == action),
            "{action} was not recorded: {changes:?}"
        );
    }
    for forbidden_value in [
        "created-secret-value-canary",
        "rotated-secret-value-canary",
        "Webhook bearer",
        "local-master-key",
    ] {
        assert!(
            !stored.contains(forbidden_value),
            "{forbidden_value} reached the evidence"
        );
    }
}

#[test]
fn poisoned_connection_secret_mutation_lock_fails_closed() {
    let lock = std::sync::Mutex::new(());
    let poisoned = std::panic::catch_unwind(|| {
        let _guard = lock.lock().expect("fresh mutation lock should acquire");
        panic!("poison connection-secret mutation lock for regression coverage");
    });
    assert!(poisoned.is_err());

    match lock_connection_secret_mutations(&lock) {
        Ok(_) => panic!("poisoned connection-secret mutation lock must not be recovered"),
        Err(response) => assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE),
    };
}

#[tokio::test]
async fn connection_secret_mutations_allow_only_one_same_etag_winner() {
    let connection_db = TempDb::new("connection-secret-admin-races");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let audit_drain = audit_log.clone();
    let router = connection_admin_router(&connection_db, &policy, audit_log);
    let principal = test_principal(&["connections-secret-manager"]);

    let initial = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(principal.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("initial secret list should complete");
    let collection_etag = initial
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("initial secret list should include collection ETag")
        .to_owned();

    let create_one = router.clone().oneshot(connection_admin_request(
        Method::POST,
        CONNECTION_SECRETS_ADMIN_ROUTE,
        Some(principal.clone()),
        Some(
            json!({
                "label": "Race one",
                "purpose": "static_bearer",
                "value": "race-create-one-canary"
            })
            .to_string(),
        ),
        Some(&collection_etag),
        true,
    ));
    let create_two = router.clone().oneshot(connection_admin_request(
        Method::POST,
        CONNECTION_SECRETS_ADMIN_ROUTE,
        Some(principal.clone()),
        Some(
            json!({
                "label": "Race two",
                "purpose": "static_bearer",
                "value": "race-create-two-canary"
            })
            .to_string(),
        ),
        Some(&collection_etag),
        true,
    ));
    let (create_one, create_two) = tokio::join!(create_one, create_two);
    let create_one = create_one.expect("first concurrent create should complete");
    let create_two = create_two.expect("second concurrent create should complete");
    let mut create_statuses = [create_one.status(), create_two.status()];
    create_statuses.sort_by_key(|status| status.as_u16());
    assert_eq!(
        create_statuses,
        [StatusCode::CREATED, StatusCode::PRECONDITION_FAILED]
    );
    let create_loser = if create_one.status() == StatusCode::PRECONDITION_FAILED {
        &create_one
    } else {
        &create_two
    };
    assert!(
        !create_loser.headers().contains_key(header::ETAG),
        "a collection race loser must not return an item representation validator"
    );
    let create_loser_collection_etag = create_loser
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("a collection race loser should return the current collection validator")
        .to_owned();

    let after_create = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(principal.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("secret list after concurrent create should complete");
    assert_eq!(
        after_create
            .headers()
            .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(create_loser_collection_etag.as_str())
    );
    let after_create = json_body(after_create).await;
    let locals = after_create["secrets"]
        .as_array()
        .expect("secret list should include an array")
        .iter()
        .filter(|secret| secret["provider"] == json!("local_encrypted"))
        .collect::<Vec<_>>();
    assert_eq!(locals.len(), 1);
    let secret_id = locals[0]["id"]
        .as_str()
        .expect("race winner should have an ID")
        .to_owned();
    let item_etag = locals[0]["etag"]
        .as_str()
        .expect("race winner should have an ETag")
        .to_owned();
    let local_uri = format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/{secret_id}");

    let rotate_one = router.clone().oneshot(connection_admin_request(
        Method::PUT,
        &local_uri,
        Some(principal.clone()),
        Some(
            json!({
                "purpose": "static_bearer",
                "value": "race-rotate-one-canary"
            })
            .to_string(),
        ),
        Some(&item_etag),
        true,
    ));
    let rotate_two = router.clone().oneshot(connection_admin_request(
        Method::PUT,
        &local_uri,
        Some(principal.clone()),
        Some(
            json!({
                "purpose": "static_bearer",
                "value": "race-rotate-two-canary"
            })
            .to_string(),
        ),
        Some(&item_etag),
        true,
    ));
    let (rotate_one, rotate_two) = tokio::join!(rotate_one, rotate_two);
    let rotate_one = rotate_one.expect("first concurrent rotate should complete");
    let rotate_two = rotate_two.expect("second concurrent rotate should complete");
    let mut rotate_statuses = [rotate_one.status(), rotate_two.status()];
    rotate_statuses.sort_by_key(|status| status.as_u16());
    assert_eq!(
        rotate_statuses,
        [StatusCode::OK, StatusCode::PRECONDITION_FAILED]
    );
    let rotate_loser = if rotate_one.status() == StatusCode::PRECONDITION_FAILED {
        &rotate_one
    } else {
        &rotate_two
    };
    assert!(
        rotate_loser.headers().contains_key(header::ETAG),
        "a stale rotate keeps returning the current item validator while the item exists"
    );
    assert!(
        !rotate_loser
            .headers()
            .contains_key(CONNECTION_SECRET_COLLECTION_ETAG_HEADER),
        "an item-version conflict must not relabel its validator as a collection validator"
    );

    let after_rotate = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(principal.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("secret list after concurrent rotate should complete");
    let after_rotate = json_body(after_rotate).await;
    let rotated_etag = after_rotate["secrets"]
        .as_array()
        .and_then(|secrets| {
            secrets
                .iter()
                .find(|secret| secret["id"] == json!(secret_id))
        })
        .and_then(|secret| secret["etag"].as_str())
        .expect("rotated race winner should have a new ETag")
        .to_owned();

    let delete_one = router.clone().oneshot(connection_admin_request(
        Method::DELETE,
        &local_uri,
        Some(principal.clone()),
        None,
        Some(&rotated_etag),
        true,
    ));
    let delete_two = router.clone().oneshot(connection_admin_request(
        Method::DELETE,
        &local_uri,
        Some(principal.clone()),
        None,
        Some(&rotated_etag),
        true,
    ));
    let (delete_one, delete_two) = tokio::join!(delete_one, delete_two);
    let delete_one = delete_one.expect("first concurrent delete should complete");
    let delete_two = delete_two.expect("second concurrent delete should complete");
    let mut delete_statuses = [delete_one.status(), delete_two.status()];
    delete_statuses.sort_by_key(|status| status.as_u16());
    assert_eq!(
        delete_statuses,
        [StatusCode::OK, StatusCode::PRECONDITION_FAILED]
    );
    let delete_loser = if delete_one.status() == StatusCode::PRECONDITION_FAILED {
        &delete_one
    } else {
        &delete_two
    };
    assert!(
        !delete_loser.headers().contains_key(header::ETAG),
        "a disappeared item has no current item validator"
    );
    let delete_loser_collection_etag = delete_loser
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("a disappeared item should return the current secret collection validator")
        .to_owned();
    let missing_rotate = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &local_uri,
            Some(principal.clone()),
            Some(
                json!({
                    "purpose": "static_bearer",
                    "value": "missing-rotate-after-delete-canary"
                })
                .to_string(),
            ),
            Some(&rotated_etag),
            true,
        ))
        .await
        .expect("rotate of an already-deleted secret should complete");
    assert_eq!(missing_rotate.status(), StatusCode::PRECONDITION_FAILED);
    assert!(
        !missing_rotate.headers().contains_key(header::ETAG),
        "an already-deleted item has no current item validator"
    );
    let missing_rotate_collection_etag = missing_rotate
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("an already-deleted item should return the current collection validator")
        .to_owned();

    let after_delete = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(principal),
            None,
            None,
            false,
        ))
        .await
        .expect("secret list after concurrent delete should complete");
    assert_eq!(
        after_delete
            .headers()
            .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(delete_loser_collection_etag.as_str())
    );
    assert_eq!(
        after_delete
            .headers()
            .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some(missing_rotate_collection_etag.as_str())
    );

    audit_drain
        .close_and_drain(Duration::from_secs(5))
        .await
        .expect("connection-secret race audit events should drain");
    let secret_events = capture
        .events()
        .into_iter()
        .filter(|event| event.event_type == audit::event::CONNECTION_SECRET_CHANGED)
        .collect::<Vec<_>>();
    assert_eq!(secret_events.len(), 3);
    let serialized =
        serde_json::to_string(&secret_events).expect("race audit events should serialize");
    for secret in [
        "race-create-one-canary",
        "race-create-two-canary",
        "race-rotate-one-canary",
        "race-rotate-two-canary",
        "missing-rotate-after-delete-canary",
    ] {
        assert!(!serialized.contains(secret));
    }
}

#[tokio::test]
async fn connection_secret_routes_follow_the_custom_admin_prefix() {
    let connection_db = TempDb::new("connection-secret-custom-prefix");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router =
        connection_admin_router_with_prefix(&connection_db, &policy, test_audit_log(), "/ops");
    let principal = test_principal(&["connections-secret-manager"]);
    let custom_route = "/v1/ops/connection-secrets";

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            custom_route,
            Some(principal.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("custom-prefix secret list should complete");
    assert_eq!(list.status(), StatusCode::OK);
    let collection_etag = list
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("custom-prefix list should include collection ETag")
        .to_owned();

    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            custom_route,
            Some(principal),
            Some(
                json!({
                    "label": "Custom prefix",
                    "purpose": "header_api_key",
                    "value": "custom-prefix-value-canary"
                })
                .to_string(),
            ),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("custom-prefix secret create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    assert!(!json_body(created)
        .await
        .to_string()
        .contains("custom-prefix-value-canary"));

    let default_route = router
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(test_principal(&["connections-secret-manager"])),
            None,
            None,
            false,
        ))
        .await
        .expect("default secret route should complete under custom prefix");
    assert_ne!(default_route.status(), StatusCode::OK);
}

#[tokio::test]
async fn connection_secret_list_stays_safe_when_local_management_is_unconfigured() {
    let connection_db = TempDb::new("connection-secret-local-unconfigured");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let secret_root = connection_db.path.with_extension("operator-secrets");
    fs::create_dir_all(&secret_root).expect("operator secret root should create");
    let operator_file = secret_root.join("operator-token");
    fs::write(&operator_file, b"unconfigured-local-operator-value-canary")
        .expect("operator secret fixture should write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("operator secret root permissions should set");
        fs::set_permissions(&operator_file, fs::Permissions::from_mode(0o600))
            .expect("operator secret permissions should set");
    }
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.connections_sqlite_path = Some(connection_db.path.to_string_lossy().into_owned());
    config.connection_secrets_root = Some(connections::secret::SecretRootConfig::new(secret_root));
    config.connection_secret_aliases = vec![connections::secret::OperatorSecretAliasConfig {
        id: "operator-only-alias".to_owned(),
        label: "Operator only".to_owned(),
        source: connections::secret::OperatorSecretAliasSource::File {
            key: "operator-token".to_owned(),
        },
    }];
    config
        .rbac_exempt_paths
        .push(CONNECTIONS_ADMIN_ROUTE.to_owned());
    config
        .rbac_exempt_paths
        .push(CONNECTION_SECRETS_ADMIN_ROUTE.to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("operator-only connection admin app should build");
    let principal = test_principal(&["connections-secret-manager"]);

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(principal.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("operator-only secret list should complete");
    assert_eq!(list.status(), StatusCode::OK);
    assert_managed_admin_no_store(&list);
    let collection_etag = list
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("operator-only list should include collection ETag")
        .to_owned();
    let list = json_body(list).await;
    assert_eq!(list["actions"]["can_create"], json!(false));
    assert_eq!(list["providers"]["operator_aliases"], json!(true));
    assert_eq!(list["providers"]["local_encrypted"], json!(false));
    assert_eq!(list["secrets"][0]["id"], json!("operator-only-alias"));
    assert_eq!(list["secrets"][0]["actions"]["can_rotate"], json!(false));
    assert_eq!(list["secrets"][0]["actions"]["can_delete"], json!(false));
    let operator_etag = list["secrets"][0]["etag"]
        .as_str()
        .expect("operator alias should include an ETag")
        .to_owned();
    let serialized = list.to_string();
    assert!(!serialized.contains("unconfigured-local-operator-value-canary"));
    assert!(!serialized.contains("operator-token"));

    let connections = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(principal.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("operator-only connection list should complete");
    assert_eq!(connections.status(), StatusCode::OK);
    assert_managed_admin_no_store(&connections);
    assert_eq!(
        json_body(connections).await["actions"]["can_manage_secrets"],
        json!(false)
    );

    let unavailable_create = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(principal.clone()),
            Some(
                json!({
                    "label": "Unavailable local",
                    "purpose": "static_bearer",
                    "value": "unavailable-local-value-canary"
                })
                .to_string(),
            ),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("unconfigured local secret create should complete");
    assert_eq!(unavailable_create.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_managed_admin_no_store(&unavailable_create);
    assert!(!body_string(unavailable_create)
        .await
        .contains("unavailable-local-value-canary"));

    for method in [Method::PUT, Method::DELETE] {
        let body = (method == Method::PUT).then(|| {
            json!({
                "purpose": "static_bearer",
                "value": "operator-write-value-canary"
            })
            .to_string()
        });
        let read_only = router
            .clone()
            .oneshot(connection_admin_request(
                method,
                &format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/operator-only-alias"),
                Some(principal.clone()),
                body,
                Some(&operator_etag),
                true,
            ))
            .await
            .expect("operator alias mutation should complete");
        assert_eq!(read_only.status(), StatusCode::CONFLICT);
        assert_managed_admin_no_store(&read_only);
        let body = body_string(read_only).await;
        assert!(!body.contains("operator-write-value-canary"));
        assert!(!body.contains("operator-token"));
    }
}

/// A `delegated_issuer_token` client secret's alias cannot be bound under any
/// other purpose by another Connection (issue #441), because nothing else ties
/// an operator alias to one purpose. The save is refused with the candidate's
/// field and a fixed code, says nothing about the other Connection or the
/// alias, and writes nothing.
#[tokio::test]
async fn connection_admin_refuses_a_token_exchange_secret_shared_with_another_purpose() {
    let connection_db = TempDb::new("connection-admin-token-exchange-secret");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = connection_admin_router(&connection_db, &policy, test_audit_log());
    let secrets_editor = test_principal(&["connections-secrets-editor"]);
    let collection_etag = |response: &Response| {
        response
            .headers()
            .get(CONNECTION_COLLECTION_ETAG_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("collection response should include an ETag")
            .to_owned()
    };

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(secrets_editor.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let etag = collection_etag(&list);
    let bearer = json!({
        "display_name": "Billing API",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://billing.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "static_bearer",
            "secret_id": "shared-alias-canary"
        }
    });
    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(secrets_editor.clone()),
            Some(bearer.to_string()),
            Some(&etag),
            true,
        ))
        .await
        .expect("bearer create should complete");
    assert_eq!(created.status(), StatusCode::CREATED);
    let etag = collection_etag(&created);

    let mut assertion = admin_caller_assertion_json();
    assertion["bind_request"] = json!(false);
    let delegated = json!({
        "display_name": "Mail",
        "enabled": false,
        "kind": "http_api",
        "endpoint": {
            "base_url": "https://mail.example.test",
            "base_path": "/v1"
        },
        "authentication": {
            "type": "delegated_issuer_token",
            "token_exchange_url": "https://issuer.example.test/oauth2/token-exchange",
            "client_id": "greengateway",
            "client_secret_id": "shared-alias-canary",
            "subject_token_source": "caller_assertion"
        },
        "caller_assertion": assertion
    });
    let refused = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(secrets_editor.clone()),
            Some(delegated.to_string()),
            Some(&etag),
            true,
        ))
        .await
        .expect("delegated create should complete");
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_managed_admin_no_store(&refused);
    let body = body_string(refused).await;
    assert!(!body.contains("shared-alias-canary"), "{body}");
    let body: Value = serde_json::from_str(&body).expect("refusal should be JSON");
    assert_eq!(
        body["problems"],
        json!([{
            "field": "authentication.client_secret_id",
            "code": "secret_purpose_conflict"
        }])
    );

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(secrets_editor),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    assert_eq!(
        collection_etag(&list),
        etag,
        "the refused create wrote nothing"
    );
    assert_eq!(
        json_body(list).await["connections"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
}

#[tokio::test]
async fn connection_admin_authorizes_before_lookup_and_keeps_csrf_and_body_caps() {
    let connection_db = TempDb::new("connection-admin-boundaries");
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let router = connection_admin_router(&connection_db, &policy, test_audit_log());

    let missing_principal = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/invalid@id"),
            None,
            None,
            None,
            false,
        ))
        .await
        .expect("missing principal request should complete");
    assert_eq!(missing_principal.status(), StatusCode::UNAUTHORIZED);
    assert_managed_admin_no_store(&missing_principal);

    let forbidden_lookup = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/00000000-0000-0000-0000-000000000000"),
            Some(test_principal(&["connections-observer"])),
            None,
            None,
            false,
        ))
        .await
        .expect("forbidden lookup should complete");
    assert_eq!(forbidden_lookup.status(), StatusCode::FORBIDDEN);
    assert_managed_admin_no_store(&forbidden_lookup);

    let list = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-reader"])),
            None,
            None,
            false,
        ))
        .await
        .expect("list request should complete");
    assert_eq!(list.status(), StatusCode::OK);
    assert_managed_admin_no_store(&list);
    let collection_etag = list
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("list should include collection ETag")
        .to_owned();

    let mut unknown_binding: Value = serde_json::from_str(&credentialed_connection_body())
        .expect("credentialed body should parse");
    unknown_binding["authentication"]["secret_id"] = json!("unknown-secret-alias");
    let unknown_binding = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-secrets-editor"])),
            Some(unknown_binding.to_string()),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("unknown enabled binding should complete");
    assert_eq!(unknown_binding.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_managed_admin_no_store(&unknown_binding);
    assert_eq!(
        json_body(unknown_binding).await["problems"][0]["code"],
        json!("unresolvable_binding")
    );

    let csrf_denied = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-editor"])),
            Some(plain_connection_body("CSRF denied")),
            Some(&collection_etag),
            false,
        ))
        .await
        .expect("CSRF denial should complete");
    assert_eq!(csrf_denied.status(), StatusCode::FORBIDDEN);
    assert_managed_admin_no_store(&csrf_denied);
    assert_eq!(
        json_body(csrf_denied).await["error"],
        json!("csrf token missing or invalid")
    );

    let mut disabled_draft: Value = serde_json::from_str(&plain_connection_body("Disabled draft"))
        .expect("plain body should parse");
    disabled_draft
        .as_object_mut()
        .expect("plain body should be an object")
        .remove("enabled");
    let disabled_draft = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-editor"])),
            Some(disabled_draft.to_string()),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("disabled draft create should complete");
    assert_eq!(disabled_draft.status(), StatusCode::CREATED);
    assert_managed_admin_no_store(&disabled_draft);
    assert_eq!(json_body(disabled_draft).await["enabled"], json!(false));

    let oversized = router
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(test_principal(&["connections-editor"])),
            Some("x".repeat(connections::admin::MAX_CONNECTION_ADMIN_BODY_BYTES + 1)),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("oversized connection body should complete");
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_managed_admin_no_store(&oversized);
}

#[tokio::test]
async fn all_connection_mutations_report_unconfigured_store_as_unavailable() {
    let policy = TempPolicyFile::new(&connection_policy_document_string());
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config
        .rbac_exempt_paths
        .push(CONNECTIONS_ADMIN_ROUTE.to_owned());
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("read-only connection app should build");
    let editor = test_principal(&["connections-editor"]);

    for (method, uri, body) in [
        (
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE.to_owned(),
            Some(plain_connection_body("Unavailable create")),
        ),
        (
            Method::PUT,
            format!("{CONNECTIONS_ADMIN_ROUTE}/missing"),
            Some(plain_connection_body("Unavailable update")),
        ),
        (
            Method::DELETE,
            format!("{CONNECTIONS_ADMIN_ROUTE}/missing"),
            None,
        ),
    ] {
        let expected_method = method.clone();
        let response = router
            .clone()
            .oneshot(connection_admin_request(
                method,
                &uri,
                Some(editor.clone()),
                body,
                Some("\"unused\""),
                true,
            ))
            .await
            .expect("unconfigured-store mutation should complete");
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{expected_method} mutation should report the unconfigured store"
        );
        assert_eq!(
            json_body(response).await["error"],
            json!("connection mutations require CONNECTIONS_SQLITE_PATH to be configured")
        );
    }
}

/// The connection admin router, with an operator alias holding a generated
/// caller-assertion signing key under the alias [`admin_caller_assertion_json`]
/// binds. Saving an enabled Connection loads its key, so an attested
/// Connection only saves where a real key sits behind the alias.
fn attested_connection_admin_router(
    connection_db: &TempDb,
    policy: &TempPolicyFile,
    audit_log: audit::AuditLog,
) -> Router {
    let mut config = connection_admin_config(connection_db, policy, config::DEFAULT_ADMIN_PREFIX);
    config
        .connection_secret_aliases
        .push(connections::test_support::write_assertion_signing_key(
            &connection_db.path.with_extension("secrets"),
            &connections::test_support::generated_es256_pem(),
        ));
    let recorder = PrometheusBuilder::new().build_recorder();

    app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("attested connection admin app should build")
}
