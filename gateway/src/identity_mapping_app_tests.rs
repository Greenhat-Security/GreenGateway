//! Identity mappings served through the whole application (issue #243).
//!
//! A policy v1 document with `identity_mappings` starts from `POLICY_FILE`
//! and is served: the RBAC route lane, the admin capabilities endpoint, the
//! policy-write header and service-token scope delegation all judge a
//! principal by the internal roles its mappings grant. Mapping each claimed
//! role to the internal role of the same name, for the principal's own
//! issuer, answers every one of those questions exactly as the same policy
//! without mappings does; and nothing but the organization the principal's
//! issuer verified -- no header, no other issuer, no service-token scope --
//! can make a mapping apply.
use super::*;

const ISSUER: &str = "https://idp.example.test";
const ROLES: [&str; 4] = ["probe-reader", "token-admin", "policy-admin", "superadmin"];

fn claimed_document() -> Value {
    json!({
        "schema_version": "1.0.0",
        "id": "claimed-roles",
        "default_action": "deny",
        "roles": {
            "probe-reader": { "permissions": ["test:read"] },
            "token-admin": {
                "permissions": [ADMIN_TOKENS_READ_PERMISSION, ADMIN_TOKENS_WRITE_PERMISSION]
            },
            "policy-admin": {
                "permissions": [ADMIN_POLICY_READ_PERMISSION, ADMIN_POLICY_WRITE_PERMISSION]
            },
            "superadmin": { "permissions": ["*"], "issuers": [ISSUER] }
        },
        "routes": [
            { "id": "probe", "methods": ["GET"], "path_prefix": "/__test", "permission": "test:read" }
        ]
    })
}

/// [`claimed_document`] in mapped-role mode, each claimed role mapped to the
/// internal role of the same name for the trusted issuer.
fn self_mapped_document() -> Value {
    let mut document = claimed_document();
    document["id"] = json!("self-mapped-roles");
    document["identity_mappings"] = Value::Array(
        ROLES
            .iter()
            .map(|role| {
                json!({
                    "id": format!("self-{role}"),
                    "issuer": ISSUER,
                    "claimed_roles": [role],
                    "grant_roles": [role]
                })
            })
            .collect(),
    );
    document
}

struct MappedApp {
    router: Router,
    _policy: TempPolicyFile,
    _tokens: TempDb,
}

/// The application serving `document` from `POLICY_FILE`, with the admin
/// routes this suite asks exempted from the route lane so that the
/// management lane alone answers them.
fn mapped_app(name: &str, document: &Value) -> MappedApp {
    let policy = TempPolicyFile::new(&document.to_string());
    let tokens = TempDb::new(name);
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.service_token_sqlite_path = Some(tokens.path.to_string_lossy().into_owned());
    // The suite sends far more requests from one client than the default
    // global lanes admit; a 429 would make both modes agree for no reason.
    config.rate_limit_read_burst = 10_000;
    config.rate_limit_write_burst = 10_000;
    for route in [
        TOKENS_ADMIN_ROUTE,
        POLICY_ADMIN_ROUTE,
        ADMIN_CAPABILITIES_ROUTE,
    ] {
        config.rbac_exempt_paths.push(route.to_owned());
    }
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("a policy with identity mappings starts");
    MappedApp {
        router,
        _policy: policy,
        _tokens: tokens,
    }
}

fn person(
    issuer: Option<&str>,
    organization: Option<&str>,
    roles: &[&str],
    auth_method: auth::AuthMethod,
) -> auth::Principal {
    auth::Principal {
        user_id: "synthetic-subject".to_owned(),
        issuer: issuer.map(str::to_owned),
        email: None,
        org_id: organization.map(str::to_owned),
        roles: roles.iter().map(|role| (*role).to_owned()).collect(),
        session_id: "synthetic-session".to_owned(),
        auth_method,
    }
}

/// What the application answers `principal` on each lane this suite reads.
#[derive(Debug, PartialEq)]
struct Answers {
    probe: StatusCode,
    permissions: Value,
    policy_read: StatusCode,
    policy_write_header: Option<String>,
    delegate_probe_reader: StatusCode,
    delegate_superadmin: StatusCode,
}

async fn answers(router: &Router, principal: &auth::Principal) -> Answers {
    let send = move |request: Request<Body>| async move {
        router
            .clone()
            .oneshot(request)
            .await
            .expect("the request completes")
    };
    let probe = send(token_admin_request(
        Method::GET,
        "/__test/principal",
        Some(principal.clone()),
        None,
    ))
    .await
    .status();
    let capabilities = send(token_admin_request(
        Method::GET,
        ADMIN_CAPABILITIES_ROUTE,
        Some(principal.clone()),
        None,
    ))
    .await;
    assert_eq!(capabilities.status(), StatusCode::OK);
    let permissions = json_body(capabilities).await["permissions"].clone();
    let policy = send(policy_admin_request(
        Method::GET,
        POLICY_ADMIN_ROUTE,
        Some(principal.clone()),
        None,
        None,
    ))
    .await;
    let policy_read = policy.status();
    let policy_write_header = policy
        .headers()
        .get("x-greengateway-policy-write")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let delegate = |scope: &str| {
        token_admin_request(
            Method::POST,
            TOKENS_ADMIN_ROUTE,
            Some(principal.clone()),
            Some(json!({ "scopes": [scope] }).to_string()),
        )
    };
    let delegate_probe_reader = send(delegate("probe-reader")).await.status();
    let delegate_superadmin = send(delegate("superadmin")).await.status();
    // Every answer is the policy's: none is the global rate lane's.
    for status in [
        probe,
        policy_read,
        delegate_probe_reader,
        delegate_superadmin,
    ] {
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
    }
    Answers {
        probe,
        permissions,
        policy_read,
        policy_write_header,
        delegate_probe_reader,
        delegate_superadmin,
    }
}

#[tokio::test]
async fn mapping_each_role_to_itself_serves_exactly_what_claimed_role_mode_serves() {
    let claimed = mapped_app("claimed-roles", &claimed_document());
    let mapped = mapped_app("self-mapped-roles", &self_mapped_document());
    let role_sets: [&[&str]; 8] = [
        &[],
        &["probe-reader"],
        &["token-admin"],
        &["policy-admin"],
        &["superadmin"],
        &["probe-reader", "token-admin"],
        &["token-admin", "policy-admin", "probe-reader"],
        &["unmapped"],
    ];
    let mut granted = 0;
    for roles in role_sets {
        for auth_method in [auth::AuthMethod::Bearer, auth::AuthMethod::Cookie] {
            let principal = person(Some(ISSUER), None, roles, auth_method.clone());
            let expected = answers(&claimed.router, &principal).await;
            let actual = answers(&mapped.router, &principal).await;
            assert_eq!(actual, expected, "{roles:?} {auth_method:?}");
            granted += usize::from(expected.probe == StatusCode::OK);
        }
    }
    // The comparison is not vacuous: some principals are admitted.
    assert!(granted > 0);

    // Off the trusted issuer the two modes part: the claimed role still
    // grants in claimed-role mode, and nothing in mapped-role mode.
    let elsewhere = person(
        Some("https://other.example.test"),
        None,
        &["probe-reader", "token-admin"],
        auth::AuthMethod::Bearer,
    );
    assert_eq!(
        answers(&claimed.router, &elsewhere).await.probe,
        StatusCode::OK
    );
    let unmapped = answers(&mapped.router, &elsewhere).await;
    assert_eq!(unmapped.probe, StatusCode::FORBIDDEN);
    assert_eq!(unmapped.permissions, json!([]));
    assert_eq!(unmapped.delegate_probe_reader, StatusCode::FORBIDDEN);
}

/// An organization mapping applies only to the organization the principal's
/// own issuer verified. Headers, another issuer's organization and a service
/// token's scopes grant nothing.
#[tokio::test]
async fn only_the_verified_organization_makes_a_mapping_apply() {
    let mut document = claimed_document();
    document["identity_mappings"] = json!([
        {
            "id": "acme-probes",
            "issuer": ISSUER,
            "organizations": ["acme"],
            "grant_roles": ["probe-reader", "token-admin"]
        }
    ]);
    let app = mapped_app("organization-mapped", &document);

    let verified = answers(
        &app.router,
        &person(Some(ISSUER), Some("acme"), &[], auth::AuthMethod::Bearer),
    )
    .await;
    assert_eq!(verified.probe, StatusCode::OK);
    assert_eq!(verified.delegate_probe_reader, StatusCode::CREATED);
    assert_eq!(verified.delegate_superadmin, StatusCode::FORBIDDEN);
    assert!(verified
        .permissions
        .as_array()
        .expect("permissions")
        .contains(&json!(ADMIN_TOKENS_WRITE_PERMISSION)));

    let refused = [
        (
            "another organization",
            person(Some(ISSUER), Some("globex"), &[], auth::AuthMethod::Bearer),
        ),
        (
            "no verified organization",
            person(Some(ISSUER), None, &[], auth::AuthMethod::Bearer),
        ),
        (
            "acme under another issuer",
            person(
                Some("https://other.example.test"),
                Some("acme"),
                &["probe-reader", "token-admin"],
                auth::AuthMethod::Bearer,
            ),
        ),
        (
            "a service token whose scopes name the roles",
            person(
                None,
                Some("acme"),
                &["probe-reader", "token-admin", "superadmin"],
                auth::AuthMethod::ServiceToken,
            ),
        ),
    ];
    for (label, principal) in refused {
        let answers = answers(&app.router, &principal).await;
        assert_eq!(answers.probe, StatusCode::FORBIDDEN, "{label}");
        assert_eq!(answers.permissions, json!([]), "{label}");
        assert_eq!(
            answers.delegate_probe_reader,
            StatusCode::FORBIDDEN,
            "{label}"
        );
        assert_eq!(answers.policy_read, StatusCode::FORBIDDEN, "{label}");
    }

    // Organization-like headers on a principal whose provider verified no
    // organization: the route lane and the management lane both ignore them.
    for (name, value) in [
        ("x-org-id", "acme"),
        ("x-organization", "acme"),
        ("x-tenant-id", "acme"),
        ("forwarded", "for=192.0.2.1;org=acme"),
    ] {
        let principal = person(Some(ISSUER), None, &[], auth::AuthMethod::Bearer);
        for uri in ["/__test/principal", ADMIN_CAPABILITIES_ROUTE] {
            let mut request = token_admin_request(Method::GET, uri, Some(principal.clone()), None);
            request
                .headers_mut()
                .insert(name, http::HeaderValue::from_static(value));
            let response = app
                .router
                .clone()
                .oneshot(request)
                .await
                .expect("the request completes");
            if uri == ADMIN_CAPABILITIES_ROUTE {
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    json_body(response).await["permissions"],
                    json!([]),
                    "{name}"
                );
            } else {
                assert_eq!(response.status(), StatusCode::FORBIDDEN, "{name}");
            }
        }
    }
}
