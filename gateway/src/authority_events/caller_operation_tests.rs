use super::*;

fn operator() -> ChangeActor {
    ChangeActor::for_test_with_issuer("operator", "https://issuer.example.test")
}

fn bind(binding: &CallerOperationBinding<'_>) -> CallerOperation {
    CallerOperation::bind(test_caller_key(1), binding).expect("the key binds")
}

/// The digest is SHA-256 over the domain and every field as an eight-byte
/// big-endian length and its bytes, in the documented order. Moving bytes
/// from one field into the next, changing any one field, or computing it
/// outside the domain each give another digest.
#[test]
fn the_binding_digest_is_domain_separated_and_length_prefixed() {
    let actor = operator();
    let base = CallerOperationBinding {
        action: "connection.replace",
        actor: &actor,
        target: "connection-a",
        precondition: "\"etag-1\"",
        request: br#"{"name":"a"}"#,
    };
    let digest = bind(&base).binding_digest().to_owned();
    assert_eq!(digest.len(), 64);
    assert!(digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_eq!(bind(&base).binding_digest(), digest, "deterministic");

    let mut expected = Sha256::new();
    expected.update(b"greengateway.caller_operation.binding.v1");
    for field in [
        &b"connection.replace"[..],
        b"principal",
        b"https://issuer.example.test",
        b"operator",
        b"bearer_token",
        b"connection-a",
        b"\"etag-1\"",
        br#"{"name":"a"}"#,
    ] {
        expected.update((field.len() as u64).to_be_bytes());
        expected.update(field);
    }
    assert_eq!(digest, hex::encode(expected.finalize()));

    let mut undomained = Sha256::new();
    for field in [
        &b"connection.replace"[..],
        b"principal",
        b"https://issuer.example.test",
        b"operator",
        b"bearer_token",
        b"connection-a",
        b"\"etag-1\"",
        br#"{"name":"a"}"#,
    ] {
        undomained.update((field.len() as u64).to_be_bytes());
        undomained.update(field);
    }
    assert_ne!(digest, hex::encode(undomained.finalize()));

    // The same bytes, split at another field boundary.
    let shifted = CallerOperationBinding {
        target: "connection-a\"etag-1",
        precondition: "\"",
        ..base
    };
    assert_ne!(bind(&shifted).binding_digest(), digest);
    let into_request = CallerOperationBinding {
        precondition: "",
        request: br#""etag-1"{"name":"a"}"#,
        ..base
    };
    assert_ne!(bind(&into_request).binding_digest(), digest);

    let other_issuer = ChangeActor::for_test_with_issuer("operator", "https://other.example.test");
    let other_subject =
        ChangeActor::for_test_with_issuer("operator-2", "https://issuer.example.test");
    let service = ChangeActor::service_token_for_test("operator");
    let mut digests = vec![digest];
    for changed in [
        CallerOperationBinding {
            action: "connection.create",
            ..base
        },
        CallerOperationBinding {
            actor: &other_issuer,
            ..base
        },
        CallerOperationBinding {
            actor: &other_subject,
            ..base
        },
        CallerOperationBinding {
            actor: &service,
            ..base
        },
        CallerOperationBinding {
            target: "connection-b",
            ..base
        },
        CallerOperationBinding {
            precondition: "\"etag-2\"",
            ..base
        },
        CallerOperationBinding {
            request: br#"{"name":"b"}"#,
            ..base
        },
    ] {
        let changed = bind(&changed).binding_digest().to_owned();
        assert!(
            !digests.contains(&changed),
            "every field is bound: {changed}"
        );
        digests.push(changed);
    }
}

/// A key the caller did not assign, an actor nobody authenticated, a
/// principal without a canonical issuer, and a request naming no action
/// cannot bind. An issuer-bound principal and a service token can.
#[test]
fn a_system_actor_or_a_non_v7_id_cannot_bind() {
    let principal = operator();
    let binding = |actor| CallerOperationBinding {
        action: "service_token.issue",
        actor,
        target: "",
        precondition: "",
        request: b"{}",
    };
    for refused in [
        uuid::Uuid::nil(),
        uuid::Uuid::new_v4(),
        uuid::Uuid::from_u128(u128::MAX),
    ] {
        assert_eq!(
            CallerOperation::bind(refused, &binding(&principal)),
            Err(BindingRefusal::NotCallerAssigned),
            "{refused}"
        );
    }
    let system = ChangeActor::system("operator:revoke-jwt");
    let unissued = ChangeActor::for_test("operator");
    for actor in [&system, &unissued] {
        assert_eq!(
            CallerOperation::bind(test_caller_key(2), &binding(actor)),
            Err(BindingRefusal::ActorCannotBind)
        );
    }
    assert_eq!(
        CallerOperation::bind(
            test_caller_key(2),
            &CallerOperationBinding {
                action: "",
                ..binding(&principal)
            }
        ),
        Err(BindingRefusal::MissingAction)
    );

    let service = ChangeActor::service_token_for_test("service-token:automation");
    for actor in [&principal, &service] {
        let bound =
            CallerOperation::bind(test_caller_key(3), &binding(actor)).expect("the actor binds");
        assert_eq!(bound.id(), test_caller_key(3));
        assert_eq!(bound.action(), "service_token.issue");
    }
}

/// The binding digest never appears in a `{:?}` rendering, so a `tracing`
/// field or an error message cannot leak it. The key and action still do.
#[test]
fn debug_output_redacts_the_binding_digest() {
    let actor = operator();
    let operation = bind(&CallerOperationBinding {
        action: "connection.create",
        actor: &actor,
        target: "",
        precondition: "",
        request: br#"{"secret_id":"alias-a"}"#,
    });
    for rendered in [format!("{operation:?}"), format!("{operation:#?}")] {
        assert!(!rendered.contains(operation.binding_digest()), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains(&operation.id().to_string()), "{rendered}");
        assert!(rendered.contains("connection.create"), "{rendered}");
    }
    let wrapped: Result<CallerOperation, BindingRefusal> = Ok(operation.clone());
    assert!(!format!("{wrapped:?}").contains(operation.binding_digest()));
}

/// Only the same action with the same digest is the same request. A
/// reservation without a digest -- a keyed revoke's or prepare's -- never is.
#[test]
fn only_the_same_action_and_digest_is_the_same_request() {
    let actor = operator();
    let operation = bind(&CallerOperationBinding {
        action: "service_token.rotate",
        actor: &actor,
        target: "token-a",
        precondition: "",
        request: b"{}",
    });
    let digest = operation.binding_digest().to_owned();
    assert_eq!(
        operation.judge("service_token.rotate", Some(&digest)),
        CallerKeyState::SameBinding
    );
    for (action, stored) in [
        ("service_token.issue", Some(digest.as_str())),
        ("service_token.rotate", Some(&"0".repeat(64)[..])),
        ("service_token.rotate", None),
        ("service_token.revoke", None),
    ] {
        assert_eq!(
            operation.judge(action, stored),
            CallerKeyState::OtherBinding,
            "{action} {stored:?}"
        );
    }
}
