//! Unit tests of the compiler's own helpers and setting types, moved from
//! the gateway's `config_tests` with the code they test (issue #242).

use super::*;

#[test]
fn raw_auth_provider_config_debug_redacts_client_secret() {
    let secret = "raw-auth-provider-secret-value";
    let raw_with_secret: RawAuthProviderConfig = serde_json::from_str(&format!(
        r#"{{
                "name": "primary",
                "type": "jwt",
                "issuer": "https://issuer.example.test/",
                "jwks_url": "https://issuer.example.test/.well-known/jwks.json",
                "client_id": "admin-ui",
                "client_secret": "{secret}",
                "redirect_uri": "https://gateway.example.test/v1/admin/auth/callback"
            }}"#
    ))
    .expect("raw auth provider should parse");

    let output = format!("{:?}", raw_with_secret);

    assert!(!output.contains(secret));
    assert!(output.contains("<redacted>"));
    assert!(output.contains("client_secret"));

    let raw_without_secret: RawAuthProviderConfig = serde_json::from_str(
        r#"{
                "name": "primary",
                "type": "jwt",
                "issuer": "https://issuer.example.test/",
                "jwks_url": "https://issuer.example.test/.well-known/jwks.json",
                "client_id": "admin-ui",
                "redirect_uri": "https://gateway.example.test/v1/admin/auth/callback"
            }"#,
    )
    .expect("raw auth provider without secret should parse");

    let output_without_secret = format!("{:?}", raw_without_secret);

    assert!(output_without_secret.contains("client_secret: None"));
}

#[test]
fn parse_var_records_independent_problems() {
    let mut problems = Vec::new();

    let listen_addr = parse_var(
        "PRIMARY_LISTEN_ADDR",
        Ok("not-a-socket".to_owned()),
        "127.0.0.1:8080"
            .parse::<SocketAddr>()
            .expect("test default address should parse"),
        "socket address",
        &mut problems,
    );
    let enabled = parse_var(
        "FEATURE_ENABLED",
        Ok("maybe".to_owned()),
        false,
        "boolean",
        &mut problems,
    );

    assert_eq!(
        listen_addr,
        "127.0.0.1:8080"
            .parse::<SocketAddr>()
            .expect("test default address should parse")
    );
    assert!(!enabled);
    assert_eq!(problems.len(), 2);
    assert!(problems.iter().any(|problem| problem
            == "PRIMARY_LISTEN_ADDR must be a valid socket address, got 'not-a-socket': invalid socket address syntax"));
    assert!(problems.iter().any(|problem| problem
            == "FEATURE_ENABLED must be a valid boolean, got 'maybe': provided string was not `true` or `false`"));
}
