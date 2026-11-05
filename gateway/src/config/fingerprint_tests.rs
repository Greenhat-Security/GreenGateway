//! The static-configuration fingerprint of a compiled configuration (issue
//! #433, PR 2).
//!
//! The compiler's stage tests (`gateway_config::compiler`) hold its plans
//! free of printed secrets. The fingerprint is computed from the gateway's
//! `Config`, so the test that it ignores them is the gateway's.

use std::env::VarError;

use super::into_config;

/// The static-configuration fingerprint -- the one digest of the
/// configuration, written to the membership roster and served by the
/// cluster status API -- is the same whatever the secrets are and wherever
/// they are kept, while the plans it is computed from do differ in them.
///
/// A route's upstream TLS material locators are deliberately part of it
/// (`ha::insert_route`: they decide which trust the route carries), so they
/// are held fixed here.
#[test]
fn the_fingerprint_is_the_same_whatever_the_secrets_and_their_locators_are() {
    let configuration = |tag: &str| -> Vec<(&'static str, String)> {
        vec![
            ("STATE_BACKEND", "postgres".to_owned()),
            ("DEPLOYMENT_ID", "deploy-prod-eu".to_owned()),
            ("DATABASE_URL_FILE", format!("/run/{tag}/database-url")),
            ("CONNECTION_SECRETS_ROOT", format!("/run/{tag}")),
            (
                "RATE_LIMIT_KEYRING",
                format!(r#"[{{"id":"rate","file":"{tag}-rate-key","role":"primary"}}]"#),
            ),
            (
                "ADMIN_LOGIN_KEYRING",
                format!(r#"[{{"id":"login","file":"{tag}-login-key","role":"primary"}}]"#),
            ),
            ("TLS_CERT_FILE", "/run/tls/data.crt".to_owned()),
            ("TLS_KEY_FILE", format!("/run/{tag}/data.key")),
            (
                "AUTH_PROVIDERS",
                format!(
                    r#"[{{"name":"primary","type":"jwt","issuer":"https://issuer.example.test","client_id":"admin-ui","client_secret":"{tag}-client-secret"}}]"#
                ),
            ),
            (
                "UPSTREAM_ROUTES",
                format!(
                    r#"[{{"id":"billing","path_prefix":"/billing","upstream_url":"https://billing.example.test","add_request_headers":{{"x-route-key":"{tag}-header-value"}}}}]"#
                ),
            ),
            (
                "CONNECTION_SECRET_ALIASES",
                format!(
                    r#"[{{"id":"billing","label":"Billing","source":{{"type":"environment","key":"{}_TOKEN"}}}}]"#,
                    tag.to_ascii_uppercase()
                ),
            ),
            (
                "CONNECTION_GCP_PROVIDER",
                format!(
                    r#"{{"profiles":[{{"id":"primary","audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gateway-pool/providers/gateway-provider","token_root":"/run/{tag}-tokens","token_file":"{tag}-token"}}],"aliases":[{{"id":"gcp-ledger","label":"Ledger","profile":"primary","project":"{tag}-project","secret":"{tag}-secret"}}]}}"#
                ),
            ),
        ]
    };
    let compiled = |tag: &str| {
        let fixture = configuration(tag);
        let fixture: Vec<(&str, &str)> = fixture
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();
        super::compile(|name| {
            fixture
                .iter()
                .find(|(variable, _)| *variable == name)
                .map(|(_, value)| (*value).to_owned())
                .ok_or(VarError::NotPresent)
        })
        .unwrap_or_else(|error| panic!("{tag}: {error}"))
    };
    let (first, second) = (compiled("zqcanary"), compiled("relocated"));
    assert_ne!(first, second, "the plans differ in their secrets");

    let (first, second) = (into_config(first), into_config(second));
    let fingerprint = crate::ha::static_config_fingerprint(&first);
    assert_eq!(fingerprint, crate::ha::static_config_fingerprint(&second));
    let rendered = format!("{fingerprint} {fingerprint:?}").to_ascii_lowercase();
    assert!(!rendered.contains("zqcanary"), "{rendered}");
}
