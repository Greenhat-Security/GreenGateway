//! What `ggctl --env` decides about an environment file is what the
//! gateway's startup decides about the same variables (issue #242).
//!
//! `ggctl validate`, `ggctl doctor` and `ggctl diff --env` parse a file with
//! `gateway_config::env_file`, the grammar `gateway import-standalone` reads
//! too, and compile what it sets with `EnvFile::compile`; a file is valid
//! when no line is malformed and that compilation succeeds. The gateway
//! compiles its environment with `Config::from_env_vars`. Each parity
//! fixture below is a set of variables, after the parity goldens and rule
//! fixtures of `gateway_config::compiler`, written out as an environment
//! file in each spelling the grammar accepts: the file must parse back to
//! exactly those variables, `ggctl`'s verdict must be the gateway's, a
//! refusal must carry the gateway's problems and diagnostics, and an
//! accepted file must convert to the very `Config` the gateway would start
//! from.

use std::{collections::BTreeMap, env::VarError};

use gateway_config::env_file::EnvFile;

use super::{into_config, Config};

/// An upstream route document, and an identity provider document holding a
/// client secret inline.
const ROUTES: &str = r#"[{"id":"billing","path_prefix":"/billing","upstreams":[{"id":"primary","url":"https://billing.example.test"}],"add_request_headers":{"x-route-label":"zqcanary"}}]"#;
const PROVIDERS: &str = r#"[{"name":"primary","type":"jwt","issuer":"https://issuer.example.test","client_id":"admin-ui","client_secret":"zqcanary","redirect_uri":"https://management.example.test/v1/admin/auth/callback"}]"#;

const PARITY_FIXTURES: &[(&str, &[(&str, &str)])] = &[
    ("the empty environment", &[]),
    (
        "split listeners",
        &[
            ("LISTEN_ADDR", "127.0.0.1:9090"),
            ("ADMIN_LISTEN_ADDR", "127.0.0.1:9091"),
        ],
    ),
    (
        "the admin listener on the data listener's address",
        &[("ADMIN_LISTEN_ADDR", "0.0.0.0:8080")],
    ),
    ("an unknown authentication mode", &[("AUTH_MODE", "zqcanary")]),
    (
        "authentication observed, CSRF off and private egress allowed",
        &[
            ("AUTH_MODE", "observe"),
            ("CSRF_ENABLED", "false"),
            ("EGRESS_DENY_PRIVATE_IPS", "false"),
            ("AUDIT_DURABILITY", "best_effort"),
        ],
    ),
    (
        "a certificate without its key",
        &[("TLS_CERT_FILE", "/run/tls/data.crt")],
    ),
    (
        "paired listener TLS",
        &[
            ("TLS_CERT_FILE", "/run/tls/data.crt"),
            ("TLS_KEY_FILE", "/run/secrets/zqcanary-data.key"),
        ],
    ),
    (
        "client certificates without a CA bundle",
        &[
            ("TLS_CERT_FILE", "/run/tls/data.crt"),
            ("TLS_KEY_FILE", "/run/secrets/data.key"),
            ("CLIENT_CERT_MODE", "required"),
        ],
    ),
    (
        "blank values, cleared lists and a custom admin prefix",
        &[
            ("ADMIN_PREFIX", "/operations"),
            ("CORS_ALLOW_ORIGINS", ""),
            ("AUTH_EXEMPT_PATHS", ","),
            ("AUDIT_LOG_FILE", ""),
        ],
    ),
    (
        "values with leading spaces, equals signs, quotes and hashes",
        &[
            ("LISTEN_ADDR", " 127.0.0.1:9090"),
            ("UPSTREAM_URL", "https://api.example.test/base?a=b#c"),
            ("CSRF_COOKIE_NAME", "\"quoted\""),
        ],
    ),
    (
        "both routing sources",
        &[
            ("UPSTREAM_URL", "https://api.example.test"),
            ("UPSTREAM_ROUTES", ROUTES),
        ],
    ),
    (
        "a route document and a policy",
        &[
            ("UPSTREAM_ROUTES", ROUTES),
            ("POLICY_FILE", "/srv/policy.json"),
        ],
    ),
    (
        "an identity provider holding a client secret inline",
        &[("AUTH_PROVIDERS", PROVIDERS)],
    ),
    (
        "an unparseable identity provider document",
        &[("AUTH_PROVIDERS", "[{\"name\":\"corp\",\"type\":\"zqcanary\"}")],
    ),
    (
        "proxy headers trusted from no network",
        &[("TRUST_PROXY_HEADERS", "true")],
    ),
    (
        "cluster mode without what it requires",
        &[("STATE_BACKEND", "postgres")],
    ),
    (
        "a cluster setting in standalone mode",
        &[("CLUSTER_HEARTBEAT_MS", "5000")],
    ),
    (
        "standalone payload capture without a store",
        &[("PAYLOAD_CAPTURE_ENABLED", "true")],
    ),
    (
        "an authority-event sink without its key",
        &[("AUTHORITY_EVENT_SINK", "log")],
    ),
    (
        "egress hosts, one of them refused",
        &[("EGRESS_ALLOWED_HOSTS", "api.example.test, not a host")],
    ),
    (
        "several problems at once, in the order they are read",
        &[
            ("LISTEN_ADDR", "zqcanary"),
            ("MAX_BODY_SIZE", "-1"),
            ("AUTH_MODE", "zqcanary"),
            ("STATE_BACKEND", "zqcanary"),
        ],
    ),
];

/// The fixture's variables, as the gateway's reader answers them.
fn variables(fixture: &[(&str, &str)]) -> BTreeMap<String, String> {
    fixture
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

/// The spellings of one fixture the grammar must read back as its
/// variables: plain lines; `export`, comments, blank lines, indentation,
/// space before `=` and CRLF line endings; and every key first assigned a
/// decoy that a later assignment overrides.
fn spellings(fixture: &[(&str, &str)]) -> Vec<(String, usize)> {
    let plain: String = fixture
        .iter()
        .map(|(name, value)| format!("{name}={value}\n"))
        .collect();
    let decorated: String = std::iter::once("# the gateway's environment\r\n\r\n".to_owned())
        .chain(
            fixture
                .iter()
                .map(|(name, value)| format!("  export {name} ={value}\r\n# --\r\n")),
        )
        .collect();
    let overridden: String = fixture
        .iter()
        .map(|(name, value)| format!("{name}=zqcanary-decoy\n{name}={value}\n"))
        .collect();
    vec![(plain, 0), (decorated, 0), (overridden, fixture.len())]
}

#[test]
fn ggctl_reaches_the_gateways_verdict_on_every_parity_fixture() {
    let mut accepted = 0;
    let mut refused = 0;
    for (name, fixture) in PARITY_FIXTURES {
        let expected = variables(fixture);
        let gateway = Config::from_env_vars(|variable| {
            expected
                .get(variable)
                .cloned()
                .ok_or(VarError::NotPresent)
        });
        match &gateway {
            Ok(_) => accepted += 1,
            Err(_) => refused += 1,
        }
        for (text, repeated) in spellings(fixture) {
            let file = EnvFile::parse(&text);
            assert!(file.malformed_lines().is_empty(), "{name}: {text:?}");
            assert_eq!(file.duplicate_keys().len(), repeated, "{name}");
            assert_eq!(file.clone().into_variables(), expected, "{name}: {text:?}");
            match (file.compile(), &gateway) {
                (Ok(plan), Ok(config)) => {
                    assert_eq!(&into_config(plan), config, "{name}");
                }
                (Err(error), Err(expected)) => {
                    assert_eq!(error.problems(), expected.problems(), "{name}");
                    assert_eq!(error.diagnostics(), expected.diagnostics(), "{name}");
                }
                (ggctl, _) => panic!(
                    "{name}: ggctl {} what the gateway {}",
                    if ggctl.is_ok() { "accepts" } else { "refuses" },
                    if gateway.is_ok() { "accepts" } else { "refuses" },
                ),
            }
        }
    }
    assert!(
        accepted >= 5 && refused >= 10,
        "the fixtures cover both verdicts: {accepted} accepted, {refused} refused"
    );
}
