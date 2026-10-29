//! Serving startup's stages (issue #433, PR 3), run against a recording
//! double.
//!
//! `start_serving` is the sequence `run()` executes: the configuration
//! compiler, then preflight, activation and serving. The double stands in
//! for every stage that does I/O and records each call, interleaved with
//! every variable the compiler asks the environment for. That shows the
//! compiler runs first and alone, that every stage receives its one result,
//! that a refused configuration reaches no stage at all, and that a stage
//! that fails stops the ones after it -- with a failure before the gateway
//! served withdrawing what preflight had published.

use std::{cell::RefCell, env::VarError, rc::Rc};

use super::*;

/// One thing startup did, in the order it did it.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Call {
    /// The compiler asked the environment for a variable.
    Read(String),
    Preflight,
    Activate,
    Withdraw,
    Serve,
}

/// Where the double fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    /// Preflight, before it publishes anything.
    Preflight,
    /// Preflight, after it published this boot's membership row.
    PreflightAfterPublishing,
    Activation,
    /// Serving, before any listener served: a bind failure.
    Serving,
    /// Serving, after the gateway became ready.
    ServingAfterReady,
}

/// What the double's preflight hands activation and what it publishes, so
/// the tests can see each reach the stage it is meant for.
const SEEDS: u64 = 433;
const PUBLISHED: &str = "this boot's membership row";

/// A stand-in for the stages that do I/O. It records every call and the
/// configuration each stage was given, and fails at `fail_at`. Its
/// preflight also runs `at_preflight`, which sees the world as the compiler
/// left it.
struct RecordingStages {
    calls: Rc<RefCell<Vec<Call>>>,
    fail_at: Option<Stage>,
    at_preflight: Box<dyn Fn()>,
    preflighted: Option<config::Config>,
    activated: Option<config::Config>,
    withdrawn: Option<&'static str>,
}

impl StartupStages for RecordingStages {
    type Seeds = u64;
    type Published = &'static str;
    type Activated = u64;

    async fn preflight(
        &mut self,
        config: &config::Config,
        published: &mut Option<&'static str>,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        self.calls.borrow_mut().push(Call::Preflight);
        (self.at_preflight)();
        self.preflighted = Some(config.clone());
        if self.fail_at == Some(Stage::Preflight) {
            return Err("the database did not answer".into());
        }
        *published = Some(PUBLISHED);
        if self.fail_at == Some(Stage::PreflightAfterPublishing) {
            return Err("the authority event journal capacity could not be applied".into());
        }
        Ok(SEEDS)
    }

    async fn activate(
        &mut self,
        config: config::Config,
        seeds: u64,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        self.calls.borrow_mut().push(Call::Activate);
        assert_eq!(seeds, SEEDS, "activation builds from preflight's seeds");
        self.activated = Some(config);
        if self.fail_at == Some(Stage::Activation) {
            return Err("the TLS private key could not be read".into());
        }
        Ok(seeds + 1)
    }

    async fn withdraw(&mut self, published: &'static str) {
        self.calls.borrow_mut().push(Call::Withdraw);
        self.withdrawn = Some(published);
    }

    async fn serve(&mut self, activated: u64) -> Result<(), ServingFailure> {
        self.calls.borrow_mut().push(Call::Serve);
        assert_eq!(activated, SEEDS + 1, "serving gets what activation built");
        match self.fail_at {
            Some(Stage::Serving) => Err(ServingFailure::NeverServed(
                "the data listener address is in use".into(),
            )),
            Some(Stage::ServingAfterReady) => Err(ServingFailure::AfterServing(
                "the data listener stopped accepting connections".into(),
            )),
            _ => Ok(()),
        }
    }
}

fn fixture_value(fixture: &[(&str, &str)], name: &str) -> Result<String, VarError> {
    fixture
        .iter()
        .find(|(variable, _)| *variable == name)
        .map(|(_, value)| (*value).to_owned())
        .ok_or(VarError::NotPresent)
}

/// Serving startup over `fixture`, with the double failing at `fail_at`.
fn start(
    fixture: &[(&str, &str)],
    fail_at: Option<Stage>,
    at_preflight: Box<dyn Fn()>,
) -> (Result<(), StartupFailure>, RecordingStages) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    let mut stages = RecordingStages {
        calls: Rc::clone(&calls),
        fail_at,
        at_preflight,
        preflighted: None,
        activated: None,
        withdrawn: None,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a current-thread runtime should build");
    let result = runtime.block_on(start_serving(&mut stages, |name| {
        calls.borrow_mut().push(Call::Read(name.to_owned()));
        fixture_value(fixture, name)
    }));
    (result, stages)
}

/// The variables `Config::from_env_vars` asks for, in order.
fn legacy_reads(fixture: &[(&str, &str)]) -> Vec<Call> {
    let mut reads = Vec::new();
    let _ = config::Config::from_env_vars(|name| {
        reads.push(Call::Read(name.to_owned()));
        fixture_value(fixture, name)
    });
    reads
}

/// What the stages were called for, after the compiler's reads.
fn stage_calls(stages: &RecordingStages) -> Vec<Call> {
    stages
        .calls
        .borrow()
        .iter()
        .filter(|call| !matches!(call, Call::Read(_)))
        .cloned()
        .collect()
}

fn stage_error(result: Result<(), StartupFailure>) -> String {
    match result {
        Err(StartupFailure::Stage(error)) => error.to_string(),
        other => panic!("expected a stage failure, got {other:?}"),
    }
}

fn nothing_to_check() -> Box<dyn Fn()> {
    Box::new(|| {})
}

/// A standalone configuration that names upstreams, an identity provider
/// and an MCP server by host, TLS material, and stores and documents by
/// path.
const STANDALONE: &[(&str, &str)] = &[
    ("ADMIN_LISTEN_ADDR", "127.0.0.1:9091"),
    ("TLS_CERT_FILE", "tls/data.crt"),
    ("TLS_KEY_FILE", "tls/data.key"),
    ("UPSTREAM_URL", "https://upstream.invalid"),
    (
        "AUTH_PROVIDERS",
        r#"[{"name":"corp","type":"jwt","issuer":"https://issuer.invalid"}]"#,
    ),
    (
        "MCP_UPSTREAM_SERVERS",
        r#"[{"name":"docs","url":"https://mcp.invalid/mcp"}]"#,
    ),
    ("AUDIT_SQLITE_PATH", "stores/audit.sqlite"),
    ("POLICY_FILE", "documents/policy.json"),
];

#[test]
fn the_compiler_runs_first_and_alone_and_every_stage_gets_its_one_result() {
    let (result, stages) = start(STANDALONE, None, nothing_to_check());
    assert!(result.is_ok(), "{result:?}");

    // Every read comes first, and they are exactly the reads the legacy
    // parser makes: no stage asks the environment for anything.
    let calls = stages.calls.borrow().clone();
    let reads = legacy_reads(STANDALONE);
    assert!(!reads.is_empty());
    assert_eq!(calls[..reads.len()], reads[..]);
    assert_eq!(
        calls[reads.len()..],
        [Call::Preflight, Call::Activate, Call::Serve]
    );

    // Preflight and activation are given the one compiled result, which
    // is the configuration `Config::from_env` builds.
    let expected = config::Config::from_env_vars(|name| fixture_value(STANDALONE, name))
        .expect("the fixture is valid");
    assert_eq!(stages.preflighted.as_ref(), Some(&expected));
    assert_eq!(stages.activated.as_ref(), Some(&expected));
    assert_eq!(stages.withdrawn, None);
}

#[test]
fn a_refused_configuration_stops_startup_before_any_stage() {
    let refused = [
        ("LISTEN_ADDR", "not an address"),
        ("STATE_BACKEND", "postgres"),
        ("UPSTREAM_URL", "https://upstream.invalid"),
    ];
    let (result, stages) = start(&refused, None, nothing_to_check());
    let Err(StartupFailure::Configuration(error)) = result else {
        panic!("expected the compiler to refuse the configuration, got {result:?}");
    };
    // The refusal is the one `Config::from_env` reports, problem for
    // problem and diagnostic for diagnostic ...
    let legacy = config::Config::from_env_vars(|name| fixture_value(&refused, name))
        .expect_err("the fixture is refused");
    assert_eq!(error, legacy);
    // ... and nothing but the environment was consulted to find it.
    assert_eq!(*stages.calls.borrow(), legacy_reads(&refused));
    assert!(stage_calls(&stages).is_empty());
    assert_eq!(stages.preflighted, None);
}

#[test]
fn a_preflight_failure_activates_nothing() {
    let (result, stages) = start(STANDALONE, Some(Stage::Preflight), nothing_to_check());
    assert_eq!(stage_error(result), "the database did not answer");
    assert_eq!(stage_calls(&stages), [Call::Preflight]);
    assert_eq!(stages.activated, None);
    assert_eq!(stages.withdrawn, None, "nothing was published to withdraw");
}

#[test]
fn a_preflight_failure_after_publishing_withdraws_what_it_published() {
    // Cluster preflight writes this boot's membership row and then still
    // has the first agreement check to run, and with it the admission
    // writes (the authority-event journal capacity); a boot refused there
    // never serves, so its row must not be left looking like one that
    // might.
    let (result, stages) = start(
        STANDALONE,
        Some(Stage::PreflightAfterPublishing),
        nothing_to_check(),
    );
    assert_eq!(
        stage_error(result),
        "the authority event journal capacity could not be applied"
    );
    assert_eq!(stage_calls(&stages), [Call::Preflight, Call::Withdraw]);
    assert_eq!(stages.activated, None);
    assert_eq!(stages.withdrawn, Some(PUBLISHED));
}

#[test]
fn an_activation_failure_withdraws_what_preflight_published_and_never_serves() {
    let (result, stages) = start(STANDALONE, Some(Stage::Activation), nothing_to_check());
    assert_eq!(stage_error(result), "the TLS private key could not be read");
    assert_eq!(
        stage_calls(&stages),
        [Call::Preflight, Call::Activate, Call::Withdraw]
    );
    assert_eq!(stages.withdrawn, Some(PUBLISHED));
}

#[test]
fn a_listener_that_cannot_be_bound_withdraws_what_preflight_published() {
    // No listener served, so this is a startup failure like activation's:
    // a replica crash-looping on an address in use must not keep a row
    // that holds every newcomer at the fingerprint door.
    let (result, stages) = start(STANDALONE, Some(Stage::Serving), nothing_to_check());
    assert_eq!(stage_error(result), "the data listener address is in use");
    assert_eq!(
        stage_calls(&stages),
        [Call::Preflight, Call::Activate, Call::Serve, Call::Withdraw]
    );
    assert_eq!(stages.withdrawn, Some(PUBLISHED));
}

#[test]
fn a_failure_after_serving_is_returned_as_it_is() {
    // Serving owns its own shutdown once a listener has served, so nothing
    // is withdrawn on its behalf.
    let (result, stages) = start(
        STANDALONE,
        Some(Stage::ServingAfterReady),
        nothing_to_check(),
    );
    assert_eq!(
        stage_error(result),
        "the data listener stopped accepting connections"
    );
    assert_eq!(
        stage_calls(&stages),
        [Call::Preflight, Call::Activate, Call::Serve]
    );
    assert_eq!(stages.withdrawn, None);
}

/// The gateway's serving stage tells the two apart by the lifecycle phase
/// `serve_gateway` left: it marks the gateway ready only once every
/// listener is bound and readiness is announced, so an error while it is
/// still starting means nothing served.
#[test]
fn a_serving_error_is_classified_by_whether_the_gateway_became_ready() {
    let classify = |lifecycle: &GatewayLifecycle| {
        ServingFailure::from_lifecycle("the listener failed".into(), lifecycle)
    };

    let lifecycle = GatewayLifecycle::new();
    assert!(matches!(
        classify(&lifecycle),
        ServingFailure::NeverServed(error) if error.to_string() == "the listener failed"
    ));

    lifecycle.mark_ready();
    assert!(matches!(
        classify(&lifecycle),
        ServingFailure::AfterServing(_)
    ));

    lifecycle.begin_draining();
    assert!(matches!(
        classify(&lifecycle),
        ServingFailure::AfterServing(_)
    ));
}

/// Compiling a configuration opens, creates, resolves, connects to and
/// migrates nothing it names.
///
/// Every file, store, secret root and keyring below lives under a directory
/// that does not exist, the database URL file included, and every host is
/// under `.invalid`, which never resolves (RFC 6761). Both configurations
/// are accepted, which they could not be if the compiler had read the URL
/// file to connect -- let alone migrate, as `DATABASE_AUTO_MIGRATE` allows
/// -- or had resolved an issuer, an upstream, an MCP server or a provider's
/// endpoint. The double's preflight is the first call after the compiler
/// returns, and it finds the directory still absent: nothing was created
/// on the way there, no SQLite store, audit file or keyring. The compiler is
/// handed no resolver, client, store or provider to call, and the source
/// scan in `config/stage_tests.rs` holds that it reaches for none.
#[test]
fn compiling_touches_nothing_the_configuration_names() {
    let root =
        std::env::temp_dir().join(format!("greengateway-433-startup-{}", uuid::Uuid::new_v4()));
    assert!(!root.exists(), "{} should not exist", root.display());
    let path = |file: &str| root.join(file).to_string_lossy().into_owned();
    let (secrets, database_url) = (path("secrets"), path("secrets/database-url"));
    let gcp_provider = format!(
        r#"{{"profiles":[{{"id":"primary","audience":"//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gateway-pool/providers/gateway-provider","token_root":"{}","token_file":"gcp-token"}}],"aliases":[{{"id":"billing","label":"Billing","profile":"primary","project":"billing-project","secret":"billing-credential"}}]}}"#,
        path("tokens").replace('\\', "\\\\"),
    );
    let keyring = r#"[{"id":"primary","file":"local-key","role":"primary"}]"#;
    let (certificate, key) = (path("tls/data.crt"), path("tls/data.key"));
    let (audit_log, audit, discovery, connections, tokens) = (
        path("audit.jsonl"),
        path("stores/audit.sqlite"),
        path("stores/discovery.sqlite"),
        path("stores/connections.sqlite"),
        path("stores/tokens.sqlite"),
    );
    let (policy, tools) = (path("documents/policy.json"), path("documents/tools.json"));
    let names_every_dependency: [(&str, &str); 5] = [
        ("UPSTREAM_URL", "https://upstream.invalid"),
        (
            "AUTH_PROVIDERS",
            r#"[{"name":"corp","type":"jwt","issuer":"https://issuer.invalid"}]"#,
        ),
        (
            "MCP_UPSTREAM_SERVERS",
            r#"[{"name":"docs","url":"https://mcp.invalid/mcp"}]"#,
        ),
        ("EGRESS_ALLOWED_HOSTS", "egress.invalid"),
        ("CONNECTION_GCP_PROVIDER", &gcp_provider),
    ];
    let standalone = [
        ("TLS_CERT_FILE", certificate.as_str()),
        ("TLS_KEY_FILE", &key),
        ("AUDIT_LOG_FILE", &audit_log),
        ("AUDIT_SQLITE_PATH", &audit),
        ("DISCOVERY_SQLITE_PATH", &discovery),
        ("CONNECTIONS_SQLITE_PATH", &connections),
        ("SERVICE_TOKEN_SQLITE_PATH", &tokens),
        ("POLICY_FILE", &policy),
        ("TOOLS_FILE", &tools),
        ("CONNECTION_SECRETS_ROOT", &secrets),
        ("CONNECTION_LOCAL_SECRET_KEYRING", keyring),
    ];
    let cluster = [
        ("STATE_BACKEND", "postgres"),
        ("DEPLOYMENT_ID", "deploy-prod-eu"),
        ("DATABASE_URL_FILE", database_url.as_str()),
        ("DATABASE_AUTO_MIGRATE", "true"),
        ("CONNECTION_SECRETS_ROOT", &secrets),
        ("RATE_LIMIT_KEYRING", keyring),
    ];

    for mode in [&standalone[..], &cluster[..]] {
        let fixture = [mode, &names_every_dependency[..]].concat();
        let absent = root.clone();
        let (result, stages) = start(
            &fixture,
            None,
            Box::new(move || {
                assert!(
                    !absent.exists(),
                    "compiling the configuration created {}",
                    absent.display()
                );
            }),
        );
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            stage_calls(&stages),
            [Call::Preflight, Call::Activate, Call::Serve]
        );
        let preflighted = stages.preflighted.expect("preflight ran");
        assert_eq!(
            preflighted.upstream_url.as_deref(),
            Some("https://upstream.invalid")
        );
    }
    assert!(!root.exists());
}
