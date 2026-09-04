//! Tests for `gateway import-standalone` (issue #241, PR 15).
//!
//! The pure halves -- argument parsing, the environment-file reader, the
//! redaction of configuration problems -- run everywhere. The sections run
//! against a real PostgreSQL and are gated on the same locator every other
//! storage suite uses; a checkout without a database skips them.

use super::*;

#[test]
fn the_default_mode_is_a_dry_run_and_apply_resume_are_explicit() {
    let request = ImportRequest::parse(words(&["--from", "env"])).expect("a --from is enough");
    assert_eq!(request.mode, ImportMode::DryRun);
    assert_eq!(request.standalone_env_file, PathBuf::from("env"));
    assert!(!request.mode.writes(), "the default must write nothing");

    assert_eq!(
        ImportRequest::parse(words(&["--from", "env", "--apply"]))
            .expect("apply parses")
            .mode,
        ImportMode::Apply
    );
    assert_eq!(
        ImportRequest::parse(words(&["--from", "env", "--apply", "--resume"]))
            .expect("apply+resume parses")
            .mode,
        ImportMode::Resume
    );
}

#[test]
fn contradictory_or_incomplete_argument_lists_are_refused() {
    for arguments in [
        vec![],
        vec!["--apply"],
        vec!["--from"],
        vec!["--from", "env", "--apply", "--dry-run"],
        vec!["--from", "env", "--resume"],
        vec!["--from", "env", "--from", "other"],
        vec!["--from", "env", "--unknown"],
        vec!["env"],
    ] {
        let error = ImportRequest::parse(words(&arguments))
            .expect_err("the argument list should be refused");
        assert_eq!(error.code(), "usage", "for {arguments:?}");
    }
}

/// A refusal's `code()` is what an operator's runbook matches on, so the
/// codes are asserted verbatim: renaming one is a breaking change.
#[test]
fn every_refusal_carries_a_stable_code() {
    assert_eq!(
        ImportError::TargetNamespaceNotEmpty {
            occupied: vec!["audit_events=3".to_owned()]
        }
        .code(),
        "target_namespace_not_empty"
    );
    assert_eq!(
        ImportError::StandaloneNotStandalone.code(),
        "standalone_config_is_not_standalone"
    );
    assert_eq!(
        ImportError::StandalonePolicyFileMissing.code(),
        "standalone_policy_file_missing"
    );
    assert_eq!(
        ImportError::SectionConflict { section: "policy" }.code(),
        "section_conflict"
    );
}

/// The report's "not imported" list and the list the validation pass
/// actually PROVES empty are two lists, and a table that fell out of one
/// of them would be a table the import could silently write while still
/// claiming it does not. Tie them together.
///
/// The report's list is the longer one: it also names `security_outbox`
/// and the principal directory, which are not-imported for reasons of
/// their own rather than because a replica rebuilds them (see
/// [`NOT_IMPORTED`]).
#[test]
fn every_runtime_table_the_report_disclaims_is_one_the_validation_proves_empty() {
    for table in super::validation::EXCLUDED_RUNTIME_TABLES {
        assert!(
            NOT_IMPORTED.contains(table),
            "{table} is proven empty but the report never says it was left behind"
        );
    }
    for entry in NOT_IMPORTED {
        // The entries with an explanation after the name are the ones the
        // validation deliberately does not assert empty: `security_outbox`
        // (the control-plane commits append their own rows), the principal
        // directory and the local-secret keyring (neither has a cluster
        // table to be empty).
        if entry.contains(' ') {
            continue;
        }
        assert!(
            super::validation::EXCLUDED_RUNTIME_TABLES.contains(entry),
            "{entry} is disclaimed but nothing checks that the import left it alone"
        );
    }
}

/// The audit section's deduplication is bounded by the PAGE, not by the
/// deployment's history.
///
/// It exists for one reason: a batch that presents the same `event_id`
/// twice reserves two stream positions and inserts one row, which leaves a
/// permanent gap in a sequence whose contract with durable cursors is that
/// it has none. That is a within-batch property, so a within-page set
/// answers it. A set of every id in the log would be the one thing the
/// section holds that grows with the operator's whole history -- ten
/// million events is ten million 36-byte ids plus set overhead, hundreds of
/// megabytes to a gigabyte, in a one-shot command run inside a cutover
/// window, and a `--dry-run` rehearsal would pay it too. Nothing needs it:
/// the standalone sink declares `event_id TEXT NOT NULL UNIQUE`, so an id
/// cannot repeat in the source at all.
#[test]
fn the_audit_sections_deduplication_is_bounded_by_one_page() {
    let mut dedup = super::sections::PageDedup::default();
    assert!(dedup.offer("event-a"), "an id new to the page is offered");
    assert!(dedup.offer("event-b"));
    assert!(
        !dedup.offer("event-a"),
        "the same id twice in one batch would burn a stream position"
    );
    assert_eq!(dedup.tracked(), 2);

    dedup.start_page();
    assert_eq!(
        dedup.tracked(),
        0,
        "the set is cleared at every page, so its size is a function of AUDIT_PAGE and \
         not of the length of the log"
    );
    assert!(
        dedup.offer("event-a"),
        "and an id an earlier page already stored costs no position: the store's own \
         anti-join excludes it"
    );
}

/// The environment-file reader takes the shape `.env.example` ships and
/// the shape `docker compose env_file` reads, and never quotes a line's
/// text back at the operator.
#[test]
fn the_environment_file_reader_takes_the_shipped_shape() {
    let directory = temp_directory("env-shape");
    let path = directory.join("standalone.env");
    std::fs::write(
        &path,
        "# a comment\n\
         \n\
         POLICY_FILE=/srv/policy.json\n\
         export TOOLS_FILE=/srv/tools.json\n\
         BLANK=\n\
         WITH_EQUALS=a=b=c\n\
         POLICY_FILE=/srv/policy-2.json\n",
    )
    .expect("the environment file should write");
    let variables = super::source::read_env_file(&path).expect("the file should parse");
    assert_eq!(
        variables.get("POLICY_FILE").map(String::as_str),
        Some("/srv/policy-2.json"),
        "a later assignment wins, as every env-file reader does it"
    );
    assert_eq!(
        variables.get("TOOLS_FILE").map(String::as_str),
        Some("/srv/tools.json")
    );
    assert_eq!(variables.get("BLANK").map(String::as_str), Some(""));
    assert_eq!(
        variables.get("WITH_EQUALS").map(String::as_str),
        Some("a=b=c"),
        "only the FIRST '=' separates the key from the value"
    );

    std::fs::write(&path, "POLICY_FILE=/srv/policy.json\nSUPER_SECRET_LINE\n")
        .expect("the environment file should write");
    let error = super::source::read_env_file(&path).expect_err("a malformed line is refused");
    assert_eq!(error.code(), "standalone_env_file_malformed");
    let rendered = error.to_string();
    assert!(
        rendered.contains("line 2") && !rendered.contains("SUPER_SECRET_LINE"),
        "the line NUMBER is reported and its text is withheld: {rendered}"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// A standalone configuration that does not validate is reported by
/// SETTING NAME. The validator's own messages quote the offending value,
/// and some of those values are key material.
#[test]
fn invalid_standalone_configuration_is_reported_without_its_values() {
    let directory = temp_directory("env-invalid");
    let path = directory.join("standalone.env");
    std::fs::write(
        &path,
        "POLICY_FILE=/srv/policy.json\nLISTEN_ADDR=not-a-socket-FAKE_SECRET_VALUE\n",
    )
    .expect("the environment file should write");
    // `StandaloneSource` deliberately implements no `Debug`: it holds a
    // whole `Config`, and a test helper that formatted one would be a
    // standing invitation to print credential material.
    let Err(error) = StandaloneSource::load(&path) else {
        panic!("an invalid standalone configuration must be refused");
    };
    assert_eq!(error.code(), "standalone_config_invalid");
    let rendered = error.to_string();
    assert!(
        rendered.contains("LISTEN_ADDR"),
        "the operator must learn which setting failed: {rendered}"
    );
    assert!(
        !rendered.contains("FAKE_SECRET_VALUE"),
        "the offending VALUE must never be echoed: {rendered}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// Cluster mode refuses to start without an initialized policy document,
/// so a standalone deployment with no POLICY_FILE has nothing to import
/// that a replica could serve. Say so before touching the database.
#[test]
fn a_standalone_configuration_without_a_policy_file_is_refused() {
    let directory = temp_directory("env-no-policy");
    let path = directory.join("standalone.env");
    std::fs::write(&path, "AUDIT_SQLITE_PATH=/srv/audit.sqlite\n")
        .expect("the environment file should write");
    let Err(error) = StandaloneSource::load(&path) else {
        panic!("a standalone configuration with no POLICY_FILE must be refused");
    };
    assert_eq!(error.code(), "standalone_policy_file_missing");
    let _ = std::fs::remove_dir_all(&directory);
}

/// A `--from` file that selects cluster mode is the operator pointing the
/// import at its own destination.
#[test]
fn a_cluster_configuration_as_the_source_is_refused() {
    let directory = temp_directory("env-cluster-source");
    let dsn_path = directory.join("database-url");
    std::fs::write(&dsn_path, "postgres://gateway@127.0.0.1:5432/gateway\n")
        .expect("the DSN file should write");
    let path = directory.join("standalone.env");
    std::fs::write(
        &path,
        format!(
            "STATE_BACKEND=postgres\nDEPLOYMENT_ID=deploy-a\nDATABASE_URL_FILE={}\n\
             RATE_LIMIT_KEYRING={FAKE_RATE_LIMIT_KEYRING}\n\
             CONNECTION_SECRETS_ROOT={}\n",
            dsn_path.display(),
            directory.display(),
        ),
    )
    .expect("the environment file should write");
    let Err(error) = StandaloneSource::load(&path) else {
        panic!("a cluster configuration as the source must be refused");
    };
    assert_eq!(
        error.code(),
        "standalone_config_is_not_standalone",
        "{error}"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// A keyring declaration for a fixture configuration. It names a key
/// FILE, not key material -- the file is never read by validation and
/// never exists here.
const FAKE_RATE_LIMIT_KEYRING: &str =
    r#"[{"id":"rl-primary","file":"FAKE_rate-limit-key","role":"primary"}]"#;

fn words(arguments: &[&str]) -> Vec<OsString> {
    arguments.iter().map(OsString::from).collect()
}

fn temp_directory(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "greengateway-import-{label}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).expect("temp directory should create");
    directory
}

// ---------------------------------------------------------------------------
// The sections, against a real PostgreSQL. Gated on the same locator every
// other storage suite uses: a checkout without a database skips.
// ---------------------------------------------------------------------------

mod database {
    use super::*;

    use serde_json::json;

    use crate::{
        audit::{
            sqlite_sink::{SqliteSink, SqliteSinkConfig},
            Actor, AuditEvent, AuditSink,
        },
        auth::tokens::{CreateTokenRequest, SqliteTokenStore, TokenStore},
        config::{Config, DatabaseTlsMode, StateBackend, DEFAULT_DISCOVERY_ENDPOINT_LIMIT},
        connections::{
            model::{ConnectionId, ConnectionWrite, MAX_CONNECTIONS},
            pg_store::PostgresConnectionStore,
            status::{ConnectionOperationalState, ConnectionStatusReason},
            store::{
                ConnectionDependencyKind, ConnectionStatusUpdate, ConnectionStore,
                SqliteConnectionStore, StoredMcpCatalogEntry,
            },
        },
        discovery::{
            aggregator::{EndpointAggregatorSink, EndpointAggregatorSinkConfig},
            lifecycle::TransitionPrecondition,
            signals::{SignalDetectorConfig, SignalLifecycleState, SignalListFilters},
            suggestions::{RuleSuggestionConfig, RuleSuggestionEngine},
        },
        rbac::{policy_history::PolicyHistoryStore, Policy},
        storage::{
            migrations, postgres::PostgresFoundation, postgres_audit::PostgresAuditEventStore,
            postgres_discovery_read::PostgresDiscoveryReadStore,
            postgres_policy::PostgresPolicyStore, postgres_tools::PostgresToolStore,
            AuditEventStore, PolicyControlPlane, ToolControlPlane,
        },
    };

    fn locator() -> Option<String> {
        let key = "GATEWAY_TEST_POSTGRES_URL_FILE".to_owned();
        let file = std::env::var(&key).ok()?;
        if file.trim().is_empty() {
            return None;
        }
        let contents = std::fs::read_to_string(file).ok()?;
        let trimmed = contents.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    }

    struct DsnFile {
        path: String,
        directory: PathBuf,
    }

    impl Drop for DsnFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn write_dsn_file(dsn: &str) -> DsnFile {
        let directory = temp_directory("dsn");
        let path = directory.join("database-url");
        std::fs::write(&path, format!("{dsn}\n")).expect("DSN file should write");
        // The foundation refuses credential material that grants group or
        // other anything.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("DSN permissions should set");
        }
        DsnFile {
            path: path.display().to_string(),
            directory,
        }
    }

    struct TestDatabase {
        dsn: String,
        admin_dsn: String,
        name: String,
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let admin_dsn = self.admin_dsn.clone();
            let name = self.name.clone();
            std::thread::spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let Ok((client, connection)) =
                        tokio_postgres::connect(&admin_dsn, tokio_postgres::NoTls).await
                    else {
                        return;
                    };
                    let connection = tokio::spawn(connection);
                    let _ = client
                        .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                        .await;
                    let _ = connection.await;
                });
            });
        }
    }

    async fn create_test_database(admin_dsn: &str) -> TestDatabase {
        let name = format!("ggw_import_test_{}", uuid::Uuid::new_v4().simple());
        let (client, connection) = tokio_postgres::connect(admin_dsn, tokio_postgres::NoTls)
            .await
            .expect("admin connection");
        let connection_task = tokio::spawn(connection);
        client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .expect("test database should create");
        drop(client);
        let _ = connection_task.await;
        // Rewrite ONLY the database path segment: a plain replace would
        // also rewrite a username spelled like the database.
        let database_start = admin_dsn
            .rfind('/')
            .expect("locator DSN has a database path segment");
        let dsn = format!("{}/{}", &admin_dsn[..database_start], name);
        TestDatabase {
            dsn,
            admin_dsn: admin_dsn.to_owned(),
            name,
        }
    }

    /// A target configuration naming the disposable database. The DSN file
    /// is returned with it: dropping it removes the file.
    fn target_config(dsn: &str, deployment_id: &str) -> (Config, DsnFile) {
        let dsn_file = write_dsn_file(dsn);
        let mut config = Config::test_defaults();
        config.state_backend = StateBackend::Postgres;
        config.deployment_id = Some(deployment_id.to_owned());
        config.database.url_file = Some(dsn_file.path.clone());
        config.database.tls_mode = DatabaseTlsMode::LoopbackDev;
        (config, dsn_file)
    }

    async fn migrate(config: &Config) -> deadpool_postgres::Pool {
        let foundation = PostgresFoundation::establish(config)
            .await
            .expect("the test database should establish");
        migrations::apply_missing_for_startup(foundation.pool(), &config.database)
            .await
            .expect("the schema should migrate");
        foundation.pool().clone()
    }

    fn policy_with_id(id: &str) -> Policy {
        Policy::validate_json_value(json!({
            "schema_version": "0.1.0",
            "id": id,
            "default_action": "deny",
            "roles": {
                "admin": { "permissions": ["data:read", "policy:write"] }
            }
        }))
        .expect("the fixture policy should validate")
    }

    fn tools_document() -> Value {
        json!({
            "schema_version": "0.1.0",
            "tools": [{
                "name": "echo.message",
                "description": "Echoes the provided message.",
                "input_json_schema": {
                    "type": "object",
                    "required": ["message"],
                    "properties": { "message": { "type": "string" } },
                    "additionalProperties": false
                },
                "upstream": {
                    "method": "POST",
                    "path_template": "/v1/echo",
                    "body": { "mode": "whole_args_json" }
                }
            }]
        })
    }

    /// A managed HTTP Connection whose authentication names a SECRET ID.
    /// The id is a locator in the operator's secret store; no value
    /// behind it exists anywhere in this test, which is the point --
    /// the import carries the reference and never the credential.
    const FAKE_SECRET_REFERENCE: &str = "FAKE_billing-token-reference";
    const FAKE_ACCESS_CLIENT_ID_REFERENCE: &str = "FAKE_access-client-id-reference";
    const FAKE_ACCESS_CLIENT_SECRET_REFERENCE: &str = "FAKE_access-client-secret-reference";

    /// The fixture's audit log. Four import batches' worth, so the
    /// section's paging, its per-batch transactions and the stream's
    /// position assignment are exercised rather than described.
    const AUDIT_FIXTURE_EVENTS: usize = 2_000;

    fn http_connection() -> ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": "Billing API",
            "enabled": true,
            "kind": "http_api",
            "endpoint": {
                "base_url": "https://billing.example.test",
                "base_path": "/v1"
            },
            "authentication": {
                "type": "static_bearer",
                "secret_id": FAKE_SECRET_REFERENCE
            },
            "additional_headers": [
                {
                    "header_name": "CF-Access-Client-Id",
                    "secret_id": FAKE_ACCESS_CLIENT_ID_REFERENCE
                },
                {
                    "header_name": "CF-Access-Client-Secret",
                    "secret_id": FAKE_ACCESS_CLIENT_SECRET_REFERENCE
                }
            ],
            "tls": {}
        }))
        .expect("the HTTP fixture Connection should deserialize")
    }

    fn mcp_connection() -> ConnectionWrite {
        serde_json::from_value(json!({
            "display_name": "Managed MCP",
            "enabled": true,
            "kind": "mcp_streamable_http",
            "endpoint": {
                "base_url": "https://mcp.example.test",
                "base_path": "/mcp"
            },
            "authentication": { "type": "none" },
            "tls": {},
            "discovery": {
                "type": "managed_mcp",
                "use_connection_authentication": false
            }
        }))
        .expect("the MCP fixture Connection should deserialize")
    }

    fn mcp_entry(name: &str) -> StoredMcpCatalogEntry {
        StoredMcpCatalogEntry {
            remote_tool_name: name.to_owned(),
            description: format!("{name} description"),
            input_schema: json!({ "type": "object", "properties": {} }),
        }
    }

    /// A standalone deployment on disk: a policy file, a policy history
    /// with `history` versions written through the standalone store, a
    /// tools file, a Connections database holding two Connections (one
    /// with a credential binding and a status observation, one with a
    /// published MCP catalog), an audit log of `audit_events` events, and
    /// the environment file that names them all. Every one of them is
    /// written through the store the standalone gateway itself writes it
    /// with, so the import reads exactly what a real deployment leaves.
    struct Fixture {
        directory: PathBuf,
        env_file: PathBuf,
        policy: Policy,
        http_id: ConnectionId,
        mcp_id: ConnectionId,
        audit_events: i64,
        /// The discovery state the fixture actually produced, read back
        /// through the standalone store rather than assumed: the
        /// aggregator decides how many endpoints and signals a set of
        /// observations yields, and a test that guessed would be testing
        /// its own guess.
        discovery_endpoints: i64,
        discovery_signals: i64,
        discovery_suggestions: i64,
        discovery_reviews: i64,
        /// The signal the fixture acknowledged, so its revision is 2 and
        /// not the column default.
        acknowledged_signal: String,
        service_tokens: i64,
        /// The token hashes as the source stores them, so "token hashes
        /// equal" can be asserted against the target's rows.
        token_hashes: Vec<String>,
        /// What the suggestion engine reported about its own run, so a
        /// fixture that stops producing suggestions says WHY rather than
        /// just failing.
        suggestion_generation: String,
    }

    impl Fixture {
        fn connections_file(&self) -> PathBuf {
            self.directory.join("connections.sqlite")
        }

        fn discovery_file(&self) -> PathBuf {
            self.directory.join("discovery.sqlite")
        }

        /// How many events the SOURCE holds, read through the same store
        /// the import reads it with.
        fn source_audit_event_count(&self) -> i64 {
            let store =
                crate::audit::query::AuditQueryStore::open(self.directory.join("audit.sqlite"))
                    .expect("the source audit log should reopen");
            let mut cursor = 0_i64;
            let mut total = 0_i64;
            loop {
                let page = store
                    .events_after(cursor, 500)
                    .expect("the source audit log should page");
                if page.is_empty() {
                    return total;
                }
                total += i64::try_from(page.len()).expect("the page should fit");
                cursor = page.last().map(|(id, _)| *id).unwrap_or(cursor);
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }

    fn build_fixture(label: &str, history: usize, audit_events: usize) -> Fixture {
        let directory = temp_directory(label);
        let policy_file = directory.join("policy.json");
        let tools_file = directory.join("tools.json");
        let connections_file = directory.join("connections.sqlite");
        let audit_file = directory.join("audit.sqlite");
        let discovery_file = directory.join("discovery.sqlite");
        let service_token_file = directory.join("tokens.sqlite");
        let principal_file = directory.join("principals.sqlite");

        // The history lives at the path the standalone gateway derives
        // from POLICY_FILE, and is written through the standalone store,
        // so the import reads exactly what a real deployment leaves.
        let history_file = PathBuf::from(format!("{}.history.sqlite", policy_file.display()));
        let store = PolicyHistoryStore::open(&history_file).expect("history store should open");
        for index in 0..history {
            store
                .append_version(
                    &format!("admin-{index}"),
                    &json!({ "action": "test", "index": index }),
                    &policy_with_id(&format!("history-{index}")),
                )
                .expect("history version should append");
        }
        drop(store);

        let policy = policy_with_id("live");
        std::fs::write(
            &policy_file,
            serde_json::to_vec_pretty(&policy).expect("the fixture policy should serialize"),
        )
        .expect("the policy file should write");
        std::fs::write(&tools_file, tools_document().to_string())
            .expect("the tools file should write");

        // The Connections, through the standalone store: a record with a
        // credential binding, a dependency and a status observation, and
        // a second one carrying a published MCP catalog (whose entries the
        // store derives `managed_tool` dependencies from).
        let store =
            SqliteConnectionStore::open(&connections_file).expect("connections store should open");
        let http = store
            .create(http_connection())
            .expect("the HTTP fixture Connection should create");
        store
            .add_dependency(
                &http.id,
                ConnectionDependencyKind::ProxyRoute,
                "billing-proxy-route",
            )
            .expect("the proxy-route dependency should record");
        store
            .append_status(
                &http.id,
                &http.etag(),
                ConnectionStatusUpdate {
                    state: ConnectionOperationalState::Healthy,
                    reason: ConnectionStatusReason::TestSucceeded,
                    latency_ms: Some(42),
                    catalog_age_secs: None,
                    catalog_entry_count: None,
                },
            )
            .expect("the status observation should append");
        let mcp = store
            .create(mcp_connection())
            .expect("the MCP fixture Connection should create");
        store
            .replace_mcp_catalog(
                &mcp.id,
                &mcp.etag(),
                &[mcp_entry("alpha"), mcp_entry("beta")],
                &[],
                &[],
            )
            .expect("the MCP catalog should publish");
        let http_id = http.id.clone();
        let mcp_id = mcp.id.clone();
        drop(store);

        // The audit log, through the sink the standalone gateway emits
        // with. Its `event_id` column is UNIQUE, so the deliberate
        // re-emission below is dropped at the source -- which is why the
        // import's own deduplication is falsified against the target
        // instead (see the duplicate-event test).
        //
        // The observation events come last and go to BOTH sinks: the
        // discovery aggregator is fed exactly what the audit log
        // recorded, which is what a standalone deployment does, and what
        // makes the suggestion engine's baseline agree with the endpoint
        // inventory.
        let sink = SqliteSink::new(SqliteSinkConfig {
            path: audit_file.clone(),
            retention_days: None,
        })
        .expect("the audit sink should open");
        for index in 0..audit_events {
            sink.emit(&fixture_event(index));
            if index == audit_events / 2 {
                // The same event again, verbatim.
                sink.emit(&fixture_event(index));
            }
        }
        let aggregator = EndpointAggregatorSink::new(EndpointAggregatorSinkConfig {
            path: discovery_file.clone(),
            payload_capture_enabled: false,
            endpoint_limit: DEFAULT_DISCOVERY_ENDPOINT_LIMIT,
            signal_event_sender: None,
            signal_detector_config: SignalDetectorConfig::default(),
        })
        .expect("the discovery aggregator should open");
        for index in 0..OBSERVATION_EVENTS {
            let event = observation_event(index);
            sink.emit(&event);
            AuditSink::emit(&aggregator, &event);
        }
        sink.flush().expect("the audit sink should flush");
        drop(sink);
        AuditSink::flush(&aggregator).expect("the discovery aggregator should flush");
        drop(aggregator);

        // The lifecycle rows an operator leaves behind: an acknowledged
        // signal (revision 2, so the import cannot pass by leaving the
        // column at its default), a marked review, and a CLEARED review,
        // which keeps its row at a higher revision precisely so a stale
        // precondition cannot match a later review.
        let discovery = crate::discovery::query::DiscoveryQueryStore::open(discovery_file.clone())
            .expect("the discovery store should open");
        let signals = discovery
            .list_signals(&SignalListFilters {
                state: None,
                signal_type: None,
                target_kind: None,
                target_key: None,
                limit: 100,
                cursor: None,
            })
            .expect("the fixture signals should list")
            .signals;
        let acknowledged_signal = signals
            .first()
            .map(|signal| signal.id.clone())
            .expect("the observations should have raised at least one signal");
        discovery
            .transition_signal(
                &acknowledged_signal,
                SignalLifecycleState::Acknowledged,
                Some("operator@example.test"),
                TransitionPrecondition::from_state(SignalLifecycleState::Open),
            )
            .expect("the fixture transition should run")
            .expect_applied("the open signal should acknowledge");
        for (method, template, keep) in [
            ("GET", OBSERVED_TEMPLATE_A, true),
            ("GET", OBSERVED_TEMPLATE_B, false),
        ] {
            discovery
                .set_endpoint_review(method, template, true, Some("reviewer@example.test"), None)
                .expect("the fixture review should write")
                .expect_applied("the endpoint should mark reviewed");
            if !keep {
                discovery
                    .set_endpoint_review(method, template, false, None, None)
                    .expect("the fixture review should clear")
                    .expect_applied("the endpoint review should clear");
            }
        }
        let discovery_signals =
            i64::try_from(signals.len()).expect("the fixture signal count should fit");
        let discovery_reviews = 2;
        drop(discovery);

        // The rule suggestions, generated by the standalone engine from
        // the same two inputs it uses in production: the endpoint
        // inventory and the audit log's role/endpoint matrix.
        let engine = RuleSuggestionEngine::open(
            &discovery_file,
            Some(&audit_file),
            RuleSuggestionConfig::default(),
        )
        .expect("the suggestion engine should open");
        let generation = engine
            .generate(&policy)
            .expect("the fixture suggestions should generate");
        let discovery_suggestions = i64::try_from(
            engine
                .list_suggestions()
                .expect("the fixture suggestions should list")
                .len(),
        )
        .expect("the fixture suggestion count should fit");
        let suggestion_generation = format!("{generation:?}");
        drop(engine);

        let discovery_endpoints = i64::try_from(
            crate::discovery::query::DiscoveryQueryStore::open(discovery_file.clone())
                .expect("the discovery store should reopen")
                .observed_endpoints()
                .expect("the fixture endpoints should list")
                .len(),
        )
        .expect("the fixture endpoint count should fit");

        // Service tokens, through the store standalone serves them from:
        // one live, one revoked. The plaintexts are dropped here and never
        // written down; only their hashes are durable, which is exactly
        // what the import has to carry.
        let token_store = SqliteTokenStore::open(&service_token_file)
            .expect("the service token store should open");
        let live = TokenStore::create(
            &token_store,
            CreateTokenRequest {
                scopes: vec!["tools:invoke".to_owned()],
                created_by: "operator@example.test".to_owned(),
                expires_at: None,
            },
        )
        .expect("the live fixture token should mint");
        let revoked = TokenStore::create(
            &token_store,
            CreateTokenRequest {
                scopes: vec!["admin:read".to_owned()],
                created_by: "operator@example.test".to_owned(),
                expires_at: None,
            },
        )
        .expect("the revoked fixture token should mint");
        TokenStore::revoke(&token_store, &revoked.record.id)
            .expect("the fixture token should revoke");
        drop(live);
        drop(revoked);
        let exported = token_store
            .exported_tokens()
            .expect("the fixture tokens should export");
        let service_tokens =
            i64::try_from(exported.len()).expect("the fixture token count should fit");
        let token_hashes = exported
            .iter()
            .map(|token| token.token_hash.clone())
            .collect::<Vec<_>>();
        drop(token_store);

        // A principal directory the import must NOT carry: cluster mode
        // has no destination for it, and the report has to say so.
        drop(
            crate::auth::PrincipalDirectory::open(principal_file.clone())
                .expect("the principal directory should open"),
        );

        let env_file = directory.join("standalone.env");
        std::fs::write(
            &env_file,
            format!(
                "# the standalone deployment being imported\n\
                 POLICY_FILE={}\n\
                 TOOLS_FILE={}\n\
                 CONNECTIONS_SQLITE_PATH={}\n\
                 AUDIT_SQLITE_PATH={}\n\
                 DISCOVERY_SQLITE_PATH={}\n\
                 SERVICE_TOKEN_SQLITE_PATH={}\n\
                 PRINCIPAL_SQLITE_PATH={}\n",
                policy_file.display(),
                tools_file.display(),
                connections_file.display(),
                audit_file.display(),
                discovery_file.display(),
                service_token_file.display(),
                principal_file.display(),
            ),
        )
        .expect("the environment file should write");

        Fixture {
            directory,
            env_file,
            policy,
            http_id,
            mcp_id,
            audit_events: i64::try_from(audit_events + OBSERVATION_EVENTS)
                .expect("the fixture count should fit"),
            discovery_endpoints,
            discovery_signals,
            discovery_suggestions,
            discovery_reviews,
            acknowledged_signal,
            service_tokens,
            token_hashes,
            suggestion_generation,
        }
    }

    /// The two endpoints the fixture's observations produce, in the shape
    /// the aggregator templates them.
    const OBSERVED_TEMPLATE_A: &str = "/v1/orders";
    const OBSERVED_TEMPLATE_B: &str = "/v1/invoices";

    /// How many observation events the fixture emits. Enough for the
    /// aggregator to admit both endpoints, accumulate per-principal rows,
    /// and raise its `new_endpoint_seen` signals.
    const OBSERVATION_EVENTS: usize = 24;

    /// One observation event, emitted to BOTH the audit sink and the
    /// discovery aggregator, exactly as a serving standalone gateway emits
    /// it. Deterministic in every field so a rehearsal and the apply
    /// digest to the same value.
    fn observation_event(index: usize) -> AuditEvent {
        let template = if index.is_multiple_of(2) {
            OBSERVED_TEMPLATE_A
        } else {
            OBSERVED_TEMPLATE_B
        };
        let status = if index % 8 == 7 { 500 } else { 200 };
        let mut event = AuditEvent::new(
            "http.request_observed",
            format!("observation-{index:03}"),
            "198.51.100.9",
            Some(Actor {
                user_id: format!("service-{}", index % 2),
                issuer: Some("https://issuer.example.test".to_owned()),
                email: None,
                roles: Some(vec!["reader".to_owned()]),
                auth_mode: "bearer_token".to_owned(),
            }),
            json!({
                "method": "GET",
                "path": template,
                "endpoint_template": template,
                "status": status,
                "latency_ms": 12 + (index % 5),
                // The routing context is what makes an observation
                // CLASSIFIED, and only a classified observation reaches
                // the signal detectors: without it the fixture would
                // produce an endpoint inventory and no signals at all.
                // It is classified as CONTEXTLESS -- no route host, no
                // path prefix, no upstream origin -- which is also the
                // one shape the suggestion engine will propose a direct
                // rule for, so the fixture carries suggestions too.
                "routing_context_known": true,
            }),
        );
        event.event_id = format!("observation-event-{index:03}");
        event
    }

    /// The base the fixture's event ids count DOWN from, so that the ids'
    /// lexicographic order is the reverse of the log's order. A real
    /// deployment's `event_id` is a random UUIDv4 whose sort order has
    /// nothing to do with the order the events happened in; a fixture whose
    /// ids happened to sort into insertion order would let a stream that
    /// numbered positions by `event_id` pass this whole suite and then
    /// shuffle every real import.
    const FIXTURE_EVENT_ID_BASE: usize = 99_999;

    /// One fixture audit event. The `event_id` is derived from the index
    /// rather than random so a re-emission is a genuine duplicate and the
    /// stream's ordering can be asserted against it; `request_id` counts
    /// UP with the index and the id counts DOWN, so a reader can tell the
    /// two orders apart. See [`FIXTURE_EVENT_ID_BASE`].
    fn fixture_event(index: usize) -> AuditEvent {
        let mut event = AuditEvent::new(
            "http.request_observed",
            format!("request-{index:05}"),
            "203.0.113.7",
            Some(Actor {
                user_id: format!("user-{}", index % 3),
                issuer: Some("https://issuer.example.test".to_owned()),
                email: None,
                roles: Some(vec!["reader".to_owned()]),
                auth_mode: "bearer_token".to_owned(),
            }),
            json!({
                "method": "GET",
                "path": format!("/v1/items/{index}"),
                "status": 200,
            }),
        );
        event.event_id = format!("fixture-event-{:05}", FIXTURE_EVENT_ID_BASE - index);
        event
    }

    fn request(fixture: &Fixture, mode: ImportMode) -> ImportRequest {
        ImportRequest {
            standalone_env_file: fixture.env_file.clone(),
            mode,
        }
    }

    fn section<'a>(report: &'a ImportReport, name: &str) -> &'a SectionReport {
        report
            .sections
            .iter()
            .find(|section| section.section == name)
            .unwrap_or_else(|| panic!("the report should carry a {name} section"))
    }

    /// The whole of steps 1-3: a dry run writes nothing, an apply installs
    /// the policy with its history and the tools document with its name
    /// reservations, a second apply is refused by preflight, and a resume
    /// changes nothing.
    #[tokio::test]
    async fn the_policy_and_tools_sections_import_a_standalone_deployment() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import");
        let pool = migrate(&config).await;
        let fixture = build_fixture("sections", 3, 0);

        // --- the dry run -------------------------------------------------
        let planned = run(&request(&fixture, ImportMode::DryRun), &config)
            .await
            .expect("the dry run should succeed");
        assert_eq!(planned.mode, "dry-run");
        assert_eq!(section(&planned, "policy").status, "planned");
        assert_eq!(
            section(&planned, "policy").counts.get("policy_documents"),
            Some(&4),
            "three history versions plus the activation of the policy file"
        );
        assert_eq!(section(&planned, "tools").counts.get("tools"), Some(&1));
        assert_eq!(
            planned.source.policy_history_versions, 3,
            "the source's history is read through the standalone store"
        );
        assert!(
            planned.not_imported.contains(&"cluster_members")
                && planned
                    .not_imported
                    .iter()
                    .any(|entry| entry.starts_with("principal_directory")),
            "every run names what it deliberately leaves behind"
        );
        assert_eq!(
            planned.validation.status, "planned",
            "a dry run computes the source half of the comparison and verifies nothing"
        );
        // Nothing was written: the namespace is still empty, binding
        // included (a dry run does not claim the database either).
        assert!(
            super::super::preflight::occupied_namespace(&pool)
                .await
                .expect("the namespace should be readable")
                .is_empty(),
            "a dry run must write nothing"
        );
        assert_eq!(
            crate::storage::postgres::read_deployment_binding(&pool)
                .await
                .ok()
                .flatten(),
            None,
            "a dry run must not bind the database to this deployment either"
        );

        // --- the apply ---------------------------------------------------
        let applied = run(&request(&fixture, ImportMode::Apply), &config)
            .await
            .expect("the apply should succeed");
        assert_eq!(applied.mode, "apply");
        let policy_section = section(&applied, "policy");
        assert_eq!(policy_section.status, "imported");
        assert_eq!(
            policy_section.counts.get("policy_history_versions"),
            Some(&3)
        );
        assert_eq!(policy_section.counts.get("policy_active_version"), Some(&4));
        assert_eq!(
            policy_section.checksum,
            section(&planned, "policy").checksum,
            "the dry run's checksum is the apply's: that is what makes a rehearsal evidence"
        );
        let tools_section = section(&applied, "tools");
        assert_eq!(tools_section.status, "imported");
        assert_eq!(tools_section.counts.get("tool_name_reservations"), Some(&1));
        assert_eq!(
            tools_section.checksum,
            section(&planned, "tools").checksum,
            "the tools checksum must match the rehearsal's too"
        );

        // The active policy is the standalone POLICY FILE, and its ETag is
        // the one this binary derives from it.
        let policy_store = PostgresPolicyStore::new(pool.clone());
        let active = PolicyControlPlane::active(&policy_store)
            .await
            .expect("the active policy should read")
            .expect("an active policy should exist");
        assert_eq!(
            active.etag,
            crate::policy_etag(&fixture.policy).expect("the fixture ETag should compute")
        );
        assert_eq!(active.policy.id.as_deref(), Some("live"));
        assert_eq!(active.version, 4);

        // The history kept the standalone deployment's own numbering,
        // actors and snapshots.
        let history = client_rows(
            &pool,
            "SELECT version, actor_user_id, document->>'id' FROM greengateway.policy_documents \
             ORDER BY version",
        )
        .await;
        assert_eq!(
            history,
            vec![
                (1, "admin-0".to_owned(), "history-0".to_owned()),
                (2, "admin-1".to_owned(), "history-1".to_owned()),
                (3, "admin-2".to_owned(), "history-2".to_owned()),
                (4, IMPORT_ACTOR.to_owned(), "live".to_owned()),
            ],
            "imported versions keep their numbers and actors; the activation is its own version"
        );

        // The tools document is active and its names are reserved to the
        // local lane at the authority.
        let tool_store = PostgresToolStore::new(pool.clone());
        let active_tools = ToolControlPlane::active_tools(&tool_store)
            .await
            .expect("the active tools document should read")
            .expect("a tools document should exist");
        assert_eq!(active_tools.document, tools_document());
        let reservations = client_names(
            &pool,
            "SELECT tool_name || ':' || lane FROM greengateway.tool_name_reservations \
             WHERE lane = 'local' ORDER BY tool_name",
        )
        .await;
        assert_eq!(reservations, vec!["echo.message:local".to_owned()]);

        // The two commits took two revisions of the ONE shared counter.
        assert!(
            active.security_revision < active_tools.security_revision,
            "policy and tools advance the same security revision counter, in order"
        );

        // --- the report is redacted -------------------------------------
        let rendered = applied.to_string();
        for forbidden in ["postgres://", "password", "dbname", &database.dsn] {
            assert!(
                !rendered.contains(forbidden),
                "the report must carry no DSN or credential material: {rendered}"
            );
        }

        // --- a second apply is refused, a resume is a no-op --------------
        let Err(refused) = run(&request(&fixture, ImportMode::Apply), &config).await else {
            panic!("an apply into a non-empty namespace must be refused");
        };
        assert_eq!(refused.code(), "target_namespace_not_empty");

        let resumed = run(&request(&fixture, ImportMode::Resume), &config)
            .await
            .expect("a resume of a completed import should succeed");
        assert_eq!(section(&resumed, "policy").status, "already-imported");
        assert_eq!(section(&resumed, "tools").status, "already-imported");
        assert_eq!(
            section(&resumed, "policy").checksum,
            policy_section.checksum
        );
        let history_after = client_rows(
            &pool,
            "SELECT version, actor_user_id, document->>'id' FROM greengateway.policy_documents \
             ORDER BY version",
        )
        .await;
        assert_eq!(
            history_after, history,
            "a resumed import that is already complete writes nothing"
        );
    }

    /// The namespace-empty refusal, falsified: a single row in ONE
    /// authoritative table is enough, and `--resume` is the only way past
    /// it.
    #[tokio::test]
    async fn a_non_empty_namespace_refuses_the_import() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-occupied");
        let pool = migrate(&config).await;
        let fixture = build_fixture("occupied", 1, 0);

        // Empty: the dry run passes preflight.
        run(&request(&fixture, ImportMode::DryRun), &config)
            .await
            .expect("an empty namespace should pass preflight");

        // One row in one authoritative table is enough.
        pool.get()
            .await
            .expect("checkout")
            .execute(
                "INSERT INTO greengateway.service_tokens (
                     id, token_hash, token_prefix, scopes_json, created_by, security_revision
                 ) VALUES ($1, $2, $3, $4, $5, 1)",
                &[
                    &"fixture-token",
                    &FAKE_TOKEN_HASH,
                    &"ggw_FAKE",
                    &"[]",
                    &"fixture",
                ],
            )
            .await
            .expect("the occupying row should insert");

        let Err(refused) = run(&request(&fixture, ImportMode::DryRun), &config).await else {
            panic!("a non-empty namespace must be refused, dry run included");
        };
        assert_eq!(refused.code(), "target_namespace_not_empty");
        assert!(
            refused.to_string().contains("service_tokens=1"),
            "the refusal names the occupied table and its count: {refused}"
        );

        let Err(refused) = run(&request(&fixture, ImportMode::Apply), &config).await else {
            panic!("an apply into a non-empty namespace must be refused");
        };
        assert_eq!(refused.code(), "target_namespace_not_empty");

        // `--resume` is the documented way past the namespace check, and
        // it is NOT a bypass: each section still judges its own resource
        // by the natural key. The occupying token is not one this import
        // carries, so the principals section refuses -- after the policy
        // section, whose resource really was untouched, has committed.
        let Err(refused) = run(&request(&fixture, ImportMode::Resume), &config).await else {
            panic!("a resume must not adopt another import's rows");
        };
        assert_eq!(
            refused.code(),
            "section_conflict",
            "--resume skips the namespace check, never a section's own key: {refused}"
        );
        assert_eq!(
            count_of(&pool, "SELECT count(*) FROM greengateway.policy_documents").await,
            2,
            "the sections before the conflict stay committed, which is what makes a run resumable"
        );
    }

    /// Step 4, end to end: the records with their identifiers and
    /// per-axis revisions, the credential bindings as references, the
    /// dependencies with `source_revision` 0, the status and its history,
    /// and the published catalog with its tool-name reservations.
    ///
    /// The strongest assertion here is the last one: the cluster's own
    /// boot-time validation
    /// (`PostgresConnectionStore::validate_persisted_state`) accepts the
    /// imported namespace. That check re-derives every cross-table
    /// invariant -- bindings against their record, current status against
    /// the record's revisions, catalog counters against their child rows,
    /// managed-tool dependencies against catalog entries -- so a replica
    /// would boot on what the import wrote.
    #[tokio::test]
    async fn the_connections_section_carries_records_bindings_statuses_and_catalogs() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-connections");
        let pool = migrate(&config).await;
        let fixture = build_fixture("connections", 1, 0);

        let planned = run(&request(&fixture, ImportMode::DryRun), &config)
            .await
            .expect("the dry run should succeed");
        let planned_section = section(&planned, "connections");
        assert_eq!(planned_section.status, "planned");
        assert_eq!(planned_section.counts.get("connection_records"), Some(&2));
        assert_eq!(planned_section.counts.get("credential_bindings"), Some(&3));
        assert_eq!(
            planned_section.counts.get("dependencies"),
            Some(&3),
            "one proxy route plus one managed_tool dependency per catalog entry"
        );
        assert_eq!(planned_section.counts.get("current_statuses"), Some(&1));
        assert_eq!(planned_section.counts.get("mcp_catalogs"), Some(&1));
        assert_eq!(
            planned_section.counts.get("tool_name_reservations"),
            Some(&2)
        );
        assert!(
            super::super::preflight::occupied_namespace(&pool)
                .await
                .expect("the namespace should be readable")
                .is_empty(),
            "planning the Connections section must write nothing"
        );

        let applied = run(&request(&fixture, ImportMode::Apply), &config)
            .await
            .expect("the apply should succeed");
        let applied_section = section(&applied, "connections");
        assert_eq!(applied_section.status, "imported");
        assert_eq!(
            applied_section.checksum, planned_section.checksum,
            "the rehearsal's checksum is the apply's"
        );
        assert_eq!(applied_section.counts.get("connection_records"), Some(&2));
        assert_eq!(applied_section.counts.get("connection_documents"), Some(&2));
        assert_eq!(applied_section.counts.get("credential_bindings"), Some(&3));
        assert_eq!(applied_section.counts.get("status_history"), Some(&1));
        assert_eq!(applied_section.counts.get("catalog_entries"), Some(&2));

        // The identifiers and the per-axis revisions are the source's:
        // the ETag an operator's automation holds is derived from them.
        let source_store = SqliteConnectionStore::open(fixture.connections_file())
            .expect("the source store should reopen");
        let mut expected = source_store.list().expect("the source should list");
        expected.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        let target_store = PostgresConnectionStore::new(pool.clone(), MAX_CONNECTIONS)
            .expect("the target store should construct");
        let mut actual = target_store.list().await.expect("the target should list");
        actual.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        assert_eq!(
            actual, expected,
            "records, specifications, revisions and timestamps are carried verbatim"
        );

        // Credential bindings are references. The secret ID names an entry
        // in the operator's secret store; the value behind it was never
        // read and is nowhere in the target.
        let bindings = pool
            .get()
            .await
            .expect("binding checkout")
            .query(
                "SELECT purpose, header_name, secret_id \
                 FROM greengateway.connection_credential_bindings \
                 ORDER BY purpose, header_name",
                &[],
            )
            .await
            .expect("binding query")
            .into_iter()
            .map(|row| {
                (
                    row.get::<_, String>(0),
                    row.get::<_, String>(1),
                    row.get::<_, String>(2),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            bindings,
            vec![
                (
                    "additional_header".to_owned(),
                    "cf-access-client-id".to_owned(),
                    FAKE_ACCESS_CLIENT_ID_REFERENCE.to_owned(),
                ),
                (
                    "additional_header".to_owned(),
                    "cf-access-client-secret".to_owned(),
                    FAKE_ACCESS_CLIENT_SECRET_REFERENCE.to_owned(),
                ),
                (
                    "http_authentication".to_owned(),
                    String::new(),
                    FAKE_SECRET_REFERENCE.to_owned(),
                ),
            ]
        );

        // Dependencies keep their kinds and claim no source document.
        let dependencies = client_pairs(
            &pool,
            "SELECT consumer_kind, consumer_id FROM greengateway.connection_dependencies \
             ORDER BY consumer_kind, consumer_id",
        )
        .await;
        assert_eq!(
            dependencies,
            vec![
                (
                    "managed_tool".to_owned(),
                    format!("{}:alpha", fixture.mcp_id.as_str())
                ),
                (
                    "managed_tool".to_owned(),
                    format!("{}:beta", fixture.mcp_id.as_str())
                ),
                ("proxy_route".to_owned(), "billing-proxy-route".to_owned()),
            ]
        );
        assert_eq!(
            count_of(
                &pool,
                "SELECT count(*) FROM greengateway.connection_dependencies \
                 WHERE source_revision = 0"
            )
            .await,
            3,
            "an imported dependency set is not one this deployment's documents derived"
        );

        // The status and its history.
        let status = target_store
            .latest_status(&fixture.http_id)
            .await
            .expect("the imported status should read")
            .expect("the HTTP Connection should carry a status");
        assert_eq!(status.state, ConnectionOperationalState::Healthy);
        assert_eq!(status.reason, ConnectionStatusReason::TestSucceeded);
        assert_eq!(status.latency_ms, Some(42));
        assert_eq!(
            count_of(
                &pool,
                "SELECT count(*) FROM greengateway.connection_status_history"
            )
            .await,
            1
        );

        // The catalog kept its own revision, and its names are reserved to
        // the MCP lane at the authority.
        let catalogs = target_store
            .mcp_catalogs()
            .await
            .expect("the imported catalog should read");
        assert_eq!(catalogs.len(), 1);
        assert_eq!(catalogs[0].connection_id, fixture.mcp_id);
        assert_eq!(catalogs[0].catalog_revision, 1);
        assert_eq!(catalogs[0].entries.len(), 2);
        let reservations = client_names(
            &pool,
            "SELECT tool_name || ':' || lane FROM greengateway.tool_name_reservations \
             WHERE lane = 'mcp' ORDER BY tool_name",
        )
        .await;
        assert_eq!(
            reservations,
            vec![
                format!("{}:alpha:mcp", fixture.mcp_id.as_str()),
                format!("{}:beta:mcp", fixture.mcp_id.as_str()),
            ]
        );

        // The connections high-water mark took one shared revision and did
        // not overtake the counter the gate compares it against.
        let activation = count_of(
            &pool,
            "SELECT last_revision FROM greengateway.connection_state_revision WHERE singleton",
        )
        .await;
        let authority = count_of(
            &pool,
            "SELECT last_revision FROM greengateway.security_revision_state WHERE singleton",
        )
        .await;
        assert!(
            activation > 0 && activation <= authority,
            "the connections activation revision ({activation}) must be a revision of the \
             shared counter ({authority})"
        );

        // A replica would boot on this namespace.
        target_store
            .validate_persisted_state()
            .await
            .expect("the cluster's own startup validation should accept the imported state");

        // The report is counts, checksums and durations. A secret ID is a
        // locator rather than a secret, but it identifies an entry in the
        // operator's secret store and has no business on stdout either.
        let rendered = applied.to_string();
        for forbidden in [
            FAKE_SECRET_REFERENCE,
            FAKE_ACCESS_CLIENT_ID_REFERENCE,
            FAKE_ACCESS_CLIENT_SECRET_REFERENCE,
            "secret_id",
            "postgres://",
            &database.dsn,
        ] {
            assert!(
                !rendered.contains(forbidden),
                "the report must carry no locator, DSN or credential material: {rendered}"
            );
        }

        // A resume of a completed section writes nothing.
        let resumed = run(&request(&fixture, ImportMode::Resume), &config)
            .await
            .expect("a resume should succeed");
        assert_eq!(section(&resumed, "connections").status, "already-imported");
        assert_eq!(
            count_of(
                &pool,
                "SELECT count(*) FROM greengateway.connection_records"
            )
            .await,
            2
        );
        assert_eq!(
            count_of(
                &pool,
                "SELECT last_revision FROM greengateway.connection_state_revision WHERE singleton"
            )
            .await,
            activation,
            "a resumed section that is already complete takes no further revision"
        );
    }

    /// Step 5, end to end: the log in event order, deduplicated by
    /// `event_id`, on a stream whose positions are contiguous -- and a
    /// second run that changes nothing.
    #[tokio::test]
    async fn the_audit_section_imports_the_log_in_order_and_a_second_run_changes_nothing() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-audit");
        let pool = migrate(&config).await;
        let fixture = build_fixture("audit", 1, AUDIT_FIXTURE_EVENTS);

        // The fixture emitted one event twice. The standalone sink's own
        // UNIQUE(event_id) dropped the second, so the SOURCE holds each
        // event once -- which is why the import's deduplication is
        // falsified against the target below and not here.
        assert_eq!(
            fixture.source_audit_event_count(),
            fixture.audit_events,
            "the standalone sink stores an event id exactly once"
        );

        let planned = run(&request(&fixture, ImportMode::DryRun), &config)
            .await
            .expect("the dry run should succeed");
        let planned_section = section(&planned, "audit");
        assert_eq!(planned_section.status, "planned");
        assert_eq!(
            planned_section.counts.get("audit_events_source"),
            Some(&fixture.audit_events)
        );
        assert_eq!(
            planned_section.counts.get("audit_events_deduplicated"),
            Some(&fixture.audit_events)
        );
        assert!(
            super::super::preflight::occupied_namespace(&pool)
                .await
                .expect("the namespace should be readable")
                .is_empty(),
            "a dry run reads the whole log and writes none of it"
        );

        let applied = run(&request(&fixture, ImportMode::Apply), &config)
            .await
            .expect("the apply should succeed");
        let applied_section = section(&applied, "audit");
        assert_eq!(applied_section.status, "imported");
        assert_eq!(
            applied_section.checksum, planned_section.checksum,
            "the rehearsal's checksum is the apply's"
        );
        assert_eq!(
            applied_section.counts.get("audit_events"),
            Some(&fixture.audit_events)
        );
        assert_eq!(
            applied_section.counts.get("audit_stream_rows"),
            Some(&fixture.audit_events)
        );
        assert_eq!(
            applied_section.counts.get("audit_stream_first_position"),
            Some(&1)
        );
        assert_eq!(
            applied_section.counts.get("audit_stream_head"),
            Some(&fixture.audit_events),
            "positions 1..n with no gaps: one row per event and a head equal to the count"
        );

        // Event order: the stream's lowest positions carry the log's
        // oldest events.
        //
        // This is the assertion that separates the log's order from the
        // ids' order, and it is the whole point of the fixture counting its
        // ids DOWN (see `FIXTURE_EVENT_ID_BASE`). The stream's positions are
        // assigned from the order the batch was PRESENTED in, so the first
        // three positions carry the first three events emitted -- whose ids
        // are the three largest, not the three smallest. Numbering
        // positions by `event_id` instead (which is what a random UUIDv4
        // would scramble in production) reverses this list.
        let head_of_stream = client_names(
            &pool,
            "SELECT event_id FROM greengateway.audit_stream ORDER BY position LIMIT 3",
        )
        .await;
        assert_eq!(
            head_of_stream,
            vec![
                fixture_event(0).event_id,
                fixture_event(1).event_id,
                fixture_event(2).event_id,
            ],
            "the stream is in the log's order, not the event ids' order"
        );
        let last_of_the_fixture_block = client_names(
            &pool,
            "SELECT event_id FROM greengateway.audit_stream ORDER BY position DESC LIMIT 1",
        )
        .await;
        assert_eq!(
            last_of_the_fixture_block,
            vec![observation_event(OBSERVATION_EVENTS - 1).event_id],
            "and the head of the stream is the last event the source recorded"
        );

        // A second run over the same log stores nothing twice and appends
        // no second stream row: every insert is ON CONFLICT on the
        // event id, and the stream's anti-join costs a stored id no
        // position.
        let resumed = run(&request(&fixture, ImportMode::Resume), &config)
            .await
            .expect("a resume should succeed");
        let resumed_section = section(&resumed, "audit");
        assert_eq!(resumed_section.status, "already-imported");
        assert_eq!(
            resumed_section.counts.get("audit_events_inserted"),
            Some(&0)
        );
        assert_eq!(
            resumed_section.checksum, applied_section.checksum,
            "the same log digests to the same value on every pass"
        );
        assert_eq!(
            count_of(&pool, "SELECT count(*) FROM greengateway.audit_events").await,
            fixture.audit_events
        );
        assert_eq!(
            count_of(
                &pool,
                "SELECT coalesce(max(position), 0) FROM greengateway.audit_stream"
            )
            .await,
            fixture.audit_events,
            "a second run assigns no further positions"
        );
    }

    /// Why the audit section deduplicates by `event_id` before handing a
    /// batch to the store, falsified.
    ///
    /// The stream's position reservation counts the ids a batch presents
    /// that are not yet on the stream, and then inserts them `ON CONFLICT
    /// (event_id) DO NOTHING`. A batch carrying one id twice therefore
    /// reserves two positions and inserts one row, and the number the
    /// second reservation burned is never used again -- a permanent gap in
    /// a sequence whose entire contract with durable cursors is that it
    /// has none.
    #[tokio::test]
    async fn one_event_id_twice_in_a_batch_burns_a_stream_position() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-audit-dedup");
        let pool = migrate(&config).await;
        let store = PostgresAuditEventStore::new(pool.clone(), None);

        let duplicated = fixture_event(0);
        store
            .insert_events(&[duplicated.clone(), duplicated])
            .await
            .expect("the batch should store");
        store
            .insert_events(&[fixture_event(1)])
            .await
            .expect("the second batch should store");

        let positions = client_positions(
            &pool,
            "SELECT position FROM greengateway.audit_stream ORDER BY position",
        )
        .await;
        assert_eq!(
            positions,
            vec![1, 3],
            "the duplicate burned position 2; the section deduplicates so this cannot happen"
        );
        assert_eq!(
            count_of(&pool, "SELECT count(*) FROM greengateway.audit_events").await,
            2,
            "the event itself is still stored exactly once"
        );
    }

    /// Steps 6 and 7 end to end, plus the step-8 verification of both.
    ///
    /// The fixture is a real standalone discovery database: observations
    /// written through the aggregator sink (so the endpoint inventory, its
    /// principals, its routing contexts and its signals are what the
    /// aggregator itself produced), one signal acknowledged so its
    /// revision is 2 rather than the column default, one endpoint marked
    /// reviewed and one review CLEARED, and suggestions generated by the
    /// standalone engine from the audit log's role matrix. Two service
    /// tokens, one revoked.
    #[tokio::test]
    async fn the_discovery_and_principal_sections_carry_the_inventory_signals_and_token_hashes() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-discovery");
        let pool = migrate(&config).await;
        let fixture = build_fixture("discovery", 1, 0);

        // The fixture has to be a real one, or the test below tests
        // nothing. Assert the shape it produced before relying on it.
        assert_eq!(
            fixture.discovery_endpoints, 2,
            "the observations describe exactly two endpoints"
        );
        assert!(
            fixture.discovery_signals >= 2,
            "the aggregator raised {} signals; the fixture needs at least one per endpoint",
            fixture.discovery_signals
        );
        assert!(
            fixture.discovery_suggestions >= 1,
            "the standalone engine generated no rule suggestion, so the section would carry              none; the engine reported {}",
            fixture.suggestion_generation
        );
        assert_eq!(fixture.service_tokens, 2);

        // --- the dry run -------------------------------------------------
        let planned = run(&request(&fixture, ImportMode::DryRun), &config)
            .await
            .expect("the dry run should succeed");
        let planned_discovery = section(&planned, "observations_and_discovery");
        assert_eq!(planned_discovery.status, "planned");
        assert_eq!(
            planned_discovery.counts.get("discovery_endpoints"),
            Some(&fixture.discovery_endpoints)
        );
        assert_eq!(
            planned_discovery.counts.get("discovery_signals"),
            Some(&fixture.discovery_signals)
        );
        assert_eq!(
            planned_discovery.counts.get("discovery_rule_suggestions"),
            Some(&fixture.discovery_suggestions)
        );
        assert_eq!(
            planned_discovery.counts.get("discovery_endpoint_reviews"),
            Some(&fixture.discovery_reviews),
            "a CLEARED review is still a row, and dropping it would restart its revisions"
        );
        let planned_principals = section(&planned, "principals_and_service_tokens");
        assert_eq!(
            planned_principals.counts.get("service_tokens"),
            Some(&fixture.service_tokens)
        );
        assert_eq!(
            planned_principals.counts.get("principal_directory_present"),
            Some(&1),
            "the source HAS a principal directory, and the report has to say it stayed behind"
        );
        assert_eq!(
            planned_principals
                .counts
                .get("principal_directory_rows_imported"),
            Some(&0)
        );

        // --- the apply ---------------------------------------------------
        let applied = run(&request(&fixture, ImportMode::Apply), &config)
            .await
            .expect("the apply should succeed");
        let discovery = section(&applied, "observations_and_discovery");
        assert_eq!(discovery.status, "imported");
        assert_eq!(
            discovery.checksum, planned_discovery.checksum,
            "the rehearsal's checksum is the apply's"
        );
        assert_eq!(
            discovery.counts.get("discovery_endpoints"),
            Some(&fixture.discovery_endpoints)
        );
        assert_eq!(
            discovery.counts.get("detector_states"),
            Some(&fixture.discovery_endpoints),
            "one detector state per endpoint: the counters a restart would have rebuilt"
        );

        // The lifecycle rows kept their state AND their revisions, which
        // is what PR 12's conditional transitions match on.
        let acknowledged = client_pairs(
            &pool,
            &format!(
                "SELECT state, revision::text FROM greengateway.discovery_signals \
                 WHERE id = '{}'",
                fixture.acknowledged_signal
            ),
        )
        .await;
        assert_eq!(
            acknowledged,
            vec![("acknowledged".to_owned(), "2".to_owned())],
            "an acknowledged signal arrives acknowledged, at the revision an If-Match holds"
        );
        assert_eq!(
            count_of(
                &pool,
                "SELECT count(*) FROM greengateway.discovery_signals WHERE revision = 1"
            )
            .await,
            fixture.discovery_signals - 1,
            "every other signal is at revision 1 because the import SET it, not because \
             migration 11 defaulted it"
        );
        assert_eq!(
            count_of(
                &pool,
                "SELECT count(*) FROM greengateway.discovery_endpoint_reviews \
                 WHERE reviewed_at IS NULL"
            )
            .await,
            1,
            "the cleared review crossed as a row with no reviewed_at, keeping its revision"
        );
        assert_eq!(
            count_of(
                &pool,
                "SELECT max(revision) FROM greengateway.discovery_endpoint_reviews \
                 WHERE reviewed_at IS NULL"
            )
            .await,
            2,
            "a clear bumps the revision; restarting it would let a stale If-Match match a \
             later review"
        );

        // The projector checkpoint sits at the imported stream head, so
        // the first leader re-projects none of the history these
        // aggregates were already built from.
        let checkpoint = count_of(
            &pool,
            "SELECT checkpoint_position FROM greengateway.discovery_projector_state \
             WHERE singleton",
        )
        .await;
        let head = count_of(
            &pool,
            "SELECT coalesce(max(position), 0) FROM greengateway.audit_stream",
        )
        .await;
        assert!(
            checkpoint > 0 && checkpoint == head,
            "{checkpoint} vs {head}"
        );
        assert_eq!(
            count_of(
                &pool,
                "SELECT fence FROM greengateway.discovery_projector_state WHERE singleton"
            )
            .await,
            0,
            "the import elects no leader; the first replica's claim is what moves the fence"
        );

        // Signals and reviews read back through the CLUSTER's own store,
        // in the same shape the standalone store returned them.
        let read_store = PostgresDiscoveryReadStore::new(pool.clone());
        let target_signals = read_store
            .exported_signals()
            .await
            .expect("the imported signals should read")
            .into_iter()
            .map(|signal| (signal.id, signal.target_key, signal.state, signal.revision))
            .collect::<Vec<_>>();
        let source_signals =
            crate::discovery::query::DiscoveryQueryStore::open(fixture.discovery_file())
                .expect("the source discovery store should reopen")
                .exported_signals()
                .expect("the source signals should export")
                .into_iter()
                .map(|signal| (signal.id, signal.target_key, signal.state, signal.revision))
                .collect::<Vec<_>>();
        assert_eq!(
            target_signals, source_signals,
            "ids, target keys, lifecycle states and revisions cross verbatim"
        );

        // The token hashes are the source's: that, and nothing else, is
        // what makes an already-issued token still verify after cutover.
        let principals = section(&applied, "principals_and_service_tokens");
        assert_eq!(principals.status, "imported");
        assert_eq!(
            principals.counts.get("service_tokens_inserted"),
            Some(&fixture.service_tokens)
        );
        let mut hashes = client_names(
            &pool,
            "SELECT token_hash FROM greengateway.service_tokens ORDER BY token_hash",
        )
        .await;
        let mut expected = fixture.token_hashes.clone();
        expected.sort();
        hashes.sort();
        assert_eq!(hashes, expected, "token hashes cross verbatim");
        assert_eq!(
            count_of(
                &pool,
                "SELECT count(*) FROM greengateway.service_tokens WHERE revoked_at IS NOT NULL"
            )
            .await,
            1,
            "a revoked token arrives revoked; a revoke can never be undone by an import"
        );
        assert_eq!(
            count_of(
                &pool,
                "SELECT count(*) FROM greengateway.service_tokens WHERE revision = 1"
            )
            .await,
            fixture.service_tokens,
            "the standalone table has no revision column, so 1 is a decision this import made"
        );

        // --- step 8 -------------------------------------------------------
        assert_eq!(applied.validation.status, "verified");
        assert!(
            applied.validation.checks.iter().all(|check| check.passed),
            "{:?}",
            applied.validation.checks
        );
        for expected_check in [
            "row_counts_match",
            "checksums_match",
            "constraints_validated",
            "referential_integrity",
            "connections_graph_boots",
            "active_etags_match_the_source",
            "projector_checkpoint_at_stream_head",
            "runtime_tables_untouched",
        ] {
            assert!(
                applied
                    .validation
                    .checks
                    .iter()
                    .any(|check| check.check == expected_check),
                "the validation must run {expected_check}"
            );
        }
        assert!(
            applied
                .validation
                .checksums
                .iter()
                .all(|row| !row.source.is_empty() && row.source == row.target),
            "both sides' checksums are printed and equal: {:?}",
            applied.validation.checksums
        );

        // The runtime tables the spec excludes hold nothing.
        for table in [
            "cluster_members",
            "maintenance_jobs",
            "execution_leases",
            "rate_limit_buckets",
            "rate_limit_cardinality",
            "admin_pending_logins",
            "jwt_revocations",
        ] {
            assert_eq!(
                count_of(&pool, &format!("SELECT count(*) FROM greengateway.{table}")).await,
                0,
                "{table} is runtime state a replica rebuilds; the import must not write it"
            );
        }

        // --- the report is redacted ---------------------------------------
        let rendered = applied.to_string();
        for forbidden in fixture.token_hashes.iter().map(String::as_str).chain([
            "token_hash",
            "ggw_",
            "postgres://",
            database.dsn.as_str(),
        ]) {
            assert!(
                !rendered.contains(forbidden),
                "the report must carry no token material or DSN: {rendered}"
            );
        }

        // --- a resume changes nothing --------------------------------------
        let resumed = run(&request(&fixture, ImportMode::Resume), &config)
            .await
            .expect("a resume should succeed");
        assert_eq!(
            section(&resumed, "observations_and_discovery").status,
            "already-imported"
        );
        assert_eq!(
            section(&resumed, "principals_and_service_tokens").status,
            "already-imported"
        );
        assert_eq!(resumed.validation.status, "verified");
        assert_eq!(
            count_of(
                &pool,
                "SELECT checkpoint_position FROM greengateway.discovery_projector_state \
                 WHERE singleton"
            )
            .await,
            checkpoint,
            "a resumed section that is already complete moves no checkpoint"
        );
    }

    /// `--dry-run` writes nothing: table counts before and after, the
    /// deployment binding included. And a dry run against a namespace an
    /// apply has already filled is REFUSED rather than silently comparing
    /// against somebody else's rows.
    #[tokio::test]
    async fn a_dry_run_writes_nothing() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-dry-run");
        let pool = migrate(&config).await;
        let fixture = build_fixture("dry-run", 2, 16);

        let before = super::super::preflight::occupied_namespace(&pool)
            .await
            .expect("the namespace should be readable");
        assert!(
            before.is_empty(),
            "the fixture starts on an empty namespace"
        );
        let binding_before = crate::storage::postgres::read_deployment_binding(&pool)
            .await
            .expect("the binding should be readable");

        let planned = run(&request(&fixture, ImportMode::DryRun), &config)
            .await
            .expect("the dry run should succeed");
        assert_eq!(planned.validation.status, "planned");
        assert!(
            planned
                .validation
                .tables
                .iter()
                .any(|table| table.table == "discovery_signals" && table.source > 0),
            "the rehearsal states what the target WOULD hold, per table"
        );
        assert!(
            planned
                .validation
                .tables
                .iter()
                .all(|table| table.target == 0),
            "and reads zero from the target, because it wrote nothing"
        );

        let after = super::super::preflight::occupied_namespace(&pool)
            .await
            .expect("the namespace should be readable");
        assert_eq!(
            after, before,
            "every authoritative table and counter is exactly as the dry run found it"
        );
        assert_eq!(
            crate::storage::postgres::read_deployment_binding(&pool)
                .await
                .expect("the binding should be readable"),
            binding_before,
            "a dry run does not even claim the database for this deployment"
        );

        // Once an apply has filled the namespace, a dry run is refused.
        run(&request(&fixture, ImportMode::Apply), &config)
            .await
            .expect("the apply should succeed");
        let Err(refused) = run(&request(&fixture, ImportMode::DryRun), &config).await else {
            panic!("a dry run into a filled namespace must be refused");
        };
        assert_eq!(refused.code(), "target_namespace_not_empty");
    }

    /// The two step-8 properties that would otherwise be assertions about
    /// this build's own good intentions, falsified against the database:
    /// the projector checkpoint at the stream head, and the runtime tables
    /// left untouched. Break each in turn and the validation says so.
    #[tokio::test]
    async fn the_checkpoint_and_the_excluded_runtime_tables_are_really_checked() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-falsify");
        let pool = migrate(&config).await;
        let fixture = build_fixture("falsify", 1, 0);

        run(&request(&fixture, ImportMode::Apply), &config)
            .await
            .expect("the apply should succeed");

        // The same inputs the run builds, minus the per-section
        // checksums: this test is about the other checks, and an empty
        // checksum list compares nothing.
        let source = StandaloneSource::load(&fixture.env_file).expect("the source should reload");
        fn inputs<'a>(
            source: &'a StandaloneSource,
            audit_events: i64,
        ) -> super::super::validation::ValidationInputs<'a> {
            super::super::validation::ValidationInputs {
                source,
                checksums: Vec::new(),
                expected_rows: super::super::validation::expected_rows(source, audit_events),
            }
        }
        super::super::validation::run(Some(&pool), &inputs(&source, fixture.audit_events))
            .await
            .expect("the imported namespace verifies as it stands");

        // 1. Rewind the checkpoint. A cluster booted like this would
        // re-project every imported event on top of the imported
        // counters: every call counted twice, every threshold crossed a
        // second time.
        execute(
            &pool,
            "UPDATE greengateway.discovery_projector_state SET checkpoint_position = 0 \
             WHERE singleton",
        )
        .await;
        let Err(refused) =
            super::super::validation::run(Some(&pool), &inputs(&source, fixture.audit_events))
                .await
        else {
            panic!("a rewound checkpoint must fail the validation");
        };
        assert_eq!(refused.code(), "validation_failed");
        assert!(
            refused
                .to_string()
                .contains("projector_checkpoint_at_stream_head"),
            "{refused}"
        );
        let head = count_of(
            &pool,
            "SELECT coalesce(max(position), 0) FROM greengateway.audit_stream",
        )
        .await;
        execute(
            &pool,
            &format!(
                "UPDATE greengateway.discovery_projector_state \
                 SET checkpoint_position = {head} WHERE singleton"
            ),
        )
        .await;

        // 2. Put a row in a table the import must never write.
        execute(
            &pool,
            "INSERT INTO greengateway.cluster_members (
                 deployment_id, instance_id, boot_id, binary_version,
                 schema_version_min, schema_version_max,
                 document_version_min, document_version_max, fingerprint
             ) VALUES (
                 'deploy-import-falsify',
                 '11111111-1111-4111-8111-111111111111',
                 '22222222-2222-4222-8222-222222222222',
                 'test', 1, 1, 1, 1,
                 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
             )",
        )
        .await;
        let Err(refused) =
            super::super::validation::run(Some(&pool), &inputs(&source, fixture.audit_events))
                .await
        else {
            panic!("a written runtime table must fail the validation");
        };
        assert!(
            refused.to_string().contains("runtime_tables_untouched")
                && refused.to_string().contains("cluster_members=1"),
            "{refused}"
        );
    }

    /// A standalone deployment that never enabled discovery still gets its
    /// projector checkpoint parked at the imported stream head.
    ///
    /// The audit section put the whole standalone log on the durable
    /// stream. A checkpoint left at the value migration seeded it with
    /// would have the cluster's first leader project all of it: an endpoint
    /// inventory built out of pre-cutover traffic, and a
    /// `new_endpoint_seen` signal raised for every endpoint in the
    /// operator's history against empty detector state. The step-8 check
    /// used to pass automatically whenever the aggregates table was empty,
    /// which is exactly this case, so nothing caught it.
    #[tokio::test]
    async fn a_source_with_no_discovery_database_still_parks_the_checkpoint_at_the_stream_head() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-no-discovery");
        let pool = migrate(&config).await;
        let fixture = build_fixture("no-discovery", 1, 4);

        // The same standalone deployment with DISCOVERY_SQLITE_PATH unset:
        // a gateway that logged its traffic and never turned discovery on.
        let env_file = fixture.directory.join("no-discovery.env");
        let contents =
            std::fs::read_to_string(&fixture.env_file).expect("the fixture env file should read");
        let without_discovery: String = contents
            .lines()
            .filter(|line| !line.starts_with("DISCOVERY_SQLITE_PATH="))
            .map(|line| format!("{line}\n"))
            .collect();
        std::fs::write(&env_file, without_discovery).expect("the env file should write");

        let report = run(
            &ImportRequest {
                standalone_env_file: env_file,
                mode: ImportMode::Apply,
            },
            &config,
        )
        .await
        .expect("the apply should succeed");
        assert!(
            !report.source.discovery_present,
            "the fixture under test is the one with no discovery database"
        );

        let head = count_of(
            &pool,
            "SELECT coalesce(max(position), 0) FROM greengateway.audit_stream",
        )
        .await;
        assert!(head > 0, "the log was imported, so the stream has a head");
        assert_eq!(
            count_of(
                &pool,
                "SELECT count(*) FROM greengateway.discovery_endpoint_aggregates"
            )
            .await,
            0,
            "and no aggregates, which is what used to make the check vacuous"
        );
        assert_eq!(
            count_of(
                &pool,
                "SELECT checkpoint_position FROM greengateway.discovery_projector_state \
                 WHERE singleton"
            )
            .await,
            head,
            "the checkpoint sits at the imported stream head, so the first leader projects \
             none of the imported log"
        );
        let checkpoint_check = report
            .validation
            .checks
            .iter()
            .find(|check| check.check == "projector_checkpoint_at_stream_head")
            .expect("the validation should carry the checkpoint check");
        assert!(
            checkpoint_check.passed,
            "and the check is the unconditional one: {:?}",
            checkpoint_check.detail
        );
    }

    /// An `--apply` pointed at another deployment's database refuses with
    /// the code that means "stop", not the one that means "retry".
    ///
    /// The apply establishes the foundation before preflight runs, and
    /// `start_if_selected` refuses a foreign binding. Mapping every
    /// foundation failure to `target_unavailable` told an operator who had
    /// typed the wrong `DATABASE_URL_FILE` that they had a connectivity or
    /// TLS problem -- which the runbook says to retry -- when what they had
    /// was another deployment's database. Both modes must name it the same
    /// way, because the code is the part operators script against.
    #[tokio::test]
    async fn an_apply_pointed_at_another_deployments_database_says_deployment_mismatch() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-mine");
        let pool = migrate(&config).await;
        let fixture = build_fixture("mismatch", 1, 0);

        execute(
            &pool,
            "INSERT INTO greengateway.deployment_binding (singleton, deployment_id) \
             VALUES (true, 'deploy-somebody-else')",
        )
        .await;

        let Err(dry_run) = run(&request(&fixture, ImportMode::DryRun), &config).await else {
            panic!("a dry run against a foreign binding must refuse");
        };
        assert_eq!(dry_run.code(), "target_deployment_mismatch");

        let Err(applied) = run(&request(&fixture, ImportMode::Apply), &config).await else {
            panic!("an apply against a foreign binding must refuse");
        };
        assert_eq!(
            applied.code(),
            "target_deployment_mismatch",
            "the apply refuses with the same code the rehearsal did: {applied}"
        );
        assert!(
            applied.to_string().contains("deploy-somebody-else"),
            "and names the deployment it found: {applied}"
        );
    }

    /// `--dry-run` writes NOTHING to the standalone deployment it reads.
    ///
    /// Every store the import reads the source with normalizes a schema
    /// when it opens a file, and the discovery suggestions engine goes
    /// further: it dismisses every open legacy `baseline_allow` suggestion
    /// whose proposed rule binds no issuer or auth method. Opened against
    /// the operator's live deployment, a cutover REHEARSAL would therefore
    /// throw away lifecycle state an administrator was still working
    /// through, in a gateway the cutover has not yet stopped -- while the
    /// runbook says a rehearsal is free. So the import reads private copies
    /// and the source's files come back byte for byte.
    #[tokio::test]
    async fn a_dry_run_leaves_the_standalone_deployment_byte_for_byte() {
        let Some(admin_dsn) = locator() else {
            eprintln!("skipping: no test database locator; CI runs this test");
            return;
        };
        let database = create_test_database(&admin_dsn).await;
        let (config, _dsn_file) = target_config(&database.dsn, "deploy-import-readonly");
        let pool = migrate(&config).await;
        let fixture = build_fixture("readonly-source", 1, 4);

        // Plant the one shape whose normalization is a data change rather
        // than a schema change: an open baseline suggestion proposing a
        // rule that binds neither an issuer nor an auth method. Written
        // with a direct statement because this is a LEGACY row -- the
        // engine that owns the table is the thing that dismisses it, so it
        // cannot be asked to produce one.
        let planted = {
            let connection = rusqlite::Connection::open(fixture.discovery_file())
                .expect("the fixture discovery database should open");
            let id: String = connection
                .query_row(
                    "SELECT id FROM discovery_rule_suggestions ORDER BY id LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .expect("the fixture should have generated a suggestion");
            connection
                .execute(
                    "UPDATE discovery_rule_suggestions
                     SET suggestion_type = 'baseline_allow',
                         state = 'open',
                         proposed_rule_json = json_set(
                             json_set(proposed_rule_json, '$.principal.issuers', json('[]')),
                             '$.principal.auth_methods', json('[]')
                         )
                     WHERE id = ?1",
                    [&id],
                )
                .expect("the legacy suggestion should plant");
            id
        };

        let before = source_tree_digest(&fixture.directory);
        let planned = run(&request(&fixture, ImportMode::DryRun), &config)
            .await
            .expect("the dry run should succeed");
        assert_eq!(planned.mode, "dry-run");
        let after = source_tree_digest(&fixture.directory);
        assert_eq!(
            before, after,
            "a dry run reads the standalone deployment and writes none of it"
        );
        // Reading a WAL database is what creates its `-shm` index and an
        // empty `-wal`, and any reader does it -- the standalone gateway
        // included. An EMPTY write-ahead log is the proof no write
        // happened: a byte in one is a committed change waiting to be
        // checkpointed into the file the digest above just compared.
        for (name, bytes) in journal_sizes(&fixture.directory) {
            assert_eq!(
                bytes, 0,
                "{name} carries a pending write, so something wrote to the source"
            );
        }

        // And the operator's suggestion is still theirs to decide about.
        // Read through a READ-ONLY connection: opening the engine would
        // dismiss it, which is the whole point.
        let state: String = rusqlite::Connection::open_with_flags(
            fixture.discovery_file(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("the source discovery database should open read-only")
        .query_row(
            "SELECT state FROM discovery_rule_suggestions WHERE id = ?1",
            [&planted],
            |row| row.get(0),
        )
        .expect("the planted suggestion should still be there");
        assert_eq!(
            state, "open",
            "the rehearsal did not transition the operator's suggestion"
        );

        // The namespace is untouched too, which is the half that was
        // already true.
        assert!(super::super::preflight::occupied_namespace(&pool)
            .await
            .expect("the namespace should be readable")
            .is_empty());

        // The local-secret keyring is named in the report rather than left
        // for the operator to discover after scale-out.
        assert_eq!(
            planned.source.connection_local_secrets, 0,
            "the fixture's bindings reference an external secret store"
        );
        assert!(
            planned
                .not_imported
                .iter()
                .any(|entry| entry.starts_with("connection_local_secrets")),
            "the report names the local-secret material it never moves"
        );
    }

    /// Every durable file in the standalone deployment's directory, by name
    /// and SHA-256. Names as well as digests, so a run that CREATED a file
    /// is caught as surely as one that changed a byte.
    ///
    /// SQLite's `-wal` and `-shm` sidecars are excluded and checked
    /// separately by [`journal_sizes`]: opening a WAL database for READING
    /// creates them, so their existence says nothing, while their SIZE says
    /// everything.
    fn source_tree_digest(directory: &std::path::Path) -> Vec<(String, String)> {
        use sha2::{Digest, Sha256};

        let mut entries: Vec<(String, String)> = source_files(directory)
            .into_iter()
            .filter(|(name, _)| !is_sqlite_sidecar(name))
            .map(|(name, path)| {
                let bytes = std::fs::read(&path).expect("the source file should read");
                (name, hex::encode(Sha256::digest(&bytes)))
            })
            .collect();
        entries.sort();
        entries
    }

    /// The size of every write-ahead log in the directory. Zero is the
    /// proof: a WAL with bytes in it holds a committed change that has not
    /// been folded into the database file yet.
    fn journal_sizes(directory: &std::path::Path) -> Vec<(String, u64)> {
        source_files(directory)
            .into_iter()
            .filter(|(name, _)| name.ends_with("-wal"))
            .map(|(name, path)| {
                let bytes = std::fs::metadata(&path)
                    .expect("the journal should stat")
                    .len();
                (name, bytes)
            })
            .collect()
    }

    fn source_files(directory: &std::path::Path) -> Vec<(String, PathBuf)> {
        std::fs::read_dir(directory)
            .expect("the fixture directory should list")
            .map(|entry| entry.expect("the directory entry should read").path())
            .filter(|path| path.is_file())
            .map(|path| {
                let name = path
                    .file_name()
                    .expect("a file has a name")
                    .to_string_lossy()
                    .into_owned();
                (name, path)
            })
            .collect()
    }

    fn is_sqlite_sidecar(name: &str) -> bool {
        name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal")
    }

    async fn execute(pool: &deadpool_postgres::Pool, sql: &str) {
        pool.get()
            .await
            .expect("checkout")
            .execute(sql, &[])
            .await
            .expect("the fixture statement should run");
    }

    /// A token hash column wants 64 hex characters. This one is a literal
    /// with no token behind it; nothing ever hashed to it.
    const FAKE_TOKEN_HASH: &str =
        "fa4e0000000000000000000000000000000000000000000000000000000000fa";

    async fn client_rows(pool: &deadpool_postgres::Pool, sql: &str) -> Vec<(i64, String, String)> {
        pool.get()
            .await
            .expect("checkout")
            .query(sql, &[])
            .await
            .expect("the verification query should run")
            .iter()
            .map(|row| (row.get(0), row.get(1), row.get(2)))
            .collect()
    }

    async fn client_names(pool: &deadpool_postgres::Pool, sql: &str) -> Vec<String> {
        pool.get()
            .await
            .expect("checkout")
            .query(sql, &[])
            .await
            .expect("the verification query should run")
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    async fn client_pairs(pool: &deadpool_postgres::Pool, sql: &str) -> Vec<(String, String)> {
        pool.get()
            .await
            .expect("checkout")
            .query(sql, &[])
            .await
            .expect("the verification query should run")
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect()
    }

    async fn client_positions(pool: &deadpool_postgres::Pool, sql: &str) -> Vec<i64> {
        pool.get()
            .await
            .expect("checkout")
            .query(sql, &[])
            .await
            .expect("the verification query should run")
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    async fn count_of(pool: &deadpool_postgres::Pool, sql: &str) -> i64 {
        pool.get()
            .await
            .expect("checkout")
            .query_one(sql, &[])
            .await
            .expect("the verification query should run")
            .get(0)
    }
}
