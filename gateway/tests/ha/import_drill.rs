//! The standalone-to-cluster import drill, end to end (issue #241, PR 16
//! part 2).
//!
//! `docs/deployment/postgres.md` documents a cutover an operator performs
//! once, against a deployment they cannot afford to lose: migrate, rehearse
//! with `--dry-run`, cut over with `--apply`, verify, and — until traffic
//! moves — be able to walk away from the whole thing and start the
//! standalone gateway again. This file is that runbook as a test.
//!
//! ## The source is a real deployment, not a fixture
//!
//! [`Standalone::build`] starts the real binary in standalone mode and
//! drives it through its own admin API: four conditional policy commits
//! (so the history the import carries has real version numbers and real
//! actors), two Connections — one of them bound to a credential in the
//! local keyring — a service token, and forty proxied requests, which is
//! the only way an audit log and a discovery inventory come into
//! existence. What the drill then compares the import's report against is
//! read back out of those SQLite files by this test, never out of the
//! report: a report checked against itself would agree with any bug that
//! was consistent.
//!
//! ## What each phase pins
//!
//! * [`a_dry_run_writes_nothing_to_the_target_and_nothing_to_the_source`]
//!   — both halves of the rehearsal's promise. The target half is
//!   structural (`import::run` takes `PostgresFoundation::establish`, not
//!   `start_if_selected`). The SOURCE half is the one a review of PR 15
//!   caught: the stores the import reads through normalize a SQLite file
//!   when they open it, so a rehearsal that opened the operator's live
//!   databases would have written to the deployment it was rehearsing
//!   against. PR 15 answers that with a `VACUUM INTO` snapshot; this
//!   asserts it, by digesting every source file and re-reading every
//!   source count on both sides of the run.
//! * [`the_cutover_writes_what_the_rehearsal_planned`] — the property that
//!   makes a free rehearsal worth running: section-by-section checksum
//!   equality between the two modes, counts equal to the source's own, and
//!   the target read directly (preserved version numbers, a realigned
//!   identity sequence, the activation the import signs).
//! * [`the_imported_deployment_serves_across_a_restart_and_a_scale_out`] —
//!   phases 4-6, as one test because they are one claim: a replica serves
//!   the imported state, still serves it after a restart, and a second
//!   replica joins without a second import.
//! * [`a_second_apply_is_refused_and_the_source_survives_the_cutover`] —
//!   the rollback boundary in both directions.
//! * [`an_interrupted_apply_resumes_to_the_state_a_clean_apply_reaches`] —
//!   a real interruption (the database refuses the connections section's
//!   first insert) and the resume that finishes it.
//! * [`every_refusal_the_runbook_names_answers_with_its_own_code`] — the
//!   refusal codes an operator scripts against, and the four this drill
//!   cannot provoke through the CLI, each named with its reason.
//! * [`the_import_needs_the_migration_role_not_a_runtime_one`] — the
//!   privilege claim `postgres_policy.rs` documents, made executable.
//! * [`no_report_carries_a_field_a_credential_could_hide_in`] — privacy,
//!   as a shape rule over the parsed report rather than a substring grep.
//!
//! ## Three things this drill found, and did not paper over
//!
//! 1. **The report is not the only thing on stdout.**
//!    `initialize_tracing_for_one_shot_commands` installs a `fmt` layer
//!    with its default writer, so a one-shot command's log lines and its
//!    JSON report share stdout and `gateway import-standalone … | jq`
//!    fails on the first log line. [`report`] finds the JSON rather than
//!    parsing the stream, and says so.
//! 2. **The wrong DSN reports `store_failure: … unavailable`.** SQLSTATE
//!    `42501` classifies as `Unavailable`, so an operator who runs the
//!    cutover with a least-privilege role is told the target is not
//!    usable rather than that the role is not privileged. See
//!    [`the_import_needs_the_migration_role_not_a_runtime_one`].
//! 3. **`/v1/admin/audit` is a standalone-only surface.** It is backed by
//!    the SQLite query store, which cluster mode rejects, so after a
//!    cutover it answers `503 audit query store not configured` on every
//!    replica. The imported log is read through the durable event stream,
//!    which is what [`assert_imported_state`] asserts.
//!
//! ## What it does not cover
//!
//! * The discovery and service-token sections are asserted through the
//!   report's counts, the import's own validation pass (`verified`), and
//!   the row counts in the target — not through an admin API comparison.
//!   The cluster's discovery surface is filled by the projector from the
//!   imported stream, which is `events_discovery_leader.rs`'s subject.
//! * `source_snapshot_failed`, `validation_failed`,
//!   `target_deployment_id_missing` and `section_conflict` are not
//!   provoked; the first two need filesystem and read-back faults, the
//!   third is unreachable through the CLI, and the fourth needs a
//!   namespace another import started. See the refusal test's own
//!   documentation.
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`, and without
//! `GATEWAY_TEST_HA_GATE`, like every other suite under `tests/ha/`.

#![cfg(feature = "postgres")]

mod harness;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Output,
    time::Duration,
};

use serde_json::{json, Value};

use harness::{gateway_binary, http_client, Database, Replica, TempDir, INHERITED_ENVIRONMENT};

/// The admin API the fixture is driven through.
const ADMIN_POLICY: &str = "/v1/admin/policy";
const ADMIN_CONNECTIONS: &str = "/v1/admin/connections";
const ADMIN_SECRETS: &str = "/v1/admin/connection-secrets";
const ADMIN_TOKENS: &str = "/v1/admin/tokens";

/// The collection preconditions a create carries: both resources publish
/// their collection's own ETag beside the ordinary one.
const CONNECTION_COLLECTION_ETAG: &str = "x-greengateway-connections-etag";
const SECRET_COLLECTION_ETAG: &str = "x-greengateway-connection-secrets-etag";

/// The role the fixture's administrator holds, and the one its policy
/// grants everything to.
const ADMIN_ROLE: &str = "drill";

/// How many policy commits the fixture makes after its initial document.
const POLICY_COMMITS: usize = 4;
/// How many requests the fixture proxies, so the audit log and the
/// discovery aggregates have content that a count can be compared against.
const PROXIED_REQUESTS: usize = 40;

fn skipped() {
    eprintln!(
        "skipping: no test database locator, or this run is not the gate; the ha-release-gate \
         CI job runs this suite"
    );
}

// ---------------------------------------------------------------------
// The standalone deployment being imported
// ---------------------------------------------------------------------

/// A real standalone deployment: a policy file and its history, a tools
/// document, a Connections database with a credential binding, an audit
/// log, discovery aggregates and a service token — all written by a real
/// gateway process serving real requests, because the import reads what a
/// deployment leaves behind and a hand-written fixture would only prove
/// the import can read the test's idea of one.
struct Standalone {
    /// Everything the import reads. Nothing else is written here, so the
    /// whole directory can be digested and compared.
    source: TempDir,
    /// The process's own artifacts: its JSONL audit sink (which is how the
    /// harness discovers the port it bound) and nothing the import looks
    /// at.
    runtime: TempDir,
    env_file: PathBuf,
    policy_file: PathBuf,
    tools_file: PathBuf,
    connections_file: PathBuf,
    audit_file: PathBuf,
    discovery_file: PathBuf,
    service_token_file: PathBuf,
    principal_file: PathBuf,
    upstream: harness::FakeUpstream,
    /// The issuer the fixture's administrator authenticates against. The
    /// admin API takes no unauthenticated caller even with `AUTH_ENABLED`
    /// off — every handler wants a principal — so a fixture driven through
    /// that API needs a real one.
    oidc: harness::FakeOidcIssuer,
    /// What the fixture is known to contain, derived from the source files
    /// themselves rather than from the import's own report.
    facts: SourceFacts,
}

/// The source's content, counted by this test from the source files.
///
/// The drill compares the import's report against these, never against
/// itself: a report that agreed only with a second reading of the report
/// would be evidence of nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceFacts {
    policy_history_versions: i64,
    tools: i64,
    connections: i64,
    connection_local_secrets: i64,
    audit_events: i64,
    service_tokens: i64,
    discovery_endpoints: i64,
}

/// The source as bytes and as content, for the assertion that the import
/// changed neither.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceState {
    /// Every file in the source directory, by name, as `sha256:<hex>`.
    files: BTreeMap<String, String>,
    facts: SourceFacts,
}

impl Standalone {
    /// Build the fixture: start a standalone gateway, drive it, stop it.
    async fn build(label: &str) -> Self {
        let source = TempDir::new(&format!("standalone-{label}"));
        let runtime = TempDir::new(&format!("standalone-runtime-{label}"));
        let path = |name: &str| source.path().join(name);
        let policy_file = path("policy.json");
        let tools_file = path("tools.json");
        let connections_file = path("connections.sqlite");
        let audit_file = path("audit.sqlite");
        let discovery_file = path("discovery.sqlite");
        let service_token_file = path("tokens.sqlite");
        let principal_file = path("principals.sqlite");

        std::fs::write(&policy_file, initial_policy().to_string())
            .expect("the fixture policy file should write");
        std::fs::write(&tools_file, tools_document().to_string())
            .expect("the fixture tools file should write");
        // The local-secret keyring encrypts the Connections database's
        // secret material. It lives OUTSIDE the source directory: the
        // import never moves key material, and a keyring inside the
        // digested directory would only measure the harness.
        runtime.write_private("connection-key", &random_key_material());

        let env_file = source.path().join("standalone.env");
        std::fs::write(
            &env_file,
            format!(
                "# the standalone deployment this drill imports\n\
                 POLICY_FILE={}\n\
                 TOOLS_FILE={}\n\
                 CONNECTIONS_SQLITE_PATH={}\n\
                 AUDIT_SQLITE_PATH={}\n\
                 DISCOVERY_SQLITE_PATH={}\n\
                 SERVICE_TOKEN_SQLITE_PATH={}\n\
                 PRINCIPAL_SQLITE_PATH={}\n\
                 CONNECTION_SECRETS_ROOT={}\n\
                 CONNECTION_LOCAL_SECRET_KEYRING={}\n",
                policy_file.display(),
                tools_file.display(),
                connections_file.display(),
                audit_file.display(),
                discovery_file.display(),
                service_token_file.display(),
                principal_file.display(),
                runtime.path().display(),
                keyring_declaration("connection-key"),
            ),
        )
        .expect("the standalone environment file should write");

        let upstream = harness::FakeUpstream::start().await;
        let oidc = harness::FakeOidcIssuer::start().await;
        let mut standalone = Self {
            source,
            runtime,
            env_file,
            policy_file,
            tools_file,
            connections_file,
            audit_file,
            discovery_file,
            service_token_file,
            principal_file,
            upstream,
            oidc,
            facts: SourceFacts {
                policy_history_versions: 0,
                tools: 0,
                connections: 0,
                connection_local_secrets: 0,
                audit_events: 0,
                service_tokens: 0,
                discovery_endpoints: 0,
            },
        };

        {
            let mut gateway = standalone.serve("seed").await;
            standalone.drive(&gateway.base_url()).await;
            gateway.stop();
        }
        standalone.quiesce();
        standalone.facts = standalone.read_facts();
        standalone
    }

    /// The environment a standalone gateway runs with: the source settings
    /// the env file names, plus the ones a running process needs and an
    /// import never reads.
    fn process_environment(&self, label: &str) -> Vec<(String, String)> {
        let mut env: Vec<(String, String)> = source_settings(&self.env_file)
            .into_iter()
            .collect::<Vec<_>>();
        env.push(("LISTEN_ADDR".to_owned(), "127.0.0.1:0".to_owned()));
        env.push(("AUTH_ENABLED".to_owned(), "true".to_owned()));
        env.push((
            "AUTH_PROVIDERS".to_owned(),
            json!([{
                "name": harness::oidc::PRIMARY_PROVIDER,
                "type": "jwt",
                "issuer": self.oidc.issuer,
                "jwks_url": self.oidc.jwks_url,
                "audience": harness::oidc::AUDIENCE,
                "require_jti": true,
            }])
            .to_string(),
        ));
        env.push(("CSRF_ENABLED".to_owned(), "false".to_owned()));
        env.push((
            "AUDIT_LOG_FILE".to_owned(),
            self.runtime
                .path()
                .join(format!("process-{label}.jsonl"))
                .display()
                .to_string(),
        ));
        // `UPSTREAM_URL` rather than `UPSTREAM_ROUTES`: the fixture's tools
        // document holds legacy HTTP tools, and the tool executor refuses
        // to start without the catch-all upstream they resolve against.
        // The two settings are mutually exclusive.
        env.push(("UPSTREAM_URL".to_owned(), self.upstream.base_url.clone()));
        env.push(("EGRESS_ALLOWED_HOSTS".to_owned(), "127.0.0.1".to_owned()));
        env.push(("EGRESS_DENY_PRIVATE_IPS".to_owned(), "false".to_owned()));
        env.push(("SHUTDOWN_DRAIN_DELAY_MS".to_owned(), "0".to_owned()));
        env.push(("SHUTDOWN_TIMEOUT_MS".to_owned(), "5000".to_owned()));
        env.push(("AUDIT_DRAIN_TIMEOUT_MS".to_owned(), "5000".to_owned()));
        env
    }

    /// Start the standalone gateway and wait until it is serving.
    async fn serve(&self, label: &str) -> Replica {
        let audit_path = self.runtime.path().join(format!("process-{label}.jsonl"));
        let mut process = Replica::spawn(
            &format!("standalone-{label}"),
            &gateway_binary(),
            self.process_environment(label),
            audit_path,
        );
        process.wait_until_listening(harness::LISTEN_BUDGET).await;
        process.wait_until_ready(harness::READY_BUDGET).await;
        process
    }

    /// An authenticated client for a running fixture.
    fn api(&self, base_url: &str) -> Api {
        Api {
            base_url: base_url.to_owned(),
            bearer: self.oidc.mint_role_token(
                harness::oidc::PRIMARY_KID,
                "drill-admin@ha.test",
                &format!("jti-{}", uuid::Uuid::new_v4().simple()),
                &[ADMIN_ROLE],
                3_600,
            ),
        }
    }

    /// Drive the deployment: policy commits, Connections, a service token
    /// and proxied traffic.
    async fn drive(&self, base_url: &str) {
        let api = self.api(base_url);

        // Policy: one conditional commit per version, so the history the
        // import carries has real version numbers and real actors.
        for index in 0..POLICY_COMMITS {
            let (status, headers, body) = api
                .send(reqwest::Method::GET, ADMIN_POLICY, &[], None)
                .await;
            assert_eq!(status, 200, "the standalone policy should read: {body}");
            let etag = header(&headers, reqwest::header::ETAG.as_str());
            let (status, _, body) = api
                .send(
                    reqwest::Method::PUT,
                    ADMIN_POLICY,
                    &[("if-match", etag.as_str())],
                    Some(&policy_with_marker(index)),
                )
                .await;
            assert_eq!(status, 200, "policy commit {index} should succeed: {body}");
        }

        // A Connection with no credential, and one whose credential is a
        // reference into the local keyring: the import carries the second
        // as a REFERENCE and leaves the key material behind, which is the
        // property the report's `connection_local_secrets` count exists to
        // make visible.
        let collection = api.collection_etag().await;
        let (status, _, body) = api
            .send(
                reqwest::Method::POST,
                ADMIN_CONNECTIONS,
                &[("if-match", collection.as_str())],
                Some(&json!({
                    "display_name": "drill upstream",
                    "kind": "http_api",
                    "endpoint": { "base_url": self.upstream.base_url, "base_path": "/" },
                    "authentication": { "type": "none" },
                    "enabled": false,
                })),
            )
            .await;
        assert_eq!(status, 201, "the plain Connection should create: {body}");

        let secrets = api
            .collection_precondition(ADMIN_SECRETS, SECRET_COLLECTION_ETAG)
            .await;
        let (status, _, body) = api
            .send(
                reqwest::Method::POST,
                ADMIN_SECRETS,
                &[("if-match", secrets.as_str())],
                Some(&json!({
                    "label": "drill vendor bearer",
                    "purpose": "static_bearer",
                    "value": FAKE_CONNECTION_SECRET,
                })),
            )
            .await;
        assert_eq!(status, 201, "the fixture secret should create: {body}");
        let secret_id = body["id"]
            .as_str()
            .unwrap_or_else(|| panic!("a created secret should carry an id: {body}"))
            .to_owned();

        let collection = api.collection_etag().await;
        let (status, _, body) = api
            .send(
                reqwest::Method::POST,
                ADMIN_CONNECTIONS,
                &[("if-match", collection.as_str())],
                Some(&json!({
                    "display_name": "drill vendor",
                    "kind": "http_api",
                    "endpoint": { "base_url": "https://127.0.0.1:9", "base_path": "/" },
                    "authentication": { "type": "static_bearer", "secret_id": secret_id },
                    "enabled": false,
                })),
            )
            .await;
        assert_eq!(
            status, 201,
            "the credential-bound Connection should create: {body}"
        );

        // A service token, so the principals-and-service-tokens section has
        // something to carry.
        let (status, _, body) = api
            .send(
                reqwest::Method::POST,
                ADMIN_TOKENS,
                &[],
                Some(&json!({ "scopes": [ADMIN_ROLE] })),
            )
            .await;
        assert_eq!(status, 201, "the fixture service token should mint: {body}");

        // Traffic: the audit log and the discovery aggregates, produced the
        // only way a deployment produces them.
        for index in 0..PROXIED_REQUESTS {
            let (status, _, body) = api
                .send(reqwest::Method::GET, &format!("/orders/{index}"), &[], None)
                .await;
            assert_eq!(status, 200, "the fixture request should proxy: {body}");
        }
    }

    /// Fold every SQLite write-ahead log back into its database.
    ///
    /// Fixture preparation, and it happens BEFORE the state this drill
    /// compares against is recorded, so it can never hide a write the
    /// import made. It exists because a gateway that was killed rather
    /// than asked to exit (Windows has no signal a test can send) leaves a
    /// hot `-wal`, and the import opens the source read-only: the point of
    /// the drill is what the import does to a quiescent deployment, not
    /// what SQLite does with a journal a crash left behind.
    fn quiesce(&self) {
        for path in self.sqlite_files() {
            if !path.exists() {
                continue;
            }
            let connection = rusqlite::Connection::open(&path)
                .unwrap_or_else(|error| panic!("{} should reopen: {error}", path.display()));
            connection
                .pragma_update(None, "journal_mode", "DELETE")
                .unwrap_or_else(|error| panic!("{} should checkpoint: {error}", path.display()));
            drop(connection);
        }
    }

    fn sqlite_files(&self) -> Vec<PathBuf> {
        vec![
            self.connections_file.clone(),
            self.audit_file.clone(),
            self.discovery_file.clone(),
            self.service_token_file.clone(),
            self.principal_file.clone(),
            self.policy_history_file(),
        ]
    }

    /// Where the standalone gateway keeps the policy history: derived from
    /// `POLICY_FILE`, exactly as `main.rs::default_policy_history_sqlite_path`
    /// derives it.
    fn policy_history_file(&self) -> PathBuf {
        PathBuf::from(format!("{}.history.sqlite", self.policy_file.display()))
    }

    /// Count the source's content, from the source.
    fn read_facts(&self) -> SourceFacts {
        SourceFacts {
            policy_history_versions: sqlite_count(
                &self.policy_history_file(),
                "SELECT count(*) FROM policy_versions",
            ),
            tools: json_file(&self.tools_file)["tools"]
                .as_array()
                .map(|tools| tools.len() as i64)
                .unwrap_or(0),
            connections: sqlite_count(
                &self.connections_file,
                "SELECT count(*) FROM connection_records",
            ),
            connection_local_secrets: sqlite_count(
                &self.connections_file,
                "SELECT count(*) FROM connection_local_secrets",
            ),
            audit_events: sqlite_count(&self.audit_file, "SELECT count(*) FROM audit_events"),
            service_tokens: sqlite_count(
                &self.service_token_file,
                "SELECT count(*) FROM service_tokens",
            ),
            discovery_endpoints: sqlite_count(
                &self.discovery_file,
                "SELECT count(*) FROM discovery_endpoint_aggregates",
            ),
        }
    }

    /// The standalone history's `(version, actor)` pairs, read from the
    /// deployment's own SQLite store.
    fn source_policy_actors(&self) -> Vec<(i64, String)> {
        let path = self.policy_history_file();
        let connection = rusqlite::Connection::open(&path)
            .unwrap_or_else(|error| panic!("{} should open: {error}", path.display()));
        let mut statement = connection
            .prepare("SELECT version, actor_user_id FROM policy_versions ORDER BY version")
            .expect("the history query should prepare");
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .expect("the history query should run");
        rows.map(|row| row.expect("a history row should read"))
            .collect()
    }

    /// The source as it stands right now: every file's digest, and the
    /// content those files hold.
    ///
    /// Two readings rather than one, because they fail differently. A
    /// changed digest catches a write that landed anywhere in a file; the
    /// counts catch a write that landed in a journal the digest of the
    /// database file would not have seen.
    fn state(&self) -> SourceState {
        SourceState {
            files: directory_digests(self.source.path()),
            facts: self.read_facts(),
        }
    }
}

/// The policy the deployment starts from.
fn initial_policy() -> Value {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    })
}

/// The document commit `index` writes: the same policy with one more
/// harmless role, so every version differs from the one before it.
fn policy_with_marker(index: usize) -> Value {
    let mut document = initial_policy();
    document["roles"][format!("drill-{index}")] = json!({ "permissions": [] });
    document
}

fn tools_document() -> Value {
    let tool = |name: &str, path: &str| {
        json!({
            "name": name,
            "description": "an import-drill fixture tool",
            "input_json_schema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false,
            },
            "upstream": { "method": "GET", "path_template": path },
        })
    };
    json!({
        "schema_version": "0.1.0",
        "tools": [tool("drill_alpha", "/alpha"), tool("drill_beta", "/beta")],
    })
}

/// A credential-shaped canary. Never a real secret, and prefixed so a
/// history scanner reads it as the fixture value it is.
const FAKE_CONNECTION_SECRET: &str = "FAKE_DRILL_CONNECTION_SECRET_9f2a";

/// A one-key keyring naming a file beneath `CONNECTION_SECRETS_ROOT`,
/// which is the only shape the key readers accept.
fn keyring_declaration(file: &str) -> String {
    json!([{ "id": format!("drill-{file}"), "file": file, "role": "primary" }]).to_string()
}

fn random_key_material() -> Vec<u8> {
    let mut material = Vec::with_capacity(32);
    material.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    material.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    material
}

/// The `KEY=VALUE` assignments of an environment file, read the way the
/// import reads them.
fn source_settings(env_file: &Path) -> BTreeMap<String, String> {
    let contents = std::fs::read_to_string(env_file).expect("the environment file should read");
    let mut variables = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (key, value) = trimmed
            .split_once('=')
            .unwrap_or_else(|| panic!("the fixture environment file line {trimmed} is malformed"));
        variables.insert(key.trim().to_owned(), value.to_owned());
    }
    variables
}

// ---------------------------------------------------------------------
// Reading the source without the gateway
// ---------------------------------------------------------------------

fn sqlite_count(path: &Path, sql: &str) -> i64 {
    if !path.exists() {
        return 0;
    }
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("{} should open: {error}", path.display()));
    connection
        .query_row(sql, [], |row| row.get::<_, i64>(0))
        .unwrap_or_else(|error| panic!("{sql} against {} failed: {error}", path.display()))
}

fn json_file(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{} should read: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("{} should parse as JSON: {error}", path.display()))
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Every file in `directory`, by file name, as a digest.
fn directory_digests(directory: &Path) -> BTreeMap<String, String> {
    let mut digests = BTreeMap::new();
    let entries = std::fs::read_dir(directory).expect("the source directory should list");
    for entry in entries {
        let entry = entry.expect("a source directory entry should read");
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        let bytes = std::fs::read(&path).expect("a source file should read");
        digests.insert(
            path.file_name()
                .expect("a source file has a name")
                .to_string_lossy()
                .into_owned(),
            digest(&bytes),
        );
    }
    digests
}

// ---------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------

/// An authenticated client against one running gateway.
struct Api {
    base_url: String,
    bearer: String,
}

impl Api {
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&Value>,
    ) -> (u16, reqwest::header::HeaderMap, Value) {
        let url = format!("{}{path}", self.base_url);
        let mut builder = http_client()
            .request(method, &url)
            .bearer_auth(&self.bearer);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        if let Some(body) = body {
            builder = builder.json(body);
        }
        let response = builder
            .send()
            .await
            .unwrap_or_else(|error| panic!("the gateway did not answer {url}: {error}"));
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = response.bytes().await.unwrap_or_default();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn get(&self, path: &str) -> (u16, reqwest::header::HeaderMap, Value) {
        self.send(reqwest::Method::GET, path, &[], None).await
    }

    /// A collection's own precondition, published beside the ordinary
    /// `ETag` so a create can be conditional on the collection.
    async fn collection_precondition(&self, route: &str, header_name: &str) -> String {
        let (status, headers, body) = self.get(route).await;
        assert_eq!(status, 200, "{route} should list: {body}");
        header(&headers, header_name)
    }

    async fn collection_etag(&self) -> String {
        self.collection_precondition(ADMIN_CONNECTIONS, CONNECTION_COLLECTION_ETAG)
            .await
    }
}

fn header(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("the response carried no {name} header"))
        .to_owned()
}

// ---------------------------------------------------------------------
// The target cluster deployment
// ---------------------------------------------------------------------

/// The database an import writes into: created, migrated, and nothing
/// else. The harness's `Cluster` seeds a policy document, which is exactly
/// what an import target must not have.
struct Target {
    database: Database,
    deployment_id: String,
    files: TempDir,
    migrator_dsn_file: PathBuf,
}

impl Target {
    /// Create and migrate a target, or answer `None` on the skip path.
    async fn create(label: &str) -> Option<Self> {
        let target = Self::unmigrated(label).await?;
        target.migrate();
        Some(target)
    }

    /// A target database with no schema at all: what
    /// `target_schema_not_current` is about, and the state every real
    /// cutover starts from.
    async fn unmigrated(label: &str) -> Option<Self> {
        let admin_dsn = harness::locator()?;
        let database = Database::create(&admin_dsn).await;
        let files = TempDir::new(&format!("target-{label}"));
        let migrator_dsn_file = files.write_private(
            "database-url-migrator",
            format!("{}\n", database.migrator_dsn).as_bytes(),
        );
        files.write_private("rate-limit-key", &random_key_material());
        Some(Self {
            database,
            deployment_id: format!("drill-{}", uuid::Uuid::new_v4().simple()),
            files,
            migrator_dsn_file,
        })
    }

    /// Apply the schema as the migration role, exactly as the cutover
    /// order in `docs/deployment/postgres.md` prescribes.
    fn migrate(&self) {
        let output = self.command(&self.migrator_dsn_file, &["migrate", "up"]);
        assert!(
            output.status.success(),
            "gateway migrate up failed\n{}",
            combined(&output)
        );
    }

    /// The cluster-side (TARGET) environment: the process environment
    /// `import-standalone` reads, and nothing local.
    fn environment(&self, dsn_file: &Path) -> Vec<(String, String)> {
        vec![
            ("STATE_BACKEND".to_owned(), "postgres".to_owned()),
            ("DEPLOYMENT_ID".to_owned(), self.deployment_id.clone()),
            (
                "DATABASE_URL_FILE".to_owned(),
                dsn_file.display().to_string(),
            ),
            ("DATABASE_TLS_MODE".to_owned(), "loopback-dev".to_owned()),
            // A one-shot command needs one connection, on a server this
            // suite shares with every other row.
            ("DATABASE_POOL_MAX".to_owned(), "2".to_owned()),
            // Cluster mode keys its shared rate-limit buckets under a
            // keyring, and requires one even from a command that never
            // serves a request.
            (
                "CONNECTION_SECRETS_ROOT".to_owned(),
                self.files.path().display().to_string(),
            ),
            (
                "RATE_LIMIT_KEYRING".to_owned(),
                keyring_declaration("rate-limit-key"),
            ),
        ]
    }

    fn command(&self, dsn_file: &Path, arguments: &[&str]) -> Output {
        run_gateway(&self.environment(dsn_file), arguments)
    }

    /// Run the import with the MIGRATION role's DSN, which is what the
    /// runbook says and what the policy history's identity insert and
    /// sequence realignment need.
    fn import(&self, arguments: &[&str]) -> Output {
        self.command(&self.migrator_dsn_file, arguments)
    }

    async fn count(&self, sql: &str) -> i64 {
        self.database.count(sql).await
    }

    /// The deployment this database is bound to and when it was claimed,
    /// or `None` while it is unclaimed. The timestamp is part of the
    /// answer: a command that re-claimed an already-bound database would
    /// move it, and "unchanged" is what the dry run has to be.
    async fn binding(&self) -> Option<(String, String)> {
        let rows = self
            .database
            .query_all(
                "SELECT deployment_id, bound_at::text                  FROM greengateway.deployment_binding WHERE singleton",
            )
            .await;
        rows.first()
            .map(|row| (row.get::<_, String>(0), row.get::<_, String>(1)))
    }

    /// The imported history's `(version, actor)` pairs, oldest first,
    /// excluding the activation commit the import signs itself.
    async fn policy_actors(&self) -> Vec<(i64, String)> {
        self.database
            .query_all(
                "SELECT version, actor_user_id FROM greengateway.policy_documents \
                 WHERE actor_user_id <> 'import-standalone' ORDER BY version",
            )
            .await
            .iter()
            .map(|row| (row.get::<_, i64>(0), row.get::<_, String>(1)))
            .collect()
    }

    /// The authoritative tables that hold rows and the counters that have
    /// moved, as `name=count` strings — the same shape
    /// `preflight::occupied_namespace` reports, computed here from a
    /// deliberately independent list so a bug that dropped a table from
    /// the product's list is still visible to this drill.
    async fn occupancy(&self) -> Vec<String> {
        let mut occupied = Vec::new();
        for table in AUTHORITATIVE_TABLES {
            let count = self
                .count(&format!(
                    "SELECT count(*)::bigint FROM greengateway.{table}"
                ))
                .await;
            if count > 0 {
                occupied.push(format!("{table}={count}"));
            }
        }
        for (table, column) in AUTHORITATIVE_COUNTERS {
            let value = self
                .count(&format!(
                    "SELECT coalesce(max({column}), 0)::bigint FROM greengateway.{table}"
                ))
                .await;
            if value > 0 {
                occupied.push(format!("{table}={value}"));
            }
        }
        occupied.sort();
        occupied
    }
}

/// Run the gateway binary with a cleared environment plus `env`.
fn run_gateway(env: &[(String, String)], arguments: &[&str]) -> Output {
    let mut command = std::process::Command::new(gateway_binary());
    command.env_clear();
    for key in INHERITED_ENVIRONMENT {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    for (key, value) in env {
        command.env(key, value);
    }
    command
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("the gateway command {arguments:?} should run: {error}"))
}

fn combined(output: &Output) -> String {
    format!(
        "--- status ---\n{}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// The report a successful invocation printed, parsed.
///
/// The report is found rather than simply parsed, and that is worth being
/// explicit about: `initialize_tracing_for_one_shot_commands`
/// (`main.rs:2792`) installs a `tracing_subscriber::fmt` layer with its
/// default writer, which is **stdout**, so a one-shot command's log lines
/// and its JSON report share one stream and
/// `gateway import-standalone --from … | jq` fails on the first log line.
/// Nothing in this drill depends on that staying true — the report is
/// located by its opening brace, so this keeps working if a later change
/// moves diagnostics to stderr where they belong — but a reader of this
/// file should know the report is not, today, the only thing on stdout.
fn report(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "the import should have succeeded\n{}",
        combined(output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let start = stdout
        .find("\n{\n")
        .map(|index| index + 1)
        .or_else(|| stdout.starts_with('{').then_some(0))
        .unwrap_or_else(|| panic!("stdout carried no report\n{}", combined(output)));
    serde_json::from_str(&stdout[start..])
        .unwrap_or_else(|error| panic!("the report should be JSON ({error})\n{}", combined(output)))
}

/// The section report named `section`, or a panic naming what was there
/// instead.
fn section<'a>(report: &'a Value, name: &str) -> &'a Value {
    report["sections"]
        .as_array()
        .expect("a report carries its sections")
        .iter()
        .find(|entry| entry["section"] == name)
        .unwrap_or_else(|| panic!("the report has no {name} section: {report}"))
}

fn section_names(report: &Value) -> Vec<String> {
    report["sections"]
        .as_array()
        .expect("a report carries its sections")
        .iter()
        .map(|entry| entry["section"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// What "an empty namespace" means, written out here rather than read from
/// the product: `preflight::AUTHORITATIVE_TABLES` is the list the import
/// checks against, and a drill that asked the import to define emptiness
/// and then checked emptiness with the import's own definition would agree
/// with itself no matter what fell off the list.
const AUTHORITATIVE_TABLES: [&str; 36] = [
    "audit_events",
    "audit_stream",
    "policy_documents",
    "policy_active",
    "security_outbox",
    "tool_documents",
    "tool_active",
    "tool_name_reservations",
    "connection_records",
    "connection_documents",
    "connection_credential_bindings",
    "connection_dependencies",
    "connection_current_status",
    "connection_status_history",
    "connection_mcp_catalogs",
    "connection_mcp_catalog_entries",
    "connection_mcp_catalog_resources",
    "connection_mcp_catalog_resource_templates",
    "connection_openapi_catalogs",
    "connection_openapi_catalog_entries",
    "service_tokens",
    "discovery_endpoint_aggregates",
    "discovery_endpoint_status_counts",
    "discovery_endpoint_principals",
    "discovery_endpoint_routing_contexts",
    "discovery_endpoint_routing_principals",
    "discovery_endpoint_routing_classifications",
    "discovery_endpoint_classified_signal_stats",
    "discovery_endpoint_classified_signal_principals",
    "discovery_payload_shape_stats",
    "discovery_payload_shape_samples",
    "discovery_endpoint_reviews",
    "discovery_signals",
    "discovery_rule_suggestions",
    "discovery_detector_state",
    "discovery_template_groups",
];

/// The singleton counters migration seeds at zero. A moved counter is an
/// occupied namespace even when every table is still empty.
const AUTHORITATIVE_COUNTERS: [(&str, &str); 5] = [
    ("security_revision_state", "last_revision"),
    ("audit_stream_state", "last_position"),
    ("connection_state_revision", "last_revision"),
    ("service_token_state_revision", "last_revision"),
    ("discovery_projector_state", "checkpoint_position"),
];

/// The sections the import writes, in the order it writes them.
const SECTIONS: [&str; 6] = [
    "policy",
    "tools",
    "connections",
    "audit",
    "observations_and_discovery",
    "principals_and_service_tokens",
];

// =====================================================================
// Phase 1 — the rehearsal writes nothing
// =====================================================================

/// A dry run reads both sides and writes to neither.
///
/// The target half is the one the command's own structure turns on
/// (`import::run` takes `PostgresFoundation::establish` rather than
/// `start_if_selected` for a dry run, so it cannot even bind the
/// database). The SOURCE half is the one a review caught: the stores the
/// import reads through normalize a SQLite file when they open it, so a
/// rehearsal that opened the operator's live databases directly would
/// write to the deployment it was rehearsing against. Both halves are
/// asserted here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dry_run_writes_nothing_to_the_target_and_nothing_to_the_source() {
    let Some(target) = Target::create("dry-run").await else {
        return skipped();
    };
    let standalone = Standalone::build("dry-run").await;
    let before = standalone.state();

    // `gateway migrate up` is what claims a database for a deployment
    // (`migrations::execute` binds after applying), so the binding already
    // exists when the rehearsal runs. What the dry run must not do is
    // change it — including its `bound_at`, which a re-claim would move.
    let binding_before = target.binding().await;
    assert!(
        binding_before.is_some(),
        "the migration step should have claimed this database"
    );

    let output = target.import(&[
        "import-standalone",
        "--from",
        &standalone.env_file.display().to_string(),
    ]);
    let report = report(&output);

    assert_eq!(report["command"], "import-standalone");
    assert_eq!(report["mode"], "dry-run", "no mode flag means a dry run");
    assert_eq!(report["deployment_id"], target.deployment_id);
    assert_eq!(report["schema"]["status"], "current");
    assert_eq!(
        section_names(&report),
        SECTIONS.to_vec(),
        "every section, in the order the import writes them"
    );
    for name in SECTIONS {
        assert_eq!(
            section(&report, name)["status"],
            "planned",
            "a dry run plans {name} and writes nothing"
        );
    }
    assert_eq!(
        report["validation"]["status"], "planned",
        "there is nothing to verify until something is written"
    );
    assert!(
        report["not_imported"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty()),
        "every report names what it did not carry: {report}"
    );
    assert_eq!(
        report["source"]["principal_present"], true,
        "the principal directory must be NAMED as staying behind, not silently dropped"
    );

    // The target: nothing claimed, nothing written.
    assert_eq!(
        target.binding().await,
        binding_before,
        "a dry run must leave the deployment binding exactly as it found it"
    );
    assert_eq!(
        target.occupancy().await,
        Vec::<String>::new(),
        "a dry run must leave the namespace empty"
    );
    // And the emptiness check itself agrees: preflight refuses a
    // non-empty namespace in every mode but `--resume`, so a second dry
    // run succeeding is the whole namespace's receipt.
    let second = target.import(&[
        "import-standalone",
        "--from",
        &standalone.env_file.display().to_string(),
        "--dry-run",
    ]);
    assert!(
        second.status.success(),
        "the namespace should still be empty enough for a second rehearsal\n{}",
        combined(&second)
    );

    // The source: byte-identical, and holding exactly what it held.
    assert_eq!(
        standalone.state(),
        before,
        "a rehearsal must not write to the deployment it is rehearsing against"
    );
}

// =====================================================================
// Phase 3 — the cutover, and the rehearsal's promise
// =====================================================================

/// `--apply` writes what the rehearsal said it would.
///
/// The property that makes a free rehearsal worth running is that the two
/// runs agree, so this runs both against the same fresh target and
/// compares them section by section — on the CHECKSUM, which is the one
/// field both modes compute the same way (`canonical_digest` over the
/// section's export). The counts are compared against the source instead,
/// read out of the SQLite databases by this test: a report checked against
/// itself would agree with any bug that was consistent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cutover_writes_what_the_rehearsal_planned() {
    let Some(target) = Target::create("cutover").await else {
        return skipped();
    };
    let standalone = Standalone::build("cutover").await;
    let from = standalone.env_file.display().to_string();

    let rehearsal = report(&target.import(&["import-standalone", "--from", &from]));
    let applied = report(&target.import(&["import-standalone", "--from", &from, "--apply"]));

    assert_eq!(applied["mode"], "apply");
    assert_eq!(section_names(&applied), SECTIONS.to_vec());
    for name in SECTIONS {
        let section = section(&applied, name);
        assert_eq!(
            section["status"], "imported",
            "{name} should report what it did: {section}"
        );
        assert_eq!(
            section["checksum"],
            self::section(&rehearsal, name)["checksum"],
            "the {name} section's cutover must digest to what the rehearsal digested"
        );
    }
    assert_eq!(
        applied["validation"]["status"], "verified",
        "an import that cannot verify itself is not one to scale out on: {applied}"
    );

    // The report's view of the source is the source.
    let facts = &standalone.facts;
    let source = &applied["source"];
    assert_eq!(
        source["policy_history_versions"],
        facts.policy_history_versions
    );
    assert_eq!(source["tools"], facts.tools);
    assert_eq!(source["connections"], facts.connections);
    assert_eq!(
        source["connection_local_secrets"], facts.connection_local_secrets,
        "the keyring rows that stay behind are counted, so the re-provisioning \
         the cutover owes is a number an operator reads during the rehearsal"
    );
    assert_eq!(source["service_tokens"], facts.service_tokens);
    assert_eq!(source["discovery_endpoints"], facts.discovery_endpoints);

    // And the sections' counts are the source's counts.
    assert_eq!(
        section(&applied, "policy")["counts"]["policy_history_versions"],
        facts.policy_history_versions
    );
    assert_eq!(section(&applied, "tools")["counts"]["tools"], facts.tools);
    assert_eq!(
        section(&applied, "connections")["counts"]["connection_records"],
        facts.connections
    );
    assert_eq!(
        section(&applied, "audit")["counts"]["audit_events_deduplicated"],
        facts.audit_events,
        "every event in the standalone log, deduplicated by event_id"
    );
    assert_eq!(
        section(&applied, "principals_and_service_tokens")["counts"]["service_tokens"],
        facts.service_tokens
    );

    // The target, read directly rather than through the report.
    let history = facts.policy_history_versions;
    assert_eq!(
        target
            .count("SELECT count(*)::bigint FROM greengateway.policy_documents")
            .await,
        history + 1,
        "the imported history plus the operator's live document"
    );
    assert_eq!(
        target
            .count(
                "SELECT count(*)::bigint FROM greengateway.policy_documents \
                 WHERE version BETWEEN 1 AND $$LIMIT$$"
                    .replace("$$LIMIT$$", &(history + 1).to_string())
                    .as_str()
            )
            .await,
        history + 1,
        "the standalone version numbers are preserved and contiguous"
    );
    // History fidelity: an imported version keeps the version number and
    // the actor the standalone deployment recorded — the import is not the
    // author of somebody else's history. It IS the author of the
    // activation commit that follows, and that row is the one stamped
    // `import-standalone`, which is how a reader tells the two apart.
    assert_eq!(
        target.policy_actors().await,
        standalone.source_policy_actors(),
        "every imported history row keeps the version and the actor the standalone \
         deployment recorded for it"
    );
    assert_eq!(
        target
            .count(&format!(
                "SELECT count(*)::bigint FROM greengateway.policy_documents \
                 WHERE version = {} AND actor_user_id = 'import-standalone'",
                history + 1
            ))
            .await,
        1,
        "the activation the import itself performed is the row it signs"
    );
    assert_eq!(
        target
            .count("SELECT active_version::bigint FROM greengateway.policy_active WHERE singleton")
            .await,
        history + 1,
        "the live document is the newest version, above the imported history"
    );
    // The identity was bypassed to preserve the version numbers, so the
    // sequence has to have been moved past them: the next administrator
    // commit must take the next number rather than colliding with an
    // imported one.
    assert_eq!(
        target
            .count(
                "SELECT last_value::bigint FROM pg_sequences \
                 WHERE schemaname = 'greengateway' AND sequencename = \
                   (SELECT split_part(pg_get_serial_sequence(\
                      'greengateway.policy_documents', 'version'), '.', 2))"
            )
            .await,
        history + 1,
        "the policy_documents sequence is realigned past the imported versions"
    );

    // The rehearsal's promise ran BEFORE this apply, and the source is
    // still exactly what it was.
    assert_eq!(
        standalone.state().facts,
        standalone.facts,
        "a cutover reads the source and writes only to the target"
    );
}

// =====================================================================
// Phases 4-6 — verification, restart, scale-out
// =====================================================================

/// The imported deployment is a live cluster, not a restored snapshot.
///
/// One replica is started against the database the import wrote — as the
/// RUNTIME role, which is not the role that wrote it — and asked for what
/// the standalone deployment held. Then it is restarted, which separates
/// durable state from a cache the import warmed. Then a second replica is
/// added, which is the property an operator actually cuts over for: a
/// replica joining an imported deployment needs no second import, and the
/// two agree.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_imported_deployment_serves_across_a_restart_and_a_scale_out() {
    let Some(target) = Target::create("serves").await else {
        return skipped();
    };
    let standalone = Standalone::build("serves").await;
    let applied = report(&target.import(&[
        "import-standalone",
        "--from",
        &standalone.env_file.display().to_string(),
        "--apply",
    ]));
    let stream_head = section(&applied, "audit")["counts"]["audit_stream_head"]
        .as_i64()
        .unwrap_or_else(|| panic!("the audit section reports its stream head: {applied}"));

    // What the standalone deployment served, computed from its own files.
    let expected_policy_etag = harness::database::policy_etag(
        &std::fs::read_to_string(&standalone.policy_file).expect("the policy file should read"),
    );
    let facts = standalone.facts.clone();

    let Target {
        database,
        deployment_id,
        ..
    } = target;
    let Some(mut cluster) = harness::Cluster::start(harness::ClusterOptions {
        replicas: 1,
        auth: harness::AuthShape::Oidc,
        proxy: harness::ProxyShape::LegacyUpstream,
        adopt_database: Some(database),
        deployment_id: Some(deployment_id),
        ..harness::ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    cluster.wait_until_all_ready().await;
    let admin = cluster.oidc.mint_role_token(
        harness::oidc::PRIMARY_KID,
        "drill-admin@ha.test",
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    );

    // Phase 4: the replica serves what was imported.
    assert_imported_state(&cluster, "a", &admin, &expected_policy_etag, &facts).await;
    let body = wait_for_roster(&cluster, "a", &admin, 1).await;
    assert_eq!(body["mode"], "cluster");
    assert_eq!(body["state"], "ready", "the status said {body}");
    assert_eq!(body["reason"], Value::Null);
    assert_eq!(body["schema"]["compatible"], true);
    assert_eq!(
        cluster
            .database
            .count("SELECT coalesce(max(position), 0)::bigint FROM greengateway.audit_stream")
            .await,
        stream_head,
        "the durable stream head is the one the import's report named"
    );

    // Phase 5: a restart changes nothing. A replica that only served
    // because the import had warmed something would fail here.
    cluster.restart("a").await;
    cluster.wait_until_all_ready().await;
    assert_imported_state(&cluster, "a", &admin, &expected_policy_etag, &facts).await;

    // Phase 6: scale out. No second import, no seed, nothing but a process.
    let second = cluster.add_replica().await;
    cluster.wait_until_all_ready().await;
    for replica in ["a", second.as_str()] {
        assert_imported_state(&cluster, replica, &admin, &expected_policy_etag, &facts).await;
    }
    for replica in ["a", second.as_str()] {
        let body = wait_for_roster(&cluster, replica, &admin, 2).await;
        assert_eq!(
            body["local"]["revision_lag"], 0,
            "a replica of an imported deployment compiles the revision it observes"
        );
    }

    // And it is live: a policy committed on the new replica is served by
    // the old one.
    let (status, headers, body) = cluster
        .get("a", ADMIN_POLICY)
        .bearer(&admin)
        .send_with_headers()
        .await;
    assert_eq!(status, 200, "the policy should read: {body}");
    let precondition = headers
        .get(reqwest::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("the policy read carries its ETag")
        .to_owned();
    let mut after_cutover = initial_policy();
    after_cutover["roles"]["written-after-the-cutover"] = json!({ "permissions": [] });
    let (status, body) = cluster
        .put(&second, ADMIN_POLICY)
        .bearer(&admin)
        .if_match(&precondition)
        .json(&after_cutover)
        .send()
        .await;
    assert_eq!(
        status, 200,
        "the imported deployment must accept a commit on the new replica: {body}"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (status, _, body) = settled(|| cluster.get("a", ADMIN_POLICY).bearer(&admin)).await;
        assert_eq!(status, 200, "the policy should read: {body}");
        if body["roles"].get("written-after-the-cutover").is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the first replica never observed the commit made on the second: {body}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    cluster.shutdown();
}

/// How long a read re-asks a replica that answered `503`.
///
/// Cluster mode's revision gate re-reads the authority on every protected
/// request within its own bounded budget, so `503 policy state
/// unavailable` is a documented TRANSIENT after a topology change — a
/// restart or a scale-out leaves the pool replacing backends for a moment,
/// and `/readyz` going ready is not a promise about the very next request.
/// Tolerating it costs nothing that matters: a `503` dispatches nothing and
/// decides nothing, and every caller below still asserts the answer it
/// settles on.
const SETTLE_BUDGET: Duration = Duration::from_secs(20);

/// Send until the replica stops answering `503`, or [`SETTLE_BUDGET`]
/// passes and the last answer is returned as it is.
async fn settled(
    build: impl Fn() -> harness::PinnedRequest,
) -> (u16, reqwest::header::HeaderMap, Value) {
    let deadline = std::time::Instant::now() + SETTLE_BUDGET;
    loop {
        let outcome = build().send_with_headers().await;
        if outcome.0 != 503 || std::time::Instant::now() >= deadline {
            return outcome;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Poll `GET /v1/admin/cluster` until the roster reports `expected`
/// replicas ready out of `expected` live, and answer the body it settled
/// on.
///
/// A poll rather than a read: `ready_at` is stamped by a heartbeat, so the
/// roster trails a replica's own `/readyz` by up to one heartbeat
/// interval. That lag is the deployment converging, not a defect.
async fn wait_for_roster(
    cluster: &harness::Cluster,
    replica: &str,
    admin: &str,
    expected: u64,
) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (status, _, body) =
            settled(|| cluster.get(replica, "/v1/admin/cluster").bearer(admin)).await;
        assert_eq!(status, 200, "the cluster status should answer: {body}");
        if body["replicas"]["ready"] == expected && body["replicas"]["total"] == expected {
            return body;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "replica {replica} never saw {expected} ready member(s): {body}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Everything a replica of the imported deployment must serve.
async fn assert_imported_state(
    cluster: &harness::Cluster,
    replica: &str,
    admin: &str,
    expected_policy_etag: &str,
    facts: &SourceFacts,
) {
    // Settled, because this is the FIRST protected read after a restart or
    // a scale-out; once one request has been admitted the pool is warm and
    // the reads below need no budget of their own.
    let (status, headers, body) =
        settled(|| cluster.get(replica, ADMIN_POLICY).bearer(admin)).await;
    assert_eq!(
        status, 200,
        "replica {replica} should serve the policy: {body}"
    );
    assert_eq!(
        headers
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok()),
        Some(expected_policy_etag),
        "replica {replica} must serve the standalone deployment's own document, byte for \
         byte under canonical ordering"
    );

    let (status, body) = cluster
        .get(replica, "/v1/admin/tools")
        .bearer(admin)
        .send()
        .await;
    assert_eq!(
        status, 200,
        "replica {replica} should serve the tools: {body}"
    );
    assert_eq!(
        body["total_count"], facts.tools,
        "replica {replica} served {body}"
    );
    let empty = Vec::new();
    let served: Vec<String> = body["capabilities"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|entry| entry["name"].as_str().map(str::to_owned))
        .collect();
    assert_eq!(
        served,
        vec!["drill_alpha".to_owned(), "drill_beta".to_owned()],
        "replica {replica} should serve the standalone deployment's own tools"
    );

    let (status, body) = cluster
        .get(replica, ADMIN_CONNECTIONS)
        .bearer(admin)
        .send()
        .await;
    assert_eq!(
        status, 200,
        "replica {replica} should serve the Connections: {body}"
    );
    // Only the MANAGED rows are the imported ones: the list also projects
    // the replica's own `UPSTREAM_URL` as a read-only legacy Connection,
    // which no import carried and no import should.
    let empty = Vec::new();
    let managed: Vec<&Value> = body["connections"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter(|row| row["source"] == "managed")
        .collect();
    assert_eq!(
        managed.len() as i64,
        facts.connections,
        "replica {replica} served {body}"
    );
    let mut names: Vec<&str> = managed
        .iter()
        .filter_map(|row| row["display_name"].as_str())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["drill upstream", "drill vendor"],
        "replica {replica} should serve the standalone deployment's own Connections"
    );
    assert!(
        managed
            .iter()
            .any(|row| row["authentication"] == "static_bearer"
                && row["revisions"]["credential"] == 1),
        "the credential binding must cross as a reference, not vanish: {body}"
    );
    let rendered = body.to_string();
    assert!(
        !rendered.contains(FAKE_CONNECTION_SECRET),
        "a credential binding crosses as a reference; replica {replica} rendered the secret"
    );

    // The audit log: every source event is durable, at a contiguous
    // position, and readable by a consumer through this replica.
    //
    // Through the durable STREAM, not through `/v1/admin/audit`: that
    // endpoint is backed by the SQLite query store
    // (`main.rs:2874`, from `AUDIT_SQLITE_PATH`), which cluster mode
    // rejects, so after a cutover it answers
    // `503 audit query store not configured` on every replica. An
    // operator's post-cutover audit reader is the event stream, and that
    // is what this asserts.
    assert_eq!(
        cluster
            .database
            .count("SELECT count(*)::bigint FROM greengateway.audit_events")
            .await,
        facts.audit_events,
        "the imported audit log holds every source event, deduplicated by event_id"
    );
    let contiguous: i64 = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.audit_stream \
             WHERE position BETWEEN 1 AND (SELECT count(*) FROM greengateway.audit_stream)",
        )
        .await;
    assert_eq!(
        contiguous, facts.audit_events,
        "the imported stream positions are contiguous from 1: a durable cursor's \
         contract is that the sequence has no gaps"
    );
    let mut stream = harness::sse::Request::new(
        &cluster.replica(replica).base_url(),
        "/v1/admin/events/stream?event_type=http.request_observed",
        admin,
    )
    .resume_after(0)
    .open_ok()
    .await;
    let frame = stream
        .next_frame(Duration::from_secs(20))
        .await
        .unwrap_or_else(|| {
            panic!("replica {replica} replayed no imported event to a consumer resuming from 0")
        });
    let first_observation = cluster
        .database
        .count(
            "SELECT min(s.position)::bigint FROM greengateway.audit_stream s \
             JOIN greengateway.audit_events e ON e.event_id = s.event_id \
             WHERE e.event_type = 'http.request_observed'",
        )
        .await;
    assert_eq!(
        frame.position(),
        first_observation,
        "a consumer resuming from the beginning is served the earliest imported event \
         it asked for, not whatever happened after the cutover"
    );
}

// =====================================================================
// Phase 7 — the rollback boundary
// =====================================================================

/// Until traffic moves, the cutover is discardable; after it, the import
/// is one-way.
///
/// Both halves are asserted here. The discardable half: the source is
/// byte-identical after a full apply, and the standalone gateway starts
/// again against its untouched environment file and serves exactly what it
/// served before. The one-way half: a second `--apply` is REFUSED rather
/// than merged, doubled, or silently skipped — idempotence enforced by a
/// refusal is the only kind an operator can audit.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_apply_is_refused_and_the_source_survives_the_cutover() {
    let Some(target) = Target::create("rollback").await else {
        return skipped();
    };
    let standalone = Standalone::build("rollback").await;
    let from = standalone.env_file.display().to_string();
    let before = standalone.state();

    let applied = report(&target.import(&["import-standalone", "--from", &from, "--apply"]));
    assert_eq!(applied["mode"], "apply");

    // The boundary: a second apply is refused, and the refusal names the
    // occupied tables as `name=count` — never a row, never a value.
    let second = target.import(&["import-standalone", "--from", &from, "--apply"]);
    let message = refusal(&second, "target_namespace_not_empty");
    let occupied = target.occupancy().await;
    assert!(
        !occupied.is_empty(),
        "the apply should have occupied the namespace"
    );
    for entry in &occupied {
        assert!(
            message.contains(entry),
            "the refusal should name {entry} as occupied: {message}"
        );
    }
    assert!(
        !message.contains("drill-admin"),
        "an occupancy refusal reports names and counts, never row content: {message}"
    );
    assert_eq!(
        target.occupancy().await,
        occupied,
        "a refused second apply must write nothing"
    );

    // A dry run is refused for the same reason: the rehearsal is only free
    // against an empty namespace, and after the cutover there is not one.
    refusal(
        &target.import(&["import-standalone", "--from", &from]),
        "target_namespace_not_empty",
    );

    // The discardable half. The source is untouched...
    assert_eq!(
        standalone.state(),
        before,
        "an import that has not been cut over to must leave nothing behind on the source"
    );

    // ...and the standalone deployment still runs, serving what it served.
    let mut again = standalone.serve("rollback").await;
    let api = standalone.api(&again.base_url());
    let (status, headers, body) = api.get(ADMIN_POLICY).await;
    assert_eq!(
        status, 200,
        "the standalone gateway should serve again: {body}"
    );
    assert_eq!(
        header(&headers, reqwest::header::ETAG.as_str()),
        harness::database::policy_etag(
            &std::fs::read_to_string(&standalone.policy_file).expect("the policy file should read")
        ),
        "the standalone deployment serves the document it served before the drill"
    );
    let (status, _, body) = api.get(ADMIN_CONNECTIONS).await;
    assert_eq!(
        status, 200,
        "the standalone Connections should list: {body}"
    );
    assert_eq!(
        body["connections"]
            .as_array()
            .map(|rows| rows.iter().filter(|row| row["source"] == "managed").count() as i64),
        Some(standalone.facts.connections),
        "the standalone deployment still holds its own Connections"
    );
    again.stop();

    // Dropping the target leaves nothing the standalone deployment needs:
    // the harness's database reaper does that when this test returns, and
    // the state comparison above is what proves the source never depended
    // on it.
}

// =====================================================================
// Phase 2 — the refusals an operator scripts against
// =====================================================================

/// Every refusal this drill can provoke through the CLI, by code.
///
/// The codes are the contract (`ImportError::code`): an operator's runbook
/// matches on them, so each is provoked and asserted by name, and the
/// message is checked for what it must NOT carry as well as what it must.
///
/// Fifteen of the nineteen codes are provoked by this drill: twelve here,
/// and `target_namespace_not_empty`, `section_failed` and `store_failure`
/// in the rollback and resume drills, where the state they need already
/// exists. The remaining **four** are not provoked anywhere in this suite,
/// and each for a reason rather than by omission:
///
/// * `target_deployment_id_missing` is **unreachable through the CLI**.
///   `Config::from_env` refuses `STATE_BACKEND=postgres` with no
///   `DEPLOYMENT_ID` before `import::run` is ever called (`config.rs`'s
///   `reject_local_authority_in_postgres_mode`), so the process exits on a
///   configuration error and the import's own code never renders. It is
///   reachable only by calling `run()` in-process, which the crate's own
///   tests do.
/// * `source_snapshot_failed` needs the private snapshot directory to be
///   uncreatable, which is a filesystem fault, not an input.
/// * `validation_failed` needs the import to write correctly and then read
///   back something else, which nothing here can arrange. It is the one
///   refusal that means the target may hold a WRONG state rather than no
///   state (`cutover.md`), so its absence from the gate is recorded in the
///   deployment guide's "What the gate does not prove" list as well as
///   here.
/// * `section_conflict` needs a target whose namespace is occupied by a
///   *different* import's output and then resumed onto, which the rollback
///   drill deliberately does not build: it asserts the boundary instead —
///   a second `--apply` is refused rather than merged.
///
/// An earlier version of this comment listed `store_failure` among the
/// unprovoked and claimed `section_conflict` was provoked elsewhere; both
/// were the wrong way round. The list is checkable: grep this file for each
/// code string.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_refusal_the_runbook_names_answers_with_its_own_code() {
    let Some(target) = Target::create("refusals").await else {
        return skipped();
    };
    let standalone = Standalone::build("refusals").await;
    let from = standalone.env_file.display().to_string();
    let scratch = TempDir::new("refusals");

    // Every invocation below is kept, not just asserted on and dropped.
    // The privacy check at the foot of this test used to run over a fresh
    // dry run and one refusal, which left the refusals most able to echo a
    // connection string — `target_unavailable`, whose input IS a DSN file,
    // and the two that name a target the process could reach — outside the
    // only assertion in this suite that greps for one.
    let mut provoked: Vec<Output> = Vec::new();

    // usage: five ways to get the command line wrong.
    for arguments in [
        vec!["import-standalone", "--from", &from, "--apply", "--dry-run"],
        vec!["import-standalone", "--from", &from, "--resume"],
        vec!["import-standalone", "--apply"],
        vec!["import-standalone", "--from", &from, "--unknown"],
        vec!["import-standalone", "--from", &from, "--from", &from],
    ] {
        let message = record(&mut provoked, target.import(&arguments), "usage");
        assert!(
            message.contains("gateway import-standalone --from"),
            "a usage refusal should print the usage: {message}"
        );
    }

    // The source file itself.
    let missing = scratch.path().join("absent.env");
    record(
        &mut provoked,
        target.import(&[
            "import-standalone",
            "--from",
            &missing.display().to_string(),
        ]),
        "standalone_env_file_unreadable",
    );

    let malformed = scratch.path().join("malformed.env");
    std::fs::write(
        &malformed,
        format!(
            "POLICY_FILE={}\n{MALFORMED_LINE}\n",
            standalone.policy_file.display()
        ),
    )
    .expect("the malformed environment file should write");
    let message = record(
        &mut provoked,
        target.import(&[
            "import-standalone",
            "--from",
            &malformed.display().to_string(),
        ]),
        "standalone_env_file_malformed",
    );
    assert!(
        message.contains("line 2"),
        "the refusal should name the line NUMBER: {message}"
    );
    assert!(
        !message.contains(MALFORMED_LINE),
        "the line's text may be credential material and must be withheld: {message}"
    );

    let invalid = scratch.path().join("invalid.env");
    std::fs::write(
        &invalid,
        format!(
            "POLICY_FILE={}\nLISTEN_ADDR=not-a-socket-{FAKE_CONNECTION_SECRET}\n",
            standalone.policy_file.display()
        ),
    )
    .expect("the invalid environment file should write");
    let message = record(
        &mut provoked,
        target.import(&[
            "import-standalone",
            "--from",
            &invalid.display().to_string(),
        ]),
        "standalone_config_invalid",
    );
    assert!(
        message.contains("LISTEN_ADDR"),
        "the refusal should name the setting: {message}"
    );
    assert!(
        !message.contains(FAKE_CONNECTION_SECRET),
        "a validator's message quotes the VALUE, and some values are key material, \
         so the refusal must not: {message}"
    );

    // A `--from` that names a cluster is not a standalone deployment.
    let cluster_env = scratch.path().join("cluster.env");
    std::fs::write(
        &cluster_env,
        format!(
            "STATE_BACKEND=postgres\nDEPLOYMENT_ID=not-this-one\nDATABASE_URL_FILE={}\n\
             CONNECTION_SECRETS_ROOT={}\nRATE_LIMIT_KEYRING={}\n",
            target.migrator_dsn_file.display(),
            target.files.path().display(),
            keyring_declaration("rate-limit-key"),
        ),
    )
    .expect("the cluster environment file should write");
    record(
        &mut provoked,
        target.import(&[
            "import-standalone",
            "--from",
            &cluster_env.display().to_string(),
        ]),
        "standalone_config_is_not_standalone",
    );

    // A standalone deployment with no policy has nothing a cluster could
    // serve: cluster mode has no "no policy" state.
    let no_policy = scratch.path().join("no-policy.env");
    std::fs::write(
        &no_policy,
        format!(
            "CONNECTIONS_SQLITE_PATH={}\n",
            standalone.connections_file.display()
        ),
    )
    .expect("the policy-less environment file should write");
    record(
        &mut provoked,
        target.import(&[
            "import-standalone",
            "--from",
            &no_policy.display().to_string(),
        ]),
        "standalone_policy_file_missing",
    );

    // A configured SQLite file that is not one.
    let corrupt = scratch.path().join("corrupt.sqlite");
    std::fs::write(&corrupt, vec![0x7f_u8; 100]).expect("the corrupt database should write");
    let corrupt_env = scratch.path().join("corrupt.env");
    std::fs::write(
        &corrupt_env,
        format!(
            "POLICY_FILE={}\nCONNECTIONS_SQLITE_PATH={}\n",
            standalone.policy_file.display(),
            corrupt.display()
        ),
    )
    .expect("the corrupt environment file should write");
    let message = record(
        &mut provoked,
        target.import(&[
            "import-standalone",
            "--from",
            &corrupt_env.display().to_string(),
        ]),
        "source_sqlite_unreadable",
    );
    assert!(
        message.contains("CONNECTIONS_SQLITE_PATH"),
        "the refusal should name the setting that points at it: {message}"
    );

    // A document this binary cannot read is a document the cluster could
    // not have served.
    let unparseable = scratch.path().join("policy-truncated.json");
    std::fs::write(&unparseable, "{\"policy\":").expect("the truncated policy should write");
    let unparseable_env = scratch.path().join("unparseable.env");
    std::fs::write(
        &unparseable_env,
        format!("POLICY_FILE={}\n", unparseable.display()),
    )
    .expect("the unparseable environment file should write");
    let message = record(
        &mut provoked,
        target.import(&[
            "import-standalone",
            "--from",
            &unparseable_env.display().to_string(),
        ]),
        "source_document_unparseable",
    );
    assert!(
        message.contains("policy"),
        "the refusal should name the kind of document: {message}"
    );

    // The target half.
    record(
        &mut provoked,
        run_gateway(
            &[("STATE_BACKEND".to_owned(), "sqlite".to_owned())],
            &["import-standalone", "--from", &from],
        ),
        "target_not_postgres",
    );

    let closed_port = scratch.path().join("database-url-closed");
    std::fs::write(
        &closed_port,
        "postgres://greengateway_ci@127.0.0.1:1/greengateway_ci\n",
    )
    .expect("the closed-port DSN should write");
    let mut unreachable = target.environment(&target.migrator_dsn_file);
    set(
        &mut unreachable,
        "DATABASE_URL_FILE",
        &closed_port.display().to_string(),
    );
    set(&mut unreachable, "DATABASE_STARTUP_RETRY_LIMIT", "1");
    set(&mut unreachable, "DATABASE_CONNECT_TIMEOUT_MS", "1000");
    record(
        &mut provoked,
        run_gateway(&unreachable, &["import-standalone", "--from", &from]),
        "target_unavailable",
    );

    // A database nobody has migrated, and a database bound elsewhere.
    let Some(unmigrated) = Target::unmigrated("refusals-unmigrated").await else {
        return skipped();
    };
    let message = record(
        &mut provoked,
        unmigrated.import(&["import-standalone", "--from", &from]),
        "target_schema_not_current",
    );
    assert!(
        message.contains("migrate up"),
        "the refusal should name the command that fixes it: {message}"
    );

    let mut other_deployment = target.environment(&target.migrator_dsn_file);
    set(
        &mut other_deployment,
        "DEPLOYMENT_ID",
        "some-other-deployment",
    );
    let message = record(
        &mut provoked,
        run_gateway(&other_deployment, &["import-standalone", "--from", &from]),
        "target_deployment_mismatch",
    );
    assert!(
        message.contains(&target.deployment_id),
        "the refusal should name the deployment the database is BOUND to: {message}"
    );

    // Nothing above printed a credential — every refusal provoked in this
    // test, and a successful dry run alongside them so the check covers the
    // reporting path as well as the refusing one.
    provoked.push(target.import(&["import-standalone", "--from", &from]));
    assert!(
        provoked.len() >= 17,
        "the privacy check should see every invocation this test made, not a sample; \
         it saw {}",
        provoked.len()
    );
    let outputs: Vec<&Output> = provoked.iter().collect();
    assert_no_credentials(&outputs, &standalone, &target);
}

/// [`refusal`], keeping the invocation's output for the privacy check at
/// the foot of the refusal drill.
///
/// The privacy assertion is only worth what it is run over, and a refusal
/// asserted and dropped is a refusal it never sees.
fn record(provoked: &mut Vec<Output>, output: Output, code: &str) -> String {
    let message = refusal(&output, code);
    provoked.push(output);
    message
}

/// A line that is not a `KEY=VALUE` assignment, and that reads like the
/// credential material an environment file's lines may be — which is why
/// the refusal reports the line number and not the line.
const MALFORMED_LINE: &str = "FAKE_DRILL_BEARER_TOKEN_c41d";

/// Assert an invocation failed with `code`, and answer its message.
fn refusal(output: &Output, code: &str) -> String {
    assert!(
        !output.status.success(),
        "the import should have refused with {code}\n{}",
        combined(output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        stderr.contains(&format!("{code}: ")),
        "the refusal should carry the stable code {code}\n{}",
        combined(output)
    );
    stderr
}

/// Replace (or add) one setting in a prepared environment.
fn set(environment: &mut Vec<(String, String)>, key: &str, value: &str) {
    environment.retain(|(existing, _)| existing != key);
    environment.push((key.to_owned(), value.to_owned()));
}

// =====================================================================
// Phase 9 — privacy
// =====================================================================

/// Nothing the command prints is a credential.
///
/// Both streams of every invocation, and the report walked as a tree
/// rather than as text: a `password`, `secret`, `token` or `dsn` KEY at
/// any depth would be a field that could carry one tomorrow even if it
/// carries nothing today.
fn assert_no_credentials(outputs: &[&Output], standalone: &Standalone, target: &Target) {
    let mut forbidden = vec![
        FAKE_CONNECTION_SECRET.to_owned(),
        MALFORMED_LINE.to_owned(),
        "postgres://".to_owned(),
        target.database.runtime_dsn.clone(),
        target.database.migrator_dsn.clone(),
    ];
    // The keyring's own bytes, rendered the way a leak would render them.
    forbidden.push(
        std::fs::read(standalone.runtime.path().join("connection-key"))
            .map(hex::encode)
            .expect("the fixture keyring should read"),
    );
    for output in outputs {
        for stream in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(stream);
            for needle in &forbidden {
                assert!(
                    !text.contains(needle.as_str()),
                    "the import printed something it must never print"
                );
            }
        }
    }
}

/// Every `(key, value)` pair in a JSON tree, at any depth.
fn json_fields<'a>(value: &'a Value, into: &mut Vec<(String, &'a Value)>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                into.push((key.clone(), child));
                json_fields(child, into);
            }
        }
        Value::Array(values) => {
            for child in values {
                json_fields(child, into);
            }
        }
        _ => {}
    }
}

/// The report is counts, checksums, revisions and durations — and the
/// absence of a field is the only guarantee that survives a future change
/// to what fills it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_report_carries_a_field_a_credential_could_hide_in() {
    let Some(target) = Target::create("privacy").await else {
        return skipped();
    };
    let standalone = Standalone::build("privacy").await;
    let from = standalone.env_file.display().to_string();

    let rehearsal = target.import(&["import-standalone", "--from", &from]);
    let cutover = target.import(&["import-standalone", "--from", &from, "--apply"]);
    // The rule is about SHAPE, not about a list of blessed names, so it
    // keeps working as the report grows: a field whose name mentions
    // credential material may be a COUNT of such things
    // (`connection_local_secrets`, `credential_bindings`,
    // `service_tokens_inserted`) or a PATH the operator configured
    // (`service_token_file`, already all over the report) — but never a
    // free-form string, because a free-form string is where a value would
    // one day land.
    for output in [&rehearsal, &cutover] {
        let report = report(output);
        let mut fields = Vec::new();
        json_fields(&report, &mut fields);
        for (key, value) in &fields {
            let lowered = key.to_ascii_lowercase();
            let mentions_material = ["password", "secret", "token", "dsn", "credential"]
                .iter()
                .any(|needle| lowered.contains(needle));
            if !mentions_material || key.ends_with("_file") {
                continue;
            }
            assert!(
                value.is_number() || value.is_boolean(),
                "the report's {key} field is a {value}; a field that mentions credential \
                 material may be a count or a flag, never free-form text"
            );
        }
    }
    assert_no_credentials(&[&rehearsal, &cutover], &standalone, &target);
}

// =====================================================================
// The role the runbook says to run this as
// =====================================================================

/// A login role created for one test, holding exactly the privileges that
/// test is about, and dropped when the test ends — panic or not.
///
/// The harness's own runtime role is not usable for this: it is granted
/// `UPDATE` on the sequences (`Database::grant_runtime_privileges`) so the
/// suites that share it can seed, which is one privilege more than the
/// runtime role `docs/deployment/postgres.md:69` describes. The claim
/// under test is about that documented role, so the test creates it.
struct ImportRole {
    name: String,
    dsn_file: PathBuf,
    admin_dsn: String,
    migrator_dsn: String,
}

impl ImportRole {
    /// `sequence_update` is the whole difference between the documented
    /// RUNTIME role and the MIGRATION role, as far as this command is
    /// concerned: preserving a standalone deployment's policy version
    /// numbers means writing identity values and then realigning the
    /// sequence with `setval`, and `setval` needs `UPDATE` on it
    /// (`postgres_policy.rs::insert_imported_policy_versions_in`).
    async fn create(target: &Target, label: &str, sequence_update: bool) -> Self {
        let name = format!("ggw_drill_{}", uuid::Uuid::new_v4().simple());
        target
            .database
            .admin_batch(&format!("CREATE ROLE {name} LOGIN"))
            .await;
        let sequences = match sequence_update {
            true => "USAGE, SELECT, UPDATE",
            false => "USAGE, SELECT",
        };
        target
            .database
            .run_batch(&format!(
                "GRANT CONNECT ON DATABASE {database} TO {name}; \
                 GRANT USAGE ON SCHEMA greengateway TO {name}; \
                 GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA greengateway \
                   TO {name}; \
                 GRANT {sequences} ON ALL SEQUENCES IN SCHEMA greengateway TO {name};",
                database = target.database.name,
            ))
            .await;
        let dsn = with_user(&target.database.migrator_dsn, &name);
        let dsn_file = target.files.write_private(
            &format!("database-url-{label}"),
            format!("{dsn}\n").as_bytes(),
        );
        Self {
            name,
            dsn_file,
            admin_dsn: target.database.admin_dsn.clone(),
            migrator_dsn: target.database.migrator_dsn.clone(),
        }
    }
}

impl Drop for ImportRole {
    fn drop(&mut self) {
        // Privileges granted to a role are dependencies of it, so the
        // grants go first; a leaked role would outlive this run on a
        // server the whole suite shares.
        run_sql_blocking(
            &self.migrator_dsn,
            &format!("DROP OWNED BY {name}", name = self.name),
        );
        run_sql_blocking(
            &self.admin_dsn,
            &format!("DROP ROLE IF EXISTS {name}", name = self.name),
        );
    }
}

/// Rewrite the user of a DSN of the form `postgres://user@host:port/db`.
fn with_user(dsn: &str, user: &str) -> String {
    let scheme_end = dsn.find("://").expect("the DSN names a scheme") + 3;
    let rest = &dsn[scheme_end..];
    let authority = rest.find('@').expect("the DSN names its user explicitly");
    format!("{}{user}{}", &dsn[..scheme_end], &rest[authority..])
}

/// Run one statement batch on its own connection, from a context that
/// cannot await — a `Drop`, on a runtime that may already be shutting
/// down. Failures are reported, never swallowed: a reversal that did not
/// happen poisons whatever runs next.
fn run_sql_blocking(dsn: &str, sql: &str) {
    let dsn = dsn.to_owned();
    let sql = sql.to_owned();
    let _ = std::thread::spawn(move || {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        else {
            eprintln!("the drill could not build a runtime; {sql} did not run");
            return;
        };
        runtime.block_on(async move {
            let Ok((client, connection)) =
                tokio_postgres::connect(&dsn, tokio_postgres::NoTls).await
            else {
                eprintln!("the drill could not connect; {sql} did not run");
                return;
            };
            let pump = tokio::spawn(async move {
                let _ = connection.await;
            });
            if let Err(error) = client.batch_execute(&sql).await {
                eprintln!("the drill statement failed ({error}); {sql} did not run");
            }
            drop(client);
            pump.abort();
        });
    })
    .join();
}

/// The import is a cutover command run with the MIGRATION role's DSN, and
/// the documented runtime role cannot stand in for it.
///
/// The refusal is the interesting half. A least-privilege role gets
/// through preflight — it can read every table — and fails inside the
/// policy section's transaction, which means it fails having written
/// NOTHING: the namespace is as empty afterwards as it was before, so the
/// operator's next move is to re-run with the right DSN rather than to
/// clean up.
///
/// The code it fails with is `store_failure`, not `section_failed`, and
/// the message ends in `unavailable`. That is worth pinning rather than
/// smoothing over: `classify_postgres_error` maps SQLSTATE `42501`
/// (`insufficient_privilege`) to `RepositoryErrorKind::Unavailable`
/// (`storage/postgres.rs`), and the section propagates that through
/// `ImportError::Store` rather than wrapping it. So the operator who runs
/// the cutover with the wrong DSN is told the target is "not usable:
/// ... unavailable", which the runbook reads as a connectivity, TLS or
/// credentials problem. The privilege is the real answer, and it is only
/// in the operation name (`policy_history_import`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_import_needs_the_migration_role_not_a_runtime_one() {
    let Some(target) = Target::create("role").await else {
        return skipped();
    };
    let standalone = Standalone::build("role").await;
    let from = standalone.env_file.display().to_string();
    let runtime = ImportRole::create(&target, "runtime", false).await;

    let output = run_gateway(
        &target.environment(&runtime.dsn_file),
        &["import-standalone", "--from", &from, "--apply"],
    );
    let message = refusal(&output, "store_failure");
    assert!(
        message.contains("policy_history_import"),
        "the refusal should name the operation that failed: {message}"
    );
    assert!(
        !message.contains("setval") && !message.contains("SELECT"),
        "a classified failure carries no SQL text: {message}"
    );
    assert_eq!(
        target.occupancy().await,
        Vec::<String>::new(),
        "a section that failed inside its transaction wrote nothing"
    );

    // The same source, the same target, the migration role: it works.
    let applied = report(&target.import(&["import-standalone", "--from", &from, "--apply"]));
    assert_eq!(applied["mode"], "apply");
    assert_eq!(
        section(&applied, "policy")["counts"]["policy_history_versions"],
        standalone.facts.policy_history_versions
    );
}

// =====================================================================
// Phase 8 — an interrupted apply, and the resume that finishes it
// =====================================================================

/// A section failure leaves whole sections committed and nothing partial,
/// and `--apply --resume` finishes the job.
///
/// The interruption is a real one: the connections section's very first
/// insert is refused by the database. Each section is its own transaction,
/// so policy and tools stay committed and connections leaves nothing
/// behind — and the resumed run recognizes the two committed sections by
/// their natural keys, reports them `already-imported` with the SAME
/// checksums, and imports the rest. The final state is the state a clean
/// single-pass apply reaches, which is what the checksum comparison
/// against the rehearsal proves.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_interrupted_apply_resumes_to_the_state_a_clean_apply_reaches() {
    let Some(target) = Target::create("resume").await else {
        return skipped();
    };
    let standalone = Standalone::build("resume").await;
    let from = standalone.env_file.display().to_string();
    let importer = ImportRole::create(&target, "importer", true).await;
    let environment = target.environment(&importer.dsn_file);

    // The rehearsal first: its checksums are what the interrupted-then-
    // resumed run has to end up agreeing with.
    let rehearsal = report(&run_gateway(
        &environment,
        &["import-standalone", "--from", &from],
    ));

    target
        .database
        .run_batch(&format!(
            "REVOKE INSERT ON greengateway.connection_records FROM {}",
            importer.name
        ))
        .await;
    let interrupted = run_gateway(
        &environment,
        &["import-standalone", "--from", &from, "--apply"],
    );
    let message = refusal(&interrupted, "section_failed");
    assert!(
        message.contains("connections"),
        "the refusal should name the section that failed: {message}"
    );
    assert!(
        !message.contains("INSERT") && !message.contains("connection_records"),
        "a section failure carries no SQL text: {message}"
    );

    // Whole sections committed, nothing partial.
    assert_eq!(
        target
            .count("SELECT count(*)::bigint FROM greengateway.policy_documents")
            .await,
        standalone.facts.policy_history_versions + 1,
        "the policy section committed before the failure"
    );
    assert_eq!(
        target
            .count("SELECT count(*)::bigint FROM greengateway.tool_documents")
            .await,
        1,
        "the tools section committed before the failure"
    );
    assert_eq!(
        target
            .count("SELECT count(*)::bigint FROM greengateway.connection_records")
            .await,
        0,
        "the section that failed left nothing behind"
    );
    assert_eq!(
        target
            .count("SELECT count(*)::bigint FROM greengateway.audit_events")
            .await,
        0,
        "a section failure aborts the run: the sections after it never ran"
    );
    assert!(
        !target.occupancy().await.is_empty(),
        "the namespace is now non-empty, which is why the re-run needs --resume"
    );

    // Without `--resume`, the re-run is refused rather than merged.
    refusal(
        &run_gateway(
            &environment,
            &["import-standalone", "--from", &from, "--apply"],
        ),
        "target_namespace_not_empty",
    );

    target
        .database
        .run_batch(&format!(
            "GRANT INSERT ON greengateway.connection_records TO {}",
            importer.name
        ))
        .await;
    let resumed = report(&run_gateway(
        &environment,
        &["import-standalone", "--from", &from, "--apply", "--resume"],
    ));

    assert_eq!(resumed["mode"], "apply-resume");
    for name in ["policy", "tools"] {
        assert_eq!(
            section(&resumed, name)["status"],
            "already-imported",
            "a resumed section this import had already committed is recognized, not rewritten"
        );
    }
    for name in [
        "connections",
        "audit",
        "observations_and_discovery",
        "principals_and_service_tokens",
    ] {
        assert_eq!(
            section(&resumed, name)["status"],
            "imported",
            "the sections the interruption skipped are the ones the resume writes"
        );
    }
    for name in SECTIONS {
        assert_eq!(
            section(&resumed, name)["checksum"],
            section(&rehearsal, name)["checksum"],
            "the {name} section of a resumed import must digest to what a clean one would"
        );
    }
    assert_eq!(
        resumed["validation"]["status"], "verified",
        "a resumed import verifies itself like any other: {resumed}"
    );

    // And the target holds the source, once.
    assert_eq!(
        target
            .count("SELECT count(*)::bigint FROM greengateway.policy_documents")
            .await,
        standalone.facts.policy_history_versions + 1,
        "the resumed policy section wrote no second copy of the history"
    );
    assert_eq!(
        target
            .count("SELECT count(*)::bigint FROM greengateway.connection_records")
            .await,
        standalone.facts.connections
    );
    assert_eq!(
        target
            .count("SELECT count(*)::bigint FROM greengateway.audit_events")
            .await,
        standalone.facts.audit_events
    );
}
