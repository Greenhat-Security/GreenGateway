//! The multi-replica harness behind the #241 release-gate suites.
//!
//! What it stands up, per test: a disposable PostgreSQL database and a
//! disposable no-DDL runtime role; a migration run as a separate one-shot
//! command; **two real gateway processes** in cluster mode against that
//! database; a test load balancer in front of them; a fake OIDC issuer
//! with a JWKS endpoint; and a fake upstream.
//!
//! Four rules run through every line of it.
//!
//! **The replicas must agree on the static-configuration fingerprint.**
//! PR 13 refuses readiness to a replica whose fingerprint differs from any
//! live member's, so a harness that varied the wrong setting would produce
//! two processes that are healthy, correct, and permanently `503`. Only
//! settings `ha.rs::static_config_fingerprint` does not read may differ per
//! replica: the listen address, the DSN file path, the audit file, the pool
//! size, and — the one that earns its keep — the *values* of a route's
//! `add_request_headers`, which the fingerprint covers by header name only.
//! That is how each replica stamps `x-ha-replica: a` / `b` on what it
//! proxies while still agreeing with its sibling.
//!
//! **Never bind a port and hand the number to a child.** Replicas are
//! started with `LISTEN_ADDR=127.0.0.1:0` and asked afterwards what they
//! got; the in-process servers hold their own listener from bind to serve.
//! Nothing in this harness frees a port and hopes.
//!
//! **Never advance the wall clock.** Database time is the authority
//! ([`database::Database::epoch_seconds`], [`database::Database::wait_for_elapsed`]),
//! and every other wait is a bounded poll on an observable condition — a
//! `/readyz` status, a row count, a process exit — never a sleep sized to
//! guess how long something takes.
//!
//! **Everything is cleaned up on panic.** Processes, temporary
//! directories, the database and the role all tear down from `Drop`, which
//! runs while a failing test unwinds. The database's teardown is owned by a
//! value created *before* the first `CREATE`, so a panic part-way through
//! standing one up still removes what had been created.
//!
//! ## What the gate covers, and what it does not yet
//!
//! The #241 verification matrix names eight suite files, and all eight are
//! here — `security_two_replica.rs`, `events_discovery_leader.rs`,
//! `saturation.rs`, `secret_leak.rs`, `failure_matrix.rs`,
//! `import_drill.rs`, `rolling_upgrade.rs` and `performance.rs` — plus
//! `smoke.rs`, which is the harness's proof of itself. The individual
//! matrix rows that are *not* asserted are listed here rather than left to
//! be inferred from absence:
//!
//! * The mixed-version half of `rolling_upgrade.rs` — no released
//!   GreenGateway binary supports cluster mode (v1.0.1 has no `postgres`
//!   feature at all), so no pair of binaries can form one deployment.
//!   That suite substitutes the *states* a newer version produces, names
//!   each substitution, and carries a tripwire that fails the day a
//!   cluster-capable release is tagged.
//! * `performance.rs` is `#[ignore]`d by default and belongs to the
//!   nightly workflow, not to the merge gate; the exception is its
//!   documentation-coverage test, which needs no database and runs
//!   everywhere.
//! * The clock-skew row of `events_discovery_leader.rs` — the matrix asks
//!   for a replica whose *wall clock* is skewed "via a test hook". No such
//!   hook exists in the product, and adding one is a production change this
//!   test-only PR does not make. Recorded as an open row.
//! * The "during notification" projector-kill window — the matrix names
//!   three windows (between read and commit, after commit, during
//!   notification). The first two are asserted; the third has no
//!   counterpart on `main`, where the durable stream is polled on an idle
//!   cadence and woken by an in-process broadcast, with no `LISTEN`/`NOTIFY`
//!   anywhere in the binary. It becomes a real window only if one is
//!   introduced.

#![allow(dead_code)] // one shared harness, many suites: each uses a slice of it

pub mod balancer;
pub mod database;
pub mod oidc;
pub mod replica;
pub mod sse;
pub mod upstream;

use std::{net::SocketAddr, path::PathBuf, sync::OnceLock, time::Duration};

use axum::Router;

// The harness is one module used by many suites, each of which needs a
// different slice of it; a re-export no suite has reached for yet is not a
// mistake, in the same way an unused helper is not.
#[allow(unused_imports)]
pub use balancer::{Balancer, Dispatch, Target, PIN_HEADER};
#[allow(unused_imports)]
pub use database::{
    locator, AuditEventSeed, Database, MemberIdentity, SeedActor, HTTP_REQUEST_OBSERVED,
};
#[allow(unused_imports)]
pub use oidc::{ExchangeRecord, FakeOidcIssuer};
#[allow(unused_imports)]
pub use replica::{Replica, LISTEN_BUDGET, READY_BUDGET};
#[allow(unused_imports)]
pub use upstream::{Behaviour, FakeUpstream, RecordedRequest, REPLICA_HEADER};

/// Platform variables a spawned replica keeps out of an otherwise cleared
/// environment.
///
/// The environment is cleared so no ambient `DEPLOYMENT_ID`,
/// `AUTH_ENABLED`, or test locator can reach a replica the harness did not
/// configure. These are not configuration: a Windows process cannot
/// initialize its socket library without `SystemRoot`, and neither
/// platform can resolve a temporary directory without its own.
pub const INHERITED_ENVIRONMENT: &[&str] = &[
    "SystemRoot",
    "windir",
    "SystemDrive",
    "COMSPEC",
    "PATHEXT",
    "NUMBER_OF_PROCESSORS",
    "PATH",
    "HOME",
    "TEMP",
    "TMP",
    "TMPDIR",
    "LOCALAPPDATA",
    "APPDATA",
    "ProgramData",
    "USERPROFILE",
];

/// The shared client for probes and traffic.
///
/// Redirects are never followed: several of these suites are about what a
/// `302` from the OIDC start endpoint says, and a client that chased it
/// would turn the assertion into a round trip through the issuer.
pub fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .expect("the harness HTTP client should build")
    })
}

/// A running in-process server (upstream, issuer, balancer).
pub struct ServerHandle {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl ServerHandle {
    pub fn shutdown(&mut self) {
        if let Some(sender) = self.shutdown.take() {
            let _ = sender.send(());
        }
    }
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.shutdown();
        self.task.abort();
    }
}

/// Bind an ephemeral port and serve `router` on it.
///
/// The listener is created and handed straight to `axum::serve`; it is
/// never dropped in between, so no sibling test can take the port out from
/// under it.
pub async fn serve_on_ephemeral_port(router: Router) -> (SocketAddr, ServerHandle) {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("the harness server should bind a loopback port");
    let addr = listener
        .local_addr()
        .expect("the harness server address should be readable");
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = receiver.await;
            })
            .await;
    });
    (
        addr,
        ServerHandle {
            shutdown: Some(sender),
            task,
        },
    )
}

/// One request in flight to a named replica, plus enough of its identity
/// to say what failed.
pub struct PinnedRequest {
    builder: reqwest::RequestBuilder,
    description: String,
}

impl PinnedRequest {
    pub fn bearer(mut self, token: &str) -> Self {
        self.builder = self.builder.bearer_auth(token);
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.builder = self.builder.header(name, value);
        self
    }

    pub fn if_match(self, etag: &str) -> Self {
        self.header("if-match", etag)
    }

    pub fn json(mut self, body: &serde_json::Value) -> Self {
        self.builder = self.builder.json(body);
        self
    }

    /// The body a bodyless `POST` still has to carry.
    ///
    /// Several admin actions take no input at all (rotate a token, accept
    /// a suggestion), but the request-validation layer refuses a `POST`
    /// that does not declare `application/json` — a `415` that would
    /// otherwise look like the action failing.
    pub fn empty_json(self) -> Self {
        self.json(&serde_json::json!({}))
    }

    /// Send, and answer `(status, body)` with the body decoded as JSON
    /// where it is JSON and `Null` where it is not.
    pub async fn send(self) -> (u16, serde_json::Value) {
        let (status, _, body) = self.send_with_headers().await;
        (status, body)
    }

    /// Send, and answer the status, the response headers, and the decoded
    /// body — for the assertions that are about an `ETag` or a `Location`.
    pub async fn send_with_headers(self) -> (u16, reqwest::header::HeaderMap, serde_json::Value) {
        let Self {
            builder,
            description,
        } = self;
        let response = builder
            .send()
            .await
            .unwrap_or_else(|error| panic!("the balancer did not answer {description}: {error}"));
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let bytes = response.bytes().await.unwrap_or_default();
        (
            status,
            headers,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }
}

/// A directory removed when the test finishes, panic or not.
pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "greengateway-ha-{label}-{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&path).expect("the harness temporary directory should create");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("the harness temporary directory permissions should set");
        }
        Self { path }
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Write a file the gateway will read as secret material: owner-only
    /// on unix, which is what the DSN and keyring readers require.
    pub fn write_private(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.path.join(name);
        std::fs::write(&path, contents).expect("the harness secret file should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("the harness secret file permissions should set");
        }
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The gateway binary under test.
pub fn gateway_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_gateway"))
}

/// How the replicas authenticate callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthShape {
    /// No authentication: the shape the traffic-only suites want.
    Disabled,
    /// One JWT provider pointed at the harness's fake issuer and its JWKS
    /// endpoint, plus the admin OIDC login flow over the cluster's shared
    /// pending-login store.
    Oidc,
}

/// How the replicas reach the fake upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyShape {
    /// `UPSTREAM_ROUTES` with a `/echo` route whose injected
    /// `x-ha-replica` value names the replica. The default, because it is
    /// the only way the upstream can say which replica proxied a request.
    Routes,
    /// `UPSTREAM_URL`: the legacy catch-all upstream, which
    /// `UPSTREAM_ROUTES` is mutually exclusive with and which legacy HTTP
    /// tool definitions require. A suite that executes tools needs this;
    /// it identifies replicas by pinning the balancer instead.
    LegacyUpstream,
}

pub struct ClusterOptions {
    pub replicas: usize,
    pub auth: AuthShape,
    pub proxy: ProxyShape,
    /// Extra environment applied to *every* replica. Anything the
    /// fingerprint reads must go here, never per replica.
    pub shared_env: Vec<(String, String)>,
    /// `DATABASE_POOL_MAX` per replica. Deliberately small: this database
    /// server is shared with the rest of the suite and, in development,
    /// with other builds.
    pub pool_max: u32,
    /// `DATABASE_STATEMENT_TIMEOUT_MS`. The lever the statement-timeout
    /// row actually has, because the gateway sets the timeout as a
    /// connection startup parameter that outranks any role default.
    pub statement_timeout_ms: Option<u64>,
    pub heartbeat_ms: u64,
    pub member_stale_ms: u64,
    /// The policy document the deployment starts from. `None` seeds
    /// [`database::SEED_POLICY_DOCUMENT`], which initializes the
    /// deployment and enforces nothing.
    pub seed_policy: Option<String>,
    /// The tools document the deployment starts from, seeded only when
    /// given: the tools control plane is optional at startup, and a
    /// suite that never writes or executes a tool wants no document.
    pub seed_tools: Option<String>,
    /// The providers' `jwks_max_key_age_secs`, which is also what sets the
    /// scheduled refresh interval (half the age, floored at ten seconds).
    /// The key-removal row shrinks this so the window it waits on is the
    /// configured one rather than five minutes.
    pub jwks_max_key_age_secs: u64,
    /// Start a SECOND fake issuer and configure a second JWT provider
    /// against it: what "an equal `jti` from two issuers" needs, because
    /// two issuers means two issuer URLs and so two servers.
    pub secondary_issuer: bool,
    /// Give the runtime role a password, so the DSN the replicas read
    /// actually carries a credential. Only the secret-leak suite wants
    /// this: elsewhere a passwordless loopback DSN is one less thing to
    /// go wrong.
    pub database_password: Option<String>,
    /// Attach the replicas to a database the caller created, migrated and
    /// populated itself, instead of creating and seeding one.
    ///
    /// The import drill's target. `import-standalone` refuses a namespace
    /// that already holds authoritative state, so a deployment the harness
    /// had seeded a policy document into could never *be* an import
    /// target; and the state the drill's replicas have to serve is the
    /// state the import wrote, not the state a seed would have written.
    /// With this set the harness creates no database, runs no migration
    /// and seeds nothing — it grants the runtime role its privileges (the
    /// caller's migration created the tables) and reads
    /// [`Cluster::seed_policy_etag`] back out of the database.
    pub adopt_database: Option<Database>,
    /// The `DEPLOYMENT_ID` the replicas run with, when the caller needs it
    /// to be a particular one. Required with [`Self::adopt_database`]: the
    /// database is already bound to the id the import claimed it for, and
    /// a replica carrying any other id is refused at boot.
    pub deployment_id: Option<String>,
    /// Give the `/echo` route an active health check marked
    /// `required_for_readiness`, so the upstream's health is a rung of the
    /// readiness chain.
    ///
    /// Off by default, and deliberately: with it on, every replica polls
    /// the fake upstream on a timer, a suite that stops the upstream loses
    /// readiness as a side effect, and the recorded-request log carries
    /// probe traffic no other suite wants to filter. On, it is the only way
    /// to reach `readiness_blocked_reason`'s **last** arm — the proxy rung
    /// that answers `required_upstream_unavailable` — from an integration
    /// test, because nothing else in the chain can produce that word.
    /// `ProxyShape::LegacyUpstream` ignores it: `UPSTREAM_URL` carries no
    /// health-check configuration.
    ///
    /// The block is identical on every replica, so the static-configuration
    /// fingerprint still agrees.
    pub upstream_required_for_readiness: bool,
}

impl Default for ClusterOptions {
    fn default() -> Self {
        Self {
            replicas: 2,
            auth: AuthShape::Disabled,
            proxy: ProxyShape::Routes,
            shared_env: Vec::new(),
            pool_max: 4,
            statement_timeout_ms: None,
            heartbeat_ms: 1_000,
            member_stale_ms: 10_000,
            seed_policy: None,
            seed_tools: None,
            jwks_max_key_age_secs: 300,
            secondary_issuer: false,
            database_password: None,
            adopt_database: None,
            deployment_id: None,
            upstream_required_for_readiness: false,
        }
    }
}

/// Two (or more) real gateway processes, a balancer, an issuer, an
/// upstream, and the database they all share.
pub struct Cluster {
    pub deployment_id: String,
    pub database: Database,
    pub upstream: FakeUpstream,
    pub oidc: FakeOidcIssuer,
    /// The second issuer, when [`ClusterOptions::secondary_issuer`] asked
    /// for one.
    pub oidc_secondary: Option<FakeOidcIssuer>,
    pub balancer: Balancer,
    pub replicas: Vec<Replica>,
    /// The ETag of the document the harness seeded — the precondition a
    /// suite's first `If-Match` policy write must carry.
    pub seed_policy_etag: String,
    /// The seeded tools document's ETag, when one was seeded.
    pub seed_tools_etag: Option<String>,
    /// `CLUSTER_MEMBER_STALE_MS` the replicas run with — the window a
    /// roster read decides liveness in.
    pub member_stale_ms: u64,
    /// The environment a one-shot command (`revoke-jwt`) runs with: the
    /// shared settings plus the runtime DSN, so it reaches this cluster's
    /// deployment and no other.
    one_shot_env: Vec<(String, String)>,
    /// The settings every replica shares, kept so [`Cluster::add_replica`]
    /// can build a new member's environment from the same fingerprint
    /// inputs the existing ones agreed on.
    shared: Vec<(String, String)>,
    /// The DSN file the replicas read, for the same reason.
    runtime_dsn_file: PathBuf,
    /// The options this cluster was started with, minus the adopted
    /// database (which was moved into [`Self::database`]).
    options: ClusterOptions,
    secrets: TempDir,
    files: TempDir,
    binary: PathBuf,
}

impl Cluster {
    /// Stand the cluster up, or answer `None` when there is no database to
    /// stand it up against.
    ///
    /// `None` is the skip path every PostgreSQL-backed suite in this
    /// repository takes without the `GATEWAY_TEST_POSTGRES_URL_FILE`
    /// locator; CI sets it, a bare checkout does not.
    pub async fn start(mut options: ClusterOptions) -> Option<Self> {
        let admin_dsn = locator()?;
        assert!(
            options.replicas >= 1,
            "a cluster needs at least one replica"
        );

        let binary = gateway_binary();
        // An adopted database is already bound to a deployment; a fresh
        // one is named per run so two clusters on one server never share
        // a namespace.
        let adopted = options.adopt_database.take();
        assert!(
            adopted.is_none() || options.deployment_id.is_some(),
            "an adopted database is bound to a deployment already; name it with \
             ClusterOptions::deployment_id"
        );
        let deployment_id = options
            .deployment_id
            .clone()
            .unwrap_or_else(|| format!("ha-{}", uuid::Uuid::new_v4().simple()));

        // The balancer first: its address is the deployment's public URL,
        // which both replicas' fingerprints cover, so it must exist before
        // either environment is built.
        let balancer = Balancer::start().await;
        let upstream = FakeUpstream::start().await;
        let oidc = FakeOidcIssuer::start().await;
        let oidc_secondary = match options.secondary_issuer {
            true => Some(FakeOidcIssuer::start().await),
            false => None,
        };

        // Whether this harness must migrate and seed is decided here, by
        // whether it is the thing that created the database.
        let harness_created_the_database = adopted.is_none();
        let database = match adopted {
            Some(database) => database,
            None => {
                Database::create_with_password(&admin_dsn, options.database_password.as_deref())
                    .await
            }
        };

        let secrets = TempDir::new("secrets");
        // Exactly 32 bytes, which the local-secret keyring reader
        // requires. Derived from a per-run UUID rather than written as a
        // literal: nothing in this repository's history should look like a
        // key.
        secrets.write_private("rate-limit-key", &random_key_material());
        secrets.write_private("admin-login-key", &random_key_material());

        let files = TempDir::new("files");
        let migrator_dsn_file = files.write_private(
            "database-url-migrator",
            format!("{}\n", database.migrator_dsn).as_bytes(),
        );
        let runtime_dsn_file = files.write_private(
            "database-url",
            format!("{}\n", database.runtime_dsn).as_bytes(),
        );

        let shared = shared_environment(
            &deployment_id,
            &secrets,
            &balancer,
            &oidc,
            oidc_secondary.as_ref(),
            &options,
        );

        let (policy_etag, seed_tools_etag) = if harness_created_the_database {
            // The schema is applied by a one-shot command as the migration
            // role, exactly as `docs/deployment/postgres.md` prescribes;
            // serving replicas validate only and never migrate.
            run_migrate_up(&binary, &shared, &migrator_dsn_file);
            // Cluster mode refuses to serve an uninitialized deployment, so
            // the policy control plane gets its first active document
            // before any replica boots.
            let policy_document = options
                .seed_policy
                .clone()
                .unwrap_or_else(|| database::SEED_POLICY_DOCUMENT.to_owned());
            let policy_etag = database.seed_policy_document(&policy_document).await;
            let seed_tools_etag = match options.seed_tools.as_deref() {
                Some(document) => Some(database.seed_tools_document(document).await),
                None => None,
            };
            (policy_etag, seed_tools_etag)
        } else {
            // An adopted database was migrated and initialized by whoever
            // created it (the import drill's `import-standalone --apply`).
            // The document the deployment serves is therefore a fact to be
            // read, not one the harness knows.
            assert!(
                options.seed_policy.is_none() && options.seed_tools.is_none(),
                "an adopted database carries its own documents; seeding one over them would \
                 be writing to a namespace the caller populated deliberately"
            );
            (database.active_policy_etag().await, None)
        };
        // Either way the runtime role needs its grants: the tables exist
        // only after a migration, whoever ran it.
        database.grant_runtime_privileges().await;

        let mut one_shot_env = shared.clone();
        one_shot_env.push((
            "DATABASE_URL_FILE".to_owned(),
            runtime_dsn_file.display().to_string(),
        ));

        let mut replicas = Vec::with_capacity(options.replicas);
        for index in 0..options.replicas {
            let name = replica_name(index);
            let audit_path = files.path().join(format!("audit-{name}.jsonl"));
            let env = replica_environment(
                &shared,
                &name,
                &runtime_dsn_file,
                &audit_path,
                &upstream,
                &options,
            );
            let mut replica = Replica::spawn(&name, &binary, env, audit_path);
            replica.wait_until_listening(LISTEN_BUDGET).await;
            replicas.push(replica);
        }

        balancer.set_targets(
            replicas
                .iter()
                .map(|replica| Target {
                    name: replica.name.clone(),
                    base_url: replica.base_url(),
                })
                .collect(),
        );

        Some(Self {
            deployment_id,
            database,
            upstream,
            oidc,
            oidc_secondary,
            balancer,
            replicas,
            seed_policy_etag: policy_etag,
            seed_tools_etag,
            member_stale_ms: options.member_stale_ms,
            one_shot_env,
            shared,
            runtime_dsn_file,
            options,
            secrets,
            files,
            binary,
        })
    }

    /// Start one more replica against the same deployment, with the same
    /// shared configuration, and put it in the balancer's rotation.
    ///
    /// Scale-out. The new member gets the next letter, the same
    /// fingerprint inputs as its siblings (anything else would be refused
    /// readiness by PR 13's gate), its own ephemeral port and its own
    /// audit file. It is not waited for here beyond binding a listener:
    /// whether a replica joining an already-serving deployment reaches
    /// `ready` — and how fast — is the caller's assertion, not the
    /// harness's precondition.
    pub async fn add_replica(&mut self) -> String {
        let name = replica_name(self.replicas.len());
        let audit_path = self.files.path().join(format!("audit-{name}.jsonl"));
        let env = replica_environment(
            &self.shared,
            &name,
            &self.runtime_dsn_file,
            &audit_path,
            &self.upstream,
            &self.options,
        );
        let mut replica = Replica::spawn(&name, &self.binary, env, audit_path);
        replica.wait_until_listening(LISTEN_BUDGET).await;
        self.replicas.push(replica);
        self.refresh_balancer_targets();
        name
    }

    /// Run a one-shot gateway command (`revoke-jwt`, `migrate check`)
    /// against this cluster's deployment, and return its output.
    ///
    /// The environment is the replicas' shared settings plus the runtime
    /// DSN — never the ambient one — so the command reaches this
    /// disposable database and no other.
    pub fn run_command(&self, arguments: &[&str]) -> std::process::Output {
        let mut command = std::process::Command::new(&self.binary);
        command.env_clear();
        for key in INHERITED_ENVIRONMENT {
            if let Ok(value) = std::env::var(key) {
                command.env(key, value);
            }
        }
        for (key, value) in &self.one_shot_env {
            command.env(key, value);
        }
        command
            .args(arguments)
            .output()
            .unwrap_or_else(|error| panic!("the gateway command {arguments:?} should run: {error}"))
    }

    /// The second issuer, or a panic naming what the test forgot to ask
    /// for.
    pub fn secondary_issuer(&self) -> &FakeOidcIssuer {
        self.oidc_secondary
            .as_ref()
            .expect("this cluster was not built with ClusterOptions::secondary_issuer")
    }

    /// Wait until every replica answers `/readyz` with `200`.
    pub async fn wait_until_all_ready(&mut self) {
        for replica in &mut self.replicas {
            replica.wait_until_ready(READY_BUDGET).await;
        }
    }

    pub fn replica(&self, name: &str) -> &Replica {
        self.replicas
            .iter()
            .find(|replica| replica.name == name)
            .unwrap_or_else(|| panic!("this cluster has no replica {name}"))
    }

    pub fn replica_mut(&mut self, name: &str) -> &mut Replica {
        self.replicas
            .iter_mut()
            .find(|replica| replica.name == name)
            .unwrap_or_else(|| panic!("this cluster has no replica {name}"))
    }

    /// Restart a replica and point the balancer at its new port.
    pub async fn restart(&mut self, name: &str) {
        self.replica_mut(name).restart().await;
        self.refresh_balancer_targets();
    }

    /// Kill a replica and take it out of the balancer's rotation.
    pub fn kill(&mut self, name: &str) {
        self.replica_mut(name).kill();
        self.refresh_balancer_targets();
    }

    fn refresh_balancer_targets(&self) {
        self.balancer.set_targets(
            self.replicas
                .iter()
                .filter(|replica| replica.addr_if_bound().is_some())
                .map(|replica| Target {
                    name: replica.name.clone(),
                    base_url: replica.base_url(),
                })
                .collect(),
        );
    }

    /// A request through the balancer, with the harness's shared client.
    pub async fn get_through_balancer(&self, path: &str) -> reqwest::Response {
        http_client()
            .get(format!("{}{path}", self.balancer.base_url))
            .send()
            .await
            .unwrap_or_else(|error| panic!("the balancer did not answer GET {path}: {error}"))
    }

    /// A request through the balancer pinned to one replica.
    pub async fn get_pinned(&self, name: &str, path: &str) -> reqwest::Response {
        http_client()
            .get(format!("{}{path}", self.balancer.base_url))
            .header(PIN_HEADER, name)
            .send()
            .await
            .unwrap_or_else(|error| {
                panic!("the balancer did not answer GET {path} pinned to {name}: {error}")
            })
    }

    /// A request aimed at one named replica through the balancer, with a
    /// bearer credential and any extra headers.
    ///
    /// Every admin assertion in these suites is about *which replica*
    /// answered, so there is no unpinned variant: a test that did not say
    /// would be asserting about the round-robin cursor.
    pub fn request(&self, method: reqwest::Method, replica: &str, path: &str) -> PinnedRequest {
        PinnedRequest {
            builder: http_client()
                .request(method, format!("{}{path}", self.balancer.base_url))
                .header(PIN_HEADER, replica),
            description: format!("{path} pinned to {replica}"),
        }
    }

    pub fn get(&self, replica: &str, path: &str) -> PinnedRequest {
        self.request(reqwest::Method::GET, replica, path)
    }

    pub fn post(&self, replica: &str, path: &str) -> PinnedRequest {
        self.request(reqwest::Method::POST, replica, path)
    }

    pub fn put(&self, replica: &str, path: &str) -> PinnedRequest {
        self.request(reqwest::Method::PUT, replica, path)
    }

    pub fn delete(&self, replica: &str, path: &str) -> PinnedRequest {
        self.request(reqwest::Method::DELETE, replica, path)
    }

    /// The identities of the live members, in replica order (`a` first).
    ///
    /// See [`database::Database::member_identities`] for why the order is
    /// the replica order.
    pub async fn member_identities(&self) -> Vec<database::MemberIdentity> {
        self.database.member_identities().await
    }

    /// Everything every replica has written to stdout and stderr.
    ///
    /// The secret-leak suite's haystack: structured logs, panic messages,
    /// and anything a library printed on its way past the tracing layer.
    pub fn captured_output(&self) -> String {
        self.replicas
            .iter()
            .map(|replica| {
                format!(
                    "--- replica {} stdout/stderr ---\n{}\n",
                    replica.name,
                    replica.captured_output()
                )
            })
            .collect()
    }

    /// A replica's Prometheus exposition, scraped from its own listener.
    pub async fn metrics(&self, replica: &str) -> String {
        let response = http_client()
            .get(format!("{}/metrics", self.replica(replica).base_url()))
            .send()
            .await
            .unwrap_or_else(|error| panic!("replica {replica} did not answer /metrics: {error}"));
        assert_eq!(
            response.status().as_u16(),
            200,
            "the metrics endpoint should be scrapable without a credential"
        );
        response.text().await.unwrap_or_default()
    }

    /// Every replica's value of the Prometheus sample `name`, added up
    /// across all label sets: the deployment's total.
    pub async fn metric_total(&self, name: &str) -> f64 {
        let mut total = 0.0;
        for replica in &self.replicas {
            total += metric_sum(&self.metrics(&replica.name).await, name);
        }
        total
    }

    /// Every audit record every replica has written to its own file sink.
    pub fn audit_records(&self) -> Vec<serde_json::Value> {
        self.replicas
            .iter()
            .flat_map(|replica| replica.audit_events())
            .collect()
    }

    /// Stop a replica cleanly and take it out of the balancer's rotation.
    pub fn stop(&mut self, name: &str) {
        self.replica_mut(name).stop();
        self.refresh_balancer_targets();
    }

    /// The cluster's live membership rows, as the deployment sees them:
    /// not draining, and heartbeating inside the stale window.
    ///
    /// Liveness is decided on *database* time (`now()` against the row's
    /// `last_heartbeat_at`), never on the test process's clock — the same
    /// rule the gateway's own roster read follows.
    pub async fn live_member_count(&self) -> i64 {
        let seconds = self.member_stale_ms as f64 / 1000.0;
        self.database
            .count(&format!(
                "SELECT count(*)::bigint FROM greengateway.cluster_members \
                 WHERE draining_at IS NULL \
                   AND last_heartbeat_at > now() - make_interval(secs => {seconds})"
            ))
            .await
    }

    /// Poll until the deployment has no live member left.
    ///
    /// A replica that stopped cleanly stamps its row draining and leaves at
    /// once (on every platform: `Replica::stop` is `SIGTERM` on unix and
    /// `Ctrl+Break` on Windows); one that was killed leaves a row that
    /// simply stops being refreshed and ages out of the stale window. Both
    /// are "gone" as far as the roster is concerned, and this waits for
    /// either without caring which happened — a row that cares asserts
    /// the `draining_at` stamp itself, as the smoke suite's teardown does.
    pub async fn wait_until_no_live_members(&self, budget: Duration) {
        let deadline = std::time::Instant::now() + budget;
        loop {
            let live = self.live_member_count().await;
            if live == 0 {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{live} membership row(s) were still live {budget:?} after shutdown"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    /// Shut every replica down cleanly, then drop the rest. Explicit so a
    /// test can assert on what teardown left behind; `Drop` does the same
    /// thing for a test that panics first.
    pub fn shutdown(&mut self) {
        for replica in &mut self.replicas {
            replica.stop();
        }
    }

    /// The gateway binary these replicas run, for a suite that needs to
    /// invoke a one-shot command (`migrate check`, `revoke-jwt`) against
    /// the same deployment.
    pub fn binary(&self) -> &std::path::Path {
        &self.binary
    }

    /// The temporary directories this cluster owns: the secrets root and
    /// the DSN/audit files. Exposed so the harness's own teardown test can
    /// assert they are gone.
    pub fn temporary_paths(&self) -> (PathBuf, PathBuf) {
        (self.secrets.path().to_owned(), self.files.path().to_owned())
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        // Order matters and cannot be left to field declaration order: a
        // replica still holding its pool would race `DROP DATABASE`,
        // reconnecting between the terminate and the drop. Kill the
        // processes first, then let the database, the servers and the
        // temporary directories drop in turn.
        for replica in &mut self.replicas {
            replica.kill();
        }
    }
}

fn replica_name(index: usize) -> String {
    // a, b, c, ... — short enough to be a header value and a pin.
    let letter = char::from(b'a' + u8::try_from(index % 26).unwrap_or(0));
    letter.to_string()
}

/// 32 bytes of key material from a per-run source.
///
/// Never a literal: a checked-in 32-byte constant would look exactly like
/// a leaked key to a history scanner, and this repository's scanner reads
/// history.
fn random_key_material() -> Vec<u8> {
    let mut material = Vec::with_capacity(32);
    material.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    material.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
    material
}

/// The settings every replica must share, because the fingerprint reads
/// them. A change here changes both replicas or neither.
fn shared_environment(
    deployment_id: &str,
    secrets: &TempDir,
    balancer: &Balancer,
    oidc: &FakeOidcIssuer,
    oidc_secondary: Option<&FakeOidcIssuer>,
    options: &ClusterOptions,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("STATE_BACKEND".to_owned(), "postgres".to_owned()),
        ("DEPLOYMENT_ID".to_owned(), deployment_id.to_owned()),
        ("DATABASE_TLS_MODE".to_owned(), "loopback-dev".to_owned()),
        (
            "CONNECTION_SECRETS_ROOT".to_owned(),
            secrets.path().display().to_string(),
        ),
        (
            "RATE_LIMIT_KEYRING".to_owned(),
            r#"[{"id":"ha-rate-limit","file":"rate-limit-key","role":"primary"}]"#.to_owned(),
        ),
        ("GATEWAY_PUBLIC_URL".to_owned(), balancer.base_url.clone()),
        ("CSRF_ENABLED".to_owned(), "false".to_owned()),
        ("EGRESS_ALLOWED_HOSTS".to_owned(), "127.0.0.1".to_owned()),
        ("EGRESS_DENY_PRIVATE_IPS".to_owned(), "false".to_owned()),
    ];
    match options.auth {
        AuthShape::Disabled => {
            env.push(("AUTH_ENABLED".to_owned(), "false".to_owned()));
        }
        AuthShape::Oidc => {
            env.push(("AUTH_ENABLED".to_owned(), "true".to_owned()));
            // `require_jti` because the shared denylist names a token by
            // its `jti`: a provider that accepted tokens without one would
            // accept tokens no revocation could ever name.
            let mut providers = vec![serde_json::json!({
                "name": oidc::PRIMARY_PROVIDER,
                "type": "jwt",
                "issuer": oidc.issuer,
                "jwks_url": oidc.jwks_url,
                "audience": oidc::AUDIENCE,
                "client_id": oidc::CLIENT_ID,
                "client_secret": oidc::FAKE_CLIENT_SECRET,
                "redirect_uri": admin_callback_url(balancer),
                "require_jti": true,
                "jwks_max_key_age_secs": options.jwks_max_key_age_secs,
            })];
            if let Some(secondary) = oidc_secondary {
                providers.push(serde_json::json!({
                    "name": oidc::SECONDARY_PROVIDER,
                    "type": "jwt",
                    "issuer": secondary.issuer,
                    "jwks_url": secondary.jwks_url,
                    "audience": oidc::AUDIENCE,
                    "require_jti": true,
                    "jwks_max_key_age_secs": options.jwks_max_key_age_secs,
                }));
            }
            env.push((
                "AUTH_PROVIDERS".to_owned(),
                serde_json::Value::Array(providers).to_string(),
            ));
            // The admin login flow, over the cluster's shared pending-login
            // store: its envelopes are sealed with this keyring, so a
            // callback can be opened by whichever replica it lands on.
            env.push((
                "ADMIN_LOGIN_PROVIDER".to_owned(),
                oidc::PRIMARY_PROVIDER.to_owned(),
            ));
            env.push((
                "ADMIN_LOGIN_KEYRING".to_owned(),
                r#"[{"id":"ha-admin-login","file":"admin-login-key","role":"primary"}]"#.to_owned(),
            ));
        }
    }
    for (key, value) in &options.shared_env {
        env.retain(|(existing, _)| existing != key);
        env.push((key.clone(), value.clone()));
    }
    env
}

/// One replica's environment: the shared settings, plus the ones the
/// fingerprint does not read.
fn replica_environment(
    shared: &[(String, String)],
    name: &str,
    dsn_file: &std::path::Path,
    audit_path: &std::path::Path,
    upstream: &FakeUpstream,
    options: &ClusterOptions,
) -> Vec<(String, String)> {
    let mut env: Vec<(String, String)> = shared.to_vec();
    env.push(("LISTEN_ADDR".to_owned(), "127.0.0.1:0".to_owned()));
    env.push((
        "DATABASE_URL_FILE".to_owned(),
        dsn_file.display().to_string(),
    ));
    env.push((
        "AUDIT_LOG_FILE".to_owned(),
        audit_path.display().to_string(),
    ));
    env.push(("DATABASE_POOL_MAX".to_owned(), options.pool_max.to_string()));
    if let Some(milliseconds) = options.statement_timeout_ms {
        env.push((
            "DATABASE_STATEMENT_TIMEOUT_MS".to_owned(),
            milliseconds.to_string(),
        ));
    }
    env.push((
        "CLUSTER_HEARTBEAT_MS".to_owned(),
        options.heartbeat_ms.to_string(),
    ));
    env.push((
        "CLUSTER_MEMBER_STALE_MS".to_owned(),
        options.member_stale_ms.to_string(),
    ));
    env.push(("SHUTDOWN_DRAIN_DELAY_MS".to_owned(), "0".to_owned()));
    env.push(("SHUTDOWN_TIMEOUT_MS".to_owned(), "5000".to_owned()));
    env.push(("AUDIT_DRAIN_TIMEOUT_MS".to_owned(), "5000".to_owned()));
    match options.proxy {
        // The route that identifies the replica. `path_prefix` and
        // `upstream_url` are identical on every replica (the fingerprint
        // reads both); only the injected header's VALUE differs, which the
        // fingerprint deliberately does not read.
        ProxyShape::Routes => {
            let mut route = serde_json::json!({
                "path_prefix": "/echo",
                "upstream_url": upstream.base_url,
                "add_request_headers": { REPLICA_HEADER: name },
            });
            if options.upstream_required_for_readiness {
                // Thresholds of one and a sub-second interval: the row that
                // wants this is waiting for a readiness TRANSITION, and a
                // default three-strike streak on a ten-second timer would
                // make the row's budget a measure of the health checker's
                // cadence rather than of the chain's last arm. Identical on
                // every replica, so the fingerprint still agrees.
                route["health_check"] = serde_json::json!({
                    "method": "GET",
                    "path": "/",
                    // `timeout_ms` may not exceed `interval_ms` (the
                    // validator says so), so both are set together.
                    "interval_ms": 500,
                    "timeout_ms": 400,
                    "healthy_threshold": 1,
                    "unhealthy_threshold": 1,
                    "expected_statuses": [200],
                    "required_for_readiness": true,
                    "minimum_healthy": 1,
                });
            }
            env.push((
                "UPSTREAM_ROUTES".to_owned(),
                serde_json::json!([route]).to_string(),
            ))
        }
        // `UPSTREAM_URL` and `UPSTREAM_ROUTES` are mutually exclusive, and
        // a legacy HTTP tool definition needs the former. Identical on
        // both replicas, so nothing here tells them apart — a suite on
        // this shape identifies replicas by pinning the balancer.
        ProxyShape::LegacyUpstream => {
            env.push(("UPSTREAM_URL".to_owned(), upstream.base_url.clone()))
        }
    }
    env
}

/// The sum of every Prometheus sample whose name is `name`, across all
/// label sets.
///
/// Written against the exposition rather than against a particular label
/// set on purpose: `audit_events_dropped_total` is emitted with a `reason`
/// label whose values are the drop causes, and a test that named one
/// reason would miss a drop for another. Here rather than in one suite
/// because the audit accounting is read by two of them (saturation, and
/// the smoke leg's request-path audit row).
pub fn metric_sum(exposition: &str, name: &str) -> f64 {
    exposition
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| {
            let rest = line.strip_prefix(name)?;
            // Either `name value` or `name{labels} value`, and either of
            // those with the exposition's `_total` suffix already on it —
            // anything else is a different metric that merely starts with
            // these bytes.
            let rest = rest.strip_prefix("_total").unwrap_or(rest);
            if !(rest.starts_with(' ') || rest.starts_with('{')) {
                return None;
            }
            rest.rsplit_once(char::is_whitespace)
                .and_then(|(_, value)| value.parse::<f64>().ok())
        })
        .sum()
}

/// The admin OIDC callback the deployment publishes, which is also the
/// `redirect_uri` its provider is configured with: the balancer's address,
/// because that is the deployment's public URL and the callback may land
/// on either replica.
pub fn admin_callback_url(balancer: &Balancer) -> String {
    format!("{}{ADMIN_CALLBACK_PATH}", balancer.base_url)
}

/// The default admin API prefix these suites drive.
pub const ADMIN_API_PREFIX: &str = "/v1/admin";
pub const ADMIN_LOGIN_PATH: &str = "/v1/admin/auth/login";
pub const ADMIN_CALLBACK_PATH: &str = "/v1/admin/auth/callback";

/// Preserve the browser's login binding across pinned replica requests.
pub fn admin_login_cookies(headers: &reqwest::header::HeaderMap) -> String {
    headers
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .expect("cookie header")
                .split(';')
                .next()
                .expect("cookie pair")
        })
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn admin_login_completion(
    cluster: &Cluster,
    replica: &str,
    callback: &str,
    cookies: &str,
) -> PinnedRequest {
    let url = url::Url::parse(&format!("{}{}", cluster.balancer.base_url, callback))
        .expect("callback URL");
    let query: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
    cluster
        .post(replica, ADMIN_CALLBACK_PATH)
        .header("cookie", cookies)
        .header("origin", &cluster.balancer.base_url)
        .json(&serde_json::json!({"code": query["code"], "state": query["state"]}))
}

/// Apply the schema with the one-shot migration command, as the migration
/// role. Panics with the command's own output when it fails: a harness
/// that swallowed this would report every later failure as "the replica
/// did not become ready".
fn run_migrate_up(
    binary: &std::path::Path,
    shared: &[(String, String)],
    migrator_dsn_file: &std::path::Path,
) {
    let mut command = std::process::Command::new(binary);
    command.env_clear();
    for key in INHERITED_ENVIRONMENT {
        if let Ok(value) = std::env::var(key) {
            command.env(key, value);
        }
    }
    for (key, value) in shared {
        command.env(key, value);
    }
    command.env("DATABASE_URL_FILE", migrator_dsn_file);
    // A one-shot command needs one connection, and the default pool of ten
    // is ten more sessions on a server this suite already shares with the
    // replicas, the harness's own pools, and (in development) other
    // builds. Asking for what it needs is the difference between a
    // migration and an occasional "the database did not become reachable".
    command.env("DATABASE_POOL_MAX", "2");
    let output = command
        .arg("migrate")
        .arg("up")
        .output()
        .expect("the migration command should run");
    assert!(
        output.status.success(),
        "gateway migrate up failed ({})\n--- stdout ---\n{}\n--- stderr ---\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
