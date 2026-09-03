//! The per-run PostgreSQL database and runtime role, plus the database
//! faults the failure suites inject.
//!
//! Two rules shape this module.
//!
//! **One disposable database and one disposable role per run.** The server
//! is shared with every other suite in the repository (and, on a developer
//! box, with whatever else is running), so nothing here may touch a shared
//! role or a shared database. Faults are injected against a role this run
//! created and scoped to the database this run created, so a revoked
//! `CONNECT` or a read-only default can never reach a sibling test.
//!
//! **Database time is authoritative.** No helper here reads the wall
//! clock to decide anything. [`Database::epoch_seconds`] asks the server
//! what time it is, and [`Database::wait_for_elapsed`] polls that value;
//! a test that needs "a heartbeat interval later" waits for the database
//! to say so.

use std::{str::FromStr, time::Duration};

use deadpool_postgres::{Manager, Pool, PoolConfig, Runtime};
use tokio_postgres::{Config as PgConfig, NoTls};

/// The variable that opts a run in to the release gate.
///
/// These suites are minutes of two-process, one-database work each — the
/// `ha-release-gate` CI job exists to pay for them, on its own budget and
/// parallelised by file. `postgres-foundation` runs `cargo test -p gateway`
/// with the DSN locator set, and would otherwise run every one of them a
/// second time inside a budget sized for the unit and contract suites. So
/// the locator below asks for BOTH: the database, and a run that meant to
/// pay for the gate.
pub const GATE_ENABLED: &str = "GATEWAY_TEST_HA_GATE";

/// The locator every PostgreSQL-backed suite skips on. Identical in
/// contract and shape to `gateway/src/storage/contract_tests.rs::locator`:
/// an environment variable naming a file whose contents are the admin DSN.
/// Absent or empty means "no database here", which is a skip, never a
/// failure.
///
/// Plus [`GATE_ENABLED`], which is what separates "there is no database
/// here" from "this run is not the gate". A run that has the database but
/// not the opt-in says so on stderr rather than skipping quietly: a gate
/// that skipped in silence would be indistinguishable from a gate that
/// passed.
pub fn locator() -> Option<String> {
    let file = std::env::var("GATEWAY_TEST_POSTGRES_URL_FILE").ok()?;
    if file.trim().is_empty() {
        return None;
    }
    if std::env::var(GATE_ENABLED)
        .ok()
        .is_none_or(|value| value.trim().is_empty())
    {
        eprintln!(
            "skipping the #241 multi-replica release gate: {GATE_ENABLED} is unset. The \
             ha-release-gate CI job sets it; `cargo test -p gateway` deliberately does not \
             pay for these suites twice."
        );
        return None;
    }
    let contents = std::fs::read_to_string(file).ok()?;
    let trimmed = contents.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// The deployment's initial policy document.
///
/// Deliberately minimal and deliberately `allow`: it exists so the
/// deployment is *initialized*, not so it enforces anything. A suite that
/// is about authorization commits its own document over this one and
/// asserts against that.
///
/// Written with every field the gateway's `Policy` serializes and none it
/// skips, so `deserialize` then `serialize` is the identity — which is
/// what makes the ETag below computable here rather than only inside the
/// binary.
pub const SEED_POLICY_DOCUMENT: &str = r#"{"default_action":"allow","enforcement_mode":"enforce","roles":{},"routes":[],"rules":[],"schema_version":"0.1.0"}"#;

/// When a seeded endpoint was first classified. Deliberately far in the
/// past: the routing context must be older than the evidence a suggestion
/// was raised from, or the accept handler refuses the suggestion as
/// predating trusted routing context.
pub const SEEDED_OBSERVATION_TIMESTAMP: &str = "2020-01-01T00:00:00Z";
/// When a seeded suggestion was raised: after the classification above.
pub const SEEDED_SUGGESTION_TIMESTAMP: &str = "2020-01-02T00:00:00Z";

/// The deployment's initial tools document, seeded only for suites that
/// write or execute tools. Same round-trip rule as the policy: exactly the
/// fields `ToolsFileAdminDocument` serializes, so the harness can compute
/// the ETag the gateway will compute.
pub const SEED_TOOLS_DOCUMENT: &str = r#"{"schema_version":"0.1.0","tools":[]}"#;

/// The gateway's ETag rule, restated: serialize the document with its
/// object keys sorted, SHA-256 the bytes, render `"sha256:<hex>"`
/// (`main.rs::policy_etag`). The startup read recomputes this from the
/// stored document and refuses to serve a pointer whose ETag disagrees, so
/// a seed that got this wrong would fail closed rather than silently.
pub fn policy_etag(document: &str) -> String {
    use sha2::Digest as _;
    let mut value: serde_json::Value =
        serde_json::from_str(document).expect("the seed policy document should be valid JSON");
    sort_json_value(&mut value);
    let bytes = serde_json::to_vec(&value).expect("a JSON value should reserialize");
    format!("\"sha256:{}\"", hex::encode(sha2::Sha256::digest(&bytes)))
}

fn sort_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                sort_json_value(value);
            }
        }
        serde_json::Value::Object(map) => {
            let mut entries = std::mem::take(map).into_iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (_, value) in &mut entries {
                sort_json_value(value);
            }
            map.extend(entries);
        }
        _ => {}
    }
}

/// The audit schema version every seeded event carries; the value
/// `audit::event::SCHEMA_VERSION` stamps on a real one.
pub const AUDIT_SCHEMA_VERSION: &str = "0.1.0";

/// The event type the discovery projector applies. Every other type only
/// moves its checkpoint.
pub const HTTP_REQUEST_OBSERVED: &str = "http.request_observed";

/// One live replica's foundation identity, as the roster records it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemberIdentity {
    pub instance_id: uuid::Uuid,
    pub boot_id: uuid::Uuid,
}

fn parse_uuid(text: String) -> uuid::Uuid {
    uuid::Uuid::parse_str(&text)
        .unwrap_or_else(|error| panic!("a roster identity should be a UUID: {error}"))
}

/// Who a seeded event was acting as.
#[derive(Clone, Debug)]
pub struct SeedActor {
    pub user_id: String,
    pub issuer: String,
    pub auth_mode: String,
}

impl SeedActor {
    /// A bearer-token principal at the harness's own issuer.
    pub fn bearer(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_owned(),
            issuer: "https://ha-harness.invalid/".to_owned(),
            auth_mode: "bearer_token".to_owned(),
        }
    }
}

/// One event to commit onto the durable stream.
#[derive(Clone, Debug)]
pub struct AuditEventSeed {
    pub event_id: String,
    pub event_type: String,
    /// RFC 3339, the application timestamp the event claims. Deliberately
    /// the caller's: retention and the aggregator's recency ordering both
    /// read it, and a suite about either needs to choose it.
    pub occurred_at: String,
    /// Which replica ingested it. The provenance column the HA state model
    /// requires an event to keep; the harness stamps a real member's
    /// identity so "an event from replica B" is true of the row even
    /// though the harness performed the write.
    pub instance_id: Option<uuid::Uuid>,
    pub boot_id: Option<uuid::Uuid>,
    pub request_id: String,
    pub source_ip: String,
    pub actor: Option<SeedActor>,
    pub payload: serde_json::Value,
}

impl AuditEventSeed {
    /// An `http.request_observed` event the projector will aggregate.
    ///
    /// `endpoint_template` is given explicitly rather than left to the
    /// path-template learner, so a suite about cardinality controls how
    /// many distinct endpoints it creates instead of discovering how many
    /// the learner merged.
    pub fn observation(
        method: &str,
        endpoint_template: &str,
        occurred_at: &str,
        actor: Option<SeedActor>,
    ) -> Self {
        Self {
            event_id: format!("ha-{}", uuid::Uuid::new_v4().simple()),
            event_type: HTTP_REQUEST_OBSERVED.to_owned(),
            occurred_at: occurred_at.to_owned(),
            instance_id: None,
            boot_id: None,
            request_id: format!("req-{}", uuid::Uuid::new_v4().simple()),
            source_ip: "203.0.113.10".to_owned(),
            actor,
            payload: serde_json::json!({
                "method": method,
                "path": endpoint_template,
                "endpoint_template": endpoint_template,
                "status": 200,
                "latency_ms": 5,
                "routing_context_known": true,
            }),
        }
    }

    /// A marker event: something the stream carries and the projector only
    /// steps over. What the SSE rows stream, so a stream assertion is not
    /// also an assertion about aggregation.
    pub fn marker(event_type: &str, path: &str, occurred_at: &str) -> Self {
        Self {
            event_id: format!("ha-{}", uuid::Uuid::new_v4().simple()),
            event_type: event_type.to_owned(),
            occurred_at: occurred_at.to_owned(),
            instance_id: None,
            boot_id: None,
            request_id: format!("req-{}", uuid::Uuid::new_v4().simple()),
            source_ip: "203.0.113.10".to_owned(),
            actor: None,
            payload: serde_json::json!({ "path": path }),
        }
    }

    pub fn attributed_to(mut self, instance_id: uuid::Uuid, boot_id: uuid::Uuid) -> Self {
        self.instance_id = Some(instance_id);
        self.boot_id = Some(boot_id);
        self
    }

    pub fn with_event_id(mut self, event_id: &str) -> Self {
        self.event_id = event_id.to_owned();
        self
    }

    pub fn with_payload_field(mut self, key: &str, value: serde_json::Value) -> Self {
        if let Some(map) = self.payload.as_object_mut() {
            map.insert(key.to_owned(), value);
        }
        self
    }
}

fn payload_string(payload: &serde_json::Value, key: &str) -> Option<String> {
    payload
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

/// The advisory-lock key the audit stream serializes position assignment
/// on, derived the way `postgres_audit.rs` derives it (and pinned there by
/// its own unit test). A harness on a different key would not serialize
/// against the production writer at all.
fn audit_stream_lock_key() -> i64 {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(b"greengateway.audit-stream");
    let mut value = [0_u8; 8];
    value.copy_from_slice(&digest[..8]);
    value[0] &= 0x7f;
    i64::from_be_bytes(value)
}

/// `storage/postgres_audit.rs::INSERT_EVENTS_SQL`, verbatim.
const INSERT_EVENTS_SQL: &str = r#"
INSERT INTO greengateway.audit_events (
    event_id, event_type, occurred_at, instance_id, boot_id, schema_version,
    request_id, source_ip, user_agent, actor_user_id, actor_issuer,
    actor_auth_mode, actor_json, payload_method, payload_path, payload_status,
    payload_matched_rule_id, payload_json
)
SELECT * FROM UNNEST(
    $1::text[], $2::text[], $3::text[]::timestamptz[],
    $4::text[]::uuid[], $5::text[]::uuid[],
    $6::text[], $7::text[], $8::text[], $9::text[], $10::text[],
    $11::text[], $12::text[], $13::text[]::jsonb[], $14::text[], $15::text[],
    $16::int[], $17::text[], $18::text[]::jsonb[]
)
ON CONFLICT (event_id) DO NOTHING
"#;

/// `storage/postgres_audit.rs::APPEND_STREAM_SQL`, verbatim.
const APPEND_STREAM_SQL: &str = r#"
WITH pending AS (
    SELECT batch.event_id
    FROM UNNEST($1::text[]) AS batch(event_id)
    WHERE NOT EXISTS (
        SELECT 1 FROM greengateway.audit_stream s WHERE s.event_id = batch.event_id
    )
),
reserved AS (
    UPDATE greengateway.audit_stream_state
    SET last_position = last_position + (SELECT count(*) FROM pending)
    WHERE singleton
    RETURNING last_position - (SELECT count(*) FROM pending) AS base_position
),
assigned AS (
    SELECT reserved.base_position
           + row_number() OVER (ORDER BY pending.event_id) AS position,
           pending.event_id
    FROM pending CROSS JOIN reserved
)
INSERT INTO greengateway.audit_stream (position, event_id)
SELECT position, event_id FROM assigned
ON CONFLICT (event_id) DO NOTHING
"#;

/// Does the server still hold a database of this name?
///
/// For the harness's own teardown proof: after a [`Database`] is dropped
/// the answer must be no, whether the test that owned it passed or
/// panicked.
pub async fn database_exists(admin_dsn: &str, name: &str) -> bool {
    catalog_probe(
        admin_dsn,
        "SELECT count(*)::bigint FROM pg_database WHERE datname = $1",
        name,
    )
    .await
}

/// Does the server still hold a role of this name?
pub async fn role_exists(admin_dsn: &str, role: &str) -> bool {
    catalog_probe(
        admin_dsn,
        "SELECT count(*)::bigint FROM pg_roles WHERE rolname = $1",
        role,
    )
    .await
}

async fn catalog_probe(admin_dsn: &str, sql: &str, name: &str) -> bool {
    let pool = pool_for(admin_dsn, 1);
    let client = pool
        .get()
        .await
        .expect("harness admin connection should establish");
    let count: i64 = client
        .query_one(sql, &[&name])
        .await
        .expect("the catalog probe should run")
        .get(0);
    count > 0
}

/// Rewrite only the database path segment of a DSN.
///
/// A plain string replace would also rewrite the user name, which in these
/// test DSNs is spelled like the database.
fn with_database(dsn: &str, database: &str) -> String {
    let start = dsn
        .rfind('/')
        .expect("the locator DSN has a database path segment");
    format!("{}/{database}", &dsn[..start])
}

/// Rewrite the user of a DSN of the form `postgres://user@host:port/db`.
fn with_user(dsn: &str, user: &str) -> String {
    let scheme_end = dsn.find("://").expect("the locator DSN has a scheme") + 3;
    let rest = &dsn[scheme_end..];
    let authority_end = rest
        .find('@')
        .expect("the locator DSN names its user explicitly");
    format!("{}{user}{}", &dsn[..scheme_end], &rest[authority_end..])
}

fn pool_for(dsn: &str, size: usize) -> Pool {
    let config = PgConfig::from_str(dsn).expect("harness DSN should parse");
    Pool::builder(Manager::new(config, NoTls))
        .config({
            let mut pool_config = PoolConfig::new(size);
            pool_config.timeouts.create = Some(Duration::from_secs(10));
            pool_config.timeouts.wait = Some(Duration::from_secs(10));
            pool_config
        })
        .runtime(Runtime::Tokio1)
        .build()
        .expect("harness pool should build")
}

/// One run's disposable database and runtime role.
///
/// * `admin_dsn` — the locator's DSN, owning the maintenance connection.
/// * `migrator_dsn` — the admin role against this run's database; the
///   migration job's shape (DDL allowed).
/// * `runtime_dsn` — this run's own no-DDL role against this run's
///   database; what the serving replicas connect as, mirroring the
///   `ggw_runtime_noddl` boundary the `postgres-foundation` CI job proves.
pub struct Database {
    pub admin_dsn: String,
    pub migrator_dsn: String,
    pub runtime_dsn: String,
    pub name: String,
    pub role: String,
    admin_pool: Pool,
    run_pool: Pool,
    /// The teardown. It is a field rather than a `Drop` on `Database`
    /// itself so it can be created BEFORE the first `CREATE ROLE`: every
    /// statement in the constructor panics on failure, and a panic between
    /// creating the role and returning the value would otherwise leave the
    /// role on a shared server with nothing owning it.
    _reaper: Reaper,
}

/// Owns the removal of one run's database and role.
///
/// Constructed from the names alone, before either object exists, because
/// its whole job is to run on the unwind path — `DROP ... IF EXISTS` makes
/// "it was never created" the same case as "it was".
struct Reaper {
    name: String,
    role: String,
    admin_pool: Pool,
}

impl Drop for Reaper {
    fn drop(&mut self) {
        // Teardown must survive a panicking test, so it runs on its own
        // single-threaded runtime rather than the test's (which may
        // already be shutting down). Order matters: terminate the
        // replicas' backends, drop the database, then the role — a role
        // is undroppable while it still holds privileges on a live
        // database.
        let name = self.name.clone();
        let role = self.role.clone();
        let pool = self.admin_pool.clone();
        let _ = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                eprintln!(
                    "harness teardown could not build a runtime; {name} and {role} may survive"
                );
                return;
            };
            runtime.block_on(async move {
                let client = match pool.get().await {
                    Ok(client) => client,
                    Err(error) => {
                        eprintln!(
                            "harness teardown could not reach the server ({error}); \
                             {name} and {role} may survive"
                        );
                        return;
                    }
                };
                let _ = client
                    .batch_execute(&format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                         WHERE datname = '{name}' AND pid <> pg_backend_pid()"
                    ))
                    .await;
                if let Err(error) = client
                    .batch_execute(&format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
                    .await
                {
                    eprintln!("harness teardown could not drop {name}: {error}");
                }
                // The role is dropped last and its failure is reported: a
                // surviving role is invisible until the shared server has
                // collected hundreds of them, which is exactly the kind of
                // leak a silent `let _ =` used to hide.
                if let Err(error) = client
                    .batch_execute(&format!("DROP ROLE IF EXISTS {role}"))
                    .await
                {
                    eprintln!("harness teardown could not drop role {role}: {error}");
                }
            });
        })
        .join();
    }
}

impl Database {
    /// Create the database and the runtime role. The role is created
    /// before the database so the `CONNECT` grant can be applied in the
    /// same maintenance session.
    pub async fn create(admin_dsn: &str) -> Self {
        Self::create_with_password(admin_dsn, None).await
    }

    /// [`Self::create`], optionally giving the runtime role a password
    /// that then appears in the runtime DSN.
    ///
    /// The secret-leak suite needs a DSN that actually *carries* a
    /// credential: a passwordless DSN cannot prove the gateway keeps
    /// passwords out of its logs, because there is nothing to keep out.
    /// The local server authenticates by trust, so the password is never
    /// exchanged — it exists only to be a canary the replica must never
    /// print.
    pub async fn create_with_password(admin_dsn: &str, password: Option<&str>) -> Self {
        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let name = format!("ggw_ha_{suffix}");
        let role = format!("ggw_ha_r_{suffix}");
        let admin_pool = pool_for(admin_dsn, 2);
        // Before the first `CREATE`: every statement below panics on
        // failure, and this is the only thing that removes what they
        // created. Nothing between here and the `Self { .. }` may leak.
        let reaper = Reaper {
            name: name.clone(),
            role: role.clone(),
            admin_pool: admin_pool.clone(),
        };

        {
            let client = admin_pool
                .get()
                .await
                .expect("harness admin connection should establish");
            // Single statements on the simple protocol: CREATE DATABASE
            // cannot run inside a transaction block.
            let login = match password {
                // The value is a per-run canary of the harness's own
                // making, never caller input, and it is quoted as a
                // literal; a password containing a quote would be a
                // harness bug, so it is rejected rather than escaped.
                Some(secret) => {
                    assert!(
                        secret
                            .chars()
                            .all(|character| character.is_ascii_alphanumeric() || character == '-'),
                        "a harness database password must stay in the DSN-safe alphabet"
                    );
                    format!("CREATE ROLE {role} LOGIN PASSWORD '{secret}'")
                }
                None => format!("CREATE ROLE {role} LOGIN"),
            };
            client
                .batch_execute(&login)
                .await
                .unwrap_or_else(|error| panic!("the harness runtime role should create: {error}"));
            client
                .batch_execute(&format!("CREATE DATABASE {name}"))
                .await
                .unwrap_or_else(|error| panic!("the harness database should create: {error}"));
            // PUBLIC holds CONNECT on every new database by default, which
            // would make "revoke the runtime role's CONNECT" a no-op. Take
            // it away first, then grant the runtime role explicitly, so the
            // fault has something to revoke.
            client
                .batch_execute(&format!(
                    "REVOKE CONNECT ON DATABASE {name} FROM PUBLIC; \
                     GRANT CONNECT ON DATABASE {name} TO {role};"
                ))
                .await
                .unwrap_or_else(|error| panic!("the CONNECT grant should apply: {error}"));
        }

        let migrator_dsn = with_database(admin_dsn, &name);
        let runtime_dsn = match password {
            Some(secret) => with_user(&migrator_dsn, &format!("{role}:{secret}")),
            None => with_user(&migrator_dsn, &role),
        };
        let run_pool = pool_for(&migrator_dsn, 2);
        Self {
            admin_dsn: admin_dsn.to_owned(),
            migrator_dsn,
            runtime_dsn,
            name,
            role,
            admin_pool,
            run_pool,
            _reaper: reaper,
        }
    }

    /// Grant the runtime role exactly what a serving replica needs, after
    /// the migration job has created the schema: DML on the tables, usage
    /// on the sequences, and nothing that could change the schema. Run
    /// after `gateway migrate up`, never before — there is nothing to
    /// grant on until then.
    pub async fn grant_runtime_privileges(&self) {
        let role = &self.role;
        self.run_batch(&format!(
            "GRANT USAGE ON SCHEMA greengateway TO {role}; \
             GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA greengateway TO {role}; \
             GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA greengateway TO {role};"
        ))
        .await;
    }

    /// Seed the deployment's first active policy document.
    ///
    /// Cluster mode refuses to serve a deployment whose policy control
    /// plane has no active document — deliberately, because a gateway that
    /// started anyway would serve protected traffic with no authorization
    /// policy. Initialization is an explicit workflow, and the one the
    /// product ships (the standalone import of #241 PR 15) is not on this
    /// branch, so the harness writes the initial version the same way
    /// `storage/postgres_documents.rs::commit_in` does: one transaction
    /// that appends the immutable version, reserves the security revision,
    /// initializes the singleton pointer, and appends the outbox row.
    ///
    /// Returns the document's ETag, which is also the precondition a suite
    /// hands to its first `If-Match` write.
    pub async fn seed_policy_document(&self, document: &str) -> String {
        self.seed_document(
            "greengateway.policy_documents",
            "greengateway.policy_active",
            "policy",
            document,
        )
        .await
    }

    /// Seed the deployment's first active tools document, by the same
    /// section-2 transaction.
    ///
    /// A replica seeds an *empty* tools document itself at first boot, so
    /// this is not needed to start; it exists so a suite can start from a
    /// document that already carries tools. It runs before any replica, so
    /// the replica's own initialize finds the resource initialized and is
    /// the no-op its precondition makes it.
    ///
    /// The table names are the ones `postgres_tools.rs` uses, which are
    /// singular (`tool_documents`, `tool_active`) while the outbox label
    /// is plural (`tools`) — a mismatch worth spelling out here, because
    /// guessing it wrong fails as "the tools control plane is unavailable".
    pub async fn seed_tools_document(&self, document: &str) -> String {
        self.seed_document(
            "greengateway.tool_documents",
            "greengateway.tool_active",
            "tools",
            document,
        )
        .await
    }

    /// The section-2 initialize transaction for one document resource:
    /// the immutable version, the reserved security revision, the
    /// singleton pointer, and the outbox row, all or nothing.
    async fn seed_document(
        &self,
        documents_table: &str,
        active_table: &str,
        resource: &str,
        document: &str,
    ) -> String {
        let etag = policy_etag(document);
        let client = self
            .run_pool
            .get()
            .await
            .expect("harness run-database connection should establish");
        let seed = async {
            client.batch_execute("BEGIN").await?;
            let version: i64 = client
                .query_one(
                    &format!(
                        "INSERT INTO {documents_table} \
                           (actor_user_id, diff_summary, document, document_etag) \
                         VALUES ($1, $2::text::jsonb, $3::text::jsonb, $4) \
                         RETURNING version"
                    ),
                    &[
                        &"harness:seed",
                        &r#"{"seeded_by":"ha-harness"}"#,
                        &document,
                        &etag,
                    ],
                )
                .await?
                .get(0);
            let revision: i64 = client
                .query_one(
                    "UPDATE greengateway.security_revision_state \
                     SET last_revision = last_revision + 1 \
                     WHERE singleton RETURNING last_revision",
                    &[],
                )
                .await?
                .get(0);
            client
                .execute(
                    &format!(
                        "INSERT INTO {active_table} \
                           (singleton, active_version, document_etag, security_revision) \
                         VALUES (true, $1, $2, $3)"
                    ),
                    &[&version, &etag, &revision],
                )
                .await?;
            client
                .execute(
                    "INSERT INTO greengateway.security_outbox \
                       (revision, resource_type, from_version, to_version) \
                     VALUES ($1, $2, NULL, $3)",
                    &[&revision, &resource, &version],
                )
                .await?;
            client.batch_execute("COMMIT").await?;
            Ok::<(), tokio_postgres::Error>(())
        }
        .await;
        if let Err(error) = seed {
            let _ = client.batch_execute("ROLLBACK").await;
            panic!("the harness {resource} seed failed: {error}");
        }
        etag
    }

    /// Record one observed endpoint with a known routing context, as the
    /// PR 11 projector would have.
    ///
    /// The suggestion-acceptance row needs a suggestion whose target the
    /// accept handler can still re-validate. Generating one for real means
    /// traffic, a projection pass and an audit scan; seeding the two rows
    /// the re-validation actually reads keeps the test about the thing it
    /// names — that two replicas accepting at once produce one rule and one
    /// transition — instead of about the projector.
    ///
    /// The endpoint is left *contextless* (no routing-context row), which
    /// is the shape `direct_rule_safety_for_target` calls safe, and the
    /// classification is stamped in the past so the suggestion's evidence
    /// is never older than the routing context it was classified under.
    pub async fn seed_observed_endpoint(&self, method: &str, endpoint_template: &str) {
        let client = self
            .run_pool
            .get()
            .await
            .expect("harness run-database connection should establish");
        client
            .execute(
                "INSERT INTO greengateway.discovery_endpoint_aggregates \
                   (method, endpoint_template, first_seen, last_seen, call_count, \
                    latency_count, latency_p50_ms, latency_p95_ms, latency_p99_ms, \
                    latency_samples_json, distinct_principal_count, updated_at) \
                 VALUES ($1, $2, $3, $3, 1, 1, 1, 1, 1, '[1]', 1, $3) \
                 ON CONFLICT (method, endpoint_template) DO NOTHING",
                &[&method, &endpoint_template, &SEEDED_OBSERVATION_TIMESTAMP],
            )
            .await
            .unwrap_or_else(|error| panic!("the harness endpoint seed failed: {error}"));
        client
            .execute(
                "INSERT INTO greengateway.discovery_endpoint_routing_classifications \
                   (method, endpoint_template, first_classified_at) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (method, endpoint_template) DO NOTHING",
                &[&method, &endpoint_template, &SEEDED_OBSERVATION_TIMESTAMP],
            )
            .await
            .unwrap_or_else(|error| panic!("the harness classification seed failed: {error}"));
    }

    /// Insert one open rule suggestion, returning its id.
    pub async fn seed_rule_suggestion(
        &self,
        suggestion_type: &str,
        method: &str,
        path_pattern: &str,
        proposed_rule: &serde_json::Value,
    ) -> String {
        let id = format!("sug-{}", uuid::Uuid::new_v4().simple());
        let rule_json = proposed_rule.to_string();
        let client = self
            .run_pool
            .get()
            .await
            .expect("harness run-database connection should establish");
        client
            .execute(
                "INSERT INTO greengateway.discovery_rule_suggestions \
                   (id, suggestion_type, method, path_pattern, principal_key, \
                    proposed_rule_json, rationale, evidence_json, state, \
                    created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'open', $9, $9)",
                &[
                    &id,
                    &suggestion_type,
                    &method,
                    &path_pattern,
                    &"harness",
                    &rule_json,
                    &"seeded by the #241 release-gate harness",
                    &r#"{"source":"ha-harness"}"#,
                    &SEEDED_SUGGESTION_TIMESTAMP,
                ],
            )
            .await
            .unwrap_or_else(|error| panic!("the harness suggestion seed failed: {error}"));
        id
    }

    // ------------------------------------------------------------------
    // The durable audit stream.
    // ------------------------------------------------------------------

    /// Commit a batch of audit events onto the deployment's durable
    /// stream, exactly as `storage/postgres_audit.rs::insert_events` does.
    ///
    /// **Why the harness writes these at all.** The durable audit store
    /// (PR 5), its commit-ordered stream (PR 5), the cross-replica SSE
    /// transport (PR 6) and the fenced discovery projector (PR 11) are all
    /// on this branch. The *runtime ingestion sink* that would feed the
    /// stream from live traffic is not: nothing in the binary calls
    /// `AuditEventStore::insert_events`, so a replica serving a request
    /// writes its observation to the file and broadcast sinks and to
    /// nothing else. Every consumer this suite is about would therefore
    /// have an empty stream to consume, and the rows the issue asks about
    /// could not be tested at all.
    ///
    /// So the harness plays the missing writer, and only the writer: the
    /// three statements below are the production ones, verbatim, in the
    /// production order and the production transaction, including the
    /// transaction-scoped advisory lock that makes position order commit
    /// order. Everything *downstream* — the stream endpoint, the cursor
    /// protocol, the projector, its lease and its fence — is the real
    /// binary. Calling this twice with the same events is the ambiguous
    /// at-least-once retry the contract promises to absorb.
    ///
    /// The same justification the policy seed carries: initialize the
    /// state a shipped-but-later workflow would have written, then test
    /// the code that reads it.
    pub async fn ingest_audit_events(&self, events: &[AuditEventSeed]) {
        if events.is_empty() {
            return;
        }
        let mut event_ids = Vec::with_capacity(events.len());
        let mut event_types = Vec::with_capacity(events.len());
        let mut occurred_at = Vec::with_capacity(events.len());
        let mut instance_ids: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut boot_ids: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut schema_versions = Vec::with_capacity(events.len());
        let mut request_ids = Vec::with_capacity(events.len());
        let mut source_ips = Vec::with_capacity(events.len());
        let mut user_agents: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut actor_user_ids: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut actor_issuers: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut actor_auth_modes: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut actor_jsons: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut payload_methods: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut payload_paths: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut payload_statuses: Vec<Option<i32>> = Vec::with_capacity(events.len());
        let mut payload_rule_ids: Vec<Option<String>> = Vec::with_capacity(events.len());
        let mut payload_jsons = Vec::with_capacity(events.len());

        for event in events {
            event_ids.push(event.event_id.clone());
            event_types.push(event.event_type.clone());
            occurred_at.push(event.occurred_at.clone());
            instance_ids.push(event.instance_id.map(|id| id.to_string()));
            boot_ids.push(event.boot_id.map(|id| id.to_string()));
            schema_versions.push(AUDIT_SCHEMA_VERSION.to_owned());
            request_ids.push(event.request_id.clone());
            source_ips.push(event.source_ip.clone());
            user_agents.push(None);
            actor_user_ids.push(event.actor.as_ref().map(|actor| actor.user_id.clone()));
            actor_issuers.push(event.actor.as_ref().map(|actor| actor.issuer.clone()));
            actor_auth_modes.push(event.actor.as_ref().map(|actor| actor.auth_mode.clone()));
            actor_jsons.push(event.actor.as_ref().map(|actor| {
                serde_json::json!({
                    "user_id": actor.user_id,
                    "issuer": actor.issuer,
                    "auth_mode": actor.auth_mode,
                })
                .to_string()
            }));
            payload_methods.push(payload_string(&event.payload, "method"));
            payload_paths.push(payload_string(&event.payload, "path"));
            payload_statuses.push(
                event
                    .payload
                    .get("status")
                    .and_then(serde_json::Value::as_i64)
                    .and_then(|status| i32::try_from(status).ok()),
            );
            payload_rule_ids.push(payload_string(&event.payload, "matched_rule_id"));
            payload_jsons.push(event.payload.to_string());
        }

        let client = self
            .run_pool
            .get()
            .await
            .expect("harness run-database connection should establish");
        let ingest = async {
            client.batch_execute("BEGIN").await?;
            client
                .execute(
                    INSERT_EVENTS_SQL,
                    &[
                        &event_ids,
                        &event_types,
                        &occurred_at,
                        &instance_ids,
                        &boot_ids,
                        &schema_versions,
                        &request_ids,
                        &source_ips,
                        &user_agents,
                        &actor_user_ids,
                        &actor_issuers,
                        &actor_auth_modes,
                        &actor_jsons,
                        &payload_methods,
                        &payload_paths,
                        &payload_statuses,
                        &payload_rule_ids,
                        &payload_jsons,
                    ],
                )
                .await?;
            client
                .execute(
                    "SELECT pg_advisory_xact_lock($1)",
                    &[&audit_stream_lock_key()],
                )
                .await?;
            client.execute(APPEND_STREAM_SQL, &[&event_ids]).await?;
            client.batch_execute("COMMIT").await?;
            Ok::<(), tokio_postgres::Error>(())
        }
        .await;
        if let Err(error) = ingest {
            let _ = client.batch_execute("ROLLBACK").await;
            panic!("the harness audit ingest failed: {error}");
        }
    }

    /// The highest assigned stream position, read the way
    /// `PostgresAuditEventStore::stream_head` reads it.
    pub async fn stream_head(&self) -> i64 {
        self.count("SELECT coalesce(max(position), 0)::bigint FROM greengateway.audit_stream")
            .await
    }

    /// The identities of the deployment's live members, oldest boot
    /// first.
    ///
    /// The harness starts replicas one at a time and waits for each to
    /// bind before starting the next, so this order is the replica order:
    /// index 0 is `a`, index 1 is `b`.
    pub async fn member_identities(&self) -> Vec<MemberIdentity> {
        let client = self
            .run_pool
            .get()
            .await
            .expect("harness run-database connection should establish");
        client
            // Read as text: the harness's tokio-postgres is built without
            // the `uuid` type feature (the gateway binds UUIDs as text and
            // casts in SQL for the same reason).
            .query(
                "SELECT instance_id::text, boot_id::text \
                 FROM greengateway.cluster_members \
                 WHERE draining_at IS NULL ORDER BY started_at, instance_id",
                &[],
            )
            .await
            .unwrap_or_else(|error| panic!("the harness member read failed: {error}"))
            .iter()
            .map(|row| MemberIdentity {
                instance_id: parse_uuid(row.get::<_, String>(0)),
                boot_id: parse_uuid(row.get::<_, String>(1)),
            })
            .collect()
    }

    /// Run one statement batch as the admin role inside this run's
    /// database.
    pub async fn run_batch(&self, sql: &str) {
        let client = self
            .run_pool
            .get()
            .await
            .expect("harness run-database connection should establish");
        client
            .batch_execute(sql)
            .await
            .unwrap_or_else(|error| panic!("harness statement failed: {error}\nsql: {sql}"));
    }

    /// Run one statement batch on the maintenance connection (the admin
    /// database), for catalog-wide objects such as `DATABASE` privileges.
    pub async fn admin_batch(&self, sql: &str) {
        let client = self
            .admin_pool
            .get()
            .await
            .expect("harness admin connection should establish");
        client
            .batch_execute(sql)
            .await
            .unwrap_or_else(|error| panic!("harness admin statement failed: {error}\nsql: {sql}"));
    }

    /// A single-column, single-row query as the admin role inside this
    /// run's database.
    pub async fn query_one(&self, sql: &str) -> tokio_postgres::Row {
        let client = self
            .run_pool
            .get()
            .await
            .expect("harness run-database connection should establish");
        client
            .query_one(sql, &[])
            .await
            .unwrap_or_else(|error| panic!("harness query failed: {error}\nsql: {sql}"))
    }

    /// Every row a query returns, as the admin role inside this run's
    /// database.
    pub async fn query_all(&self, sql: &str) -> Vec<tokio_postgres::Row> {
        let client = self
            .run_pool
            .get()
            .await
            .expect("harness run-database connection should establish");
        client
            .query(sql, &[])
            .await
            .unwrap_or_else(|error| panic!("harness query failed: {error}\nsql: {sql}"))
    }

    pub async fn count(&self, sql: &str) -> i64 {
        self.query_one(sql).await.get::<_, i64>(0)
    }

    // ------------------------------------------------------------------
    // Database time. Never the wall clock.
    // ------------------------------------------------------------------

    /// The server's current time, in seconds since the Unix epoch.
    ///
    /// `clock_timestamp()` rather than `now()`: `now()` is the
    /// transaction start, which does not advance inside one statement
    /// batch and would make a wait loop spin forever.
    pub async fn epoch_seconds(&self) -> f64 {
        self.query_one("SELECT extract(epoch FROM clock_timestamp())::float8")
            .await
            .get::<_, f64>(0)
    }

    /// Block until the database's own clock has advanced by `seconds`.
    ///
    /// The polling interval is wall-clock sleep between questions; the
    /// answer is always the database's. Panics if `budget` elapses first,
    /// which can only mean the database stopped answering.
    pub async fn wait_for_elapsed(&self, seconds: f64, budget: Duration) {
        let start = self.epoch_seconds().await;
        let deadline = std::time::Instant::now() + budget;
        loop {
            if self.epoch_seconds().await - start >= seconds {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the database clock did not advance {seconds}s within the harness budget"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // ------------------------------------------------------------------
    // Faults. Every one is scoped to this run's role and database.
    // ------------------------------------------------------------------

    /// Take away the runtime role's `CONNECT`. New connections are
    /// refused; established ones keep working until they are terminated,
    /// which is the real shape of a revoked grant and the reason the
    /// partition tests pair this with [`Self::terminate_runtime_backends`].
    pub async fn revoke_connect(&self) {
        self.admin_batch(&format!(
            "REVOKE CONNECT ON DATABASE {} FROM {}",
            self.name, self.role
        ))
        .await;
    }

    pub async fn restore_connect(&self) {
        self.admin_batch(&format!(
            "GRANT CONNECT ON DATABASE {} TO {}",
            self.name, self.role
        ))
        .await;
    }

    /// Terminate every backend this run's runtime role holds against this
    /// run's database. Returns how many were signalled.
    pub async fn terminate_runtime_backends(&self) -> i64 {
        self.query_one(&format!(
            "SELECT count(*)::bigint FROM ( \
               SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
               WHERE usename = '{}' AND datname = '{}' AND pid <> pg_backend_pid() \
             ) AS terminated",
            self.role, self.name
        ))
        .await
        .get::<_, i64>(0)
    }

    /// Make the runtime role's *new* sessions read-only in this database:
    /// the read-only-target row of the failure matrix.
    ///
    /// Role-and-database settings apply at session start, so this takes
    /// effect for connections opened after it — pair it with
    /// [`Self::terminate_runtime_backends`] to force the pool to reopen.
    pub async fn set_read_only(&self, read_only: bool) {
        let clause = if read_only {
            "SET default_transaction_read_only = on".to_owned()
        } else {
            "RESET default_transaction_read_only".to_owned()
        };
        self.admin_batch(&format!(
            "ALTER ROLE {} IN DATABASE {} {clause}",
            self.role, self.name
        ))
        .await;
    }

    /// Shrink (or reset) the runtime role's default `statement_timeout` in
    /// this database.
    ///
    /// Honest caveat, and the reason a test that wants the gateway's own
    /// statements to time out must use `DATABASE_STATEMENT_TIMEOUT_MS`
    /// instead: the gateway sets `statement_timeout` as a *startup
    /// parameter* on every pooled connection (`storage/postgres.rs`), and
    /// a startup parameter outranks a role default. This helper therefore
    /// bounds sessions that do not set their own — the harness's own
    /// probes, and any future one-shot command — and is here so a suite
    /// can prove that precedence rather than assume it.
    pub async fn set_role_statement_timeout(&self, milliseconds: Option<u64>) {
        let clause = match milliseconds {
            Some(value) => format!("SET statement_timeout = {value}"),
            None => "RESET statement_timeout".to_owned(),
        };
        self.admin_batch(&format!(
            "ALTER ROLE {} IN DATABASE {} {clause}",
            self.role, self.name
        ))
        .await;
    }

    /// How many backends the runtime role currently holds — the
    /// observable a pool-exhaustion or recovery test polls on.
    pub async fn runtime_backend_count(&self) -> i64 {
        self.count(&format!(
            "SELECT count(*)::bigint FROM pg_stat_activity \
             WHERE usename = '{}' AND datname = '{}'",
            self.role, self.name
        ))
        .await
    }
}
