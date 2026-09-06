//! Rolling upgrades, and the three things that stall one (issue #241,
//! PR 16 part 2).
//!
//! The parent contract asks for this suite in one sentence: "build the
//! previous release tag's binary and the current one, run mixed replicas
//! with expand/contract migrations while traffic and control-plane writes
//! continue, and prove the old binary never parses or writes unsupported
//! document versions." Writing it against the real repository turned that
//! sentence into one documented substitution and five executable claims,
//! and the substitution is the first thing to read.
//!
//! ## Why there is no second binary here
//!
//! The newest release tag in this repository is **v1.0.1** (2026-07-16).
//! Its `gateway/src` has no `storage/` directory, no `postgres` feature in
//! `gateway/Cargo.toml`, and no `STATE_BACKEND=postgres`: cluster mode is
//! what issue #241 is *adding*, and no released binary can join a
//! PostgreSQL deployment at all. A mixed-version cluster is therefore not
//! something this suite declined to build — it is something no pair of
//! GreenGateway binaries can currently form. The first release that ships
//! this sequence is the first one a mixed-version rollout can be measured
//! against.
//!
//! That is stated twice, on purpose, in two different registers:
//!
//! * [`mixed_binary_replicas_need_a_release_that_ships_cluster_mode`] is
//!   the `#[ignore]`d row that names the missing coverage, so a reader
//!   counting rows finds a reason rather than an absence.
//! * [`the_newest_release_tag_still_predates_cluster_mode`] is the
//!   tripwire that makes the reason expire. It reads the newest previous
//!   `v*` tag's own `gateway/Cargo.toml` (excluding the current commit) and
//!   **fails** the moment one
//!   carries the `postgres` feature — which is the moment the substitution
//!   stops being honest and the real mixed-binary row becomes writable.
//!
//! Everything else here runs one binary against a deployment put into the
//! states a rolling upgrade puts it in, with the *other* version's effects
//! written straight to the authority. That is the same substitution
//! discipline `failure_matrix.rs` uses for `iptables`: the injected fault
//! is not the real-world cause, it is the state the real-world cause
//! produces, and the row says which is which.
//!
//! ## What a rolling upgrade of this product can and cannot do
//!
//! Three gates decide, and each one has a row here.
//!
//! 1. **The schema ledger.** `storage::migrations::schema_version_range()`
//!    returns `(len, len)` — a single point, not a window. A replica
//!    refuses a ledger behind its manifest *and* one ahead of it, so there
//!    is no version pair that tolerates the same database. A migration
//!    applied mid-rollout makes every not-yet-upgraded replica
//!    `schema_incompatible` the moment it lands
//!    ([`an_expand_migration_has_no_overlap_window_so_it_cannot_roll`]).
//!    `docs/architecture/ha-state-model.md` §7 says "expand/contract so
//!    version N and N+1 binaries coexist"; the code does not implement
//!    that yet, and this row asserts the code.
//! 2. **The static-configuration fingerprint.** PR 13 holds a replica
//!    unready while any *live* member runs a different fingerprint, and
//!    agreement is sticky once granted. So an incumbent keeps serving when
//!    a new-configuration replica joins and stalls
//!    ([`a_new_static_configuration_stalls_at_the_gate_instead_of_serving_mismatched`]),
//!    but an incumbent that restarts while that replica is live loses its
//!    stickiness and stalls too
//!    ([`restarting_an_incumbent_while_a_new_configuration_is_live_costs_it_its_agreement`]).
//!    A configuration change completes only after the old set has drained,
//!    which is the parent contract's "cannot complete with zero
//!    unavailability", made executable.
//! 3. **The document version.** The policy document's `schema_version`
//!    must start with `0.` (`rbac/policy.rs::validate`), and the roster
//!    advertises the accepted range as
//!    `cluster_membership::DOCUMENT_VERSION_RANGE = (0, 0)`. A document a
//!    replica cannot parse is never compiled and never served — the
//!    replica goes to `security_revision_not_compiled` rather than
//!    continuing under the allow state it had
//!    ([`an_unsupported_document_version_is_never_compiled_and_never_served`])
//!    — and this binary will not write one either
//!    ([`this_binary_refuses_to_write_a_document_version_it_does_not_support`]).
//!
//! What *does* roll, and is asserted first, is the migration-free
//! replacement: one replica at a time, traffic and conditional
//! control-plane writes continuing throughout, nothing refused
//! ([`a_migration_free_rollout_replaces_every_replica_without_dropping_a_request`]).
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`, and without
//! `GATEWAY_TEST_HA_GATE`, like every other suite under `tests/ha/`.

#![cfg(feature = "postgres")]

mod harness;

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use serde_json::{json, Value};

use harness::{
    replica::{Replica, LISTEN_BUDGET},
    AuthShape, Cluster, ClusterOptions, FakeOidcIssuer, Target, TempDir, ADMIN_API_PREFIX,
};

// ---------------------------------------------------------------------
// Vocabulary and budgets — derived, never invented
// ---------------------------------------------------------------------

/// The `/readyz` reasons this suite waits for, checked against the same
/// closed vocabulary `failure_matrix.rs` publishes. A reason outside it
/// reaching a probe is a widened public contract.
const REASON_VOCABULARY: [&str; 8] = [
    "draining",
    "starting",
    "config_fingerprint_mismatch",
    "storage_unavailable",
    "schema_incompatible",
    "instance_lease_invalid",
    "security_revision_not_compiled",
    "required_upstream_unavailable",
];

const CONFIG_FINGERPRINT_MISMATCH: &str = "config_fingerprint_mismatch";
const SCHEMA_INCOMPATIBLE: &str = "schema_incompatible";
const SECURITY_REVISION_NOT_COMPILED: &str = "security_revision_not_compiled";

/// The migration ledger, spelled as `storage::migrations::LEDGER_TABLE`
/// spells it.
const LEDGER_TABLE: &str = "greengateway.schema_migrations";

/// A readiness transition caused by an authority-visible fault is
/// observable within `READINESS_PROBE_CACHE_MS` plus a probe round trip.
/// Generous, because every wait here is a bounded poll that returns the
/// instant its condition holds.
const AUTHORITY_BUDGET: Duration = Duration::from_secs(30);

/// A replica joining, or rejoining, a live deployment: a boot, a schema
/// validation, a membership write and at least one heartbeat.
const JOIN_BUDGET: Duration = Duration::from_secs(90);

/// `security_revision_not_compiled` needs
/// `security_cluster::RECONCILE_BACKGROUND_DEADLINE` — a hard-coded
/// `Duration::from_secs(30)` with no environment variable — to elapse, so
/// the unsupported-document row costs 30 s of real time that nothing here
/// can shorten.
const REVISION_BUDGET: Duration = Duration::from_secs(75);

/// `CLUSTER_MEMBER_STALE_MS` these clusters run with. Short, because two
/// rows wait for a stopped replica's roster row to age out of it, and that
/// wait is the price of the "drain first" strategy those rows measure.
const STALE_WINDOW_MS: u64 = 6_000;
const HEARTBEAT_MS: u64 = 1_000;

/// `READINESS_PROBE_CACHE_MS`. Shrunk from the 1 000 ms default so a
/// transition is observed within a probe or two: the condition is what is
/// under test, not the cache in front of it.
const PROBE_CACHE_MS: u64 = 250;

/// The one setting these rows vary to change a replica's fingerprint.
///
/// `ha::static_config_fingerprint` reads it through
/// `insert_egress_restrictions`, and nothing on a loopback deployment can
/// observe the difference: a connect timeout of 9 s and one of 10 s behave
/// identically against a fake upstream on `127.0.0.1`. That is exactly
/// what makes it the right lever — the row is about the *gate*, and a
/// setting that also changed behaviour would let a reader argue the
/// replica stalled for some other reason.
const FINGERPRINT_SETTING: &str = "EGRESS_CONNECT_TIMEOUT_MS";
const FINGERPRINT_SETTING_NEW_VALUE: &str = "9000";

const ADMIN_ROLE: &str = "ha-admin";
const PROXIED_PATH: &str = "/echo/rolling-upgrade";
const CLUSTER_ROUTE: &str = "/v1/admin/cluster";
/// The per-member roster. The version windows a rolling upgrade is about
/// — `schema_version_*` and `document_version_*` — are published here and
/// not on the summary at [`CLUSTER_ROUTE`], whose `local` object carries
/// only this process's identity and its revision watermarks.
const REPLICAS_ROUTE: &str = "/v1/admin/cluster/replicas";

fn policy_route() -> String {
    format!("{ADMIN_API_PREFIX}/policy")
}

fn skipped() {
    eprintln!(
        "skipping: no test database locator, or this run is not the gate; the ha-release-gate \
         CI job runs this suite"
    );
}

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

/// A policy granting [`ADMIN_ROLE`] everything and leaving the data plane
/// open, optionally carrying a marker role so a test can tell one revision
/// of the document from another by reading it back.
fn policy_document(marker: Option<&str>) -> String {
    let mut roles = json!({ ADMIN_ROLE: { "permissions": ["*"] } });
    if let Some(marker) = marker {
        roles
            .as_object_mut()
            .expect("the roles map is an object")
            .insert(marker.to_owned(), json!({ "permissions": [] }));
    }
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": roles,
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    })
    .to_string()
}

/// The same document at a `schema_version` this binary does not accept.
///
/// `Policy::validate` refuses anything whose `schema_version` does not
/// start with `0.`, and the roster advertises that as
/// `document_version_max = 0`. This is what a *newer* replica's commit
/// would look like to this one.
fn unsupported_document() -> String {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "schema_version": "1.0.0",
    })
    .to_string()
}

fn admin_token(issuer: &FakeOidcIssuer, subject: &str) -> String {
    issuer.mint_role_token(
        harness::oidc::PRIMARY_KID,
        subject,
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    )
}

/// This suite's cluster shape: authentication on (the cluster status API
/// and the security gate both want a principal), a short probe cache and a
/// short stale window.
fn rollout_options(replicas: usize) -> ClusterOptions {
    ClusterOptions {
        replicas,
        auth: AuthShape::Oidc,
        seed_policy: Some(policy_document(None)),
        heartbeat_ms: HEARTBEAT_MS,
        member_stale_ms: STALE_WINDOW_MS,
        shared_env: vec![(
            "READINESS_PROBE_CACHE_MS".to_owned(),
            PROBE_CACHE_MS.to_string(),
        )],
        ..ClusterOptions::default()
    }
}

async fn start_rollout_cluster(replicas: usize) -> Option<Cluster> {
    let mut cluster = Cluster::start(rollout_options(replicas)).await?;
    cluster.wait_until_all_ready().await;
    Some(cluster)
}

// ---------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------

fn assert_reason_is_in_the_vocabulary(replica: &str, body: &Value) {
    let Some(reason) = body["reason"].as_str() else {
        return;
    };
    assert!(
        REASON_VOCABULARY.contains(&reason),
        "replica {replica} answered /readyz with {reason:?}, which is not one of the eight \
         published reasons {REASON_VOCABULARY:?}; a new reason is a widened public contract"
    );
}

/// Poll `/readyz` until it answers `503` with exactly `expected`.
async fn wait_for_reason(replica: &Replica, expected: &str, budget: Duration) {
    assert!(
        REASON_VOCABULARY.contains(&expected),
        "{expected:?} is not a published /readyz reason"
    );
    let deadline = Instant::now() + budget;
    loop {
        let (status, body) = replica.readyz().await;
        assert_reason_is_in_the_vocabulary(&replica.name, &body);
        if status == 503 && body["reason"] == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "replica {} never reported {expected:?} within {budget:?}; last /readyz said \
             {status} {body}",
            replica.name
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Poll `/readyz` until it answers `200`.
async fn wait_until_ready(replica: &Replica, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        let (status, body) = replica.readyz().await;
        assert_reason_is_in_the_vocabulary(&replica.name, &body);
        if status == 200 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "replica {} did not become ready within {budget:?}; last /readyz said {status} \
             {body}",
            replica.name
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Sample one replica's `/readyz` across a window and fail on the first
/// sample that is not `503 <expected>`.
///
/// The subject of a "stalls" row is the whole window: a replica that
/// answered `200` once in the middle served under a configuration nobody
/// agreed to, which is precisely the defect the gate exists to prevent.
async fn assert_stalled_across(replica: &Replica, expected: &str, window: Duration) {
    let deadline = Instant::now() + window;
    let mut samples = 0_usize;
    while Instant::now() < deadline {
        let (status, body) = replica.readyz().await;
        assert_reason_is_in_the_vocabulary(&replica.name, &body);
        assert_eq!(
            status, 503,
            "replica {} must not become ready while it is held at the gate; it answered {body}",
            replica.name
        );
        assert_eq!(
            body["reason"], expected,
            "replica {} should be held for {expected:?}, and said {body}",
            replica.name
        );
        samples += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(samples >= 4, "the stall window sampled almost nothing");
}

/// Sample every replica of `cluster` across a window and fail on the first
/// sample that is not `200`.
async fn assert_ready_across(cluster: &Cluster, window: Duration, context: &str) {
    let deadline = Instant::now() + window;
    let mut samples = 0_usize;
    while Instant::now() < deadline {
        for replica in &cluster.replicas {
            let (status, body) = replica.readyz().await;
            assert_reason_is_in_the_vocabulary(&replica.name, &body);
            assert_eq!(
                status, 200,
                "{context}: replica {} should still be ready, and said {body}",
                replica.name
            );
        }
        samples += 1;
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(samples >= 4, "the {context} window sampled almost nothing");
}

/// How long an admin read is re-asked while the replica answers `503`.
///
/// The admin surfaces are authorized against the compiled policy, so a
/// replica whose revision check has not settled declines to judge and
/// answers `503 policy state unavailable` — the same transient
/// `security_two_replica.rs::send_settled` exists for. Nothing in this
/// suite asserts a `503` from these two routes, so re-asking within a
/// bound is the honest reading rather than a retry that hides a result.
const ADMIN_RETRY_BUDGET: Duration = Duration::from_secs(20);

/// One admin `GET`, re-issued while the replica answers `503`.
async fn admin_get(cluster: &Cluster, replica: &str, route: &str, admin: &str) -> Value {
    let deadline = Instant::now() + ADMIN_RETRY_BUDGET;
    loop {
        let (status, body) = cluster.get(replica, route).bearer(admin).send().await;
        if status == 200 {
            return body;
        }
        assert!(
            status == 503 && Instant::now() < deadline,
            "{route} on replica {replica} should answer, and said {status} {body}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// `GET /v1/admin/cluster` on one replica.
async fn cluster_status(cluster: &Cluster, replica: &str, admin: &str) -> Value {
    admin_get(cluster, replica, CLUSTER_ROUTE, admin).await
}

/// `GET /v1/admin/cluster/replicas` on one replica, as an array.
async fn cluster_replicas(cluster: &Cluster, replica: &str, admin: &str) -> Vec<Value> {
    let body = admin_get(cluster, replica, REPLICAS_ROUTE, admin).await;
    body["replicas"]
        .as_array()
        .unwrap_or_else(|| panic!("the roster should be an array: {body}"))
        .clone()
}

/// Poll `GET /v1/admin/cluster` until it reports `expected` replicas ready
/// out of `expected` live.
///
/// The roster's `ready_at` is written by a heartbeat, so it trails a
/// replica's own `/readyz`; and a replica that was hard-killed (`kill`,
/// the crash-shaped exit some rows choose) leaves a row that ages out of
/// the stale window rather than stamping itself draining. Both are the
/// deployment converging, and this polls through both.
async fn wait_for_ready_replicas(
    cluster: &Cluster,
    replica: &str,
    admin: &str,
    expected: u64,
    budget: Duration,
) {
    let deadline = Instant::now() + budget;
    loop {
        let body = cluster_status(cluster, replica, admin).await;
        if body["state"] == "ready"
            && body["replicas"]["ready"] == expected
            && body["replicas"]["total"] == expected
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the roster never converged on {expected} ready replicas within {budget:?}; \
             replica {replica} last said {body}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Poll the roster until exactly `expected` members are live on
/// **database** time.
///
/// Liveness is `now() - last_heartbeat_at` inside the stale window and no
/// draining stamp — the deployment's own rule, evaluated by the
/// deployment's own clock, never by this process's.
async fn wait_for_live_members(cluster: &Cluster, expected: i64, budget: Duration) {
    let deadline = Instant::now() + budget;
    loop {
        let live = cluster.live_member_count().await;
        if live == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the roster held {live} live member(s) rather than {expected} after {budget:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// How many *proxied* requests have reached the fake upstream.
///
/// Not `FakeUpstream::request_count`, which also counts the proxy's own
/// upstream health check — a request the pool issues on its own schedule
/// to decide `required_upstream_unavailable`. Counting those would make
/// "nothing was dispatched" a race against a background probe, and would
/// let a real dispatch hide inside the noise. (`failure_matrix.rs` keeps
/// the same helper for the same reason; the two suites are separate cargo
/// targets and cannot share it.)
fn proxied_count(cluster: &Cluster) -> usize {
    cluster
        .upstream
        .requests()
        .iter()
        .filter(|request| request.path.starts_with("/echo"))
        .count()
}

/// A `/metrics` scrape from an address the harness's `Cluster` does not
/// own — the extra replicas these rows spawn by hand.
async fn scrape_metrics(base_url: &str) -> String {
    let response = harness::http_client()
        .get(format!("{base_url}/metrics"))
        .send()
        .await
        .unwrap_or_else(|error| panic!("{base_url} did not answer /metrics: {error}"));
    assert_eq!(
        response.status().as_u16(),
        200,
        "the metrics endpoint should be scrapable without a credential"
    );
    response.text().await.unwrap_or_default()
}

// ---------------------------------------------------------------------
// A replica the cluster did not build
// ---------------------------------------------------------------------

/// One extra gateway process, started from an existing replica's
/// environment with some settings replaced.
///
/// `ClusterOptions` has no per-replica environment hook, and deliberately
/// so: every setting the fingerprint reads is shared, which is what makes
/// the harness's replicas agree. These rows are the ones that need
/// *disagreement*, so they build the environment themselves out of
/// [`Replica::environment`], change exactly what they mean to change, and
/// spawn the process directly. Nothing about the harness is loosened to
/// let them.
///
/// The returned handle owns its own audit file and kills its process on
/// drop, so a panicking row leaves no orphan.
struct ExtraReplica {
    replica: Replica,
    #[allow(dead_code)] // held for its Drop: the audit file lives here
    files: TempDir,
}

impl ExtraReplica {
    async fn spawn(cluster: &Cluster, name: &str, overrides: &[(&str, &str)]) -> Self {
        let files = TempDir::new("rolling-extra");
        let audit_path = files.path().join(format!("audit-{name}.jsonl"));
        let mut env: Vec<(String, String)> = cluster
            .replica("a")
            .environment()
            .into_iter()
            .filter(|(key, _)| key != "AUDIT_LOG_FILE")
            .collect();
        env.push((
            "AUDIT_LOG_FILE".to_owned(),
            audit_path.display().to_string(),
        ));
        for (key, value) in overrides {
            env.retain(|(existing, _)| existing != key);
            env.push(((*key).to_owned(), (*value).to_owned()));
        }
        let mut replica = Replica::spawn(name, cluster.binary(), env, audit_path);
        replica.wait_until_listening(LISTEN_BUDGET).await;
        Self { replica, files }
    }

    fn base_url(&self) -> String {
        self.replica.base_url()
    }
}

// ---------------------------------------------------------------------
// Writing to the authority as the other version would
// ---------------------------------------------------------------------

/// A privileged session that activates policy documents the way
/// `storage/postgres_documents.rs::commit_in` does.
///
/// This is how the "other version" appears in a suite that has only one
/// binary: a document written straight into the authority, with the
/// revision counter advanced and the outbox row appended, is
/// indistinguishable to a serving replica from a document a sibling
/// committed through the admin API. It is also the only way to activate a
/// document the admin API would (correctly) refuse — which is the whole
/// point of the unsupported-version row.
struct Authority {
    client: Option<tokio_postgres::Client>,
    pump: Option<tokio::task::JoinHandle<()>>,
}

impl Authority {
    async fn connect(dsn: &str) -> Self {
        let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
            .await
            .unwrap_or_else(|error| panic!("the authority session should establish: {error}"));
        let pump = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self {
            client: Some(client),
            pump: Some(pump),
        }
    }

    fn client(&self) -> &tokio_postgres::Client {
        self.client
            .as_ref()
            .expect("the authority session is still open")
    }

    /// Append a policy version, reserve the next security revision, move
    /// the active pointer and append the outbox row — one transaction, the
    /// same six steps and the same order as a real commit.
    ///
    /// Returns `(version, revision, etag)`.
    async fn activate(&self, document: &str, actor: &str) -> (i64, i64, String) {
        let etag = harness::database::policy_etag(document);
        let client = self.client();
        let result = async {
            client.batch_execute("BEGIN").await?;
            let previous: i64 = client
                .query_one(
                    "SELECT active_version FROM greengateway.policy_active WHERE singleton",
                    &[],
                )
                .await?
                .get(0);
            let version: i64 = client
                .query_one(
                    "INSERT INTO greengateway.policy_documents \
                       (actor_user_id, diff_summary, document, document_etag) \
                     VALUES ($1, $2::text::jsonb, $3::text::jsonb, $4) \
                     RETURNING version",
                    &[
                        &actor,
                        &r#"{"written_by":"rolling-upgrade"}"#,
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
                    "UPDATE greengateway.policy_active \
                     SET active_version = $1, document_etag = $2, security_revision = $3, \
                         activated_at = now() \
                     WHERE singleton",
                    &[&version, &etag, &revision],
                )
                .await?;
            client
                .execute(
                    "INSERT INTO greengateway.security_outbox \
                       (revision, resource_type, from_version, to_version) \
                     VALUES ($1, 'policy', $2, $3)",
                    &[&revision, &previous, &version],
                )
                .await?;
            client.batch_execute("COMMIT").await?;
            Ok::<(i64, i64), tokio_postgres::Error>((version, revision))
        }
        .await;
        match result {
            Ok((version, revision)) => (version, revision, etag),
            Err(error) => {
                let _ = client.batch_execute("ROLLBACK").await;
                panic!("the authority write failed: {error}");
            }
        }
    }
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.client.take();
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
    }
}

/// One injected ledger row and the statement that removes it, reversed
/// from `Drop` so a panicking row hands the next one a clean database.
struct LedgerRow {
    dsn: String,
    version: i64,
    armed: bool,
}

impl LedgerRow {
    /// Add a migration row above this binary's manifest: what a newer
    /// gateway's `migrate up` leaves behind.
    async fn insert_above_the_manifest(dsn: &str, highest: i64) -> Self {
        // Far enough above the manifest that no future migration count
        // can accidentally make this compatible.
        let version = highest + 1_000;
        run_sql(
            dsn,
            &format!(
                "INSERT INTO {LEDGER_TABLE} (version, name, checksum) \
                 VALUES ({version}, 'ha-rolling-upgrade-synthetic', \
                         'ha-rolling-upgrade-synthetic')"
            ),
        )
        .await;
        Self {
            dsn: dsn.to_owned(),
            version,
            armed: true,
        }
    }

    async fn revert(&mut self) {
        if self.armed {
            self.armed = false;
            run_sql(
                &self.dsn,
                &format!(
                    "DELETE FROM {LEDGER_TABLE} WHERE version = {}",
                    self.version
                ),
            )
            .await;
        }
    }
}

impl Drop for LedgerRow {
    fn drop(&mut self) {
        if self.armed {
            let dsn = self.dsn.clone();
            let version = self.version;
            let _ = std::thread::spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    eprintln!("the ledger row {version} could not be removed: no runtime");
                    return;
                };
                runtime.block_on(async move {
                    let connected = tokio_postgres::connect(&dsn, tokio_postgres::NoTls).await;
                    let Ok((client, connection)) = connected else {
                        eprintln!("the ledger row {version} could not be removed: no connection");
                        return;
                    };
                    let pump = tokio::spawn(async move {
                        let _ = connection.await;
                    });
                    if let Err(error) = client
                        .batch_execute(&format!(
                            "DELETE FROM {LEDGER_TABLE} WHERE version = {version}"
                        ))
                        .await
                    {
                        eprintln!("the ledger row {version} could not be removed: {error}");
                    }
                    drop(client);
                    pump.abort();
                });
            })
            .join();
        }
    }
}

/// One statement on a fresh connection, for the injections that need no
/// session state.
async fn run_sql(dsn: &str, sql: &str) {
    let (client, connection) = tokio_postgres::connect(dsn, tokio_postgres::NoTls)
        .await
        .unwrap_or_else(|error| panic!("the injection connection should establish: {error}"));
    let pump = tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute(sql)
        .await
        .unwrap_or_else(|error| panic!("the injection failed: {error}\nsql: {sql}"));
    drop(client);
    pump.abort();
}

// =====================================================================
// Row 1 — the rollout that works
// =====================================================================

/// What a *proxied* request got, sampled continuously through the whole
/// rollout.
#[derive(Default)]
struct TrafficReport {
    attempts: usize,
    refusals: Vec<(u16, String)>,
}

/// Drive proxied traffic through the balancer until told to stop.
///
/// Deliberately takes owned values rather than a borrow of the cluster:
/// the rollout mutates the cluster (stopping and starting processes,
/// rewriting the balancer's target list) while this runs, and a task
/// holding a reference could not coexist with that.
async fn drive_traffic(
    base_url: String,
    token: String,
    stop: Arc<AtomicBool>,
    completed: Arc<AtomicUsize>,
) -> TrafficReport {
    let mut report = TrafficReport::default();
    while !stop.load(Ordering::Relaxed) {
        let response = harness::http_client()
            .get(format!("{base_url}{PROXIED_PATH}"))
            .bearer_auth(&token)
            .send()
            .await;
        report.attempts += 1;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                if status != 200 {
                    let body = response.text().await.unwrap_or_default();
                    report.refusals.push((status, body));
                }
            }
            Err(error) => report.refusals.push((0, error.to_string())),
        }
        completed.fetch_add(1, Ordering::Release);
        // Back to back. The window this has to cover is a real process
        // stop and start, on a machine that may be running the rest of
        // this suite at the same time, and a fixed pause between requests
        // would make the sample count a measure of that load rather than
        // of the rollout.
        tokio::task::yield_now().await;
    }
    report
}

/// What the conditional control-plane writer did.
struct ControlPlaneReport {
    commits: Vec<String>,
    failures: Vec<(u16, Value)>,
    final_etag: String,
}

/// Commit a new policy every 100 ms, chaining `If-Match` from the previous
/// response, until told to stop.
///
/// Conditional writes are the point: an unconditional write would succeed
/// against any state at all and would prove nothing about a control plane
/// whose replicas are being replaced underneath it.
async fn drive_control_plane(
    base_url: String,
    token: String,
    mut etag: String,
    stop: Arc<AtomicBool>,
    completed: Arc<AtomicUsize>,
) -> ControlPlaneReport {
    let mut commits = Vec::new();
    let mut failures = Vec::new();
    let mut sequence = 0_usize;
    while !stop.load(Ordering::Relaxed) {
        sequence += 1;
        let marker = format!("rollout-{sequence}");
        let document: Value = serde_json::from_str(&policy_document(Some(&marker)))
            .expect("the policy document is JSON");
        let response = harness::http_client()
            .put(format!("{base_url}{}", policy_route()))
            .bearer_auth(&token)
            .header("if-match", &etag)
            .json(&document)
            .send()
            .await;
        match response {
            Ok(response) => {
                let status = response.status().as_u16();
                let next = response
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned);
                let body: Value =
                    serde_json::from_slice(&response.bytes().await.unwrap_or_default())
                        .unwrap_or(Value::Null);
                if status == 200 {
                    commits.push(marker);
                    if let Some(next) = next {
                        etag = next;
                    }
                } else {
                    failures.push((status, body));
                }
            }
            Err(error) => failures.push((0, Value::String(error.to_string()))),
        }
        completed.fetch_add(1, Ordering::Release);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    ControlPlaneReport {
        commits,
        failures,
        final_etag: etag,
    }
}

/// Wait until the drivers have completed `count` more requests than they
/// had, or fail saying they stopped.
async fn drain_in_flight(completed: &Arc<AtomicUsize>, count: usize) {
    let target = completed.load(Ordering::Acquire) + count;
    let deadline = Instant::now() + Duration::from_secs(30);
    while completed.load(Ordering::Acquire) < target {
        assert!(
            Instant::now() < deadline,
            "the traffic drivers stopped making progress while a replica was being drained"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Replace one replica the way a readiness-gated orchestrator does: take
/// it out of the load balancer, stop it, start it again, and put it back
/// **only once its own `/readyz` says `200`**.
///
/// That last clause is the discipline under test. `Cluster::restart`
/// returns as soon as the process has a listener, which is earlier than an
/// orchestrator would route to it; a rollout that added a bound-but-not-
/// ready replica back into rotation would be measuring the harness's
/// impatience rather than the product's behaviour.
async fn roll_one(cluster: &mut Cluster, name: &str, completed: &Arc<AtomicUsize>) {
    let surviving: Vec<Target> = cluster
        .replicas
        .iter()
        .filter(|replica| replica.name != name)
        .map(|replica| Target {
            name: replica.name.clone(),
            base_url: replica.base_url(),
        })
        .collect();
    assert!(
        !surviving.is_empty(),
        "a rolling replacement needs at least one replica left serving"
    );
    cluster.balancer.set_targets(surviving);

    // Connection draining, which is the orchestrator's job and not the
    // product's: a request already dispatched to this replica must finish
    // before the process goes. Each driver runs one request at a time, so
    // once two more requests have completed anywhere, the at-most-one that
    // was in flight to this replica is among them.
    //
    // `stop` is the drain path on every platform (`SIGTERM` on unix,
    // `Ctrl+Break` on Windows) and the gateway finishes what it is
    // holding, so this wait is belt and braces: it keeps the row's subject
    // the rollout discipline rather than the product's in-flight drain,
    // which `tests/lifecycle_shutdown.rs` pins on its own.
    drain_in_flight(completed, 2).await;

    cluster.replica_mut(name).restart().await;
    wait_until_ready(cluster.replica(name), JOIN_BUDGET).await;

    cluster.balancer.set_targets(
        cluster
            .replicas
            .iter()
            .map(|replica| Target {
                name: replica.name.clone(),
                base_url: replica.base_url(),
            })
            .collect(),
    );
}

/// **The rollout that works: no migration, no configuration change.**
///
/// Every replica is replaced, one at a time, while proxied traffic and
/// conditional control-plane writes continue. Nothing is refused, every
/// commit lands, the version numbers are contiguous, and the document both
/// replicas serve at the end is the last one written.
///
/// This is the shape the fingerprint gate and the schema ledger both
/// admit, and it is therefore the only rolling upgrade this product
/// supports today with no window of reduced service. The three rows below
/// are the three ways to leave it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_migration_free_rollout_replaces_every_replica_without_dropping_a_request() {
    let Some(mut cluster) = start_rollout_cluster(2).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    cluster.balancer.round_robin();

    let stop = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicUsize::new(0));
    let traffic = tokio::spawn(drive_traffic(
        cluster.balancer.base_url.clone(),
        admin.clone(),
        Arc::clone(&stop),
        Arc::clone(&completed),
    ));
    let control_plane = tokio::spawn(drive_control_plane(
        cluster.balancer.base_url.clone(),
        admin.clone(),
        cluster.seed_policy_etag.clone(),
        Arc::clone(&stop),
        Arc::clone(&completed),
    ));

    // The rollout itself: b first, then a, each gated on its own
    // readiness before it takes traffic again.
    let started = Instant::now();
    for name in ["b", "a"] {
        roll_one(&mut cluster, name, &completed).await;
    }
    let rollout = started.elapsed();

    stop.store(true, Ordering::Relaxed);
    let traffic = traffic.await.expect("the traffic task should not panic");
    let control_plane = control_plane
        .await
        .expect("the control-plane task should not panic");

    // 1. Not one proxied request was refused.
    //
    // The count guard is a floor, not a target: it exists so a traffic
    // task that never ran cannot pass this row by refusing nothing.
    assert!(
        traffic.attempts >= 10,
        "the traffic task made only {} attempts across a {rollout:?} rollout, which is too \
         few to have covered either replacement",
        traffic.attempts
    );
    assert!(
        traffic.refusals.is_empty(),
        "a migration-free rolling replacement must not refuse a request; {} of {} were \
         refused, first: {:?}",
        traffic.refusals.len(),
        traffic.attempts,
        traffic.refusals.first()
    );

    // 2. Every conditional control-plane write landed, and the authority
    //    holds exactly the seed plus those commits, contiguously.
    assert!(
        control_plane.commits.len() >= 3,
        "the control-plane task landed only {} commits across a {rollout:?} rollout",
        control_plane.commits.len()
    );
    assert!(
        control_plane.failures.is_empty(),
        "a conditional write during a migration-free rollout must not fail; {} of {} did, \
         first: {:?}",
        control_plane.failures.len(),
        control_plane.commits.len() + control_plane.failures.len(),
        control_plane.failures.first()
    );
    let versions = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.policy_documents")
        .await;
    assert_eq!(
        versions as usize,
        control_plane.commits.len() + 1,
        "the authority should hold the seed plus one row per commit"
    );
    let gaps = cluster
        .database
        .count(
            "SELECT (max(version) - min(version) + 1 - count(*))::bigint \
             FROM greengateway.policy_documents",
        )
        .await;
    assert_eq!(
        gaps, 0,
        "the policy history must be contiguous across a rollout: {gaps} version number(s) \
         are missing"
    );

    // 3. Both replicas serve the last document written, and neither is
    //    serving the one it booted with.
    let last = control_plane
        .commits
        .last()
        .expect("at least one commit landed")
        .clone();
    for name in ["a", "b"] {
        let (status, headers, body) = cluster
            .get(name, &policy_route())
            .bearer(&admin)
            .send_with_headers()
            .await;
        assert_eq!(
            status, 200,
            "replica {name} should serve the policy: {body}"
        );
        assert!(
            body["roles"].get(&last).is_some(),
            "replica {name} should serve the last committed document ({last}), and served \
             {body}"
        );
        let etag = headers
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert_eq!(
            etag, control_plane.final_etag,
            "replica {name} should serve the ETag the last commit returned"
        );
    }

    // 4. The deployment is two ready replicas again, from its own roster's
    //    point of view and not just from the probes'.
    wait_for_ready_replicas(&cluster, "a", &admin, 2, JOIN_BUDGET).await;

    cluster.shutdown();
}

// =====================================================================
// Row 2 — the configuration change that stalls
// =====================================================================

/// **PR 13's fingerprint gate: a new configuration stalls rather than
/// serving.**
///
/// A replica whose static configuration differs from a live member's is
/// held at `503 config_fingerprint_mismatch` for as long as that member is
/// live. The incumbents are unaffected — agreement is granted once and is
/// sticky (`cluster_membership::check_fingerprint_agreement` returns early
/// for an already-agreed replica), which is exactly what keeps a rollout
/// from taking the cluster down when its first new-configuration replica
/// arrives.
///
/// The row then measures the cost the parent contract names: the change
/// completes **only after the old set has drained**. There is no ordering
/// of starts and stops that gets a fingerprint change through with two
/// replicas serving throughout, because the gate is defined against live
/// membership rather than against a rollout's intent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_static_configuration_stalls_at_the_gate_instead_of_serving_mismatched() {
    let Some(mut cluster) = start_rollout_cluster(2).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    // The new-configuration replica. One setting differs; the fingerprint
    // therefore differs; nothing else about it does.
    let mut upgraded = ExtraReplica::spawn(
        &cluster,
        "c",
        &[(FINGERPRINT_SETTING, FINGERPRINT_SETTING_NEW_VALUE)],
    )
    .await;

    // 1. It is held at the gate, with that reason and no other, for the
    //    whole window — not merely at the instant we happened to look.
    wait_for_reason(
        &upgraded.replica,
        CONFIG_FINGERPRINT_MISMATCH,
        AUTHORITY_BUDGET,
    )
    .await;
    assert_stalled_across(
        &upgraded.replica,
        CONFIG_FINGERPRINT_MISMATCH,
        Duration::from_secs(5),
    )
    .await;

    // 2. The incumbents never left ready across that same window. This is
    //    the half that makes the gate usable: a rollout's first new
    //    replica must not take the deployment with it.
    assert_ready_across(
        &cluster,
        Duration::from_secs(3),
        "while a mismatched replica is live",
    )
    .await;

    // 3. The disagreement is visible where an operator looks. The roster
    //    carries two distinct fingerprints, the mismatched replica
    //    publishes the alert series and the incumbents do not.
    let fingerprints = cluster
        .database
        .count(
            "SELECT count(DISTINCT fingerprint)::bigint FROM greengateway.cluster_members \
             WHERE draining_at IS NULL",
        )
        .await;
    assert_eq!(
        fingerprints, 2,
        "the roster should carry the incumbents' fingerprint and the new one"
    );
    let upgraded_metrics = scrape_metrics(&upgraded.base_url()).await;
    assert!(
        upgraded_metrics.contains("greengateway_cluster_config_mismatch 1"),
        "the mismatched replica should publish greengateway_cluster_config_mismatch 1"
    );
    let incumbent_metrics = cluster.metrics("a").await;
    assert!(
        incumbent_metrics.contains("greengateway_cluster_config_mismatch 0"),
        "an incumbent that already agreed should publish \
         greengateway_cluster_config_mismatch 0"
    );

    // 4. And what the *status* surface says, which is not what an
    //    operator might assume. A stalled member is a difference between
    //    `replicas.ready` and `replicas.total`; it is NOT a degraded
    //    cluster. `cluster_status::state_and_reason` degrades on four
    //    conditions and "a live member is not ready" is not one of them —
    //    `replicas_unavailable` means the roster read itself failed. A
    //    rollout stuck at the gate therefore shows as `ready` with a
    //    short count, and this row pins that so the alert thresholds in
    //    the deployment guide are written against the truth.
    let deadline = Instant::now() + JOIN_BUDGET;
    let status = loop {
        let status = cluster_status(&cluster, "a", &admin).await;
        if status["replicas"]["total"] == 3 {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "the roster never showed the third member within {JOIN_BUDGET:?}: {status}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(
        status["replicas"]["ready"], 2,
        "two of the three live members are ready: {status}"
    );
    assert_eq!(
        status["state"], "ready",
        "a member held at the fingerprint gate does not degrade the cluster's state: {status}"
    );
    assert_eq!(
        status["reason"],
        Value::Null,
        "and carries no cluster-level reason: {status}"
    );

    // 5. The strategy the gate admits, and its price. Drain the old set
    //    completely; only then does the new configuration become ready.
    //    The deployment serves nothing between the last incumbent leaving
    //    and this replica passing the gate, and that window is the
    //    "zero unavailability is not available" result.
    cluster.shutdown();
    // Down to one live member — the new configuration's own row. The
    // harness's `wait_until_no_live_members` cannot be used here: this
    // deployment still has a replica in it, and it is the one whose
    // readiness is the point.
    wait_for_live_members(&cluster, 1, Duration::from_millis(STALE_WINDOW_MS * 8)).await;
    wait_until_ready(&upgraded.replica, JOIN_BUDGET).await;

    upgraded.replica.stop();
}

/// **The sharp edge of that strategy: an incumbent that restarts
/// mid-rollout loses its agreement.**
///
/// Fingerprint agreement is granted once, in the process that earned it,
/// and is not persisted anywhere. A replica that restarts starts again at
/// "not agreed" and must re-read the roster — which, mid-rollout, contains
/// a live member it disagrees with. So a rollout that has started placing
/// new-configuration replicas cannot restart an old one, for any reason,
/// without that one stalling too.
///
/// This is asserted rather than merely documented because it is the
/// failure an operator meets by accident: a crash, an eviction, or a
/// node-drain during a configuration rollout is not an unusual event, and
/// the resulting `503` looks nothing like its cause.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarting_an_incumbent_while_a_new_configuration_is_live_costs_it_its_agreement() {
    let Some(mut cluster) = start_rollout_cluster(2).await else {
        return skipped();
    };

    let mut upgraded = ExtraReplica::spawn(
        &cluster,
        "c",
        &[(FINGERPRINT_SETTING, FINGERPRINT_SETTING_NEW_VALUE)],
    )
    .await;
    wait_for_reason(
        &upgraded.replica,
        CONFIG_FINGERPRINT_MISMATCH,
        AUTHORITY_BUDGET,
    )
    .await;

    // b was ready a moment ago and is about to be ready no longer, having
    // changed nothing about itself.
    let (status, _) = cluster.replica("b").readyz().await;
    assert_eq!(status, 200, "b should be ready before it is restarted");

    cluster.replica_mut("b").restart().await;
    wait_for_reason(
        cluster.replica("b"),
        CONFIG_FINGERPRINT_MISMATCH,
        AUTHORITY_BUDGET,
    )
    .await;
    assert_stalled_across(
        cluster.replica("b"),
        CONFIG_FINGERPRINT_MISMATCH,
        Duration::from_secs(3),
    )
    .await;

    // a, which did not restart, is still serving on its sticky agreement.
    let (status, body) = cluster.replica("a").readyz().await;
    assert_eq!(
        status, 200,
        "the replica that did not restart keeps its agreement, and said {body}"
    );

    // Removing the new configuration frees b again: the gate is about live
    // membership, so it opens as soon as the disagreement stops being
    // live. (Killed rather than stopped, so the row ages out of the stale
    // window instead of stamping itself draining — the crash-shaped exit,
    // which is the harder one for the gate to notice.)
    upgraded.replica.kill();
    wait_until_ready(cluster.replica("b"), JOIN_BUDGET).await;

    cluster.shutdown();
}

// =====================================================================
// Row 3 — the migration that stalls
// =====================================================================

/// **A migration applied mid-rollout has no overlap window.**
///
/// `storage::migrations::schema_version_range()` answers `(len, len)`: the
/// accepted range is a single point, and the module says why — the ledger
/// rules admit exactly one shape, a checksum-matching prefix covering the
/// whole manifest, so a replica tolerates neither a ledger behind its
/// manifest nor one ahead of it.
///
/// The consequence for a rolling upgrade is total: the instant the new
/// version's `migrate up` commits, every replica still running the old
/// version is `schema_incompatible` and serves nothing. There is no
/// ordering that avoids it, because there is no pair of versions that
/// accepts the same ledger.
///
/// `docs/architecture/ha-state-model.md` §7 currently claims
/// "expand/contract so version N and N+1 binaries coexist". That is a
/// design intent the code has not implemented, and this row asserts the
/// code: the range is a point, and the stall is total. The advertised
/// range is a *pair* precisely so a future release can widen it without a
/// schema change — and the day it widens, this row fails and says so.
///
/// The row also pins something the state model does not say: this is a
/// **readiness** refusal, not a request refusal. A replica whose ledger it
/// does not accept keeps serving whatever is still routed to it. See step
/// 3b, which asserts that and explains why it makes the load balancer's
/// `/readyz` wiring load-bearing rather than advisory.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expand_migration_has_no_overlap_window_so_it_cannot_roll() {
    let Some(mut cluster) = start_rollout_cluster(2).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    cluster.balancer.round_robin();

    // 1. The structural reason, read from the product rather than assumed:
    //    the accepted schema range this binary advertises is one number
    //    wide.
    let status = cluster_status(&cluster, "a", &admin).await;
    let minimum = status["schema"]["binary_min"]
        .as_i64()
        .unwrap_or_else(|| panic!("the binary minimum should be reported: {status}"));
    let maximum = status["schema"]["binary_max"]
        .as_i64()
        .unwrap_or_else(|| panic!("the binary maximum should be reported: {status}"));
    assert_eq!(
        minimum, maximum,
        "this binary advertises a schema range of [{minimum}, {maximum}]. A range wider than \
         one point would mean a rolling upgrade across a migration is possible, and this row \
         — which asserts that it is not — is the thing to rewrite"
    );

    let dispatched_before = proxied_count(&cluster);
    let highest: i64 = cluster
        .database
        .query_one(&format!(
            "SELECT coalesce(max(version), 0)::bigint FROM {LEDGER_TABLE}"
        ))
        .await
        .get(0);

    // 2. The newer version migrates the shared database. Nothing else
    //    about the deployment changes.
    let mut ledger =
        LedgerRow::insert_above_the_manifest(&cluster.database.migrator_dsn, highest).await;

    // 3. Every replica still on the old binary refuses readiness — every
    //    one of them, because the range is a point and they all share the
    //    ledger. There is no surviving member for a rollout to lean on.
    for replica in &cluster.replicas {
        wait_for_reason(replica, SCHEMA_INCOMPATIBLE, AUTHORITY_BUDGET).await;
    }

    // 3b. And the part that is worth stating precisely, because it is not
    //     what a reader of the state model would assume: this is a
    //     *readiness* refusal and not a request refusal. The authority is
    //     perfectly reachable, the security-revision gate is satisfied,
    //     and the request path has no schema check of its own — so a
    //     replica held out of rotation by `/readyz` keeps answering
    //     anything still routed to it, and keeps dispatching upstream.
    //
    //     The operational consequence is the whole reason to assert it: a
    //     load balancer whose health check is not wired to `/readyz`, or
    //     is wired with a long failure threshold, will serve production
    //     traffic from replicas running against a schema they have
    //     declared they do not understand. The deployment guide's
    //     "point the health check at /readyz" is load-bearing, not
    //     advisory.
    let mut served = 0_usize;
    for _ in 0..5 {
        let response = harness::http_client()
            .get(format!("{}{PROXIED_PATH}", cluster.balancer.base_url))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("the balancer should answer");
        if response.status().as_u16() == 200 {
            served += 1;
        }
    }
    assert_eq!(
        served, 5,
        "a schema_incompatible replica refuses readiness, not requests; if it began refusing \
         requests too, this row and the deployment guide's health-check advice both change"
    );
    assert!(
        proxied_count(&cluster) > dispatched_before,
        "and those requests reached the upstream, which is what makes the readiness signal \
         the only thing keeping such a replica out of rotation"
    );

    let status = cluster_status(&cluster, "a", &admin).await;
    assert_eq!(
        status["reason"], SCHEMA_INCOMPATIBLE,
        "the cluster status must agree with /readyz word for word: {status}"
    );
    assert_eq!(
        status["schema"]["compatible"],
        Value::Bool(false),
        "the status should report the schema as incompatible: {status}"
    );

    // 4. Recovery is the operator finishing the upgrade — here, removing
    //    the row the newer binary would have left. The deployment comes
    //    back without a restart.
    ledger.revert().await;
    for replica in &cluster.replicas {
        wait_until_ready(replica, AUTHORITY_BUDGET).await;
    }
    let response = harness::http_client()
        .get(format!("{}{PROXIED_PATH}", cluster.balancer.base_url))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("the balancer should answer");
    assert_eq!(
        response.status().as_u16(),
        200,
        "the deployment should serve again once the ledger matches the manifest"
    );

    cluster.shutdown();
}

// =====================================================================
// Row 4 — the document version
// =====================================================================

/// **The old binary never parses, and never serves, a document version it
/// does not support.**
///
/// The parent contract's central claim, made executable with the one
/// binary that exists. A newer replica's commit is written straight to the
/// authority — same six steps, same order, same outbox row as a real
/// commit — first at a `schema_version` this binary accepts, to prove the
/// injection path works, and then at one it does not.
///
/// What must happen at that point is not "an error somewhere". It is:
/// the document is never compiled, no request is ever served under the
/// allow state the replica had before it, readiness is refused with
/// `security_revision_not_compiled` once the reconcile deadline passes,
/// and the refusal is predictable from what the replica advertises —
/// `cluster_membership::DOCUMENT_VERSION_RANGE` is `(0, 0)` and the
/// injected document's major is `1`.
///
/// One replica, because the claim is about one binary meeting one
/// document, and because the row already costs the 30 s of
/// `RECONCILE_BACKGROUND_DEADLINE` that nothing can shorten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unsupported_document_version_is_never_compiled_and_never_served() {
    let Some(mut cluster) = start_rollout_cluster(1).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");
    let authority = Authority::connect(&cluster.database.migrator_dsn).await;

    // 0. The advertised window, read from the product. Everything below
    //    is a consequence of this pair being (0, 0) — the replica tells
    //    the deployment, on its own roster row, which document majors it
    //    can carry.
    let roster = cluster_replicas(&cluster, "a", &admin).await;
    let member = roster
        .first()
        .unwrap_or_else(|| panic!("the roster should carry this replica: {roster:?}"));
    assert_eq!(
        member["document_version_min"], 0,
        "the advertised document range should start at 0: {member}"
    );
    assert_eq!(
        member["document_version_max"], 0,
        "the advertised document range should end at 0, which is why a 1.x document is \
         refused: {member}"
    );

    // 1. The control. A document written by this same path, at a version
    //    this binary does accept, IS adopted — so everything that follows
    //    is attributable to the version and not to the injection.
    let supported = policy_document(Some("written-by-a-peer"));
    let (_, _, supported_etag) = authority.activate(&supported, "peer-replica").await;
    let deadline = Instant::now() + AUTHORITY_BUDGET;
    loop {
        let (status, headers, body) = cluster
            .get("a", &policy_route())
            .bearer(&admin)
            .send_with_headers()
            .await;
        let etag = headers
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        if status == 200 && etag == supported_etag {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the replica should have adopted a supported document written straight to the \
             authority within {AUTHORITY_BUDGET:?}; it last said {status} {body}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (status, _) = cluster.replica("a").readyz().await;
    assert_eq!(
        status, 200,
        "the replica is ready on the supported document"
    );

    // 2. Now the newer version's document, at a major this binary does not
    //    carry.
    let (unsupported_version, unsupported_revision, _) = authority
        .activate(&unsupported_document(), "peer-replica")
        .await;

    // 3. Wait for the replica to have *observed* the change, and say
    //    plainly what that wait is.
    //
    //    The guarantee is bounded staleness, not instantaneous knowledge:
    //    the runtime serves under its compiled revision, and a request
    //    that arrives before this replica has read the authority's counter
    //    again is served under the policy it had. That window is the
    //    design (`security_cluster.rs`: "a request serves under
    //    `compiled_revision`"), it is bounded by the poller, and pretending
    //    it does not exist would make this row assert something the
    //    product does not claim.
    //
    //    What the product does claim begins here, the moment the lag is
    //    visible: from now on nothing is served under the old allow.
    //    `/metrics` rather than the admin API, because the admin surfaces
    //    are authorized against the very policy that cannot be compiled
    //    and answer `503 policy state unavailable` for the whole of the
    //    rest of this row.
    let lag_deadline = Instant::now() + AUTHORITY_BUDGET;
    loop {
        let metrics = cluster.metrics("a").await;
        if metrics.lines().any(|line| {
            line.starts_with("greengateway_security_revision_lag ")
                && line != "greengateway_security_revision_lag 0"
        }) {
            break;
        }
        assert!(
            Instant::now() < lag_deadline,
            "the replica never observed the new revision within {AUTHORITY_BUDGET:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let dispatched_before = proxied_count(&cluster);

    // 4. From that point it is never served. Sampled across the whole
    //    reconcile grace and past it: a replica that answered one request
    //    under its old compiled allow, at any point in that window, has
    //    taken a security decision on a policy the authority has replaced.
    let sampling_deadline = Instant::now() + REVISION_BUDGET;
    let mut reason_seen = false;
    while Instant::now() < sampling_deadline {
        let response = harness::http_client()
            .get(format!("{}{PROXIED_PATH}", cluster.replica("a").base_url()))
            .bearer_auth(&admin)
            .send()
            .await
            .expect("the replica should answer");
        assert!(
            response.status().as_u16() >= 500,
            "a request must never be served under a document version the replica could not \
             compile; it answered {}",
            response.status()
        );
        let (status, body) = cluster.replica("a").readyz().await;
        assert_reason_is_in_the_vocabulary("a", &body);
        if status == 503 && body["reason"] == SECURITY_REVISION_NOT_COMPILED {
            reason_seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        reason_seen,
        "the replica never reported {SECURITY_REVISION_NOT_COMPILED:?} within \
         {REVISION_BUDGET:?} of a document it cannot compile"
    );
    assert_eq!(
        proxied_count(&cluster),
        dispatched_before,
        "not one request may reach the upstream once the replica knows the active document \
         has moved past what it can compile"
    );

    // 5. The authority's own numbers say what happened: the pointer moved,
    //    the counter advanced, and this replica's compiled watermark did
    //    not follow.
    let active_version: i64 = cluster
        .database
        .query_one("SELECT active_version FROM greengateway.policy_active WHERE singleton")
        .await
        .get(0);
    assert_eq!(
        active_version, unsupported_version,
        "the unsupported document is the active one; the replica's refusal is not a failure \
         to see it"
    );
    let metrics = cluster.metrics("a").await;
    assert!(
        metrics.lines().any(
            |line| line.starts_with("greengateway_security_revision_lag ")
                && line != "greengateway_security_revision_lag 0"
        ),
        "the replica should publish a non-zero security revision lag while it cannot compile \
         the active document"
    );

    // 6. Recovery is forward, never backward: revisions are monotonic, so
    //    an operator rolls to a document this binary supports rather than
    //    winding the counter back. The replica compiles it and serves it.
    let recovered = policy_document(Some("rolled-forward"));
    let (_, recovered_revision, recovered_etag) =
        authority.activate(&recovered, "operator@ha.test").await;
    assert!(
        recovered_revision > unsupported_revision,
        "the recovery must advance the revision counter, never rewind it"
    );
    wait_until_ready(cluster.replica("a"), REVISION_BUDGET).await;
    let (status, headers, body) = cluster
        .get("a", &policy_route())
        .bearer(&admin)
        .send_with_headers()
        .await;
    assert_eq!(status, 200, "the replica should serve again: {body}");
    assert!(
        body["roles"].get("rolled-forward").is_some(),
        "the replica should serve the document it was rolled forward to, and served {body}"
    );
    assert_eq!(
        headers
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
        recovered_etag,
        "and at that document's ETag"
    );
    let response = harness::http_client()
        .get(format!("{}{PROXIED_PATH}", cluster.replica("a").base_url()))
        .bearer_auth(&admin)
        .send()
        .await
        .expect("the replica should answer");
    assert_eq!(
        response.status().as_u16(),
        200,
        "and the data plane serves again"
    );

    cluster.shutdown();
}

/// **The other half: this binary will not *write* a version it does not
/// support either.**
///
/// The read side above is what protects a replica from a newer peer. This
/// is what protects the deployment from the replica: an administrator
/// pointed at an old replica during a rollout, submitting a document
/// written for the new one, must be refused at the door — with a `4xx`,
/// because the request is wrong rather than the deployment — and must
/// leave the authority untouched.
///
/// The control matters as much as the claim: the identical request at a
/// supported version succeeds, so the refusal is the version's doing and
/// not the route's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn this_binary_refuses_to_write_a_document_version_it_does_not_support() {
    let Some(mut cluster) = start_rollout_cluster(1).await else {
        return skipped();
    };
    let admin = admin_token(&cluster.oidc, "admin@ha.test");

    let versions_before = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.policy_documents")
        .await;
    let active_before: i64 = cluster
        .database
        .query_one("SELECT active_version FROM greengateway.policy_active WHERE singleton")
        .await
        .get(0);

    let (status, body) = cluster
        .put("a", &policy_route())
        .bearer(&admin)
        .if_match(&cluster.seed_policy_etag)
        .json(
            &serde_json::from_str::<Value>(&unsupported_document())
                .expect("the unsupported document is JSON"),
        )
        .send()
        .await;
    assert!(
        (400..500).contains(&status),
        "a document at an unsupported version is a bad request, not a server failure and not \
         an accepted write; the replica answered {status}: {body}"
    );

    let versions_after = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.policy_documents")
        .await;
    assert_eq!(
        versions_before, versions_after,
        "a refused write must append no policy version"
    );
    let active_after: i64 = cluster
        .database
        .query_one("SELECT active_version FROM greengateway.policy_active WHERE singleton")
        .await
        .get(0);
    assert_eq!(
        active_before, active_after,
        "a refused write must not move the active pointer"
    );

    // The control: the same route, the same precondition, a supported
    // version — accepted.
    let (status, body) = cluster
        .put("a", &policy_route())
        .bearer(&admin)
        .if_match(&cluster.seed_policy_etag)
        .json(
            &serde_json::from_str::<Value>(&policy_document(Some("supported")))
                .expect("the supported document is JSON"),
        )
        .send()
        .await;
    assert_eq!(
        status, 200,
        "the same write at a supported version must succeed, or the refusal above proves \
         nothing about versions: {body}"
    );

    cluster.shutdown();
}

// =====================================================================
// The substitution, named twice
// =====================================================================

/// **Not injectable: two binaries.**
///
/// The mixed-version half of the parent contract — "build the previous
/// release tag's binary and the current one, run mixed replicas" — cannot
/// be built from anything this repository has released. The newest tag,
/// v1.0.1 (2026-07-16), predates cluster mode entirely: its
/// `gateway/Cargo.toml` has no `postgres` feature, its `gateway/src` has
/// no `storage/` module, and `STATE_BACKEND=postgres` is not a setting it
/// knows. A v1.0.1 process cannot register a membership row, cannot read
/// the schema ledger, and cannot join a deployment; there is no
/// configuration under which it and a current binary form one cluster.
///
/// What the rows above substitute for it, and why each substitution is
/// faithful:
///
/// * **A newer binary's migration** →
///   [`an_expand_migration_has_no_overlap_window_so_it_cannot_roll`]
///   writes the ledger row `migrate up` would have written. The old binary
///   reads the ledger, not the other process, so what it sees is
///   identical.
/// * **A newer binary's control-plane write** →
///   [`an_unsupported_document_version_is_never_compiled_and_never_served`]
///   writes the document through the authority in the same six steps and
///   the same order as a commit, with the revision counter advanced and
///   the outbox row appended. A serving replica reads the authority, not
///   the writer, so again what it sees is identical.
/// * **A newer binary's configuration** →
///   [`a_new_static_configuration_stalls_at_the_gate_instead_of_serving_mismatched`]
///   changes one fingerprint-covered setting on a real second process.
///   This substitution is the weakest of the three and it is worth saying
///   why: a genuine version change would alter the fingerprint *and* the
///   schema range *and* the document range at once, and the gate would
///   report whichever it evaluates first. Here only the fingerprint moves.
///
/// What no substitution reaches, and what the real row will have to add
/// when a cluster-capable release exists: a binary whose *code* differs —
/// an old parser meeting a new document shape it can deserialize but
/// misinterprets, a new column an old `SELECT *` does not expect, a
/// behaviour change inside a version both binaries call `0.1.0`. Those are
/// the failures a version range cannot catch, and only two binaries can
/// find them.
#[tokio::test]
#[ignore = "no released GreenGateway binary supports cluster mode; see the doc comment"]
async fn mixed_binary_replicas_need_a_release_that_ships_cluster_mode() {
    panic!(
        "this row is a placeholder for the mixed-binary rollout described in its doc comment. \
         It becomes writable when a release tag ships the `postgres` feature, which \
         the_newest_release_tag_still_predates_cluster_mode watches for."
    );
}

/// The tripwire that makes the substitution above expire.
///
/// A documented substitution is only honest while its reason holds. This
/// reads the newest `v*` tag on a different commit's `gateway/Cargo.toml` and
/// fails if it declares the `postgres` feature — because at that moment a
/// previous release's binary *can* be built and *can* join a cluster, and
/// the row above stops being a description of reality and becomes an
/// excuse.
/// Tags on HEAD name the current candidate, not a previous binary. This
/// distinction lets the first cluster-capable release pass its own tag CI;
/// subsequent commits still trip the guard until mixed-binary coverage exists.
///
/// It skips, loudly, when no tags are reachable: `actions/checkout@v4`
/// fetches no tags at its default depth, so the CI gate must set
/// `fetch-depth: 0` (or `fetch-tags: true`) for this to be live there. A
/// skip that says so is evidence; a silent pass is not.
#[tokio::test]
async fn the_newest_release_tag_still_predates_cluster_mode() {
    let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the gateway crate has a parent directory")
        .to_owned();

    let git = |arguments: &[&str]| -> Option<String> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(arguments)
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    };

    let Some(tags) = git(&["tag", "--list", "v*", "--sort=-v:refname"]) else {
        eprintln!(
            "skipping: git is not available here, so the previous release tag cannot be \
             inspected"
        );
        return;
    };
    let Some(newest) = previous_release_tag(&tags, &git) else {
        eprintln!(
            "skipping: no release tags on a different commit are available in this checkout, so the previous \
             release cannot be inspected. actions/checkout@v4 fetches no tags at its default \
             depth; the ha-release-gate job needs fetch-depth: 0 for this tripwire to be live \
             in CI."
        );
        return;
    };

    let Some(manifest) = git(&["show", &format!("{newest}:gateway/Cargo.toml")]) else {
        eprintln!("skipping: {newest} carries no gateway/Cargo.toml to inspect");
        return;
    };

    let ships_cluster_mode =
        manifest.contains("dep:tokio-postgres") || manifest.contains("tokio-postgres = {");
    assert!(
        !ships_cluster_mode,
        "release {newest} declares the PostgreSQL dependency, so a previous release's binary \
         can now be built and can now join a cluster. The documented substitution in \
         mixed_binary_replicas_need_a_release_that_ships_cluster_mode has expired: build \
         {newest} into a second binary, run it beside the current one against one database, \
         and assert the mixed-version claims for real."
    );
}

fn previous_release_tag(tags: &str, git: &impl Fn(&[&str]) -> Option<String>) -> Option<String> {
    let head = git(&["rev-parse", "--verify", "HEAD"]).expect("resolve the checked commit");
    tags.lines()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .find(|tag| {
            // Peel annotated tags as well as lightweight tags to their commit.
            let commit = git(&[
                "rev-parse",
                "--verify",
                &format!("refs/tags/{tag}^{{commit}}"),
            ])
            .expect("release tags must resolve to commits");
            commit.trim() != head.trim()
        })
        .map(str::to_owned)
}

#[test]
fn previous_release_selection_excludes_candidate_tags_but_keeps_cluster_releases() {
    let repository = TempDir::new("release-selection");
    let git = |arguments: &[&str]| -> Option<String> {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(repository.path())
            .args(arguments)
            .output()
            .expect("run git for the release-selection fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    };
    git(&["init"]);
    git(&["config", "user.name", "Release Test"]);
    git(&["config", "user.email", "release-test@example.invalid"]);
    git(&["config", "commit.gpgsign", "false"]);
    git(&["config", "tag.gpgsign", "false"]);
    git(&["commit", "--allow-empty", "-m", "SQLite release"]);
    git(&["tag", "v1.0.1"]);
    git(&["commit", "--allow-empty", "-m", "First cluster release"]);
    git(&["tag", "v2.0.0"]);
    git(&["tag", "-a", "v2.0.1", "-m", "Candidate alias"]);
    let tags = git(&["tag", "--list", "v*", "--sort=-v:refname"]).unwrap();
    assert_eq!(previous_release_tag(&tags, &git).as_deref(), Some("v1.0.1"));

    // Once HEAD advances, the cluster release must become the previous
    // binary again; its PostgreSQL manifest will still trip the guard above.
    git(&["commit", "--allow-empty", "-m", "Next candidate"]);
    assert_eq!(previous_release_tag(&tags, &git).as_deref(), Some("v2.0.1"));
    assert_eq!(previous_release_tag("", &git), None);
}
