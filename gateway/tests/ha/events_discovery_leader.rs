//! Events, the durable stream cursor, the discovery projector and the
//! maintenance singleton, across two replicas (issue #241, PR 16).
//!
//! The question this file asks is the twin of the security suite's: **is
//! there exactly one of each thing the deployment is supposed to have one
//! of, and does it survive the replica that owned it dying?** One stored
//! copy of an event however many times it was retried. One stream position
//! per committed event, in commit order, resumable from either replica.
//! One projector applying each observation exactly once, whichever replica
//! is leading when the batch lands. One maintenance owner, whose successor
//! is fenced past it rather than racing it.
//!
//! ## Where the events come from, and why the harness writes them
//!
//! Everything downstream of the durable audit stream is on this branch:
//! the store and its commit-ordered positions (PR 5), the cross-replica SSE
//! transport and its `Last-Event-ID` protocol (PR 6), the fenced discovery
//! projector (PR 11), audit retention's position floor and the maintenance
//! singleton (PR 13). The **runtime ingestion sink** that would feed the
//! stream from live traffic is not: nothing in the binary calls
//! `AuditEventStore::insert_events`, so a request a replica serves reaches
//! its file and broadcast sinks and stops there.
//!
//! So [`harness::Database::ingest_audit_events`] plays that one missing
//! part — the production statements, verbatim, in the production
//! transaction under the production advisory lock — and stamps each event
//! with a real member's instance and boot IDs, so an event "from replica
//! B" is genuinely provenanced to replica B's identity. Every consumer
//! under test is the real binary: the replicas' stream endpoints, their
//! projector, their leases, their fences. What is faked is the writer, and
//! only the writer; that is called out on each test whose claim depends on
//! it.
//!
//! ## Two matrix rows this file does not assert
//!
//! Both are recorded here rather than left to be inferred from absence.
//!
//! **The projector's third kill window.** The matrix names three — between
//! read and commit, after commit, and *during notification*. The first two
//! are asserted below. The third has no counterpart in the binary on this
//! branch: there is no `LISTEN`/`NOTIFY` anywhere in it, and a successor
//! learns of new work from its own idle poll (and, within one process, a
//! broadcast). Killing a leader "during notification" would therefore be
//! killing it during nothing. The window becomes real, and this file
//! incomplete, the moment a database notification is introduced.
//!
//! **Clock skew.** The matrix asks for a replica whose *wall clock* is
//! skewed by a test hook, showing database-time behaviour unchanged. The
//! product has no such hook, and adding one is a change to shipping code
//! that a test-only PR should not make; nothing here fakes it, because a
//! skew this suite could apply (to its own process, or to the database it
//! shares with every other suite on the server) would not be the thing the
//! row is about. The row is open, and the harness's rule that every wait
//! reads database time is what stands in for it in the meantime.
//!
//! Skips silently without `GATEWAY_TEST_POSTGRES_URL_FILE`, like every
//! other PostgreSQL-backed suite in this repository.

#![cfg(feature = "postgres")]

mod harness;

use std::{collections::BTreeMap, future::Future, time::Duration};

use serde_json::json;

use harness::{
    oidc, sse, AuditEventSeed, AuthShape, Cluster, ClusterOptions, MemberIdentity, SeedActor,
};

/// The role the suite's admin token carries, granted everything by the
/// seeded policy: this file is about cluster agreement, not about which
/// permission guards the stream endpoint.
const ADMIN_ROLE: &str = "ha-admin";

/// The stream endpoint under test.
const EVENTS_STREAM_PATH: &str = "/v1/admin/events/stream";

/// How long a cross-replica effect may take before the test calls it a
/// failure. Generous on purpose: this machine runs other builds, and every
/// wait is a bounded poll that returns the moment its condition holds.
const CONVERGENCE_BUDGET: Duration = Duration::from_secs(60);

/// How long a frame may take to travel from a committed row to a streaming
/// client. The durable stream polls on its own idle cadence (500 ms) as
/// well as on the local broadcast wake-up, and cross-replica events have
/// only the poll.
const FRAME_BUDGET: Duration = Duration::from_secs(20);

/// The interval the maintenance singleton runs its pass on, and the TTL of
/// the lease that elects it. Both at (or just above) the configured floor,
/// so a failover is observable in seconds rather than in the production
/// minute.
const MAINTENANCE_INTERVAL_MS: u64 = 1_000;
const MAINTENANCE_LEASE_TTL_MS: u64 = 2_000;

/// The projector's cadence: poll at the configured floor and hold its
/// leadership lease for a second, so a killed leader's slot lapses inside
/// a test's patience instead of the production fifteen.
const PROJECTOR_POLL_MS: u64 = 50;
const PROJECTOR_LEASE_TTL_MS: u64 = 1_000;

fn skipped() {
    eprintln!("skipping: no test database locator, or this run is not the gate; the ha-release-gate CI job runs this suite");
}

/// A policy that grants [`ADMIN_ROLE`] everything and leaves the data
/// plane open. Exactly the fields `rbac::Policy` serializes, so the
/// harness can compute the ETag the gateway will compute.
fn admin_policy() -> String {
    json!({
        "default_action": "allow",
        "enforcement_mode": "enforce",
        "roles": { ADMIN_ROLE: { "permissions": ["*"] } },
        "routes": [],
        "rules": [],
        "schema_version": "0.1.0",
    })
    .to_string()
}

/// The cadence settings every replica in this file shares. None of them is
/// read by the static-configuration fingerprint, but they are applied to
/// both replicas anyway: a cluster whose members disagreed about how often
/// to contend for a singleton would be testing the disagreement.
fn cadence_environment() -> Vec<(String, String)> {
    vec![
        (
            "CLUSTER_MAINTENANCE_INTERVAL_MS".to_owned(),
            MAINTENANCE_INTERVAL_MS.to_string(),
        ),
        (
            "CLUSTER_MAINTENANCE_LEASE_TTL_MS".to_owned(),
            MAINTENANCE_LEASE_TTL_MS.to_string(),
        ),
        (
            "DISCOVERY_PROJECTOR_POLL_MS".to_owned(),
            PROJECTOR_POLL_MS.to_string(),
        ),
        (
            "DISCOVERY_PROJECTOR_LEASE_TTL_MS".to_owned(),
            PROJECTOR_LEASE_TTL_MS.to_string(),
        ),
    ]
}

/// Start a two-replica cluster with the suite's cadence, plus whatever
/// else the caller asked for.
///
/// Filled in field by field rather than with struct-update syntax: a field
/// listed in a literal wins over `..options`, which would silently discard
/// a caller's own `shared_env`.
async fn start_cluster(mut options: ClusterOptions) -> Option<Cluster> {
    let mut environment = cadence_environment();
    environment.append(&mut options.shared_env);
    options.shared_env = environment;
    if options.auth == AuthShape::Oidc && options.seed_policy.is_none() {
        options.seed_policy = Some(admin_policy());
    }
    let mut cluster = Cluster::start(options).await?;
    cluster.wait_until_all_ready().await;
    Some(cluster)
}

/// A token the seeded policy grants everything to.
fn admin_token(cluster: &Cluster) -> String {
    cluster.oidc.mint_role_token(
        oidc::PRIMARY_KID,
        "streamer@ha.test",
        &format!("jti-{}", uuid::Uuid::new_v4().simple()),
        &[ADMIN_ROLE],
        3_600,
    )
}

/// Poll `probe` until it answers `Some`, or fail saying what never
/// happened.
///
/// Every wait in this file goes through here: a bounded poll on an
/// observable condition, never a sleep sized to guess how long a leader
/// takes to notice a slot is free.
async fn wait_until<T, F, Fut>(budget: Duration, description: &str, mut probe: F) -> T
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Option<T>>,
{
    let deadline = std::time::Instant::now() + budget;
    loop {
        if let Some(value) = probe().await {
            return value;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "{description} did not happen within {budget:?}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// A fixed, ordered RFC 3339 timestamp. Derived from a constant epoch and
/// an offset, never from the test process's clock: these values decide
/// aggregate recency ordering and retention eligibility, and a suite that
/// read `now()` would be asserting about when it happened to run.
fn timestamp(offset_seconds: i64) -> String {
    // 2026-01-01T00:00:00Z.
    const BASE: i64 = 1_767_225_600;
    time::OffsetDateTime::from_unix_timestamp(BASE + offset_seconds)
        .expect("the harness epoch offset should be a valid instant")
        .format(&time::format_description::well_known::Rfc3339)
        .expect("an OffsetDateTime should format as RFC 3339")
}

/// Stamp a batch alternately with each live member's identity, so the
/// deployment's stored events genuinely carry both replicas' provenance.
fn attribute(events: Vec<AuditEventSeed>, members: &[MemberIdentity]) -> Vec<AuditEventSeed> {
    assert!(
        !members.is_empty(),
        "attributing events needs at least one live member"
    );
    events
        .into_iter()
        .enumerate()
        .map(|(index, event)| {
            let member = members[index % members.len()];
            event.attributed_to(member.instance_id, member.boot_id)
        })
        .collect()
}

// ---------------------------------------------------------------------
// The durable stream: stored once, positioned in commit order
// ---------------------------------------------------------------------

/// A batch retried after an ambiguous commit is stored once, positioned
/// once, and streamed once — and the retry burns no position, so the
/// stream stays gapless for the reader that follows it.
///
/// This is the property the whole cursor protocol rests on. An ingest
/// client cannot tell a `COMMIT` the server applied but never
/// acknowledged from one that rolled back, so it must retry; if the retry
/// stored a second copy, every consumer would double-count, and if it
/// reserved positions for rows it then did not insert, a contiguous
/// reader would wait forever at the hole.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_ambiguously_retried_batch_is_stored_positioned_and_streamed_exactly_once() {
    const EVENT_TYPE: &str = "ha.retry.probe";
    let Some(cluster) = start_cluster(ClusterOptions {
        auth: AuthShape::Oidc,
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    let members = cluster.member_identities().await;
    assert_eq!(members.len(), 2, "the cluster should have two live members");

    let head_before = cluster.database.stream_head().await;

    // Two disjoint batches, each attributed to both replicas.
    let first = attribute(
        (0..6)
            .map(|index| {
                AuditEventSeed::marker(EVENT_TYPE, &format!("/first/{index}"), &timestamp(index))
            })
            .collect(),
        &members,
    );
    let second = attribute(
        (0..4)
            .map(|index| {
                AuditEventSeed::marker(
                    EVENT_TYPE,
                    &format!("/second/{index}"),
                    &timestamp(100 + index),
                )
            })
            .collect(),
        &members,
    );

    // The ambiguous shape: commit, retry the identical batch, commit a
    // different batch, then retry BOTH — so the last retry carries ids
    // that already exist alongside none that do not, which is exactly the
    // case that would over-reserve positions if the append were not an
    // anti-join.
    cluster.database.ingest_audit_events(&first).await;
    cluster.database.ingest_audit_events(&first).await;
    cluster.database.ingest_audit_events(&second).await;
    let both = [first.clone(), second.clone()].concat();
    cluster.database.ingest_audit_events(&both).await;

    let expected: Vec<String> = both.iter().map(|event| event.event_id.clone()).collect();
    let stored: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.audit_events \
             WHERE event_type = '{EVENT_TYPE}'"
        ))
        .await;
    assert_eq!(
        stored,
        expected.len() as i64,
        "an at-least-once retry must leave exactly one stored row per event"
    );

    let streamed: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.audit_stream s \
             JOIN greengateway.audit_events e ON e.event_id = s.event_id \
             WHERE e.event_type = '{EVENT_TYPE}'"
        ))
        .await;
    assert_eq!(
        streamed,
        expected.len() as i64,
        "exactly one stream row must exist per stored event"
    );

    // Gapless: the positions these commits assigned are the contiguous
    // run after the head we started from. A retry that reserved a
    // position for an id it did not insert would show up here as a hole.
    let head_after = cluster.database.stream_head().await;
    assert_eq!(
        head_after - head_before,
        expected.len() as i64,
        "the retries must reserve no positions of their own"
    );
    let contiguous: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.audit_stream \
             WHERE position > {head_before} AND position <= {head_after}"
        ))
        .await;
    assert_eq!(
        contiguous,
        expected.len() as i64,
        "the committed stream must be gapless between {head_before} and {head_after}"
    );

    let provenances: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(DISTINCT instance_id)::bigint FROM greengateway.audit_events \
             WHERE event_type = '{EVENT_TYPE}'"
        ))
        .await;
    assert_eq!(
        provenances, 2,
        "the batch should carry both replicas' provenance"
    );

    // Queryable once: replay the whole run from the position we started
    // at and count what a consumer sees.
    let admin = admin_token(&cluster);
    let mut stream = sse::Request::new(
        &cluster.replica("a").base_url(),
        &format!("{EVENTS_STREAM_PATH}?event_type={EVENT_TYPE}"),
        &admin,
    )
    .resume_after(head_before)
    .open_ok()
    .await;
    let frames = stream.next_frames(expected.len(), FRAME_BUDGET).await;

    let mut positions: Vec<i64> = frames.iter().map(sse::Frame::position).collect();
    let sorted = {
        let mut sorted = positions.clone();
        sorted.sort_unstable();
        sorted
    };
    assert_eq!(
        positions, sorted,
        "the durable stream must deliver positions in order"
    );
    positions.dedup();
    assert_eq!(
        positions.len(),
        frames.len(),
        "no position may be delivered twice"
    );

    let mut delivered: Vec<String> = frames
        .iter()
        .map(|frame| frame.event_id().to_owned())
        .collect();
    delivered.sort();
    let mut wanted = expected;
    wanted.sort();
    assert_eq!(
        delivered, wanted,
        "each stored event must reach a consumer exactly once"
    );
}

/// A client streaming from one replica receives events it committed
/// nowhere near that replica.
///
/// Standalone mode's stream is an in-process broadcast: a subscriber on
/// replica A sees what replica A emitted and nothing else, which in a
/// cluster is a silently partial audit feed. These events are committed by
/// no replica's own process at all, so a broadcast-backed stream would
/// deliver none of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_on_one_replica_receives_events_committed_elsewhere() {
    const EVENT_TYPE: &str = "ha.elsewhere.probe";
    let Some(cluster) = start_cluster(ClusterOptions {
        auth: AuthShape::Oidc,
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    let members = cluster.member_identities().await;
    let admin = admin_token(&cluster);

    // Opened with no cursor: the stream starts at the committed head, so
    // everything it delivers was committed after it was opened.
    let mut stream = sse::Request::new(
        &cluster.replica("a").base_url(),
        &format!("{EVENTS_STREAM_PATH}?event_type={EVENT_TYPE}"),
        &admin,
    )
    .open_ok()
    .await;

    let batch = attribute(
        (0..3)
            .map(|index| {
                AuditEventSeed::marker(EVENT_TYPE, &format!("/live/{index}"), &timestamp(index))
            })
            .collect(),
        &members,
    );
    cluster.database.ingest_audit_events(&batch).await;

    let frames = stream.next_frames(batch.len(), FRAME_BUDGET).await;
    let mut delivered: Vec<String> = frames
        .iter()
        .map(|frame| frame.event_id().to_owned())
        .collect();
    delivered.sort();
    let mut committed: Vec<String> = batch.iter().map(|event| event.event_id.clone()).collect();
    committed.sort();
    assert_eq!(
        delivered, committed,
        "a stream on replica A should deliver a batch no replica's own process emitted"
    );

    // And it keeps following: a second commit arrives on the same open
    // stream without a reconnect.
    let more = attribute(
        (0..2)
            .map(|index| {
                AuditEventSeed::marker(
                    EVENT_TYPE,
                    &format!("/live/second/{index}"),
                    &timestamp(200 + index),
                )
            })
            .collect(),
        &members,
    );
    cluster.database.ingest_audit_events(&more).await;
    let followed = stream.next_frames(more.len(), FRAME_BUDGET).await;
    let mut followed_ids: Vec<String> = followed
        .iter()
        .map(|frame| frame.event_id().to_owned())
        .collect();
    followed_ids.sort();
    let mut wanted: Vec<String> = more.iter().map(|event| event.event_id.clone()).collect();
    wanted.sort();
    assert_eq!(
        followed_ids, wanted,
        "an open stream should keep following the deployment's commits"
    );
}

/// A client that disconnects from one replica and reconnects to the other
/// with its `Last-Event-ID` resumes exactly where it stopped: nothing
/// repeated, nothing skipped.
///
/// The cursor is a *deployment* position, not a per-replica one. If it
/// were per-replica — an offset into some local buffer, or a broadcast
/// subscription with no position at all — a reconnect through the other
/// replica would silently start somewhere else, and the gap would be
/// invisible to the client.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_reconnects_through_the_other_replica_without_a_gap() {
    const EVENT_TYPE: &str = "ha.reconnect.probe";
    const TOTAL: usize = 8;
    const READ_ON_A: usize = 3;
    let Some(cluster) = start_cluster(ClusterOptions {
        auth: AuthShape::Oidc,
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    let members = cluster.member_identities().await;
    let admin = admin_token(&cluster);
    let head_before = cluster.database.stream_head().await;

    let batch = attribute(
        (0..TOTAL as i64)
            .map(|index| {
                AuditEventSeed::marker(EVENT_TYPE, &format!("/gap/{index}"), &timestamp(index))
            })
            .collect(),
        &members,
    );
    cluster.database.ingest_audit_events(&batch).await;

    let path = format!("{EVENTS_STREAM_PATH}?event_type={EVENT_TYPE}");
    let mut on_a = sse::Request::new(&cluster.replica("a").base_url(), &path, &admin)
        .resume_after(head_before)
        .open_ok()
        .await;
    let first = on_a.next_frames(READ_ON_A, FRAME_BUDGET).await;
    let cursor = first
        .last()
        .expect("the first read should deliver frames")
        .position();
    // The disconnect: dropping the stream closes the connection, which is
    // what a client crashing or a load balancer moving it looks like.
    drop(on_a);

    let mut on_b = sse::Request::new(&cluster.replica("b").base_url(), &path, &admin)
        .resume_after(cursor)
        .open_ok()
        .await;
    let rest = on_b.next_frames(TOTAL - READ_ON_A, FRAME_BUDGET).await;

    assert_eq!(
        rest.first().map(sse::Frame::position),
        Some(cursor + 1),
        "the reconnect must resume at the position immediately after the cursor"
    );
    let mut seen: Vec<i64> = first
        .iter()
        .chain(rest.iter())
        .map(sse::Frame::position)
        .collect();
    let expected: Vec<i64> = (head_before + 1..=head_before + TOTAL as i64).collect();
    assert_eq!(
        seen, expected,
        "the two halves must join into the contiguous run with no gap and no repeat"
    );
    seen.dedup();
    assert_eq!(seen.len(), TOTAL, "no event may be delivered twice");

    let mut delivered: Vec<String> = first
        .iter()
        .chain(rest.iter())
        .map(|frame| frame.event_id().to_owned())
        .collect();
    delivered.sort();
    let mut wanted: Vec<String> = batch.iter().map(|event| event.event_id.clone()).collect();
    wanted.sort();
    assert_eq!(
        delivered, wanted,
        "the reconnecting client must see every committed event exactly once"
    );
}

/// A `Last-Event-ID` that is not a stream position is refused rather than
/// quietly interpreted.
///
/// The failure mode this rules out is a client whose header was mangled
/// silently starting at the head: it would then be *told* it was resuming
/// while missing everything between.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_resume_cursor_is_refused() {
    let Some(cluster) = start_cluster(ClusterOptions {
        auth: AuthShape::Oidc,
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    let admin = admin_token(&cluster);
    let response = harness::http_client()
        .get(format!(
            "{}{EVENTS_STREAM_PATH}",
            cluster.replica("a").base_url()
        ))
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .header("last-event-id", "not-a-position")
        .bearer_auth(&admin)
        .send()
        .await
        .expect("the stream endpoint should answer a malformed cursor");
    assert_eq!(
        response.status().as_u16(),
        400,
        "a cursor that is not a position must be refused, never reinterpreted"
    );
}

// ---------------------------------------------------------------------
// The discovery projector: one leader, fenced, exactly-once
// ---------------------------------------------------------------------

/// The projector's singleton row, as the deployment publishes it.
#[derive(Clone, Copy, Debug)]
struct ProjectorState {
    checkpoint: i64,
    fence: i64,
    projected_events: i64,
    leader: Option<uuid::Uuid>,
}

async fn projector_state(cluster: &Cluster) -> ProjectorState {
    let row = cluster
        .database
        .query_one(
            "SELECT checkpoint_position, fence, projected_events, leader_instance::text \
             FROM greengateway.discovery_projector_state WHERE singleton",
        )
        .await;
    ProjectorState {
        checkpoint: row.get::<_, i64>(0),
        fence: row.get::<_, i64>(1),
        projected_events: row.get::<_, i64>(2),
        leader: row
            .get::<_, Option<String>>(3)
            .map(|text| uuid::Uuid::parse_str(&text).expect("a leader instance should be a UUID")),
    }
}

/// Poll until the projector has committed through `position`.
async fn wait_until_projected(cluster: &Cluster, position: i64) -> ProjectorState {
    wait_until(
        CONVERGENCE_BUDGET,
        &format!("the projector committing through position {position}"),
        || async {
            let state = projector_state(cluster).await;
            (state.checkpoint >= position).then_some(state)
        },
    )
    .await
}

/// Which replica holds an instance ID, by the roster order the harness
/// spawns replicas in.
fn replica_of(members: &[MemberIdentity], instance: uuid::Uuid) -> String {
    let index = members
        .iter()
        .position(|member| member.instance_id == instance)
        .unwrap_or_else(|| panic!("{instance} is not one of this cluster's members"));
    char::from(b'a' + u8::try_from(index).unwrap_or(0)).to_string()
}

/// A batch of observations over `endpoints` distinct endpoints, `each`
/// times apiece, with a stable timestamp per observation.
fn observations(endpoints: usize, each: usize, prefix: &str, offset: i64) -> Vec<AuditEventSeed> {
    let mut seeds = Vec::with_capacity(endpoints * each);
    for endpoint in 0..endpoints {
        for repeat in 0..each {
            let index = (endpoint * each + repeat) as i64;
            seeds.push(AuditEventSeed::observation(
                "GET",
                &format!("{prefix}/{endpoint}"),
                &timestamp(offset + index),
                Some(SeedActor::bearer(&format!("principal-{}", endpoint % 3))),
            ));
        }
    }
    seeds
}

/// What the projector persisted, per endpoint.
async fn aggregate_call_counts(cluster: &Cluster) -> BTreeMap<String, i64> {
    let client_rows = cluster
        .database
        .query_all(
            "SELECT endpoint_template, call_count FROM greengateway.discovery_endpoint_aggregates",
        )
        .await;
    client_rows
        .iter()
        .map(|row| (row.get::<_, String>(0), row.get::<_, i64>(1)))
        .collect()
}

/// Killing the leader *while it is behind* leaves the successor resuming
/// from the committed checkpoint: every observation applied exactly once,
/// none lost and none applied twice.
///
/// The dangerous window is between reading a batch from the stream and
/// committing it with its checkpoint. A projector that advanced its
/// checkpoint before the data would lose the batch; one that committed the
/// data outside the checkpoint's transaction would let the successor apply
/// it again. The kill is verified to have landed inside that window — the
/// checkpoint is asserted to be behind the stream head at the moment the
/// leader dies — so this is not a test that hopes it raced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killing_the_projector_mid_backlog_leaves_the_successor_exactly_once() {
    const ENDPOINTS: usize = 12;
    const EACH: usize = 3;
    const BACKLOG_ENDPOINTS: usize = 40;
    const BACKLOG_EACH: usize = 20;
    let Some(mut cluster) = start_cluster(ClusterOptions {
        // A batch small enough that a large backlog takes many commits,
        // so a kill lands between two of them rather than after the last.
        shared_env: vec![("DISCOVERY_PROJECTOR_BATCH".to_owned(), "25".to_owned())],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    let members = cluster.member_identities().await;

    // A first, small batch, so a leader exists and has committed
    // something before anything is killed.
    let warmup = attribute(observations(ENDPOINTS, EACH, "/warm", 0), &members);
    cluster.database.ingest_audit_events(&warmup).await;
    let warm_head = cluster.database.stream_head().await;
    let before = wait_until_projected(&cluster, warm_head).await;
    let leader = replica_of(
        &members,
        before
            .leader
            .expect("a projector that committed a checkpoint has a leader"),
    );
    let survivor = if leader == "a" { "b" } else { "a" };

    // Now a backlog it cannot finish immediately, and a kill while it is
    // still working through it.
    let backlog = attribute(
        observations(BACKLOG_ENDPOINTS, BACKLOG_EACH, "/backlog", 10_000),
        &members,
    );
    cluster.database.ingest_audit_events(&backlog).await;
    let head = cluster.database.stream_head().await;
    cluster.kill(&leader);
    let at_kill = projector_state(&cluster).await;
    assert!(
        at_kill.checkpoint < head,
        "the kill was meant to land while the leader was behind, but it had \
         already committed through {} of {head}",
        at_kill.checkpoint
    );

    // The successor takes the slot at a strictly newer fence and finishes
    // the backlog.
    let after = wait_until(
        CONVERGENCE_BUDGET,
        "the surviving replica leading the projector and catching up",
        || async {
            let state = projector_state(&cluster).await;
            let led_by_survivor = state
                .leader
                .is_some_and(|instance| replica_of(&members, instance) == survivor);
            (led_by_survivor && state.checkpoint >= head && state.fence > before.fence)
                .then_some(state)
        },
    )
    .await;

    // The claim: every observation applied exactly once. Absolute counts,
    // per endpoint, against what was committed to the stream.
    let counts = aggregate_call_counts(&cluster).await;
    for endpoint in 0..BACKLOG_ENDPOINTS {
        let template = format!("/backlog/{endpoint}");
        assert_eq!(
            counts.get(&template).copied(),
            Some(BACKLOG_EACH as i64),
            "{template} must be counted exactly once per committed observation \
             (fence went {} -> {})",
            before.fence,
            after.fence
        );
    }
    for endpoint in 0..ENDPOINTS {
        let template = format!("/warm/{endpoint}");
        assert_eq!(
            counts.get(&template).copied(),
            Some(EACH as i64),
            "{template} must survive the failover with its count intact"
        );
    }
    let total = (ENDPOINTS * EACH + BACKLOG_ENDPOINTS * BACKLOG_EACH) as i64;
    assert_eq!(
        after.projected_events, total,
        "the deployment's applied-observation counter must equal what was committed: \
         a lower number is loss, a higher one is double application"
    );
}

/// Killing the leader when it is *caught up* is the other half: the
/// successor resumes from a checkpoint that is already at the head,
/// applies the events committed after it, and applies nothing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn killing_the_projector_after_it_committed_leaves_the_successor_exactly_once() {
    const ENDPOINTS: usize = 10;
    const EACH: usize = 4;
    let Some(mut cluster) = start_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let members = cluster.member_identities().await;

    let first = attribute(observations(ENDPOINTS, EACH, "/before", 0), &members);
    cluster.database.ingest_audit_events(&first).await;
    let first_head = cluster.database.stream_head().await;
    let before = wait_until_projected(&cluster, first_head).await;
    let leader = replica_of(
        &members,
        before.leader.expect("a committed checkpoint has a leader"),
    );
    let survivor = if leader == "a" { "b" } else { "a" };

    // Killed with nothing outstanding: the checkpoint is the head.
    cluster.kill(&leader);

    let second = attribute(observations(ENDPOINTS, EACH, "/after", 10_000), &members);
    cluster.database.ingest_audit_events(&second).await;
    let head = cluster.database.stream_head().await;

    let after = wait_until(
        CONVERGENCE_BUDGET,
        "the surviving replica leading the projector and catching up",
        || async {
            let state = projector_state(&cluster).await;
            let led_by_survivor = state
                .leader
                .is_some_and(|instance| replica_of(&members, instance) == survivor);
            (led_by_survivor && state.checkpoint >= head && state.fence > before.fence)
                .then_some(state)
        },
    )
    .await;

    let counts = aggregate_call_counts(&cluster).await;
    for endpoint in 0..ENDPOINTS {
        for prefix in ["/before", "/after"] {
            let template = format!("{prefix}/{endpoint}");
            assert_eq!(
                counts.get(&template).copied(),
                Some(EACH as i64),
                "{template} must be counted exactly once per committed observation"
            );
        }
    }
    assert_eq!(
        after.projected_events,
        (ENDPOINTS * EACH * 2) as i64,
        "a successor resuming from a committed checkpoint applies nothing twice"
    );
}

/// The endpoint cardinality bound is the deployment's, not each replica's.
///
/// The bound exists so a spray of distinct paths cannot grow the
/// inventory without limit. Enforced per replica it would be N times the
/// number set, and the operator's ceiling would silently scale with the
/// fleet. One projector at a time owns the working set, so the count the
/// deployment persists is the count that was configured — whichever
/// replica's traffic contributed the endpoints.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_endpoint_cardinality_bound_is_the_deployments_not_each_replicas() {
    const LIMIT: usize = 20;
    const ENDPOINTS: usize = 90;
    let Some(cluster) = start_cluster(ClusterOptions {
        shared_env: vec![("DISCOVERY_ENDPOINT_LIMIT".to_owned(), LIMIT.to_string())],
        ..ClusterOptions::default()
    })
    .await
    else {
        return skipped();
    };
    let members = cluster.member_identities().await;
    assert_eq!(members.len(), 2, "the bound is only interesting with two");

    let batch = attribute(observations(ENDPOINTS, 1, "/wide", 0), &members);
    cluster.database.ingest_audit_events(&batch).await;
    let head = cluster.database.stream_head().await;
    wait_until_projected(&cluster, head).await;

    let persisted: i64 = cluster
        .database
        .count("SELECT count(*)::bigint FROM greengateway.discovery_endpoint_aggregates")
        .await;
    assert!(
        persisted <= LIMIT as i64,
        "{ENDPOINTS} distinct endpoints observed across two replicas left {persisted} \
         rows, past the deployment's bound of {LIMIT}"
    );
    assert!(
        persisted > 0,
        "the bound should evict the least recent endpoints, not the inventory"
    );

    // Recency, not arrival: the endpoints kept are the ones whose events
    // carried the latest timestamps, which is what makes a successor
    // rebuild the same working set the killed leader had.
    let counts = aggregate_call_counts(&cluster).await;
    let newest = format!("/wide/{}", ENDPOINTS - 1);
    assert!(
        counts.contains_key(&newest),
        "the most recently seen endpoint should survive eviction; kept {:?}",
        counts.keys().collect::<Vec<_>>()
    );

    // The child tables follow their parents out: an eviction that left
    // orphans would grow without bound behind a bounded parent count.
    let orphans: i64 = cluster
        .database
        .count(
            "SELECT count(*)::bigint FROM greengateway.discovery_endpoint_principals p \
             WHERE NOT EXISTS ( \
               SELECT 1 FROM greengateway.discovery_endpoint_aggregates a \
               WHERE a.method = p.method AND a.endpoint_template = p.endpoint_template)",
        )
        .await;
    assert_eq!(
        orphans, 0,
        "eviction must take an endpoint's children with it"
    );
}

// ---------------------------------------------------------------------
// The maintenance singleton: one owner, fenced past its predecessor
// ---------------------------------------------------------------------

/// The maintenance lease, as the deployment holds it.
#[derive(Clone, Copy, Debug)]
struct MaintenanceLease {
    fence: i64,
    holder: uuid::Uuid,
}

async fn maintenance_lease(cluster: &Cluster) -> Option<MaintenanceLease> {
    let rows = cluster
        .database
        .query_all(
            "SELECT fence, holder_instance::text FROM greengateway.execution_leases \
             WHERE scope = 'maintenance' AND expires_at > now()",
        )
        .await;
    assert!(
        rows.len() <= 1,
        "the maintenance scope has one slot; found {} live leases",
        rows.len()
    );
    rows.first().map(|row| MaintenanceLease {
        fence: row.get::<_, i64>(0),
        holder: uuid::Uuid::parse_str(&row.get::<_, String>(1))
            .expect("a lease holder should be a UUID"),
    })
}

/// The highest fence any maintenance ledger row carries, and how many
/// distinct fences there are.
async fn ledger_fences(cluster: &Cluster) -> (i64, i64, i64) {
    let row = cluster
        .database
        .query_one(
            "SELECT coalesce(min(fence), 0)::bigint, coalesce(max(fence), 0)::bigint, \
                    count(*)::bigint \
             FROM greengateway.maintenance_jobs",
        )
        .await;
    (
        row.get::<_, i64>(0),
        row.get::<_, i64>(1),
        row.get::<_, i64>(2),
    )
}

/// Only one replica ever runs the housekeeping, and the ledger it writes
/// carries only that owner's fence.
///
/// Run on every replica the jobs would be N sweeps racing over the same
/// shared tables: two retention deletes competing for the same rows, two
/// stale-member sweeps reaping each other's members. The lease makes it
/// one replica's job, and the ledger's fence is how a reader tells whose.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_deployment_runs_one_maintenance_owner_at_a_time() {
    let Some(cluster) = start_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let members = cluster.member_identities().await;

    let lease = wait_until(
        CONVERGENCE_BUDGET,
        "a replica taking the maintenance lease",
        || async { maintenance_lease(&cluster).await },
    )
    .await;
    assert!(
        members
            .iter()
            .any(|member| member.instance_id == lease.holder),
        "the maintenance lease should be held by a live member"
    );

    // The ledger exists and every row is at the owner's fence.
    let (min_fence, max_fence, rows) = wait_until(
        CONVERGENCE_BUDGET,
        "the maintenance owner writing its job ledger",
        || async {
            let fences = ledger_fences(&cluster).await;
            (fences.2 > 0).then_some(fences)
        },
    )
    .await;
    assert!(rows > 0, "the owner should record the jobs it ran");
    assert_eq!(
        min_fence, max_fence,
        "every ledger row belongs to one owner's fence, not to a mixture"
    );

    // And it stays one owner across several passes. Sampled on database
    // time so the window is passes, not a guessed number of seconds.
    let passes = 3;
    cluster
        .database
        .wait_for_elapsed(
            passes as f64 * MAINTENANCE_INTERVAL_MS as f64 / 1000.0,
            CONVERGENCE_BUDGET,
        )
        .await;
    let still = maintenance_lease(&cluster)
        .await
        .expect("the maintenance lease should still be held");
    assert_eq!(
        still.holder, lease.holder,
        "an owner that keeps renewing must not be displaced by its peer"
    );
    let (min_after, max_after, _) = ledger_fences(&cluster).await;
    assert_eq!(
        (min_after, max_after),
        (lease.fence, lease.fence),
        "an uninterrupted owner's ledger stays at the fence it adopted"
    );
}

/// Killing the owner hands the housekeeping to its peer at a strictly
/// newer fence, and the dead owner's fence can no longer match a ledger
/// row — so a late write from it is refused by the predicate rather than
/// by hoping the successor got there first.
///
/// A paused-then-resumed leader is the case this protects: it believes it
/// still owns the pass, and without the fence its write would land on top
/// of the successor's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_killed_maintenance_owner_is_succeeded_and_its_fence_stops_matching() {
    let Some(mut cluster) = start_cluster(ClusterOptions::default()).await else {
        return skipped();
    };
    let members = cluster.member_identities().await;

    let lease = wait_until(
        CONVERGENCE_BUDGET,
        "a replica taking the maintenance lease",
        || async { maintenance_lease(&cluster).await },
    )
    .await;
    wait_until(
        CONVERGENCE_BUDGET,
        "the owner adopting the job ledger at its fence",
        || async {
            let (min_fence, max_fence, rows) = ledger_fences(&cluster).await;
            (rows > 0 && min_fence == lease.fence && max_fence == lease.fence).then_some(())
        },
    )
    .await;

    let owner = replica_of(&members, lease.holder);
    let survivor = if owner == "a" { "b" } else { "a" };
    let survivor_instance = members[if survivor == "a" { 0 } else { 1 }].instance_id;
    cluster.kill(&owner);

    let successor = wait_until(
        CONVERGENCE_BUDGET,
        "the surviving replica taking the maintenance lease",
        || async {
            let held = maintenance_lease(&cluster).await?;
            (held.holder == survivor_instance && held.fence > lease.fence).then_some(held)
        },
    )
    .await;

    wait_until(
        CONVERGENCE_BUDGET,
        "the successor adopting the ledger at its own fence",
        || async {
            let (min_fence, max_fence, rows) = ledger_fences(&cluster).await;
            (rows > 0 && min_fence == successor.fence && max_fence == successor.fence).then_some(())
        },
    )
    .await;

    // The refusal, stated as the row state that makes it certain: every
    // ledger write carries `WHERE fence = <the writer's fence>`, and no
    // row is at the dead owner's fence any more, so nothing it sends can
    // match. It cannot "win a race" it has no row to write to.
    let stale: i64 = cluster
        .database
        .count(&format!(
            "SELECT count(*)::bigint FROM greengateway.maintenance_jobs \
             WHERE fence <= {}",
            lease.fence
        ))
        .await;
    assert_eq!(
        stale, 0,
        "after adoption no ledger row remains at or below the dead owner's fence {}",
        lease.fence
    );

    // And the deployment is still doing its housekeeping, not merely
    // holding a lease.
    wait_until(
        CONVERGENCE_BUDGET,
        "the successor recording a job outcome",
        || async {
            let successes: i64 = cluster
                .database
                .count(
                    "SELECT count(*)::bigint FROM greengateway.maintenance_jobs \
                     WHERE last_success_at IS NOT NULL",
                )
                .await;
            (successes > 0).then_some(())
        },
    )
    .await;
}
