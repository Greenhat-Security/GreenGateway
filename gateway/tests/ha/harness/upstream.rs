//! The fake upstream every replica proxies to.
//!
//! It is deliberately the *same* upstream for both replicas: the
//! static-configuration fingerprint covers `upstream_url`, so two replicas
//! pointed at different upstreams would never agree and would never become
//! ready (PR 13). What distinguishes them instead is a per-replica value in
//! `add_request_headers`, which the fingerprint covers by header *name*
//! only (`ha.rs::insert_route`) — so `x-ha-replica: a` and `x-ha-replica: b`
//! agree on the fingerprint while telling this upstream, and therefore the
//! test, exactly which replica served a request.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use serde_json::json;

/// The header the routes inject, whose value names the replica.
pub const REPLICA_HEADER: &str = "x-ha-replica";

/// At most this much request body is buffered per call. Large enough for
/// every control-plane document these suites write, small enough that a
/// saturation test cannot exhaust the test process.
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub sequence: u64,
    pub method: String,
    pub path: String,
    /// Which replica proxied it, from [`REPLICA_HEADER`].
    pub replica: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// How the upstream answers. Changed at any time from a test.
#[derive(Clone, Copy, Debug, Default)]
pub enum Behaviour {
    #[default]
    Ok,
    /// Answer after this delay: the slow-query and saturation rows.
    Slow(Duration),
    /// Answer with this status and an empty body.
    Status(u16),
}

struct UpstreamState {
    requests: Mutex<Vec<RecordedRequest>>,
    behaviour: Mutex<Behaviour>,
    sequence: AtomicU64,
    /// Requests currently inside the handler, and the high-water mark.
    ///
    /// This is what a cluster-wide concurrency bound is actually *about*:
    /// not how many callers asked, but how many reached the upstream at
    /// once. Both counters are held under one lock so the peak can never
    /// be read between an increment and its own comparison.
    in_flight: Mutex<InFlight>,
}

#[derive(Default)]
struct InFlight {
    current: usize,
    peak: usize,
}

/// Decrements the in-flight count however the handler leaves — including
/// a client that hung up mid-response, which drops the future.
struct InFlightGuard(Arc<UpstreamState>);

impl InFlightGuard {
    fn enter(state: &Arc<UpstreamState>) -> Self {
        {
            let mut counters = lock(&state.in_flight);
            counters.current += 1;
            counters.peak = counters.peak.max(counters.current);
        }
        Self(Arc::clone(state))
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut counters = lock(&self.0.in_flight);
        counters.current = counters.current.saturating_sub(1);
    }
}

/// A running fake upstream. Dropping it stops the server.
pub struct FakeUpstream {
    pub addr: SocketAddr,
    pub base_url: String,
    state: Arc<UpstreamState>,
    server: super::ServerHandle,
}

impl FakeUpstream {
    pub async fn start() -> Self {
        let state = Arc::new(UpstreamState {
            requests: Mutex::new(Vec::new()),
            behaviour: Mutex::new(Behaviour::Ok),
            sequence: AtomicU64::new(0),
            in_flight: Mutex::new(InFlight::default()),
        });
        let router = Router::new()
            .fallback(handle)
            .with_state(Arc::clone(&state));
        let (addr, server) = super::serve_on_ephemeral_port(router).await;
        Self {
            addr,
            base_url: format!("http://{addr}"),
            state,
            server,
        }
    }

    pub fn set_behaviour(&self, behaviour: Behaviour) {
        *lock(&self.state.behaviour) = behaviour;
    }

    pub fn requests(&self) -> Vec<RecordedRequest> {
        lock(&self.state.requests).clone()
    }

    pub fn request_count(&self) -> usize {
        lock(&self.state.requests).len()
    }

    /// Which replicas have proxied at least one request here, in the order
    /// the upstream first saw them.
    pub fn replicas_seen(&self) -> Vec<String> {
        let mut seen: Vec<String> = Vec::new();
        for request in lock(&self.state.requests).iter() {
            if let Some(replica) = &request.replica {
                if !seen.contains(replica) {
                    seen.push(replica.clone());
                }
            }
        }
        seen
    }

    pub fn clear(&self) {
        lock(&self.state.requests).clear();
        let mut counters = lock(&self.state.in_flight);
        counters.peak = counters.current;
    }

    /// The most requests this upstream ever had in flight at once — the
    /// observable a cluster-wide concurrency bound is asserted against.
    pub fn peak_in_flight(&self) -> usize {
        lock(&self.state.in_flight).peak
    }

    pub fn in_flight(&self) -> usize {
        lock(&self.state.in_flight).current
    }

    /// Poll until at least `count` requests are in flight, or fail saying
    /// how far it got. A bounded poll on an observable, never a sleep sized
    /// to guess how long a replica takes to dispatch.
    pub async fn wait_for_in_flight(&self, count: usize, budget: Duration) {
        let deadline = std::time::Instant::now() + budget;
        loop {
            let current = self.in_flight();
            if current >= count {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "only {current} request(s) reached the upstream within {budget:?}, expected {count}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Stop the server. Called by `Drop` too; explicit shutdown exists so
    /// a test can prove the teardown order it cares about.
    pub fn shutdown(&mut self) {
        self.server.shutdown();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panicking test must not cascade into the rest of the harness.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn handle(State(state): State<Arc<UpstreamState>>, request: Request) -> Response {
    let _in_flight = InFlightGuard::enter(&state);
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAX_BODY_BYTES)
        .await
        .unwrap_or_default()
        .to_vec();
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let replica = headers.get(REPLICA_HEADER).cloned();
    let sequence = state.sequence.fetch_add(1, Ordering::SeqCst) + 1;
    let path = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string);
    lock(&state.requests).push(RecordedRequest {
        sequence,
        method: parts.method.as_str().to_owned(),
        path: path.clone(),
        replica: replica.clone(),
        headers,
        body,
    });

    let behaviour = *lock(&state.behaviour);
    match behaviour {
        Behaviour::Slow(delay) => tokio::time::sleep(delay).await,
        Behaviour::Status(status) => {
            return (
                StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                [(header::CONTENT_TYPE, "application/json")],
                Body::from("{}"),
            )
                .into_response();
        }
        Behaviour::Ok => {}
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        Body::from(
            json!({
                "upstream": "fake",
                "sequence": sequence,
                "path": path,
                "replica": replica,
            })
            .to_string(),
        ),
    )
        .into_response()
}
