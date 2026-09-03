//! The test load balancer: one address in front of both replicas.
//!
//! It answers the two questions the #241 matrix keeps asking. *Round
//! robin* is the default, so a burst spread across the cluster exercises
//! both replicas without the test choosing which. *Pinning* — either for
//! the whole balancer ([`Balancer::pin`]) or for one request (the
//! [`PIN_HEADER`] header) — is what lets a test say "start the login on A
//! and complete it on B" without opening a second client.
//!
//! It is a plain forwarder, not a proxy under test: it copies the method,
//! headers and body across, and copies status, headers and body back. It
//! never follows redirects, because half these suites are about what a
//! `302` says.

use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Router,
};

/// Per-request override: name the replica this request must reach.
pub const PIN_HEADER: &str = "x-ha-pin";

const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Target {
    pub name: String,
    pub base_url: String,
}

/// How the balancer chooses a target when a request does not pin one.
#[derive(Clone, Debug)]
pub enum Dispatch {
    RoundRobin,
    Pin(String),
}

struct BalancerState {
    targets: Mutex<Vec<Target>>,
    mode: Mutex<Dispatch>,
    next: AtomicUsize,
    dispatches: Mutex<Vec<String>>,
    client: reqwest::Client,
}

/// A running balancer. Dropping it stops the server.
pub struct Balancer {
    pub addr: SocketAddr,
    pub base_url: String,
    state: Arc<BalancerState>,
    server: super::ServerHandle,
}

impl Balancer {
    /// Start with no targets.
    ///
    /// Started *before* the replicas on purpose: its address is the
    /// deployment's public URL, which is part of the static-configuration
    /// fingerprint both replicas must agree on, so it has to exist before
    /// either replica's environment is built. Targets are added by
    /// [`Balancer::set_targets`] once the replicas own their ports.
    pub async fn start() -> Self {
        let state = Arc::new(BalancerState {
            targets: Mutex::new(Vec::new()),
            mode: Mutex::new(Dispatch::RoundRobin),
            next: AtomicUsize::new(0),
            dispatches: Mutex::new(Vec::new()),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()
                .expect("the harness balancer client should build"),
        });
        let router = Router::new()
            .fallback(forward)
            .with_state(Arc::clone(&state));
        let (addr, server) = super::serve_on_ephemeral_port(router).await;
        Self {
            addr,
            base_url: format!("http://{addr}"),
            state,
            server,
        }
    }

    pub fn set_targets(&self, targets: Vec<Target>) {
        *lock(&self.state.targets) = targets;
    }

    pub fn round_robin(&self) {
        *lock(&self.state.mode) = Dispatch::RoundRobin;
    }

    /// Send every unpinned request to one replica until told otherwise.
    pub fn pin(&self, name: &str) {
        *lock(&self.state.mode) = Dispatch::Pin(name.to_owned());
    }

    /// The replica names this balancer dispatched to, in order.
    pub fn dispatches(&self) -> Vec<String> {
        lock(&self.state.dispatches).clone()
    }

    pub fn clear_dispatches(&self) {
        lock(&self.state.dispatches).clear();
    }

    pub fn shutdown(&mut self) {
        self.server.shutdown();
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn choose(state: &BalancerState, pin: Option<&str>) -> Option<Target> {
    let targets = lock(&state.targets);
    if targets.is_empty() {
        return None;
    }
    let requested = match pin {
        Some(name) => Some(name.to_owned()),
        None => match &*lock(&state.mode) {
            Dispatch::RoundRobin => None,
            Dispatch::Pin(name) => Some(name.clone()),
        },
    };
    match requested {
        Some(name) => targets.iter().find(|target| target.name == name).cloned(),
        None => {
            let index = state.next.fetch_add(1, Ordering::SeqCst) % targets.len();
            targets.get(index).cloned()
        }
    }
}

async fn forward(State(state): State<Arc<BalancerState>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let pin = parts
        .headers
        .get(PIN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let Some(target) = choose(&state, pin.as_deref()) else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "the harness balancer has no target for this request",
        )
            .into_response();
    };
    lock(&state.dispatches).push(target.name.clone());

    let body = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("the harness balancer could not read the request body: {error}"),
            )
                .into_response()
        }
    };
    let path_and_query = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path().to_owned(), ToString::to_string);
    let url = format!("{}{path_and_query}", target.base_url);

    let mut headers = HeaderMap::new();
    for (name, value) in parts.headers.iter() {
        if name == header::HOST || name == header::CONTENT_LENGTH || name.as_str() == PIN_HEADER {
            continue;
        }
        headers.append(name.clone(), value.clone());
    }

    let response = match state
        .client
        .request(parts.method.clone(), &url)
        .headers(headers)
        .body(body)
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) => {
            return (
                StatusCode::BAD_GATEWAY,
                format!(
                    "the harness balancer could not reach {}: {error}",
                    target.name
                ),
            )
                .into_response()
        }
    };

    let status = response.status();
    let response_headers = response.headers().clone();
    let bytes = response.bytes().await.unwrap_or_default();
    let mut builder = Response::builder().status(status);
    for (name, value) in response_headers.iter() {
        if name == header::CONTENT_LENGTH || name == header::TRANSFER_ENCODING {
            continue;
        }
        builder = builder.header(name, value);
    }
    builder
        .header("x-ha-served-by", target.name)
        .body(Body::from(bytes))
        .unwrap_or_else(|error| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("the harness balancer could not rebuild the response: {error}"),
            )
                .into_response()
        })
}
