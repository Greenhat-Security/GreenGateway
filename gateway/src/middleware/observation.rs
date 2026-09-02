//! Per-request observation audit event middleware.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use http::{header::CONTENT_TYPE, HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::{
    audit::{
        redact::{hash_args, sha256_hex},
        AuditEvent, AuditLog,
    },
    auth::actor_from_principal,
    client_ip::{canonical_client_ip, request_id, ClientIpPolicy},
    config::Config,
    discovery::{
        openapi::{OpenApiRequestShape, SchemaCoverage},
        query::{
            DiscoveryQueryError, DiscoveryQueryStore, DiscoveryReadStore, InferredJsonBodyKey,
            InferredQueryParam, InferredRequestSchema, ObservedEndpoint,
        },
    },
    lifecycle::GatewayLifecycle,
    upstream_route::{
        request_host_without_port, ProxyRouteClassificationCompleted, ProxyRouteObservationContext,
    },
};

use super::decision::{AuthOutcome, PolicyDecision, PolicyDecisionOutcome, UpstreamOutcome};

const HTTP_REQUEST_OBSERVED: &str = "http.request_observed";
pub(crate) const MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT: u64 = 5;
/// Inferred-schema conformance is advisory and based on captured samples. Cache
/// discovery lookups briefly so endpoint/sample updates become visible within
/// this window without scanning SQLite or reparsing historical samples on every
/// request.
const INFERRED_SCHEMA_CACHE_TTL: Duration = Duration::from_secs(5);
/// Cluster mode refreshes its conformance snapshot on the same cadence the
/// standalone cache expires on, so an endpoint's samples become visible to
/// every replica within one window either way.
#[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Read by cluster startup.
pub(crate) const CLUSTER_CONFORMANCE_REFRESH_INTERVAL: Duration = INFERRED_SCHEMA_CACHE_TTL;
/// How many endpoints a replica tracks inferred schemas for in cluster
/// mode: the endpoints its own traffic has asked about, bounded so one
/// replica's refresh reads (in one query) at most this many endpoints'
/// samples per interval. Past the bound the endpoint asked about least
/// recently makes room, so an endpoint is never locked out for good: a
/// request for it misses the snapshot, asks again, and the next refresh
/// loads it.
const MAX_TRACKED_INFERRED_ENDPOINTS: usize = 4096;
/// A captured payload shape carries one entry per distinct query parameter and
/// per top-level JSON body key, and every retained sample of it is stored whole.
/// The request body itself is only bounded by `EGRESS_MAX_REQUEST_BODY_BYTES`,
/// so without these caps a single wide body decides how much memory and SQLite
/// one endpoint consumes. A capture past the cap is truncated and marked, never
/// silently dropped.
const MAX_CAPTURED_QUERY_PARAMS: usize = 64;
const MAX_CAPTURED_JSON_BODY_KEYS: usize = 64;

#[derive(Clone)]
pub struct ObservationState {
    pub audit: AuditLog,
    pub client_ip_policy: ClientIpPolicy,
    payload_capture: Option<PayloadCaptureConfig>,
    conformance: Option<SchemaConformanceState>,
}

impl ObservationState {
    pub fn from_config(config: &Config, audit: AuditLog) -> Self {
        Self {
            audit,
            client_ip_policy: ClientIpPolicy::from_config(config),
            payload_capture: PayloadCaptureConfig::from_config(config),
            conformance: None,
        }
    }

    pub fn with_conformance(mut self, conformance: Option<SchemaConformanceState>) -> Self {
        self.conformance = conformance;
        self
    }
}

#[derive(Clone, Debug)]
pub struct PayloadCaptureConfig {
    sample_rate: f64,
}

#[derive(Clone)]
pub struct SchemaConformanceState {
    coverage: SchemaCoverage,
    inferred: Option<InferredSchemaSource>,
    payload_capture_enabled: bool,
    min_inferred_sample_count: u64,
    skip_exact_paths: Vec<String>,
    skip_path_prefixes: Vec<String>,
}

/// Where the inferred-schema conformance check gets its schemas.
#[derive(Clone)]
enum InferredSchemaSource {
    /// Standalone: the SQLite store, read on the request path behind the
    /// short TTL cache (a local file read, never a network round trip).
    Sqlite {
        store: Arc<DiscoveryQueryStore>,
        cache: Arc<InferredSchemaCache>,
    },
    /// Cluster: a snapshot a background task refreshes from the PostgreSQL
    /// read store. The request path reads the snapshot and nothing else --
    /// it holds no store handle at all, so it cannot reach the authority.
    Cluster(Arc<ClusterConformanceCache>),
}

/// The cluster conformance cache: the last refreshed snapshot, and the set
/// of endpoints this replica's traffic has asked about, which the next
/// refresh loads inferred schemas for.
pub struct ClusterConformanceCache {
    snapshot: Arc<ArcSwap<ObservedSnapshot>>,
    wanted: Mutex<WantedEndpoints>,
}

/// The endpoints a replica's traffic has asked about and found no schema
/// for in the snapshot, each with the sequence of its latest ask. Bounded:
/// at capacity a new endpoint replaces the one asked about least recently,
/// so the set follows the traffic instead of freezing on the first
/// endpoints seen.
struct WantedEndpoints {
    capacity: usize,
    next_seq: u64,
    by_key: BTreeMap<EndpointSchemaCacheKey, u64>,
}

impl WantedEndpoints {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_seq: 0,
            by_key: BTreeMap::new(),
        }
    }

    fn note(&mut self, key: EndpointSchemaCacheKey) {
        self.next_seq = self.next_seq.wrapping_add(1);
        let seq = self.next_seq;
        if let Some(existing) = self.by_key.get_mut(&key) {
            *existing = seq;
            return;
        }
        if self.by_key.len() >= self.capacity {
            let least_recent = self
                .by_key
                .iter()
                .min_by_key(|(_, seq)| **seq)
                .map(|(key, _)| key.clone());
            if let Some(least_recent) = least_recent {
                self.by_key.remove(&least_recent);
            }
        }
        self.by_key.insert(key, seq);
    }

    fn retain(&mut self, mut keep: impl FnMut(&EndpointSchemaCacheKey) -> bool) {
        self.by_key.retain(|key, _| keep(key));
    }

    fn keys(&self) -> Vec<EndpointSchemaCacheKey> {
        self.by_key.keys().cloned().collect()
    }
}

/// What the cluster hot path reads: the observed endpoints (for template
/// matching) and the inferred schemas of the tracked endpoints that have
/// samples, as of the last refresh.
#[derive(Default)]
pub struct ObservedSnapshot {
    endpoints: Arc<Vec<ObservedEndpoint>>,
    schemas: BTreeMap<EndpointSchemaCacheKey, Arc<InferredRequestSchema>>,
}

struct InferredSchemaCache {
    ttl: Duration,
    inner: Mutex<InferredSchemaCacheInner>,
}

#[derive(Default)]
struct InferredSchemaCacheInner {
    observed_endpoints: Option<CacheEntry<Arc<Vec<ObservedEndpoint>>>>,
    schemas: BTreeMap<EndpointSchemaCacheKey, CacheEntry<Option<Arc<InferredRequestSchema>>>>,
}

struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EndpointSchemaCacheKey {
    method: String,
    endpoint_template: String,
}

#[derive(Clone, Debug)]
pub struct PayloadCaptureHandle {
    state: Arc<Mutex<PayloadCaptureState>>,
}

#[derive(Clone, Debug)]
struct PayloadCaptureState {
    shape: CapturedPayloadShape,
    body_status: BodyCaptureStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BodyCaptureStatus {
    NotObserved,
    Complete,
    Incomplete,
}

impl BodyCaptureStatus {
    fn audit_label(self) -> &'static str {
        match self {
            Self::NotObserved => "not_observed",
            Self::Complete => "complete",
            Self::Incomplete => "incomplete",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct CapturedPayloadShape {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    query_params: Vec<CapturedQueryParam>,
    #[serde(default, skip_serializing_if = "is_false")]
    query_params_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    json_body: Option<CapturedJsonBodyShape>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct CapturedQueryParam {
    #[serde(flatten)]
    name: CapturedFieldName,
    value_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct CapturedJsonBodyShape {
    top_level_keys: Vec<CapturedFieldName>,
    #[serde(default, skip_serializing_if = "is_false")]
    top_level_keys_truncated: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct CapturedFieldName {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name_hash: Option<String>,
    redacted: bool,
}

pub async fn observation_middleware(
    State(state): State<ObservationState>,
    mut req: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let request_host = request_host_without_port(req.headers());
    let request_id = request_id(req.headers(), req.extensions());
    let source_ip = canonical_client_ip(req.headers(), req.extensions(), &state.client_ip_policy);
    let query = req.uri().query().map(str::to_owned);
    let conformance_check = state
        .conformance
        .as_ref()
        .and_then(|conformance| conformance.prepare_check(&method, &path, query.as_deref()));
    let payload_capture_sampled = state
        .payload_capture
        .as_ref()
        .is_some_and(|config| should_sample_payload_capture(config, &method, &path, &request_id));
    let needs_conformance_body_capture = conformance_check
        .as_ref()
        .is_some_and(PreparedSchemaConformanceCheck::needs_body_capture);
    let payload_capture = (payload_capture_sampled || needs_conformance_body_capture)
        .then(|| PayloadCaptureHandle::new(CapturedPayloadShape::from_query(query.as_deref())));
    if let Some(handle) = payload_capture.as_ref() {
        req.extensions_mut().insert(handle.clone());
    }

    let response = next.run(req).await;
    let status = response.status().as_u16();
    let latency_ms = duration_millis(start.elapsed());
    let auth_outcome = response.extensions().get::<AuthOutcome>();
    let policy_decision = response.extensions().get::<PolicyDecision>();
    let upstream_outcome = response.extensions().get::<UpstreamOutcome>();
    let routing_context_known = response
        .extensions()
        .get::<ProxyRouteClassificationCompleted>()
        .is_some();
    let upstream_route = response.extensions().get::<ProxyRouteObservationContext>();
    let actor = auth_outcome
        .and_then(|outcome| outcome.principal.as_ref())
        .map(actor_from_principal);
    let payload_shape = payload_capture_sampled
        .then(|| {
            payload_capture
                .as_ref()
                .and_then(PayloadCaptureHandle::captured_data_snapshot)
        })
        .flatten();
    let conformance_shape = payload_capture.as_ref().map(PayloadCaptureHandle::snapshot);
    let body_capture_status = payload_capture
        .as_ref()
        .map(PayloadCaptureHandle::body_capture_status);
    let schema_mismatch = conformance_check.as_ref().and_then(|check| {
        check.schema_mismatch(
            conformance_shape.as_ref(),
            body_capture_status.unwrap_or(BodyCaptureStatus::NotObserved),
        )
    });

    state.audit.emit(AuditEvent::new(
        HTTP_REQUEST_OBSERVED,
        &request_id,
        &source_ip,
        actor,
        observation_payload(ObservationPayloadInput {
            method: &method,
            path: &path,
            status,
            latency_ms,
            auth_outcome,
            policy_decision,
            upstream_outcome,
            routing_context_known,
            request_host: request_host.as_deref(),
            upstream_route,
            payload_shape: payload_shape.as_ref(),
            body_capture_status,
            schema_mismatch,
        }),
    ));

    response
}

struct ObservationPayloadInput<'a> {
    method: &'a str,
    path: &'a str,
    status: u16,
    latency_ms: u64,
    auth_outcome: Option<&'a AuthOutcome>,
    policy_decision: Option<&'a PolicyDecision>,
    upstream_outcome: Option<&'a UpstreamOutcome>,
    routing_context_known: bool,
    request_host: Option<&'a str>,
    upstream_route: Option<&'a ProxyRouteObservationContext>,
    payload_shape: Option<&'a CapturedPayloadShape>,
    body_capture_status: Option<BodyCaptureStatus>,
    schema_mismatch: Option<bool>,
}

fn observation_payload(input: ObservationPayloadInput<'_>) -> Value {
    let mut payload = Map::new();
    payload.insert("method".to_owned(), json!(input.method));
    payload.insert("path".to_owned(), json!(input.path));
    payload.insert("status".to_owned(), json!(input.status));
    payload.insert("latency_ms".to_owned(), json!(input.latency_ms));
    payload.insert(
        "auth_outcome".to_owned(),
        json!(auth_outcome_label(input.auth_outcome)),
    );

    if let Some(outcome) = input.auth_outcome {
        if !outcome.authenticated {
            if let Some(reason) = outcome.reason.as_deref() {
                payload.insert("auth_reason".to_owned(), json!(reason));
            }
        }
    }

    payload.insert(
        "policy_decision".to_owned(),
        json!(policy_decision_label(input.policy_decision)),
    );
    payload.insert(
        "routing_context_known".to_owned(),
        json!(input.routing_context_known),
    );

    if let Some(request_host) = input.request_host {
        payload.insert("request_host".to_owned(), json!(request_host));
    }

    if let Some(route) = input.upstream_route {
        payload.insert("upstream_origin".to_owned(), json!(route.upstream_origin));
        if let Some(route_id) = route.route_id.as_deref() {
            payload.insert("upstream_route_id".to_owned(), json!(route_id));
        }
        if let Some(host) = route.route_host.as_deref() {
            payload.insert("upstream_route_host".to_owned(), json!(host));
        }
        if let Some(path_prefix) = route.route_path_prefix.as_deref() {
            payload.insert("upstream_route_path_prefix".to_owned(), json!(path_prefix));
        }
    }

    if let Some(decision) = input.policy_decision {
        payload.insert("policy_reason".to_owned(), json!(decision.reason));

        if let Some(permission) = decision.permission.as_deref() {
            payload.insert("permission".to_owned(), json!(permission));
        }

        if let Some(path_prefix) = decision.path_prefix.as_deref() {
            payload.insert("path_prefix".to_owned(), json!(path_prefix));
        }

        if let Some(matched_rule_id) = decision.matched_rule_id.as_deref() {
            payload.insert("matched_rule_id".to_owned(), json!(matched_rule_id));
        }
    }

    if let Some(outcome) = input.upstream_outcome {
        payload.insert("upstream_latency_ms".to_owned(), json!(outcome.latency_ms));

        if let Some(status) = outcome.status {
            payload.insert("upstream_status".to_owned(), json!(status));
        }
        if let Some(pool_id) = outcome.pool_id.as_deref() {
            payload.insert("upstream_pool_id".to_owned(), json!(pool_id));
        }
        if let Some(endpoint_id) = outcome.endpoint_id.as_deref() {
            payload.insert("upstream_endpoint_id".to_owned(), json!(endpoint_id));
        }
        payload.insert(
            "upstream_attempts".to_owned(),
            json!(outcome
                .attempts
                .iter()
                .map(|attempt| json!({
                    "endpoint_id": attempt.endpoint_id,
                    "result": attempt.result,
                    "duration_ms": attempt.duration_ms,
                }))
                .collect::<Vec<_>>()),
        );
        payload.insert(
            "upstream_retry_exhausted".to_owned(),
            json!(outcome.retry_exhausted),
        );
        payload.insert(
            "upstream_stream_terminal_pending".to_owned(),
            json!(outcome.stream_terminal_pending),
        );
    }

    if let Some(payload_shape) = input.payload_shape {
        payload.insert(
            "payload_shape".to_owned(),
            serde_json::to_value(payload_shape).expect("captured payload shape should serialize"),
        );
    }

    if let Some(status) = input.body_capture_status {
        payload.insert(
            "request_body_capture_status".to_owned(),
            json!(status.audit_label()),
        );
    }

    if let Some(schema_mismatch) = input.schema_mismatch {
        payload.insert("schema_mismatch".to_owned(), json!(schema_mismatch));
    }

    Value::Object(payload)
}

impl PayloadCaptureConfig {
    fn from_config(config: &Config) -> Option<Self> {
        config.payload_capture_enabled.then_some(Self {
            sample_rate: config.payload_capture_sample_rate,
        })
    }
}

impl SchemaConformanceState {
    /// Standalone mode: inferred schemas come from the SQLite store on the
    /// request path, behind the TTL cache.
    pub fn from_config(
        config: &Config,
        coverage: SchemaCoverage,
        query_store: Option<Arc<DiscoveryQueryStore>>,
    ) -> Option<Self> {
        let mut state = Self::from_parts(coverage, query_store, config.payload_capture_enabled)?;
        state.apply_config_skips(config);
        Some(state)
    }

    /// Cluster mode: inferred schemas come from `cache`, which
    /// [`spawn_cluster_conformance_refresher`] keeps current from the
    /// PostgreSQL read store; the request path never queries the store.
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Wired by cluster startup.
    pub fn from_config_cluster(
        config: &Config,
        coverage: SchemaCoverage,
        cache: Option<Arc<ClusterConformanceCache>>,
    ) -> Option<Self> {
        let mut state = Self::from_source(
            coverage,
            cache.map(InferredSchemaSource::Cluster),
            config.payload_capture_enabled,
        )?;
        state.apply_config_skips(config);
        Some(state)
    }

    fn apply_config_skips(&mut self, config: &Config) {
        self.skip_exact_paths = vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
        ];
        self.skip_path_prefixes = vec![
            config.admin_prefix.clone(),
            format!("/v1{}", config.admin_prefix),
        ];
    }

    pub fn from_parts(
        coverage: SchemaCoverage,
        query_store: Option<Arc<DiscoveryQueryStore>>,
        payload_capture_enabled: bool,
    ) -> Option<Self> {
        Self::from_parts_with_cache_ttl(
            coverage,
            query_store,
            payload_capture_enabled,
            INFERRED_SCHEMA_CACHE_TTL,
        )
    }

    fn from_parts_with_cache_ttl(
        coverage: SchemaCoverage,
        query_store: Option<Arc<DiscoveryQueryStore>>,
        payload_capture_enabled: bool,
        inferred_cache_ttl: Duration,
    ) -> Option<Self> {
        Self::from_source(
            coverage,
            query_store.map(|store| InferredSchemaSource::Sqlite {
                store,
                cache: Arc::new(InferredSchemaCache::new(inferred_cache_ttl)),
            }),
            payload_capture_enabled,
        )
    }

    fn from_source(
        coverage: SchemaCoverage,
        inferred: Option<InferredSchemaSource>,
        payload_capture_enabled: bool,
    ) -> Option<Self> {
        (coverage.spec_configured() || (payload_capture_enabled && inferred.is_some())).then_some(
            Self {
                coverage,
                inferred,
                payload_capture_enabled,
                min_inferred_sample_count: MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT,
                skip_exact_paths: Vec::new(),
                skip_path_prefixes: Vec::new(),
            },
        )
    }

    #[cfg(test)]
    fn new_for_test(
        coverage: SchemaCoverage,
        query_store: Option<Arc<DiscoveryQueryStore>>,
        payload_capture_enabled: bool,
    ) -> Self {
        Self::new_for_test_with_cache_ttl(
            coverage,
            query_store,
            payload_capture_enabled,
            INFERRED_SCHEMA_CACHE_TTL,
        )
    }

    #[cfg(test)]
    fn new_for_test_with_cache_ttl(
        coverage: SchemaCoverage,
        query_store: Option<Arc<DiscoveryQueryStore>>,
        payload_capture_enabled: bool,
        inferred_cache_ttl: Duration,
    ) -> Self {
        Self::new_for_test_with_source(
            coverage,
            query_store.map(|store| InferredSchemaSource::Sqlite {
                store,
                cache: Arc::new(InferredSchemaCache::new(inferred_cache_ttl)),
            }),
            payload_capture_enabled,
        )
    }

    #[cfg(test)]
    fn new_for_test_with_source(
        coverage: SchemaCoverage,
        inferred: Option<InferredSchemaSource>,
        payload_capture_enabled: bool,
    ) -> Self {
        Self {
            coverage,
            inferred,
            payload_capture_enabled,
            min_inferred_sample_count: MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT,
            skip_exact_paths: Vec::new(),
            skip_path_prefixes: Vec::new(),
        }
    }

    fn prepare_check(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
    ) -> Option<PreparedSchemaConformanceCheck> {
        if self.should_skip_path(path) {
            return None;
        }
        let observed_shape = CapturedPayloadShape::from_query(query);

        if self.coverage.spec_configured() {
            return match self.coverage.request_shape_for(method, path) {
                Some(shape) => Some(PreparedSchemaConformanceCheck::Expected {
                    expected: ExpectedRequestShape::from_openapi(&shape),
                    observed_shape,
                }),
                None => Some(PreparedSchemaConformanceCheck::Undocumented),
            };
        }

        if !self.payload_capture_enabled {
            return None;
        }
        let schema = self.inferred_schema_for_request(method, path)?;
        if schema.sample_count < self.min_inferred_sample_count {
            return None;
        }

        Some(PreparedSchemaConformanceCheck::Expected {
            expected: ExpectedRequestShape::from_inferred(&schema),
            observed_shape,
        })
    }

    fn inferred_schema_for_request(
        &self,
        method: &str,
        path: &str,
    ) -> Option<Arc<InferredRequestSchema>> {
        match self.inferred.as_ref()? {
            InferredSchemaSource::Sqlite { store, cache } => {
                cache.schema_for_request(store, method, path)
            }
            InferredSchemaSource::Cluster(cache) => cache.schema_for_request(method, path),
        }
    }

    fn should_skip_path(&self, path: &str) -> bool {
        self.skip_exact_paths.iter().any(|exact| path == exact)
            || self
                .skip_path_prefixes
                .iter()
                .any(|prefix| path_prefix_matches(path, prefix))
    }
}

impl InferredSchemaCache {
    fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(InferredSchemaCacheInner::default()),
        }
    }

    fn schema_for_request(
        &self,
        query_store: &DiscoveryQueryStore,
        method: &str,
        path: &str,
    ) -> Option<Arc<InferredRequestSchema>> {
        let endpoints = self.observed_endpoints(query_store);
        let endpoint_template = best_matching_endpoint_template(&endpoints, method, path)?;

        self.schema_for_endpoint(query_store, method, endpoint_template)
    }

    fn observed_endpoints(&self, query_store: &DiscoveryQueryStore) -> Arc<Vec<ObservedEndpoint>> {
        let now = Instant::now();
        if let Some(endpoints) = self.cached_observed_endpoints(now) {
            return endpoints;
        }

        let endpoints = Arc::new(query_store.observed_endpoints().unwrap_or_default());
        self.store_observed_endpoints(Arc::clone(&endpoints), Instant::now());
        endpoints
    }

    fn cached_observed_endpoints(&self, now: Instant) -> Option<Arc<Vec<ObservedEndpoint>>> {
        let inner = self.inner_guard();
        inner
            .observed_endpoints
            .as_ref()
            .and_then(|entry| entry.fresh_value(now))
    }

    fn store_observed_endpoints(&self, endpoints: Arc<Vec<ObservedEndpoint>>, now: Instant) {
        let mut inner = self.inner_guard();
        inner.observed_endpoints = Some(CacheEntry::new(endpoints, now + self.ttl));
    }

    fn schema_for_endpoint(
        &self,
        query_store: &DiscoveryQueryStore,
        method: &str,
        endpoint_template: &str,
    ) -> Option<Arc<InferredRequestSchema>> {
        let key = EndpointSchemaCacheKey {
            method: method.to_owned(),
            endpoint_template: endpoint_template.to_owned(),
        };
        let now = Instant::now();
        if let Some(schema) = self.cached_schema(&key, now) {
            return schema;
        }

        let schema = query_store
            .inferred_request_schema(method, endpoint_template)
            .ok()
            .flatten()
            .map(Arc::new);
        self.store_schema(key, schema.clone(), Instant::now());
        schema
    }

    fn cached_schema(
        &self,
        key: &EndpointSchemaCacheKey,
        now: Instant,
    ) -> Option<Option<Arc<InferredRequestSchema>>> {
        let inner = self.inner_guard();
        inner
            .schemas
            .get(key)
            .and_then(|entry| entry.fresh_value(now))
    }

    fn store_schema(
        &self,
        key: EndpointSchemaCacheKey,
        schema: Option<Arc<InferredRequestSchema>>,
        now: Instant,
    ) {
        let mut inner = self.inner_guard();
        inner
            .schemas
            .insert(key, CacheEntry::new(schema, now + self.ttl));
    }

    fn inner_guard(&self) -> std::sync::MutexGuard<'_, InferredSchemaCacheInner> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl<T: Clone> CacheEntry<T> {
    fn new(value: T, expires_at: Instant) -> Self {
        Self { value, expires_at }
    }

    fn fresh_value(&self, now: Instant) -> Option<T> {
        (now < self.expires_at).then(|| self.value.clone())
    }
}

/// The observed endpoint template that best matches `path` for `method`:
/// the most exact literal segments, then the fewest wildcard segments.
fn best_matching_endpoint_template<'a>(
    endpoints: &'a [ObservedEndpoint],
    method: &str,
    path: &str,
) -> Option<&'a str> {
    endpoints
        .iter()
        .filter(|endpoint| endpoint.method == method)
        .filter_map(|endpoint| {
            endpoint_template_match_score(&endpoint.endpoint_template, path)
                .map(|score| (score, endpoint.endpoint_template.as_str()))
        })
        .max_by(|(left, _), (right, _)| left.cmp(right))
        .map(|(_, endpoint_template)| endpoint_template)
}

impl Default for ClusterConformanceCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterConformanceCache {
    pub fn new() -> Self {
        Self::with_tracking_capacity(MAX_TRACKED_INFERRED_ENDPOINTS)
    }

    /// A cache tracking at most `capacity` wanted endpoints (the
    /// production value is `MAX_TRACKED_INFERRED_ENDPOINTS`).
    pub(crate) fn with_tracking_capacity(capacity: usize) -> Self {
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(ObservedSnapshot::default())),
            wanted: Mutex::new(WantedEndpoints::with_capacity(capacity)),
        }
    }

    /// The request-path lookup: match the path against the snapshot's
    /// endpoints and return the snapshot's schema for the match. A miss
    /// records the endpoint as wanted so the next refresh loads its
    /// schema; nothing here touches a store.
    fn schema_for_request(&self, method: &str, path: &str) -> Option<Arc<InferredRequestSchema>> {
        let snapshot = self.snapshot.load();
        let endpoint_template = best_matching_endpoint_template(&snapshot.endpoints, method, path)?;
        let key = EndpointSchemaCacheKey {
            method: method.to_owned(),
            endpoint_template: endpoint_template.to_owned(),
        };
        match snapshot.schemas.get(&key) {
            Some(schema) => Some(Arc::clone(schema)),
            None => {
                self.note_wanted(key);
                None
            }
        }
    }

    fn note_wanted(&self, key: EndpointSchemaCacheKey) {
        self.wanted_guard().note(key);
    }

    /// Load a fresh snapshot from `store`: every observed endpoint, and the
    /// inferred schemas of the wanted endpoints that are still observed
    /// (endpoints that are gone are dropped from the wanted set), read in
    /// one round trip for the whole set. On a failure the previous snapshot
    /// stays in service.
    pub(crate) async fn refresh(
        &self,
        store: &dyn DiscoveryReadStore,
    ) -> Result<(), DiscoveryQueryError> {
        let endpoints = store.observed_endpoints().await?;
        let observed = endpoints
            .iter()
            .map(|endpoint| EndpointSchemaCacheKey {
                method: endpoint.method.clone(),
                endpoint_template: endpoint.endpoint_template.clone(),
            })
            .collect::<BTreeSet<_>>();
        let wanted = {
            let mut wanted = self.wanted_guard();
            wanted.retain(|key| observed.contains(key));
            wanted.keys()
        };
        let requested = wanted
            .iter()
            .map(|key| (key.method.clone(), key.endpoint_template.clone()))
            .collect::<Vec<_>>();
        let schemas = store
            .inferred_request_schemas(&requested)
            .await?
            .into_iter()
            .zip(wanted)
            .filter_map(|(schema, key)| schema.map(|schema| (key, Arc::new(schema))))
            .collect::<BTreeMap<_, _>>();
        self.snapshot.store(Arc::new(ObservedSnapshot {
            endpoints: Arc::new(endpoints),
            schemas,
        }));
        Ok(())
    }

    /// The snapshot the request path is reading right now.
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> arc_swap::Guard<Arc<ObservedSnapshot>> {
        self.snapshot.load()
    }

    fn wanted_guard(&self) -> std::sync::MutexGuard<'_, WantedEndpoints> {
        match self.wanted.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

#[cfg(test)]
impl ObservedSnapshot {
    pub(crate) fn endpoints(&self) -> &[ObservedEndpoint] {
        &self.endpoints
    }

    pub(crate) fn schema_count(&self) -> usize {
        self.schemas.len()
    }
}

/// Keep `cache` current from `store` for the life of the process: one
/// refresh now, then one every `interval` until the lifecycle's background
/// cancellation fires. A refresh that fails is logged and the previous
/// snapshot keeps serving; the request path is never blocked on it.
#[cfg_attr(not(feature = "postgres"), allow(dead_code))] // Wired by cluster startup.
pub(crate) fn spawn_cluster_conformance_refresher(
    lifecycle: &GatewayLifecycle,
    cache: Arc<ClusterConformanceCache>,
    store: Arc<dyn DiscoveryReadStore>,
    interval: Duration,
) {
    let cancellation = lifecycle.background_cancellation();
    let handle = tokio::spawn(async move {
        loop {
            if let Err(error) = cache.refresh(store.as_ref()).await {
                tracing::warn!(
                    error = %error,
                    "cluster conformance snapshot refresh failed; the previous snapshot stays in service"
                );
            }
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                () = cancellation.cancelled() => return,
            }
        }
    });
    lifecycle.register_background_task(handle);
}

enum PreparedSchemaConformanceCheck {
    Undocumented,
    Expected {
        expected: ExpectedRequestShape,
        observed_shape: CapturedPayloadShape,
    },
}

impl PreparedSchemaConformanceCheck {
    fn needs_body_capture(&self) -> bool {
        match self {
            Self::Undocumented => false,
            Self::Expected { expected, .. } => expected.needs_body_capture(),
        }
    }

    fn schema_mismatch(
        &self,
        captured_shape: Option<&CapturedPayloadShape>,
        body_status: BodyCaptureStatus,
    ) -> Option<bool> {
        match self {
            Self::Undocumented => Some(true),
            Self::Expected {
                expected,
                observed_shape,
            } if expected.needs_body_capture() && body_status != BodyCaptureStatus::Complete => {
                None
            }
            Self::Expected {
                expected,
                observed_shape,
            } => {
                let observed = captured_shape.unwrap_or(observed_shape);
                // Same reasoning as an incomplete body capture: decline the
                // verdict rather than report a mismatch the cap manufactured.
                (!observed.is_truncated()).then(|| expected.mismatches(observed))
            }
        }
    }
}

#[derive(Clone)]
struct ExpectedRequestShape {
    required_query_params: Vec<CapturedFieldName>,
    required_json_body_keys: Vec<CapturedFieldName>,
}

impl ExpectedRequestShape {
    fn from_openapi(shape: &OpenApiRequestShape) -> Self {
        Self {
            required_query_params: shape
                .query_params
                .iter()
                .filter(|param| param.required)
                .map(|param| captured_field_name(&param.name))
                .collect(),
            required_json_body_keys: shape
                .json_body_keys
                .iter()
                .filter(|key| key.required)
                .map(|key| captured_field_name(&key.name))
                .collect(),
        }
    }

    fn from_inferred(schema: &InferredRequestSchema) -> Self {
        Self {
            required_query_params: schema
                .query_params
                .iter()
                .filter(|param| param.required)
                .filter_map(inferred_query_param_field)
                .collect(),
            required_json_body_keys: schema
                .json_body_keys
                .iter()
                .filter(|key| key.required)
                .filter_map(inferred_json_body_key_field)
                .collect(),
        }
    }

    fn needs_body_capture(&self) -> bool {
        !self.required_json_body_keys.is_empty()
    }

    fn mismatches(&self, observed: &CapturedPayloadShape) -> bool {
        self.required_query_params
            .iter()
            .any(|field| !observed.has_query_param(field))
            || self
                .required_json_body_keys
                .iter()
                .any(|field| !observed.has_json_body_key(field))
    }
}

fn inferred_query_param_field(param: &InferredQueryParam) -> Option<CapturedFieldName> {
    inferred_field_name(
        param.name.as_ref(),
        param.name_hash.as_ref(),
        param.redacted,
    )
}

fn inferred_json_body_key_field(key: &InferredJsonBodyKey) -> Option<CapturedFieldName> {
    inferred_field_name(key.name.as_ref(), key.name_hash.as_ref(), key.redacted)
}

fn inferred_field_name(
    name: Option<&String>,
    name_hash: Option<&String>,
    redacted: bool,
) -> Option<CapturedFieldName> {
    if name.is_none() && name_hash.is_none() {
        return None;
    }

    Some(CapturedFieldName {
        name: name.cloned(),
        name_hash: name_hash.cloned(),
        redacted,
    })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EndpointTemplateMatchScore {
    exact_literals: usize,
    wildcard_segments: usize,
}

fn endpoint_template_match_score(
    endpoint_template: &str,
    path: &str,
) -> Option<EndpointTemplateMatchScore> {
    let template_segments = split_path(endpoint_template);
    let path_segments = split_path(path);
    if template_segments.len() != path_segments.len() {
        return None;
    }

    let mut score = EndpointTemplateMatchScore {
        exact_literals: 0,
        wildcard_segments: 0,
    };
    for (template, segment) in template_segments.iter().zip(path_segments.iter()) {
        if is_placeholder_segment(template) {
            score.wildcard_segments += 1;
        } else if template == segment {
            score.exact_literals += 1;
        } else {
            return None;
        }
    }

    Some(score)
}

fn split_path(path: &str) -> Vec<&str> {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let path = path.strip_prefix('/').unwrap_or(path);

    if path.is_empty() {
        Vec::new()
    } else {
        path.split('/').collect()
    }
}

fn is_placeholder_segment(segment: &str) -> bool {
    segment.len() >= 3 && segment.starts_with('{') && segment.ends_with('}')
}

fn path_prefix_matches(path: &str, path_prefix: &str) -> bool {
    if path_prefix.is_empty() || !path_prefix.starts_with('/') {
        return false;
    }
    if path == path_prefix {
        return true;
    }

    path.strip_prefix(path_prefix)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

impl PayloadCaptureHandle {
    fn new(shape: CapturedPayloadShape) -> Self {
        Self {
            state: Arc::new(Mutex::new(PayloadCaptureState {
                shape,
                body_status: BodyCaptureStatus::NotObserved,
            })),
        }
    }

    pub fn capture_json_body(&self, headers: &HeaderMap, body: &[u8]) {
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let json_body = captured_json_body_shape(content_type, body);
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        state.shape.json_body = json_body;
        state.body_status = BodyCaptureStatus::Complete;
    }

    pub fn mark_body_capture_incomplete(&self) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if state.body_status != BodyCaptureStatus::Complete {
            state.body_status = BodyCaptureStatus::Incomplete;
        }
    }

    fn snapshot(&self) -> CapturedPayloadShape {
        match self.state.lock() {
            Ok(guard) => guard.shape.clone(),
            Err(poisoned) => poisoned.into_inner().shape.clone(),
        }
    }

    fn body_capture_status(&self) -> BodyCaptureStatus {
        match self.state.lock() {
            Ok(guard) => guard.body_status,
            Err(poisoned) => poisoned.into_inner().body_status,
        }
    }

    fn captured_data_snapshot(&self) -> Option<CapturedPayloadShape> {
        if self.body_capture_status() == BodyCaptureStatus::Incomplete {
            return None;
        }
        let shape = self.snapshot();
        shape.has_captured_data().then_some(shape)
    }
}

impl CapturedPayloadShape {
    fn from_query(query: Option<&str>) -> Self {
        let (query_params, query_params_truncated) = captured_query_params(query);
        Self {
            query_params,
            query_params_truncated,
            json_body: None,
        }
    }

    /// A truncated capture has seen only part of the request, so it can never
    /// prove a documented field absent.
    fn is_truncated(&self) -> bool {
        self.query_params_truncated
            || self
                .json_body
                .as_ref()
                .is_some_and(|json_body| json_body.top_level_keys_truncated)
    }

    fn has_captured_data(&self) -> bool {
        !self.query_params.is_empty() || self.json_body.is_some()
    }

    fn has_query_param(&self, field: &CapturedFieldName) -> bool {
        self.query_params.iter().any(|param| param.name == *field)
    }

    fn has_json_body_key(&self, field: &CapturedFieldName) -> bool {
        self.json_body
            .as_ref()
            .is_some_and(|json_body| json_body.top_level_keys.iter().any(|key| key == field))
    }
}

fn should_sample_payload_capture(
    config: &PayloadCaptureConfig,
    method: &str,
    path: &str,
    request_id: &str,
) -> bool {
    if config.sample_rate <= 0.0 {
        return false;
    }

    let seed = json!({
        "method": method,
        "path": path,
        "request_id": request_id,
    });
    hash_fraction(&hash_args(&seed)) < config.sample_rate
}

#[cfg(test)]
pub(crate) fn captured_payload_shape(
    query: Option<&str>,
    content_type: Option<&str>,
    body: Option<&[u8]>,
) -> Option<CapturedPayloadShape> {
    let mut shape = CapturedPayloadShape::from_query(query);
    if let Some(body) = body {
        shape.json_body = captured_json_body_shape(content_type, body);
    }

    shape.has_captured_data().then_some(shape)
}

fn captured_query_params(query: Option<&str>) -> (Vec<CapturedQueryParam>, bool) {
    let Some(query) = query else {
        return (Vec::new(), false);
    };
    let mut params = BTreeMap::<String, &'static str>::new();
    let mut truncated = false;

    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let value_type = query_value_type(value.trim());
        if let Some(existing) = params.get_mut(name) {
            *existing = merge_query_value_type(existing, value_type);
            continue;
        }
        if params.len() >= MAX_CAPTURED_QUERY_PARAMS {
            truncated = true;
            continue;
        }
        params.insert(name.to_owned(), value_type);
    }

    let params = params
        .into_iter()
        .map(|(name, value_type)| CapturedQueryParam {
            name: captured_field_name(&name),
            value_type: value_type.to_owned(),
        })
        .collect();

    (params, truncated)
}

/// Top-level object keys read without materializing the body: values are
/// discarded as they are parsed and keys stop being retained at the cap, so
/// neither the body's size nor its key count drives an allocation here.
struct TopLevelJsonObjectKeys {
    keys: BTreeSet<String>,
    truncated: bool,
}

impl<'de> Deserialize<'de> for TopLevelJsonObjectKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(TopLevelJsonObjectKeysVisitor)
    }
}

struct TopLevelJsonObjectKeysVisitor;

impl<'de> serde::de::Visitor<'de> for TopLevelJsonObjectKeysVisitor {
    type Value = TopLevelJsonObjectKeys;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        let mut truncated = false;
        while let Some(key) = map.next_key::<String>()? {
            map.next_value::<serde::de::IgnoredAny>()?;
            if keys.len() < MAX_CAPTURED_JSON_BODY_KEYS || keys.contains(&key) {
                keys.insert(key);
            } else {
                truncated = true;
            }
        }

        Ok(TopLevelJsonObjectKeys { keys, truncated })
    }
}

fn captured_json_body_shape(
    content_type: Option<&str>,
    body: &[u8],
) -> Option<CapturedJsonBodyShape> {
    if !is_json_content_type(content_type?) {
        return None;
    }

    let object = serde_json::from_slice::<TopLevelJsonObjectKeys>(body).ok()?;

    Some(CapturedJsonBodyShape {
        top_level_keys: object
            .keys
            .iter()
            .map(|key| captured_field_name(key))
            .collect::<Vec<_>>(),
        top_level_keys_truncated: object.truncated,
    })
}

fn is_json_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/json"))
}

fn captured_field_name(name: &str) -> CapturedFieldName {
    if is_sensitive_field_name(name) {
        let normalized = normalized_field_name(name);
        CapturedFieldName {
            name: None,
            name_hash: Some(sha256_hex(normalized.as_bytes())),
            redacted: true,
        }
    } else {
        CapturedFieldName {
            name: Some(name.to_owned()),
            name_hash: None,
            redacted: false,
        }
    }
}

fn is_sensitive_field_name(name: &str) -> bool {
    const MARKERS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "ssn",
        "socialsecurity",
        "token",
        "secret",
        "apikey",
        "credential",
        "creditcard",
        "cardnumber",
        "authorization",
        "jwt",
        "bearer",
    ];

    let normalized = normalized_field_name(name);
    MARKERS.iter().any(|marker| normalized.contains(marker))
}

fn normalized_field_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn query_value_type(value: &str) -> &'static str {
    if value.parse::<f64>().is_ok_and(f64::is_finite) {
        "number"
    } else {
        "string"
    }
}

fn merge_query_value_type(left: &'static str, right: &'static str) -> &'static str {
    if left == right {
        left
    } else {
        "string"
    }
}

fn hash_fraction(hash: &str) -> f64 {
    let hex = hash.strip_prefix("sha256:").unwrap_or(hash);
    let prefix = hex.get(..16).unwrap_or(hex);
    let value = u64::from_str_radix(prefix, 16).unwrap_or(0);
    value as f64 / u64::MAX as f64
}

fn auth_outcome_label(auth_outcome: Option<&AuthOutcome>) -> &'static str {
    match auth_outcome {
        Some(outcome) if outcome.authenticated => "authenticated",
        Some(_) => "anonymous_or_failed",
        None => "not_evaluated",
    }
}

fn policy_decision_label(policy_decision: Option<&PolicyDecision>) -> &'static str {
    match policy_decision {
        Some(decision) => match decision.outcome {
            PolicyDecisionOutcome::Allowed => "allowed",
            PolicyDecisionOutcome::Denied => "denied",
            PolicyDecisionOutcome::WouldDeny => "would_deny",
        },
        None => "not_evaluated",
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        fs,
        path::PathBuf,
        sync::Arc,
        time::{Duration, Instant},
    };

    use axum::{
        body::Body,
        middleware::{from_fn, from_fn_with_state},
        response::IntoResponse,
        routing::{any, get},
        Router,
    };
    use http::{
        header::{AUTHORIZATION, CONTENT_TYPE},
        Method, Request, StatusCode,
    };
    use rusqlite::{params, Connection};
    use serde_json::json;
    use tower::ServiceExt;

    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};

    use super::*;
    use crate::{
        audit::{sink::tests::CaptureSink, AuditSink},
        auth::{AuthError, AuthMethod, Principal, SessionCredential, SessionValidator},
        discovery::{
            lifecycle::{TransitionOutcome, TransitionPrecondition},
            openapi::{OpenApiSpec, SchemaCoverage},
            query::{
                DiscoveryQueryStore, EndpointAggregateDetail, EndpointListFilters,
                EndpointListPage, EndpointReviewState, PrincipalPage, PrincipalPageFilters,
            },
            signals::{Signal, SignalLifecycleState, SignalListFilters, SignalListPage},
        },
        middleware::{auth, rbac},
        rbac::{
            policy::{EgressPolicy, RoleEntry},
            DefaultAction, EnforcementMode, Policy, PrincipalMatcher, RouteRule, Rule, RuleAction,
        },
        storage::{RepositoryError, RepositoryErrorKind},
    };

    #[test]
    fn incomplete_stream_capture_is_omitted_and_body_conformance_is_unknown() {
        let handle = PayloadCaptureHandle::new(CapturedPayloadShape::from_query(Some("page=1")));
        handle.mark_body_capture_incomplete();

        assert_eq!(handle.body_capture_status(), BodyCaptureStatus::Incomplete);
        assert!(handle.captured_data_snapshot().is_none());

        let check = PreparedSchemaConformanceCheck::Expected {
            expected: ExpectedRequestShape {
                required_query_params: Vec::new(),
                required_json_body_keys: vec![captured_field_name("message")],
            },
            observed_shape: CapturedPayloadShape::from_query(None),
        };
        assert_eq!(
            check.schema_mismatch(Some(&handle.snapshot()), handle.body_capture_status()),
            None
        );
    }

    #[test]
    fn complete_non_json_stream_capture_is_truthfully_complete() {
        let handle = PayloadCaptureHandle::new(CapturedPayloadShape::from_query(None));
        handle.capture_json_body(&HeaderMap::new(), b"opaque bytes");

        assert_eq!(handle.body_capture_status(), BodyCaptureStatus::Complete);
        assert!(handle.snapshot().json_body.is_none());
    }

    #[derive(Clone)]
    enum FakeAuthLayer {
        Success(Principal),
        Failure(&'static str),
    }

    #[derive(Clone)]
    enum FakePolicyLayer {
        Allowed,
        Denied,
        WouldDeny,
    }

    #[derive(Clone)]
    struct MockValidator {
        outcome: Result<Principal, &'static str>,
    }

    #[async_trait::async_trait]
    impl SessionValidator for MockValidator {
        async fn validate_session(
            &self,
            _credential: &SessionCredential,
        ) -> Result<Principal, AuthError> {
            self.outcome
                .clone()
                .map_err(|reason| AuthError::InvalidSession(reason.to_owned()))
        }
    }

    #[tokio::test]
    async fn observation_only_emits_not_evaluated_event() {
        let (state, capture) = test_observation_state();

        let response = observation_router(state)
            .oneshot(request(Method::GET, "/", "request-observed-only"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(capture.events().len(), 1);
        assert_eq!(event.request_id, "request-observed-only");
        assert_eq!(event.payload["method"], json!("GET"));
        assert_eq!(event.payload["path"], json!("/"));
        assert_eq!(event.payload["status"], json!(200));
        assert!(event.payload["latency_ms"].as_u64().is_some());
        assert_eq!(event.payload["auth_outcome"], json!("not_evaluated"));
        assert_eq!(event.payload["policy_decision"], json!("not_evaluated"));
        assert!(event.actor.is_none());
    }

    #[tokio::test]
    async fn payload_capture_disabled_by_default_omits_shape_from_observation_events() {
        let (state, capture) = test_observation_state();

        let response = observation_router(state)
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/?token=fake-token-value")
                    .header(crate::REQUEST_ID_HEADER, "request-payload-disabled")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        r#"{"password":"correct horse battery staple","name":"Alice"}"#,
                    ))
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert!(event.payload.get("payload_shape").is_none());
    }

    #[test]
    fn payload_capture_sampling_rate_less_than_one_does_not_sample_every_request() {
        let config = PayloadCaptureConfig { sample_rate: 0.5 };
        let sampled = (0..200)
            .filter(|index| {
                should_sample_payload_capture(
                    &config,
                    "POST",
                    "/widgets",
                    &format!("request-{index}"),
                )
            })
            .count();

        assert!(sampled > 0, "sample rate should accept some requests");
        assert!(
            sampled < 200,
            "sample rate below 1.0 must not accept every request"
        );
    }

    #[test]
    fn payload_capture_shape_never_includes_query_or_json_values() {
        let shape = captured_payload_shape(
            Some("page=123&filter=Alice&card=4111111111111111"),
            Some("application/json"),
            Some(
                br#"{
                    "name": "Alice",
                    "address": { "city": "Portland" },
                    "ssn": "123-45-6789"
                }"#,
            ),
        )
        .expect("shape should be captured");

        let serialized = serde_json::to_string(&shape).expect("shape should serialize");

        assert!(serialized.contains(r#""name":"page""#));
        assert!(serialized.contains(r#""value_type":"number""#));
        assert!(serialized.contains(r#""name":"filter""#));
        assert!(serialized.contains(r#""name":"address""#));
        for forbidden in ["123-45-6789", "4111111111111111", "Alice", "Portland"] {
            assert!(
                !serialized.contains(forbidden),
                "captured shape leaked value {forbidden}: {serialized}"
            );
        }
    }

    #[test]
    fn payload_capture_redacts_sensitive_query_and_body_key_names() {
        let shape = captured_payload_shape(
            Some("token=fake-token&safe=visible"),
            Some("application/json"),
            Some(br#"{"password":"secret","ssn":"123-45-6789","name":"Alice"}"#),
        )
        .expect("shape should be captured");

        let serialized = serde_json::to_string(&shape).expect("shape should serialize");

        assert!(serialized.contains(r#""name":"safe""#));
        assert!(serialized.contains(r#""name":"name""#));
        assert!(serialized.contains(r#""redacted":true"#));
        assert!(serialized.contains(r#""name_hash":"sha256:"#));
        for forbidden in ["token", "password", "ssn"] {
            assert!(
                !serialized.contains(forbidden),
                "sensitive key name leaked verbatim: {serialized}"
            );
        }
    }

    #[test]
    fn payload_capture_caps_query_parameter_and_body_key_counts() {
        let query = (0..MAX_CAPTURED_QUERY_PARAMS * 4)
            .map(|index| format!("q{index}=1"))
            .collect::<Vec<_>>()
            .join("&");
        let body = format!(
            "{{{}}}",
            (0..MAX_CAPTURED_JSON_BODY_KEYS * 4)
                .map(|index| format!("\"k{index}\":1"))
                .collect::<Vec<_>>()
                .join(",")
        );

        let shape = captured_payload_shape(
            Some(&query),
            Some("application/json"),
            Some(body.as_bytes()),
        )
        .expect("shape should be captured");

        assert_eq!(shape.query_params.len(), MAX_CAPTURED_QUERY_PARAMS);
        assert!(shape.query_params_truncated);
        let json_body = shape.json_body.as_ref().expect("body shape should capture");
        assert_eq!(json_body.top_level_keys.len(), MAX_CAPTURED_JSON_BODY_KEYS);
        assert!(json_body.top_level_keys_truncated);
        assert!(shape.is_truncated());
    }

    #[test]
    fn payload_capture_keeps_every_field_below_the_cap() {
        let shape = captured_payload_shape(
            Some("page=1&filter=alpha"),
            Some("application/json"),
            Some(br#"{"name":"Alice","city":"Portland"}"#),
        )
        .expect("shape should be captured");

        assert_eq!(shape.query_params.len(), 2);
        let json_body = shape.json_body.as_ref().expect("body shape should capture");
        assert_eq!(json_body.top_level_keys.len(), 2);
        assert!(!shape.is_truncated());

        let serialized = serde_json::to_string(&shape).expect("shape should serialize");
        assert!(
            !serialized.contains("truncated"),
            "an untruncated capture must serialize exactly as before: {serialized}"
        );
    }

    #[test]
    fn truncated_capture_declines_a_schema_conformance_verdict() {
        let expected = ExpectedRequestShape {
            required_query_params: vec![captured_field_name("beyond-the-cap")],
            required_json_body_keys: Vec::new(),
        };
        let query = (0..MAX_CAPTURED_QUERY_PARAMS * 2)
            .map(|index| format!("q{index}=1"))
            .collect::<Vec<_>>()
            .join("&");
        let observed_shape = CapturedPayloadShape::from_query(Some(&query));
        assert!(observed_shape.is_truncated());
        assert!(
            expected.mismatches(&observed_shape),
            "the required field is genuinely absent from the truncated capture"
        );

        let check = PreparedSchemaConformanceCheck::Expected {
            expected,
            observed_shape,
        };

        assert_eq!(
            check.schema_mismatch(None, BodyCaptureStatus::NotObserved),
            None,
            "a capped capture must not manufacture a schema mismatch"
        );
    }

    #[test]
    fn payload_capture_skips_non_json_bodies() {
        assert_eq!(
            captured_payload_shape(None, Some("text/plain"), Some(b"hello=world")),
            None
        );
        assert_eq!(
            captured_payload_shape(
                None,
                Some("application/json"),
                Some(br#"["array contents are not captured"]"#)
            ),
            None
        );
    }

    #[tokio::test]
    async fn observed_authenticated_marker_populates_actor() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakeAuthLayer::Success(test_principal(&["reader"])),
                fake_auth_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-authenticated"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(
            event.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }

    #[tokio::test]
    async fn observed_upstream_marker_is_reported() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn(fake_upstream_layer))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/")
                    .header("host", "API.EXAMPLE.TEST:8443")
                    .header("x-request-id", "request-upstream")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["upstream_latency_ms"], json!(42));
        assert_eq!(event.payload["upstream_status"], json!(201));
        assert_eq!(event.payload["request_host"], json!("api.example.test"));
        assert_eq!(
            event.payload["upstream_route_host"],
            json!("api.example.test")
        );
        assert_eq!(event.payload["upstream_route_path_prefix"], json!("/api"));
        assert_eq!(
            event.payload["upstream_origin"],
            json!("https://upstream.example.test")
        );
    }

    #[tokio::test]
    async fn spec_conformance_flags_missing_required_query_param() {
        let spec = OpenApiSpec::parse_str(
            "inline.yaml",
            r#"
openapi: 3.0.3
info:
  title: Test
  version: 1.0.0
paths:
  /users/{userId}:
    get:
      parameters:
        - in: query
          name: page
          required: true
"#,
        )
        .expect("spec should parse");
        let (state, capture) =
            test_observation_state_with_conformance(SchemaConformanceState::new_for_test(
                SchemaCoverage::global_for_test(spec),
                None,
                false,
            ));

        let missing = observation_router(state.clone())
            .oneshot(request(Method::GET, "/users/123", "request-spec-missing"))
            .await
            .expect("request should complete");
        assert_eq!(missing.status(), StatusCode::OK);

        let present = observation_router(state)
            .oneshot(request(
                Method::GET,
                "/users/123?page=1",
                "request-spec-present",
            ))
            .await
            .expect("request should complete");
        assert_eq!(present.status(), StatusCode::OK);

        assert_eventually(Duration::from_secs(1), || capture.events().len() == 2);
        let events = capture.events();
        let missing = events
            .iter()
            .find(|event| event.request_id == "request-spec-missing")
            .expect("missing-param event should be captured");
        let present = events
            .iter()
            .find(|event| event.request_id == "request-spec-present")
            .expect("present-param event should be captured");

        assert_eq!(missing.payload["schema_mismatch"], json!(true));
        assert_eq!(present.payload["schema_mismatch"], json!(false));
    }

    #[tokio::test]
    async fn inferred_conformance_respects_minimum_sample_count_gate() {
        let high_confidence_db = TempDb::new("observation-inferred-high");
        seed_endpoint(&high_confidence_db.path, "POST", "/users");
        seed_payload_shape_samples(
            &high_confidence_db.path,
            "POST",
            "/users",
            &vec![
                json!({
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false }
                        ]
                    }
                });
                MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT as usize
            ],
        );
        let high_store = Arc::new(
            DiscoveryQueryStore::open(&high_confidence_db.path)
                .expect("discovery query store should open"),
        );
        let (high_state, high_capture) = test_observation_state_with_conformance(
            SchemaConformanceState::new_for_test(SchemaCoverage::default(), Some(high_store), true),
        );

        let high_response = body_capture_router(high_state)
            .oneshot(json_request(
                "/users",
                "request-inferred-high",
                r#"{"other":"value"}"#,
            ))
            .await
            .expect("request should complete");
        assert_eq!(high_response.status(), StatusCode::OK);
        let high_event = one_observation_event(&high_capture).await;
        assert_eq!(high_event.payload["schema_mismatch"], json!(true));

        let low_confidence_db = TempDb::new("observation-inferred-low");
        seed_endpoint(&low_confidence_db.path, "POST", "/users");
        seed_payload_shape_samples(
            &low_confidence_db.path,
            "POST",
            "/users",
            &[
                json!({
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false }
                        ]
                    }
                }),
                json!({
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false }
                        ]
                    }
                }),
            ],
        );
        let low_store = Arc::new(
            DiscoveryQueryStore::open(&low_confidence_db.path)
                .expect("discovery query store should open"),
        );
        let (low_state, low_capture) = test_observation_state_with_conformance(
            SchemaConformanceState::new_for_test(SchemaCoverage::default(), Some(low_store), true),
        );

        let low_response = body_capture_router(low_state)
            .oneshot(json_request(
                "/users",
                "request-inferred-low",
                r#"{"other":"value"}"#,
            ))
            .await
            .expect("request should complete");
        assert_eq!(low_response.status(), StatusCode::OK);
        let low_event = one_observation_event(&low_capture).await;
        assert!(low_event.payload.get("schema_mismatch").is_none());
    }

    #[test]
    fn inferred_conformance_reuses_lookup_for_repeated_same_endpoint_checks() {
        let db = TempDb::new("observation-inferred-cache-reuse");
        for index in 0..250 {
            let endpoint_template = format!("/noise/{index}");
            seed_endpoint(&db.path, "POST", &endpoint_template);
        }
        seed_endpoint(&db.path, "POST", "/users");
        seed_payload_shape_samples(
            &db.path,
            "POST",
            "/users",
            &vec![
                json!({
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false }
                        ]
                    }
                });
                MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT as usize
            ],
        );
        let store = Arc::new(DiscoveryQueryStore::open(&db.path).expect("query store should open"));
        let conformance = SchemaConformanceState::new_for_test(
            SchemaCoverage::default(),
            Some(Arc::clone(&store)),
            true,
        );

        let first = conformance
            .prepare_check("POST", "/users", None)
            .expect("inferred conformance check should be prepared");
        assert!(first.needs_body_capture());
        assert_eq!(store.query_counts_for_test(), (1, 1));

        for _ in 0..10 {
            let check = conformance
                .prepare_check("POST", "/users", None)
                .expect("cached inferred conformance check should be prepared");
            assert!(check.needs_body_capture());
        }

        assert_eq!(
            store.query_counts_for_test(),
            (1, 1),
            "repeated checks for the same inferred endpoint must not rescan endpoints or reparse stored samples"
        );
    }

    #[test]
    fn inferred_conformance_refreshes_cached_schema_after_ttl() {
        let db = TempDb::new("observation-inferred-cache-refresh");
        seed_endpoint(&db.path, "POST", "/users");
        seed_payload_shape_samples(
            &db.path,
            "POST",
            "/users",
            &vec![
                json!({
                    "json_body": {
                        "top_level_keys": [
                            { "name": "display_name", "redacted": false }
                        ]
                    }
                });
                MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT as usize
            ],
        );
        let store = Arc::new(DiscoveryQueryStore::open(&db.path).expect("query store should open"));
        // A generous TTL keeps this test reliable under parallel workspace test
        // execution: the DB churn between the "still cached" and "refreshed"
        // checks below (deleting and reseeding samples) can itself take tens of
        // milliseconds under CPU contention, so a tight TTL risks the window
        // expiring before the "still cached" assertion runs.
        let ttl = Duration::from_millis(300);
        let conformance = SchemaConformanceState::new_for_test_with_cache_ttl(
            SchemaCoverage::default(),
            Some(Arc::clone(&store)),
            true,
            ttl,
        );
        let display_name_shape = captured_payload_shape(
            None,
            Some("application/json"),
            Some(r#"{"display_name":"Alice"}"#.as_bytes()),
        )
        .expect("display_name shape should capture");

        let first = conformance
            .prepare_check("POST", "/users", None)
            .expect("initial inferred conformance check should be prepared");
        assert_eq!(
            first.schema_mismatch(Some(&display_name_shape), BodyCaptureStatus::Complete),
            Some(false)
        );
        assert_eq!(store.query_counts_for_test(), (1, 1));

        replace_payload_shape_samples(
            &db.path,
            "POST",
            "/users",
            &vec![
                json!({
                    "json_body": {
                        "top_level_keys": [
                            { "name": "nickname", "redacted": false }
                        ]
                    }
                });
                MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT as usize
            ],
        );

        let cached = conformance
            .prepare_check("POST", "/users", None)
            .expect("cached inferred conformance check should be prepared");
        assert_eq!(
            cached.schema_mismatch(Some(&display_name_shape), BodyCaptureStatus::Complete),
            Some(false)
        );
        assert_eq!(store.query_counts_for_test(), (1, 1));

        std::thread::sleep(ttl + Duration::from_millis(150));

        let refreshed = conformance
            .prepare_check("POST", "/users", None)
            .expect("refreshed inferred conformance check should be prepared");
        assert_eq!(
            refreshed.schema_mismatch(Some(&display_name_shape), BodyCaptureStatus::Complete),
            Some(true)
        );
        assert_eq!(store.query_counts_for_test(), (2, 2));
    }

    /// A read store that counts what the refresher asks of it and can be
    /// made to fail. The methods the conformance path never needs are
    /// unreachable: reaching one is a test failure, not a stub answer.
    struct CountingReadStore {
        endpoints: Mutex<Vec<ObservedEndpoint>>,
        schemas: Vec<InferredRequestSchema>,
        observed_calls: AtomicU64,
        inferred_calls: AtomicU64,
        fail: AtomicBool,
    }

    impl CountingReadStore {
        fn new(endpoints: Vec<ObservedEndpoint>, schemas: Vec<InferredRequestSchema>) -> Self {
            Self {
                endpoints: Mutex::new(endpoints),
                schemas,
                observed_calls: AtomicU64::new(0),
                inferred_calls: AtomicU64::new(0),
                fail: AtomicBool::new(false),
            }
        }

        /// `(observed_endpoints calls, inferred_request_schema calls)`.
        fn counts(&self) -> (u64, u64) {
            (
                self.observed_calls.load(AtomicOrdering::Relaxed),
                self.inferred_calls.load(AtomicOrdering::Relaxed),
            )
        }

        fn set_endpoints(&self, endpoints: Vec<ObservedEndpoint>) {
            *self.endpoints.lock().expect("endpoints lock") = endpoints;
        }

        fn set_failing(&self, failing: bool) {
            self.fail.store(failing, AtomicOrdering::Relaxed);
        }

        fn failure(&self) -> Result<(), DiscoveryQueryError> {
            if self.fail.load(AtomicOrdering::Relaxed) {
                Err(DiscoveryQueryError::Repository(RepositoryError::new(
                    RepositoryErrorKind::Unavailable,
                    "counting_read_store",
                )))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait::async_trait]
    impl DiscoveryReadStore for CountingReadStore {
        async fn observed_endpoints(&self) -> Result<Vec<ObservedEndpoint>, DiscoveryQueryError> {
            self.observed_calls.fetch_add(1, AtomicOrdering::Relaxed);
            self.failure()?;
            Ok(self.endpoints.lock().expect("endpoints lock").clone())
        }

        async fn list_endpoints_with_open_signal_summaries(
            &self,
            _filters: &EndpointListFilters,
            _include_open_signals: bool,
        ) -> Result<EndpointListPage, DiscoveryQueryError> {
            unreachable!("the conformance path never lists endpoints")
        }

        async fn get_endpoint_with_open_signal_summaries(
            &self,
            _method: &str,
            _endpoint_template: &str,
            _new_since_hours: u64,
            _include_open_signals: bool,
        ) -> Result<Option<EndpointAggregateDetail>, DiscoveryQueryError> {
            unreachable!("the conformance path never reads endpoint detail")
        }

        async fn inferred_request_schema(
            &self,
            method: &str,
            endpoint_template: &str,
        ) -> Result<Option<InferredRequestSchema>, DiscoveryQueryError> {
            self.inferred_calls.fetch_add(1, AtomicOrdering::Relaxed);
            self.failure()?;
            Ok(self
                .schemas
                .iter()
                .find(|schema| {
                    schema.method == method && schema.endpoint_template == endpoint_template
                })
                .cloned())
        }

        async fn set_endpoint_review(
            &self,
            _method: &str,
            _endpoint_template: &str,
            _reviewed: bool,
            _reviewed_by: Option<&str>,
            _expected_revision: Option<i64>,
        ) -> Result<TransitionOutcome<EndpointReviewState>, DiscoveryQueryError> {
            unreachable!("the conformance path never writes reviews")
        }

        async fn list_signals(
            &self,
            _filters: &SignalListFilters,
        ) -> Result<SignalListPage, DiscoveryQueryError> {
            unreachable!("the conformance path never lists signals")
        }

        async fn list_principal_endpoint_signals(
            &self,
            _principal: &str,
            _issuer: &str,
            _auth_method: &str,
            _limit: usize,
        ) -> Result<Vec<Signal>, DiscoveryQueryError> {
            unreachable!("the conformance path never lists principal signals")
        }

        async fn transition_signal(
            &self,
            _signal_id: &str,
            _state: SignalLifecycleState,
            _transitioned_by: Option<&str>,
            _expected: TransitionPrecondition<SignalLifecycleState>,
        ) -> Result<TransitionOutcome<Signal>, DiscoveryQueryError> {
            unreachable!("the conformance path never transitions signals")
        }

        async fn list_principals(
            &self,
            _method: &str,
            _endpoint_template: &str,
            _filters: &PrincipalPageFilters,
        ) -> Result<PrincipalPage, DiscoveryQueryError> {
            unreachable!("the conformance path never lists principals")
        }
    }

    fn observed(method: &str, endpoint_template: &str) -> ObservedEndpoint {
        ObservedEndpoint {
            method: method.to_owned(),
            endpoint_template: endpoint_template.to_owned(),
            route_host: None,
            route_path_prefix: None,
            upstream_origin: None,
            routing_context_known_since: None,
        }
    }

    fn inferred_schema_with_required_body_key(
        method: &str,
        endpoint_template: &str,
        key: &str,
        sample_count: u64,
    ) -> InferredRequestSchema {
        InferredRequestSchema {
            method: method.to_owned(),
            endpoint_template: endpoint_template.to_owned(),
            sample_count,
            required_threshold: crate::discovery::query::INFERRED_SCHEMA_REQUIRED_THRESHOLD,
            query_params: Vec::new(),
            json_body_keys: vec![InferredJsonBodyKey {
                name: Some(key.to_owned()),
                name_hash: None,
                redacted: false,
                present_count: sample_count,
                frequency: 1.0,
                required: true,
            }],
        }
    }

    fn cluster_conformance(cache: &Arc<ClusterConformanceCache>) -> SchemaConformanceState {
        SchemaConformanceState::new_for_test_with_source(
            SchemaCoverage::default(),
            Some(InferredSchemaSource::Cluster(Arc::clone(cache))),
            true,
        )
    }

    /// PR 11 contract test 8: in cluster mode the conformance hot path
    /// reads the refreshed snapshot and nothing else. The state holds no
    /// store handle at all; every read of the authority is the refresher's,
    /// and a thousand requests add none.
    #[tokio::test]
    async fn the_request_path_never_queries_the_authority() {
        let store = Arc::new(CountingReadStore::new(
            vec![observed("POST", "/users"), observed("GET", "/health")],
            vec![inferred_schema_with_required_body_key(
                "POST",
                "/users",
                "display_name",
                MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT,
            )],
        ));
        let cache = Arc::new(ClusterConformanceCache::new());
        let conformance = cluster_conformance(&cache);

        // Before the first refresh the snapshot is empty: no check, no read.
        assert!(conformance.prepare_check("POST", "/users", None).is_none());
        assert_eq!(store.counts(), (0, 0));

        cache.refresh(store.as_ref()).await.expect("first refresh");
        assert_eq!(cache.snapshot().endpoints().len(), 2);
        assert_eq!(
            store.counts(),
            (1, 0),
            "nothing was wanted yet, so no schema was read"
        );

        // The first request for the endpoint finds no schema in the
        // snapshot (and prepares no check), and records the endpoint as
        // wanted -- without reading the store.
        assert!(conformance.prepare_check("POST", "/users", None).is_none());
        assert!(conformance.prepare_check("GET", "/health", None).is_none());
        assert_eq!(store.counts(), (1, 0));

        cache.refresh(store.as_ref()).await.expect("second refresh");
        assert_eq!(
            store.counts(),
            (2, 2),
            "the refresh read one schema per wanted endpoint"
        );
        assert_eq!(
            cache.snapshot().schema_count(),
            1,
            "only the endpoint with samples has a schema"
        );

        for _ in 0..1_000 {
            let check = conformance
                .prepare_check("POST", "/users", None)
                .expect("the snapshot schema prepares the check");
            assert!(check.needs_body_capture());
            assert!(conformance.prepare_check("GET", "/health", None).is_none());
        }
        assert_eq!(
            store.counts(),
            (2, 2),
            "a thousand requests made zero reads of the authority"
        );
    }

    /// A failed refresh keeps the previous snapshot in service, and a
    /// successful one drops endpoints the authority no longer lists (and
    /// stops asking for their schemas).
    #[tokio::test]
    async fn cluster_conformance_refresh_keeps_serving_through_failures_and_prunes_gone_endpoints()
    {
        let store = Arc::new(CountingReadStore::new(
            vec![observed("POST", "/users")],
            vec![inferred_schema_with_required_body_key(
                "POST",
                "/users",
                "display_name",
                MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT,
            )],
        ));
        let cache = Arc::new(ClusterConformanceCache::new());
        let conformance = cluster_conformance(&cache);

        cache.refresh(store.as_ref()).await.expect("refresh");
        assert!(conformance.prepare_check("POST", "/users", None).is_none());
        cache.refresh(store.as_ref()).await.expect("refresh");
        assert!(conformance.prepare_check("POST", "/users", None).is_some());
        assert_eq!(store.counts(), (2, 1));

        store.set_failing(true);
        let error = cache
            .refresh(store.as_ref())
            .await
            .expect_err("the refresh reports the store failure");
        assert!(matches!(error, DiscoveryQueryError::Repository(_)));
        assert_eq!(cache.snapshot().endpoints().len(), 1);
        assert_eq!(cache.snapshot().schema_count(), 1);
        assert!(
            conformance.prepare_check("POST", "/users", None).is_some(),
            "the previous snapshot keeps serving"
        );

        store.set_failing(false);
        store.set_endpoints(Vec::new());
        cache.refresh(store.as_ref()).await.expect("refresh");
        assert!(cache.snapshot().endpoints().is_empty());
        assert_eq!(cache.snapshot().schema_count(), 0);
        assert!(conformance.prepare_check("POST", "/users", None).is_none());
        let (_, inferred_before) = store.counts();
        cache.refresh(store.as_ref()).await.expect("refresh");
        assert_eq!(
            store.counts().1,
            inferred_before,
            "an endpoint the authority no longer lists is no longer asked about"
        );
    }

    /// The tracked set is bounded, and at the bound the endpoint asked
    /// about least recently makes room: an endpoint first seen after the
    /// bound is reached still gets its schema on the next refresh, instead
    /// of being locked out for the life of the replica.
    #[tokio::test]
    async fn cluster_conformance_tracks_endpoints_past_the_bound_by_replacing_the_least_recent() {
        let schema = |template: &str| {
            inferred_schema_with_required_body_key(
                "POST",
                template,
                "display_name",
                MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT,
            )
        };
        let store = Arc::new(CountingReadStore::new(
            vec![
                observed("POST", "/a"),
                observed("POST", "/b"),
                observed("POST", "/c"),
            ],
            vec![schema("/a"), schema("/b"), schema("/c")],
        ));
        let cache = Arc::new(ClusterConformanceCache::with_tracking_capacity(2));
        let conformance = cluster_conformance(&cache);
        cache.refresh(store.as_ref()).await.expect("refresh");

        // /a then /b fill the set; /c arrives at the bound and replaces
        // /a, the least recently asked about.
        for path in ["/a", "/b", "/c"] {
            assert!(conformance.prepare_check("POST", path, None).is_none());
        }
        cache.refresh(store.as_ref()).await.expect("refresh");
        assert_eq!(cache.snapshot().schema_count(), 2);
        assert!(conformance.prepare_check("POST", "/b", None).is_some());
        assert!(
            conformance.prepare_check("POST", "/c", None).is_some(),
            "the endpoint seen after the bound was reached is served"
        );
        // Asking for /a again (a miss) replaces /b, the least recent ask,
        // and the next refresh serves /a.
        assert!(conformance.prepare_check("POST", "/a", None).is_none());
        cache.refresh(store.as_ref()).await.expect("refresh");
        assert!(conformance.prepare_check("POST", "/a", None).is_some());
        assert!(conformance.prepare_check("POST", "/c", None).is_some());
        assert!(conformance.prepare_check("POST", "/b", None).is_none());
    }

    #[tokio::test]
    async fn no_schema_available_omits_schema_mismatch_and_shape_capture_handle() {
        let (state, capture) = test_observation_state();

        let response = no_shape_handle_router(state)
            .oneshot(json_request(
                "/users",
                "request-no-schema",
                r#"{"display_name":"Alice"}"#,
            ))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let event = one_observation_event(&capture).await;
        assert!(event.payload.get("schema_mismatch").is_none());
        assert!(event.payload.get("payload_shape").is_none());
    }

    #[tokio::test]
    async fn observed_failed_auth_marker_still_emits_rejection_event() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakeAuthLayer::Failure("missing_credential"),
                fake_auth_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-auth-failed"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["status"], json!(401));
        assert_eq!(event.payload["auth_outcome"], json!("anonymous_or_failed"));
        assert_eq!(event.payload["auth_reason"], json!("missing_credential"));
        assert!(event.actor.is_none());
    }

    #[tokio::test]
    async fn observed_allowed_policy_marker_is_reported() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakePolicyLayer::Allowed,
                fake_policy_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-policy-allowed"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["policy_decision"], json!("allowed"));
        assert_eq!(event.payload["policy_reason"], json!("matched_rule"));
        assert_eq!(event.payload["permission"], json!("data:read"));
        assert!(event.payload.get("matched_rule_id").is_none());
    }

    #[tokio::test]
    async fn observed_denied_policy_marker_still_emits_rejection_event() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakePolicyLayer::Denied,
                fake_policy_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-policy-denied"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["status"], json!(403));
        assert_eq!(event.payload["policy_decision"], json!("denied"));
        assert_eq!(event.payload["policy_reason"], json!("missing_permission"));
        assert_eq!(event.payload["permission"], json!("data:read"));
        assert!(event.payload.get("matched_rule_id").is_none());
    }

    #[tokio::test]
    async fn observed_would_deny_policy_marker_is_distinct_from_allowed() {
        let (state, capture) = test_observation_state();

        let response = base_router()
            .layer(from_fn_with_state(
                FakePolicyLayer::WouldDeny,
                fake_policy_layer,
            ))
            .layer(from_fn_with_state(state, observation_middleware))
            .oneshot(request(Method::GET, "/", "request-policy-would-deny"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["status"], json!(200));
        assert_eq!(event.payload["policy_decision"], json!("would_deny"));
        assert_eq!(event.payload["policy_reason"], json!("missing_permission"));
        assert_eq!(event.payload["permission"], json!("data:read"));
        assert_eq!(event.payload["path_prefix"], json!("/data"));
        assert!(event.payload.get("matched_rule_id").is_none());
    }

    #[tokio::test]
    async fn observation_correlates_with_real_auth_and_rbac_allowed_events() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy(
                DefaultAction::Deny,
                &[("reader", &["data:read"])],
                &[route(&["GET"], "/data", "data:read")],
            ),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/data/items")
                    .header(crate::REQUEST_ID_HEADER, "request-real-allowed")
                    .header(AUTHORIZATION, "Bearer token-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 3);
        let events = capture.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == HTTP_REQUEST_OBSERVED)
                .count(),
            1
        );
        for event_type in ["auth.success", "authz.allowed", HTTP_REQUEST_OBSERVED] {
            let event = events
                .iter()
                .find(|event| event.event_type == event_type)
                .expect("expected event should be captured");
            assert_eq!(event.request_id, "request-real-allowed");
        }

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(observed.payload["policy_decision"], json!("allowed"));
        assert_eq!(observed.payload["permission"], json!("data:read"));
        assert!(observed.payload.get("matched_rule_id").is_none());
        assert_eq!(
            observed.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }

    #[tokio::test]
    async fn observation_correlates_with_real_direct_rule_decision() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy_with_rules(
                DefaultAction::Deny,
                &[("reader", &["data:read"])],
                &[],
                &[direct_rule(
                    Some("allow-data-item"),
                    &["GET"],
                    "/data/items",
                    RuleAction::Allow,
                )],
            ),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/data/items")
                    .header(crate::REQUEST_ID_HEADER, "request-real-direct-rule")
                    .header(AUTHORIZATION, "Bearer token-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 3);
        let events = capture.events();
        let authz = events
            .iter()
            .find(|event| event.event_type == "authz.allowed")
            .expect("authz allowed event should be captured");
        assert_eq!(authz.payload["matched_rule_id"], json!("allow-data-item"));
        assert!(authz.payload.get("permission").is_none());
        assert!(authz.payload.get("path_prefix").is_none());

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(observed.payload["policy_decision"], json!("allowed"));
        assert_eq!(observed.payload["policy_reason"], json!("matched_rule"));
        assert_eq!(
            observed.payload["matched_rule_id"],
            json!("allow-data-item")
        );
        assert!(observed.payload.get("permission").is_none());
        assert!(observed.payload.get("path_prefix").is_none());
    }

    #[tokio::test]
    async fn observation_correlates_with_real_default_allow_decision() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy(DefaultAction::Allow, &[], &[]),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/data/items")
                    .header(crate::REQUEST_ID_HEADER, "request-real-default-allow")
                    .header(AUTHORIZATION, "Bearer token-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 3);
        let events = capture.events();
        let authz = events
            .iter()
            .find(|event| event.event_type == "authz.allowed")
            .expect("authz allowed event should be captured");
        assert_eq!(authz.payload["reason"], json!("default_allow"));
        assert_eq!(authz.request_id, "request-real-default-allow");

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(observed.payload["policy_decision"], json!("allowed"));
        assert_eq!(observed.payload["policy_reason"], json!("default_allow"));
        assert!(observed.payload.get("permission").is_none());
        assert!(observed.payload.get("matched_rule_id").is_none());
        assert_eq!(
            observed.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }

    #[tokio::test]
    async fn observation_correlates_with_real_shadow_would_deny_decision() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy_with_enforcement(
                DefaultAction::Deny,
                EnforcementMode::Shadow,
                &[("reader", &["data:read"])],
                &[route(&["GET"], "/data", "admin:read")],
            ),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/data/items")
                    .header(crate::REQUEST_ID_HEADER, "request-real-shadow-would-deny")
                    .header(AUTHORIZATION, "Bearer token-123")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 3);
        let events = capture.events();
        for event_type in ["auth.success", "authz.would_deny", HTTP_REQUEST_OBSERVED] {
            let event = events
                .iter()
                .find(|event| event.event_type == event_type)
                .expect("expected event should be captured");
            assert_eq!(event.request_id, "request-real-shadow-would-deny");
        }

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["auth_outcome"], json!("authenticated"));
        assert_eq!(observed.payload["policy_decision"], json!("would_deny"));
        assert_eq!(
            observed.payload["policy_reason"],
            json!("missing_permission")
        );
        assert_eq!(observed.payload["permission"], json!("admin:read"));
        assert_eq!(observed.payload["path_prefix"], json!("/data"));
        assert!(observed.payload.get("matched_rule_id").is_none());
        assert_eq!(
            observed.actor.as_ref().map(|actor| actor.user_id.as_str()),
            Some("user-123")
        );
    }

    #[tokio::test]
    async fn observation_correlates_with_real_auth_failure_event() {
        let (audit, capture) = test_audit_log();
        let router = auth_rbac_observation_router(
            audit,
            validator(Ok(test_principal(&["reader"]))),
            test_policy(
                DefaultAction::Deny,
                &[("reader", &["data:read"])],
                &[route(&["GET"], "/data", "data:read")],
            ),
        );

        let response = router
            .oneshot(request(Method::GET, "/data/items", "request-real-denied"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eventually(Duration::from_secs(1), || capture.events().len() >= 2);
        let events = capture.events();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == HTTP_REQUEST_OBSERVED)
                .count(),
            1
        );
        for event_type in ["auth.failure", HTTP_REQUEST_OBSERVED] {
            let event = events
                .iter()
                .find(|event| event.event_type == event_type)
                .expect("expected event should be captured");
            assert_eq!(event.request_id, "request-real-denied");
        }

        let observed = events
            .iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured");
        assert_eq!(observed.payload["status"], json!(401));
        assert_eq!(
            observed.payload["auth_outcome"],
            json!("anonymous_or_failed")
        );
        assert_eq!(observed.payload["auth_reason"], json!("missing_credential"));
        assert_eq!(observed.payload["policy_decision"], json!("not_evaluated"));
        assert!(observed.actor.is_none());
    }

    fn observation_router(state: ObservationState) -> Router {
        base_router().layer(from_fn_with_state(state, observation_middleware))
    }

    fn body_capture_router(state: ObservationState) -> Router {
        Router::new()
            .route("/{*path}", any(capture_body))
            .layer(from_fn_with_state(state, observation_middleware))
    }

    fn no_shape_handle_router(state: ObservationState) -> Router {
        Router::new()
            .route("/{*path}", any(no_shape_handle_probe))
            .layer(from_fn_with_state(state, observation_middleware))
    }

    fn base_router() -> Router {
        async fn ok() -> &'static str {
            "ok"
        }

        Router::new().route("/", get(ok)).route("/{*path}", get(ok))
    }

    async fn capture_body(req: Request<Body>) -> Response {
        let (parts, body) = req.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("test body should read");
        if let Some(payload_capture) = parts.extensions.get::<PayloadCaptureHandle>() {
            payload_capture.capture_json_body(&parts.headers, &body);
        }

        StatusCode::OK.into_response()
    }

    async fn no_shape_handle_probe(req: Request<Body>) -> Response {
        if req.extensions().get::<PayloadCaptureHandle>().is_some() {
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        } else {
            StatusCode::NO_CONTENT.into_response()
        }
    }

    fn json_request(uri: &str, request_id: &str, body: &str) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(crate::REQUEST_ID_HEADER, request_id)
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .expect("request should build")
    }

    async fn fake_auth_layer(
        State(outcome): State<FakeAuthLayer>,
        req: Request<Body>,
        next: Next,
    ) -> Response {
        match outcome {
            FakeAuthLayer::Success(principal) => {
                let mut response = next.run(req).await;
                response.extensions_mut().insert(AuthOutcome {
                    principal: Some(principal),
                    authenticated: true,
                    reason: None,
                });
                response
            }
            FakeAuthLayer::Failure(reason) => {
                let mut response = StatusCode::UNAUTHORIZED.into_response();
                response.extensions_mut().insert(AuthOutcome {
                    principal: None,
                    authenticated: false,
                    reason: Some(reason.to_owned()),
                });
                response
            }
        }
    }

    async fn fake_policy_layer(
        State(decision): State<FakePolicyLayer>,
        req: Request<Body>,
        next: Next,
    ) -> Response {
        match decision {
            FakePolicyLayer::Allowed => {
                let mut response = next.run(req).await;
                response.extensions_mut().insert(PolicyDecision {
                    outcome: PolicyDecisionOutcome::Allowed,
                    reason: "matched_rule",
                    permission: Some("data:read".to_owned()),
                    path_prefix: Some("/data".to_owned()),
                    matched_rule_id: None,
                });
                response
            }
            FakePolicyLayer::Denied => {
                let mut response = StatusCode::FORBIDDEN.into_response();
                response.extensions_mut().insert(PolicyDecision {
                    outcome: PolicyDecisionOutcome::Denied,
                    reason: "missing_permission",
                    permission: Some("data:read".to_owned()),
                    path_prefix: Some("/data".to_owned()),
                    matched_rule_id: None,
                });
                response
            }
            FakePolicyLayer::WouldDeny => {
                let mut response = next.run(req).await;
                response.extensions_mut().insert(PolicyDecision {
                    outcome: PolicyDecisionOutcome::WouldDeny,
                    reason: "missing_permission",
                    permission: Some("data:read".to_owned()),
                    path_prefix: Some("/data".to_owned()),
                    matched_rule_id: None,
                });
                response
            }
        }
    }

    async fn fake_upstream_layer(req: Request<Body>, next: Next) -> Response {
        let mut response = next.run(req).await;
        response
            .extensions_mut()
            .insert(crate::middleware::decision::UpstreamOutcome {
                latency_ms: 42,
                status: Some(201),
                pool_id: None,
                endpoint_id: None,
                attempts: Vec::new(),
                retry_exhausted: false,
                stream_terminal_pending: false,
            });
        response
            .extensions_mut()
            .insert(crate::upstream_route::ProxyRouteObservationContext::new(
                Some("api.example.test".to_owned()),
                Some("/api".to_owned()),
                "https://upstream.example.test".to_owned(),
            ));
        response
    }

    fn auth_rbac_observation_router(
        audit: AuditLog,
        validator: Arc<dyn SessionValidator>,
        policy: Policy,
    ) -> Router {
        async fn ok() -> &'static str {
            "ok"
        }

        Router::new()
            .route("/data/items", get(ok))
            .layer(from_fn_with_state(
                rbac::RbacState::new(policy, Vec::new(), false, audit.clone()),
                rbac::rbac_middleware,
            ))
            .layer(from_fn_with_state(
                auth::AuthState {
                    validator: Some(validator),
                    mode: crate::config::AuthMode::Required,
                    cookie_name: "session".to_owned(),
                    exempt_paths: Vec::new(),
                    audit: audit.clone(),
                    principal_directory: crate::auth::PrincipalDirectory::disabled(),
                    client_ip_policy: ClientIpPolicy::default(),
                    mcp_route_paths: vec![
                        crate::auth::protected_resource::MCP_RESOURCE_PATH.to_owned()
                    ],
                    mcp_resource: None,
                    mcp_resource_metadata_url: None,
                },
                auth::auth_middleware,
            ))
            .layer(from_fn_with_state(
                ObservationState {
                    audit,
                    client_ip_policy: ClientIpPolicy::default(),
                    payload_capture: None,
                    conformance: None,
                },
                observation_middleware,
            ))
    }

    fn test_observation_state() -> (ObservationState, CaptureSink) {
        let (audit, capture) = test_audit_log();
        (
            ObservationState {
                audit,
                client_ip_policy: ClientIpPolicy::default(),
                payload_capture: None,
                conformance: None,
            },
            capture,
        )
    }

    fn test_observation_state_with_conformance(
        conformance: SchemaConformanceState,
    ) -> (ObservationState, CaptureSink) {
        let (audit, capture) = test_audit_log();
        (
            ObservationState {
                audit,
                client_ip_policy: ClientIpPolicy::default(),
                payload_capture: None,
                conformance: Some(conformance),
            },
            capture,
        )
    }

    fn test_audit_log() -> (AuditLog, CaptureSink) {
        let capture = CaptureSink::new();
        let audit = AuditLog::new(Arc::new(capture.clone()) as Arc<dyn AuditSink>);
        (audit, capture)
    }

    fn validator(outcome: Result<Principal, &'static str>) -> Arc<dyn SessionValidator> {
        Arc::new(MockValidator { outcome })
    }

    fn test_policy(
        default_action: DefaultAction,
        roles: &[(&str, &[&str])],
        routes: &[RouteRule],
    ) -> Policy {
        test_policy_with_enforcement(default_action, EnforcementMode::Enforce, roles, routes)
    }

    fn test_policy_with_rules(
        default_action: DefaultAction,
        roles: &[(&str, &[&str])],
        routes: &[RouteRule],
        rules: &[Rule],
    ) -> Policy {
        let mut policy = test_policy(default_action, roles, routes);
        policy.rules = rules.to_vec();
        policy
    }

    fn test_policy_with_enforcement(
        default_action: DefaultAction,
        enforcement_mode: EnforcementMode,
        roles: &[(&str, &[&str])],
        routes: &[RouteRule],
    ) -> Policy {
        Policy {
            schema_version: "0.1.0".to_owned(),
            id: Some("test-policy".to_owned()),
            default_action,
            enforcement_mode,
            roles: roles
                .iter()
                .map(|(role, permissions)| {
                    (
                        (*role).to_owned(),
                        RoleEntry {
                            permissions: permissions
                                .iter()
                                .map(|permission| (*permission).to_owned())
                                .collect(),
                            issuers: Vec::new(),
                            auth_methods: Vec::new(),
                        },
                    )
                })
                .collect::<HashMap<_, _>>(),
            routes: routes.to_vec(),
            rules: Vec::new(),
            egress: EgressPolicy::default(),
            rate_limits: Vec::new(),
            tools: HashMap::new(),
        }
    }

    fn route(methods: &[&str], path_prefix: &str, permission: &str) -> RouteRule {
        RouteRule {
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            hosts: Vec::new(),
            path_prefix: path_prefix.to_owned(),
            permission: permission.to_owned(),
            enforcement_mode: None,
        }
    }

    fn direct_rule(id: Option<&str>, methods: &[&str], path: &str, action: RuleAction) -> Rule {
        Rule {
            id: id.map(str::to_owned),
            enabled: true,
            methods: methods.iter().map(|method| (*method).to_owned()).collect(),
            path: path.to_owned(),
            tool_name: None,
            dispatch: None,
            principal: PrincipalMatcher::default(),
            action,
        }
    }

    fn seed_endpoint(path: &PathBuf, method: &str, endpoint_template: &str) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS discovery_endpoint_aggregates (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    call_count INTEGER NOT NULL,
                    latency_count INTEGER NOT NULL,
                    latency_p50_ms INTEGER NOT NULL,
                    latency_p95_ms INTEGER NOT NULL,
                    latency_p99_ms INTEGER NOT NULL,
                    latency_samples_json TEXT NOT NULL,
                    distinct_principal_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template)
                );
                "#,
            )
            .expect("discovery schema should create");
        connection
            .execute(
                r#"
                INSERT INTO discovery_endpoint_aggregates (
                    method,
                    endpoint_template,
                    first_seen,
                    last_seen,
                    call_count,
                    latency_count,
                    latency_p50_ms,
                    latency_p95_ms,
                    latency_p99_ms,
                    latency_samples_json,
                    distinct_principal_count,
                    updated_at
                ) VALUES (?1, ?2, '2024-06-01T12:00:00Z', '2024-06-01T12:00:00Z', 1, 1, 1, 1, 1, '[]', 0, '2024-06-01T12:00:00Z')
                "#,
                params![method, endpoint_template],
            )
            .expect("endpoint aggregate should insert");
    }

    fn seed_payload_shape_samples(
        path: &PathBuf,
        method: &str,
        endpoint_template: &str,
        shapes: &[serde_json::Value],
    ) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS discovery_payload_shape_stats (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    shape_observation_count INTEGER NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template)
                );

                CREATE TABLE IF NOT EXISTS discovery_payload_shape_samples (
                    method TEXT NOT NULL,
                    endpoint_template TEXT NOT NULL,
                    sample_slot INTEGER NOT NULL,
                    observed_at TEXT NOT NULL,
                    shape_hash TEXT NOT NULL,
                    shape_json TEXT NOT NULL,
                    PRIMARY KEY (method, endpoint_template, sample_slot)
                );
                "#,
            )
            .expect("payload shape schema should create");
        connection
            .execute(
                r#"
                INSERT INTO discovery_payload_shape_stats (
                    method,
                    endpoint_template,
                    shape_observation_count,
                    updated_at
                ) VALUES (?1, ?2, ?3, '2024-06-01T12:00:00Z')
                "#,
                params![
                    method,
                    endpoint_template,
                    i64::try_from(shapes.len()).expect("shape count should fit i64")
                ],
            )
            .expect("payload shape stats should insert");

        for (index, shape) in shapes.iter().enumerate() {
            connection
                .execute(
                    r#"
                    INSERT INTO discovery_payload_shape_samples (
                        method,
                        endpoint_template,
                        sample_slot,
                        observed_at,
                        shape_hash,
                        shape_json
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    "#,
                    params![
                        method,
                        endpoint_template,
                        i64::try_from(index).expect("sample slot should fit i64"),
                        format!("2024-06-01T12:00:0{index}Z"),
                        format!("sha256:test-shape-{index}"),
                        shape.to_string(),
                    ],
                )
                .expect("payload shape sample should insert");
        }
    }

    fn replace_payload_shape_samples(
        path: &PathBuf,
        method: &str,
        endpoint_template: &str,
        shapes: &[serde_json::Value],
    ) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute(
                r#"
                DELETE FROM discovery_payload_shape_samples
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
                params![method, endpoint_template],
            )
            .expect("payload shape samples should delete");
        connection
            .execute(
                r#"
                DELETE FROM discovery_payload_shape_stats
                WHERE method = ?1 AND endpoint_template = ?2
                "#,
                params![method, endpoint_template],
            )
            .expect("payload shape stats should delete");
        drop(connection);

        seed_payload_shape_samples(path, method, endpoint_template, shapes);
    }

    struct TempDb {
        path: PathBuf,
    }

    impl TempDb {
        fn new(test_name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "greengateway-observation-{test_name}-{}.sqlite",
                uuid::Uuid::new_v4()
            ));

            Self { path }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let path = PathBuf::from(format!("{}{}", self.path.display(), suffix));
                let _ = fs::remove_file(path);
            }
        }
    }

    fn test_principal(roles: &[&str]) -> Principal {
        Principal {
            user_id: "user-123".to_owned(),
            issuer: None,
            email: Some("user@example.test".to_owned()),
            org_id: None,
            roles: roles.iter().map(|role| (*role).to_owned()).collect(),
            session_id: "session-123".to_owned(),
            auth_method: AuthMethod::Bearer,
        }
    }

    async fn one_observation_event(capture: &CaptureSink) -> AuditEvent {
        assert_eventually(Duration::from_secs(1), || {
            capture
                .events()
                .iter()
                .filter(|event| event.event_type == HTTP_REQUEST_OBSERVED)
                .count()
                == 1
        });

        capture
            .events()
            .into_iter()
            .find(|event| event.event_type == HTTP_REQUEST_OBSERVED)
            .expect("observation event should be captured")
    }

    fn request(method: Method, uri: &str, request_id: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(crate::REQUEST_ID_HEADER, request_id)
            .body(Body::empty())
            .expect("request should build")
    }

    fn assert_eventually(timeout: Duration, condition: impl Fn() -> bool) {
        let started = Instant::now();

        while started.elapsed() < timeout {
            if condition() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        assert!(
            condition(),
            "condition did not become true within {timeout:?}"
        );
    }
}
