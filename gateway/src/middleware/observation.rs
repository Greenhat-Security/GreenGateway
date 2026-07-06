//! Per-request observation audit event middleware.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

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
    client_ip::{canonical_client_ip, request_id},
    config::Config,
    discovery::{
        openapi::{OpenApiRequestShape, SchemaCoverage},
        query::{
            DiscoveryQueryStore, InferredJsonBodyKey, InferredQueryParam, InferredRequestSchema,
            ObservedEndpoint,
        },
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

#[derive(Clone)]
pub struct ObservationState {
    pub audit: AuditLog,
    pub trust_proxy_headers: bool,
    payload_capture: Option<PayloadCaptureConfig>,
    conformance: Option<SchemaConformanceState>,
}

impl ObservationState {
    pub fn from_config(config: &Config, audit: AuditLog) -> Self {
        Self {
            audit,
            trust_proxy_headers: config.trust_proxy_headers,
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
    query_store: Option<Arc<DiscoveryQueryStore>>,
    payload_capture_enabled: bool,
    min_inferred_sample_count: u64,
    skip_exact_paths: Vec<String>,
    skip_path_prefixes: Vec<String>,
    inferred_cache: Arc<InferredSchemaCache>,
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
    shape: Arc<Mutex<CapturedPayloadShape>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct CapturedPayloadShape {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    query_params: Vec<CapturedQueryParam>,
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
    let request_id = request_id(req.headers(), req.extensions());
    let source_ip = canonical_client_ip(req.headers(), req.extensions(), state.trust_proxy_headers);
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
    let schema_mismatch = conformance_check
        .as_ref()
        .map(|check| check.schema_mismatch(conformance_shape.as_ref()));

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
            payload_shape: payload_shape.as_ref(),
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
    payload_shape: Option<&'a CapturedPayloadShape>,
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
    }

    if let Some(payload_shape) = input.payload_shape {
        payload.insert(
            "payload_shape".to_owned(),
            serde_json::to_value(payload_shape).expect("captured payload shape should serialize"),
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
    pub fn from_config(
        config: &Config,
        coverage: SchemaCoverage,
        query_store: Option<Arc<DiscoveryQueryStore>>,
    ) -> Option<Self> {
        let mut state = Self::from_parts(coverage, query_store, config.payload_capture_enabled)?;
        state.skip_exact_paths = vec![
            "/health".to_owned(),
            "/version".to_owned(),
            "/metrics".to_owned(),
        ];
        state.skip_path_prefixes = vec![
            config.admin_prefix.clone(),
            format!("/v1{}", config.admin_prefix),
        ];
        Some(state)
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
        (coverage.spec_configured() || (payload_capture_enabled && query_store.is_some()))
            .then_some(Self {
                coverage,
                query_store,
                payload_capture_enabled,
                min_inferred_sample_count: MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT,
                skip_exact_paths: Vec::new(),
                skip_path_prefixes: Vec::new(),
                inferred_cache: Arc::new(InferredSchemaCache::new(inferred_cache_ttl)),
            })
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
        Self {
            coverage,
            query_store,
            payload_capture_enabled,
            min_inferred_sample_count: MIN_INFERRED_CONFORMANCE_SAMPLE_COUNT,
            skip_exact_paths: Vec::new(),
            skip_path_prefixes: Vec::new(),
            inferred_cache: Arc::new(InferredSchemaCache::new(inferred_cache_ttl)),
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
        let query_store = self.query_store.as_ref()?;
        self.inferred_cache
            .schema_for_request(query_store, method, path)
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
        let endpoint_template = endpoints
            .iter()
            .filter(|endpoint| endpoint.method == method)
            .filter_map(|endpoint| {
                endpoint_template_match_score(&endpoint.endpoint_template, path)
                    .map(|score| (score, endpoint.endpoint_template.as_str()))
            })
            .max_by(|(left, _), (right, _)| left.cmp(right))
            .map(|(_, endpoint_template)| endpoint_template)?;

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

    fn schema_mismatch(&self, captured_shape: Option<&CapturedPayloadShape>) -> bool {
        match self {
            Self::Undocumented => true,
            Self::Expected {
                expected,
                observed_shape,
            } => expected.mismatches(captured_shape.unwrap_or(observed_shape)),
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
            shape: Arc::new(Mutex::new(shape)),
        }
    }

    pub fn capture_json_body(&self, headers: &HeaderMap, body: &[u8]) {
        let content_type = headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let Some(json_body) = captured_json_body_shape(content_type, body) else {
            return;
        };

        let mut shape = match self.shape.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        shape.json_body = Some(json_body);
    }

    fn snapshot(&self) -> CapturedPayloadShape {
        match self.shape.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    fn captured_data_snapshot(&self) -> Option<CapturedPayloadShape> {
        let shape = self.snapshot();
        shape.has_captured_data().then_some(shape)
    }
}

impl CapturedPayloadShape {
    fn from_query(query: Option<&str>) -> Self {
        Self {
            query_params: captured_query_params(query),
            json_body: None,
        }
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

fn captured_query_params(query: Option<&str>) -> Vec<CapturedQueryParam> {
    let Some(query) = query else {
        return Vec::new();
    };
    let mut params = BTreeMap::<String, &'static str>::new();

    for (name, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let value_type = query_value_type(value.trim());
        params
            .entry(name.to_owned())
            .and_modify(|existing| *existing = merge_query_value_type(existing, value_type))
            .or_insert(value_type);
    }

    params
        .into_iter()
        .map(|(name, value_type)| CapturedQueryParam {
            name: captured_field_name(&name),
            value_type: value_type.to_owned(),
        })
        .collect()
}

fn captured_json_body_shape(
    content_type: Option<&str>,
    body: &[u8],
) -> Option<CapturedJsonBodyShape> {
    if !is_json_content_type(content_type?) {
        return None;
    }

    let value = serde_json::from_slice::<Value>(body).ok()?;
    let Value::Object(object) = value else {
        return None;
    };

    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    Some(CapturedJsonBodyShape {
        top_level_keys: keys
            .into_iter()
            .map(captured_field_name)
            .collect::<Vec<_>>(),
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

    use super::*;
    use crate::{
        audit::{sink::tests::CaptureSink, AuditSink},
        auth::{AuthError, AuthMethod, Principal, SessionCredential, SessionValidator},
        discovery::{
            openapi::{OpenApiSpec, SchemaCoverage},
            query::DiscoveryQueryStore,
        },
        middleware::{auth, rbac},
        rbac::{
            policy::{EgressPolicy, RoleEntry},
            DefaultAction, EnforcementMode, Policy, PrincipalMatcher, RouteRule, Rule, RuleAction,
        },
    };

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
            .oneshot(request(Method::GET, "/", "request-upstream"))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        let event = one_observation_event(&capture).await;
        assert_eq!(event.payload["upstream_latency_ms"], json!(42));
        assert_eq!(event.payload["upstream_status"], json!(201));
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
        assert!(!first.schema_mismatch(Some(&display_name_shape)));
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
        assert!(!cached.schema_mismatch(Some(&display_name_shape)));
        assert_eq!(store.query_counts_for_test(), (1, 1));

        std::thread::sleep(ttl + Duration::from_millis(150));

        let refreshed = conformance
            .prepare_check("POST", "/users", None)
            .expect("refreshed inferred conformance check should be prepared");
        assert!(refreshed.schema_mismatch(Some(&display_name_shape)));
        assert_eq!(store.query_counts_for_test(), (2, 2));
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
            });
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
                    trust_proxy_headers: false,
                    mcp_resource: None,
                    mcp_resource_metadata_url: None,
                },
                auth::auth_middleware,
            ))
            .layer(from_fn_with_state(
                ObservationState {
                    audit,
                    trust_proxy_headers: false,
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
                trust_proxy_headers: false,
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
                trust_proxy_headers: false,
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
