use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use http::{HeaderMap, HeaderName, HeaderValue, Request};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{audit, config, egress, lifecycle, upstream_route};

mod admission;
mod forward;
mod health;

pub(crate) use health::{UpstreamHealthAdminResponse, UpstreamHealthResponse};

/// Data-only route classifier used before authentication and authorization.
///
/// This type intentionally has no resolver, HTTP client, health-check, or
/// forwarding capability. Pre-gate middleware can classify a stable logical
/// route, but only [`ProxyState`] can select and contact a physical upstream.
#[derive(Clone, Debug)]
pub(crate) struct ProxyClassifier {
    routes: ClassifierRoutes,
}

#[derive(Clone, Debug)]
enum ClassifierRoutes {
    Legacy {
        route_id: String,
        upstream_origin: String,
    },
    RoutingTable {
        routes: Vec<ClassifierRoute>,
    },
}

#[derive(Clone, Debug)]
struct ClassifierRoute {
    route_id: String,
    path_prefix: Option<String>,
    host: Option<String>,
    upstream_origin: String,
}

impl upstream_route::RouteMatch for ClassifierRoute {
    fn path_prefix(&self) -> Option<&str> {
        self.path_prefix.as_deref()
    }

    fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
}

impl ProxyClassifier {
    pub(crate) fn observation_context_for_request(
        &self,
        path: &str,
        headers: &HeaderMap,
    ) -> Option<upstream_route::ProxyRouteObservationContext> {
        match &self.routes {
            ClassifierRoutes::Legacy {
                route_id,
                upstream_origin,
            } => Some(
                upstream_route::ProxyRouteObservationContext::new_with_route_id(
                    route_id.clone(),
                    None,
                    None,
                    upstream_origin.clone(),
                ),
            ),
            ClassifierRoutes::RoutingTable { routes } => {
                let route = classifier_route_for_request(routes, path, headers)?;
                Some(
                    upstream_route::ProxyRouteObservationContext::new_with_route_id(
                        route.route_id.clone(),
                        route.host.clone(),
                        route.path_prefix.clone(),
                        route.upstream_origin.clone(),
                    ),
                )
            }
        }
    }

    #[cfg(test)]
    fn upstream_origin_for_request(&self, path: &str, headers: &HeaderMap) -> Option<&str> {
        match &self.routes {
            ClassifierRoutes::Legacy {
                upstream_origin, ..
            } => Some(upstream_origin),
            ClassifierRoutes::RoutingTable { routes } => {
                classifier_route_for_request(routes, path, headers)
                    .map(|route| route.upstream_origin.as_str())
            }
        }
    }
}

fn classifier_route_for_request<'a>(
    routes: &'a [ClassifierRoute],
    path: &str,
    headers: &HeaderMap,
) -> Option<&'a ClassifierRoute> {
    let request_host = upstream_route::request_host_without_port(headers);
    upstream_route::matching_route(routes, path, request_host.as_deref())
}

#[derive(Clone)]
pub(crate) struct ProxyState {
    routes: ProxyRoutes,
    upstream_health: Vec<health::UpstreamHealthTarget>,
    max_request_body_bytes: usize,
    health_runtime: health::UpstreamHealthRuntime,
    #[cfg(test)]
    request_selection_count: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    request_body_mode_override: Option<RequestBodyMode>,
}

#[derive(Clone)]
enum ProxyRoutes {
    Legacy { pool: Arc<UpstreamPool> },
    RoutingTable { routes: Vec<ProxyRoute> },
}

#[derive(Clone)]
struct ProxyRoute {
    route_id: String,
    path_prefix: Option<String>,
    host: Option<String>,
    authorization_origin: String,
    request_header_policy: RouteRequestHeaderPolicy,
    pool: Arc<UpstreamPool>,
    request_body_mode: RequestBodyMode,
}

impl upstream_route::RouteMatch for ProxyRoute {
    fn path_prefix(&self) -> Option<&str> {
        self.path_prefix.as_deref()
    }

    fn host(&self) -> Option<&str> {
        self.host.as_deref()
    }
}

#[derive(Clone, Debug, Default)]
struct RouteRequestHeaderPolicy {
    add_request_headers: Vec<(HeaderName, HeaderValue)>,
    strip_request_headers: Vec<HeaderName>,
}

#[derive(Clone)]
struct MatchedUpstream {
    request_header_policy: RouteRequestHeaderPolicy,
    pool: Arc<UpstreamPool>,
    request_body_mode: RequestBodyMode,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RequestBodyMode {
    #[default]
    Buffered,
    // Public route selection is wired by the stable route/pool PR that follows this one.
    #[allow(dead_code)]
    Stream,
}

impl From<config::UpstreamRequestBodyMode> for RequestBodyMode {
    fn from(mode: config::UpstreamRequestBodyMode) -> Self {
        match mode {
            config::UpstreamRequestBodyMode::Buffered => Self::Buffered,
            config::UpstreamRequestBodyMode::Stream => Self::Stream,
        }
    }
}

#[derive(Clone)]
struct ProxyEndpoint {
    id: Arc<str>,
    upstream_origin: String,
    weight: u16,
    egress_client: Arc<egress::EgressClient>,
    health: health::UpstreamHealthState,
    health_config: Option<Arc<config::UpstreamHealthCheckConfig>>,
}

struct UpstreamPool {
    id: Arc<str>,
    endpoints: Vec<ProxyEndpoint>,
    next_selection: AtomicU64,
    admission: admission::PoolAdmission,
}

impl UpstreamPool {
    fn new(
        id: String,
        endpoints: Vec<ProxyEndpoint>,
        limits: &config::UpstreamPoolLimitsConfig,
    ) -> Self {
        let id: Arc<str> = Arc::from(id);
        Self {
            admission: admission::PoolAdmission::new(
                Arc::clone(&id),
                limits.max_in_flight,
                limits.queue_depth,
                Duration::from_millis(limits.queue_timeout_ms),
            ),
            id,
            endpoints,
            next_selection: AtomicU64::new(0),
        }
    }

    fn select_endpoint(&self) -> Option<ProxyEndpoint> {
        let total_weight = self
            .endpoints
            .iter()
            .filter(|endpoint| {
                endpoint
                    .health_config
                    .as_ref()
                    .is_none_or(|_| endpoint.health.eligible())
            })
            .map(|endpoint| u64::from(endpoint.weight))
            .sum::<u64>();
        if total_weight == 0 {
            return None;
        }
        let ticket = self.next_selection.fetch_add(1, Ordering::Relaxed) % total_weight;
        let mut cumulative = 0_u64;
        self.endpoints
            .iter()
            .filter(|endpoint| {
                endpoint
                    .health_config
                    .as_ref()
                    .is_none_or(|_| endpoint.health.eligible())
            })
            .find(|endpoint| {
                cumulative = cumulative.saturating_add(u64::from(endpoint.weight));
                ticket < cumulative
            })
            .cloned()
    }
}

impl ProxyState {
    pub(crate) fn from_config(
        config: &config::Config,
        default_egress_config: &egress::EgressConfig,
        egress_client: Arc<egress::EgressClient>,
        audit: audit::AuditLog,
    ) -> Result<Option<Self>, egress::EgressError> {
        if let Some(upstream_url) = config.upstream_url.as_deref() {
            let upstream_origin = upstream_origin_from_url(upstream_url, "UPSTREAM_URL");
            let health = health::UpstreamHealthState::new("legacy", "primary", Some(audit.clone()));
            let pool = Arc::new(UpstreamPool::new(
                "legacy".to_owned(),
                vec![ProxyEndpoint {
                    id: Arc::from("primary"),
                    upstream_origin: upstream_origin.clone(),
                    weight: 1,
                    egress_client: Arc::clone(&egress_client),
                    health: health.clone(),
                    health_config: None,
                }],
                &config::UpstreamPoolLimitsConfig::default(),
            ));

            return Ok(Some(Self {
                routes: ProxyRoutes::Legacy { pool },
                upstream_health: health::upstream_health_targets([(
                    "legacy".to_owned(),
                    "primary".to_owned(),
                    upstream_origin,
                    Arc::clone(&egress_client),
                    health,
                    None,
                )]),
                max_request_body_bytes: config.egress_max_request_body_bytes,
                health_runtime: health::UpstreamHealthRuntime::default(),
                #[cfg(test)]
                request_selection_count: None,
                #[cfg(test)]
                request_body_mode_override: None,
            }));
        }

        if config.upstream_routes.is_empty() {
            return Ok(None);
        }

        let mut route_clients = HashMap::new();
        let mut seen_route_ids = HashSet::new();
        let routes: Vec<_> = config
            .upstream_routes
            .iter()
            .enumerate()
            .map(|(index, route)| {
                let route_id = route.id.clone().unwrap_or_else(|| legacy_route_id(route));
                if !seen_route_ids.insert(route_id.clone()) {
                    return Err(egress::EgressError::InvalidPolicy(
                        "upstream routes have duplicate effective route IDs".to_owned(),
                    ));
                }
                let endpoints = route_endpoints(
                    route,
                    index,
                    default_egress_config,
                    &egress_client,
                    &mut route_clients,
                    &route_id,
                    &audit,
                )?;
                let authorization_origin = if route.upstreams.is_empty() {
                    endpoints
                        .first()
                        .expect("validated route must have one endpoint")
                        .upstream_origin
                        .clone()
                } else {
                    logical_pool_origin(&route_id)
                };
                let pool = Arc::new(UpstreamPool::new(
                    route_id.clone(),
                    endpoints,
                    &route.limits,
                ));

                Ok(ProxyRoute {
                    route_id,
                    path_prefix: route.path_prefix.clone(),
                    host: route.host.as_ref().map(|host| host.to_ascii_lowercase()),
                    authorization_origin,
                    request_header_policy: route_request_header_policy(route),
                    pool,
                    request_body_mode: route.request_body.mode.into(),
                })
            })
            .collect::<Result<_, egress::EgressError>>()?;
        let upstream_health = health::upstream_health_targets(routes.iter().flat_map(|route| {
            route.pool.endpoints.iter().map(|endpoint| {
                (
                    route.route_id.clone(),
                    endpoint.id.to_string(),
                    endpoint.upstream_origin.clone(),
                    Arc::clone(&endpoint.egress_client),
                    endpoint.health.clone(),
                    endpoint.health_config.as_deref().cloned(),
                )
            })
        }));

        Ok(Some(Self {
            routes: ProxyRoutes::RoutingTable { routes },
            upstream_health,
            max_request_body_bytes: config.egress_max_request_body_bytes,
            health_runtime: health::UpstreamHealthRuntime::default(),
            #[cfg(test)]
            request_selection_count: None,
            #[cfg(test)]
            request_body_mode_override: None,
        }))
    }

    #[cfg(test)]
    pub(crate) fn with_request_selection_counter(
        mut self,
        counter: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.request_selection_count = Some(counter);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_streaming_request_bodies(mut self) -> Self {
        self.request_body_mode_override = Some(RequestBodyMode::Stream);
        self
    }

    pub(crate) fn classifier(&self) -> ProxyClassifier {
        let routes = match &self.routes {
            ProxyRoutes::Legacy { pool } => ClassifierRoutes::Legacy {
                route_id: pool.id.to_string(),
                upstream_origin: pool.endpoints[0].upstream_origin.clone(),
            },
            ProxyRoutes::RoutingTable { routes } => ClassifierRoutes::RoutingTable {
                routes: routes
                    .iter()
                    .map(|route| ClassifierRoute {
                        route_id: route.route_id.clone(),
                        path_prefix: route.path_prefix.clone(),
                        host: route.host.clone(),
                        upstream_origin: route.authorization_origin.clone(),
                    })
                    .collect(),
            },
        };

        ProxyClassifier { routes }
    }

    fn upstream_for_request(&self, path: &str, headers: &HeaderMap) -> Option<MatchedUpstream> {
        let upstream = match &self.routes {
            ProxyRoutes::Legacy { pool } => Some(MatchedUpstream {
                request_header_policy: RouteRequestHeaderPolicy::default(),
                pool: Arc::clone(pool),
                request_body_mode: RequestBodyMode::Buffered,
            }),
            ProxyRoutes::RoutingTable { routes } => {
                routing_route_for_request(routes, path, headers).map(|route| MatchedUpstream {
                    request_header_policy: route.request_header_policy.clone(),
                    pool: Arc::clone(&route.pool),
                    request_body_mode: route.request_body_mode,
                })
            }
        };

        #[cfg(test)]
        let upstream = upstream.map(|mut upstream| {
            if let Some(mode) = self.request_body_mode_override {
                upstream.request_body_mode = mode;
            }
            if let Some(counter) = &self.request_selection_count {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            upstream
        });

        upstream
    }

    pub(crate) async fn forward_request(
        &self,
        request: Request<axum::body::Body>,
        source_ip: &str,
    ) -> axum::response::Response {
        forward::forward_request(self, request, source_ip).await
    }

    pub(crate) async fn upstream_health_response(&self) -> UpstreamHealthResponse {
        health::upstream_health_response(&self.routes, &self.upstream_health).await
    }

    pub(crate) async fn upstream_health_admin_response(
        &self,
    ) -> health::UpstreamHealthAdminResponse {
        health::upstream_health_admin_response(&self.upstream_health).await
    }

    pub(crate) fn spawn_upstream_health_checks(&self) {
        self.health_runtime
            .spawn(&self.upstream_health, Arc::new(lifecycle::SystemClock));
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RouteEgressClientKey {
    timeout_ms: Option<u64>,
    response_idle_timeout_ms: Option<u64>,
    connect_timeout_ms: Option<u64>,
    tls_ca_bundle_path: Option<PathBuf>,
}

impl RouteEgressClientKey {
    fn from_route(
        route: &config::UpstreamRouteConfig,
        tls_ca_bundle_path: Option<PathBuf>,
    ) -> Self {
        Self {
            timeout_ms: route.timeout_ms,
            response_idle_timeout_ms: route.response_idle_timeout_ms,
            connect_timeout_ms: route.connect_timeout_ms,
            tls_ca_bundle_path,
        }
    }

    fn is_default(&self) -> bool {
        self.timeout_ms.is_none()
            && self.response_idle_timeout_ms.is_none()
            && self.connect_timeout_ms.is_none()
            && self.tls_ca_bundle_path.is_none()
    }

    fn apply_to_config(
        &self,
        config: &mut egress::EgressConfig,
    ) -> Result<(), egress::EgressError> {
        config.apply_timeout_overrides(
            self.timeout_ms,
            self.response_idle_timeout_ms,
            self.connect_timeout_ms,
        );
        if let Some(path) = &self.tls_ca_bundle_path {
            config.apply_tls_ca_bundle_path(path.clone())?;
        }

        Ok(())
    }
}

fn route_egress_client(
    route: &config::UpstreamRouteConfig,
    tls_ca_bundle_path: Option<PathBuf>,
    default_config: &egress::EgressConfig,
    default_client: &Arc<egress::EgressClient>,
    route_clients: &mut HashMap<RouteEgressClientKey, Arc<egress::EgressClient>>,
) -> Result<Arc<egress::EgressClient>, egress::EgressError> {
    let key = RouteEgressClientKey::from_route(route, tls_ca_bundle_path);
    if key.is_default() {
        return Ok(Arc::clone(default_client));
    }
    if let Some(client) = route_clients.get(&key) {
        return Ok(Arc::clone(client));
    }

    let mut config = default_config.clone();
    key.apply_to_config(&mut config)?;
    let client = Arc::new(default_client.reconfigured(config)?);
    route_clients.insert(key, Arc::clone(&client));

    Ok(client)
}

fn route_endpoints(
    route: &config::UpstreamRouteConfig,
    route_index: usize,
    default_config: &egress::EgressConfig,
    default_client: &Arc<egress::EgressClient>,
    route_clients: &mut HashMap<RouteEgressClientKey, Arc<egress::EgressClient>>,
    route_id: &str,
    audit: &audit::AuditLog,
) -> Result<Vec<ProxyEndpoint>, egress::EgressError> {
    if route.upstreams.is_empty() {
        let client = route_egress_client(
            route,
            route.tls_ca_bundle_path.clone(),
            default_config,
            default_client,
            route_clients,
        )?;
        let endpoint_id: Arc<str> = Arc::from("primary");
        return Ok(vec![ProxyEndpoint {
            id: Arc::clone(&endpoint_id),
            upstream_origin: upstream_origin_from_url(
                &route.upstream_url,
                &format!("UPSTREAM_ROUTES[{route_index}].upstream_url"),
            ),
            weight: 1,
            egress_client: client,
            health: health::UpstreamHealthState::new(
                Arc::<str>::from(route_id),
                endpoint_id,
                Some(audit.clone()),
            ),
            health_config: route.health_check.clone().map(Arc::new),
        }]);
    }

    route
        .upstreams
        .iter()
        .enumerate()
        .map(|(endpoint_index, endpoint)| {
            let client = route_egress_client(
                route,
                endpoint.tls_ca_bundle_path.clone(),
                default_config,
                default_client,
                route_clients,
            )?;
            let endpoint_id: Arc<str> = Arc::from(endpoint.id.as_str());
            Ok(ProxyEndpoint {
                id: Arc::clone(&endpoint_id),
                upstream_origin: upstream_origin_from_url(
                    &endpoint.url,
                    &format!("UPSTREAM_ROUTES[{route_index}].upstreams[{endpoint_index}].url"),
                ),
                weight: endpoint.weight,
                egress_client: client,
                health: health::UpstreamHealthState::new(
                    Arc::<str>::from(route_id),
                    endpoint_id,
                    Some(audit.clone()),
                ),
                health_config: route.health_check.clone().map(Arc::new),
            })
        })
        .collect()
}

fn route_request_header_policy(route: &config::UpstreamRouteConfig) -> RouteRequestHeaderPolicy {
    let mut add_request_headers = route
        .add_request_headers
        .iter()
        .map(|(name, value)| {
            (
                HeaderName::from_bytes(name.as_bytes())
                    .expect("validated route add header name should parse"),
                HeaderValue::from_str(value)
                    .expect("validated route add header value should parse"),
            )
        })
        .collect::<Vec<_>>();
    add_request_headers.sort_by(|(left, _), (right, _)| left.as_str().cmp(right.as_str()));

    let mut strip_request_headers = route
        .strip_request_headers
        .iter()
        .map(|name| {
            HeaderName::from_bytes(name.as_bytes())
                .expect("validated route strip header name should parse")
        })
        .collect::<Vec<_>>();
    strip_request_headers.sort_by(|left, right| left.as_str().cmp(right.as_str()));

    RouteRequestHeaderPolicy {
        add_request_headers,
        strip_request_headers,
    }
}

fn routing_route_for_request<'a>(
    routes: &'a [ProxyRoute],
    path: &str,
    headers: &HeaderMap,
) -> Option<&'a ProxyRoute> {
    let request_host = upstream_route::request_host_without_port(headers);
    upstream_route::matching_route(routes, path, request_host.as_deref())
}

pub(crate) fn upstream_origin_from_url(upstream_url: &str, source: &str) -> String {
    Url::parse(upstream_url)
        .unwrap_or_else(|err| {
            panic!("validated {source} should parse when building proxy state: {err}")
        })
        .origin()
        .ascii_serialization()
}

pub(crate) fn logical_pool_origin(route_id: &str) -> String {
    format!("pool:{route_id}")
}

fn legacy_route_id(route: &config::UpstreamRouteConfig) -> String {
    let mut digest = Sha256::new();
    digest.update(b"greengateway:legacy-route-id:v1\0");
    if let Some(host) = route.host.as_deref() {
        digest.update((host.len() as u64).to_be_bytes());
        digest.update(host.as_bytes());
    } else {
        digest.update(0_u64.to_be_bytes());
    }
    if let Some(path_prefix) = route.path_prefix.as_deref() {
        digest.update((path_prefix.len() as u64).to_be_bytes());
        digest.update(path_prefix.as_bytes());
    } else {
        digest.update(0_u64.to_be_bytes());
    }
    let digest = digest.finalize();
    format!("legacy-{}", hex::encode(&digest[..16]))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;

    use super::*;

    struct CountingResolver {
        calls: AtomicUsize,
        address: SocketAddr,
    }

    #[async_trait]
    impl egress::DnsResolver for CountingResolver {
        async fn resolve(
            &self,
            _host: &str,
            _port: u16,
        ) -> Result<Vec<SocketAddr>, std::io::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![self.address])
        }
    }

    #[test]
    fn weighted_pool_selection_is_deterministic_and_uses_only_configured_endpoints() {
        let client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::default())
                .expect("test client should build"),
        );
        let pool = UpstreamPool::new(
            "payments".to_owned(),
            vec![
                ProxyEndpoint {
                    id: Arc::from("a"),
                    upstream_origin: "https://a.example.test".to_owned(),
                    weight: 3,
                    egress_client: Arc::clone(&client),
                    health: health::UpstreamHealthState::new("payments", "a", None),
                    health_config: None,
                },
                ProxyEndpoint {
                    id: Arc::from("b"),
                    upstream_origin: "https://b.example.test".to_owned(),
                    weight: 1,
                    egress_client: client,
                    health: health::UpstreamHealthState::new("payments", "b", None),
                    health_config: None,
                },
            ],
            &config::UpstreamPoolLimitsConfig::default(),
        );

        let selected = (0..8)
            .map(|_| {
                pool.select_endpoint()
                    .expect("unconfigured health should remain eligible")
                    .id
                    .to_string()
            })
            .collect::<Vec<_>>();
        assert_eq!(selected, ["a", "a", "a", "b", "a", "a", "a", "b"]);
    }

    #[test]
    fn generated_legacy_route_id_depends_on_logical_matcher_not_endpoint() {
        let mut route = config::UpstreamRouteConfig {
            id: None,
            path_prefix: Some("/api".to_owned()),
            host: Some("api.example.test".to_owned()),
            upstream_url: "https://first.example.test".to_owned(),
            upstreams: Vec::new(),
            load_balancing: config::UpstreamLoadBalancingConfig::default(),
            request_body: config::UpstreamRequestBodyConfig::default(),
            limits: config::UpstreamPoolLimitsConfig::default(),
            health_check: None,
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
            add_request_headers: HashMap::new(),
            strip_request_headers: Vec::new(),
            tls_ca_bundle_path: None,
            openapi_spec_path: None,
        };
        let first = legacy_route_id(&route);
        route.upstream_url = "https://replacement.example.test".to_owned();
        assert_eq!(legacy_route_id(&route), first);
        route.path_prefix = Some("/other".to_owned());
        assert_ne!(legacy_route_id(&route), first);
    }

    #[test]
    fn data_only_classifier_preserves_equal_specificity_declaration_order() {
        let classifier = ProxyClassifier {
            routes: ClassifierRoutes::RoutingTable {
                routes: vec![
                    ClassifierRoute {
                        route_id: "first".to_owned(),
                        path_prefix: Some("/api".to_owned()),
                        host: None,
                        upstream_origin: "https://first.example.test".to_owned(),
                    },
                    ClassifierRoute {
                        route_id: "second".to_owned(),
                        path_prefix: Some("/api".to_owned()),
                        host: None,
                        upstream_origin: "https://second.example.test".to_owned(),
                    },
                ],
            },
        };

        assert_eq!(
            classifier.upstream_origin_for_request("/api/items", &HeaderMap::new()),
            Some("https://first.example.test")
        );
    }

    #[test]
    fn classifier_returns_only_logical_observation_context() {
        let classifier = ProxyClassifier {
            routes: ClassifierRoutes::Legacy {
                route_id: "legacy".to_owned(),
                upstream_origin: "https://upstream.example.test".to_owned(),
            },
        };

        let context = classifier
            .observation_context_for_request("/items", &HeaderMap::new())
            .expect("legacy route should classify");

        assert_eq!(
            context,
            upstream_route::ProxyRouteObservationContext::new_with_route_id(
                "legacy".to_owned(),
                None,
                None,
                "https://upstream.example.test".to_owned(),
            )
        );
    }

    #[test]
    fn classifier_from_transport_state_performs_no_resolution() {
        let resolver = Arc::new(CountingResolver {
            calls: AtomicUsize::new(0),
            address: "8.8.8.8:443"
                .parse()
                .expect("test resolver address should parse"),
        });
        let egress_client = Arc::new(
            egress::EgressClient::new_with_resolver(
                egress::EgressConfig::default(),
                resolver.clone(),
            )
            .expect("test egress client should build"),
        );
        let pool = Arc::new(UpstreamPool::new(
            "legacy".to_owned(),
            vec![ProxyEndpoint {
                id: Arc::from("primary"),
                upstream_origin: "https://upstream.example.test".to_owned(),
                weight: 1,
                egress_client,
                health: health::UpstreamHealthState::new("legacy", "primary", None),
                health_config: None,
            }],
            &config::UpstreamPoolLimitsConfig::default(),
        ));
        let state = ProxyState {
            routes: ProxyRoutes::Legacy { pool },
            upstream_health: Vec::new(),
            max_request_body_bytes: 1024,
            health_runtime: health::UpstreamHealthRuntime::default(),
            request_selection_count: None,
            request_body_mode_override: None,
        };

        let context = state
            .classifier()
            .observation_context_for_request("/items", &HeaderMap::new());

        assert!(context.is_some());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn route_derived_client_preserves_injected_resolver() {
        let host = "route-resolver.example.test";
        let resolver = Arc::new(CountingResolver {
            calls: AtomicUsize::new(0),
            address: "8.8.8.8:80"
                .parse()
                .expect("test resolver address should parse"),
        });
        let egress_config = egress::EgressConfig {
            allowed_hosts: HashSet::from([host.to_owned()]),
            ..egress::EgressConfig::default()
        };
        let default_client = Arc::new(
            egress::EgressClient::new_with_resolver(egress_config.clone(), resolver.clone())
                .expect("default client should build"),
        );
        let route = config::UpstreamRouteConfig {
            id: None,
            path_prefix: Some("/api".to_owned()),
            host: None,
            upstream_url: format!("http://{host}"),
            upstreams: Vec::new(),
            load_balancing: config::UpstreamLoadBalancingConfig::default(),
            request_body: config::UpstreamRequestBodyConfig::default(),
            limits: config::UpstreamPoolLimitsConfig::default(),
            health_check: None,
            timeout_ms: Some(1234),
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
            add_request_headers: HashMap::new(),
            strip_request_headers: Vec::new(),
            tls_ca_bundle_path: None,
            openapi_spec_path: None,
        };
        let mut route_clients = HashMap::new();

        let derived = route_egress_client(
            &route,
            None,
            &egress_config,
            &default_client,
            &mut route_clients,
        )
        .expect("route-derived client should build");
        let destination = derived
            .checked_destination(&route.upstream_url)
            .await
            .expect("route-derived client should use injected resolver");

        assert_eq!(destination.pinned_addr, resolver.address);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }
}
