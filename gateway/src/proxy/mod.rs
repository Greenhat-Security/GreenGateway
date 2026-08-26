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

use crate::{
    audit, config,
    connections::{
        http::{ConnectionHttpRuntime, ConnectionHttpTarget},
        store::ConnectionDependencyKind,
    },
    egress, lifecycle, upstream_route,
};

mod admission;
mod circuit;
mod forward;
mod health;
mod retry;

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
    connection_http: Option<ConnectionHttpRuntime>,
    upstream_health: Vec<health::UpstreamHealthTarget>,
    max_request_body_bytes: usize,
    health_runtime: health::UpstreamHealthRuntime,
    lifecycle: lifecycle::GatewayLifecycle,
    audit: audit::AuditLog,
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
    connection_id: Option<String>,
    request_header_policy: RouteRequestHeaderPolicy,
    pool: Arc<UpstreamPool>,
    request_body_mode: RequestBodyMode,
    sse: Option<SseResponseConfig>,
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
    connection_id: Option<String>,
    request_header_policy: RouteRequestHeaderPolicy,
    pool: Arc<UpstreamPool>,
    request_body_mode: RequestBodyMode,
    sse: Option<SseResponseConfig>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SseResponseConfig {
    max_duration: Option<Duration>,
    max_response_bytes: Option<Option<usize>>,
}

impl From<&config::UpstreamSseConfig> for SseResponseConfig {
    fn from(config: &config::UpstreamSseConfig) -> Self {
        Self {
            max_duration: (config.max_duration_ms != 0)
                .then(|| Duration::from_millis(config.max_duration_ms)),
            max_response_bytes: config
                .max_response_bytes
                .map(|maximum| (maximum != 0).then_some(maximum)),
        }
    }
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
    circuit: Option<circuit::CircuitBreaker>,
}

struct SelectedEndpoint {
    endpoint: ProxyEndpoint,
    circuit_permit: Option<circuit::CircuitPermit>,
}

struct UpstreamPool {
    id: Arc<str>,
    endpoints: Vec<ProxyEndpoint>,
    next_selection: AtomicU64,
    admission: admission::PoolAdmission,
    retry_policy: retry::RetryPolicy,
    retry_budget: retry::RetryBudget,
}

impl UpstreamPool {
    fn new(
        id: String,
        endpoints: Vec<ProxyEndpoint>,
        limits: &config::UpstreamPoolLimitsConfig,
        retry_config: Option<&config::UpstreamRetryConfig>,
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
            retry_policy: retry::RetryPolicy::from_config(retry_config),
            retry_budget: retry::RetryBudget::new(limits.max_in_flight),
        }
    }

    #[cfg(test)]
    fn select_endpoint(&self) -> Option<ProxyEndpoint> {
        self.select_endpoint_avoiding(&HashSet::new())
            .map(|selected| selected.endpoint)
    }

    fn request_timeout(&self) -> Duration {
        self.endpoints
            .first()
            .expect("validated upstream pool must contain an endpoint")
            .egress_client
            .request_timeout()
    }

    fn select_endpoint_avoiding(
        &self,
        attempted_endpoint_ids: &HashSet<Arc<str>>,
    ) -> Option<SelectedEndpoint> {
        let mut unavailable_circuits = HashSet::new();
        loop {
            // Endpoint health lives in an `AtomicU8` that health probes and proxied
            // responses store into from other tasks. Re-reading it once per pass let an
            // endpoint contribute weight to the total and then disappear before the
            // cumulative walk, which left the walk with no endpoint to return. Snapshot
            // the eligible set exactly once per attempt and drive every pass from it.
            let mut eligible = Vec::with_capacity(self.endpoints.len());
            eligible.extend(self.endpoints.iter().filter(|endpoint| {
                endpoint
                    .health_config
                    .as_ref()
                    .is_none_or(|_| endpoint.health.eligible())
                    && !unavailable_circuits.contains(&endpoint.id)
            }));
            let has_fresh_endpoint = eligible
                .iter()
                .any(|endpoint| !attempted_endpoint_ids.contains(&endpoint.id));
            if has_fresh_endpoint {
                eligible.retain(|endpoint| !attempted_endpoint_ids.contains(&endpoint.id));
            }
            let total_weight = eligible
                .iter()
                .map(|endpoint| u64::from(endpoint.weight))
                .sum::<u64>();
            if total_weight == 0 {
                return None;
            }
            let ticket = self.next_selection.fetch_add(1, Ordering::Relaxed) % total_weight;
            let mut cumulative = 0_u64;
            let selected = eligible.iter().copied().find(|endpoint| {
                cumulative = cumulative.saturating_add(u64::from(endpoint.weight));
                ticket < cumulative
            });
            let endpoint = match selected {
                Some(endpoint) => endpoint,
                None => {
                    // Unreachable while the ticket is drawn from this snapshot's own
                    // weight total. Degrade to the last eligible endpoint rather than
                    // panicking the request task and dropping the client connection.
                    tracing::warn!(
                        pool_id = self.id.as_ref(),
                        error_category = "endpoint_selection_fell_through",
                        "weighted endpoint selection found no ticket holder; using the last eligible endpoint"
                    );
                    eligible.last().copied()?
                }
            }
            .clone();
            let circuit_permit = match endpoint.circuit.as_ref() {
                Some(circuit) => match circuit.try_acquire() {
                    Some(permit) => Some(permit),
                    None => {
                        unavailable_circuits.insert(Arc::clone(&endpoint.id));
                        continue;
                    }
                },
                None => None,
            };
            return Some(SelectedEndpoint {
                endpoint,
                circuit_permit,
            });
        }
    }
}

impl ProxyState {
    pub(crate) fn from_config_with_connections_and_lifecycle(
        config: &config::Config,
        default_egress_config: &egress::EgressConfig,
        egress_client: Arc<egress::EgressClient>,
        connection_http: Option<ConnectionHttpRuntime>,
        audit: audit::AuditLog,
        lifecycle: lifecycle::GatewayLifecycle,
    ) -> Result<Option<Self>, egress::EgressError> {
        if let Some(upstream_url) = config.upstream_url.as_deref() {
            if let Some(runtime) = connection_http.as_ref() {
                runtime
                    .replace_dependencies(ConnectionDependencyKind::ProxyRoute, &[])
                    .map_err(|error| {
                        egress::EgressError::InvalidPolicy(format!(
                            "proxy dependencies could not be reconciled: {}",
                            error.safe_reason()
                        ))
                    })?;
            }
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
                    circuit: None,
                }],
                &config::UpstreamPoolLimitsConfig::default(),
                None,
            ));

            return Ok(Some(Self {
                routes: ProxyRoutes::Legacy { pool },
                connection_http,
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
                lifecycle,
                audit,
                #[cfg(test)]
                request_selection_count: None,
                #[cfg(test)]
                request_body_mode_override: None,
            }));
        }

        if config.upstream_routes.is_empty() {
            if let Some(runtime) = connection_http.as_ref() {
                runtime
                    .replace_dependencies(ConnectionDependencyKind::ProxyRoute, &[])
                    .map_err(|error| {
                        egress::EgressError::InvalidPolicy(format!(
                            "proxy dependencies could not be reconciled: {}",
                            error.safe_reason()
                        ))
                    })?;
            }
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
                let connection_target = route
                    .connection_id
                    .as_deref()
                    .map(|connection_id| {
                        let runtime = connection_http.as_ref().ok_or_else(|| {
                            egress::EgressError::InvalidPolicy(
                                "connection-bound proxy route requires the Connection HTTP runtime"
                                    .to_owned(),
                            )
                        })?;
                        runtime.target(connection_id, "/").map_err(|error| {
                            egress::EgressError::InvalidPolicy(format!(
                                "connection-bound proxy route is unavailable: {}",
                                error.safe_reason()
                            ))
                        })
                    })
                    .transpose()?;
                let request_header_policy = route_request_header_policy(route);
                if let Some(target) = connection_target.as_ref() {
                    validate_connection_header_policy(&request_header_policy, target)?;
                }
                let endpoints = if let Some(target) = connection_target.as_ref() {
                    let endpoint_id: Arc<str> = Arc::from("primary");
                    vec![ProxyEndpoint {
                        id: Arc::clone(&endpoint_id),
                        upstream_origin: upstream_origin_from_url(
                            target.url(),
                            "connection-bound route",
                        ),
                        weight: 1,
                        egress_client: Arc::clone(target.preflight_client()),
                        health: health::UpstreamHealthState::new(
                            Arc::<str>::from(route_id.as_str()),
                            endpoint_id,
                            Some(audit.clone()),
                        ),
                        health_config: None,
                        circuit: None,
                    }]
                } else {
                    route_endpoints(
                        route,
                        index,
                        default_egress_config,
                        &egress_client,
                        &mut route_clients,
                        &route_id,
                        &audit,
                    )?
                };
                let authorization_origin =
                    if let Some(connection_id) = route.connection_id.as_deref() {
                        format!("connection:{connection_id}")
                    } else if route.upstreams.is_empty() {
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
                    route.retry.as_ref(),
                ));

                Ok(ProxyRoute {
                    route_id,
                    path_prefix: route.path_prefix.clone(),
                    host: route.host.as_ref().map(|host| host.to_ascii_lowercase()),
                    authorization_origin,
                    connection_id: route.connection_id.clone(),
                    request_header_policy,
                    pool,
                    request_body_mode: route.request_body.mode.into(),
                    sse: route.sse.as_ref().map(Into::into),
                })
            })
            .collect::<Result<_, egress::EgressError>>()?;
        let upstream_health = routing_table_health_targets(&routes);
        if let Some(runtime) = connection_http.as_ref() {
            let dependencies = routes
                .iter()
                .filter_map(|route| {
                    route
                        .connection_id
                        .as_ref()
                        .map(|connection_id| (connection_id.clone(), route.route_id.clone()))
                })
                .collect::<Vec<_>>();
            runtime
                .replace_dependencies(ConnectionDependencyKind::ProxyRoute, &dependencies)
                .map_err(|error| {
                    egress::EgressError::InvalidPolicy(format!(
                        "connection-bound proxy dependencies could not be reconciled: {}",
                        error.safe_reason()
                    ))
                })?;
        }

        Ok(Some(Self {
            routes: ProxyRoutes::RoutingTable { routes },
            connection_http,
            upstream_health,
            max_request_body_bytes: config.egress_max_request_body_bytes,
            health_runtime: health::UpstreamHealthRuntime::default(),
            lifecycle,
            audit,
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
                connection_id: None,
                request_header_policy: RouteRequestHeaderPolicy::default(),
                pool: Arc::clone(pool),
                request_body_mode: RequestBodyMode::Buffered,
                sse: None,
            }),
            ProxyRoutes::RoutingTable { routes } => {
                routing_route_for_request(routes, path, headers).map(|route| MatchedUpstream {
                    connection_id: route.connection_id.clone(),
                    request_header_policy: route.request_header_policy.clone(),
                    pool: Arc::clone(&route.pool),
                    request_body_mode: route.request_body_mode,
                    sse: route.sse,
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

    pub(crate) fn required_pools_ready(&self) -> bool {
        health::required_pools_ready(&self.upstream_health)
    }

    pub(crate) fn spawn_upstream_health_checks(&self) {
        match &self.routes {
            ProxyRoutes::Legacy { .. } => self.health_runtime.spawn(
                &self.upstream_health,
                Arc::new(lifecycle::SystemClock),
                &self.lifecycle,
            ),
            ProxyRoutes::RoutingTable { routes } => {
                let active_targets = routing_table_active_health_targets(routes);
                self.health_runtime.spawn(
                    &active_targets,
                    Arc::new(lifecycle::SystemClock),
                    &self.lifecycle,
                );
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct RouteEgressClientKey {
    timeout_ms: Option<u64>,
    response_idle_timeout_ms: Option<u64>,
    connect_timeout_ms: Option<u64>,
    tls_ca_bundle_path: Option<PathBuf>,
    client_identity_pem_path: Option<PathBuf>,
}

impl RouteEgressClientKey {
    fn from_route(
        route: &config::UpstreamRouteConfig,
        tls_ca_bundle_path: Option<PathBuf>,
        client_identity_pem_path: Option<PathBuf>,
    ) -> Self {
        Self {
            timeout_ms: route.timeout_ms,
            response_idle_timeout_ms: route.response_idle_timeout_ms,
            connect_timeout_ms: route.connect_timeout_ms,
            tls_ca_bundle_path,
            client_identity_pem_path,
        }
    }

    fn is_default(&self) -> bool {
        self.timeout_ms.is_none()
            && self.response_idle_timeout_ms.is_none()
            && self.connect_timeout_ms.is_none()
            && self.tls_ca_bundle_path.is_none()
            && self.client_identity_pem_path.is_none()
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
        if let Some(path) = &self.client_identity_pem_path {
            config.apply_tls_client_identity_pem_path(path.clone())?;
        }

        Ok(())
    }
}

fn routing_table_health_targets(routes: &[ProxyRoute]) -> Vec<health::UpstreamHealthTarget> {
    health::upstream_health_targets(routes.iter().flat_map(|route| {
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
    }))
}

fn routing_table_active_health_targets(routes: &[ProxyRoute]) -> Vec<health::UpstreamHealthTarget> {
    health::upstream_health_targets(
        routes
            .iter()
            .filter(|route| route.connection_id.is_none())
            .flat_map(|route| {
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
            }),
    )
}

fn route_egress_client(
    route: &config::UpstreamRouteConfig,
    tls_ca_bundle_path: Option<PathBuf>,
    client_identity_pem_path: Option<PathBuf>,
    default_config: &egress::EgressConfig,
    default_client: &Arc<egress::EgressClient>,
    route_clients: &mut HashMap<RouteEgressClientKey, Arc<egress::EgressClient>>,
) -> Result<Arc<egress::EgressClient>, egress::EgressError> {
    let key = RouteEgressClientKey::from_route(route, tls_ca_bundle_path, client_identity_pem_path);
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
            None,
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
            circuit: None,
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
                endpoint.client_identity_pem_path.clone(),
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
                    Arc::clone(&endpoint_id),
                    Some(audit.clone()),
                ),
                health_config: route.health_check.clone().map(Arc::new),
                circuit: route.circuit_breaker.as_ref().map(|config| {
                    circuit::CircuitBreaker::new(
                        Arc::<str>::from(route_id),
                        Arc::clone(&endpoint_id),
                        config.clone(),
                        route.retry.as_ref(),
                        Some(audit.clone()),
                    )
                }),
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

fn validate_connection_header_policy(
    policy: &RouteRequestHeaderPolicy,
    target: &ConnectionHttpTarget,
) -> Result<(), egress::EgressError> {
    validate_connection_credential_header_policy(policy, target.credential_header_name())
}

fn validate_connection_credential_header_policy(
    policy: &RouteRequestHeaderPolicy,
    credential_header: Option<&HeaderName>,
) -> Result<(), egress::EgressError> {
    let Some(credential_header) = credential_header else {
        return Ok(());
    };
    if policy
        .add_request_headers
        .iter()
        .any(|(name, _)| name == credential_header)
        || policy
            .strip_request_headers
            .iter()
            .any(|name| name == credential_header)
    {
        return Err(egress::EgressError::InvalidPolicy(
            "connection-bound route must not add or strip its credential header".to_owned(),
        ));
    }
    Ok(())
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

/// The effective route ID for a route that carries no explicit `id`.
///
/// This is the identity the classifier, the dispatch matcher, and the
/// `upstream_route_id` audit dimension all use, so policy validation derives it
/// through this same function rather than reimplementing the digest.
pub(crate) fn legacy_route_id(route: &config::UpstreamRouteConfig) -> String {
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
        fs,
        net::SocketAddr,
        path::PathBuf,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use serde_json::Value;

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

    fn write_test_client_identity(name: &str) -> PathBuf {
        let identity = rcgen::generate_simple_self_signed(vec![format!("{name}.example.test")])
            .expect("test client identity should generate");
        let pem = format!(
            "{}{}",
            identity.cert.pem(),
            identity.key_pair.serialize_pem()
        );
        let path = std::env::temp_dir().join(format!(
            "greengateway-proxy-{name}-{}.pem",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, pem).expect("test client identity should be written");
        path
    }

    #[test]
    fn connection_route_header_policy_rejects_credential_conflicts() {
        let credential_header = HeaderName::from_static("x-api-key");
        let safe = RouteRequestHeaderPolicy {
            add_request_headers: vec![(
                HeaderName::from_static("x-route-label"),
                HeaderValue::from_static("billing"),
            )],
            strip_request_headers: vec![HeaderName::from_static("x-caller-value")],
        };
        validate_connection_credential_header_policy(&safe, Some(&credential_header))
            .expect("unrelated route transforms should remain valid");

        let adding_credential = RouteRequestHeaderPolicy {
            add_request_headers: vec![(
                credential_header.clone(),
                HeaderValue::from_static("forbidden"),
            )],
            strip_request_headers: Vec::new(),
        };
        assert!(matches!(
            validate_connection_credential_header_policy(
                &adding_credential,
                Some(&credential_header)
            ),
            Err(egress::EgressError::InvalidPolicy(_))
        ));

        let stripping_credential = RouteRequestHeaderPolicy {
            add_request_headers: Vec::new(),
            strip_request_headers: vec![credential_header.clone()],
        };
        assert!(matches!(
            validate_connection_credential_header_policy(
                &stripping_credential,
                Some(&credential_header)
            ),
            Err(egress::EgressError::InvalidPolicy(_))
        ));
        validate_connection_credential_header_policy(&safe, None)
            .expect("no-auth Connections have no credential header conflict");
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
                    circuit: None,
                },
                ProxyEndpoint {
                    id: Arc::from("b"),
                    upstream_origin: "https://b.example.test".to_owned(),
                    weight: 1,
                    egress_client: client,
                    health: health::UpstreamHealthState::new("payments", "b", None),
                    health_config: None,
                    circuit: None,
                },
            ],
            &config::UpstreamPoolLimitsConfig::default(),
            None,
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
    fn endpoint_selection_survives_health_flipping_concurrently_with_selection() {
        let client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig::default())
                .expect("test client should build"),
        );
        let health_config = Arc::new(config::UpstreamHealthCheckConfig {
            method: "GET".to_owned(),
            path: "/ready".to_owned(),
            interval_ms: 1_000,
            jitter_ms: 0,
            timeout_ms: 100,
            healthy_threshold: 1,
            unhealthy_threshold: 1,
            expected_statuses: vec![200],
            passive_failure_statuses: vec![503],
            required_for_readiness: false,
            minimum_healthy: 1,
        });
        let flapping = health::UpstreamHealthState::new("payments", "flapping", None);
        let stable = health::UpstreamHealthState::new("payments", "stable", None);
        flapping.mark_healthy_for_test();
        stable.mark_healthy_for_test();
        // The flapping endpoint carries almost all of the pool weight, so a health flip
        // between the weight total and the cumulative walk vacates almost every ticket.
        let pool = Arc::new(UpstreamPool::new(
            "payments".to_owned(),
            vec![
                ProxyEndpoint {
                    id: Arc::from("flapping"),
                    upstream_origin: "https://flapping.example.test".to_owned(),
                    weight: 1_000,
                    egress_client: Arc::clone(&client),
                    health: flapping.clone(),
                    health_config: Some(Arc::clone(&health_config)),
                    circuit: None,
                },
                ProxyEndpoint {
                    id: Arc::from("stable"),
                    upstream_origin: "https://stable.example.test".to_owned(),
                    weight: 1,
                    egress_client: client,
                    health: stable,
                    health_config: Some(health_config),
                    circuit: None,
                },
            ],
            &config::UpstreamPoolLimitsConfig::default(),
            None,
        ));

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flipper = {
            let flapping = flapping.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    flapping.mark_unhealthy_for_test();
                    flapping.mark_healthy_for_test();
                }
            })
        };
        let selectors = (0..4)
            .map(|_| {
                let pool = Arc::clone(&pool);
                std::thread::spawn(move || {
                    for _ in 0..200_000 {
                        assert!(
                            pool.select_endpoint().is_some(),
                            "an always-healthy endpoint must keep the pool selectable"
                        );
                    }
                })
            })
            .collect::<Vec<_>>();
        let outcomes = selectors
            .into_iter()
            .map(std::thread::JoinHandle::join)
            .collect::<Vec<_>>();
        stop.store(true, Ordering::Relaxed);
        flipper.join().expect("health flipper should not panic");

        for outcome in outcomes {
            assert!(
                outcome.is_ok(),
                "endpoint selection must not panic when endpoint health changes concurrently"
            );
        }
    }

    #[test]
    fn generated_legacy_route_id_depends_on_logical_matcher_not_endpoint() {
        let mut route = config::UpstreamRouteConfig {
            id: None,
            connection_id: None,
            path_prefix: Some("/api".to_owned()),
            host: Some("api.example.test".to_owned()),
            upstream_url: "https://first.example.test".to_owned(),
            upstreams: Vec::new(),
            load_balancing: config::UpstreamLoadBalancingConfig::default(),
            request_body: config::UpstreamRequestBodyConfig::default(),
            sse: None,
            limits: config::UpstreamPoolLimitsConfig::default(),
            health_check: None,
            retry: None,
            circuit_breaker: None,
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
                circuit: None,
            }],
            &config::UpstreamPoolLimitsConfig::default(),
            None,
        ));
        let state = ProxyState {
            routes: ProxyRoutes::Legacy { pool },
            connection_http: None,
            upstream_health: Vec::new(),
            max_request_body_bytes: 1024,
            health_runtime: health::UpstreamHealthRuntime::default(),
            lifecycle: lifecycle::GatewayLifecycle::new(),
            audit: audit::AuditLog::new(Arc::new(audit::sink::tests::CaptureSink::new())),
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
    async fn connection_bound_mtls_route_is_not_probed_by_legacy_health_client() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mTLS sentinel listener should bind");
        let address = listener
            .local_addr()
            .expect("mTLS sentinel address should load");
        let preflight_client = Arc::new(
            egress::EgressClient::new(egress::EgressConfig {
                allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
                deny_private_ips: false,
                ..egress::EgressConfig::default()
            })
            .expect("preflight-only client should build"),
        );
        assert_eq!(
            preflight_client.client_identity_fingerprint(),
            None,
            "connection-owned mTLS material must not exist on the preflight client"
        );
        let pool = Arc::new(UpstreamPool::new(
            "connection-route".to_owned(),
            vec![ProxyEndpoint {
                id: Arc::from("primary"),
                upstream_origin: format!("https://{address}"),
                weight: 1,
                egress_client: preflight_client,
                health: health::UpstreamHealthState::new("connection-route", "primary", None),
                health_config: None,
                circuit: None,
            }],
            &config::UpstreamPoolLimitsConfig::default(),
            None,
        ));
        let connection_route = ProxyRoute {
            route_id: "connection-route".to_owned(),
            path_prefix: Some("/secure".to_owned()),
            host: None,
            authorization_origin: "connection:mtls-api".to_owned(),
            connection_id: Some("mtls-api".to_owned()),
            request_header_policy: RouteRequestHeaderPolicy::default(),
            pool: Arc::clone(&pool),
            request_body_mode: RequestBodyMode::Buffered,
            sse: None,
        };
        let upstream_health = routing_table_health_targets(std::slice::from_ref(&connection_route));
        assert_eq!(
            upstream_health.len(),
            1,
            "connection-bound endpoints must remain in safe unknown-state health inventory"
        );
        assert!(
            routing_table_active_health_targets(std::slice::from_ref(&connection_route)).is_empty(),
            "connection-bound endpoints require prepared TLS and credentials and must not enter the legacy HEAD loop"
        );

        let state = ProxyState {
            routes: ProxyRoutes::RoutingTable {
                routes: vec![connection_route.clone()],
            },
            connection_http: None,
            upstream_health,
            max_request_body_bytes: 1024,
            health_runtime: health::UpstreamHealthRuntime::default(),
            lifecycle: lifecycle::GatewayLifecycle::new(),
            audit: audit::AuditLog::new(Arc::new(audit::sink::tests::CaptureSink::new())),
            request_selection_count: None,
            request_body_mode_override: None,
        };
        let health_response = serde_json::to_value(state.upstream_health_response().await)
            .expect("health response should serialize");
        assert_eq!(health_response["reachable"], Value::Null);
        let admin_response = serde_json::to_value(state.upstream_health_admin_response().await)
            .expect("admin health response should serialize");
        assert_eq!(admin_response["pools"][0]["pool_id"], "connection-route");
        assert_eq!(
            admin_response["pools"][0]["endpoints"][0]["state"],
            "unknown"
        );
        assert_eq!(
            admin_response["pools"][0]["endpoints"][0]["last_checked"],
            Value::Null
        );

        state.spawn_upstream_health_checks();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "the custom-CA/mTLS endpoint must not receive an unauthenticated preflight-only HEAD"
        );
        assert!(
            pool.select_endpoint().is_some(),
            "excluding the unsafe active probe must not falsely mark the Connection endpoint unhealthy"
        );

        let mut legacy_route = connection_route;
        legacy_route.connection_id = None;
        assert_eq!(
            routing_table_active_health_targets(&[legacy_route]).len(),
            1,
            "ordinary configured upstreams must retain legacy active health behavior"
        );
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
            connection_id: None,
            path_prefix: Some("/api".to_owned()),
            host: None,
            upstream_url: format!("http://{host}"),
            upstreams: Vec::new(),
            load_balancing: config::UpstreamLoadBalancingConfig::default(),
            request_body: config::UpstreamRequestBodyConfig::default(),
            sse: None,
            limits: config::UpstreamPoolLimitsConfig::default(),
            health_check: None,
            retry: None,
            circuit_breaker: None,
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

    #[test]
    fn pooled_endpoints_receive_distinct_mounted_client_identities() {
        let first_identity_path = write_test_client_identity("first");
        let second_identity_path = write_test_client_identity("second");
        let route = config::UpstreamRouteConfig {
            id: Some("payments".to_owned()),
            connection_id: None,
            path_prefix: Some("/payments".to_owned()),
            host: None,
            upstream_url: String::new(),
            upstreams: vec![
                config::UpstreamEndpointConfig {
                    id: "first".to_owned(),
                    url: "https://first.example.test".to_owned(),
                    weight: 1,
                    tls_ca_bundle_path: None,
                    client_identity_pem_path: Some(first_identity_path.clone()),
                },
                config::UpstreamEndpointConfig {
                    id: "second".to_owned(),
                    url: "https://second.example.test".to_owned(),
                    weight: 1,
                    tls_ca_bundle_path: None,
                    client_identity_pem_path: Some(second_identity_path.clone()),
                },
            ],
            load_balancing: config::UpstreamLoadBalancingConfig::default(),
            request_body: config::UpstreamRequestBodyConfig::default(),
            sse: None,
            limits: config::UpstreamPoolLimitsConfig::default(),
            health_check: None,
            retry: None,
            circuit_breaker: None,
            timeout_ms: None,
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
            add_request_headers: HashMap::new(),
            strip_request_headers: Vec::new(),
            tls_ca_bundle_path: None,
            openapi_spec_path: None,
        };
        let default_config = egress::EgressConfig::default();
        let default_client = Arc::new(
            egress::EgressClient::new(default_config.clone())
                .expect("default egress client should build"),
        );
        let mut route_clients = HashMap::new();
        let audit = audit::AuditLog::new(Arc::new(audit::sink::tests::CaptureSink::new()));

        let endpoints = route_endpoints(
            &route,
            0,
            &default_config,
            &default_client,
            &mut route_clients,
            "payments",
            &audit,
        )
        .expect("endpoint-specific identities should validate at startup");

        let first_fingerprint = endpoints[0]
            .egress_client
            .client_identity_fingerprint()
            .expect("first identity fingerprint");
        let second_fingerprint = endpoints[1]
            .egress_client
            .client_identity_fingerprint()
            .expect("second identity fingerprint");
        assert_ne!(first_fingerprint, second_fingerprint);
        assert_eq!(
            route_clients.len(),
            2,
            "identity path is part of endpoint client isolation"
        );

        let _ = fs::remove_file(first_identity_path);
        let _ = fs::remove_file(second_identity_path);
    }
}
