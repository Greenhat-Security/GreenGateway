use std::{collections::HashMap, path::PathBuf, sync::Arc};

use http::{HeaderMap, HeaderName, HeaderValue, Request};
use url::Url;

use crate::{config, egress, lifecycle, upstream_route};

mod forward;
mod health;

pub(crate) use health::UpstreamHealthResponse;

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
    Legacy { upstream_origin: String },
    RoutingTable { routes: Vec<ClassifierRoute> },
}

#[derive(Clone, Debug)]
struct ClassifierRoute {
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
            ClassifierRoutes::Legacy { upstream_origin } => {
                Some(upstream_route::ProxyRouteObservationContext::new(
                    None,
                    None,
                    upstream_origin.clone(),
                ))
            }
            ClassifierRoutes::RoutingTable { routes } => {
                let route = classifier_route_for_request(routes, path, headers)?;
                Some(upstream_route::ProxyRouteObservationContext::new(
                    route.host.clone(),
                    route.path_prefix.clone(),
                    route.upstream_origin.clone(),
                ))
            }
        }
    }

    #[cfg(test)]
    fn upstream_origin_for_request(&self, path: &str, headers: &HeaderMap) -> Option<&str> {
        match &self.routes {
            ClassifierRoutes::Legacy { upstream_origin } => Some(upstream_origin),
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
    egress_client: Arc<egress::EgressClient>,
    max_request_body_bytes: usize,
    #[cfg(test)]
    request_selection_count: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

#[derive(Clone)]
enum ProxyRoutes {
    Legacy { upstream_origin: String },
    RoutingTable { routes: Vec<ProxyRoute> },
}

#[derive(Clone)]
struct ProxyRoute {
    path_prefix: Option<String>,
    host: Option<String>,
    upstream_origin: String,
    request_header_policy: RouteRequestHeaderPolicy,
    egress_client: Arc<egress::EgressClient>,
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
    upstream_origin: String,
    request_header_policy: RouteRequestHeaderPolicy,
    egress_client: Arc<egress::EgressClient>,
}

impl ProxyState {
    pub(crate) fn from_config(
        config: &config::Config,
        default_egress_config: &egress::EgressConfig,
        egress_client: Arc<egress::EgressClient>,
    ) -> Result<Option<Self>, egress::EgressError> {
        if let Some(upstream_url) = config.upstream_url.as_deref() {
            let upstream_origin = upstream_origin_from_url(upstream_url, "UPSTREAM_URL");

            return Ok(Some(Self {
                routes: ProxyRoutes::Legacy {
                    upstream_origin: upstream_origin.clone(),
                },
                upstream_health: health::upstream_health_targets([(
                    upstream_origin,
                    Arc::clone(&egress_client),
                )]),
                egress_client,
                max_request_body_bytes: config.egress_max_request_body_bytes,
                #[cfg(test)]
                request_selection_count: None,
            }));
        }

        if config.upstream_routes.is_empty() {
            return Ok(None);
        }

        let mut route_clients = HashMap::new();
        let routes: Vec<_> = config
            .upstream_routes
            .iter()
            .enumerate()
            .map(|(index, route)| {
                let egress_client = route_egress_client(
                    route,
                    default_egress_config,
                    &egress_client,
                    &mut route_clients,
                )?;

                Ok(ProxyRoute {
                    path_prefix: route.path_prefix.clone(),
                    host: route.host.as_ref().map(|host| host.to_ascii_lowercase()),
                    upstream_origin: upstream_origin_from_url(
                        &route.upstream_url,
                        &format!("UPSTREAM_ROUTES[{index}].upstream_url"),
                    ),
                    request_header_policy: route_request_header_policy(route),
                    egress_client,
                })
            })
            .collect::<Result<_, egress::EgressError>>()?;
        let upstream_health = health::upstream_health_targets(routes.iter().map(|route| {
            (
                route.upstream_origin.clone(),
                Arc::clone(&route.egress_client),
            )
        }));

        Ok(Some(Self {
            routes: ProxyRoutes::RoutingTable { routes },
            upstream_health,
            egress_client,
            max_request_body_bytes: config.egress_max_request_body_bytes,
            #[cfg(test)]
            request_selection_count: None,
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

    pub(crate) fn classifier(&self) -> ProxyClassifier {
        let routes = match &self.routes {
            ProxyRoutes::Legacy { upstream_origin } => ClassifierRoutes::Legacy {
                upstream_origin: upstream_origin.clone(),
            },
            ProxyRoutes::RoutingTable { routes } => ClassifierRoutes::RoutingTable {
                routes: routes
                    .iter()
                    .map(|route| ClassifierRoute {
                        path_prefix: route.path_prefix.clone(),
                        host: route.host.clone(),
                        upstream_origin: route.upstream_origin.clone(),
                    })
                    .collect(),
            },
        };

        ProxyClassifier { routes }
    }

    fn upstream_for_request(&self, path: &str, headers: &HeaderMap) -> Option<MatchedUpstream> {
        let upstream = match &self.routes {
            ProxyRoutes::Legacy { upstream_origin } => Some(MatchedUpstream {
                upstream_origin: upstream_origin.clone(),
                request_header_policy: RouteRequestHeaderPolicy::default(),
                egress_client: Arc::clone(&self.egress_client),
            }),
            ProxyRoutes::RoutingTable { routes } => {
                routing_route_for_request(routes, path, headers).map(|route| MatchedUpstream {
                    upstream_origin: route.upstream_origin.clone(),
                    request_header_policy: route.request_header_policy.clone(),
                    egress_client: Arc::clone(&route.egress_client),
                })
            }
        };

        #[cfg(test)]
        if upstream.is_some() {
            if let Some(counter) = &self.request_selection_count {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }

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

    pub(crate) fn spawn_upstream_health_checks(&self) {
        health::spawn_upstream_health_checks(
            &self.upstream_health,
            Arc::new(lifecycle::SystemClock),
        );
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
    fn from_route(route: &config::UpstreamRouteConfig) -> Self {
        Self {
            timeout_ms: route.timeout_ms,
            response_idle_timeout_ms: route.response_idle_timeout_ms,
            connect_timeout_ms: route.connect_timeout_ms,
            tls_ca_bundle_path: route.tls_ca_bundle_path.clone(),
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
    default_config: &egress::EgressConfig,
    default_client: &Arc<egress::EgressClient>,
    route_clients: &mut HashMap<RouteEgressClientKey, Arc<egress::EgressClient>>,
) -> Result<Arc<egress::EgressClient>, egress::EgressError> {
    let key = RouteEgressClientKey::from_route(route);
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
    fn data_only_classifier_preserves_equal_specificity_declaration_order() {
        let classifier = ProxyClassifier {
            routes: ClassifierRoutes::RoutingTable {
                routes: vec![
                    ClassifierRoute {
                        path_prefix: Some("/api".to_owned()),
                        host: None,
                        upstream_origin: "https://first.example.test".to_owned(),
                    },
                    ClassifierRoute {
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
                upstream_origin: "https://upstream.example.test".to_owned(),
            },
        };

        let context = classifier
            .observation_context_for_request("/items", &HeaderMap::new())
            .expect("legacy route should classify");

        assert_eq!(
            context,
            upstream_route::ProxyRouteObservationContext::new(
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
        let state = ProxyState {
            routes: ProxyRoutes::Legacy {
                upstream_origin: "https://upstream.example.test".to_owned(),
            },
            upstream_health: Vec::new(),
            egress_client,
            max_request_body_bytes: 1024,
            request_selection_count: None,
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
            path_prefix: Some("/api".to_owned()),
            host: None,
            upstream_url: format!("http://{host}"),
            timeout_ms: Some(1234),
            response_idle_timeout_ms: None,
            connect_timeout_ms: None,
            add_request_headers: HashMap::new(),
            strip_request_headers: Vec::new(),
            tls_ca_bundle_path: None,
            openapi_spec_path: None,
        };
        let mut route_clients = HashMap::new();

        let derived =
            route_egress_client(&route, &egress_config, &default_client, &mut route_clients)
                .expect("route-derived client should build");
        let destination = derived
            .checked_destination(&route.upstream_url)
            .await
            .expect("route-derived client should use injected resolver");

        assert_eq!(destination.pinned_addr, resolver.address);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }
}
