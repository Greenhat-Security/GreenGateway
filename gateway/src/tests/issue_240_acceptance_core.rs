use super::*;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use futures_util::future::join_all;
use std::{
    path::{Path as FsPath, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tower::ServiceExt;

const OPERATOR_ALIAS_ID: &str = "acceptance-operator-bearer";
const OPERATOR_ALIAS_FILE: &str = "operator-file-locator-canary";
const TLS_CA_ALIAS_ID: &str = "acceptance-tls-ca";
const TLS_CA_FILE: &str = "acceptance-tls-ca.pem";
const MASTER_KEY_ID: &str = "acceptance-primary-key";
const MASTER_KEY_FILE: &str = "local-master-key";
const OPERATOR_API_KEY_HEADER: &str = "x-acceptance-api-key";

struct CoreSecretFixture {
    root: PathBuf,
}

impl CoreSecretFixture {
    fn new(database: &TempDb, operator_value: &[u8], tls_ca_pem: &str) -> Self {
        let root = database
            .path
            .with_extension(format!("issue-240-core-secrets-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("acceptance secret root should create");
        set_directory_permissions(&root, 0o700);
        write_secret_file(&root.join(OPERATOR_ALIAS_FILE), operator_value);
        write_secret_file(&root.join(TLS_CA_FILE), tls_ca_pem.as_bytes());
        write_secret_file(&root.join(MASTER_KEY_FILE), &[0x52; 32]);
        Self { root }
    }

    fn configure(&self, config: &mut config::Config) {
        config.connection_secrets_root = Some(connections::secret::SecretRootConfig::new(
            self.root.clone(),
        ));
        config.connection_secret_aliases = vec![
            connections::secret::OperatorSecretAliasConfig {
                id: OPERATOR_ALIAS_ID.to_owned(),
                label: "Acceptance operator credential".to_owned(),
                source: connections::secret::OperatorSecretAliasSource::File {
                    key: OPERATOR_ALIAS_FILE.to_owned(),
                },
            },
            connections::secret::OperatorSecretAliasConfig {
                id: TLS_CA_ALIAS_ID.to_owned(),
                label: "Acceptance TLS CA".to_owned(),
                source: connections::secret::OperatorSecretAliasSource::File {
                    key: TLS_CA_FILE.to_owned(),
                },
            },
        ];
        config.connection_local_secret_keyring =
            vec![connections::local_secret::LocalSecretKeyConfig {
                id: MASTER_KEY_ID.to_owned(),
                file: MASTER_KEY_FILE.to_owned(),
                role: connections::local_secret::LocalSecretKeyRole::Primary,
            }];
    }
}

impl Drop for CoreSecretFixture {
    fn drop(&mut self) {
        if self.root.starts_with(std::env::temp_dir())
            && self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.contains("issue-240-core-secrets-"))
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[derive(Clone, Debug)]
struct CoreTlsRequest {
    method: Method,
    path_and_query: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

struct CoreTlsResponse {
    status: &'static str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl CoreTlsResponse {
    fn empty(status: &'static str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn json(status: &'static str, body: Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.to_string().into_bytes(),
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

struct CoreTlsUpstream {
    addr: std::net::SocketAddr,
    ca_pem: String,
    task: tokio::task::JoinHandle<()>,
}

impl CoreTlsUpstream {
    fn base_url(&self) -> String {
        format!("https://{}", self.addr)
    }

    fn shutdown(&self) {
        self.task.abort();
    }
}

impl Drop for CoreTlsUpstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_core_tls_upstream(
    handler: Arc<dyn Fn(CoreTlsRequest) -> CoreTlsResponse + Send + Sync>,
) -> CoreTlsUpstream {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let (ca_pem, server_cert_der, server_key_der) = test_ca_signed_server_certificate();
    let server_config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
                server_cert_der,
            )],
            tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(server_key_der),
            ),
        )
        .expect("core acceptance TLS server config should build");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("core acceptance TLS server should bind");
    let addr = listener
        .local_addr()
        .expect("core acceptance TLS server address should be available");
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let Some(request) = read_core_tls_request(&mut stream).await else {
                    return;
                };
                let response = handler(request);
                let mut head = format!(
                    "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                );
                for (name, value) in response.headers {
                    head.push_str(&name);
                    head.push_str(": ");
                    head.push_str(&value);
                    head.push_str("\r\n");
                }
                head.push_str("\r\n");
                if stream.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                if !response.body.is_empty()
                    && stream.write_all(response.body.as_slice()).await.is_err()
                {
                    return;
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    CoreTlsUpstream { addr, ca_pem, task }
}

async fn read_core_tls_request(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
) -> Option<CoreTlsRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(index) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break index;
        }
        if buffer.len() > 16 * 1024 {
            return None;
        }
    };
    let raw_headers = std::str::from_utf8(&buffer[..header_end]).ok()?;
    let mut lines = raw_headers.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = Method::from_bytes(request_line.next()?.as_bytes()).ok()?;
    let path_and_query = request_line.next()?.to_owned();
    let mut headers = HeaderMap::new();
    let mut content_length = 0_usize;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        let name = HeaderName::from_bytes(name.trim().as_bytes()).ok()?;
        let value = HeaderValue::from_str(value.trim()).ok()?;
        if name == header::CONTENT_LENGTH {
            content_length = value.to_str().ok()?.parse().ok()?;
        }
        headers.append(name, value);
    }
    if content_length > 64 * 1024 {
        return None;
    }
    let body_start = header_end + 4;
    while buffer.len() < body_start.saturating_add(content_length) {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    Some(CoreTlsRequest {
        method,
        path_and_query,
        headers,
        body: buffer[body_start..body_start + content_length].to_vec(),
    })
}

fn core_policy_document() -> String {
    json!({
        "schema_version": "0.1.0",
        "id": "issue-240-core-acceptance",
        "default_action": "deny",
        "enforcement_mode": "enforce",
        "roles": {
            "acceptance-admin": {
                "permissions": [
                    ADMIN_CONNECTIONS_READ_PERMISSION,
                    ADMIN_CONNECTIONS_WRITE_PERMISSION,
                    ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
                    ADMIN_CONNECTIONS_TEST_PERMISSION,
                    ADMIN_CONNECTIONS_REFRESH_PERMISSION,
                    ADMIN_TOOLS_READ_PERMISSION,
                    ADMIN_TOOLS_WRITE_PERMISSION,
                    ADMIN_TOOLS_EXECUTE_PERMISSION,
                    ADMIN_MCP_USE_PERMISSION
                ]
            },
            "ordinary-writer": {
                "permissions": [
                    ADMIN_CONNECTIONS_READ_PERMISSION,
                    ADMIN_CONNECTIONS_WRITE_PERMISSION
                ]
            },
            "secrets-writer": {
                "permissions": [
                    ADMIN_CONNECTIONS_READ_PERMISSION,
                    ADMIN_CONNECTIONS_WRITE_PERMISSION,
                    ADMIN_CONNECTIONS_SECRETS_WRITE_PERMISSION,
                    ADMIN_CONNECTIONS_TEST_PERMISSION
                ]
            }
        },
        "routes": [],
        "tools": {
            "getWidget": {
                "allowed_roles": ["acceptance-admin"],
                "timeout_ms": 5000,
                "max_concurrent": 2
            }
        }
    })
    .to_string()
}

fn core_app_config(
    database: &TempDb,
    secrets: &CoreSecretFixture,
    policy: &TempPolicyFile,
    tools: &TempToolsFile,
) -> config::Config {
    let mut config = test_config(Vec::new());
    config.auth_enabled = false;
    config.policy_file = Some(policy.path.to_string_lossy().into_owned());
    config.tools_file = Some(tools.path.to_string_lossy().into_owned());
    config.connections_sqlite_path = Some(database.path.to_string_lossy().into_owned());
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    config.rbac_exempt_paths.extend([
        CONNECTIONS_ADMIN_ROUTE.to_owned(),
        TOOLS_ADMIN_ROUTE.to_owned(),
    ]);
    config
        .rbac_exempt_paths
        .push(CONNECTION_SECRETS_ADMIN_ROUTE.to_owned());
    secrets.configure(&mut config);
    config
}

fn build_core_router(config: config::Config, audit_log: audit::AuditLog) -> Router {
    let recorder = PrometheusBuilder::new().build_recorder();
    app(
        config,
        recorder.handle(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("issue #240 acceptance app should build")
}

fn with_principal(mut request: Request<Body>, principal: auth::Principal) -> Request<Body> {
    request.extensions_mut().insert(principal);
    request
}

fn connection_collection_etag(response: &Response) -> String {
    response
        .headers()
        .get(CONNECTION_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("connection response should include collection ETag")
        .to_owned()
}

fn item_etag(response: &Response) -> String {
    response
        .headers()
        .get(header::ETAG)
        .and_then(|value| value.to_str().ok())
        .expect("item response should include ETag")
        .to_owned()
}

fn managed_http_body(
    display_name: &str,
    base_url: &str,
    secret_id: &str,
    enabled: bool,
    test_path: &str,
    discovery: Option<Value>,
) -> String {
    managed_http_body_with_authentication(
        display_name,
        base_url,
        json!({
            "type": "static_bearer",
            "secret_id": secret_id
        }),
        enabled,
        test_path,
        discovery,
    )
}

fn managed_api_key_body(
    display_name: &str,
    base_url: &str,
    secret_id: &str,
    enabled: bool,
    test_path: &str,
    discovery: Option<Value>,
) -> String {
    managed_http_body_with_authentication(
        display_name,
        base_url,
        json!({
            "type": "header_api_key",
            "header_name": OPERATOR_API_KEY_HEADER,
            "secret_id": secret_id
        }),
        enabled,
        test_path,
        discovery,
    )
}

fn managed_http_body_with_authentication(
    display_name: &str,
    base_url: &str,
    authentication: Value,
    enabled: bool,
    test_path: &str,
    discovery: Option<Value>,
) -> String {
    let mut body = json!({
        "display_name": display_name,
        "enabled": enabled,
        "kind": "http_api",
        "endpoint": {
            "base_url": base_url,
            "base_path": "/v1"
        },
        "authentication": authentication,
        "tls": {
            "ca_bundle_alias": TLS_CA_ALIAS_ID
        },
        "timeouts": {
            "connect_timeout_ms": 1000,
            "request_timeout_ms": 3000,
            "response_idle_timeout_ms": 1000
        },
        "test_profile": {
            "method": "HEAD",
            "path": test_path,
            "expected_statuses": [204]
        }
    });
    if let Some(discovery) = discovery {
        body["discovery"] = discovery;
    }
    body.to_string()
}

fn acceptance_openapi_spec() -> &'static str {
    r#"
openapi: 3.0.3
info:
  title: Acceptance Widget API
  version: 1.0.0
paths:
  /widgets/{widgetId}:
    get:
      operationId: getWidget
      summary: Fetch one widget
      parameters:
        - in: path
          name: widgetId
          required: true
          schema:
            type: string
      responses:
        "200":
          description: widget
"#
}

#[tokio::test]
async fn e2e_01_operator_alias_http_openapi_inventory_and_playground_workflow() {
    const OPERATOR_VALUE: &str = "issue-240-e2e01-operator-api-key";
    let received_authorization = Arc::new(Mutex::new(Vec::<String>::new()));
    let captured = Arc::clone(&received_authorization);
    let upstream = spawn_core_tls_upstream(Arc::new(move |request| {
        let api_key = request
            .headers
            .get(OPERATOR_API_KEY_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        captured
            .lock()
            .expect("API-key capture should not poison")
            .push(api_key.clone());
        if api_key != OPERATOR_VALUE {
            return CoreTlsResponse::empty("401 Unauthorized");
        }
        if request.path_and_query == "/v1/ready" {
            return CoreTlsResponse::empty("204 No Content");
        }
        if let Some(widget_id) = request.path_and_query.strip_prefix("/v1/widgets/") {
            return CoreTlsResponse::json("200 OK", json!({ "widget_id": widget_id }));
        }
        CoreTlsResponse::empty("404 Not Found")
    }))
    .await;

    let database = TempDb::new("issue-240-e2e01");
    let secrets = CoreSecretFixture::new(&database, OPERATOR_VALUE.as_bytes(), &upstream.ca_pem);
    let policy = TempPolicyFile::new(&core_policy_document());
    let tools = TempToolsFile::new(&empty_tools_document());
    let config = core_app_config(&database, &secrets, &policy, &tools);
    let router = build_core_router(config, test_audit_log());
    let principal = test_principal(&["acceptance-admin"]);

    let listed = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(principal.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("initial connection list should complete");
    assert_eq!(listed.status(), StatusCode::OK);
    let collection_etag = connection_collection_etag(&listed);

    let base_url = upstream.base_url();
    let disabled_body = managed_api_key_body(
        "Acceptance widgets",
        &base_url,
        OPERATOR_ALIAS_ID,
        false,
        "/ready",
        Some(json!({
            "type": "managed_openapi",
            "use_connection_authentication": true
        })),
    );
    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(principal.clone()),
            Some(disabled_body),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("disabled connection draft should create");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_etag = item_etag(&created);
    let created_body = json_body(created).await;
    let connection_id = created_body["id"]
        .as_str()
        .expect("created connection should include ID")
        .to_owned();
    assert_eq!(created_body["enabled"], json!(false));
    assert_eq!(
        created_body["configuration"]["authentication"]["secret_configured"],
        json!(true)
    );
    assert!(!created_body.to_string().contains(OPERATOR_VALUE));

    let enabled = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}"),
            Some(principal.clone()),
            Some(managed_api_key_body(
                "Acceptance widgets",
                &base_url,
                OPERATOR_ALIAS_ID,
                true,
                "/ready",
                Some(json!({
                    "type": "managed_openapi",
                    "use_connection_authentication": true
                })),
            )),
            Some(&created_etag),
            true,
        ))
        .await
        .expect("bound connection should enable");
    assert_eq!(enabled.status(), StatusCode::OK);
    let enabled_etag = item_etag(&enabled);
    assert_eq!(json_body(enabled).await["enabled"], json!(true));

    let tested = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/test"),
            Some(principal.clone()),
            None,
            Some(&enabled_etag),
            true,
        ))
        .await
        .expect("stored connection test should complete");
    assert_eq!(tested.status(), StatusCode::OK);
    let tested_body = json_body(tested).await;
    assert_eq!(tested_body["ok"], json!(true));
    assert_eq!(tested_body["state"], json!("healthy"));

    let preview = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/preview"),
            Some(principal.clone()),
            Some(json!({ "spec": acceptance_openapi_spec() }).to_string()),
            None,
            true,
        ))
        .await
        .expect("managed OpenAPI preview should complete");
    assert_eq!(preview.status(), StatusCode::OK);
    let preview = json_body(preview).await;
    assert_eq!(preview["tools"][0]["name"], json!("getWidget"));

    let registered = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/openapi/register"),
            Some(principal.clone()),
            Some(
                json!({
                    "spec": acceptance_openapi_spec(),
                    "spec_digest": preview["spec_digest"],
                    "expected_spec_revision": preview["spec_revision"],
                    "expected_catalog_revision": preview["catalog_revision"],
                    "selected_tool_names": ["getWidget"],
                    "security_confirmations": preview["security_confirmations"]
                })
                .to_string(),
            ),
            Some(&enabled_etag),
            true,
        ))
        .await
        .expect("managed OpenAPI registration should complete");
    assert_eq!(registered.status(), StatusCode::CREATED);
    assert_eq!(
        json_body(registered).await["registered_tool_names"],
        json!(["getWidget"])
    );

    let inventory = router
        .clone()
        .oneshot(with_principal(
            tools_inventory_request(None, &format!("{TOOLS_ADMIN_ROUTE}?text=getWidget")),
            principal.clone(),
        ))
        .await
        .expect("capability inventory should complete");
    assert_eq!(inventory.status(), StatusCode::OK);
    assert_capability_inventory_no_store(&inventory);
    let inventory = json_body(inventory).await;
    assert_eq!(inventory["total_count"], json!(1));
    let capability_id = inventory["capabilities"][0]["id"]
        .as_str()
        .expect("managed capability should have opaque ID")
        .to_owned();

    let detail = router
        .clone()
        .oneshot(with_principal(
            tools_inventory_request(None, &format!("{TOOLS_ADMIN_ROUTE}/{capability_id}")),
            principal.clone(),
        ))
        .await
        .expect("capability detail should complete");
    assert_eq!(detail.status(), StatusCode::OK);
    let execution_etag = item_etag(&detail);
    let detail_body = json_body(detail).await;
    assert_eq!(detail_body["connection"]["id"], json!(connection_id));
    assert_eq!(detail_body["actions"]["can_execute"], json!(true));

    let executed = router
        .oneshot(with_principal(
            tool_playground_request(
                Some("csrf-safe-bearer"),
                &capability_id,
                Some(&execution_etag),
                Body::from(r#"{"arguments":{"widgetId":"42"}}"#),
            ),
            principal,
        ))
        .await
        .expect("connection-bound playground execution should complete");
    assert_eq!(executed.status(), StatusCode::OK);
    assert_capability_inventory_no_store(&executed);
    let executed = json_body(executed).await;
    assert_eq!(executed["body"]["value"]["widget_id"], json!("42"));
    assert!(!executed.to_string().contains(OPERATOR_VALUE));

    let received = received_authorization
        .lock()
        .expect("authorization capture should not poison")
        .clone();
    assert_eq!(
        received,
        vec![OPERATOR_VALUE.to_owned(), OPERATOR_VALUE.to_owned()]
    );
}

#[tokio::test]
async fn e2e_02_encrypted_local_bearer_rotation_revision_and_redaction_workflow() {
    const FIRST_VALUE: &str = "issue-240-e2e02-local-first";
    const ROTATED_VALUE: &str = "issue-240-e2e02-local-rotated";
    let outbound_authorization = Arc::new(Mutex::new(Vec::<String>::new()));
    let capture_headers = Arc::clone(&outbound_authorization);
    let upstream = spawn_core_tls_upstream(Arc::new(move |request| {
        if !matches!(
            request.path_and_query.as_str(),
            "/v1/ready" | "/v1/ready-rotated"
        ) {
            return CoreTlsResponse::empty("404 Not Found");
        }
        let authorization = request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        capture_headers
            .lock()
            .expect("outbound capture should not poison")
            .push(authorization.clone());
        if matches!(
            authorization.as_str(),
            "Bearer issue-240-e2e02-local-first" | "Bearer issue-240-e2e02-local-rotated"
        ) {
            CoreTlsResponse::empty("204 No Content")
        } else {
            CoreTlsResponse::empty("401 Unauthorized")
        }
    }))
    .await;

    let database = TempDb::new("issue-240-e2e02");
    let secrets = CoreSecretFixture::new(&database, b"unused-operator-value", &upstream.ca_pem);
    let policy = TempPolicyFile::new(&core_policy_document());
    let tools = TempToolsFile::new(&empty_tools_document());
    let config = core_app_config(&database, &secrets, &policy, &tools);
    let capture = audit::sink::tests::CaptureSink::new();
    let audit_log = audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>);
    let recorder = PrometheusBuilder::new().build_recorder();
    let metrics = recorder.handle();
    let router = app(
        config,
        metrics.clone(),
        audit_log,
        test_audit_event_sender(),
    )
    .expect("local-secret acceptance app should build");
    let principal = test_principal(&["acceptance-admin"]);
    let mut safe_observables = Vec::new();

    let initial_secrets = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(principal.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("initial secret list should complete");
    let secret_collection_etag = initial_secrets
        .headers()
        .get(CONNECTION_SECRET_COLLECTION_ETAG_HEADER)
        .and_then(|value| value.to_str().ok())
        .expect("secret list should include mutation ETag")
        .to_owned();
    safe_observables.push(body_string(initial_secrets).await);

    let created_secret = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTION_SECRETS_ADMIN_ROUTE,
            Some(principal.clone()),
            Some(
                json!({
                    "label": "E2E bearer",
                    "purpose": "static_bearer",
                    "value": FIRST_VALUE
                })
                .to_string(),
            ),
            Some(&secret_collection_etag),
            true,
        ))
        .await
        .expect("encrypted local secret should create");
    assert_eq!(created_secret.status(), StatusCode::CREATED);
    let secret_etag = item_etag(&created_secret);
    let created_secret_body = body_string(created_secret).await;
    safe_observables.push(created_secret_body.clone());
    let created_secret_json: Value =
        serde_json::from_str(&created_secret_body).expect("secret response should be JSON");
    let secret_id = created_secret_json["id"]
        .as_str()
        .expect("secret response should include ID")
        .to_owned();
    assert_eq!(created_secret_json["version"], json!(1));

    let connections = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(principal.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let connection_collection_etag = connection_collection_etag(&connections);
    safe_observables.push(body_string(connections).await);
    let base_url = upstream.base_url();
    let created_connection = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(principal.clone()),
            Some(managed_http_body(
                "Encrypted local bearer",
                &base_url,
                &secret_id,
                true,
                "/ready",
                None,
            )),
            Some(&connection_collection_etag),
            true,
        ))
        .await
        .expect("secret-bound connection should create");
    assert_eq!(created_connection.status(), StatusCode::CREATED);
    let connection_etag = item_etag(&created_connection);
    let created_connection_body = body_string(created_connection).await;
    safe_observables.push(created_connection_body.clone());
    let created_connection_json: Value =
        serde_json::from_str(&created_connection_body).expect("connection response should be JSON");
    let connection_id = created_connection_json["id"]
        .as_str()
        .expect("connection response should include ID")
        .to_owned();
    let initial_credential_revision = created_connection_json["revisions"]["credential"]
        .as_u64()
        .expect("connection response should include credential revision");

    let first_test = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/test"),
            Some(principal.clone()),
            None,
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("pre-rotation connection test should complete");
    assert_eq!(first_test.status(), StatusCode::OK);
    let first_test_body = body_string(first_test).await;
    assert_eq!(
        serde_json::from_str::<Value>(&first_test_body)
            .expect("pre-rotation test response should be JSON")["ok"],
        json!(true)
    );
    safe_observables.push(first_test_body);
    assert_eq!(
        outbound_authorization
            .lock()
            .expect("outbound capture should not poison")
            .as_slice(),
        &[format!("Bearer {FIRST_VALUE}")]
    );

    let rotated = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTION_SECRETS_ADMIN_ROUTE}/{secret_id}"),
            Some(principal.clone()),
            Some(
                json!({
                    "purpose": "static_bearer",
                    "value": ROTATED_VALUE
                })
                .to_string(),
            ),
            Some(&secret_etag),
            true,
        ))
        .await
        .expect("encrypted local secret should rotate");
    assert_eq!(rotated.status(), StatusCode::OK);
    let rotated_body = body_string(rotated).await;
    safe_observables.push(rotated_body.clone());
    assert_eq!(
        serde_json::from_str::<Value>(&rotated_body)
            .expect("rotated secret response should be JSON")["version"],
        json!(2)
    );

    let updated_connection = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}"),
            Some(principal.clone()),
            Some(managed_http_body(
                "Encrypted local bearer",
                &base_url,
                &secret_id,
                true,
                "/ready-rotated",
                None,
            )),
            Some(&connection_etag),
            true,
        ))
        .await
        .expect("credential-bearing test profile should update atomically");
    assert_eq!(updated_connection.status(), StatusCode::OK);
    let updated_etag = item_etag(&updated_connection);
    let updated_body = body_string(updated_connection).await;
    safe_observables.push(updated_body.clone());
    let updated_json: Value =
        serde_json::from_str(&updated_body).expect("updated connection response should be JSON");
    assert_eq!(
        updated_json["revisions"]["credential"],
        json!(initial_credential_revision + 1)
    );
    // The production per-Connection probe bucket intentionally permits one
    // probe every five seconds. Wait for its real refill rather than bypassing
    // admission in this end-to-end rotation workflow.
    tokio::time::sleep(Duration::from_millis(5_050)).await;

    let tested = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}/test"),
            Some(principal.clone()),
            None,
            Some(&updated_etag),
            true,
        ))
        .await
        .expect("rotated connection test should complete");
    assert_eq!(tested.status(), StatusCode::OK);
    let tested_body = body_string(tested).await;
    safe_observables.push(tested_body.clone());
    assert_eq!(
        serde_json::from_str::<Value>(&tested_body).expect("test response should be JSON")["ok"],
        json!(true)
    );
    assert_eq!(
        outbound_authorization
            .lock()
            .expect("outbound capture should not poison")
            .as_slice(),
        &[
            format!("Bearer {FIRST_VALUE}"),
            format!("Bearer {ROTATED_VALUE}")
        ]
    );

    assert_eventually(Duration::from_secs(1), || {
        capture.events().iter().any(|event| {
            event.event_type == audit::event::CONNECTION_SECRET_CHANGED
                && event.payload["action"] == json!("rotated")
        }) && capture.events().iter().any(|event| {
            event.event_type == audit::event::CONNECTION_CREDENTIAL_CHANGED
                && event.payload["action"] == json!("updated")
        })
    });
    safe_observables
        .push(serde_json::to_string(&capture.events()).expect("acceptance audit should serialize"));
    let detail = router
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}"),
            Some(principal),
            None,
            None,
            false,
        ))
        .await
        .expect("post-rotation connection detail should complete");
    assert_eq!(detail.status(), StatusCode::OK);
    safe_observables.push(body_string(detail).await);
    safe_observables.push(metrics.render());
    for suffix in ["", "-wal", "-shm"] {
        let path = if suffix.is_empty() {
            database.path.clone()
        } else {
            let mut raw = database.path.as_os_str().to_os_string();
            raw.push(suffix);
            PathBuf::from(raw)
        };
        if let Ok(bytes) = fs::read(path) {
            safe_observables.push(String::from_utf8_lossy(&bytes).into_owned());
        }
    }
    let safe_observables = safe_observables.join("\n");
    for canary in [
        FIRST_VALUE,
        ROTATED_VALUE,
        OPERATOR_ALIAS_FILE,
        MASTER_KEY_FILE,
    ] {
        assert!(
            !safe_observables.contains(canary),
            "API, status, audit, metric, or SQLite observable leaked {canary}"
        );
    }
}

async fn execute_oauth_batch(
    runtime: &connections::http::ConnectionHttpRuntime,
    target: Arc<connections::http::ConnectionHttpTarget>,
) -> Vec<Vec<u8>> {
    let checked = target
        .preflight_client()
        .checked_destination(target.url())
        .await
        .expect("OAuth resource destination should pass egress");
    let prepared = runtime
        .prepare_transport(&target, &checked)
        .await
        .expect("OAuth resource TLS should prepare");
    let client = Arc::clone(prepared.client());
    let destination = prepared.destination().clone();
    join_all((0..100).map(|_| {
        let runtime = runtime.clone();
        let target = Arc::clone(&target);
        let client = Arc::clone(&client);
        let destination = destination.clone();
        async move {
            let credential = runtime
                .resolve_credential(&target)
                .await
                .expect("OAuth credential should resolve")
                .expect("OAuth target should have a credential");
            let mut headers = HeaderMap::new();
            credential
                .inject(&mut headers)
                .expect("OAuth credential should inject");
            let response = client
                .request_with_headers_at_checked_destination(
                    &destination,
                    Method::GET,
                    target.url(),
                    headers,
                    None,
                )
                .await
                .expect("OAuth-backed resource request should complete");
            assert_eq!(response.status, StatusCode::OK);
            response.body
        }
    }))
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_03_oauth_single_flight_expiry_and_secret_rotation_workflow() {
    const FIRST_SECRET: &str = "issue-240-e2e03-oauth-first";
    const ROTATED_SECRET: &str = "issue-240-e2e03-oauth-rotated";
    let mint_count = Arc::new(AtomicUsize::new(0));
    let basic_headers = Arc::new(Mutex::new(Vec::<String>::new()));
    let resource_headers = Arc::new(Mutex::new(Vec::<String>::new()));
    let count = Arc::clone(&mint_count);
    let captured = Arc::clone(&basic_headers);
    let resources = Arc::clone(&resource_headers);
    let upstream = spawn_core_tls_upstream(Arc::new(move |request| {
        if request.method == Method::POST && request.path_and_query == "/oauth/token" {
            captured
                .lock()
                .expect("OAuth Basic capture should not poison")
                .push(
                    request
                        .headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned(),
                );
            let generation = count.fetch_add(1, Ordering::SeqCst) + 1;
            return CoreTlsResponse::json(
                "200 OK",
                json!({
                    "access_token": format!("acceptance-access-{generation}"),
                    "token_type": "Bearer",
                    "expires_in": 1
                }),
            );
        }
        if request.method == Method::GET && request.path_and_query == "/v1/widgets" {
            resources
                .lock()
                .expect("OAuth resource capture should not poison")
                .push(
                    request
                        .headers
                        .get(header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default()
                        .to_owned(),
                );
            return CoreTlsResponse::json("200 OK", json!({"ok": true}));
        }
        CoreTlsResponse::empty("404 Not Found")
    }))
    .await;

    let database = TempDb::new("issue-240-e2e03");
    let secrets = CoreSecretFixture::new(&database, b"unused-oauth-operator", &upstream.ca_pem);
    let mut config = config::Config::test_defaults();
    config.connections_sqlite_path = Some(database.path.to_string_lossy().into_owned());
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    secrets.configure(&mut config);
    let control_plane = connections::control_plane::ConnectionControlPlane::from_config(&config)
        .expect("OAuth acceptance control plane should build");
    let manager = control_plane
        .local_secret_manager()
        .expect("OAuth acceptance local manager should exist");
    let secret = manager
        .create(
            "OAuth acceptance secret",
            connections::secret::ResolvedSecret::new(
                connections::secret::SecretPurpose::OAuthClientSecret,
                FIRST_SECRET.as_bytes().to_vec(),
            )
            .expect("first OAuth secret should validate"),
        )
        .expect("first OAuth secret should create");
    let snapshot = control_plane.runtime_snapshot();
    let candidate: connections::model::ConnectionWrite = serde_json::from_value(json!({
        "display_name": "OAuth acceptance",
        "enabled": true,
        "kind": "http_api",
        "endpoint": {
            "base_url": upstream.base_url(),
            "base_path": "/v1"
        },
        "authentication": {
            "type": "oauth2_client_credentials",
            "client_id": "acceptance-client",
            "client_secret_id": secret.id.clone(),
            "token_url": format!("{}/oauth/token", upstream.base_url()),
            "scopes": ["widgets.read"],
            "client_auth_method": "client_secret_basic"
        },
        "tls": {
            "ca_bundle_alias": TLS_CA_ALIAS_ID
        }
    }))
    .expect("OAuth acceptance connection should deserialize");
    let record = control_plane
        .create_managed(snapshot.collection_etag(), candidate)
        .expect("OAuth acceptance connection should create");
    let capture = audit::sink::tests::CaptureSink::new();
    let egress_config = egress::EgressConfig::from_config(&config);
    let mut egress_config = egress_config;
    egress_config
        .apply_tls_ca_bundle_path(secrets.root.join(TLS_CA_FILE))
        .expect("OAuth token CA should configure");
    let egress_client = Arc::new(
        egress::EgressClient::new(egress_config.clone())
            .expect("OAuth acceptance egress client should build"),
    );
    let runtime = connections::http::ConnectionHttpRuntime::new(
        control_plane.clone(),
        egress_config,
        egress_client,
    )
    .with_audit(audit::AuditLog::new(
        Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>
    ));
    let target = Arc::new(
        runtime
            .target(record.id.as_str(), "/widgets")
            .expect("OAuth acceptance target should resolve"),
    );
    target
        .client()
        .checked_destination(target.url())
        .await
        .expect("upstream preflight should pass before OAuth work");

    let first = execute_oauth_batch(&runtime, Arc::clone(&target)).await;
    assert_eq!(first.len(), 100);
    assert!(first.iter().all(|body| body == br#"{"ok":true}"#));
    assert_eq!(mint_count.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_millis(1_050)).await;
    let refreshed = execute_oauth_batch(&runtime, Arc::clone(&target)).await;
    assert!(refreshed.iter().all(|body| body == br#"{"ok":true}"#));
    assert_eq!(mint_count.load(Ordering::SeqCst), 2);

    manager
        .rotate(
            &secret.id,
            connections::secret::ResolvedSecret::new(
                connections::secret::SecretPurpose::OAuthClientSecret,
                ROTATED_SECRET.as_bytes().to_vec(),
            )
            .expect("rotated OAuth secret should validate"),
        )
        .expect("OAuth client secret should rotate");
    let rotated = execute_oauth_batch(&runtime, target).await;
    assert!(rotated.iter().all(|body| body == br#"{"ok":true}"#));
    assert_eq!(mint_count.load(Ordering::SeqCst), 3);
    let resource_headers = resource_headers
        .lock()
        .expect("OAuth resource capture should not poison");
    assert_eq!(resource_headers.len(), 300);
    assert!(resource_headers[..100]
        .iter()
        .all(|value| value == "Bearer acceptance-access-1"));
    assert!(resource_headers[100..200]
        .iter()
        .all(|value| value == "Bearer acceptance-access-2"));
    assert!(resource_headers[200..]
        .iter()
        .all(|value| value == "Bearer acceptance-access-3"));

    let expected_first = format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("acceptance-client:{FIRST_SECRET}"))
    );
    let expected_rotated = format!(
        "Basic {}",
        BASE64_STANDARD.encode(format!("acceptance-client:{ROTATED_SECRET}"))
    );
    assert_eq!(
        basic_headers
            .lock()
            .expect("OAuth Basic capture should not poison")
            .as_slice(),
        &[expected_first.clone(), expected_first, expected_rotated]
    );
    assert_eventually(Duration::from_secs(1), || {
        capture
            .events()
            .iter()
            .filter(|event| event.event_type == audit::event::CONNECTION_OAUTH_TOKEN_REFRESH)
            .count()
            == 3
    });
    let audit_json =
        serde_json::to_string(&capture.events()).expect("OAuth audit should serialize");
    for canary in [FIRST_SECRET, ROTATED_SECRET, "acceptance-access-"] {
        assert!(!audit_json.contains(canary), "OAuth audit leaked {canary}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_04_authenticated_mcp_stream_refresh_lkg_and_delete_workflow() {
    let downstream = mcp_test_harness(&["admin"], test_audit_log()).await;
    let (initialize_status, initialize) = mcp_rpc(
        &downstream.router,
        Some(&downstream.admin_token),
        1,
        "initialize",
        Some(json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "issue-240-acceptance", "version": "1.0.0" }
        })),
        "issue-240-e2e04-initialize",
    )
    .await;
    assert_eq!(initialize_status, StatusCode::OK);
    assert_eq!(initialize["error"], Value::Null);
    let (list_status, listed) = mcp_rpc(
        &downstream.router,
        Some(&downstream.admin_token),
        2,
        "tools/list",
        Some(json!({})),
        "issue-240-e2e04-list",
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert!(listed["result"]["tools"]
        .as_array()
        .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "echo")));
    let (call_status, called) = mcp_rpc(
        &downstream.router,
        Some(&downstream.admin_token),
        3,
        "tools/call",
        Some(json!({
            "name": "echo",
            "arguments": { "message": "streamable HTTP acceptance" }
        })),
        "issue-240-e2e04-call",
    )
    .await;
    assert_eq!(call_status, StatusCode::OK);
    assert_eq!(called["result"]["isError"], json!(false));

    const MANAGED_MCP_BEARER: &str = "issue-240-e2e04-managed-mcp-bearer";
    let managed_requests = Arc::new(Mutex::new(Vec::<CoreTlsRequest>::new()));
    let captured_requests = Arc::clone(&managed_requests);
    let upstream = spawn_core_tls_upstream(Arc::new(move |request| {
        let authorized = request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            == Some("Bearer issue-240-e2e04-managed-mcp-bearer");
        captured_requests
            .lock()
            .expect("managed MCP request capture should not poison")
            .push(request.clone());
        if !authorized {
            return CoreTlsResponse::empty("401 Unauthorized");
        }
        match request.method {
            Method::GET => CoreTlsResponse::empty("405 Method Not Allowed"),
            Method::DELETE => CoreTlsResponse::empty("200 OK"),
            Method::POST => {
                let body: Value = serde_json::from_slice(&request.body)
                    .expect("managed MCP request body should be JSON");
                let rpc_method = body["method"].as_str().unwrap_or_default();
                let id = body["id"].clone();
                match rpc_method {
                    "initialize" => CoreTlsResponse::json(
                        "200 OK",
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "protocolVersion": "2025-06-18",
                                "capabilities": {"tools": {}},
                                "serverInfo": {
                                    "name": "issue-240-authenticated-mcp",
                                    "version": "1.0.0"
                                }
                            }
                        }),
                    )
                    .with_header("Mcp-Session-Id", "issue-240-managed-session"),
                    "notifications/initialized" => CoreTlsResponse::empty("202 Accepted"),
                    "tools/list" => CoreTlsResponse::json(
                        "200 OK",
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "tools": [{
                                    "name": "remote_echo",
                                    "description": "Authenticated remote echo",
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": {"message": {"type": "string"}}
                                    }
                                }]
                            }
                        }),
                    ),
                    "tools/call" => CoreTlsResponse::json(
                        "200 OK",
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": {
                                "content": [],
                                "structuredContent": {"ok": true},
                                "isError": false
                            }
                        }),
                    ),
                    _ => CoreTlsResponse::empty("400 Bad Request"),
                }
            }
            _ => CoreTlsResponse::empty("405 Method Not Allowed"),
        }
    }))
    .await;
    let database = TempDb::new("issue-240-e2e04-managed");
    let secrets =
        CoreSecretFixture::new(&database, MANAGED_MCP_BEARER.as_bytes(), &upstream.ca_pem);
    let mut config = config::Config::test_defaults();
    config.connections_sqlite_path = Some(database.path.to_string_lossy().into_owned());
    config.egress_allowed_hosts = vec!["127.0.0.1".to_owned()];
    config.egress_deny_private_ips = false;
    secrets.configure(&mut config);
    let control_plane = connections::control_plane::ConnectionControlPlane::from_config(&config)
        .expect("managed MCP acceptance control plane should build");
    let snapshot = control_plane.runtime_snapshot();
    let candidate: connections::model::ConnectionWrite = serde_json::from_value(json!({
        "display_name": "Managed MCP acceptance",
        "enabled": true,
        "kind": "mcp_streamable_http",
        "endpoint": {
            "base_url": upstream.base_url(),
            "base_path": "/mcp"
        },
        "authentication": {
            "type": "static_bearer",
            "secret_id": OPERATOR_ALIAS_ID
        },
        "tls": {"ca_bundle_alias": TLS_CA_ALIAS_ID},
        "timeouts": {
            "connect_timeout_ms": 1000,
            "request_timeout_ms": 3000,
            "response_idle_timeout_ms": 1000
        },
        "discovery": {
            "type": "managed_mcp",
            "use_connection_authentication": true
        }
    }))
    .expect("managed MCP acceptance connection should deserialize");
    let record = control_plane
        .create_managed(snapshot.collection_etag(), candidate)
        .expect("managed MCP acceptance connection should create");
    let egress_config = egress::EgressConfig::from_config(&config);
    let egress_client = Arc::new(
        egress::EgressClient::new(egress_config.clone())
            .expect("managed MCP acceptance egress client should build"),
    );
    let http = connections::http::ConnectionHttpRuntime::new(
        control_plane.clone(),
        egress_config,
        egress_client,
    );
    let registry = tools::definitions::ToolRegistry::disabled();
    let service = connections::mcp::McpConnectionCatalogService::load(
        control_plane.clone(),
        http.clone(),
        registry.clone(),
    )
    .expect("managed MCP acceptance service should load");

    let refreshed = service
        .refresh(record.id.as_str(), record.etag().as_str())
        .await
        .expect("managed MCP discovery should initialize and list");
    assert_eq!(refreshed.total_count, 1);
    let public_name = format!("{}:remote_echo", record.id);
    assert!(registry.get(&public_name).is_some());
    tools::mcp_upstream::call_connection_tool(
        &http,
        record.id.as_str(),
        record.etag().as_str(),
        "remote_echo",
        json!({ "message": "managed MCP call" }),
    )
    .await
    .expect("managed MCP call should succeed");
    let captured = managed_requests
        .lock()
        .expect("managed MCP request capture should not poison")
        .clone();
    assert!(captured.iter().all(|request| {
        request
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            == Some("Bearer issue-240-e2e04-managed-mcp-bearer")
    }));
    let rpc_methods = captured
        .iter()
        .filter_map(|request| serde_json::from_slice::<Value>(&request.body).ok())
        .filter_map(|body| body["method"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    for required in [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "tools/call",
    ] {
        assert!(
            rpc_methods.iter().any(|method| method == required),
            "managed MCP lifecycle did not issue {required}"
        );
    }
    assert!(captured.iter().any(|request| request.method == Method::GET));
    assert!(captured
        .iter()
        .any(|request| request.method == Method::DELETE));

    upstream.shutdown();
    tokio::task::yield_now().await;
    let failed_refresh = service
        .refresh(record.id.as_str(), record.etag().as_str())
        .await
        .expect_err("failed refresh must preserve last-known-good catalog");
    assert!(matches!(
        failed_refresh,
        connections::mcp::McpCatalogRefreshError::RequestFailed
            | connections::mcp::McpCatalogRefreshError::InvalidResponse
    ));
    assert!(registry.get(&public_name).is_some());
    assert!(control_plane
        .managed_store()
        .expect("managed store should exist")
        .mcp_catalog(&record.id)
        .expect("last-known-good catalog read should succeed")
        .is_some());

    let store = control_plane
        .managed_store()
        .expect("managed store should exist");
    registry
        .replace_mcp_connection_catalog(record.id.as_str(), Vec::new(), || {
            store
                .replace_mcp_catalog(&record.id, &record.etag(), &[], &[], &[])
                .map(|_| ())
        })
        .expect("managed MCP catalog should clear before delete");
    control_plane
        .delete_managed(&record.id, &record.etag())
        .expect("managed MCP connection should delete");
    service.remove_connection(&record.id);
    let after_delete = tools::mcp_upstream::call_connection_tool(
        &http,
        record.id.as_str(),
        record.etag().as_str(),
        "remote_echo",
        json!({}),
    )
    .await;
    assert!(
        after_delete.is_err(),
        "deleted managed MCP connection must be non-invocable"
    );
    assert!(registry.get(&public_name).is_none());
    assert!(service
        .runtime()
        .expected_connection_etag(record.id.as_str())
        .is_none());
    assert!(!control_plane
        .runtime_snapshot()
        .managed()
        .contains_key(&record.id));
}

#[tokio::test]
async fn e2e_05_secret_authority_denial_and_atomic_writer_revision_workflow() {
    const OPERATOR_VALUE: &str = "issue-240-e2e05-operator";
    let outbound_calls = Arc::new(AtomicUsize::new(0));
    let origin_calls = Arc::clone(&outbound_calls);
    let origin = spawn_core_tls_upstream(Arc::new(move |_| {
        origin_calls.fetch_add(1, Ordering::SeqCst);
        CoreTlsResponse::empty("204 No Content")
    }))
    .await;
    let redirect_calls = Arc::clone(&outbound_calls);
    let redirect_target = spawn_core_tls_upstream(Arc::new(move |_| {
        redirect_calls.fetch_add(1, Ordering::SeqCst);
        CoreTlsResponse::empty("204 No Content")
    }))
    .await;
    let trusted_ca_bundle = format!("{}\n{}", origin.ca_pem, redirect_target.ca_pem);
    let database = TempDb::new("issue-240-e2e05");
    let secrets = CoreSecretFixture::new(&database, OPERATOR_VALUE.as_bytes(), &trusted_ca_bundle);
    let policy = TempPolicyFile::new(&core_policy_document());
    let tools = TempToolsFile::new(&empty_tools_document());
    let config = core_app_config(&database, &secrets, &policy, &tools);
    let capture = audit::sink::tests::CaptureSink::new();
    let router = build_core_router(
        config,
        audit::AuditLog::new(Arc::new(capture.clone()) as Arc<dyn audit::AuditSink>),
    );
    let ordinary = test_principal(&["ordinary-writer"]);
    let secrets_writer = test_principal(&["secrets-writer"]);

    let listed = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            CONNECTIONS_ADMIN_ROUTE,
            Some(secrets_writer.clone()),
            None,
            None,
            false,
        ))
        .await
        .expect("connection list should complete");
    let collection_etag = connection_collection_etag(&listed);
    let base_url = origin.base_url();
    let created = router
        .clone()
        .oneshot(connection_admin_request(
            Method::POST,
            CONNECTIONS_ADMIN_ROUTE,
            Some(secrets_writer.clone()),
            Some(managed_http_body(
                "Secret authority acceptance",
                &base_url,
                OPERATOR_ALIAS_ID,
                false,
                "/ready",
                None,
            )),
            Some(&collection_etag),
            true,
        ))
        .await
        .expect("credentialed draft should create");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created_etag = item_etag(&created);
    let created_body = json_body(created).await;
    let connection_id = created_body["id"]
        .as_str()
        .expect("credentialed draft should include ID")
        .to_owned();
    let initial_connection_revision = created_body["revisions"]["connection"]
        .as_u64()
        .expect("draft should include connection revision");
    let initial_credential_revision = created_body["revisions"]["credential"]
        .as_u64()
        .expect("draft should include credential revision");

    let replacement = managed_http_body(
        "Credential redirect acceptance",
        &redirect_target.base_url(),
        OPERATOR_ALIAS_ID,
        true,
        "/ready-updated",
        None,
    );
    let forbidden = router
        .clone()
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}"),
            Some(ordinary.clone()),
            Some(replacement.clone()),
            Some(&created_etag),
            true,
        ))
        .await
        .expect("ordinary writer denial should complete");
    assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
    assert_eq!(outbound_calls.load(Ordering::SeqCst), 0);
    assert!(!body_string(forbidden).await.contains(OPERATOR_VALUE));

    let unchanged = router
        .clone()
        .oneshot(connection_admin_request(
            Method::GET,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}"),
            Some(ordinary),
            None,
            None,
            false,
        ))
        .await
        .expect("unchanged detail should complete");
    assert_eq!(unchanged.status(), StatusCode::OK);
    assert_eq!(item_etag(&unchanged), created_etag);
    let unchanged = json_body(unchanged).await;
    assert_eq!(
        unchanged["revisions"]["connection"],
        json!(initial_connection_revision)
    );
    assert_eq!(
        unchanged["revisions"]["credential"],
        json!(initial_credential_revision)
    );
    assert_eq!(unchanged["enabled"], json!(false));

    let allowed = router
        .oneshot(connection_admin_request(
            Method::PUT,
            &format!("{CONNECTIONS_ADMIN_ROUTE}/{connection_id}"),
            Some(secrets_writer),
            Some(replacement),
            Some(&created_etag),
            true,
        ))
        .await
        .expect("secrets writer update should complete");
    assert_eq!(allowed.status(), StatusCode::OK);
    let allowed = json_body(allowed).await;
    assert_eq!(allowed["enabled"], json!(true));
    assert_eq!(
        allowed["revisions"]["connection"],
        json!(initial_connection_revision + 1)
    );
    assert_eq!(
        allowed["revisions"]["credential"],
        json!(initial_credential_revision + 1)
    );
    assert_eq!(
        outbound_calls.load(Ordering::SeqCst),
        0,
        "configuration mutation must not contact the stored destination"
    );

    assert_eventually(Duration::from_secs(1), || {
        let events = capture.events();
        events.iter().any(|event| {
            event.event_type == "authz.denied"
                && event.payload["authorization_layer"] == json!("connection_secret_authority")
                && event.payload["operation"] == json!("replace")
        }) && events
            .iter()
            .filter(|event| {
                event.event_type == audit::event::CONNECTION_CREDENTIAL_CHANGED
                    && event.payload["action"] == json!("updated")
            })
            .count()
            == 1
    });
    let serialized =
        serde_json::to_string(&capture.events()).expect("authority audit should serialize");
    assert!(!serialized.contains(OPERATOR_VALUE));
    assert!(!serialized.contains(OPERATOR_ALIAS_FILE));
}

fn write_secret_file(path: &FsPath, contents: &[u8]) {
    fs::write(path, contents).expect("acceptance secret file should write");
    set_file_permissions(path, 0o600);
}

#[cfg(unix)]
fn set_directory_permissions(path: &FsPath, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("acceptance secret directory permissions should set");
}

#[cfg(not(unix))]
fn set_directory_permissions(_: &FsPath, _: u32) {}

#[cfg(unix)]
fn set_file_permissions(path: &FsPath, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("acceptance secret file permissions should set");
}

#[cfg(not(unix))]
fn set_file_permissions(_: &FsPath, _: u32) {}
