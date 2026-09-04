//! Exercise MCP authorization bootstrap with a local authorization server.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_oauth_bootstrap_challenge_metadata_registration_authorize_token_initialize() {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("AS listener");
    let issuer = format!("http://{}", listener.local_addr().expect("AS address"));
    let resource = "https://gateway.example.test/mcp";
    let redirect_uri = "http://127.0.0.1:49152/callback";
    let verifier = "issue373-verifier-with-at-least-forty-three-characters";
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let jwks_addr = spawn_test_jwks_server().await;
    let discovery = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "registration_endpoint": format!("{issuer}/register"),
        "jwks_uri": format!("http://{jwks_addr}/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"]
    });
    let token = signed_token_with_claims(json!({
        "sub": "mcp-bootstrap-user", "iss": issuer, "aud": resource,
        "exp": OffsetDateTime::now_utc().unix_timestamp() + 300,
        "jti": uuid::Uuid::new_v4().to_string(), "roles": ["admin"], "scope": "mcp:tools"
    }));
    // The mock AS records order and validates the client's PKCE/resource binding.
    // Browser sign-in is represented by its authorize response; no live IdP is used.
    let stage = Arc::new(AtomicUsize::new(0));
    let register_stage = Arc::clone(&stage);
    let authorize_stage = Arc::clone(&stage);
    let token_stage = Arc::clone(&stage);
    let as_router = Router::new()
        .route("/.well-known/openid-configuration", get(move || {
            let discovery = discovery.clone();
            async move { Json(discovery) }
        }))
        .route("/register", post(move |Json(body): Json<Value>| async move {
            assert_eq!(register_stage.fetch_add(1, Ordering::SeqCst), 0);
            assert_eq!(body["redirect_uris"], json!([redirect_uri]));
            assert_eq!(body["token_endpoint_auth_method"], "none");
            (StatusCode::CREATED, Json(json!({"client_id": "issue373-client", "redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none"})))
        }))
        .route("/authorize", get(move |axum::extract::Query(query): axum::extract::Query<HashMap<String, String>>| async move {
            assert_eq!(authorize_stage.fetch_add(1, Ordering::SeqCst), 1);
            assert_eq!(query["client_id"], "issue373-client");
            assert_eq!(query["redirect_uri"], redirect_uri);
            assert_eq!(query["response_type"], "code");
            assert_eq!(query["resource"], resource);
            assert_eq!(query["scope"], "mcp:tools");
            assert_eq!(query["code_challenge_method"], "S256");
            assert_eq!(query["code_challenge"], challenge);
            axum::response::Redirect::temporary(&format!("{redirect_uri}?code=issue373-code&state={}", query["state"]))
        }))
        .route("/token", post(move |axum::Form(form): axum::Form<HashMap<String, String>>| async move {
            assert_eq!(token_stage.fetch_add(1, Ordering::SeqCst), 2);
            assert_eq!(form["grant_type"], "authorization_code");
            assert_eq!(form["client_id"], "issue373-client");
            assert_eq!(form["code"], "issue373-code");
            assert_eq!(form["redirect_uri"], redirect_uri);
            assert_eq!(form["resource"], resource);
            assert_eq!(form["code_verifier"], verifier);
            Json(json!({"access_token": token, "token_type": "Bearer", "expires_in": 300}))
        }));
    let as_server = tokio::spawn(async move {
        axum::serve(listener, as_router).await.expect("AS serve");
    });
    let mut config = test_config(Vec::new());
    config.gateway_public_url = Some("https://gateway.example.test".to_owned());
    configure_test_jwt_provider(&mut config, jwks_addr);
    config.auth_providers[0].issuer = Some(issuer.clone());
    config.egress_deny_private_ips = false;
    assert!(config.csrf_enabled);
    let recorder = PrometheusBuilder::new().build_recorder();
    let router = app(
        config,
        recorder.handle(),
        test_audit_log(),
        test_audit_event_sender(),
    )
    .expect("app");
    let (gateway_addr, gateway_server) = spawn_gateway_router(router).await;
    let gateway_url = format!("http://{gateway_addr}");
    let http = egress::EgressClient::new(egress::EgressConfig {
        allowed_hosts: HashSet::from(["127.0.0.1".to_owned()]),
        deny_private_ips: false,
        ..egress::EgressConfig::default()
    })
    .expect("HTTP client");
    let headers = HeaderMap::from_iter([
        (
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        ),
        (
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        ),
    ]);
    let response = http.request_with_headers(Method::POST, &format!("{gateway_url}/mcp"), headers,
        Some(serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": mcp_initialize_params()})).expect("initialize JSON")))
        .await.expect("initial request");
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    let challenge_header = response.headers[header::WWW_AUTHENTICATE]
        .to_str()
        .expect("challenge");
    let metadata_url = challenge_header
        .split("resource_metadata=\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .expect("resource metadata link");
    let metadata_path = url::Url::parse(metadata_url)
        .expect("metadata URL")
        .path()
        .to_owned();
    // Route the advertised public URL to the local gateway fixture.
    let metadata = response_json(
        http.request(Method::GET, &format!("{gateway_url}{metadata_path}"))
            .await
            .expect("metadata"),
    );
    assert_eq!(metadata["resource"], resource);
    let authorization_server = metadata["authorization_servers"][0]
        .as_str()
        .expect("AS issuer");
    assert_eq!(authorization_server, issuer);
    let discovery = response_json(
        http.request(
            Method::GET,
            &format!("{authorization_server}/.well-known/openid-configuration"),
        )
        .await
        .expect("AS discovery"),
    );
    let registration = response_json(http.request_with_headers(Method::POST, discovery["registration_endpoint"].as_str().expect("registration URL"),
        HeaderMap::from_iter([(header::CONTENT_TYPE, HeaderValue::from_static("application/json"))]),
        Some(serde_json::to_vec(&json!({"client_name": "issue373-client", "redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none"})).expect("registration JSON")))
        .await.expect("registration"));
    let client_id = registration["client_id"].as_str().expect("client ID");
    let code_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let mut authorize_url = url::Url::parse(
        discovery["authorization_endpoint"]
            .as_str()
            .expect("authorize URL"),
    )
    .expect("authorize URL should parse");
    authorize_url.query_pairs_mut().extend_pairs([
        ("client_id", client_id),
        ("redirect_uri", redirect_uri),
        ("response_type", "code"),
        ("resource", resource),
        ("scope", "mcp:tools"),
        ("state", "issue373-state"),
        ("code_challenge_method", "S256"),
        ("code_challenge", code_challenge.as_str()),
    ]);
    let authorize = http
        .request(Method::GET, authorize_url.as_str())
        .await
        .expect("authorize");
    assert!(authorize.status.is_redirection());
    let callback = url::Url::parse(
        authorize.headers[header::LOCATION]
            .to_str()
            .expect("callback"),
    )
    .expect("callback URL");
    let params: HashMap<_, _> = callback.query_pairs().into_owned().collect();
    assert_eq!(params["state"], "issue373-state");
    let form = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs([
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("redirect_uri", redirect_uri),
            ("resource", resource),
            ("code", params["code"].as_str()),
            ("code_verifier", verifier),
        ])
        .finish();
    let tokens = response_json(
        http.request_with_headers(
            Method::POST,
            discovery["token_endpoint"].as_str().expect("token URL"),
            HeaderMap::from_iter([(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded"),
            )]),
            Some(form.into_bytes()),
        )
        .await
        .expect("token exchange"),
    );
    let transport = StreamableHttpClientTransport::from_config(
        StreamableHttpClientTransportConfig::with_uri(format!("{gateway_url}/mcp")).auth_header(
            tokens["access_token"]
                .as_str()
                .expect("access token")
                .to_owned(),
        ),
    );
    let client = ().serve(transport).await.expect("real MCP client should initialize after OAuth");
    assert_eq!(stage.load(Ordering::SeqCst), 3);
    client.cancel().await.expect("client shutdown");
    gateway_server.abort();
    as_server.abort();
}

fn response_json(response: egress::EgressResponse) -> Value {
    assert!(
        response.status.is_success(),
        "HTTP status: {}",
        response.status
    );
    serde_json::from_slice(&response.body).expect("response JSON")
}
