//! HTTPS receiver for the two-process approved mutation test.

use std::{
    convert::Infallible,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, Response},
};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_rustls::{
    rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig},
    TlsAcceptor,
};

struct Captured {
    method: Method,
    path: String,
    assertion: String,
    body: Vec<u8>,
}

pub(super) struct MutationUpstream {
    addr: SocketAddr,
    ca_pem: String,
    accepted: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Captured>>>,
    listener: tokio::task::JoinHandle<()>,
}

impl Drop for MutationUpstream {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

impl MutationUpstream {
    pub(super) async fn start() -> Self {
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let mut leaf_params = rcgen::CertificateParams::default();
        leaf_params.distinguished_name = rcgen::DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mutation receiver");
        leaf_params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = leaf_params
            .signed_by(&leaf_key, &rcgen::Issuer::from_params(&ca_params, &ca_key))
            .unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let socket = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let server_count = Arc::clone(&accepted);
        let server_requests = Arc::clone(&requests);
        let listener = tokio::spawn(async move {
            while let Ok((stream, _)) = socket.accept().await {
                server_count.fetch_add(1, Ordering::SeqCst);
                let acceptor = acceptor.clone();
                let requests = Arc::clone(&server_requests);
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(|request: Request<Incoming>| {
                        let requests = Arc::clone(&requests);
                        async move {
                            let (parts, body) = request.into_parts();
                            assert_eq!(
                                parts
                                    .headers
                                    .get_all("x-ha-mutation-assertion")
                                    .iter()
                                    .count(),
                                1
                            );
                            let assertion = parts.headers["x-ha-mutation-assertion"]
                                .to_str()
                                .unwrap()
                                .to_owned();
                            assert!(!parts.headers.contains_key("authorization"));
                            assert!(!parts.headers.contains_key("cookie"));
                            let body = to_bytes(Body::new(body), 4096).await.unwrap().to_vec();
                            requests.lock().unwrap().push(Captured {
                                method: parts.method,
                                path: parts.uri.to_string(),
                                body,
                                assertion,
                            });
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .header("content-type", "application/json")
                                    .body(Body::from("{}"))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            addr,
            ca_pem: ca.pem(),
            accepted,
            requests,
            listener,
        }
    }

    pub(super) fn base_url(&self) -> String {
        format!("https://{}", self.addr)
    }

    pub(super) fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub(super) fn accepted_connections(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    pub(super) fn assert_one_verified_request(
        &self,
        jwks: &Value,
        approval_id: &str,
        expected_issuer: &str,
        expected_audience: &str,
        expected_caller_issuer: &str,
        expected_caller_subject: &str,
    ) {
        assert_eq!(self.accepted_connections(), 1);
        let captured = self.requests.lock().unwrap();
        let [request] = captured.as_slice() else {
            panic!("expected one request, received {}", captured.len());
        };
        assert_eq!(request.method, Method::POST);
        assert_eq!(request.path, "/v1/widgets");
        assert_eq!(request.body, br#"{"name":"approved change"}"#);
        let header = decode_header(&request.assertion).unwrap();
        assert_eq!(header.typ.as_deref(), Some("at+jwt"));
        let keys: JwkSet = serde_json::from_value(jwks.clone()).unwrap();
        let key = keys.find(&header.kid.unwrap()).unwrap();
        assert_eq!(
            key.common.key_algorithm,
            Some(jsonwebtoken::jwk::KeyAlgorithm::ES256)
        );
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[expected_issuer]);
        validation.set_audience(&[expected_audience]);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.leeway = 0;
        let claims = decode::<Value>(
            &request.assertion,
            &DecodingKey::from_jwk(key).unwrap(),
            &validation,
        )
        .expect("the published key must verify the assertion")
        .claims;
        assert_eq!(claims["approval_id"], approval_id);
        assert_eq!(claims["caller_iss"], expected_caller_issuer);
        assert_eq!(claims["caller_sub"], expected_caller_subject);
        assert_eq!(
            claims["sub"],
            format!("{expected_caller_issuer}#{expected_caller_subject}")
        );
        assert_eq!(claims["method"], request.method.as_str());
        assert_eq!(claims["path"], request.path);
        assert_eq!(
            claims["request_sha256"],
            hex::encode(Sha256::digest(&request.body))
        );
        let target = format!("{}{}", self.base_url(), request.path);
        assert_eq!(
            claims["target_sha256"],
            hex::encode(Sha256::digest(target.as_bytes()))
        );
    }
}
