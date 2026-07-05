use std::{sync::Arc, time::Duration};

use http::Method;
use serde::Deserialize;
use tokio::time::timeout;

use crate::egress::EgressClient;

use super::AuthError;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct DiscoveryDocument {
    jwks_uri: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
}

impl DiscoveryDocument {
    pub(crate) fn jwks_uri(&self) -> Option<String> {
        normalize_discovery_endpoint(self.jwks_uri.as_deref())
    }

    pub(crate) fn authorization_endpoint(&self) -> Option<String> {
        normalize_discovery_endpoint(self.authorization_endpoint.as_deref())
    }

    pub(crate) fn token_endpoint(&self) -> Option<String> {
        normalize_discovery_endpoint(self.token_endpoint.as_deref())
    }
}

pub(crate) async fn discover_jwks_uri(
    issuer: &str,
    http_timeout: Duration,
    egress_client: &EgressClient,
) -> Result<String, AuthError> {
    let document = discover_document(issuer, http_timeout, egress_client).await?;

    document
        .jwks_uri()
        .ok_or_else(|| AuthError::Upstream("OIDC discovery response missing jwks_uri".to_owned()))
}

pub(crate) async fn discover_document(
    issuer: &str,
    http_timeout: Duration,
    egress_client: &EgressClient,
) -> Result<DiscoveryDocument, AuthError> {
    let issuer = issuer.trim().trim_end_matches('/');
    if issuer.is_empty() {
        return Err(AuthError::Upstream(
            "OIDC discovery issuer must be non-empty".to_owned(),
        ));
    }

    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let response = timeout(
        http_timeout,
        egress_client.request(Method::GET, &discovery_url),
    )
    .await
    .map_err(|_| AuthError::Upstream("OIDC discovery fetch failed".to_owned()))?
    .map_err(|err| {
        tracing::warn!(error = %err, "OIDC discovery fetch through egress failed");
        AuthError::Upstream("OIDC discovery fetch failed".to_owned())
    })?;

    if !response.status.is_success() {
        return Err(AuthError::Upstream(
            "OIDC discovery fetch failed".to_owned(),
        ));
    }

    serde_json::from_slice::<DiscoveryDocument>(&response.body)
        .map_err(|_| AuthError::Upstream("invalid OIDC discovery response".to_owned()))
}

pub(crate) fn discover_jwks_uri_blocking(
    issuer: &str,
    http_timeout: Duration,
    egress_client: Arc<EgressClient>,
) -> Result<String, AuthError> {
    let issuer = issuer.to_owned();
    let worker = std::thread::Builder::new()
        .name("oidc-discovery".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| {
                    AuthError::Upstream(format!("OIDC discovery runtime failed: {err}"))
                })?;

            runtime.block_on(discover_jwks_uri(
                &issuer,
                http_timeout,
                egress_client.as_ref(),
            ))
        })
        .map_err(|err| AuthError::Upstream(format!("OIDC discovery worker failed: {err}")))?;

    worker
        .join()
        .map_err(|_| AuthError::Upstream("OIDC discovery worker panicked".to_owned()))?
}

pub(crate) fn discover_document_blocking(
    issuer: &str,
    http_timeout: Duration,
    egress_client: Arc<EgressClient>,
) -> Result<DiscoveryDocument, AuthError> {
    let issuer = issuer.to_owned();
    let worker = std::thread::Builder::new()
        .name("oidc-discovery".to_owned())
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|err| {
                    AuthError::Upstream(format!("OIDC discovery runtime failed: {err}"))
                })?;

            runtime.block_on(discover_document(
                &issuer,
                http_timeout,
                egress_client.as_ref(),
            ))
        })
        .map_err(|err| AuthError::Upstream(format!("OIDC discovery worker failed: {err}")))?;

    worker
        .join()
        .map_err(|_| AuthError::Upstream("OIDC discovery worker panicked".to_owned()))?
}

fn normalize_discovery_endpoint(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}
