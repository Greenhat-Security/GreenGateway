use std::{sync::Arc, time::Duration};

use http::Method;
use serde::Deserialize;
use tokio::time::timeout;

use crate::egress::EgressClient;

use super::AuthError;

#[derive(Deserialize)]
struct DiscoveryDocument {
    jwks_uri: Option<String>,
}

pub(crate) async fn discover_jwks_uri(
    issuer: &str,
    http_timeout: Duration,
    egress_client: &EgressClient,
) -> Result<String, AuthError> {
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

    let document = serde_json::from_slice::<DiscoveryDocument>(&response.body)
        .map_err(|_| AuthError::Upstream("invalid OIDC discovery response".to_owned()))?;

    document
        .jwks_uri
        .map(|jwks_uri| jwks_uri.trim().to_owned())
        .filter(|jwks_uri| !jwks_uri.is_empty())
        .ok_or_else(|| AuthError::Upstream("OIDC discovery response missing jwks_uri".to_owned()))
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
