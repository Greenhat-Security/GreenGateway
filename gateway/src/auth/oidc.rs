use std::{sync::Arc, time::Duration};

use http::Method;
use serde::Deserialize;
use tokio::time::timeout;

use crate::egress::EgressClient;

use super::{principal::canonical_issuer, AuthError};

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct DiscoveryDocument {
    issuer: Option<String>,
    jwks_uri: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
}

impl DiscoveryDocument {
    pub(crate) fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

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
    let issuer = normalize_required_issuer(issuer)?;

    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let response = timeout(
        http_timeout,
        egress_client.request(Method::GET, &discovery_url),
    )
    .await
    .map_err(|_| AuthError::Upstream("OIDC discovery fetch failed".to_owned()))?
    .map_err(|err| {
        tracing::warn!(
            error_category = err.safe_category(),
            "OIDC discovery fetch through egress failed"
        );
        AuthError::Upstream("OIDC discovery fetch failed".to_owned())
    })?;

    if !response.status.is_success() {
        return Err(AuthError::Upstream(
            "OIDC discovery fetch failed".to_owned(),
        ));
    }

    let document = serde_json::from_slice::<DiscoveryDocument>(&response.body)
        .map_err(|_| AuthError::Upstream("invalid OIDC discovery response".to_owned()))?;
    validate_discovery_issuer(&document, &issuer)?;

    Ok(document)
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

pub(crate) fn normalize_issuer(issuer: &str) -> Option<String> {
    canonical_issuer(issuer)
}

pub(crate) fn normalize_required_issuer(issuer: &str) -> Result<String, AuthError> {
    normalize_issuer(issuer)
        .ok_or_else(|| AuthError::Upstream("OIDC discovery issuer must be non-empty".to_owned()))
}

fn validate_discovery_issuer(
    document: &DiscoveryDocument,
    expected_issuer: &str,
) -> Result<(), AuthError> {
    match document.issuer() {
        Some(document_issuer) => {
            let expected_issuer = normalize_required_issuer(expected_issuer)?;
            let document_issuer_normalized =
                normalize_issuer(document_issuer).ok_or_else(|| {
                    AuthError::Upstream("OIDC discovery response missing issuer".to_owned())
                })?;
            if document_issuer_normalized == expected_issuer {
                Ok(())
            } else {
                Err(AuthError::Upstream(format!(
                    "OIDC discovery issuer mismatch: expected '{expected_issuer}', got '{document_issuer}'"
                )))
            }
        }
        None => Err(AuthError::Upstream(
            "OIDC discovery response missing issuer".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{io, sync::Mutex};

    use tracing_subscriber::fmt::MakeWriter;

    use super::*;
    use crate::egress::EgressConfig;

    #[tokio::test(flavor = "current_thread")]
    async fn discovery_egress_failures_log_only_bounded_categories() {
        let logs = CapturedLogs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(logs.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let client = EgressClient::new(EgressConfig::default())
            .expect("OIDC test egress client should build");

        let error = discover_document(
            "https://secret-issuer.example/private?token=secret-query",
            Duration::from_millis(100),
            &client,
        )
        .await
        .expect_err("non-allowlisted discovery host should fail");
        drop(_guard);

        assert_eq!(
            error.to_string(),
            "upstream identity service error: OIDC discovery fetch failed"
        );
        let output = logs.contents();
        assert!(output.contains("host_not_allowed"));
        for secret in ["secret-issuer", "private", "secret-query", "https://"] {
            assert!(
                !output.contains(secret),
                "OIDC egress log leaked {secret}: {output}"
            );
        }
    }

    #[derive(Clone, Default)]
    struct CapturedLogs {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedLogs {
        fn contents(&self) -> String {
            String::from_utf8(
                self.buffer
                    .lock()
                    .expect("captured logs should not be poisoned")
                    .clone(),
            )
            .expect("captured logs should be UTF-8")
        }
    }

    impl<'a> MakeWriter<'a> for CapturedLogs {
        type Writer = CapturedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogWriter {
                buffer: Arc::clone(&self.buffer),
            }
        }
    }

    struct CapturedLogWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl io::Write for CapturedLogWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.buffer
                .lock()
                .map_err(|_| io::Error::other("captured logs lock poisoned"))?
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}
