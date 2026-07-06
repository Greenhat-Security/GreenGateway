use serde::Serialize;

use crate::config::{AuthProviderType, Config};

use super::oidc;

pub(crate) const MCP_RESOURCE_PATH: &str = "/mcp";
pub(crate) const WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";

pub(crate) const MCP_SCOPE: &str = "mcp:tools";
const BEARER_METHOD: &str = "header";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProtectedResourceMetadataConfig {
    public_url: String,
    authorization_servers: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct ProtectedResourceMetadataDocument {
    resource: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    authorization_servers: Vec<String>,
    scopes_supported: Vec<&'static str>,
    bearer_methods_supported: Vec<&'static str>,
}

impl ProtectedResourceMetadataConfig {
    pub(crate) fn from_config(config: &Config) -> Option<Self> {
        let public_url = config.gateway_public_url.clone()?;

        Some(Self {
            public_url,
            authorization_servers: authorization_servers(config),
        })
    }

    pub(crate) fn mcp_resource(&self) -> String {
        public_url_with_path(&self.public_url, MCP_RESOURCE_PATH)
    }

    pub(crate) fn metadata_url(&self) -> String {
        public_url_with_path(&self.public_url, WELL_KNOWN_PATH)
    }

    pub(crate) fn document(&self) -> ProtectedResourceMetadataDocument {
        ProtectedResourceMetadataDocument {
            resource: self.mcp_resource(),
            authorization_servers: self.authorization_servers.clone(),
            scopes_supported: vec![MCP_SCOPE],
            bearer_methods_supported: vec![BEARER_METHOD],
        }
    }
}

fn authorization_servers(config: &Config) -> Vec<String> {
    let mut issuers = Vec::new();

    for provider in &config.auth_providers {
        if provider.provider_type != AuthProviderType::Jwt {
            continue;
        }

        let Some(issuer) = provider.issuer.as_deref().and_then(oidc::normalize_issuer) else {
            continue;
        };

        if !issuers.iter().any(|existing| existing == &issuer) {
            issuers.push(issuer);
        }
    }

    issuers
}

fn public_url_with_path(public_url: &str, path: &str) -> String {
    debug_assert!(path.starts_with('/'));
    format!("{}{}", public_url.trim_end_matches('/'), path)
}
