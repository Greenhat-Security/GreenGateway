use serde::Serialize;
use url::Url;

use crate::config::{AuthProviderType, Config};

use super::oidc;

pub(crate) const MCP_RESOURCE_PATH: &str = "/mcp";
pub(crate) const WELL_KNOWN_PATH: &str = "/.well-known/oauth-protected-resource";
pub(crate) const WELL_KNOWN_SUFFIX_ROUTE: &str =
    "/.well-known/oauth-protected-resource/{*resource_path}";

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
        public_url_with_appended_path(&self.public_url, MCP_RESOURCE_PATH)
    }

    pub(crate) fn mcp_resource_path(&self) -> String {
        Url::parse(&self.mcp_resource())
            .expect("MCP resource URL should parse")
            .path()
            .to_owned()
    }

    pub(crate) fn metadata_url(&self) -> String {
        public_url_with_path(&self.mcp_resource(), WELL_KNOWN_PATH)
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

pub(crate) fn mcp_route_paths(config: &Config) -> Vec<String> {
    let mut paths = vec![MCP_RESOURCE_PATH.to_owned()];
    if let Some(metadata) = ProtectedResourceMetadataConfig::from_config(config) {
        paths.push(metadata.mcp_resource_path());
    }
    paths.sort();
    paths.dedup();
    paths
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

    let mut url = Url::parse(public_url).expect("GATEWAY_PUBLIC_URL should have been validated");
    let resource_path = url.path().trim_end_matches('/');
    let metadata_path = if resource_path.is_empty() {
        path.to_owned()
    } else {
        format!("{path}{resource_path}")
    };

    url.set_path(&metadata_path);
    url.to_string()
}

fn public_url_with_appended_path(public_url: &str, path: &str) -> String {
    debug_assert!(path.starts_with('/'));

    let mut url = Url::parse(public_url).expect("GATEWAY_PUBLIC_URL should have been validated");
    let base_path = url.path().trim_end_matches('/');
    let resource_path = if base_path.is_empty() {
        path.to_owned()
    } else {
        format!("{base_path}{path}")
    };

    url.set_path(&resource_path);
    url.to_string()
}

pub(crate) fn is_well_known_path(path: &str) -> bool {
    path == WELL_KNOWN_PATH
        || path
            .strip_prefix(WELL_KNOWN_PATH)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_url_uses_mcp_resource_path_for_public_url_path() {
        let metadata = ProtectedResourceMetadataConfig {
            public_url: "https://gateway.example.test/base".to_owned(),
            authorization_servers: Vec::new(),
        };

        assert_eq!(
            metadata.mcp_resource(),
            "https://gateway.example.test/base/mcp"
        );
        assert_eq!(
            metadata.metadata_url(),
            "https://gateway.example.test/.well-known/oauth-protected-resource/base/mcp"
        );
        assert_metadata_suffix_matches_resource_path(&metadata);
    }

    #[test]
    fn metadata_url_trims_public_url_path_trailing_slash_to_match_mcp_resource() {
        let metadata = ProtectedResourceMetadataConfig {
            public_url: "https://gateway.example.test/base/".to_owned(),
            authorization_servers: Vec::new(),
        };

        assert_eq!(
            metadata.mcp_resource(),
            "https://gateway.example.test/base/mcp"
        );
        assert_eq!(
            metadata.metadata_url(),
            "https://gateway.example.test/.well-known/oauth-protected-resource/base/mcp"
        );
        assert_metadata_suffix_matches_resource_path(&metadata);
    }

    #[test]
    fn metadata_url_uses_mcp_resource_path_for_bare_origin() {
        let metadata = ProtectedResourceMetadataConfig {
            public_url: "https://gateway.example.test".to_owned(),
            authorization_servers: Vec::new(),
        };

        assert_eq!(metadata.mcp_resource(), "https://gateway.example.test/mcp");
        assert_eq!(
            metadata.metadata_url(),
            "https://gateway.example.test/.well-known/oauth-protected-resource/mcp"
        );
        assert_metadata_suffix_matches_resource_path(&metadata);
    }

    fn assert_metadata_suffix_matches_resource_path(metadata: &ProtectedResourceMetadataConfig) {
        let resource = Url::parse(&metadata.mcp_resource()).expect("resource URL should parse");
        let metadata_url = Url::parse(&metadata.metadata_url()).expect("metadata URL should parse");

        assert_eq!(
            metadata_url.path().strip_prefix(WELL_KNOWN_PATH),
            Some(resource.path())
        );
    }
}
