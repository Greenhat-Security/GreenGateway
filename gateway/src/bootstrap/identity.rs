//! Identity at startup: the authentication validator chain, OIDC
//! discovery and the egress hosts it seeds, and the admin login and
//! session state.
use super::*;

pub(crate) fn auth_validator_from_config(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
    service_token_validator: Option<Arc<auth::ServiceTokenValidator>>,
    discovered_oidc_jwks_urls: &HashMap<String, String>,
    jwt_revocation: Option<JwtRevocationStoreFactory<'_>>,
    revoked_credentials: Option<Arc<dyn auth::RevokedCredentialObserver>>,
    lifecycle: Option<&GatewayLifecycle>,
) -> Result<Option<Arc<dyn auth::SessionValidator>>, auth::AuthError> {
    let client_certificate_auth = config.client_certificate_auth_enabled();
    if config.auth_providers.is_empty()
        && service_token_validator.is_none()
        && !client_certificate_auth
    {
        return Ok(None);
    }

    let mut validators = Vec::with_capacity(
        config.auth_providers.len()
            + usize::from(service_token_validator.is_some())
            + usize::from(client_certificate_auth),
    );
    if let Some(service_token_validator) = service_token_validator {
        validators.push(service_token_validator as Arc<dyn auth::SessionValidator>);
    }
    if client_certificate_auth {
        // Position in the chain is not a precedence decision. Every validator
        // is offered every credential and each rejects the kinds it does not
        // own, so the certificate validator sits first only because it is the
        // cheapest rejection: it does no work at all on a credential that is
        // not a certificate, and it never returns `AuthError::Upstream`, so it
        // cannot turn another provider's 401 into a 503.
        validators
            .push(Arc::new(auth::ClientCertificateValidator) as Arc<dyn auth::SessionValidator>);
    }
    for provider in &config.auth_providers {
        match provider.provider_type {
            config::AuthProviderType::Jwt => {
                let jwks_url = match provider.jwks_url.clone() {
                    Some(jwks_url) => jwks_url,
                    None => {
                        let issuer = provider.issuer.as_deref().ok_or_else(|| {
                            auth::AuthError::Upstream(format!(
                                "JWT auth provider '{}' is missing jwks_url and issuer",
                                provider.name
                            ))
                        })?;
                        discovered_oidc_jwks_urls
                            .get(&provider.name)
                            .cloned()
                            .ok_or_else(|| {
                                auth::AuthError::Upstream(format!(
                                    "JWT auth provider '{}' is missing discovered jwks_uri for issuer '{issuer}'",
                                    provider.name
                                ))
                            })?
                    }
                };
                let jwt_config = auth::JwtAuthConfig::from_provider_config(provider, jwks_url);
                let validator = match jwt_revocation {
                    Some(factory) => {
                        // The denylist is keyed by exactly the issuer the
                        // validator will stamp on its principals.
                        let boundary = auth::JwtValidator::provider_principal_issuer(
                            &jwt_config,
                            &provider.name,
                        )?;
                        let validator = auth::JwtValidator::new_for_provider_with_revocation(
                            jwt_config,
                            &provider.name,
                            Arc::clone(&egress_client),
                            factory(&boundary),
                        )?;
                        // Only a denylist can refuse a token as revoked, so
                        // only a validator with one has anything to report.
                        match revoked_credentials.as_ref() {
                            Some(observer) => {
                                validator.with_revoked_credential_observer(Arc::clone(observer))
                            }
                            None => validator,
                        }
                    }
                    None => auth::JwtValidator::new_for_provider(
                        jwt_config,
                        &provider.name,
                        Arc::clone(&egress_client),
                    )?,
                };
                let validator = Arc::new(validator);
                // Keys are refreshed on a schedule, not only on a kid miss,
                // so a withdrawn signing key disappears promptly.
                if let Some(lifecycle) = lifecycle {
                    validator.spawn_background_refresh(lifecycle);
                }
                validators.push(validator as Arc<dyn auth::SessionValidator>);
            }
            config::AuthProviderType::CookieSession => {
                let cookie_config = auth::CookieSessionAuthConfig::from_provider_config(provider)?;
                validators.push(Arc::new(auth::CookieSessionValidator::new_for_provider(
                    cookie_config,
                    &provider.name,
                    Arc::clone(&egress_client),
                )?) as Arc<dyn auth::SessionValidator>);
            }
        }
    }

    Ok(Some(
        Arc::new(auth::ChainValidator::new(validators)) as Arc<dyn auth::SessionValidator>
    ))
}

/// The session store `config` selects. Cluster mode's store rides the
/// pending-login seed (the pool, the deployment ID and the login keyring
/// its access tokens are sealed under); without it there is no store, and
/// startup fails rather than fall back to process memory.
pub(crate) fn admin_session_store(
    config: &auth::admin_session::AdminSessionConfig,
    cluster_store: Option<Arc<dyn auth::admin_session::AdminSessionStore>>,
) -> Result<Arc<dyn auth::admin_session::AdminSessionStore>, auth::AuthError> {
    match config.storage {
        auth::admin_session::AdminSessionStorage::StandaloneMemory => Ok(Arc::new(
            auth::admin_session::MemoryAdminSessionStore::new(config.clone()),
        )),
        auth::admin_session::AdminSessionStorage::ClusterPostgres => cluster_store.ok_or_else(|| {
            auth::AuthError::Upstream(
                "ADMIN_SESSION_MODE=cluster_postgres requires the PostgreSQL session store and ADMIN_LOGIN_KEYRING"
                    .to_owned(),
            )
        }),
    }
}

pub(crate) fn admin_auth_state_from_config(
    config: &config::Config,
    audit: audit::AuditLog,
    discovered_oidc: &DiscoveredOidcConfig,
    egress_client: Arc<egress::EgressClient>,
    pending_login_backend: Option<Arc<dyn auth::oidc_login::PendingLoginBackend>>,
    lifecycle: Option<&GatewayLifecycle>,
) -> Result<Option<AdminAuthState>, auth::AuthError> {
    let Some(admin_login_provider) = config.admin_login_provider.as_deref() else {
        return Ok(None);
    };
    let provider = config
        .auth_providers
        .iter()
        .find(|provider| provider.name == admin_login_provider)
        .ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "ADMIN_LOGIN_PROVIDER references unknown auth provider '{admin_login_provider}'"
            ))
        })?;
    let endpoints = discovered_oidc
        .admin_login
        .as_ref()
        .filter(|endpoints| endpoints.provider_name == provider.name)
        .ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "ADMIN_LOGIN_PROVIDER '{}' is missing discovered OIDC login endpoints",
                provider.name
            ))
        })?;

    let login_config = auth::OidcLoginConfig {
        client_id: required_admin_login_provider_field(provider, "client_id", &provider.client_id)?,
        client_secret: required_admin_login_provider_field(
            provider,
            "client_secret",
            &provider.client_secret,
        )?,
        redirect_uri: required_admin_login_provider_field(
            provider,
            "redirect_uri",
            &provider.redirect_uri,
        )?,
        issuer: endpoints.issuer.clone(),
        jwks_url: endpoints.jwks_url.clone(),
        authorization_endpoint: endpoints.authorization_endpoint.clone(),
        token_endpoint: endpoints.token_endpoint.clone(),
        http_timeout: Duration::from_millis(provider.jwks_timeout_ms),
        jwks_max_key_age: Duration::from_secs(provider.jwks_max_key_age_secs),
    };

    let pending_limits = auth::PendingLoginLimits {
        ttl: Duration::from_secs(config.admin_login_pending_ttl_secs),
        max_entries: config.admin_login_pending_max_entries,
        max_per_ip: config.admin_login_pending_max_per_ip,
    };
    // Cluster mode consumes the login on whichever replica the callback
    // lands; standalone mode keeps the process-local store.
    let login = match pending_login_backend {
        Some(backend) => {
            auth::OidcLoginState::new_with_backend(login_config, egress_client, backend)?
        }
        None => auth::OidcLoginState::new(login_config, egress_client, pending_limits)?,
    };
    // The ID-token validator refreshes its JWKS on the same schedule as the
    // bearer validators, so a retired signing key stops being accepted at
    // the half-age refresh rather than only at the cache's maximum age.
    if let Some(lifecycle) = lifecycle {
        login.spawn_background_refresh(lifecycle);
    }

    Ok(Some(AdminAuthState {
        login,
        sessions: None,
        csrf: middleware::csrf::CsrfConfig::from_config(config),
        audit,
        admin_prefix: config.admin_prefix.clone(),
        cookie_max_age: config.admin_login_pending_ttl_secs,
        client_ip_policy: client_ip::ClientIpPolicy::from_config(config),
    }))
}

pub(crate) fn required_admin_login_provider_field(
    provider: &config::AuthProviderConfig,
    field_name: &str,
    value: &Option<String>,
) -> Result<String, auth::AuthError> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "admin login provider '{}' is missing {field_name}",
                provider.name
            ))
        })
}

pub(crate) fn discover_oidc_from_config(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
) -> Result<DiscoveredOidcConfig, auth::AuthError> {
    let mut discovered = DiscoveredOidcConfig::default();

    for provider in &config.auth_providers {
        if provider.provider_type != config::AuthProviderType::Jwt {
            continue;
        }
        let is_admin_login_provider = config
            .admin_login_provider
            .as_deref()
            .is_some_and(|name| name == provider.name);
        if provider.jwks_url.is_some() && !is_admin_login_provider {
            continue;
        }

        let issuer = provider.issuer.as_deref().ok_or_else(|| {
            auth::AuthError::Upstream(format!(
                "JWT auth provider '{}' is missing jwks_url and issuer",
                provider.name
            ))
        })?;
        if !is_admin_login_provider {
            let jwks_url = auth::oidc::discover_jwks_uri_blocking(
                issuer,
                Duration::from_millis(provider.jwks_timeout_ms),
                Arc::clone(&egress_client),
            )?;
            discovered.jwks_urls.insert(provider.name.clone(), jwks_url);
            continue;
        }

        let document = auth::oidc::discover_document_blocking(
            issuer,
            Duration::from_millis(provider.jwks_timeout_ms),
            Arc::clone(&egress_client),
        )?;
        let issuer = document
            .issuer()
            .and_then(auth::oidc::normalize_issuer)
            .ok_or_else(|| {
                auth::AuthError::Upstream("OIDC discovery response missing issuer".to_owned())
            })?;

        let jwks_url = match provider.jwks_url.clone() {
            Some(jwks_url) => jwks_url,
            None => {
                let jwks_url = document.jwks_uri().ok_or_else(|| {
                    auth::AuthError::Upstream("OIDC discovery response missing jwks_uri".to_owned())
                })?;
                discovered
                    .jwks_urls
                    .insert(provider.name.clone(), jwks_url.clone());
                jwks_url
            }
        };

        let authorization_endpoint = document.authorization_endpoint().ok_or_else(|| {
            auth::AuthError::Upstream(
                "OIDC discovery response missing authorization_endpoint".to_owned(),
            )
        })?;
        let token_endpoint = document.token_endpoint().ok_or_else(|| {
            auth::AuthError::Upstream("OIDC discovery response missing token_endpoint".to_owned())
        })?;
        auth::oidc::validate_login_transports(
            &issuer,
            [&jwks_url, &authorization_endpoint, &token_endpoint],
        )?;
        discovered.admin_login = Some(DiscoveredAdminLoginEndpoints {
            provider_name: provider.name.clone(),
            issuer,
            jwks_url,
            authorization_endpoint,
            token_endpoint,
        });
    }

    if let Some(admin_login_provider) = config.admin_login_provider.as_deref() {
        if discovered.admin_login.is_none() {
            return Err(auth::AuthError::Upstream(format!(
                "ADMIN_LOGIN_PROVIDER '{admin_login_provider}' could not be resolved through OIDC discovery"
            )));
        }
    }

    Ok(discovered)
}

#[cfg(test)]
pub(crate) fn discover_oidc_jwks_urls_from_config(
    config: &config::Config,
    egress_client: Arc<egress::EgressClient>,
) -> Result<HashMap<String, String>, auth::AuthError> {
    discover_oidc_from_config(config, egress_client).map(|discovered| discovered.jwks_urls)
}

pub(crate) fn auto_seed_discovered_oidc_hosts(
    egress_config: &mut egress::EgressConfig,
    discovered_oidc: &DiscoveredOidcConfig,
) {
    let mut auto_seeded_hosts = discovered_oidc
        .jwks_urls
        .values()
        .filter_map(|jwks_url| egress_config.auto_seed_endpoint_host(jwks_url))
        .collect::<Vec<_>>();
    if let Some(admin_login) = &discovered_oidc.admin_login {
        if let Some(host) = egress_config.auto_seed_endpoint_host(&admin_login.token_endpoint) {
            auto_seeded_hosts.push(host);
        }
    }

    if !auto_seeded_hosts.is_empty() {
        tracing::debug!(
            hosts = ?auto_seeded_hosts,
            "auto-seeded egress allowlist from discovered OIDC endpoints"
        );
    }
}
