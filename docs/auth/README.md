# Auth Provider Recipes

These recipes show copy-pasteable `AUTH_PROVIDERS` examples for common OIDC identity providers:

- [Keycloak](keycloak.md)
- [Auth0](auth0.md)
- [Microsoft Entra ID](entra-id.md)
- [Okta](okta.md)

Use these alongside the raw field reference in [docs/configuration.md](../configuration.md). Each recipe uses OIDC discovery by setting `issuer` and leaving `jwks_url` unset.

The JSON examples in this directory are regression-tested by `auth_provider_doc_examples_parse_as_configured_providers` in `gateway/src/config.rs`. That test reads the marked Markdown examples and parses each one through `Config::from_env_vars`, then asserts the resulting `AuthProviderConfig` values. These examples were not validated against live or containerized IdP instances in this environment.
