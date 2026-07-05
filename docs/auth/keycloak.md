# Keycloak Auth Provider Recipe

This recipe configures GreenGateway to validate JWTs issued by a Keycloak realm using OIDC discovery.

The examples below are parsed by the `auth_provider_doc_examples_parse_as_configured_providers` config test. They were not validated against a live or containerized Keycloak instance in this environment.

## Issuer URL

Use the realm issuer URL:

```text
https://keycloak.example.com/realms/acme
```

Replace `https://keycloak.example.com` with your Keycloak base URL and `acme` with the realm name. GreenGateway appends `/.well-known/openid-configuration` to the issuer for discovery.

## Realm Roles

Keycloak realm roles are emitted under a top-level `realm_access` object with a `roles` array. Use `roles_claim: "realm_access.roles"`.

<!-- auth-providers-example: keycloak-realm -->
```json
[
  {
    "name": "keycloak",
    "type": "jwt",
    "issuer": "https://keycloak.example.com/realms/acme",
    "audience": "greengateway-api",
    "roles_claim": "realm_access.roles"
  }
]
```

Set this value as `AUTH_PROVIDERS`. For example, in a shell:

```sh
AUTH_PROVIDERS='[{"name":"keycloak","type":"jwt","issuer":"https://keycloak.example.com/realms/acme","audience":"greengateway-api","roles_claim":"realm_access.roles"}]'
```

## Client Roles

If your deployment authorizes by Keycloak client roles instead of realm roles, Keycloak emits those under `resource_access.{client-id}.roles`. For a Keycloak client ID of `greengateway-api`, use:

<!-- auth-providers-example: keycloak-client-roles -->
```json
[
  {
    "name": "keycloak-client-roles",
    "type": "jwt",
    "issuer": "https://keycloak.example.com/realms/acme",
    "audience": "greengateway-api",
    "roles_claim": "resource_access.greengateway-api.roles"
  }
]
```

GreenGateway treats dotted claim names as nested paths only after checking for an exact top-level claim key. If your Keycloak client ID itself contains dots, prefer a Keycloak protocol mapper that emits a simple string-array claim such as `roles`.

## Scope String Alternative

If an OAuth2-style token carries authorization values in a space-delimited `scope` string, GreenGateway can split it with `roles_claim_delimiter`. This is a secondary pattern, not Keycloak's default role shape.

<!-- auth-providers-example: keycloak-scope -->
```json
[
  {
    "name": "keycloak-scope",
    "type": "jwt",
    "issuer": "https://keycloak.example.com/realms/acme",
    "audience": "greengateway-api",
    "roles_claim": "scope",
    "roles_claim_delimiter": " "
  }
]
```

## Organization Claim

Keycloak's realm model often maps tenancy to the issuer itself rather than to one token claim. Do not force `org_claim` unless your realm adds a real string claim for tenant identity, such as a custom mapper that emits `tenant_id`.

## Verifying It Works

Start GreenGateway with the configured `AUTH_PROVIDERS`. A discovery failure, missing `jwks_uri`, or unreachable issuer prevents the provider from being constructed during startup. There is no dedicated successful-discovery log line today.

Then call a protected gateway route with a real Keycloak access token:

```sh
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/your/protected/path
```

`401 Unauthorized` means the token was not accepted by authentication. `403 Forbidden` means authentication succeeded but RBAC denied the principal. A `200` or upstream response means the token validated and policy allowed the request.

## References

- Keycloak OIDC discovery endpoint: https://www.keycloak.org/securing-apps/oidc-layers
- Keycloak realm and client role token claims: https://www.keycloak.org/docs/latest/server_admin/index.html#role-mappings-in-the-token
