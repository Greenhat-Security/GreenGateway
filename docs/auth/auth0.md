# Auth0 Auth Provider Recipe

This recipe configures GreenGateway to validate JWTs issued by Auth0 using OIDC discovery.

The examples below are parsed by the `auth_provider_doc_examples_parse_as_configured_providers` config test. They were not validated against a live Auth0 tenant in this environment.

## Issuer URL

Use your Auth0 issuer URL, including the trailing slash:

```text
https://your-tenant.us.auth0.com/
```

If you use an Auth0 custom domain, use that domain's issuer URL instead. GreenGateway trims the issuer's trailing slash for discovery and appends `/.well-known/openid-configuration`.

## Namespaced Role Claim

Auth0 custom claims should use collision-resistant names. A URL-shaped namespaced claim is the safest portable pattern for application roles, for example:

```json
{
  "https://greengateway.example.com/roles": ["admin", "operator"]
}
```

Set `roles_claim` to the full claim key. Do not shorten it to a dotted path. GreenGateway first resolves an exact top-level claim key, which is what makes URL-shaped Auth0 claim names work correctly.

Auth0 Organizations add an `org_id` claim to ID and access tokens issued in an organization context. Set `org_claim: "org_id"` if GreenGateway should populate `Principal.org_id` from that value.

<!-- auth-providers-example: auth0-namespaced-roles -->
```json
[
  {
    "name": "auth0",
    "type": "jwt",
    "issuer": "https://your-tenant.us.auth0.com/",
    "audience": "https://api.example.com",
    "roles_claim": "https://greengateway.example.com/roles",
    "org_claim": "org_id"
  }
]
```

Set this value as `AUTH_PROVIDERS`. For example, in a shell:

```sh
AUTH_PROVIDERS='[{"name":"auth0","type":"jwt","issuer":"https://your-tenant.us.auth0.com/","audience":"https://api.example.com","roles_claim":"https://greengateway.example.com/roles","org_claim":"org_id"}]'
```

## Verifying It Works

Start GreenGateway with the configured `AUTH_PROVIDERS`. A discovery failure, missing `jwks_uri`, or unreachable issuer prevents the provider from being constructed during startup. There is no dedicated successful-discovery log line today.

Then call a protected gateway route with a real Auth0 access token minted for the configured API audience:

```sh
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/your/protected/path
```

`401 Unauthorized` means the token was not accepted by authentication. `403 Forbidden` means authentication succeeded but RBAC denied the principal. A `200` or upstream response means the token validated and policy allowed the request.

## References

- Auth0 OIDC discovery: https://auth0.com/docs/get-started/applications/configure-applications-with-oidc-discovery
- Auth0 custom claims: https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-token-claims
- Auth0 organization token claims: https://auth0.com/docs/manage-users/organizations/using-tokens
