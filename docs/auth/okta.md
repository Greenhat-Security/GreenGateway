# Okta Auth Provider Recipe

This recipe configures GreenGateway to validate JWTs issued by an Okta authorization server using OIDC discovery.

The examples below are parsed by the `auth_provider_doc_examples_parse_as_configured_providers` config test. They were not validated against a live Okta org in this environment.

## Issuer URL

For APIs you validate yourself, use an Okta custom authorization server issuer:

```text
https://your-org.okta.com/oauth2/default
```

The built-in default custom authorization server uses `default` as its authorization server ID. Other custom authorization servers use:

```text
https://your-org.okta.com/oauth2/{authorization-server-id}
```

Okta also has an org authorization server at `https://your-org.okta.com`, but Okta documents those access tokens as intended for Okta APIs rather than your own resource servers. Prefer a custom authorization server for GreenGateway.

## Groups Claim

Okta commonly exposes application roles through a custom authorization server claim mapped from Okta group membership. The claim is often named `groups`, but the exact name depends on how the Okta admin configured the authorization server's claims.

<!-- auth-providers-example: okta-groups -->
```json
[
  {
    "name": "okta",
    "type": "jwt",
    "issuer": "https://your-org.okta.com/oauth2/default",
    "audience": "api://greengateway",
    "roles_claim": "groups"
  }
]
```

Set this value as `AUTH_PROVIDERS`. For example, in a shell:

```sh
AUTH_PROVIDERS='[{"name":"okta","type":"jwt","issuer":"https://your-org.okta.com/oauth2/default","audience":"api://greengateway","roles_claim":"groups"}]'
```

If your Okta claim is named something else, set `roles_claim` to that exact claim name.

## Organization Claim

Okta group claims usually model authorization groups, not a single tenant or organization string. Only set `org_claim` if your authorization server adds a dedicated string claim for tenant identity, such as `tenant_id`.

## Verifying It Works

Start GreenGateway with the configured `AUTH_PROVIDERS`. A discovery failure, missing `jwks_uri`, or unreachable issuer prevents the provider from being constructed during startup. There is no dedicated successful-discovery log line today.

Then call a protected gateway route with a real Okta access token minted by the configured authorization server and audience:

```sh
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/your/protected/path
```

`401 Unauthorized` means the token was not accepted by authentication. `403 Forbidden` means authentication succeeded but RBAC denied the principal. A `200` or upstream response means the token validated and policy allowed the request.

## References

- Okta authorization server issuers: https://developer.okta.com/docs/concepts/auth-servers/
- Okta groups claim guide: https://developer.okta.com/docs/guides/customize-tokens-groups-claim/main/
- Okta custom claims guide: https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/
