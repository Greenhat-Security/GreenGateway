# Microsoft Entra ID Auth Provider Recipe

This recipe configures GreenGateway to validate JWTs issued by Microsoft Entra ID using OIDC discovery.

The examples below are parsed by the `auth_provider_doc_examples_parse_as_configured_providers` config test. They were not validated against a live Entra tenant in this environment.

## Issuer URL

Use a tenant-specific v2.0 issuer URL:

```text
https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0
```

Replace the GUID with your tenant ID. GreenGateway does exact issuer validation, so tenant-specific issuers are the safest shape. Avoid `common` or `organizations` unless the token `iss` claim exactly matches the configured issuer.

## App Roles

Use the `roles` claim when your API authorization model is based on Entra app roles assigned through the app registration or enterprise application.

<!-- auth-providers-example: entra-app-roles -->
```json
[
  {
    "name": "entra-app-roles",
    "type": "jwt",
    "issuer": "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
    "audience": "api://22222222-2222-2222-2222-222222222222",
    "roles_claim": "roles",
    "org_claim": "tid"
  }
]
```

`org_claim: "tid"` maps the Entra tenant ID into `Principal.org_id`.

## Groups

Use the `groups` claim when your API authorization model is based on Microsoft Entra security groups. In access tokens, Entra emits group object IDs, not display names, unless you have configured a different optional-claims format.

<!-- auth-providers-example: entra-groups -->
```json
[
  {
    "name": "entra-groups",
    "type": "jwt",
    "issuer": "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0",
    "audience": "api://22222222-2222-2222-2222-222222222222",
    "roles_claim": "groups",
    "org_claim": "tid"
  }
]
```

Set one of the examples above as `AUTH_PROVIDERS`. For example, in a shell:

```sh
AUTH_PROVIDERS='[{"name":"entra-app-roles","type":"jwt","issuer":"https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0","audience":"api://22222222-2222-2222-2222-222222222222","roles_claim":"roles","org_claim":"tid"}]'
```

## Groups Overage Caveat

Microsoft Entra ID limits how many groups it can place in a JWT. When the user exceeds the group limit, Entra omits the `groups` array and emits an overage indicator such as `_claim_names` and `_claim_sources`, or `hasgroups`, so the application can query Microsoft Graph. GreenGateway does not resolve group overage claims today. If your users commonly exceed the limit, prefer app roles or reduce the emitted group set.

## Verifying It Works

Start GreenGateway with the configured `AUTH_PROVIDERS`. A discovery failure, missing `jwks_uri`, or unreachable issuer prevents the provider from being constructed during startup. There is no dedicated successful-discovery log line today.

Then call a protected gateway route with a real Entra access token for the configured API audience:

```sh
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:8080/your/protected/path
```

`401 Unauthorized` means the token was not accepted by authentication. `403 Forbidden` means authentication succeeded but RBAC denied the principal. A `200` or upstream response means the token validated and policy allowed the request.

## References

- Microsoft identity platform OIDC endpoints: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
- Microsoft identity platform access-token claims: https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference
- Microsoft guidance on group claims and app roles: https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles
