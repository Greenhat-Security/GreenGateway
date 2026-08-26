# HashiCorp Vault KV v2 secret provider

GreenGateway can resolve Connection credentials from a HashiCorp Vault KV v2 mount. The integration is one more implementation of the stable Connections `SecretResolver` contract: it adds no Connection authority, no secret CRUD service, no reveal endpoint, and no general Vault proxy. Callers, tool arguments, and ordinary Connection mutations continue to name only an opaque alias ID; every provider locator is trusted startup configuration.

Every value on this page is a placeholder. Do not copy a real address, namespace, mount, path, data key, role, or token into a repository, an issue, or a support bundle.

## What the provider does and does not do

The provider implements exactly one Vault operation: KV v2 *read secret version* (`GET /v1/<mount>/data/<path>`, optionally with `?version=<n>`). It never lists keys, never reads `<mount>/metadata/...`, never writes, rotates, deletes, or administers anything, never creates or renews leases, and never accepts a caller-supplied portion of a request URL. Each alias carries a request line that was assembled and validated once at startup from operator configuration.

Out of scope, and deliberately not implemented: Vault engine, policy, or auth administration; KV v1; Transit; PKI; dynamic secrets; lease management; and caller-selected paths.

## Configuration document

The provider is configured with one trusted JSON document of at most 256 KiB that declares up to 8 Vault *profiles* and up to 512 aliases. A profile fixes one Vault endpoint plus the identity used against it. An alias fixes the profile, KV v2 mount, secret path, data key, and an optional pinned version.

```json
{
  "profiles": [
    {
      "id": "primary",
      "address": "https://vault.placeholder.example",
      "namespace": "placeholder-namespace",
      "auth": {
        "type": "workload_jwt",
        "mount": "kubernetes",
        "role": "greengateway",
        "token_root": "/var/run/secrets/greengateway/vault",
        "token_file": "token"
      }
    }
  ],
  "aliases": [
    {
      "id": "billing-api-key",
      "label": "Billing API key",
      "profile": "primary",
      "mount": "secret",
      "path": "placeholder-team/placeholder-service",
      "key": "api_key",
      "version": 7
    }
  ]
}
```

Validation is fail-closed and rejects the whole document on the first problem, reporting only the offending index and never the offending value.

| Field | Rule |
| --- | --- |
| `profiles[].id`, `aliases[].id` | 1–128 URL-safe ASCII bytes starting with a letter or digit; unique, and an alias ID may not collide with an alias served by another provider |
| `profiles[].address` | absolute `https` URL with a host and no credentials, path, query, or fragment; `http` is rejected outright |
| `profiles[].namespace` | optional; slash-separated segments of `A-Za-z0-9._-`, at most 128 bytes, no `.`, `..`, empty, leading, or trailing segment |
| `aliases[].mount`, `aliases[].path` | same segment grammar, at most 128 and 512 bytes; traversal, absolute paths, percent-encoding, query, and fragment syntax are all rejected |
| `aliases[].key` | 1–128 bytes of `A-Za-z0-9._-` |
| `aliases[].version` | optional; when present must be at least 1, and the response version must match it exactly |
| `aliases[].label` | 1–128 non-control characters; safe to show in the admin UI |

Alias metadata exposed by the Connections API reports only the alias ID, the safe label, the provider kind `vault_kv_v2`, and the pinned version when one is configured. It never reports the address, namespace, mount, path, or data key.

> Startup binding: set this document as [`CONNECTION_VAULT_PROVIDER`](../configuration.md#connection_vault_provider). Aliases are resolved asynchronously at request time and validated on first use, so a Vault outage at startup does not block the gateway from starting.

## Identity

Authentication always completes before the secret read. The provider never probes anonymously, never uses an ambient credential chain, and never falls back to a weaker credential if the configured one fails.

`workload_jwt` is the recommended mechanism and needs no bootstrap secret at all. It reads a projected workload token from a directory that GreenGateway canonicalizes and holds as a capability handle at startup, so replacing the path or an ancestor afterwards cannot redirect the read, and it posts that token to a fixed auth mount and role. The leaf read rejects symbolic links and reparse points, opens without following links and in nonblocking mode, revalidates the opened handle as a regular file, and caps the read. Because container runtimes publish projected service-account tokens world readable, group and other *read* permissions are tolerated on this file only; group or other *write* on either the file or the directory still fails closed.

```yaml
# Kubernetes: project a short-lived, audience-bound token into the pinned root.
volumes:
  - name: vault-identity
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: vault
            expirationSeconds: 600
```

`token` and `app_role` exist for deployments with no workload identity provider. Both take their bootstrap material from an alias that another provider already serves — never from an inline value in this document — and configuration rejects a bootstrap alias that this provider itself serves, so a Vault alias can never bootstrap Vault. The AppRole `role_id` is configuration; the `secret_id` comes from the alias.

A login response is rejected unless it carries a non-empty printable token of at most 1 KiB and a non-zero `lease_duration`. A zero lease means a root or never-expiring token, which this provider refuses rather than accepting as an unbounded grant. Accepted tokens are cached per profile for the shorter of the returned lease and one hour, minus a 30-second refresh skew.

## Least-privilege Vault policy

Grant `read` on each `.../data/...` path an alias needs, and nothing else. Do not grant `list`, do not grant anything on `.../metadata/...`, do not use a wildcard that covers paths no alias reads, and never use the root token or the `root` policy.

```hcl
# greengateway-kv-read
path "secret/data/placeholder-team/placeholder-service" {
  capabilities = ["read"]
}
```

Add one `path` block per alias. A `list` capability is unnecessary because the provider never lists, and granting it only widens what a compromised token could enumerate. A `metadata` grant is likewise unnecessary: version state arrives inside the read response.

Bind the auth role tightly and keep token TTLs short.

```shell
# Kubernetes auth: fixed service account, namespace, and audience.
vault write auth/kubernetes/role/greengateway \
    bound_service_account_names=greengateway \
    bound_service_account_namespaces=greengateway \
    audience=vault \
    token_policies=greengateway-kv-read \
    token_no_default_policy=true \
    token_ttl=10m \
    token_max_ttl=20m

# AppRole: bootstrap only, with a short secret ID lifetime.
vault write auth/approle/role/greengateway \
    token_policies=greengateway-kv-read \
    token_no_default_policy=true \
    token_ttl=10m \
    token_max_ttl=20m \
    secret_id_ttl=24h \
    secret_id_num_uses=0
```

`token_no_default_policy=true` matters: the `default` policy carries self-management capabilities this provider never needs.

## Egress

Every identity and provider request travels through GreenGateway egress controls, so the deployment egress policy applies unchanged: HTTPS only, allowlisted host and port, strict CA, hostname, and SNI validation, all-answer DNS validation with exact address pinning, and a disabled redirect policy. Add the Vault host to the egress allowlist explicitly; the provider never expands the allowlist and never follows a redirect. A `3xx` response is a refusal, not a hop.

## Bounds

| Bound | Value |
| --- | --- |
| Profiles / aliases | 8 / 512 |
| Configuration document | 256 KiB |
| Concurrent resolutions | 8, admission fails fast with `provider_busy` |
| Total resolution deadline | 10 s |
| Transient retries | 1, with a 100 ms backoff, and only for a timeout, a transport failure, `429`, or `5xx` |
| Login response / read response | 16 KiB / 64 KiB, `application/json` only |
| Vault token | 1 KiB, cached for at most one hour minus a 30 s skew |
| Resolved value cache | 256 entries, 60 s |
| Secret value | the credential-purpose byte limit, and empty or NUL-bearing values are rejected |

The resolved-value cache is keyed by provider configuration, egress configuration, identity generation, alias, purpose, and pinned version, and entries are zeroized when they are evicted or replaced. A new login changes the identity generation, so values cached under a previous identity are never reused.

An unpinned alias therefore observes the next valid version at most 60 seconds after it is written. A pinned alias keeps requesting exactly that version and fails closed if the provider answers with a different one.

## Failure behavior

Rotation, revocation, deletion, destruction, malformed data, provider outage, and newly denied access all fail closed. A failed resolution purges any cached value for that alias, so a later caller never receives a stale or previous value, and the provider never retries anonymously or switches credential sources. A denied read earns exactly one fresh login through the same fixed identity source — that is the rotation path — and a second denial fails.

Observability carries only the provider kind, outcome, a bounded safe reason, and latency, through `connection_secret_provider_read_total` and `connection_secret_provider_read_duration_seconds`. Resource locators, alias-to-resource mappings, tokens, headers, request and response bodies, secret values, and raw library errors are never logged, exported, or rendered in `Debug` output.

| Safe reason | Meaning |
| --- | --- |
| `unknown_alias` | the alias is not configured for this provider |
| `provider_busy` | concurrent-resolution admission is saturated |
| `deadline_exceeded` | the resolution deadline elapsed |
| `egress_denied` | egress policy refused the destination or the transport |
| `redirect_refused` | the provider answered with a redirect |
| `identity_unavailable` / `identity_denied` / `identity_invalid` | the identity source or login failed, was refused, or returned an unusable token |
| `provider_unavailable` / `provider_denied` | Vault was unreachable or refused the read |
| `secret_absent` / `secret_destroyed` | the version, the data, or the data key is gone |
| `invalid_response` / `invalid_material` | the response or the value failed validation |
| `provider_failure` | an internal fail-closed condition |

## Testing

Provider tests are hermetic: they drive a fake transport and a fake identity source, so CI never contacts a Vault server. They cover authorization ordering, egress and redirect denial, identity rotation and re-authentication, deleted, destroyed, absent, malformed, oversized, and non-string responses, retry, concurrency, deadline, and cache bounds, version pinning and rotation, and the absence of secret canaries from metadata, `Debug`, error, and metric output.
