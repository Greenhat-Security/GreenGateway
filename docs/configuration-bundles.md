# Configuration bundles (`v1alpha1`)

**Status: alpha format, not yet selectable.** This page is the reference for the
versioned configuration bundle format and the reader that validates it (issue
#242). The reader lives in the shared `gateway-config` crate, so the gateway and
[`ggctl validate` and `ggctl doctor`](ggctl.md#validate) run the same code, and
`ggctl` checks a bundle offline today. [`ggctl init`](ggctl.md#init) creates a
new bundle for a deployment profile ([generated bundles](#generated-bundles)) and
[`ggctl convert`](ggctl.md#convert) converts one between document versions. Nothing in a released gateway reads a
bundle yet: there is no startup mode, environment variable, or admin route that
selects one. Bundle mode, which maps a deployment document onto the
configuration compiler, is a later #242 slice. Until it lands, environment
configuration ([configuration.md](configuration.md)) is the only way to
configure a gateway, and the format below may still change before it is
released.

The design this follows is
[ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md) (setup, operator
CLI, and configuration bundles), which is still **Proposed**: where this page
and the ADR differ, this page describes what the reader does today.

## What a bundle is

A bundle is a **flat directory**:

| File | Kind | Syntax | Byte bound |
| --- | --- | --- | --- |
| `bundle.yaml` (fixed name) | `GatewayBundle` manifest | YAML subset | 64 KiB |
| the deployment document the manifest names | `GatewayDeployment` | YAML subset (`.yaml`) or strict JSON (`.json`) | 1 MiB |
| the policy document the manifest names, if any | policy `0.1.0` | strict JSON (`.json`) | 1 MiB |
| the tools document the manifest names, if any | tools `0.1.0` | strict JSON (`.json`) | 1 MiB |

The files the manifest references may total at most 4 MiB, and the reader
examines at most 256 directory entries.

```yaml
# bundle.yaml
apiVersion: greengateway.dev/v1alpha1
kind: GatewayBundle
metadata:
  name: payments-production
spec:
  deployment:
    path: deployment.yaml
    sha256: "<64 lowercase hex digits of deployment.yaml's exact bytes>"
  resources:
    policy:
      source: bundle
      path: policy.json
      schema_version: "0.1.0"
      sha256: "<64 lowercase hex digits>"
    tools:
      source: server
    connections:
      source: server
```

```yaml
# deployment.yaml
apiVersion: greengateway.dev/v1alpha1
kind: GatewayDeployment
spec:
  profile: production
```

Published schemas (Draft 2020-12):

- [`gateway-bundle.v1alpha1.schema.json`](schemas/gateway-bundle.v1alpha1.schema.json)
- [`gateway-deployment.v1alpha1.schema.json`](schemas/gateway-deployment.v1alpha1.schema.json)

Validate the documents' JSON values against them in CI if you like. They are
necessary but not sufficient: the gateway's reader is authoritative, and it also
checks the directory, the digests, the YAML subset, duplicate references, and
the referenced documents.

## Compatibility

| Document | `apiVersion` | `kind` | Status |
| --- | --- | --- | --- |
| Manifest | `greengateway.dev/v1alpha1` | `GatewayBundle` | alpha |
| Deployment document | `greengateway.dev/v1alpha1` | `GatewayDeployment` | alpha; the profile and the deployment settings |
| Policy resource | (its own `schema_version`) | | `0.1.0` only |
| Tools resource | (its own `schema_version`) | | `0.1.0` only |

The reader accepts only these exact pairs. There is no prefix match, no "any
alpha", no case folding, and no downgrade. An unknown `apiVersion` stops
validation before any other member is read (`compat.unsupported_api_version`),
and a `kind` other than the one expected is `compat.unsupported_kind`. Changing
a document version is an explicit conversion; a release that adds a version
keeps reading the previous one for at least one minor release.

The conversion is `ggctl convert BUNDLE --to VERSION`. Every version has one
place on an ordered ladder, and one step converts each version to the next: a
bundle the reader accepts is converted step by step from its own version up to
the target, so the result depends only on the bundle and the target, and a
bundle already at the target is returned byte for byte, so converting twice is
converting once. A target older than the bundle is refused
(`convert.downgrade_refused`), and so is any version the ladder does not hold
(`convert.unsupported_version`). `greengateway.dev/v1alpha1` is the only version
today, so the only conversion is the identity: `--output` writes an unchanged
copy and `--in-place` changes nothing.

Environment-mode policy and tools loading is unchanged: it still accepts any
`0.` schema version, and the policy loader still warns about unknown top-level
members and drops them. The exact version and the refusal below apply only at
the bundle boundary.

## The manifest

- `metadata.name` is a lowercase DNS label (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).
- `spec.deployment` is required: `path` names a `.yaml` or `.json` file and
  `sha256` pins its exact bytes.
- `spec.resources` is optional, and so is each of its members.
  - `policy` and `tools` take `source: bundle` with `path` (a `.json` file),
    `schema_version`, and `sha256`, or `source: server` with nothing else. With
    `source: bundle` the bundle is the resource's only writer; with
    `source: server` the gateway's existing store is. What each choice means in
    each deployment mode is decided by the configuration compiler, not by the
    reader.
  - `connections` accepts only `source: server`; Connections are never bundle
    content in `v1alpha1` (`reference.source_unsupported`).
- No two references may name the same file (`reference.duplicate_path`), and no
  reference may name `bundle.yaml` (`reference.reserved_path`).
- Every object is closed: a member the version does not define is refused, not
  ignored (`schema.unknown_member`).

## The deployment document

`spec` holds the deployment profile and the deployment settings. The profile is
`production`, `migration`, or `development`: the reader fixes the names, and the
compiler will enforce each profile's invariants.

The settings come from the [field catalog](configuration-catalog.json). Every
catalog field a bundle can set has a document path there, the sections of `spec`
are exactly the ones those paths imply, and the [published
schema](schemas/gateway-deployment.v1alpha1.schema.json) and the
[tables below](#settings) are generated from the same paths, so the three cannot
disagree. Every section is a closed object (`schema.unknown_member` for any
other member, and `schema.wrong_type` for a section that is not an object), and
every section and setting is optional: leaving a setting out means what leaving
its environment variable unset means. What a setting does is its variable's
entry in [configuration.md](configuration.md), which each row links.

```yaml
apiVersion: greengateway.dev/v1alpha1
kind: GatewayDeployment
spec:
  profile: production
  listeners:
    public:
      address: "0.0.0.0:8080"
      tls: required
    admin:
      address: "127.0.0.1:9443"
      prefix: /admin
  public_url: https://gateway.example.test
  authentication:
    providers:
      - name: corporate
        type: jwt
        issuer: https://idp.example.test
        audience: greengateway
  admin_login:
    provider: corporate
    client_id: greengateway-admin
    client_secret: { secret: idp-client }
    redirect_uri: https://gateway.example.test/v1/admin/auth/callback
  upstream:
    routes:
      - id: orders
        path_prefix: /orders
        upstreams:
          - id: orders-a
            url: { secret: orders-a }
  egress:
    deny_private_addresses: true
    allowed_hosts: [api.example.test]
  rate_limits:
    read: { requests_per_second: "50", burst: 100 }
  state:
    backend: sqlite
    stores: [audit, connections]
```

Each setting is held to its catalog entry, and the code says what is wrong
without repeating the value:

- **Booleans** are `true` or `false`, and **choices** exactly one of their words
  (`schema.invalid_value`). A value of another JSON type is `schema.wrong_type`,
  and `null` is never a value: leave the member out instead.
- **Integers** are JSON integers within the field's own range
  (`schema.invalid_value`). A document cannot hold an integer beyond the I-JSON
  safe range (`syntax.integer_out_of_range`), so a field with no maximum of its
  own goes up to 2^53 - 1 in a bundle.
- **Fractional settings** are decimal strings (below) within the field's own
  range (`schema.invalid_value`), compared as the gateway compares the
  floating-point value the same text gives in the environment. The schema states
  a decimal's range in its description; the reader enforces it.
- **Socket addresses, URLs and other strings** are non-empty, with no whitespace
  at either end (`schema.invalid_value`). A **list** is an array of such strings
  with no comma in any of them, one per entry of the environment variable's
  comma-separated list, which trims entries and drops empty ones; the reader
  reports the entry at fault by its index. An empty array is an empty list: for
  the lists with a default (`csrf.exempt_paths`, `authentication.exempt_paths`,
  `authorization.exempt_paths` and `limits.allowed_content_types`) it replaces
  the default, as an empty environment value does.
- **`upstream.url`** can carry a credential in its user information or query, so
  it takes a secret reference (`secret.inline_value` for a URL written inline).
- **`authentication.providers`, `upstream.routes` and `upstream.mcp_servers`**
  hold what `AUTH_PROVIDERS`, `UPSTREAM_ROUTES` and `MCP_UPSTREAM_SERVERS` hold
  as JSON in the environment, in [structured forms](#structured-settings).
- **`listeners.public.tls` and `listeners.admin.tls`** (`required` or `off`)
  state whether a listener terminates TLS, and
  **`listeners.public.client_certificate_crl` and
  `listeners.admin.client_certificate_crl`** whether it checks client
  certificates against a revocation list. The certificate, key and list are
  host locators that stay in the environment, so the document states the intent
  only; holding the intent and the locators to each other, in both directions,
  arrives with the mapping onto the compiler. Whether a listener asks for client
  certificates at all (`client_certificates`), and so needs a CA bundle, was
  already a setting.
- **`admin_login.client_id`, `admin_login.client_secret` and
  `admin_login.redirect_uri`** are the OAuth client admin sign-in uses, which in
  environment mode are members of the `AUTH_PROVIDERS` entry
  `ADMIN_LOGIN_PROVIDER` names. No other provider reads them, so the document
  keeps them beside the provider's name rather than in a provider. The client
  secret takes a secret reference.
- **`compatibility.acknowledged`** names the compatibility behaviors a
  `migration` document keeps, each once: `policy_default_allow`,
  `policy_shadow_mode` and `wildcard_role` (`schema.invalid_value` for another
  word or a repeat), canonicalized into that order. Any other profile that
  acknowledges one is refused (`schema.not_applicable`); see
  [deployment profiles](#deployment-profiles).
- **`state.stores`** names the standalone stores a deployment keeps beneath its
  state directory, each once: `audit`, `discovery`, `principals`, `connections`
  and `service_tokens` (`schema.invalid_value` for another word or a repeat),
  each the store of one fixed file in [the state directory](#the-state-directory).
  In environment mode they are the stores whose `*_SQLITE_PATH` variable is set.
  The policy publication history is not one of them: ADR-0008 has not decided
  whether bundle mode keeps one beside a bundle-owned policy.

The reader checks each setting's shape and its own bounds, and nothing else.
Rules that relate settings (an idle timeout within its session's lifetime, a
client certificate mode that needs a CA, settings only one state backend reads)
and each string's own grammar (addresses, URLs, CIDRs, header and cookie names)
are the configuration compiler's, and the compiler does not read a deployment
document yet. So a document the reader accepts can still be one the compiler
would refuse, and no gateway starts from it. The profiles' invariants on these
settings arrive with the mapping onto the compiler (see
[deployment profiles](#deployment-profiles)).

Some environment variables have no document form:

- The host locators (certificate, key, CA, CRL, secret-root, database-URL and
  audit log files) and the secret-provider wiring are bootstrap inputs that stay
  in the environment beside a bundle
  ([ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md#bootstrap-inputs)).
- `POLICY_FILE`, `TOOLS_FILE` and every `*_SQLITE_PATH` are replaced by bundle
  resources and by `spec.state.stores`.
- The legacy single JWT provider (`JWT_*`, `ROLES_CLAIM`) is not representable:
  a bundle names its authentication providers explicitly. Nor is
  `OPENAPI_SPEC_PATH`, a host path whose OpenAPI discovery managed Connections
  provide, and `AUTHORITY_EVENT_FILE` is a host path ADR-0008 has not placed yet.

The value forms those settings will use are fixed now, with the reader and the
schema's `$defs`:

- **Secret references.** A sensitive setting accepts only `{ secret: <alias-id> }`,
  where the alias ID is an opaque ID in the one alias namespace the secret
  providers maintain: 1 to 128 bytes of `[A-Za-z0-9._-]`, starting with a letter
  or digit. A plain value in a sensitive setting is `secret.inline_value`, and the
  diagnostic never contains it; any other shape is `secret.invalid_reference`.
  The form cannot express a value, an environment-variable name, a file path, a
  provider locator, or ciphertext. The reader never resolves a reference.
- **Unresolved placeholders.** `{ unresolved: legacy_inline_secret | template_value | not_representable }`
  marks a value an export, conversion, or template could not or would not
  supply. No setting accepts one (`reference.unresolved`), so an output that
  contains one can never be mistaken for a deployable bundle.
- **Decimals.** JSON numbers in bundle documents are integers within the I-JSON
  safe range (magnitude at most 2^53 - 1). A fractional setting is a string in the
  grammar `^(0|[1-9][0-9]{0,15})(\.[0-9]{1,6})?$` (`schema.invalid_decimal`
  otherwise), canonicalized to its shortest exact spelling (`"0.10"` is `"0.1"`,
  `"3.0"` is `"3"`) in the document's canonical form, so a respelled decimal
  changes neither the canonical bytes nor any digest made from them. It parses
  to exactly the floating-point value the same text gives in an environment
  variable. The store list is canonicalized the same way, into the order above.

### Structured settings

`authentication.providers`, `upstream.routes` and `upstream.mcp_servers` are
arrays of the entry objects their environment variables hold as JSON, with the
same member names: an [authentication provider](#authentication-provider), an
[upstream route](#upstream-route) and an
[MCP upstream server](#mcp-upstream-server), with the objects beneath them. Each
object is closed (`schema.unknown_member`), names its required members
(`schema.missing_member`), and is typed member by member as the tables after the
settings say. An integer lies within the range of the integer type the compiler
reads it as, a string is non-empty with no whitespace at either end (a provider's
`roles_claim_delimiter`, which can be a space, is kept exactly as written), and
`null` is never a value. Each problem is reported at the member at fault, and an
empty array is an empty list, as `[]` is in the environment.

Each form classifies the members of one of the compiler's own types, and the
reader rebuilds each setting in its environment form and has the compiler's
types read it; tests hold every form to its type's member list, required
members and integer ranges, so a member the compiler gains is refused in a
document until its form is decided, and the two forms cannot drift. They
differ from the environment's in what a document must never hold:

- **Values that can carry a credential take a secret reference.** An upstream
  route's `upstream_url`, an endpoint's `url` and an MCP upstream server's `url`
  can carry one in their user information or query, as `upstream.url` can, so
  each is `{ secret: <alias-id> }` (`secret.inline_value` for a URL written
  inline, never echoed). The admin login client secret is
  `admin_login.client_secret`, a reference too.
- **Static request headers are not representable.** A literal
  `add_request_headers` value can be a credential, which belongs in a managed
  Connection, so every entry is refused (`schema.not_representable`, reported at
  `add_request_headers` and never by the header's name); only an empty object is
  accepted. Whether a non-credential literal header may be representable is left
  for a later document version.
- **Host paths are not representable.** A route's or endpoint's
  `tls_ca_bundle_path`, an endpoint's `client_identity_pem_path` and a route's
  `openapi_spec_path` name files on the gateway's host, which never enter a
  bundle (`schema.not_representable`).
- **The admin login client is not a provider member.** `client_id`,
  `client_secret` and `redirect_uri` are `spec.admin_login` members
  (`schema.unknown_member` inside a provider).

An environment value converts to a document by these rules alone; the tests
convert each environment fixture this way and prove that the document,
resolved back, compiles to exactly the configuration the fixture does. A secret
converts to a reference to an alias its value must then be stored under, and a
value a document cannot hold to `{ unresolved: not_representable }`, so a
converted document that lost something never validates. Defaults, each member's own grammar and bounds, and
every rule relating members stay the compiler's, as for the environment form.

### Settings

One table per member of `spec`, then one per structured form. The value column gives the type and the field's
own range; the default is the value the document would spell, or what the
default follows.

<!-- deployment-settings:begin -->

#### `spec.listeners`

The listeners the gateway binds. Certificate, key, CA and CRL files are host locators and stay in the environment; the document states whether each listener terminates TLS and checks a revocation list.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `listeners.public.address` | socket address string | `"0.0.0.0:8080"` | [`LISTEN_ADDR`](configuration.md#listen_addr) |
| `listeners.public.client_certificates` | `off`, `optional` or `required` | `"off"` | [`CLIENT_CERT_MODE`](configuration.md#client_cert_mode) |
| `listeners.public.tls` | `required` or `off` | `"off"` | `required` when [`TLS_CERT_FILE`](configuration.md#tls_cert_file) and [`TLS_KEY_FILE`](configuration.md#tls_key_file) are set |
| `listeners.public.client_certificate_crl` | `required` or `off` | `"off"` | `required` when [`CLIENT_CERT_CRL_FILE`](configuration.md#client_cert_crl_file) is set |
| `listeners.admin.address` | socket address string | unset | [`ADMIN_LISTEN_ADDR`](configuration.md#admin_listen_addr) |
| `listeners.admin.client_certificates` | `off`, `optional` or `required` | `"off"` | [`ADMIN_CLIENT_CERT_MODE`](configuration.md#admin_client_cert_mode) |
| `listeners.admin.prefix` | string | `"/admin"` | [`ADMIN_PREFIX`](configuration.md#admin_prefix) |
| `listeners.admin.tls` | `required` or `off` | `"off"` | `required` when [`ADMIN_TLS_CERT_FILE`](configuration.md#admin_tls_cert_file) and [`ADMIN_TLS_KEY_FILE`](configuration.md#admin_tls_key_file) are set |
| `listeners.admin.client_certificate_crl` | `required` or `off` | `"off"` | `required` when [`ADMIN_CLIENT_CERT_CRL_FILE`](configuration.md#admin_client_cert_crl_file) is set |
| `listeners.grpc.address` | socket address string | unset | [`GRPC_LISTEN_ADDR`](configuration.md#grpc_listen_addr) |
| `listeners.grpc.max_concurrent_streams` | integer, 1 to 10000 | `100` | [`GRPC_MAX_CONCURRENT_STREAMS`](configuration.md#grpc_max_concurrent_streams) |
| `listeners.grpc.max_metadata_bytes` | integer bytes, 1024 to 1048576 | `16384` | [`GRPC_MAX_METADATA_BYTES`](configuration.md#grpc_max_metadata_bytes) |
| `listeners.tls.min_version` | `1.2` or `1.3` | `"1.2"` | [`TLS_MIN_VERSION`](configuration.md#tls_min_version) |
| `listeners.tls.handshake_timeout_ms` | integer milliseconds, at least 1 | `10000` | [`TLS_HANDSHAKE_TIMEOUT_MS`](configuration.md#tls_handshake_timeout_ms) |
| `listeners.tls.max_concurrent_handshakes` | integer, at least 1 | `256` | [`TLS_MAX_CONCURRENT_HANDSHAKES`](configuration.md#tls_max_concurrent_handshakes) |
| `listeners.tls.client_certificate_identity` | `spiffe`, `uri` or `dns` | unset | [`CLIENT_CERT_IDENTITY_SOURCE`](configuration.md#client_cert_identity_source) |

#### `spec.admin_login`

Admin sign-in through an authentication provider, and the OAuth client it signs in with.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `admin_login.provider` | string | unset | [`ADMIN_LOGIN_PROVIDER`](configuration.md#admin_login_provider) |
| `admin_login.pending_ttl_secs` | integer seconds, at least 1 | `300` | [`ADMIN_LOGIN_PENDING_TTL_SECS`](configuration.md#admin_login_pending_ttl_secs) |
| `admin_login.pending_max_entries` | integer, at least 1 | `1024` | [`ADMIN_LOGIN_PENDING_MAX_ENTRIES`](configuration.md#admin_login_pending_max_entries) |
| `admin_login.pending_max_per_ip` | integer, at least 1 | `16` | [`ADMIN_LOGIN_PENDING_MAX_PER_IP`](configuration.md#admin_login_pending_max_per_ip) |
| `admin_login.client_id` | string | unset | `client_id` of the [`AUTH_PROVIDERS`](configuration.md#auth_providers) entry [`ADMIN_LOGIN_PROVIDER`](configuration.md#admin_login_provider) names |
| `admin_login.client_secret` | secret reference | unset | `client_secret` of the [`AUTH_PROVIDERS`](configuration.md#auth_providers) entry [`ADMIN_LOGIN_PROVIDER`](configuration.md#admin_login_provider) names |
| `admin_login.redirect_uri` | string | unset | `redirect_uri` of the [`AUTH_PROVIDERS`](configuration.md#auth_providers) entry [`ADMIN_LOGIN_PROVIDER`](configuration.md#admin_login_provider) names |

#### `spec.admin_sessions`

Admin sessions.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `admin_sessions.mode` | `disabled`, `standalone_memory` or `cluster_postgres` | `"disabled"` | [`ADMIN_SESSION_MODE`](configuration.md#admin_session_mode) |
| `admin_sessions.ttl_secs` | integer seconds, 1 to 86400 | `3600` | [`ADMIN_SESSION_TTL_SECS`](configuration.md#admin_session_ttl_secs) |
| `admin_sessions.idle_timeout_secs` | integer seconds, at least 0 | follows `admin_sessions.ttl_secs` | [`ADMIN_SESSION_IDLE_TIMEOUT_SECS`](configuration.md#admin_session_idle_timeout_secs) |
| `admin_sessions.max_entries` | integer, 1 to 100000 | `1024` | [`ADMIN_SESSION_MAX_ENTRIES`](configuration.md#admin_session_max_entries) |

#### `spec.public_url`

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `public_url` | URL string | unset | [`GATEWAY_PUBLIC_URL`](configuration.md#gateway_public_url) |

#### `spec.audit`

The audit trail: durability, the shutdown drain, probe observations and retention.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `audit.successful_probes_metrics_only` | `true` or `false` | `false` | [`AUDIT_SUCCESSFUL_PROBES_METRICS_ONLY`](configuration.md#audit_successful_probes_metrics_only) |
| `audit.sqlite_retention_days` | integer days, 0 to 36500 | unset | [`AUDIT_SQLITE_RETENTION_DAYS`](configuration.md#audit_sqlite_retention_days) |
| `audit.drain_timeout_ms` | integer milliseconds, 1 to 60000 | `5000` | [`AUDIT_DRAIN_TIMEOUT_MS`](configuration.md#audit_drain_timeout_ms) |
| `audit.durability` | `required` or `best_effort` | `"required"` | [`AUDIT_DURABILITY`](configuration.md#audit_durability) |
| `audit.durability_timeout_ms` | integer milliseconds, 1 to 60000 | `5000` | [`AUDIT_DURABILITY_TIMEOUT_MS`](configuration.md#audit_durability_timeout_ms) |
| `audit.postgres_retention_days` | integer days, 0 to 36500 | unset | [`AUDIT_POSTGRES_RETENTION_DAYS`](configuration.md#audit_postgres_retention_days) |

#### `spec.shutdown`

Graceful shutdown.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `shutdown.drain_delay_ms` | integer milliseconds, 0 to 30000 | `1000` | [`SHUTDOWN_DRAIN_DELAY_MS`](configuration.md#shutdown_drain_delay_ms) |
| `shutdown.timeout_ms` | integer milliseconds, 1 to 300000 | `30000` | [`SHUTDOWN_TIMEOUT_MS`](configuration.md#shutdown_timeout_ms) |

#### `spec.discovery`

API discovery, payload capture and the discovery signals.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `discovery.endpoint_limit` | integer, at least 1 | `10000` | [`DISCOVERY_ENDPOINT_LIMIT`](configuration.md#discovery_endpoint_limit) |
| `discovery.projector.lease_ttl_ms` | integer milliseconds, at least 1000 | `15000` | [`DISCOVERY_PROJECTOR_LEASE_TTL_MS`](configuration.md#discovery_projector_lease_ttl_ms) |
| `discovery.projector.poll_ms` | integer milliseconds, at least 50 | `250` | [`DISCOVERY_PROJECTOR_POLL_MS`](configuration.md#discovery_projector_poll_ms) |
| `discovery.projector.batch` | integer, 1 to 5000 | `500` | [`DISCOVERY_PROJECTOR_BATCH`](configuration.md#discovery_projector_batch) |
| `discovery.payload_capture.enabled` | `true` or `false` | `false` | [`PAYLOAD_CAPTURE_ENABLED`](configuration.md#payload_capture_enabled) |
| `discovery.payload_capture.sample_rate` | decimal string, at least 0 and below 1 | `"0.1"` | [`PAYLOAD_CAPTURE_SAMPLE_RATE`](configuration.md#payload_capture_sample_rate) |
| `discovery.signals.schema_mismatch_threshold` | integer, at least 1 | `5` | [`SCHEMA_MISMATCH_SIGNAL_THRESHOLD`](configuration.md#schema_mismatch_signal_threshold) |
| `discovery.signals.error_rate_spike_threshold` | decimal string, above 0 and at most 1 | `"0.4"` | [`ERROR_RATE_SPIKE_SIGNAL_THRESHOLD`](configuration.md#error_rate_spike_signal_threshold) |
| `discovery.signals.principal_new_to_endpoint_threshold` | integer, at least 1 | `1` | [`PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD`](configuration.md#principal_new_to_endpoint_signal_threshold) |
| `discovery.signals.volume_outlier_threshold` | decimal string, above 1 | `"3"` | [`VOLUME_OUTLIER_SIGNAL_THRESHOLD`](configuration.md#volume_outlier_signal_threshold) |
| `discovery.rule_suggestion_baseline_window_hours` | integer hours, 1 to 876000 | `24` | [`RULE_SUGGESTION_BASELINE_WINDOW_HOURS`](configuration.md#rule_suggestion_baseline_window_hours) |

#### `spec.policy_tests`

The stored policy test suite as a gate on policy changes.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `policy_tests.required` | `true` or `false` | `false` | [`POLICY_TESTS_REQUIRED`](configuration.md#policy_tests_required) |

#### `spec.cors`

Cross-origin resource sharing.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `cors.allowed_origins` | array of strings | unset | [`CORS_ALLOW_ORIGINS`](configuration.md#cors_allow_origins) |

#### `spec.limits`

Request bounds, and the media types mutating requests may carry.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `limits.max_body_bytes` | integer bytes, at least 0 | `1048576` | [`MAX_BODY_SIZE`](configuration.md#max_body_size) |
| `limits.max_request_path_bytes` | integer bytes, 1 to 8192 | `8192` | [`MAX_REQUEST_PATH_BYTES`](configuration.md#max_request_path_bytes) |
| `limits.allowed_content_types` | array of strings | `["application/json"]` | [`VALIDATION_ALLOWED_CONTENT_TYPES`](configuration.md#validation_allowed_content_types) |

#### `spec.rate_limits`

The global rate limits applied before authentication, in two lanes.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `rate_limits.read.requests_per_second` | decimal string, at least 0 | `"50"` | [`RATE_LIMIT_READ_RPS`](configuration.md#rate_limit_read_rps) |
| `rate_limits.read.burst` | integer, 0 to 4294967295 | `100` | [`RATE_LIMIT_READ_BURST`](configuration.md#rate_limit_read_burst) |
| `rate_limits.write.requests_per_second` | decimal string, at least 0 | `"10"` | [`RATE_LIMIT_WRITE_RPS`](configuration.md#rate_limit_write_rps) |
| `rate_limits.write.burst` | integer, 0 to 4294967295 | `20` | [`RATE_LIMIT_WRITE_BURST`](configuration.md#rate_limit_write_burst) |
| `rate_limits.max_buckets` | integer, at least 1 | `65536` | [`RATE_LIMIT_MAX_BUCKETS`](configuration.md#rate_limit_max_buckets) |
| `rate_limits.bucket_ttl_ms` | integer milliseconds, at least 1 | `600000` | [`RATE_LIMIT_BUCKET_TTL_MS`](configuration.md#rate_limit_bucket_ttl_ms) |

#### `spec.trusted_proxies`

Which proxies' forwarded client addresses are believed.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `trusted_proxies.trust_headers` | `true` or `false` | `false` | [`TRUST_PROXY_HEADERS`](configuration.md#trust_proxy_headers) |
| `trusted_proxies.cidrs` | array of strings | unset | [`TRUSTED_PROXY_CIDRS`](configuration.md#trusted_proxy_cidrs) |

#### `spec.authorization`

Authorization outside the policy document.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `authorization.exempt_paths` | array of strings | follows `listeners.admin.prefix` | [`RBAC_EXEMPT_PATHS`](configuration.md#rbac_exempt_paths) |

#### `spec.authentication`

Request authentication and the authentication providers.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `authentication.enabled` | `true` or `false` | `true` | [`AUTH_ENABLED`](configuration.md#auth_enabled) |
| `authentication.mode` | `required` or `observe` | `"required"` | [`AUTH_MODE`](configuration.md#auth_mode) |
| `authentication.cookie_name` | string | `"session"` | [`AUTH_COOKIE_NAME`](configuration.md#auth_cookie_name) |
| `authentication.exempt_paths` | array of strings | follows `listeners.admin.prefix` | [`AUTH_EXEMPT_PATHS`](configuration.md#auth_exempt_paths) |
| `authentication.service_token_cache_ttl_ms` | integer milliseconds, at least 1 | `5000` | [`SERVICE_TOKEN_CACHE_TTL_MS`](configuration.md#service_token_cache_ttl_ms) |
| `authentication.providers` | array of [authentication provider](#authentication-provider) objects | unset | [`AUTH_PROVIDERS`](configuration.md#auth_providers) |

#### `spec.tool_runtime`

Tool execution.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `tool_runtime.queue_depth` | integer, at least 1 | `1024` | [`TOOL_RUNTIME_QUEUE_DEPTH`](configuration.md#tool_runtime_queue_depth) |
| `tool_runtime.global_concurrency` | integer, at least 1 | `64` | [`TOOL_RUNTIME_GLOBAL_CONCURRENCY`](configuration.md#tool_runtime_global_concurrency) |
| `tool_runtime.queue_timeout_ms` | integer milliseconds, at least 1 | `1000` | [`TOOL_RUNTIME_QUEUE_TIMEOUT_MS`](configuration.md#tool_runtime_queue_timeout_ms) |
| `tool_runtime.lease_ttl_ms` | integer milliseconds, at least 1000 | `15000` | [`TOOL_LEASE_TTL_MS`](configuration.md#tool_lease_ttl_ms) |
| `tool_runtime.default_timeout_ms` | integer milliseconds, at least 1 | `30000` | [`TOOL_RUNTIME_DEFAULT_TIMEOUT_MS`](configuration.md#tool_runtime_default_timeout_ms) |

#### `spec.cluster`

Cluster identity, membership, readiness and status, in cluster mode.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `cluster.heartbeat_ms` | integer milliseconds, at least 1000 | `5000` | [`CLUSTER_HEARTBEAT_MS`](configuration.md#cluster_heartbeat_ms) |
| `cluster.member_stale_ms` | integer milliseconds, at least 1 | `30000` | [`CLUSTER_MEMBER_STALE_MS`](configuration.md#cluster_member_stale_ms) |
| `cluster.maintenance_interval_ms` | integer milliseconds, at least 1000 | `60000` | [`CLUSTER_MAINTENANCE_INTERVAL_MS`](configuration.md#cluster_maintenance_interval_ms) |
| `cluster.maintenance_lease_ttl_ms` | integer milliseconds, at least 1000 | `15000` | [`CLUSTER_MAINTENANCE_LEASE_TTL_MS`](configuration.md#cluster_maintenance_lease_ttl_ms) |
| `cluster.readiness_probe_cache_ms` | integer milliseconds, 0 to 60000 | `1000` | [`READINESS_PROBE_CACHE_MS`](configuration.md#readiness_probe_cache_ms) |
| `cluster.status_expose_hostnames` | `true` or `false` | `false` | [`CLUSTER_STATUS_EXPOSE_HOSTNAMES`](configuration.md#cluster_status_expose_hostnames) |
| `cluster.deployment_id` | string | unset | [`DEPLOYMENT_ID`](configuration.md#deployment_id) |

#### `spec.csrf`

Cross-site request forgery protection for cookie-authenticated requests.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `csrf.enabled` | `true` or `false` | `true` | [`CSRF_ENABLED`](configuration.md#csrf_enabled) |
| `csrf.cookie_name` | string | `"csrf_token"` | [`CSRF_COOKIE_NAME`](configuration.md#csrf_cookie_name) |
| `csrf.header_name` | string | `"x-csrf-token"` | [`CSRF_HEADER_NAME`](configuration.md#csrf_header_name) |
| `csrf.cookie_domain` | string | unset | [`CSRF_COOKIE_DOMAIN`](configuration.md#csrf_cookie_domain) |
| `csrf.exempt_paths` | array of strings | `["/health", "/livez", "/startupz", "/readyz", "/version", "/metrics"]` | [`CSRF_EXEMPT_PATHS`](configuration.md#csrf_exempt_paths) |

#### `spec.upstream`

The single upstream or the upstream routes, the MCP upstream servers, and the timeouts of proxied requests.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `upstream.url` | secret reference | unset | [`UPSTREAM_URL`](configuration.md#upstream_url) |
| `upstream.routes` | array of [upstream route](#upstream-route) objects | unset | [`UPSTREAM_ROUTES`](configuration.md#upstream_routes) |
| `upstream.mcp_servers` | array of [MCP upstream server](#mcp-upstream-server) objects | unset | [`MCP_UPSTREAM_SERVERS`](configuration.md#mcp_upstream_servers) |
| `upstream.timeout_ms` | integer milliseconds, at least 1 | follows `egress.timeout_ms` | [`UPSTREAM_TIMEOUT_MS`](configuration.md#upstream_timeout_ms) |
| `upstream.response_idle_timeout_ms` | integer milliseconds, at least 1 | follows `egress.response_idle_timeout_ms` | [`UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS`](configuration.md#upstream_response_idle_timeout_ms) |
| `upstream.connect_timeout_ms` | integer milliseconds, at least 1 | follows `egress.connect_timeout_ms` | [`UPSTREAM_CONNECT_TIMEOUT_MS`](configuration.md#upstream_connect_timeout_ms) |

#### `spec.egress`

Requests the gateway itself sends.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `egress.allowed_hosts` | array of strings | unset | [`EGRESS_ALLOWED_HOSTS`](configuration.md#egress_allowed_hosts) |
| `egress.timeout_ms` | integer milliseconds, at least 1 | `30000` | [`EGRESS_TIMEOUT_MS`](configuration.md#egress_timeout_ms) |
| `egress.response_idle_timeout_ms` | integer milliseconds, at least 1 | `30000` | [`EGRESS_RESPONSE_IDLE_TIMEOUT_MS`](configuration.md#egress_response_idle_timeout_ms) |
| `egress.connect_timeout_ms` | integer milliseconds, at least 1 | `10000` | [`EGRESS_CONNECT_TIMEOUT_MS`](configuration.md#egress_connect_timeout_ms) |
| `egress.max_response_bytes` | integer bytes, at least 0 | `5242880` | [`EGRESS_MAX_RESPONSE_BYTES`](configuration.md#egress_max_response_bytes) |
| `egress.max_request_body_bytes` | integer bytes, at least 0 | `1048576` | [`EGRESS_MAX_REQUEST_BODY_BYTES`](configuration.md#egress_max_request_body_bytes) |
| `egress.nat64_prefixes` | array of strings | unset | [`EGRESS_NAT64_PREFIXES`](configuration.md#egress_nat64_prefixes) |
| `egress.deny_private_addresses` | `true` or `false` | `true` | [`EGRESS_DENY_PRIVATE_IPS`](configuration.md#egress_deny_private_ips) |

#### `spec.state`

The state backend and, in standalone mode, the stores kept beneath the state directory.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `state.backend` | `sqlite` or `postgres` | `"sqlite"` | [`STATE_BACKEND`](configuration.md#state_backend) |
| `state.postgres.tls_mode` | `verify` or `loopback-dev` | `"verify"` | [`DATABASE_TLS_MODE`](configuration.md#database_tls_mode) |
| `state.postgres.pool_max` | integer, 1 to 256 | `10` | [`DATABASE_POOL_MAX`](configuration.md#database_pool_max) |
| `state.postgres.connect_timeout_ms` | integer milliseconds, at least 1 | `5000` | [`DATABASE_CONNECT_TIMEOUT_MS`](configuration.md#database_connect_timeout_ms) |
| `state.postgres.acquire_timeout_ms` | integer milliseconds, at least 1 | `5000` | [`DATABASE_ACQUIRE_TIMEOUT_MS`](configuration.md#database_acquire_timeout_ms) |
| `state.postgres.statement_timeout_ms` | integer milliseconds, at least 1 | `15000` | [`DATABASE_STATEMENT_TIMEOUT_MS`](configuration.md#database_statement_timeout_ms) |
| `state.postgres.idle_in_transaction_timeout_ms` | integer milliseconds, at least 1 | `30000` | [`DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS`](configuration.md#database_idle_in_transaction_timeout_ms) |
| `state.postgres.lock_timeout_ms` | integer milliseconds, at least 1 | `5000` | [`DATABASE_LOCK_TIMEOUT_MS`](configuration.md#database_lock_timeout_ms) |
| `state.postgres.startup_retry_limit` | integer, 0 to 300 | `5` | [`DATABASE_STARTUP_RETRY_LIMIT`](configuration.md#database_startup_retry_limit) |
| `state.postgres.auto_migrate` | `true` or `false` | `false` | [`DATABASE_AUTO_MIGRATE`](configuration.md#database_auto_migrate) |
| `state.postgres.migration_statement_timeout_ms` | integer milliseconds, 1 to 600000 | `60000` | [`DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS`](configuration.md#database_migration_statement_timeout_ms) |
| `state.stores` | array of distinct `audit`, `discovery`, `principals`, `connections` and `service_tokens` | unset | which of `AUDIT_SQLITE_PATH`, `DISCOVERY_SQLITE_PATH`, `PRINCIPAL_SQLITE_PATH`, `CONNECTIONS_SQLITE_PATH` and `SERVICE_TOKEN_SQLITE_PATH` are set |

#### `spec.authority_evidence`

Authority evidence and its event delivery.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `authority_evidence.durability` | `required` or `best_effort` | `"best_effort"` | [`AUTHORITY_EVIDENCE_DURABILITY`](configuration.md#authority_evidence_durability) |
| `authority_evidence.event_sink` | `none`, `log` or `file` | `"none"` | [`AUTHORITY_EVENT_SINK`](configuration.md#authority_event_sink) |
| `authority_evidence.pseudonym_key_alias` | string | unset | [`AUTHORITY_PSEUDONYM_KEY_ALIAS`](configuration.md#authority_pseudonym_key_alias) |
| `authority_evidence.previous_pseudonym_key_alias` | string | unset | [`AUTHORITY_PSEUDONYM_PREVIOUS_KEY_ALIAS`](configuration.md#authority_pseudonym_previous_key_alias) |
| `authority_evidence.event_journal_capacity` | integer, 1 to 1000000000 | `1000000` | [`AUTHORITY_EVENT_JOURNAL_CAPACITY`](configuration.md#authority_event_journal_capacity) |
| `authority_evidence.event_retention_hours` | integer hours, 0 to 87600 | `168` | [`AUTHORITY_EVENT_RETENTION_HOURS`](configuration.md#authority_event_retention_hours) |

#### `spec.compatibility`

The compatibility behaviors a migration document acknowledges.

| Member | Value | Default | Environment mode |
| --- | --- | --- | --- |
| `compatibility.acknowledged` | array of distinct `policy_default_allow`, `policy_shadow_mode` and `wildcard_role` | unset | none: environment mode has no profile |

#### Authentication provider

One authentication provider, an AUTH_PROVIDERS entry. client_id, client_secret and redirect_uri, which only the admin login provider reads, are set under spec.admin_login.

| Member | Value |
| --- | --- |
| `name` | string, required |
| `type` | `jwt` or `cookie_session`, required |
| `jwks_url` | string |
| `issuer` | string |
| `audience` | string |
| `jwks_timeout_ms` | integer, 0 to 9007199254740991 |
| `jwks_max_key_age_secs` | integer, 0 to 9007199254740991 |
| `require_jti` | `true` or `false` |
| `roles_claim` | string |
| `roles_claim_delimiter` | string, kept exactly as written |
| `org_claim` | string |
| `verified_claims` | array of strings |
| `introspection_url` | string |
| `introspection_timeout_ms` | integer, 0 to 9007199254740991 |
| `cache_ttl_ms` | integer, 0 to 9007199254740991 |
| `user_id_claim` | string |
| `email_claim` | string |
| `client_id` | not here: set `admin_login.client_id` |
| `client_secret` | not here: set `admin_login.client_secret` |
| `redirect_uri` | not here: set `admin_login.redirect_uri` |

#### Upstream route

One upstream route, an UPSTREAM_ROUTES entry.

| Member | Value |
| --- | --- |
| `id` | string |
| `forward_cookie_session` | `true` or `false` |
| `body_limit_profile` | `greenpm_research_v1` |
| `upstream_csrf_cookie_name` | string |
| `connection_id` | string |
| `path_prefix` | string |
| `host` | string |
| `upstream_url` | secret reference |
| `upstreams` | array of [upstream endpoint](#upstream-endpoint) objects |
| `load_balancing` | [upstream load balancing](#upstream-load-balancing) object |
| `request_body` | [upstream request body](#upstream-request-body) object |
| `sse` | [upstream server-sent events](#upstream-server-sent-events) object |
| `websocket` | [upstream WebSocket](#upstream-websocket) object |
| `grpc` | [upstream gRPC](#upstream-grpc) object |
| `limits` | [upstream limits](#upstream-limits) object |
| `health_check` | [upstream health check](#upstream-health-check) object |
| `retry` | [upstream retry](#upstream-retry) object |
| `circuit_breaker` | [upstream circuit breaker](#upstream-circuit-breaker) object |
| `timeout_ms` | integer, 0 to 9007199254740991 |
| `response_idle_timeout_ms` | integer, 0 to 9007199254740991 |
| `connect_timeout_ms` | integer, 0 to 9007199254740991 |
| `add_request_headers` | not representable: only `{}`; use a managed Connection |
| `strip_request_headers` | array of strings |
| `tls_ca_bundle_path` | not representable: a host path |
| `openapi_spec_path` | not representable: a host path |

#### Upstream endpoint

One endpoint of an upstream route's pool.

| Member | Value |
| --- | --- |
| `id` | string, required |
| `url` | secret reference, required |
| `weight` | integer, 0 to 65535 |
| `tls_ca_bundle_path` | not representable: a host path |
| `client_identity_pem_path` | not representable: a host path |

#### Upstream load balancing

How a route's pool chooses an endpoint.

| Member | Value |
| --- | --- |
| `strategy` | `weighted_round_robin` |

#### Upstream request body

How a route forwards request bodies.

| Member | Value |
| --- | --- |
| `mode` | `buffered` or `stream` |

#### Upstream server-sent events

A route's server-sent event streams.

| Member | Value |
| --- | --- |
| `max_duration_ms` | integer, 0 to 9007199254740991 |
| `max_response_bytes` | integer, 0 to 9007199254740991 |

#### Upstream WebSocket

A route's WebSocket proxying.

| Member | Value |
| --- | --- |
| `max_connections` | integer, 0 to 9007199254740991 |
| `max_connections_per_endpoint` | integer, 0 to 9007199254740991 |
| `queue_depth` | integer, 0 to 9007199254740991 |
| `queue_timeout_ms` | integer, 0 to 9007199254740991 |
| `handshake_timeout_ms` | integer, 0 to 9007199254740991 |
| `idle_timeout_ms` | integer, 0 to 9007199254740991 |
| `max_duration_ms` | integer, 0 to 9007199254740991 |
| `max_frame_bytes` | integer, 0 to 9007199254740991 |
| `max_message_bytes` | integer, 0 to 9007199254740991 |
| `max_write_buffer_bytes` | integer, 0 to 9007199254740991 |
| `allowed_origins` | array of strings |
| `require_origin` | `true` or `false` |
| `allowed_subprotocols` | array of strings |

#### Upstream gRPC

A route's transparent gRPC proxying.

| Member | Value |
| --- | --- |
| `max_concurrent_calls` | integer, 0 to 9007199254740991 |
| `max_concurrent_calls_per_endpoint` | integer, 0 to 9007199254740991 |
| `queue_depth` | integer, 0 to 9007199254740991 |
| `queue_timeout_ms` | integer, 0 to 9007199254740991 |
| `connect_timeout_ms` | integer, 0 to 9007199254740991 |
| `idle_timeout_ms` | integer, 0 to 9007199254740991 |
| `max_duration_ms` | integer, 0 to 9007199254740991 |
| `max_message_bytes` | integer, 0 to 9007199254740991 |
| `max_request_bytes` | integer, 0 to 9007199254740991 |
| `max_response_bytes` | integer, 0 to 9007199254740991 |
| `max_metadata_entries` | integer, 0 to 9007199254740991 |

#### Upstream limits

A route's in-flight and queue bounds.

| Member | Value |
| --- | --- |
| `max_in_flight` | integer, 0 to 9007199254740991 |
| `queue_depth` | integer, 0 to 9007199254740991 |
| `queue_timeout_ms` | integer, 0 to 9007199254740991 |

#### Upstream health check

Active and passive health checks of a route's pool.

| Member | Value |
| --- | --- |
| `method` | string |
| `path` | string |
| `interval_ms` | integer, 0 to 9007199254740991 |
| `jitter_ms` | integer, 0 to 9007199254740991 |
| `timeout_ms` | integer, 0 to 9007199254740991 |
| `healthy_threshold` | integer, 0 to 4294967295 |
| `unhealthy_threshold` | integer, 0 to 4294967295 |
| `expected_statuses` | array of integers, 0 to 65535 |
| `passive_failure_statuses` | array of integers, 0 to 65535 |
| `required_for_readiness` | `true` or `false` |
| `minimum_healthy` | integer, 0 to 9007199254740991 |

#### Upstream retry

Which failed requests a route retries.

| Member | Value |
| --- | --- |
| `max_attempts` | integer, 0 to 255 |
| `methods` | array of strings |
| `statuses` | array of integers, 0 to 65535 |

#### Upstream circuit breaker

When a route stops sending to a failing endpoint.

| Member | Value |
| --- | --- |
| `failure_threshold` | integer, 0 to 4294967295 |
| `open_ms` | integer, 0 to 9007199254740991 |
| `half_open_max_requests` | integer, 0 to 4294967295 |
| `recovery_threshold` | integer, 0 to 4294967295 |

#### MCP upstream server

One MCP upstream server, an MCP_UPSTREAM_SERVERS entry.

| Member | Value |
| --- | --- |
| `name` | string, required |
| `url` | secret reference, required |
| `timeout_ms` | integer, 0 to 9007199254740991 |
| `response_idle_timeout_ms` | integer, 0 to 9007199254740991 |
| `connect_timeout_ms` | integer, 0 to 9007199254740991 |

<!-- deployment-settings:end -->

## Referenced policy and tools documents

A bundle pins its policy and tools documents but does not redefine them. Each is
read as strict JSON (a duplicate member is refused, never overwritten), its
`schema_version` must equal the version the manifest declares
(`resource.schema_version_mismatch`), and the manifest may declare only a version
this reader implements (`resource.unsupported_schema_version`). Then:

- a policy document may not have a top-level member the policy loader would warn
  about and drop (`resource.unknown_member`), and must pass both
  [`policy.v0.schema.json`](schemas/policy.v0.schema.json) and the production
  policy validator;
- a tools document must pass both
  [`tools.v0.schema.json`](schemas/tools.v0.schema.json) and the production tools
  validator, which applies the same schema first.

A failure of either is `resource.invalid`. Validator messages can quote document
values, so they are not repeated.

The production validators are the validating parses the gateway's policy and
tools loaders run in environment mode, and they live in the shared
`gateway-config` library with the reader (`gateway_config::rbac` and
`gateway_config::tools`; issue #242). The reader takes them from its caller as
`ResourceValidators`, and the gateway and every `ggctl` command pass the same
`ProductionValidators`, so a bundle `ggctl validate` accepts is one the gateway's
loaders accept.

## Deployment profiles

A bundled policy is held to the deployment profile's policy invariants
([ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md#initialization-profiles))
once it has passed its schema:

| Profile | Policy invariants |
| --- | --- |
| `production` | Deny by default (`profile.policy_default_allow` for `default_action: allow`), enforce mode (`profile.policy_shadow_mode` for `enforcement_mode: shadow` at the top level or on any route), and no role granting the `*` wildcard permission (`profile.wildcard_role`). |
| `migration` | The production invariants, except that each behavior the deployment document lists under `compatibility.acknowledged` (`policy_default_allow`, `policy_shadow_mode`, `wildcard_role`) is reported as a warning with the same code instead of an error, so the bundle is read and every report still shows it. A behavior it does not acknowledge is an error, as in `production`. |
| `development` | None. |

An absent `default_action` is `deny` and an absent `enforcement_mode` is
`enforce`, as in environment mode. Role names are policy values, so a wildcard
role is reported at `/roles` and the line of its `*`, never by name. A policy left
to the server's store (`source: server`) is not checked by the reader. The
profiles' other invariants (authentication, egress, CSRF, audit durability,
listeners) concern deployment settings, which the reader checks for shape and
bounds only: they are enforced once the compiler reads a deployment document, a
later #242 slice. Until then a `production` document that, say, turns
authentication off is accepted by the reader, and no gateway can start from it.

## Generated bundles

`ggctl init --profile PROFILE --output DIR` writes a bundle that the reader
accepts strictly with the production policy and tools validators, which `init`
reads it back with, and `gateway-config`'s tests hold every one it can write to
them and to the policy enforcement it configures. The output is deterministic:
the same profile and answers always give the same bytes, and so the same
digests. `init` writes only the profile into the deployment document. Every
setting it leaves out keeps its default, which is already what the production
profile asks for (authentication required, private-address egress denied, CSRF
on, required audit durability), so what `init` writes is the same safe starting
point for every profile:

| File | Standalone topology (default) | Cluster topology |
| --- | --- | --- |
| `bundle.yaml` | Pins every file below; `connections` from the server | Policy, tools and Connections all from the server, which is their writer in cluster mode (the PostgreSQL control planes) |
| `deployment.yaml` | `spec.profile`, with a comment marking `development` and `migration` as not for production | The same |
| `policy.json` | `default_action: deny`, `enforcement_mode: enforce`, no route, and no role unless the answers bind an operator | Not written |
| `tools.json` | No tools | Not written |
| `.gitattributes` | `* text eol=lf`, so a Windows checkout cannot change a pinned file's bytes; the reader ignores it | The same |

The permissive starter policy (`docs/examples/policy.starter.json`) is never
written. No file holds a secret or a credential, and nothing is generated that
would need one.

The defaults can be replaced by a `GatewayInitAnswers` document
([schema](schemas/gateway-init-answers.v1alpha1.schema.json)), given with
`--answers FILE` and read under the same rules as a bundle document (the YAML
subset, or strict JSON when the file name ends in `.json`; LF line endings;
closed objects; at most 64 KiB):

```yaml
apiVersion: greengateway.dev/v1alpha1
kind: GatewayInitAnswers
spec:
  name: payments            # metadata.name and the policy id; default greengateway
  topology: standalone      # or cluster
  operator:                 # standalone only
    issuer: "provider:corporate"
    auth_methods: [bearer_token]
```

Every member is an ordinary value, and none can hold a secret value. The profile
is not an answer: it is `--profile`. `operator` generates a policy role named
`operator` bound to exactly that issuer and those authentication methods
(at least one), granting `admin:config:read` and `admin:status:read` with a
`GET` route for each under the default admin prefix (`/v1/admin/config`,
`/v1/admin/status`): enough for the [version handshake](ggctl.md#version-handshake)
and the status read, and nothing that changes anything. The issuer is an exact
`https` issuer without a user name, password, query or fragment (trailing slashes
are dropped, as the gateway compares issuers), or the `provider:<name>`
boundary of an authentication provider configured without an issuer, with the
name percent-encoded as the gateway encodes it. `operator` with
`topology: cluster` is `schema.not_applicable`, because a cluster's policy is the
server's. With a custom `ADMIN_PREFIX`, edit the two routes, then run `ggctl pin`
to update the policy's pin.

## Digests

- **File pins.** Each referenced file's `sha256` is checked against its exact
  bytes before the file is parsed (`bundle.digest_mismatch`), so a document whose
  bytes differ from what was reviewed is never interpreted. Pins are what
  `sha256sum` prints, so CI and reviewers can verify them with standard tools.
- **Re-pinning.** [`ggctl pin BUNDLE`](ggctl.md#pin) is the only command that
  rewrites pins, and it pins only files that validate. It reads the bundle with
  this reader and every check but the pin comparison, and writes nothing unless
  they all pass. Then it replaces only the digits of each pin that differs from
  its file's SHA-256, so the rest of `bundle.yaml` stays byte for byte, comments
  and order included, and replaces `bundle.yaml` atomically (a new hidden file,
  flushed, renamed over it). A pin it must change has to be written as its 64
  digits between double or single quotes, as `ggctl init` writes it; any other
  spelling is `reference.pin_not_rewritable`. A linked `bundle.yaml`, as in a
  Kubernetes atomic-writer volume, is never replaced. After an edit, run
  `ggctl pin` and review the change together with the file it pins.
- **Source digest.** The bundle's identity is `sha256:` and 64 lowercase hex
  digits over ADR-0004's `GGDIGEST` frame of the manifest's exact bytes, with
  kind `source`, media type `application/vnd.greengateway.bundle+yaml`, and the
  manifest's `apiVersion` as the schema version. Because the manifest pins every
  other file, it identifies the whole bundle.
- **Canonical form.** Bundle documents are compared and hashed as their RFC 8785
  canonical JSON, which is the same whether the document was written as YAML or
  JSON and whatever its member order or formatting.

A digest is integrity metadata. It does not make an unsigned bundle trusted,
verified, or authentic; control who can change the delivery channel (branch
protection, Kubernetes RBAC on the ConfigMaps, admission policy).

Two read bundles can be compared semantically: by their validated manifest,
deployment, policy and tools documents rather than their text, with each
change classified by how it takes effect and what it weakens, under stable
risk codes and with no value shown: `ggctl diff BUNDLE --against BUNDLE`
([reference](ggctl.md#diff), [semantic diff](semantic-diff.md)).

## Files and the directory

The reader canonicalizes the bundle root once and opens it as a capability. Each
file is then opened beneath it by one name, without following links, checked on
the opened handle, and read once into memory under its byte bound; nothing is
reopened. Specifically:

- **Names.** A referenced file name matches `^[a-z0-9][a-z0-9._-]{0,62}$`, does
  not end in `.`, and is not a Windows device name (`con`, `prn`, `aux`, `nul`,
  `com0`-`com9`, `lpt0`-`lpt9`, with or without an extension); otherwise
  `reference.invalid_path`. Lowercase only, so valid names never collide under
  case folding, and no separator, `..`, drive, or `:` stream suffix can be
  written. A name must match a directory entry exactly, so on a case-insensitive
  filesystem `policy.json` does not open `POLICY.JSON` (`bundle.file_missing`,
  `bundle.manifest_missing`).
- **Flat and regular.** Symbolic links, junctions, and reparse points are
  refused wherever they are (`bundle.symlink_forbidden`); so are subdirectories
  and special files (`bundle.not_regular_file`) and files with more than one hard
  link (`bundle.hard_link_forbidden`).
- **Dot entries** (`.git`, `.gitattributes`) are ignored and never opened. Any
  other entry the manifest does not reference is a warning
  (`bundle.unreferenced_entry`) and, when reading strictly, an error.
- **Permissions (Unix).** The directory files are read from (a flat bundle's
  root, or the generation directory of the layout below) and each file must not
  be writable by group or other (`bundle.unsafe_permissions`). The sticky bit
  does not relax this: it stops another account replacing an entry, not adding
  one, so in a sticky world-writable directory such as `/tmp` that account could
  add a `bundle.yaml` or a referenced file before the operator does. Only the
  root of the Kubernetes layout below may be world-writable, and only with the
  sticky bit, which is how the kubelet publishes volume roots; nothing is read
  from it but `..data` and the generation it names. A read-only mount does not
  relax these checks in this alpha.
- **Ownership (Unix).** Each file must be owned by root or by the account that
  owns the directory it is read from, and the generation directory by root or
  by the owner of the volume root (`bundle.untrusted_owner`): any other owner
  could change a file whatever its mode says. Files the kubelet writes, a
  checkout or copy made by one account, and a bind mount whose files and
  directory belong to one host account all pass; an archive unpacked as root
  that kept another account's ownership does not until it is `chown`ed. Windows
  ACLs remain an operator and platform responsibility, as they are for
  `CONNECTION_SECRETS_ROOT`.
- **Kubernetes ConfigMap and projected volumes.** When the root contains
  `..data`, it must be a symbolic link to one sibling directory whose name starts
  with `..`, and every other non-dot entry at the root must be one of the
  kubelet's per-key links. The reader resolves `..data` once, reads every file as
  a regular file from that one generation, and never follows the per-key links,
  so an update in the middle of a read cannot mix two generations. Anything else
  is `bundle.atomic_writer_invalid`.
- **Bounds.** Per-file bounds (`bundle.file_too_large`), the 4 MiB total
  (`bundle.bundle_too_large`), and the 256-entry listing bound
  (`bundle.too_many_entries`) are checked from metadata before a byte is
  allocated, and again while reading; a file whose length changes during the
  read is `bundle.changed_during_read`.
- **Text.** Every file is UTF-8 (`bundle.not_utf8`) without a byte-order mark
  (`bundle.byte_order_mark`) and with LF line endings (`bundle.carriage_return`).
  Add a `.gitattributes` with `* text eol=lf` to the bundle's directory so a
  Windows checkout with `core.autocrlf` cannot change a digest. Bundle documents
  (not policy or tools) also may not contain C0 or C1 control characters other
  than tab and line feed, DEL, the byte-order mark, bidirectional formatting
  characters, or the line and paragraph separators U+2028 and U+2029 (which,
  like NEL, YAML 1.1 readers treat as line breaks), anywhere including comments
  and escapes (`syntax.forbidden_character`): a reviewer, another YAML reader,
  and the gateway must not read the same bytes differently.

Bundles are directories only. There is no archive form of a bundle, so no
archive reader sits in the configuration path; the
[standalone backup](standalone-backup.md) archive has its own reader, which
applies the [archive entry admission rules](archive-admission.md).

## The YAML subset

The manifest and a `.yaml` deployment document are read by a reader for a small
subset of YAML 1.2, so that a reviewer and the gateway can never read the same
file differently. It accepts:

- one document, optionally preceded by `---`;
- block mappings and block sequences indented with spaces, including a sequence
  written at its key's indentation and a mapping or sequence that starts on a
  `- ` line;
- flow sequences and mappings (`[a, b]`, `{ secret: idp-client }`) that close on
  the line they open, without trailing commas;
- double-quoted strings with exactly the JSON escapes (`\" \\ \/ \b \f \n \r \t \uXXXX`),
  single-quoted strings (`''` for a quote), and plain scalars, each ending on the
  line it starts;
- `#` comments, after whitespace.

A **plain (unquoted) scalar** is `true`, `false`, `null`, an RFC 8259 integer
(`0`, `-7`, `8443`), or a string that starts with an ASCII letter, `_`, `/`, or a
non-ASCII character and is not one of the YAML 1.1 boolean or null words in any
case. Anything else must be quoted (`yaml.ambiguous_scalar`): for example `yes`,
`No`, `ON`, `~`, `Null`, `TRUE`, `0x1F`, `017`, `1_000`, `12:30`, `2026-10-21`, `1.5`,
`.inf`, `-foo`, `0.0.0.0:8080`, and any hex digest that starts with a digit.
A plain key is an identifier (`[A-Za-z_][A-Za-z0-9_.-]*`) that is not a boolean or
null word; quote any other key (`yaml.key_must_be_quoted`, `yaml.non_string_key`).

Refused, each with its own code:

| Construct | Code |
| --- | --- |
| Anchors `&a` and aliases `*a` | `yaml.anchor_forbidden`, `yaml.alias_forbidden` |
| Tags `!t`, `!!str` | `yaml.tag_forbidden` |
| Merge keys `<<` | `yaml.merge_key_forbidden` |
| Directives `%YAML`, `%TAG` | `yaml.directive_forbidden` |
| A second document, or `...` | `yaml.multiple_documents` |
| Explicit `? ` keys and collection keys | `yaml.complex_key_forbidden` |
| Keys another reader would type as a boolean, null, or number | `yaml.non_string_key` |
| Block scalars `\|` and `>` | `yaml.block_scalar_forbidden` |
| Multi-line plain, quoted, or flow values | `yaml.multiline_value_forbidden` |
| YAML-only escapes (`\x41`, `\0`, `\N`, lone surrogates, ...) | `yaml.unsupported_escape` |
| Tabs outside quoted strings and comments | `yaml.tab_forbidden` |
| Inconsistent indentation | `yaml.bad_indentation` |
| A key or item with no value (write `null`) | `yaml.empty_value` |
| A key given twice | `yaml.duplicate_key` |
| Anything else outside the subset | `yaml.syntax_error` |

There are no includes, globs, remote URLs, templates, shell expansion,
environment interpolation, Git directives, or code. Every path in a manifest is
one file name in the bundle root, never relative to the caller's working
directory.

## Strict JSON

A `.json` deployment document and the policy and tools documents are read by a
strict RFC 8259 reader: a duplicate member name is `json.duplicate_key` (it is
refused when the second one is met, before any value could be replaced), and
trailing content, comments, single quotes, trailing commas, leading zeros, `NaN`,
`Infinity`, unescaped control characters, and lone surrogates are
`json.syntax_error`. In bundle documents a number with a fraction or exponent is
`syntax.number_not_integer` and an integer beyond the safe range is
`syntax.integer_out_of_range`; policy and tools documents keep their own
validators' number rules.

## Structural bounds

Applied while parsing, before the value they limit is built. A bound is a
ceiling; nothing raises one, and zero never means unlimited.

| Dimension | Bundle documents | Policy and tools documents |
| --- | --- | --- |
| Nested collections | 32 (`syntax.too_deep`) | 32 |
| Members per object | 1,024 (`syntax.too_many_members`) | their validators' limits |
| Elements per array | 4,096 (`syntax.too_many_elements`) | their validators' limits |
| Values per document | 65,536 (`syntax.too_many_nodes`) | their validators' limits |
| String | 64 KiB (`syntax.string_too_long`) | their validators' limits |
| Object key | 128 bytes (`syntax.key_too_long`) | their validators' limits |

An empty document is `syntax.empty_document`.

The deployment document can use up to 512 secret references across all
settings, including nested route endpoints and MCP servers. Each occurrence
counts, even when multiple settings refer to the same alias. The reader checks
this limit before it builds the typed settings.

## The state directory

**Not yet selectable.** In bundle mode with standalone stores, and in ledger
mode, a standalone deployment will keep every local store beneath one
directory, `GATEWAY_STATE_DIR`, under the fixed names below
([ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md#bundle-mode)). Those
modes replace each store's environment variable with its fixed name, so they
will refuse the variable. No gateway reads `GATEWAY_STATE_DIR` yet, and in
environment mode every store stays where its variable puts it. The layout, the
admission rules and the lock are the shared `gateway-config` library's
`state_dir` module, which the gateway and `ggctl` both use. Today the revision
ledger, the `ggctl ledger` commands over it, and `ggctl backup create` and
`ggctl backup restore` ([standalone backups](standalone-backup.md)) are the only
things that open through it.

| File | Store | Environment-mode variable |
| --- | --- | --- |
| `audit.sqlite3` | The audit store of record | `AUDIT_SQLITE_PATH` |
| `discovery.sqlite3` | Discovered endpoints and sampled request shapes | `DISCOVERY_SQLITE_PATH` |
| `principals.sqlite3` | The principal directory | `PRINCIPAL_SQLITE_PATH` |
| `connections.sqlite3` | Connections and their credential bindings | `CONNECTIONS_SQLITE_PATH` |
| `service-tokens.sqlite3` | Service tokens | `SERVICE_TOKEN_SQLITE_PATH` |
| `policy-history.sqlite3` | Policy publication history | `POLICY_HISTORY_SQLITE_PATH` |
| `config-ledger.sqlite3` | The [configuration revision ledger](configuration-ledger.md) | none |
| `state.lock` | The directory's lock file | none |
| `restore-marker.json` | The [restore marker](standalone-backup.md#the-restore-marker) `ggctl backup restore` leaves for the next gateway start, which records it and removes it | none |

SQLite keeps `-wal`, `-shm` and `-journal` files beside each store; they belong
to it. A test holds this table to the field catalog: every store the catalog
replaces with a fixed file has exactly one name here. The names never change
meaning, and a store that moves gets a new one. Admin sessions have no file:
the standalone store (`ADMIN_SESSION_MODE=standalone_memory`) lives in process
memory, so a restart still ends every session
([ADR-0009](adr/0009-shared-admin-sessions.md)). Connections key files stay
under `CONNECTION_SECRETS_ROOT`, outside the state directory. The policy history
name is fixed now so no later store can take it. Bundle mode will decide
whether it keeps a policy history beside a bundle-owned policy; in ledger mode
the ledger is the history.

**Admission.** The state directory must be a real directory: not a symbolic
link, junction or other reparse point, and on Unix not writable by group or
other, who could otherwise replace a store. It is checked by path, then opened
without following a link at its last component and checked again on the open
handle. Links in the directories above it are followed, since only someone who
can write those can redirect the path. Windows ACLs remain the operator's
responsibility, as they are for bundle directories.

**The lock.** Opening the state directory takes an exclusive operating-system
advisory lock on `state.lock` (`flock` on Unix, `LockFileEx` on Windows),
opened beneath the admitted directory without following a link. It never
waits: if another process, or another handle in the same process, holds the
lock, the attempt fails with `state_dir.locked`, which the `ggctl ledger`
commands, the ones that open a state directory, exit with as code 5. The lock is held for as long as the handle and every store opened
through it live, and is released when the last of them closes or the process
exits. An open ledger keeps it held. The lock file is created empty and
owner-only on Unix. Its content is never read or written, and it is never
removed: removing a held lock file would let a second process lock a new file
of the same name. The lock is advisory. It keeps the gateway and `ggctl` apart,
not other programs, and whoever can write the state directory controls the
deployment.

**Network filesystems.** Locks and SQLite are unsupported on network
filesystems (ADR-0002). A best-effort check recognises the common ones so that
`ggctl doctor` can warn with `state_dir.network_filesystem`. It is never a
reason to refuse, because a filesystem the check does not recognise is no proof
of a local disk:

- Linux: `statfs` magic numbers for NFS, SMB, CIFS, SMB2, NCP, Coda, AFS, Ceph,
  9P (which includes WSL 2's Windows drives), Lustre and GPFS. FUSE mounts are
  not reported, because `sshfs` and `ntfs-3g` share one magic number.
- macOS: `statfs` type names `nfs`, `smbfs`, `afpfs`, `webdav` and `ftp`.
- Windows: a canonical UNC path, which is what Windows resolves a mapped network
  drive to.

| Code | Meaning | `ggctl` exit (ADR-0008) |
| --- | --- | --- |
| `state_dir.missing` | Nothing is at the path. | 3 |
| `state_dir.not_directory` | The path names something other than a directory. | 3 |
| `state_dir.link` | The path is a symbolic link, junction or reparse point. | 3 |
| `state_dir.unsafe_permissions` | On Unix, the directory is writable by group or other. | 3 |
| `state_dir.unsafe_lock_file` | `state.lock` is a link, not a regular file, or on Unix writable by group or other. | 3 |
| `state_dir.locked` | Another process, or another handle in this one, holds the lock. | 5 |
| `state_dir.lock_unsupported` | The filesystem cannot take the lock, so exclusive use cannot be promised. | 3 |
| `state_dir.unavailable` | The directory or the lock file could not be inspected, opened or locked. | 1 |
| `state_dir.network_filesystem` | A warning: the directory is on a recognised network filesystem. | none |

The codes are value-free like every other: no path and no operating-system
message.

## Diagnostics

Every problem is reported, not just the first, as a diagnostic with a stable
`family.reason` code, a severity, the bundle-relative file name, a JSON Pointer,
and a line and column:

```text
bundle.yaml:8:13: error[reference.invalid_digest]: a pinned digest is not 64 lowercase hexadecimal digits (at /spec/deployment/sha256)
```

Diagnostics are value-free by construction: the message is fixed text chosen by
the code, the file name is one that passed the file-name grammar, and the pointer
is built from member names the reader itself defines. An unknown member is
reported at its parent's pointer and its own line and column, never by its name.
No document value, host path, environment value, or validator or library message
can appear in one. A published code never changes meaning.

| Code | Meaning |
| --- | --- |
| `bundle.root_unavailable` | The bundle directory cannot be opened. |
| `bundle.root_not_directory` | The bundle location is not a directory. |
| `bundle.unsafe_permissions` | A bundle directory or file is writable by group or other. |
| `bundle.untrusted_owner` | A bundle file or generation directory is owned by an account other than root or the owner of the directory holding it. |
| `bundle.too_many_entries` | The directory holds more than 256 entries. |
| `bundle.manifest_missing` | There is no `bundle.yaml`. |
| `bundle.file_missing` | A referenced file is not in the bundle. |
| `bundle.symlink_forbidden` | An entry is a symbolic link, junction, or reparse point. |
| `bundle.not_regular_file` | An entry is a directory or special file. |
| `bundle.hard_link_forbidden` | A file has more than one hard link. |
| `bundle.file_too_large` | A file is larger than its kind allows. |
| `bundle.bundle_too_large` | The referenced files exceed 4 MiB together. |
| `bundle.read_failed` | A file could not be read. |
| `bundle.changed_during_read` | A file changed while it was being read. |
| `bundle.atomic_writer_invalid` | The `..data` layout is not one resolvable generation. |
| `bundle.unreferenced_entry` | An entry is not referenced by the manifest (warning; an error when strict). |
| `bundle.byte_order_mark` | A file starts with a byte-order mark. |
| `bundle.carriage_return` | A file contains a carriage return. |
| `bundle.not_utf8` | A file is not valid UTF-8. |
| `bundle.digest_mismatch` | A file's SHA-256 differs from its pin. |
| `syntax.empty_document` | The document is empty. |
| `syntax.too_deep` | Too many nested collections. |
| `syntax.too_many_members` | An object has too many members. |
| `syntax.too_many_elements` | An array has too many elements. |
| `syntax.too_many_nodes` | The document has too many values. |
| `syntax.string_too_long` | A string is too long. |
| `syntax.key_too_long` | An object key is too long. |
| `syntax.number_not_integer` | A number in a bundle document is not an integer. |
| `syntax.integer_out_of_range` | An integer is outside the I-JSON safe range. |
| `syntax.forbidden_character` | A control, bidirectional formatting, or line or paragraph separator character. |
| `json.syntax_error` | Not valid JSON. |
| `json.duplicate_key` | An object names a member twice. |
| `yaml.syntax_error` | Outside the YAML subset. |
| `yaml.duplicate_key` | A mapping names a key twice. |
| `yaml.alias_forbidden` | A YAML alias. |
| `yaml.anchor_forbidden` | A YAML anchor. |
| `yaml.tag_forbidden` | A YAML tag. |
| `yaml.merge_key_forbidden` | A YAML merge key. |
| `yaml.directive_forbidden` | A YAML directive. |
| `yaml.multiple_documents` | More than one YAML document. |
| `yaml.complex_key_forbidden` | An explicit or collection key. |
| `yaml.non_string_key` | A key that would be read as a boolean, null, or number. |
| `yaml.key_must_be_quoted` | A key outside the plain identifier form. |
| `yaml.ambiguous_scalar` | An unquoted value another reader could type differently. |
| `yaml.block_scalar_forbidden` | A literal or folded block scalar. |
| `yaml.multiline_value_forbidden` | A value that does not end on the line it starts. |
| `yaml.unsupported_escape` | An escape outside the JSON set. |
| `yaml.tab_forbidden` | A tab outside quoted strings and comments. |
| `yaml.bad_indentation` | Inconsistent indentation. |
| `yaml.empty_value` | A key or item with no value. |
| `compat.unsupported_api_version` | An `apiVersion` this reader does not implement. |
| `compat.unsupported_kind` | A `kind` other than the one expected. |
| `schema.unknown_member` | A member the document version does not define. |
| `schema.missing_member` | A required member is missing. |
| `schema.wrong_type` | A value has the wrong type. |
| `schema.invalid_value` | A value the document version does not allow. |
| `schema.invalid_name` | `metadata.name` is not a lowercase DNS label. |
| `schema.invalid_decimal` | A decimal outside the decimal grammar. |
| `schema.not_applicable` | A member that does not apply given another member's value, such as an init answers `operator` with `topology: cluster`, or an acknowledged compatibility behavior outside the `migration` profile. |
| `schema.not_representable` | A member this document version has no form for: a host path, a literal static request header. The reference says what to use instead. |
| `reference.invalid_path` | A referenced name is not a portable file name of the right type. |
| `reference.reserved_path` | A reference names `bundle.yaml`. |
| `reference.duplicate_path` | Two references name the same file. |
| `reference.invalid_digest` | A pin is not 64 lowercase hex digits. |
| `reference.pin_not_rewritable` | `ggctl pin` must change a pin that is not written as its 64 digits between quotes (plain, or with escapes), so it cannot replace it in place; quote it. |
| `reference.source_unsupported` | The resource cannot come from this source in this version. |
| `reference.unresolved` | An unresolved placeholder. |
| `secret.inline_value` | A sensitive setting holds a literal value. |
| `secret.invalid_reference` | A secret reference is not a single opaque alias ID. |
| `secret.too_many_references` | The deployment exceeds 512 secret references. Repeated uses of an alias count separately across all settings. |
| `resource.unsupported_schema_version` | The manifest declares a resource version this reader does not implement. |
| `resource.schema_version_mismatch` | The resource's `schema_version` differs from the declared one. |
| `resource.unknown_member` | A policy top-level member the loader would drop. |
| `resource.invalid` | The resource fails its published schema or production validator. |
| `profile.policy_default_allow` | The profile requires a deny-by-default policy. |
| `profile.policy_shadow_mode` | The profile requires the policy to enforce its decisions, not shadow them. |
| `profile.wildcard_role` | The profile forbids a role that grants every permission. |
