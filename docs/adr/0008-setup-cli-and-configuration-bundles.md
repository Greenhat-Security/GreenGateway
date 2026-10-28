# ADR-0008: Setup, Operator CLI, and Configuration Bundles

## Status

Proposed. Submitted for maintainer acceptance as issue #242 PR 1 (ADR and threat model).

This ADR is documentation-only. It ships no runtime code, schema file, endpoint, permission, environment variable, binary, or migration. Every variable, command, route, permission, schema identifier, diagnostic code, risk code, and bound below is a proposed contract name, not a claim that the current gateway recognizes it; the #242 slice that implements each one (see [Rollout](#rollout)) must add and test it before anything advertises it. Until a maintainer accepts this ADR, later #242 slices treat it as the design under review rather than as settled.

This decision was prepared against main commit `198ab93b92509e4355a937d874b63a117708824f`. Later slices re-check the anchors below against their own base.

## Context

### What exists today

- **One server binary with environment-only configuration.** `gateway` with no arguments compiles its configuration from the environment (`gateway/src/config.rs`) and serves. The input inventory from #433 PR 1 (`gateway/src/config/inventory.rs`) lists 134 variables that `Config::from_env_vars` requests. Several hold JSON documents (`AUTH_PROVIDERS`, `UPSTREAM_ROUTES`, `MCP_UPSTREAM_SERVERS`, `CONNECTION_SECRET_ALIASES`, the `CONNECTION_*_PROVIDER` objects), and much of the validation is cross-field. Value-free diagnostics for those inputs exist (`gateway/src/config/diagnostic.rs`). `Config::from_env_vars` now runs #433 PR 2's pure parse and validate stages for every domain (`gateway/src/config/plan.rs`), which return a validated plan that carries secret locators rather than secrets. Serving startup consumes that plan (#433 PR 3, `bootstrap::start_serving` in `gateway/src/bootstrap.rs`): the compiler runs first and alone, with nothing but the environment reader, and file, store, provider and network work happens only in the preflight, activation and serving stages after it, in the order startup has always done it. The compiler contract documentation (#433 PR 4) has not landed.
- **One-shot operator commands already live on the server binary.** `gateway/src/bootstrap.rs` dispatches `healthcheck`, `migrate check|up`, `import-standalone`, `revoke-jwt`, `jwt-revocations-cleanup`, `rate-limit-buckets-cleanup`, `cluster-members`, `maintenance-run`, and `connection-secrets reencrypt|ensure-key-unused` before it parses configuration for serving. They run where the database credentials and network already are: inside the image, typically as a Kubernetes Job.
- **Drift checks cover names only.** `gateway/tests/env_example.rs` holds `.env.example` and the Cloudflare forwarding list (`cloudflare/src/config.ts`) to the variables the source reads. Nothing machine-readable records a field's type, default, sensitivity, reload class, or platform support.
- **Resource documents have their own authorities.** Policy (`POLICY_FILE`, `docs/schemas/policy.v0.schema.json`) and tools (`TOOLS_FILE`, `docs/schemas/tools.v0.schema.json`) have their own validators, ETags, and watcher and SIGHUP reload paths, and policy has a separate SQLite history. [The authority-evidence contract](../authority-evidence.md) records that file persistence, reload, and history are separate steps with no common transaction, and that #425's standalone evidence work waits on a #242 ledger. Both validators accept any `0.` schema version, and the policy loader warns on unknown top-level members and then ignores them.
- **Canonical digests exist.** `gateway/src/canonical_json.rs` implements RFC 8785 JCS over the I-JSON integer domain and the ADR-0004 `GGDIGEST` frame. It refuses fractional numbers, while five settings (`PAYLOAD_CAPTURE_SAMPLE_RATE`, `RATE_LIMIT_READ_RPS`, `RATE_LIMIT_WRITE_RPS`, `ERROR_RATE_SPIKE_SIGNAL_THRESHOLD`, and `VOLUME_OUTLIER_SIGNAL_THRESHOLD`) are `f64` today.
- **The dependency epics have landed.** #239 (lifecycle probes `/livez`, `/startupz`, and `/readyz`, and drain budgets), #240 (Connections, the opaque-ID `SecretResolver`, and the operator, encrypted-local, Vault, GCP, Azure, AWS, and Kubernetes secret providers), and #241 (cluster mode, the PostgreSQL control planes, the checksummed migration ledger, the standalone import, and the static-configuration fingerprint) are closed. ADR-0005, ADR-0006, and ADR-0007 record their contracts. #433 (configuration compiler), #425 (authority evidence), #424 (cookie sessions as the normal admin UI flow), and #243 (Policy Studio, ADR-0004) are open.
- **Container posture.** The image is distroless and runs as `10001:10001`. `deploy/kubernetes/greengateway.example.yaml` supplies configuration through `envFrom` with one ConfigMap and one Secret, uses a read-only root filesystem, and wires #239's probes. Listener certificates mounted by the kubelet are already watched and reloaded when the `..data` symlink flips.

### The problem

Operators assemble up to 134 variables by hand, several of them JSON inside environment strings. There is no offline validation that is guaranteed to agree with startup, no semantic diff a reviewer can read in a pull request, no stable exit codes for CI, no truthful record of desired versus active state, and no secure first-run path. Each of those is easy to add badly: a configuration file that silently overrides policy becomes a second authority, a CLI that approximates the gateway's rules becomes a weaker validator, exports and diffs leak secrets, and a setup route becomes a takeover race.

### Maintainer direction

The design is platform agnostic and cloud-native first. Containers and Kubernetes are the primary target, the twelve-factor environment model stays first-class, and bundles are GitOps-friendly: deterministic, reviewable, and deliverable by any pull-based controller without GreenGateway knowing which one. It fails closed. Bundles contain secret references only, never secret values.

## Scope

This ADR fixes, for every later #242 slice:

- terminology, source modes, and the authority of each source;
- the bundle layout, document kinds, reference forms, parser safety rules, digests, and compatibility policy;
- hard input bounds;
- the initialization profiles and the bootstrap model, including the local first-run wizard;
- revision, activation, drift, and rollback semantics per mode;
- the `ggctl` command tree, output contract, exit codes, and diagnostic code format;
- the admin API resources, permissions, and status codes;
- doctor, export, backup, and renderer boundaries;
- the threat model; and
- the dependency boundaries with #239, #240, #241, #243, #425, and #433.

## Non-goals

This decision does not introduce, and later slices must not add without amending it:

- Multi-tenancy (ADR-0002 is unchanged).
- A route on a running gateway where a request claims administrator access, or any unauthenticated setup mutation surface.
- A Git client, repository polling, webhook receiver, remote include, template language, environment interpolation, or executable configuration hook.
- Automatic Docker, Kubernetes, Cloudflare, package-manager, or operating-system mutation. Renderers produce files and exact instructions; the platform applies them.
- A self-updater, an install script piped into a shell, telemetry, or any network request `ggctl` was not explicitly asked to make.
- Plaintext secret storage in bundles, answers, exports, history, browser storage, process arguments, logs, or backups.
- A replacement for #240's secret providers or #241's database migration, import, and point-in-time recovery procedures.
- Atomicity across an external secret manager, a Kubernetes rollout, PostgreSQL, and local files. Atomicity is stated per authority below and nowhere else.
- Self-restart. GreenGateway never restarts itself to activate configuration.
- Authenticity. A content digest is integrity metadata. Signed bundles may follow under their own decision.
- Deprecating environment configuration.

## Terminology

| Term | Meaning |
| --- | --- |
| Environment mode | Startup with no configuration source selected: today's `Config::from_env` behavior, exactly. The issue calls it legacy environment mode; this ADR does not, because it is a supported twelve-factor mode and is not deprecated. |
| Bundle mode | Startup from a read-only bundle directory selected by bootstrap variables. |
| Ledger mode | Standalone startup from the gateway's own revision ledger, which online apply can advance. |
| Bootstrap input | One of the closed set of environment variables that may accompany a bundle: source selection, host locators for mounted material, and secret-provider configuration. |
| Deployment configuration | Listeners, authentication providers, admin login, routing, egress, storage selection, limits, public URL, cookie, CORS, CSRF and trusted-proxy behavior, and the other mostly restart-scoped settings. |
| Control-plane resource | Policy, tools, and Connections, each governed by its own validator, store, and revision contract. |
| Bundle | A flat directory holding one manifest, one deployment document, and the resource documents or references the manifest names. |
| Secret reference | An opaque #240 alias ID in a sensitive field. It is not a secret value, a locator, or a fingerprint of one. |
| Host locator | A filesystem path to mounted material (certificate, CA, CRL, secret root, DSN file, log file). Host locators are bootstrap inputs and never bundle content. |
| Configuration compiler | The one side-effect-free library that turns any source into a typed, validated candidate. Gateway startup and `ggctl` both call it. |
| Candidate | The compiled, normalized result of one source, carrying references and per-field provenance and no resolved secrets. |
| Field catalog | The machine-readable table describing every configuration field (see [Configuration compiler and field catalog](#configuration-compiler-and-field-catalog)). |
| apiVersion and kind | The exact document format identifier, for example `greengateway.dev/v1alpha1` and `GatewayBundle`. Compatibility is decided per exact pair. |
| Revision | An immutable desired-state generation in the standalone ledger. It is distinct from document versions, the binary version, database migration versions, and #241's security revision. |
| Desired revision | The revision an operator selected to run next. |
| Active revision | The revision the running process compiled and is enforcing. |
| Restart pending | Desired differs from active because the change cannot activate in the running process. |
| Drift | The active state, or a pinned resource the bundle references, no longer matches what the selected source says. |
| Plan | A server-computed, owner-scoped, expiring record of one candidate's semantic diff, risk codes, required permissions, and activation class, which apply binds to. |

## Decision

This entire Decision section defines target architecture for #242. Environment mode, the existing policy and tools APIs, the PostgreSQL control planes, and the existing one-shot commands remain authoritative and unchanged until the slice that replaces a given path proves parity.

### Design principles

1. **One compiler.** Gateway startup, `ggctl validate`, `ggctl diff`, plans, and offline doctor call the same parser and semantic validator. No caller approximates it.
2. **Configuration is delivered, not fetched.** The gateway reads what the platform put on its filesystem and environment. It never contacts Git, a registry, or a configuration service.
3. **The platform owns rollout.** For containers, a configuration change is a new release: new bundle, new pods. GreenGateway reports what it is running; it does not hot-swap restart-scoped state or restart itself.
4. **One writer per resource per mode.** Every resource has exactly one writer in each mode. A bundle never forks a store, and a store never silently overrides a bundle.
5. **References, never values.** A secret reaches a bundle only as an opaque alias ID. Host paths reach it not at all.
6. **Fail closed, explain without echoing.** Ambiguous, unknown, conflicting, oversized, stale, or incomplete input refuses with a stable code that names the field and never the value.
7. **Truthful state.** Staged is never reported as active; skipped is never reported as passed; unsupported is never reported as success.

How the decision maps to the twelve-factor model:

- **Config.** Environment mode is unchanged and fully supported. In bundle mode the environment still carries what genuinely differs per running process or platform: source selection, mount locations, secret-provider wiring, and the secrets those providers read.
- **Build, release, run.** A release is identified by the image digest plus the bundle source digest. Both are immutable, and `ggctl deploy render` writes both into the rendered manifests.
- **Disposability.** Bundle-mode configuration activates at process start and drains through #239's lifecycle. A pod that cannot compile its bundle exits before binding a listener.
- **Logs and backing services.** Unchanged: audit and logs go where they go today, and PostgreSQL remains a backing service configured by reference (`DATABASE_URL_FILE`).

### Source modes

A new bootstrap variable, `GATEWAY_CONFIG_SOURCE`, selects one mode. Unset is environment mode.

| Mode | Selection | Desired-state authority | How it changes | State backends |
| --- | --- | --- | --- | --- |
| Environment | `GATEWAY_CONFIG_SOURCE` unset or `environment` | The process environment | Restart with a new environment; policy and tools as today | `sqlite`, `postgres` |
| Bundle | `GATEWAY_CONFIG_SOURCE=bundle` plus `GATEWAY_CONFIG_BUNDLE` (a read-only directory) and, for standalone stores, `GATEWAY_STATE_DIR` | The mounted bundle | A new bundle and a new process: a rollout, a container recreate, or a service restart | `sqlite`, `postgres` |
| Ledger | `GATEWAY_CONFIG_SOURCE=ledger` plus `GATEWAY_STATE_DIR` | The standalone revision ledger beneath the state directory | Conditional online apply; restart-class revisions activate at the next start | `sqlite` only |

Rules:

- **Environment mode is exact.** Its defaults, precedence, error aggregation, legacy single-provider `JWT_*` fallback, dynamic exemption defaults, and relative-path behavior keep golden parity (#433). Nothing is migrated, rewritten, or newly warned about. The only new refusal is that `GATEWAY_CONFIG_BUNDLE` or `GATEWAY_STATE_DIR` set without a matching `GATEWAY_CONFIG_SOURCE` fails startup with `source.selector_without_mode`; neither name exists today, and material a mode will never read is refused rather than ignored, as ADR-0002 already does for cluster-only settings.
- **Each mode refuses the selectors it will not read.** Ledger mode refuses `GATEWAY_CONFIG_BUNDLE`. Bundle mode refuses `GATEWAY_STATE_DIR` when the state backend is `postgres` or no standalone store is enabled, because a local store beside cluster authority is exactly what ADR-0002 rejects.
- **Bundle and ledger modes reject overlapping environment.** Any inventoried configuration variable outside the [bootstrap set](#bootstrap-inputs) that is present in the environment, including present and empty, fails startup with `source.conflicting_environment`. The diagnostic names each variable and never its value. There is no precedence switch and no "environment wins" rule.
- **No interpolation.** Bundle documents cannot read the environment. A value that differs between environments lives in a separate bundle (for example one Kustomize overlay or one directory per environment) and is rendered deterministically.
- **Provenance is per field.** The candidate records each field's source as `default`, `environment`, `bundle`, `ledger`, `bootstrap`, or `store`. Status, diff, and the Setup Center show field identifiers and source kinds only, so an operator can see why a field is read-only without seeing its value or locator.
- **Cluster replicas compile the same way.** In cluster mode each replica mounts its bundle and compiles it at start. The static-configuration fingerprint is computed from the compiled `Config` today (`static_config_fingerprint` in `gateway/src/ha.rs`) and must stay so: the source mode is not part of it, and a bundle's decimal strings must parse to exactly the `f64` values the equivalent environment strings produce. A fleet moving from environment to bundle delivery with identical effective settings therefore rolls rather than stalling at the fingerprint door; a fleet changing a fingerprinted setting still needs ADR-0007's coordinated cutover.

#### Bootstrap inputs

In bundle and ledger modes, exactly these may be present in the environment. Changing the set requires amending this ADR; the field catalog makes the classification machine-readable once it lands (PR 3).

| Category | Variables | Why they stay in the environment |
| --- | --- | --- |
| Source selection | `GATEWAY_CONFIG_SOURCE`, `GATEWAY_CONFIG_BUNDLE`, `GATEWAY_STATE_DIR` | They locate the configuration and cannot be inside it. |
| Host locators for mounted material | `TLS_CERT_FILE`, `TLS_KEY_FILE`, `ADMIN_TLS_CERT_FILE`, `ADMIN_TLS_KEY_FILE`, `CLIENT_CERT_CA_FILE`, `CLIENT_CERT_CRL_FILE`, `ADMIN_CLIENT_CERT_CA_FILE`, `ADMIN_CLIENT_CERT_CRL_FILE`, `CONNECTION_SECRETS_ROOT`, `DATABASE_URL_FILE`, `DATABASE_TLS_CA_FILE`, `AUDIT_LOG_FILE` | Mount paths differ between Compose, Kubernetes, and hosts, and host paths must never enter a bundle or export. The bundle states intent (for example `tls: required`); the compiler fails closed when the intent and the locator disagree in either direction. Rotating the mounted material keeps working as today and is not a configuration change. |
| Secret-provider wiring | `CONNECTION_SECRET_ALIASES`, `CONNECTION_LOCAL_SECRET_KEYRING`, `CONNECTION_VAULT_PROVIDER`, `CONNECTION_GCP_PROVIDER`, `CONNECTION_AZURE_PROVIDER`, `CONNECTION_AWS_PROVIDER`, `CONNECTION_KUBERNETES_PROVIDER`, `ADMIN_LOGIN_KEYRING`, `RATE_LIMIT_KEYRING`, and every variable an `environment` alias names | They map opaque alias IDs to locators, which ADR-0006 treats as trusted startup configuration, never admin or bundle input. |
| Platform and process | Variables the gateway does not inventory as configuration, such as `HOSTNAME`, `COMPUTERNAME`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, and `RUST_*` | They are not GreenGateway configuration. Doctor reports `SSL_CERT_FILE` and `SSL_CERT_DIR` because they change trust anchors. |

Everything else inventoried today maps to a deployment-document field, or is not representable in bundle mode and is refused there:

- `POLICY_FILE`, `TOOLS_FILE`, `POLICY_HISTORY_SQLITE_PATH`, and every `*_SQLITE_PATH` are replaced by bundle resources and by fixed file names beneath `GATEWAY_STATE_DIR`. The bundle declares which standalone stores are enabled; PR 4 fixes their file names.
- The single-provider `JWT_*` fallback is not representable: a bundle names its authentication providers explicitly.
- `OPENAPI_SPEC_PATH` is not representable in `v1alpha1`; managed Connections (ADR-0006) provide OpenAPI discovery. A later document version may add an OpenAPI resource kind.
- Literal credential values in `UPSTREAM_ROUTES` `add_request_headers` and inline `AUTH_PROVIDERS` `client_secret` values are not representable. Credentials use secret references or managed Connections. PR 4 decides whether non-credential literal headers are representable; until then the field is classified sensitive and export treats it as such.

#### Resource ownership

| Resource | Environment mode | Bundle mode, standalone | Bundle mode, cluster | Ledger mode |
| --- | --- | --- | --- | --- |
| Deployment configuration | Environment | The bundle, read-only | Each replica's bundle, held to the fingerprint door | Ledger revision |
| Policy | `POLICY_FILE` and its history, as today | The bundle's policy file; admin writes refused | PostgreSQL policy control plane, as today; the bundle may only pin | Ledger revision |
| Tools | `TOOLS_FILE`, as today | The bundle's tools file; admin writes refused | PostgreSQL tools control plane, as today; the bundle may only pin | Ledger revision |
| Connections and credential bindings | Connections SQLite or PostgreSQL, as today | Connections SQLite beneath the state directory; never bundle content in `v1alpha1` | PostgreSQL, as today | Connections SQLite beneath the state directory |
| Secret material | #240 providers | #240 providers | #240 providers | #240 providers |
| Database schema | `gateway migrate` | `gateway migrate` | `gateway migrate` | Not applicable |

A refused write answers `409 Conflict` with reason `resource_managed_by_bundle`. The remedy is a new bundle, so Policy Studio publication, suggestion acceptance, shadow promotion, and tool registration are refused in standalone bundle mode rather than written somewhere the next rollout would discard. An operator who wants interactive edits on a single node chooses ledger mode.

A pin (`source: server` with an expected digest) never writes and never affects readiness. A mismatch is drift, reported in protected status and metrics. Drift deliberately does not fail readiness: during an ordinary rollout old and new replicas see different pins, and turning that into unreadiness would make every resource change an outage.

### Bundle format

#### Layout and delivery

A `v1alpha1` bundle is a **flat directory**. Flat matches the Kubernetes ConfigMap key model and makes containment trivial.

- The manifest has the fixed name `bundle.yaml`.
- Every other file is named by the manifest and matches `^[a-z0-9][a-z0-9._-]{0,62}$`, does not end in `.`, and is not a Windows reserved device name. Lowercase-only names make case-fold collisions impossible by construction.
- The deployment document may be `.yaml` or `.json`. Policy and tools documents are `.json`, because their production validators read JSON.
- Files are UTF-8 without a byte-order mark and use LF line endings; a CR byte fails validation with `bundle.carriage_return`. `ggctl init` writes a `.gitattributes` that pins LF for the bundle's files, so a Windows checkout with `core.autocrlf` cannot silently change a digest.
- The reader opens only files the manifest names. It ignores entries whose names begin with `.`. Any other unreferenced entry is a warning (`bundle.unreferenced_entry`) and an error under `--strict`.
- Bundles are directories only. Archive input for bundles is not part of `v1alpha1`; the only archive this ADR defines is the backup archive.

Delivery is the platform's choice:

| Delivery | How | Notes |
| --- | --- | --- |
| Kubernetes | One or more **immutable** ConfigMaps named with the bundle source digest, combined into one directory by a `projected` volume mounted `readOnly` | A ConfigMap holds at most 1 MiB, so a bundle may span several ConfigMaps; digest-named immutable ConfigMaps change the pod template whenever content changes, which is what triggers the rollout. |
| Container image | A derived image that copies the bundle into a read-only path | The bundle digest is fixed by the image digest. |
| Compose, systemd, or a host | A read-only bind mount or a root-owned directory | `ggctl deploy render --target compose` emits the mount. |

**Kubernetes atomic-writer layout.** The kubelet publishes ConfigMap and projected volumes as a `..data` symlink to a timestamped sibling directory, with one top-level symlink per key. When the bundle root contains `..data`, the reader requires it to be a symlink whose target is one sibling name beginning with `..`, resolves it **once**, and reads every referenced file from that one generation directory as regular files. It never follows the per-key symlinks. Any other symlink, junction, or reparse point anywhere in the bundle is refused. Reading one resolved generation means a ConfigMap update in the middle of a read cannot mix two generations; the digest checks below catch anything else. This follows the precedent `DATABASE_URL_FILE` already sets for Kubernetes Secret volumes.

**Handles and metadata.** Each file is opened without following links, checked on the opened handle to be a regular file with one link and within its byte bound, read once into memory, and validated from that buffer; nothing is reopened. The configured root is canonicalized once at startup. On Unix the directory files are read from, and each file, must not be group- or other-writable unless the filesystem is mounted read-only, as a `readOnly` Kubernetes volume is. Special files, hard links, device names, and alternate data streams are refused. Windows enforces the reparse-point, regular-file, and name rules; ACL ownership remains an operator and platform responsibility, as it is for `CONNECTION_SECRETS_ROOT`.

#### Manifest

Field names are illustrative; the PR 4 schema is normative.

```yaml
apiVersion: greengateway.dev/v1alpha1
kind: GatewayBundle
metadata:
  name: payments-production
spec:
  deployment:
    path: deployment.yaml
    sha256: "<64 lowercase hex digits>"
  resources:
    policy:
      source: bundle
      path: policy.json
      schema_version: "0.1.0"
      sha256: "<64 lowercase hex digits>"
    tools:
      source: bundle
      path: tools.json
      schema_version: "0.1.0"
      sha256: "<64 lowercase hex digits>"
    connections:
      source: server
```

`source: bundle` means the bundle is the resource's only writer in that mode (see [Resource ownership](#resource-ownership)). `source: server` means the existing store is the writer; it may carry an expected digest as a drift pin. Connections accept only `server` in `v1alpha1`. The declared `schema_version` must equal the version the referenced document declares, exactly, and the gateway must implement that exact version; this makes resource compatibility exact at the bundle boundary without changing the environment-mode validators.

#### Deployment document

```yaml
apiVersion: greengateway.dev/v1alpha1
kind: GatewayDeployment
spec:
  profile: production
  listeners:
    public: { address: "0.0.0.0:8080", tls: required }
    admin: { address: "0.0.0.0:9443", tls: required, prefix: /admin }
  public_url: https://gateway.example.com
  authentication:
    providers:
      - name: corporate
        type: jwt
        issuer: https://idp.example.com
        audience: greengateway
  admin_login:
    provider: corporate
    client_id: greengateway-admin
    client_secret: { secret: idp-client }
  egress:
    deny_private_addresses: true
  state:
    backend: sqlite
```

Again illustrative: the field catalog (PR 3) and schema (PR 4) define the names. The document uses snake_case like the existing policy, tools, and Connection documents, inside the Kubernetes-style `apiVersion`/`kind`/`metadata`/`spec` envelope so that a future custom resource could embed the same `spec` unchanged.

**Typed values that the canonical form needs:**

- **Secret references.** A sensitive field accepts only `{ secret: <alias-id> }`, where the ID follows ADR-0006's grammar and lives in the one alias namespace #240 already maintains. The field's catalog entry fixes the secret purpose and byte bound. A plain string in a sensitive field fails with `secret.inline_value`, and the diagnostic never contains the string. The form cannot express an environment-variable name, file path, provider locator, ciphertext, or value.
- **Unresolved placeholders.** `{ unresolved: <reason-code> }` marks a value that export, conversion, or a template could not or would not supply (`legacy_inline_secret`, `template_value`, `not_representable`). Validation always fails on it with `reference.unresolved`, so an output that contains one can never be mistaken for a deployable bundle.
- **Decimals.** Fractional settings are JSON strings in the grammar `^(0|[1-9][0-9]{0,15})(\.[0-9]{1,6})?$`, normalized to their shortest exact form before hashing (`"0.10"` becomes `"0.1"`). JSON numbers in configuration documents are integers within the I-JSON safe range, which is the domain `canonical_json.rs` already enforces. Floating-point is never parsed from a JSON number.

#### Parser safety

Before typed deserialization:

- **YAML is a safe subset.** Anchors, aliases, merge keys, tags, multiple documents, complex or non-string keys, and duplicate keys are refused. A plain scalar is accepted only as a JSON literal (`true`, `false`, `null`), a JSON integer, or an unambiguous string. Plain scalars that another YAML 1.1 or 1.2 reader would type differently (`yes`, `no`, `on`, `off`, `y`, `n`, `~`, `Null`, `TRUE`, `0x1F`, `0o17`, `017`, `1_000`, `12:30`, `2026-10-21`, `.inf`, `.nan`, and similar) are refused with `yaml.ambiguous_scalar` and must be quoted. A reviewer and the gateway must never read the same file differently.
- **JSON is strict.** Duplicate member names, non-finite numbers, and trailing content are refused. Duplicate detection happens in the parser, before any map is built that would keep only the last value.
- **Unknown members are refused** in every bundle document and, in bundle and ledger modes, in every referenced resource. A referenced resource must pass its published JSON Schema and its production validator, and the reader additionally refuses any member either would ignore. For policy `0.1.0` that is any unknown top-level member, which the published schema admits and the loader drops with a warning, so warn-and-ignore cannot drop data in these modes. Environment mode is unchanged.
- **Exact formats.** No includes, globs, remote URLs, templates, shell expansion, environment interpolation, Git directives, or code.
- **Relative to the bundle.** Every path in a manifest is one file name in the bundle root, never relative to the caller's working directory.
- **Bounded before allocation.** The limits in [Bounds](#bounds) apply while reading and parsing, not after.

#### Digests

Three digests, each with one job:

| Digest | Over | Form | Used for |
| --- | --- | --- | --- |
| File pin | The exact bytes of one referenced file | `sha256` lowercase hex in the manifest | Integrity of each file; verifiable with standard tools (`sha256sum`) in CI or by a reviewer |
| Source digest | The exact manifest bytes, framed with ADR-0004's `GGDIGEST` frame (`kind` `source`, media type `application/vnd.greengateway.bundle+yaml`, schema version the manifest's `apiVersion`) | `sha256:` and 64 lowercase hex digits | Identity of the whole source bundle, transitively through the pins; ConfigMap names and rollout annotations |
| Semantic digest | The RFC 8785 bytes of the normalized compiled candidate, framed with `kind` `semantic` | `sha256:` and 64 lowercase hex digits | Meaning, insensitive to formatting and member order: no-op detection, plans, risk acknowledgments, revision identity |

A referenced resource whose document version has no normative normalization (policy and tools `0.1.0` today; ADR-0004 gives such a version no semantic digest) contributes its source digest to the semantic digest rather than an invented normalization. A digest is integrity metadata. Documentation never calls an unsigned bundle trusted, verified, or authentic.

`ggctl pin` is the only command that rewrites manifest digests, and it pins only files that validate.

#### Compatibility and versions

- A reader accepts only the exact `(apiVersion, kind)` pairs it implements. `v1alpha1` is the only version this ADR defines. There is no prefix match, no "any alpha", and no downgrade.
- Changing a document version is explicit: `ggctl convert` is deterministic and idempotent, writes create-new or replaces atomically on request, and refuses to downgrade.
- A release that introduces a new document version keeps reading the previous version for at least one minor release, so a fleet can finish a rolling upgrade before its bundles are converted.
- A gateway that does not implement a bundle's version refuses to start; `ggctl` exits `3`.

#### Published schemas

Draft 2020-12 schemas under `https://greengateway.dev/schemas/`, beside the existing ones:

| Kind | Proposed file | Lands in |
| --- | --- | --- |
| `GatewayBundle` | `docs/schemas/gateway-bundle.v1alpha1.schema.json` | PR 4 |
| `GatewayDeployment` | `docs/schemas/gateway-deployment.v1alpha1.schema.json` | PR 4 |
| `GatewayInitAnswers` | `docs/schemas/gateway-init-answers.v1alpha1.schema.json` | PR 6 |
| `GgctlReport` (validate, doctor, diff, and plan output) | `docs/schemas/ggctl-report.v1alpha1.schema.json` | PR 5 and PR 8 |
| `GatewayBackup` (backup manifest) | `docs/schemas/gateway-backup.v1alpha1.schema.json` | PR 15 |
| Admin API DTOs | The OpenAPI 3.1 admin document | PR 12 |

An export is a bundle (see [Export, backup, and restore](#export-backup-and-restore)), so reference-only export and import use the bundle schemas plus the unresolved placeholder; there is no separate import format. JSON Schema is necessary but not sufficient: the Rust semantic validator is authoritative.

### Configuration compiler and field catalog

The compiler is #433's extraction, which this epic consumes as its PR 2. Environment variables and bundle documents are two front ends into one raw input model, followed by the same stages:

1. bounded source reading and safe syntax parsing;
2. exact document validation;
3. deterministic normalization;
4. typing of secret references and host-locator intents, without resolution;
5. cross-field and cross-resource semantic validation;
6. optional local filesystem checks (existence, type, permissions, containment);
7. optional runtime preflight (stores, providers, network) — gateway startup and server-side diagnostics only; and
8. activation.

Stages 1–5 perform no file mutation, store open or migration, DNS, TLS, HTTP, OIDC, MCP, provider, or upstream work, and are callable without application state. `ggctl` links stages 1–6. Stage 7 runs only inside a gateway process, with its production clients.

The field catalog (PR 3) is a table in the shared library with, per field: stable identifier and document path; environment variable name; type, default, bounds, and normalization; sensitivity, secret purpose, and safe display; exportability and whether the value is environment-specific (for templates); bootstrap category, if any; reload class (`live`, `restart`, or `bootstrap`); whether it is in the static-configuration fingerprint; support per platform (native, Compose, Kubernetes, Cloudflare) with a reason for every exclusion; and the doctor checks and documentation anchor. The bundle schema, environment mapping, `.env.example` and `docs/configuration.md` coverage, `ggctl` help and redaction, the Cloudflare forwarding list and its documented exclusions, and renderer coverage are generated from it or parity-checked against it, replacing today's name-only checks.

### Bounds

Compile-time ceilings. Configuration may lower a ceiling where a later slice exposes it; nothing raises one, and zero never means unlimited. The structural limits (depth, members, elements, nodes, scalars, keys) apply to `GatewayBundle` and `GatewayDeployment` documents; a referenced policy or tools document keeps its own validator's limits plus the byte and depth ceilings here, so a document environment mode accepts today is not refused for its size alone.

| Dimension | Ceiling |
| --- | --- |
| Manifest | 64 KiB |
| Deployment document | 1 MiB |
| Policy or tools document | The existing 1 MiB each |
| Total bundle bytes | 4 MiB |
| Files a manifest references | 16 |
| Directory entries examined in a bundle root | 256 |
| Nesting depth | 32 |
| Members per object | 1,024 |
| Elements per array | 4,096 |
| Nodes per document | 65,536 |
| String scalar | 64 KiB, lower where the catalog says |
| Object key | 128 bytes |
| Identifiers (names, alias IDs) | 128 bytes, matching ADR-0006 |
| Secret references per bundle | 512, matching the alias limit |
| Plan lifetime | 15 minutes |
| Risk acknowledgment lifetime | 10 minutes, and never beyond its plan |
| Live plans | 8 per actor, 64 per deployment |
| Revisions retained in the ledger | 1,024; pruning never removes the active or desired revision |
| Revision list page | 100 entries |
| `ggctl` response body | 8 MiB |
| `ggctl` request timeout | 30 seconds by default, at most 300 |
| `ggctl apply --wait` | 10 minutes by default, at most 30 |
| Local wizard request body | 64 KiB |

### Initialization profiles

`spec.profile` is enforced by the compiler at validation and at startup, not just used as a set of `init` defaults.

| Profile | Enforced invariants |
| --- | --- |
| `production` | Authentication required; policy default deny; enforce mode, no shadow; private-address egress denied; CSRF enabled; durable audit; no wildcard (`*`) role; no credential sent to an upstream, token endpoint, or provider over plain HTTP; every sensitive value a secret reference. Inbound TLS may terminate at an ingress or load balancer instead of the listener. `init` writes no upstreams, routes, CORS origins, or trusted proxies. |
| `migration` | The production invariants, except that each compatibility behavior — default allow, shadow or observe mode, broadened exemptions, literal route headers, and similar — is permitted only when the document lists its code under `spec.compatibility.acknowledged`. Each listed behavior is a warning in every report and a risk code in every plan. |
| `development` | Every listener binds a loopback address, and startup refuses a non-loopback bind. Every report labels the deployment non-production. Placeholder credentials are generated only for loopback evaluation. |

The repository's permissive starter policy (`docs/examples/policy.starter.json`, default allow) never becomes a production default. Environment mode has no profile; doctor can evaluate an environment against the production profile as advice.

### Bootstrap model

**Creating the first configuration.** `ggctl init --profile P --output DIR` builds a bundle offline; no gateway needs to be running. It prompts only on a terminal; non-interactive use takes a versioned `GatewayInitAnswers` document that holds ordinary values and secret references only and cannot represent a secret value. It writes into a new staging directory beside the destination, validates every artifact with the compiler, flushes where the platform supports it, and renames into place. It refuses a non-empty destination, never overwrites without an explicit, narrowly scoped flag, and leaves nothing that looks like a valid bundle if interrupted. Output is not group- or other-writable on Unix; on a platform where `ggctl` cannot establish that, it fails unless a documented development-only override is given. It then prints the exact next command, and starts and deploys nothing.

**The first administrative authority comes from the identity provider.** A production bundle grants admin access only through a policy role bound to a configured issuer (`provider:<name>`) and authentication method, with an explicit least-privilege permission list. There is no gateway-local bootstrap password. There is no route where the first request becomes admin, no setup route on a live gateway, and no setup token that authenticates anything on a gateway. Service tokens are minted afterwards by that operator through the existing `admin:tokens:write` delegation rules.

**Secrets are provisioned out of band.** The operator stores material in a #240 provider (a Kubernetes Secret volume or the Kubernetes Secrets API provider, Compose secrets under `/run/secrets` through file aliases, Vault, or a cloud provider), maps alias IDs to locators in the bootstrap environment, and writes only alias IDs into the bundle. Offline validation reports references it cannot check as `not_checked`, never as present, and that alone does not fail validation; doctor run where the bootstrap environment exists checks presence and permissions without reading values.

**First start.** The gateway compiles the bundle and resolves required references. Any failure exits non-zero before a listener binds or a store migrates. Missing secrets at startup fail closed.

**Seeding a ledger.** A ledger is created only by `ggctl ledger seed BUNDLE --state-dir DIR`, from a bundle that validates, into an empty ledger, while holding the state-directory lock. A gateway in ledger mode with an empty or unreadable ledger refuses to start.

**Recovery and lockout.** The deployment channel is the recovery channel. With a mounted bundle, revert the commit and roll out. In ledger mode, stop the gateway and run `ggctl ledger rollback REVISION --state-dir DIR` under the state-directory lock; filesystem access to the state directory is already full control of a standalone deployment. In cluster mode, ADR-0007's procedures apply. No network-reachable recovery credential is part of this decision. If one is ever needed, it requires an amendment that keeps it route-scoped, hashed, expiring, rate-limited, audited, and incapable of authenticating proxy, MCP, tool, token, or ordinary admin requests.

### Local first-run wizard

`ggctl init --web` runs the same initializer behind an ephemeral local web server inside the `ggctl` process (PR 7). It is not part of the gateway.

- It binds `127.0.0.1` and `[::1]` on an ephemeral port. There is no public bind option; a remote operator uses an SSH tunnel.
- It accepts a request only when `Host` is `127.0.0.1`, `[::1]`, or `localhost` (any port, so tunnels work) and, for every non-`GET`, `Origin` is exactly `http://` plus that `Host` and `Sec-Fetch-Site` is `same-origin`. This defeats DNS rebinding and cross-site requests.
- A one-time setup code of at least 60 bits from the operating system's CSPRNG, in a typeable alphabet, is printed to the controlling terminal or written once to a new owner-only file. Only its hash is kept in memory. It is entered in a form body, never a URL or fragment; it expires after 10 minutes, allows 5 attempts, after which the process exits, and is consumed on first success.
- The exchange sets an `HttpOnly`, `SameSite=Strict`, `Path=/` session cookie (`Secure` where the browser accepts it on loopback). Every form carries a CSRF token bound to the session.
- Pages are server-rendered HTML with no script: `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`, plus `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, and same-origin opener and resource policies. No CORS, third-party asset, analytics, service worker, or remote font. Because there is no script there is no browser storage use at all, and `ggctl` builds without a Node toolchain.
- Wizard state lives in process memory. Forms collect secret references, not values.
- The browser chooses typed field values only. Every file goes inside the output root fixed on the command line.
- It shuts down on completion, cancel, 15 minutes of inactivity, or 60 minutes total.
- Output passes the same compiler as gateway startup.

The authenticated Setup Center (PR 13) is a separate admin UI route on a configured gateway; see [Admin API and permissions](#admin-api-and-permissions).

### Revisions, activation, and drift

#### Bundle mode

The bundle is read once, at process start. A changed bundle on disk is never applied to a running process: a bundle that changes restart-scoped fields cannot be applied whole without a restart, and applying only its live parts would produce a generation that mixes two bundles. The process re-reads the manifest's source digest on a bounded interval and reports `drift` in protected status and metrics when it differs; it changes nothing else. SIGHUP does not reload configuration in this mode; it keeps reloading mounted certificate material, as today. Startup records `config.activated` with the source and semantic digests.

The state directory, when used, is held under an exclusive operating-system lock for the life of the process, so a second process cannot open the same standalone stores. Locks and SQLite on network filesystems are unsupported (ADR-0002), and doctor warns when it can detect one.

#### Ledger mode (standalone)

The ledger is one SQLite database beneath `GATEWAY_STATE_DIR`, using the discipline the existing standalone stores already use (WAL, `synchronous = FULL`, immediate transactions). It holds immutable revision rows, a desired/active pointer row, and evidence and outbox rows. Each revision records: opaque revision ID; exact document versions; source and semantic digests; the canonical documents; parent revision; actor and source kind when authenticated; changed section names and risk codes, without values; activation class and required permissions; validation and activation outcome; and timestamps.

The commit protocol:

1. Serialize on the deployment's mutation lock: an in-process lock taken inside the state-directory lock the process already holds, so offline `ggctl ledger` commands cannot run concurrently.
2. Verify the exact base revision and ETag.
3. Compile and validate the complete candidate off the request path, including every referenced resource with its production validator.
4. Verify the union of required permissions and the bound risk acknowledgment.
5. In one immediate transaction, insert the immutable revision, its evidence and outbox rows, and the pointer update.
6. For a `live`-class revision, publish one immutable runtime snapshot. If publication fails after commit, which is not expected, the process becomes unready and exits; it never serves the prior snapshot while reporting the new revision active.
7. For a `restart`-class revision, move only the desired pointer. Active is unchanged and status reports restart pending.

Failure before step 5 leaves the ledger and the running state unchanged. A crash before commit recovers the old revision; a crash after commit recovers the new one, and a mixed generation is not representable. Audit delivery reads the outbox, so a committed revision cannot lose its evidence and an uncommitted one cannot emit any.

At start, the gateway activates the desired revision. If the desired revision no longer compiles or a required reference is missing, the gateway **refuses to start**; it does not fall back to the previous active revision, because the desired revision may have been a tightening and the fallback would be a stale allow. Recovery is an explicit rollback.

While a restart is pending, every new revision is staged only. Rollback creates a new forward revision from prior content and runs current validation, compatibility, permission, risk, and preflight checks; it never deletes or reorders history, downgrades a schema, or restores secret material, revoked credentials, or Connections. When a ledger's stored documents no longer match their recorded digests, for example after an edit outside the gateway, the gateway refuses to start.

In ledger mode, policy and tools writes through their existing admin APIs, under their existing permissions, become ledger revisions, and there is no file-watcher or SIGHUP activation path. That gives #425 what [the authority-evidence contract](../authority-evidence.md) asks of this ledger: a ledger-owned manifest and digest, parent revision and compare-and-set, actor and operation intent, atomic activation and evidence, and authoritative replay after interruption. The Connections store stays its own authority, and the ledger does not claim atomicity with it; a change that would need both is rejected.

#### Cluster mode

- Deployment configuration comes from each replica's bundle. A fingerprinted change is classed `coordinated_cutover` and follows ADR-0007's procedure. Ledger mode and online deployment apply are not available.
- Policy and tools stay with the PostgreSQL control planes and their existing APIs. Bundle pins report drift. Applying bundle-delivered resource content in cluster mode is `unsupported` until PR 17 defines it as a conditional one-shot write through #241's control planes, never performed by serving replicas at boot.
- Revisions, outbox, replica acknowledgment, and stale-state behavior belong to #241.

#### Change classes

Every change in a plan or diff carries exactly one class:

| Class | Meaning |
| --- | --- |
| `live` | Activates in the running process in ledger mode. |
| `restart` | Durable once staged; active only after a new process proves it compiled the revision. |
| `coordinated_cutover` | A fingerprinted change in cluster mode. |
| `bootstrap` | Owned by a bootstrap input; a bundle cannot change it. |
| `connection_or_secret` | A #240 Connection or secret operation; performed through #240's APIs, never by a bundle. |
| `cluster_operation` | A #241 migration, import, or cluster operation; performed by its `gateway` command. |
| `unsupported` | Not possible in this mode; the operation is refused. |

### Plan, risk acknowledgment, and conditional apply

A client preview never authorizes anything. The server compiles the submitted bundle and returns a plan containing: plan ID; base revision and ETag; candidate source and semantic digests; the semantic diff over normalized typed state (order-insensitive and redacted, with secret changes shown only as `reference changed`); one change class per change; the sorted risk-code set; required permissions; and expiry. Plans are owner-scoped like ADR-0004 drafts.

Risk codes include at least `risk.auth_disabled`, `risk.auth_observe_only`, `risk.policy_default_allow`, `risk.shadow_enabled`, `risk.exemptions_broadened`, `risk.listener_exposed`, `risk.trusted_proxies_changed`, `risk.public_origin_changed`, `risk.cookie_or_csrf_weakened`, `risk.cors_broadened`, `risk.egress_broadened`, `risk.private_egress_allowed`, `risk.plaintext_transport`, `risk.credential_binding_changed`, `risk.audit_durability_reduced`, `risk.limits_loosened`, `risk.storage_changed`, `risk.profile_changed`, `risk.admin_access_path_removed`, and `risk.unknown_impact`. A change the detectors cannot classify gets `risk.unknown_impact`, never no code.

An acknowledgment binds the exact sorted risk-code set, the plan's candidate semantic digest and base revision, the acknowledging actor, and a short expiry, as ADR-0004 requires. There is no `--force` and no blanket flag. A candidate carrying `risk.admin_access_path_removed`, which means the server cannot show that the applying actor keeps an admin authentication path, is not acknowledgeable online; it goes through the deployment channel.

Apply submits the bundle with the plan ID, `If-Match` set to the base ETag, and an `Idempotency-Key`. At the commit point the server recompiles, recomputes the plan, and requires the semantic digest, base revision, risk set, and acknowledgment to match exactly (`409` otherwise), then checks the union of every touched resource's permissions. A missing precondition is `428`; a stale one is `412`; nothing is refetched or retried automatically. The same key with the same payload returns the authoritative prior result; the same key with a different payload is `409`. After an ambiguous transport outcome, `ggctl` reads authoritative state by idempotency key and reports what it finds; it never resends the mutation.

### `ggctl`

`ggctl` is a separate binary (PR 5). The `gateway` binary keeps its name, its no-argument behavior, and its one-shot commands unchanged.

#### Command tree

```text
ggctl version [--server URL]
ggctl schema [KIND] [--api-version VERSION]
ggctl init --profile production|migration|development --output DIR [--answers FILE] [--web]
ggctl validate (BUNDLE | --env FILE) [--strict] [--warnings-as-errors] [--format human|json|sarif]
ggctl pin BUNDLE
ggctl convert (BUNDLE | --env FILE) --to API_VERSION (--output DIR | --in-place)
ggctl doctor [BUNDLE | --env FILE | --server URL [--network]] [--format human|json]
ggctl diff (BUNDLE | --env FILE) (--against BUNDLE | --against-env FILE | --server URL) [--check]
ggctl plan (BUNDLE | --rollback REVISION) --server URL [--output FILE]
ggctl apply BUNDLE --server URL --if-match ETAG --plan PLAN_ID [--acknowledge RISK_CODE]... [--stage-only] [--wait]
ggctl status --server URL
ggctl history --server URL [--limit N]
ggctl rollback REVISION --server URL --if-match ETAG --plan PLAN_ID [--acknowledge RISK_CODE]... [--stage-only] [--wait]
ggctl export --server URL --output DIR [--template]
ggctl ledger seed BUNDLE --state-dir DIR
ggctl ledger verify --state-dir DIR
ggctl ledger rollback REVISION --state-dir DIR
ggctl backup create --state-dir DIR --output FILE
ggctl backup verify FILE
ggctl backup restore FILE --state-dir DIR
ggctl deploy render BUNDLE --target compose|kubernetes|cloudflare --output DIR
ggctl mcp-config --server URL --client generic|claude-desktop|cursor|vscode
ggctl completion SHELL
```

`--env FILE` reads a `KEY=VALUE` file as data, in the grammar `gateway import-standalone` already accepts for its source file; it never reads the process environment for that purpose and never sources the file. A key assigned twice is a warning (`env.duplicate_key`), and an error under `--strict`, because a reviewer may read the first assignment while every reader applies the last. This lets a deployment that stays in environment mode get the same offline validation, doctor, and diff in CI.

The names `ggctl db` and `ggctl cluster` are reserved. `ggctl` never opens a PostgreSQL connection: database migration, import, revocation, and cluster maintenance stay on the `gateway` one-shot commands (#241), which run where the DDL role and network already are. Invoking a reserved name exits `2` with `usage.reserved_command` and names the `gateway` command to run. Renderers emit the migration Job; `ggctl` does not run it.

#### Changes from the issue's sketch

| Issue sketch | This ADR | Why |
| --- | --- | --- |
| "Legacy environment mode" | Environment mode | It is a supported twelve-factor mode; the word legacy invites a deprecation nobody decided. |
| `ggctl migrate BUNDLE --to VERSION` | `ggctl convert` | `gateway migrate` already means database schema migration (#241). |
| `ggctl import BUNDLE --server --if-match` | Folded into `ggctl apply`; an export is a bundle | One mutation verb, one permission set, one audit path. `config.imported` is therefore not an event. |
| `ggctl doctor ... --offline\|--network` | Offline is the default; `--network` exists only with `--server` | Network checks must use production DNS, egress, and TLS controls, which exist only in the gateway. A local network check would be the weaker diagnostic client invariant 16 forbids. |
| `POST /config/preview` | `POST /config/plans`, plus acknowledgements | Apply binds to a server-owned, expiring, owner-scoped plan. |
| Exit codes 0–7 | Adds `8` | An authentication or authorization refusal is neither an internal failure nor invalid configuration, and automation must neither retry it nor read it as drift. |
| `GET /setup/status`, "a public form if retained" | Authenticated only | No public setup surface. |
| Archive import for bundles | Directories only | Archives exist only for backups, which removes a parser surface from the GitOps path. |
| — | `ggctl pin`, `ggctl status`, `ggctl ledger seed\|verify\|rollback` | Digests must be maintainable by a tool, `--wait` needs a status read, and ledger mode needs an offline seed and an offline lockout recovery. |

#### Output contract

- Human output by default. `--format json` emits one `GgctlReport` document (`apiVersion: greengateway.dev/v1alpha1`) for every command that does not write an artifact; `--format sarif` emits SARIF 2.1.0 for `validate`.
- Stdout carries only the requested artifact or report. Progress and diagnostics go to stderr.
- No prompts unless stdin is a terminal; a command that needs input it cannot prompt for exits `2`. No ANSI color unless stdout is a terminal and `NO_COLOR` is unset.
- `ggctl` has no configuration file and reads no ambient environment beyond `NO_COLOR`. Every remote target, CA, and credential source is an explicit flag.
- Help, man pages, and shell completion are generated from the same command definition.

#### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success; for `diff --check`, no drift; for `doctor`, no required check failed. |
| `1` | Unexpected internal, I/O, or transport failure, including a mutation whose outcome could not be determined. |
| `2` | Usage error, including a reserved command or a refused insecure option. |
| `3` | Invalid, incompatible, or unsupported configuration; a required doctor check failed; a risk needs acknowledgment; any warning under `--warnings-as-errors`. |
| `4` | Drift found by `diff --check`. |
| `5` | Precondition conflict: missing or stale ETag (`428`, `412`), stale plan, acknowledgment, or idempotency binding (`409`), or a held lock. |
| `6` | A dependency was unavailable and nothing was committed (`503`, or a failure before any request byte was sent). |
| `7` | Backup or archive integrity failure, or restore verification failure. |
| `8` | Authentication or authorization refused (`401`, `403`). |

Exit `6` means "safe to retry". An ambiguous mutation outcome is `1`, never `6`, so a pipeline that retries on `6` cannot resend a mutation that may have committed.

#### Diagnostics

Every diagnostic has a stable code of the form `family.reason` in lowercase snake segments (`yaml.alias_forbidden`, `bundle.digest_mismatch`, `path.escapes_root`, `source.conflicting_environment`, `secret.inline_value`, `reference.unresolved`, `compat.unsupported_api_version`, `risk.policy_default_allow`, `doctor.state_dir_writable`, `remote.redirect_refused`, `archive.entry_outside_root`), a severity (`error`, `warning`, `info`), a location given as the bundle-relative file name plus a JSON Pointer and, for YAML, a line and column, the catalog field identifier when there is one, fixed message text, a remediation documentation anchor, and the stages it blocks (`validate`, `apply`, `startup`). Diagnostics are value-free by construction, as `config/diagnostic.rs` already is: no value, host path, URL, DSN, address, DNS answer, locator, SQL, header, body, or library error text. A published code never changes meaning; renaming or removing one requires a new report schema version.

#### Remote client

- `--server` takes the admin API base: `https://host[:port]/v1<ADMIN_PREFIX>`. Userinfo, query, and fragment are refused. `ggctl` never derives the prefix.
- Non-loopback targets require HTTPS with normal certificate and hostname verification; `--ca-file` adds a trust anchor. Plain HTTP is accepted only for a loopback literal, which covers `kubectl port-forward` and SSH tunnels. There is no `--insecure`.
- Redirects are refused. Ambient proxy variables are ignored.
- Credentials come from `--token-stdin` or `--token-file PATH` (a regular file of at most 8 KiB that must not be group- or other-readable on Unix). An operating-system credential store may follow in a later slice. No option takes a token value, and executable credential plugins are excluded: an executable named by configuration is exactly the hook the non-goals rule out.
- Before any mutation, `ggctl` reads the server's capabilities (API version, supported `(apiVersion, kind)` pairs, source mode, enabled operations, effective limits) and refuses a mutation the server cannot accept; `version` and read-only `status` still work against an incompatible server.
- ETags are opaque and preserved byte for byte.
- Requests are sequential. Mutations are never retried. Idempotent reads are retried at most twice, and only when the connection was never established. A legacy endpoint's history or audit warning is reported as an ambiguous compatibility warning, never retried.

#### Build and dependency boundary

The compiler, field catalog, bundle reader, and digest code move into a shared library crate that both binaries depend on. PR 5 fixed the names, `gateway-config` for the library and `ggctl` for the binary, and created the library with the contracts both binaries already exchange: the published document schemas and the `GatewayCapabilities` handshake document. The bundle reader, compiler, catalog, and digest code move into it in PR 8, the first slice whose command needs them, together with the policy and tools validators the reader calls, so that no slice ships a second copy of a validator. `ggctl` does not embed the admin UI, so it builds without Node. It has no PostgreSQL client. Its only network capability is the admin API client, built on the workspace's existing HTTP and TLS stack with redirects disabled and ambient proxies ignored, and registered in `transport-ownership.json` like any other transport. It uses SQLite through the existing `rusqlite` dependency only for ledger and backup commands. New dependencies follow `docs/deployment/cargo-dependency-policy.md`. Output permissions, path handling, terminal detection, and exit codes are tested on Linux, macOS, and Windows.

### Admin API and permissions

All routes live under `/v1{ADMIN_PREFIX}` on the admin listener, honoring a custom prefix and the split listener, behind authentication, RBAC, CSRF for cookie sessions, request bounds, and structured audit. No route accepts a host output path, an arbitrary diagnostic target, or a secret value.

| Route | Purpose | Permission |
| --- | --- | --- |
| `GET /config` | Effective redacted state, source mode, per-field provenance, active and desired revision, drift and restart-pending flags, strong ETag, and server-computed action booleans | `admin:config:read` |
| `GET /config/capabilities` | Supported document versions, source mode, enabled operations, effective limits | `admin:config:read` |
| `POST /config/validate` | Pure structured validation of a submitted bundle | `admin:config:validate` |
| `POST /config/plans`, `GET /config/plans/{id}` | Create an owner-scoped plan from a submitted bundle or a rollback target, or read one | `admin:config:validate` and `admin:config:read` |
| `POST /config/plans/{id}/acknowledgements` | Bind an acknowledgment of the exact risk set | `admin:config:write` |
| `POST /config/revisions` | Stage a plan; `If-Match` and `Idempotency-Key` required | `admin:config:write` and the union of touched permissions |
| `GET /config/revisions`, `GET /config/revisions/{id}` | Paginated metadata; one revision's metadata and redacted diff against its parent | `admin:config:read` |
| `POST /config/revisions/{id}/activate` | Activate a staged `live`-class revision | `admin:config:write` and the union |
| `POST /config/rollback/{id}` | Create a new forward revision from a prior one, bound to a rollback plan; `If-Match` and `Idempotency-Key` required | `admin:config:write` and the union |
| `GET /config/operations/{id}` | Desired, active, restart, and readiness state of one operation | `admin:config:read` |
| `POST /config/exports` | Release a reference-only export; the `config.exported` event is accepted before any byte is released | `admin:config:export` |
| `GET /setup/status` | Readiness checklist derived from authoritative state | `admin:config:read` |
| `POST /diagnostics` | Run fixed check IDs against persisted targets | `admin:diagnostics:run` |
| `GET /mcp/client-configs` | Credential-free client templates | `admin:mcp:clients:read` |
| `GET /openapi.json` | The OpenAPI 3.1 admin contract with the configured prefix | Any authenticated admin principal; PR 12 fixes the exact permission |

Mode availability: in environment mode and bundle mode, `POST /config/revisions`, activation, and rollback answer `409` with `config_source_read_only`, and every read, validate, plan, and export route works. In cluster mode the same applies to deployment configuration, and resource-content revisions answer `unsupported` until PR 17. `GET /config/capabilities` advertises exactly what the mode allows, and the Setup Center renders actions only from server-provided booleans.

| Permission | Grants |
| --- | --- |
| `admin:config:read` | Effective state, capabilities, revisions, operations, own plans, setup status |
| `admin:config:validate` | Validation and plan creation |
| `admin:config:write` | Staging, activation, rollback, and acknowledgments |
| `admin:config:secrets:write` | Additionally required for any change to a secret reference, or to a destination a referenced secret is sent to (for example the admin login issuer), following ADR-0006's rule that changing where a credential may be sent is a secret-use mutation |
| `admin:config:export` | Export release |
| `admin:diagnostics:run` | Server-side diagnostics |
| `admin:mcp:clients:read` | MCP client templates, without configuration read |

Applying a revision additionally requires every permission the touched resources already require: `admin:policy:write` for policy content and `admin:tools:write` for tools content. A failure of any one leaves everything unchanged. Config permissions never mint credentials.

| Status | Meaning |
| --- | --- |
| `400` | Malformed or unsafe syntax |
| `401`, `403` | Not authenticated or not authorized; no validation, provider, or network work happens first |
| `409` | Read-only source mode, `resource_managed_by_bundle`, stale plan or acknowledgment, idempotency key reused with a different payload, or activation requested while a restart is pending |
| `412` | Stale ETag |
| `413` | A byte, count, or depth bound exceeded |
| `415` | Unsupported media type |
| `422` | Invalid candidate, with structured diagnostics |
| `428` | Missing `If-Match` or `Idempotency-Key` |
| `429` | Rate or plan quota exceeded |
| `503` | A dependency is unavailable or the commit rolled back; nothing changed |

PR 12 publishes one OpenAPI 3.1 admin document covering these routes and the existing ones (absorbing `docs/openapi/admin-connections.v1.openapi.json`), generated from or verified against the route table so that routes, DTOs, permissions, status codes, and the prefix representation cannot drift. ADR-0004 already defers final Policy Studio route suffixes to this contract.

### Doctor

Doctor is offline by default and makes zero network requests. Its checks have stable IDs, a severity, a status of `pass`, `warning`, `fail`, or `skipped`, a safe reason code, a remediation anchor, and a duration. It reports no raw paths, URLs, DSNs, addresses, DNS answers, locators, SQL, bodies, headers, or library errors.

Offline checks cover version compatibility, source conflicts, full compiler validation, references and digests, file type, size, permissions, and containment, standalone store compatibility and integrity where a read-only open is safe, secret-reference presence and permissions without reading values, profile contradictions (public URL, cookies, CORS, trusted proxies, exemptions, listeners, policy mode, audit durability), trust-anchor overrides, network filesystems under the state directory, and the desired revision, active revision, and drift when a local ledger is readable.

Network checks run only inside a gateway, through `ggctl doctor --server URL --network` and `POST /diagnostics`, with the gateway's production DNS, egress, TLS, redirect, timeout, and credential paths, against persisted targets only, under `admin:diagnostics:run`, rate and concurrency limits, cancellation, and audit. Each check declares whether it can cause an upstream side effect. A check outside the requested scope is `skipped`, and `skipped` never counts as `pass`. A check inside the scope that cannot run is `fail`.

### Export, backup, and restore

These are different artifacts with different handling.

**Export** (PR 14) releases the server's desired state as a bundle. It contains normalized fields and opaque references only: no secret values, ciphertext, token hashes, key IDs, provider locators, host paths, environment dumps, or audit data. Bootstrap inputs are excluded and listed by name only in the report. A legacy inline credential (an `AUTH_PROVIDERS` client secret or a credential in `add_request_headers`) becomes an unresolved placeholder, so the output fails validation until an operator supplies a reference; GreenGateway never writes a file that looks deployable after lossy redaction. `--template` also replaces fields the catalog marks environment-specific with placeholders. Output is created new; replacing an existing directory needs explicit intent and is atomic.

**Backup** (PR 15) is sensitive recovery material, not GitOps configuration. It is supported for bundle and ledger modes, where the state-directory lock and the fixed store layout make "every selected store" well defined. Creation requires that lock, so the gateway is stopped. Each SQLite store is snapshotted through the SQLite backup API or `VACUUM INTO` from a read-only connection, as `gateway import-standalone` already does, never by copying live main, WAL, and SHM files. The archive carries a `GatewayBackup` manifest with binary, document, and store versions, a logical inventory, counts, and per-entry checksums. It omits pending logins, caches, plaintext tokens, secret values, and master keys; the Connections store keeps #240's ciphertext, and its key files under `CONNECTION_SECRETS_ROOT` are a separate recovery artifact, as ADR-0006 states. The archive is written to a new temporary file, flushed, verified, then renamed, is owner-only, and is never streamed to stdout.

**Restore** requires an empty or explicitly prepared state directory held under its lock. It extracts bounded regular entries into a fresh staging root, verifies checksums, versions, SQLite integrity, references, and permissions, and switches only after complete success; any failure leaves the target untouched. The archive reader rejects absolute paths, `..`, duplicate and case-colliding names, alternate data streams, links, reparse points, devices, sockets, excessive entry counts, truncation, decompression past its declared bound, and incompatible versions. PR 15 chooses the archive container under the dependency policy; whatever it chooses must enforce that list. PostgreSQL backup and point-in-time recovery remain #241's runbooks, and Cloudflare durable backup and restore answer `unsupported`.

### MCP client templates

`ggctl mcp-config` and `GET /mcp/client-configs` (PR 14) return versioned templates for a generic Streamable HTTP client and for the clients the project explicitly supports (Claude Desktop, Cursor, VS Code).

- The URL comes from the server-computed `GATEWAY_PUBLIC_URL` and protected-resource metadata, never from `Host`, forwarding headers, `window.location`, or caller input, and always points at GreenGateway's MCP endpoint, never at an upstream Connection.
- An OAuth-capable template contains only the canonical MCP URL. A token-based template names an environment-variable or operating-system secret placeholder; no template, archive, URL, argument, or clipboard write ever contains a token. Minting a service token stays a separate `admin:tokens:write` action under the existing delegation rules, and the documentation names the `mcp:tools` binding and the least-privilege role a client needs.
- Every output is serialized and parse-tested per client, including hostile names, path prefixes, escaping, Windows paths, and URL normalization. `ggctl` never edits a client's configuration file.

### Setup Center

The Setup Center (PR 13) is an authenticated admin UI route over a configured gateway; it is not a setup surface and it has no unauthenticated state.

- Readiness and every action come from authoritative server state and server-provided permission booleans, never from client-decoded token claims, `window.location`, an absolute `/version`, a missing resource, or browser storage. It uses the configured admin prefix and split listener.
- Cookie-authenticated mutations go through one CSRF-aware path in the shared API client, distinct from bearer handling (#424).
- Secrets are never prefilled: a sensitive field shows only `unset`, `set`, `set by the environment`, or a replace or clear intent. Bootstrap-owned fields are visibly read-only, with their provenance.
- Server diagnostics, diffs, and templates render as text. The admin CSP is not weakened.
- `401`, `403`, `409`, `412`, `422`, `428`, and `503` are distinguished. A restart-required apply shows staged and active state separately with exact recovery instructions, and never implies a self-restart.
- Mutating actions are offered only where the source mode allows them, which in the first release means ledger mode.
- Accessibility follows the issue's list (semantic ordered stepper, `aria-current`, fieldsets and legends, a linked error summary, focus management, live regions, keyboard-only operation, reduced motion, 200% zoom, narrow layouts), and visual tests use synthetic, secret-free fixtures only.

### Deployment renderers

`ggctl deploy render` (PR 16) writes deterministic files and never invokes Docker, `kubectl`, Wrangler, or a package manager. Output is plain YAML or JSON that Helm, Kustomize, Argo CD, Flux, or a human can consume unchanged.

- **Kubernetes.** Immutable, digest-named ConfigMaps for the bundle in a read-only projected volume; secrets through Secret volumes, `envFrom` for the variables aliases name, or the Kubernetes Secrets API provider — never generated Secret literals; image pinned by digest; `runAsNonRoot`, user `10001`, read-only root filesystem, dropped capabilities, `RuntimeDefault` seccomp, and bounded resources; #239's startup, liveness, and readiness probes and termination grace. Standalone renders `replicas: 1`, a `Recreate` strategy, and a PersistentVolumeClaim for `GATEWAY_STATE_DIR`. Cluster renders no PVC, a separate migration Job running `gateway migrate up` under the DDL role, and application pods that never run production DDL.
- **Compose.** A read-only bundle mount, a separate named state volume, user `10001:10001`, a read-only root filesystem with tmpfs, Compose secrets under `/run/secrets` through file aliases, an image pinned by digest, and `gateway healthcheck`.
- **Cloudflare.** Bundle mode is not available, because the container has no bundle mount. The renderer projects the bundle to flat Worker variables through the catalog's environment mapping, keeps the documented listener and TLS exclusions explicit, and refuses a field whose bundle value is a secret reference with no environment-mode reference form (`render.not_projectable`) rather than inlining it. Durable apply, backup, and restore are `unsupported`; every change requires a redeploy.

Rendered manifests carry the bundle source digest and image digest so that `ggctl diff --server` and protected status can show exactly which release is active.

### Audit, status, and metrics

Events: `config.revision_staged`, `config.activation_requested`, `config.activated`, `config.activation_failed`, `config.rolled_back`, `config.exported`, `config.backup_created`, `config.backup_verified`, `config.restore_detected`, and `diagnostic.run`. Allowed fields: opaque revision and plan IDs, exact document versions, parent revision, source kind, changed section names, stable risk and reason codes, result, restart-pending flag, bounded counts and durations, and the existing authenticated actor and request envelope. Forbidden: configuration values; variable names that identify secrets; locators, host paths, and archive names; URLs with userinfo or query; host topology, addresses, DNS answers, DSNs, and SQL; secrets, ciphertext, secret fingerprints, key IDs, tokens, cookies, certificates, private keys, headers, bodies, and raw library errors. Offline `ggctl` commands never write gateway audit events.

Protected status shows the source mode, supported document versions, opaque active and desired revisions, source and semantic digests, restart-pending, drift, the last activation time and result, and a safe failure class. Public probes keep exposing coarse lifecycle state only. Metrics use bounded source, result, reason, document-version, and check-class labels, and never label by actor, principal, revision, digest, path, Git reference, Connection ID, URL, tool name, or raw error.

## Threat model

### Assets

- Integrity of desired and active configuration, and the truth of the reported difference between them.
- Confidentiality of secret material and of locators and host topology.
- Administrative authority: who can obtain it, and whether it can be lost.
- Availability of the data plane during configuration change, rollout, and recovery.
- Integrity and completeness of configuration evidence and audit.
- Bundles, exports, and backups wherever they are stored: Git, CI artifacts, registries, operator workstations.
- The integrity of the `ggctl` binary and the gateway image.

### Trust boundaries

1. Git, CI, and their delivery channel (registry, ConfigMap, volume) into the gateway's bundle reader.
2. The bootstrap environment and mounted secret material, which are trusted operator configuration.
3. The gateway into #240 secret providers and #241 PostgreSQL, both unchanged by this decision.
4. `ggctl` into the admin API across a network, a port-forward, or a tunnel.
5. A browser into the local wizard on loopback.
6. `ggctl` into the local filesystem: output directories, the state directory, and archives received from elsewhere.
7. The standalone ledger and state directory at rest.

### Actors

External attackers reaching a public listener; malicious web pages in an operator's browser; other local users on an operator host or CI runner; malicious or careless pull-request authors and compromised CI jobs; admins with partial permissions; fully authorized admins acting mistakenly or maliciously; network attackers between `ggctl` and the gateway; compromised dependencies; and operators under incident pressure.

### Abuse cases and controls

| Threat | Prevention and detection | Residual risk |
| --- | --- | --- |
| A pull request disables authentication, sets default allow, or broadens egress | The production profile refuses those invariants; plans and `diff` emit risk codes CI can gate on; the migration profile requires per-behavior acknowledgment in the document | Reviewers must read the diff; anyone who can merge to the delivery channel controls configuration, as with environment variables today |
| A reviewer and the gateway read YAML differently | Safe subset; duplicate keys, aliases, tags, merge keys, and ambiguous scalars refused; `diff` shows normalized typed values | A future document version must keep the subset |
| Bundle and environment both configure a field | Overlapping inventoried variables refused at startup; per-field provenance | Non-inventoried variables read by dependencies (`SSL_CERT_FILE`) are reported by doctor, not refused |
| Traversal, symlink, reparse point, hard link, special file, or case collision in a bundle | Flat directory, portable lowercase names, no-follow opens with handle checks, one resolved atomic-writer generation | Platform filesystem guarantees vary; Windows ACLs remain operator responsibility |
| A ConfigMap update mixes two generations mid-read | One resolved `..data` generation, file pins, the source digest, immutable digest-named ConfigMaps | A mis-rendered mutable ConfigMap fails closed at startup (crash loop) rather than serving a mix |
| A secret is committed to Git | Sensitive fields can hold only references; inline values refused without echo; `init` and export never write values | Free-form non-sensitive fields could still carry pasted secrets; secret scanning in CI remains necessary |
| A secret leaks through diagnostics, diffs, digests, status, audit, or metrics | Value-free diagnostics by construction; secret changes shown as reference changes; no secret-derived fingerprints; canary tests across every output surface | Process memory and privileged host inspection remain trusted |
| A preview or plan is replayed, forged, or used after state moved | Server-side recompilation, owner-scoped expiring plans, exact digest, base-revision, risk-set, and actor binding, strong ETags, idempotency keys | An ambiguous outcome requires an authoritative read before any retry |
| A generic force flag bypasses validation | None exists; acknowledgment binds exact risk codes; some risks are not acknowledgeable online | A fully authorized operator can still acknowledge and apply deliberate risk |
| An apply locks every admin out | `risk.admin_access_path_removed` refused online; the deployment channel and the offline ledger rollback are the recovery path | An operator who also loses access to the delivery channel or host has no in-band recovery, by design |
| A malicious web page drives the local wizard (CSRF, DNS rebinding) | Loopback bind, Host allowlist, exact Origin and `Sec-Fetch-Site` checks, one-time code, `SameSite=Strict` session, CSRF token, no CORS, no script | A malicious local process with the operator's privileges can do anything the operator can |
| Another local user guesses or reads the setup code | At least 60 bits, hashed in memory, 5 attempts then exit, 10-minute expiry, terminal or new owner-only file | Shared multi-user hosts remain a weaker environment; documentation says so |
| A network attacker intercepts `ggctl` credentials | HTTPS with verification, no `--insecure`, no redirects, no ambient proxy, tokens never in arguments | A compromised trusted CA or operator workstation |
| `ggctl` output follows an attacker's symlink | A create-new staging directory with an unpredictable name, refusal of non-empty destinations, rename into place, no-follow checks | A destination directory an attacker can already write is not made safe by any of this; documentation says to write only where the operator controls the parent |
| Archive attacks: traversal, bombs, alternate streams, links, duplicates | Bounded regular entries, staged extraction, checksums, rejection list; bundles have no archive form | Archive libraries are dependencies and stay under supply-chain review |
| A backup becomes a secret dump | Backups exclude values, master keys, plaintext tokens, and caches; owner-only; documented as sensitive recovery material | Connections ciphertext is included; whoever holds the backup and the key files holds the secrets |
| A rollback revives revoked access or downgrades a schema | Forward-only revisions; secrets, Connections, and schema are outside revisions; full revalidation on rollback | Rolling back to a looser policy is a deliberate, risk-coded operation |
| A crash during activation leaves a mixed or stale generation | Single-transaction ledger commit; unready-and-exit after commit-then-publication failure; startup refuses an uncompilable desired revision rather than falling back | Availability is lost until an operator acts; that is the fail-closed choice |
| Ledger or state files are edited on disk | Digest verification at start; the gateway refuses to start | A local administrator can replace the whole state directory, which is already full control |
| Diagnostics become an SSRF scanner | Fixed check IDs, persisted targets only, production egress controls, a dedicated permission, rate limits, and audit; `ggctl` has no local network checks | An authorized operator can exercise already configured destinations |
| An MCP client template embeds a token or points past the gateway | Canonical URL from `GATEWAY_PUBLIC_URL`; placeholders for tokens; parse tests for every client | A user can still paste a token into their own client configuration |
| Version skew silently drops fields | Exact document versions, unknown members refused, capability handshake before mutation | An operator can pin an old `ggctl`; it then refuses newer bundles rather than misreading them |
| An unsigned bundle is presented as trusted | Digests are documented as integrity only; signing is a separate future decision | Delivery-channel access control (branch protection, Kubernetes RBAC on the ConfigMaps, admission policy) is the authenticity control today |
| Telemetry or an unexpected network call | None in `ggctl`; network only for an explicit `--server` | — |
| The `ggctl` binary is tampered with | Release checksums, SBOM, and provenance (PR 18, following #428); no self-update | Users who skip verification |
| Oversized bundles or plan floods exhaust resources | Bounds checked before allocation; plan quotas and lifetimes | Limits may need reviewed tuning |

## Dependency boundaries

| Issue | Authority it owns | How #242 integrates |
| --- | --- | --- |
| #239 (closed) | Probes, drain, termination budgets, transport | Renderers wire `/startupz`, `/livez`, `/readyz`, drain settings, and `gateway healthcheck`; nothing in #242 changes lifecycle semantics. |
| #240 (closed) | Connections, credential bindings, `SecretResolver`, providers, encrypted-local storage and its key recovery | Bundles carry alias IDs only and resolve through the existing resolver and purposes. Connections are server-managed. Nothing exports values, ciphertext, keys, or locators, and no second Connection store exists. |
| #241 (closed) | Cluster mode, PostgreSQL control planes, migrations, import, fingerprint, membership, PostgreSQL backup and recovery | Database and cluster operations stay on `gateway` commands; cluster resource activation through bundles waits for PR 17; the fingerprint is computed from compiled configuration. |
| #426 (open) | Expand and contract compatibility and capability-gated operations | Any cluster-mode bundle operation added by PR 17 registers its operation requirements through #426's gate. |
| #433 (open) | The configuration compiler extraction | Is this epic's PR 2; #242 consumes it rather than building a second engine. |
| #425 (open) | Durable authority-change evidence | The standalone ledger provides the transaction, CAS, intent, and replay its standalone slice requires; required-durability configuration stays unsupported until both sides prove it. |
| #243 (open), ADR-0004 | Policy semantics, Policy Studio drafts, publication, evidence | Policy stays its own document and validator. In ledger mode, publication becomes a ledger revision; in standalone bundle mode it is refused as bundle-managed. ADR-0004's digest frame is reused, not reinvented. |
| #424 (open) | Cookie sessions as the normal admin UI flow | The Setup Center's cookie and CSRF mutation path depends on it. |
| #428 (closed) | Image SBOM and provenance | `ggctl` release artifacts follow the same evidence model. |

## Rollout

Each step is one focused PR as listed in #242; nothing is advertised beyond what its gate proved.

1. **This ADR.** No behavior change.
2. **Compiler** (#433 PRs 2–4). Environment mode keeps golden parity.
3. **Field catalog and generated parity.** Replaces name-only drift checks, including the Cloudflare list.
4. **Bundle reader, schemas, and digests.** Bundle mode exists only behind `GATEWAY_CONFIG_SOURCE=bundle`.
5. **`ggctl` foundation.** Shared library crate, output contract, exit codes, completion, credential inputs, handshake.
6. **`init` and `convert`.** Profiles, atomic scaffolding, answers.
7. **Local wizard.**
8. **`validate`, offline `doctor`, `pin`, and CI examples.**
9. **Semantic diff and risk engine.**
10. **Standalone ledger.** Ledger mode exists only behind `GATEWAY_CONFIG_SOURCE=ledger`.
11. **Plan, apply, history, and rollback.**
12. **Admin API and the OpenAPI 3.1 document.**
13. **Setup Center**, after #424.
14. **Export and MCP client templates.**
15. **Backup, verify, and restore.**
16. **Renderers.**
17. **#240 and #241 integrations**, including cluster resource activation.
18. **Observability, packaging, documentation, and the release gate.**

Steps 1–9 deliver the local, reference-only GitOps workflow (init, validate, pin, convert, diff, offline doctor, and startup from a mounted bundle) without any online mutation. Remote whole-bundle apply, cluster bundle activation, durable Cloudflare configuration, and Connection GitOps are not advertised until their steps pass.

## Consequences

This ADR is documentation-only. It ships no runtime code, schema, endpoint, permission, variable, binary, or migration.

The principal benefits: one compiler for startup, CI, and review; bundles that any GitOps controller can deliver and any reviewer can diff semantically; secrets that never enter Git or exports; exit codes and reports automation can rely on; desired and active state that are reported truthfully; and a bootstrap path with no backdoor. Environment-mode deployments are untouched.

The costs:

- Three source modes to document and test, each with a different writer for policy and tools. Standalone bundle mode deliberately refuses interactive policy and tool edits.
- Strictness that environment mode does not have: exact versions, unknown-member refusal for policy and tools, LF-only files, quoted ambiguous scalars, and decimal strings for fractional settings.
- A bootstrap set split across environment and bundle for features such as listener TLS, where the bundle states intent and the environment states the mount.
- A ledger-mode gateway that refuses to start when its desired revision no longer compiles, trading availability for the guarantee that no stale configuration is served.
- A new crate, a new binary with its own release artifacts, and a growing catalog that every new setting must be entered into.

## Rejected alternatives

- **The gateway pulls from Git or receives webhooks.** A second network authority and credential inside the security boundary; pull-based controllers already exist and stay outside it.
- **Environment interpolation inside bundles.** Hidden precedence, unreviewable values, and secrets flowing into rendered artifacts.
- **Live reload of mounted bundles.** Restart-scoped changes cannot apply whole, and partial application creates generations that never existed in Git.
- **A Helm chart or templating language as the contract.** Rendering becomes non-deterministic and the template becomes the configuration language. Plain rendered files can be wrapped by Helm or Kustomize without either being authoritative.
- **A Kubernetes operator or custom resource first.** Requires cluster-wide installation privileges and couples the product to one platform. The `apiVersion`/`kind`/`spec` envelope keeps that path open later.
- **Encrypted secrets inside bundles** (SOPS-style). It would make the gateway a decryption authority for repository content; secret custody stays with #240 providers, which can themselves be fed by such tooling outside GreenGateway.
- **A precedence switch or `--force`.** Either one turns every invariant into a suggestion.
- **Replacing environment configuration with a file.** It breaks twelve-factor deployments and existing operators.
- **`ggctl` with its own PostgreSQL client or egress stack.** A second database authority on operator laptops, and a weaker diagnostic client.
- **A setup route on the live gateway, even short-lived.** A takeover race on the first request.
- **Falling back to the previous revision when the desired one fails at start.** A stale allow when the desired revision was a tightening.
- **Signing bundles in the first release.** Signing needs trust-root distribution, rotation, and revocation designs of its own; digests ship now and are labeled as integrity only.

## Traceability for #242 PR 1

| PR 1 requirement | Section |
| --- | --- |
| Terminology | [Terminology](#terminology) |
| Source authority | [Source modes](#source-modes), [Bootstrap inputs](#bootstrap-inputs), [Resource ownership](#resource-ownership) |
| Command tree | [Command tree](#command-tree), [Changes from the issue's sketch](#changes-from-the-issues-sketch) |
| Schemas | [Bundle format](#bundle-format), [Published schemas](#published-schemas) |
| Bounds | [Bounds](#bounds) |
| Permissions | [Admin API and permissions](#admin-api-and-permissions) |
| Bootstrap model | [Bootstrap model](#bootstrap-model), [Local first-run wizard](#local-first-run-wizard), [Initialization profiles](#initialization-profiles) |
| Exit and status codes | [Exit codes](#exit-codes), [Admin API and permissions](#admin-api-and-permissions) |
| Dependencies on #239–#241 | [Dependency boundaries](#dependency-boundaries) |
| Explicit non-goals | [Non-goals](#non-goals) |
| Threat model | [Threat model](#threat-model) |
