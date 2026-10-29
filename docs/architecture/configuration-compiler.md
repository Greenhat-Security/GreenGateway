# Configuration compiler contract

Issue #433 split the gateway's environment configuration into a compiler
(`gateway/src/config/`) and the startup stages that act on what it compiles
(`gateway/src/bootstrap.rs`). This page is the compiler's contract: what it
reads, what it returns, how secret material travels through it, what it never
does, and what the configuration bundles, `ggctl` and doctor work of #242 can
build on today. It describes the code as it is. Where
[ADR-0008](../adr/0008-setup-cli-and-configuration-bundles.md#configuration-compiler-and-field-catalog)
describes the compiler #242 needs, the sections on [extension
points](#extension-points-for-242) say how far today's compiler goes and what
is still missing.

The per-variable reference stays in [configuration.md](../configuration.md).
Nothing here changes a variable, a default, or a message: the compiler was
extracted under golden parity with the parser it replaced
(`gateway/src/config/parity_tests.rs`).

## Scope

- **One source: the environment.** The compiler reads named string values
  from a reader and nothing else. No bundle, file, store, or command-line
  argument is a configuration source, and no released gateway can start from
  a bundle (see [configuration-bundles.md](../configuration-bundles.md)).
- **One semantic validator.** `config::compile` is the only code that parses
  and validates these settings. `Config::from_env_vars` is `compile` followed
  by a conversion; it adds no rule of its own.
- **Gateway crate only.** The compiler is `pub(crate)` in the `gateway` crate.
  `ggctl` and the `gateway-config` library cannot call it (see [Moving the
  compiler](#moving-the-compiler-into-gateway-config)).

## Callers

| Caller | Reader | What it does with the result |
| --- | --- | --- |
| `gateway` with no arguments: `bootstrap::start_serving` | `config::process_environment`, the process environment | Runs the startup stages on the plan (see [Startup](#startup)). A refused configuration is printed and the process exits with status 1 before any stage runs. |
| The one-shot commands: `migrate`, `connection-secret`, `revoke-jwt`, `jwt-revocations-cleanup`, `rate-limit-buckets-cleanup`, `cluster-members`, `maintenance-run`, and `import-standalone`'s own configuration | `Config::from_env`, the same reader | Uses the converted `Config`. A refusal is returned as the command's error, in the same operator-facing form. |
| `gateway import-standalone --from FILE`, for the source deployment | The variables parsed from `FILE`, as a map | Refuses the import with `ImportError::StandaloneConfigInvalid`, naming only the settings that failed, never their values. |
| Tests | Fixture maps and recording doubles | Parity goldens, stage tests, and the startup-stage tests. |

## Inputs

### The reader

```rust
pub(crate) fn compile(
    get_var: impl FnMut(&str) -> Result<String, VarError>,
) -> Result<ConfigPlan, ConfigError>
```

The reader answers one variable name at a time, as `std::env::var` does:
`Ok(value)`, `Err(VarError::NotPresent)` for an unset variable, or
`Err(VarError::NotUnicode(_))` for a value that is not valid Unicode. A value
that is not Unicode counts as set, never as the default, and a problem about
it gets the diagnostic code `NotUnicode`. The compiler never reads the process
environment itself; whatever the reader returns is the configuration.

### The inventory

`inventory::CONFIG_INPUTS` (`gateway/src/config/inventory.rs`) lists every
variable the compiler asks for, in the order it asks. The contract on reads:

- Every inventoried variable is requested exactly once, and no other name is
  requested.
- The requests do not depend on the values: each block of inputs (see
  [Stages](#stages)) is requested in full before any of it is parsed, so a
  refused, unset, or unusual value never skips or adds a read.
- Requests follow inventory order.

`inventory::tests::the_inventory_is_exactly_what_from_env_vars_requests` and
`stage_tests::each_block_requests_its_inputs_once_and_the_blocks_read_the_inventory_in_order`
hold the compiler to this. A variable added to a stage and not to the
inventory, or left in the inventory after its stage stops reading it, fails
them.

### Blank values

Unset and blank (empty or whitespace-only) are different inputs, and each
inventoried variable treats a blank value by exactly one of three rules:

| Rule | Meaning | Where the classification lives |
| --- | --- | --- |
| Blank is unset | The default applies, exactly as if the variable were absent. | `BLANK_IS_UNSET` in `parity_tests.rs` |
| Blank is refused | The value is parsed as it stands and refused, with diagnostic code `Empty`. | `BLANK_IS_REFUSED` in `parity_tests.rs` |
| Blank clears the default | The value is an empty list, which replaces a non-empty default. | `BLANK_CLEARS_THE_DEFAULT` in `parity_tests.rs` |

`parity_tests::every_input_treats_a_blank_value_by_one_of_three_legacy_rules`
classifies every inventoried variable, so a new one has to say which rule it
follows. These four lists are the ones a blank value clears:

| Setting | Default it replaces |
| --- | --- |
| `RBAC_EXEMPT_PATHS` | [The probe and status routes and the effective `ADMIN_PREFIX`](../configuration.md#rbac_exempt_paths) |
| `VALIDATION_ALLOWED_CONTENT_TYPES` | [`application/json`](../configuration.md#validation_allowed_content_types) |
| `AUTH_EXEMPT_PATHS` | [The probe and status routes and the effective `ADMIN_PREFIX`](../configuration.md#auth_exempt_paths) |
| `CSRF_EXEMPT_PATHS` | [The probe and status routes](../configuration.md#csrf_exempt_paths) |

Each of the four splits on commas and ignores empty entries, so a lone `,`
also gives an empty list, without being blank
(`parity_tests::a_lone_comma_clears_a_list_as_a_blank_value_does`). That
matters to an adapter that drops blank values before they reach the gateway,
as the [Cloudflare wrapper](#platform-adapters) does.
`stage_tests::the_compiler_contract_lists_every_list_a_blank_value_clears`
holds this table to `BLANK_CLEARS_THE_DEFAULT`.

Whether a non-blank value is trimmed before parsing is decided per setting
(`ADMIN_PREFIX` and `STATE_BACKEND` are trimmed; `LISTEN_ADDR` and
`AUTH_ENABLED` are not), and
`parity_tests::some_settings_are_trimmed_and_others_are_parsed_exactly_as_given`
pins it.

### What is not an input

The compiler sees only what its reader returns. These are read elsewhere and
are not configuration inputs:

- **Other reads in the gateway's own source**, listed and source-scanned in
  `inventory.rs` (`ENVIRONMENT_READS`): `HOSTNAME` or `COMPUTERNAME`, read
  once at startup and only when `CLUSTER_STATUS_EXPOSE_HOSTNAMES=true`; the
  variable an environment-kind operator secret alias names, read when a
  Connection credential is resolved (the compiler checks only the alias's
  shape); and the test harness's `GATEWAY_TEST_POSTGRES_*` locators, which a
  deployment never sets.
- **Dependency reads**, recorded from the dependencies' sources but not
  scanned (`DEPENDENCY_READS`): `SSL_CERT_FILE` and `SSL_CERT_DIR` choose the
  platform trust anchors of the egress and PostgreSQL TLS verifiers on Linux;
  `TOKIO_WORKER_THREADS`, `NO_COLOR`, and `TMPDIR` are read by Tokio,
  `tracing-subscriber`, and the standard library. The record is not
  exhaustive: a dependency update can add a read, and the Rust runtime's own
  variables and code compiled from C are not listed.

## Stages

The compiler requests its inputs in blocks, in the order the legacy parser
requested them, and gives each block's values to a pure stage function. A
stage parses each input of its block on its own, then checks the rules that
relate inputs, and returns a value and its findings. A stage is given values,
never a reader.

| Order | Block | Domain | Also reads |
| --- | --- | --- | --- |
| 1 | `ListenerInputs` | listeners | |
| 2 | `AdminSurfaceInputs` | identity | |
| 3 | `AuditStoreInputs` | storage | |
| 4 | `ShutdownInputs` | runtime | |
| 5 | `DiscoveryStoreInputs` | storage | |
| 6 | `ConnectionInputs` | connections | |
| 7 | `SignalInputs` | runtime | |
| 8 | `DocumentInputs` | storage | |
| 9 | `RequestBoundInputs` | runtime | |
| 10 | `TrustedProxyInputs` | proxy | |
| 11 | `RbacExemptionInputs` | identity | The admin surface: the exemption defaults follow `ADMIN_PREFIX` and `ADMIN_LOGIN_PROVIDER` |
| 12 | `ContentTypeInputs` | runtime | |
| 13 | `AuthenticationInputs` | identity | The admin surface, as for block 11 |
| 14 | `ToolRuntimeInputs` | runtime | |
| 15 | `ClusterInputs` | storage | |
| 16 | `ToolTimeoutInputs` | runtime | Builds the runtime plan |
| 17 | `ProviderAndCsrfInputs` | identity | Builds the identity plan |
| 18 | `RoutingInputs` | proxy | The identity plan (cookie-session delegation) and whether `POLICY_FILE` is set (host-bound routes) |
| 19 | `EgressInputs` | egress | |
| 20 | `StateBackendInputs` | storage | |
| 21 | `AuthorityEventInputs` | storage | The identity, Connections and runtime plans: every store and every cluster-only setting is paired with the backend that reads it. Builds the storage plan. |

Three properties follow:

- **One pass reports everything.** A refused input still yields a placeholder
  value (its default), so every later block checks its own inputs. The plan is
  validated only when no stage found anything; otherwise no plan is returned.
- **Problems keep their legacy order.** A stage parses all of its inputs
  before it checks a rule, while the legacy parser checked some rules between
  two reads. Each finding records the inventoried input after which the legacy
  parser reported it, and the report is sorted on that, stably
  (`stage::Checked::report`).
- **Domains see only validated values.** A cross-domain rule receives another
  domain's plan, never its raw inputs.

## Outputs

### The plan

`ConfigPlan` (`gateway/src/config/plan.rs`) holds one validated plan per
domain: `listeners`, `identity`, `proxy`, `storage`, `connections`, `egress`,
and `runtime`. Each records the provenance of its inputs:

```rust
pub(crate) struct Provenance {
    pub(crate) setting: &'static str,
    pub(crate) source: Source, // Default | Environment
}
```

`setting` is an inventory name and `source` says whether the default applied
or the environment set the value. A blank value that means unset is
`Default`; a blank value that clears a list is `Environment`. Both fields are
fixed text chosen by the gateway, so provenance cannot carry a value or a
locator however it is printed. Provenance is recorded today but no production
path reports it; the stage tests read it.

`ConfigPlan::into_config` consumes the plan and returns the legacy `Config`
that startup and the one-shot commands build from. It moves every value
across unchanged and hands the locators over as the plain paths activation
opens. There is no conversion back.

### Refusals

A refusal is a `ConfigError` with two parallel lists, one entry per problem,
in the legacy order:

- **Problems** (`ConfigError::problems`, and its `Display`) are the
  operator-facing report the gateway has always printed. A problem names its
  setting and may quote the value it refuses. That is right for a gateway
  describing its own environment back to the operator who set it, and wrong
  for anything that must not echo values.
- **Diagnostics** (`ConfigError::diagnostics`) are the same problems without
  values. Each `ConfigDiagnostic` carries the inventoried variable the problem
  begins with, a code describing how that variable was set, the rule that
  refused it, and a message built from those and fixed text alone. Nothing in
  a diagnostic is copied from a value or from a problem's wording, so it is
  value-free by construction rather than by redaction. No production path
  reports diagnostics yet; `import-standalone` keeps only the leading setting
  names of the problems instead.

#### Codes

| Code | The variable the problem begins with |
| --- | --- |
| `Unset` | is not set |
| `Empty` | is set to an empty or whitespace-only value |
| `NotUnicode` | is not valid Unicode |
| `Refused` | is set to a value that was refused, on its own or with another setting |
| `Unattributed` | is not an inventoried variable; no problem the compiler reports today has this shape |

#### Rules

`Value` is the refusal of one input's own value. Every other rule relates
inputs. `stage_tests::every_rule_is_reported_by_name_in_the_diagnostics`
reaches each rule, and `stage_tests::the_compiler_contract_lists_every_rule`
holds this table to `diagnostic::ConfigRule`.

| Rule | Refuses |
| --- | --- |
| `Value` | An input's own value: it does not parse, is out of bounds, or is not an accepted word. |
| `AdminListenerCollision` | `ADMIN_LISTEN_ADDR` on the data listener's address. |
| `GrpcListenerCollision` | `GRPC_LISTEN_ADDR` on the data or admin listener's address. |
| `TlsMaterialUnpaired` | Certificate and key files not set together, or not one key per certificate chain. |
| `AdminTlsWithoutAdminListener` | Admin TLS material without a separate admin listener. |
| `ClientCertificateAuth` | Client-certificate authentication without TLS, a CA bundle, or an identity source, or a CA or CRL file while the mode is `off`. |
| `ClientCertIdentitySourceUnused` | An identity source while both listeners' client-certificate modes are `off`. |
| `AdminSessionSettingsWithoutMode` | Admin session settings without a session mode that reads them. |
| `AdminSessionIdleTimeoutBounds` | An idle timeout outside 1 and the session's absolute lifetime. |
| `AdminLoginProviderUnusable` | An `ADMIN_LOGIN_PROVIDER` that cannot serve the admin login. |
| `AdminSessionRequirements` | An admin session store without the login, authentication, CSRF protection, or HTTPS redirect it relies on. |
| `AdminSessionCsrfExemption` | CSRF exemptions for admin API routes while an admin session store is on. |
| `TrustedProxyNetworksRequired` | `TRUST_PROXY_HEADERS` without a trusted proxy network. |
| `CookieSessionDelegation` | A route delegating the cookie session without the authentication and CSRF settings it relies on, or overlapping an exemption. |
| `UpstreamRoutingSourcesExclusive` | `UPSTREAM_URL` and `UPSTREAM_ROUTES` together. |
| `HostRoutesRequirePolicy` | A host-bound route without `POLICY_FILE`. |
| `SecretsRootRequired` | A file-backed secret alias or a keyring without `CONNECTION_SECRETS_ROOT`. |
| `LocalKeyringRequiresConnectionsStore` | `CONNECTION_LOCAL_SECRET_KEYRING` without `CONNECTIONS_SQLITE_PATH`. |
| `SecretAliasIdReserved` | A provider alias reusing an operator secret alias's ID. |
| `ClusterMemberStaleWindow` | A `CLUSTER_MEMBER_STALE_MS` shorter than the heartbeats a live replica may miss. |
| `ClusterModeRequirements` | `STATE_BACKEND=postgres` without the deployment ID, the database URL file, or a keyring it requires. |
| `LocalAuthorityInClusterMode` | A local file or SQLite store while PostgreSQL is the authority. |
| `AdminSessionStoreBackend` | An admin session store the state backend cannot host. |
| `ClusterSettingInStandaloneMode` | A cluster-only setting while `STATE_BACKEND` is `sqlite`. |
| `PayloadCaptureDestination` | Standalone payload capture without `DISCOVERY_SQLITE_PATH`. |
| `AuthorityEventSinkRequirements` | An authority-event sink without its pseudonym key alias or, for the file sink, its file. |
| `AuthorityEventMaterialUnused` | Authority-event material the configured sink never reads. |
| `AuthorityPseudonymKeysDistinct` | The current and previous pseudonym key aliases naming the same alias. |

Codes and rules are Rust enums. They have no serialized names yet: the first
report format that carries them must assign stable codes, and from then on a
rule's meaning is part of that format's contract.

## Sensitivity wrappers

A configuration names secret material in two ways: by value, which only the
legacy `AUTH_PROVIDERS` format allows, and by locator, which says where the
material is kept. A locator is sensitive too, because it maps where a
deployment keeps its keys. The compiler resolves neither. It carries each in a
type whose `Debug` output does not show it:

| Material | Inputs | Carried as | Prints as |
| --- | --- | --- | --- |
| Any raw value | Every input, before parsing | `stage::RawInput` | Nothing: it implements neither `Debug` nor `Display` |
| Inbound TLS private keys | `TLS_KEY_FILE`, `ADMIN_TLS_KEY_FILE` | `SecretLocator` inside `TlsMaterial` | `SecretLocator(<redacted>)` |
| The database connection string's file | `DATABASE_URL_FILE` | `SecretLocator` inside `DatabasePlan` | `SecretLocator(<redacted>)` |
| The secrets root, operator secret aliases, the three keyrings, the five provider documents | `CONNECTION_SECRETS_ROOT`, `CONNECTION_SECRET_ALIASES`, `CONNECTION_LOCAL_SECRET_KEYRING`, `ADMIN_LOGIN_KEYRING`, `RATE_LIMIT_KEYRING`, `CONNECTION_*_PROVIDER` | The Connections configuration types | Redacted, or as counts, by each type's own `Debug` |
| An OIDC client secret | `AUTH_PROVIDERS[].client_secret` | `AuthProviderConfig`, by value | `<redacted>` |
| Static request header values, client identity locators, URL query parameters | `UPSTREAM_ROUTES`, `MCP_UPSTREAM_SERVERS`, `UPSTREAM_URL` | `ProxyPlan` | Counts and booleans: how many routes and servers, and whether an upstream URL is set |

The client secret is the one secret value in the plan. The legacy document
holds it inline; making it a reference is an input-format change for #242's
bundle format, not a change to this stage.

What the contract covers, and what holds it:

- **No plan prints a secret or a locator**, whether a domain plan, the
  provenance, or the whole `ConfigPlan`
  (`stage_tests::no_plan_prints_a_secret_or_a_secret_locator`).
- **Diagnostics never carry a value**
  (`parity_tests::no_diagnostic_carries_a_value_even_when_every_input_holds_a_canary`,
  `parity_tests::no_diagnostic_carries_a_secret_or_locator_from_a_structured_input`).
- **A refusal does not carry the secrets or locators of settings it is not
  about**, in its problems, its `Debug`, or its diagnostics
  (`stage_tests::a_refusal_reports_no_secret_or_locator`). A problem may still
  quote the value it refuses.
- **The static-configuration fingerprint does not depend on secrets or their
  locators.** Two configurations that differ only in them get the same
  fingerprint
  (`stage_tests::the_fingerprint_is_the_same_whatever_the_secrets_and_their_locators_are`).
  A route's upstream TLS material locators are deliberately part of it, because
  they decide which trust the route carries.
- **The compiler logs one thing**: a warning naming the setting when an audit
  retention of `0` days disables pruning. It carries no value.

What the contract does not cover:

- **`Config`, after `into_config`.** It is activation's input, holds the
  locators as plain strings, and derives an ordinary `Debug` that prints them
  and the route documents in full. Do not log, serialize, or report a
  `Config`.
- **Problems.** They are for the operator who set the values, as above.
  Anything that reports another deployment's configuration, or reports
  configuration anywhere but the gateway's own startup output, uses
  diagnostics.

## The zero-I/O guarantee

Compiling a configuration does no I/O except asking the reader for values and
logging the one warning above. In particular, `compile`:

- opens, reads, creates, inspects, or canonicalizes no file or directory;
- resolves no host name and opens no socket, so no DNS, TLS, HTTP, OIDC
  discovery, JWKS fetch, MCP, or upstream request;
- opens, creates, or migrates no SQLite or PostgreSQL store;
- calls no secret provider and reads no key file;
- starts no process, thread, or task.

So a configuration can name files that do not exist and hosts that do not
resolve and still compile. The checks that need the world (a key file that
cannot be read, a store that cannot be opened, an issuer that does not answer)
happen in the startup stages after the compiler, and fail startup there.

What holds it:

1. **Shape.** Every stage is a function of its block's values and other
   domains' plans. `compile` takes nothing but the reader, and no stage is
   given one.
2. **A source scan.**
   `stage_tests::the_configuration_modules_name_no_input_or_output_api` reads
   `config.rs` and the compiler's modules and refuses any line of code (outside
   comments) naming a file, socket, resolver, process, Tokio, Hyper, SQLite,
   or PostgreSQL API, and counts their logging. It sees only those files. The
   functions they call in other modules (path matching, issuer and cookie-name
   canonicalization, route and ID shapes, header parsing, and the Connections
   document validators) are functions of their arguments, but the scan does
   not prove that. `scripts/check-egress-only.sh` separately refuses the
   outbound HTTP client anywhere outside `gateway/src/egress.rs`.
3. **Behavior.**
   `stage_tests::the_stages_carry_locators_and_destinations_without_touching_them`
   compiles a configuration of absent files and `.invalid` hosts and finds
   each carried unchanged and nothing created.
   `bootstrap_tests::compiling_touches_nothing_the_configuration_names` runs
   serving startup against a recording double, in standalone mode and in
   cluster mode with `DATABASE_AUTO_MIGRATE=true`, and its preflight, the first
   call after the compiler returns, finds the configured directory still
   absent.

Two limits. The reader is the caller's: `process_environment` reads the
process environment, and the import reader is a map the import parsed from
its file before compiling. And `gateway/src/config/bundle.rs`, the gateway's
half of the bundle reader, does read files. It is not part of the compiler,
the scan does not cover it, and nothing at startup calls it.

## Startup

`bootstrap::start_serving` runs the compiler first and alone, converts the
plan once, and then runs the stages of `StartupStages` in order, each given
that one `Config`:

1. **Preflight** proves the configured authority can be served: the backend
   this build carries and, in cluster mode, the database foundation, the
   control-plane seeds, the keyrings, and this boot's membership row.
2. **Activation** builds the gateway: metrics, the listeners' TLS material,
   the audit sinks, every store, client, and background task, and the
   routers. It binds nothing.
3. **Serving** binds the listeners and serves until shutdown.

A refused configuration reaches no stage. When a stage fails before any
listener served, what preflight published (the membership row) is withdrawn,
and background work activation started is stopped within
`SHUTDOWN_TIMEOUT_MS`, before the error is returned. The stages run the startup
work in the order it always ran, so effective values, configuration errors,
and their order are what `Config::from_env` has always produced. The one-shot
commands use the compiler through `Config::from_env` and run none of these
stages.

`bootstrap_tests.rs` runs the sequence against a recording double: a refused
configuration reaches no stage, each failure withdraws what was published, and
a failure after serving began is returned unchanged.

## Platform adapters

An adapter that sets the gateway's environment for a platform is part of the
contract only through the variables it passes. The Cloudflare wrapper
(`cloudflare/src/config.ts`) forwards an exact allowlist,
`GREEN_GATEWAY_ENV_KEYS`. `gateway/tests/env_example.rs`
(`cloudflare_forwarding_matches_supported_gateway_env_vars`) holds that list
to the variables the gateway reads, minus the exclusions it names with their
reasons, so a new setting cannot be silently left out.

The wrapper forwards only non-empty, non-whitespace string bindings, so on
Cloudflare a blank value always arrives as unset. For a blank-is-unset
setting that changes nothing. For a blank-is-refused setting the default
applies instead of a startup refusal. For the four lists a blank value clears,
the default applies instead of an empty list; set the binding to `,` to clear
one. See [Deploy GreenGateway on
Cloudflare](../deployment/cloudflare.md#blank-values).

## Extension points for #242

ADR-0008 places the compiler under bundle mode, `ggctl validate`, offline
doctor, and the Setup Center. Today's compiler covers stages 2 to 5 of the
ADR's pipeline (document validation, normalization, typing of secret
locators, and cross-field validation) for the environment only. What a #242
slice can build on, and what it must add:

### A second source

The stages consume values, not a reader, so another front end can feed them
without a second parser or validator. Today every input is a `RawInput`
holding the string a reader returned, and `Source` has two variants,
`Default` and `Environment`. A bundle front end must:

- produce the same block inputs and run the same stage functions, so that a
  setting means the same thing from either source and the parity goldens keep
  holding for the environment;
- record its own `Source` variant (the ADR names `bundle`, `ledger`,
  `bootstrap`, and `store`) instead of reporting bundle values as
  `Environment`;
- apply the ADR's source rules (overlapping environment variables refused,
  a documented bootstrap set allowed to coexist) before the stages, because
  the stages assume one coherent source.

The bundle reader in `gateway-config` (`bundle::read_bundle`) validates a
bundle's files, digests, documents, and profile today. Its deployment document
has one member, `spec.profile`, and nothing maps a bundle onto compiler
inputs. Profile invariants on deployment settings (authentication required,
private-address egress denied, and so on) are not enforced by the compiler
yet.

### Reports

`ConfigDiagnostic` is the form a validate or doctor report should carry for
environment configuration: it is value-free by construction and names the
setting, how it was set, and the rule. The report format must give codes and
rules stable string names (see [Rules](#rules)). Provenance is recorded per
input and is what a status or Setup Center view needs to explain where a
field came from; no API exposes it yet.

### The field catalog

`CONFIG_INPUTS` is a list of names in read order. The ADR's field catalog
adds per-field type, default, bounds, sensitivity, reload class, and platform
support. Until it lands, the facts it will hold are spread across the stage
code, the parity goldens (defaults and the blank-value classification),
`configuration.md`, `.env.example`, and the Cloudflare exclusions in
`gateway/tests/env_example.rs`. A catalog must be checked against all of them,
not written beside them.

### Moving the compiler into `gateway-config`

`ggctl` cannot compile environment configuration, because the compiler and
the validators it calls live in the gateway crate: the Connections secret
provider, alias, and keyring validators, upstream route validation, issuer
canonicalization (`auth::principal`), admin session types, inbound TLS and
client-certificate modes, and the discovery signal defaults. ADR-0008 does
not allow `ggctl` to approximate the gateway, so moving the compiler means
moving those validators with it. Until then, any `ggctl` report on
environment configuration must say it did not run the gateway's compiler.

### Local filesystem checks and preflight

The ADR's optional local filesystem stage (existence, type, permissions, and
containment of the files a configuration names) does not exist as a separate
step. Today those properties are discovered when preflight or activation opens
the files, and preflight is part of serving startup, not callable on its own.
An offline doctor needs a read-only filesystem stage that runs after the
compiler and before any preflight. It must not live in the compiler modules,
which the zero-I/O scan holds to no I/O.

## Changing the compiler

- **A new variable** gets a constant, an entry in `CONFIG_INPUTS` where its
  block reads it, a field in its block's inputs read in that block's `read`,
  its parse in the stage, a plan field, the `into_config` mapping, a
  classification in one of the three blank-value lists, a `### NAME` entry in
  `configuration.md`, a line in `.env.example`, and either an entry in the
  Cloudflare allowlist or an exclusion with its reason in
  `gateway/tests/env_example.rs`.
- **Secret material** (a value or a locator) gets a wrapper that does not
  print it, and a canary in the stage tests' secret fixtures.
- **A new cross-field rule** gets a `ConfigRule` variant, a fixture in
  `stage_tests::rule_fixture`, and a row in [Rules](#rules).
- **No I/O in the compiler modules.** Work that needs a file, a store, a
  provider, or the network belongs to a startup stage.
- **A changed golden is a behavior change.** The parity fixtures pin legacy
  semantics on purpose; a pull request that changes one says so in the
  CHANGELOG.
