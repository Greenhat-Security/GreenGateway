# Application composition boundaries

`gateway/src/main.rs` declares modules and translates process startup errors into
an exit code. Implementation is grouped by responsibility:

| Module | Responsibility |
|---|---|
| `bootstrap` | Process startup: the one-shot commands, the serving stages and cluster preflight, and the gateway build with its identity and tool bindings (see below) |
| `routing` | Listener routers, route registration and shared middleware ordering |
| `app_state` | Shared application state and route identities |
| `api_contracts` | Request/response types and application error contracts |
| `probes` | Health/readiness, metrics and proxy fallback |
| `admin_identity`, `admin_authorization` | Admin login, capabilities and final permission checks |
| `admin_config` | The configuration admin API: the `config/capabilities` version handshake `ggctl` reads |
| `admin_connections`, `admin_tools`, `admin_tokens`, `admin_policy`, `admin_policy_drafts` | Domain-specific handlers and mutations; policy drafts, including a discovery suggestion opened in one, publish only through `admin_policy`'s mutation path |
| `admin_observability`, `admin_events` | Audit, traffic, signals, suggestions and change telemetry |
| `admin_responses`, `admin_ui` | Shared error mapping and embedded UI serving |
| `admin_policy_test_runs`, `admin_policy_tests`, `admin_policy_test_gate`, `policy_testing` | Policy test suites: the run endpoint, the stored suite's `GET`/`PUT` (its stores are `storage::policy_tests` and `storage::postgres_policy_tests`), the `POLICY_TESTS_REQUIRED` gate every policy publication asks inside its commit precondition, and the state-free suite parser, evaluator-backed runner and JSON/SARIF/JUnit reports |
| `admin_policy_simulations`, `policy_simulation` | Synthetic policy simulation: the simulation endpoint and its concurrency bound, and the state-free request parser, position-aware edits, shadow projections and evaluator-backed runner |
| `admin_policy_analyses`, `admin_policy_analysis_suppressions`, `policy_analysis` | Structural policy analysis: the analysis endpoint and its concurrency bound, the finding suppression routes, and the state-free request parser, sound inclusion checks, evaluator-confirmed findings, advisory patches, suppression matching and JSON/SARIF reports |
| `admin_policy_replays`, `policy_replay` | Historical policy replay: the replay job endpoints, their process-local job registry and quotas, the cluster-mode job store front and the replay worker every cluster replica runs (`admin_policy_replays_cluster.rs`), and the state-free `replay-context.v1` record and parser, the legacy adapters that read one out of a stored audit event, their evaluator-backed replay, the `policy-replay.v1` request parser, the bounded job engine and the base-to-candidate and recorded-to-base impact comparison |
| `admin_policy_evidence`, `policy_evidence` | Policy evidence packages: the evidence endpoint, its history and owner-scoped draft reads, revalidation, analysis with suppressions, replay-job binding and export audit record, and the state-free `policy-evidence-request.v1` parser, deterministic `policy-evidence.v1` package assembler and fixed-template Markdown renderer |

`bootstrap.rs` is startup's root. `run` either runs the one-shot command the
arguments name or compiles the configuration and runs the serving stages, and
each part has its own module under `bootstrap/`:

| Module | Startup concern |
|---|---|
| `bootstrap/commands.rs` | The one-shot operator commands (`healthcheck`, `migrate`, `revoke-jwt`, `jwt-revocations-cleanup`, `rate-limit-buckets-cleanup`, `cluster-members`, `maintenance-run`, `import-standalone`, `connection-secrets`), dispatched before anything serving needs is initialized |
| `bootstrap/stages.rs` | `start_serving` and the `StartupStages` it runs (the configuration compiler, then preflight, activation and serving), and the gateway process's implementation of them |
| `bootstrap/cluster_preflight.rs` | Cluster mode's preflight: the boot seeds read and checked from the authority, and this boot's membership row (`postgres` builds only) |
| `bootstrap/gateway_app.rs` | Activation's gateway build: every store, client, background task and admin state, and the routers, in the order startup has always built them |
| `bootstrap/identity.rs` | The authentication validator chain, OIDC discovery and the egress hosts it seeds, and the admin login and session state |
| `bootstrap/tool_bindings.rs` | The Connection-binding check for tool definitions and the MCP upstream rediscovery a tools-file reload runs |

`bootstrap.rs` re-exports each module's items, which keep the visibility they
had when startup was one file, so callers name them as before
(`bootstrap::start_serving`). The split moved code without reordering it: the
stages run the same work in the same order, and the gateway build registers
routes, middleware and background tasks exactly as before.

Sibling modules share crate-private contracts through the composition root.
The extraction preserves the previous effective visibility and middleware order;
it does not introduce a second authorization or persistence path. New handlers
belong in their domain module and must be registered through `routing`.

Large inline unit suites in configuration, connection stores and tool execution
are in adjacent `*_tests.rs` files. The application suite, which drives the
composed router, is the set of subsystem modules `app_tests.rs` declares next
to the code they exercise: `auth_app_tests.rs` (authentication and the
validator chain), `admin_identity_app_tests.rs` (admin login, capabilities and
the admin-endpoint denial audit), `admin_tokens_app_tests.rs` (the token admin
API), `admin_policy_app_tests.rs` (policy administration),
`admin_connections_app_tests.rs` (Connections and local secrets),
`admin_tools_app_tests.rs` (the capability inventory, the tool playground and
OpenAPI tool registration), `mcp_app_tests.rs` (the MCP endpoint),
`admin_observability_app_tests.rs` (audit, status, traffic, signals,
suggestions, principals and schema coverage), `cluster_app_tests.rs` (cluster
status, readiness and the HA metric registry) and `routing_app_tests.rs`
(listeners, routing, proxying and the middleware order), beside the
per-feature `*_app_tests.rs`, `admin_policy_*_tests.rs`,
`admin_suggestion_drafts_tests.rs` and `admin_suggestion_acceptance_tests.rs`
modules it already declared and the
acceptance modules under `tests/`. `app_tests.rs` itself
defines no tests; it owns the fixtures more than one of these modules uses.
[The application test inventory](../testing/application-test-inventory.md)
counts the moves. A moved test keeps its function name, so a name filter still
selects it; only its module path gains the subsystem module, so an `--exact`
filter names the full path, `tests::<module>::<name>`.

`main.rs` declares `app_tests.rs` as `#[cfg(test)] mod tests`, so none of these
modules is compiled into the shipped binary, and moving a test between them
moves no production code. The security coverage floors in
`.github/security-coverage.json` name production files only, and CI measures
them with `cargo llvm-cov -p gateway --bin gateway`, the one test binary all of
these modules are compiled into: where a test lives decides neither what a floor
measures nor whether the test counts toward it.

The inbound TLS suite in `inbound_tls_tests.rs`, which drives real handshakes
against real listeners, is split the same way by the part of `inbound_tls.rs`
each family exercises: `inbound_tls_listener_tests.rs` (the accept path, the
handshake bound, saturation shedding and the negotiated protocol),
`inbound_tls_material_tests.rs` (loading certificates and keys at startup,
and their permission rules), `inbound_tls_client_certificate_tests.rs`
(client-certificate verification and failure labels),
`inbound_tls_session_resumption_tests.rs`,
`inbound_tls_credential_precedence_tests.rs`, `inbound_tls_sni_tests.rs` and
`inbound_tls_reload_tests.rs`. `inbound_tls_tests.rs` declares them as
modules of `inbound_tls::tests` and keeps the fixtures more than one of them
uses.

The React connection editor delegates validation, binding intent and request
serialization to `connection-editor/model.ts`; reusable form sections and local
secret controls live in `connection-editor/sections.tsx`. The view owns loading,
save orchestration and navigation. Maintain these boundaries when adding fields:
the server remains authoritative for permissions and secret binding validity.

## Shared configuration contracts

`gateway-config` is the library the gateway and `ggctl` both link (issue #242,
ADR-0008). Besides the bundle reader, catalog, ledger and digests its own
documentation lists, it holds the I/O-free leaves of the configuration
compiler, which is moving into it from `gateway/src/config`: the types and
validators a setting is parsed into, with no file, socket, clock or provider
behind them. The gateway re-exports each one from the module it used to live
in, so call sites did not change:

| `gateway-config` module | Holds | Re-exported by |
|---|---|---|
| `connections` | Connections limits (`MAX_CREDENTIALS`, display name, Connection and secret ID bounds) and the Connection ID grammar | `connections::model` |
| `connections::secret` | The operator alias document, the secrets root, and the alias, environment-key and file-key grammars | `connections::secret` |
| `connections::{aws,azure,gcp,vault,kubernetes}_secret` | Each secret provider's configuration document and validator | the gateway module of the same name |
| `connections::local_secret` | The local keyring document and validator | `connections::local_secret` |
| `inbound_tls` | `TlsMinVersion`, `ClientCertMode`, `ClientCertRequirement` | `inbound_tls` |
| `auth` | Issuer canonicalization and bound, JWKS key age bounds, the cookie-name grammar, `ClientCertIdentitySource`, admin session settings | `auth::principal`, `auth::jwt`, `middleware::auth`, `auth::client_certificate`, `auth::admin_session` |
| `path_match` | Exempt-path and prefix matching, unsafe request paths | `path_match` |
| `request_bounds` | The request shape bounds admission, the policy kernel and configuration share | `request_bounds` |
| `upstream_route` | The stable route ID grammar | `upstream_route` |
| `discovery` | Signal detector thresholds and the rule suggestion window, with their defaults | `discovery::signals`, `discovery::suggestions` |

Their unit tests moved with them and run under `cargo test -p gateway-config`,
except `path_match`'s: the tests `security-mutations.json` selects and the
property tests stay in the gateway's `path_match` module, because the mutation
campaign builds and runs only the gateway's test binary. Tests that exercise a
provider, a listener or a store, rather than the document, stay in the gateway.
What touches files, the network or a clock (provider construction, key and
secrets-root reads, listener binding) stays in the gateway, and the compiler's
zero-I/O scan (`config::stage_tests`) reads these modules too.
