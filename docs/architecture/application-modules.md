# Application composition boundaries

`gateway/src/main.rs` declares modules and translates process startup errors into
an exit code. Implementation is grouped by responsibility:

| Module | Responsibility |
|---|---|
| `bootstrap` | CLI dispatch, configuration, stores and runtime construction |
| `routing` | Listener routers, route registration and shared middleware ordering |
| `app_state` | Shared application state and route identities |
| `api_contracts` | Request/response types and application error contracts |
| `probes` | Health/readiness, metrics and proxy fallback |
| `admin_identity`, `admin_authorization` | Admin login, capabilities and final permission checks |
| `admin_connections`, `admin_tools`, `admin_tokens`, `admin_policy`, `admin_policy_drafts` | Domain-specific handlers and mutations; policy drafts publish only through `admin_policy`'s mutation path |
| `admin_observability`, `admin_events` | Audit, traffic, signals, suggestions and change telemetry |
| `admin_responses`, `admin_ui` | Shared error mapping and embedded UI serving |
| `admin_policy_test_runs`, `policy_testing` | Policy test suites: the run endpoint, and the state-free suite parser, evaluator-backed runner and JSON/SARIF/JUnit reports |
| `admin_policy_simulations`, `policy_simulation` | Synthetic policy simulation: the simulation endpoint and its concurrency bound, and the state-free request parser, position-aware edits, shadow projections and evaluator-backed runner |
| `admin_policy_replays`, `policy_replay` | Historical policy replay: the replay job endpoints, their process-local job registry and quotas, and the state-free `replay-context.v1` record and parser, the legacy adapters that read one out of a stored audit event, their evaluator-backed replay, the `policy-replay.v1` request parser, the bounded job engine and the base-to-candidate and recorded-to-base impact comparison |

Sibling modules share crate-private contracts through the composition root.
The extraction preserves the previous effective visibility and middleware order;
it does not introduce a second authorization or persistence path. New handlers
belong in their domain module and must be registered through `routing`.

Large inline unit suites in configuration, connection stores and tool execution
are in adjacent `*_tests.rs` files. The main application suite is `app_tests.rs`,
with acceptance modules still under `tests/`. Test module names remain stable.

The React connection editor delegates validation, binding intent and request
serialization to `connection-editor/model.ts`; reusable form sections and local
secret controls live in `connection-editor/sections.tsx`. The view owns loading,
save orchestration and navigation. Maintain these boundaries when adding fields:
the server remains authoritative for permissions and secret binding validity.
