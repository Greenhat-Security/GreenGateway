# Application test inventory

`gateway/src/app_tests.rs` is the gateway binary's `tests` module: the
application-level suite that drives the composed router, its middleware and
its admin API. Issue #434 moves it into subsystem test modules next to the
code they exercise. This page records what the file held before that work
started and where each family is meant to go, so every move can be checked
against a count instead of a read-through.

## How the tests were counted

The baseline is `origin/main` at `66a4b09`, listed the way the CI `test` job
lists it:

```bash
cargo test --workspace --locked -- --list --format terse
```

That listing has 3951 tests. The gateway binary's `tests::` tree holds 569 of
them. The listing does not say which binary a line came from, and `ggctl`'s
own `tests` module adds 4 more `tests::` lines, which are not counted here.

| Where the 569 are defined | Tests |
| --- | --- |
| `app_tests.rs`, top-level test functions | 404 |
| `app_tests.rs`, the four inline `#[cfg(feature = "postgres")]` modules (`durable_sse_tests` 7, `cluster_policy_tests` 13, `cluster_tools_tests` 9, `cluster_discovery_tests` 8) | 37 |
| Separate files already declared from `app_tests.rs` (below) | 128 |

Three of the top-level tests and all 37 inline-module tests need the
`postgres` feature, so a `--no-default-features` build has 401 tests in
`app_tests.rs` itself.

The files that were already separate keep their module paths: the
`admin_config_app_tests` (4), `admin_session_app_tests` (3),
`audit_durability_app_tests` (1), `audit_stream_app_tests` (7),
`admin_policy_drafts_tests` (13), `admin_policy_test_runs_tests` (12),
`admin_policy_simulations_tests` (9) and `admin_policy_replays_tests` (12)
suites, and the acceptance modules under `gateway/src/tests/`
(`issue_240_acceptance_core` 5, `issue_240_acceptance_security` 4,
`issue_256_acceptance_websocket` 35, `issue_257_acceptance_grpc` 17,
`issue_360_composite_acceptance` 2, `issue_373_oauth_bootstrap` 1,
`issue_463_caller_assertion_jwks` 3).

## Families

Each test in `app_tests.rs` belongs to the subsystem whose behaviour it
asserts, not to whichever helper it happens to call. The proposed modules are
a plan for the later slices of #434; each slice confirms its family's
membership and updates this table when it moves it.

| Family | Code it exercises | Proposed module | Tests | Status |
| --- | --- | --- | --- | --- |
| Identity and authentication: auth modes, the validator chain (OIDC discovery, JWKS, service tokens, cookie sessions, client certificates) and authentication ahead of RBAC | `auth/`, `middleware/auth.rs`, `bootstrap::auth_validator_from_config` | `auth_app_tests.rs` | 16 | moved (#434 PR 1) |
| Admin login and capabilities: the admin OIDC login flow, the capabilities endpoint and the admin-endpoint denial audit | `admin_identity.rs` | `admin_identity_app_tests.rs` | 19 | moved (#434 PR 1) |
| Admin API tokens: create, list, get, rotate and revoke, actor recording and scope delegation | `admin_tokens.rs`, `admin_authorization::authorize_requested_scopes` | `admin_tokens_app_tests.rs` | 19, 2 of them PostgreSQL-only | moved (#434 PR 1) |
| Policy administration: policy and rule CRUD, history, rollback, validate and convert, rule preview, hits and shadow review | `admin_policy.rs` | `admin_policy_app_tests.rs` | 65, plus 13 in `cluster_policy_tests` | in `app_tests.rs` |
| Connections: Connection and local-secret CRUD, test and refresh, managed OpenAPI, overlays and caller assertions | `admin_connections.rs` | `admin_connections_app_tests.rs` | 33 | in `app_tests.rs` |
| Tools: the capability inventory, the tool playground and OpenAPI tool registration | `admin_tools.rs` | `admin_tools_app_tests.rs` | 20, plus 9 in `cluster_tools_tests` | in `app_tests.rs` |
| MCP: `/mcp`, protected-resource metadata, upstream MCP tools and their traffic inventory rows | `mcp.rs`, `tools/` | `mcp_app_tests.rs` | 53 | in `app_tests.rs` |
| Observability: audit query and stream, status, traffic, signals, suggestions, principals and schema coverage | `admin_observability.rs`, `admin_events.rs` | `admin_observability_app_tests.rs` | 86, plus 7 in `durable_sse_tests` and 8 in `cluster_discovery_tests` | in `app_tests.rs` |
| Cluster status and readiness: the cluster routes, readiness gates and the HA metric registry | `probes.rs`, `cluster_status.rs`, `ha.rs` | `cluster_app_tests.rs` | 12 | in `app_tests.rs` |
| Listeners, routing and proxy: listener split, admin prefix, admin UI serving, probes, the routing table, proxying and the middleware order | `routing.rs`, `probes.rs`, `proxy/`, `middleware/` | `routing_app_tests.rs` | 81 | in `app_tests.rs` |

The rows add up to the 441 tests defined in `app_tests.rs`.

## After the first move

The identity, admin login and capabilities, and token admin families now live
in `auth_app_tests.rs`, `admin_identity_app_tests.rs` and
`admin_tokens_app_tests.rs`, declared from `app_tests.rs`. The listing still
has 3951 tests with the same test names. Exactly 54 paths changed, each from
`tests::<name>` to `tests::<module>::<name>`, so a filter on the test name
still selects the test. `app_tests.rs` now defines 387 tests (350 top-level and
the same 37 inline), and the separate files 182.

The 28 fixtures that only these tests used moved with them. The rest of what
they use stays in `app_tests.rs`, because another family or an already
separate module names it too: for example `test_config`, `TempDb`,
`TempPolicyFile`, the JWT signing fixtures, the mock OIDC endpoints
(`admin_session_app_tests.rs` uses them) and the token admin router (the
capabilities and denial tests drive it as well as the token tests).

## Shared fixtures

A fixture moves with a family only when nothing outside that family names
it. Everything else stays in `app_tests.rs`, which owns the shared fixtures
for every module declared from it: the test configuration (`test_config`),
the temporary database, policy, tools and spec files, the audit log
builders, the JWT signing key and JWKS servers, the mock OIDC endpoints, the
per-surface admin routers and request builders, and the polling helpers.
There is no separate helper module; a test's authority setup stays visible
in the test or in the one fixture it calls.
