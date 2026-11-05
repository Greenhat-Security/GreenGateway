# Application test inventory

`gateway/src/app_tests.rs` is the gateway binary's `tests` module: the
application-level suite that drives the composed router, its middleware and
its admin API. Issue #434 moved its tests into subsystem test modules next to
the code they exercise. This page records what the file held before that work
started and where each family went, so every move can be checked against a
count instead of a read-through. The issue's last slice applied the same rule
to startup (`bootstrap.rs`) and to the inbound TLS suite
(`inbound_tls_tests.rs`);
[the third move](#the-third-move-startup-and-the-inbound-tls-suite) records it.

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
asserts, not to whichever helper it happens to call. The first slice of #434
proposed a module and a count for each family; each slice confirmed a
family's membership when it moved it, and the table gives the confirmed
counts.

| Family | Code it exercises | Module | Tests | Status |
| --- | --- | --- | --- | --- |
| Identity and authentication: auth modes, the validator chain (OIDC discovery, JWKS, service tokens, cookie sessions, client certificates) and authentication ahead of RBAC | `auth/`, `middleware/auth.rs`, `bootstrap::auth_validator_from_config` | `auth_app_tests.rs` | 16 | moved (#434 PR 1) |
| Admin login and capabilities: the admin OIDC login flow, the capabilities endpoint and the admin-endpoint denial audit | `admin_identity.rs` | `admin_identity_app_tests.rs` | 19 | moved (#434 PR 1) |
| Admin API tokens: create, list, get, rotate and revoke, actor recording and scope delegation | `admin_tokens.rs`, `admin_authorization::authorize_requested_scopes` | `admin_tokens_app_tests.rs` | 19, 2 of them PostgreSQL-only | moved (#434 PR 1) |
| Policy administration: policy and rule CRUD, history, rollback, validate and convert, rule preview, hits and shadow review, and the startup refusal of an invalid policy file | `admin_policy.rs` | `admin_policy_app_tests.rs` | 66, plus 13 in `cluster_policy_tests` | moved (#434 PR 2) |
| Connections: Connection and local-secret CRUD, test and refresh, managed OpenAPI, overlays and caller assertions | `admin_connections.rs` | `admin_connections_app_tests.rs` | 33 | moved (#434 PR 2) |
| Tools: the capability inventory, the tool playground and OpenAPI tool registration | `admin_tools.rs` | `admin_tools_app_tests.rs` | 18, plus 9 in `cluster_tools_tests` | moved (#434 PR 2) |
| MCP: `/mcp`, protected-resource metadata, upstream MCP tools, the MCP route's streaming body limit and the traffic inventory rows MCP calls record | `mcp.rs`, `tools/` | `mcp_app_tests.rs` | 52 | moved (#434 PR 2) |
| Observability: audit query and stream, status, traffic, signals, suggestions, principals, schema coverage and inference, and the startup refusal of a missing or broken OpenAPI spec | `admin_observability.rs`, `admin_events.rs` | `admin_observability_app_tests.rs` | 85, plus 7 in `durable_sse_tests` and 8 in `cluster_discovery_tests` | moved (#434 PR 2) |
| Cluster status and readiness: the cluster routes, readiness gates and the HA metric registry | `probes.rs`, `cluster_status.rs`, `ha_status.rs` | `cluster_app_tests.rs` | 12 | moved (#434 PR 2) |
| Listeners, routing and proxy: listener split, admin prefix, admin UI serving, probes, the routing table, proxying, rate limits, CORS and the middleware order | `routing.rs`, `probes.rs`, `proxy/`, `middleware/` | `routing_app_tests.rs` | 84 | moved (#434 PR 2) |

The rows add up to the 441 tests `app_tests.rs` defined at the baseline.

## After the first move

The identity, admin login and capabilities, and token admin families now live
in `auth_app_tests.rs`, `admin_identity_app_tests.rs` and
`admin_tokens_app_tests.rs`, declared from `app_tests.rs`. Measured on the
same `66a4b09` baseline with only this move applied, the listing still has
3951 tests with the same test names. Exactly 54 paths changed, each from
`tests::<name>` to `tests::<module>::<name>`, so a filter on the test name
still selects the test. `app_tests.rs` now defines 387 tests (350 top-level and
the same 37 inline), and the separate files 182.

The 28 fixtures that only these tests used moved with them. The rest of what
they use stays in `app_tests.rs`, because another family or an already
separate module names it too: for example `test_config`, `TempDb`,
`TempPolicyFile`, the JWT signing fixtures, the mock OIDC endpoints
(`admin_session_app_tests.rs` uses them) and the token admin router (the
capabilities and denial tests drive it as well as the token tests).

## After the second move

The other seven families now live in `admin_policy_app_tests.rs`,
`admin_connections_app_tests.rs`, `admin_tools_app_tests.rs`,
`mcp_app_tests.rs`, `admin_observability_app_tests.rs`, `cluster_app_tests.rs`
and `routing_app_tests.rs`, declared from `app_tests.rs`. Each of the four
inline PostgreSQL modules moved whole into its family's module and kept its
name: `cluster_policy_tests` is in `admin_policy_app_tests.rs`,
`cluster_tools_tests` in `admin_tools_app_tests.rs`, and `durable_sse_tests`
and `cluster_discovery_tests` in `admin_observability_app_tests.rs`.
`app_tests.rs` no longer defines a test.

The second move was measured on `origin/main` at `0d483e9`, which includes
the first move, before and after the move. Both listings have 4027 tests,
with the same test names. Exactly 387 paths changed: 350 from
`tests::<name>` to `tests::<module>::<name>`, and 37 from
`tests::<inline module>::<name>` to `tests::<module>::<inline module>::<name>`.
A filter on the test name, or on `<inline module>::<name>`, still selects the
test.

Confirming each family's membership changed five counts from the first
slice's proposal: policy 65 to 66, tools 20 to 18, MCP 53 to 52, observability
86 to 85 and listeners, routing and proxy 81 to 84. The table gives the confirmed
counts, and the rows still add up to 441. Where a name does not say the
family: the startup refusal of an invalid policy file is a policy test, the
startup refusal of a missing or broken OpenAPI spec an observability test, the
traffic inventory rows MCP calls record are MCP tests, and the two
cache-control path matchers in `routing.rs`, connection-bound proxying and
the host-qualified fallback policy are routing tests.

A fixture counts once with its impl blocks. Of the 375 fixtures
`app_tests.rs` held before this move, 221 were used by one family alone and
moved with it. The other 154 stay, because more than one family or an already
separate module names them. One of them,
`clear_discovery_routing_classification`, was observability's alone at
`0d483e9`; `admin_suggestion_drafts_tests.rs`, which main added later, names
it too, so it stays in `app_tests.rs`.

## Shared fixtures

A fixture moves with a family only when nothing outside that family names
it. Everything else stays in `app_tests.rs`, which now holds only the shared
fixtures for every module declared from it: the test configuration
(`test_config`), the temporary database, policy and tools files, the audit
log builders, the JWT signing key and JWKS servers, the mock OIDC endpoints,
the admin routers and request builders more than one module drives, and the
polling helpers.
There is no separate helper module; a test's authority setup stays visible
in the test or in the one fixture it calls.

## Acceptance evidence

The issue's selector and documentation slice measured both application moves
once more, after `main` had moved on, and checked everything that names a test
or a test file.

**Every test still runs once.** On `origin/main` at `952e3677`, which has the
first move but not the second, and on that same commit with the second move
merged, the listing, taken as above, has 4173 tests, with the same multiset of
test names and no path listed twice. Exactly 387 paths differ, and each is the old path
with the family module inserted after `tests::`: 350 top-level tests and the
37 in the four inline PostgreSQL modules. Both listings were taken with the
same toolchain on Windows, where a `#[cfg(unix)]` test compiles to nothing. No
application test is gated that way: the suite's `#[cfg(unix)]` blocks only set
file permissions inside a test or fixture body, so a Linux listing changes the
same 387 paths.

**Nothing changed on the way.** Compared line by line as a multiset,
`app_tests.rs` and the ten family modules hold every line `app_tests.rs` and
the modules it declared held before each move. Across the first move's merge
(`453e8fc1`) no line is missing and 21 are new; against `952e3677`, with the
second move merged, no line is missing and 60 are new, as in the second move's
own merge into `main` (`390bb0ec`). The new lines are only the wiring (a
`#[path]` and `mod` pair per module in `app_tests.rs` and `use super::*;` at
the top of each module), each module's doc comment and a blank line after
it. So every test and fixture, with every assertion, moved
unedited, and `main`'s later edits to tests that had moved landed in their new
modules.

**Every selector still selects.** A moved test keeps its name, so a filter on
the name, or on `<inline module>::<name>`, still selects it. What names a test
or a test file by path was updated with the move or was already
path-independent:

- No CI workflow selects a test from `app_tests.rs` or the family modules,
  and no workflow has a path filter. The coverage run excludes one test,
  `audit::sqlite_sink::tests::moderate_scale_batched_inserts_complete_quickly`,
  which did not move.
- `security-mutations.json` names no moved test, and the CI test-list check
  (`security_mutations.py --check-test-list`) passes on both listings. The
  microbenchmark kernel (`policy_benchmark::http_policy_evaluation`) and the
  security corpus worker (`security_corpus::bounded_corpus_worker`) are not
  application tests.
- The issue #240 acceptance ledger and `docs/authority-evidence-inventory.json`
  cite tests as a file and a function; their citations of `app_tests.rs` name
  the family modules, and `check-issue-240-acceptance.mjs` and
  `check-authority-evidence.mjs` find every cited function there.
- `ENVIRONMENT_READS` (`gateway/src/config/environment_reads.rs`) counts the
  `GATEWAY_TEST_POSTGRES_URL_FILE` reads in the modules the inline PostgreSQL
  suites moved to.
- [The load-sensitive test list](load-sensitive-tests.md) gives each test's
  full path, which its `--exact` re-run needs, and the three application
  tests on it are under `tests::admin_observability_app_tests::` and
  `tests::mcp_app_tests::`.
- Every other document or comment that cites a moved test names it by its
  bare name, by `<inline module>::<name>` or by
  `cluster_app_tests::<name>`, each of which still selects it.

**Coverage floors still apply.** No file that `.github/security-coverage.json`
floors changed in either move, and no production code moved: `main.rs`
declares `app_tests.rs` under `#[cfg(test)]`, so every module it declares is
compiled for tests only. The gateway coverage run,
`cargo llvm-cov -p gateway --bin gateway`, builds the one test binary all of
them are compiled into, and the gate reads only the floored files, so neither
a floor's denominator nor the set of tests that exercise floored code changed.

**Secret scanning needed no new exception.** `.gitleaksignore` pins each
reviewed finding to a commit, path and line, and none of its entries names
`app_tests.rs` or a family module. `.gitleaks.toml` allows three exact
values wherever they appear. The only one in this suite, the test RSA key that
signs the JWT fixtures (`TEST_JWT_PRIVATE_KEY`), is a shared fixture and stayed
in `app_tests.rs`; no family module contains an allowlisted value or a private
key block. The moved lines are byte for byte the lines the full-history scan
already reads in `app_tests.rs`, so no fingerprint or allowlist entry was moved
or added.

## The third move: startup and the inbound TLS suite

The last slice of #434 split the two other large files the issue names. It was
measured on `origin/main` at `cffd168f`, before and after the move.

**Startup.** `bootstrap.rs` is production code, so splitting it moved no test.
Its 3396 lines are now `bootstrap.rs`, which keeps `run` and the module wiring,
and six modules under `bootstrap/`, one per startup concern, listed in [the
module map](../architecture/application-modules.md). `bootstrap_tests.rs`, the
9 tests that run the serving stages against a recording double, is still
declared from `bootstrap.rs`, so they keep their `bootstrap::tests::<name>`
paths. Compared as a multiset, the new files hold every line `bootstrap.rs`
held except the ones the move had to change:

- an item's visibility where its new module needed it. What was `pub(super)`
  in `bootstrap` is `pub(crate)` in its module and re-exported from
  `bootstrap.rs`, and what was private but is used from another module (or
  from `bootstrap_tests.rs`) is `pub(super)`, so every item is visible exactly
  where it was. rustfmt rewrapped the two of these lines that grew too long.
- the one-shot commands' early returns. The commands left `run` for
  `run_one_shot_command`, which returns `Ok(true)` when a command ran, so its 8
  `return Ok(());` lines became `return Ok(true);`, and the `healthcheck`
  probe's result is now checked with `?` before its own `return Ok(true);`.
- the `#[cfg(feature = "postgres")]` attributes of the two cluster preflight
  items, which the declaration and re-export of their module now carry.

A second commit moved two blocks of the gateway build that read only the
configuration and the route table, the suggestion engine's proxy routes and
the warning about unowned exempt paths, into functions with the same bodies,
called where the blocks ran.

**The inbound TLS suite.** `inbound_tls_tests.rs` held the 87 tests of
`inbound_tls::tests`, 10 of them Unix-only, divided by section comments. Each
section family is now a module of `inbound_tls::tests` in a file of its own:

| Family | Code it exercises | Module | Tests |
| --- | --- | --- | --- |
| The listener path: plaintext when TLS is not configured, a handshake end to end, the handshake bound, saturation shedding, and the negotiated protocol floor and ALPN | `TlsListener`, `accept_loop`, `HandshakeLimits` | `inbound_tls_listener_tests.rs` (`listener`) | 11 |
| Material at startup: missing, malformed, mismatched or oversized material, and on Unix the private key's permission rules and projected material | `load_server_config`, `read_material`, `open_material_directory` | `inbound_tls_material_tests.rs` (`material`) | 19, 8 of them Unix-only |
| Client-certificate authentication and its failure labels | `load_client_verifier`, `client_identity`, `classify_client_certificate_failure` | `inbound_tls_client_certificate_tests.rs` (`client_certificates`) | 15 |
| Session resumption on client-certificate listeners | `disable_session_resumption` | `inbound_tls_session_resumption_tests.rs` (`session_resumption`) | 6 |
| Credential precedence over a real listener | the credential order of `middleware::auth` | `inbound_tls_credential_precedence_tests.rs` (`credential_precedence`) | 6 |
| SNI chain selection and the chain-set rules | `SniServerCertResolver`, `load_certified_chains`, `validate_server_name` | `inbound_tls_sni_tests.rs` (`sni`) | 17 |
| Material reload | `reload_listener_material` and the material watcher | `inbound_tls_reload_tests.rs` (`reload`) | 13, 2 of them Unix-only |

A fixture counts once with its impl blocks and with its `cfg(unix)` twin. Of
the 70 fixtures the file held, 28 were used by one family alone and moved with
it. The other 42 stay in `inbound_tls_tests.rs`: 17 of the 19 at the top of the
file (`tls_request` and `plaintext_request` were the listener family's alone),
and 25 defined among the client-certificate and SNI tests that later families
use too, now under two short headers. `pem_encode`, defined among the SNI
tests but used by one client-certificate test alone, moved to
`client_certificates`. Both import blocks stay in `inbound_tls_tests.rs`.

**Every test still runs once.** On `cffd168f` and on the same commit with this
move, the listing, taken as above on Windows, has 4254 tests, with the same
multiset of test names and no path listed twice. Exactly 77 paths differ, each
`inbound_tls::tests::<name>` becoming `inbound_tls::tests::<family>::<name>`.
The 10 Unix-only tests, which a Windows build compiles to nothing, are in
`material` and `reload`, so on Linux their paths change the same way; a Linux
`cargo check --workspace --all-targets` of the moved tree, with default
features and with `--no-default-features`, compiles them.

**Nothing changed on the way.** Compared line by line as a multiset, the eight
TLS test files hold every line `inbound_tls_tests.rs` held, and none is
missing. The 63 new lines are the wiring (a `#[path]` and `mod` pair per family
and `use super::*;` at the top of each), each module's doc comment and the two
fixture headers.

**Every selector still selects.** A moved TLS test keeps its name, so a filter
on the name still selects it, and an `--exact` filter names
`inbound_tls::tests::<family>::<name>`. No CI workflow, script, registry or
document names an inbound TLS test, `security-mutations.json` names none, and
the CI test-list check passes on the new listing. What named `bootstrap.rs` by
path was updated with the split: the authority evidence inventory's citations
of the `revoke-jwt` command and of `start_serving`, which
`check-authority-evidence.mjs` resolves, the pool-sizing test that reads the
cluster command words, ADR-0008 and the compiler contract.
`config/inventory.rs` still finds the tracing subscriber that reads `NO_COLOR`
in `bootstrap.rs`, where `run` builds it.

**Coverage floors still apply.** No file that `.github/security-coverage.json`
floors changed. The startup code moved to production files under
`gateway/src/bootstrap/`, which the gateway coverage run instruments as it did
`bootstrap.rs`, and the TLS suite is still `#[cfg(test)]` under
`inbound_tls.rs`, compiled into the same test binary.

**Secret scanning needed no new exception.** No `.gitleaksignore` entry names
`bootstrap.rs` or the TLS suite, the suite generates its certificates and keys
at run time, and its moved lines are byte for byte the lines the full-history
scan already reads in `inbound_tls_tests.rs`, so no fingerprint or allowlist
entry was moved or added. `transport-ownership.json` gained a record for each
new glob import and re-export and for `run_one_shot_command`, whose only
capability is the `std::process::exit` it had in `run`, and `run`'s record has
its new hash; no network or process authority was added.
