# Load-sensitive tests

Some tests in this repository fail intermittently when the suite runs under heavy parallel load, and pass in isolation. This page names the ones that have actually been observed doing so, because the alternative is that each person who hits one re-investigates it from scratch — which has already happened several times in a single day of concurrent work.

## The rule

**Re-run a suspected flake in isolation before concluding anything.**

```bash
cargo test -p gateway --bin gateway <test_name> -- --exact
```

**Membership in this list is not permission to ignore a failure.** A listed test failing *consistently*, or failing in isolation, is a regression. The list exists to stop people re-deriving a known answer, not to provide a reason to skip one. If a listed test starts failing reliably, treat it as a real defect and investigate it as one.

If you add a test to this list, say what makes it timing-dependent. "It's flaky" is not a diagnosis, and a test nobody can explain is a test nobody can fix.

## Observed

Each of these has been seen to fail under parallel load and pass in isolation. None is believed to be a real defect.

| Test | Why it is timing-dependent |
| --- | --- |
| `status_commit_refreshes_busy_timeout_from_current_deadline_budget` | Asserts on a deadline budget computed from wall-clock time. |
| `inferred_conformance_refreshes_cached_schema_after_ttl` | Depends on a cache TTL elapsing. |
| `retryable_connect_failure_prefers_a_different_endpoint` | Depends on connect failure and retry ordering. |
| `traffic_endpoint_lifecycle_flags_rule_coverage_and_hot_reload` | Depends on a file-watch reload being observed. |
| `sse_circuit_permit_stays_pending_until_stream_completion` | Asserts a permit is still held at a point in a stream's lifetime. |
| `connections::http::tests::stalled_oauth_denial_is_classified_and_invalidates_the_cached_token` | Drives a deliberately stalled request against a timeout. |
| `connections::http::tests::timed_out_connection_test_drops_owned_oauth_mint_before_return` | Asserts a drop ordering that a timeout races. |
| `tools::definitions::tests::reload_rejects_local_tool_colliding_with_preserved_mcp_proxy_tool_name` | Depends on a registry reload being observed. |
| `repeated_mcp_tool_calls_accumulate_into_one_inventory_row` | Depends on inventory aggregation completing. |
| `proxied_mcp_tool_call_appears_as_per_tool_traffic_inventory_row` | Depends on inventory aggregation completing. |
| `egress::tests::rejected_scheme_log_exposes_only_a_bounded_category` | Asserts on log output whose capture competes with parallel test output. |

## The admin UI live acceptance test races the page's own sign-in probe

`admin-ui/tests/issue-240-live.spec.ts` drives a real browser against a real
gateway, and its `saveBearerToken` helper navigates to `/admin/`, fills the
token field and clicks Save. On load the app requests its own capabilities with
whatever credential it has, which on a fresh tab is none; that request answers
`401`, and `adminSessionEnded` clears the credential field and sets the status
to "Session ended. Sign in again." — deliberately, because a field holding a
credential should not survive a session ending.

If that `401` lands between the helper's fill and its click, Save reads an empty
field, and the test fails waiting for "Token active in this tab until reload or
session expiry." The captured page state proves this shape rather than a lost
save: the token box is empty and the status reads "Session ended. Sign in
again." Run it in isolation to confirm before concluding anything:

```bash
cd admin-ui && npx playwright test --config playwright.issue240.config.ts \
  -g 'uses real jwt read capabilities'
```

This became easier to lose with Vite 8 (PR #507), which serves the dev bundle
sooner and so moves the fill earlier relative to that probe; the application
code and the test are both unchanged from before that upgrade. The durable fix
belongs on the test side — wait for the logged-out steady state before typing,
rather than teaching the app to keep a credential in a field across a session
end — and is deliberately not bundled into a dependency upgrade.

## Platform coverage gaps, which are not flakiness

Worth knowing separately, because they produce the *opposite* symptom — a test that silently does not run rather than one that fails.

`gateway/tests/lifecycle_shutdown.rs` is `#![cfg(unix)]`. On a Windows development machine cargo compiles it to nothing: it does not run, and it does not even typecheck. A change to it can look locally clean and fail on CI.

To typecheck or run it on Windows, temporarily replace the `#![cfg(unix)]` attribute on line 1, run, and restore it. The SIGTERM tests themselves still need a Unix `kill`, but the rest will compile and the non-signal tests will run.

That gap is how a real defect reached CI: a port-collision race in that file's startup gate let one test's probe connect to *another* test's gateway and conclude its own child had started (fixed in #318). The gate now requires a served response rather than a bare TCP connect, and port allocation through child startup is serialized.
