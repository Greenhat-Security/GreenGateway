# Required CI test evidence

A successful producer must leave its required evidence before its job can pass.
Validation and required uploads use `always()` with that producer's explicit
`outcome == 'success'`. Earlier failures, cancellation, and skipped producers do
not require success-only files. No producer or validator uses
`continue-on-error`. Available failure diagnostics are preserved separately with
best-effort uploads, without changing the original test result.

| Producer | Required successful output and validation | Optional diagnostics / boundary |
| --- | --- | --- |
| Security coverage | `target/security-coverage.json`: the existing coverage-floor checker parses JSON and requires nonzero line/branch instrumentation for every configured source. Upload absence is an error. | Partial coverage from a failed producer is retained when available. |
| Live admin UI Playwright suite | Distinct JSON report in runner temporary storage; validated nonzero executed counts agree with nested test outcomes, with no unexpected tests or global errors. Only `admin-ui/playwright-report/live-summary.json`, containing counts, is uploaded. | Live auth traces remain disabled. Raw reporter JSON may include fixture values and stays outside artifact paths. |
| Screenshot Playwright suite | A separate temporary JSON report with the same count checks, plus a nonempty `admin-ui/.screenshots/**/*.png` group. Every PNG must have its PNG header, IHDR and terminal IEND marker. `screenshots-summary.json` records counts and screenshot count. The validator checks both groups independently. | Existing `test-results/` failure diagnostics are optional; absence is normal on success. Hidden-file upload is enabled only for the explicitly selected PNG paths, so `.screenshots` is actually retained. Pixel/layout assertions remain in Playwright. |
| Dev traffic smoke / streamed upload | `artifacts/proxy-load/ci-stream.json` must parse, complete all requested requests, record successful response counts and positive duration, and have no errors or failed assertions. The uploaded `ci-stream-summary.json` retains only bounded counts and timing. | Validation is eligible only when the complete smoke step succeeds; a failure before the streaming scenario does not require this output. Raw configuration, URLs, run IDs and errors are not uploaded. |
| HA release matrix | Each of the eight suites emits `gate.log` and runner logs. Existing checks require a completed nonempty suite and elapsed time above the silent-skip boundary. | These tests do not declare a separate downloadable report. Runner logs are their evidence; this change does not invent per-test artifacts or upload temporary database/secret files. |
| Nightly HA performance | Existing `${runner.temp}/ha/ha-performance.json` upload remains strict, including on failure; the producer updates its JSON after every measurement. Nonempty test counts, a valid locator and minimum elapsed time are already enforced. | This existing always-on strict upload is unchanged. A previous-night baseline is optional. |
| Manual proxy load / resilience | Commands in [the performance guide](../performance/proxy-baseline.md) emit JSON in `artifacts/proxy-load/<timestamp>/`; preserve the selected run with its release evidence. | These commands are not run by the ordinary PR job. Target-environment capacity and recovery approval remain #389. |
| Release image checks | Candidate scanning, provenance/SBOM verification and preview runtime checks retain their existing strict artifacts and independent validators. | No release/promotion contract is relaxed by test-evidence handling. |

The CI commands explicitly enable Playwright's built-in JSON reporter. Neither
Playwright configuration previously enabled an HTML reporter; merely naming
`playwright-report/` in an upload did not produce a report. The new files in that
directory are counts-only JSON summaries, not HTML or raw test output. No new
assertion requires credentials, sensitive traces or local secret files.

Offline validation runs with the existing suite:

```sh
python scripts/test_security_gates.py
```

The fixtures cover complete evidence, missing groups, empty/invalid files,
truncated PNGs, empty/skipped/failed test runs, optional diagnostic absence,
counts-only redaction and producer eligibility. A real admin UI and coverage CI
run is required when changing producer paths, reporters or upload behavior.
