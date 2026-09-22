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
| Live admin UI Playwright suite | Distinct JSON report in runner temporary storage; validated nonzero executed attempts agree with each test outcome and aggregate counts, with no interrupted attempts, unexpected tests or global errors. Only `admin-ui/playwright-report/live-summary.json`, containing counts, is uploaded. | Live auth traces remain disabled. Raw reporter JSON may include fixture values and stays outside artifact paths. |
| Screenshot Playwright suite | A separate temporary JSON report with the same count checks, plus a nonempty `admin-ui/.screenshots/**/*.png` group. Every PNG must pass chunk ordering/length/CRC checks, valid IHDR dimensions and format, palette presence where required, complete IDAT decompression, and scanline length/filter checks. `screenshots-summary.json` records counts and screenshot count. The validator checks both groups independently. | Existing `test-results/` failure diagnostics are optional; absence is normal on success. Hidden-file upload is enabled only for the explicitly selected PNG paths, so `.screenshots` is actually retained. Pixel/layout assertions remain in Playwright. |
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

Offline validation requires the Python and PyYAML versions pinned in
`build-tools.json` (Python 3.13.15 and PyYAML 6.0.3). Install the dependency before
running the existing suite; CI uses the same pin:

```sh
python -m pip install PyYAML==6.0.3
python scripts/test_security_gates.py
```

The fixtures cover complete evidence, missing groups, empty/invalid files,
truncated PNGs, empty/skipped/failed test runs, optional diagnostic absence,
counts-only redaction and producer eligibility. A real admin UI and coverage CI
run is required when changing producer paths, reporters or upload behavior.

## Evidence content checks

Playwright test outcomes are recomputed from `expectedStatus` and each
`results[].status` using the pinned reporter's outcome rules. A claimed
`expected` result with only a skipped or unexpectedly failed attempt cannot pass.
The total must include at least one executed attempt (`passed`, `failed`, or
`timedOut`); empty or entirely skipped reports fail. An interrupted attempt fails
evidence validation even when Playwright reports it as a skipped test and the
report also contains completed tests. Producer eligibility remains unchanged,
so this does not require success artifacts from an interrupted CI producer.

Expected failures and retries remain supported. CI currently permits Playwright
`flaky` outcomes, including a failed attempt followed by an expected skip; this
validator verifies that classification without introducing a new flaky-test
policy. When Playwright changes, compare these rules with the pinned reporter's
`computeTestCaseOutcome` and rerun the outcome fixtures.

PNG validation checks structural and compressed scanline integrity. It accepts
legal grayscale, RGB, palette, grayscale-alpha and RGBA bit depths, including
Adam7 interlacing and consecutive IDAT chunks. It rejects missing image data,
broken checksums, malformed ordering, invalid compressed streams, truncated or
extra scanlines, invalid row filters and bytes after IEND. Each screenshot is
limited to 32 MiB of input and 128 MiB of decompressed scanline data; reads and
decompression are bounded before accepting the image. Oversized output fails
with a safe error and must be deliberately reviewed if future screenshots need
larger bounds.

This is not a pixel/layout assertion or a full semantic validator of ancillary
PNG metadata; those checks remain in the browser tests. Reports still retain
only counts. Raw test messages, fixture values, URL locators and PNG metadata
are not copied into summaries or validation errors. No producer path, upload
eligibility, retention setting, optional diagnostic requirement or nightly
performance control changes.
