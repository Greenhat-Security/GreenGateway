# Security coverage gate

CI measures real branch coverage with `cargo-llvm-cov` 0.9.0 and the pinned
`nightly-2026-09-01` compiler on Windows. Nightly is needed for Rust branch
instrumentation; production builds continue using the Dockerfile toolchain.
The existing Linux, PostgreSQL and protocol acceptance gates remain mandatory.

[Targeted security mutations](security-mutations.md) provide a separate check
that selected pure predicates have behavior assertions strong enough to detect
reviewed source changes. The bounded mutation campaign runs on a trusted
schedule or manual dispatch; pull requests only check, inside the existing
`supply-chain` job, that its registry still matches the source. Neither changes
these coverage floors or the set of pull-request or image-promotion jobs; the
reviewed scope and individual outcomes must not be presented as a
whole-gateway mutation score.

The gate checks each file in `.github/security-coverage.json` separately:
JWT handling, authentication and RBAC middleware, CSRF, response headers,
validation, role evaluation, admin authorization and egress, and for the
`ggctl` operator CLI (issue #242) its refusal of secret-carrying and
verification-disabling options (`ggctl/src/cli.rs`), its bearer-token input
(`ggctl/src/credential.rs`) and its admin API client (`ggctl/src/remote.rs`).
Their inline test suites are separate test files, so test implementation lines
cannot inflate these production-file percentages. Missing files, absent branch
instrumentation, results below either floor and a shrunken denominator (below)
fail the job. Evidence is uploaded even when a floor fails, and image promotion
depends on the coverage job.

`ggctl` is its own workspace package with its own tests, so it is measured in
its own run, before the gateway's, and the gateway run stays exactly the command
its floors were set against. Its integration tests run the instrumented `ggctl`
binary itself, so exit codes, standard streams, token files and loopback HTTPS
count. The floor check reads both reports as one: every gated file must appear
in exactly one of them, so a file measured twice fails instead of passing on its
better run. A failed `ggctl` run skips the gateway run, and with it the floor
check and the evidence upload.

Reproduce on the same compiler/platform:

Use the Python 3.13.15 and PyYAML 6.0.3 versions pinned in `build-tools.json`.
The offline gate regression suite imports PyYAML to inspect the CI workflow.

```powershell
python -m pip install PyYAML==6.0.3
rustup toolchain install nightly-2026-09-01 --profile minimal --component llvm-tools-preview
cargo install cargo-llvm-cov --version 0.9.0 --locked
cargo +nightly-2026-09-01 llvm-cov --no-rustc-wrapper --branch --json --output-path target/ggctl-security-coverage.json -p ggctl --locked --jobs 4
cargo +nightly-2026-09-01 llvm-cov --no-rustc-wrapper --branch --json --output-path target/security-coverage.json -p gateway --bin gateway --locked --jobs 4 -- --test-threads=8 --skip audit::sqlite_sink::tests::moderate_scale_batched_inserts_complete_quickly
python scripts/check-security-coverage.py target/security-coverage.json target/ggctl-security-coverage.json
python scripts/test_security_gates.py
```

CI also compiles the instrumented gateway crate faster with three settings for
that one package, written to the runner's user-level Cargo configuration
(`%CARGO_HOME%\config.toml`) rather than the repository's:

```toml
[unstable]
profile-rustflags = true
[profile.test.package.gateway]
debug = 0
rustflags = ["-Zthreads=4", "-Clinker=rust-lld"]
```

No debug information for the crate (coverage comes from the instrumentation's
counters and coverage mapping, not from debug information), the nightly
compiler's parallel front end, and the LLVM linker shipped in the pinned
toolchain instead of the MSVC linker. They change how fast the test binary is
built, not what is instrumented, run or measured. On October 21, 2026 the same
command with and without them produced reports with identical line, branch,
function, region and instantiation counts in all 165 instrumented files and
identical covered counts in every file `.github/security-coverage.json` names,
both locally and in CI (run 39680234689 against run 39652237161, the same
gateway sources), where the crate's build took 3m32s instead of 6m53s. The
covered counts of a few timing-dependent modules outside the floors (connection
administration, the PostgreSQL audit sink, the proxy health and forwarding
paths) vary between runs of one build either way. Reproducing without the
configuration gives the same measurements, only more slowly. Because the
floors' [recorded denominators](#recorded-denominators) are checked on every
run, a later toolchain or setting change that made the instrumentation report
fewer lines or branches for a gated file fails the job instead of raising its
percentage.

Wrapper-free mode is intentional: Cargo can pass the long Windows compiler
command through a response file, which cargo-llvm-cov 0.9.0's wrapper does not
inspect for the crate name. Without the flag, tests can pass while the gateway
receives no instrumentation; report generation and our missing-data gate refuse
that result.

The SQLite insert throughput test retains its ten-second wall-clock budget in
the mandatory, uninstrumented `test` job. Only the instrumented coverage run
excludes that performance measurement: instrumentation on hosted Windows changes
its timing. All security coverage floors and the normal test gate still apply.

Do not run UI tests concurrently with a Rust build in the same checkout: the
existing Rust build script runs the reviewed npm installer (`scripts/npm-script-policy.mjs`) to rebuild embedded UI assets.

## Recorded denominators

A floor is a percentage of the lines or branches the instrumentation reports
for a file. A compiler, linker or build-setting change that dropped the coverage
records of uncovered code would raise that percentage without a single new test.
So every entry in `.github/security-coverage.json` also records
`min_line_count` and `min_branch_count`: the instrumented line and branch counts
of that file when the minimum was last set. `scripts/check-security-coverage.py`
prints each file's covered/total counts and fails when a total is below its
recorded minimum, or when either minimum is missing or not a positive integer.
A larger total (new code) passes.

When the gate reports that a denominator shrank:

- if the toolchain, `cargo-llvm-cov`, the linker or a build setting changed,
  find out why records were dropped. Do not lower the minimum to make it pass;
- if code was really removed from that file, set the minimum to the new count
  the gate printed, in the same change that removes the code, and say in the
  pull request which code went. Raising a minimum after code is added is
  optional but keeps the guard tight.

The current gateway minimums are the counts the `main` CI run 39717886274
measured on October 22, 2026 (commit `6fc83e9`). The `ggctl` minimums are the
counts of a Windows run of the same `ggctl` command with the same pinned
compiler and `cargo-llvm-cov` on October 22, 2026, before the files first
reached `main`; see [the operator CLI baseline](#operator-cli-baseline). The
one exception is the branch minimum of `credential.rs`, 22 since October 28,
2026: its permission check took an `owner_only` flag and tested it with `&&`,
two conditions, and now takes one permission mode, one condition, so that
branch pair is gone without any test or check going with it (the same Windows
run measured 95.45%, 21/22).

## Initial measured baseline

The September 6, 2026 Windows run passed 2,541 unit tests, with five existing
ignored cases, and produced the following production-file measurements. Floors
are set per file close to that baseline, with small margins for paths affected
by platform/runtime outcomes. Fully covered deterministic modules retain 100%
floors.

| File (under `gateway/src/`) | Lines | Branches | Line / branch floors |
|---|---:|---:|---:|
| `auth/jwt.rs` | 88.86% | 83.93% | 85% / 80% |
| `middleware/auth.rs` | 96.02% | 90.91% | 95% / 88% |
| `middleware/rbac.rs` | 96.43% | 86.72% | 94% / 84% |
| `middleware/csrf.rs` | 97.04% | 90.62% | 95% / 88% |
| `middleware/headers.rs` | 100.00% | 87.50% | 100% / 85% |
| `middleware/validate.rs` | 100.00% | 100.00% | 100% / 100% |
| `rbac/rule.rs` | 100.00% | 100.00% | 100% / 100% |
| `rbac/engine.rs` | 100.00% | 100.00% | 100% / 100% |
| `admin_authorization.rs` | 78.50% | 78.26% | 75% / 75% |
| `egress.rs` | 89.91% | 76.42% | 87% / 74% |

### Operator CLI baseline

The October 22, 2026 Windows measurement of `ggctl` (issue #242, PR 5), with
`nightly-2026-09-01` and `cargo-llvm-cov` 0.9.0, ran its 47 unit tests and 6
integration tests. Windows compiles no Unix-only code, so the Unix mode check
on token files is outside these counts; the Linux and macOS legs of the `ggctl`
CI job run its tests.

| File (under `ggctl/src/`) | Lines | Branches | Line / branch floors |
|---|---:|---:|---:|
| `cli.rs` | 96.45% (163/169) | 98.21% (55/56) | 94% / 94% |
| `credential.rs` | 89.72% (96/107) | 95.83% (23/24) | 87% / 90% |
| `remote.rs` | 97.06% (264/272) | 91.07% (51/56) | 95% / 87% |

What stays uncovered is code Windows does not reach or no test can provoke on
demand: the refusal of a token file that group or other can access, or of a
CA file they can write (both mappings are compiled on Windows, where the mode
checks always pass; the Linux and macOS legs run those tests), a read error
from standard input or from a file after it opened, the UTF-8 conversion of
bytes already checked as ASCII, a client builder or response body that fails,
the mapping of a redirect error that the client's no-redirect policy never
raises, and the `Debug` form of a command table entry.

These are initial per-file minimums, not evidence that every security outcome is
tested. Use uncovered branches to choose the next tests, raise floors as coverage
improves, and review compiler or policy changes explicitly. Coverage does not
replace protocol parity, secret-redaction, live failover or production capacity
tests. The coverage run uses the default feature set; database-backed contracts
are exercised by the dedicated PostgreSQL CI jobs.

[Deterministic pure-parser properties](pure-parser-properties.md) complement
these execution floors with generated assertions for address classification,
host parsing and literal path boundaries. They preserve the existing floors and
run in the normal workspace test gate. The [bounded security corpus](security-corpus.md)
adds a mandatory promotion dependency with committed seeds, resource limits,
redacted results and trusted scheduled exploration; it does not lower these floors.
