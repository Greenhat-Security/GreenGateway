# Security coverage gate

CI measures real branch coverage with `cargo-llvm-cov` 0.9.0 and the pinned
`nightly-2026-09-01` compiler on Windows. Nightly is needed for Rust branch
instrumentation; production builds continue using the Dockerfile toolchain.
The existing Linux, PostgreSQL and protocol acceptance gates remain mandatory.

The gate checks each file in `.github/security-coverage.json` separately:
JWT handling, authentication and RBAC middleware, CSRF, response headers,
validation, role evaluation, admin authorization and egress. Their inline test
suites are separate test files, so test implementation lines cannot
inflate these production-file percentages. Missing files, absent branch
instrumentation and results below either floor fail the job. Evidence is uploaded
even when a floor fails, and image promotion depends on the coverage job.

Reproduce on the same compiler/platform:

```powershell
rustup toolchain install nightly-2026-09-01 --profile minimal --component llvm-tools-preview
cargo install cargo-llvm-cov --version 0.9.0 --locked
cargo +nightly-2026-09-01 llvm-cov --no-rustc-wrapper --branch --json --output-path target/security-coverage.json -p gateway --bin gateway --locked --jobs 2 -- --test-threads=8
python scripts/check-security-coverage.py target/security-coverage.json
python scripts/test_security_gates.py
```

Wrapper-free mode is intentional: Cargo can pass the long Windows compiler
command through a response file, which cargo-llvm-cov 0.9.0's wrapper does not
inspect for the crate name. Without the flag, tests can pass while the gateway
receives no instrumentation; report generation and our missing-data gate refuse
that result.

Do not run UI tests concurrently with a Rust build in the same checkout: the
existing Rust build script runs `npm ci` to rebuild embedded UI assets.

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

These are initial per-file minimums, not evidence that every security outcome is
tested. Use uncovered branches to choose the next tests, raise floors as coverage
improves, and review compiler or policy changes explicitly. Coverage does not
replace protocol parity, secret-redaction, live failover or production capacity
tests. The coverage run uses the default feature set; database-backed contracts
are exercised by the dedicated PostgreSQL CI jobs.
