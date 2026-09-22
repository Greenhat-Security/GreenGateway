# Bounded local security corpus

Part of [#435](https://github.com/Greenhat-Security/GreenGateway/issues/435).
This deterministic mutation harness complements the
[fixed properties](pure-parser-properties.md) and unchanged
[coverage floors](security-coverage.md). It is not coverage-guided fuzzing or
a claim of exhaustive safety.

## Actual code under test

`scripts/security_corpus.py` builds the existing gateway unit-test executable
once with locked dependencies, discovers the exact ignored test
`security_corpus::bounded_corpus_worker`, and invokes it directly. It never
starts the gateway. No parser is copied and no production validation,
visibility, dependency or security default changes.

| Target | Actual entry points and assertions |
| --- | --- |
| JWT | `cached_decoding_key`, `JwtValidator::decode_with_key`: real signature verification, deterministic classification, required claims and key/algorithm compatibility |
| Policy | `CompiledPolicy::compile`, `evaluate`: deterministic errors, snapshots, complete decisions and bounded traces; stale context versions cannot be reused |
| Host | `host_header`, `request_host_without_port`: bounded ASCII output, stable classification and duplicate-field rejection |
| Path | `path_prefix_matches`, `is_unsafe_request_path`, `exempt_path_matches`: literal boundaries, unsafe dot insertion and exact probe exemptions |

JWT setup generates fresh ES256 and EdDSA keys in memory. Every JWT case forces
two valid-signature acceptances and 24 denials covering issuer, audience, expiry,
not-before, required claims, signature corruption and algorithm confusion.
Arbitrary token/header/claim/JWK fragments reach the real decoders. RSA JWK
parsing is reachable, but this harness generates no positive RS256 signatures;
the existing RSA tests remain unchanged.

The JWT helper never calls asynchronous JWKS refresh or principal/revocation
admission. Its client uses a counting DNS resolver that panics if called, and
its revocation double has the same contract. Both counters must remain zero.
No async runtime, DNS lookup, provider request or upstream connection starts.
This covers pure decoding, not the complete authentication flow.

Numeric `exp` and `nbf` in generated claim fragments map to fixed distant
timestamps. This does not fuzz negative/fractional numeric timestamp semantics
or the current-clock leeway boundary. Missing and nonnumeric claims remain
unchanged. The positive fixture expires in 2100; the forced future-not-before
fixture is in 2200. Review these explicit dates before 2100.

## Run and reproduce

Use the exact Python, Rust CI, Node and npm pins in `build-tools.json`.
The controller enforces Python/Rust versions; the ordinary build enforces
Node/npm and performs the reviewed embedded-UI build. Compilation may download
dependencies; no build-time network work occurs for each corpus input.

```sh
python scripts/test_security_corpus.py
python scripts/security_corpus.py --mode regression --report target/security-corpus/report.json
python scripts/security_corpus.py --mode exploration --report target/security-corpus/exploration.json
```

The manifest at `fuzz/corpus/manifest.json` initially contains 13 nonempty,
synthetic files across all four targets. Each runs unchanged, then with the
configured number of mutations, in manifest order: 117 default regression
cases or 6,669 exploration cases. Counts are derived from the actual manifest.
Missing/empty corpora, missing targets, invalid paths, symlinks, nonregular files
and excessive sizes fail before worker execution.

Both modes default to seed `435005`. The owned algorithm
`splitmix64-byte-mutations-v1` performs bounded bit flips, substitutions,
insertion, deletion, truncation, small duplication and structural-marker changes.
Each mutation starts from its committed seed input. Preserve the exact source,
manifest order, corpus digest, seed, mutation count and toolchain for replay.
Never replace a failing seed just to obtain a pass.

For example, replay zero-based case 10 from the regression stream:

```sh
python scripts/security_corpus.py --mode regression --seed 435005 \
  --mutations-per-seed 8 --replay-case 10 \
  --report target/security-corpus/replay.json
```

Replay advances the same RNG stream before selecting the case and requires
exactly one result. It reproduces mutation bytes and classification invariants,
not ephemeral generated key/signature bytes. The optional `--binary` argument
reuses a locally verified test executable; the report marks its origin as
`provided` and records its hash without claiming it came from current source.
CI uses the ordinary build-and-discover path.

## Resource and evidence contract

Linux/POSIX resource limits are required. Unsupported platforms fail rather
than silently dropping limits.

| Budget | Regression | Exploration |
| --- | ---: | ---: |
| Mutations per seed | 8 | 512 |
| Worker CPU soft/hard limits | 20/21 seconds | 120/121 seconds |
| Worker wall timeout | 30 seconds | 180 seconds |
| Virtual address space (`RLIMIT_AS`) | 2,048 MiB | 2,048 MiB |
| Each child output/receipt file (`RLIMIT_FSIZE`) | 64 KiB | 64 KiB |
| Core dump size | 0 | 0 |
| Separate compile timeout | 3,600 seconds | 3,600 seconds |

Worker limits apply separately to filtered discovery and corpus execution,
not to the entire compiler or controller. Tool-version and Git subprocesses
have separate 30-second timeouts. A wall timeout kills the process group.
Nonzero exit, resource exhaustion, missing/truncated receipts, zero selected
tests and inconsistent counts all fail. A valid failure receipt survives a
nonzero exit; a success receipt cannot override process failure.

Limits also bound the corpus to 64 files, 16,384 bytes per file, 262,144 total
seed bytes and 100,000 cases. Rust independently enforces input/case bounds
and a 2 MiB job-document limit. Mutations remain within 16,384 bytes. Explicit
CLI overrides are capped at 3,600 CPU/wall seconds, 8,192 MiB address space and
7,200 compile seconds.

Reports are at most 64 KiB. They record source/lockfile/tool hashes, exact
Rust/Cargo versions and runtime pins, executable hash/origin, corpus/manifest
hashes, seed, mutator version, budgets, counts and elapsed time. A finding adds
only case index, target, input SHA-256 and fixed failure kind. No raw inputs,
JWTs, keys, panic text or child stdout/stderr are published. Temporary job files
are private and removed after execution; core dumps are disabled. Report
overflow itself causes a failed report and nonzero exit.

## Planned CI integration

The next #435 slice adds mandatory regression and trusted scheduled/manual
exploration jobs, workflow contract tests, and a corpus promotion dependency.
The regression/exploration budgets above are the controller's current mode
defaults. No corpus workflow or automatic report upload is present in this
slice.

The ordinary `test` job already runs fixed ChaCha property seeds: egress
`435001`, host/route `435002`, and path `435003`, each with 128 cases. Existing
coverage thresholds and promotion dependencies remain unchanged.

## Triage, minimization and ownership

GreenGateway maintainers own recurring failures with the affected auth,
policy or parser owner. Distinguish resource/runner failures from parser
findings; never raise a limit or remove a failing seed merely to obtain green.

1. Preserve the report and exact source/corpus revision privately. Reproduce
   the recorded case and confirm its input hash before modifying anything.
2. Inspect the selected `input` locally in `security_corpus::run` with a debugger
   if bytes are needed. Keep raw reproductions and ephemeral signing material
   out of public logs, issues, CI artifacts and commits.
3. Minimize to synthetic bytes by removing unrelated fields/byte spans and
   simplifying nesting/strings, rechecking the same invariant after each change.
   Use a private copy of the four-domain manifest with `--mutations-per-seed 0`
   to test a proposed minimized seed directly under the same bounds.
4. Suspected exploitable results follow [SECURITY.md](../../SECURITY.md) before
   disclosure. Maintainers decide when a safe minimal fixture can enter the
   corpus with an explanatory regression assertion. Nothing automatically
   creates public issues or publishes input bytes.

The shared evaluator is available and the policy corpus uses its pure API.
Generated evaluator properties are the remaining #435 PR 4 slice. Keep corpus
targets on authoritative entry points if modules move.
This suite establishes neither live PostgreSQL/HA coverage nor exhaustive safety.
