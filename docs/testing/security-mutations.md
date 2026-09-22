# Targeted security mutation checks

Mutation checks ask whether the selected tests detect a deliberate change to
a security predicate. `scripts/security_mutations.py` is an in-tree, Python
standard-library harness, version **1.0.0**, with an explicit target and mutation
registry in `security-mutations.json`. This is the compatible equivalent tool
selected for issue #436; it does not install or invoke `cargo-mutants`.

The registry and controller versions must agree. Compiler, runtime and embedded
UI build versions come from `build-tools.json`, including the CI Rust profile.
Review changes to those pins, the harness, targets and selected tests together
with their measured effect. A score over this small, reviewed registry does not
measure every possible mutation or prove the gateway correct.

## Owned scope

The initial registry names four functions and eight source changes. Each
target records its file, fully qualified function name, unique source markers,
function SHA-256, exact test names and exact replacement text. Missing or moved
functions, changed source, ambiguous anchors and absent tests fail the campaign
until a reviewer reconciles the registry with the authoritative code. Selection
does not silently fall back to a substring match or another similarly named
function.

| Target | Security decision | Reviewed changes |
|---|---|---|
| `path_match::path_prefix_matches` | Path segment and subtree boundaries | Remove the segment-boundary check; reject a valid slash-ended subtree |
| `path_match::is_unsafe_request_path` | Ambiguous request-path rejection | Permit backslashes; permit empty interior segments |
| `egress::host_glob_matches` | Egress exact and wildcard host matching | Remove the wildcard label boundary; skip request-host case folding |
| `policy_eval::route_host_matches` | Shared evaluator host binding | Ignore a required binding; accept an absent request host |

The shared evaluator already exists, so the host-binding target belongs to
`policy_eval` from the start. The live adapter migration tracked by #422 is
separate and incomplete; this campaign does not claim that every production
decision has moved to that kernel. When ownership moves, update the target,
function hash and exact tests in the same reviewed change, remove the retired
target, and remeasure. Keep shared path and egress functions selected while
they remain authoritative for those decisions.

Only these pure tests run during mutation execution. They need no DNS,
credential provider, database, upstream server or third-party API. Dependency
resolution and the normal embedded UI build can access package registries;
this is build activity, not a security test exercising a third-party system.

## Local reproduction

Use a clean Linux checkout with the exact Python, Rust CI, Node and npm
versions from `build-tools.json`. Make test changes in a reviewable commit
before measurement: the campaign uses the exact committed `HEAD` source, not
an unrecorded working-tree overlay. The existing reviewed npm installer and
embedded UI build remain part of compilation.

```sh
export RUSTUP_TOOLCHAIN="$(python -c "import json;print(json.load(open('build-tools.json'))['rust_ci'])")"
export CARGO_BUILD_JOBS=1
python scripts/test_security_mutations.py
python scripts/security_mutations.py --report target/security-mutations/report.json
```

The controller uses only Python's standard library.
The harness creates a disposable copy of the committed source, validates the
registry against that copy, and compiles the unmodified baseline first. Each
listed baseline test must be discovered and pass. An empty selection, ignored
test, missing summary or failed baseline cannot establish a successful run.
Each mutant is then applied only to the disposable source and compiled before
its selected tests run. The source checkout remains unchanged.

`--manifest` selects a reviewed registry and `--target-dir` selects compilation
storage. Record those choices with the report. `--calibrate` runs a small,
separate Rust fixture: a deliberately weakened predicate must be killed, an
equivalent change must survive, and an ill-typed change must be unviable. This
checks outcome classification; it does not measure the production registry or
replace the complete registry campaign.

## Budgets and evidence

The controller bounds each phase and the complete campaign.

| Resource | Default limit |
|---|---:|
| One compilation: wall time | 3,600 seconds |
| One compilation: CPU time per process | 1,800 seconds |
| One selected test: wall time | 30 seconds |
| One selected test: CPU time per process | 20 seconds |
| Complete campaign: wall time | 7,200 seconds |
| Cargo build concurrency | One job |

CPU limits are inherited by child processes; they are not an aggregate CPU
quota for a compiler process tree. Wall timeouts terminate the process group.
The Rust build uses the runner's available memory; this harness does not claim
a per-build memory ceiling. Tool setup sits outside the campaign timer.
A cold compilation can consume a large part of these budgets; runtime evidence
must identify the compiler,
machine and cache state rather than treating a warm local measurement as a
hosted-runner guarantee.

The bounded JSON report identifies the base commit, toolchain, harness and
registry versions, target functions, test commands, reproducible mutation
identity, timings and per-mutant outcomes. It reports generated, killed,
survived, unviable, timed-out and excluded counts separately. It does not
convert compilation failures or equivalent mutations into killed mutations.
Raw test output, source payloads, environment variables and credentials do not
belong in the bounded report.

## Survivor review and baseline ownership

The checked-in registry is the reviewed baseline, with no exceptions initially.
Maintainers responsible for the selected path, egress and evaluator decisions
own recurring failures. The contributor changing a selected function must
reconcile its source hash, selected tests and measured outcomes in that same
review. A failed campaign is not resolved merely by rerunning until green.

For a new survivor, reproduce its exact identity against the reported commit
and inspect the security behavior being changed. Add an assertion that
distinguishes the intended behavior from a meaningful changed behavior, then
rerun the baseline and mutation campaign. Keep production code unchanged while
strengthening those tests. Record the before/after outcomes and runtime in the
review; do not weaken a policy or coverage floor to make the experiment pass.

An equivalent or unreachable mutation requires a narrow explanation tied to
that exact mutation identity and an explicit owner in the registry. Exceptions
are reviewed changes, never a generated allowlist or wildcard pattern. The
campaign still observes every excepted mutation; a missing mutation or changed
outcome makes its exception stale and fails the gate. Unexpected survivors,
unviable mutations, timeouts, incomplete results and controller errors remain
separate evidence, not evidence of a killed mutation. Review a source rename,
algorithm change, test change or toolchain change before updating the baseline.

If a survivor suggests a real vulnerability, use the repository's
[private vulnerability reporting process](../../SECURITY.md). Do not publish
the exploit, production payloads, credentials or raw diagnostics in a public
issue or CI artifact. Reduce the reproduction to synthetic, non-sensitive
inputs and involve the owning maintainers before public disclosure.

## Later automation

Trusted scheduled/manual execution is planned in a later #436 slice. This
slice provides the local controller and registry. The existing
[security coverage gate](security-coverage.md), normal tests and image-promotion
dependencies remain unchanged. A future PR mutation gate requires a separately
reviewed target scope and measured end-to-end runtime.
