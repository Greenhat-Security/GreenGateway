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

Use a Linux checkout with clean tracked files and the exact Python, Rust CI,
Node and npm versions from `build-tools.json`. Make test changes in a
reviewable commit before measurement: the campaign uses an archive of the
exact committed `HEAD` source. Unrelated untracked files are ignored and never
overlaid on that archive. The report records this as
`source_state: tracked_clean_head_archive`. The existing reviewed npm installer
and embedded UI build remain part of compilation.

```sh
export RUSTUP_TOOLCHAIN="$(python -c "import json;print(json.load(open('build-tools.json'))['rust_ci'])")"
export CARGO_BUILD_JOBS=1
python scripts/test_security_mutations.py
python scripts/test_security_mutations_workflows.py
python scripts/security_mutations.py --report target/security-mutations/report.json
```

The workflow tests additionally require the `PyYAML==6.0.3` parser pinned in
`build-tools.json`; the controller itself uses only Python's standard library.
The harness creates a disposable copy of the committed source, validates the
registry against that copy, and compiles the unmodified baseline first. Each
listed baseline test must be discovered and pass. An empty selection, ignored
test, missing summary or failed baseline cannot establish a successful run.
Each mutant is then applied only to the disposable source and compiled before
its selected tests run. The source checkout remains unchanged, and no workflow
step commits or pushes mutated files.

`--manifest` selects a tracked registry inside the source repository and
`--target-dir` selects compilation storage. Compilation storage must be under
the repository's `target/` directory or in a separate safe directory outside
the source tree. Record those choices with the report. `--report` accepts a
regular-file destination under the repository's `target/` directory or outside
the source repository; symlink path components and other in-tree destinations
are rejected before any report write. That rejection prints a bounded reason
and exits unsuccessfully without creating a report at the unsafe destination.

`--calibrate` runs a small,
separate Rust fixture: a deliberately weakened predicate must be killed, an
equivalent change must survive, and an ill-typed change must be unviable. This
checks outcome classification; it does not measure the production registry or
replace the complete scheduled campaign.

## Budgets and evidence

The controller bounds each phase and the complete campaign. CI adds an outer
job budget covering tool setup and artifact upload as well as measurement.

| Resource | Default limit |
|---|---:|
| One compilation: wall time | 3,600 seconds |
| One compilation: CPU time per process | 1,800 seconds |
| One selected test: wall time | 30 seconds |
| One selected test: CPU time per process | 20 seconds |
| Tests and short metadata commands: virtual address space per process | 2,048 MiB |
| Complete campaign: wall time | 7,200 seconds |
| Cargo build concurrency | One job |
| Captured build output, per output stream | 8 MiB |
| Captured test output, per output stream | 64 KiB |
| Report size | 256 KiB |
| Scheduled/manual CI job | 150 minutes |

CPU limits are inherited by child processes; they are not an aggregate CPU
quota for a compiler process tree. Wall timeouts terminate the process group.
`--memory-mib` changes the virtual-address-space limit for tests and short
metadata commands, within 512–32,768 MiB. Cargo builds have no address-space
limit because the embedded UI build's JavaScript runtime reserves a large
virtual range; their memory use remains subject to the runner's capacity.
Builds retain CPU and wall limits, a 4 GiB per-file limit, disabled core dumps
and bounded captured output. The controller stops a process whose output
exceeds its cap; exceeding a resource limit cannot count as a killed mutation.

Tool setup and artifact handling sit outside the campaign timer and inside
the CI job timer. A cold compilation can consume a large part of these budgets;
runtime evidence must identify the compiler, machine and cache state rather
than treating a warm local measurement as a hosted-runner guarantee.

The bounded JSON report identifies the base commit, toolchain, harness version
and hash, registry hash, source archive hash, target function hashes, selected
tests, test commands, reproducible mutation identity, timings and per-mutant
outcomes. `generated` is the full planned registry count, `completed` counts
recorded results and `not_run` shows the remaining work. Outcomes are reported
separately as `killed`, `survived`, `unviable`, `timed_out` and `harness_error`.
`excluded` is a subset of those observed outcomes with exact approved
exceptions; it is not another outcome to add to their total. Compilation
failures and equivalent mutations are never counted as killed mutations.

Progress checkpoints remain failed and incomplete until the complete campaign
satisfies its reviewed expectations. Missing results or interruption therefore
cannot leave a successful score. Raw test output, source payloads, environment
variables and credentials do not belong in the uploaded report. The workflow
uploads only that report, retains it for 14 days and fails when it is absent.

## Initial measured campaign

The first complete local campaign used commit
`e939613fc79230dd65216118fadb44a2ad2638fe`, before the survivor-driven assertion
additions. All nine selected baseline tests passed. The four functions produced
eight mutations: all eight completed, four were killed and four survived.
Unviable, timed-out, excluded, harness-error and not-run counts were each zero.
The report correctly finished with `status: failed` and
`reason: unapproved_or_stale_outcome`; the four survivors were not approved
exceptions.

| Mutation identity | Initial outcome | Rebuild wall time, seconds |
|---|---|---:|
| `path-prefix/drop-segment-boundary` | killed | 139.4 |
| `path-prefix/reject-slash-subtree` | survived | 185.7 |
| `unsafe-path/allow-backslash` | killed | 180.9 |
| `unsafe-path/allow-empty-segment` | killed | 80.9 |
| `egress-host/drop-label-boundary` | killed | 215.3 |
| `egress-host/skip-host-case-fold` | survived | 211.3 |
| `kernel-host/ignore-required-binding` | survived | 91.2 |
| `kernel-host/accept-absent-host` | survived | 98.7 |

The complete run took **1,953.5154 seconds (32 minutes 33.5 seconds)**. The
unmodified baseline rebuild took 742.2086 seconds; mutant rebuilds ranged from
80.9112 to 215.347 seconds. Each individual selected test took under 0.15 seconds
in this run, so compilation dominated the measurement. Evidence is recorded in
the review's `registry-initial.json` and `machine.json`.

This was a local Linux x86-64 container on an Intel Xeon Platinum 8272CL at
2.60 GHz, with nine visible logical CPUs, an eight-CPU quota and a 20 GiB memory
limit. Cargo used one build job. Rust CI 1.98.1, Node 26.8.2, npm 11.19.1 and
Python 3.13.15 matched the pinned contract. The run reused an existing dependency
cache but compiled from a fresh disposable source path. It is not a cold-cache
benchmark or evidence of execution on GitHub-hosted runners; a cold workflow
must still finish within its own complete-pipeline budgets.

The exact baseline selectors at that revision were:

```text
egress::tests::host_glob_matching_supports_exact_and_leading_wildcard_patterns
path_match::tests::empty_interior_segments_are_unsafe_but_ordinary_paths_are_not
path_match::tests::non_absolute_prefixes_do_not_match
path_match::tests::non_probe_exempt_entries_keep_subtree_semantics
path_match::tests::prefix_matches_at_segment_boundary_only
path_match::tests::unsafe_paths_include_encoding_dot_segments_and_backslashes
policy_eval::tests::a_permissive_default_does_not_authorize_an_unrouted_virtual_upstream
policy_eval::tests::a_route_host_alone_makes_the_host_binding_mandatory
policy_eval::tests::an_ipv6_request_host_is_evaluated_rather_than_refused_as_malformed
```

The observed survivors identify missing assertions for slash-ended subtree
matching, request-host case folding, an unbound route when binding is required,
and an absent request host for a bound route. They measure assertion strength
within this selected scope; the original production predicates remained
unchanged. Follow-up assertion changes require a fresh complete campaign and
their own report. Consult the current registry and that report for its selected
tests and observed outcomes, rather than treating this initial failing run as
the final baseline.

## Survivor review and baseline ownership

The checked-in registry is the reviewed baseline, with no exceptions initially.
Maintainers responsible for the selected path, egress and evaluator decisions
own recurring failures. The contributor changing a selected function must
reconcile its source hash, selected tests and measured outcomes in that same
review. A scheduled failure is not resolved merely by rerunning until green.

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

## Trusted scheduled execution

`.github/workflows/security-mutations.yml` runs nightly at 04:41 UTC and accepts
manual dispatch without input overrides. The job requires the upstream
`Greenhat-Security/GreenGateway` repository, its default branch and a schedule
or manual event. Checkout uses the exact event SHA with persisted credentials
disabled. The workflow grants only `contents: read`, uses immutable action
references, installs the pinned build tools, tests controller failure handling
and workflow trust boundaries, then runs the complete registry.

There is no mutation job on pull requests yet. The existing
[security coverage gate](security-coverage.md), normal tests and image-promotion
dependencies remain unchanged. A future small PR gate requires a separately
reviewed target scope and measured end-to-end runtime; the scheduled baseline
does not authorize a slow or partial mutation job on every pull request.
