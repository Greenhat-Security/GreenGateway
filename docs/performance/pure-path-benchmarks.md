# Pure-path microbenchmark budgets

Part of #437. The required `microbench` CI job compares deterministic allocation
counts for a small set of pure production predicates. Wall-clock timings remain
informational. The existing nightly, HA, failover, load and release workflows
remain in place; these microbenchmarks do not establish a production SLO.

## Measured scope

The controller reads both revisions from Git and compiles their production
source projections with the same standalone Rust harness, pinned CI compiler,
optimization settings and datasets. It invokes `rustc` directly with the
standard library; it does not build the gateway, install Cargo dependencies,
contact upstreams or run the admin UI build. Source extraction rejects an
unrecognized layout instead of silently substituting an implementation.

The transport guard registers the standalone harness as an exact, hash-reviewed
nonproduction syntax root in `transport-ownership.json`. It still parses the file;
otherwise-unowned Rust files fail, and importing this root into production causes a
mixed-ownership failure. When the harness changes, generate its review record with
`python scripts/transport_guard.py inventory --standalone-benchmark scripts/benchmarks/pure_paths.rs`
and review the candidate hash, owner and purpose alongside the benchmark policy.
This registration does not exempt directories or change production transport rules.

Both sides use the exact CI compiler declared by the head revision. The report
records each revision's declared pin as well as the compiler actually used.
This permits a reviewed compiler-update PR to compare both source trees under
the new compiler; it does not compare measurements produced by different
compilers or claim to measure the compiler's own before/after performance.

| Target | Production code | Cases per iteration | Decisions per iteration | Fixture string bytes |
| --- | --- | ---: | ---: | ---: |
| `request_path` | `is_unsafe_request_path` and `exempt_path_matches` | 16 | 32 | 712 |
| `path_prefix` | `path_prefix_matches` | 16 | 16 | 867 |
| `rule_path` | Precompiled `PathPattern::matches` | 16 | 16 | 1,367 |
| `egress_host` | `host_glob_matches` | 16 | 16 | 1,118 |

Fixture byte counts sum the pattern/input strings in each dataset. The largest
path is 216 UTF-8 bytes and the largest host is 144 ASCII bytes. Cases include
matching and nonmatching boundaries, ambiguous path syntax, wildcard and
capture patterns, case folding and host-label boundaries.

The rule target measures compiled path-pattern matching. Rule parsing, pattern
compilation and the complete `RuleMatcher` are outside the measured interval.
The request target counts its two independent boolean decisions separately.
The egress target measures static host matching; it does not measure URL
classification, resolution, address policy, HTTP or network transport.

The shared evaluator exists, but live adapter migration remains tracked by
#422. This slice does not claim an authoritative end-to-end policy benchmark.
Issue #437 PR 3 remains deferred until that authority boundary is established;
retired predicates must receive equivalent authoritative coverage before their
benchmarks are removed. Cached JWT work is also deferred: this harness has no
JWT verification, keys, cache or cache-lifetime model.

All inputs are public synthetic fixtures. Host cases use reserved test names;
there are no tokens, real upstream hostnames or external network dependencies.
The report records dataset sizes and the hashes of the exact harness and
projected source. Fixture decisions are checked before measurement so that an
incorrect result cannot be counted as a faster implementation.

## Measurement contract

Each target has 100 warmup iterations over the full dataset, followed by nine
allocation samples and nine separate timing samples. Each sample performs
1,000 complete dataset iterations. The same prepared inputs and compiled path
patterns are reused by both revisions. Setup, expected-result assertions and
report serialization are outside the measured intervals.

A wrapper around Rust's `System` allocator counts `alloc`, `alloc_zeroed` and
`realloc` calls, plus their requested bytes. Reallocation contributes its full
new requested size, not its growth delta. Deallocations are not counted, and
the overflow check fails closed. These are executed allocator calls in this
optimized fixture; Rust may optimize allocations away. The figures are not a
semantic guarantee of zero allocation, peak memory, retained memory or RSS.

Allocation counting is disabled during the separate timing samples. The
wrapper's disabled-state check still exists, so those timings describe this
harness rather than the uninstrumented gateway. Raw samples, dispersion and
base/head comparisons are diagnostic evidence. They do not supply confidence
that a production latency threshold has been met. Hosted scheduling, CPU
frequency and contention can change timing without a source regression.

The initial blocking budget permits **zero growth in allocation calls and
requested bytes** for every selected target. All targets must be present and
compatible. Missing results, an unknown schema, mismatched measured compiler or dataset,
an extraction or compilation failure, a crashed benchmark, a timeout and an
incomplete target set fail the comparison. A timing improvement cannot offset
an allocation regression.

A comparison whose total elapsed time exceeds 120 seconds cannot pass. The
controller checks that acceptance budget before child processes and again at
completion. Compiler processes have a 30-second limit, benchmark processes a
15-second limit, and Git lookups their own ten-second timeout. Python source
projection is not forcibly interrupted, so 120 seconds is not a hard kill
deadline for the entire controller. CI imposes a separate ten-minute job
timeout, including checkout, pinned tool setup, fixture tests and artifact
upload. The [hosted CI record](#hosted-ci-record) shows GitHub-hosted jobs
finishing well inside both limits.

## Reproduce a comparison

Use the exact Rust and Python versions from `build-tools.json`. Both revisions
must exist in the local repository, and source changes must be committed:

```sh
export RUSTUP_TOOLCHAIN="$(python -c "import json;print(json.load(open('build-tools.json'))['rust_ci'])")"
MICROBENCH_BASE="$(git rev-parse --verify origin/main)"
MICROBENCH_HEAD="$(git rev-parse --verify HEAD)"
python scripts/microbench.py run \
  --base "$MICROBENCH_BASE" --head "$MICROBENCH_HEAD" \
  --output target/microbench-local
```

Use a fresh output directory for each repetition. Preserve the entire directory:
`base.json`, `head.json`, `base.raw.json`, `head.raw.json`, `context.json`,
`summary.json`, source projections, the exact harness, and compiler/process
stdout and stderr. The context records the runtime and CPU characteristics.
The base/head envelopes retain raw samples, input metadata and revision/source
hashes, and bind them to the actual common compiler, profile, harness and
machine context. Raw binary reports alone cannot pass the saved-result
comparison. CI adds `workflow.json` identifying the event, immutable comparison
commits and the meaning of the head revision.

Exercise the neutral rebuild and controlled regression independently:

```sh
python scripts/microbench.py self-test \
  --revision "$MICROBENCH_HEAD" --output target/microbench-self-test
python -m unittest discover -s scripts -p 'test_microbench*.py' -v
rustfmt --edition 2021 --check scripts/benchmarks/pure_paths.rs
```

The self-test must show that an independent rebuild of the same revision passes
and a deliberately introduced allocation regression fails. Its overall success
means that both expectations held; the intentionally rejected comparison must
remain visible in the saved evidence. It does not modify production source.

## Initial local measurement record

On 2026-09-22, three independent comparisons of base
`167cc5ecf816197f34e1cbb7455c1c21854aa6c8` with benchmark implementation
`d7d68937f365accaac91702d4b0af5e3015b8f00` passed. Both sides had identical
production-source and projection hashes. Each comparison rebuilt both binaries
with Rust 1.98.1, edition 2021, `opt-level=3`, one codegen unit and no debug info.
Python was 3.13.15. The host was Linux 6.18.44 x86-64 on an Intel Xeon Platinum
8272CL, with nine visible logical CPUs, an eight-CPU cgroup quota and a 20 GiB
memory limit. A separate full-workspace Cargo build was running concurrently.
This was an uncontrolled development host, not a qualified timing runner.

Every target had identical allocation counts in all 54 samples across the
three comparisons and both revisions. Counts below are per sample of 1,000
dataset iterations. Timing ranges span the six base/head sample-set medians;
the last column is the largest within-set `(max - min) / median`, not a
confidence interval.

| Target | Allocation calls | Requested bytes | Median timing range (ms) | Largest within-set spread |
| --- | ---: | ---: | ---: | ---: |
| `request_path` | 0 | 0 | 2.607–3.300 | 272.9% |
| `path_prefix` | 0 | 0 | 0.066–0.126 | 185.4% |
| `rule_path` | 87,000 | 5,286,000 | 7.406–11.239 | 71.3% |
| `egress_host` | 31,000 | 1,118,000 | 0.973–1.887 | 322.5% |

The full comparison commands completed in 6.311, 6.081 and 6.299 seconds,
including controller startup. The independent self-test completed in 9.866
seconds: its neutral rebuild passed and its deliberate allocation regression
failed all four target budgets. That fixture adds one 64-byte allocation per
decision, producing 32,000 extra calls for `request_path` and 16,000 for each
other target per sample.

The associated validation record retains `repeat-1`, `repeat-2`, `repeat-3`,
`self-test` and `measurement-commands.json`, including raw samples and exact
commands. The stable allocator counts support the initial zero-growth budget
for this fixture. The large timing spread on unchanged source supports leaving
time informational; these local measurements do not establish a blocking timing
threshold, and they do not describe the hosted CI job recorded below.

## Hosted CI record

Every main-push CI run from the #523 merge (run 35839228763, 2026-09-23)
through run 37222074807 (2026-10-04) included a passing `microbench` job on a
GitHub-hosted `ubuntu-latest` runner. Those nine jobs took 26 to 45 seconds
from job start to completion, excluding queue time.

The latest successful main-push run, 37222074807, compared push commit
`0c264de0f75911c804f854d7a285f983e372c127` with the event's `before` SHA
`9a48f0e2731920a4ee49cad4896d5f88dce75382`. Its `microbench` job took 29
seconds on the `ubuntu-24.04` image version 20260927.320.1, with Rust 1.98.1
and Python 3.13.15. Pinned tool setup took 10 seconds and the fixture step,
which ran 52 tests, 7 seconds. By its log timestamps, the comparison step
reported `passed` with no errors 1.8 seconds after it started, and the evidence
upload succeeded.

Pull-request mode has also run on a hosted runner. In run 37221295106, the
`microbench` job for #538 compared the checked-out merge commit
`5b753edaf10e3d9568f4c5bf95ed035a9af97c31` with `pull_request.base.sha`
`9a48f0e2731920a4ee49cad4896d5f88dce75382` and passed in 27 seconds.

These are durations on shared hosted runners, not a timing qualification. The
evidence artifacts have 30-day retention, so this record keeps run and commit
identifiers rather than relying on the artifacts. The scheduled
`nightly-performance` workflow remains separate and does not run these
microbenchmarks; its run 38537287732 on 2026-10-14 passed the `ha-performance`
job on commit `0c264de0f75911c804f854d7a285f983e372c127`.

## Authoritative HTTP policy decision

Budget schema 2 adds a fifth target, `http_policy`. It counts the allocations
of `CompiledPolicy::evaluate`, the call the live RBAC adapter makes, over the
fixed synthetic policy and request set in
`gateway/tests/support/policy_benchmark.rs`. The benchmark is an ignored test
in the gateway test binary, behind a counting global allocator that exists
only in `cfg(test)` builds, so production binaries are unaffected.
`scripts/microbench.py` builds each revision's own test binary: it cleans the
gateway package before each build, so a shared target directory cannot hand
one revision's binary to the other.

The target was adopted in two reviewed steps. First, the harness landed with no
budget entry (`pending`: measured, never blocking). Then
`microbench-budget.json` moved to schema 2, approving the harness digest in
`kernel_harness_sha256` and adding a zero-growth `http_policy` entry. That PR
ran in the `proposed` state against its schema-1 base. Every later comparison
whose base carries schema 2 is `enforced`: like the pure paths, any increase in
allocation count or allocated bytes fails the job, and a head budget cannot
retire the target. Changing the harness follows the same two-hash procedure as
the pure-path harness below.

## Tool-admission and rate-lane decisions

Two more targets measure the shared evaluator's other live lanes. They run in
the same gateway test binary as `http_policy`, under the same warmup, sample
and iteration counts, compiler and Cargo profile:

| Target | Kernel call | Live caller | Cases per iteration | Fact bytes |
| --- | --- | --- | ---: | ---: |
| `tool_policy` | `CompiledPolicy::evaluate_tool` | tool invocation, visibility, inventory, composite and rendered-HTTP adapters | 27 | 1,409 |
| `rate_lane` | `CompiledPolicy::select_rate_lane` | the rate-limit stage's override selection | 14 | 830 |

The tool dataset covers all five tool operations and every reason and
limitation the tool lane reports: invocations with no rule and with allow,
deny and shadow rules; role, issuer and authentication-method constraints;
unknown and disabled tools; both preview operations, where a shadow rule does
not hide a tool; composite enablement without a principal; rendered HTTP
rules under unknown dispatch, including a percent-encoded path; and each
uncaptured fact. The rate dataset covers first-match selection over
principal, method and path constraints, an override shadowed by an earlier
one, capture and recursive-wildcard patterns, a principal-id override, no
override, the anonymous bypass and each uncaptured fact. Its contexts have the
shape the live rate stage supplies, with routing, host and dispatch facts
uncaptured. Fact bytes sum the tool name, method, path and the principal's
subject, issuer and roles across the cases.

Selecting a rate lane is not admitting a request: token buckets and their
remaining capacity are mutable state outside the kernel and are not measured.
Neither target measures registry visibility, composite grants, request
rendering, leases, credentials, egress or transport.

The benchmarks are the ignored `tool_policy_evaluation` and
`rate_lane_selection` tests in `gateway/tests/support/lane_benchmark.rs`. That
file is a child module of the `http_policy` harness: a binary has exactly one
global allocator, and a child can count through its parent's without the
parent widening its visibility. The declaration is therefore part of the
`http_policy` digest, while the lane file has a digest of its own, so a lane
dataset can change without touching the enforced `http_policy` harness. Each
build checks that discovery lists both lane tests exactly when the revision
declares them. Their evidence is saved as `base.tool_policy.kernel.json`,
`head.rate_lane.kernel.json` and so on, beside the raw reports, and is
summarized under `lanes` in `summary.json`. The self-test also requires a
neutral rebuild to pass and the deliberate regression fixture to fail for each
lane target.

These targets are adopted in the same reviewed steps as `http_policy`, with
one more step first, because declaring the child module changes the enforced
`http_policy` harness:

1. Pre-approval: `kernel_harness_sha256` approves the digest of the
   `http_policy` harness with the declaration, beside the current digest,
   while the harness itself stays unchanged.
2. Harness: the declaration and the lane benchmarks land. No budget lists the
   lane targets, so they are `pending`: measured wherever the revision carries
   them, reported, never blocking. The `http_policy` comparison stays enforced
   across the change, because its base budget approves both digests.
3. Budget: `microbench-budget.json` moves to schema 3, which adds
   `lane_harness_sha256` approving the lane harness digest and zero-growth
   `tool_policy` and `rate_lane` entries after `http_policy`. That change runs
   `proposed` against its schema-2 base. Every later comparison whose base
   carries schema 3 is `enforced`, and a head budget cannot retire the lanes.

Steps 1 and 2 have landed; until step 3 lands, these targets are measured and
reported but do not block. After it, a lane harness change follows the
two-hash procedure below for `lane_harness_sha256`.

## Base ownership and reviewed updates

`microbench-budget.json` versions the benchmark schema and regression budget.
The active comparison loads its policy from the **base commit**. Changing the
head's budget cannot make that comparison pass. This is a review boundary;
repository administrators must retain the normal required-check and review
protections. The job does not write baselines or grant itself repository write
access.

Initial adoption has one explicit exception: the exact reviewed commit
`c0b098a08df1091fc129ae54348f022d529cfb02` predates the budget file and may use
the head's proposed bootstrap policy only after strict validation: it must
approve exactly the reviewed initial harness digest and permit zero allocation growth. An
arbitrary base without a budget fails. After this change lands, subsequent
comparisons use the versioned policy in their selected base.

Treat budget, dataset, measurement and harness changes as baseline changes.
Review their motivation and repeated base/head evidence rather than accepting
a new threshold just because a PR fails. The policy pins one or two unique
accepted harness hashes; both the base and proposed head policies must approve
the active harness. A harness transition therefore needs two reviewed
changes: first add the next hash alongside the current hash while leaving the
active harness unchanged; then change the harness in a later PR whose base
approves both hashes. The second PR may retire the old hash in its new budget.
The first PR is checked against its old base policy, and the second against the
new policy; intervening PRs retain a valid current harness. Do not add a fallback
that accepts arbitrary head hashes or automatically rewrites the budget.

## CI comparison and evidence

For pull requests, checkout uses the exact `github.sha` merge commit and compares
it with the event's `pull_request.base.sha`. This measures the proposed merged
tree against its pinned target branch state. For main pushes, the comparison
uses the push event's immutable `before` SHA, covering every commit in a
multi-commit push. Release-tag pushes compare the event commit with its first
parent. A root commit without a parent fails; a missing base is never replaced
with the head.
Complete Git history is fetched, and the resolver verifies that the checkout
matches the event commit before running the comparison.

The job runs for every existing CI pull-request and push trigger, without path
filters, skipped targets or optional failure status. It has read-only contents
permission, no persisted checkout credentials and no secrets, so fork pull
requests use the ordinary unprivileged `pull_request` event. Failure evidence is
uploaded with `always()` and missing artifacts are an error. Image promotion
depends on `microbench` succeeding alongside all pre-existing validation jobs.

Local workflow fixtures exercise real Git revision resolution and reject
credential persistence, a mutable or shallow checkout, changed event scopes,
skipped comparisons, permissive failure handling, incomplete evidence uploads
and removal of the promotion dependency. These fixtures do not substitute for
hosted runs; the [hosted CI record](#hosted-ci-record) identifies passing
pull-request and main-push executions. Hosted execution does not qualify runner
timing.

Keep timing informational until repeated runs on the intended controlled runner
show a usable signal-to-noise margin and a reviewed regression fixture proves
the proposed threshold. Follow the broader comparison rules in
[the proxy baseline](proxy-baseline.md); production load qualification remains
tracked by #389.
