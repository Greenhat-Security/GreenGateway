# Pure-path microbenchmark budgets

Part of #437. The `microbench` CI job compares deterministic allocation counts
for a small set of pure production predicates and for the shared policy
evaluator's HTTP, tool, rate-lane and static egress decisions. Image promotion
requires it; see [CI comparison and evidence](#ci-comparison-and-evidence) for
what it does and does not gate. Wall-clock timings remain informational. The
existing nightly, HA, failover, load and release workflows remain in place;
these microbenchmarks do not establish a production SLO.

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

These four targets measure predicates, not policy decisions. The shared
evaluator's HTTP, tool, rate and static egress decisions have kernel targets
of their own, described from
[the HTTP policy decision](#authoritative-http-policy-decision) on. Every
predicate measured here is still called by production code: on main
`2280797aef866a6ea5eef8318a9d60bbfec55f2c` the request predicates are called
by the authentication, RBAC and rate-limit middleware, `path_prefix_matches`
by the gateway-owned path check, discovery and observation, compiled path
patterns by the evaluator's rule matcher, and `host_glob_matches` by the
static egress lane. A kernel target exercises such a predicate only on the
cases its own dataset reaches, mixed with the rest of the decision, so it is
not equivalent coverage for a predicate that stays live. None has been
retired, so none of these targets is stale or removed; a predicate retired
later needs equivalent authoritative coverage before its benchmark goes.
Cached JWT work is deferred: this harness has no JWT verification, keys,
cache or cache-lifetime model.

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

The pure-path stage must finish within 120 seconds of the controller's start,
and the whole comparison, including the two gateway test-binary builds the
kernel targets below need, within 480 seconds. Exceeding either budget fails
the comparison. The controller checks the applicable budget before each child
process and again at completion. Compiler processes have a 30-second limit,
benchmark processes a 15-second limit, each gateway build 300 seconds, other
Cargo and test-binary processes and Git archives 60 seconds, and Git lookups
their own ten-second timeout. Source projection and tree extraction are not
forcibly interrupted, so neither budget is a hard kill deadline for the entire
controller. CI imposes a separate ten-minute job timeout, including checkout,
pinned tool setup, fixture tests and artifact upload. The
[hosted CI record](#hosted-ci-record) shows the pure-path stage finishing well
inside its budget and the gateway builds taking most of the total.

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

Since the `http_policy` harness landed (#586, 2026-10-20), every comparison
also builds two gateway test binaries, and the comparison step dominates the
job. The 37 `microbench` jobs of the pull-request and main-push CI runs
created from 2026-10-21 07:05 to 2026-10-22 07:06 UTC all passed. Their
comparison steps took 258 to 469 seconds, 36 of them under 410, and the jobs
took 299 to 519 seconds. In the four runs whose head carried the lane
benchmarks, from main-push run 39737047860, which landed them, to
pull-request run 39738214098, the step took 283 to 469 seconds. Each lane
test finished in under a second in the
[lane measurement record](#lane-measurement-record), so the lanes add little
to a step bound by the two builds. The slowest step, in run 39738214098,
finished about 11 seconds inside the 480-second comparison budget. That margin
is the job's main timing risk, and it comes from build time, not from the
measured decisions. The 30 `microbench` jobs of the pull-request and
main-push CI runs created from 2026-10-22 12:07 to 2026-10-25 20:34 UTC, after
the lane benchmarks landed, all passed. Their comparison steps took 252 to 438
seconds, so the slowest finished about 42 seconds inside the budget, and the
jobs took 297 to 489 seconds. The static egress target first ran on 2026-10-28
in pull-request run 40746530358 for merge train #655 and in main-push run
40750474992, which landed it. Both `microbench` jobs passed, with comparison
steps of 319 and 398 seconds. Their base, main
`4d28b278304f5b367ba6836a786a15eda4d2e2a9` before #655, lacked the test, so it
ran on the head only, as a pending target.

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

All three steps have landed: f6728d2 pre-approved the declaring harness,
870ad67 added the lane benchmarks, and the budget step moved
`microbench-budget.json` to schema 3, running `proposed` against its schema-2
base. Every comparison whose base carries schema 3 enforces both lanes as it
enforces `http_policy`. Any increase in either target's allocation count or
allocated bytes fails the job. So does a lane benchmark that is missing,
undiscovered, crashed, timed out or reporting another dataset, and a head
budget cannot retire the lanes. A timing change cannot offset an allocation
regression. The same budget stopped approving
`f10830a181046792488b7749f2c367276756027eee7b31a9f7157e446d634936`, the
`http_policy` harness from before the declaration: a revision carrying it
lacks the lanes, so it cannot pass against a schema-3 base anyway. A lane
dataset or harness change now follows the two-hash procedure below for
`lane_harness_sha256`. A change to the `http_policy` harness, including its
declaration of the lane module, follows it for `kernel_harness_sha256`.

The static egress lane is measured by a further target in the same file,
[`static_egress`](#static-egress-decision), which budget schema 4 enforces
after the lanes.

### Lane measurement record

On 2026-10-22, before the budget step, the two lane tests were run directly
from a gateway test binary built from main
`120f5571947b80368fc8495a2ce8094dd6c7406e` with Rust 1.98.1 and Cargo's
default test profile. The host was Windows 11 x86-64 with 16 logical CPUs and
other builds running: an uncontrolled development host, not a qualified
runner. The build differed from the controller's in three ways. It kept debug
info and incremental compilation, it set `-D warnings`, and `gateway/build.rs`
was replaced by a script that skips the admin UI build, which requires the
pinned Node. The measured decisions never read the UI bundle. Each target ran
in three separate processes and once more with the regression fixture switch;
each test finished in under a second.

| Target | Allocation calls | Requested bytes | Median timing range (ms) | Largest within-run spread | Fixture growth (calls / bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `tool_policy` | 9,000 | 1,007,400 | 34.7–55.6 | 39.3% | 2,700 / 172,800 |
| `rate_lane` | 19,600 | 909,800 | 25.1–26.6 | 54.8% | 1,400 / 89,600 |

Counts are per sample of 100 dataset passes. Timing ranges span the three
runs' medians, and the spread column is the largest within-run
`(max - min) / median`, not a confidence interval. All 27 samples of each
target had identical counts, equal to those captured from a separate build
when the harness was added (`LANE_ROWS` in `scripts/test_microbench.py`).
Compared with `compare_kernel_results` under the schema-3 budget, each pair of
neutral runs passed and each fixture run failed, by exactly one 64-byte
allocation per decision. The stable counts support the zero-growth budget; the
timing spread on unchanged source again supports leaving time informational.
On this host the controller's `run` command passed its pure-path stage and
then refused the kernel stage, because building the real gateway needs the
pinned Node; `self-test` needs it too. The processes above shared one binary,
so an independent rebuild of the same revision is what `self-test` adds.

## Static egress decision

One more target measures the shared evaluator's static egress lane. It runs in
the same gateway test binary as the lanes above, under the same warmup, sample
and iteration counts, compiler and Cargo profile:

| Target | Kernel call | Live caller | Cases per iteration | Fact bytes |
| --- | --- | --- | ---: | ---: |
| `static_egress` | `CompiledEgressPolicy::evaluate` | the egress adapter's destination checks: `checked_destination` and the DNS-free rebinding and revalidation of a pinned destination | 25 | 550 |

The dataset asks every refusal the lane can reach from a parsed URL, in its
checking order: missing host, userinfo, fragment, scheme, host, pattern label
boundary, and default and explicit port. It also asks a static refusal that
carries resolution facts, and both static admissions, an exact and a pattern
host, which the lane answers by asking for resolution facts. The rest are
address questions: an empty answer set and an answer on an unexpected port,
policy-CIDR exemptions in both address families, IPv4, well-known NAT64 and
configured NAT64 global exceptions, several admitted answers with the first
pinned, and non-global, IPv4-mapped, NAT64-embedded, loopback and out-of-CIDR
IPv6 refusals. Hosts use the reserved `.test` suffix and addresses come from
documentation and IANA special-purpose blocks. Fact bytes sum the scheme and
host bytes of the destinations.

The resolution facts are fixed answer sets: nothing is resolved, connected or
sent. URL parsing and destination and context construction stay outside the
measured intervals, as in the live adapter, which parses the URL before it
asks the lane. The target does not measure the DNS lookup, redirect refusal,
TLS, request and response bounds or transport.

The benchmark is the ignored `static_egress_evaluation` test in
`gateway/tests/support/lane_benchmark.rs`, so it counts through the same
allocator as the lanes and changes only the lane harness digest. Each build
checks that discovery lists it exactly when the revision's lane harness
declares it. A lane harness from before the test is still valid, so a base
may lack it; the head must carry it. Its evidence is saved as
`head.static_egress.kernel.json`, and `base.static_egress.kernel.json` when the
base carries the test, beside the raw reports and `egress-context.json`, and is
summarized under `static_egress` in `summary.json`. The self-test also
requires a neutral rebuild to pass and the deliberate regression fixture to
fail, under the revision's own budget entry.

The target is adopted in the lanes' reviewed steps. The pre-approval comes
first because the lane harness is already enforced:

1. Pre-approval: b5b103f added the next lane harness digest,
   `c6bceb2b37eef9ebffa02baa24db09ab09a9c9b28c08ff7f4b69ebb7c02d364c`, to
   `lane_harness_sha256` beside the current one, while the harness itself
   stayed unchanged.
2. Harness: the test lands, and `scripts/microbench.py` runs it as a
   `pending` target: measured on each revision that declares it, reported,
   never blocking. The `tool_policy` and `rate_lane` comparisons stay enforced
   across the change, because the base budget approves both lane digests. It
   must merge after the pre-approval, never in the same merge.
3. Budget: `microbench-budget.json` moves to schema 4, which lists
   `static_egress` at zero growth after `rate_lane`. The test lives in the
   lane harness, so `lane_harness_sha256` approves it and the schema adds no
   digest list of its own. That change runs `proposed` against its schema-3
   base: the base must already carry the test, both revisions are measured
   and compared, and the result is reported without blocking. Every later
   comparison whose base carries schema 4 is `enforced`, and a head budget
   cannot retire the target. A schema-3 budget that names the target fails
   validation.

All three steps have landed: b5b103f pre-approved the lane harness digest,
d5c1ddc added the test, and the budget step moved `microbench-budget.json` to
schema 4, running `proposed` against its schema-3 base. Every comparison whose
base carries schema 4 enforces `static_egress` as it enforces the lanes. Any
increase in its allocation count or allocated bytes fails the job. So does a
static egress run that is missing, undiscovered, crashed, timed out or
reporting another dataset, a base without the test, and a lane harness digest
that the governing budget does not approve. While only the head's budget
lists the target, that budget governs it, so it must approve the base's lane
harness as well as the head's. A timing change cannot offset an allocation
regression. The same budget stopped approving
`9e70d5c545a5cb02316de2922cfb12518ba3fd803032b70ba72383a142018deb`, the lane
harness from before the test: a head carrying it lacks the test and is
refused, and a schema-4 base cannot be measured without the test, so that
digest can no longer pass. Dropping it frees the second slot for the next
two-hash transition. A static egress dataset or harness change now follows the
two-hash procedure below for `lane_harness_sha256`, like a lane change.

Enforcement adds no test process: each revision that declares the target runs
one static egress process, whatever its state. Every schema-4 base declares
it, while the base of every hosted run so far did not, so an enforced
comparison runs one more process than those runs did, on the base. In the
[hosted CI record](#hosted-ci-record) the slowest comparison step finished
about 11 seconds inside its 480-second budget, and the slowest of the later
ones about 42 seconds inside it, so this narrows a margin that is already the
job's main timing risk.

### Static egress measurement record

On 2026-10-22, before the harness step was merged, the three lane tests were
run directly from one gateway test binary built from main
`ebb579e6444d437bf477d0617b8841d1eea34cfc` with the pre-approval and the
harness edit applied, under the same build and host conditions as the
[lane measurement record](#lane-measurement-record). Each target ran in three
separate processes and once more with the regression fixture switch; timing
ranges and spreads are computed as there.

| Target | Allocation calls | Requested bytes | Median timing range (ms) | Largest within-run spread | Fixture growth (calls / bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `static_egress` | 4,800 | 387,500 | 44.2–60.0 | 54.9% | 2,500 / 160,000 |

Counts are per sample of 100 dataset passes. All 27 samples had identical
counts, equal to those recorded when the harness digest was pre-approved
(`LANE_ROWS` in `scripts/test_microbench.py`). Compared with
`compare_kernel_results` under the zero-growth limit, each pair of neutral
runs passed and the fixture run failed, by exactly one 64-byte allocation per
decision. In the same binary `tool_policy` and `rate_lane` still counted 9,000
calls and 1,007,400 bytes, and 19,600 calls and 909,800 bytes, so the harness
edit leaves their enforced baselines alone. libtest reported each static
egress run finishing in about 0.8 seconds; each process, including startup,
took about 1.9 seconds on this host. Timing stays informational.

On 2026-10-28, for the budget step, the four kernel tests were run the same
way from one gateway test binary built from main
`2280797aef866a6ea5eef8318a9d60bbfec55f2c`, which carries the harness step,
under the same build and host conditions. Each run was compared with
`compare_kernel_results` under its target's entry in the schema-4 budget.

| Target | Allocation calls | Requested bytes | Median timing range (ms) | Largest within-run spread | Fixture growth (calls / bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `http_policy` | 41,700 | 1,439,000 | 76.0–78.4 | 36.4% | 1,700 / 108,800 |
| `tool_policy` | 9,000 | 1,007,400 | 63.8–66.7 | 17.2% | 2,700 / 172,800 |
| `rate_lane` | 19,600 | 909,800 | 52.7–55.1 | 30.1% | 1,400 / 89,600 |
| `static_egress` | 4,800 | 387,500 | 54.2–56.0 | 24.2% | 2,500 / 160,000 |

All 27 samples of each target had identical counts. The lane and static
egress counts equal the records above, and the `http_policy` counts equal
those captured when its harness was added (`kernel_result` in
`scripts/test_microbench.py`), so the merged harness and the intervening
evaluator changes left every kernel baseline where it was. Every pair of
neutral runs passed and
every fixture run failed, by exactly one 64-byte allocation per decision.
libtest reported each static egress run finishing in about one second; each
process took about two. The independent rebuild that `self-test` adds was not
run, for the reason given in the
[lane measurement record](#lane-measurement-record).

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
It is not one of the status checks that branch protection requires on `main`
(checked 2026-10-28), so a failing comparison fails the job, is visible on the
pull request and blocks image promotion, but does not by itself prevent a
merge. Requiring it is a repository-settings decision outside this document.

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

## Issue #437 status

PR 3's kernel step is complete: every live lane of the shared evaluator, the
HTTP, tool, rate and static egress decisions, has a kernel target enforced at
zero allocation growth. No pure-path target is stale, because every predicate
they measure is still live (see [Measured scope](#measured-scope)), so none was
retired. Against the issue's acceptance list, this record shows:

- **Signal and noise.** Allocation counts were identical in every sample of
  every local record, and the controller rejects a run whose samples differ,
  so every passing hosted comparison had identical samples too. The largest
  within-run timing spreads on unchanged source ranged from 17% to 322% by
  target. Allocation budgets therefore block and timing stays informational,
  as the issue allows. No controlled runner has been qualified, so no timing
  threshold exists.
- **Controlled regression and neutral rebuild.** The pure-path `self-test`
  passed locally ([initial record](#initial-local-measurement-record)). For
  the kernel targets the evidence is the fixture runs recorded above, compared
  with `compare_kernel_results`, and the self-test's fixture tests in
  `scripts/test_microbench_process.py`; no end-to-end kernel `self-test` run
  is recorded, because it builds the real gateway and needs the pinned Node.
  CI runs the comparison, not the self-test.
- **Failing closed.** Missing base or head results, unknown schemas,
  mismatched compilers, profiles or datasets, crashed, timed-out or
  undiscovered benchmarks and incomplete target sets fail the comparison; the
  fixture tests in `scripts/test_microbench*.py`, which CI runs before the
  comparison, cover each case.
- **No production data or network.** Every dataset is synthetic: hosts use
  the reserved `.test` suffix, addresses come from documentation and
  special-purpose blocks, there are no tokens, and nothing is resolved,
  connected or sent.
- **Time budget.** Hosted comparisons have stayed inside the 480-second budget
  ([hosted CI record](#hosted-ci-record)), with a margin as small as about 11
  seconds. The nightly performance, HA, failover and release workflows are
  unchanged.
- **Promotion and evidence.** Image promotion depends on `microbench`, and the
  job uploads base, head, raw and summary evidence even when it fails. It is
  not a required branch-protection check on `main`
  ([CI comparison and evidence](#ci-comparison-and-evidence)).
- **UI bundle analysis.** Not measured, and outside this backend benchmark.

Cached JWT verification remains unmeasured, because this harness has no JWT
verification, keys or cache model.
