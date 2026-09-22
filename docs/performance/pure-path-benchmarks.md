# Pure-path microbenchmark budgets

Part of #437. The standalone microbenchmark controller compares allocation
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
upload. Total hosted job duration still needs verification on an actual GitHub
runner.

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

## Base ownership and reviewed updates

`microbench-budget.json` versions the benchmark schema and regression budget.
The active comparison loads its policy from the **base commit**. Changing the
head's budget cannot make that comparison pass. This is a review boundary;
repository administrators must retain the normal required-check and review
protections. The job does not write baselines or grant itself repository write
access.

Initial adoption has one explicit exception: the exact reviewed commit
`167cc5ecf816197f34e1cbb7455c1c21854aa6c8` predates the budget file and may use
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

## CI integration follow-up

The next PR slice wires this measured controller into pull-request and push checks,
with immutable event revisions, required evidence uploads and image-promotion
dependencies. Hosted execution remains unverified until that integration runs
on GitHub Actions.
