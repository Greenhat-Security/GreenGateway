# Targeted security mutation checks

Mutation checks ask whether the selected tests detect a deliberate change to
a security predicate. `scripts/security_mutations.py` is an in-tree, Python
standard-library harness, version **1.1.0**, with an explicit target and mutation
registry in `security-mutations.json`. This is the compatible equivalent tool
selected for issue #436; it does not install or invoke `cargo-mutants`.

The registry and controller versions must agree. Compiler, runtime and embedded
UI build versions come from `build-tools.json`, including the CI Rust profile.
Review changes to those pins, the harness, targets and selected tests together
with their measured effect. A score over this small, reviewed registry does not
measure every possible mutation or prove the gateway correct.

## Owned scope

The registry names eleven functions and twenty-one source changes. Each
target records its file, fully qualified function name, unique source markers,
function SHA-256, exact test names and exact replacement text. Missing or moved
functions, changed source, ambiguous anchors and absent tests fail the campaign
until a reviewer reconciles the registry with the authoritative code. Selection
does not silently fall back to a substring match or another similarly named
function. Pull requests check the registry side of that reconciliation, and
that every selected test still exists, before merge; see
[Pull-request registry check](#pull-request-registry-check).

| Target | Security decision | Reviewed changes |
|---|---|---|
| `path_match::path_prefix_matches` | Path segment and subtree boundaries | Remove the segment-boundary check; reject a valid slash-ended subtree |
| `path_match::is_unsafe_request_path` | Ambiguous request-path rejection | Permit backslashes; permit empty interior segments |
| `egress::host_glob_matches` | Egress exact and wildcard host matching | Remove the wildcard label boundary; skip request-host case folding |
| `policy_eval::route_host_matches` | Shared evaluator host binding | Ignore a required binding; accept an absent request host |
| `policy_eval::CompiledPolicy::select_rate_lane` | Which `rate_limits` override governs an authenticated request | Ignore the override's principal constraint; ignore its path pattern; select the last matching override instead of the first |
| `policy_eval::CompiledPolicy::evaluate_tool` | Tool admission, previews and the rendered-HTTP rule | Admit a disabled tool; ignore a matching deny rule; never consult the rendered request's HTTP rule |
| `policy_eval::tools::tool_principal_matches` | A tool entry's role, issuer and authentication-method constraints | Admit an anonymous caller to a constrained tool; ignore `allowed_roles` |
| `policy_eval::tools::validate_rendered_http_path` | Rendered tool paths the HTTP rule is evaluated over | Accept a `..` segment |
| `policy_eval::egress::CompiledEgressPolicy::evaluate` | That a destination the static egress checks refuse is refused before any name is resolved | Ask for resolution facts while a static refusal is pending |
| `policy_eval::egress::CompiledEgressPolicy::admit_destination` | The static egress checks: URL shape, scheme, host and port allowlists | Let an exact host entry admit any host ending in it; ignore the policy port list |
| `policy_eval::egress::CompiledEgressPolicy::check_answers` | The address checks over resolution facts | Judge only the answer that will be pinned |

A target is a module-level function, or a method one indentation level into a
module-level inherent `impl Type {` block. A method's registry name ends
`Type::method`, its start marker carries the four-space indentation, and its
end marker is `"\n    }\n"`, the closing brace at that indentation. The
nearest line above the method that starts in column zero must be exactly
`impl Type {`, so a method moved to another type, a trait impl or a generic
impl fails as drift instead of being matched by name.

The host-binding target belonged to the shared evaluator from the start. Since
#569 the live tool lane decides through `CompiledPolicy::evaluate_tool`:
invocation admission, MCP visibility, inventory eligibility, composite leaf
enablement and the rendered-HTTP rule. Since #598 the policy rate stage selects
its override through `CompiledPolicy::select_rate_lane`. The registry targets
those evaluator functions, not the frozen pre-cutover consumers that remain
only as test oracles. Executor rendering refuses a path with the evaluator's
own `validate_rendered_http_path` before the rule is asked, so that guard is
selected too. Since #422 PR 3b the static egress checks decide through
`CompiledEgressPolicy::evaluate`: its static checks (`admit_destination`) and
its address checks over resolution facts (`check_answers`). The cutovers
retired no registered function. `egress::host_glob_matches` is the host-pattern
predicate that lane calls, so it stays selected; its start marker now carries
`pub(crate)` because the lane in `policy_eval` calls it. The shared path
functions stay selected too, since the evaluator and the HTTP lane still call
them. Legacy retirement tracked by #422 is still open. When ownership moves
again, update the target, function hash and exact tests in the same reviewed
change, remove the retired target, and remeasure.

The tool-lane targets select tests that state the evaluator's answers
outright. The live adapters ask this same evaluator, so a test that only
compares the evaluator with them would compare it with itself and kill
nothing. The rate-lane target compares each selection with the frozen
pre-cutover selector. The static egress targets select tests that state the
lane's answers outright, and the named matrix that compares the live adapter
with the frozen pre-cutover checks; the decision-order target also selects
the harness whose resolver panics if a refused destination ever reaches it.

Only these pure tests run during mutation execution. They need no DNS,
credential provider, database, upstream server or third-party API: the egress
tests answer lookups from in-process resolvers and never open a connection. Dependency
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
python scripts/security_mutations.py --validate-registry
mkdir -p target/security-mutations
cargo test --workspace --locked -- --list --format terse > target/security-mutations/test-list.txt
python scripts/security_mutations.py --check-test-list target/security-mutations/test-list.txt
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

## Evaluator adoption

Issue #436 PR 4 followed the tool lane (#569) and rate-lane selection (#598)
onto the shared evaluator. It added the four `policy_eval` targets above and
nine mutations, so the registry has 17. Two tests were added with it:
`a_disabled_entry_and_a_denying_tool_or_rendered_rule_each_block_on_their_own`
and
`each_tool_identity_constraint_refuses_a_caller_without_it_and_an_anonymous_one`.
Existing tests already stated a rendered-request deny and an anonymous refusal
outright. A disabled entry, a tool deny rule and each identity constraint were
otherwise checked only through the frozen-oracle corpus, or against live
adapters that ask the same evaluator and so change with it. Production code
did not change.

Pull requests build no mutants. The scheduled workflow runs only on the
default branch, so a dispatch against a pull-request branch skips the job.
The first hosted campaign of this registry is therefore the first scheduled or
manual run after merge, and its report is the reviewed baseline.

Before review, the registry was measured locally with the same loader, spans,
`old`/`new` replacements and `--exact --test-threads=1` test commands. It ran
on a Windows working tree of the change, based on `4a32d10`, with Rust CI
1.98.1 and a local manifest that skipped the embedded UI build. It did not
have the controller's rlimits, process groups or pinned Python and Node. All
17 selected baseline tests passed, each within 1.3 seconds of wall time, most
of it the test binary's start-up. All 17 mutants were killed; none survived,
failed to build or timed out. Each original mutant was killed by the same test
as in the nightly reports, and each new mutant by the first test listed for
it. Mutant rebuilds took 59–217 seconds on a shared workstation. This is
review evidence, not a substitute for the controller's report.

Issue #422 PR 3b moved the static egress checks onto the shared evaluator. It
added the three `policy_eval::egress` targets above and four mutations, so the
registry has 21; it retired no registered target. Before review, each new
mutant was applied to a Windows working tree of the change, based on
`198ab93` (the rebase onto `db4160f` changed no Rust source), and its selected
tests were run with `--exact` under Rust CI 1.98.1 and a local build script
that skipped the embedded UI build, without the controller's rlimits or
process groups. All four were killed.
`egress-static-evaluate/resolve-before-static-denial` failed
`a_refused_destination_is_decided_without_resolution_facts` and, on its own,
the refused-destination harness;
`egress-static-admit/exact-host-admits-suffix` and
`egress-static-admit/ignore-port-allowlist` failed the host and port tests
selected for them respectively, and the named matrix; and
`egress-static-answers/check-only-pinned-answer` failed
`every_answer_is_judged_and_the_first_is_pinned` and the named matrix. Mutant
rebuilds took 104–683 seconds on a shared workstation. This is review
evidence, not a substitute for the controller's report.

On GitHub-hosted runners, two nightly campaigns of the eight-mutant registry
on `main`, on 2026-10-13 and 2026-10-20, took 1,358 and 2,232 seconds. Their
baseline builds took 284 and 467 seconds, and mutant rebuilds 133–228
seconds. At those rates 17 mutants take about 2,550–4,350 seconds, and the 21
after the static egress adoption about 3,080–5,260 seconds, inside the
7,200-second campaign bound and the 150-minute job. With a baseline like
those, rebuilds of 21 mutants would have to average about 320 seconds to
exceed the bound, against about 390 for 17. The controller then fails the
campaign as timed out rather than reporting a partial score. Re-measure before
adding more mutations.

## Survivor review and baseline ownership

The checked-in registry is the reviewed baseline, with no exceptions initially.
Maintainers responsible for the selected path, egress and evaluator decisions
own recurring failures. The contributor changing a selected function must
reconcile its source hash, selected tests and measured outcomes in that same
review. The [pull-request registry check](#pull-request-registry-check)
enforces the registry part of that rule before merge. A scheduled failure is
not resolved merely by rerunning until green.

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

## Pull-request registry check

Every pull request, `main` push and version tag runs two registry checks, each
in an existing required CI job. Reusing those jobs leaves the required-check
and image-promotion lists unchanged.

The `supply-chain` job runs the controller's `ManifestTests` and
`TestListTests`, which need neither a compiler nor a child process, then
`scripts/test_security_mutations_workflows.py`, which confirms that these
steps and the scheduled campaign's trust boundary are still in place, and then
`python scripts/security_mutations.py --validate-registry`. The remaining
controller tests stay in the scheduled job because they include a real Rust
calibration build and real process-limit checks.

`--validate-registry` runs the campaign's registry loader against the
checked-out tree: schema and harness version, safe regular-file paths, a start
marker that occurs once at the beginning of a line, the function scope it
opens, for a method the inherent impl around it, the function SHA-256, each
mutation's `old` text occurring exactly once in that function, selected test
names' syntax, count and uniqueness, and each exception's binding to a current
mutation identity. A pass prints
`security mutation registry check: passed (registry_valid)` and reports
`source_state: checkout_registry_only`. Nothing is compiled, discovered,
tested or mutated, so its counts stay zero and it is not a mutation score.

The `test` job, after `cargo test --workspace --locked` has built and run the
suite, repeats that exact invocation with `-- --list --format terse` to list
the same test binaries without rebuilding them, and passes the listing to
`python scripts/security_mutations.py --check-test-list`. That mode applies the
same registry validation, then requires every selected test to be listed
exactly once, as a test, under its exact name. A renamed or deleted test fails
with `registry_test_not_listed`; one listed more than once, for example by two
test binaries, or only as a benchmark fails with `registry_test_ambiguous`.
Both print the affected registry names and record them in the report as
`unlisted_tests` and `ambiguous_tests`. A listing line that is not terse
libtest output fails with `invalid_test_list`, and an empty listing with
`empty_test_list`; the check never falls back to a prefix or substring match.
A pass reports `reason: registry_tests_listed` with
`source_state: checkout_registry_and_test_list`, the listing's SHA-256 and
the number of listed entries, again with zero counts.

Like the campaign, both modes run only on Linux. They cannot be combined with
each other or with `--calibrate`.

The reconciliation rule for pull requests: a change that edits, moves or
renames a registered function or its file, or edits the registry, must leave
this check passing in the same pull request. Update the target's `path`,
`function`, `start_marker` and `source_sha256` as needed, and revise any
mutation whose `old` text no longer occurs exactly once. A new digest is a
review statement rather than a formality: confirm that each mutation still
expresses its reviewed security change and that each selected test still
asserts that behavior. Measured outcomes still come from a complete campaign,
as described above.

The digest covers the committed bytes from the start of the `start_marker` line
through the first following `end_marker`, inclusive: `\n}\n` for a
module-level function, `\n    }\n` for a method. To recompute one, for example:

```sh
python - <<'PY'
import hashlib, pathlib
source = pathlib.Path("gateway/src/path_match.rs").read_bytes()
start = source.index(b"pub fn path_prefix_matches(")
print(hashlib.sha256(source[start:source.index(b"\n}\n", start) + 3]).hexdigest())
source = pathlib.Path("gateway/src/policy_eval/mod.rs").read_bytes()
start = source.index(b"    pub(crate) fn select_rate_lane(")
print(hashlib.sha256(source[start:source.index(b"\n    }\n", start) + 7]).hexdigest())
PY
```

Then rerun `--validate-registry`, which applies the exact rules. A working tree
with CRLF line endings, such as a Windows checkout with `core.autocrlf=true`,
fails with `function_scope_drift`; hash the committed LF bytes instead.

A selected test that is renamed or deleted must be updated in the registry in
the same pull request, with the same review of what the replacement asserts.
Neither check can detect a new survivor, an unviable mutant, a timeout or a
selected test marked `#[ignore]`. Those need mutated builds or a baseline run
and remain campaign results. The required `test` job still runs every
non-ignored selected test.

## Trusted scheduled execution

`.github/workflows/security-mutations.yml` runs nightly at 04:41 UTC and accepts
manual dispatch without input overrides. The job requires the upstream
`Greenhat-Security/GreenGateway` repository, its default branch and a schedule
or manual event. Checkout uses the exact event SHA with persisted credentials
disabled. The workflow grants only `contents: read`, uses immutable action
references, installs the pinned build tools, tests controller failure handling
and workflow trust boundaries, then runs the complete registry.

Pull requests run only the registry checks above; no mutant is built or
measured on a pull request. The existing
[security coverage gate](security-coverage.md), normal tests and
image-promotion dependencies remain unchanged. A future small
PR mutation gate requires a separately reviewed target scope and measured
end-to-end runtime; the scheduled baseline does not authorize a slow or partial
mutation job on every pull request.
