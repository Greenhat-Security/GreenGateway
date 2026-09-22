# Deterministic properties for pure security parsers

Part of [#435](https://github.com/Greenhat-Security/GreenGateway/issues/435),
the first property-inventory and parser-suite slice. These tests exercise the
existing production helpers directly. They do not create a second parser,
change accepted inputs, or start a gateway, DNS resolver, provider, or HTTP
client for generated cases.

## Existing coverage

Inventory at the introduction of this suite:

| Source | Existing generated coverage | Configuration |
| --- | --- | --- |
| `gateway/src/rbac/matcher.rs` | Path-pattern matching against a reference; generated nonmatches; optimized rule matcher against first-match scan | Three properties, 160 cases each; an additional generator-coverage test draws 64 pairs |
| `gateway/src/tools/codecs/decimal_scale.rs` | Canonical scaled integer encode/decode round trip | One property using the Proptest default case count |
| `gateway/src/policy_eval/tests.rs` | Requests/principals accepted by admission/authentication are not refused by the kernel for shape | One property, 256 cases; samples across method, path, host, subject and role bounds |
| `gateway/src/egress/tests.rs` | Special-use IP examples, RFC6052 layouts, host wildcards and mixed-answer rejection | Deterministic examples and local transport doubles; not previously a generated pure-parser suite |
| `gateway/src/upstream_route.rs`, `gateway/src/path_match.rs` | Host syntax/authority conflicts, route precedence, exact probe exemptions and unsafe paths | Deterministic examples |

The three existing generated suites use Proptest's default random-seed selection.
They remain unchanged. The admission/kernel property already exists on main;
future #435 evaluator work should extend it rather than duplicate it.

## New invariant boundaries

### Egress addresses and hostname patterns

The generated address properties preserve IPv4 deny classification through
IPv4-mapped IPv6 and each supported RFC6052 layout: `/32`, `/40`, `/48`, `/56`,
`/64`, and `/96`. The encoder in the test uses explicit byte positions rather
than repeating the production extractor's bit-shift algorithm. It tests the
well-known NAT64 prefix and one valid configured prefix at a time.

The extractor rejects unsupported prefix lengths and a nonzero u octet
(`octets()[8]`), including `/96`. It does not currently enforce zero suffix
padding. Configuration rejects overlapping prefixes and invalid reserved
octets; properties do not claim that such configurations are supported or that
arbitrary overlapping prefixes are order-independent.

Synthetic answer sets prove that admission inspects every member, rejects an
empty set, and selects the first answer only after the entire set passes.
Reordering a mixed set cannot make it admissible. A denied error may identify a
different member after reordering. CIDR exceptions apply to the original address
family; an IPv4 CIDR is not an exception for a mapped IPv6 address merely because
it embeds the same IPv4 value.

Generated hostname labels test ASCII case folding and the leading wildcard's
dot boundary, including apex and concatenated lookalikes. These are textual
allowlist properties; they perform no DNS lookup or internationalized-domain
canonicalization.

### Request hosts and route selection

The request-host parser strips a valid numeric port and IPv6 brackets and folds
ASCII case. It preserves percent escapes and trailing dots; it does not decode
escapes or equate different IPv6 spellings. A Host field and URI authority must
agree after the parser's raw trimming/case normalization, including the port's
text: `:080` and `:80` are deliberately not equivalent.

Generated tests cover duplicate/conflicting fields, arbitrary IPv6 literals,
host lengths through the configured bound plus 32 bytes, and bounded arbitrary
Unicode/ASCII input. A present output must be a bounded, bare, ASCII-lowercase
host. Invalid `HeaderValue` bytes are handled without assuming they can enter
the typed host-header API. Route selection retains longest-prefix priority,
host-specific tie breaking and first-in-order behavior for identical ties.

### Literal request paths

Generated safe segments match only at literal segment boundaries. Appending a
non-slash lookalike cannot turn a protected prefix into a match. Inserting
percent escapes, backslashes, dot/dot-dot segments or duplicate slashes remains
unsafe. Fixed probe exemptions match only themselves, never their generated
descendants. Ordinary subtree exemptions and single trailing slashes retain
their existing semantics.

These are properties of literal path helpers. They do not assert that decoding
or collapsing an unsafe representation should produce an equivalent admitted
request. The existing admission/kernel property covers the shared request-size
bounds; path-helper properties do not replace that admission check.

## Reproduce

Use the exact compiler, Node/npm and Python versions in `build-tools.json`, as
described in [the contribution guide](../../CONTRIBUTING.md). The locked
Proptest version is 1.11.0; no dependency or tool pin changes are needed.

```sh
export RUSTUP_TOOLCHAIN="$(python -c "import json; print(json.load(open('build-tools.json'))['rust_ci'])")"
cargo test -p gateway --locked property_tests:: -- --list
cargo test -p gateway --locked property_tests:: -- --test-threads=1
```

Confirm the list includes all three modules: `egress::property_tests`,
`upstream_route::property_tests`, and `path_match::property_tests`. Cargo accepts
an unmatched filter as an empty successful run, so do not treat an empty list
as evidence. The normal `cargo test --workspace --locked` CI job runs these
tests without a filter and already gates image promotion.

The new modules explicitly select the ChaCha RNG, fixed seeds and 128 cases per
property, with at most 2,048 shrink iterations:

| Module | Seed | Properties | Input bounds |
| --- | --- | --- | --- |
| `egress::property_tests` | `435001` | 10 | 4/16-byte addresses; at most 12 answers; DNS labels up to 12 bytes |
| `upstream_route::property_tests` | `435002` | 8 | Bounded host strings, IPv6 literals and small generated route lists |
| `path_match::property_tests` | `435003` | 4 | At most eight 24-byte path segments plus fixed ambiguity markers |

Generated host strings have at most 256 Unicode
characters (1,024 UTF-8 bytes), except the deliberate host-length test at the
4,096-byte boundary. Every generated port in that test visits lengths 4,095,
4,096 and 4,097 as well as its random length, so both sides always run.
Paths contain at most eight generated 24-byte segments;
address/answer generators are separately bounded in the egress module. No
generator uses production identities, credential values or external targets.

These deterministic seeds are part of the regression contract. Proptest's
environment seed/algorithm overrides do not replace the new modules' explicit
selections.
Use the same source, lockfile, seed and toolchain to reproduce a failure; when
deliberately exploring another seed, review that test-only change and record
the chosen seed. Do not silently replace a failing seed to obtain green.
Proptest may persist a minimized failure seed using its normal regression-file
mechanism; inspect and retain a safe deterministic fixture for a confirmed bug.

Run the existing generated suites and ordinary repository gates as well:

```sh
cargo test -p gateway --locked rbac::matcher::tests
cargo test -p gateway --locked canonical_scaled_integers_round_trip
cargo test -p gateway --locked a_request_and_principal_that_pass_admission_and_authentication_cannot_be_refused_by_the_kernel_for_shape
cargo fmt --check
cargo clippy --workspace --locked -- -D warnings
cargo test --workspace --locked
python scripts/transport_guard.py check
python scripts/cargo_policy.py install
python scripts/cargo_policy.py check
```

The first Cargo build still runs the reviewed npm installer and builds the
embedded UI. The pure test bodies do no external I/O per input; this is not a
claim that a fresh repository build requires no downloads. Coverage thresholds,
transport ownership and existing test selectors remain unchanged; existing
promotion gates remain mandatory.

## Remaining #435 work

The [bounded corpus harness](security-corpus.md) now adds synthetic
JWT/policy/host/path seeds, explicit process time/memory budgets, nonempty-corpus
checks and retained seed/corpus identity. Trusted scheduled/manual exploration
and a mandatory regression promotion dependency now run in CI. The final slice
adds generated properties for the already-available shared evaluator.
These checks do not establish exhaustive parser safety or perform external
target testing.

Triage recurring failures with the owners of the affected parser and security
tests. Preserve the reproducing seed and toolchain, minimize to synthetic input,
and follow [SECURITY.md](../../SECURITY.md) for a suspected exploitable issue
before publishing raw findings. Keep these properties with the authoritative
helpers if later kernel extraction moves them; do not keep testing retired
implementations just to preserve a green selector.
