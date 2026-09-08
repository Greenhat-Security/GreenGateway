# Rust dependency policy

Issue #431 complements RustSec and GitHub dependency review with source, license
and architecture checks. It does not replace the fresh `cargo audit --deny
warnings` gate or the final-image scanner.

## Reviewed baseline

`cargo-dependency-inventory.json` records the locked graph at the source commit
in its header: 412 packages, including the workspace, 411 crates.io packages,
and 26 duplicated package names. It includes exact checksums, declared license
expressions and incoming dependency chains. No external Git source or additional
registry occurs. The snapshot contains no developer filesystem paths.

The inventory command is `cargo metadata --locked --all-features --format-version
1`, with no platform filter. Normal, build, development and foreign-platform
dependencies are retained. This intentionally includes more than the Linux
amd64 image: Windows qualification dependencies and other resolved platform
packages must not disappear from review. Cargo-deny evaluates the feature-active
edges in this metadata; the inventory additionally records packages retained by
Cargo resolution even when no active build edge reaches them.

## License acceptance

The repository's actual `LICENSE` is Apache-2.0. Keep it as the workspace license
file; cargo-deny identifies its text instead of ignoring the workspace package.
The policy retains the existing permissive dependency footprint. Its global
allowlist is Apache-2.0, MIT, MIT-0, ISC, BSD-3-Clause, Unicode-3.0 and Zlib.
An OR expression may select one accepted alternative; every term in an AND
expression must be satisfied. For example, the AWS-LC native bundle has several
simultaneous obligations; the LGPL alternative on r-efi is not selected.

Three existing requirements are permitted only at their reviewed versions:

| Dependency | License | Reason and distribution obligation |
| --- | --- | --- |
| notify 8.2.0 | CC0-1.0 | Existing file watcher; retain the supplied text. This does not approve new CC0 code dependencies or assert a patent grant. |
| webpki-root-certs 1.0.8 | CDLA-Permissive-2.0 | Existing certificate-root data; preserve the data license when sharing the roots. |
| winx 0.36.4 | Apache-2.0 WITH LLVM-exception | Existing Windows filesystem binding; preserve the Apache license and its exception. |

Keep third-party license texts, attribution, copyright notices and any applicable
NOTICE content in distributions as required by each selected license. A green
license-expression check does not itself assemble notices or certify legal
compliance. The image SBOM supplies package identities, not a replacement for
the underlying license texts.

Maintainers own changes to this acceptance policy. New copyleft, proprietary,
custom, missing or ambiguous licensing requires an explicit maintainer decision;
do not add it automatically from tool output. This change retains licenses of
dependencies already in the project, adds no new application dependency, and
does not adopt a catch-all license allowance. Refer to the
[SPDX license texts](https://spdx.org/licenses/), the
[CDLA data license](https://spdx.org/licenses/CDLA-Permissive-2.0.html), and
[cargo-deny's expression and exception rules](https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html).

## Sources and bans

Only the exact crates.io registry is allowed. Unknown registries and all Git
sources are denied. Workspace path packages remain subject to licensing and
bans. A future external source needs a reviewed, immutable identity and policy
change, not an organization-wide Git allowance.

OpenSSL, openssl-sys, native-tls, tokio-native-tls and hyper-tls are banned to
preserve the reviewed Rustls transport/credential TLS architecture. Platform
certificate-store adapters are not alternative HTTP TLS stacks and are not
blanket-banned. These are architecture bans, not claims that every use of these
libraries is vulnerable. See the feature rationale in the workspace manifest
and the existing egress guard.

## Duplicates and exceptions

Duplicate versions are denied unless explicitly listed. `deny.toml` permits
only exact versions, never a skipped dependency subtree. The associated
`cargo-policy-exceptions.json` records the complete version group, concrete
parents, rationale, maintainer ownership, expiry and remediation condition.
Groups largely arise from distinct RustCrypto generations, SQLite/PostgreSQL
interfaces, random-number APIs and Windows import-library generations. Their
interfaces cannot be forcibly unified through a lockfile edit.

Re-evaluate each exception when its listed parents update; remove it when their
requirements converge. Do not extend an expiry merely because CI becomes red.
The policy runner validates exception scope/expiry and current graph identities
before executing the pinned tool.

## Pinned executable proof

The initial inventory was checked with cargo-deny **0.20.2**, downloaded from
the [official release](https://github.com/EmbarkStudios/cargo-deny/releases/tag/0.20.2)
and checked against its published archive SHA-256 before executing it:

```sh
cargo-deny --locked --all-features --workspace check licenses bans sources
```

The native check passes. It reports the workspace's license-file-only manifest,
whose Apache license text it successfully recognizes, and a locked but inactive
rand_core 0.6.4 skip entry. Neither warning suppresses a license, source or ban
finding. The repository's separate RustSec warning policy remains unchanged.

Install and run the same gate used by CI:

```sh
python scripts/cargo_policy.py install
python scripts/cargo_policy.py check
```

`build-tools.json` pins cargo-deny and the official Linux/Windows x86_64 archive
checksums. Installation verifies bytes before extracting only the executable;
checking verifies its actual version. A missing tool is an error, not an install
fallback. The runner invokes the locked all-feature workspace with no target,
package, unpublished-package or development-dependency exclusions.

Before native checks it compares resolved package identities with Cargo.lock,
verifies exact duplicate versions and parent chains, and rejects stale license
exceptions, broad or expired exceptions, hidden policy overrides and policy
configuration drift. Unapproved lockfile sources fail before metadata fetching.
The `cargo-policy` job is a required promotion dependency. It preserves
`target/cargo-policy/decision.json` and native `diagnostics.jsonl`; configuration,
metadata, tool and policy failures cannot produce a passed report. Exception
metadata is included in every passing report.

## Updating dependencies and exceptions

1. Update the lockfile with the pinned compiler, keeping the full workspace and
   shipped features represented. Do not edit lock checksums manually.
2. Run the policy checker. Review new sources, license expressions and duplicate
   groups. A newly banned TLS stack requires an architecture decision, not a
   routine exception. Registry/Git origins remain closed by default.
3. For unavoidable duplicate changes, inspect `cargo tree --locked --all-features
   --target all --invert NAME@VERSION` and the metadata parent edges. Update only
   the exact version group and parents, explain why they cannot converge yet,
   assign maintainer ownership and a concrete remediation condition, and choose
   an expiry no more than 90 days ahead. Remove stale entries instead of
   carrying them forward. Renewals require substantive review.
4. License exceptions must pin one crate/version and its selected license IDs.
   Preserve applicable notices. New licensing outside the existing acceptance
   policy remains an explicit maintainer decision; do not broaden allowances to
   silence a failed check. Update the corresponding `deny.toml` entries in the
   same reviewed PR. Undeclared hidden exception files are rejected.
5. Run `python -m unittest discover -s scripts -p 'test_cargo_policy.py' -v`,
   `python scripts/cargo_policy.py check`, the security-gate tests and publication
   tests. CI performs these policy checks on Linux and Windows with the same
   verified executable version. Normal Cargo audits and image scans remain
   required independently.

The native fixtures edit disposable metadata only. They prove the actual pinned
cargo-deny rejects an unapproved license, a banned crate and unknown registry/Git
sources, with networking disabled and no dependency files changed or compiled.
A clean native control prevents a broken fixture from masquerading as rejection.
Other regressions cover expired/unowned/broad/stale exceptions, duplicate-parent
changes, graph pruning, hidden overrides, missing tools/config, and required CI
wiring. Reports bind their lockfile, config, review metadata and tool contract by
SHA-256 and retain exact exceptions, including their ownership and expiry.
