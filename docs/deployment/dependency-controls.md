# Dependency controls

External Actions use full commit SHAs, and production Docker, Kubernetes, HA
Compose and CI service images use registry-resolved manifest digests. Preserve
the tag comments when updating action pins. Dependabot opens weekly update PRs
for Actions, Cargo, npm and the Dockerfile; deployment image updates are reviewed
alongside the release they consume. CI rejects missing pins.

Digest pinning fixes artifact identity; it does not certify the contents. The
Kubernetes examples now use the promoted September audit remediation image at
revision `878e6c904da65683ca72d312a529ad79984a6978`. Its immutable digest,
published platform and local verification evidence are recorded in
[`deploy/kubernetes/README.md`](../../deploy/kubernetes/README.md).
For each release, wait for successful CI and promotion, verify its revision and
digest, then update deployment references before rollout. Never substitute a
build candidate or invent a digest.

Both npm lockfiles have a high-severity audit gate. Pull requests also run GitHub
dependency review, rejecting newly introduced advisories at moderate severity
or higher. Review open Dependabot alerts before release as well: dependency
review evaluates changes, and GitHub's advisory catalog can differ from RustSec.
Cargo audit denies warnings, including yanked dependencies;
there are no advisory exceptions. Any future exception needs a tracked owner,
dependency chain, exposure analysis, removal condition and expiry, reviewed in
the same PR as the exception.

## September 2026 audit reconciliation

The supplied external report used an older snapshot and contains configuration
names and dependency claims that do not match the current tree. In particular:

- [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html)
  concerns `glib`; [RUSTSEC-2025-0057](https://rustsec.org/advisories/RUSTSEC-2025-0057.html)
  concerns unmaintained `fxhash`. Neither package occurs in this Cargo.lock and
  neither advisory is suppressed by current CI. They are not open application
  vulnerabilities in this dependency graph.
- `chacha20` 0.10.0 was yanked. The lockfile now selects compatible 0.10.2, and
  `cargo audit --deny warnings` passes with no exceptions. Yanked status alone
  is not a CVE.
- [GHSA-h395-gr6q-cpjc](https://github.com/Keats/jsonwebtoken/security/advisories/GHSA-h395-gr6q-cpjc)
  affected the runtime `jsonwebtoken` dependency. Its minimum version is now
  10.3.0, the first patched release, and Cargo.lock selects 10.4.0. JWT validation
  uses the AWS-LC backend already present in the TLS stack. Publish and verify a
  new image before updating deployment digests; a previous image retains its
  original dependencies.
- The npm gates and the nightly fixture/HTTP buffering fixes are included in
  the preceding production-readiness change. The five release benchmarks passed
  locally without increasing budgets; production load validation is separate.
- `GG_ADMIN_API` is not a supported setting here. Kubernetes management isolation
  uses the actual `ADMIN_LISTEN_ADDR` split-listener setting.

Run `python3 scripts/check-supply-chain.py` and `cargo audit --deny warnings`
when updating inputs. Use `docker buildx imagetools inspect IMAGE:TAG` to resolve
the multi-platform manifest digest, then inspect the selected artifact before
changing a production reference.

## Executable build-tool contract

`build-tools.json` is the reviewed version inventory. The native
`rust-toolchain.toml`, `.node-version`, `.npm-version`, both npm engine fields,
and the Dockerfile must agree with it. `scripts/build_tools.py check` rejects
missing declarations, version drift, unpinned installs and implicit npx downloads.
CI uses the shared `.github/actions/build-tools` action before any build.

The production/default compiler remains Rust 1.88.0, matching the existing
Docker image and the maximum declared MSRV in the locked dependency graph.
The required `production-compiler` job checks all targets with that compiler;
ordinary CI uses the previously passing Rust 1.98.1. Coverage remains on
nightly-2026-09-01 with cargo-llvm-cov 0.9.0 and unchanged floors. Its dated
compiler is deliberate, not an invitation to follow nightly updates.
Node 24.20.0 and bundled npm 11.19.0 match the current pinned Node image.
Gateway builds verify the actual Node/npm executable versions before installing
UI dependencies, and Docker additionally checks its actual Rust version.
Cargo builds use the existing lockfile without resolution updates.

Buildx is selected explicitly and its BuildKit daemon image is digest-pinned,
including CI Compose builds. Action pins and the exact cargo-audit version
remain separate declarations; cargo-audit installation retains checksum
verification. Gitleaks retains its reviewed archive checksum. Rustup and the
setup actions remain the pinned installation trust roots; npm lockfile integrity
continues to authenticate dependency archives. Advisory databases still refresh.

To update tools, change the manifest and native/package/Docker consumers in one
PR, preserve image/action digests and installation verification, run the tool and
publication-gate tests, and run fresh Linux, Windows coverage and production
image builds. Record actual versions in the CI log. A coverage compiler/tool
change needs a baseline comparison without reducing floors. Existing Dependabot
PRs must satisfy this parity contract; do not merge a major Node/Rust Docker bump
without updating and testing the declared compiler/runtime contract.

This pins project-selected executable tools, not every program in a hosted
runner OS. Runner Git, Docker Engine/Compose, system Python bootstrap and OS
utilities remain platform inputs; the shared action selects project Python before
repository scripts run. Debian package repositories also remain mutable inputs.
The candidate image scan and provenance work cover final-image inventory and
attribution; no byte-for-byte hermetic-build guarantee is claimed.


## Final candidate image gate

`image-scan` reads the current build's immutable OCI digest and resolves its
runtime manifest and configuration by digest. Only `linux/amd64` is currently
supported; an additional or missing runtime platform fails until this policy and
its validation are deliberately extended. BuildKit's `unknown/unknown`
attestation descriptors are preserved and distinguished from runnable images.
The runtime configuration's source revision must match the triggering commit.

Trivy 0.74.0 is installed from the checksum recorded in `build-tools.json`.
Every run starts with a fresh cache, downloads the advisory database, and checks
its schema and UTC update time. An unavailable database, age over 48 hours,
future timestamp beyond five minutes, scanner error, malformed report, absent
OS inventory, unsupported/end-of-life OS, or subject/platform mismatch fails the
gate. The scan requests OS and discoverable application packages, all package
inventory and all severities. Repository Trivy configuration and ambient
`TRIVY_*` variables cannot silently alter this policy.

High, critical and unknown-severity findings block, including unfixed findings.
Lower-severity findings remain in the raw evidence. Cargo and npm source audits
remain mandatory: compiled Rust binaries and embedded JavaScript bundles do not
provide a complete language dependency inventory to an image scanner. Passing
this gate is not a claim that every embedded component has been identified.

`image-scan-policy.json` contains the reviewed exceptions (initially empty).
Each entry requires `advisory`, exact `package`, exact installed `version`,
`owner`, substantive `rationale`, and timezone-qualified `expires`, at most 90
days ahead. Optional `digest` further restricts the exception to one OCI index.
Wildcards, missing fields, duplicates and expired exceptions fail validation.
Review the affected package, vendor advisory and exposure before approving an
exception in a PR; never add blanket exceptions to obtain a green release.
Reports retain both the original finding and the applied review metadata.

Update the scanner release and its verified official Linux archive checksum
together, run the gate regressions and a real registry scan, and review changes
in package detection. The database intentionally refreshes independently of the
scanner pin. See [Trivy image options](https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/).

CI retains `image-scan-<source SHA>` for 30 days: raw platform JSON inventories,
OCI index, database metadata and `decision.json` with identities, scanner version,
report hashes, unexcepted blocking findings, applied exceptions and gate stage.
Export this evidence to your release archive for longer retention. Failure to
upload available evidence also fails the job. A failed or skipped scan emits no
passing digest, and promotion requires that output to equal the candidate digest.


## Signed final-image evidence

`image-verification` is a separate required promotion dependency alongside
`image-scan`. The reusable candidate builder alone has OIDC/attestation write
permissions, explicitly granted by its trusted push caller. PR previews remain
read-only. The verifier has read permissions and consumes this run's downloaded
SBOM; it independently retrieves image attestations from GHCR and SBOM-file
provenance from GitHub. It constrains the certificate's source repository,
source ref/commit and reusable signer workflow/commit, rather than trusting those
values merely because they appear in the signed predicate.

The GitHub CLI verifier version and Linux archive SHA are recorded in
`build-tools.json`; the executable is checked before use. The signing and artifact
transfer actions use full commit SHAs. Updating these requires the publication,
scan, evidence and tool-contract regression suites and a real trusted candidate
verification. Failed/skipped verification or a digest different from the scan/build
output prevents promotion. See [operator verification and offline evidence](../RELEASING.md#verifying-image-provenance-and-retrieving-the-sbom).
