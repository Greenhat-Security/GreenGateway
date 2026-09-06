# Dependency controls

External Actions use full commit SHAs, and production Docker, Kubernetes, HA
Compose and CI service images use registry-resolved manifest digests. Preserve
the tag comments when updating action pins. Dependabot opens weekly update PRs
for Actions, Cargo, npm and the Dockerfile; deployment image updates are reviewed
alongside the release they consume. CI rejects missing pins.

Digest pinning fixes artifact identity; it does not certify the contents. The
Kubernetes digest records the published image snapshot reviewed on 2026-09-06.
It does not contain unmerged changes in this branch. After a release passes CI
and is promoted, verify its revision/provenance and update deployment digests
before rollout. Never substitute a build candidate or invent a digest.

Both npm lockfiles have a high-severity audit gate. Pull requests also run GitHub
dependency review. Cargo audit denies warnings, including yanked dependencies;
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
- The npm gates and the nightly fixture/HTTP buffering fixes are included in
  the preceding production-readiness change. The five release benchmarks passed
  locally without increasing budgets; production load validation is separate.
- `GG_ADMIN_API` is not a supported setting here. Kubernetes management isolation
  uses the actual `ADMIN_LISTEN_ADDR` split-listener setting.

Run `python3 scripts/check-supply-chain.py` and `cargo audit --deny warnings`
when updating inputs. Use `docker buildx imagetools inspect IMAGE:TAG` to resolve
the multi-platform manifest digest, then inspect the selected artifact before
changing a production reference.
