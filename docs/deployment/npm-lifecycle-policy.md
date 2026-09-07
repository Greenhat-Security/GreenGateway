# Dependency lifecycle review

Issue #430 covers dependency installation in both npm projects, Cargo's embedded
UI build, Docker and CI. Node and npm versions come from `build-tools.json`;
the capability fixture must run on that exact npm (currently 11.19.0).

## Reviewed inventory

`npm-script-policy.json` records every lockfile location with `hasInstallScript`,
including optional packages for other platforms. Each entry binds the decision
to its version, resolved tarball URL, SHA-512 integrity and platform conditions.
It also records the published scripts, reviewed source hashes and rationale.
Tarballs were downloaded without installing them, checked against lockfile
integrity and read without extracting or executing their contents.

| Package | Projects | Published lifecycle behavior | Decision |
| --- | --- | --- | --- |
| esbuild 0.28.1 | root, admin-ui | `postinstall: node install.js`; selects a platform binary, may rewrite its launcher, validates the version, and can invoke npm or fetch a fallback binary | Deny; use the locked platform optional dependency |
| workerd 1.20260903.1 | root | `postinstall: node install.js`; selects and validates the native binary, optimizes its launcher, and can fetch a fallback binary | Deny; use the locked platform optional dependency |
| fsevents 2.3.3 | root, admin-ui | Lockfile flags install scripts, but the published archive has no install hook or `binding.gyp`; explicit build/prepublish scripts compile the Darwin addon | Deny conservatively; optional Darwin-only watcher |
| fsevents 2.3.2 | admin-ui, nested under playwright | Same lifecycle distinction as 2.3.3 | Deny conservatively; optional Darwin-only watcher |

Esbuild's native dependencies cover Linux, Windows and other platforms. Workerd
provides Linux, Darwin and Windows binaries. Keep optional dependencies enabled;
an absent platform binary should fail the build instead of starting a second,
unreviewed installation. Linux and Windows are the clean-build qualification
targets. The fsevents inventory is retained even on those platforms, where npm
does not install it.

## Supported npm policy

The project `package.json` field `allowScripts` and `.npmrc` setting
`strict-allow-scripts=true` are the supported mechanism. Use exact resolved URLs
for decisions; do not grant a package-name-wide approval. The separate inventory
binds decisions to integrity as well as URL/version and covers foreign-platform
dependencies that npm's platform-specific preflight may skip.

The executable proof is:

```sh
python -m unittest discover -s scripts -p 'test_npm_script_policy.py' -v
```

It serves harmless temporary tarballs over a loopback-only HTTP server (no public
registry), whose only hook writes a marker in their own
temporary installation directory. It verifies noninteractive rejection before
execution, explicit denial, explicit approval of one resolved identity, rejection
of a changed identity, and intentional `npm run build`. It does not publish or
modify any real dependency. A mismatched Node/npm version fails the fixture.

The [npm ci documentation](https://docs.npmjs.com/cli/v11/commands/npm-ci/)
describes the policy, but executable results on the pinned version are the
compatibility gate. `ignore-scripts` suppresses npm's strict preflight as well as
hooks, so it is not a substitute for detecting newly unreviewed dependencies.
No production dependency currently needs permission to run an install hook.

## Enforced install boundaries

- Root Cloudflare package: dependencies stay denied; explicit test, typecheck,
  Wrangler and deployment commands remain intentional executable code.
- Admin UI: the same committed policy for local installs, CI and Cargo.
- `gateway/build.rs`: verify tool versions and review inputs before npm; policy
  and installer changes must invalidate Cargo's embedded-UI build.
- Docker: copy the policy and installer required by the real Cargo build.
- Tooling: use lockfile-installed executables; `npx --no-install` must fail if a
  command is absent instead of downloading it.

From the repository root, install with:

```sh
node scripts/npm-script-policy.mjs install .
node scripts/npm-script-policy.mjs install admin-ui
```

The dependency-free Node gate checks the review before invoking the pinned npm,
with strict policy enabled, hook bypasses disabled and optional packages included.
Both project manifests also run the inventory check as their own `preinstall`, so
ordinary `npm ci` and dependency updates verify the inventory. npm's strict
preflight rejects unreviewed dependencies before any dependency hooks; the
project preinstall checks denied identities after npm has installed them. There
are no approved dependency hooks. The root package no longer uses
`--ignore-scripts`, because that disables strict preflight; exact explicit denials
preserve its no-dependency-script behavior while detecting new hooks.

CI checks both inventories, independently of the runner's platform. A policy
change invalidates Cargo's UI build. Docker includes the same checker and policy.
Never use an approval-all flag or bypass the checker to get an upgrade through.
Explicit `npm run build`, tests and lockfile-installed tools still run normally.


## Dependency upgrades

1. Use the pinned tools and produce a proposed lockfile without running hooks:
   `npm install --package-lock-only --ignore-scripts <package>@<version>` in the
   appropriate project. This is a review preparation command; do not use that
   override to install `node_modules` or run a build.
2. Run `node scripts/npm-script-policy.mjs check` from the repository root.
   Added or removed flagged locations, versions, resolved URLs, integrity, and
   platform changes fail review, including optional packages for other OSes.
3. For each changed entry, fetch the proposed tarball as data, verify its SRI,
   and inspect its package manifest, lifecycle entrypoints, native build files
   and any code they invoke. Record the exact identity, published scripts,
   reviewed source hashes, platform conditions and reason in the inventory.
   Never execute an unreviewed dependency's hook as part of reviewing it.
4. Update the matching exact URL denial in the project's `allowScripts`.
   No current dependency needs an install hook. An exception would require a
   separate code and policy review, because the gate refuses `allow: true`.
5. Run the installer and required checks. Linux supply-chain CI and Windows
   npm-policy CI run the real npm marker fixtures and inventory mutations.
   Both platforms test and build the UI and test/typecheck the root package;
   Linux additionally builds the Docker image and exercises the live gateway.

The marker fixture also replaces tarball bytes without changing the approved
URL and verifies npm rejects the integrity mismatch before the hook runs.
The review-gate suite covers both projects, foreign-platform optional packages,
alias locations, broad approvals, missing checks, new project hooks and config
bypasses. The Windows job is a required image-promotion dependency.

Dependabot proposals follow this same process. Do not auto-update the review
inventory from a new lockfile or automatically approve a new installer. Normal
package code, explicit build/test scripts and executable binaries still require
ordinary dependency and code review; this gate controls install lifecycle code.
