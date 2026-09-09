# AGENTS.md

## Purpose

This is the orientation doc for anyone, human or AI agent, picking up an issue in this repository.

## Project Summary

GreenGateway is an open-source, self-hosted universal MCP and API gateway written in Rust. It is intended to point at any HTTP backend, enforce authentication and authorization on every call, discover traffic, support a visual rule builder, and provide native MCP support.

## Current Repo State And Intended Structure

GreenGateway is alpha software, and code is landing incrementally according to the project roadmap. This repository may temporarily look sparse while foundational work lands through separate issues and pull requests.

The intended structure will look roughly like a Rust Cargo workspace with a gateway binary crate plus focused library crates for concerns such as middleware and hardening, authentication, RBAC and policy enforcement, egress firewalling, and audit. Issues #3 through #9 are the authoritative source for how that structure actually lands, including the initial workspace scaffold, CI, and subsequent porting work.

Prefer `git log`, open issues, and open pull requests over this document for structural details. `AGENTS.md` is orientation, not a source of truth, and it may lag reality until it is updated alongside each landing change.

## Build, Test, And Lint Commands

The workspace exists: a `gateway` binary crate and the `admin-ui` front end. The commands CI runs, and the ones to run before opening a pull request, are:

```sh
# Select the CI toolchain first. RUSTUP_TOOLCHAIN overrides rust-toolchain.toml,
# which is what the build-tools action does on every CI job.
export RUSTUP_TOOLCHAIN="$(python -c "import json;print(json.load(open('build-tools.json'))['rust_ci'])")"
rustup toolchain install "$RUSTUP_TOOLCHAIN" --component rustfmt --component clippy

cargo fmt --check
cargo clippy --workspace --locked -- -D warnings
cargo test --workspace --locked
python scripts/transport_guard.py check
python scripts/cargo_policy.py install   # `check` execs the pinned cargo-deny directly
python scripts/cargo_policy.py check
```

Four things about this repository surprise people, human and agent alike, and each costs a red CI run to discover.

**Build-tool versions are pinned exactly, and they are not the ones in `rust-toolchain.toml`.** `build-tools.json` at the repository root is the source of truth, read by `scripts/build_tools.py` and the `.github/actions/build-tools` composite action. It declares `rust_ci` (what CI lints and tests with), `rust_production` (what the shipped binary is built with), `rust_coverage`, `node`, `npm` and `python`. `rust_ci` and `rust-toolchain.toml` currently differ, so a bare `cargo clippy` lints with the wrong compiler: export `RUSTUP_TOOLCHAIN` as above, or you will chase lints CI does not enforce and miss ones it does. Re-read `build-tools.json` after every pull; the pins move.

**`gateway/build.rs` enforces the Node and npm pins exactly and builds `admin-ui` on every compile.** There is no skip flag. A Node that is even a patch version off fails with `build tool differs from repository version contract` before any Rust compiles, so keep the declared version on `PATH`.

**The `gateway` crate has no lib target.** `cargo test -p gateway` works, and so does `cargo test --workspace`, but anything expecting a library target does not. Unit tests live beside their modules with `#[path = "..._tests.rs"] mod`.

**Two fail-closed policy gates run in CI and are easy to trip.** `scripts/transport_guard.py` reviews production transport authority: every aliased or glob import, and every unexpanded macro or attribute input, needs an entry in `transport-ownership.json` recording its file, scope, hash, owner and purpose. Adding `use foo::Trait as _;` fails CI until it is registered, which is the point — a new capability should appear in review rather than arrive unnoticed. Do not hand-write the entry: run `python scripts/transport_guard.py inventory`, take the computed record from `target/transport-guard/candidate.json`, add `owner` and `purpose`, and insert it at the position the candidate file shows. `scripts/cargo_policy.py` does the equivalent for the dependency graph.

**Secret scanning reads the whole history.** CI runs `gitleaks detect --source . --no-git=false`, so a credential-shaped string is a finding for as long as it is reachable, and fixing it in the working tree is not enough — the commit has to be rewritten. Keep test fixtures obviously fake and low-entropy: a realistic-looking token next to a name like `api_key` trips the generic rule on shape alone, and the scanner is right to flag it. `.gitleaksignore` is for reviewed historical exceptions pinned to a commit, not a way past a new avoidable finding. Note that a local scan in a shared worktree also sees other branches' commits, which CI would never fetch; before believing a finding, check whether the commit is actually an ancestor of your branch.

## Code Conventions

These are standing rules for future Rust code in this repository:

- Fail closed by default. Security-relevant checks, including authentication, authorization, egress controls, and rate limiting, must deny or reject on ambiguous or error states and must never silently allow.
- Do not put secrets, tokens, or real credentials in code, tests, fixtures, or example configuration. Use placeholder or generated values only.
- Make every security-relevant decision observable. Authentication outcomes, policy allow or deny decisions, and egress blocks should emit structured audit events rather than failing silently or only writing human-readable log lines.
- Prefer plain, boring Rust. Use explicit error handling, avoid `unwrap` and `expect` outside tests and startup-time configuration validation, avoid premature abstraction, and do not add dependencies without a clear reason.
- Configuration is environment-variable driven with startup validation. Do not hardcode values that should be operator-configurable, such as hostnames, cookie names, ports, or allowlists.

## How To Pick Up An Issue

Work is tracked as GitHub issues, one per feature area. Each checklist item within an issue is intended to be sized as one pull request.

Use the pinned roadmap in issue #44 for the full 7-phase plan. Pull request descriptions should include `Part of #N`, where `#N` is the issue being advanced.

## Guardrails For AI Agents

- Never weaken a security default just to make a task easier or a test pass. Do not change fail-closed behavior to fail-open behavior, skip validation, or disable a check; flag that as a blocker instead.
- Do not invent files, APIs, modules, or crate names that are not referenced by the current issue or already present in the repository.
- When a task depends on code that has not landed yet, say so clearly instead of fabricating the missing code.

## Where To Look Next

- [CONTRIBUTING.md](CONTRIBUTING.md) for contribution process and pull request expectations.
- Issue #44 for the pinned roadmap and full project scope.
- [docs/architecture.md](docs/architecture.md) for the request lifecycle once that document lands.
