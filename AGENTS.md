# AGENTS.md

## Purpose

This is the orientation doc for anyone, human or AI agent, picking up an issue in this repository.

[`CLAUDE.md`](CLAUDE.md) is its companion, not a competitor: this file stays canonical for conventions, commands, and guardrails, and `CLAUDE.md` adds what this file leaves out — the workspace shape including the `admin-ui` build coupling, the nine ADRs (one still proposed), and the `.env.example` drift test. Keep the two in step; when one changes a fact the other repeats, change both in the same commit.

## Project Summary

GreenGateway is an open-source, self-hosted universal MCP and API gateway written in Rust. It is intended to point at any HTTP backend, enforce authentication and authorization on every call, discover traffic, support a visual rule builder, and provide native MCP support.

## Current Repo State And Structure

GreenGateway is alpha software, and code lands incrementally according to the project roadmap.

The Cargo workspace has three packages: `gateway`, the gateway binary; `ggctl`, the operator CLI binary; and `gateway-config`, the library of configuration contracts the two share (issue #242, ADR-0008). Beside them, `admin-ui/` is the React front end that `gateway` builds and embeds. The gateway's concerns, such as middleware and hardening, authentication, RBAC and policy enforcement, egress firewalling, audit, Connections, tools and MCP, are modules of the one `gateway` crate rather than separate library crates. [docs/architecture.md](docs/architecture.md) describes the request lifecycle and which module owns each concern, and [docs/architecture/application-modules.md](docs/architecture/application-modules.md) maps the application modules `gateway/src/main.rs` declares and where their tests live.

Prefer `git log`, open issues, and open pull requests over this document for structural details. `AGENTS.md` is orientation, not a source of truth, and it may lag reality until it is updated alongside each landing change.

## Build, Test, And Lint Commands

The workspace has three packages, `gateway`, `ggctl` and `gateway-config`, plus the `admin-ui` front end. The commands CI runs, and the ones to run before opening a pull request, are:

```sh
# Select the CI toolchain first. RUSTUP_TOOLCHAIN overrides rust-toolchain.toml,
# which is what the build-tools action does on every CI job.
export RUSTUP_TOOLCHAIN="$(python -c "import json;print(json.load(open('build-tools.json'))['rust_ci'])")"
rustup toolchain install "$RUSTUP_TOOLCHAIN" --component rustfmt --component clippy

cargo fmt --check
cargo clippy --workspace --locked -- -D warnings
RUSTFLAGS="-D warnings" cargo test --workspace --locked
python scripts/transport_guard.py check
python scripts/cargo_policy.py install   # `check` execs the pinned cargo-deny directly
python scripts/cargo_policy.py check
```

Five things about this repository surprise people, human and agent alike, and each costs a red CI run to discover.

**Build-tool versions are pinned exactly, and they are not the ones in `rust-toolchain.toml`.** `build-tools.json` at the repository root is the source of truth, read by `scripts/build_tools.py` and the `.github/actions/build-tools` composite action. It declares `rust_ci` (what CI lints and tests with), `rust_production` (what the shipped binary is built with), `rust_coverage`, `node`, `npm` and `python`. `rust_ci` and `rust-toolchain.toml` currently differ, so a bare `cargo clippy` lints with the wrong compiler: export `RUSTUP_TOOLCHAIN` as above, or you will chase lints CI does not enforce and miss ones it does. Re-read `build-tools.json` after every pull; the pins move.

**`gateway/build.rs` enforces the Node and npm pins exactly and builds `admin-ui` on every compile.** There is no skip flag. A Node that is even a patch version off fails with `build tool differs from repository version contract` before any Rust compiles, so keep the declared version on `PATH`.

**The `gateway` crate has no lib target.** `cargo test -p gateway` works, and so does `cargo test --workspace`, but anything expecting a library target does not. Unit tests live beside their modules with `#[path = "..._tests.rs"] mod`. The application suite, which drives the composed router, is `gateway/src/app_tests.rs` (the binary's `tests` module) and the subsystem `*_app_tests.rs` modules it declares: a new application test belongs in the module of the subsystem whose behaviour it asserts, and `app_tests.rs` keeps only the fixtures more than one of those modules uses. Their tests' paths are `tests::<module>::<name>`, so `cargo test -p gateway <name>` selects a test by name, while `-- --exact` needs the full path that `-- --list` prints.

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
- [docs/architecture.md](docs/architecture.md) for the request lifecycle and module ownership, and [docs/architecture/application-modules.md](docs/architecture/application-modules.md) for the application module map.
