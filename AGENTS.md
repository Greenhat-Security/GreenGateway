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

There is nothing to build yet until the Rust workspace lands in issue #3.

Once the workspace exists, the expected standard commands are:

```sh
cargo build
cargo test
cargo fmt --check
cargo clippy -- -D warnings
```

Treat these commands as the project convention now so new code, CI, and contributor workflows converge on the same baseline.

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
