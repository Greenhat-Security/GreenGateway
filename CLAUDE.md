# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Read AGENTS.md first

[`AGENTS.md`](AGENTS.md) is the orientation doc and the source of truth for conventions, the
CI command set, the fail-closed rules, and the AI-agent guardrails. It also carries the four
repository facts that each cost a red CI run to discover: the exact build-tool pins,
`gateway/build.rs` enforcing the Node/npm contract, the missing lib target, and the two
fail-closed policy gates. This file does not duplicate it — it holds only what AGENTS.md does
not cover.

## What this is

GreenGateway is an open-source (**Apache-2.0**), self-hosted security gateway for APIs, MCP
servers, and AI-agent traffic, written in Rust (axum). It is **pre-GA alpha** — the README's
status badge is the honest label. Enough has landed that the roadmap framing in AGENTS.md
undersells it: `gateway/src/middleware/` already ships `auth.rs`, `bearer.rs`, `rbac.rs`,
`decision.rs`, `observation.rs`, `csrf.rs`, `headers.rs`, `rate_limit.rs` and `validate.rs`,
and `gateway/src/` carries the full `admin_*` control-plane surface. Check the tree before
assuming a capability is still roadmap.

Work is tracked in GitHub issues; the pinned roadmap is **issue #44**. One checklist item per
PR, and the description says `Part of #N`.

## Workspace shape

The Cargo workspace has exactly one member — `gateway` (`Cargo.toml`: `members = ["gateway"]`).
Alongside it, `admin-ui/` is a Node front end that **`gateway/build.rs` builds on every Rust
compile, with no skip flag**, against the Node and npm versions pinned in `build-tools.json`.
A Node even a patch version off fails the build before any Rust compiles. Do not invent crate
or module names ahead of their issues.

Design decisions live in `docs/adr/` — eight ADRs, not two. `0001` (HTTP upstreams only) and
`0002` (single-tenant per deployment) still bound the scope; `0003`–`0008` cover the admin-UI
stack, Policy Studio authority and evidence, the production proxy data plane, first-class
connections and credentials, shared state / HA modes with the PostgreSQL trust boundary, and
shared admin sessions in cluster mode.
Read them before proposing a design; new scope of that shape needs a new ADR.

`docs/architecture.md` is the authoritative request-lifecycle design and has landed, despite
the "once that document lands" wording still in AGENTS.md.

## Config drift is a test failure

`gateway/tests/env_example.rs` scans `gateway/src` for env-var reads and asserts the set
matches `.env.example` **in both directions** — a var read but undocumented fails, and so does
a var documented but no longer read. Adding, renaming or removing an env var means editing
`.env.example` in the same change. A second test forbids hardcoding `AUTH_EXEMPT_PATHS` and
`RBAC_EXEMPT_PATHS` there.
