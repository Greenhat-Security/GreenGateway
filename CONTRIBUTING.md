# Contributing to GreenGateway

GreenGateway is a pre-alpha, open-source, self-hosted universal MCP and API gateway. The project is still early, so contributions may involve documentation, governance, repository scaffolding, and architecture work before the main implementation is fully present.

## Development Setup

GreenGateway is a Rust workspace built with Cargo. As the codebase lands, the standard local workflow is expected to be:

```sh
cargo build
cargo test
cargo fmt
cargo clippy
```

The actual workspace scaffold is landing in a parallel effort under Issue #3. Until that work is merged, contributors should expect this repository to be light on buildable code and heavier on documentation and scaffolding. That is expected for the current phase of the project.

## Picking Up Work

Project work is tracked in GitHub issues. Each feature area has an issue, and each checklist item in that issue is intended to be sized as one pull request.

Start with the pinned roadmap:

https://github.com/Greenhat-Security/GreenGateway/issues/44

When picking up work, choose a checklist item from the relevant issue and keep the pull request focused on that item.

## Pull Request Conventions

Pull requests should be small, focused, and tied to one checklist item. The pull request description should reference the issue it belongs to, for example:

```text
Part of #12
```

Use clear commit messages. Commit subjects should be written in the imperative mood, such as:

```text
Add gateway configuration schema
Document egress policy model
Fix audit event serialization
```

## Commit Style

GreenGateway does not require a fixed commit message format beyond clarity.

Prefer an imperative subject line. Add a commit body when the reason for the change is not obvious from the diff, especially when documenting tradeoffs, compatibility decisions, or security implications.

## Review Expectations

Pull requests are reviewed before merge.

Security-relevant changes receive extra scrutiny because GreenGateway is a security product. This includes changes touching authentication, RBAC, egress controls, audit behavior, secrets handling, policy evaluation, and similar areas.

## Code of Conduct

Contributors are expected to follow the project Code of Conduct:

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## Security Issues

Do not open a public GitHub issue for a suspected security vulnerability.

Follow the project security policy instead:

[SECURITY.md](SECURITY.md)
