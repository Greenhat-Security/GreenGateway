# ADR-0002: Single-Tenant Per Deployment

## Status

Accepted

## Context

The Principal and identity model carries organization and role claims from JWTs or IdP tokens. It would be easy to assume this means GreenGateway supports multi-tenant SaaS-style deployment, with one gateway instance serving multiple isolated customer organizations and providing data and policy isolation between them.

That is a much larger and harder feature than what is currently being built. It would require isolation guarantees, per-tenant rate limits and quotas, tenant-scoped storage, and related design and testing work. Conflating those concerns with the current identity model leads to incorrectly scoped policy and identity work.

## Decision

GreenGateway is **single-tenant per deployment**. One running instance of GreenGateway protects one trust domain: one operator's backend or backends.

Organization and role claims extracted from identity tokens are **rule-matching inputs**. For example, an operator can write a rule that allows one role and denies another. They are not **isolation boundaries**. GreenGateway does not promise to keep two different customer organizations' data or traffic cryptographically or architecturally separated within one instance.

An operator who needs to serve genuinely separate trust domains runs separate GreenGateway deployments.

## Consequences

Policy, identity, and storage design can stay simple. There is no per-tenant partitioning and no cross-tenant isolation guarantee to design or test for.

If true multi-tenant SaaS hosting of GreenGateway becomes a goal later, that is a significant separate effort warranting its own ADR that would supersede or amend this one. It is not assumed as a natural extension of today's organization and role fields.
