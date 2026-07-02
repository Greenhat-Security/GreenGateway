# ADR-0001: HTTP Upstreams Only

## Status

Accepted

## Context

GreenGateway's stated purpose is to sit in front of "any backend" and provide auth, authorization, discovery, and rule-building. That phrase is ambiguous. It could mean fronting raw database wire protocols, such as Postgres or MySQL, or fronting HTTP-based backends, such as REST APIs, PostgREST/Hasura-style HTTP database gateways, and MCP servers.

This needs to be settled explicitly and early, so downstream design conversations about proxy design, rule matching, the tool registry, and related features can share one assumption instead of relitigating scope per feature.

## Decision

GreenGateway fronts **HTTP upstreams only**: REST and HTTP APIs, HTTP-based database gateways such as PostgREST and Hasura, and MCP servers that run over HTTP and JSON-RPC.

GreenGateway does not proxy raw database wire protocols, such as Postgres or MySQL, or arbitrary non-HTTP TCP traffic. If someone wants GreenGateway in front of their database, the expectation is that they front the database through an HTTP-based data API layer rather than connect GreenGateway directly to the database's native protocol.

## Consequences

Future features, including rule matching, the tool registry, schema-conformance checking, and the egress firewall, are designed against HTTP semantics: method, path, headers, and status codes. This simplifies the design space considerably.

A generic TCP or UDP proxy mode is explicitly out of scope. If that is wanted later, it would be a distinct, deliberately scoped feature requiring its own ADR, not an assumed extension of the HTTP proxy.
