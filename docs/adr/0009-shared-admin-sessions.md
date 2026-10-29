# ADR-0009: Shared Admin Sessions in Cluster Mode

## Status

Accepted. Implements the shared admin-session backend of issue #424 for `STATE_BACKEND=postgres`. It extends [ADR-0007](0007-shared-state-and-ha-modes.md) and does not change it. The normative state rules are in [the HA state model](../architecture/ha-state-model.md).

## Context

Since #424 the gateway can issue its own admin session after a browser-bound OIDC login. The browser receives an HttpOnly cookie, and no bearer token reaches page script. The one shipped store, `ADMIN_SESSION_MODE=standalone_memory`, is a bounded map in process memory. Cluster mode refused that setting because a replica-local session store would be an undocumented HA fallback. Under a load balancer, logout on one replica would leave the session alive on another, and a login started on one replica could not complete on another. Without a shared store, cluster deployments had only the bearer completion, which hands the access token to the browser. That is the credential exposure #424 exists to remove.

The maintainers chose cloud-native first: cluster mode needs admin sessions, with the same security properties as standalone mode and nothing weaker.

## Decision

### One session contract, two stores

`ADMIN_SESSION_MODE` has three values: `disabled`, `standalone_memory` (only with `STATE_BACKEND=sqlite`) and `cluster_postgres` (only with `STATE_BACKEND=postgres`). Each store is valid in exactly one state backend, and startup refuses every other combination. There is no hybrid and no fallback. A cluster replica never keeps a session in memory.

Both stores implement one contract (`auth::admin_session::AdminSessionStore`). The front end both modes share owns the cookie, the exact-origin check, the CSRF binding, provider revalidation and the identity comparison. The stores own persistence, expiry and capacity.

### The provider stays the authority

As in standalone mode, the access token from the browser-bound OIDC completion stays on the server. The selected login provider's own bearer validator checks it before issuance and again on every request: issuer, audience, claim mapping, expiry, signing keys and, in cluster mode, the shared JWT revocation list. A session ends at the first rejection, or when the token names a different subject or issuer than the session was issued to. No refresh token is requested or kept. Storing only the identity was rejected because it would freeze roles and claims at sign-in and skip the provider's verdict on every later request.

### What the database holds

All rows live on the writable primary, under the ADR-0007 trust boundary.

- **Session IDs are stored only as digests.** The cookie carries 256 random bits. The row key is `SHA-256` over a purpose label, the deployment ID and the cookie value. The cookie value itself is never written anywhere. Neither is the double-submit token or the login's browser binding: each appears only as its own purpose-separated digest.
- **The access token is sealed.** It is encrypted with XChaCha20-Poly1305 under the primary `ADMIN_LOGIN_KEYRING` key, the keyring that already seals pending logins. The deployment ID, the session digest and the session's random ID are bound as associated data, so a ciphertext moved to another row or deployment fails to open. A `decrypt_only` predecessor key still opens sessions sealed before a rotation, so keep it for one `ADMIN_SESSION_TTL_SECS`. A row this replica cannot open is a dependency failure (`503`), never a sign-in prompt.
- **The pending cookie logins are shared too.** Logout can cancel a completion that is still waiting on the IdP, or an issued cookie whose response never reached the browser, even when the logout lands on another replica.

### CSRF binding

When the session is issued, the session records a digest of the double-submit token the completion presented. Every unsafe, cookie-authenticated admin request must carry that same token in the configured CSRF header. A pair that agrees with itself but belongs to another token is refused with `403` and audited as `admin_session_csrf_unbound`. The global double-submit check and the exact-origin check still run first. The completion also sets the CSRF cookie again, with its usual name, domain and attributes and the session's `Max-Age`. The bound token then lives as long as the session cookie, and a browser restart that keeps the session cookie keeps the token as well. The binding applies in both modes.

### Expiry on one clock

Each session has an absolute deadline (`ADMIN_SESSION_TTL_SECS`) and an idle deadline (`ADMIN_SESSION_IDLE_TIMEOUT_SECS`, default: the TTL, which disables it). Each authenticated request moves the idle deadline forward, never past the absolute one. Requests never extend the absolute deadline. In cluster mode both deadlines are judged by the database clock in the statement that admits the request, so replica clock skew cannot keep a session alive.

### Revocation every replica sees

A replica reads the session row on the primary for every request and caches nothing. Logout, replacement by a new sign-in in the same browser, a rejected access token and an identity change each delete the row in one transaction. The next request on any replica is refused. After the provider has answered, the request is admitted only if its row still exists and is still live, so a logout or expiry during validation wins. Requests already admitted and bytes already sent are not recalled.

The one admitted request that keeps sending is the admin audit event stream (`events/stream`). It does not rely on its admission: every 15 seconds it asks the session store and the login provider again, with the same checks as a request but without a CSRF token and without moving the idle deadline, and it ends with a `stream.closed` frame once the session is gone (see the audit routes in [configuration](../configuration.md)).

### Bounded state and cleanup

`ADMIN_SESSION_MAX_ENTRIES` bounds both the live sessions and the pending cookie logins across the deployment. Admissions serialize on one transaction-scoped advisory lock, so two replicas cannot both take the last slot, and capacity answers `503` without evicting anyone. Each admission first prunes a bounded batch of expired rows. The maintenance singleton runs `admin_session_prune`, one bounded step per pass, for deployments whose logins stopped.

### Evidence and audit

Each grant and each withdrawal writes one append-only `admin_session_evidence` row in the same transaction as the change: the session's random ID, the action, a reason (`issued`, `logout`, `replaced`, `rejected` or `expired`), the subject and issuer, the absolute deadline and the database-clock commit time. If the evidence cannot be written, the change rolls back. The rows have no foreign key, hold no credential material and are never deleted by the gateway. An expiry is recorded when the prune removes the row, not at the instant of expiry. Delivering the evidence downstream is still open (#425). The existing `admin_login.transaction` and `auth.*` audit events keep their shape; a CSRF binding refusal is one more `auth.failure` reason.

### Failure semantics

A store that cannot be reached, cannot open a row, or is at capacity answers `503`. A session that is unknown, expired, revoked or rejected answers `401`. Cannot-check is never reported as checked-and-denied, as ADR-0007 requires.

## Consequences

- Cluster deployments get the HttpOnly session the UI already defaults to, and logout in one place ends the session everywhere.
- In cluster mode, sessions survive a replica restart and a rolling restart. In standalone mode a restart still ends them.
- Migration 19 adds the three tables. It is a coordinated drain, migrate and restart, like every schema change so far (`docs/deployment/postgres.md`).
- Each cookie-authenticated admin request costs two primary-key statements on the primary: a lookup before the provider check and a conditional admit after it. They count toward the HA state model's per-request authority budget like any other authority read; no benchmark of this path has been run.
- The CSRF binding is new in standalone mode too. A browser that loses only its CSRF cookie can still read with its session but cannot change anything until it signs in again.
- The session store limits are part of the static-configuration fingerprint while sessions are enabled, so every replica enforces one set.

## Alternatives considered

- **Sticky sessions over the memory store.** Rejected by ADR-0007: logout, expiry and capacity would each multiply by replica count, and a lost replica would silently end sessions.
- **Signed or encrypted stateless cookies.** Rejected: the session could not be revoked before its deadline, and logout would only clear one browser's copy.
- **Redis or another shared cache.** Rejected for the reasons in ADR-0007: it adds a second failure and consistency domain to a security decision.
- **Re-deriving the CSRF token from the session cookie.** Rejected: it would change the CSRF cookie the global double-submit layer and the bearer flows already share. Binding the existing token keeps one CSRF mechanism.
