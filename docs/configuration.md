# Configuration

GreenGateway reads configuration from environment variables. Each variable is documented below with its own level-3 heading of the exact form `### VAR_NAME`. This document is kept in sync with the code by the drift test in `gateway/tests/env_example.rs`, so drift here is a test failure, not just a documentation staleness risk.

### LISTEN_ADDR

The socket address the gateway binds to when it starts.

Default: `0.0.0.0:8080`

Format and validation: must parse as a Rust `SocketAddr`, such as `127.0.0.1:8080`, `0.0.0.0:8080`, or `[::1]:8080`. Non-Unicode values and invalid socket addresses are rejected during configuration loading.

### ADMIN_LISTEN_ADDR

Optional socket address for serving the gateway admin UI and control-plane API on a separate listener.

Default: empty, which serves the admin surface on `LISTEN_ADDR` with the data-path routes, matching the single-listener default.

Format and validation: unset, empty, or whitespace-only values disable split-listener mode. Non-empty values must parse as a Rust `SocketAddr`, using the same validation as `LISTEN_ADDR`. When set, `ADMIN_LISTEN_ADDR` must differ from `LISTEN_ADDR`.

When set, GreenGateway starts two listeners in the same process. `LISTEN_ADDR` serves `/health`, `/livez`, `/startupz`, `/readyz`, `/version`, `/metrics`, and the reverse proxy fallback when `UPSTREAM_URL` is configured. `ADMIN_LISTEN_ADDR` serves the admin UI at `ADMIN_PREFIX` and admin APIs under `/v1{ADMIN_PREFIX}`. The same security middleware stack applies to both listeners; only the route sets differ.

The deployment probes are exact, gateway-owned `GET`/`HEAD` routes on the data listener. They never fall through to an upstream and their handlers read cached process state only:

- `/livez` returns `200` while the process is running, including while it is draining.
- `/startupz` returns `503` until listener startup completes, then remains `200` for the lifetime of the process.
- `/readyz` returns `200` only while the process accepts work and every upstream pool configured with `required_for_readiness:true` has at least `minimum_healthy` eligible endpoints. It returns `503` while starting, while draining, or when a required pool lacks capacity. Pools not marked as required do not affect readiness.
- `/health` remains a backward-compatible `200` aggregate response. Detailed per-pool and per-endpoint state remains available only from the protected admin status endpoint.

Probe bodies contain only aggregate state and stable reason categories; they do not expose upstream URLs, endpoint topology, credentials, or internal errors. The default authentication, RBAC, and CSRF exemptions include all four probe routes. Setting an exempt-path variable explicitly replaces that default, so operators using explicit lists should retain the probes needed by their orchestrator.

### GRPC_LISTEN_ADDR

Optional socket address for the transparent gRPC (HTTP/2) listener added by issue #257.

Default: empty, which means **no HTTP/2 server is constructed at all**. gRPC proxying is opt-in twice over: this address must be set, and each route that may carry gRPC must declare an `UPSTREAM_ROUTES[].grpc` policy block. A route without one is refused with `UNIMPLEMENTED` rather than proxied with invented limits.

Format and validation: unset, empty, or whitespace-only values disable the listener. A non-empty value must parse as a Rust `SocketAddr`, and must differ from both `LISTEN_ADDR` and `ADMIN_LISTEN_ADDR`. A shared address is rejected at startup rather than resolved: this listener speaks HTTP/2 and nothing else, while `LISTEN_ADDR` and `ADMIN_LISTEN_ADDR` refuse an HTTP/2 connection preface, so one of the two would simply never answer.

**Why a third listener.** `axum::serve`, which serves the data and admin listeners, constructs its HTTP/2 handling internally and exposes no way to configure it, so the resource bounds this transport requires would be unreachable. It also enables RFC 8441 extended `CONNECT` unconditionally, which is an explicit non-goal. And with `ADMIN_LISTEN_ADDR` unset — the default — the admin API shares the data listener's socket, so a mode on that listener would put h2c on the admin surface for every default deployment. The gRPC listener is therefore a separate socket with its own HTTP/2 server, and the other two listeners are unchanged: they still answer an HTTP/2 preface by closing the connection.

**Deployment.** The listener speaks h2c prior knowledge over plaintext. Front it with something that terminates client TLS and re-originates h2c — nginx `grpc_pass`, Envoy, or an equivalent. See [docs/deployment/grpc.md](deployment/grpc.md), which also records the deployments where gRPC cannot work at all.

The gRPC listener runs the identical middleware stack as the data listener: authentication, rate limiting, CSRF, request validation, route classification, RBAC, and direct policy, in the same order. Two things differ, and both are narrowings. Request validation is given the gRPC media types (`application/grpc`, `application/grpc+proto`, `application/grpc+json`) as its allow-list instead of `VALIDATION_ALLOWED_CONTENT_TYPES`. And the router carries no admin routes and no probe routes — its only route is the gRPC proxy.

Because CSRF protection applies to the whole router, a gRPC call must carry a bearer credential in `authorization` metadata, be on a `CSRF_EXEMPT_PATHS` entry, or run with `CSRF_ENABLED=false`. This is the same rule non-browser HTTP clients already follow on the data listener.

### GRPC_MAX_CONCURRENT_STREAMS

Maximum concurrent HTTP/2 streams the gRPC listener will carry on one connection.

Default: `100`. Range: 1 to 10000.

This is the single most load-bearing inbound bound the gateway has, because it multiplies: one accepted TCP connection becomes up to this many concurrent in-flight calls, so the real inbound ceiling is this value times the connection cap. It is deliberately half of hyper's own default of 200.

Per-route and per-endpoint call ceilings are configured separately in `UPSTREAM_ROUTES[].grpc`, and admission runs before any DNS resolution or connection acquisition.

### GRPC_MAX_METADATA_BYTES

Maximum decoded size, in bytes, of one gRPC request's metadata (its HTTP/2 header list).

Default: `16384`, which matches hyper's own default. Range: 1024 to 1048576.

Raise it for callers that carry large bearer tokens or tracing metadata. The number of metadata entries is bounded separately by `UPSTREAM_ROUTES[].grpc.max_metadata_entries`, because a byte budget does not constrain a count.

### TLS_CERT_FILE

Optional path to the PEM certificate chain that terminates TLS on `LISTEN_ADDR`, leaf certificate first. More than one path may be given as a comma-separated list, positionally paired with `TLS_KEY_FILE`, which turns on SNI selection on that listener.

Default: empty, which serves the data listener as plaintext HTTP/1.1 exactly as it is served today.

Format and validation: unset, empty, or whitespace-only values leave the listener plaintext. A non-empty value is a comma-separated list of one or more paths with no empty entry -- an empty entry would silently shift every later certificate/key pairing by one, so it fails startup instead of being skipped. The two lists must name exactly one key per certificate chain; a count mismatch fails startup. Each entry must name a readable regular file containing at least one PEM `CERTIFICATE` section, and the pair of settings must be set together; setting one without the other fails startup rather than quietly serving plaintext on a listener an operator believes is protected. Every entry is read once at startup with a 1 MiB bound. A certificate file that also contains a `PRIVATE KEY` section is rejected, because a key concatenated into the certificate file inherits the certificate's permissions and a certificate is the one half of the pair operators reasonably mount world-readable. Paths containing commas cannot be expressed; nothing else about a single-path value changes, and a deployment that sets exactly one path gets byte-for-byte the behaviour it had before lists existed.

Each file's directory is opened as a capability root and the leaf is read through the same bounded reader that resolves connection secrets, so symlink resolution is confined beneath that directory and a link pointing outside it fails closed. A Kubernetes Secret volume is supported as published: the kubelet's atomic writer exposes each leaf as a relative symlink into a `..data` directory, and that shape loads.

**Certificate files are watched after startup.** When the files named by `TLS_CERT_FILE`/`TLS_KEY_FILE` change -- rewritten in place, atomically replaced by a rename, or rotated by the kubelet flipping the `..data` symlink they resolve through -- the listener reloads them for new connections without a restart, and established connections are untouched: a reload swaps only what future TLS handshakes are served, so an in-flight request or a long-lived keep-alive connection keeps serving on the connection it already has. Validation on reload is exactly validation at startup -- parse, size, permissions, the key-matches-leaf pairing, and the SNI name rules over the whole set -- through the same code path, so nothing can be served after a reload that startup would have refused. When the new material fails any of those checks the listener keeps serving the last good chains, which is the fail-closed direction: a broken rotation degrades to "the certificate is not yet renewed", never to "the listener is down" or "the gateway serves nothing". Every outcome is observable: `inbound_tls.reloaded` and `inbound_tls.reload_failed` audit events and the `inbound_tls_reloads_total{listener,outcome}` counter, where `outcome="rejected"` on a listener whose certificate expires soon is the alert to raise. There is no retry schedule -- one change is one reload attempt -- and `SIGHUP` triggers a reload attempt on Unix. The file watcher also emits a liveness heartbeat: `inbound_tls_watch_heartbeats_total{listener}` advances every few seconds while the watching task is running, so a watcher that has died -- after which certificate reloads silently stop -- is distinguishable from simply unchanging certificate files; a flat heartbeat alongside an approaching expiry is the second alert to raise (the first being `outcome="rejected"`). The watcher's name set is fixed when it starts: it watches the paths as they were first seen, plus the first component of a symlinked leaf's relative target so the kubelet's `..data` flip is detected, so a volume that changes its *shape* mid-flight -- plain files becoming projected symlinks, or an absolute symlink target -- needs a restart to be watched. Reloads never touch anything except the server certificate chains: the client-certificate CA bundle and CRL are read once at startup regardless, session resumption settings are startup decisions, and ALPN stays `http/1.1`.

**SNI selection with more than one chain.** The DNS subject alternative names on each chain's leaf are the server names that chain answers to, read by the same certificate parser that verifies chains, lower-cased for ASCII, and the subject CN is deliberately not consulted: it is deprecated for name matching and can disagree with the SANs. A caller naming a server an exact name claims gets that chain; otherwise a wildcard claim (`*.example.com`) matches exactly one further label, so it serves `a.example.com` and neither `a.b.example.com` nor `example.com`; an exact claim beats a wildcard that would also cover the name; and everything else -- a client that sends no server name, a name nothing claims -- is served by the *first* chain in the list, which is therefore the listener's default. A caller whose name selects no chain it trusts simply fails its own certificate verification against the served default; the gateway does not refuse the handshake for an unrecognised name. Two chains claiming the same name, or the same wildcard, is a configuration whose selection could never be honest, so it fails startup naming the duplicated name -- as does a later chain that presents no DNS SANs at all, because no server name could ever select it (only the first chain may be nameless). IP SANs and URI SANs do not participate, because SNI carries DNS names only; a name that is neither a valid DNS name nor a valid wildcard name -- `a.*.b`, `*foo.b` -- is unclaimable and a chain carrying only such names is nameless in the same way. The whole set reloads as a unit: a rewrite of the files replaces the entire list, and the SNI rules are re-checked over the new set before it is served.

Certificate or key material that is missing, unreadable, malformed, mismatched, or unsafely permissioned prevents startup. There is no fallback to plaintext.

### TLS_KEY_FILE

Optional path to the PEM private key matching `TLS_CERT_FILE`. PKCS#8 (`PRIVATE KEY`), PKCS#1 (`RSA PRIVATE KEY`), and SEC1 (`EC PRIVATE KEY`) encodings are all accepted. Like `TLS_CERT_FILE` it accepts a comma-separated list, whose entries pair positionally with the certificate list and must equal it in length.

Default: empty, which serves the data listener as plaintext HTTP/1.1.

Format and validation: as for `TLS_CERT_FILE`, with a 256 KiB read bound per entry, and each key must match the public key of the leaf certificate it is paired with. A mismatch fails startup.

The certificate is held to a looser permission rule than the key, deliberately: it is public material, served to every client that connects, so group and other *read* on it is normal and permitted. Group or other *write* on either file still fails startup, because material an attacker can rewrite is material an attacker chooses.

Permissions: **the key file must grant no group or other permission at all -- not write, and not read.** Its directory must not be group- or world-writable unless it carries the sticky bit, which is the same rule the gateway applies to platform-projected connection secrets: `drwxrwxrwt` is what a container runtime publishes a projected volume as, and the sticky bit is what makes it safe, because a process that does not own an entry cannot swap it.

**Kubernetes deployment requirement.** A Secret volume publishes its files as mode `0644` by default, which is world-readable, so a default TLS Secret mount is refused and the gateway will not start. Set `defaultMode: 0400` on the volume (or `chmod 0400` for a bind mount). This fails closed on purpose. Reading a server private key is the entire compromise -- every session it ever protected, retroactively -- so *read* is as disqualifying as *write* here, and it is the rule every other private key in this gateway is already held to.

The leaf may still be a symlink, which is what makes the requirement satisfiable in the shape Kubernetes actually publishes: the kubelet's atomic writer exposes `tls.key` as a relative link into its `..data` directory, and that shape loads as long as the file it resolves to is `0400`. The two rules are independent -- whether a symlinked leaf is permitted, and who may read the file -- and only the certificate relaxes the second.

Key bytes are read into zeroizing buffers, are never written to logs, audit events, metrics, error responses, or `Debug` output, and no startup error names the path the key was read from -- only the setting to fix.

### ADMIN_TLS_CERT_FILE

Optional path to the PEM certificate chain that terminates TLS on `ADMIN_LISTEN_ADDR`. Like `TLS_CERT_FILE` it accepts a comma-separated list, with the same SNI selection and the first chain as the default, independently of the data listener's chains.

Default: empty, which serves the admin listener as plaintext HTTP/1.1.

Format and validation: validated exactly as `TLS_CERT_FILE`, and must be set together with `ADMIN_TLS_KEY_FILE`. Both require `ADMIN_LISTEN_ADDR`: without a separate admin listener there is nothing for them to terminate, and accepting them anyway would leave the admin surface on the data listener's scheme while its own settings claimed otherwise.

The two listeners are configured independently on purpose. They are frequently reached over different networks, and terminating TLS on one says nothing about the other. They are reloaded independently too, on the same watcher machinery: a change to one listener's material files swaps that listener's chains and leaves the other listener on its current ones, in both directions, with a separate `inbound_tls_reloads_total{listener,...}` series and separate audit events for each.

### ADMIN_TLS_KEY_FILE

Optional path to the PEM private key matching `ADMIN_TLS_CERT_FILE`. Like `TLS_KEY_FILE` it accepts a comma-separated list, positionally paired with `ADMIN_TLS_CERT_FILE`.

Default: empty, which serves the admin listener as plaintext HTTP/1.1.

Format and validation: validated exactly as `TLS_KEY_FILE`, including the permission rules and the read bound.

### TLS_MIN_VERSION

The minimum TLS protocol version any inbound listener will negotiate.

Default: `1.2`

Format and validation: must be exactly `1.2` or `1.3`. Anything else fails startup. The floor is stated explicitly rather than inherited from whatever the TLS library defaults to, so that the version an operator is running on is an auditable configured value that cannot move on a dependency bump.

`1.3` is the stronger choice and is recommended wherever every client can reach it; it refuses TLS 1.2 clients outright. `1.2` is the default because raising a floor has a compatibility cost, and a default that silently refuses a working client on upgrade is a change that should be made deliberately.

This setting applies to both listeners. Inbound listeners advertise only `http/1.1` over ALPN; a client offering only `h2` is refused during the handshake rather than handed a connection nothing will parse.

### TLS_HANDSHAKE_TIMEOUT_MS

Deadline for a single inbound TLS handshake, in milliseconds.

Default: `10000`

Format and validation: must parse as an unsigned integer greater than 0. Zero is rejected at startup, because a zero deadline fails every handshake.

A client that connects and never sends a ClientHello is dropped when this expires, and the admission slot it held is released immediately. Handshakes do not run on the listener's accept path, so a slow client cannot stall other connections; this deadline bounds how long one can hold a slot against the `TLS_MAX_CONCURRENT_HANDSHAKES` budget, and therefore how long a saturated listener keeps refusing.

Lowering it makes a flood of silent connections cheaper to shrug off; raising it accommodates clients on slow or lossy links. It does not bound how long a *legitimate* client waits: a connection that cannot be admitted is refused at once rather than held for this long.

### TLS_MAX_CONCURRENT_HANDSHAKES

The maximum number of inbound TLS handshakes running at once, per listener.

Default: `256`

Format and validation: must parse as an unsigned integer greater than 0. Zero is rejected at startup, because it would admit no connections at all.

Handshakes are the expensive, attacker-triggerable half of accepting a TLS connection, so this is the bound that stops a flood of half-open connections from becoming unbounded work inside the process.

When the bound is reached the listener keeps accepting and **sheds**: a connection that finds no free slot is closed immediately, so the client learns at once and can retry or fail over, and the kernel's accept queue keeps draining. Saturation therefore degrades to "some connections are refused promptly", never to "the listener stopped accepting". Slots are released on every outcome, including a failed or timed-out handshake, so service resumes about one `TLS_HANDSHAKE_TIMEOUT_MS` after a flood stops.

The budget is per listener, not per process. The data and admin listeners run separate accept loops with separate budgets, so a flood on the data listener cannot spend the budget that reaches the admin surface -- which matters, because the admin listener is how an operator reaches a deployment that is already under load.

The default is set well above any plausible legitimate burst, so reaching it is a signal rather than a routine event. `inbound_tls_handshakes_in_flight` reports the slots in use and `inbound_tls_handshakes_total{listener,outcome}` counts every outcome, including `outcome="shed"`; a non-zero shed rate means real clients are being refused and is worth alerting on.

### CLIENT_CERT_MODE

Whether the data listener asks callers for a client certificate, and what it does with a caller who has none.

Default: `off`

Format and validation: must be exactly `off`, `optional`, or `required`.

- `off` requests nothing. A listener with this setting behaves exactly as one without it.
- `optional` requests a certificate and serves callers who decline. A caller who declines has **no certificate identity at all** and must authenticate by some other method or be refused; there is no partially-trusted state.
- `required` refuses the handshake when no certificate is offered.

A certificate that *is* offered is verified identically under `optional` and `required`. `optional` softens only the anonymous case; it never means a certificate is trusted less. So presenting nothing is never worth more than presenting something invalid: an invalid certificate fails the handshake, and no certificate produces no identity.

`optional` exists for migrations — a listener already serving bearer-token callers can begin accepting certificate identities before every caller has been issued one.

Setting this to anything but `off` requires `TLS_CERT_FILE` (a listener that terminates no TLS never sees a certificate), `CLIENT_CERT_CA_FILE`, and `CLIENT_CERT_IDENTITY_SOURCE`. Any of them missing fails startup rather than leaving a listener that an operator believes requires certificates accepting anonymous connections.

**A listener that asks for client certificates does not resume TLS sessions.** Every connection to it completes a full handshake. This is a deliberate cost, and it is charged only where certificates are requested: with `CLIENT_CERT_MODE=off` resumption behaves exactly as it always has. The reason is that a resumed handshake — TLS 1.2's abbreviated form or TLS 1.3's PSK — carries no `Certificate` and no `CertificateVerify` message. rustls restores the *previous* connection's certificate chain and re-checks nothing about it: not the validity window, not the CRL, not the trust path. With resumption enabled, an expired or revoked client certificate would go on authenticating for up to 24 hours after it stopped being valid, and everything `CLIENT_CERT_CRL_FILE` says below would stop applying to the callers it exists to stop. The deeper problem is that a resumed connection proves the caller holds the *resumption secret*, not the certificate's private key, which is the proposition mutual TLS is bought for. Re-validating the restored chain would not recover it, because there is nothing on a resumed connection for the caller to have signed. 0-RTT early data is likewise never enabled on any inbound listener.

**A credential the caller sends outranks the certificate their connection was established with.** On an `optional` or `required` listener, a request carrying an `Authorization: Bearer` header or a session cookie is judged on that credential; the connection's certificate is what authenticates a caller who sends nothing else. So a caller presenting a valid certificate *and* an expired, revoked, or unknown token is answered `401` — the token is not silently ignored in favour of the certificate. A caller presenting a valid certificate and a valid token authenticates as the token's subject, not the certificate's. The order is deliberate: a caller who sends a token is asking to be judged as that token's subject, and preferring the certificate would mean a bad token quietly succeeded as somebody else.

### CLIENT_CERT_CA_FILE

PEM bundle of the certificate authorities permitted to issue client certificates for the data listener.

Default: empty. Required when `CLIENT_CERT_MODE` is not `off`, and rejected when it is.

Format and validation: read through the same bounded, capability-confined reader as `TLS_CERT_FILE`, with the same 1 MiB bound and the same directory rules. Every certificate in the file must be usable as a trust anchor; one that is not fails startup rather than being skipped, because silently trusting the remainder would mean the set of callers who can authenticate is not the set the operator wrote down. A file that also contains a `PRIVATE KEY` section is refused.

Permissions: the bundle is public material, so group and other *read* is permitted. Group or other *write* fails startup — a trust bundle an attacker can rewrite is a trust bundle an attacker chooses.

**The platform trust store is never consulted for client authentication, and there is no setting that opts into it.** Trusting the operating system's roots here would mean every certificate every public CA has ever issued authenticates to this gateway, which is essentially never what configuring mutual TLS means. This is the one place where the gateway's outbound behaviour and its inbound behaviour deliberately differ: an outbound connection is verifying a *server* that a public CA plausibly vouches for, and an inbound client certificate is a credential the operator issues.

### CLIENT_CERT_CRL_FILE

Optional PEM certificate revocation list, or concatenation of lists, for data-listener client certificates.

Default: empty.

**Revocation is not checked unless this is set.** rustls consults neither CRLs nor OCSP by default, and this gateway adds no other revocation source: with this setting empty, a revoked certificate authenticates until it expires. That is stated here rather than left implied, because an operator who believes revocation works when it does not is in a worse position than one who knows it does not.

When it is set, revocation is enforced strictly:

- **The whole verified chain** is checked, not just the end-entity certificate. A deployment with intermediate CAs needs CRLs covering them too. The trust anchor itself is excluded.
- **An undeterminable status is a failure.** A certificate whose revocation status no configured CRL covers is refused.
- **An expired CRL is treated as no CRL, not as a still-valid one.** A CRL whose `nextUpdate` has passed refuses every certificate in its scope.

The last point is the sharp one and it is deliberate. The alternative — honouring a stale CRL — means a deployment whose CRL publishing quietly broke keeps accepting certificates revoked since the last list it managed to fetch, with nothing to show for it. Refresh the CRL on a schedule shorter than its validity window. `inbound_client_certificates_total{outcome="rejected_expired_revocation_list"}` is the counter to alert on; `outcome="rejected_revoked"` is the evidence that revocation is being consulted at all.

Server certificate chains reload when their files change (see `TLS_CERT_FILE`), but this file and the CA bundle do not: both are read once at startup, so refreshing a CRL or rotating a client-certificate CA means restarting the process. That remains deliberately deferred under issue #324, and it is the sharp edge of a stale-CRL deployment -- the CRL refuses every caller when it expires, and only a restart can install a fresh one.

### CLIENT_CERT_IDENTITY_SOURCE

Which field of a verified client certificate carries the caller's identity. Applies to both listeners.

Default: empty. Required when either listener requests client certificates, and rejected when neither does.

Format and validation: must be exactly `spiffe`, `uri`, or `dns`.

| value | reads | notes |
| --- | --- | --- |
| `spiffe` | the URI SAN whose scheme is `spiffe` | Recommended. Exactly one per SVID by specification, canonical by specification, and stable across the certificate rotation SPIFFE expects. |
| `uri` | the URI SAN, verbatim | For a private PKI that names workloads with URIs that are not SPIFFE IDs. |
| `dns` | the DNS SAN, lower-cased | Weakest. DNS SANs were designed to name the server being connected *to*, so certificates commonly carry several — and a certificate with several different ones has no identity. Wildcards are never an identity. |

**The rule is exactly one.** A certificate carrying no value of the configured kind has no identity. A certificate carrying two *different* values has no identity either. The gateway never takes the first of several: whoever assembles a certificate chooses the order of its SANs, so if order decided the principal, a caller who can persuade a CA to add one more SAN would choose which principal they authenticate as. Two SANs spelling the same canonical value are one identity, not two.

A certificate that verifies but yields no identity does not authenticate. The connection is established — the certificate was valid — and the request is answered `401` with no principal, which is the same position a caller with no certificate is in.

The identity must already be in canonical form; the gateway rejects rather than repairs. A SPIFFE ID must have a lower-case `spiffe` scheme and trust domain, no userinfo, port, query, or fragment, and no empty or dot path segments. Normalising any of these would be deciding that two different strings are the same principal. It must also be non-empty printable ASCII with no spaces and at most 255 bytes, because it becomes a `principal_id` in policy, a `user_id` in audit, and text in a log line.

**Why the subject DN is not an option.** A DN is not a string but a sequence of relative distinguished names, each holding possibly several attributes in possibly several string encodings. Rendering one as text means choosing an escaping and an ordering that libraries disagree about, and the escaping is where the bugs are: a CA that lets a requester choose their own `CN` lets them choose one containing `,OU=`, and produce a rendered DN that collides with somebody else's identity. There is no canonical DN renderer in this dependency graph, and writing one to decide who an authenticated caller is would be the wrong place to hand-roll ASN.1. Email SANs are excluded for a duller reason: `rfc822Name` identifies a mailbox rather than a workload, and mailboxes get reassigned.

### ADMIN_CLIENT_CERT_MODE

Whether the admin listener asks callers for a client certificate.

Default: `off`

Format and validation: as `CLIENT_CERT_MODE`, and requires `ADMIN_TLS_CERT_FILE` rather than `TLS_CERT_FILE`. Configured independently of the data listener: the two are frequently reached over different networks, and requiring certificates on one says nothing about the other. `CLIENT_CERT_IDENTITY_SOURCE` is shared, because it describes how an organisation issues certificates rather than which listener receives them.

### ADMIN_CLIENT_CERT_CA_FILE

PEM bundle of the certificate authorities permitted to issue client certificates for the admin listener.

Default: empty. Required when `ADMIN_CLIENT_CERT_MODE` is not `off`, and rejected when it is.

Format and validation: as `CLIENT_CERT_CA_FILE`, including the permission rules and the refusal to fall back to the platform trust store.

### ADMIN_CLIENT_CERT_CRL_FILE

Optional PEM certificate revocation list for admin-listener client certificates.

Default: empty, which means **no revocation checking on that listener**.

Format and validation: as `CLIENT_CERT_CRL_FILE`, including the strict enforcement and the expired-CRL behaviour.

### ADMIN_PREFIX

Path prefix for the gateway's admin UI and control-plane API surface.

Default: `/admin`

Format and validation: must be a non-root URI path prefix that starts with `/`, has no trailing slash, and contains only non-empty path segments made of ASCII letters, digits, `.`, `-`, `_`, or `~`. Invalid prefixes are rejected during configuration loading.

With the default, the admin UI remains at `/admin` and the existing admin APIs remain under `/v1/admin`, including `/v1/admin/audit`, `/v1/admin/events/stream`, `/v1/admin/status`, `/v1/admin/policy`, `/v1/admin/policy/history`, `/v1/admin/policy/rollback/{version}`, `/v1/admin/policy/validate`, the policy rule-management routes under `/v1/admin/policy/rules`, the token-management routes under `/v1/admin/tokens`, the schema routes `/v1/admin/schema/coverage` and `/v1/admin/schema/inferred`, `/v1/admin/signals`, the signal transition routes under `/v1/admin/signals/{id}`, the traffic inventory routes `/v1/admin/traffic/endpoints`, `/v1/admin/traffic/endpoint`, and `/v1/admin/traffic/endpoints/review`, and the principal directory routes `/v1/admin/principals` and `/v1/admin/principal`. When `ADMIN_PREFIX` is changed, the admin UI moves to the new prefix and the admin APIs move to the corresponding `/v1{ADMIN_PREFIX}` prefix: for example, `ADMIN_PREFIX=/ops` serves the UI at `/ops` and admin APIs at `/v1/ops/audit`, `/v1/ops/events/stream`, `/v1/ops/status`, `/v1/ops/policy`, `/v1/ops/policy/history`, `/v1/ops/policy/rollback/{version}`, `/v1/ops/policy/validate`, `/v1/ops/policy/rules`, `/v1/ops/tokens`, `/v1/ops/schema/coverage`, `/v1/ops/schema/inferred`, `/v1/ops/signals`, `/v1/ops/signals/{id}/acknowledge`, `/v1/ops/signals/{id}/dismiss`, `/v1/ops/traffic/endpoints`, `/v1/ops/traffic/endpoint`, `/v1/ops/traffic/endpoints/review`, `/v1/ops/principals`, and `/v1/ops/principal`. The default `/admin` path and default `/v1/admin/*` API paths are no longer intercepted in that mode, so they can fall through to the reverse proxy when `UPSTREAM_URL` is configured.

The Connection and capability surfaces follow the same dynamic prefix: the Connection collection/detail routes, `/{id}/test`, `/{id}/refresh`, `/{id}/openapi/preview`, and `/{id}/openapi/register`; the `/v1{ADMIN_PREFIX}/connection-secrets` collection and item routes; and the capability inventory, detail, and constrained playground routes at `/v1{ADMIN_PREFIX}/tools`, `/tools/{id}`, and `/tools/{id}/execute`.

When `ADMIN_LOGIN_PROVIDER` is set, the admin OIDC login routes are also registered under the effective API prefix: `/v1{ADMIN_PREFIX}/auth/login` starts the browser redirect to the identity provider, and `/v1{ADMIN_PREFIX}/auth/callback` receives the authorization-code callback.

The default `AUTH_EXEMPT_PATHS` and `RBAC_EXEMPT_PATHS` include the effective `ADMIN_PREFIX` so the static admin UI shell can load before an operator pastes a token. When `ADMIN_LOGIN_PROVIDER` is set, they also include `/v1{ADMIN_PREFIX}/auth/login` and `/v1{ADMIN_PREFIX}/auth/callback` so an unauthenticated browser can complete the login flow. Other admin APIs remain protected by authentication and endpoint-specific authorization checks.

Leave `AUTH_EXEMPT_PATHS` and `RBAC_EXEMPT_PATHS` unset to keep these defaults synchronized with `ADMIN_PREFIX`. Setting either variable replaces its entire dynamic default with one exception: while `ADMIN_LOGIN_PROVIDER` is set, `/v1{ADMIN_PREFIX}/auth/login` and `/v1{ADMIN_PREFIX}/auth/callback` remain exempt even when either variable is set explicitly, because an unauthenticated browser has to reach both routes for the OIDC authorization-code flow to complete. There is no configuration that removes them while admin SSO login is enabled; unset `ADMIN_LOGIN_PROVIDER` to drop them. When changing `ADMIN_PREFIX`, update every explicit exempt list at the same time so a stale former admin prefix is not forwarded upstream without the corresponding security check. Neither list applies on the gRPC listener (`GRPC_LISTEN_ADDR`); see [docs/deployment/grpc.md](deployment/grpc.md#3-authentication) for why.

### ADMIN_LOGIN_PROVIDER

Optional name of the `AUTH_PROVIDERS` entry used for admin UI OIDC login.

Default: empty, which disables the SSO login button and leaves the existing manual bearer-token paste flow unchanged.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must exactly match an `AUTH_PROVIDERS[].name` entry whose `type` is `jwt`. The selected provider must set `issuer`, `client_id`, `client_secret`, and `redirect_uri`; startup fails closed with the normal aggregated configuration error if any of those are missing or if the named provider does not exist. `ADMIN_LOGIN_PROVIDER` does not use `cookie_session` providers.

At startup, GreenGateway fetches the selected provider's OIDC discovery document from `{issuer}/.well-known/openid-configuration`. In addition to the `jwks_uri` used by bearer-token validation, the discovery document must include `authorization_endpoint` and `token_endpoint`. Missing discovery fields or discovery failures prevent startup rather than silently disabling SSO.

The admin UI login flow uses OAuth2 authorization-code with PKCE. `GET /v1{ADMIN_PREFIX}/auth/login` creates a short-lived pending login, generates a PKCE S256 challenge and an independent 256-bit browser secret, and sets the secret in a host-only `HttpOnly; SameSite=Lax` cookie. The OAuth `state` is a purpose-separated SHA-256 digest of that secret; the secret itself never travels to the provider. The cookie name is derived from `ADMIN_PREFIX`, its path is `/`, and its maximum age is `ADMIN_LOGIN_PENDING_TTL_SECS`. With an HTTPS `redirect_uri`, the cookie is `Secure` and uses the `__Host-` prefix to prevent sibling-subdomain cookie injection. Use HTTPS for production; HTTP redirect URIs are supported for local development. Starting another login in the same browser for the same admin prefix replaces the cookie, so complete the most recently started login.

`GET /v1{ADMIN_PREFIX}/auth/callback` checks the returned state against that browser cookie and redirects to `{ADMIN_PREFIX}/#/auth/complete?code=...&state=...`. This fragment contains the PKCE-protected authorization code, never an access token. The UI immediately clears the fragment and makes a same-origin JSON `POST /v1{ADMIN_PREFIX}/auth/callback` with `{ "code": "...", "state": "..." }`, the browser cookie, and the configured CSRF header. The POST requires an `Origin` matching the configured redirect URI's origin and rejects missing, mismatched, or duplicate binding cookies before consuming any state. Only this POST atomically consumes the pending login, exchanges the code through the shared egress client, and validates the ID token's signature, issuer, audience and nonce. It returns `{ "access_token": "..." }` once, clears the binding cookie, and the UI stores the token using the same `sessionStorage` helper as the manual paste flow. Login route responses use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Authentication and RBAC exemptions for the callback remain necessary; the completion POST retains CSRF protection.

In standalone mode the pending-login state is process-local and bounded in memory; multiple standalone instances need sticky routing for login start and the completion POST. In cluster mode (`STATE_BACKEND=postgres`) it lives in the database, sealed under `ADMIN_LOGIN_KEYRING`, and completion can run on any replica. Exactly one concurrent POST can consume a transaction. Missing or expired state fails closed, and unavailable storage returns `503` without exchanging a code. Both modes reject new logins at the global or per-client capacity limit without evicting valid entries and remove expired entries before evaluating capacity. In cluster mode the three limits govern one shared store and are part of the static-configuration fingerprint.

Upgrade all replicas and reload open admin pages before starting a new login. In-flight logins from the previous protocol must be restarted; the updated UI rejects legacy `token` completion fragments. No database migration or new environment setting is required.

### ADMIN_LOGIN_KEYRING

Cluster mode's keyring for sealing pending admin logins in the database.

Default: empty

Format and validation: the same JSON array of `{ "id", "file", "role" }` objects as `CONNECTION_LOCAL_SECRET_KEYRING`, with key files beneath `CONNECTION_SECRETS_ROOT` and exactly one `primary`. Required when `STATE_BACKEND=postgres` and `ADMIN_LOGIN_PROVIDER` is set; rejected when `STATE_BACKEND=sqlite`, where nothing reads it. The PKCE verifier and nonce of every pending login are AEAD-encrypted under the primary key with the deployment ID, the row, and the field bound as associated data; the login `state` is stored only as a digest. To rotate, add the new key as `primary`, demote the old one to `decrypt_only`, and keep it in the ring for at least one `ADMIN_LOGIN_PENDING_TTL_SECS` so logins sealed before the rotation can still complete. Key IDs and roles are part of the static-configuration fingerprint replicas must agree on.

### ADMIN_LOGIN_PENDING_TTL_SECS

Maximum lifetime, in seconds, of an unconsumed admin OIDC login state.

Default: `300`

Format and validation: must be an integer greater than `0`. The value is parsed and validated even when `ADMIN_LOGIN_PROVIDER` is unset. Expired entries cannot complete a login and are removed when the pending-state store is accessed.

### ADMIN_LOGIN_PENDING_MAX_ENTRIES

Maximum number of pending admin OIDC login states retained by one GreenGateway process (standalone mode) or by the deployment as a whole (cluster mode, where the limit is enforced in the database).

Default: `1024`

Format and validation: must be an integer greater than `0`. The value is parsed and validated even when `ADMIN_LOGIN_PROVIDER` is unset. Once the store reaches this limit, new login attempts fail closed until an existing state is consumed or expires; existing valid states are never evicted to admit a newer request.

### ADMIN_LOGIN_PENDING_MAX_PER_IP

Maximum number of pending admin OIDC login states retained for one canonical client IP.

Default: `16`

Format and validation: must be an integer greater than `0`. The value is parsed and validated even when `ADMIN_LOGIN_PROVIDER` is unset. The client key uses the same trusted-proxy-aware canonical IP policy as the rest of GreenGateway: forwarding headers are honored only when `TRUST_PROXY_HEADERS=true` and the connection peer is within `TRUSTED_PROXY_CIDRS`; otherwise the connection peer address is used. This bound limits abuse from one source, while the process-wide limit remains the backstop for distributed traffic.

### GATEWAY_PUBLIC_URL

Optional public base URL clients use to reach this gateway.

Default: empty, which disables the OAuth protected-resource metadata document. In this mode `GET /.well-known/oauth-protected-resource` and RFC 9728 path-derived children under it return a clear not-configured error, MCP 401 responses keep the same plain bearer challenge as other endpoints, and JWT validation behavior is unchanged.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be a valid `https` URL with a host and no fragment. Plain `http` is accepted only for loopback local-development hosts such as `localhost`, `127.0.0.1`, and `::1`. The configured URL may include a path prefix; GreenGateway appends `/mcp` to compute the MCP protected resource identifier. The metadata document URL advertised to MCP clients follows RFC 9728 by inserting `/.well-known/oauth-protected-resource` between the MCP resource identifier's origin and its path and/or query components. For example, `https://gateway.example.test/base` advertises `https://gateway.example.test/.well-known/oauth-protected-resource/base/mcp`; `https://gateway.example.test` advertises `https://gateway.example.test/.well-known/oauth-protected-resource/mcp`.

When the configured URL includes a path prefix, GreenGateway mounts the derived MCP resource path alongside bare `/mcp`. With `GATEWAY_PUBLIC_URL=https://gateway.example.test/base`, clients may reach the native endpoint at `/base/mcp`; a front reverse proxy that strips `/base` may instead forward it to bare `/mcp`. Both paths use `/mcp` as their canonical RBAC policy identity. Exact configured MCP routes always remain subject to authentication, RBAC, and CSRF checks, even when an enclosing prefix appears in `AUTH_EXEMPT_PATHS`, `RBAC_EXEMPT_PATHS`, or the exact route appears in `CSRF_EXEMPT_PATHS`. Startup logs a warning when an MCP route falls under an authentication or RBAC exempt prefix because that overlap is usually accidental. HTTP direct firewall rules evaluate the canonical `/mcp` path and the raw alias path together for prefixed MCP requests, preferring restrictive matches (`deny`, then `shadow`, then `allow`) so neither a broad raw allow on `/base/**` nor a canonical `/mcp` allow can suppress a deny or shadow on the other identity. The front proxy should forward OAuth metadata URLs under `/.well-known/oauth-protected-resource` while preserving the RFC 9728 suffix, so public `GET /.well-known/oauth-protected-resource/base/mcp` reaches GreenGateway at the same path.

When set, `GET` at the derived metadata document URL is public and unauthenticated. The response advertises `resource` as `{GATEWAY_PUBLIC_URL}/mcp`, `authorization_servers` from configured JWT/OIDC provider issuers when present, `scopes_supported` as `["mcp:tools"]`, and `bearer_methods_supported` as `["header"]`. MCP authentication failures include a `WWW-Authenticate` challenge with `realm="mcp"` and `resource_metadata` pointing at the derived metadata document URL.

The protected-resource requirement applies to every credential type that can otherwise authenticate to `/mcp`. JWT bearer tokens must include the MCP resource identifier in the `aud` claim, in addition to any existing provider-level static `audience` requirement. GreenGateway `ggw_` service tokens must include the exact `mcp:tools` scope. Cookie-session credentials are not accepted for `/mcp` when protected-resource binding is active; browser admin sessions remain valid for non-MCP routes. Non-MCP endpoints are unchanged by this setting.

### AUDIT_LOG_FILE

Optional JSON Lines audit log file path.

Default: empty, which disables the file sink. Audit events are always written to stdout. A failed stdout write is audit loss, so it increments `audit_events_dropped_total{reason="sink_error"}` and is reported by the shutdown audit drain; the accompanying log line is best effort only, because the default log writer is the same stdout descriptor that failed.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. The file sink opens lazily on first write, appends one JSON event per line, and logs write/open failures without stopping request handling.

### AUDIT_SQLITE_PATH

Optional SQLite audit event store path for queryable local audit history.

Default: empty, which disables the SQLite sink.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, the gateway opens or creates the database at startup, creates the audit event schema and indexes if needed, and fans audit events out to SQLite in addition to stdout and any JSONL file sink. Startup also migrates older audit databases in place by adding any missing promoted payload columns used for indexed queries, including `payload_matched_rule_id` for rule hit counts. It also adds and backfills an indexed `timestamp_epoch_us` column used by retention pruning; the original timestamp column and index remain available for audit queries and compatibility.

### AUDIT_SQLITE_RETENTION_DAYS

Optional SQLite audit event retention window, in days.

Default: empty, which disables SQLite pruning.

Format and validation: must parse as a `u32` day count when set. `0` is accepted and means the same as leaving the variable empty: pruning disabled. A literal zero-day window would place the prune cutoff at the current instant and delete the entire audit history on every prune tick, so GreenGateway reads `0` as the "no retention limit" the value is normally written to mean and logs a warning at startup. Set a positive day count to prune. This value is only applied when `AUDIT_SQLITE_PATH` is also set; if the path is unset, the parsed retention value is accepted but has no effect. Retention pruning uses the indexed epoch column and runs at most once per minute, independently of the more frequent audit flush cadence. Rows with malformed external timestamps retain a `NULL` epoch and are not deleted automatically.

### SHUTDOWN_DRAIN_DELAY_MS

Delay between entering the draining phase and stopping the listeners, in milliseconds.

Default: `1000`

Format and validation: must parse as a `u64` no greater than `30000`; `0` is allowed. On the first shutdown signal (`SIGINT` or `SIGTERM` on Unix; Ctrl-C or Ctrl-Break on Windows), GreenGateway immediately marks readiness false, emits `gateway.shutdown_started`, and cancels retry and health-check work. This delay gives external load balancers time to observe `/readyz` before the listeners stop accepting work.

### SHUTDOWN_TIMEOUT_MS

Maximum time allowed for listeners and registered background tasks to finish after the drain delay.

Default: `30000`

Format and validation: must parse as a `u64` between `1` and `300000`. When the deadline expires, GreenGateway cancels the remaining server futures, emits `gateway.shutdown_forced` with the safe reason `deadline`, and continues to the bounded audit drain. A second termination signal forces the same path immediately with reason `second_signal`.

### AUDIT_DRAIN_TIMEOUT_MS

Maximum time allowed for the asynchronous audit writer to close admission and deliver queued events during shutdown, in milliseconds.

Default: `5000`

Format and validation: must parse as a `u64` between `1` and `60000`. GreenGateway admits lifecycle events through capacity reserved from ordinary request audit traffic, emits one terminal `gateway.shutdown_completed` or `gateway.shutdown_forced` event before closing the audit queue, then waits for the writer and sink-flush acknowledgement. A control-event admission failure, writer panic, drain timeout, or sink flush failure makes shutdown return an error. The always-present stdout sink participates: a failed stdout audit write is counted on `audit_events_dropped_total{reason="sink_error"}` and recorded, so the drain reports it and the process exits unsuccessfully instead of reporting a clean stop without its terminal audit record.

### DISCOVERY_SQLITE_PATH

Optional SQLite endpoint discovery inventory store path.

Default: empty, which disables endpoint aggregation.

Standalone mode only. In cluster mode (`STATE_BACKEND=postgres`) this setting is rejected like every other `*_SQLITE_PATH`: discovery is always on there, served from the shared PostgreSQL tables one fenced projector fills from the durable audit stream (see [the PostgreSQL deployment guide](deployment/postgres.md), "Global discovery"), and the admin discovery surfaces described below answer identically on every replica.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, the gateway opens or creates the database at startup, creates discovery aggregate tables and indexes if needed, creates the persisted endpoint-review, signal, and rule-suggestion tables if needed, and consumes `http.request_observed` audit events into per-method, per-endpoint-template aggregates on the audit writer thread. Proxy dispatch classification runs immediately inside observation, before validation, rate limiting, authentication, or RBAC can reject a request. Every new observation is stamped with `routing_context_known`, and each classified observation records a routing context in `discovery_endpoint_routing_contexts`; contextless traffic uses an empty internal origin sentinel, while selected proxy routes additionally record the configured route host/path prefix and upstream origin. This preserves contextless and routed variants when both are observed for the same endpoint. Raw caller-supplied Host values are retained in the audit event but are not used as aggregate keys; only the bounded configured route host is keyed. `discovery_endpoint_routing_classifications` stores the earliest trusted classification timestamp for each endpoint. `discovery_endpoint_classified_signal_stats` and `discovery_endpoint_classified_signal_principals` separately persist only classified observations used by suggestion-eligible signal detectors. This keeps aggregation and signal persistence out of the request hot path without creating an attacker-controlled Host-cardinality surface.

Upgrade behavior is fail closed. Aggregate and audit rows created before routing classification was available have no trusted classification timestamp and are reported as unknown rather than contextless. They cannot produce direct-rule suggestions. If classification begins after an endpoint aggregate's `first_seen`, that endpoint remains `routing_context_known:false` while the aggregate retains the older observations, even though `routing_context_known_since` and newer classified routing contexts are returned for diagnosis. Coverage therefore remains `unknown` instead of treating a context-bound rule as covering mixed historical evidence. Legacy aggregate counts, error baselines, and principal history are excluded from classified signal-detector state, so the first classified observation cannot combine with old evidence to open a suggestion-eligible signal. Classified detector counters and principal history survive restarts; transient error and volume windows are rebuilt only from classified observations. Existing open suggestions are revalidated against current discovery state before acceptance; host-routed targets and suggestions that predate trusted classification return `409 Conflict` without changing policy or suggestion state. A newly classified observation establishes context for future generation, but does not retroactively make older evidence trusted. Operators must dismiss a rejected pre-classification suggestion and review newly classified traffic instead of accepting the stale suggestion.

This uses a separate config surface from `AUDIT_SQLITE_PATH` because audit history and derived endpoint inventory often have different retention and lifecycle requirements. Operators that prefer a single SQLite file may explicitly set `DISCOVERY_SQLITE_PATH` to the same path as `AUDIT_SQLITE_PATH`; the discovery tables use their own `discovery_` prefixes.

Capacity: endpoint-template cardinality is bounded by `DISCOVERY_ENDPOINT_LIMIT`. When the cap is reached, the aggregator evicts a batch of the least-recently-observed `(method, endpoint_template)` entries and deletes their aggregate, satellite, and derived `discovery_signals` rows on the next flush. Signals are derived state, so an evicted endpoint's signals are removed with it and its in-memory signal dedupe entries are released; a signal queued for a key evicted in the same flush window is never written. The path-template learner uses the same limit for its in-memory shape groups. Distinct principal tracking within each retained endpoint remains exact and has no separate per-endpoint cap, eviction, or retention setting. The `discovery_endpoint_principals` table stores one row per distinct authenticated `actor.user_id` per retained `(method, endpoint_template)`, and `discovery_endpoint_routing_principals` stores the corresponding per-routing-context set. In deployments with many authenticated identities, plan database and memory capacity for those per-endpoint sets before enabling discovery. Unauthenticated calls contribute to aggregate call counts but not to distinct principal rows.

Signal engine: discovery signals are stored in the same SQLite file because they are derived from discovered traffic inventory rather than raw audit history. The first shipped signal type is `new_endpoint_seen`, emitted only when the live endpoint aggregator creates a new `(method, endpoint_template)` aggregate in memory. Existing aggregate rows loaded from `DISCOVERY_SQLITE_PATH` at startup are treated as already known, so upgrading with a populated discovery database does not backfill or flood `new_endpoint_seen` signals on the next request to those endpoints.

Additional signal detectors also run only inside the discovery aggregator on the audit writer thread. Request middleware emits the same `http.request_observed` audit event as before; detector window maintenance, signal construction, and SQLite `INSERT OR IGNORE` persistence are not performed inline in request handling. All signal detectors write through the generic `discovery_signals` table, whose `(signal_type, target_kind, target_key)` uniqueness prevents duplicate lifecycle rows for the same logical target.

Rule suggestions are also stored in this SQLite file, in `discovery_rule_suggestions`. Suggestion generation is an explicit off-hot-path computation; the request handler and discovery aggregator do not compute suggestions while serving traffic. A generated suggestion reflects traffic and signals as of the last explicit generation run. Re-running generation is idempotent for the same logical target because the table has a uniqueness constraint on `(suggestion_type, method, path_pattern, principal_key)` and inserts use `INSERT OR IGNORE` (`ON CONFLICT ... DO NOTHING` against the shared table in cluster mode, so two replicas generating at once cannot double-insert a target either).

### DISCOVERY_ENDPOINT_LIMIT

Maximum number of distinct `(method, endpoint_template)` discovery aggregates retained in memory and in `DISCOVERY_SQLITE_PATH`.

Default: `10000`.

Format and validation: must be a positive integer greater than zero. The limit applies whenever discovery aggregation is enabled. On admission of a new endpoint at capacity, GreenGateway uses approximate-LRU batch eviction so recently observed endpoints remain discoverable without scanning the full map for every request. Evicted aggregate, status, principal, routing-context, classified-signal, payload-shape, and derived signal rows are removed transactionally on the next discovery flush. The path-template learner's in-memory shape-group count is bounded by the same value and falls back to stateless templating for novel shapes after reaching the cap.

On restart, access order is approximated from each persisted aggregate's `last_seen` timestamp. If an existing database exceeds a newly configured lower limit, startup retains the most recently seen entries in memory and queues the complete excess for deletion on the first flush. No schema or manual data migration is required.

In cluster mode (`STATE_BACKEND=postgres`) the same limit bounds the projector's working set and the shared `greengateway.discovery_endpoint_aggregates` table: eviction is performed only by the replica holding the projector lease, under its fence, on the global last-seen order, so no replica can evict an endpoint another replica's traffic still evidences.

### DISCOVERY_PROJECTOR_LEASE_TTL_MS

How long the cluster-mode discovery projector's leadership lease lives on the database clock before another replica may take the slot, in milliseconds.

Default: `15000`

Format and validation: must parse as a `u64` millisecond duration of at least `1000`. In cluster mode (`STATE_BACKEND=postgres`) discovery is not a per-process SQLite aggregator but one replica projecting the durable audit stream into the shared discovery tables (see [the PostgreSQL deployment guide](deployment/postgres.md), "Global discovery"). Leadership is the single slot of the `discovery-projector` scope in `greengateway.execution_leases`, held under this TTL — its own setting, separate from `TOOL_LEASE_TTL_MS`, because failover of a long-running job and admission of one tool invocation have different needs. The leader renews at a third of the TTL and stops projecting on the first renewal that finds the lease gone, or once half the TTL has passed without an answer, always before the slot can be reclaimed; a crashed leader's slot returns after the TTL elapses on the database clock, which is therefore the longest discovery views can go without a projector after a crash. Rejected when `STATE_BACKEND=sqlite`: standalone mode never starts a projector.

### DISCOVERY_PROJECTOR_POLL_MS

How long the cluster-mode discovery projector waits when the durable audit stream has nothing new before reading again, in milliseconds; also its retry wait after a flush the authority could not commit for a transient reason.

Default: `250`

Format and validation: must parse as a `u64` millisecond duration of at least `50`. The default matches the standalone aggregator's flush cadence, so discovery views lag live traffic by about the same amount in either mode; a replica that does not hold the lease waits four times this, with jitter, between attempts to take it. Rejected when `STATE_BACKEND=sqlite`.

### DISCOVERY_PROJECTOR_BATCH

How many durable audit stream rows the cluster-mode discovery projector reads per batch.

Default: `500`

Format and validation: must parse as an integer between `1` and `5000`. Each batch is one bounded stream read followed by bounded flush transactions (one per 200 applied observations and one at the batch's end), and the projector's checkpoint advances to the last position read even when nothing in the batch was an observation, so the bound is on the size of one transaction, not on how far behind the projector may fall. Rejected when `STATE_BACKEND=sqlite`.

### PRINCIPAL_SQLITE_PATH

Optional SQLite principal directory store path for a local authenticated-identity ledger.

Default: empty, which disables principal directory persistence.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, the gateway opens or creates the database at startup, creates the `principal_directory` table if needed, and records every successfully authenticated request through a bounded asynchronous flusher rather than writing SQLite rows inline on the request path. The channel feeding that flusher is bounded (not unbounded like the audit sink's buffer): under a traffic burst large enough to fill it, or if a flush attempt itself fails, the affected observations are dropped rather than queued indefinitely, so `request_count`/`last_seen` can undercount during sustained overload. This is a deliberate trade-off — a bounded, occasionally-lossy queue is preferable to unbounded memory growth on a sink that runs on every authenticated request — and is metered (dropped-observation and flush-failure counters) rather than silent in the metrics sense, even though no individual request sees an error.

Rows are keyed by `(subject, issuer, auth_method)`, where `subject` is `Principal.user_id`, `auth_method` is `bearer`, `service_token`, `cookie`, or `client_certificate`, and `issuer` uses the empty string as the documented sentinel for principals with no issuer. SQLite composite primary keys handle `NULL` surprisingly, so GreenGateway stores this sentinel instead of `NULL` for the identity key.

Each upsert preserves the earliest `first_seen`, refreshes `last_seen`, increments `request_count`, and overwrites `email` and `org_id` with the latest observed values. Roles are intentionally not persisted here; RBAC evaluates fresh roles on every request.

Issuer note: configure `issuer` for JWT providers when tokens carry a stable issuer claim that GreenGateway should validate. A deployment with more than one JWT provider must configure an explicit issuer on every JWT provider so provider order cannot relabel a token that validates against shared keys. A single JWT provider configured only with `jwks_url` receives a stable `provider:<percent-encoded-name>` identity-boundary label; use that same provider label in policy issuer constraints when no token issuer is configured.

### CONNECTIONS_SQLITE_PATH

Optional SQLite control-plane store path for managed Connections.

Default: empty. When unset, GreenGateway creates no implicit database, keeps the existing `UPSTREAM_URL`, `UPSTREAM_ROUTES`, and `MCP_UPSTREAM_SERVERS` runtime unchanged, and exposes up to `256` of those settings internally as immutable legacy projections. If a larger legacy-only runtime is configured, startup remains compatible and a warning reports how many read-only projections were omitted. Managed connection mutations remain unavailable until an explicit path is configured.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. GreenGateway opens the configured database, applies ordered connection-schema migrations in one immediate transaction, validates the resulting schema and foreign keys, and fails startup before either listener is built if opening, migration, or validation fails. Reopening an already migrated store is idempotent.

The store contains connection metadata, opaque credential-binding IDs, dependency records, monotonic revisions, bounded safe status history, and—only when the encrypted local provider is enabled—authenticated ciphertext envelopes. It does not store resolved plaintext, master keys, OAuth access tokens, or unencrypted private-key material. Connection changes use transactions and canonical ETags; dependent records prevent deletion rather than being silently cascaded. A status observation is accepted only for the exact connection ETag it tested, and reconfiguration invalidates the prior current observation. With managed storage configured, the combined managed and projected connection count is capped at `256`; credential-binding and encrypted-local-secret rows are each capped at `512`; dependency rows are capped at `4096`; and current plus historical safe-status rows are capped at `4096`. Every persisted bound is revalidated before startup.

Use a durable filesystem location and include the SQLite database, WAL, and SHM files in the same operational backup boundary. An ephemeral container path does not make managed configuration durable.

Connection admin API: `GET /v1{ADMIN_PREFIX}/connections` returns a filterable, cursor-paginated safe summary collection and requires `admin:connections:read`. It accepts `limit` (1-100), `cursor`, `enabled`, `kind`, `source`, and `state`; its `ETag` identifies the exact representation while `x-greengateway-connections-etag` identifies the configuration collection used by the page. Mutation responses also return the collection value when their normal `ETag` identifies one connection resource. `GET /v1{ADMIN_PREFIX}/connections/{id}` uses the same permission and returns a redacted detail plus the resource `ETag`. Read responses report only safe authentication/TLS configuration flags and, for each additional secret header, the normalized header name plus `secret_configured`: they never return secret IDs, provider locators, resolved values, ciphertext, raw errors, or certificate/key material. TLS certificate and private-key bindings have separate configured flags so disabled partial drafts also round-trip without revealing or discarding either hidden ID. On full `PUT`, omitting a hidden binding ID (or returning its `*_configured: true` redaction marker from the detail DTO) retains the current binding under the required resource `If-Match`; an additional-header marker is matched to the existing entry with the same normalized name. Any explicitly submitted hidden binding field—including the current value or `null`—requires `admin:connections:secrets:write`, preventing redacted-ID equality probing; authentication, additional-header, and TLS authority changes require it as well. Enabled candidates resolve every referenced binding for its exact credential/TLS purpose before persistence or runtime publication. CA validation parses every PEM entry as valid X.509 DER and rejects the entire bundle if any entry is malformed; client certificate and private-key material must also parse and match. Legacy configuration appears as read-only projections with all mutation actions disabled.

`POST /v1{ADMIN_PREFIX}/connections`, `PUT /v1{ADMIN_PREFIX}/connections/{id}`, and `DELETE /v1{ADMIN_PREFIX}/connections/{id}` require `admin:connections:write`. Binding, clearing, redirecting, or deleting credential/TLS authority additionally requires `admin:connections:secrets:write`; this includes adding, removing, reordering, renaming, binding, or clearing any `additional_headers` entry, changing the destination of a credentialed connection, changing an authenticated discovery target, or adding/removing/changing the method or path of its stored test profile. Expected test status changes alone do not redirect credential use. A replacement that changes credential authority advances the Connection and credential revisions, creates a new resource ETag, and invalidates the previous current status. A rejected secondary secrets-write check emits a redacted `authz.denied` event with the stable route pattern, operation, and required permission, but no submitted binding ID or target. The request body is capped at the lower of `MAX_BODY_SIZE` and 64 KiB. `POST` requires an exact collection `If-Match`; `PUT` and `DELETE` require the resource `ETag`. Missing preconditions return `428`, stale state returns `412`, validation returns `400` or structured `422`, an authorized unknown ID returns `404`, retained dependencies return `409`, and unavailable configured storage returns a sanitized `503`. There is no force-delete option. Successful writes publish one immutable runtime snapshot and emit `connection.changed`; sensitive writes also emit `connection.credential_changed`, with stable IDs and changed-field names rather than targets or secret references. Existing CSRF rules remain active for cookie-authenticated mutations, while bearer authentication retains its CSRF exemption.

`POST /v1{ADMIN_PREFIX}/connections/{id}/refresh` requires `admin:connections:refresh`, an exact resource `If-Match`, and an empty body. It is available for enabled managed Connections with either `managed_mcp` or `managed_openapi` discovery. At most four refreshes may run at once and the same Connection cannot refresh concurrently; contention returns `409`. A refresh and metadata or catalog-registration mutation for the same Connection are also mutually exclusive.

For managed MCP, GreenGateway initializes the stored endpoint and paginates `tools/list` within fixed page, tool, byte, and timeout bounds. It validates every remote name and input schema, rejects collisions against the complete live registry, commits the durable catalog and managed-tool dependencies transactionally, and then swaps the complete candidate into the live registry. For managed OpenAPI, refresh fetches only the stored discovery path through the Connection's fixed endpoint, TLS, primary/additional credential, timeout, egress, and response-size policy, then republishes only a previously registered selection when the fetched specification still satisfies that binding. It does not accept a caller URL or silently select new operations. The primary and additional credentials are both sent only when the discovery profile sets `use_connection_authentication` to `true`; additional headers do not satisfy or alter OpenAPI security-scheme matching.

Any authentication, transport, pagination, schema, collision, limit, revision, or storage failure publishes nothing. The prior catalog remains available as last-known-good and status becomes `degraded/catalog_stale`; without a prior catalog status becomes unavailable. A Connection with retained managed-tool dependencies cannot change to an incompatible kind or remove its discovery configuration; first publish an empty successful catalog so dependency pruning is explicit and atomic. The following incompatible update or deletion removes that zero-entry catalog from durable and runtime state. Compiled input-schema validators are capped at 4096 entries and the cache is cleared before accepting another unseen schema revision. Successful and failed attempts emit `connection.refreshed` with only the stable Connection ID/kind, bounded outcome/reason/latency, and add/change/remove counts on success.

`POST /v1{ADMIN_PREFIX}/connections/{id}/test` requires `admin:connections:test`, an exact resource `If-Match`, and an empty body. It tests enabled or disabled managed Connections without accepting a caller-supplied URL, method, path, body, header, credential, TLS, timeout, or egress override. HTTP tests use only the stored uppercase `GET` or `HEAD` profile and its expected statuses. Previously persisted v0 `OPTIONS` profiles remain readable so an upgrade does not turn them into corrupt records, but the test endpoint does not execute them and new or replacement writes must use `GET` or `HEAD`. Managed MCP tests initialize the saved endpoint and request at most one advertised tools or resources metadata page; they never paginate, invoke a tool, read a resource, or publish a catalog. The endpoint applies bounded global, per-principal, and per-Connection rate/concurrency admission plus a ten-second hard deadline. It runs the normal egress check before resolving saved TLS or application credentials, uses the same exact-pinned production transport and response limits, and never auto-seeds an egress rule. Operational failures still return a `200` test result with only fixed stage names, outcomes, safe reasons, and latency; API, authorization, precondition, and admission failures use their normal HTTP statuses. Results never include targets, DNS answers, IP addresses, upstream status codes, bodies, headers, OAuth challenges/errors, certificate details, secret references, fingerprints, or raw transport errors. Accepted observations update status only if the captured Connection ETag is still current, and every completed or admission-rejected attempt emits one sanitized `connection.tested` event.

### CONNECTION_LOCAL_SECRET_KEYRING

Optional startup keyring for the encrypted local secret provider.

Default: `[]`, which disables local-secret creation and rotation. If the configured Connections database already contains encrypted local-secret rows, an empty keyring fails startup closed rather than making those bindings appear absent.

Format: a JSON array of at most `16 KiB` with at most `8` entries. Each entry contains a safe opaque `id`, a one-segment `file` below `CONNECTION_SECRETS_ROOT`, and `role` equal to `primary` or `decrypt_only`. Exactly one key must be primary. The setting requires both `CONNECTIONS_SQLITE_PATH` and `CONNECTION_SECRETS_ROOT`. File keys use the same traversal, device-name, symlink, reparse-point, regular-file, nonblocking-open, and platform permission protections as operator file aliases. Each file must contain exactly 32 raw random bytes with no newline or encoding. Configuration `Debug`, startup errors, metadata, and provider errors never expose key IDs, filenames, root paths, or key material.

Generate a new key directly into the protected mount rather than printing it or placing it in shell history. On Unix, for example, set a restrictive umask and run `openssl rand -out /protected/greengateway-secrets/local-secret-primary.key 32`, then verify the file is owned by the gateway account and has mode `0600`. On Windows, apply an ACL that grants read access only to the gateway service identity and administrators. Never commit, base64-wrap, newline-terminate, or place the key beside the database, an image, or a source checkout.

The primary key encrypts all newly created or rotated values with XChaCha20-Poly1305 and a fresh cryptographically random 24-byte nonce. Previous keys are decrypt-only. Canonical authenticated additional data binds schema version, secret UUID, secret version, credential purpose, and the encrypted field purpose, so moving ciphertext, nonces, tags, or metadata between rows fails authentication. Unknown algorithms, missing/wrong keys, changed AAD, modified ciphertext, and invalid decrypted material fail startup or resolution closed. Before an in-use value rotates, every enabled Connection that references it is preflighted with the proposed material, including every CA bundle entry's X.509 DER and certificate/private-key pairing; a failed preflight leaves the previous encrypted value and active runtime unchanged.

To rotate a master key, mount the new 32-byte key, change the former primary to `decrypt_only`, add the new entry as `primary`, and restart. Run `gateway connection-secrets reencrypt --batch-size N` repeatedly, with `N` from `1` through `64`, until it reports `remaining=0`. Then run `gateway connection-secrets ensure-key-unused --key-id ID` for the former key before removing that entry and file. Source builds may use `cargo run -p gateway -- connection-secrets reencrypt --batch-size N` and `cargo run -p gateway -- connection-secrets ensure-key-unused --key-id ID`. These are the only shipped maintenance operations; neither command reveals a value, locator, ciphertext, nonce, or key. A failed re-encryption batch rolls back the entire batch, and the unused-key check fails while any row still depends on that key. Rotating a stored credential value is independent: it increments that secret's version and uses the current primary immediately.

Back up the SQLite database (including its WAL boundary) and the mounted key files separately. A database backup without every key still referenced by its rows is intentionally unrecoverable; a key backup without the database contains no secret records. Test restore by opening a copy with the copied keyring. There is no reveal/export-value operation: create and rotate consume a value once and return only stable safe metadata, while delete refuses referenced secrets with bounded connection dependency IDs.

### CONNECTION_SECRET_ALIASES

Trusted startup configuration for opaque operator-provisioned secret aliases.

Default: `[]`.

Format: a JSON array of at most `256 KiB` with at most `512` entries. Every entry has a safe opaque `id`, a non-control-character `label` of at most `128` characters, and a typed `source`. Environment sources use `{"type":"environment","key":"GGW_BILLING_TOKEN"}`. File sources use `{"type":"file","key":"billing-token"}` and require `CONNECTION_SECRETS_ROOT`. IDs are unique, contain 1–128 URL-safe ASCII characters, and start with an ASCII letter or digit. Environment keys contain at most 128 ASCII letters, digits, or underscores and start with a letter or underscore. File keys are one safe filename segment of at most 255 bytes: absolute paths, `.`/`..`, separators, drive/alternate-stream syntax, control bytes, trailing dot/space, and Windows device names are rejected.

The JSON is an operator trust boundary, not an admin payload. Ordinary connection APIs accept and expose only alias IDs and safe labels; they never accept or return environment keys, file keys, host paths, or values. Configuration `Debug` and errors redact both environment and filesystem locators. Alias metadata reports the operator provider kind and configured alias record but has no secret reveal operation.

`GET /v1{ADMIN_PREFIX}/connection-secrets` requires `admin:connections:secrets:write` and returns only safe alias metadata, purpose compatibility, dependency counts, availability flags, and safe actions. `POST` on that collection creates an encrypted-local value and requires an exact `If-Match` of `x-greengateway-connection-secrets-etag`; `PUT /v1{ADMIN_PREFIX}/connection-secrets/{id}` rotates one encrypted-local value using its resource ETag; and `DELETE` removes only an unreferenced encrypted-local value using that same precondition. Operator environment/file aliases are read-only through this API. Create and rotate request bodies contain `label` or `purpose` plus a one-use `value`; bodies are bounded, zeroized on the best-effort paths, never logged, and responses contain metadata only. Missing preconditions return `428`, stale state returns `412`, referenced deletes return `409`, invalid material returns `422`, and an unavailable local provider returns a sanitized `503`. Every response is `Cache-Control: no-store`.

For rollout and rollback, use the [Connection migration guide](connections/migration.md). Day-two key, backup, alert, and recovery procedures are in the [operator guide](connections/operator-guide.md), and the permission-separated control-plane workflow is in the [admin guide](connections/admin-guide.md).

Values are resolved afresh for each authorized use and are never cached by this provider. An atomic mounted-file replacement is therefore visible to the next resolution while already resolved in-flight values remain isolated until their redacted, zeroizing wrapper is dropped. Environment values are also re-read, although most deployment environments require a process restart to change them. Reads are capped at 16 concurrent resolutions and at the credential-purpose byte limit; admission reserves that permit before any blocking filesystem, environment, or encrypted-store job is submitted, so excess work fails closed instead of accumulating in the blocking queue. Missing, empty, oversized, NUL-bearing, inaccessible, or invalid-Unicode environment values fail closed without an anonymous fallback.

### CONNECTION_SECRETS_ROOT

Canonical root directory for `file` entries in `CONNECTION_SECRET_ALIASES`.

Default: empty. It is required when any file alias or encrypted-local-secret keyring entry is configured.

Format and validation: a valid Unicode filesystem path that exists and canonicalizes to a directory at startup. GreenGateway retains a capability-backed handle to that validated directory, so renaming or replacing the configured path or an ancestor after startup cannot redirect later reads. File aliases are restricted to one validated filename segment relative to the retained handle. Every resolution rejects symbolic links and Windows reparse points, opens the leaf without following links and in nonblocking mode, validates the opened handle as a regular file, and caps the read before material is parsed. On Unix, the root must not be group/other writable and secret files must grant no group/other permissions. Windows enforces the regular-file and reparse-point boundary, but ACL ownership/readability policy remains an operator and deployment-platform responsibility.

Use atomic replacement within the same protected root for file rotation. Do not point this setting at a general configuration, home, host-root, or service-account directory. Cloudflare container deployments must provide an explicit durable secret mount; forwarding the path alone does not create or persist that mount.

### CONNECTION_VAULT_PROVIDER

Optional Vault KV v2 secret provider. Profiles define how to authenticate to one or more HashiCorp Vault clusters; aliases map opaque IDs to individual KV v2 data keys.

Default: `{}` (Vault secret provider disabled).

Format: a JSON object of at most `256 KiB` with a `profiles` array (at most `8` entries) and an `aliases` array (at most `512` entries). Each profile has a safe opaque `id`, an `address` (scheme + authority), an optional `namespace`, and an `auth` object. Auth types are `workload_jwt` (mount, role, token_root, token_file), `token` (secret_alias referencing another provider), and `app_role` (mount, role_id, secret_id_alias referencing another provider). Each alias has a safe opaque `id`, a non-control-character `label` of at most `128` characters, a `profile` referencing a configured profile ID, a KV v2 `mount`, `path`, `key`, and an optional pinned `version`.

The `auth` mount is the mount name alone, without the `auth/` prefix that Vault's own CLI paths carry: the login request is built as `{address}/v1/auth/{mount}/login`, so a Kubernetes auth backend mounted at `auth/kubernetes` is configured as `"mount": "kubernetes"`.

Alias IDs share the same namespace as operator aliases (`CONNECTION_SECRET_ALIASES`), encrypted-local secrets (`CONNECTION_LOCAL_SECRET_KEYRING`), and other network secret providers, and duplicate alias IDs are rejected at startup; profile IDs must be unique within this provider. Vault aliases are resolved asynchronously at request time and are validated on first use, not at startup. The synchronous `resolve_blocking` path returns `SourceUnavailable` for Vault aliases, so connections that reference Vault secrets skip material validation during startup binding checks.

Every identity and data-plane request travels through the gateway egress client, so HTTPS, strict CA/hostname/SNI validation, all-answer DNS validation with exact pinning, and the disabled redirect policy apply unchanged. Operators must add each configured Vault `address` host to `EGRESS_ALLOWED_HOSTS`; the allowlist is never expanded automatically.

A resolved value is cached for at most 60 seconds, so a revocation or deletion at the Vault side becomes visible on the next resolution after that window rather than immediately; pinned aliases stay pinned, and unpinned aliases observe the next valid version after the same bounded expiry.

The [Vault KV v2 operator guide](secrets/vault-kv-v2.md) carries the full worked example, the least-privilege policy granting only `read` on each `.../data/...` path, and the short-TTL auth-role binding.

Configuration `Debug`, startup errors, metadata, and provider errors redact addresses, namespaces, mounts, paths, keys, token roots, token files, and all auth locators. The JSON is an operator trust boundary: ordinary connection APIs accept and expose only alias IDs and safe labels. Alias metadata reports the Vault provider kind and configured alias record but has no secret reveal operation.

### CONNECTION_GCP_PROVIDER

Optional read-only Google Cloud Secret Manager provider. Profiles fix one Workload Identity Federation identity; aliases map opaque IDs to exactly one secret version resource.

Default: `{}` (Google Cloud Secret Manager provider disabled).

Format: a JSON object of at most `256 KiB` with a `profiles` array (at most `8` entries) and an `aliases` array (at most `512` entries). Each profile has a safe opaque `id`, an `audience` that must be the complete workload identity pool provider resource (`//iam.googleapis.com/projects/{number}/locations/{location}/workloadIdentityPools/{pool}/providers/{provider}`), a `token_root` directory and `token_file` naming the projected subject-token file, and an optional `service_account` impersonation target that must be a dedicated service account of the form `{name}@{project}.iam.gserviceaccount.com`. Each alias has a safe opaque `id`, a non-control-character `label` of at most `128` characters, a `profile` referencing a configured profile ID, a `project` (ID or number), an optional `location` for regional secrets, a `secret` ID, and an optional pinned numeric `version`; when `version` is omitted the alias tracks the fixed `latest` version alias and observes rotation after a bounded cache expiry, while a pinned version never follows rotation.

Identity is Workload Identity Federation only: the projected subject token is exchanged at the fixed Google STS endpoint (`https://sts.googleapis.com/v1/token`) for a `https://www.googleapis.com/auth/cloud-platform` access token, and, only when `service_account` is configured, that federated token is exchanged once more through the fixed iamcredentials `generateAccessToken` endpoint for a service-account token with a bounded `600s` lifetime. There is no Application Default Credentials chain, no gcloud or CLI invocation, no user credential, no metadata-server fallback, and no support for service-account keys; a `401`/`403` from the data plane purges the cached token and re-exchanges through the same fixed identity source exactly once, never falling back to weaker credentials. Tokens are cached per profile with a bounded lifetime and an expiry safety margin, and are zeroized on rotation and drop.

The data plane implements exactly one operation, `AccessSecretVersion`, against `https://secretmanager.googleapis.com` for global secrets or `https://secretmanager.{location}.rep.googleapis.com` when `location` is set; there is no list, discovery, write, rotate, disable, destroy, or administration path. The returned resource `name` is validated against the alias binding: the secret ID, location, and version components must match exactly, and the project component must match the configured project — except that when the alias is configured with a project ID, any well-formed numeric project component is tolerated, because Google canonicalizes resource names to the project number and the gateway cannot derive that number from configuration. Configure the numeric project number instead of the project ID for byte-exact response binding. The payload is strictly base64-decoded, the returned `dataCrc32c` checksum is verified against a locally computed CRC32C, and purpose byte bounds are enforced. Disabled or destroyed versions, checksum mismatches, malformed or oversized responses, provider outage, and newly denied access all fail closed with no stale value and no fallback.

Every identity and data-plane request travels through the gateway egress client, so HTTPS, strict CA/hostname/SNI validation, all-answer DNS validation with exact pinning, and the disabled redirect policy apply unchanged. Operators must add `sts.googleapis.com`, `iamcredentials.googleapis.com` (only when impersonation is configured), and `secretmanager.googleapis.com` or the regional `secretmanager.{location}.rep.googleapis.com` hosts to `EGRESS_ALLOWED_HOSTS`; the allowlist is never expanded automatically.

Least privilege: grant the federated identity (or the impersonated service account) `roles/secretmanager.secretAccessor` on each exact secret — or a narrower custom role containing only `secretmanager.versions.access` — never at project or folder scope. When impersonation is used, grant the workload identity principal `roles/iam.workloadIdentityUser` (and `roles/iam.serviceAccountTokenCreator` where required) only on that dedicated service account, and grant that service account nothing beyond the exact-secret accessor role. Do not create or distribute service-account keys for this integration; the provider cannot consume them by design. All values in this documentation are placeholders.

Alias IDs share the same namespace as operator aliases (`CONNECTION_SECRET_ALIASES`), encrypted-local secrets (`CONNECTION_LOCAL_SECRET_KEYRING`), and other network secret providers, and duplicate alias IDs are rejected at startup; profile IDs must be unique within this provider. Aliases are resolved asynchronously at request time and are validated on first use, not at startup. The synchronous `resolve_blocking` path returns `SourceUnavailable` for these aliases, so connections that reference them skip material validation during startup binding checks.

Configuration `Debug`, startup errors, metadata, and provider errors redact audiences, token roots, token files, service accounts, projects, locations, secret IDs, tokens, and payloads. The JSON is an operator trust boundary: ordinary connection APIs accept and expose only alias IDs and safe labels. Alias metadata reports the provider kind and configured alias record but has no secret reveal operation.
### CONNECTION_KUBERNETES_PROVIDER

Optional read-only Kubernetes Secrets API provider. Profiles define how to authenticate to one or more API servers; aliases map opaque IDs to exactly one namespace, Secret name, and `data` key.

Default: `{}` (Kubernetes secret provider disabled).

Format: a JSON object of at most `256 KiB` with a `profiles` array (at most `8` entries) and an `aliases` array (at most `512` entries). Each profile has a safe opaque `id`, a `server`, an optional CA trust source (`ca_bundle_root` plus `ca_bundle_file`, or `ca_bundle_alias`), and an `auth` object. `server` is an explicit absolute `https` URL of scheme and authority only (no credentials, path, query, or fragment); the provider never derives an endpoint from `KUBERNETES_SERVICE_HOST`, a kubeconfig, or any other ambient in-cluster environment. Auth types are `projected_token` (`token_root`, `token_file`: an audience-bound short-lived ServiceAccount token projected by the kubelet into a pinned directory, re-read on a bounded interval so rotation is observed within about a minute and immediately after a `401`), `bearer_alias` (`secret_alias`: a static bearer token taken from an already configured alias of another provider, never from an inline value), and `client_certificate` (`certificate_alias`, `private_key_alias`: mutual TLS, with the certificate chain and private key taken from already configured non-reveal aliases of another provider, combined into the client identity of the profile's derived egress transport; requests carry no `Authorization` header, the material is re-resolved per resolution so rotation is observed and invalidates cached values, and a `401` fails closed without retry). There is no anonymous mode, no kubeconfig discovery or parsing, no exec/credential plugin, no external command, and no proxy support. Each alias has a safe opaque `id`, a non-control-character `label` of at most `128` characters, a `profile` referencing a configured profile ID, a `namespace` (RFC 1123 DNS label), a Secret `name` (RFC 1123 DNS subdomain), and a `key` restricted to ASCII alphanumerics, `-`, `_`, and `.`. Every path segment is validated against these rules at startup and defensively percent-encoded when the fixed request URL is assembled, so no request URL ever contains a caller-supplied byte.

The provider implements exactly one operation, `GET /api/v1/namespaces/{namespace}/secrets/{name}` with `Accept: application/json`; there is no discovery, list, watch, write, rotate, delete, or administration path. The returned object must be `kind: Secret` at `apiVersion: v1` with `metadata.namespace` and `metadata.name` exactly matching the alias binding, the configured `data` key is selected exactly, and its value must be canonical Base64 (whitespace-laced, unpadded, over-padded, or trailing-bit-bearing encodings are rejected). A missing Secret, missing key, object identity mismatch, malformed document, oversized response, or decoded value outside the purpose byte bounds fails closed; a failed resolution purges any cached value for that alias and never returns a previous value, retries anonymously, or switches credential sources. A `401` earns exactly one re-read of the fixed identity source; an RBAC `403` never retries. Resolutions are bounded by an `8`-way concurrency cap, a total deadline, one transient retry with backoff, a `2 MiB` response cap that the provider clamps into its derived egress client so it is enforced while the response is being received (never widening a tighter deployment `EGRESS_MAX_RESPONSE_BYTES`), and a bounded short-TTL value cache keyed by provider configuration, egress generation, identity generation, alias, and purpose.

Egress admission is explicit. Every request travels through the standard egress client (HTTPS only, strict certificate and hostname verification, all-answer DNS validation with exact address pinning, no redirects), and the API-server host must be present in `EGRESS_ALLOWED_HOSTS`; nothing is ever allowed implicitly, including `.svc` names, cluster-local suffixes, and private ranges. When the API server resolves to a private or otherwise non-global address (the usual case for in-cluster endpoints such as `kubernetes.default.svc` or a ClusterIP), the default `EGRESS_DENY_PRIVATE_IPS=true` still blocks the connection unless the deployment's egress policy allowlists that address range through an explicit policy CIDR; prefer that scoped CIDR over disabling `EGRESS_DENY_PRIVATE_IPS` globally, and remember that a non-`443` API-server port (commonly `6443`) must also be admitted wherever the egress policy restricts ports. TLS trust for API servers issued by a private cluster CA comes from at most one of two per-profile sources whose PEM bundle is added to the verification trust set of a derived egress client for that profile only. On a live cluster, configure `ca_bundle_root` and `ca_bundle_file` to read the platform-projected bundle — typically `{"ca_bundle_root":"/var/run/secrets/kubernetes.io/serviceaccount","ca_bundle_file":"ca.crt"}` — through the same platform-projected file rules as the token path, which accept the world-readable layout the kubelet publishes; the bundle is re-read on every resolution, so certificate-authority rotation is observed without a restart, and a rotated bundle invalidates values cached under the previous trust generation. Alternatively `ca_bundle_alias` names an already configured non-reveal alias of another provider for operators who provision the bundle themselves; note that an operator *file* alias enforces exclusive permissions (no group/other bits, symlinks rejected) on a regular file under `CONNECTION_SECRETS_ROOT`, so it cannot point directly at the projected `ca.crt` — use the projected source for that. Trust is only ever added through the explicit validated bundle, hostname verification still applies, and there is no insecure-skip-verify option; a missing or unusable bundle fails the resolution closed (purging any cached value for the alias) rather than connecting with reduced verification, and without either source the API-server certificate must chain to the platform trust store.

Alias IDs share the same namespace as operator aliases (`CONNECTION_SECRET_ALIASES`), encrypted-local secrets (`CONNECTION_LOCAL_SECRET_KEYRING`), and other network secret providers, and duplicate alias IDs are rejected at startup; profile IDs must be unique within this provider. Kubernetes aliases are resolved asynchronously at request time and are validated on first use, not at startup. The synchronous `resolve_blocking` path returns `SourceUnavailable` for Kubernetes aliases, so connections that reference them skip material validation during startup binding checks.

Configuration `Debug`, startup errors, metadata, and provider errors redact servers, namespaces, Secret names, data keys, token roots, token files, and all auth locators; tokens, request headers, and response bodies are never logged, and secret material is zeroized on drop. The JSON is an operator trust boundary: ordinary connection APIs accept and expose only alias IDs and safe labels. Alias metadata reports the Kubernetes provider kind and configured alias record but has no secret reveal operation.

Grant the gateway's ServiceAccount the least privilege the provider needs: a namespaced Role with only the `get` verb on `secrets`, restricted with `resourceNames` to exactly the Secrets that aliases bind, and a RoleBinding in that namespace. Do not grant `list` or `watch`; the provider never issues them, and their absence keeps the identity unable to enumerate. Placeholder values only:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: greengateway-secret-reader
  namespace: your-namespace
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["your-secret-name"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: greengateway-secret-reader
  namespace: your-namespace
subjects:
  - kind: ServiceAccount
    name: your-gateway-serviceaccount
    namespace: your-gateway-namespace
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: greengateway-secret-reader
```

For `client_certificate`, bind the Role to the `User` (certificate Common Name) or `Group` (Organization) the API server derives from the client certificate instead of a ServiceAccount subject, keep the certificate lifetime short, and remember that Kubernetes client certificates cannot be revoked before expiry — prefer `projected_token` wherever a ServiceAccount identity is available. For `projected_token`, project a dedicated audience-bound token rather than mounting the ServiceAccount's default credential: a `projected` volume with a `serviceAccountToken` source, an explicit `audience` the API server accepts (for self-hosted authentication this is typically `https://kubernetes.default.svc`; keep it distinct from tokens minted for other services), and a short `expirationSeconds` (the Kubernetes minimum is `600`; keep it at or near that minimum so a leaked token ages out quickly). The kubelet rotates the projected file automatically and the provider re-reads it on a bounded interval, so no restart is needed on rotation. Encryption of Secret data at rest (for example KMS-backed `EncryptionConfiguration` for the `secrets` resource in etcd) is the cluster operator's responsibility and is not something this provider can observe or enforce.

### CONNECTION_AZURE_PROVIDER

Optional read-only Azure Key Vault Secrets provider. Profiles fix a Microsoft Entra authority and workload identity; aliases map opaque IDs to individual Key Vault secrets. Only the Get Secret operation is implemented, against the pinned stable `api-version=7.5`; there is no list, write, rotate, delete, recover, purge, backup, restore, or administration path, and no request URL ever contains a caller-supplied byte.

Default: `{}` (Azure Key Vault secret provider disabled).

Format: a JSON object of at most `256 KiB` with a `profiles` array (at most `8` entries) and an `aliases` array (at most `512` entries). Each profile has a safe opaque `id`, a GUID `tenant_id`, a GUID `client_id`, an optional `authority_host` (a bare lowercase DNS host, default `login.microsoftonline.com`), an optional `scope` (an absolute https URL ending in `/.default`, default `https://vault.azure.net/.default`), and an `auth` object. Auth types are `workload_jwt` (`token_root`, `token_file`: a fixed projected OIDC token exchanged as a federated client assertion), `client_secret` (`secret_alias` referencing an alias of another provider), and `client_certificate` (`key_alias` referencing an RSA private key PEM alias of another provider plus a 40-character hex SHA-1 `certificate_thumbprint`; the provider signs an RS256 client assertion with the matching `x5t` header). Interactive, device-code, CLI, managed-identity probing, and `DefaultAzureCredential`-style ambient chains are not representable. Each alias has a safe opaque `id`, a non-control-character `label` of at most `128` characters, a `profile` referencing a configured profile ID, a `vault` authority (`https://` plus host only, for example `https://example-vault.vault.azure.net`), a secret `name` of at most 127 alphanumeric-or-dash characters, and an optional pinned 32-hex-character `version`.

Sovereign clouds are supported only by explicit configuration: set `authority_host` (for example `login.microsoftonline.us` or `login.partner.microsoftonline.cn`) and the matching `scope` (for example `https://vault.usgovcloudapi.net/.default` or `https://vault.azure.cn/.default`) on the profile. The provider never discovers the authority, tenant, scope, or vault from an unauthenticated challenge: an Entra token for the fixed scope is acquired before any vault access, and a `WWW-Authenticate` challenge on a denial is treated purely as a denial.

Least privilege: grant the profile's service principal (or federated workload identity) only the `Key Vault Secrets User` built-in role, or a narrower custom role containing just the `Microsoft.KeyVault/vaults/secrets/getSecret/action` data action (`secrets/get` under access policies), scoped to the individual vault or, tighter still, the individual secret. No control-plane (management-plane) role assignment is needed: the provider only performs data-plane reads. For workload identity federation, create a federated identity credential on the app registration that trusts your cluster's OIDC issuer and the service account subject, mount the projected token at a fixed path, and reference that path as `token_root`/`token_file`; no bootstrap secret is required.

Every identity and data-plane request travels through the gateway egress client, so the Entra authority host and every configured vault authority host must be present in `EGRESS_ALLOWED_HOSTS`; HTTPS, strict CA/hostname/SNI validation, all-answer DNS validation with exact pinning, and the disabled redirect policy apply unchanged. Alias IDs share the same namespace as operator aliases (`CONNECTION_SECRET_ALIASES`), encrypted-local secrets, and every other network secret provider, and duplicate alias IDs are rejected at startup; profile IDs must be unique within this provider. Azure aliases are resolved asynchronously at request time and are validated on first use, not at startup; the synchronous `resolve_blocking` path returns `SourceUnavailable` for Azure aliases, so connections that reference Azure secrets skip material validation during startup binding checks.

Rotation, revocation, disablement, deletion, temporal (`nbf`/`exp`) violations, malformed data, provider outage, and newly denied access fail closed and purge any cached value; the provider never returns a stale value, retries anonymously, or falls back to a weaker credential. Resolutions are bounded by a per-read deadline, a single transient retry with backoff, a fixed concurrency cap, bounded response sizes, and bounded token/value caches keyed by provider configuration, egress generation, identity generation, alias, purpose, and pinned version; token and value material is zeroized on eviction and drop. Configuration `Debug`, startup errors, metadata, and provider errors redact authority hosts, tenant and client IDs, scopes, vault authorities, secret names, versions, token roots, token files, and all auth locators; observability carries only the bounded provider kind, outcome, safe reason, and latency. The JSON is an operator trust boundary: ordinary connection APIs accept and expose only alias IDs and safe labels, and alias metadata has no secret reveal operation.

### CONNECTION_AWS_PROVIDER

Optional read-only AWS Secrets Manager secret provider. Profiles fix one region-independent AWS identity each; aliases map opaque IDs to complete Secrets Manager secret ARNs. Only the `GetSecretValue` operation is implemented: there is no list, discovery, write, rotate, delete, or administration operation, and callers, tool arguments, and ordinary Connection mutations can never select ARNs, regions, versions, stages, JSON members, or endpoints.

Default: `{}` (AWS Secrets Manager secret provider disabled).

Format: a JSON object of at most `256 KiB` with a `profiles` array (at most `8` entries) and an `aliases` array (at most `512` entries). Each profile has a safe opaque `id`, an `auth` object, and an `sts_endpoint` (absolute `https` URL with no credentials, path, query, or fragment). Auth types are `web_identity` (a fixed `role_arn`, plus `token_root` and `token_file` naming a platform-projected workload identity token, exchanged through unsigned `AssumeRoleWithWebIdentity` at the configured STS endpoint for bounded session credentials) and `static_keys` (`access_key_id_alias` and `secret_access_key_alias` referencing aliases of another provider, used directly as SigV4 signing credentials). `sts_endpoint` is required by `web_identity`, which is the only mode that contacts STS; `static_keys` signs directly with its bootstrap key pair and issues no STS request, so it may omit the field entirely. A `static_keys` profile that supplies one anyway — including one written before the field became optional — still starts, and the value is still shape-validated, but it is never contacted. A `web_identity` endpoint whose host states a partition must agree with the partition of every alias bound to that profile: a host under `amazonaws.com` naming a `us-gov-` region is GovCloud and one naming none is commercial, so pairing either with an alias in the other partition is refused at startup, naming the alias index, the profile index, and both partitions. The endpoint is where the session credentials are minted and the alias host is where they are then signed, so a mismatched pair would send one partition's access key and `x-amz-security-token` bearer to the other partition's host — a separate trust domain in which that principal does not exist, which rejects it on every request for the life of the process. A host outside `amazonaws.com` (a private endpoint, an interface VPC CNAME) states no partition and constrains nothing, and a `static_keys` endpoint binds nothing because it is never dialled. The role ARN is not constrained either: IAM is global, so a role ARN carries no region and derives no host. There is no SDK default credential chain, no instance metadata service, no shared configuration or credentials file, and no process or CLI credential source; a denied or unavailable identity fails closed without any fallback.

Each alias has a safe opaque `id`, a non-control-character `label` of at most `128` characters, a `profile` referencing a configured profile ID, the complete secret `arn`, at most one of `version_id` or `version_stage`, and an optional `json_key` naming one fixed top-level JSON member to extract from `SecretString`. The ARN must be the full `arn:aws:secretsmanager:<region>:<account-id>:secret:<name>-<6-character-suffix>` form; partial ARNs without the random creation suffix are rejected because Secrets Manager treats them as ambiguous name lookups. Accepted partitions are `aws` and `aws-us-gov`, the two whose regional endpoint is deterministically `secretsmanager.<region>.amazonaws.com`; `aws-cn` is rejected because its endpoints live under `amazonaws.com.cn`. The partition must agree with the region — `aws-us-gov` with a `us-gov-` region, `aws` with any other — because the endpoint is derived from the region alone, so a mismatched pair (an ARN AWS never issues) would otherwise send one partition's locator to the other partition's host. When neither selector is pinned the provider explicitly requests `VersionStage=AWSCURRENT`; pinning `AWSPREVIOUS` is rejected outright, and the provider never falls back to `AWSPREVIOUS`, another stage, or a stale cached value. `AWSPREVIOUS` is a label AWS moves at every rotation, so pinning it would not name a version at all: it would make the alias a standing read of whatever the secret was last superseded by. To roll back a bad rotation, pin that version's `version_id` instead. Responses are accepted only when they are bounded JSON whose `ARN` matches the alias binding, whose version or stage matches the pinned selector, and which carry exactly one of `SecretString` or `SecretBinary` (base64) within the purpose byte bounds.

The data-plane endpoint is derived deterministically from each alias ARN as `secretsmanager.<region>.amazonaws.com`; nothing about the endpoint is request-derived or caller-selectable. Every identity and data-plane request is SigV4 signed (the unsigned `AssumeRoleWithWebIdentity` exchange excepted, which is unsigned by protocol) and travels through the standard egress controls, so operators must add the configured STS host and every derived `secretsmanager.<region>.amazonaws.com` host to `EGRESS_ALLOWED_HOSTS` or policy `egress.hosts`; nothing is auto-seeded into the allowlist. Session credentials are cached per profile with a safety margin before the STS expiration, resolved values are cached for at most `60` seconds keyed by provider, egress, and identity generation plus alias, purpose, and pinned selector, and rotation of `AWSCURRENT` therefore becomes visible after bounded cache expiry. A denied read purges the cache and re-authenticates through the same fixed identity source exactly once; resolutions are bounded by an admission semaphore and a total deadline and fail fast when saturated.

Alias IDs share one namespace with operator aliases (`CONNECTION_SECRET_ALIASES`), encrypted-local secrets (`CONNECTION_LOCAL_SECRET_KEYRING`), and other network providers such as `CONNECTION_VAULT_PROVIDER`; duplicate alias IDs across any provider are rejected at startup. Profile IDs must be unique within this provider. AWS aliases are resolved asynchronously at request time and are validated on first use, not at startup; the synchronous `resolve_blocking` path returns `SourceUnavailable` for AWS aliases, so connections that reference AWS secrets skip material validation during startup binding checks.

Configuration `Debug`, startup errors, metadata, and provider errors redact ARNs, endpoints, role ARNs, token roots, token files, JSON member names, and all credential material; observability carries only the bounded provider kind, outcome, safe reason, and latency. The JSON is an operator trust boundary: ordinary connection APIs accept and expose only alias IDs and safe labels. Alias metadata reports the AWS provider kind and configured alias record but has no secret reveal operation.

Grant the identity exactly one permission per secret, naming the full ARN. Add `kms:Decrypt` only when the secret is encrypted with a customer managed key, and only for that exact key. Placeholder values only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GreenGatewayReadOneSecret",
      "Effect": "Allow",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/billing-AbCdEf"
    },
    {
      "Sid": "GreenGatewayDecryptExactCustomerKey",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
      "Condition": {
        "StringEquals": {
          "kms:ViaService": "secretsmanager.us-east-1.amazonaws.com"
        }
      }
    }
  ]
}
```

Scope the web-identity trust policy to the exact OIDC provider, audience, and subject so no other workload can assume the role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GreenGatewayWorkloadIdentityOnly",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0123456789"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0123456789:aud": "sts.amazonaws.com",
          "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE0123456789:sub": "system:serviceaccount:greengateway:greengateway"
        }
      }
    }
  ]
}
```

### SCHEMA_MISMATCH_SIGNAL_THRESHOLD

Cumulative schema mismatch count that opens a `schema_mismatch` discovery signal for an endpoint.

Default: `5`.

Format and validation: must parse as an integer greater than `0`.

Trigger condition: when an endpoint's persisted rolling/cumulative `schema_mismatch_count` crosses this threshold from below. The signal target is the endpoint `(method, endpoint_template)`. Clean schema checks with `schema_mismatch:false` and requests where no conformance check was possible do not increment the counter and therefore cannot trigger the signal. Existing endpoints loaded from `DISCOVERY_SQLITE_PATH` with counts already at or above the threshold are treated as already past the crossing point, so startup does not backfill signals for old mismatches.

Minimum sample behavior: none beyond the threshold itself; this detector is count-based. Duplicate prevention is endpoint-scoped through `UNIQUE(signal_type, target_kind, target_key)`.

### ERROR_RATE_SPIKE_SIGNAL_THRESHOLD

Recent error-rate increase, as a ratio delta, that opens an `error_rate_spike` discovery signal for an endpoint.

Default: `0.40`, meaning a 40 percentage-point increase over baseline.

Format and validation: must parse as a finite number greater than `0.0` and less than or equal to `1.0`.

Trigger condition: status codes `400` through `599` count as errors. The aggregator keeps a fixed recent window of the last 20 observations for each endpoint and compares that recent error rate to the endpoint's cumulative baseline excluding that recent window. A signal opens when `recent_error_rate - baseline_error_rate >= ERROR_RATE_SPIKE_SIGNAL_THRESHOLD`. This is deterministic and O(1) per observation: the endpoint aggregate tracks cumulative error count plus a fixed in-memory recent error window.

Minimum sample behavior: evaluation waits until both the recent window and the baseline have at least 20 calls. An endpoint with one failed request, or with only a recent window and no baseline, cannot trigger this detector.

### PRINCIPAL_NEW_TO_ENDPOINT_SIGNAL_THRESHOLD

Prior distinct principal count required before a new authenticated principal/endpoint pair opens a `principal_new_to_endpoint` discovery signal.

Default: `1`.

Format and validation: must parse as an integer greater than `0`.

Trigger condition: an authenticated `actor.user_id` makes its first observed call to an endpoint that is not brand new and already had at least this many other distinct authenticated principals in `discovery_endpoint_principals`. The signal target kind is `principal_endpoint`, with identity including the method, endpoint template, and principal. Unauthenticated requests do not participate in this detector. A brand-new endpoint's first principal does not trigger this detector; that event is covered by `new_endpoint_seen` instead.

Minimum sample behavior: the configured prior-principal threshold is the floor. With the default of `1`, the second distinct authenticated principal on an existing endpoint triggers; with `2`, the third distinct principal triggers.

### VOLUME_OUTLIER_SIGNAL_THRESHOLD

Per-endpoint call-volume multiple that opens a `volume_outlier` discovery signal.

Default: `3.0`.

Format and validation: must parse as a finite number greater than `1.0`.

Trigger condition: the aggregator groups each endpoint's traffic into non-overlapping 20-call windows using the audit event timestamps. After a baseline of three completed windows is established, each completed 20-call window is compared to the endpoint's average baseline calls-per-second rate. A signal opens when the new window is at least `VOLUME_OUTLIER_SIGNAL_THRESHOLD` times faster than baseline (`direction:"increase"`) or at most `1 / VOLUME_OUTLIER_SIGNAL_THRESHOLD` of baseline (`direction:"decrease"`). Window duration is clamped to at least one second so same-second bursts are deterministic and finite.

Minimum sample behavior: evaluation starts only after three completed baseline windows, so a brand-new endpoint needs at least 80 calls in the current process before this detector can fire. The volume baseline is in-memory and re-establishes after restart; persisted aggregate counts are not scanned to recreate historical timing windows.

### RULE_SUGGESTION_BASELINE_WINDOW_HOURS

Lookback window, in hours, used by explicit rule suggestion generation for baseline allow candidates.

Default: `24`

Format and validation: must parse as an integer between `1` and `876000`.

Baseline behavior: generation reads discovered endpoint templates and routing contexts from `DISCOVERY_SQLITE_PATH` and role claims from `AUDIT_SQLITE_PATH` over this lookback window. For each observed `(method, endpoint_template, routing context, role)` combination that is not already covered by an active policy, it may persist an open `baseline_allow` suggestion whose proposed rule has `action:"allow"`, the discovered endpoint template as `path`, the observed method as its single method, and `principal.roles` containing that one role. Before persisting a direct-rule suggestion, GreenGateway compares the target with observed routing contexts, the active `UPSTREAM_URL`, and the complete configured `UPSTREAM_ROUTES` table, including routes that have not received traffic. Host-routed observations are never converted into host-blind direct rules: an existing host-bound `routes` rule with a permission granted to the observed role counts as covered, while an uncovered host-routed observation is skipped and reported in `skipped_host_routed_observations` for explicit route-policy authoring. Path-routed targets are always suppressed and reported in `skipped_path_routed_observations`, even when only one route currently matches, because the proposed direct rule cannot retain that dispatch binding after a future route-table change. A non-path-routed method/template with multiple observed origins, a changed legacy origin, or upstream evidence that no longer matches an active dispatch is reported in `skipped_ambiguous_routing_observations`; captured template segments such as `{id}` are checked for overlap with literal configured route prefixes.

Audit dependency: baseline role suggestions require audit history — `AUDIT_SQLITE_PATH` in standalone mode, and the durable PostgreSQL audit stream in cluster mode, where generation scans it instead and the evidence of a baseline suggestion records `source: "audit_postgres"` rather than `"audit_sqlite"`. Discovery tracks distinct `actor.user_id` values per endpoint but does not store role claims, so GreenGateway does not fall back to per-principal-id allow suggestions when audit history is unavailable. In that case explicit generation still evaluates anomaly-derived suggestions, but the baseline section is reported unavailable with `omitted_reason:"baseline role suggestions require AUDIT_SQLITE_PATH because role claims are only stored in audit history"`.

Unauthenticated and role-less traffic: baseline generation skips unauthenticated observations and authenticated observations whose audit actor has no role claims. It also skips observations whose audit payload says `policy_decision:"denied"` so denied probes do not become allow-rule candidates.

Matching limitation: audit history stores concrete request paths. Baseline generation uses the same `stateless_path_template` matching strategy as traffic endpoint audit enrichment, so it matches literal paths and immediate well-known identifier templates such as `/users/{id}`. Stateful learned slug templates such as `/catalog/{param}` are not reverse-mapped from raw audit paths.

Anomaly-derived behavior: generation reads open discovery signals only. Acknowledged and dismissed signals are ignored. Each open signal with a usable endpoint target creates a `signal_shadow_<signal_type>` suggestion unless the active direct policy already has a first-matching `deny` or `shadow` rule for that target. Endpoint signals currently remain method/template scoped, so the generator suppresses a signal-derived direct-rule suggestion when the endpoint has a host-routed context and reports it in `skipped_host_routed`; path-routed targets are reported in `skipped_path_routed`, and non-path-routed targets spanning multiple upstream origins are reported in `skipped_ambiguous_routing`. This prevents an endpoint signal from silently becoming a rule that spans virtual or path-selected upstreams. Other suggestions use `action:"shadow"` rather than `deny` because discovery signals are deterministic advisory signals with false-positive risk; operators can review the referenced signal id, signal type, explanation, and evidence in the suggestion before deciding whether to enforce a blocking rule.

### PAYLOAD_CAPTURE_ENABLED

Explicit opt-in for sampled request-shape capture into the discovery SQLite database.

Default: `false`, which disables payload-shape capture. With the default, the request path does not create payload capture handles, observation events do not include `payload_shape`, and fresh discovery databases do not create the payload capture tables.

Format and validation: must parse as a boolean. When set to `true` in standalone mode, `DISCOVERY_SQLITE_PATH` must also be set; otherwise startup fails closed with a clear configuration error because this feature has no output destination without the discovery database. In cluster mode (`STATE_BACKEND=postgres`) the destination is the shared discovery tables the projector writes, so no local path is needed (or accepted): captured shapes travel inside the `http.request_observed` event on the durable audit stream and are persisted by the projector.

When enabled and sampled, GreenGateway captures request shape only:

- Query string parameters: parameter names and a coarse `value_type` of `number` or `string`. Query parameter values are read only for this in-memory type guess and are never stored.
- JSON request bodies for proxied requests: top-level object keys only. The default buffered proxy mode captures after the complete bounded body has been read. The internal streaming mode uses a separate 64 KiB capture tee; if that sample is truncated, cancelled, or fails, the observation records `request_body_capture_status:"incomplete"` and omits `payload_shape` rather than inferring that omitted bytes or keys were absent. Nested object keys, array contents, and scalar values are not captured.

The capture output is attached to the existing `http.request_observed` audit event as `payload_shape` and is consumed by the existing SQLite discovery aggregator on the audit writer thread. SQLite writes and reservoir maintenance are not performed in the request handler.

Runtime schema conformance may reuse the same in-memory shape extraction for a request, but it does not cause `payload_shape` to be emitted or stored unless payload capture itself sampled that request.

The on-disk tables are created only when payload capture is enabled:

- `discovery_payload_shape_stats(method, endpoint_template, shape_observation_count, updated_at)`
- `discovery_payload_shape_samples(method, endpoint_template, sample_slot, observed_at, shape_hash, shape_json)`

Rows are keyed by the same `(method, endpoint_template)` concept used by `discovery_endpoint_aggregates`. Each endpoint keeps at most 128 `discovery_payload_shape_samples` rows in a deterministic reservoir. `shape_observation_count` is the number of sampled shapes offered to that endpoint reservoir, which can exceed the stored row count.

Each captured shape is bounded in size as well as in count. At most 64 distinct query parameters and 64 top-level JSON body keys are captured per request; a request with more is captured up to the cap and marked with `query_params_truncated` or `top_level_keys_truncated`, and a truncated capture never reports a schema-conformance mismatch, because it has not seen the whole request. The aggregator additionally refuses any `payload_shape` whose serialized form exceeds 16 KiB: the observation is still counted in `shape_observation_count`, but no sample row is stored. These bounds apply when a shape is captured; samples already stored by an earlier version are loaded unchanged.

`shape_json` has this shape:

```json
{
  "query_params": [
    {
      "name": "page",
      "redacted": false,
      "value_type": "number"
    },
    {
      "name_hash": "sha256:...",
      "redacted": true,
      "value_type": "string"
    }
  ],
  "json_body": {
    "top_level_keys": [
      {
        "name": "name",
        "redacted": false
      },
      {
        "name_hash": "sha256:...",
        "redacted": true
      }
    ]
  }
}
```

Sensitive-looking query parameter names and JSON top-level key names are not stored verbatim. A name is treated as sensitive when its normalized ASCII-alphanumeric form contains one of these markers: `password`, `passwd`, `pwd`, `ssn`, `socialsecurity`, `token`, `secret`, `apikey`, `credential`, `creditcard`, `cardnumber`, `authorization`, `jwt`, or `bearer`. For those names, GreenGateway stores `redacted: true` and `name_hash`, a `sha256:` hash of the normalized name. It omits `name`.

Under every configuration, payload capture never stores query parameter values, JSON values, full request bodies, response bodies, non-JSON body bytes, nested JSON structure, array contents, headers, cookies, credentials, or authorization decisions beyond the existing observation event fields.

### PAYLOAD_CAPTURE_SAMPLE_RATE

Deterministic per-request sample rate for payload-shape capture.

Default: `0.10`.

Format and validation: must parse as a finite `f64` greater than or equal to `0.0` and less than `1.0`. Values of `1.0`, negative numbers, `NaN`, and infinity are rejected. The upper bound is intentionally exclusive so enabling payload capture cannot become exhaustive.

Sampling uses a canonical JSON SHA-256 hash of the request id, method, and path, then compares that hash to the configured rate. Query parameter values and body bytes are not part of the sampling seed. A rate of `0.0` creates no payload shape samples even when `PAYLOAD_CAPTURE_ENABLED=true`.

### OPENAPI_SPEC_PATH

Optional local OpenAPI 3.x JSON or YAML document path for schema coverage in the legacy single `UPSTREAM_URL` mode.

Default: empty, which disables schema coverage unless one or more `UPSTREAM_ROUTES` entries set `openapi_spec_path`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, the gateway verifies that the file exists and parses as an OpenAPI 3.x document during startup. Invalid paths, unsupported OpenAPI versions, malformed JSON, or malformed YAML fail startup with an aggregated `OpenAPI schema configuration is invalid` error.

The schema coverage API is `GET /v1{ADMIN_PREFIX}/schema/coverage`. It requires a loaded RBAC policy and the `admin:schema:read` permission. Missing authentication returns `401 Unauthorized`, and a principal without `admin:schema:read` returns `403 Forbidden`.

When a spec and `DISCOVERY_SQLITE_PATH` are both configured, the response is:

```json
{
  "spec_configured": true,
  "discovery_configured": true,
  "undocumented_endpoints": [
    {
      "method": "GET",
      "endpoint_template": "/internal/health"
    }
  ],
  "unused_operations": [
    {
      "method": "PATCH",
      "path_template": "/users/{userId}",
      "operation_id": "updateUser",
      "summary": "Update a user",
      "source": "/etc/greengateway/openapi.yaml"
    }
  ]
}
```

`undocumented_endpoints` are observed `(method, endpoint_template)` pairs from `discovery_endpoint_aggregates` with no matching spec operation. `unused_operations` are OpenAPI operations with no matching observed endpoint. Matching compares normalized path shapes: any whole path segment shaped like `{anything}` on either side is treated as the same wildcard marker, so `/users/{userId}` matches the discovery template `/users/{id}`. Segment counts must still match; `/reports/{id}/summary` does not match `/reports/{id}/summary/details`.

For request-time conformance, the OpenAPI parser also reads inline operation/path query parameters and inline `application/json` object request-body schemas. It checks required query parameter names and required top-level JSON body keys. It does not resolve `$ref`, validate nested schemas, validate scalar value types, or enforce optional fields.

When no spec is configured, the endpoint returns `404 Not Found` with `{"error":"schema coverage requires OPENAPI_SPEC_PATH or UPSTREAM_ROUTES[].openapi_spec_path to be configured","spec_configured":false}`. When no discovery database path is configured, it returns `503 Service Unavailable` with `{"error":"schema coverage requires DISCOVERY_SQLITE_PATH to be configured","discovery_configured":false}`.

The inferred request schema API is `GET /v1{ADMIN_PREFIX}/schema/inferred?method=POST&endpoint_template=/users/{id}`. It uses query parameters, not path captures, so endpoint templates containing `/` can be passed directly with normal query-string encoding. It requires a loaded RBAC policy and the same `admin:schema:read` permission as schema coverage. Missing authentication returns `401 Unauthorized`, and a principal without `admin:schema:read` returns `403 Forbidden`.

The endpoint reads the payload-shape reservoir in `discovery_payload_shape_samples` and returns a per-`(method, endpoint_template)` inferred request shape.

When `PAYLOAD_CAPTURE_ENABLED=true` and captured samples exist for the requested endpoint, the response is:

```json
{
  "method": "POST",
  "endpoint_template": "/users/{id}",
  "sample_count": 2,
  "required_threshold": 0.95,
  "query_params": [
    {
      "name": "page",
      "redacted": false,
      "present_count": 2,
      "frequency": 1.0,
      "required": true,
      "value_types": [
        { "value_type": "number", "count": 2 }
      ]
    },
    {
      "name": "search",
      "redacted": false,
      "present_count": 1,
      "frequency": 0.5,
      "required": false,
      "value_types": [
        { "value_type": "string", "count": 1 }
      ]
    }
  ],
  "json_body_keys": [
    {
      "name": "display_name",
      "redacted": false,
      "present_count": 2,
      "frequency": 1.0,
      "required": true
    },
    {
      "name_hash": "sha256:...",
      "redacted": true,
      "present_count": 1,
      "frequency": 0.5,
      "required": false
    }
  ]
}
```

`sample_count` is the number of stored reservoir samples used for the inference, not a claim that the endpoint has only received that many requests. `present_count` is the number of those samples containing the query parameter or JSON top-level key, and `frequency` is `present_count / sample_count`. Query parameter `value_types` reuse the coarse `number` or `string` values captured by payload shape sampling. JSON body key entries do not include value types because payload capture records top-level key presence only, not JSON values or nested structure.

A field is inferred as `required: true` when its frequency is at least `0.95`; otherwise it is reported as optional with `required: false`. This high threshold is intentionally conservative because payload capture is sampled and bounded, so a field should be present in nearly every retained sample before the gateway labels it likely required.

Redacted field names remain redacted. If payload capture stored only `name_hash` for a sensitive-looking query parameter or JSON top-level key, the inferred schema response also uses only `name_hash` with `redacted: true` and never reconstructs or guesses the original name.

If `PAYLOAD_CAPTURE_ENABLED` is not enabled, the endpoint returns `404 Not Found` with `{"error":"inferred schema requires PAYLOAD_CAPTURE_ENABLED=true","payload_capture_configured":false}`. If payload capture is enabled but `DISCOVERY_SQLITE_PATH` is unavailable, it returns `503 Service Unavailable` with `{"error":"inferred schema requires DISCOVERY_SQLITE_PATH to be configured","discovery_configured":false}`. If payload capture is enabled and the discovery database exists but there are no captured samples for the requested endpoint, it returns `404 Not Found` with `{"error":"inferred schema has no captured payload samples for method and endpoint_template","schema_inferred":false}`.

Runtime conformance emits `schema_mismatch` on `http.request_observed` only when a check was possible. With a configured OpenAPI spec, matching operations use the spec shape and non-matching data-plane requests are flagged as undocumented with `schema_mismatch: true`. Without a configured spec, GreenGateway falls back to the inferred schema only when payload capture is enabled, a matching discovered endpoint has an inferred schema, and `sample_count >= 5`. Lower-sample inferred schemas are treated as insufficient evidence and leave `schema_mismatch` absent rather than `false`.

Conformance checks are intentionally conservative: a mismatch means a required query parameter or required top-level JSON body key is missing, or a request is undocumented while a spec is configured. Unexpected extra query parameters or JSON keys are not flagged, because many backends tolerate additive inputs and flagging them would create noisy false positives. Gateway-owned routes such as `/health`, `/version`, `/metrics`, `ADMIN_PREFIX`, and `/v1{ADMIN_PREFIX}` are skipped so admin polling does not pollute upstream schema inventory.

The request-time path avoids unnecessary body work. If no OpenAPI spec match, undocumented-spec check, or sufficiently sampled inferred schema is available, no conformance body-shape handle is attached. If the selected expected shape only has required query parameters, no JSON body parsing is requested. JSON body top-level key extraction runs only when a selected schema has required body keys, and it reuses the same shape-capture handle as payload capture when payload capture sampled the same request.

Remote OpenAPI URLs are intentionally not supported by this setting. Runtime URL fetching must go through the SSRF-hardened egress client and is future work.

Principal directory admin API: when `PRINCIPAL_SQLITE_PATH` is set, `GET /v1{ADMIN_PREFIX}/principals` lists authenticated principals and `GET /v1{ADMIN_PREFIX}/principal` returns one principal detail. Both routes require `admin:principals:read`. They return `401 Unauthorized` with no authenticated principal, `404 Not Found` with `{"error":"principal directory requires POLICY_FILE to be configured"}` when RBAC is not configured, and `403 Forbidden` when the principal lacks the route permission. If `PRINCIPAL_SQLITE_PATH` is unset, they return `404 Not Found` with `{"error":"principal directory requires PRINCIPAL_SQLITE_PATH to be configured"}` after authentication and permission checks.

`GET /v1{ADMIN_PREFIX}/principals` supports `issuer`, `auth_method`, `principal_type=human|service`, `last_seen_after`, `last_seen_before`, `limit`, and `cursor`. `issuer` is an exact match and `issuer=` matches the empty no-issuer sentinel. Timestamp filters must be RFC 3339. `principal_type=service` maps to `auth_method=service_token`; `principal_type=human` maps to `auth_method` in `bearer` or `cookie`, which is a simple operational grouping rather than proof that a JWT caller is a human. Results sort by `last_seen` descending with stable identity-key tie-breakers and use the same opaque limit-plus-cursor pagination shape as traffic inventory: `{"principals":[...],"next_cursor":...,"anonymous_request_count":N}`. `anonymous_request_count` counts `http.request_observed` audit rows with no actor over the same `last_seen_after`/`last_seen_before` window when `AUDIT_SQLITE_PATH` is configured; otherwise it is `0`.

Principal detail uses query parameters for the full identity key: `GET /v1{ADMIN_PREFIX}/principal?subject=user-123&issuer=&auth_method=bearer`. The response contains `principal` for the directory row, `endpoints_touched` aggregated from recent audit events for the same subject, issuer, and auth method, `rules_hit` for distinct matched rule ids in that same bounded audit scan, `anomaly_history` for recent `principal_new_to_endpoint` discovery signals involving that subject, and `tools_called: []`. Tool-call telemetry now feeds the traffic inventory path, but this principal-detail field is not yet wired to it. New audit actors carry `issuer` and `auth_mode`; legacy audit rows without an issuer are treated as the empty issuer boundary for backward compatibility.

Traffic inventory admin API: when `DISCOVERY_SQLITE_PATH` is set, `GET /v1{ADMIN_PREFIX}/traffic/endpoints` lists discovered endpoint aggregates, and `GET /v1{ADMIN_PREFIX}/traffic/endpoint` returns one endpoint detail. These read routes require a principal with the dedicated `admin:traffic:read` permission. `POST /v1{ADMIN_PREFIX}/traffic/endpoints/review` marks or clears an endpoint review flag and requires `admin:traffic:write`. All traffic admin routes return `401 Unauthorized` with no authenticated principal, return `404 Not Found` with `{"error":"traffic endpoint inventory requires POLICY_FILE to be configured"}` when RBAC is not configured, and return `403 Forbidden` when the principal lacks the route's required permission. If `DISCOVERY_SQLITE_PATH` is unset, the traffic inventory routes return `404 Not Found` with `{"error":"traffic endpoint inventory requires DISCOVERY_SQLITE_PATH to be configured"}` after authentication and permission checks.

`GET /v1{ADMIN_PREFIX}/traffic/endpoints` supports `method`, `endpoint_template` substring, `endpoint_template_prefix`, `first_seen_after`, `first_seen_before`, `last_seen_after`, `last_seen_before`, `min_call_count`, `new_since_hours`, `is_new=true|false`, `reviewed=true|false`, `covered_by_rule=true|false`, `sort`, `limit`, and `cursor` query parameters. Timestamp filters must be RFC 3339. `new_since_hours` defaults to `24`, making "new since yesterday" the default `is_new` window. `sort` accepts `last_seen`, `call_count`, or `first_seen`; all sorts are descending with a deterministic method/template tie-breaker, and the default is `last_seen`. Pagination follows the admin API limit-plus-cursor pattern: the response has `{"endpoints":[...],"next_cursor":...}`, and clients pass the returned cursor back as `cursor` with the same filters and sort. Each endpoint entry includes `method`, `endpoint_template`, `first_seen`, `last_seen`, `call_count`, `schema_mismatch_count`, `distinct_principal_count`, `is_new`, `reviewed`, `reviewed_at`, `reviewed_by`, `review_revision`, `covered_by_rule`, `coverage_scope`, `routing_context_known`, nullable `routing_context_known_since`, `routing_contexts`, `latency` count and p50/p95/p99 milliseconds, and exact per-status counts. Each routing context includes the configured route host/path prefix, nullable upstream origin (`null` means classified traffic without proxy dispatch), first/last seen timestamps, call and distinct-principal counts, and its own coverage scope.

`schema_mismatch_count` is persisted in `discovery_endpoint_aggregates` and increments only for observed requests whose `http.request_observed` payload has `schema_mismatch: true`. Clean checks with `schema_mismatch: false` and requests where no check was possible do not increment it. The same field is returned on the endpoint detail object from `GET /v1{ADMIN_PREFIX}/traffic/endpoint`.

Lifecycle fields remain independent. `is_new` is computed from `first_seen` and the `new_since_hours` window; it is not persisted. `reviewed`, `reviewed_at`, and `reviewed_by` are persisted in `discovery_endpoint_reviews`, keyed by `(method, endpoint_template)`, and the endpoint reports that row's `review_revision` (`0` only while the endpoint has never been reviewed). Clearing a review keeps the row — it nulls `reviewed_at` and increments the revision — so an endpoint's review revision only ever increases and an `If-Match` from a cleared review can never match a later one. A routing context first seen after the stored review timestamp makes the live endpoint response unreviewed until the operator reviews it again. Coverage is computed live from the active RBAC policy and reported as `coverage_scope: "unknown"|"none"|"principal"|"endpoint"|"mixed"`. `unknown` means routing classification does not cover the endpoint's full retained history, and the UI disables direct-rule creation. An unconstrained matching direct rule is endpoint-wide; a principal-constrained match is principal-scoped rather than being promoted through a synthetic principal. Host-routed contexts also require the matching host-bound `routes` rule and at least one role that grants its permission. `mixed` means routing contexts have different scopes. The legacy `covered_by_rule` boolean is true only for endpoint-wide coverage, so `covered_by_rule=false` includes unknown, principal-scoped, and mixed endpoints instead of hiding their remaining gaps. Manual rule creation from traffic inventory is also fail closed: it is disabled for unknown, host-routed, path-routed, missing, or ambiguous routing contexts. For exactly one trusted non-routed HTTP context, the editor prefills and preserves an immutable `contextless` or `legacy` dispatch matcher when creating the rule.

Endpoint detail uses query parameters rather than a wildcard path route so endpoint templates containing `/` do not require path-segment encoding: `GET /v1{ADMIN_PREFIX}/traffic/endpoint?method=GET&endpoint_template=/users/{id}`. The response contains `endpoint` for the aggregate row, `principals` for a bounded per-principal page, and `audit` for optional raw-event enrichment. For principals that have both `admin:traffic:read` and `admin:signals:read`, the endpoint object on both the list and detail responses includes `open_signals`, shaped as `{"count":N,"signal_types":[...]}`, for open endpoint-scoped discovery signals on that `(method, endpoint_template)`. For principals with only `admin:traffic:read`, `open_signals` is omitted entirely rather than returned as `null` or an empty summary. Principal pagination uses `principal_limit` and `principal_cursor`, with a default limit of 50 and the same maximum as the audit query API. `from`, `to`, `bucket=hour|day`, `events_limit`, and `events_before_id` control audit-derived time-series and recent-event enrichment.

`POST /v1{ADMIN_PREFIX}/traffic/endpoints/review` accepts `{"method":"GET","endpoint_template":"/users/{id}","reviewed":true}` to mark an endpoint reviewed and the same body with `"reviewed":false` to clear the mark. The endpoint must already exist in the discovery aggregate table or the request returns `404 Not Found`. On success, the response is `{"reviewed":true,"reviewed_at":"<RFC3339>","reviewed_by":"<principal user_id>","revision":<n>}` when marked or `{"reviewed":false,"reviewed_at":null,"reviewed_by":null,"revision":<n>}` when cleared, where a clear's `<n>` is one higher than the review it cleared (`0` is reported only for an endpoint that has never been reviewed). Successful review changes emit a `traffic.endpoint_review_changed` audit event with the acting principal and the method/template payload. The route also accepts an optional expected revision (see the next paragraph): `If-Match: 0` marks an endpoint only while it is still unreviewed, `If-Match: <n>` marks or clears only the review row at revision `n`, and no header replaces whatever is stored.

Lifecycle revisions and conditional transitions. Every signal, rule suggestion, and endpoint review row carries a `revision` that starts at `1` and increases by one each time the row changes, and every read returns it. A lifecycle write is one conditional statement: the row must still be in one of the states the route transitions out of (`open` for signal acknowledge and for suggestion accept and dismiss; `open` or `acknowledged` for signal dismiss, so an acknowledged signal can still be cleared) and, when the caller names an expected revision, still at that revision. A caller that names one sends it in `If-Match` — bare (`If-Match: 3`) or quoted (`If-Match: "3"`), the value a read returned — except on the suggestion accept route, where `If-Match` is already the policy ETag and the expected suggestion revision travels in `X-GreenGateway-Suggestion-Revision` instead. A malformed value, or more than one of either header, is `400 Bad Request`. A write whose predicate no longer holds changes nothing and returns `409 Conflict` with `{"error":...,"reason":...,"<signal|suggestion|review>":{...the row as it now stands...}}`; the stable `reason` values are `signal_not_open`, `signal_revision_mismatch`, `suggestion_not_open`, `suggestion_revision_mismatch`, and `review_revision_mismatch`. Omitting the header still keeps the state predicate, so acknowledging an already-acknowledged signal or dismissing an already-dismissed signal or suggestion is a `409` carrying the current row rather than a silent second success. This applies in both modes; in cluster mode it is what makes two administrators on two replicas produce exactly one winner (see [the PostgreSQL deployment guide](deployment/postgres.md), "Discovery lifecycle workflows").

Signals admin API: when `DISCOVERY_SQLITE_PATH` is set, `GET /v1{ADMIN_PREFIX}/signals` lists discovery signals. It requires `admin:signals:read`. `POST /v1{ADMIN_PREFIX}/signals/{id}/acknowledge` moves a signal to `acknowledged`, and `POST /v1{ADMIN_PREFIX}/signals/{id}/dismiss` moves a signal to `dismissed`; both require `admin:signals:write`. All signal admin routes return `401 Unauthorized` with no authenticated principal, return `404 Not Found` with `{"error":"signals API requires POLICY_FILE to be configured"}` when RBAC is not configured, and return `403 Forbidden` when the principal lacks the route's required permission. If `DISCOVERY_SQLITE_PATH` is unset, the signal routes return `404 Not Found` with `{"error":"signals API requires DISCOVERY_SQLITE_PATH to be configured"}` after authentication and permission checks.

`GET /v1{ADMIN_PREFIX}/signals` supports `state=open|acknowledged|dismissed`, `signal_type`, `target_kind`, `target_key`, `limit`, and `cursor`. Results are ordered by `created_at` descending with `id` as a deterministic tie-breaker. Pagination follows the same limit-plus-cursor pattern as traffic inventory: the response has `{"signals":[...],"next_cursor":...}`, and clients pass the returned cursor back as `cursor` with the same filters. Endpoint-scoped target filters use `target_kind=endpoint` and `target_key="<METHOD> <endpoint_template>"`, for example `target_key=GET /users/{id}`.

Each signal response includes `id`, `signal_type`, `target`, `explanation`, `evidence`, `state`, `created_at`, `updated_at`, `transitioned_at`, `transitioned_by`, and `revision`. `target` is generic and currently uses `{"kind":"endpoint","identity":{"method":"GET","endpoint_template":"/users/{id}"}}` for endpoint-scoped signals. `evidence` is structured JSON. For `new_endpoint_seen`, evidence includes `first_seen`, `initial_call_count`, `initial_status`, `initial_latency_ms`, and nullable `initial_principal`. `explanation` is a human-readable sentence that names the endpoint and explains why the signal fired.

Signal rows are persisted in `discovery_signals`. The table stores `id TEXT`, `signal_type TEXT`, `target_kind TEXT`, `target_key TEXT`, `target_identity_json TEXT`, `explanation TEXT`, `evidence_json TEXT`, `state TEXT`, `created_at TEXT`, `updated_at TEXT`, nullable `transitioned_at TEXT`, nullable `transitioned_by TEXT`, and `revision INTEGER NOT NULL DEFAULT 1`. `(signal_type, target_kind, target_key)` is unique, so a detector cannot create duplicate lifecycle records for the same logical target. New persisted signals are pushed to `/v1{ADMIN_PREFIX}/events/stream` as `signal.opened` SSE events. The SSE data is an audit-event envelope whose payload contains `id`, `signal_type`, `target`, `explanation`, `evidence`, `state`, `created_at`, `updated_at`, `transitioned_at`, and `transitioned_by`. Successful lifecycle transitions emit a `signal.lifecycle_changed` audit event with the acting principal and signal target payload; the same event is available on the SSE stream.

Suggestions admin API: when `DISCOVERY_SQLITE_PATH` is set, `GET /v1{ADMIN_PREFIX}/suggestions` lists persisted rule suggestions. It requires `admin:suggestions:read`. `POST /v1{ADMIN_PREFIX}/suggestions/generate` runs the explicit off-hot-path suggestion generator and persists newly discovered suggestions; it requires `admin:suggestions:write`. `POST /v1{ADMIN_PREFIX}/suggestions/{id}/accept` creates a real direct firewall rule from the suggestion and then moves the suggestion to `accepted`; it requires both `admin:suggestions:write` and `admin:policy:write`. `POST /v1{ADMIN_PREFIX}/suggestions/{id}/dismiss` moves a suggestion to `dismissed`; it requires `admin:suggestions:write` only. All suggestion admin routes return `401 Unauthorized` with no authenticated principal, return `404 Not Found` with `{"error":"suggestions API requires POLICY_FILE to be configured"}` when RBAC is not configured, and return `403 Forbidden` when the principal lacks the route's required permission. If `DISCOVERY_SQLITE_PATH` is unset, the suggestion routes return `404 Not Found` with `{"error":"suggestions API requires DISCOVERY_SQLITE_PATH to be configured"}` after authentication and permission checks.

`GET /v1{ADMIN_PREFIX}/suggestions` supports `state=open|dismissed|accepted`, `suggestion_type`, `limit`, and `cursor`. Results are ordered by `created_at` descending with `id` as a deterministic tie-breaker. Pagination follows the same limit-plus-cursor pattern as signals: the response has `{"suggestions":[...],"next_cursor":...}`, and clients pass the returned cursor back as `cursor` with the same filters.

Each suggestion response includes `id`, `suggestion_type`, `method`, `path_pattern`, `principal_key`, `rationale`, `evidence`, `proposed_rule`, `state`, `created_at`, `updated_at`, `transitioned_at`, `transitioned_by`, `revision`, and optional `source_signal_id`. `proposed_rule` is the structured rule that would be accepted, not an opaque serialized blob: it contains `methods`, `path`, `principal` constraints (`roles`, `issuers`, `auth_methods`, and `principal_ids`), `action`, and an `id` only if the persisted proposal already supplied one. Generated baseline suggestions normally propose `action:"allow"` with one observed role, while signal-derived suggestions normally propose `action:"shadow"`.

Suggestion freshness is explicit. Listing does not recompute suggestions. A list response reflects traffic, audit history, discovery signals, and the active policy as of the most recent successful `POST /v1{ADMIN_PREFIX}/suggestions/generate` call. Generation is idempotent for the same logical target because persisted suggestions are unique on `(suggestion_type, method, path_pattern, principal_key)`. Re-running generation may add new suggestions for newly observed traffic or newly opened signals, but it does not update already persisted suggestion rows or reopen dismissed/accepted suggestions.

`POST /v1{ADMIN_PREFIX}/suggestions/generate` returns the generator run summary: `inserted_count`, `baseline`, and `anomaly`. `baseline` reports whether audit-backed role suggestions were available, how many role/endpoint/context observations were found, how many were skipped because policy already covered them, `skipped_host_routed_observations`, `skipped_path_routed_observations`, `skipped_ambiguous_routing_observations`, `skipped_unknown_routing_context_observations`, skipped unauthenticated/no-role/denied observations, scanned audit rows, and whether the 100,000-row scan cap truncated the run. `anomaly` reports open signal count, policy/unusable-target skip counts, `skipped_host_routed`, `skipped_path_routed`, `skipped_ambiguous_routing`, and `skipped_unknown_routing_context`. Baseline suggestions require `AUDIT_SQLITE_PATH`; without it, generation still evaluates anomaly-derived suggestions and returns `baseline.available=false` with the documented `omitted_reason`.

Accepting a suggestion is intentionally a policy-write action, not just a suggestion lifecycle action. The caller must hold `admin:suggestions:write` to operate on the suggestion record and `admin:policy:write` because accepting persists a real direct firewall rule into `POLICY_FILE`. Both accept and dismiss require the suggestion to currently be in the `open` state; a suggestion that was already accepted or dismissed returns `409 Conflict` with `reason: "suggestion_not_open"` and the current suggestion row (the shape described under "Lifecycle revisions and conditional transitions" above), and its stored state/transition metadata is left unchanged. Accept also takes an optional `X-GreenGateway-Suggestion-Revision` — `If-Match` on this route is the policy ETag — and refuses with `reason: "suggestion_revision_mismatch"` when the row moved since the caller read it. Before any policy write, accept revalidates the target against current routing inventory, the active legacy upstream, and the configured route table. Host-routed targets, all path-routed targets, non-path-routed targets spanning multiple upstream origins, and suggestions whose evidence predates trusted classification return `409 Conflict` and remain open. For a safe HTTP target, acceptance ignores any stored advisory copy of routing metadata and recomputes an immutable `dispatch` matcher from current trusted state: `{"kind":"contextless"}` for classified traffic without proxy dispatch, or `{"kind":"legacy","upstream_origin":"https://api.example.test"}` for the active fallback. Runtime matching also requires legacy dispatch to have no host or path route identity, so a later route-table change cannot extend an accepted fallback rule to a routed upstream even when the origin is unchanged. Accept otherwise uses the same internal rule-create path as `POST /v1{ADMIN_PREFIX}/policy/rules`: the request must include an exact `If-Match` header for the current policy ETag, missing `If-Match` returns `428 Precondition Required`, a stale or non-matching ETag returns `412 Precondition Failed`, duplicate supplied rule ids return `400 Bad Request`, and full policy validation runs before persistence. On success, the response is `201 Created` with the new policy `ETag` and `{"suggestion":{...accepted suggestion...},"rule":{...created rule...}}`. If the policy changed after the suggestion was reviewed, the stale ETag failure is surfaced exactly as the policy rule API would surface it and the suggestion remains `open`; callers should refetch policy and suggestions before retrying. A successful accept emits the normal `policy.changed` audit event with `diff_summary.action="rule_created"` and also emits `suggestion.lifecycle_changed` for the `accepted` transition. In cluster mode the rule, its version and history row, the security-revision advance, and the suggestion's transition are one PostgreSQL transaction, and the two audit events are emitted after it commits; see [the PostgreSQL deployment guide](deployment/postgres.md), "Discovery lifecycle workflows". Standalone mode keeps its sequence — validate, write `POLICY_FILE`, then the conditional transition — so if that transition were ever refused the rule stays and the response is `409 Conflict` with `reason: "suggestion_transitioned_concurrently"` and the new policy `ETag`.

Dismiss does not mutate policy, so it does not require `admin:policy:write` and does not require a policy ETag. On success, `POST /v1{ADMIN_PREFIX}/suggestions/{id}/dismiss` returns the transitioned suggestion with `state:"dismissed"`, `transitioned_at`, `transitioned_by`, and its incremented `revision`, and emits `suggestion.lifecycle_changed`. `If-Match` on this route is the optional expected suggestion revision, not a policy ETag. Unknown suggestion ids return `404 Not Found`.

The detail route can enrich from `AUDIT_SQLITE_PATH` when it is also configured. If `AUDIT_SQLITE_PATH` is unset, the detail response still returns aggregate and principal data and marks `audit.available=false`; it omits `time_series` and `recent_events`. When audit enrichment is available, `audit.time_series_truncated` and `audit.recent_events_scan_truncated` are each `true` if their respective scan (time-series counting and recent-event listing run as two independent bounded scans) hit the 100,000-row safety cap after SQL-level method/path narrowing. Audit enrichment reverse-maps raw concrete audit paths to endpoint templates by re-running the stateless path templater and requiring an exact template match. This correctly handles literal paths and immediate well-known identifier templates such as `/users/{id}`. It does not reconstruct statefully learned slug/cardinality templates such as `/catalog/{param}`, because the discovery aggregator's live learner state is not stored in the audit database.

Audit query, audit live-tail, and status admin routes require a configured `POLICY_FILE`, matching every other admin subsystem. `GET /v1{ADMIN_PREFIX}/audit`, `GET /v1{ADMIN_PREFIX}/events/stream`, and `GET /v1{ADMIN_PREFIX}/status` return `401 Unauthorized` with no authenticated principal, return `404 Not Found` with `{"error":"audit API requires POLICY_FILE to be configured"}` / `{"error":"status API requires POLICY_FILE to be configured"}` when RBAC is not configured, and return `403 Forbidden` when the principal lacks the route's required permission (`admin:audit:read` for the query endpoint, `admin:audit:stream` for the live-tail SSE endpoint, `admin:status:read` for the status endpoint). This replaced an earlier, separate mechanism that checked only for a role literally named `admin` on the principal with no policy file required at all — see the CHANGELOG for upgrade guidance if you relied on that behavior.

The cluster status API is gated on its own permission, `admin:cluster:read` (issue #241, PR 14). `GET /v1{ADMIN_PREFIX}/cluster` reports the deployment's state -- mode, readiness state and reason, schema compatibility, replica and version counts, this replica's security revisions and their lag, the reconciler's health, the discovery projector's checkpoint and lag, the maintenance singleton's job ledger, the audit queue, and the database pool -- and `GET /v1{ADMIN_PREFIX}/cluster/replicas` returns the membership roster, live members first. Both are read-only; there are no mutation routes on this surface. Both return `401 Unauthorized` with no authenticated principal, `404 Not Found` with `{"error":"cluster status API requires POLICY_FILE to be configured"}` when RBAC is not configured, and `403 Forbidden` when the principal does not hold `admin:cluster:read`. The permission is deliberately not `admin:status:read`: `/status` describes this process's configuration, while these two describe the deployment's topology -- how many replicas exist, which are live, what versions they run, and which holds the maintenance lease -- so the two are granted separately.

`GET /v1{ADMIN_PREFIX}/cluster` returns one object. `mode` is `cluster` or `standalone`; `ready` is whether `/readyz` would answer `200` right now; `state` is `ready`, `degraded`, `draining`, or `not_ready`; and `reason` is `null` or one string from a fixed vocabulary. `not_ready` and `draining` carry `/readyz`'s own reason verbatim (`starting`, `draining`, `config_fingerprint_mismatch`, `storage_unavailable`, `schema_incompatible`, `instance_lease_invalid`, `security_revision_not_compiled`, `required_upstream_unavailable`) because both surfaces run the same chain in the same order and so cannot disagree; `degraded` means the replica is serving and one of four further conditions holds, reported worst-first as `replicas_unavailable`, `security_revision_lagging`, `maintenance_job_failing`, or `member_error_reported`. The sections beneath are `schema` (`current_version`, `binary_min`, `binary_max`, `compatible`), `replicas` (`ready`, `total`), `binary_versions` (an array of `version`/`count` over live members), `local` (`instance_id`, `boot_id`, `boot_age_secs`, `hostname`, `instance_ready`, `draining`, `compiled_security_revision`, `observed_security_revision`, `revision_lag`), `reconcile` (`last_pass_age_secs`, `failures_total`), `projector` (`fence`, `checkpoint_position`, `stream_head`, `lag_events`, `leader_present`, `last_flush_age_secs`), `leader_tasks` (an array of `name`, `held_by_this_instance`, `fence`, `last_success_age_secs`, `last_failure_code`), `audit` (`queue_depth`, `queue_capacity`, `oldest_age_secs`, `dropped_total`), and `pools` (`database`, itself `size`, `available`, `waiting`, `timeouts_total`). What each reason means and what to do about it is in [the PostgreSQL deployment guide](deployment/postgres.md#readiness-and-status).

`GET /v1{ADMIN_PREFIX}/cluster/replicas` returns `{"replicas":[...]}`: one entry per `cluster_members` row, live members first and, within each group, in the order the store returned them. Each entry carries `instance_id`, `boot_id`, `binary_version`, `schema_version_min`, `schema_version_max`, `document_version_min`, `document_version_max`, `fingerprint`, `started_at`, `last_heartbeat_at`, `heartbeat_age_secs`, `ready_at`, `draining_at`, `compiled_security_revision`, `observed_security_revision`, `last_error_code`, and `live`.

Standalone mode serves both routes with the same shapes: `mode` is `standalone`, the roster is this process alone, and the sections that describe a cluster (`projector`, `leader_tasks`, `pools.database`, `schema.current_version`) are `null` rather than invented. In cluster mode a section whose read did not answer is `null` for the same reason, and the response's `reason` says so (`replicas_unavailable`). `null` therefore always means "not reported", never "zero" -- and `schema.compatible` is `true` when `current_version` is `null`, because a ledger this replica could not read is not evidence of disagreement.

Neither route ever returns a DSN, a database host, user or name, an IP address, policy, tool or secret content, query text, or a raw error string. Instance and boot identifiers are UUIDs and are returned. Every other string field is checked against the shape its column is supposed to have -- a semantic version, 64 lowercase hex characters, a UTC timestamp, one of the repository classifier's error kinds, one of the singleton's job names -- and a value that does not match is replaced whole by `unknown` (or, for a timestamp, by `null`) rather than filtered, because filtering a `postgres://user:pass@10.0.0.5:5432/db` still leaves the address behind. Hostnames are the one opt-in exception, `local.hostname` under `CLUSTER_STATUS_EXPOSE_HOSTNAMES`, described with that setting below.

### POLICY_FILE

Optional RBAC policy JSON file path.

Default: empty, which means no policy file is loaded.

A copyable starter policy for real deployments is available at `docs/examples/policy.starter.json` — read [docs/examples/policy.starter.README.md](examples/policy.starter.README.md) first, since `default_action: "allow"` means unmatched routes pass through unauthenticated/unauthorized until you add `routes` rules.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. The policy loader reads the file as JSON, validates that `schema_version` starts with `0.`, warns on unknown top-level keys, and rejects invalid policy documents. Every `routes[].path_prefix` must be an absolute path prefix beginning with `/`; empty or relative prefixes are rejected before startup, validation, replacement, or persistence.

Route rules in a policy's `routes` array are evaluated in document order. The first rule whose `path_prefix` matches the request path, whose `methods` match the request method, and whose optional `hosts` list matches the request host determines the required permission. `hosts` entries are exact hostnames without ports and match case-insensitively; ports in the request `Host` header are ignored. Duplicate hosts in one rule are rejected case-insensitively.

When proxy fallback selects a host-qualified `UPSTREAM_ROUTES` entry, authorization requires a matching policy route with a non-empty `hosts` list. Gateway-owned handlers such as `/mcp`, probes, and admin routes are not proxy fallbacks and keep their normal path policy even when their host and path would match an upstream entry. A route rule with omitted or empty `hosts` cannot authorize the fallback request. Direct firewall `deny` rules still apply, but direct `allow` and `shadow` rules and `default_action: "allow"` cannot bypass this binding. A first-matching direct shadow still emits `authz.would_deny` before host-route evaluation. If no matching host-bound route exists, the gateway returns `403 Forbidden` and audits `reason: "host_policy_required"` together with the selected upstream host, path prefix, and origin.

Direct firewall rules in `rules` are also evaluated in document order with first-match-wins semantics. For a host-qualified proxy fallback, the binding guard prevents direct `allow` and `shadow` rules from authorizing the upstream, preserves the first matching shadow's audit signal, and applies the first matching `deny`; authorization must still come from a host-bound route rule. Each rule may set `enabled` to `true` or `false`; omitted `enabled` values default to `true` so existing policy files remain active without edits. A rule with `enabled:false` is skipped entirely during live request evaluation, as if it were not present in the rulebase, so the request falls through to the next rule and then to the policy default action if no enabled rule matches.

HTTP direct rules also evaluate each local or OpenAPI-generated tool's fully rendered upstream method and path after argument validation and immediately before egress. A matching `deny` blocks the upstream request, `shadow` emits `authz.would_deny` and continues, and `allow` continues only after the tool's own `enabled`, `allowed_roles`, and exact `tool_name` rule checks have succeeded. Audit events include the tool name, rendered method and path, and matched rule id. Remote MCP proxy tools do not render a local HTTP operation, so HTTP path rules do not apply to them; use `tool_name` rules and `tools.<name>` policy for those tools.

Identity constraints are issuer-aware. A direct rule's `principal` matcher may contain `roles`, `issuers`, `auth_methods`, and `principal_ids`. Non-empty dimensions are combined with AND semantics, while multiple values inside one dimension use OR semantics. For example, `{"roles":["operator"],"issuers":["https://idp.example/"],"auth_methods":["bearer_token"],"principal_ids":["user-123"]}` matches only a bearer-authenticated `user-123` carrying the `operator` role from that issuer. Valid auth methods are `bearer_token`, `session_cookie`, `service_token`, and `client_certificate`. Empty or omitted dimensions are unconstrained.

HTTP path rules may also carry an optional `dispatch` provenance matcher. Omitting `dispatch` preserves the historical globally scoped behavior, but explicitly setting `dispatch`, `upstream_origin`, or `route_id` to JSON `null` is invalid so a purported binding cannot silently become unbound. `"dispatch":{"kind":"contextless"}` matches only requests whose routing classification completed without selecting a proxy upstream. `"dispatch":{"kind":"legacy","upstream_origin":"https://api.example.test"}` matches only the legacy fallback at that normalized HTTP(S) origin and explicitly excludes host/path routes, including routes that select the same origin. `"dispatch":{"kind":"route","route_id":"payments"}` matches only the stable logical proxy route named `payments`; endpoint weights, ordering, health, and physical origins cannot change that authorization identity. Route IDs use the same validated 1–64 character syntax as `UPSTREAM_ROUTES[].id`. Origins containing a path, query, fragment, credentials, an uppercase or non-HTTP(S) scheme, or an invalid authority are rejected; host spelling and default ports are normalized for runtime comparison. Rendered tool HTTP egress has no trusted inbound dispatch classification, so it skips dispatch-bound rules and evaluates only unbound HTTP rules; use an unbound rule when a path policy must apply to both inbound requests and tool operations. `dispatch` is invalid on MCP `tool_name` rules. Suggestion acceptance always recomputes this field from current trusted routing state and persists it on HTTP rules; the field is intentionally omitted from the rule PATCH surface so routine edits cannot remove the provenance boundary. Requests and historical preview events without trusted `routing_context_known:true` classification fail closed for dispatch-bound rules. The admin editor preserves the binding and includes it in rule summaries and previews.

The same `issuers` and `auth_methods` constraints can be set on each `roles.<name>` entry. They determine whether a claimed role may activate that role entry's permissions for `routes`; they do not change the role claim itself. In multi-provider deployments, constrain privileged role entries by issuer so an equal role string from another provider cannot grant route permissions. Existing role entries without identity constraints remain provider-agnostic for backward compatibility.

Rate-limit overrides in a policy's `rate_limits` array are also evaluated in document order, and the first matching entry wins. Each entry may constrain `principal` with the same `roles`, `issuers`, `auth_methods`, and `principal_ids` matcher used by direct firewall rules; omit it or use `{}` to match authenticated and unauthenticated callers. Each entry may also constrain `methods` and an absolute `path` pattern using the same whole-path anchored glob syntax as `rules[].path`: literal segments, `*`, `**`, and `{name}` captures. Matching entries must set positive `requests_per_second` and positive `burst` values.

Rate limiting runs in two independent stages, not a fallback chain: a coarse, canonical-client-IP-keyed global lane (`RATE_LIMIT_READ_*`/`RATE_LIMIT_WRITE_*` below) runs early, before authentication, and always applies to every request regardless of the policy. It never keys on raw cookies or other caller-rotatable identifiers. A second, principal-keyed check runs after authentication and applies ONLY when the request has a validated `Principal` AND a `rate_limits` entry matches it — in that case the request must pass BOTH the global lane and the matching policy lane's bucket. Authenticated policy-lane buckets are keyed by issuer, authentication method, and principal ID, so equal subjects from different identity boundaries do not share a bucket. A `rate_limits` override can therefore only add an additional constraint on top of the global lane for authenticated, matched requests; it can never loosen or replace the global lane, and it has no effect at all on unauthenticated requests or authenticated requests with no matching entry (those are governed by the global lane alone).

Policy administration APIs are available only when `POLICY_FILE` is configured. When it is unset, `GET /v1{ADMIN_PREFIX}/policy`, `PUT /v1{ADMIN_PREFIX}/policy`, `GET /v1{ADMIN_PREFIX}/policy/history`, `POST /v1{ADMIN_PREFIX}/policy/rollback/{version}`, `POST /v1{ADMIN_PREFIX}/policy/validate`, the rule-management endpoints under `/v1{ADMIN_PREFIX}/policy/rules`, `POST /v1{ADMIN_PREFIX}/policy/rules/preview`, and `GET /v1{ADMIN_PREFIX}/policy/rules/hits` return `404 Not Found` with `{"error":"policy API requires POLICY_FILE to be configured"}` after the caller is authenticated. `GET /v1{ADMIN_PREFIX}/policy` returns the current in-memory live policy, not a fresh file read, and includes a strong ETag header. The ETag is `"sha256:<hex>"`, where `<hex>` is the SHA-256 digest of the policy serialized as canonical JSON with object keys sorted recursively.

Policy administration uses dedicated RBAC permissions. `GET /v1{ADMIN_PREFIX}/policy`, `GET /v1{ADMIN_PREFIX}/policy/history`, `POST /v1{ADMIN_PREFIX}/policy/validate`, and `GET /v1{ADMIN_PREFIX}/policy/rules/hits` require `admin:policy:read`; `POST /v1{ADMIN_PREFIX}/policy/rules/preview` and `GET /v1{ADMIN_PREFIX}/policy/rules/shadow-review` each require both `admin:policy:read` and `admin:audit:read`; `PUT /v1{ADMIN_PREFIX}/policy`, `POST /v1{ADMIN_PREFIX}/policy/rollback/{version}`, `POST /v1{ADMIN_PREFIX}/policy/rules`, `PATCH /v1{ADMIN_PREFIX}/policy/rules/{id}`, `DELETE /v1{ADMIN_PREFIX}/policy/rules/{id}`, and `PUT /v1{ADMIN_PREFIX}/policy/rules/order` require `admin:policy:write`. Missing authentication returns `401 Unauthorized`, and a principal without every required permission returns `403 Forbidden`.

`PUT /v1{ADMIN_PREFIX}/policy` replaces the whole policy document. It requires an exact `If-Match` header containing the current ETag. Missing `If-Match` returns `428 Precondition Required`; a stale or non-matching ETag returns `412 Precondition Failed`; invalid policy JSON or policy validation errors return `400 Bad Request` with `{"valid":false,"errors":[...]}`. A candidate that changes the policy `egress` section returns `409 Conflict` without writing `POLICY_FILE` or changing the live policy; edit `POLICY_FILE` and restart the gateway to apply egress changes. On success, the policy is persisted to `POLICY_FILE`, synchronously reloaded into the live RBAC state before the response returns, and the response includes the new ETag. A successful replace emits a `policy.changed` audit event with actor attribution, a lightweight before/after summary, and `diff_summary.action="policy_replaced"`.

`POST /v1{ADMIN_PREFIX}/policy/validate` validates a candidate whole-policy JSON document without persisting it, changing the live policy, or emitting `policy.changed`. It returns `{"valid":true}` on success or `400 Bad Request` with `{"valid":false,"errors":[...]}` on failure.

Granular rule-management endpoints mutate only the `rules` array but validate the full resulting policy before persisting. Each mutation requires an exact `If-Match` header containing the current ETag. Missing `If-Match` returns `428 Precondition Required`; a stale or non-matching ETag returns `412 Precondition Failed`; invalid JSON, invalid rule shape, invalid reordered policy, or invalid order sets return `400 Bad Request` without partial mutation.

Rules defined directly in the policy file without an explicit `id` still use the legacy array-index fallback (see the `rules[]` schema above), not the API's generated `rule-<uuid-v4>` scheme. Their effective id shifts whenever an earlier rule in the list is deleted or the list is reordered, through this API or a direct file edit — a script that captures such a rule's effective id and reuses it across separate requests can end up addressing the wrong rule. Give a rule an explicit `id` in the policy file if you need to address it reliably by id over time; rules created through `POST /v1{ADMIN_PREFIX}/policy/rules` are unaffected, since they always receive a stable id.

`POST /v1{ADMIN_PREFIX}/policy/rules` appends one direct firewall rule. The request body is a single rule object using the documented `rules[]` shape (`methods`, `path`, `principal`, `action`, optional `dispatch`, and optional `id`). If `id` is omitted, the server assigns a stable generated id using the `rule-<uuid-v4>` scheme before persisting, so API-created rules never depend on array-index fallback. If a client supplies an explicit `id` that collides with any current effective rule id, including legacy index fallback ids, the request returns `400 Bad Request`. On success it returns `201 Created` with the created rule, including its assigned or confirmed `id`, and the new ETag.

`PATCH /v1{ADMIN_PREFIX}/policy/rules/{id}` partially updates one existing rule by effective id. The JSON body may include any of `enabled`, `methods`, `path`, `principal`, and `action`; `id` is the path identity and `dispatch` is immutable through this endpoint. If the id does not resolve to exactly one current rule, the request returns `404 Not Found` for no match or `400 Bad Request` for an ambiguous duplicate. On success it returns `200 OK` with the updated rule and the new ETag.

`DELETE /v1{ADMIN_PREFIX}/policy/rules/{id}` removes one existing rule by effective id. If the id does not resolve to exactly one current rule, the request returns `404 Not Found` for no match or `400 Bad Request` for an ambiguous duplicate. On success it returns `200 OK` with `{"deleted_rule_id":"..."}` and the new ETag.

`PUT /v1{ADMIN_PREFIX}/policy/rules/order` reorders the current rules. The request body is a raw JSON array of rule ids in the desired order, for example `["allow-public","deny-admin"]`. The array must be an exact permutation of the current effective rule ids: same length, no duplicates, no missing ids, and no unknown ids. Invalid sets return `400 Bad Request` with errors describing the mismatch. On success it returns `200 OK` with `{"order":[...]}` and the new ETag.

Every successful policy mutation through the admin API appends one row to policy version history. This includes whole-policy replace, rule create/update/delete/reorder, and rollback. History is append-only: rollback never deletes, rewrites, or truncates earlier versions; it restores a stored snapshot and then appends a new version whose `diff_summary` is `{"action":"policy_rolled_back","target_version":N}`. Version rows store a monotonic integer `version`, the acting principal's `user_id`, an RFC 3339 `created_at` timestamp, the structured `diff_summary`, and the full validated policy snapshot after the mutation.

Policy file persistence and live-policy reload are the commit point for policy mutations. Whole-policy replacement and rollback reject an `egress` change with `409 Conflict` before this commit point, so the file and live policy remain unchanged. File-watcher and `SIGHUP` hot reloads that change `egress` are rejected wholesale and log an operator-facing error; the existing live policy, including its startup egress allowlist, remains active until the gateway is restarted. If the policy commit succeeds but the secondary history append fails, the mutation response still uses the normal success status, body, and ETag for that endpoint, and the gateway logs a `tracing::error!` for operators. Those rare responses include `X-GreenGateway-Policy-History-Warning: policy_history_append_failed` so API clients and admin UI code can surface that this mutation may have created a hole in version history. The header is omitted in the normal case where the history row is appended successfully.

Every successful rule mutation emits `policy.changed` with actor attribution, the same lightweight `before`/`after` policy summaries and `changed_sections` used by whole-policy replace, plus a granular `diff_summary`: `{"action":"rule_created","rule_id":"...","position":N}`, `{"action":"rule_updated","rule_id":"...","changed_fields":[...]}`, `{"action":"rule_deleted","rule_id":"...","position":N}`, or `{"action":"rules_reordered","new_order":[...]}`. Whole-policy replace uses `{"action":"policy_replaced"}`. Rollback uses `{"action":"policy_rolled_back","target_version":N}`.

`GET /v1{ADMIN_PREFIX}/policy/history` lists versions newest first. It accepts `limit` and `cursor` query parameters using the same paginated shape as other admin list APIs; `limit` defaults to 50 and is capped at 500. The response is:

```json
{
  "versions": [
    {
      "version": 12,
      "actor": "user-123",
      "created_at": "2026-07-04T12:00:00Z",
      "diff_summary": {
        "action": "rule_created",
        "rule_id": "rule-...",
        "position": 3
      }
    }
  ],
  "next_cursor": "11"
}
```

By default, list entries omit full policy snapshots. Add `include_policy=true` to include each version's `policy` snapshot for detail views or verification. Invalid `limit`, `cursor`, or `include_policy` values return `400 Bad Request`.

`POST /v1{ADMIN_PREFIX}/policy/rollback/{version}` restores the exact policy snapshot stored at the given version. It is a policy write and requires `admin:policy:write` plus an exact `If-Match` header for the current live policy ETag. Missing `If-Match` returns `428 Precondition Required`; a stale or non-matching ETag returns `412 Precondition Failed`; an unknown version returns `404 Not Found` with `{"error":"policy version was not found"}`. On success, rollback persists to `POLICY_FILE`, reloads live RBAC state, appends a new history version, emits `policy.changed`, returns the restored policy JSON, and includes the new ETag.

`POST /v1{ADMIN_PREFIX}/policy/rules/preview` evaluates a candidate direct firewall rule against historical `http.request_observed` rows in the SQLite audit store without persisting it, changing the live policy, or emitting `policy.changed`. The request body is `{"rule":{...},"from":"<RFC3339>","to":"<RFC3339>","sample_limit":20}`; `rule` uses the same `rules[]` shape as the policy document, `from`/`to` are optional RFC 3339 bounds, and `sample_limit` is optional and capped at 100. The response is `{"match_count":N,"scanned_event_count":M,"sample_strategy":"newest_matches","samples":[...]}`. Samples include `event_id`, `timestamp`, `request_id`, `source_ip`, `method`, `path`, `actor`, `status`, optional `policy_decision`, and optional historical `matched_rule_id`. Because the response includes audit-history samples and counts, the caller must hold `admin:audit:read` in addition to `admin:policy:read`; a principal missing either permission receives `403 Forbidden`. Preview requires `AUDIT_SQLITE_PATH`; when it is unset the endpoint returns `503 Service Unavailable` with `{"error":"policy rule preview requires AUDIT_SQLITE_PATH to be configured"}`.

`GET /v1{ADMIN_PREFIX}/policy/rules/hits` returns per-rule historical request hit counts for the current live policy as `{"rules":[{"rule_id":"...","hits":0}]}`. Counts are grouped from indexed `http.request_observed.payload_matched_rule_id` values, so each observed request contributes at most one hit and paired `authz.*` audit events are not double-counted. Rules without an explicit `id` use the same zero-based array index fallback as live RBAC audit attribution. When `AUDIT_SQLITE_PATH` is unset, the endpoint still succeeds and returns all live rules with `hits: 0`.

`GET /v1{ADMIN_PREFIX}/policy/rules/shadow-review` returns, for each enabled `shadow` rule in the live policy, the rule itself, a `would_deny_count`, the distinct principals it would have denied, and sample `authz.would_deny` events. Because the affected-principal list and the samples carry actor identities read from the audit store -- user ID, issuer, authentication mode, roles, and email -- the caller must hold `admin:audit:read` in addition to `admin:policy:read`, the same pair the rule preview endpoint requires and for the same reason; a principal missing either permission receives `403 Forbidden`. When `AUDIT_SQLITE_PATH` is unset, the endpoint still succeeds and returns every enabled shadow rule with a zero count and no principals or samples.

Concurrent policy mutations through this API are safely serialized against each other, including whole-policy `PUT` and granular rule create/update/delete/reorder. A losing request with an ETag from the same starting policy receives `412 Precondition Failed`, never a silently-overwritten update. The `If-Match` guard does not order against a direct edit of the `POLICY_FILE` on disk racing an in-flight API mutation. The file's own atomic write (temp file + rename) means a concurrent reader, including the background file watcher, never observes a torn/partial file, but if something outside this API writes to `POLICY_FILE` at the same moment an API mutation completes, the file watcher's next debounced reload may pick up either write, and the ETag a caller received may no longer describe the live policy a moment later. Treat the returned `ETag` as best-effort freshness, not a guarantee against external file edits, if anything outside this API also writes to `POLICY_FILE`.

### TOOLS_FILE

Optional tool definition registry JSON file path.

Default: empty, which disables only the local manual tools file. The unified runtime registry can still contain managed OpenAPI/MCP catalogs and projected legacy MCP tools.

A copyable starter registry is available at `docs/examples/tools.starter.json`. The development fixture is `dev/tools.json`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. The registry loader reads the file as JSON, validates it against `docs/schemas/tools.v0.schema.json`, rejects duplicate tool names, rejects unknown HTTP methods, and compiles each tool's `input_json_schema` as a JSON Schema document at load time.

This is deliberately separate from `POLICY_FILE`. `TOOLS_FILE` defines what a tool is and how the generic executor maps arguments onto an upstream HTTP request. The RBAC policy's `tools` section controls whether a configured tool may run, which roles may invoke it through `allowed_roles`, which identity boundaries may invoke it through `issuers` and `auth_methods`, and its runtime timeout and concurrency limits. Non-empty dimensions are combined with AND semantics. Empty or omitted `allowed_roles`, `issuers`, or `auth_methods` means that dimension is unconstrained beyond `enabled`.

`allowed_roles` matching is exact-string and case-sensitive, consistent with role matching elsewhere in the RBAC system. If your identity provider's role claims don't match your policy file's casing exactly (e.g. an IdP emitting `Admin` against a policy file expecting `admin`), the mismatch will silently deny access rather than error — double-check casing when a tool call is unexpectedly rejected by role policy.

Manually authored HTTP tools can bind to one managed Connection instead of the legacy global `UPSTREAM_URL`. Set `source` to `{"type":"manual"}` and set `target` to an HTTP target containing the stable `connection_id` and the same mapping currently retained in `upstream` for migration compatibility. A registry containing only connection-bound tools does not require `UPSTREAM_URL`.

```json
{
  "schema_version": "0.1.0",
  "tools": [
    {
      "name": "get_charge",
      "description": "Looks up a charge through the billing Connection.",
      "input_json_schema": {
        "type": "object",
        "required": ["charge_id"],
        "properties": {
          "charge_id": {"type": "string"}
        },
        "additionalProperties": false
      },
      "target": {
        "type": "http",
        "connection_id": "billing-api",
        "mapping": {
          "method": "GET",
          "path_template": "/charges/{charge_id}"
        }
      },
      "source": {"type":"manual"},
      "upstream": {
        "method": "GET",
        "path_template": "/charges/{charge_id}"
      }
    }
  ]
}
```

The connection ID is definition-owned: arguments, headers, query values, and bodies cannot select or replace it. The rendered path must remain origin-relative and is appended beneath the Connection's stored `base_path`; absolute URLs, scheme-relative paths, userinfo, authority changes, dot segments, fragments, and encoded path-confusion forms fail closed. Tool admission, caller identity rules, argument-schema validation, and direct HTTP policy run before Connection lookup. GreenGateway captures the exact Connection and catalog revision, renders the target, and validates the complete destination through egress policy and pinned DNS before reading any CA, client-certificate, private-key, API-key, bearer, OAuth client-secret, or additional-header provider. It then builds the exact pinned TLS transport, resolves or mints the complete application credential set, rechecks the queued execution precondition and live policy, strips every Connection-owned header supplied by the caller, injects the credentials last, and sends. A failure at any step denies the call; there is no anonymous, partially authenticated, or legacy-target fallback.

The executor supports manual and managed-OpenAPI HTTP targets plus refreshed managed MCP targets using Connection authentication `none`, `header_api_key`, `static_bearer`, or `oauth2_client_credentials`, up to four additional secret-backed HTTP headers, and Connection-specific CA trust and mTLS. Additional names are normalized to lowercase, must be unique and non-reserved, and cannot collide with the primary credential header. Their secrets use the `header_api_key` purpose and must all resolve before any request is sent. A referenced Connection cannot be deleted while a manual, managed OpenAPI, or managed MCP tool remains published. Binding-validation, catalog-validation, or dependency-reconciliation failure rejects the update and keeps the previous live registry.

Managed OpenAPI catalog flow uses the Connection-scoped endpoints, not an arbitrary-fetch API:

- `POST /v1{ADMIN_PREFIX}/connections/{id}/openapi/preview` requires `admin:tools:read` and accepts `{"spec":"<OpenAPI 3.x JSON or YAML>"}`. It parses and validates the bounded document without persistence, network access, or tool execution and returns the current Connection ETag, a SHA-256 specification digest, current spec/catalog revisions, typed generated definitions, required security confirmations, incompatibilities, deterministic operation-ID fallbacks, and skipped operations.
- `POST /v1{ADMIN_PREFIX}/connections/{id}/openapi/register` requires `admin:tools:write` and the exact Connection `If-Match`. The request repeats the exact specification and preview digest/revisions, explicitly names selected tools and security schemes, and fails stale rather than silently regenerating against a changed Connection or catalog. A successful transaction persists the specification and selected catalog, reconciles dependencies, publishes one complete runtime snapshot, and returns the safe catalog result.
- `POST /v1{ADMIN_PREFIX}/connections/{id}/refresh` later fetches the registered Connection discovery path using the stored target/authentication/TLS policy and re-applies that explicit registration binding. Preview/register bodies are capped by `MAX_BODY_SIZE` and the 2 MiB managed-spec limit plus a bounded JSON envelope. Unknown request fields and ambiguous or unsupported OpenAPI security are rejected.

`GET /v1{ADMIN_PREFIX}/tools` is the unified capability inventory and requires `admin:tools:read`. It combines manual file tools, managed OpenAPI tools, managed MCP tools/resources/templates, and read-only legacy projections. Filters are `kind=tool|resource|resource_template`, `connection_id`, `source=manual_file|openapi|mcp_discovery|projected_legacy_config`, `available`, `availability=available|unavailable|stale`, `text`, `limit` from 1 through 100, and an opaque same-filter `cursor`. Results expose typed source and Connection provenance, safe availability/policy state, digests and timestamps, but never upstream origins, provider locators, secret IDs, credentials, TLS material, or raw dependency errors. The list `ETag` identifies that representation and responses are `Cache-Control: no-store`.

`GET /v1{ADMIN_PREFIX}/tools/{id}` returns the capability's safe detail, typed HTTP/MCP/resource mapping, bounded input schema, and `actions.can_execute`. Its strong `ETag` binds the definition, Connection/catalog revision, and caller-visible policy eligibility. `POST /v1{ADMIN_PREFIX}/tools/{id}/execute` is the constrained admin playground: it requires `admin:tools:execute`, that exact strong ETag in `If-Match`, and only `{"arguments":{...}}`. The request is capped at the lower of `MAX_BODY_SIZE` and 64 KiB; it accepts no URL, header, credential, TLS, timeout, connection, or policy override. Queued execution rechecks the permission, ETag, Connection/catalog revision, and direct policy immediately before side effects. Projected output is capped at 64 KiB: HTTP success returns only status and a JSON or UTF-8 body (never headers), HTTP non-success bodies are withheld, and MCP returns only supported content blocks. Stable failures use `{"error":"...","reason":"..."}` without targets, credentials, provider details, or upstream bodies.

Managed MCP public names use `{connection_id}:{remote_tool_name}`. The immutable Connection ID keeps names stable across display-name edits and prevents a rename from orphaning policy references. Stored catalog entries carry typed MCP `target` and `source` metadata while retaining the legacy MCP sentinel mapping for migration compatibility. Legacy `MCP_UPSTREAM_SERVERS` names remain exactly `{legacy_server_name}:{remote_tool_name}`.

For managed MCP traffic, GreenGateway resolves the exact catalog/Connection revision before egress and credential work. A stale, missing, disabled, or wrong-kind Connection fails closed without falling back to a legacy server or anonymous call. When discovery sets `use_connection_authentication` to `true`, the configured primary API key, static bearer token, or OAuth bearer token and every additional secret header are injected last on initialize, every POST message (including notifications, `tools/list`, and `tools/call`), SSE GET, and session DELETE. A custom transport header whose name collides with any owned credential name is rejected, so neither a bearer value nor an additional-header value can override that authority. Setting the flag to `false` suppresses both the primary and additional credentials. Managed `401`/`403` responses become only `auth_failed`; challenge headers and bodies are discarded before buffering, and OAuth `401` invalidates that token generation without replaying the current request.

OAuth client credentials use only the stored `client_id`, opaque `client_secret_id`, explicit HTTPS `token_url`, sorted scopes, optional audience/resource, and `client_secret_basic`. The upstream destination passes its own full egress/DNS check before OAuth begins. On a cache miss, the token URL independently passes scheme, host, port, every-address, TLS, redirect-denial, and exact-address-pinning checks before the client secret is resolved. Neither the Connection endpoint nor token endpoint is auto-added to the egress allowlist.

Token requests are `application/x-www-form-urlencoded`, use `grant_type=client_credentials`, and carry the client identity only in a sensitive Basic authorization header. Responses are limited to 16 KiB and must be an HTTP `200` JSON object containing a non-empty bearer `access_token` of at most 8 KiB and an integer `expires_in` from 1 second through 7 days. Unknown fields, a non-bearer token type, missing/wrong content type, malformed JSON, invalid HTTP header bytes, and oversized access/refresh/scope values fail closed. A returned refresh token is discarded and never persisted.

Successful tokens live only in a bounded in-memory cache with at most the managed Connection limit of entries. The cache key includes stable Connection ID, complete Connection ETag/revisions, and encrypted-local-secret version when available. Per-key asynchronous single flight means 100 concurrent cold calls cause one mint; current waiters share the same success or sanitized failure. The detached bounded flight completes even if its leading caller disconnects or times out, so cancellation cannot multiply token requests and every started attempt emits one terminal audit/metric. Tokens refresh proactively before expiry using a bounded deterministic sub-second-capable skew/jitter window. A changed Connection/credential revision or local-secret version selects a new cache partition immediately. Operator environment/file aliases are resolved afresh on every mint; their tokens remain bounded by token expiry, so use the encrypted local provider when an admin-triggered rotation must invalidate the cache immediately.

An upstream `401` removes only the token generation used by that request so the next invocation mints again. GreenGateway does not replay the current request, even if route retry status configuration includes `401`; this prevents automatic duplication of non-idempotent operations. Authenticated Connection `401`/`403` responses become a generic `auth_failed` dependency error; their status is recognized before body buffering, then their challenge headers and bodies are discarded. An oversized, incomplete, or stalled denial body therefore cannot prevent OAuth token invalidation. Token endpoint failures, bodies, challenges, URLs, client IDs, secret IDs, access tokens, and refresh tokens are excluded from caller errors and `connection.oauth_token_refresh` audit payloads. Sensitive token-response accumulation and partially parsed access/refresh fields use best-effort zeroization on success, rejection, oversize, read error, and cancellation. Failures never fall back to an anonymous upstream call.

### MCP_UPSTREAM_SERVERS

Optional JSON array of upstream MCP streamable-HTTP servers whose tools should be discovered and proxied through GreenGateway's MCP endpoint.

Default: empty, which disables upstream MCP discovery.

Each entry requires:

- `name`: stable non-empty server name. Names must be unique. Discovered tool names are namespaced as `{name}:{remote_tool_name}`.
- `url`: the upstream MCP server's streamable-HTTP endpoint URL. It must be a valid `http` or `https` URL with a host.

Each entry may also set `timeout_ms`, `response_idle_timeout_ms`, and `connect_timeout_ms`; when unset, these inherit `EGRESS_TIMEOUT_MS`, `EGRESS_RESPONSE_IDLE_TIMEOUT_MS`, and `EGRESS_CONNECT_TIMEOUT_MS`.

Example:

```json
[
  {
    "name": "prod",
    "url": "https://mcp.example.test/mcp",
    "timeout_ms": 5000
  }
]
```

Security note: MCP upstream hosts are not auto-seeded into the egress allowlist. Their URLs are checked at startup and again before each call through the same egress URL, host, port, DNS, and non-global-IP validation used by normal gateway-originated HTTP requests. Configure `EGRESS_ALLOWED_HOSTS` or policy `egress.hosts` for every allowed MCP upstream host.

MCP upstream auth challenges, error bodies, content types, session identifiers, peer metadata, and raw egress/transport details are not emitted to process logs. Dependency-internal `rmcp` tracing is disabled because it does not provide that redaction boundary; GreenGateway continues to emit bounded MCP outcome categories and structured tool audit events.

Startup discovery imports each upstream tool into the same tool registry as `TOOLS_FILE` tools. Namespaced collisions with local tools or other MCP upstream tools fail startup rather than overwriting.

### POLICY_HISTORY_SQLITE_PATH

Optional SQLite policy version history store path.

Default: empty. When `POLICY_FILE` is configured and `POLICY_HISTORY_SQLITE_PATH` is unset, GreenGateway opens a sibling SQLite database at `<POLICY_FILE>.history.sqlite`. When `POLICY_FILE` is unset, no policy history store is opened.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When the effective history path is available, the gateway opens or creates the database at startup and creates the `policy_versions` table and indexes if needed. Startup fails if the database cannot be opened or initialized.

This is deliberately separate from `DISCOVERY_SQLITE_PATH` and `AUDIT_SQLITE_PATH`. Policy version history is a core policy administration safety feature and is not gated by traffic discovery or audit-query storage. Operators that prefer a single SQLite file may explicitly set `POLICY_HISTORY_SQLITE_PATH` to the same path as either of those settings; policy history uses its own `policy_versions` table and remains append-only.

### RBAC_EXEMPT_PATHS

Comma-separated paths that bypass RBAC authorization.

Default: `/health,/livez,/startupz,/readyz,/version,/metrics` plus the effective `ADMIN_PREFIX` (for example, `/admin` with the default prefix).

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a URI path starting with `/`. When unset, the default is `/health,/livez,/startupz,/readyz,/version,/metrics` plus the effective `ADMIN_PREFIX`; when `ADMIN_LOGIN_PROVIDER` is set, `/v1{ADMIN_PREFIX}/auth/login` and `/v1{ADMIN_PREFIX}/auth/callback` are also added. Setting this variable replaces the entire default rather than augmenting it, except that the admin OIDC login pair `/v1{ADMIN_PREFIX}/auth/login` and `/v1{ADMIN_PREFIX}/auth/callback` remain exempt even when this variable is set explicitly, for as long as `ADMIN_LOGIN_PROVIDER` is set; an unauthenticated browser has to reach both routes for the authorization-code flow to complete, so no explicit list can remove them while admin SSO login is enabled. Exempt paths are matched as segment-boundary-aware prefixes, so `/admin` covers `/admin/assets/app.js` but not `/administrator` or `/admin-panel`. The six fixed probe routes are the exception: an entry naming `/health`, `/livez`, `/startupz`, `/readyz`, `/version`, or `/metrics` exempts only that exact path. The gateway serves those paths exactly and reserves them from proxy fallback exactly, so a prefix exemption there would hand `/health/v1/orders` and every other path below them to the upstream with the check skipped. Exempt paths are allowed through without RBAC permission checks and do not emit authz audit events, except that an exact configured MCP route is never RBAC-exempt. This list does not apply on the gRPC listener at all: that listener serves no gateway-owned surface, so an exemption matching there could only grant an unauthorized upstream call. Non-MCP subpaths beneath an MCP alias keep the normal prefix behavior. At startup, GreenGateway warns when an explicit exempt path is not gateway-owned because such a path can reach proxy fallback without RBAC; this warning is non-fatal because exempting an upstream path may be intentional.

### CORS_ALLOW_ORIGINS

Comma-separated list of exact origins allowed by CORS.

Default: empty list. With the default, cross-origin browser requests receive no CORS allow-origin response header.

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a valid HTTP header value. Configure full origins such as `http://localhost:3000` or `https://app.example.test`. A wildcard entry (`*`) is rejected at startup: the gateway answers with `Access-Control-Allow-Credentials: true`, and browsers refuse a credentialed response whose allowed origin is `*`.

### MAX_BODY_SIZE

Maximum native MCP and control-plane request body size, and the early rejection threshold for declared request sizes, in bytes.

Default: `1048576` (1 MiB)

Format and validation: must parse as a non-negative byte count that fits in `usize`. Requests with a `Content-Length` larger than this value are rejected early with `413 Payload Too Large`. Native MCP and control-plane handlers also count actual streamed bytes before parsing, so chunked, no-Length, and under-declared bodies cannot bypass the cap. Reverse-proxy and outbound tool payload limits use the separate egress body-size settings documented below.

### RATE_LIMIT_READ_RPS

Global pre-authentication read-lane token refill rate for `GET` and `HEAD` requests, in requests per second. Always enforced, regardless of any policy `rate_limits` override (see above).

Default: `50.0`

Format and validation: must parse as a finite non-negative `f64`. The read lane uses a separate token bucket from mutating methods.

### RATE_LIMIT_READ_BURST

Global pre-authentication read-lane token bucket burst size for `GET` and `HEAD` requests. Always enforced, regardless of any policy `rate_limits` override (see above).

Default: `100`

Format and validation: must parse as a `u32`. A fresh read-lane bucket starts full.

### RATE_LIMIT_WRITE_RPS

Global pre-authentication write-lane token refill rate for every method other than `GET` and `HEAD`, in requests per second. Always enforced, regardless of any policy `rate_limits` override (see above).

Default: `10.0`

Format and validation: must parse as a finite non-negative `f64`. The write lane uses a separate token bucket from `GET` and `HEAD`.

### RATE_LIMIT_WRITE_BURST

Global pre-authentication write-lane token bucket burst size for every method other than `GET` and `HEAD`. Always enforced, regardless of any policy `rate_limits` override (see above).

Default: `20`

Format and validation: must parse as a `u32`. A fresh write-lane bucket starts full.

### RATE_LIMIT_KEYRING

Cluster mode's keyring for the shared rate limiter's bucket keys.

Default: empty

Format and validation: the same JSON array of `{ "id", "file", "role" }` objects as `CONNECTION_LOCAL_SECRET_KEYRING`, with key files beneath `CONNECTION_SECRETS_ROOT` and exactly one `primary`. Required when `STATE_BACKEND=postgres`; rejected when `STATE_BACKEND=sqlite`, where nothing reads it. In cluster mode every request the local buckets allow is also decided at `greengateway.rate_limit_buckets`, so one configured burst permits that many requests across the whole cluster rather than per replica -- except `/health`, `/livez`, `/readyz`, `/startupz`, and `/metrics`, which are decided by the local bucket alone so that a limiter which cannot reach the authority cannot silence the endpoints that report why; the row for a caller is keyed by an HMAC-SHA-256 under the primary key over the deployment ID, the lane, and the caller key (a client IP for the global lanes; the issuer- and method-qualified principal, prefixed by the matched rule's fingerprint, for the policy lane), so neither the address nor the principal reaches the database and a reader of the table or of a backup cannot enumerate the IPv4 space against it. Rotating the primary key retires every bucket at once (their digests change), which grants each caller one fresh burst; the bound on live buckets and the idle sweep reclaim the old rows. See [PostgreSQL deployment](deployment/postgres.md).

### RATE_LIMIT_MAX_BUCKETS

Hard ceiling on the number of distinct rate-limit keys each limiter tracks -- the read lane, the write lane, and each policy `rate_limits` rule each have their own store with this ceiling.

Default: `65536`

Format and validation: must parse as a `usize` greater than 0.

The ceiling is what bounds the limiter's memory against cardinality attack: without it, every unique source IP (a single IPv6 /64 offers more than any ceiling) or every unique principal identity adds a bucket for the lifetime of the process, and a principal's `user_id` arrives from a token claim with no length bound of its own, so the memory per entry is attacker-influenced too. Buckets are keyed by a 64-bit hash of the rate-limit key rather than by the key text, so each entry is a fixed handful of bytes no matter how long an identity is. At the ceiling, one bucket is recycled to admit each new key, second-chance: a bucket idle beyond `RATE_LIMIT_BUCKET_TTL_MS` is evicted first, then buckets in scan order, with buckets that have been used since the last scan earning one reprieve -- so a spray of throwaway identities recycles itself rather than displacing active callers. Eviction resets the evicted key's allowance: its next request starts a fresh burst. A working set larger than the ceiling therefore recycles callers continuously; that is the signal to raise this setting, and it is observable as `rate_limit_buckets` pinned at the ceiling with `rate_limit_bucket_evictions_total{reason="capacity"}` climbing (sustained `ttl` evictions on a full store are the healthy steady state). The one honest limit of the approximation: a spray of more distinct keys than the whole ceiling between two requests from one caller displaces even that active caller, as it must in any bounded store.

The ceiling applies to each store separately -- the read lane, the write lane, and every policy `rate_limits` rule -- so worst-case bucket memory is `(2 + number of policy rate-limit rules)` times the ceiling. The rule count is operator-controlled through `POLICY_FILE` and is not itself bounded.

Note that the ceiling and eviction are per limiter *and per process*: each replica of a multi-replica deployment tracks independently.

### RATE_LIMIT_BUCKET_TTL_MS

How long a rate-limit bucket may sit idle before it is preferred for eviction when the store needs capacity, in milliseconds.

Default: `600000` (10 minutes)

Format and validation: must parse as a `u64` greater than 0.

This does not bound memory -- `RATE_LIMIT_MAX_BUCKETS` does that on its own, and there is no background sweep -- it only chooses *which* bucket is recycled under capacity pressure, biasing eviction towards buckets a caller has stopped using. There is no retry or periodic expiry: an idle bucket is examined exactly when a new key needs its slot. One corner to know when pairing this with `RATE_LIMIT_READ_RPS`/`RATE_LIMIT_WRITE_RPS` of `0`: a zero refill rate means a key's burst is spent once and never again for as long as its bucket lives, so an idle key whose bucket is recycled can burst again after at least this TTL of inactivity. With any non-zero refill rate an idle-beyond-TTL key has refilled to full anyway, so eviction grants nothing the refill would not.

### TRUST_PROXY_HEADERS

Whether direct proxy peers listed in `TRUSTED_PROXY_CIDRS` may supply `X-Forwarded-For` and `X-Real-IP` as canonical client IP inputs.

Default: `false`

Format and validation: must parse as a Rust boolean, `true` or `false`. Setting this to `true` requires at least one valid `TRUSTED_PROXY_CIDRS` entry. With the default, forwarded proxy headers are ignored and the connection peer IP is used.

Only the direct connection peer is checked against the trusted CIDRs. For a valid `X-Forwarded-For` chain, GreenGateway walks from the nearest hop to the farthest, skips trusted proxy addresses, and selects the first untrusted address. This supports trusted proxies that append to an existing chain without allowing an attacker-prepended address to replace the actual client. A malformed forwarding chain fails closed to the connection peer and does not fall through to `X-Real-IP`.

`X-Real-IP` is accepted only when `X-Forwarded-For` is absent and exactly one valid IP value is present. Multiple `X-Real-IP` header lines fail closed to the connection peer. Configure the trusted proxy to remove or overwrite any inbound `X-Real-IP`; append-only proxy chains should use `X-Forwarded-For`.

### TRUSTED_PROXY_CIDRS

Comma-separated IPv4 or IPv6 CIDRs containing the reverse proxies that connect directly to GreenGateway. These are proxy peer ranges, not ranges for end-user clients.

Default: empty list

Format and validation: every non-empty entry must parse as a CIDR, for example `10.20.0.0/16,2001:db8:1234::/48`. Entries are always parsed and validated, but the resulting list is inactive while `TRUST_PROXY_HEADERS=false`. Startup fails when `TRUST_PROXY_HEADERS=true` and the list is empty or contains no valid entries. Requests from peers outside these ranges always use the socket peer IP, regardless of any forwarding headers.

Security note: keep GreenGateway reachable only through the configured proxies whenever possible. Use the narrowest stable proxy egress ranges available and update this list when proxy infrastructure changes. Catch-all networks `0.0.0.0/0` and `::/0` are rejected because they would restore unconditional trust in caller-supplied headers.

For reverse-proxy fallback requests, GreenGateway removes inbound proxy metadata before upstream egress, including `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, and other common client-IP forwarding headers. When the canonical client IP is a valid IPv4 or IPv6 address, it then sets `X-Forwarded-For` and `X-Real-IP` to that single normalized gateway-controlled value. If no valid canonical IP is available, both headers are omitted. A matching `UPSTREAM_ROUTES` entry applies `strip_request_headers` and `add_request_headers` afterward, so an operator can explicitly remove or replace these values for a particular upstream.

### VALIDATION_ALLOWED_CONTENT_TYPES

Comma-separated list of media types accepted for mutating requests.

Default: `application/json`

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a valid HTTP header value. `POST`, `PUT`, and `PATCH` requests are accepted when the media type of their `Content-Type` matches a configured entry. Matching follows RFC 9110 section 8.3.1: `;`-delimited parameters are not part of the media type, and type and subtype are compared case-insensitively, so `application/json; charset=utf-8`, `application/json;charset=utf-8`, and `Application/JSON` all match a configured `application/json`. The comparison is on the whole media type rather than a prefix of it, so `application/json-patch+json` does not match `application/json` and must be listed explicitly.

### AUTH_ENABLED

Enables global authentication middleware.

Default: `true`

Format and validation: must parse as a Rust boolean, `true` or `false`. With the default, non-exempt requests run through authentication. When disabled, authentication is a no-op passthrough and no `Principal` is injected for downstream handlers.

### AUTH_MODE

Authentication enforcement mode.

Default: `required`

Format and validation: must be `required` or `observe`. In `required` mode, non-exempt requests must present a supported, valid credential or they are rejected with `401 Unauthorized`. A credential the gateway could not judge at all is answered differently: when a validator reports an identity-provider failure rather than an invalid credential -- an unreachable or unparseable JWKS endpoint, a cookie-session introspection timeout or `5xx`, or a service-token store error -- the response is `503 Service Unavailable` with `{"error":"service unavailable"}` and a `Retry-After` header, and no `WWW-Authenticate` challenge is sent, because telling a caller to re-authenticate would make it discard a credential that may well be valid. The `auth.failure` audit event is still emitted, with its reason prefixed `upstream_error: `. This status depends only on the class of the validator's failure, never on whether a particular credential exists or is well formed. In `observe` mode, authentication still attempts to validate credentials and still emits `auth.failure` audit events, but authentication failures are forwarded without a `Principal` and tagged on observation events as unauthenticated. `AUTH_ENABLED=false` skips authentication entirely; `AUTH_MODE=observe` keeps authentication running without letting the auth layer itself block.

### AUTH_COOKIE_NAME

Cookie name read as a session credential by authentication middleware.

Default: `session`

Format and validation: must be a non-empty RFC 6265 cookie name. The cookie value is treated as credential material and is never echoed in logs, audit payloads, or client responses.

### AUTH_EXEMPT_PATHS

Comma-separated paths that bypass authentication.

Default: `/health,/livez,/startupz,/readyz,/version,/metrics` plus the effective `ADMIN_PREFIX` (for example, `/admin` with the default prefix).

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a URI path starting with `/`. When unset, the default is `/health,/livez,/startupz,/readyz,/version,/metrics` plus the effective `ADMIN_PREFIX`; when `ADMIN_LOGIN_PROVIDER` is set, `/v1{ADMIN_PREFIX}/auth/login` and `/v1{ADMIN_PREFIX}/auth/callback` are also added. Setting this variable replaces the entire default rather than augmenting it, except that the admin OIDC login pair `/v1{ADMIN_PREFIX}/auth/login` and `/v1{ADMIN_PREFIX}/auth/callback` remain exempt even when this variable is set explicitly, for as long as `ADMIN_LOGIN_PROVIDER` is set; an unauthenticated browser has to reach both routes for the authorization-code flow to complete, so no explicit list can remove them while admin SSO login is enabled. Exempt paths are matched as segment-boundary-aware prefixes, so `/admin` covers `/admin/assets/app.js` but not `/administrator` or `/admin-panel`. The six fixed probe routes are the exception: an entry naming `/health`, `/livez`, `/startupz`, `/readyz`, `/version`, or `/metrics` exempts only that exact path. The gateway serves those paths exactly and reserves them from proxy fallback exactly, so a prefix exemption there would hand `/health/v1/orders` and every other path below them to the upstream with the check skipped. Exempt paths are allowed through without credential extraction and do not emit auth audit events, except that an exact configured MCP route is never authentication-exempt. This list does not apply on the gRPC listener at all: that listener serves no gateway-owned surface, so an exemption matching there could only grant an unauthenticated upstream call. Non-MCP subpaths beneath an MCP alias keep the normal prefix behavior. At startup, GreenGateway warns when an explicit exempt path is not gateway-owned because such a path can reach proxy fallback without authentication; this warning is non-fatal because exempting an upstream path may be intentional.

### AUTH_PROVIDERS

Ordered JSON array of authentication provider objects.

Default: empty, which means the legacy single-provider `JWT_*` settings below are used as an implicit one-entry provider named `legacy` when `JWT_JWKS_URL` is set.

Format and validation: unset, empty, or whitespace-only values use the legacy fallback. Non-empty values must be a JSON array. Each entry must include a non-empty unique `name` and `type` set to `jwt` or `cookie_session`.

For `type:"jwt"`, each entry must set at least one of `jwks_url` or `issuer`. When the array contains more than one JWT provider, every JWT provider must set `issuer`; startup rejects an issuerless JWT chain because validators that share keys could otherwise assign identity according to provider order. Optional fields are `audience`, `jwks_timeout_ms`, `jwks_max_key_age_secs`, `require_jti`, `roles_claim`, `roles_claim_delimiter`, `org_claim`, `client_id`, `client_secret`, and `redirect_uri`. The OAuth client fields are ignored unless `ADMIN_LOGIN_PROVIDER` names that provider; when selected for admin login, `client_id`, `client_secret`, and `redirect_uri` are required and the provider must use OIDC discovery through `issuer`. `jwks_url`, `audience`, `org_claim`, `client_id`, `client_secret`, and `redirect_uri` are trimmed, and blank values are treated as unset. `issuer` is trimmed and trailing slashes are removed; an explicitly configured value that becomes empty after canonicalization is rejected at startup. `roles_claim_delimiter` preserves its exact configured value so a single space can split OAuth2-style scope strings; an empty delimiter is treated as unset. `jwks_timeout_ms` defaults to `2000`, `jwks_max_key_age_secs` defaults to `300` (see `JWT_JWKS_MAX_KEY_AGE_SECS`), `require_jti` defaults to `false`, and `roles_claim` defaults to `roles`.

For `type:"cookie_session"`, each entry must set `introspection_url` and `user_id_claim`. Optional fields are `introspection_timeout_ms`, `cache_ttl_ms`, `email_claim`, `org_claim`, `roles_claim`, and `roles_claim_delimiter`. `introspection_timeout_ms` defaults to `2000`; `cache_ttl_ms` defaults to `5000` and must be greater than `0`; `roles_claim` defaults to `roles`. Cookie-session-irrelevant JWT fields and JWT-irrelevant cookie-session fields are accepted by the flat JSON schema but ignored for the wrong provider type, so they do not affect validator construction or egress allowlisting.

Example with OIDC discovery: `[{"name":"primary","type":"jwt","issuer":"https://idp.example.com","audience":"greengateway","roles_claim":"roles","require_jti":false}]`

Example with an explicit JWKS endpoint: `[{"name":"primary","type":"jwt","jwks_url":"https://idp.example.com/.well-known/jwks.json","issuer":"https://idp.example.com","audience":"greengateway","roles_claim":"roles","require_jti":false}]`

Admin UI OIDC login uses the same provider object. Add standard OAuth client settings to the jwt provider and set `ADMIN_LOGIN_PROVIDER` to its `name`: `[{"name":"primary","type":"jwt","issuer":"https://idp.example.com","audience":"greengateway","roles_claim":"roles","client_id":"greengateway-admin","client_secret":"placeholder-secret","redirect_uri":"https://gateway.example.com/v1/admin/auth/callback"}]`

Claim mapping: `roles_claim`, `org_claim`, and cookie-session-only `user_id_claim`/`email_claim` first resolve the configured value as an exact top-level JSON key. Only when no exact key exists and the configured value contains `.` does GreenGateway walk it as a dotted path through nested JSON objects. This preserves Auth0-style namespaced URL claims such as `https://myapp.example.com/roles`, where dots are part of the literal claim key, while still supporting nested IdP shapes such as Keycloak `realm_access.roles`. Role arrays must contain only strings. String-valued role claims are split only when `roles_claim_delimiter` is set; each split piece is trimmed and empty pieces are dropped. `org_claim` is used only when it resolves to a string.

Keycloak-style nested roles: `[{"name":"keycloak","type":"jwt","issuer":"https://keycloak.example.com/realms/acme","audience":"greengateway","roles_claim":"realm_access.roles","org_claim":"tenant.id"}]`

OAuth2 scope string as roles: `[{"name":"oauth","type":"jwt","issuer":"https://idp.example.com","audience":"greengateway","roles_claim":"scope","roles_claim_delimiter":" "}]`

Auth0-style namespaced claims: `[{"name":"auth0","type":"jwt","issuer":"https://tenant.auth0.com/","audience":"https://api.example.com","roles_claim":"https://myapp.example.com/roles","org_claim":"https://myapp.example.com/org_id"}]`

Cookie-session introspection: a cookie-session provider validates the value from `AUTH_COOKIE_NAME` by sending a `POST` request to `introspection_url` through the egress client with `Content-Type: application/json`, `Accept: application/json`, and body `{"session":"<cookie value>"}`. A `2xx` response must be a JSON object. `user_id_claim`, `email_claim`, `org_claim`, and `roles_claim` resolve against that response with the same exact-key-first and dotted-path fallback semantics described above. `401 Unauthorized`, `403 Forbidden`, and `404 Not Found` mean the session is invalid. Timeouts, egress denials, `5xx`, other unexpected non-2xx responses, malformed JSON success bodies, and success bodies missing `user_id_claim` are treated as upstream identity-service failures rather than invalid sessions.

Cookie-session example: `[{"name":"app","type":"cookie_session","introspection_url":"https://app.example.com/session/introspect","user_id_claim":"account.id","email_claim":"account.email","roles_claim":"account.scope","roles_claim_delimiter":" ","org_claim":"account.tenant_id","cache_ttl_ms":5000}]`

Every authenticated principal receives a stable issuer boundary. JWT providers use their normalized configured `issuer` when present; the sole JWT provider in a chain may use only `jwks_url` and receives `provider:<name>`. Cookie-session providers use `provider:<name>`. The legacy single-provider JWT fallback is named `legacy`, so a deployment without `JWT_ISSUER` uses `provider:legacy`. Policy `issuers` values must match these effective values exactly. Provider names are therefore security-sensitive identifiers and should remain stable across configuration changes.

Provider-specific setup recipes for Keycloak, Auth0, Microsoft Entra ID, and Okta are in [docs/auth/README.md](auth/README.md).

When `AUTH_PROVIDERS` is set, it defines the ordered auth provider chain and takes precedence over the legacy single-provider JWT settings for validator assembly. The legacy settings remain supported for backward compatibility.

OIDC discovery: when a provider has `issuer` but no `jwks_url`, startup fetches `{issuer}/.well-known/openid-configuration` through the egress client, adds the returned `jwks_uri` host to the effective egress allowlist, and uses that `jwks_uri` for later JWKS refreshes. Discovery failure or a discovery document without `jwks_uri` prevents the provider from being constructed. When the provider is selected by `ADMIN_LOGIN_PROVIDER`, the same discovery response must also contain `authorization_endpoint` and `token_endpoint`; the token endpoint host is added to the effective egress allowlist for the authorization-code exchange.

JWT algorithms: JWKS keys with `kty` `RSA` validate RS256 tokens, `kty` `EC` with `crv` `P-256` validates ES256 tokens, and `kty` `OKP` with `crv` `Ed25519` validates EdDSA tokens. Unsupported or incomplete keys are skipped during JWKS refresh.

Egress trust: each JWT provider `jwks_url`, each JWT provider `issuer` when it is a URL with a host, each discovered OIDC `jwks_uri` host, the discovered admin-login `token_endpoint` host, and each cookie-session provider `introspection_url` host are automatically trusted for gateway-originated egress. Non-global-IP, scheme, port, and DNS-pinning checks still apply to every discovery, JWKS, token-exchange, and introspection request.

### JWT_JWKS_URL

Optional JWKS endpoint used to validate bearer JWTs.

Default: empty, which means no JWT validator is built.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode. The validator fetches public keys from this endpoint and caches them by `kid`. Supported JWKS signing keys are RSA for RS256, EC P-256 for ES256, and OKP Ed25519 for EdDSA.

Egress trust: when this value is a URL with a host, that host is automatically trusted for gateway-originated egress. Operators do not need to duplicate the JWKS host in `EGRESS_ALLOWED_HOSTS`.

### JWT_ISSUER

Optional expected JWT issuer.

Default: empty, which disables issuer checking.

Format and validation: unset, empty, or whitespace-only values become `None`. When set, bearer JWTs must include a matching `iss` claim.

Egress trust: if this value is a URL with a host, that host is automatically trusted for gateway-originated egress because some deployments use the issuer URL as an identity-provider discovery base. Non-URL issuer identifiers are ignored for egress trust.

### JWT_AUDIENCE

Optional expected JWT audience.

Default: empty, which disables audience checking.

Format and validation: unset, empty, or whitespace-only values become `None`. When set, bearer JWTs must include a matching `aud` claim.

### JWT_JWKS_TIMEOUT_MS

Timeout for JWKS HTTP fetches, in milliseconds.

Default: `2000`

Format and validation: must parse as a `u64` millisecond duration.

### JWT_JWKS_MAX_KEY_AGE_SECS

How long a fetched JWKS key set stays trusted, in seconds.

Default: `300`

Format and validation: must parse as a `u64` between `10` and `86400`; the floor is the validator's demand-refresh throttle (one fetch per 10 seconds per validator), below which a stale key set could not refresh on demand and every request would fail closed against a reachable issuer. The validator refreshes its key set in the background at half this age (never faster than every 10 seconds, with jitter so replicas do not fetch in lockstep), and past this age trusts nothing: a request refreshes first or fails closed with `503`. Every successful fetch replaces the whole set, so a signing key the issuer withdrew disappears at the next scheduled refresh rather than surviving until some request happens to age the set out. Unknown `kid` values never trigger more than one fetch per 10 seconds per validator, so an attacker cannot use them to multiply calls to the identity provider. This setting is part of the static-configuration fingerprint replicas must agree on in cluster mode.

### JWT_REQUIRE_JTI

Whether bearer JWTs must include a non-empty `jti` claim.

Default: `false`

Format and validation: must parse as a Rust boolean, `true` or `false`. When enabled, tokens without a non-empty `jti` are rejected. A `jti` identifies a JWT; it is not consumed once. In cluster mode (`STATE_BACKEND=postgres`) every JWT that carries a `jti` is also checked against the shared revocation denylist on every request (`docs/deployment/postgres.md`, "JWT revocations"); a denylist that cannot be consulted answers `503`.

### ROLES_CLAIM

JWT claim key or dotted claim path used to read roles for the legacy single-provider JWT settings.

Default: `roles`

Format and validation: must be a non-empty Unicode string. Resolution first tries the value as an exact top-level claim key, then falls back to dotted nested-object path walking only when no exact key exists and the value contains `.`. This means namespaced URL claim keys with dots remain literal keys, while paths such as `realm_access.roles` can read nested arrays. The legacy `ROLES_CLAIM` setting reads arrays of strings only; string-valued role claims require `AUTH_PROVIDERS[].roles_claim_delimiter`. Missing claims, malformed paths, non-array values, and arrays containing non-strings produce an empty role list.

### SERVICE_TOKEN_SQLITE_PATH

Optional SQLite store path for service tokens managed by `POST /v1{ADMIN_PREFIX}/tokens` and accepted as `ggw_` bearer credentials.

Default: empty, which disables the service-token admin API storage backend and does not add the service-token validator to the auth chain.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be valid Unicode and are used as a filesystem path. When set, GreenGateway creates or opens the SQLite database at startup and initializes the `service_tokens` table if needed.

When `GATEWAY_PUBLIC_URL` is configured, a service token used against `/mcp` must carry the exact `mcp:tools` scope advertised by the OAuth protected-resource metadata document. This scope is a credential-binding requirement for MCP access; route and tool authorization still uses the normal RBAC policy and tool `allowed_roles` checks after authentication.

### SERVICE_TOKEN_CACHE_TTL_MS

Service-token verification cache TTL, in milliseconds.

Default: `5000`

Format and validation: must parse as a positive `u64` millisecond duration. The validator caches successful and failed `ggw_` bearer-token verification results in-process so normal requests do not require a fresh SQLite lookup every time. Revocations or rotations performed by this process's admin API invalidate that process's cached entry immediately; in standalone mode, revocations made outside this process or in another process take effect no later than this TTL. In cluster mode (`STATE_BACKEND=postgres`) a cached entry is additionally served only while the shared security revision still reads what it read when the entry was made — and every token create, revoke, or rotation advances that revision inside its own transaction — so a revoke committed on any replica is refused by the very next request on every replica; the TTL then bounds only repeated lookups of an unchanged token. Keep the value short for security-sensitive deployments.

Service token admin API: when `SERVICE_TOKEN_SQLITE_PATH` and `POLICY_FILE` are configured (in cluster mode the PostgreSQL authority is the store, and `SERVICE_TOKEN_SQLITE_PATH` is rejected), `POST /v1{ADMIN_PREFIX}/tokens` creates a service token and requires `admin:tokens:write`; `GET /v1{ADMIN_PREFIX}/tokens` and `GET /v1{ADMIN_PREFIX}/tokens/{id}` require `admin:tokens:read`; `DELETE /v1{ADMIN_PREFIX}/tokens/{id}` revokes a token and requires `admin:tokens:write`; `POST /v1{ADMIN_PREFIX}/tokens/{id}/rotate` rotates a token and requires `admin:tokens:write`. Create and rotate responses include the plaintext `ggw_` token exactly once with a notice that it will not be shown again. List and get responses return only token metadata. Create, revoke, and rotate emit `service_token.changed` audit events with actor attribution, token id, display prefix, scopes, and lifecycle timestamps, never plaintext tokens or token hashes.

Token scope delegation is bounded by the creator's live RBAC authority. A creator with an identity-matched role that grants `*` may delegate any scope. Otherwise, every requested scope must name a policy role that the creator both carries and can activate for its current issuer and authentication method. Requests containing unknown, unheld, or identity-inactive roles return `403 Forbidden` before a token is stored. This also means a non-wildcard creator may add the `mcp:tools` marker only when it is a defined, active role the creator carries; use a wildcard administrator if the deployment intentionally treats that marker outside the role map. Rejections emit `service_token.delegation_rejected` with the actor and requested/disallowed role names, but no token secret. Tokens created before this rule are not narrowed automatically; review and revoke any token whose scopes should not have been delegatable by its creator.

### TOOL_RUNTIME_QUEUE_DEPTH

Maximum queued plus running tool invocations admitted by the generic tool runtime.

Default: `1024`

Format and validation: must parse as an integer greater than `0`. This is an admission backpressure cap: once all queue slots are held by queued or running invocations, new invocations are rejected immediately instead of waiting. This controls the runtime used by the native `/mcp` endpoint for configured tools; when no tools are configured, there are no local HTTP tool invocations to admit.

### TOOL_RUNTIME_GLOBAL_CONCURRENCY

Maximum concurrently executing tool invocations across all tools.

Default: `64`

Format and validation: must parse as an integer greater than `0`. This is separate from `TOOL_RUNTIME_QUEUE_DEPTH`: queue depth bounds admitted work, while global concurrency bounds work actively executing after runtime admission.

### TOOL_RUNTIME_QUEUE_TIMEOUT_MS

Maximum time an admitted tool invocation waits for global and per-tool execution permits, in milliseconds.

Default: `1000`

Format and validation: must parse as a `u64` millisecond duration greater than `0`. A queue timeout is reported distinctly from a tool execution timeout so operators can tell runtime congestion apart from slow tool work.

### TOOL_LEASE_TTL_MS

How long a cluster-mode execution lease lives on the database clock before an unrenewed slot can be reclaimed, in milliseconds.

Default: `15000`

Format and validation: must parse as a `u64` millisecond duration of at least `1000`. In cluster mode (`STATE_BACKEND=postgres`) the global and per-tool concurrency limits are slots leased from `greengateway.execution_leases`, so `TOOL_RUNTIME_GLOBAL_CONCURRENCY` and each tool's `max_concurrent` bound the whole cluster rather than each replica; the local semaphores remain a per-replica bound underneath. A running invocation renews its lease at a third of this TTL and is cancelled locally (reported as `lease_lost`) on the first renewal that finds the lease gone, or once half the TTL has passed without a renewal the authority could answer -- always before the slot can be reclaimed at the TTL. A crashed replica's slots return only after this TTL elapses on the database clock, so a longer value tolerates slower authorities at the cost of slower recovery of a crashed holder's slots. Standalone mode never reads it.

### TOOL_RUNTIME_DEFAULT_TIMEOUT_MS

Default execution timeout for generic tool runtime invocations, in milliseconds.

Default: `30000`

Format and validation: must parse as a `u64` millisecond duration greater than `0`. Per-tool policy entries can override this by setting `tools.<tool_name>.timeout_ms` in the RBAC policy document once a tool registry is configured.

### CSRF_ENABLED

Enables double-submit-cookie CSRF checks on every state-changing request the gateway serves, proxied traffic included.

MCP OAuth bootstrap is an exception: a request to `/mcp` or the configured public MCP route with no `Cookie` header and no verified client certificate proceeds to authentication. An unauthenticated initialize receives `401` with a bearer challenge, including `resource_metadata` when `GATEWAY_PUBLIC_URL` is configured. Any cookie header (including an empty or malformed one) or a verified client certificate keeps the CSRF check active unless a bearer credential is present. Cookie-authenticated admin mutations remain protected. OAuth clients do not need to disable `CSRF_ENABLED` to discover the authorization server.

Default: `true`

Format and validation: must parse as a Rust boolean, `true` or `false`. The check is layered over the whole router, not just the control plane, so with the default a `POST`, `PUT`, `PATCH`, or `DELETE` on any non-exempt path -- an admin API route, an MCP route, or a path handled by the reverse-proxy fallback -- must either carry an `Authorization: Bearer` credential or present a matching CSRF cookie/header token pair. A request that presents neither is answered `403 Forbidden` with `{"error":"csrf token missing or invalid"}` and never reaches the upstream. Bearer-authenticated requests bypass the check because CSRF is a browser cookie-auth concern. Safe-method responses on non-exempt paths also acquire a `Set-Cookie` for the CSRF token when the request did not already send one, so proxied `GET` responses carry that cookie too.

Deployments whose proxied clients authenticate with something other than a bearer token -- a session cookie, an API key in a custom header, mutual TLS -- and deployments running with `AUTH_ENABLED=false` are therefore blocked on writes until those clients echo the token or the paths are exempted. `CSRF_EXEMPT_PATHS` compares whole paths for equality and has no prefix or wildcard form, so exempting a proxied API with many write paths means setting `CSRF_ENABLED=false` rather than enumerating them.

### CSRF_COOKIE_NAME

Cookie name used to store the CSRF token.

Default: `csrf_token`

Format and validation: must be a non-empty RFC 6265 cookie name. The CSRF cookie is intentionally not `HttpOnly`, because browser JavaScript must read it and echo the token into the configured CSRF request header.

The CSRF cookie is issued with the `Secure` attribute, so browsers will not store it over plain `http://` except on `localhost`; deployments terminating TLS upstream are fine, but testing over non-localhost plain HTTP will not receive the cookie.

### CSRF_HEADER_NAME

Request header that must echo the CSRF cookie token on protected state-changing requests.

Default: `x-csrf-token`

Format and validation: must be a valid HTTP header name. This header is also included in the gateway CORS allow-header list.

### CSRF_COOKIE_DOMAIN

Optional `Domain` attribute for the CSRF cookie.

Default: empty, which omits the `Domain` attribute and leaves the cookie host-scoped.

Format and validation: unset or empty values become `None`. Non-empty values must be valid cookie domain attribute text, such as `.example.test` or `admin.example.test`.

### CSRF_EXEMPT_PATHS

Comma-separated paths that bypass CSRF checks.

Default: `/health,/livez,/startupz,/readyz,/version,/metrics`

Format and validation: split on commas, trim whitespace, ignore empty entries, and require each entry to be a URI path starting with `/`. Entries are compared to the request path for equality, so there is no prefix or wildcard form and a proxied path tree cannot be exempted as a whole. Exempt paths return before CSRF cookie issuance, so the default probe routes do not receive a CSRF cookie today. Exact configured MCP routes ignore matching CSRF exempt entries and remain protected; non-MCP paths are unchanged.

### UPSTREAM_URL

Optional `http` or `https` upstream origin for the catch-all reverse proxy fallback.

Default: empty, which disables proxying and leaves unmatched paths on axum's default `404`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must be a valid `http` or `https` URL with a host. The proxy uses only the configured scheme, host, and port; each incoming request's path and query are forwarded unchanged. The upstream host is automatically trusted for gateway-originated egress, so operators do not need to duplicate it in `EGRESS_ALLOWED_HOSTS`. Non-global resolved IP ranges are still blocked by default unless `EGRESS_DENY_PRIVATE_IPS=false` is explicitly configured.

The proxy fallback rejects raw request paths containing percent encoding or literal `.` or `..` path segments with `404 Not Found` before upstream route selection. This fail-closed boundary is always active, including when RBAC is not configured, so encoded or traversal-shaped variants cannot bypass gateway-owned admin, API, MCP, or probe namespaces. GreenGateway does not normalize and forward these ambiguous paths.

`UPSTREAM_URL` and `UPSTREAM_ROUTES` are mutually exclusive when `UPSTREAM_ROUTES` contains at least one entry. This keeps proxy startup deterministic and avoids an implicit precedence rule between the legacy catch-all upstream and the routing table.

### UPSTREAM_ROUTES

Optional ordered routing table for the reverse proxy fallback, encoded as a JSON array.

Default: empty, which disables route-table proxying. `UPSTREAM_URL` continues to provide the legacy catch-all proxy when this value is unset or an empty array.

Format and validation: unset, empty, or whitespace-only values become an empty route table. Non-empty values must be a JSON array of at most 128 objects. Unknown fields are rejected. Each object has optional `path_prefix` and optional `host`, and must set exactly one destination form: managed `connection_id`, legacy `upstream_url`, or a non-empty `upstreams` pool. `path_prefix`, when present, must be a URI path starting with `/`. `host`, when present, must be a hostname without a port and is normalized to lowercase. Each entry must set at least one of `path_prefix` or `host`; an entry with only `path_prefix: "/"` is rejected because it would be an unconditional catch-all. Use `UPSTREAM_URL` for the legacy catch-all behavior or add a host to make the root prefix host-specific. Duplicate host/path matchers are rejected. Any entry with `host` also requires `POLICY_FILE`; startup fails without a policy because host-qualified upstream authorization must be bound explicitly.

Legacy `upstream_url` uses the same validation as `UPSTREAM_URL` and maps internally to one endpoint named `primary` with weight 1. An existing route without `id` receives a deterministic bounded ID derived from its normalized logical host/path matcher, not its endpoint URL or declaration order. A route using `connection_id` or `upstreams` must set a unique explicit `id`. A pool may contain at most 32 endpoints, each with a unique `id`, required `url`, optional `weight` from 1 through 1000 (default 1), optional `tls_ca_bundle_path`, and optional `client_identity_pem_path`. Route and endpoint IDs are 1-64 ASCII letters, digits, `.`, `_`, or `-`, must start with a letter or digit, and are the only pool/endpoint values used as audit and metric dimensions. A pooled endpoint URL must be an `http` or `https` origin without userinfo, a base path, query, or fragment. Configure CA bundles and client identities on the endpoint; route-level TLS fields are rejected for a multi-endpoint pool.

A `connection_id` route reads its destination, base path, timeouts, primary authentication, and additional secret headers from the current immutable managed Connection snapshot. The request host, path, query, headers, and body cannot choose a different Connection or authority. Authentication, rate limiting, classification, and RBAC/direct-policy enforcement happen before Connection lookup. The complete final URL then passes egress allowlist, port, DNS, and non-global-address validation before GreenGateway resolves the complete static credential set or obtains an OAuth access token. The validated upstream address is pinned through the send, so credential resolution does not introduce a second upstream DNS decision.

Connection routes support enabled `http_api` Connections using `none`, `header_api_key`, `static_bearer`, or `oauth2_client_credentials` authentication, up to four additional `header_api_key`-purpose secret headers, and the Connection's stored TLS profile. Before route transforms, the proxy removes any caller values for the primary and additional credential names; after transforms, it injects the entire resolved set last. A configured CA bundle and client certificate/private-key pair are resolved only after upstream egress validation and select a transport partitioned by the Connection revision, pinned destination, trust roots, and client identity. Connection-owned custom trust and client identity are not inherited by the independently validated OAuth token transport. A connection route cannot also set `upstream_url` or `upstreams`, and it cannot set route `tls_ca_bundle_path`, `timeout_ms`, `response_idle_timeout_ms`, `connect_timeout_ms`, `health_check`, `retry`, or `circuit_breaker` during this phase. The stored Connection timeouts apply to both upstream and token calls, while the OAuth request and response byte limits remain independently lower. A referenced Connection cannot be deleted until the route is removed; startup atomically reconciles these dependency records.

`load_balancing.strategy` currently accepts only `weighted_round_robin`. Selection is a deterministic weighted sequence over the endpoints in the already-authorized logical route. Endpoint selection happens after authentication, rate limiting, RBAC/direct-policy evaluation, body preflight, and bounded pool admission. No request header, query value, path capture, or body field can select an endpoint, and selection never falls through to another route.

`limits` has bounded defaults and hard validation:

- `max_in_flight`: concurrent requests admitted to the pool, default `128`, range 1-4096.
- `queue_depth`: requests allowed to wait when all in-flight permits are occupied, default `256`, range 0-16384. Zero disables waiting.
- `queue_timeout_ms`: maximum queue wait, default `100`, range 1-60000.

When both active work and queue capacity are exhausted, or a queued request times out, GreenGateway returns `503 Service Unavailable` with `{"error":"service_unavailable"}`. These paths do not resolve DNS, select an endpoint, or send upstream bytes. Client cancellation releases queue and in-flight permits. Permits for streaming responses remain held until the response body completes or is dropped.

`health_check` enables endpoint-specific active and passive health tracking for a route. Endpoints begin in `unknown` and are excluded from selection until they reach `healthy_threshold`; an endpoint remains eligible until it reaches `unhealthy_threshold`. If no endpoint is eligible, the route returns the sanitized `503 Service Unavailable` response without attempting a different logical route. The active-check fields and bounds are:

- `method`: `GET` (default) or `HEAD`.
- `path`: safe absolute path without a query or fragment, default `/`, maximum 1024 bytes.
- `interval_ms`: interval between checks, default `10000`, range 100-3600000.
- `jitter_ms`: centered per-check jitter, default `0`, and less than `interval_ms`.
- `timeout_ms`: per-check timeout, default `1000`, range 10-60000 and no greater than `interval_ms`.
- `healthy_threshold`: consecutive successes required for eligibility, default `2`, range 1-1000. Only active-check successes readmit an endpoint, so the in-flight tail of requests that were dispatched before an exclusion cannot undo it.
- `unhealthy_threshold`: consecutive failures required for exclusion, default `3`, range 1-1000. The active check and passive observations keep independent streaks, so a proxied success never cancels an active-probe failure streak and either streak reaching the threshold excludes the endpoint; a state change clears the other source's streak so pre-transition evidence cannot immediately re-trigger.
- `expected_statuses`: unique active-check success statuses, default `[200,204]`, at most 32 values in 100-599.
- `passive_failure_statuses`: unique proxied response statuses counted as failures, default `[500,502,503,504]`, at most 32 values in 500-599. Connection, DNS-resolution, request, and response-idle timeout failures also count; client/configuration and request-body errors do not.
- `required_for_readiness`: whether this pool contributes to cached readiness, default `false`.
- `minimum_healthy`: eligible endpoints required when readiness is evaluated, default `1`, from 1 through the route's endpoint count.

Each logical route and endpoint has independent health state even if multiple entries use the same physical origin. Health workers retain cancellable task handles, and cancellation interrupts both sleeping and in-flight probes. State-change logs, audit events, and metrics are emitted only on threshold transitions and use bounded route and endpoint IDs plus safe error categories.

The compatibility public `/health` response exposes only aggregate `configured` and `reachable` state; it never returns endpoint origins, IPs, paths, or identifiers. Detailed cached pool and endpoint state is part of the authenticated admin status response and requires `admin:status:read`.

`request_body.mode` accepts `buffered` (default) or `stream`. Buffered mode preserves complete bounded validation before upstream forwarding. The buffered read runs while the request holds an in-flight admission permit, so it is bounded by the route's effective `timeout_ms`: a client that opens a request and stops sending receives `408 Request Timeout` with `{"error":"request_timeout"}` and releases its permit. A body over `EGRESS_MAX_REQUEST_BODY_BYTES` returns `413` with `{"error":"payload too large"}`, while a body stream that fails mid-upload (client reset, malformed chunked framing) returns `400` with `{"error":"invalid_request_body"}`, matching the streaming mode. Stream mode is non-replayable, enforces the actual byte count with backpressure, and can send a bounded prefix before an unknown-length overflow is discovered.

`sse` explicitly enables production Server-Sent Events behavior for a route. When omitted, the ordinary compatibility path still waits for the first response body chunk before committing downstream headers, so eligible pre-commit failures can retain their existing retry and sanitized `502`/`504` behavior. When `sse` is present, GreenGateway commits upstream status and headers as soon as they arrive, without waiting for the first event. The route's effective `timeout_ms` remains the bounded deadline for admission, attempts, backoff, connection setup, and response headers; it no longer limits the committed SSE lifetime.

The optional SSE fields are:

- `max_duration_ms`: maximum committed stream lifetime measured from receipt of upstream headers. Default `3600000` (one hour), maximum `604800000` (seven days). Zero explicitly allows unlimited duration.
- `max_response_bytes`: maximum bytes received from the upstream response stream. When omitted, the route inherits `EGRESS_MAX_RESPONSE_BYTES`. Zero explicitly allows unlimited total bytes.

Unlimited duration or bytes does not remove the other resource bounds: the effective `response_idle_timeout_ms` remains finite and is reset by every received chunk, including SSE keepalives, while `limits.max_in_flight` continues to bound concurrent streams. Backpressure is demand-driven with at most one response chunk in hand. Dropping the client response cancels upstream work and releases admission; shutdown drains an existing SSE stream until the process deadline and then records a `shutdown` terminal outcome.

Every non-empty ordinary response stream and every SSE response emits a payload-free `upstream.stream_terminated` audit event after completion. Outcomes are bounded categories: `completed`, `client_cancelled`, `shutdown`, `upstream_error`, `size_limit`, `idle_timeout`, `duration_limit`, or `request_timeout`. The event includes only the request envelope, stable pool/endpoint IDs, response status, bytes received and handed downstream, time to headers/first byte, total duration, and attempt count. SSE contents, paths, URLs, resolved addresses, and raw transport errors are never captured. The initial HTTP observation sets `upstream_stream_terminal_pending:true` until this correlated terminal event provides the final result.

`websocket` opts a route into WebSocket proxying. When omitted, an `Upgrade` request is forwarded as an ordinary HTTP request with hop-by-hop headers stripped, which is the behavior every existing route keeps. The transport is opt-in per route because it holds a connection open for as long as both peers allow, which is a different resource and exposure profile from a bounded request.

The gateway terminates the client's WebSocket and originates a separate one to the upstream rather than splicing bytes. Nothing the client sends is copied into the upstream handshake: the gateway generates its own `Sec-WebSocket-Key`, strips inbound `sec-websocket-*` and `origin` headers, verifies the upstream's `Sec-WebSocket-Accept`, and refuses an upstream that answers with `Sec-WebSocket-Extensions`. A subprotocol is negotiated only if the client offered it and policy allows it.

`websocket` requires an `upstreams` pool and is rejected on a legacy `upstream_url` route. It cannot be combined with `connection_id`: injecting a managed credential once into a connection that then lives for an hour is a different security question, deferred rather than assumed safe.

The optional WebSocket fields are:

- `max_connections`: concurrent established connections for the route. Default `64`, maximum `100000`.
- `max_connections_per_endpoint`: additional per-endpoint ceiling. Defaults to `max_connections`, i.e. no separate cap. Must be between 1 and `max_connections`, because a per-endpoint cap above the route cap could never bind.
- `queue_depth`: upgrades allowed to wait for capacity. Default `16`, maximum `10000`.
- `queue_timeout_ms`: how long an upgrade waits for capacity before rejection. Default `100`.
- `handshake_timeout_ms`: bound on completing the upstream handshake. Default `10000`, range `100`-`60000`.
- `idle_timeout_ms`: closes a connection with no traffic in either direction. Default `300000`, range `1000`-`3600000`. Zero explicitly disables it.
- `max_duration_ms`: ceiling on total connection lifetime. Default `3600000` (one hour). Zero explicitly disables it.
- `max_frame_bytes`: largest single frame. Default `1048576`, range `1024`-`67108864`.
- `max_message_bytes`: largest reassembled message. Default `4194304`, maximum `268435456`. Must be at least `max_frame_bytes`, since a message cap below the frame cap could not be satisfied by one legal frame.
- `max_write_buffer_bytes`: write headroom beyond one in-flight message. Default `262144`, maximum `16777216`.
- `allowed_origins`: exact origin serializations, at most 32. Scheme and host are compared case-insensitively and a default port is dropped, so `https://app.example:443` and `https://app.example` are the same entry. An entry carrying a path, query, fragment, or credentials is rejected rather than truncated. **An empty list denies every request that carries an `Origin`**: a browser-originated upgrade must be allowed explicitly, never by omission.
- `require_origin`: also reject an upgrade that carries no `Origin` at all. Default `false`.
- `allowed_subprotocols`: subprotocols this route may negotiate, at most 32, each a valid HTTP token. **An empty list denies any client that offers one.** The upstream can never select a subprotocol the client did not offer and policy does not allow.

Setting an unlimited `idle_timeout_ms` or `max_duration_ms` does not remove the other bounds: frame, message, and connection-count ceilings continue to apply, and shutdown drains established connections until the process deadline before closing them.

Control frames are relayed rather than terminated locally, so an application heartbeat reaches the upstream and keeps that connection alive rather than only the client's half. One consequence is visible to clients: a `Ping` is answered locally and also forwarded, so a pinging client can observe two `Pong` frames. RFC 6455 requires an unsolicited `Pong` to be ignored, so this is legal; the alternative, answering heartbeats locally and never forwarding them, would let an upstream idle out while the client believed the path was healthy.

Authentication, RBAC, and egress validation run on the upgrade request exactly as they do for any other request on the route, before any upstream connection is opened. A rejected upgrade contacts no upstream.

`grpc` opts a route into transparent gRPC proxying over the separate `GRPC_LISTEN_ADDR` listener. When omitted, the route carries no gRPC policy and a call matching it on the gRPC listener is refused with `UNIMPLEMENTED`. That is a denial rather than a fallback: a route that has not been given gRPC limits has no limits to enforce, and this transport must not run without them.

gRPC multiplexes many concurrent streams over one HTTP/2 connection, so the unit of admission here is the **call**, not the connection. `max_concurrent_calls` is a separate admission pool from the route's `limits.max_in_flight`, for the same reason the WebSocket transport has its own: a streaming call can hold its slot for an hour, and sharing the pool would let a handful of streams starve the route's HTTP traffic.

`grpc` requires an `upstreams` pool and is rejected on a legacy `upstream_url` route. It cannot be combined with `connection_id`, on the same reasoning as `websocket`.

The optional gRPC fields are:

- `max_concurrent_calls`: concurrent in-flight calls for the route. Default `256`, maximum `100000`.
- `max_concurrent_calls_per_endpoint`: additional per-endpoint ceiling. Defaults to `max_concurrent_calls`. Must be between 1 and `max_concurrent_calls`.
- `queue_depth`: calls allowed to wait for capacity. Default `64`, maximum `10000`.
- `queue_timeout_ms`: how long a call waits for capacity before `RESOURCE_EXHAUSTED`. Default `100`.
- `connect_timeout_ms`: one budget for establishing a *usable* HTTP/2 connection to the upstream — the TCP connect, the TLS handshake, and the peer's own connection preface, which the gateway waits for because a peer that accepts a socket and then sends nothing would otherwise pass every check hyper performs. Default `10000`, range `100`-`60000`. This is not the caller's deadline: exceeding it is `UNAVAILABLE`, not `DEADLINE_EXCEEDED`. It does not bound acquiring stream capacity on an established connection — see `max_duration_ms`.
- `idle_timeout_ms`: terminates a stream with no upstream-to-client traffic, starting when the upstream's response HEADERS arrive. Default `300000`, range `1000`-`3600000`. Zero disables it. It deliberately does not run while the gateway waits for those HEADERS: for a client-streaming call the response direction is legitimately silent for the whole upload.
- `max_duration_ms`: ceiling on one call's total duration measured from admission, and the cap applied to a client's `grpc-timeout`. Default `3600000` (one hour), maximum `604800000` (seven days). The effective deadline is the smaller of the two and is armed before the gateway connects, so one budget covers the admission queue, the wait for the upstream's response HEADERS, and the streaming phase. This is also the only bound on an upstream that has no stream capacity left, because `hyper`'s readiness check reports connection liveness rather than `SETTINGS_MAX_CONCURRENT_STREAMS` credit. Zero disables the ceiling, in which case an uncapped client deadline is honoured — and a call with no `grpc-timeout` on such a route has no total-duration bound at all.
- `max_message_bytes`: largest single *encoded* gRPC message, in either direction. Default `4194304`, range `1024`-`268435456`. Enforced on the length declared in the five-byte envelope, so an oversize message is refused on its header rather than after it has been forwarded.
- `max_request_bytes` / `max_response_bytes`: ceiling on total bytes in one direction of one call. Default `268435456` each. Zero disables. A non-zero value below `max_message_bytes` is rejected, because it could never carry a message the route explicitly permits.
- `max_metadata_entries`: ceiling on the *number* of metadata entries, in request headers and in response trailers independently. Default `64`, maximum `1024`. `GRPC_MAX_METADATA_BYTES` bounds their size; a byte budget does not constrain a count.

The canonical authorization identity is the method path `/package.Service/Method`, which is the HTTP path, so existing RBAC path rules apply to it directly. The path is held to the protobuf identifier grammar, so it has exactly one spelling: the string RBAC evaluates, the string audit records, and the string sent upstream as `:path` are the same bytes.

Retries are disabled for gRPC. A route's `retry` block does not apply to its gRPC calls, and a streaming call is never replayable in any case.

Authentication, rate limiting, CSRF, request validation, RBAC, direct policy, canonical method validation, and admission all complete before any DNS resolution, connection acquisition, or upstream byte. A denied call produces a protocol-correct trailers-only gRPC response and contacts no upstream.

`AUTH_EXEMPT_PATHS` and `RBAC_EXEMPT_PATHS` do **not** apply on the gRPC listener. Those lists exist to let gateway-owned surfaces through without a credential, and that listener serves none — so an exemption matching there could only ever grant an unauthenticated, unauthorized upstream call. `CSRF_EXEMPT_PATHS` still applies, because a CSRF exemption grants nothing on its own. Full deployment guidance, including the front-end requirement and where gRPC cannot work at all, is in [docs/deployment/grpc.md](deployment/grpc.md).

`retry` is an optional pool-only object. Omitting it preserves the compatibility default of exactly one total attempt. It is rejected on legacy `upstream_url` routes. Its fields are:

- `max_attempts`: total attempts including the initial request, default `1`, range 1-5.
- `methods`: unique replay-safe methods, default `["GET","HEAD","OPTIONS"]`. Only `GET`, `HEAD`, and `OPTIONS` are accepted.
- `statuses`: unique upstream response statuses that may trigger a retry before downstream response commitment, default `[502,503,504]`, with 1-32 values in 500-599.

Retries are enabled only when `max_attempts` is greater than one, the request method is listed, and the request body is replayable. Routes using `request_body.mode:"stream"` therefore cannot set `max_attempts` above one. Buffered bodies are read and bounded once, then replayed byte-for-byte; every attempt independently reapplies credential, hop-by-hop, forwarding, framing, configured-header, and request-ID controls.

Configured statuses, retryable TCP connection failures, and pre-commit transport timeouts may retry. Policy or egress denial, DNS validation failure, TLS configuration or certificate failure, request-body failure, response-size failure, cancellation, and any error after downstream response commitment never retry. Every attempt resolves and validates its destination again through the egress boundary, stays within the already-authorized logical pool, and prefers an eligible endpoint not yet attempted by the request.

The route's effective `timeout_ms` is one deadline shared by all attempts and backoff. Retry backoff uses deterministic request-scoped jitter over an exponential 25-250 ms ceiling and is skipped when it cannot fit within the remaining deadline. Each pool also has a non-waiting concurrent retry budget equal to 10% of `limits.max_in_flight`, rounded up and clamped to 1-32. Exhausting that budget stops amplification and returns the last sanitized upstream outcome instead of queueing more retry work.

Retry telemetry uses only bounded pool/endpoint IDs and safe result categories. Metrics include `proxy_upstream_attempts_total`, `proxy_upstream_attempt_duration_seconds`, `proxy_upstream_retries_total`, and `proxy_retry_budget_exhausted_total`. A request that exhausts its configured retry opportunity emits `upstream.retry_exhausted` with the logical request ID and a bounded attempt summary; URLs, resolved addresses, queries, credentials, and raw transport errors are excluded.

`circuit_breaker` is an optional pool-only object. Omitting it leaves circuit breaking disabled and preserves legacy behavior. It is rejected on a route using `upstream_url`. Its fields are:

- `failure_threshold`: consecutive qualifying failures within the fixed 60-second monotonic failure window that open a closed endpoint circuit, default `5`, range 1-1000. An incomplete failure sequence expires at the end of the window.
- `open_ms`: monotonic-clock cool-down before an open endpoint may enter half-open, default `30000`, range 10-3600000.
- `half_open_max_requests`: concurrent recovery probes per endpoint, default `1`, from 1 through the route's `limits.max_in_flight`.
- `recovery_threshold`: successful half-open probes required to close the circuit, default `2`, range 1-1000.

Circuit state is isolated per configured pool and endpoint ID. Retryable transport failures, request timeouts, and configured retry statuses count as failures. When `retry` is omitted, the circuit uses `[502,503,504]` as its failure statuses without enabling request retries. Client 4xx responses, authentication or policy denial, egress or TLS validation denial, request-body limits, and cancellation do not count as endpoint failures. A success resets a closed circuit's consecutive-failure count.

Open endpoints receive no ordinary traffic. After the cool-down, endpoint selection atomically reserves one of the bounded half-open probe slots. A half-open failure immediately reopens the endpoint; successful probes close it after `recovery_threshold`. Cancellation releases a probe slot without recording success or failure. Probe permits remain attached through streamed-response completion so late retryable transport failure or timeout cannot be misclassified as recovery. If every healthy endpoint is open or has no available half-open probe slot, the request returns the sanitized `503 Service Unavailable` response without DNS resolution, upstream bytes, a retry loop, or fallback to another logical route.

State changes emit `upstream.circuit_state_changed` audit events and `upstream_circuit_transitions_total`; selection rejected by open or saturated half-open state increments `upstream_circuit_rejections_total`. Telemetry contains only bounded pool/endpoint IDs, state names, and safe reason categories. It does not contain upstream URLs, addresses, queries, credentials, or raw errors.

Route entries may also set these optional per-upstream fields:

- `timeout_ms`: total timeout for this route's upstream requests, in milliseconds. When unset, the route inherits `UPSTREAM_TIMEOUT_MS` if configured, otherwise `EGRESS_TIMEOUT_MS`.
- `response_idle_timeout_ms`: maximum idle time between streamed response chunks for this route, in milliseconds. When unset, the route inherits `UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS` if configured, otherwise `EGRESS_RESPONSE_IDLE_TIMEOUT_MS`.
- `connect_timeout_ms`: TCP/TLS connection timeout for this route, in milliseconds. When unset, the route inherits `UPSTREAM_CONNECT_TIMEOUT_MS` if configured, otherwise `EGRESS_CONNECT_TIMEOUT_MS`.
- `add_request_headers`: object mapping header names to values added to requests sent to this route's upstream after the gateway strips hop-by-hop headers, removes `x-request-id`, and sets gateway-controlled client-IP forwarding headers.
- `strip_request_headers`: array of request header names removed before sending to this route's upstream after the gateway strips hop-by-hop headers, removes `x-request-id`, and sets gateway-controlled client-IP forwarding headers.
- `tls_ca_bundle_path`: filesystem path to a PEM CA bundle whose certificates are added to this route's TLS trust store.
- `client_identity_pem_path`: pooled-endpoint-only filesystem path to a mounted PEM file containing the client certificate chain and exactly one matching private key.
- `openapi_spec_path`: filesystem path to a local OpenAPI 3.x JSON or YAML document for this upstream route's schema coverage.

Per-route header validation rejects invalid header names or values, rejects adding hop-by-hop or gateway-managed headers such as `connection`, `host`, and `content-length`, and rejects adding or stripping `x-request-id`. The gateway owns the request-id header end to end: it removes any caller-supplied `x-request-id` before dispatching upstream and does not substitute one, so a caller cannot use it to poison upstream logs, and a route cannot re-introduce it. The request ID is still returned to the caller on the response and still correlates the gateway's own audit events. A route also cannot add and strip the same header.

GreenGateway always removes inbound `Authorization` and `Cookie` headers before proxying because those credentials belong to the gateway authentication boundary. Legacy routes may still configure an upstream credential with `add_request_headers`, but this should be treated as a migration-only compatibility path because the literal value lives in environment configuration. Connection routes instead resolve every stored primary and additional binding only after authorization and egress validation, remove caller-supplied values for all Connection-owned credential headers, apply safe route transforms, and inject the complete operator credential set last. Adding or stripping any owned credential header in route configuration is rejected at startup and rechecked against live Connection changes at request time.

`tls_ca_bundle_path` is the supported mechanism for upstreams served by private or internal certificate authorities. A configured bundle is *added* to the platform trust store rather than replacing it, so an upstream served by a public certificate authority stays reachable from the same route configuration that trusts a private one. Certificate verification remains strict by default, and no route inherits a custom CA unless it explicitly configures one. GreenGateway does not expose a per-route skip-verify option; use a local test CA bundle for development instead of disabling verification.

`client_identity_pem_path` enables mutual TLS for one physical `https` endpoint and is rejected with an `http` URL. It accepts only a mounted regular-file reference of at most 1 MiB inside a pooled endpoint object; inline certificate or private-key values are not supported. At startup GreenGateway reads the file through that hard byte limit, requires a PEM certificate chain plus exactly one matching PKCS#1, PKCS#8, or SEC1 private key, and refuses to start if the file is absent, oversized, malformed, incomplete, or mismatched. The parsed identity and custom CA are applied together without changing the configured hostname, so exact-address pinning still preserves TLS SNI and hostname verification.

Client identities and custom root sets are fingerprinted internally and form separate reusable-transport cache partitions. An identity configured for one endpoint is never inherited by another endpoint, even when their origins, timeouts, or CA bundles otherwise match. Debug output, logs, metrics, status, audit records, and errors expose neither certificate/private-key contents nor identity fingerprints. Rotate a mounted identity by replacing the secret and restarting GreenGateway; external secret-provider integration and live credential rotation are outside this configuration contract.

`openapi_spec_path` uses the same parser and startup validation as `OPENAPI_SPEC_PATH`. For route-table specs, coverage is scoped by `path_prefix` when a route has one. The current discovery aggregate table stores only `(method, endpoint_template)` and not the matched upstream route or request host, so host-only routes cannot yet be separated from the global observed inventory. If a route has a `path_prefix`, schema paths may be written either as gateway paths such as `/api/users/{userId}` or as upstream-local paths such as `/users/{userId}`; the coverage matcher considers both the raw spec path and the path prefixed with the route's `path_prefix`.

Matching semantics: a route with both `host` and `path_prefix` requires both to match. Host matching is exact against the request `Host` header after lowercasing and ignoring any port. Path matching uses the gateway's segment-boundary-aware prefix matcher, so `/api` matches `/api` and `/api/users` but not `/apiary`. Among matching routes, the longest `path_prefix` wins. For equal prefix lengths, a host-qualified route wins over a path-only route. Remaining exact ties use declaration order, with the first route winning; exact duplicate `host` plus `path_prefix` matcher keys are rejected at startup.

The proxy and RBAC middleware use the same route-selection implementation. For a selected host-qualified entry, the policy must contain a `routes` rule with the same request host in `hosts`. This prevents a permission granted for a shared path from being reused to reach a different virtual upstream selected by `Host`.

Every legacy or pooled route endpoint is health-checked independently where configured and auto-seeded into the egress allowlist. Managed Connection destinations are deliberately not auto-seeded: explicitly allow each Connection host through `EGRESS_ALLOWED_HOSTS` or policy `egress.hosts`. This keeps destination administration separate from network authorization.

Example:

```json
[
  {
    "id": "billing-route",
    "path_prefix": "/billing",
    "connection_id": "billing-api",
    "add_request_headers": {
      "x-gateway-route": "billing"
    }
  },
  {
    "path_prefix": "/api",
    "upstream_url": "https://api.internal.example",
    "timeout_ms": 1500,
    "add_request_headers": {
      "x-gateway-upstream": "api"
    },
    "strip_request_headers": [
      "x-client-secret"
    ],
    "tls_ca_bundle_path": "/etc/greengateway/internal-ca.pem",
    "openapi_spec_path": "/etc/greengateway/api.openapi.yaml"
  },
  {
    "path_prefix": "/events",
    "upstream_url": "https://events.internal.example",
    "timeout_ms": 5000,
    "response_idle_timeout_ms": 45000,
    "sse": {
      "max_duration_ms": 3600000,
      "max_response_bytes": 0
    }
  },
  {
    "id": "realtime",
    "path_prefix": "/socket",
    "upstreams": [
      {"id": "realtime-a", "url": "https://realtime-a.internal.example"}
    ],
    "websocket": {
      "max_connections": 256,
      "max_connections_per_endpoint": 128,
      "idle_timeout_ms": 300000,
      "allowed_origins": ["https://app.example.test"],
      "require_origin": true,
      "allowed_subprotocols": ["chat"]
    }
  },
  {
    "id": "greeter",
    "path_prefix": "/helloworld.Greeter",
    "upstreams": [
      {"id": "greeter-a", "url": "https://greeter-a.internal.example"}
    ],
    "grpc": {
      "max_concurrent_calls": 256,
      "max_concurrent_calls_per_endpoint": 128,
      "idle_timeout_ms": 300000,
      "max_duration_ms": 3600000,
      "max_message_bytes": 4194304,
      "max_metadata_entries": 64
    }
  },
  {
    "id": "app",
    "host": "app.example.test",
    "path_prefix": "/",
    "upstreams": [
      {"id": "app-a", "url": "https://app-a.internal.example", "weight": 2},
      {
        "id": "app-b",
        "url": "https://app-b.internal.example",
        "weight": 1,
        "tls_ca_bundle_path": "/run/secrets/app-ca.pem",
        "client_identity_pem_path": "/run/secrets/app-client.pem"
      }
    ],
    "health_check": {
      "method": "GET",
      "path": "/ready",
      "interval_ms": 10000,
      "jitter_ms": 1000,
      "timeout_ms": 1000,
      "healthy_threshold": 2,
      "unhealthy_threshold": 3,
      "expected_statuses": [200, 204],
      "passive_failure_statuses": [500, 502, 503, 504],
      "required_for_readiness": true,
      "minimum_healthy": 1
    },
    "retry": {
      "max_attempts": 3,
      "methods": ["GET", "HEAD", "OPTIONS"],
      "statuses": [502, 503, 504]
    },
    "circuit_breaker": {
      "failure_threshold": 5,
      "open_ms": 30000,
      "half_open_max_requests": 1,
      "recovery_threshold": 2
    }
  }
]
```

The host-qualified `app.example.test` entry above needs a policy route such as:

```json
{
  "schema_version": "0.1.0",
  "default_action": "deny",
  "roles": {
    "app-user": {
      "permissions": ["app:proxy"]
    }
  },
  "routes": [
    {
      "methods": ["*"],
      "hosts": ["app.example.test"],
      "path_prefix": "/",
      "permission": "app:proxy"
    }
  ]
}
```

### UPSTREAM_TIMEOUT_MS

Optional total timeout override for configured upstream proxy requests, in milliseconds.

Default: empty, which inherits `EGRESS_TIMEOUT_MS`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must parse as a `u64` millisecond duration. Values must be greater than `0`: startup rejects `0` because a zero millisecond timeout elapses before the first poll, so every request that uses it fails as a timeout. This matches the existing rejection of `0` for the per-route `UPSTREAM_ROUTES[].timeout_ms`, `.response_idle_timeout_ms`, and `.connect_timeout_ms` fields. This applies only to requests sent to configured upstream proxy targets, including `UPSTREAM_URL`, `UPSTREAM_ROUTES`, and the background upstream reachability checks; other gateway-originated egress, such as JWKS fetches, continues to use `EGRESS_TIMEOUT_MS`.

### UPSTREAM_RESPONSE_IDLE_TIMEOUT_MS

Optional idle timeout override between streamed upstream response body chunks, in milliseconds.

Default: empty, which inherits `EGRESS_RESPONSE_IDLE_TIMEOUT_MS`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must parse as a `u64` millisecond duration. Values must be greater than `0`: startup rejects `0` because a zero millisecond timeout elapses before the first poll, so every request that uses it fails as a timeout. This matches the existing rejection of `0` for the per-route `UPSTREAM_ROUTES[].timeout_ms`, `.response_idle_timeout_ms`, and `.connect_timeout_ms` fields. This applies only to streaming proxy responses from configured upstream proxy targets.

### UPSTREAM_CONNECT_TIMEOUT_MS

Optional TCP/TLS connection timeout override for configured upstream proxy requests, in milliseconds.

Default: empty, which inherits `EGRESS_CONNECT_TIMEOUT_MS`.

Format and validation: unset, empty, or whitespace-only values become `None`. Non-empty values must parse as a `u64` millisecond duration. Values must be greater than `0`: startup rejects `0` because a zero millisecond timeout elapses before the first poll, so every request that uses it fails as a timeout. This matches the existing rejection of `0` for the per-route `UPSTREAM_ROUTES[].timeout_ms`, `.response_idle_timeout_ms`, and `.connect_timeout_ms` fields. This applies only to requests sent to configured upstream proxy targets, including the background upstream reachability checks.

## Gateway-Owned Paths And Proxy Collisions

GreenGateway separates its control plane from proxied data-plane traffic. In the default single-listener mode, gateway-owned paths are matched before the reverse proxy fallback, and unmatched paths under gateway-owned control-plane prefixes are not forwarded to the upstream. If an upstream also serves content at one of these paths, that upstream content is unreachable through GreenGateway at the colliding path; move the gateway admin surface with `ADMIN_PREFIX` if the upstream genuinely needs that namespace.

When `ADMIN_LISTEN_ADDR` is set, this separation is stronger: the data-path listener does not register the admin UI or admin API routes, and the admin listener does not register probes, metrics, or the reverse proxy fallback.

The current gateway-owned paths are:

- `/health`
- `/version`
- `/metrics`
- `/mcp`
- The effective `ADMIN_PREFIX` UI path and its subpaths, defaulting to `/admin`
- The effective admin API prefix. With the default admin prefix this is `/v1/admin`; with `ADMIN_PREFIX=/ops` this is `/v1/ops`

The `/mcp` endpoint is gateway-owned and matched before the reverse proxy fallback. When `GATEWAY_PUBLIC_URL` includes a path prefix, GreenGateway also mounts the derived MCP resource path; both routes use canonical `/mcp` policy evaluation as described above.

### EGRESS_ALLOWED_HOSTS

Comma-separated hostnames the egress HTTP client may call for gateway-originated outbound requests.

Default: empty list, which denies all egress requests.

Format and validation: split on commas, trim whitespace, ignore empty entries, lowercase entries, and require each entry to be an ASCII hostname without a port. Configure only hostnames, not URLs. The egress client still blocks non-global resolved IP ranges by default even when a hostname is allowlisted.

Infrastructure endpoint hosts configured elsewhere, including `UPSTREAM_URL`, every legacy `UPSTREAM_ROUTES[].upstream_url`, configured `AUTH_PROVIDERS[].jwks_url` values, URL-shaped `AUTH_PROVIDERS[].issuer` values, OIDC-discovered `jwks_uri` hosts, the discovered admin-login `token_endpoint` host, `JWT_JWKS_URL`, and URL-shaped `JWT_ISSUER` values, are auto-seeded into the effective egress allowlist. This allows deployments to proxy to legacy configured upstreams, fetch OIDC discovery documents, validate tokens, or exchange admin-login authorization codes without duplicating those hosts here. Managed Connection endpoints are intentionally excluded: add their hosts explicitly here or to policy `egress.hosts` so editing a Connection cannot grant itself network reachability.

The effective egress allowlist is constructed at startup. Hot reload and the policy administration API reject changes to the policy `egress` section rather than leaving long-lived egress clients stale. To change policy hosts, CIDRs, or ports, edit `POLICY_FILE` and restart the gateway. Changes to egress environment variables likewise require a restart.

Outbound requests deliberately ignore ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and lowercase equivalents. GreenGateway must have direct network connectivity to configured upstreams and identity endpoints. There is currently no supported outbound-proxy setting; proxy support requires an explicit future design that preserves DNS validation and exact address pinning.

GreenGateway resolves and validates the complete DNS answer set before every outbound cache acquisition. A reusable HTTP client is selected only when the current exact pinned socket address, scheme/host/port, effective egress generation, timeout profile, TLS-root fingerprint, protocol profile, and disabled-proxy policy all match. A DNS error, empty answer, mixed prohibited answer, or safe-to-private change fails closed and never falls back to an older cached destination. The first bounded cache retains at most 128 exact-pinned clients process-wide. An entry becomes ineligible after five minutes without a cache hit and is removed lazily on the next access to its shard; idle HTTP pool connections expire after 90 seconds, so lazy removal cannot retain a live idle socket past that separate limit. Each client retains at most eight idle connections per host and uses a 30-second TCP keepalive interval. Eviction is safe for in-flight requests because each request owns a client reference.

The metrics endpoint exposes `egress_client_cache_requests_total{result="hit|miss|build_error"}`, `egress_client_cache_evictions_total{reason="capacity|idle"}`, and `egress_client_cache_entries`. These labels are bounded and contain no host, origin, route, address, certificate, identity, or request data.

### EGRESS_TIMEOUT_MS

Total timeout for each egress HTTP request, in milliseconds.

Default: `30000`

Format and validation: must parse as a `u64` millisecond duration. Values must be greater than `0`: startup rejects `0` because a zero millisecond timeout elapses before the first poll, so every request that uses it fails as a timeout. This matches the existing rejection of `0` for the per-route `UPSTREAM_ROUTES[].timeout_ms`, `.response_idle_timeout_ms`, and `.connect_timeout_ms` fields. The timeout applies to the whole request, including connection, sending, and response body streaming.

### EGRESS_RESPONSE_IDLE_TIMEOUT_MS

Idle timeout between streamed egress response body chunks, in milliseconds.

Default: `30000`

Format and validation: must parse as a `u64` millisecond duration. Values must be greater than `0`: startup rejects `0` because a zero millisecond timeout elapses before the first poll, so every request that uses it fails as a timeout. This matches the existing rejection of `0` for the per-route `UPSTREAM_ROUTES[].timeout_ms`, `.response_idle_timeout_ms`, and `.connect_timeout_ms` fields. For streaming proxy responses, this timeout starts before the first body chunk and resets after every successfully received chunk. If the upstream response body is idle for longer than this window, the stream is aborted and treated as a gateway timeout.

### EGRESS_CONNECT_TIMEOUT_MS

TCP/TLS connection timeout for each egress HTTP request, in milliseconds.

Default: `10000`

Format and validation: must parse as a `u64` millisecond duration. Values must be greater than `0`: startup rejects `0` because a zero millisecond timeout elapses before the first poll, so every request that uses it fails as a timeout. This matches the existing rejection of `0` for the per-route `UPSTREAM_ROUTES[].timeout_ms`, `.response_idle_timeout_ms`, and `.connect_timeout_ms` fields.

### EGRESS_MAX_RESPONSE_BYTES

Maximum egress response body size, in bytes.

Default: `5242880` (5 MiB)

Format and validation: must parse as a non-negative byte count that fits in `usize`. The egress client streams response bodies and aborts once this cap is exceeded rather than buffering unbounded data.

### EGRESS_MAX_REQUEST_BODY_BYTES

Maximum egress request body size, in bytes.

Default: `1048576` (1 MiB)

Format and validation: must parse as a non-negative byte count that fits in `usize`. Caller-provided body vectors on the direct `EgressClient` request paths are checked before DNS resolution. The proxy's default buffered mode reads no more than this limit before egress. A pooled route may opt into `request_body.mode: "stream"`; that mode rejects a valid known length above the limit before DNS, independently counts all actual bytes for missing, chunked, or underdeclared lengths, forwards no more than the configured maximum, and aborts on the first overflow indication. Gateway MCP `call_tool` payloads are conservatively sized before destination resolution or session initialization and are checked again at transport serialization. MCP initialization and discovery messages retain the transport serialization check after destination validation.

### EGRESS_NAT64_PREFIXES

Optional comma-separated RFC 6052 network-specific IPv6 translation prefixes used by the deployment's NAT64 infrastructure.

Default: empty. GreenGateway always recognizes the globally reachable well-known prefix `64:ff9b::/96` without configuration. The local-use prefix `64:ff9b:1::/48` remains blocked unless it is explicitly configured here.

Format and validation: entries must be IPv6 CIDR prefixes with an RFC 6052 prefix length of `/32`, `/40`, `/48`, `/56`, `/64`, or `/96`, and the RFC 6052 `u` octet must be zero. Prefixes must not overlap each other or the built-in `64:ff9b::/96` prefix. GreenGateway extracts the embedded IPv4 address and applies the same non-global-address policy to it, so an alternate IPv6 representation cannot hide a private, loopback, link-local, or other blocked IPv4 destination. Configure only prefixes routed to a trusted NAT64 translator in this deployment.

### EGRESS_DENY_PRIVATE_IPS

Whether the egress client blocks non-global and special-use resolved IP ranges. The legacy setting name is retained for compatibility.

Default: `true`

Format and validation: must parse as a Rust boolean, `true` or `false`. With the default, the egress client blocks the non-global entries in the IANA IPv4 and IPv6 special-purpose registries, including private, shared, loopback, link-local, documentation, benchmarking, deprecated transition, discard, multicast, and reserved ranges. Registry-defined global exceptions remain allowed. IPv4-mapped IPv6 and recognized NAT64 addresses are classified by their embedded IPv4 destination. If any resolved address for a hostname is non-global, the complete request is denied before the selected address is pinned.

### STATE_BACKEND

Which store owns shared mutable state: `sqlite` or `postgres`. `sqlite` is standalone mode — one gateway process with local files, local SQLite stores, and process-local enforcement — and is the default, fully supported behavior. `postgres` selects cluster mode, where one PostgreSQL primary is the single authority for shared state; see [the PostgreSQL deployment guide](deployment/postgres.md) and [the HA state model](architecture/ha-state-model.md).

Default: `sqlite`

Format and validation: exactly `sqlite` or `postgres`; anything else fails startup. Selecting `postgres` requires `DEPLOYMENT_ID` and `DATABASE_URL_FILE`, and rejects every writable local authority (`POLICY_FILE`, `TOOLS_FILE`, `CONNECTION_LOCAL_SECRET_KEYRING`, and every `*_SQLITE_PATH`) by naming the setting. Selecting `sqlite` rejects `DEPLOYMENT_ID`, `DATABASE_URL_FILE`, `DATABASE_TLS_CA_FILE`, the cluster-only keyrings (`ADMIN_LOGIN_KEYRING`, `RATE_LIMIT_KEYRING`), and the discovery projector's settings (`DISCOVERY_PROJECTOR_LEASE_TTL_MS`, `DISCOVERY_PROJECTOR_POLL_MS`, `DISCOVERY_PROJECTOR_BATCH`) for the inverse reason: material a mode will never read invites an operator to believe something is configured that nothing consults. Mode is a startup-time setting, deliberately not hot-swappable: it participates in the security-configuration fingerprint two replicas must agree on, and moving from sqlite to postgres is a one-way verified import, not a live switch.

Cluster mode is a supported multi-replica configuration within the boundary [Supported cluster operation](deployment/postgres.md#supported-cluster-operation) draws, which names the release-gate suite behind each guarantee and states the non-goals just as explicitly.

### DEPLOYMENT_ID

Stable, non-secret identifier of one logical PostgreSQL-mode deployment: the domain separator for every digest, sealed envelope, lock, and lease the deployment writes. A database is bound to the first deployment ID that boots against it and refuses any other, so two logical deployments never share a database; two replicas of one deployment must carry the same ID.

Default: empty (unused, and rejected, in standalone mode)

Format and validation: 1 to 64 bytes of ASCII letters, digits, `.`, `_`, or `-`, starting and ending with a letter or digit. The ID appears in logs and cluster status by design, which is exactly why its shape is pinned rather than allowing arbitrary bytes. Required when `STATE_BACKEND=postgres`; rejected when `sqlite`.

### DATABASE_URL_FILE

Path to the file containing the PostgreSQL connection string. The connection string itself is credential material and is only ever read from this file, never from a plain environment variable, and never enters configuration, `Debug` output, logs, metrics, status, or errors.

Default: empty (unused, and rejected, in standalone mode)

Format and validation: the file must be a regular file reachable beneath its parent directory (the reader accepts the relative symlinks a Kubernetes Secret volume publishes and confines resolution to that directory), must be at most 8 KiB, and must grant no group or other permission at all — a Kubernetes Secret volume needs `defaultMode: 0400`. Its contents must be a `postgresql://` URL whose query parameters are limited to `user`, `password`, `host`, `port`, `dbname`, and `application_name`: `sslmode`, `options`, and unrecognized parameters are rejected, because TLS policy comes from `DATABASE_TLS_MODE` and session timeouts from this gateway's settings, never from the DSN. The URL must name its host, user, and database explicitly — ambient defaults (the OS account, a localhost socket) are not trusted. Required when `STATE_BACKEND=postgres`.

### DATABASE_TLS_MODE

TLS policy for PostgreSQL connections: `verify` or `loopback-dev`.

Default: `verify`

Format and validation: exactly `verify` or `loopback-dev`. `verify` requires TLS with certificate and hostname verification against the platform trust store plus the optional `DATABASE_TLS_CA_FILE` bundle; a server that will not speak TLS fails the connection rather than falling back. `loopback-dev` skips TLS entirely and is the one documented exception, named for what it is: it is refused at startup for any target that is not a loopback address, the name `localhost`, or a Unix socket, so the exception cannot quietly become a production plaintext connection.

### DATABASE_TLS_CA_FILE

Optional path to a PEM bundle of extra trust anchors for PostgreSQL server-certificate verification, layered on top of the platform trust store exactly as egress TLS layers a configured CA — never a replacement for it.

Default: empty (platform trust store only)

Format and validation: a regular file of at most 1 MiB whose group and other permissions exclude write; public material may stay world-readable but must not be replaceable by another account. Only read when `STATE_BACKEND=postgres` and `DATABASE_TLS_MODE=verify`; rejected in standalone mode.

### DATABASE_POOL_MAX

Per-replica ceiling on concurrently open PostgreSQL connections. The documented sizing math is `replicas x DATABASE_POOL_MAX + migrator/leader headroom` against the server's `max_connections` — see [the PostgreSQL deployment guide](deployment/postgres.md).

Default: `10`

Format and validation: an integer between 1 and 256. The pool establishes connections lazily, so this is a ceiling, not a startup cost.

### DATABASE_CONNECT_TIMEOUT_MS

Bound, in milliseconds, on establishing one new PostgreSQL connection, applied both by the pool's create timeout and as the client-side connect timeout.

Default: `5000`

Format and validation: an integer greater than 0; a zero millisecond timeout elapses before the first poll, so every connection would fail as a timeout and the value is rejected at startup.

### DATABASE_ACQUIRE_TIMEOUT_MS

Bound, in milliseconds, on checking a connection out of the pool, including the wait for a free slot when the ceiling is reached.

Default: `5000`

Format and validation: an integer greater than 0.

### DATABASE_STATEMENT_TIMEOUT_MS

Server-side `statement_timeout` applied to every pooled PostgreSQL session, in milliseconds. It is sent as a startup parameter, so it applies to every statement on every connection the pool ever hands out — including recycled ones — and no code path in this gateway can `SET` it back.

Default: `15000`

Format and validation: an integer greater than 0.

### DATABASE_IDLE_IN_TRANSACTION_TIMEOUT_MS

Server-side `idle_in_transaction_session_timeout` applied to every pooled PostgreSQL session, in milliseconds. A session sitting in an open transaction without running a statement is exactly the lock-holding shape the bounded-operation rule exists to prevent.

Default: `30000`

Format and validation: an integer greater than 0.

### DATABASE_LOCK_TIMEOUT_MS

Server-side `lock_timeout` applied to every pooled PostgreSQL session, in milliseconds: how long a statement waits on a lock before failing.

Default: `5000`

Format and validation: an integer greater than 0.

### DATABASE_STARTUP_RETRY_LIMIT

Bounded startup policy for a selected PostgreSQL backend: how many times to retry the connectivity check after the first failed attempt before startup fails. The wait between attempts starts at 250 ms and doubles up to an 8-second ceiling. A database that stays unreachable is a startup failure, never a silent fallback to local state.

Default: `5`

Format and validation: an integer between 0 and 300; `0` fails startup on the first failed attempt.

### DATABASE_AUTO_MIGRATE

Development-only auto-migration: when `true`, a serving process in postgres mode applies pending schema migrations at startup, exactly as `gateway migrate up` would, before the schema validation runs. Production pods validate only — the default and the required posture — with migrations owned by a separate job running under the DDL-capable migration role; see [the PostgreSQL deployment guide](deployment/postgres.md).

Default: `false`

Format and validation: a Rust boolean. Rejected when `STATE_BACKEND=sqlite`. Auto-migration does not weaken any ledger rule: a tampered or newer-than-supported schema still fails startup.

### DATABASE_MIGRATION_STATEMENT_TIMEOUT_MS

Bound, in milliseconds, on each statement and each lock wait inside a migration transaction (`gateway migrate up`, and auto-migration when enabled). Applied with `SET LOCAL` inside the transaction, so it cannot leak into pooled sessions. Deliberately wider than the request-path `DATABASE_STATEMENT_TIMEOUT_MS` — real DDL takes longer than a lookup — and still finite.

Default: `60000`

Format and validation: an integer greater than 0 and at most 600000.

### CLUSTER_HEARTBEAT_MS

How often, in milliseconds, a cluster-mode replica refreshes its row in the deployment's membership roster, `greengateway.cluster_members` (issue #241, PR 13). Every heartbeat carries the replica's instance and boot identity, binary version, migration-manifest and document-schema ranges, static-configuration fingerprint, and the security revisions it has compiled and last observed, so the roster shows each replica's reconciliation lag. The row is also written at boot, stamped `ready_at` once the replica is serving and agrees with the roster, and stamped `draining_at` when it begins draining.

Default: `5000`

Format and validation: must parse as a `u64` millisecond duration of at least `1000`. Cluster mode only: rejected when `STATE_BACKEND=sqlite`, which has no membership.

### CLUSTER_MEMBER_STALE_MS

How old a member's heartbeat may be, in milliseconds, before its roster row is stale. Liveness is judged on the database clock. A stale row is ignored by the fingerprint-agreement check a booting replica runs -- a replica refuses readiness (`/readyz` answers `503` with reason `config_fingerprint_mismatch`) while any live, non-draining member carries a different static-configuration fingerprint, and is admitted on the first heartbeat after the last such member drains or goes stale -- and is swept by the maintenance singleton, never by request handling. Because agreement is one-way, a fingerprint change completes on its own only where the old replicas leave without waiting for the newcomer's readiness (a `Recreate` rollout, or a rolling update whose `maxUnavailable` covers every old replica); under a readiness-gated rolling update it stalls at the door until the operator forces the old replicas out -- see [the PostgreSQL deployment guide](deployment/postgres.md).

Default: `30000`

Format and validation: must parse as a `u64` millisecond duration of at least `3 x CLUSTER_HEARTBEAT_MS`, so one slow authority round trip never makes a live replica look gone. Cluster mode only: rejected when `STATE_BACKEND=sqlite`.

### CLUSTER_MAINTENANCE_INTERVAL_MS

How often, in milliseconds, the replica holding the maintenance lease runs one bounded pass of the singleton housekeeping jobs (issue #241, PR 13): JWT revocation cleanup, rate-limit idle sweep, pending-login prune, stale member sweep, PostgreSQL audit retention (when `AUDIT_POSTGRES_RETENTION_DAYS` is set), and execution-lease reaping, in that fixed order, each bounded to 1000 rows per step. A replica that does not hold the lease retries it with a jittered backoff of a quarter of this interval plus or minus up to an eighth, the offset fixed by its instance ID, so a leader's crash is followed by one staggered takeover rather than a stampede.

Default: `60000`

Format and validation: must parse as a `u64` millisecond duration of at least `1000`. Cluster mode only: rejected when `STATE_BACKEND=sqlite`, which has no maintenance singleton.

### CLUSTER_MAINTENANCE_LEASE_TTL_MS

How long the maintenance lease (`greengateway.execution_leases`, scope `maintenance`, one slot) lives on the database clock before an unrenewed slot can be taken over, in milliseconds. The leader renews at a third of this and stops its jobs -- cancelling the pass in flight -- on the first renewal that finds the lease gone, or once half the TTL has passed without a renewal the authority could answer, always before the slot can be reclaimed. A crashed leader's slot returns after this TTL elapses on the database clock, and a successor takes it within its acquisition backoff after that; every write to `greengateway.maintenance_jobs` carries the writer's fence and requires the lease at that fence to be live, so a paused leader finds its late writes refused from the instant its lease lapses.

Default: `15000`

Format and validation: must parse as a `u64` millisecond duration of at least `1000`. Cluster mode only: rejected when `STATE_BACKEND=sqlite`.

### AUDIT_POSTGRES_RETENTION_DAYS

Retention window, in days, for the PostgreSQL audit store (`greengateway.audit_events`). On each pass the maintenance leader deletes a bounded batch (1000 rows) of the oldest events whose `occurred_at` is past the window, oldest stream position first, drawn from an index-ordered window of ten times the batch so the step's work is bounded by the step rather than by the backlog, and never at or past the position a durable stream consumer has yet to apply (the retention floor: the discovery projector's committed checkpoint, PR 11). The stream's position counter is never deleted, so cursors keep their meaning across retention. Empty or `0` keeps everything.

Default: (empty)

Format and validation: an integer day count of at most `36500`; `0` is treated as disabled with a warning rather than as "retain nothing". Cluster mode only: rejected when `STATE_BACKEND=sqlite`, where `AUDIT_SQLITE_RETENTION_DAYS` is the equivalent.

### READINESS_PROBE_CACHE_MS

How long, in milliseconds, `/readyz` reuses one authority observation (issue #241, PR 14). In cluster mode the readiness chain consults the deployment's database with a single bounded read -- is this session writable, and how many migrations does the ledger carry -- which answers the `storage_unavailable` and `schema_incompatible` reasons. That one read is cached for this window and shared by every concurrent probe, so however often an orchestrator probes and however many replicas it probes, each replica costs the database at most one check per window. The other reasons (`starting`, `draining`, `config_fingerprint_mismatch`, `instance_lease_invalid`, `security_revision_not_compiled`, `required_upstream_unavailable`) read process-local state and are re-evaluated on every probe regardless of this setting. `0` consults the authority on every probe.

Default: `1000`

Format and validation: must parse as a `u64` millisecond duration of at most `60000`, so a readiness answer is never older than the probe interval that asked for it. Cluster mode only: rejected when `STATE_BACKEND=sqlite`, whose readiness consults no shared authority.

### CLUSTER_STATUS_EXPOSE_HOSTNAMES

Whether the cluster status API may report this replica's own hostname (issue #241, PR 14). When `true`, `local.hostname` on `GET /v1{ADMIN_PREFIX}/cluster` carries the value of `HOSTNAME` (or `COMPUTERNAME` on Windows), read once at startup; when `false`, the field is `null`. It is only ever *this* process's hostname -- no membership column holds another replica's, so `GET /v1{ADMIN_PREFIX}/cluster/replicas` has none to report at any setting. Turn it on when operators need to map a roster UUID onto a pod or a host; leave it off and nothing else on that surface changes. Everything else in these responses is a number, a UUID, or a string recognized against a fixed shape, so a hostname is the one piece of deployment topology an operator has to ask for rather than receive by default.

Default: `false`

Format and validation: must parse as a boolean. Honoured in both modes -- unlike the other cluster settings it is not rejected under `STATE_BACKEND=sqlite`, because standalone mode serves the same endpoint and has the same hostname to report. The value is still bounded on the way out: a hostname longer than 253 characters, or carrying anything but ASCII letters, digits, `-`, `.`, or `_`, is dropped whole and the field reports `null`, so an opted-in deployment cannot turn the field into a channel for arbitrary text.

## Production Deployment And Migration

Adopt pool behavior one logical route at a time. Existing `UPSTREAM_URL` and
legacy `UPSTREAM_ROUTES[].upstream_url` entries remain one-endpoint,
single-attempt, buffered compatibility routes. A pool migration assigns stable
route/endpoint IDs, moves endpoint-specific CA and client-identity paths into
the selected endpoint object, and opts into health, retry, circuit, streaming,
or SSE behavior explicitly.

For static upstream authentication, migrate a route by creating an enabled
managed `http_api` Connection with an operator secret alias, explicitly
allowlisting its host for egress, assigning the route a stable `id`, and
replacing `upstream_url` plus any literal credential headers with
`connection_id`. Remove the legacy literal only after the Connection-bound
route passes authorization, egress, and upstream smoke tests. Rollback is the
reverse configuration change; Connection dependency protection prevents
deleting the managed record while a route or manual tool still references it.

Before rollout, validate:

- policy dispatch bindings use the stable logical route ID;
- `limits`, health thresholds, retry methods/statuses, circuit bounds, and
  stream limits fit the deployment;
- every endpoint passes complete DNS/egress validation;
- mounted CA/identity files are read-only, regular files and contain no real
  secret values in environment JSON;
- `/startupz`, `/livez`, and `/readyz` are wired to their intended supervisor
  roles; and
- the supervisor grace period exceeds the drain delay, request/background
  timeout, and audit-drain timeout.

Expected pre-commit proxy failures remain sanitized: body limit `413`, no
eligible capacity `503`, upstream transport/protocol failure `502`, and
connect/total/idle timeout `504`. Detailed endpoint state is available only
through the authorized admin status API.

See the
[production data-plane deployment guide](deployment/production-data-plane.md)
for a migration example, Docker Compose and Kubernetes probes, multi-upstream
smoke scenarios, mTLS rotation, alert guidance, load/soak reproduction, and
rollback steps.
