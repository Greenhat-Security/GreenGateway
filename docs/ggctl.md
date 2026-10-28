# ggctl, the operator CLI

`ggctl` is GreenGateway's operator command-line tool (issue #242, [ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md)). It is a separate binary: the `gateway` server keeps its name, its no-argument startup, its Docker entrypoint and its one-shot commands (`gateway migrate`, `gateway healthcheck`, `gateway import-standalone`, ...) unchanged.

**Status: foundation, alpha.** This build implements `version`, `schema`, `completion` and `help`, the output contract, the exit codes, secure bearer-token input and the version handshake with a running gateway. It cannot yet validate, initialize, diff, plan, apply, export or back up anything: those commands are later #242 slices (see the ADR's [rollout](adr/0008-setup-cli-and-configuration-bundles.md#rollout)), and a name this build does not implement is refused as an unknown command (exit 2). Nothing here changes how a gateway is configured or started.

## Building

`ggctl` has no build script and does not embed the admin UI, so it builds without Node:

```sh
cargo build --locked --release -p ggctl
# target/release/ggctl (ggctl.exe on Windows)
```

It is not yet part of the release artifacts or the container image; packaging, checksums, SBOM and signing for Linux, macOS and Windows come with #242 PR 18. CI builds and tests it on all three platforms.

The configuration contracts it shares with the gateway live in the `gateway-config` library crate, which both binaries link: today the published document schemas and the `GatewayCapabilities` handshake document. The bundle reader and the configuration compiler move there when `ggctl validate` arrives (#242 PR 8).

## Commands

```text
ggctl version [--server URL] [--ca-file PATH] [--token-stdin | --token-file PATH] [--timeout SECONDS] [--format human|json]
ggctl schema [KIND] [--api-version VERSION] [--format human|json]
ggctl completion bash|zsh|fish|powershell
ggctl help [COMMAND]
ggctl --help | --version
```

`ggctl help COMMAND` and `ggctl COMMAND --help` print a command's options. Help and the completion scripts are generated from the same command table the parser uses, so they cannot drift. Man pages, which ADR-0008 also generates from that table, arrive with packaging (#242 PR 18).

### `version`

Prints the `ggctl` version and the document versions whose schemas it publishes. With `--server` it performs the [version handshake](#version-handshake) and reports the gateway version and whether this `ggctl` can work with it, exiting `3` when it cannot. The check reads only; it never changes the server.

### `schema`

Without `KIND`, lists every document kind and version this `ggctl` publishes a JSON Schema (Draft 2020-12) for. With `KIND` (`GatewayBundle`, `GatewayDeployment`, `GatewayCapabilities` or `GgctlReport`), writes that schema to standard output, byte for byte as committed under [`docs/schemas`](schemas/) with LF line endings on every platform. `--api-version` selects a document version (default: the newest published); a version with no published schema exits `3`. Printing a schema writes an artifact, so `--format` is refused there. A schema is necessary but not sufficient: the gateway's reader is authoritative.

### `completion`

Writes a completion script to standard output. It completes commands, options, fixed choices and, for path options, file names.

| Shell | Install |
| --- | --- |
| bash | `ggctl completion bash > ~/.local/share/bash-completion/completions/ggctl` |
| zsh | `ggctl completion zsh > "${fpath[1]}/_ggctl"` |
| fish | `ggctl completion fish > ~/.config/fish/completions/ggctl.fish` |
| PowerShell | `ggctl completion powershell >> $PROFILE` |

## Output contract

- **Standard output carries only what was asked for**: an artifact (a schema, a completion script, help), the human result, or with `--format json` exactly one `GgctlReport` document ([schema](schemas/ggctl-report.v1alpha1.schema.json)).
- **Diagnostics go to standard error** in human form. With `--format json` they are in the report instead and standard error stays empty.
- **An argument error found before a command runs** (an unknown option, a refused secret or insecure option, a malformed `--server`) is written to standard error only, exits `2`, and writes no report.
- **No color, no prompts, no progress output.** `ggctl` reads no configuration file and no environment variable, and makes no network request unless a command is given `--server`.

A report always has `apiVersion: greengateway.dev/v1alpha1`, `kind: GgctlReport`, the `command`, the process `exitCode` and its stable `outcome` name, the `diagnostics`, and a command-specific `result`. Every diagnostic has a stable `code`, a `severity`, fixed `message` text, an optional fixed `hint`, a `remediation` anchor in this document and, when it concerns one argument, that argument's 1-based `location.argument` position. Diagnostics are value-free by construction: they never contain an argument, token, URL, path, address, server response or library error text. An unknown option is reported by its position, never by its spelling, because the spelling may be a mistyped secret. A published code never changes meaning; renaming or removing one needs a new report version.

SARIF 2.1.0 output belongs to `validate`, the one command ADR-0008 gives it, and arrives with it; the writer is part of this foundation, and no current command offers `--format sarif`.

## Exit codes

| Code | Outcome | Meaning |
| --- | --- | --- |
| `0` | `success` | Success; for `diff --check`, no drift; for `doctor`, no required check failed. |
| `1` | `failure` | Unexpected internal, I/O or transport failure, including a mutation whose outcome could not be determined. |
| `2` | `usage` | Usage error, including a reserved command or a refused insecure option. |
| `3` | `invalid` | Invalid, incompatible or unsupported configuration, server or document version. |
| `4` | `drift` | Drift found by `diff --check`. |
| `5` | `conflict` | Precondition conflict: missing or stale ETag, plan, acknowledgment or lock. |
| `6` | `unavailable` | A dependency was unavailable and nothing was sent or committed; safe to retry. |
| `7` | `integrity` | Backup or archive integrity or restore verification failure. |
| `8` | `denied` | Authentication or authorization refused. |

When several errors apply, the one that must not be hidden wins: `1` over everything, and `6` only when nothing else went wrong, so a pipeline that retries on `6` never resends work another error left in doubt. Codes `4`, `5` and `7` belong to commands later slices add.

## Credentials

`ggctl` never accepts a secret as a command-line argument, where it would land in shell history and in every process listing. Any option spelled like one that carries a secret (`--token`, `--password`, `--api-key`, `--client-secret`, ...) is refused wherever it appears, before anything else is parsed, and so is any option that would disable verification (`--insecure`, `-k`, ...).

An admin bearer token comes from exactly one of:

- `--token-stdin`: standard input, which must be a pipe or a file. A terminal is refused (`credential.stdin_is_terminal`) because a token typed there is echoed and kept in scrollback.
- `--token-file PATH`: a regular file of at most 8 KiB. A symbolic link to one is followed, as mounted secrets use them; a FIFO, device or directory is refused without being opened, and the file is opened without blocking, so one swapped in after that check is refused rather than waited on. On Unix the file must grant group and other no access at all (mode `0600` or `0400`); Windows has no mode bits, and the file's ACL is left to the operator.

The token must be one RFC 6750 bearer token, optionally followed by a single line ending; anything else is refused before a request is built. It is held in memory that is zeroed on drop, has a redacted `Debug` form, and is sent only as `Authorization: Bearer` to the named server. An operating-system credential store may follow in a later slice.

```sh
printf '%s' "$ADMIN_TOKEN" | ggctl version --server https://gateway.example.test/v1/admin --token-stdin
```

## Remote server

`--server` takes the admin API base, `https://HOST[:PORT]/v1<ADMIN_PREFIX>` (for the default prefix, `https://HOST/v1/admin`), and `ggctl` never derives or rewrites it:

- HTTPS uses the platform's trust store with normal certificate and hostname verification. `--ca-file PATH` adds the PEM certificates in one regular file of at most 1 MiB as further trust anchors; it does not replace the platform's, and it applies only to an `https` server. It is read like `--token-file`, and because these anchors decide which server receives the token, on Unix another account must not be able to change it: the file may be world-readable (`0644`), but a file writable by group or other (`0664`, `0666`) is refused, and so is one in a directory writable by group or other without the sticky bit, whether that is the directory the path names or, for a symbolic link, the one holding the file it points to (`trust.ca_file_unsafe_permissions`). Windows leaves the file's ACL to the operator. On Linux the platform store honors `SSL_CERT_FILE` and `SSL_CERT_DIR`, as every client using it does. There is no option that disables verification.
- Plain `http` is accepted only for a loopback IP literal (`127.0.0.0/8` or `::1`), which covers SSH tunnels and `kubectl port-forward`. `localhost` is a name, not a literal, and needs `https`.
- A user name or password, a query, a fragment, percent-escapes, backslashes, `.` or `..` segments, and any space, tab, line break or other control character are refused, so the base used is exactly the one written.
- Redirects are refused, never followed. Ambient proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`) are ignored. Requests use HTTP/1.1 without compression or `Referer`.
- Each request is bounded by `--timeout` (default 30 seconds, at most 300; the connection phase at most 10), and a response body by 8 MiB or less (64 KiB for the capability document). Requests are sequential.
- An idempotent read is retried at most twice, and only when the connection was never established. Nothing that reached the server is resent, and mutations (later slices) are never retried.

## Version handshake

A gateway serves its configuration capability document at `GET /v1{ADMIN_PREFIX}/config/capabilities` ([schema](schemas/gateway-capabilities.v1alpha1.schema.json)). The route requires an authenticated principal holding `admin:config:read` and a configured `POLICY_FILE`, like the other admin read routes; see [configuration](configuration.md#configuration-capabilities). Give the operator's role the permission and route it in the policy:

```json
{"methods": ["GET"], "path_prefix": "/v1/admin/config", "permission": "admin:config:read"}
```

The document states the gateway version, the configuration source mode, the configuration document versions the server accepts and the configuration operations it has enabled. Today a gateway reports environment mode with no documents and no operations, because nothing in the admin API accepts configuration yet.

Compatibility is exact. `ggctl` reads only the capability document versions it implements, and only as a closed document: a member it does not define, a duplicate member or a value outside its grammar makes the document unreadable as a whole (`compat.capabilities_invalid`), and another document version is `compat.unsupported_capabilities_version`. Both exit `3`, and a server that does not serve the document at all is `compat.capabilities_unavailable`. `version --server` still reports the gateway version when the document stated a well-formed one. The lists of documents and operations are open: a configuration command (later slices) asks only whether the one document version and operation it is about to use are listed, and refuses to proceed when they are not.

## Diagnostics

Each code below is stable. The exit column is the exit code the diagnostic produces on its own.

### Usage diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `usage.missing_command` | 2 | No command was given. |
| `usage.unknown_command` | 2 | The command is not one this `ggctl` implements. |
| `usage.reserved_command` | 2 | `db` and `cluster` are reserved: database and cluster operations stay on the `gateway` binary (`gateway migrate check`, `gateway migrate up`, `gateway cluster-members`, ...), which the hint names. `ggctl` never opens a PostgreSQL connection. |
| `usage.unknown_option` | 2 | An argument is not an option this command accepts. |
| `usage.missing_value` | 2 | An option that takes a value was given none. |
| `usage.duplicate_option` | 2 | An option was given more than once. |
| `usage.unexpected_value` | 2 | A flag was given a value. |
| `usage.unexpected_argument` | 2 | The command takes no further positional argument. |
| `usage.missing_argument` | 2 | A required argument is missing. |
| `usage.invalid_value` | 2 | A value is empty, not one of the command's choices, or out of range. |
| `usage.argument_not_utf8` | 2 | An argument is not valid UTF-8. Only a path given as its own argument may be. |
| `usage.conflicting_options` | 2 | `--token-stdin` and `--token-file` were both given. |
| `usage.option_requires_server` | 2 | `--ca-file`, `--token-stdin`, `--token-file` or `--timeout` was given without `--server`. |
| `usage.format_unsupported` | 2 | `--format` was given to a command form that writes an artifact. |
| `usage.secret_on_command_line` | 2 | An option that would carry a secret was given; use `--token-stdin` or `--token-file`. |
| `usage.insecure_option_refused` | 2 | An option that would disable verification was given; add the CA with `--ca-file` instead. |
| `usage.ca_file_requires_https` | 2 | `--ca-file` was given for an `http` server. |

### Credential diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `credential.stdin_is_terminal` | 2 | `--token-stdin` was given a terminal; pipe the token in. |
| `credential.unreadable` | 1 | The token file could not be opened or read. |
| `credential.not_regular_file` | 2 | The token file is not a regular file. |
| `credential.unsafe_permissions` | 2 | The token file grants group or other access (Unix). |
| `credential.too_large` | 2 | The token is larger than 8 KiB. |
| `credential.empty` | 2 | The token is empty. |
| `credential.invalid` | 2 | The input is not exactly one RFC 6750 bearer token. |

### Trust diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `trust.ca_file_unreadable` | 1 | The CA file could not be opened or read. |
| `trust.ca_file_not_regular_file` | 2 | The CA file is not a regular file. |
| `trust.ca_file_unsafe_permissions` | 2 | The CA file, or a directory holding it, is writable by group or other (Unix); a directory may be only with the sticky bit. |
| `trust.ca_file_too_large` | 2 | The CA file is larger than 1 MiB. |
| `trust.ca_file_invalid` | 2 | The CA file holds no PEM certificate that can be used as a trust anchor. |

### Remote diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `remote.invalid_server_url` | 2 | `--server` is not an admin API base of the form above. |
| `remote.plaintext_refused` | 2 | `http` was given for a host other than a loopback IP literal. |
| `remote.userinfo_refused` | 2 | `--server` carries a user name or password. |
| `remote.query_or_fragment_refused` | 2 | `--server` carries a query or fragment. |
| `remote.connect_failed` | 6 | The connection or TLS handshake failed before any request was sent, including an untrusted certificate or a hostname mismatch. |
| `remote.timeout` | 1 | The request did not complete within the timeout after it was sent. |
| `remote.transport_failed` | 1 | The request failed after the connection was established. |
| `remote.redirect_refused` | 1 | The server answered with a redirect; check the admin prefix. |
| `remote.unauthenticated` | 8 | HTTP 401: supply a valid admin token. |
| `remote.forbidden` | 8 | HTTP 403: the principal lacks the route's permission (`admin:config:read` for the handshake). |
| `remote.server_unavailable` | 6 | HTTP 503: a dependency of the server is unavailable. |
| `remote.unexpected_status` | 1 | Any other HTTP status. |
| `remote.response_too_large` | 1 | The response is larger than `ggctl` accepts. |
| `remote.unexpected_content_type` | 1 | The response is not `application/json`. |

### Compat diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `compat.capabilities_unavailable` | 3 | HTTP 404 for the capability document: a gateway older than this route, a wrong admin prefix, or no `POLICY_FILE`. |
| `compat.unsupported_capabilities_version` | 3 | The capability document is a version this `ggctl` does not read; upgrade `ggctl`. |
| `compat.capabilities_invalid` | 3 | The capability document is not a valid document of its version. |

### Schema diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `schema.unsupported_api_version` | 3 | No schema is published for that kind at that document version. |

### Output diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `output.write_failed` | 1 | Standard output could not be written, for example a closed pipe. |

### Internal diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `internal.runtime_unavailable` | 1 | The asynchronous runtime could not be started. |
| `internal.client_unavailable` | 1 | The HTTP client could not be built. |

## Platform notes

`ggctl` is tested on Linux, macOS and Windows. Exit codes, stream separation, terminal detection, token-file type and size checks and the remote client behave the same on all three. The owner-only permission check on token files applies on Unix only. Shell completion is generated for bash, zsh, fish and PowerShell.
