# ggctl, the operator CLI

`ggctl` is GreenGateway's operator command-line tool (issue #242, [ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md)). It is a separate binary: the `gateway` server keeps its name, its no-argument startup, its Docker entrypoint and its one-shot commands (`gateway migrate`, `gateway healthcheck`, `gateway import-standalone`, ...) unchanged.

**Status: alpha.** This build implements `version`, `schema`, `validate`, `doctor`, `diff`, `completion` and `help`, the output contract, the exit codes, secure bearer-token input and the version handshake with a running gateway. `validate` and `doctor` check a [configuration bundle](configuration-bundles.md) offline with the gateway's own bundle reader, and `diff` compares two bundles semantically and classifies each change's risk. `ggctl` cannot yet pin, convert, initialize, plan, apply, export or back up anything, and it cannot yet validate or diff an environment file (`--env`, `--against-env`) or diff against a server (`diff --server`): those are later #242 slices (see the ADR's [rollout](adr/0008-setup-cli-and-configuration-bundles.md#rollout)), and a name this build does not implement is refused as an unknown command (exit 2). Nothing here changes how a gateway is configured or started: no gateway reads a bundle yet.

## Building

`ggctl` has no build script and does not embed the admin UI, so it builds without Node:

```sh
cargo build --locked --release -p ggctl
# target/release/ggctl (ggctl.exe on Windows)
```

It is not yet part of the release artifacts or the container image; packaging, checksums, SBOM and signing for Linux, macOS and Windows come with #242 PR 18. CI builds and tests it on all three platforms.

The configuration contracts it shares with the gateway live in the `gateway-config` library crate, which both binaries link: the published document schemas, the `GatewayCapabilities` handshake document, RFC 8785 canonical JSON and the ADR-0004 digest frame, and the configuration bundle reader. Still in the gateway crate are the environment configuration compiler (`Config::from_env_vars`, being extracted by #433) and the production policy and tools validators, which depend on the rest of the gateway. The bundle reader takes those validators from its caller: the gateway passes its own, and `ggctl`, which cannot link them, reports that they did not run.

## Commands

```text
ggctl version [--server URL] [--ca-file PATH] [--token-stdin | --token-file PATH] [--timeout SECONDS] [--format human|json]
ggctl schema [KIND] [--api-version VERSION] [--format human|json]
ggctl validate BUNDLE [--strict] [--warnings-as-errors] [--format human|json|sarif]
ggctl doctor BUNDLE [--format human|json]
ggctl diff BUNDLE --against BUNDLE [--check] [--strict] [--format human|json|sarif]
ggctl completion bash|zsh|fish|powershell
ggctl help [COMMAND]
ggctl --help | --version
```

`ggctl help COMMAND` and `ggctl COMMAND --help` print a command's options. Help and the completion scripts are generated from the same command table the parser uses, so they cannot drift. Man pages, which ADR-0008 also generates from that table, arrive with packaging (#242 PR 18).

### `version`

Prints the `ggctl` version and the document versions whose schemas it publishes. With `--server` it performs the [version handshake](#version-handshake) and reports the gateway version and whether this `ggctl` can work with it, exiting `3` when it cannot. The check reads only; it never changes the server.

### `schema`

Without `KIND`, lists every document kind and version this `ggctl` publishes a JSON Schema (Draft 2020-12) for. With `KIND` (`GatewayBundle`, `GatewayDeployment`, `GatewayCapabilities` or `GgctlReport`), writes that schema to standard output, byte for byte as committed under [`docs/schemas`](schemas/) with LF line endings on every platform. `--api-version` selects a document version (default: the newest published); a version with no published schema exits `3`. Printing a schema writes an artifact, so `--format` is refused there. A schema is necessary but not sufficient: the gateway's reader is authoritative.

### `validate`

Reads the bundle in the directory `BUNDLE` with the bundle reader the gateway uses ([configuration bundles](configuration-bundles.md)) and reports every problem it finds, not just the first: unsafe or oversized files, the YAML subset and strict JSON, exact document versions, closed documents, references and SHA-256 pins, the published policy and tools schemas, and the deployment profile's policy invariants. It reads only beneath `BUNDLE`, writes nothing, makes no network request and reads no environment variable. `BUNDLE` must be valid UTF-8.

- The human result names the bundle and says `valid` or `invalid` with counts; for a valid bundle it adds the source digest, the files and the profile, marking a `development` profile `non-production`. Each diagnostic goes to standard error with its file, line, column and JSON Pointer.
- `--format json` writes one `GgctlReport` whose `result` holds `valid` and, once the manifest was read, what it declares (`bundle`); digests and the profile appear only when every stage passed. Diagnostics carry `location.file`, `location.pointer` and, where the reader has them, `location.line` and `location.column`.
- `--format sarif` writes one SARIF 2.1.0 log with one rule per code and one result per diagnostic. File locations are relative to the `BUNDLE_ROOT` base, which the log describes but never resolves, because the bundle's path is an argument and no argument is echoed; map it to the bundle's directory in the tool that ingests the log.
- `--strict` makes an entry the manifest does not reference an error instead of a warning. `--warnings-as-errors` keeps the diagnostics as they are and exits `3` when any warning was reported (`validate.warnings_as_errors`).

`ggctl` cannot link the gateway's production policy and tools validators, so it does not run them: a bundled policy or tools document is checked against the bundle's own rules and its published schema only, every report about one says so (`validate.production_validators_not_run`, severity `info`, and `productionValidator: not_run` in the result), and the gateway can still refuse a document `validate` accepted. A digest is integrity metadata, not a signature: a valid bundle is not thereby a trusted one.

Exit codes: `0` valid, `3` invalid (or any warning with `--warnings-as-errors`), `1` when the bundle could not be read at all (`bundle.root_unavailable`, `bundle.read_failed`, `bundle.changed_during_read`).

In CI, validate the bundle a change touches and keep the SARIF log for review:

```yaml
- name: Validate the configuration bundle
  run: ggctl validate deploy/bundle --strict --warnings-as-errors --format sarif > bundle.sarif
```

The step fails on exit `3` or `1`; upload `bundle.sarif` with the CI system's SARIF tooling if it annotates reviews.

### `doctor`

Runs the offline checks on the bundle in the directory `BUNDLE`. The doctor runs the same reader as `validate`, once, reports each stage as a check of its own, and then the [checks](#doctor-checks) that need more than the reader. It writes nothing, makes no network request and reads no environment variable; the network checks of ADR-0008 run only inside a gateway, which no `ggctl` command reaches yet.

Every check has a stable `id`, a `severity` (`error` for a required check, whose failure fails the doctor; `warning` for advice), a `status` of `pass`, `warning`, `fail` or `skipped`, a `reason` (the first bundle reader code the stage found, or one of the [reasons](#doctor-reasons) below), a `remediation` anchor and a `durationMs`; the checks drawn from the one reader run all report that run's duration. `skipped` never counts as `pass`: when the reader stopped before it could show a stage clean on every file, the stage is `skipped` with `doctor.incomplete`, not `pass`.

The human result lists each check's status, ID and reason on standard output and ends with whether a required check failed; the reader's diagnostics go to standard error. `--format json` writes one `GgctlReport` whose `result` holds `bundle` (as for `validate`) and `checks`. Exit codes: `0` when no required check failed, `3` when one did (with `doctor.required_check_failed`), `1` when the bundle could not be read.

### Doctor checks

| Check | Severity | What it covers |
| --- | --- | --- |
| `bundle.files` | error | The directory and its files: containment, links, special and hard-linked files, permissions, ownership, sizes, encoding and line endings. |
| `bundle.syntax` | error | Strict JSON and the YAML subset, and the structural bounds. |
| `bundle.compatibility` | error | Exact `apiVersion`, `kind` and resource `schema_version`. |
| `bundle.structure` | error | Closed documents, required members, values and secret-reference forms. |
| `bundle.references` | error | References between files, files present, and SHA-256 pins. |
| `bundle.resources` | error | The bundled policy and tools documents against the bundle's rules and their published schemas. |
| `bundle.profile` | error | A bundled policy against the deployment profile's invariants; `skipped` when the policy is the server's or there is none. |
| `bundle.unreferenced_entries` | warning | Directory entries the manifest does not reference. |
| `resources.production_validators` | error | The gateway's production policy and tools validators: always `skipped`, because they are not part of `ggctl`. |
| `deployment.profile` | warning | Whether the deployment is a production one: `warning` for `migration` and `development`. |

### Doctor reasons

| Reason | Meaning |
| --- | --- |
| `doctor.passed` | The check ran and found nothing. |
| `doctor.incomplete` | The reader stopped before it could show this check clean; see the other checks' reasons and the diagnostics. |
| `doctor.server_managed` | The policy is left to the server's store, which an offline check cannot read. |
| `doctor.not_declared` | The bundle declares nothing this check applies to. |
| `doctor.validator_unavailable` | The bundle supplies a policy or tools document, but the production validators run only in the gateway. |
| `doctor.migration_profile` | The deployment uses the `migration` profile, meant for moving an existing deployment over, not as a final state. |
| `doctor.development_profile` | The deployment uses the `development` profile, which is not for production. |

### `diff`

Compares the bundle in the directory `BUNDLE` with the one `--against` names, semantically: both are read by the same reader as `validate`, and the [semantic diff](semantic-diff.md) compares what they configure, never their text. The change is from the `--against` bundle to `BUNDLE`. The manifest, the deployment document and the policy and tools documents are compared member by member, so formatting, member order, the order of an unordered list and a spelled-out default never register. Each change carries its field (a dotted document path such as `policy.egress.hosts`), its section, whether it was added, removed or modified, its [change class](semantic-diff.md#what-a-change-carries), whether it `loosened`, `tightened` or did something `unknown` or `neutral`, and the stable [risk codes](semantic-diff.md#risk-codes) of what it weakens; a change no detector can classify carries `risk.unknown_impact`, never no code. Only booleans, fixed words and numbers are ever shown: every other value is withheld, with entry counts for a collection, and entry names (roles, tools) never appear. It reads only beneath the two directories, writes nothing, makes no network request and reads no environment variable. `BUNDLE` must be valid UTF-8, and neither path is ever echoed.

- The human result lists one line per change (severity, field, kind, the value or `(value withheld)` with counts, class, effect and codes) and ends with the number of changes, the highest severity and every code; `no changes` when nothing differs.
- `--format json` writes one `GgctlReport` whose `result` holds `valid`, `bundle` and `against` (each as `validate` reports a bundle) and, when both were read, `diff` ([`diffResult`](schemas/ggctl-report.v1alpha1.schema.json)).
- `--format sarif` writes one SARIF 2.1.0 log: the readers' diagnostics as `validate` writes them, then one rule per risk code (level `error` for a `high` code, `warning` for `medium`, `note` for `low`) and one result per risk code of each change, located at the change's field as a logical location. A change without a code is not a finding and has no result. This extends ADR-0008, which gave SARIF to `validate` only.
- `--check` exits `4` when the bundles differ at all (`diff.drift_found`), whatever the risk. `--strict` applies to both bundles as it does for `validate`.

A bundle that is invalid is not compared: the readers' diagnostics are reported, BUNDLE's first, and the result says `valid: false`. Diagnostics name bundle-relative files, so a diagnostic about a file both bundles have does not say which bundle it concerns; read `bundle` and `against` in the result, or validate each bundle on its own. As for `validate`, the production policy and tools validators do not run (`validate.production_validators_not_run`).

Exit codes: `0` when both bundles were compared, `4` with `--check` when they differ, `3` when either is invalid, `1` when either could not be read, `2` without `--against`. To gate a change in CI on the risk it carries, compare the proposed bundle with the deployed one and fail on what the codes say:

```yaml
- name: Review the configuration change
  run: ggctl diff deploy/bundle --against deployed/bundle --format sarif > bundle-diff.sarif
```

### `completion`

Writes a completion script to standard output. It completes commands, options, fixed choices, file names for path options and directory names for a `BUNDLE` argument.

| Shell | Install |
| --- | --- |
| bash | `ggctl completion bash > ~/.local/share/bash-completion/completions/ggctl` |
| zsh | `ggctl completion zsh > "${fpath[1]}/_ggctl"` |
| fish | `ggctl completion fish > ~/.config/fish/completions/ggctl.fish` |
| PowerShell | `ggctl completion powershell >> $PROFILE` |

## Output contract

- **Standard output carries only what was asked for**: an artifact (a schema, a completion script, help), the human result, with `--format json` exactly one `GgctlReport` document ([schema](schemas/ggctl-report.v1alpha1.schema.json)), or with `validate --format sarif` or `diff --format sarif` exactly one SARIF 2.1.0 log.
- **Diagnostics go to standard error** in human form. With `--format json` or `--format sarif` they are in the document instead and standard error stays empty.
- **An argument error found before a command runs** (an unknown option, a refused secret or insecure option, a malformed `--server`) is written to standard error only, exits `2`, and writes no report.
- **No color, no prompts, no progress output.** `ggctl` reads no configuration file and no environment variable, and makes no network request unless a command is given `--server`.

A report always has `apiVersion: greengateway.dev/v1alpha1`, `kind: GgctlReport`, the `command`, the process `exitCode` and its stable `outcome` name, the `diagnostics`, and a command-specific `result`. Every diagnostic has a stable `code`, a `severity` (`error`, `warning` or `info`), fixed `message` text, an optional fixed `hint`, a `remediation` anchor and at most one location: when it concerns one argument, that argument's 1-based `location.argument` position; when the bundle reader found it, the bundle-relative `location.file`, a `location.pointer` built from member names the reader defines, and the 1-based `location.line` and `location.column` where the reader has them. Diagnostics are value-free by construction: they never contain an argument, token, URL, path, address, document value, server response or library error text. An unknown option is reported by its position, never by its spelling, because the spelling may be a mistyped secret. A published code never changes meaning; renaming or removing one needs a new report version.

A report about a bundle carries the bundle reader's own codes (the `bundle`, `syntax`, `json`, `yaml`, `compat`, `schema`, `reference`, `secret`, `resource` and `profile` families), each listed in [configuration bundles](configuration-bundles.md#diagnostics), which is its remediation anchor. No code is spelled the same in both lists. A reader warning exits `0` on its own; a reader error exits `3`, or `1` when the bundle could not be read at all.

SARIF 2.1.0 output belongs to `validate`, which ADR-0008 gives it, and to `diff`, which reports its risk codes as results.

## Exit codes

| Code | Outcome | Meaning |
| --- | --- | --- |
| `0` | `success` | Success; for `diff --check`, no drift; for `doctor`, no required check failed. |
| `1` | `failure` | Unexpected internal, I/O or transport failure, including a mutation whose outcome could not be determined. |
| `2` | `usage` | Usage error, including a reserved command or a refused insecure option. |
| `3` | `invalid` | Invalid, incompatible or unsupported configuration, server or document version; a failed required doctor check; any warning under `--warnings-as-errors`. |
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

### Validate diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `validate.production_validators_not_run` | 0 | Information: the bundle supplies a policy or tools document, and the gateway's production validators, which are not part of `ggctl`, did not run on it. The gateway can still refuse it. |
| `validate.warnings_as_errors` | 3 | `--warnings-as-errors` was given and a warning was reported. |

### Doctor diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `doctor.required_check_failed` | 3 | A required [doctor check](#doctor-checks) failed. |

### Diff diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `diff.drift_found` | 4 | `--check` was given and the bundles differ. |

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

`ggctl` is tested on Linux, macOS and Windows. Exit codes, stream separation, terminal detection, token-file type and size checks and the remote client behave the same on all three. The owner-only permission check on token files applies on Unix only, and so does the bundle reader's refusal of a group- or other-writable bundle directory or file ([files and the directory](configuration-bundles.md#files-and-the-directory)); on Windows the reader enforces the link, reparse-point, regular-file and name rules, and ACLs are left to the operator. Shell completion is generated for bash, zsh, fish and PowerShell.
