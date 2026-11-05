# ggctl, the operator CLI

`ggctl` is GreenGateway's operator command-line tool (issue #242, [ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md)). It is a separate binary: the `gateway` server keeps its name, its no-argument startup, its Docker entrypoint and its one-shot commands (`gateway migrate`, `gateway healthcheck`, `gateway import-standalone`, ...) unchanged.

**Status: alpha.** This build implements `version`, `schema`, `init`, `validate`, `pin`, `convert`, `doctor`, `diff`, `ledger seed`, `ledger verify`, `ledger rollback`, the `policy` commands (`lint`, `test`, `explain`, `replay`), `evidence verify`, `completion` and `help`, the output contract, the exit codes, secure bearer-token input and the version handshake with a running gateway. `init` writes a new [configuration bundle](configuration-bundles.md) for a deployment profile, `validate` and `doctor` check one offline with the gateway's own bundle reader, `pin` rewrites its SHA-256 pins once its files validate, `convert` converts one between document versions, and `diff` compares two bundles semantically and classifies each change's risk. The `ledger` commands seed, verify and roll back a standalone state directory's [configuration revision ledger](configuration-ledger.md) offline, under the directory's lock. The [policy commands](#policy-commands) ask a gateway's own policy validator and evaluator (issue #243), and [`evidence verify`](#evidence-verify) checks a policy evidence package's integrity offline. `ggctl` cannot yet plan, apply, export or back up anything, it has no browser wizard (`init --web`), and it cannot yet validate, convert or diff an environment file (`--env`, `--against-env`) or diff against a server (`diff --server`): those are later #242 slices (see the ADR's [rollout](adr/0008-setup-cli-and-configuration-bundles.md#rollout)), and a name this build does not implement is refused as an unknown command (exit 2). Nothing here changes how a gateway is configured or started: no gateway reads a bundle or starts from a ledger yet.

## Building

`ggctl` has no build script and does not embed the admin UI, so it builds without Node:

```sh
cargo build --locked --release -p ggctl
# target/release/ggctl (ggctl.exe on Windows)
```

It is not yet part of the release artifacts or the container image; packaging, checksums, SBOM and signing for Linux, macOS and Windows come with #242 PR 18. CI builds and tests it on all three platforms.

The configuration contracts it shares with the gateway live in the `gateway-config` library crate, which both binaries link: the published document schemas, the `GatewayCapabilities` handshake document, RFC 8785 canonical JSON and the ADR-0004 digest frame, and the configuration bundle reader. Still in the gateway crate are the environment configuration compiler (`config::compile`, extracted by #433; see [its contract](architecture/configuration-compiler.md)) and the production policy and tools validators, which depend on the rest of the gateway. The bundle reader takes those validators from its caller: the gateway passes its own, and `ggctl`, which cannot link them, reports that they did not run.

## Commands

```text
ggctl version [--server URL] [--ca-file PATH] [--token-stdin | --token-file PATH] [--timeout SECONDS] [--format human|json]
ggctl schema [KIND] [--api-version VERSION] [--format human|json]
ggctl init --profile production|migration|development --output DIR [--answers FILE] [--format human|json]
ggctl validate BUNDLE [--strict] [--warnings-as-errors] [--format human|json|sarif]
ggctl pin BUNDLE [--strict] [--format human|json]
ggctl convert BUNDLE --to VERSION (--output DIR | --in-place) [--strict] [--format human|json]
ggctl doctor BUNDLE [--format human|json]
ggctl diff BUNDLE --against BUNDLE [--check] [--strict] [--format human|json|sarif]
ggctl ledger seed BUNDLE --state-dir DIR [--format human|json]
ggctl ledger verify --state-dir DIR [--format human|json]
ggctl ledger rollback REVISION --state-dir DIR [--acknowledge RISK_CODE]... [--format human|json]
ggctl policy lint FILE --server URL [REMOTE] [--warnings-as-errors] [--format human|json|sarif]
ggctl policy test SUITE --server URL [REMOTE] [--candidate FILE | --draft ID --draft-etag ETAG] [--format human|json|junit]
ggctl policy explain CASES --server URL [REMOTE] [--format human|json]
ggctl policy replay --server URL [REMOTE] (--base-etag ETAG --window FROM[/TO] [--candidate FILE | --draft ID --draft-etag ETAG] [--enforce-all-shadow] [--max-records N] [--idempotency-key KEY] | --job ID) [--wait] [--format human|json]
ggctl policy replay --server URL [REMOTE] --cancel ID [--format human|json]
ggctl evidence verify PACKAGE [--format human|json]
ggctl completion bash|zsh|fish|powershell
ggctl help [COMMAND [SUBCOMMAND]]
ggctl --help | --version
```

`REMOTE` stands for `[--ca-file PATH] [--token-stdin | --token-file PATH] [--timeout SECONDS]`, as for `version`. `ggctl help COMMAND` and `ggctl COMMAND --help` print a command's options. `ledger`, `policy` and `evidence` are command families; for instance `ledger` is one: `ggctl help ledger` and `ggctl ledger --help` list its commands, and `ggctl help ledger seed` and `ggctl ledger seed --help` print one. Help and the completion scripts are generated from the same command table the parser uses, so they cannot drift. Man pages, which ADR-0008 also generates from that table, arrive with packaging (#242 PR 18).

### `version`

Prints the `ggctl` version and the document versions whose schemas it publishes. With `--server` it performs the [version handshake](#version-handshake) and reports the gateway version and whether this `ggctl` can work with it, exiting `3` when it cannot. The check reads only; it never changes the server.

### `schema`

Without `KIND`, lists every document kind and version this `ggctl` publishes a JSON Schema (Draft 2020-12) for. With `KIND` (`GatewayBundle`, `GatewayDeployment`, `GatewayInitAnswers`, `GatewayCapabilities` or `GgctlReport`), writes that schema to standard output, byte for byte as committed under [`docs/schemas`](schemas/) with LF line endings on every platform. `--api-version` selects a document version (default: the newest published); a version with no published schema exits `3`. Printing a schema writes an artifact, so `--format` is refused there. A schema is necessary but not sufficient: the gateway's reader is authoritative.

### `init`

Creates a new bundle in the directory `--output` for the deployment profile `--profile` (`production`, `migration` or `development`; required): `bundle.yaml`, a deployment document declaring the profile and, in the default standalone topology, a policy that denies by default and enforces its decisions with no route and no role, and a tools document with no tools, each pinned by its SHA-256 digest, plus a `.gitattributes` that keeps their line endings LF. What each profile and topology writes is in [generated bundles](configuration-bundles.md#generated-bundles); the permissive starter policy is never written, and no file holds a secret or a credential. The output is deterministic: the same profile and answers always give the same bytes.

- `--answers FILE` replaces the defaults with a `GatewayInitAnswers` document ([schema](schemas/gateway-init-answers.v1alpha1.schema.json); YAML, or strict JSON when `FILE` ends in `.json`): the bundle's `name`, the `cluster` topology, which leaves policy and tools to the server as Connections are, or an `operator` role bound to one issuer and explicit authentication methods that may read status and configuration capabilities and nothing more. No member can hold a secret value. Because the answers decide which issuer the operator role trusts, `FILE` is read like `--ca-file`: a regular file of at most 64 KiB that, on Unix, no other account can change, either by writing it or by changing what its path resolves to (the rules are under [Remote server](#remote-server)). A problem in the document is reported with the bundle reader's code, located by the position of `--answers` with a JSON Pointer, line and column, never by its path.
- `--output DIR` must not exist, or must be an empty directory that is not a link; anything else is refused with `output.destination_exists` (exit `5`) and left exactly as it was. `ggctl` never overwrites.
- The files are written into a new hidden directory beside `DIR` (`.NAME.ggctl-staging-PID-N`, created exclusively), each created new and flushed to storage with the manifest last, read back with the gateway's bundle reader strictly, and only then renamed onto `DIR` (an empty `DIR` is removed first) and the parent directory flushed. Any failure removes the staging directory, so nothing that looks like a bundle is ever left at `DIR`; only a process killed mid-write can leave the hidden staging directory, which is safe to delete. On Unix the directory is `0700` and each file `0600`, checked after writing, and a filesystem that does not keep those modes is refused (`output.permissions_unavailable`). Windows has no mode bits: the new entries inherit the ACL of the directory they are created in, which, as for the bundle reader, is left to the operator.
- `ggctl` prompts for nothing, starts and deploys nothing, and makes no network request. The human result names the bundle, its digests, files and profile (marking `development` non-production) and the next step: review the files and run `ggctl validate --strict` on `DIR`. `--format json` writes one `GgctlReport` whose `result` holds `created`, `profile`, `topology`, `operator` and, once written, `bundle` as `validate` reports it.

As for `validate`, the gateway's production policy and tools validators are not part of `ggctl`; the gateway's own tests hold every bundle `init` can write to them and to the policy enforcement it configures. No gateway reads a bundle yet, so the generated policy and tools documents are, today, also usable as `POLICY_FILE` and `TOOLS_FILE` in environment mode.

Exit codes: `0` written, `3` invalid answers (or an answers file over 64 KiB), `5` when `DIR` holds anything, `2` for an answers file that is not a regular file or that another account could change, `1` when the answers could not be read or the bundle could not be written.

```sh
ggctl init --profile production --output deploy/bundle --answers deploy/init-answers.yaml
ggctl validate deploy/bundle --strict
```

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

### `pin`

The only command that rewrites manifest digests ([ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md#digests)), and it pins only files that validate. It reads the bundle in the directory `BUNDLE` with the same reader as `validate` and every check `validate` runs but one: each referenced file's SHA-256 is recorded instead of compared with its pin. Nothing is written unless every other check passed, so `pin` refuses a policy the profile forbids, a document that fails its schema, or a file that is missing, oversized, linked or not LF, exactly as `validate` does (exit `3`), and never pins a file that does not validate.

- Each pin that differs from its file's SHA-256 is replaced digit for digit where the reader found it, so every other byte of `bundle.yaml` (comments, member order, quoting and spacing) is kept, and a review shows only the digits that changed. A pin to replace must be written as its 64 digits between double or single quotes, as `init` writes it; any other spelling, plain or with escapes, is refused with `reference.pin_not_rewritable` at its line and column, and nothing is written. The manifest itself must be valid, each pin's form included (`reference.invalid_digest` for one that is not 64 lowercase hex digits).
- The new manifest is checked in memory first: with the other files exactly as read, it must read as a valid bundle with every check, its pins included. It is then written to a new hidden file beside `bundle.yaml` (`.bundle.yaml.ggctl-pin-PID-N`, created exclusively, `0600` and checked on Unix), flushed to storage and renamed over `bundle.yaml`, and on Unix the directory is flushed. A failed write leaves `bundle.yaml` exactly as it was and removes the hidden file (`pin.write_failed`); only a process killed before the rename can leave the hidden file behind, which the reader never opens and which is safe to delete. There is never a partial `bundle.yaml`.
- `bundle.yaml` must be a regular file. A link, such as the per-key link of a Kubernetes atomic-writer volume, is refused before anything is read (`pin.manifest_link`), and neither it nor its target is touched: pin the bundle's source, not the volume it is delivered in. `bundle.yaml` must also still hold the bytes `pin` read, checked before the hidden file is created and again just before the rename (`pin.manifest_changed`). A rename cannot compare and swap, so this narrows a race with another writer but cannot close it: do not edit a bundle while pinning it.
- When every pin already matches, nothing is written.
- The bundle is then read back with every check, its pins included, and must be exactly the files that were pinned. Otherwise a file changed while `pin` ran: the reader's errors are reported with `pin.read_back_failed`, and `ggctl validate` says what the bundle is now.
- On Unix the new `bundle.yaml` is `0600` and owned by the account that ran `pin`, whatever the old one's mode and owner were; on Windows it inherits the ACL of the bundle directory. Git records neither, so a checkout is unaffected, but a bundle a gateway reads in place under another account must be made readable to it again (for example `chmod 0644`; the reader refuses only group or other write).
- The human result says whether the bundle was pinned, gives its new source digest and lists each file with whether its pin changed. `--format json` writes one `GgctlReport` whose `result` holds `valid`, `bundle` (what the manifest declares, without digests), `files` (each with its `role`, `file`, `previous` and new `sha256` pin, and `changed`), `changed`, `written` and, once read back, `pinned`, whose `sourceDigest` is the bundle's new identity. `--strict` reads `BUNDLE` as `validate --strict` does.

`pin` reads only beneath `BUNDLE`, writes nothing but `bundle.yaml` and its hidden replacement, makes no network request, reads no environment variable and never echoes the path. A pin is integrity metadata, not a signature: pinning records what the files are and does not make them trusted, so review a change before you pin it. As for `validate`, the gateway's production policy and tools validators do not run (`validate.production_validators_not_run`).

Exit codes: `0` pinned or already pinned, `3` for an invalid bundle, a pin that cannot be replaced in place or a linked `bundle.yaml`, `5` when `bundle.yaml` changed while it was being pinned, `1` when the bundle could not be read, the new manifest could not be written, or the bundle did not read back as pinned.

```sh
$EDITOR deploy/bundle/policy.json
ggctl pin deploy/bundle
ggctl validate deploy/bundle --strict
git diff deploy/bundle   # the policy, and one pin in bundle.yaml
```

### `convert`

Converts the bundle in the directory `BUNDLE` to the document version `--to` names exactly (required). The bundle is read as `validate` reads it, and an invalid bundle is not converted. Each document version has one place on an ordered ladder and one step to the next, so a bundle is converted step by step from its own version up to `--to`: the result depends only on the bundle and the target, and a bundle already at `--to` is returned byte for byte, so converting twice is converting once. A `--to` older than the bundle is refused (`convert.downgrade_refused`), and so is any version this `ggctl` does not implement (`convert.unsupported_version`); `--to` is never echoed unless it names an implemented version.

- `--output DIR` writes the converted bundle as a new directory exactly as `init` writes one (staging, read back, rename, owner-only on Unix, never over a directory that holds anything).
- `--in-place` leaves `BUNDLE` where it is. A conversion that would change the bundle is refused in place (`convert.in_place_unavailable`) until an atomic in-place writer exists; write it with `--output` instead.
- `--strict` reads `BUNDLE` as `validate --strict` does. `--format json` writes one `GgctlReport` whose `result` holds `valid`, `bundle`, `from`, `to`, `changed`, `written` and, once written, `converted`.

`greengateway.dev/v1alpha1` is the only document version, so today every bundle is already at every version `ggctl` can convert to: `--output` writes an unchanged copy (with the same source digest) and `--in-place` changes nothing. A release that adds a version adds its step, and keeps reading the previous version for at least one minor release.

Exit codes: `0` converted, `3` for an invalid bundle, an unknown `--to` or a downgrade, `5` when `--output` holds anything, `2` without `--to` or with both or neither of `--output` and `--in-place`, `1` when a bundle could not be read or written.

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

### `ledger seed`

Creates the [configuration revision ledger](configuration-ledger.md) of the standalone state directory `--state-dir` (required) names, with the bundle in the directory `BUNDLE` as its first revision ([ADR-0008, "Seeding a ledger"](adr/0008-setup-cli-and-configuration-bundles.md#bootstrap-model)). The bundle is read with the gateway's own bundle reader strictly, as `validate --strict` reads it, so an entry the manifest does not reference is an error; an invalid bundle is reported like `validate` reports it, and the state directory is not touched. Then `ggctl` takes the state directory's [exclusive lock](configuration-bundles.md#the-state-directory) without waiting, and `RevisionLedger::seed` builds the ledger under a temporary name, commits and flushes it, and links it into place without replacing anything, so an interrupted seed leaves no ledger. The new revision is desired and not active, records `ggctl-ledger` as its system actor, no request and the `restart` activation class: no gateway has compiled it yet.

- A state directory that already holds `config-ledger.sqlite3`, or a previous ledger's `-wal`, `-shm` or `-journal` file, which a new ledger could replay, is refused with `ledger.exists` (exit `5`) and left exactly as it was. A ledger is created only once; there is no option that replaces one.
- A state directory a gateway or another `ggctl` holds is `state_dir.locked` (exit `5`); one that is missing, a link, not a directory or, on Unix, writable by group or other is refused with its [`state_dir` code](#state_dir-diagnostics) (exit `3`).
- The gateway's production policy and tools validators are not part of `ggctl` and do not run (`validate.production_validators_not_run`). A gateway starting from the ledger compiles its desired revision again, with them, and refuses to start if it does not compile (`ledger.gateway_recompiles_at_start`). Ledger mode itself (`GATEWAY_CONFIG_SOURCE=ledger`) is a later #242 slice: no gateway starts from a ledger yet.
- The human result names the bundle as `validate` does, then the desired revision (its `rev-` ID, sequence and operation) and the active one (`none`). `--format json` writes one `GgctlReport` whose `result` holds `valid`, `seeded`, `bundle` and, once seeded, `ledger`: the revision count, the `desired` revision, `active` (`null`) and `restartPending`.

Exit codes: `0` seeded, `3` for an invalid bundle or an unusable state directory, `5` when the state directory is locked or already holds a ledger or a ledger's journal file, `1` when the bundle or the ledger could not be read or written.

```sh
ggctl ledger seed deploy/bundle --state-dir /var/lib/greengateway
```

### `ledger verify`

Takes the state directory's exclusive lock, opens its ledger read-only (`RevisionLedger::inspect`) and runs the [full verification](configuration-ledger.md#verification) a gateway runs at start: the location and permissions of the directory and the file, the header, SQLite's `quick_check`, the exact schema and its triggers, every document against its pin, every record, its hash and its place in the chain, every rollback against its target, the request index and the pointer. Nothing in the ledger is written: not its journal mode, not a checkpoint, not a page. SQLite may create its `-wal` and `-shm` files beside a write-ahead ledger to read it, as any reader does, and the lock file is created if it is missing.

The human result is the revision count, the desired revision and the active one, or `configuration ledger corrupt (CLASS)`. `--format json` writes one `GgctlReport` whose `result` holds `verified` and either `ledger` (as for `ledger seed`) or, for a corrupt ledger, `corruption`: the class of what verification found (`integrity`, `format`, `schema`, `record`, `record_hash`, `chain`, `document`, `pointer` or `request`). A hash chain is integrity evidence, not authentication: it detects an edit made outside the gateway, not a whole ledger replaced by a consistent one.

Exit codes: `0` verified, `3` when the ledger is corrupt, missing, of an unsupported format or unsafely placed, `5` when the state directory is locked (a running gateway holds it), `1` when the ledger could not be read.

### `ledger rollback`

The offline lockout recovery path ([ADR-0008, "Recovery and lockout"](adr/0008-setup-cli-and-configuration-bundles.md#bootstrap-model)): when a revision locks every administrator out, stop the gateway and roll the ledger back to a revision that worked. `ggctl` takes the state directory's exclusive lock, opens and verifies the ledger, and plans the rollback to `REVISION` (`rev-` and 32 lowercase hexadecimal digits, as `ledger verify` reports one) through the gateway's own revision service (`RevisionService`) with the published-schemas compiler, under the system actor `ggctl-ledger`: the target's stored content is compiled again and diffed against the desired revision with the [semantic diff](semantic-diff.md), exactly as an online rollback plan is. A change no revision can carry, stored content the reader now refuses, a target that is not a revision of this ledger or is the desired revision, and a rollback that changes nothing are refused, and nothing is written.

- **Every risk code must be acknowledged by name.** Each risk code of the plan is given with its own `--acknowledge RISK_CODE`, which may be repeated; the set must be exactly the plan's codes, no more and no fewer. There is no option that acknowledges them all. Until it matches, nothing is written, and the report shows the plan, its diff, its `riskCodes` and the `unacknowledged` ones, so the operator can read what the rollback changes before acknowledging it.
- **Every risk code is acknowledgeable offline**, `risk.admin_access_path_removed` included, which no online request can acknowledge. Filesystem access to the state directory is already full control of a standalone deployment, so the offline command asks for no permission either; the plan's union of permissions is reported and recorded, but not checked.
- **History is only appended to.** The rollback is a new forward revision recording its target, the plan's changed sections, risk codes and permissions, `ggctl-ledger` as its system actor and no request; no revision is changed, removed or reordered. It is recorded with the `restart` activation class whatever its changes are, because no gateway is running to activate it: the desired pointer moves, the active pointer stays, and the next start compiles and activates it. It restores configuration only, never database schema, secret material, Connections or revoked credentials, none of which a ledger holds.
- The gateway's production policy and tools validators do not run in `ggctl` (`validate.production_validators_not_run`); the gateway compiles the revision again with them at start and refuses to start if it does not compile (`ledger.gateway_recompiles_at_start`).
- `REVISION` is never echoed: one outside the grammar is a usage error (exit `2`) located by its position, and the report names the target only as the ledger holds it. The human result is the plan's diff, then either the new revision and the pointer or what still needs acknowledging. `--format json` writes one `GgctlReport` whose `result` holds `rolledBack`, `plan` (`base`, `target`, `riskCodes`, `unacknowledged`, `changedSections`, `requiredPermissions`, the online `activation` class and the `diff`), and once rolled back the new `revision` and the `ledger` pointer, or `corruption` for a corrupt ledger.

Exit codes: `0` rolled back, `2` for a `REVISION` that is not a revision ID or an unknown risk code, `3` when the ledger or the target's content is invalid or a risk code is not acknowledged exactly, `5` when the state directory is locked, `1` when the ledger could not be read or written.

```sh
ggctl ledger verify --state-dir /var/lib/greengateway
ggctl ledger rollback rev-0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f --state-dir /var/lib/greengateway \
  --acknowledge risk.admin_access_path_removed --acknowledge risk.policy_broadened
```

### Policy commands

`ggctl policy lint`, `test`, `explain` and `replay` send a policy document, a [test suite](policy-tests.md), [simulation cases](policy-simulation.md) or a [replay request](policy-replay.md#replay-jobs) to the gateway `--server` names (required), and report what its own policy validator and evaluator answered. Nothing is judged in `ggctl`, so nothing it reports can disagree with what the gateway enforces, and none of these commands stores, publishes or activates a policy: `lint`, `test` and `explain` are side-effect free, and `replay` starts, reads or cancels a bounded job that reads the gateway's audit log. They use the [remote client](#remote-server) as `version --server` does (`--ca-file`, `--token-stdin` or `--token-file`, `--timeout`); they do not read the configuration capability document, so a token needs only the policy permissions below. The bundle and ledger commands never call them.

- **Documents.** `FILE`, `SUITE`, `CASES` and `--candidate FILE` are each a regular file of at most 2 MiB, the gateway's own request bound (a link to one is followed; a FIFO, device or directory is refused without being opened). They are sent as their exact bytes: a candidate policy is spliced into the request unchanged, which is what the gateway's exact-source rules for a policy v1 document need. `ggctl` checks only that a document it embeds in a request (`SUITE`, `CASES`, `--candidate`) is one JSON value in UTF-8 (`input.not_json`); `lint` sends `FILE` unexamined, and the validator reports what is wrong with it. A document grants nothing, so its mode is not checked. No path is ever echoed: a diagnostic about a document names its argument's position.
- **Answers.** An answer is read only as the document version this `ggctl` implements (`policy-test-results.v1`, `policy-simulation-results.v1`, `policy-replay-job.v1`, and the validator's diagnostics) and only when no string in it holds a control or bidirectional formatting character, so an answer cannot write to the terminal; anything else is `policy.response_invalid` (exit `3`). `--format json` repeats the gateway's document in `result` as it answered it. A refused request is reported by its HTTP status, the stable `reason` and the structured request `diagnostics` (code, JSON Pointer, fixed message), never by the free-text `error` or `errors` members, which may quote a document.
- **Statuses.** `401` and `403` are `remote.unauthenticated` and `remote.forbidden` (exit `8`); `400` and `422` `policy.request_refused` (`3`); `404` `policy.not_found` (`3`); `409`, `410`, `412` and `428` `policy.precondition_failed` (`5`): a stale base or draft ETag, a draft pinned to another base or an idempotency key reused for a different request, never rebased or resent; `413` `policy.request_too_large` (`3`); `408` and `429` `policy.busy` (`6`: nothing ran); `503` `remote.server_unavailable` (`6`).
- **Permissions.** Every policy command needs `admin:policy:read`. `test`, `explain` and `replay` also need `admin:policy:simulate`, and `replay` `admin:audit:read`. A policy whose routes gate the admin API needs a route for each endpoint ahead of a catch-all for unsafe policy methods; see [the test runs](policy-tests.md#running-a-suite).

#### `policy lint`

Sends the policy document in `FILE` to `POST <server>/policy/validate` and reports what the validator found: whether the document is `valid`, its `schema_version`, its ADR-0004 source and semantic digests, every diagnostic with its stable code, severity (`error`, `warning` or `risk`), JSON Pointer, element ID, fixed message and remediation and the uses it blocks (`simulation`, `tests`, `publication`, `evidence`), and the resource snapshot the cross-resource checks read. The validator judges the document as the replacement of the active policy, for the caller, exactly as a policy write would be judged, and stores nothing.

- `--format json` writes one `GgctlReport` whose `result` holds `valid`, `schemaVersion`, `sourceDigest`, `semanticDigest`, `diagnostics` and `resourceSnapshot` (`digest`, `complete`, `unavailable`), or a `refusal`.
- `--format sarif` writes one SARIF 2.1.0 log: `ggctl`'s own diagnostics, then one rule per validator code and one result per diagnostic (level `error`, or `warning` for a warning or a risk), located by a logical location whose `fullyQualifiedName` is the JSON Pointer and whose `name` is the element ID. A result has no file location, because the document's path is never echoed.
- `--warnings-as-errors` exits `3` when the validator reported any warning or risk (`validate.warnings_as_errors`).

Exit codes: `0` for a valid document, `3` for an invalid one (`policy.invalid`), and the statuses above.

```sh
printf '%s' "$POLICY_TOKEN" |
  ggctl policy lint deploy/bundle/policy.json --server https://gateway.example.test/v1/admin \
    --token-stdin --warnings-as-errors --format sarif > policy.sarif
```

#### `policy test`

Sends the `policy-tests.v1` suite in `SUITE` to `POST <server>/policy/tests/runs`, which decides every case with the evaluator live traffic uses, and reports the run. Without a candidate the suite runs against the active policy; `--candidate FILE` runs it against a complete policy document instead (the request's `policy` member), and `--draft ID --draft-etag ETAG` against one of your server-side drafts at that ETag, quotes included. Nothing is stored or activated.

- The human result gives the run's status and counts, the suite digest and the policy it ran against, then each case that did not pass with its status and what did not hold; `--format json` repeats the gateway's `policy-test-results.v1` report in `result.results`, with its `status`.
- `--format junit` writes the gateway's own JUnit XML report to standard output exactly as it answered it, once it is UTF-8 with no control character but tabs and line breaks and its `X-GreenGateway-Policy-Tests-Status` header names a status. Diagnostics go to standard error, since the report has no place for them.

Exit codes: `0` when every case passed; `3` when any case failed, was left undecided or was refused (`policy.tests_not_passed`), so an incomplete or erroring run never passes; and the statuses above. A JUnit report is still written when the suite did not pass.

```sh
ggctl policy test deploy/policy-tests.v1.json --candidate deploy/bundle/policy.json \
  --server https://gateway.example.test/v1/admin --token-file ~/.config/gg/token \
  --format junit > policy-tests.junit.xml
```

#### `policy explain`

Sends the `policy-simulation.v1` request in `CASES`, byte for byte, to `POST <server>/policy/simulations` and explains each case: for every projection, what the policy decided (`logical`), whether a denial is `enforced` or only `shadowed`, what the request would meet (`effective_action`), the stable `reason` and, where the candidate is not the base, the base's answer when it differs. The request names its own `base_etag`, candidate, trace level and projections, as the [simulation reference](policy-simulation.md#the-request) describes; a shadowed deny is reported as `deny ... shadowed would_forward`, never as an allow. `--format json` repeats the gateway's result document in `result.results`. Nothing is stored or activated, and no live state is read or charged.

Exit codes: `0` when the simulation completed, `5` for a stale `base_etag` or draft, `3` when the gateway refused the request, and the statuses above.

#### `policy replay`

Starts a [replay job](policy-replay.md#replay-jobs), reads one or cancels one.

- **Start**: `--base-etag` (the active policy's ETag, quotes included, as `GET <server>/policy` returns it) and `--window FROM[/TO]` (RFC 3339 date-times with an offset; without `TO` the window ends when the job is created) are required. The candidate is the active policy unless `--candidate FILE` or `--draft ID --draft-etag ETAG` names another; `--enforce-all-shadow` adds the projection with every shadow enforced; `--max-records N` bounds the records read (1 to 100000); `--idempotency-key KEY` names the request. `ggctl` writes the `policy-replay.v1` request and sends it once to `POST <server>/policy/replays`.
- **Read**: `--job ID` reads `GET <server>/policy/replays/ID`. **Cancel**: `--cancel ID` sends `DELETE` to the same path, which cancels a job that has not finished or discards one that has (`discarded: true`). A job ID is `rpl_` and 32 lowercase hexadecimal digits; nothing else becomes part of a path.
- `--wait` polls the job, at most every 5 seconds and for at most 10 minutes, until it has finished (`policy.wait_timed_out` otherwise; the job keeps running). Each poll is an idempotent read.
- A start is never resent. When its answer is lost after the request was sent, the job may exist: `ggctl` reports `policy.outcome_unknown` (exit `1`) and sends nothing more. Rerunning the same request under the same `--idempotency-key` answers with the job it started, if any, and starts nothing; without a key, a rerun starts another job.
- The human result names the job, its state, base ETag and freshness, candidate, window, cutoff, records and, once finished, whether its result is complete, its digest and its limitations. `--format json` writes one `GgctlReport` whose `result` holds `action` (`start`, `read` or `cancel`), the gateway's `policy-replay-job.v1` document as last read (`job`), `discarded` for a cancellation, or a `refusal`.

Exit codes: `0` when the job was started, read or cancelled, or, once finished, `completed`; `3` when it finished `completed_incomplete`, which satisfies no gate (`policy.replay_incomplete`); `5` when the base or draft is stale, or the active policy changed after the finished job was pinned (`policy.replay_stale`: its result is not evidence about the live policy); `1` when it finished without a result (`policy.replay_failed`: failed, cancelled or expired), the wait ran out, or a start's answer was lost; and the statuses above. A job that has not finished leaves the exit at `0`, so use `--wait` to gate on a result.

### `evidence verify`

Checks a [policy evidence package](policy-evidence.md) offline: `PACKAGE` is read once, at most 4 MiB, and nothing else is read, no network request is made and no environment variable is read. The package is held to the form a gateway serves it in, with the digest code the gateway computed its manifest with:

- the file is UTF-8 JSON without a byte-order mark and exactly its own RFC 8785 bytes; a re-encoded or pretty-printed file, a repeated member name or another spelling of a number is refused (`evidence.not_canonical`) even when every digest still matches, since it is not the file that was served;
- the envelope is a `policy-evidence.v1` object of `schema_version`, `generated_at`, `manifest` and the artifacts its manifest names, and nothing else (`evidence.unlisted_member`): an extra member such as an unverified signature is refused, not ignored;
- the manifest names `report` and, in a package that carries them, `analysis` and `report_markdown`, each at most once (`evidence.duplicate_entry`) and in that order, each with exactly the media type and schema version its name defines (`evidence.artifact_type_mismatch`); any other artifact is `evidence.unsupported_artifact`;
- every artifact the manifest names is present (`evidence.missing_artifact`), and its ADR-0004 digest and size are the ones its entry states (`evidence.digest_mismatch`, `evidence.size_mismatch`): for a JSON artifact the semantic digest over its RFC 8785 bytes, whose own `schema_version` must be its entry's, and for the Markdown rendering the source digest over its UTF-8 bytes;
- the report's own record of the analysis entry (`analysis.artifact`) is the manifest's (`evidence.binding_mismatch`), so the report digest binds the analysis too, and the report says it is unsigned.

Packages are unsigned: signing them, and verifying a signature against an out-of-band trust root, is a later #243 slice. So a package that passes is reported as `integrity_valid` and `unsigned`, with the information diagnostic `evidence.unsigned`: it is unchanged since its manifest was computed, and nothing shows who computed it. `ggctl` never reports a package as trusted, and a report that claims a signature is refused (`evidence.signature_unsupported`). Integrity says nothing about whether the policy is safe or the gateway's history and audit sources were complete; the report's own `completeness` and `limitations` are repeated as the report states them.

- The human result gives the verdict, the envelope (version, `generated_at`, size and the ADR-0004 source digest of the file), each artifact's digest, size and whether it verified, and the report's completeness.
- `--format json` writes one `GgctlReport` whose `result` holds `verdict` (`integrity_valid`, `integrity_invalid`, or `not_verified` for a version, artifact or signature claim this `ggctl` does not verify), `signature` (always `unsigned`), `trusted` (always `false`), `package` (`schemaVersion`, `generatedAt`, `size`, `sourceDigest`), `artifacts` and, for a verified package, `report` (`completeness`, `limitations`).

Exit codes: `0` integrity valid, `7` integrity failure (or a package over 4 MiB), `3` for a package or artifact version this `ggctl` does not verify or a signature claim, `2` for a `PACKAGE` that is not a regular file, `1` when it could not be read.

```sh
ggctl evidence verify policy-evidence.json --format json | jq -e '.result.verdict == "integrity_valid"'
```

### `completion`

Writes a completion script to standard output. It completes commands, a family's commands after its name (`ggctl ledger <TAB>`), options, fixed choices (risk codes for `--acknowledge`), file names for path options and document arguments, and directory names for a `BUNDLE` argument.

| Shell | Install |
| --- | --- |
| bash | `ggctl completion bash > ~/.local/share/bash-completion/completions/ggctl` |
| zsh | `ggctl completion zsh > "${fpath[1]}/_ggctl"` |
| fish | `ggctl completion fish > ~/.config/fish/completions/ggctl.fish` |
| PowerShell | `ggctl completion powershell >> $PROFILE` |

## Output contract

- **Standard output carries only what was asked for**: an artifact (a schema, a completion script, help), the human result, with `--format json` exactly one `GgctlReport` document ([schema](schemas/ggctl-report.v1alpha1.schema.json)), with `validate`, `diff` or `policy lint --format sarif` exactly one SARIF 2.1.0 log, or with `policy test --format junit` exactly the gateway's JUnit XML report.
- **Diagnostics go to standard error** in human form. With `--format json` or `--format sarif` they are in the document instead and standard error stays empty. A JUnit report has no place for them, so with `--format junit` they stay on standard error.
- **An argument error found before a command runs** (an unknown option, a refused secret or insecure option, a malformed `--server`) is written to standard error only, exits `2`, and writes no report.
- **No color, no prompts, no progress output.** `ggctl` reads no configuration file and no environment variable, and makes no network request unless a command is given `--server`.
- **Files are written only where a command is told to.** `init` and `convert --output` create the one directory `--output` names, and never write anything else, overwrite anything, or echo the path. `pin` replaces only `BUNDLE`'s `bundle.yaml`. The `ledger` commands write only beneath `--state-dir`: its lock file, which they create if it is missing; `ledger seed` creates the ledger and never replaces one, `ledger rollback` appends one revision to it, and `ledger verify` writes nothing in it.

A report always has `apiVersion: greengateway.dev/v1alpha1`, `kind: GgctlReport`, the `command`, the process `exitCode` and its stable `outcome` name, the `diagnostics`, and a command-specific `result`. Every diagnostic has a stable `code`, a `severity` (`error`, `warning` or `info`), fixed `message` text, an optional fixed `hint`, a `remediation` anchor and at most one location: when it concerns one argument, that argument's 1-based `location.argument` position; when the bundle reader found it, the bundle-relative `location.file`, a `location.pointer` built from member names the reader defines, and the 1-based `location.line` and `location.column` where the reader has them. Diagnostics are value-free by construction: they never contain an argument, token, URL, path, address, document value, server response or library error text. An unknown option is reported by its position, never by its spelling, because the spelling may be a mistyped secret. A published code never changes meaning; renaming or removing one needs a new report version.

A report about a bundle carries the bundle reader's own codes (the `bundle`, `syntax`, `json`, `yaml`, `compat`, `schema`, `reference`, `secret`, `resource` and `profile` families), each listed in [configuration bundles](configuration-bundles.md#diagnostics), which is its remediation anchor. No code is spelled the same in both lists. A reader warning exits `0` on its own; a reader error exits `3`, or `1` when the bundle could not be read at all.

SARIF 2.1.0 output belongs to `validate`, which ADR-0008 gives it, to `diff`, which reports its risk codes as results, and to `policy lint`, which reports the policy validator's diagnostics as results.

## Exit codes

| Code | Outcome | Meaning |
| --- | --- | --- |
| `0` | `success` | Success; for `diff --check`, no drift; for `doctor`, no required check failed. |
| `1` | `failure` | Unexpected internal, I/O or transport failure, including a mutation whose outcome could not be determined. |
| `2` | `usage` | Usage error, including a reserved command or a refused insecure option. |
| `3` | `invalid` | Invalid, incompatible or unsupported configuration, server or document version; a failed required doctor check; a policy that does not lint clean, a policy test suite that did not pass or an incomplete replay; any warning under `--warnings-as-errors`. |
| `4` | `drift` | Drift found by `diff --check`. |
| `5` | `conflict` | Precondition conflict: missing or stale ETag, plan, draft, acknowledgment, idempotency key or lock, a replay whose base changed, an output directory that is not empty, or a manifest that changed while it was being pinned. |
| `6` | `unavailable` | A dependency was unavailable and nothing was sent or committed; safe to retry. |
| `7` | `integrity` | Backup, archive or evidence package integrity failure, or restore verification failure. |
| `8` | `denied` | Authentication or authorization refused. |

When several errors apply, the one that must not be hidden wins: `1` over everything, and `6` only when nothing else went wrong, so a pipeline that retries on `6` never resends work another error left in doubt. Today `4` comes from `diff --check`; `5` from an `init` or `convert --output` directory that is not empty, a `bundle.yaml` that changed while `pin` ran, a state directory another process holds locked (`state_dir.locked`), a `ledger seed` into a state directory that already holds a ledger (`ledger.exists`), and a stale ETag, draft or idempotency key or a replay whose base changed in the policy commands; and `7` from `evidence verify`. The plan conflicts of `5`, and the backup and restore failures of `7`, belong to commands later slices add.

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

- HTTPS uses the platform's trust store with normal certificate and hostname verification. `--ca-file PATH` adds the PEM certificates in one regular file of at most 1 MiB as further trust anchors; it does not replace the platform's, and it applies only to an `https` server. It is read like `--token-file`, and because these anchors decide which server receives the token, on Unix another account must not be able to change the file or what its path resolves to (`trust.ca_file_unsafe_permissions`). The file may be world-readable (`0644`), but a file writable by group or other (`0664`, `0666`) is refused. `ggctl` then resolves the path from `/` (a relative path from the working directory), following each symbolic link, including any inside a link's target, and refuses it when the file, any directory above it up to `/`, or any link on the way is owned by an account other than root or the one running `ggctl`, or when group or other can write one of those directories without the sticky bit: any of them lets that account put a file of its own in place. A sticky directory such as `/tmp` is accepted for a file you or root own, never for one another account created there first, and a file under a world-writable directory without the sticky bit is refused however deep it is. Running as root, a file another account owns is refused too; `chown` it or copy it somewhere root owns. Windows leaves the file's ACL to the operator. On Linux the platform store honors `SSL_CERT_FILE` and `SSL_CERT_DIR`, as every client using it does. There is no option that disables verification.
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
| `usage.conflicting_options` | 2 | Two options that exclude each other were both given: `--token-stdin` and `--token-file`, a `--candidate` and a `--draft`, or `--job`, `--cancel` and the options that start a replay. |
| `usage.option_requires_server` | 2 | `--ca-file`, `--token-stdin`, `--token-file` or `--timeout` was given without `--server`. |
| `usage.server_required` | 2 | A policy command was given no `--server`; it has no offline form. |
| `usage.missing_option` | 2 | An option the command, or another option given, needs was not given: `--draft` and `--draft-etag` go together, and starting a replay needs `--base-etag` and `--window`. |
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
| `trust.ca_file_unsafe_permissions` | 2 | Another account could change the CA file (Unix): it is writable by group or other; it, a directory above it or a link on its path is owned by an account other than root and the one running `ggctl`; or group or other can write one of those directories without the sticky bit. |
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
| `remote.forbidden` | 8 | HTTP 403: the principal lacks the route's permission (`admin:config:read` for the handshake; see [the policy commands](#policy-commands) for theirs). |
| `remote.server_unavailable` | 6 | HTTP 503: a dependency of the server is unavailable. |
| `remote.unexpected_status` | 1 | Any other HTTP status. |
| `remote.response_too_large` | 1 | The response is larger than `ggctl` accepts. |
| `remote.unexpected_content_type` | 1 | The response is not `application/json` (for `policy test --format junit`, `application/xml`). |

### Input diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `input.unreadable` | 1 | A document file (`FILE`, `SUITE`, `CASES`, `--candidate`, `PACKAGE`) could not be opened or read. |
| `input.not_regular_file` | 2 | A document file is not a regular file, such as a directory, FIFO or device. |
| `input.too_large` | 3 | A document file is larger than 2 MiB, the gateway's request bound. |
| `input.not_json` | 3 | A document `ggctl` embeds in a request is not exactly one JSON value in UTF-8. Nothing was sent. |

### Policy diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `policy.invalid` | 3 | `policy lint`: the gateway's policy validator reported an error in the document. |
| `policy.tests_not_passed` | 3 | `policy test`: a case failed, was left undecided or was refused; only a `passed` run exits `0`. |
| `policy.replay_incomplete` | 3 | The replay job finished `completed_incomplete`: its result covers less than its window and satisfies no gate. |
| `policy.replay_failed` | 1 | The replay job ended without a result: it failed, was cancelled or expired. |
| `policy.replay_stale` | 5 | The active policy changed after the finished replay job was pinned: its result is not evidence about the live policy. Start a new job. |
| `policy.wait_timed_out` | 1 | The replay job did not finish within the 10 minutes `--wait` allows; it may still be running. Read it later with `--job`. |
| `policy.request_refused` | 3 | HTTP 400 or 422: the gateway refused the request as invalid; the result's `refusal` carries its `reason` and structured diagnostics. |
| `policy.not_found` | 3 | HTTP 404: no policy is configured, or no draft, history version or replay job of the caller's has that ID. |
| `policy.precondition_failed` | 5 | HTTP 409, 410, 412 or 428: a stale base or draft ETag, an expired draft, a draft pinned to another base, or an idempotency key reused for a different request. Nothing was resent or rebased. |
| `policy.request_too_large` | 3 | HTTP 413: the request body is over the gateway's bound. |
| `policy.busy` | 6 | HTTP 408 or 429: the gateway started nothing, because its evaluation slots were taken or the body did not arrive in time. Safe to retry. |
| `policy.response_invalid` | 3 | The gateway's answer is not a document of the version this `ggctl` reads, or holds a control or bidirectional formatting character. |
| `policy.outcome_unknown` | 1 | A replay start reached the gateway but its answer was lost or unreadable, so a job may have started. Nothing was resent; the hint says how to find the job. |

### Evidence diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `evidence.unsigned` | 0 | Information: the package's integrity verified, and it is unsigned, so nothing shows who produced it. `ggctl` never reports it as trusted. |
| `evidence.package_too_large` | 7 | The package is larger than 4 MiB, the most a gateway serves. |
| `evidence.malformed` | 7 | The package is not a policy evidence envelope: not a JSON object, a member missing, of the wrong type or out of order, a manifest entry with other members than its five, or a report that does not say whether it is signed. |
| `evidence.not_canonical` | 7 | The package is not exactly its RFC 8785 bytes: whitespace, member order, a repeated member name or a number's spelling differs from the form a gateway serves. |
| `evidence.unsupported_version` | 3 | The package is a schema version other than `policy-evidence.v1`. |
| `evidence.unsupported_artifact` | 3 | The manifest names an artifact this `ggctl` does not verify. |
| `evidence.artifact_type_mismatch` | 7 | An artifact's media type or schema version is not the one its name defines, or a JSON artifact states another schema version than its entry, or the Markdown rendering is not a string. |
| `evidence.duplicate_entry` | 7 | The manifest names one artifact more than once. |
| `evidence.missing_artifact` | 7 | The manifest names an artifact the package does not hold, or does not name the report. |
| `evidence.unlisted_member` | 7 | The package holds a member its manifest does not list. |
| `evidence.size_mismatch` | 7 | An artifact's size is not the one its manifest entry states. |
| `evidence.digest_mismatch` | 7 | An artifact's ADR-0004 digest is not the one its manifest entry states: the artifact changed after the manifest was computed. |
| `evidence.binding_mismatch` | 7 | The report's own record of an artifact (the analysis) differs from the manifest's entry for it, or names one the package does not carry. |
| `evidence.signature_unsupported` | 3 | The report claims a signature, which this `ggctl` cannot verify. |

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

### Init diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `init.answers_unreadable` | 1 | The `--answers` file could not be opened or read. |
| `init.answers_not_regular_file` | 2 | The `--answers` file is not a regular file. |
| `init.answers_unsafe_permissions` | 2 | Another account could change the `--answers` file (Unix), under the same rules as `trust.ca_file_unsafe_permissions`. |
| `init.answers_too_large` | 3 | The `--answers` file is larger than 64 KiB. |

A problem inside the answers document is reported with the [bundle reader's code](configuration-bundles.md#diagnostics), such as `schema.unknown_member` or `schema.not_applicable`.

### Convert diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `convert.unsupported_version` | 3 | `--to` is not a document version this `ggctl` can convert the bundle to. |
| `convert.downgrade_refused` | 3 | `--to` is older than the bundle's document version; `ggctl` never converts down. |
| `convert.in_place_unavailable` | 3 | The conversion would change the bundle, which `--in-place` cannot do atomically yet; use `--output`. No conversion that changes a bundle exists while `greengateway.dev/v1alpha1` is the only version. |

### Pin diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `pin.manifest_link` | 3 | `bundle.yaml` is a link or not a regular file, as in a Kubernetes atomic-writer volume. Nothing was written, and the link's target was not touched; pin the bundle's source instead. |
| `pin.manifest_changed` | 5 | `bundle.yaml` changed after `ggctl pin` read it. Nothing was written; pin again once nothing else is editing the bundle. |
| `pin.write_failed` | 1 | The new `bundle.yaml` could not be created, written, flushed or renamed into place, for example on a read-only filesystem. `bundle.yaml` was left as it was, and the hidden file was removed. |
| `pin.permissions_unavailable` | 1 | The filesystem did not keep mode `0600` on the new `bundle.yaml` (Unix). `bundle.yaml` was left as it was. |
| `pin.read_back_failed` | 1 | The bundle did not read back as the files that were pinned: a file changed while `ggctl pin` ran. The reader's errors say which; run `ggctl validate`. |

A pin that must change but is not written as its 64 digits between quotes is the [bundle reader's code](configuration-bundles.md#diagnostics) `reference.pin_not_rewritable` (exit `3`), located at the pin.

### State_dir diagnostics

The [state directory](configuration-bundles.md#the-state-directory)'s own codes, located by the position of `--state-dir`. Nothing was read or written when one is reported.

| Code | Exit | Meaning |
| --- | --- | --- |
| `state_dir.missing` | 3 | Nothing is at the `--state-dir` path. |
| `state_dir.not_directory` | 3 | `--state-dir` names something other than a directory. |
| `state_dir.link` | 3 | `--state-dir` names a symbolic link, junction or reparse point. Name the directory itself. |
| `state_dir.unsafe_permissions` | 3 | The state directory is writable by group or other (Unix), who could replace a store. |
| `state_dir.unsafe_lock_file` | 3 | `state.lock` is a link, not a regular file, or writable by group or other (Unix). |
| `state_dir.locked` | 5 | A gateway or another `ggctl` holds the state directory's lock. Stop the gateway first; `ggctl` never waits. |
| `state_dir.lock_unsupported` | 3 | The filesystem cannot take an exclusive lock, so exclusive use cannot be promised. Network filesystems are unsupported. |
| `state_dir.unavailable` | 1 | The state directory or its lock file could not be inspected, opened or locked. |

### Ledger diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `ledger.missing` | 3 | The state directory holds no configuration ledger; create one with `ggctl ledger seed`. |
| `ledger.exists` | 5 | The state directory already holds a ledger, or a previous ledger's `-wal`, `-shm` or `-journal` file, which a new ledger could replay. Nothing was written. |
| `ledger.unsafe_location` | 3 | The state directory or `config-ledger.sqlite3` is a link, not the expected kind of entry, or writable by group or other (Unix). |
| `ledger.unsupported` | 3 | The ledger is in a format, or records a document version, this `ggctl` does not support. |
| `ledger.corrupt` | 3 | The ledger failed [verification](configuration-ledger.md#verification); the result's `corruption` names the class. Nothing was written. |
| `ledger.full` | 3 | The ledger holds the most revisions it may (1,024) and pruning is a later slice. Nothing was written. |
| `ledger.refused` | 3 | The ledger refused to record the revision, for example a clock before the Unix epoch. Nothing was written. |
| `ledger.stale` | 5 | The ledger's head changed while `ggctl` held its lock, which only another handle in the same process could do. Nothing was written. |
| `ledger.unavailable` | 1 | The ledger could not be read or written: busy, read-only, out of space or another I/O failure. |
| `ledger.rollback_target_unknown` | 3 | `REVISION` is not a revision of this ledger; it is located by its position and never echoed. |
| `ledger.rollback_target_is_head` | 3 | `REVISION` is already the desired revision. |
| `ledger.rollback_target_invalid` | 3 | `REVISION`'s stored content no longer passes the bundle reader's checks; the reader's diagnostics follow. |
| `ledger.head_invalid` | 3 | The desired revision's stored content no longer passes the reader's checks, so no rollback can be assessed against it. |
| `ledger.change_not_applicable` | 3 | The rollback changes what no revision can carry (a `bootstrap`, `connection_or_secret`, `cluster_operation`, `coordinated_cutover` or `unsupported` change). |
| `ledger.change_unclassified` | 3 | The rollback differs in a way the semantic diff could not classify, so it is refused rather than recorded without a code. |
| `ledger.not_normalizable` | 3 | `REVISION`'s stored content has no canonical form. |
| `ledger.no_change` | 3 | Rolling back to `REVISION` changes nothing: the desired revision already has its content. |
| `ledger.acknowledgement_required` | 3 | The rollback carries risk codes and `--acknowledge` named none; the result lists them. Nothing was written. |
| `ledger.acknowledgement_mismatch` | 3 | `--acknowledge` must name exactly the rollback's risk codes, each once or more, and nothing else. Nothing was written. |
| `ledger.nothing_to_acknowledge` | 3 | `--acknowledge` was given, but the rollback carries no risk code. Nothing was written. |
| `ledger.unexpected_refusal` | 1 | The revision service refused the rollback for a reason the offline path does not expect. Nothing was written; report it. |
| `ledger.gateway_recompiles_at_start` | 0 | Information: a gateway starting from this ledger compiles its desired revision again, with the production policy and tools validators, and refuses to start if it does not compile. |

### Output diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `output.write_failed` | 1 | Standard output could not be written, for example a closed pipe. |
| `output.destination_exists` | 5 | The `--output` directory exists and is not empty, or is a link or a file. Nothing was written, and it was left as it was. |
| `output.destination_unusable` | 1 | The `--output` directory could not be created or written, for example because its parent does not exist. Nothing was left at it. |
| `output.permissions_unavailable` | 1 | The filesystem did not keep owner-only modes on what was written (Unix). Nothing was left at the `--output` directory. |
| `output.written_bundle_invalid` | 1 | What was written did not read back as the same valid bundle; the reader's diagnostics say why. Nothing was left at the `--output` directory. |

### Internal diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `internal.runtime_unavailable` | 1 | The asynchronous runtime could not be started. |
| `internal.client_unavailable` | 1 | The HTTP client could not be built. |

## Platform notes

`ggctl` is tested on Linux, macOS and Windows. Exit codes, stream separation, terminal detection, token-file and document type and size checks, the remote client and evidence verification behave the same on all three. The owner-only permission check on token files applies on Unix only, as do the owner, mode and path checks on `--ca-file` and `--answers` files, and so does the bundle reader's refusal of a group- or other-writable bundle directory or file ([files and the directory](configuration-bundles.md#files-and-the-directory)); on Windows the reader enforces the link, reparse-point, regular-file and name rules, and ACLs are left to the operator. Likewise `init` and `convert --output` create their directory `0700` and its files `0600` on Unix and check those modes, and `pin` writes its new `bundle.yaml` `0600` and checks it, while on Windows the new entries inherit the ACL of the directory they are created in. Shell completion is generated for bash, zsh, fish and PowerShell.
