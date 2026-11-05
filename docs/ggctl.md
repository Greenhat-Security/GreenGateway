# ggctl, the operator CLI

`ggctl` is GreenGateway's operator command-line tool (issue #242, [ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md)). It is a separate binary: the `gateway` server keeps its name, its no-argument startup, its Docker entrypoint and its one-shot commands (`gateway migrate`, `gateway healthcheck`, `gateway import-standalone`, ...) unchanged.

**Status: alpha.** This build implements `version`, `schema`, `init`, `validate`, `pin`, `convert`, `doctor`, `diff`, `ledger seed`, `ledger verify`, `ledger rollback`, `backup create`, `backup verify`, `backup restore`, `completion` and `help`, the output contract, the exit codes, secure bearer-token input and the version handshake with a running gateway. `init` writes a new [configuration bundle](configuration-bundles.md) for a deployment profile, `validate` and `doctor` check one offline with the gateway's own bundle reader, `pin` rewrites its SHA-256 pins once its files validate, `convert` converts one between document versions, and `diff` compares two bundles semantically and classifies each change's risk. The `ledger` commands seed, verify and roll back a standalone state directory's [configuration revision ledger](configuration-ledger.md) offline, under the directory's lock. The `backup` commands back up the stores beneath a standalone state directory offline, under the directory's lock, verify a backup completely, and restore one into an empty or stopped state directory, which they leave as it was on any failure ([standalone backups](standalone-backup.md)). `ggctl` cannot yet plan, apply or export anything, it has no browser wizard (`init --web`), and it cannot yet validate, convert or diff an environment file (`--env`, `--against-env`) or diff against a server (`diff --server`): those are later #242 slices (see the ADR's [rollout](adr/0008-setup-cli-and-configuration-bundles.md#rollout)), and a name this build does not implement is refused as an unknown command (exit 2). Nothing here changes how a gateway is configured or started: no gateway reads a bundle or starts from a ledger yet.

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
ggctl backup create --state-dir DIR --output FILE [--format human|json]
ggctl backup verify FILE [--format human|json]
ggctl backup restore FILE --state-dir DIR [--replace-existing-state] [--format human|json]
ggctl completion bash|zsh|fish|powershell
ggctl help [COMMAND [SUBCOMMAND]]
ggctl --help | --version
```

`ggctl help COMMAND` and `ggctl COMMAND --help` print a command's options. `ledger` and `backup` are command families: `ggctl help ledger` and `ggctl ledger --help` list a family's commands, and `ggctl help ledger seed` and `ggctl ledger seed --help` print one. Help and the completion scripts are generated from the same command table the parser uses, so they cannot drift. Man pages, which ADR-0008 also generates from that table, arrive with packaging (#242 PR 18).

### `version`

Prints the `ggctl` version and the document versions whose schemas it publishes. With `--server` it performs the [version handshake](#version-handshake) and reports the gateway version and whether this `ggctl` can work with it, exiting `3` when it cannot. The check reads only; it never changes the server.

### `schema`

Without `KIND`, lists every document kind and version this `ggctl` publishes a JSON Schema (Draft 2020-12) for. With `KIND` (`GatewayBundle`, `GatewayDeployment`, `GatewayInitAnswers`, `GatewayCapabilities`, `GgctlReport` or `GatewayBackup`), writes that schema to standard output, byte for byte as committed under [`docs/schemas`](schemas/) with LF line endings on every platform. `--api-version` selects a document version (default: the newest published); a version with no published schema exits `3`. Printing a schema writes an artifact, so `--format` is refused there. A schema is necessary but not sufficient: the gateway's reader is authoritative.

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

### `backup create`

Backs up the stores beneath the standalone state directory `--state-dir` (required) names into the new archive `--output` (required) names, as [standalone backups](standalone-backup.md#creating-a-backup) describes. `ggctl` takes the state directory's [exclusive lock](configuration-bundles.md#the-state-directory) without waiting, so the gateway must be stopped. Each store of the layout that exists is snapshotted with SQLite's `VACUUM INTO` from a read-only connection, never copied file by file, and neither the store nor its write-ahead log is written; two names for one file are snapshotted once; the ledger must pass its full verification and every snapshot SQLite's integrity check. Nothing else in the directory is read. The archive is written to a new hidden file beside `--output`, owner-only on Unix, flushed, read back with every check of `backup verify`, and only then linked to `--output`, which must not exist and is never replaced. A failure leaves nothing at `--output`.

- A backup is never written to standard output: `--output -` is refused (`backup.stdout_refused`, exit `2`).
- A backup holds no pending login, session, cache, plaintext token, secret value or key. The Connections store keeps its secrets as #240 ciphertext, and the key files under `CONNECTION_SECRETS_ROOT` that decrypt them are a separate artifact to back up separately; a backup that includes the Connections store says so (`backup.secret_keys_not_included`, information).
- The human result names each store with its entry, tables and rows, the counts, the program and SQLite versions and, for the ledger, its revisions. `--format json` writes one `GgctlReport` whose `result` holds `created` and, once written, `backup`: the manifest's versions, the seven stores of the layout in order (`store`, `included`, `entry`, `tables`, `rows`), the counts and the `ledger`'s revision count, `desired` and `active` revisions and `restartPending`. A refusal about one store names it as `result.store` (`audit`, `discovery`, `principals`, `connections`, `service_tokens`, `policy_history` or `config_ledger`); no path is ever echoed.

Exit codes: `0` written, `3` for a store that is a link, not a regular file, writable by group or other, or corrupt, a ledger that does not verify or shares its file, an unusable state directory, or one that holds no store, `5` when the state directory is locked or `--output` exists, `7` when what was written did not verify, `1` when a store or the archive could not be read or written.

### `backup verify`

Reads the archive `FILE` completely through the shared [archive admission rules](archive-admission.md), into a new hidden staging directory beside it that is removed afterwards, and checks everything [standalone backups](standalone-backup.md#verifying-a-backup) lists: each entry header before its data, the `GatewayBackup` manifest as a closed document of a version this `ggctl` reads, exactly the manifest's entries in its order with each one's SHA-256, the archive's own digest, and each database's rollback-journal mode, integrity check, header versions, schema digest and table rows, and the ledger's full verification and revisions. It never changes the archive and writes nothing else. `FILE` must be valid UTF-8, and it is never echoed.

- The human result is the store list, as `backup create` reports it. `--format json` writes one `GgctlReport` whose `result` holds `verified` and, once verified, `backup`; a refusal about one store names it as `result.store`.
- A refusal by the admission rules carries their own code (the `archive` family, listed in [archive admission](archive-admission.md#codes), which is its remediation anchor) and is located by the 1-based position of the entry (`location.entry`) and, for a clash, of the earlier entry (`location.conflictsWith`); an entry's name is never echoed.
- A digest is integrity evidence, not authenticity: whoever can write an archive can write a consistent one.

Exit codes: `0` verified, `7` for any integrity failure (truncation, tampering, traversal, links or special entries, duplicate or case-colliding entries, a bomb, an unsupported version, a database that fails its checks), `3` when `FILE` is a link or not a regular file, `1` when it or the staging directory could not be read or written.

```sh
ggctl backup create --state-dir /var/lib/greengateway --output /backups/greengateway.ggbk
ggctl backup verify /backups/greengateway.ggbk
```

### `backup restore`

Restores the archive `FILE` into the state directory `--state-dir` (required) names, as [standalone backups](standalone-backup.md#restoring-a-backup) describes, or leaves it as it was. `ggctl` takes the directory's [exclusive lock](configuration-bundles.md#the-state-directory) without waiting, so the gateway must be stopped. The directory must exist and be empty apart from its lock file, or, with `--replace-existing-state`, hold nothing but the layout's entries (the stores' files with their `-wal`, `-shm` and `-journal` files, `state.lock` and `restore-marker.json`), each a regular file. There is no option that overwrites anything else. It must not be a mount point.

The archive is extracted into a new hidden staging directory beside `--state-dir`, named from 128 random bits and owner-only on Unix, and checked there with every check of `backup verify`, then with the restore's own: each store's SQLite application ID, owner-only modes, and a flush of every file. A [restore marker](standalone-backup.md#the-restore-marker) is written beside the stores; the next gateway start from the directory records it as `config.restore_detected` and removes it. Only then is `--state-dir` renamed aside, the staging directory renamed into its place and their parent flushed, and the replaced directory removed. Any failure removes the staging directory and leaves `--state-dir` as it was, except `restore.rollback_failed`. `FILE` must be valid UTF-8; no path is ever echoed.

- The human result is the store list, as `backup create` reports it, and the restore's ID. `--format json` writes one `GgctlReport` whose `result` holds `restored` and, once restored, `restoreId`, `replaced` (whether `--replace-existing-state` replaced stores) and `backup`; when nothing was restored it holds `targetUnchanged`, which is `true` unless `restore.rollback_failed` was reported. A refusal about one store names it as `result.store`.
- An archive problem carries the code `backup verify` reports for it, located at `FILE`; a state directory or target problem is located at `--state-dir`.
- Restoring the Connections store says that its key files must come back from their own backup (`restore.secret_keys_required`, information).
- Run the restore as the account the gateway runs as: the restored files belong to the account that ran `ggctl`, `0600` inside a `0700` directory on Unix.

Exit codes: `0` restored, `7` when the archive does not verify (truncation, tampering, traversal, links or special entries, duplicate or case-colliding entries, a bomb, an unsupported manifest, container or ledger version, a database that fails its checks or claims another store's identity), `3` for a state directory that is not admissible, holds what the layout does not name or is a mount point, and for an archive that is a link, not a regular file, or a PostgreSQL dump, `5` when the state directory is locked, holds stores without `--replace-existing-state`, or changed while the restore ran, `1` when anything could not be read, written, flushed or renamed. The [standalone disaster-recovery runbook](deployment/standalone-disaster-recovery.md) puts the commands in order.

```sh
ggctl backup restore /backups/greengateway.ggbk --state-dir /var/lib/greengateway/state
ggctl backup restore /backups/greengateway.ggbk --state-dir /var/lib/greengateway/state --replace-existing-state
```

### `completion`

Writes a completion script to standard output. It completes commands, a family's commands after its name (`ggctl ledger <TAB>`), options, fixed choices (risk codes for `--acknowledge`), file names for path options and for a backup archive argument, and directory names for a `BUNDLE` argument.

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
- **Files are written only where a command is told to.** `init` and `convert --output` create the one directory `--output` names, and never write anything else, overwrite anything, or echo the path. `pin` replaces only `BUNDLE`'s `bundle.yaml`. The `ledger` commands write only beneath `--state-dir`: its lock file, which they create if it is missing; `ledger seed` creates the ledger and never replaces one, `ledger rollback` appends one revision to it, and `ledger verify` writes nothing in it. `backup create` creates the archive at `--output` and nothing else that stays: in `--state-dir` it writes only the lock file, if that is missing, and the hidden working, partial and verification entries it makes beside `--output` are removed. `backup verify` writes only a hidden staging directory beside `FILE`, which it removes. `backup restore` writes only a hidden staging directory beside `--state-dir`, which becomes `--state-dir` or is removed, and the lock file in `--state-dir`, which it removes again when the restore fails and the directory had none; the replaced directory, renamed aside, is removed.

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
| `5` | `conflict` | Precondition conflict: missing or stale ETag, plan, acknowledgment or lock, an output directory that is not empty, or a manifest that changed while it was being pinned. |
| `6` | `unavailable` | A dependency was unavailable and nothing was sent or committed; safe to retry. |
| `7` | `integrity` | Backup or archive integrity or restore verification failure. |
| `8` | `denied` | Authentication or authorization refused. |

When several errors apply, the one that must not be hidden wins: `1` over everything, and `6` only when nothing else went wrong, so a pipeline that retries on `6` never resends work another error left in doubt. Today `4` comes from `diff --check` and `5` only from an `init` or `convert --output` directory that is not empty, a `bundle.yaml` that changed while `pin` ran, a state directory another process holds locked (`state_dir.locked`), a `ledger seed` into a state directory that already holds a ledger (`ledger.exists`), a `backup create --output` that exists, or a `backup restore` target that holds stores without `--replace-existing-state` or changed while it ran; `7` comes from a backup archive that does not verify or would restore a store under another store's identity. The ETag and plan conflicts of `5` belong to commands later slices add.

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

### Backup diagnostics

The [standalone backup](standalone-backup.md) codes. A store or `--state-dir` problem is located by the position of `--state-dir` and names the store as `result.store`; an `--output` problem by the position of `--output`; an archive problem by the position of `FILE`. When `backup create` reports any error, nothing is at `--output`. A refusal by the archive admission rules carries their own `archive` code instead ([archive admission](archive-admission.md#codes)): exit `7`, or `1` for `archive.read_failed` and `archive.write_failed`.

| Code | Exit | Meaning |
| --- | --- | --- |
| `backup.stdout_refused` | 2 | `--output -`: a backup is never written to standard output. Name a new file. |
| `backup.output_exists` | 5 | Something exists at `--output`, which a backup never replaces. It was left as it was. |
| `backup.output_unusable` | 1 | The archive or its working files could not be created, written, flushed or linked into place beside `--output`, for example because its directory does not exist, is read-only, is out of space, or is on a filesystem without hard links. |
| `backup.permissions_unavailable` | 1 | The filesystem did not keep mode `0600` on the archive (Unix). |
| `backup.nothing_to_back_up` | 3 | The state directory holds none of the stores of the layout. Check `--state-dir`. |
| `backup.store_link` | 3 | A store's file is a symbolic link, junction or reparse point. |
| `backup.store_not_regular_file` | 3 | A store's name is a directory, FIFO, device or socket. |
| `backup.store_unsafe_permissions` | 3 | A store's file is writable by group or other (Unix), who could have changed it. |
| `backup.store_unavailable` | 1 | A store could not be opened, read or snapshotted: busy, or a rollback journal left by a crash that a read-only connection cannot roll back. Start and stop the gateway once, then back up again. |
| `backup.store_corrupt` | 3 | A store is not a SQLite database a backup can describe, or fails SQLite's integrity check. |
| `backup.ledger_invalid` | 3 | The configuration revision ledger does not pass its [verification](configuration-ledger.md#verification); run `ggctl ledger verify`. |
| `backup.ledger_shared` | 3 | The configuration revision ledger is the same file as another store, which no ledger can be. |
| `backup.archive_unreadable` | 1 | `FILE` could not be opened or read, for example because it does not exist. |
| `backup.archive_not_regular_file` | 3 | `FILE` is a symbolic link, junction or reparse point, or not a regular file. Name the archive itself. |
| `backup.archive_too_large` | 7 | `FILE` is longer than any backup can be. |
| `backup.staging_unavailable` | 1 | The staging directory beside the archive could not be created, written or read. |
| `backup.not_a_backup` | 7 | `FILE` is not a GreenGateway backup archive. |
| `backup.postgres_unsupported` | 3 | `FILE` is a PostgreSQL custom-format dump. PostgreSQL and cluster state is backed up and restored with the [PostgreSQL runbooks](deployment/backup-and-recovery.md), never with `ggctl backup`. |
| `backup.unsupported_archive_version` | 7 | The archive is a container version this `ggctl` does not read. |
| `backup.manifest_missing` | 7 | The archive's first entry is not its `gateway-backup.json` manifest. |
| `backup.manifest_invalid` | 7 | The manifest is not a valid `GatewayBackup` document: an unknown, duplicate or missing member, a value outside its grammar, or an inventory, entry list and counts that disagree. |
| `backup.unsupported_manifest_version` | 7 | The manifest is not a `GatewayBackup` document version this `ggctl` reads. |
| `backup.unexpected_entry` | 7 | An entry is not the next one the manifest lists. |
| `backup.entry_missing` | 7 | The archive ends before an entry the manifest lists. |
| `backup.archive_digest_mismatch` | 7 | The archive's end record does not hold the SHA-256 of the archive before it. |
| `backup.checksum_mismatch` | 7 | An entry's bytes do not match the SHA-256 the manifest records; `result.store` names the store. |
| `backup.store_integrity_failed` | 7 | An entry is not a SQLite database in rollback-journal mode that passes SQLite's integrity check. |
| `backup.store_mismatch` | 7 | An entry's header versions, pages, schema digest or table rows are not what the manifest records. |
| `backup.ledger_verification_failed` | 7 | The archive's ledger does not pass the ledger's verification. |
| `backup.ledger_mismatch` | 7 | The archive's ledger verifies but does not hold the revisions the manifest names. |
| `backup.secret_keys_not_included` | 0 | Information: the backup holds the Connections store's secrets as ciphertext only. Back up the key files under `CONNECTION_SECRETS_ROOT` separately, or they cannot be decrypted after a restore. |

### Restore diagnostics

The `backup restore` codes beyond the backup codes above, which it reports for an archive that does not verify. A state directory or target problem is located by the position of `--state-dir`, a store identity problem by the position of `FILE`. Every error but `restore.rollback_failed` leaves the state directory as it was, with no hidden directory beside it.

| Code | Exit | Meaning |
| --- | --- | --- |
| `restore.target_not_empty` | 5 | The state directory holds stores and `--replace-existing-state` was not given. Restore into an empty directory, or give the flag deliberately. |
| `restore.target_not_state_dir` | 3 | The state directory holds an entry the layout does not name, or a store's name that is not a regular file. Nothing is ever replaced that the layout does not name. |
| `restore.target_mount_point` | 3 | The state directory is a mount point, which a rename within its parent cannot move. Keep it one level below the volume's mount point. |
| `restore.target_unavailable` | 1 | The state directory's entries, or the directory holding it, could not be read. |
| `restore.staging_unavailable` | 1 | The staging directory beside the state directory could not be created, written or flushed, for example because the parent is not writable by this account or is out of space. |
| `restore.permissions_unavailable` | 1 | The filesystem did not keep the staging directory `0700` or a staged store `0600` (Unix). |
| `restore.store_identity_mismatch` | 7 | An archive entry does not carry the SQLite application ID of the store it would restore (`GGLG` for the ledger, `0` for the gateway's stores); `result.store` names the store. |
| `restore.target_changed` | 5 | The state directory's entries changed between the check and the switch; it was put back. Stop whatever wrote it and restore again. |
| `restore.switch_failed` | 1 | The state directory could not be renamed aside, or the restored directory into its place; it was put back. On Windows this is what a process holding a file open beneath it causes. |
| `restore.rollback_failed` | 1 | The restored directory could not take the state directory's name, and the state directory could not be renamed back: its content is beside it as `.NAME.ggrestore-previous-HEX`. Rename that back by hand. |
| `restore.directory_not_flushed` | 0 | Information: the restore is in place, but the directory holding the state directory could not be flushed, so a crash before the filesystem writes it back could undo the rename. |
| `restore.previous_not_removed` | 0 | Information: the restore is in place, but the replaced stores could not all be removed. Delete `.NAME.ggrestore-previous-HEX` beside the state directory: it holds them. |
| `restore.secret_keys_required` | 0 | Information: the restored Connections store holds its secrets as ciphertext only. Put the key files under `CONNECTION_SECRETS_ROOT` back from their own backup before the gateway starts. |

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

`ggctl` is tested on Linux, macOS and Windows. Exit codes, stream separation, terminal detection, token-file type and size checks and the remote client behave the same on all three. The owner-only permission check on token files applies on Unix only, as do the owner, mode and path checks on `--ca-file` and `--answers` files, and so does the bundle reader's refusal of a group- or other-writable bundle directory or file ([files and the directory](configuration-bundles.md#files-and-the-directory)); on Windows the reader enforces the link, reparse-point, regular-file and name rules, and ACLs are left to the operator. Likewise `init` and `convert --output` create their directory `0700` and its files `0600` on Unix and check those modes, and `pin` writes its new `bundle.yaml` `0600` and checks it, and `backup create` writes its archive `0600` and its working and staging directories `0700` and checks the archive, and `backup restore` stages `0600` stores in a `0700` directory and checks both, while on Windows the new entries inherit the ACL of the directory they are created in. Shell completion is generated for bash, zsh, fish and PowerShell.
