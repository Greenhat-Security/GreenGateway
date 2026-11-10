# ggctl, the operator CLI

`ggctl` is GreenGateway's operator command-line tool (issue #242, [ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md)). It is a separate binary: the `gateway` server keeps its name, its no-argument startup, its Docker entrypoint and its one-shot commands (`gateway migrate`, `gateway healthcheck`, `gateway import-standalone`, ...) unchanged.

**Status: alpha.** This build implements `version`, `schema`, `init`, `validate`, `pin`, `convert`, `doctor`, `diff`, `ledger seed`, `ledger verify`, `ledger rollback`, `backup create`, `backup verify`, `backup restore`, the `policy` commands (`lint`, `test`, `explain`, `replay`), `evidence verify`, `mcp-config`, `completion` and `help`, the output contract, the exit codes, secure bearer-token input and the version handshake with a running gateway. `init` writes a new [configuration bundle](configuration-bundles.md) for a deployment profile, `validate` and `doctor` check one offline with the gateway's own bundle reader, `pin` rewrites its SHA-256 pins once its files validate, `convert` converts one between document versions, and `diff` compares two bundles semantically and classifies each change's risk. `validate`, `doctor` and `diff` also take an [environment file](#environment-files) instead of a bundle (`--env`, `--against-env`), for a deployment that stays in environment mode, and run the gateway's own configuration compiler over it. The `ledger` commands seed, verify and roll back a standalone state directory's [configuration revision ledger](configuration-ledger.md) offline, under the directory's lock. The `backup` commands back up the stores beneath a standalone state directory offline, under the directory's lock, verify a backup completely, and restore one into an empty or stopped state directory, which they leave as it was on any failure ([standalone backups](standalone-backup.md)). The [policy commands](#policy-commands) ask a gateway's own policy validator and evaluator (issue #243), and [`evidence verify`](#evidence-verify) checks a policy evidence package's integrity offline. `mcp-config` writes a credential-free MCP client configuration template from a running gateway. `ggctl` cannot yet plan, apply or export anything, it has no browser wizard (`init --web`), and it cannot yet convert an environment file (`convert --env`) or diff against a server (`diff --server`): those are later #242 slices (see the ADR's [rollout](adr/0008-setup-cli-and-configuration-bundles.md#rollout)), and a name this build does not implement is refused as an unknown command (exit 2). Nothing here changes how a gateway is configured or started: no gateway reads a bundle or starts from a ledger yet.

## Building

`ggctl` has no build script and does not embed the admin UI, so it builds without Node:

```sh
cargo build --locked --release -p ggctl
# target/release/ggctl (ggctl.exe on Windows)
```

A `ggctl-vMAJOR.MINOR.PATCH` tag builds it for Linux, macOS and Windows with checksums, SBOMs and signed build provenance; see [release artifacts](#release-artifacts). It is not part of the container image. CI builds and tests it on all three platforms.

The configuration contracts it shares with the gateway live in the `gateway-config` library crate, which both binaries link: the published document schemas, the `GatewayCapabilities` handshake document, RFC 8785 canonical JSON and the ADR-0004 digest frame, the configuration bundle reader, the environment configuration compiler (`gateway_config::compiler`, extracted by #433 and moved there by #242; see [its contract](architecture/configuration-compiler.md)), which `validate`, `doctor` and `diff` run over an environment file, the `KEY=VALUE` environment file grammar (`gateway_config::env_file`) that `gateway import-standalone` reads too, and the production policy and tools validators: the validating parses of policy and tools documents (`gateway_config::rbac` and `gateway_config::tools`, moved there by #242) that the gateway's policy and tools loaders run. Every `ggctl` command that reads a bundle runs them on its bundled policy and tools documents, exactly as the gateway would, so a bundle `ggctl` accepts is one the gateway's loaders accept. Loading, watching and evaluating policy and tools stay in the gateway.

## Release artifacts

Pushing a `ggctl-vMAJOR.MINOR.PATCH` tag runs [`.github/workflows/release-ggctl.yml`](../.github/workflows/release-ggctl.yml), which drafts a GitHub release for a maintainer to publish ([releasing ggctl](RELEASING.md#releasing-ggctl)). For `VERSION` it holds one archive per target:

| Target | Archive | Built on | Runs on |
| --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `ggctl-VERSION-x86_64-unknown-linux-gnu.tar.gz` | Ubuntu 22.04 | Linux with glibc 2.35 or later |
| `aarch64-unknown-linux-gnu` | `ggctl-VERSION-aarch64-unknown-linux-gnu.tar.gz` | Ubuntu 22.04 on Arm | Linux with glibc 2.35 or later |
| `x86_64-apple-darwin` | `ggctl-VERSION-x86_64-apple-darwin.tar.gz` | macOS 15 on Intel | macOS 11 or later |
| `aarch64-apple-darwin` | `ggctl-VERSION-aarch64-apple-darwin.tar.gz` | macOS 15 | macOS 11 or later |
| `x86_64-pc-windows-msvc` | `ggctl-VERSION-x86_64-pc-windows-msvc.zip` | Windows Server 2025 | 64-bit Windows 10 or later |

The Linux binaries link the system's glibc dynamically; they are not static musl binaries. They are built on Ubuntu 22.04, and the release fails if one needs a glibc symbol version newer than 2.35. The C code `ggctl` compiles in (SQLite and AWS-LC) is linked statically on every platform, and the Windows binary also links the C runtime statically, so it needs no Visual C++ redistributable. Each archive holds one directory, `ggctl-VERSION-TARGET/`, with:

- `ggctl` (`ggctl.exe` on Windows) and `LICENSE`;
- `man/man1/ggctl.1` and a page for every command and command family (`ggctl-validate.1`, `ggctl-ledger.1`, `ggctl-ledger-seed.1`, ...), written by that binary's `ggctl help --man` and refused at packaging unless each says everything its `ggctl help` says;
- `completion/ggctl.bash`, `completion/_ggctl` (zsh), `completion/ggctl.fish` and `completion/ggctl.ps1`, written by that binary's `ggctl completion`.

Beside the archives the release holds:

| File | What it is |
| --- | --- |
| `ggctl-VERSION-TARGET.spdx.json` | The archive's SPDX 2.3 SBOM: the archive and the executable with their SHA-256 digests, and the Cargo packages the executable is compiled from for that target (normal and build dependencies, never dev-dependencies) with each registry package's `Cargo.lock` checksum. It is generated from Cargo's resolved metadata, not by scanning the binary. |
| `SHA256SUMS` | The SHA-256 of every archive and SBOM, in `sha256sum` format. |
| `ggctl-VERSION.provenance.sigstore.jsonl` | The SLSA v1 build-provenance attestation over every archive, every SBOM and `SHA256SUMS`. |
| `ggctl-VERSION-TARGET.sbom.sigstore.jsonl` | The SPDX attestation that binds the archive to its SBOM. |
| `ggctl-VERSION-release.json` | An index naming each archive's digest, its SBOM and the attestations that cover them. |

The attestations are [GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) signed through Sigstore by the release workflow at the tagged commit. They are also stored with the repository, so `gh attestation verify` finds them without the bundle files.

Each target is built with `cargo build --locked --release` by the production compiler in `build-tools.json`, on a runner of its own platform, and then built again from an empty target directory; the release fails unless both builds package to byte-identical archives and SBOMs. That shows the build of a commit is deterministic on that runner image, not that another machine reproduces it. Before anything is published, the release job requires every archive to have its `SHA256SUMS` entry, an SBOM that names its digest and both attestations (`scripts/ggctl_release.py check`), and verifies every attestation with the GitHub CLI version pinned in `build-tools.json` and the constraints below. A pull request that can change a release runs the same builds and checks as a dry run: read-only, with no secret, nothing signed and nothing published.

There is no install script, no package-manager package and no self-updater: `ggctl` never downloads or replaces itself. Upgrading is downloading and verifying the next release.

### Verifying a release

Download the archive for your platform and `SHA256SUMS`, then check the digest:

```sh
sha256sum --check --ignore-missing SHA256SUMS        # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS    # macOS
```

```powershell
$archive = 'ggctl-VERSION-x86_64-pc-windows-msvc.zip'
$expected = ((Get-Content SHA256SUMS) | Where-Object { $_.EndsWith("  $archive") }).Split(' ')[0]
(Get-FileHash $archive -Algorithm SHA256).Hash.ToLower() -eq $expected
```

A matching checksum shows the download is the file `SHA256SUMS` names, not who built either. Verify that with the build provenance, using the GitHub CLI (`gh attestation`):

```sh
gh attestation verify ggctl-VERSION-x86_64-unknown-linux-gnu.tar.gz \
  --repo Greenhat-Security/GreenGateway \
  --signer-workflow Greenhat-Security/GreenGateway/.github/workflows/release-ggctl.yml \
  --source-ref refs/tags/ggctl-vVERSION \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners
```

Add `--source-digest COMMIT` when you know the tagged commit from a reviewed record. The same command with `--predicate-type https://spdx.dev/Document/v2.3` verifies the SBOM attestation; with `--format json`, its `verificationResult.statement.predicate` is the SBOM, and it must equal the downloaded `.spdx.json`. Verifying `SHA256SUMS` the same way covers every file it lists. Without network access to GitHub, pass the release's bundle with `--bundle` (`ggctl-VERSION.provenance.sigstore.jsonl` for provenance, `ggctl-VERSION-TARGET.sbom.sigstore.jsonl` for the SBOM) and trust roots obtained separately with `gh attestation trusted-root` with `--custom-trusted-root`, as [offline image verification](RELEASING.md#offline-verification) describes.

A verified attestation shows that the file was built by this repository's release workflow from the tagged commit on a GitHub-hosted runner. It is not a review of the code, and the SBOM is an inventory, not a vulnerability verdict.

Then extract the archive and put `ggctl` on your `PATH`. The man pages go in a `man1` directory on your `MANPATH` (for example `/usr/local/share/man/man1`), and the completion scripts where [`completion`](#completion) says.

## Commands

```text
ggctl version [--server URL] [--ca-file PATH] [--token-stdin | --token-file PATH] [--timeout SECONDS] [--format human|json]
ggctl schema [KIND] [--api-version VERSION] [--format human|json]
ggctl init --profile production|migration|development --output DIR [--answers FILE] [--format human|json]
ggctl validate (BUNDLE | --env FILE) [--strict] [--warnings-as-errors] [--format human|json|sarif]
ggctl pin BUNDLE [--strict] [--format human|json]
ggctl convert BUNDLE --to VERSION (--output DIR | --in-place) [--strict] [--format human|json]
ggctl doctor (BUNDLE | --env FILE) [--format human|json]
ggctl diff (BUNDLE | --env FILE) (--against BUNDLE | --against-env FILE) [--check] [--strict] [--format human|json|sarif]
ggctl ledger seed BUNDLE --state-dir DIR [--format human|json]
ggctl ledger verify --state-dir DIR [--format human|json]
ggctl ledger rollback REVISION --state-dir DIR [--acknowledge RISK_CODE]... [--format human|json]
ggctl backup create --state-dir DIR --output FILE [--format human|json]
ggctl backup verify FILE [--format human|json]
ggctl backup restore FILE --state-dir DIR [--replace-existing-state] [--format human|json]
ggctl policy lint FILE --server URL [REMOTE] [--warnings-as-errors] [--format human|json|sarif]
ggctl policy test SUITE --server URL [REMOTE] [--candidate FILE | --draft ID --draft-etag ETAG] [--format human|json|junit]
ggctl policy explain CASES --server URL [REMOTE] [--format human|json]
ggctl policy replay --server URL [REMOTE] (--base-etag ETAG --window FROM[/TO] [--candidate FILE | --draft ID --draft-etag ETAG] [--enforce-all-shadow] [--max-records N] [--idempotency-key KEY] | --job ID) [--wait] [--format human|json]
ggctl policy replay --server URL [REMOTE] --cancel ID [--format human|json]
ggctl evidence verify PACKAGE [--format human|json]
ggctl mcp-config --server URL --client generic|claude-desktop|cursor|vscode [--auth oauth|token] [--name NAME] [--ca-file PATH] [--token-stdin | --token-file PATH] [--timeout SECONDS]
ggctl completion bash|zsh|fish|powershell
ggctl help [COMMAND [SUBCOMMAND]] [--man]
ggctl --help | --version
```

`REMOTE` stands for `[--ca-file PATH] [--token-stdin | --token-file PATH] [--timeout SECONDS]`, as for `version`. `ggctl help COMMAND` and `ggctl COMMAND --help` print a command's options. `ledger`, `backup`, `policy` and `evidence` are command families: `ggctl help ledger` and `ggctl ledger --help` list a family's commands, and `ggctl help ledger seed` and `ggctl ledger seed --help` print one. `ggctl help --man` prints the same text as the ggctl(1) manual page, `ggctl help --man COMMAND` as ggctl-COMMAND(1) for a command or family, and `ggctl help --man ledger seed` as ggctl-ledger-seed(1), in man(7) roff; the [release archives](#release-artifacts) carry these pages under `man/man1`. Help, the man pages and the completion scripts are generated from the same command table the parser uses, so they cannot drift, and the tests hold every page to the help it repeats.

### `version`

Prints the `ggctl` version and the document versions whose schemas it publishes. With `--server` it performs the [version handshake](#version-handshake) and reports the gateway version and whether this `ggctl` can work with it, exiting `3` when it cannot. The check reads only; it never changes the server.

### `schema`

Without `KIND`, lists every document kind and version this `ggctl` publishes a JSON Schema (Draft 2020-12) for. With `KIND` (`GatewayBundle`, `GatewayDeployment`, `GatewayInitAnswers`, `GatewayCapabilities`, `GgctlReport`, `GatewayBackup` or `McpClientConfigs`), writes that schema to standard output, byte for byte as committed under [`docs/schemas`](schemas/) with LF line endings on every platform. `--api-version` selects a document version (default: the newest published); a version with no published schema exits `3`. Printing a schema writes an artifact, so `--format` is refused there. A schema is necessary but not sufficient: the gateway's reader is authoritative.

### `init`

Creates a new bundle in the directory `--output` for the deployment profile `--profile` (`production`, `migration` or `development`; required): `bundle.yaml`, a deployment document declaring the profile and, in the default standalone topology, a policy that denies by default and enforces its decisions with no route and no role, and a tools document with no tools, each pinned by its SHA-256 digest, plus a `.gitattributes` that keeps their line endings LF. What each profile and topology writes is in [generated bundles](configuration-bundles.md#generated-bundles); the permissive starter policy is never written, and no file holds a secret or a credential. The output is deterministic: the same profile and answers always give the same bytes.

- `--answers FILE` replaces the defaults with a `GatewayInitAnswers` document ([schema](schemas/gateway-init-answers.v1alpha1.schema.json); YAML, or strict JSON when `FILE` ends in `.json`): the bundle's `name`, the `cluster` topology, which leaves policy and tools to the server as Connections are, or an `operator` role bound to one issuer and explicit authentication methods that may read status and configuration capabilities and nothing more. No member can hold a secret value. Because the answers decide which issuer the operator role trusts, `FILE` is read like `--ca-file`: a regular file of at most 64 KiB that, on Unix, no other account can change, either by writing it or by changing what its path resolves to (the rules are under [Remote server](#remote-server)). A problem in the document is reported with the bundle reader's code, located by the position of `--answers` with a JSON Pointer, line and column, never by its path.
- `--output DIR` must not exist, or must be an empty directory that is not a link; anything else is refused with `output.destination_exists` (exit `5`) and left exactly as it was. `ggctl` never overwrites.
- The files are written into a new hidden directory beside `DIR` (`.NAME.ggctl-staging-PID-N`, created exclusively), each created new and flushed to storage with the manifest last, read back with the gateway's bundle reader strictly, and only then renamed onto `DIR` (an empty `DIR` is removed first) and the parent directory flushed. Any failure removes the staging directory, so nothing that looks like a bundle is ever left at `DIR`; only a process killed mid-write can leave the hidden staging directory, which is safe to delete. On Unix the directory is `0700` and each file `0600`, checked after writing, and a filesystem that does not keep those modes is refused (`output.permissions_unavailable`). Windows has no mode bits: the new entries inherit the ACL of the directory they are created in, which, as for the bundle reader, is left to the operator.
- `ggctl` prompts for nothing, starts and deploys nothing, and makes no network request. The human result names the bundle, its digests, files and profile (marking `development` non-production) and the next step: review the files and run `ggctl validate --strict` on `DIR`. `--format json` writes one `GgctlReport` whose `result` holds `created`, `profile`, `topology`, `operator` and, once written, `bundle` as `validate` reports it.

As for `validate`, the bundle is read back with the production policy and tools validators, and `gateway-config`'s tests hold every bundle `init` can write to them for every profile and kind of answer. No gateway reads a bundle yet, so the generated policy and tools documents are, today, also usable as `POLICY_FILE` and `TOOLS_FILE` in environment mode.

Exit codes: `0` written, `3` invalid answers (or an answers file over 64 KiB), `5` when `DIR` holds anything, `2` for an answers file that is not a regular file or that another account could change, `1` when the answers could not be read or the bundle could not be written.

```sh
ggctl init --profile production --output deploy/bundle --answers deploy/init-answers.yaml
ggctl validate deploy/bundle --strict
```

### `validate`

For a valid bundle, `result.bundle.deployment.offlineCompiler` reports
`compiled` when the gateway's shared configuration compiler built the
deployment plan. It reports `not_checked` when building the full plan needs
host bindings, such as a secret reference, TLS files, a state directory or
PostgreSQL bootstrap settings. The available domain checks still run. The
same status appears in the bundle summary from `doctor`.

Reads the bundle in the directory `BUNDLE` with the bundle reader the gateway uses ([configuration bundles](configuration-bundles.md)) and reports every problem it finds, not just the first: unsafe or oversized files, the YAML subset and strict JSON, exact document versions, closed documents, the deployment settings' types and bounds, the gateway compiler's egress, runtime, authentication-provider and admin-login checks, references and SHA-256 pins, the published policy and tools schemas, and the deployment profile's policy invariants. It reads only beneath `BUNDLE`, writes nothing, makes no network request and reads no environment variable. `BUNDLE` must be valid UTF-8.

- The human result names the bundle and says `valid` or `invalid` with counts; for a valid bundle it adds the source digest, the files and the profile, marking a `development` profile `non-production`. Each diagnostic goes to standard error with its file, line, column and JSON Pointer.
- `--format json` writes one `GgctlReport` whose `result` holds `valid` and, once the manifest was read, what it declares (`bundle`); digests and the profile appear only when every stage passed. Diagnostics carry `location.file`, `location.pointer` and, where the reader has them, `location.line` and `location.column`.
- `--format sarif` writes one SARIF 2.1.0 log with one rule per code and one result per diagnostic. File locations are relative to the `BUNDLE_ROOT` base, which the log describes but never resolves, because the bundle's path is an argument and no argument is echoed; map it to the bundle's directory in the tool that ingests the log.
- `--strict` makes an entry the manifest does not reference an error instead of a warning. `--warnings-as-errors` keeps the diagnostics as they are and exits `3` when any warning was reported (`validate.warnings_as_errors`).

A bundled policy or tools document is also held to the gateway's production validator for it, after the bundle's own rules and its published schema: the policy and tools loaders' own validating parse. It refuses what only it checks (for example two route hosts that differ only in case, or two tools of one name) with `resource.invalid`, by code alone, because a validator's message can quote document values. In the JSON result each bundled resource then says `productionValidator: passed`. A digest is integrity metadata, not a signature: a valid bundle is not thereby a trusted one.

With `--env FILE` instead of `BUNDLE`, `validate` reads an [environment file](#environment-files) and reports every problem in it and every setting the gateway's configuration compiler refuses, each located by line and named by setting and rule, never by value:

- The human result says `valid` or `invalid` with counts, then how many gateway settings the file sets and how many other keys it sets, which are never named.
- `--format json` writes one `GgctlReport` whose `result` holds `valid` and, once the file was parsed, `environment`: `settings` (the gateway settings it assigns, in the order the compiler reads them), `otherVariables` and `duplicateKeys` (counts). Diagnostics carry `location.argument` (the position of `--env`) and, for a line, `location.line`, and `field` (the setting) and `rule` (the [compiler rule](#configuration-rules)) where there are any.
- `--format sarif` covers the same findings: the file is listed in `run.artifacts` by the position of `--env`, never by its path, and each finding on a line refers to it by index with the line as its region and the setting as a logical location.
- `--strict` makes a key assigned twice an error instead of a warning (`env.duplicate_key`). `--warnings-as-errors` exits `3` on any warning.

Exit codes: `0` valid, `3` invalid (or any warning with `--warnings-as-errors`), `1` when the bundle or file could not be read at all (`bundle.root_unavailable`, `bundle.read_failed`, `bundle.changed_during_read`, `env.unreadable`).

In CI, validate the bundle a change touches and keep the SARIF log for review:

```yaml
- name: Validate the configuration bundle
  run: ggctl validate deploy/bundle --strict --warnings-as-errors --format sarif > bundle.sarif
```

The step fails on exit `3` or `1`; upload `bundle.sarif` with the CI system's SARIF tooling if it annotates reviews. A deployment that stays in environment mode validates its environment file the same way:

```yaml
- name: Validate the gateway environment
  run: ggctl validate --env deploy/gateway.env --strict --warnings-as-errors --format sarif > env.sarif
```

### `pin`

The only command that rewrites manifest digests ([ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md#digests)), and it pins only files that validate. It reads the bundle in the directory `BUNDLE` with the same reader as `validate` and every check `validate` runs but one: each referenced file's SHA-256 is recorded instead of compared with its pin. Nothing is written unless every other check passed, so `pin` refuses a policy the profile forbids, a document that fails its schema, or a file that is missing, oversized, linked or not LF, exactly as `validate` does (exit `3`), and never pins a file that does not validate.

- Each pin that differs from its file's SHA-256 is replaced digit for digit where the reader found it, so every other byte of `bundle.yaml` (comments, member order, quoting and spacing) is kept, and a review shows only the digits that changed. A pin to replace must be written as its 64 digits between double or single quotes, as `init` writes it; any other spelling, plain or with escapes, is refused with `reference.pin_not_rewritable` at its line and column, and nothing is written. The manifest itself must be valid, each pin's form included (`reference.invalid_digest` for one that is not 64 lowercase hex digits).
- The new manifest is checked in memory first: with the other files exactly as read, it must read as a valid bundle with every check, its pins included. It is then written to a new hidden file beside `bundle.yaml` (`.bundle.yaml.ggctl-pin-PID-N`, created exclusively, `0600` and checked on Unix), flushed to storage and renamed over `bundle.yaml`, and on Unix the directory is flushed. A failed write leaves `bundle.yaml` exactly as it was and removes the hidden file (`pin.write_failed`); only a process killed before the rename can leave the hidden file behind, which the reader never opens and which is safe to delete. There is never a partial `bundle.yaml`.
- `bundle.yaml` must be a regular file. A link, such as the per-key link of a Kubernetes atomic-writer volume, is refused before anything is read (`pin.manifest_link`), and neither it nor its target is touched: pin the bundle's source, not the volume it is delivered in. `bundle.yaml` must also still hold the bytes `pin` read, checked before the hidden file is created and again just before the rename (`pin.manifest_changed`). A rename cannot compare and swap, so this narrows a race with another writer but cannot close it: do not edit a bundle while pinning it.
- When every pin already matches, nothing is written.
- The bundle is then read back with every check, its pins included, and must be exactly the files that were pinned. Otherwise a file changed while `pin` ran: the reader's errors are reported with `pin.read_back_failed`, and `ggctl validate` says what the bundle is now.
- On Unix the new `bundle.yaml` is `0600` and owned by the account that ran `pin`, whatever the old one's mode and owner were; on Windows it inherits the ACL of the bundle directory. Git records neither, so a checkout is unaffected, but a bundle a gateway reads in place under another account must be made readable to it again (for example `chmod 0644`; the reader refuses only group or other write).
- The human result says whether the bundle was pinned, gives its new source digest and lists each file with whether its pin changed. `--format json` writes one `GgctlReport` whose `result` holds `valid`, `bundle` (what the manifest declares, without digests), `files` (each with its `role`, `file`, `previous` and new `sha256` pin, and `changed`), `changed`, `written` and, once read back, `pinned`, whose `sourceDigest` is the bundle's new identity. `--strict` reads `BUNDLE` as `validate --strict` does.

`pin` reads only beneath `BUNDLE`, writes nothing but `bundle.yaml` and its hidden replacement, makes no network request, reads no environment variable and never echoes the path. A pin is integrity metadata, not a signature: pinning records what the files are and does not make them trusted, so review a change before you pin it. As for `validate`, the bundled policy and tools documents are held to the production validators, before pinning and when the bundle is read back.

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

With `--env FILE` instead of `BUNDLE`, the doctor reads the [environment file](#environment-files) as `validate --env` does and runs its [own checks](#environment-doctor-checks): whether the file is usable and the gateway's configuration compiler accepts it, which are required, and then, because environment mode has no deployment profile, what the compiled configuration shows against ADR-0008's `production` profile, as advice that warns and never fails. Only the invariants the compiled configuration itself shows are evaluated; the policy invariants (default deny, enforce mode, no wildcard role) are in the document `POLICY_FILE` names, which the doctor does not read, so that check is `skipped` while a policy file is set. The doctor has no `--strict`, so a key assigned twice is advice. `result` holds `environment` (as for `validate`) and `checks`, and the exit codes are the same, `1` when the file could not be read.

### Doctor checks

| Check | Severity | What it covers |
| --- | --- | --- |
| `bundle.files` | error | The directory and its files: containment, links, special and hard-linked files, permissions, ownership, sizes, encoding and line endings. |
| `bundle.syntax` | error | Strict JSON and the YAML subset, and the structural bounds. |
| `bundle.compatibility` | error | Exact `apiVersion`, `kind` and resource `schema_version`. |
| `bundle.structure` | error | Closed documents, required members, values, secret-reference forms, and the gateway compiler's egress, runtime, authentication-provider and admin-login checks. |
| `bundle.references` | error | References between files, files present, and SHA-256 pins. |
| `bundle.resources` | error | The bundled policy and tools documents against the bundle's rules, their published schemas and the production validators. |
| `bundle.profile` | error | A bundled policy against the deployment profile's invariants; `skipped` when the policy is the server's or there is none. |
| `bundle.unreferenced_entries` | warning | Directory entries the manifest does not reference. |
| `resources.production_validators` | error | The bundled policy and tools documents against the production validators the gateway's loaders run: `pass` once the bundle was read, `fail` with the resources stage's first code (`resource.invalid` covers a published-schema and a production-validator refusal alike), `skipped` when the bundle supplies neither document or the reader stopped before them. |
| `deployment.profile` | warning | Whether the deployment is a production one: `warning` for `migration` and `development`. |

### Environment doctor checks

| Check | Severity | What it covers |
| --- | --- | --- |
| `environment.file` | error | The environment file: a regular file of at most 1 MiB, not writable by group or other on Unix, UTF-8, and every line blank, a comment or an assignment. Its reason is the first `env` code found. |
| `environment.duplicate_keys` | warning | No key is assigned twice (`env.duplicate_key`). |
| `environment.compiler` | error | The gateway's configuration compiler accepts the variables the file sets. Its reason is the first `config` code found. |
| `production.authentication` | warning | Authentication is on and required: `AUTH_ENABLED` is not `false` and `AUTH_MODE` is not `observe`. |
| `production.policy` | warning | A policy is configured: `warning` without `POLICY_FILE`, `skipped` with one, because its invariants are in the policy document, which this check does not read. |
| `production.csrf` | warning | CSRF protection is on (`CSRF_ENABLED`). |
| `production.private_egress` | warning | Private-address egress is denied (`EGRESS_DENY_PRIVATE_IPS`). |
| `production.audit_durability` | warning | Audit durability is `required` (`AUDIT_DURABILITY`). |
| `production.client_secrets` | warning | No `AUTH_PROVIDERS` entry holds its client secret inline; the production profile allows a secret only as a reference. |

The production checks are `skipped` with `doctor.incomplete` when the file is not a valid environment configuration, because advice about a configuration the gateway would refuse is not advice about what the file configures.

### Doctor reasons

| Reason | Meaning |
| --- | --- |
| `doctor.passed` | The check ran and found nothing. |
| `doctor.incomplete` | The reader stopped before it could show this check clean; see the other checks' reasons and the diagnostics. |
| `doctor.server_managed` | The policy is left to the server's store, which an offline check cannot read. |
| `doctor.not_declared` | The bundle declares nothing this check applies to. |
| `doctor.migration_profile` | The deployment uses the `migration` profile, meant for moving an existing deployment over, not as a final state. |
| `doctor.development_profile` | The deployment uses the `development` profile, which is not for production. |
| `doctor.authentication_not_required` | The environment turns authentication off or to `observe`, which the production profile forbids. |
| `doctor.policy_not_configured` | The environment sets no `POLICY_FILE`, so no policy authorizes requests, which the production profile forbids. |
| `doctor.policy_not_read` | The environment names a policy file, whose invariants an offline check of the environment file does not read; validate it as a bundle's policy instead. |
| `doctor.csrf_disabled` | The environment turns CSRF protection off, which the production profile forbids. |
| `doctor.private_egress_allowed` | The environment allows egress to private addresses, which the production profile forbids. |
| `doctor.audit_best_effort` | The environment makes audit durability `best_effort`, which the production profile forbids. |
| `doctor.inline_client_secret` | An `AUTH_PROVIDERS` entry holds its client secret inline, where the production profile allows only a secret reference. |

`doctor.validator_unavailable` is deprecated: earlier releases, which could not run the production validators, reported `resources.production_validators` as `skipped` with it. No release reports it now, and the reason is reserved.

### `diff`

Compares the bundle in the directory `BUNDLE` with the one `--against` names, semantically: both are read by the same reader as `validate`, with the production validators, and the [semantic diff](semantic-diff.md) compares the documents those validators built, as the revision ledger's plans do, never their text. The change is from the `--against` bundle to `BUNDLE`. The manifest, the deployment document and the policy and tools documents are compared member by member, so formatting, member order, the order of an unordered list and a spelled-out default never register. Each change carries its field (a dotted document path such as `policy.egress.hosts`), its section, whether it was added, removed or modified, its [change class](semantic-diff.md#what-a-change-carries), whether it `loosened`, `tightened` or did something `unknown` or `neutral`, and the stable [risk codes](semantic-diff.md#risk-codes) of what it weakens; a change no detector can classify carries `risk.unknown_impact`, never no code. Only booleans, fixed words and numbers are ever shown: every other value is withheld, with entry counts for a collection, and entry names (roles, tools) never appear. It reads only beneath the two directories, writes nothing, makes no network request and reads no environment variable. `BUNDLE` must be valid UTF-8, and neither path is ever echoed.

- The human result lists one line per change (severity, field, kind, the value or `(value withheld)` with counts, class, effect and codes) and ends with the number of changes, the highest severity and every code; `no changes` when nothing differs.
- `--format json` writes one `GgctlReport` whose `result` holds `valid`, `bundle` and `against` (each as `validate` reports a bundle) and, when both were read, `diff` ([`diffResult`](schemas/ggctl-report.v1alpha1.schema.json)).
- `--format sarif` writes one SARIF 2.1.0 log: the readers' diagnostics as `validate` writes them, then one rule per risk code (level `error` for a `high` code, `warning` for `medium`, `note` for `low`) and one result per risk code of each change, located at the change's field as a logical location. A change without a code is not a finding and has no result. This extends ADR-0008, which gave SARIF to `validate` only.
- `--check` exits `4` when the bundles differ at all (`diff.drift_found`), whatever the risk. `--strict` applies to both bundles as it does for `validate`.

With `--env FILE` and `--against-env FILE` instead, `diff` compiles both [environment files](#environment-files) as `validate --env` does and compares the two compiled configurations setting by setting with the same semantic diff (each change's `field` is the setting's name), so spelling, order, `export`, comments, whitespace a setting ignores and a spelled-out default never register. The result holds `environment` and `againstEnvironment` in place of `bundle` and `against`; `--check`, `--strict` and the formats behave as for two bundles. An environment file and a bundle are read and reported but never compared, in either direction: no front end maps a bundle onto the compiler's settings yet, and an environment configuration holds no policy or tools document, so there is nothing in common to compare (`diff.not_comparable`, exit `3`).

A bundle that is invalid is not compared: the readers' diagnostics are reported, BUNDLE's first, and the result says `valid: false`. Diagnostics name bundle-relative files, so a diagnostic about a file both bundles have does not say which bundle it concerns; read `bundle` and `against` in the result, or validate each bundle on its own.

Exit codes: `0` when both were compared, `4` with `--check` when they differ, `3` when either is invalid or they cannot be compared, `1` when either could not be read, `2` without `--against` or `--against-env`, or with both. To gate a change in CI on the risk it carries, compare the proposed bundle with the deployed one and fail on what the codes say:

```yaml
- name: Review the configuration change
  run: ggctl diff deploy/bundle --against deployed/bundle --format sarif > bundle-diff.sarif
```

### `ledger seed`

Creates the [configuration revision ledger](configuration-ledger.md) of the standalone state directory `--state-dir` (required) names, with the bundle in the directory `BUNDLE` as its first revision ([ADR-0008, "Seeding a ledger"](adr/0008-setup-cli-and-configuration-bundles.md#bootstrap-model)). The bundle is read with the gateway's own bundle reader strictly, as `validate --strict` reads it, so an entry the manifest does not reference is an error; an invalid bundle is reported like `validate` reports it, and the state directory is not touched. Then `ggctl` takes the state directory's [exclusive lock](configuration-bundles.md#the-state-directory) without waiting, and `RevisionLedger::seed` builds the ledger under a temporary name, commits and flushes it, and links it into place without replacing anything, so an interrupted seed leaves no ledger. The new revision is desired and not active, records `ggctl-ledger` as its system actor, no request and the `restart` activation class: no gateway has compiled it yet.

- A state directory that already holds `config-ledger.sqlite3`, or a previous ledger's `-wal`, `-shm` or `-journal` file, which a new ledger could replay, is refused with `ledger.exists` (exit `5`) and left exactly as it was. A ledger is created only once; there is no option that replaces one.
- A state directory a gateway or another `ggctl` holds is `state_dir.locked` (exit `5`); one that is missing, a link, not a directory or, on Unix, writable by group or other is refused with its [`state_dir` code](#state_dir-diagnostics) (exit `3`).
- The bundled policy and tools documents are held to the production validators, as `validate` holds them. A gateway starting from the ledger compiles its desired revision again, with the same validators, and refuses to start if it does not compile (`ledger.gateway_recompiles_at_start`). Ledger mode itself (`GATEWAY_CONFIG_SOURCE=ledger`) is a later #242 slice: no gateway starts from a ledger yet.
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

The offline lockout recovery path ([ADR-0008, "Recovery and lockout"](adr/0008-setup-cli-and-configuration-bundles.md#bootstrap-model)): when a revision locks every administrator out, stop the gateway and roll the ledger back to a revision that worked. `ggctl` takes the state directory's exclusive lock, opens and verifies the ledger, and plans the rollback to `REVISION` (`rev-` and 32 lowercase hexadecimal digits, as `ledger verify` reports one) through the gateway's own revision service (`RevisionService`) with the production compiler (`ProductionCompiler`), under the system actor `ggctl-ledger`: the target's stored content is compiled again and diffed against the desired revision with the [semantic diff](semantic-diff.md), exactly as an online rollback plan is. A change no revision can carry, stored content the reader now refuses, a target that is not a revision of this ledger or is the desired revision, and a rollback that changes nothing are refused, and nothing is written.

- **Every risk code must be acknowledged by name.** Each risk code of the plan is given with its own `--acknowledge RISK_CODE`, which may be repeated; the set must be exactly the plan's codes, no more and no fewer. There is no option that acknowledges them all. Until it matches, nothing is written, and the report shows the plan, its diff, its `riskCodes` and the `unacknowledged` ones, so the operator can read what the rollback changes before acknowledging it.
- **Every risk code is acknowledgeable offline**, `risk.admin_access_path_removed` included, which no online request can acknowledge. Filesystem access to the state directory is already full control of a standalone deployment, so the offline command asks for no permission either; the plan's union of permissions is reported and recorded, but not checked.
- **History is only appended to.** The rollback is a new forward revision recording its target, the plan's changed sections, risk codes and permissions, `ggctl-ledger` as its system actor and no request; no revision is changed, removed or reordered. It is recorded with the `restart` activation class whatever its changes are, because no gateway is running to activate it: the desired pointer moves, the active pointer stays, and the next start compiles and activates it. It restores configuration only, never database schema, secret material, Connections or revoked credentials, none of which a ledger holds.
- The target's stored content is held to the production policy and tools validators when it is compiled again, as an online rollback's is; the gateway compiles the revision again with them at start and refuses to start if it does not compile (`ledger.gateway_recompiles_at_start`).
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

### `mcp-config`

Reads the gateway's MCP client configuration templates (`GET <server>/mcp/client-configs`, permission `admin:mcp:clients:read`; see [MCP client templates](mcp-clients.md)) and writes the one `--client` and `--auth` select to standard output, byte for byte as the gateway rendered it and with LF line endings: a JSON file for `generic`, `cursor` and `vscode`, and the URL line for `claude-desktop`. `--auth` is `oauth` (the default), whose template holds only the URL, or `token`, whose template reads the bearer token from the client's `GREENGATEWAY_MCP_TOKEN` environment variable; Claude Desktop has no token template, so `--client claude-desktop --auth token` is refused before anything is sent (`mcp.no_token_template`, exit `2`). `--name` chooses the JSON templates' server entry name (1 to 64 ASCII letters, digits, `-` and `_`, starting with a letter or digit; default `greengateway`) and is sent as the route's `name` parameter; a name outside that grammar is refused before anything is sent and never echoed.

- The URL is the gateway's own MCP endpoint, which it computes from its `GATEWAY_PUBLIC_URL`. `ggctl` has no option to supply or change it, and `--server` is only the admin API it reads the templates from.
- The document is read with the same `gateway-config` reader the gateway renders it with, and a template is written only when the whole document is exactly what this `ggctl` renders for the URL, name and OAuth flag it states. A template with a token, another URL or an extra member is refused whole (`mcp.client_configs_invalid`), and so is a document naming another server entry than the one asked for.
- No template holds a credential, and the admin token from `--token-stdin` or `--token-file`, which authenticates the read, appears nowhere in the output. The handshake and `admin:config:read` are not needed.
- `ggctl` never opens, creates or edits a client's configuration file. Where the template goes is the operator's redirect; merge it into a file that already lists other servers rather than replacing that file.
- The template is an artifact, so there is no `--format`. Diagnostics go to standard error.

Exit codes: `0` written, `3` when the gateway has no `GATEWAY_PUBLIC_URL` or one that cannot be templated (`mcp.public_url_unusable`), does not serve the route (`mcp.client_configs_unavailable`), offers no OAuth template because it advertises no authorization server (`mcp.oauth_unavailable`), or serves a document this `ggctl` does not read, `8` when the read is refused, `6` when the gateway cannot be reached, and `2` for an argument error.

```sh
printf '%s' "$ADMIN_TOKEN" | ggctl mcp-config --server https://gateway.example.test/v1/admin --token-stdin --client cursor --auth token > .cursor/mcp.json
```

### `completion`

Writes a completion script to standard output. It completes commands, a family's commands after its name (`ggctl ledger <TAB>`), options, fixed choices (risk codes for `--acknowledge`), file names for path options, document arguments and a backup archive argument, and directory names for a `BUNDLE` argument. The [release archives](#release-artifacts) carry the same four scripts under `completion/`.

| Shell | Install |
| --- | --- |
| bash | `ggctl completion bash > ~/.local/share/bash-completion/completions/ggctl` |
| zsh | `ggctl completion zsh > "${fpath[1]}/_ggctl"` |
| fish | `ggctl completion fish > ~/.config/fish/completions/ggctl.fish` |
| PowerShell | `ggctl completion powershell >> $PROFILE` |

## Environment files

`--env FILE` (`validate`, `doctor`, `diff`) and `--against-env FILE` (`diff`) read a `KEY=VALUE` environment file, so that a deployment that stays in environment mode gets the same offline checks in CI as a bundle (ADR-0008). The file is read as data: `ggctl` never runs or sources it, never expands anything in it, and never reads its own process environment in its place. It is compiled by the gateway's own configuration compiler with every setting the file does not assign unset, exactly as `Config::from_env_vars` would compile a process environment holding only those variables, so `ggctl` and the gateway reach the same verdict on the same file.

- **The file**: a regular file (a symbolic link to one is followed, as mounted secrets use them) of at most 1 MiB, opened without blocking, and valid UTF-8. On Unix it must not be writable by group or other, as the bundle reader requires of bundle files. Its path is never echoed: findings name the position of the option.
- **The grammar** is the one `gateway import-standalone --from` reads (`gateway_config::env_file`), the plain shape `.env.example` ships and `docker compose env_file` and systemd `EnvironmentFile` read: each line loses its surrounding whitespace and is ignored when empty or starting with `#`; otherwise one leading `export ` is dropped, and the line must hold `=` with a non-empty key before the first one (`env.malformed_line`). The value is everything after that `=`, verbatim: quotes, leading spaces, further `=` and `#` are kept, and nothing is unquoted, unescaped or interpolated, so `AUTH_MODE="required"` sets the value `"required"`, quotes included, as the import does. A line never continues onto the next.
- **A key assigned twice** keeps its last value, as every reader of such a file applies it, and is reported at the repeating line (`env.duplicate_key`): a warning, and an error under `--strict`, because a reviewer may read the first assignment.
- **Findings are value-free**: each names the line and, when the key is one of the compiler's inventoried settings, that setting as the inventory spells it, plus the [rule](#configuration-rules) the compiler refused it under. A key outside the inventory is counted, never named, because such a key could be anything; no value, line text, path or compiler message reaches standard output, standard error, a report or a SARIF log.

## Output contract

- **Standard output carries only what was asked for**: an artifact (a schema, a completion script, help, an MCP client template), the human result, with `--format json` exactly one `GgctlReport` document ([schema](schemas/ggctl-report.v1alpha1.schema.json)), with `validate`, `diff` or `policy lint --format sarif` exactly one SARIF 2.1.0 log, or with `policy test --format junit` exactly the gateway's JUnit XML report.
- **Diagnostics go to standard error** in human form. With `--format json` or `--format sarif` they are in the document instead and standard error stays empty. A JUnit report has no place for them, so with `--format junit` they stay on standard error.
- **An argument error found before a command runs** (an unknown option, a refused secret or insecure option, a malformed `--server`) is written to standard error only, exits `2`, and writes no report.
- **No color, no prompts, no progress output.** `ggctl` reads no configuration file of its own and no environment variable, reads only the files and directories its arguments name, and makes no network request unless a command is given `--server`.
- **Files are written only where a command is told to.** `init` and `convert --output` create the one directory `--output` names, and never write anything else, overwrite anything, or echo the path. `pin` replaces only `BUNDLE`'s `bundle.yaml`. The `ledger` commands write only beneath `--state-dir`: its lock file, which they create if it is missing; `ledger seed` creates the ledger and never replaces one, `ledger rollback` appends one revision to it, and `ledger verify` writes nothing in it. `backup create` creates the archive at `--output` and nothing else that stays: in `--state-dir` it writes only the lock file, if that is missing, and the hidden working, partial and verification entries it makes beside `--output` are removed. `backup verify` writes only a hidden staging directory beside `FILE`, which it removes. `backup restore` writes only a hidden staging directory beside `--state-dir`, which becomes `--state-dir` or is removed, and the lock file in `--state-dir`, which it removes again when the restore fails and the directory had none; the replaced directory, renamed aside, is removed. `mcp-config` writes only to standard output and never opens a client's configuration file.

A report always has `apiVersion: greengateway.dev/v1alpha1`, `kind: GgctlReport`, the `command`, the process `exitCode` and its stable `outcome` name, the `diagnostics`, and a command-specific `result`. Every diagnostic has a stable `code`, a `severity` (`error`, `warning` or `info`), fixed `message` text, an optional fixed `hint`, a `remediation` anchor and at most one location: when it concerns one argument, that argument's 1-based `location.argument` position; when the bundle reader found it, the bundle-relative `location.file`, a `location.pointer` built from member names the reader defines, and the 1-based `location.line` and `location.column` where the reader has them. Diagnostics are value-free by construction: they never contain an argument, token, URL, path, address, document value, server response or library error text. An unknown option is reported by its position, never by its spelling, because the spelling may be a mistyped secret. A published code never changes meaning; renaming or removing one needs a new report version.

A report about a bundle carries the bundle reader's own codes (the `bundle`, `syntax`, `json`, `yaml`, `compat`, `schema`, `reference`, `secret`, `resource` and `profile` families), each listed in [configuration bundles](configuration-bundles.md#diagnostics), which is its remediation anchor. No code is spelled the same in both lists. A reader warning exits `0` on its own; a reader error exits `3`, or `1` when the bundle could not be read at all.

A report about an environment file carries the [`env`](#env-diagnostics) and [`config`](#config-diagnostics) codes below. Such a diagnostic is located by `location.argument`, the position of the option naming the file, and `location.line` where it concerns one line, and carries `field`, the inventoried setting it concerns, and `rule`, the [compiler rule](#configuration-rules) that refused it, where there are any.

SARIF 2.1.0 output belongs to `validate`, which ADR-0008 gives it, to `diff`, which reports its risk codes as results, and to `policy lint`, which reports the policy validator's diagnostics as results. For an environment file, the log lists the file in `run.artifacts` by the position of the option naming it and locates a finding by that artifact's index and the line.

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

When several errors apply, the one that must not be hidden wins: `1` over everything, and `6` only when nothing else went wrong, so a pipeline that retries on `6` never resends work another error left in doubt. Today `4` comes from `diff --check`; `5` from an `init` or `convert --output` directory that is not empty, a `bundle.yaml` that changed while `pin` ran, a state directory another process holds locked (`state_dir.locked`), a `ledger seed` into a state directory that already holds a ledger (`ledger.exists`), a `backup create --output` that exists, a `backup restore` target that holds stores without `--replace-existing-state` or changed while it ran, and a stale ETag, draft or idempotency key or a replay whose base changed in the policy commands; and `7` from a backup archive that does not verify or would restore a store under another store's identity, and from `evidence verify`. The plan conflicts of `5` belong to commands later slices add.

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
| `usage.conflicting_options` | 2 | Two options that exclude each other were both given: `--token-stdin` and `--token-file`, `BUNDLE` and `--env`, `--against` and `--against-env`, a `--candidate` and a `--draft`, or `--job`, `--cancel` and the options that start a replay. |
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
| `remote.forbidden` | 8 | HTTP 403: the principal lacks the route's permission (`admin:config:read` for the handshake, `admin:mcp:clients:read` for `mcp-config`; see [the policy commands](#policy-commands) for theirs). |
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

### Mcp diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `mcp.no_token_template` | 2 | `--client claude-desktop --auth token`: Claude Desktop takes a remote server by its URL and authorizes it with OAuth, so it has no token template. Nothing was sent. |
| `mcp.client_configs_unavailable` | 3 | HTTP 404 for the templates: a gateway older than this route, a wrong admin prefix, or no `POLICY_FILE`. |
| `mcp.public_url_unusable` | 3 | HTTP 409: the gateway has no `GATEWAY_PUBLIC_URL`, or its MCP endpoint holds `$`, `{`, `}` or `\` or is longer than 16 KiB. Set or fix it and restart the gateway. |
| `mcp.unsupported_version` | 3 | The template document is a version this `ggctl` does not read. |
| `mcp.client_configs_invalid` | 3 | The template document is not exactly one this `ggctl` renders, or names another server entry than the one asked for; no template from it was written. |
| `mcp.oauth_unavailable` | 3 | The gateway advertises no authorization server, so it offers no OAuth template; configure a JWT provider with an `issuer`, or use `--auth token`. |

### Validate diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `validate.warnings_as_errors` | 3 | `--warnings-as-errors` was given and a warning was reported. |

`validate.production_validators_not_run` is deprecated: earlier releases, which could not run the production policy and tools validators, reported it (exit `0`) for every bundled policy or tools document. Every command now runs them, so no release reports it, and the code is reserved.

### Doctor diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `doctor.required_check_failed` | 3 | A required [doctor check](#doctor-checks) failed. |

### Diff diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `diff.drift_found` | 4 | `--check` was given and the two configurations differ. |
| `diff.not_comparable` | 3 | One side is an environment file and the other a bundle, which configure different things; nothing was compared. |

### Env diagnostics

| Code | Exit | Meaning |
| --- | --- | --- |
| `env.unreadable` | 1 | The environment file could not be opened or read, for example because it does not exist. |
| `env.not_regular_file` | 3 | The environment file is not a regular file, such as a directory or a FIFO. |
| `env.unsafe_permissions` | 3 | The environment file is writable by group or other (Unix). |
| `env.too_large` | 3 | The environment file is larger than 1 MiB. |
| `env.not_utf8` | 3 | The environment file is not valid UTF-8. |
| `env.malformed_line` | 3 | A line is neither blank, a comment nor a `KEY=VALUE` assignment with a key; located by its line, never its text. |
| `env.duplicate_key` | 3 | A key is assigned again: located at the repeating line, and named only when it is a gateway setting. An error under `--strict`; otherwise a warning that exits `0`. |

### Config diagnostics

One code per way the gateway's configuration compiler found the setting a refusal begins with. Each is located at the line of the setting's effective (last) assignment, when the file assigns it, and names the setting and the [rule](#configuration-rules), never the value or the compiler's own message, which may quote one.

| Code | Exit | Meaning |
| --- | --- | --- |
| `config.unset` | 3 | The refusal begins with a setting the file does not set, such as one another setting requires. |
| `config.empty` | 3 | The setting is set to an empty or whitespace-only value that was refused. |
| `config.not_unicode` | 3 | The setting's value is not valid Unicode. An environment file is UTF-8, so its findings never have this code; it exists because the compiler's other readers can produce it. |
| `config.refused` | 3 | The setting is set to a value that was refused, on its own or together with another setting. |
| `config.unattributed` | 3 | The refusal begins with no inventoried setting. No refusal the compiler reports today has this shape. |

### Configuration rules

The `rule` of a `config` diagnostic: the compiler check that refused it (`gateway_config::compiler::diagnostic::ConfigRule`, described in [the compiler contract](architecture/configuration-compiler.md#rules)). `value` is the refusal of one setting's own value; every other rule relates settings. A published rule name never changes meaning; renaming or removing one needs a new report version.

| Rule | Refuses |
| --- | --- |
| `value` | A setting's own value: it does not parse, is out of bounds, or is not an accepted word. |
| `admin_listener_collision` | `ADMIN_LISTEN_ADDR` on the data listener's address. |
| `grpc_listener_collision` | `GRPC_LISTEN_ADDR` on the data or admin listener's address. |
| `tls_material_unpaired` | Certificate and key files not set together, or not one key per certificate chain. |
| `admin_tls_without_admin_listener` | Admin TLS material without a separate admin listener. |
| `client_certificate_auth` | Client-certificate authentication without TLS, a CA bundle or an identity source, or a CA or CRL file while the mode is `off`. |
| `client_cert_identity_source_unused` | An identity source while both listeners' client-certificate modes are `off`. |
| `admin_session_settings_without_mode` | Admin session settings without a session mode that reads them. |
| `admin_session_idle_timeout_bounds` | An idle timeout outside 1 and the session's absolute lifetime. |
| `admin_login_provider_unusable` | An `ADMIN_LOGIN_PROVIDER` that cannot serve the admin login. |
| `admin_session_requirements` | An admin session store without the login, authentication, CSRF protection or HTTPS redirect it relies on. |
| `admin_session_csrf_exemption` | CSRF exemptions for admin API routes while an admin session store is on. |
| `trusted_proxy_networks_required` | `TRUST_PROXY_HEADERS` without a trusted proxy network. |
| `cookie_session_delegation` | A route delegating the cookie session without the authentication and CSRF settings it relies on, or overlapping an exemption. |
| `upstream_routing_sources_exclusive` | `UPSTREAM_URL` and `UPSTREAM_ROUTES` together. |
| `host_routes_require_policy` | A host-bound route without `POLICY_FILE`. |
| `secrets_root_required` | A file-backed secret alias or a keyring without `CONNECTION_SECRETS_ROOT`. |
| `local_keyring_requires_connections_store` | `CONNECTION_LOCAL_SECRET_KEYRING` without `CONNECTIONS_SQLITE_PATH`. |
| `secret_alias_id_reserved` | A provider alias reusing an operator secret alias's ID. |
| `cluster_member_stale_window` | A `CLUSTER_MEMBER_STALE_MS` shorter than the heartbeats a live replica may miss. |
| `cluster_mode_requirements` | `STATE_BACKEND=postgres` without the deployment ID, the database URL file or a keyring it requires. |
| `local_authority_in_cluster_mode` | A local file or SQLite store while PostgreSQL is the authority. |
| `admin_session_store_backend` | An admin session store the state backend cannot host. |
| `cluster_setting_in_standalone_mode` | A cluster-only setting while `STATE_BACKEND` is `sqlite`. |
| `payload_capture_destination` | Standalone payload capture without `DISCOVERY_SQLITE_PATH`. |
| `authority_event_sink_requirements` | An authority-event sink without its pseudonym key alias or, for the file sink, its file. |
| `authority_event_material_unused` | Authority-event material the configured sink never reads. |
| `authority_pseudonym_keys_distinct` | The current and previous pseudonym key aliases naming the same alias. |
| `authority_evidence_delivery_required` | `AUTHORITY_EVIDENCE_DURABILITY=required` in cluster mode with no authority-event sink to deliver it. |
| `authority_evidence_unsupported_configuration` | `AUTHORITY_EVIDENCE_DURABILITY=required` with a setting that enables an authority change the evidence inventory marks unsupported in this mode. |

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

`ggctl` is tested on Linux, macOS and Windows. Exit codes, stream separation, terminal detection, token-file and document type and size checks, the remote client and evidence verification behave the same on all three. The owner-only permission check on token files applies on Unix only, as do the owner, mode and path checks on `--ca-file` and `--answers` files, and so do the bundle reader's refusal of a group- or other-writable bundle directory or file ([files and the directory](configuration-bundles.md#files-and-the-directory)) and the same refusal of an environment file; on Windows the reader enforces the link, reparse-point, regular-file and name rules, and ACLs are left to the operator. Likewise `init` and `convert --output` create their directory `0700` and its files `0600` on Unix and check those modes, and `pin` writes its new `bundle.yaml` `0600` and checks it, and `backup create` writes its archive `0600` and its working and staging directories `0700` and checks the archive, and `backup restore` stages `0600` stores in a `0700` directory and checks both, while on Windows the new entries inherit the ACL of the directory they are created in. Shell completion is generated for bash, zsh, fish and PowerShell.
