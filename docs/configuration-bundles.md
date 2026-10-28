# Configuration bundles (`v1alpha1`)

**Status: alpha format, not yet selectable.** This page is the reference for the
versioned configuration bundle format and the reader that validates it (issue
#242, PR 4). Nothing in a released gateway reads a bundle yet: there is no
startup mode, environment variable, admin route, or `ggctl` command that selects
one. Bundle mode, the field catalog that fills the deployment document, and
`ggctl validate` are later #242 slices. Until they land, environment
configuration ([configuration.md](configuration.md)) is the only way to configure
a gateway, and the format below may still gain deployment settings before it is
released.

The design this follows is
[ADR-0008](adr/0008-setup-cli-and-configuration-bundles.md) (setup, operator
CLI, and configuration bundles), which is still **Proposed**: where this page
and the ADR differ, this page describes what the reader does today.

## What a bundle is

A bundle is a **flat directory**:

| File | Kind | Syntax | Byte bound |
| --- | --- | --- | --- |
| `bundle.yaml` (fixed name) | `GatewayBundle` manifest | YAML subset | 64 KiB |
| the deployment document the manifest names | `GatewayDeployment` | YAML subset (`.yaml`) or strict JSON (`.json`) | 1 MiB |
| the policy document the manifest names, if any | policy `0.1.0` | strict JSON (`.json`) | 1 MiB |
| the tools document the manifest names, if any | tools `0.1.0` | strict JSON (`.json`) | 1 MiB |

The files the manifest references may total at most 4 MiB, and the reader
examines at most 256 directory entries.

```yaml
# bundle.yaml
apiVersion: greengateway.dev/v1alpha1
kind: GatewayBundle
metadata:
  name: payments-production
spec:
  deployment:
    path: deployment.yaml
    sha256: "<64 lowercase hex digits of deployment.yaml's exact bytes>"
  resources:
    policy:
      source: bundle
      path: policy.json
      schema_version: "0.1.0"
      sha256: "<64 lowercase hex digits>"
    tools:
      source: server
    connections:
      source: server
```

```yaml
# deployment.yaml
apiVersion: greengateway.dev/v1alpha1
kind: GatewayDeployment
spec:
  profile: production
```

Published schemas (Draft 2020-12):

- [`gateway-bundle.v1alpha1.schema.json`](schemas/gateway-bundle.v1alpha1.schema.json)
- [`gateway-deployment.v1alpha1.schema.json`](schemas/gateway-deployment.v1alpha1.schema.json)

Validate the documents' JSON values against them in CI if you like. They are
necessary but not sufficient: the gateway's reader is authoritative, and it also
checks the directory, the digests, the YAML subset, duplicate references, and
the referenced documents.

## Compatibility

| Document | `apiVersion` | `kind` | Status |
| --- | --- | --- | --- |
| Manifest | `greengateway.dev/v1alpha1` | `GatewayBundle` | alpha |
| Deployment document | `greengateway.dev/v1alpha1` | `GatewayDeployment` | alpha; carries `spec.profile` only |
| Policy resource | (its own `schema_version`) | | `0.1.0` only |
| Tools resource | (its own `schema_version`) | | `0.1.0` only |

The reader accepts only these exact pairs. There is no prefix match, no "any
alpha", no case folding, and no downgrade. An unknown `apiVersion` stops
validation before any other member is read (`compat.unsupported_api_version`),
and a `kind` other than the one expected is `compat.unsupported_kind`. Changing
a document version is an explicit conversion; a release that adds a version
keeps reading the previous one for at least one minor release.

Environment-mode policy and tools loading is unchanged: it still accepts any
`0.` schema version, and the policy loader still warns about unknown top-level
members and drops them. The exact version and the refusal below apply only at
the bundle boundary.

## The manifest

- `metadata.name` is a lowercase DNS label (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`).
- `spec.deployment` is required: `path` names a `.yaml` or `.json` file and
  `sha256` pins its exact bytes.
- `spec.resources` is optional, and so is each of its members.
  - `policy` and `tools` take `source: bundle` with `path` (a `.json` file),
    `schema_version`, and `sha256`, or `source: server` with nothing else. With
    `source: bundle` the bundle is the resource's only writer; with
    `source: server` the gateway's existing store is. What each choice means in
    each deployment mode is decided by the configuration compiler, not by the
    reader.
  - `connections` accepts only `source: server`; Connections are never bundle
    content in `v1alpha1` (`reference.source_unsupported`).
- No two references may name the same file (`reference.duplicate_path`), and no
  reference may name `bundle.yaml` (`reference.reserved_path`).
- Every object is closed: a member the version does not define is refused, not
  ignored (`schema.unknown_member`).

## The deployment document

In this alpha `spec` has exactly one member, `profile`: `production`,
`migration`, or `development`. The reader fixes the names; the compiler will
enforce each profile's invariants. The deployment settings themselves join
`spec` from the field catalog before a gateway can start from a bundle, so a
document that sets anything else today is refused (`schema.unknown_member`)
rather than having the setting silently dropped.

The value forms those settings will use are fixed now, with the reader and the
schema's `$defs`:

- **Secret references.** A sensitive setting accepts only `{ secret: <alias-id> }`,
  where the alias ID is an opaque ID in the one alias namespace the secret
  providers maintain: 1 to 128 bytes of `[A-Za-z0-9._-]`, starting with a letter
  or digit. A plain value in a sensitive setting is `secret.inline_value`, and the
  diagnostic never contains it; any other shape is `secret.invalid_reference`.
  The form cannot express a value, an environment-variable name, a file path, a
  provider locator, or ciphertext. The reader never resolves a reference.
- **Unresolved placeholders.** `{ unresolved: legacy_inline_secret | template_value | not_representable }`
  marks a value an export, conversion, or template could not or would not
  supply. No setting accepts one (`reference.unresolved`), so an output that
  contains one can never be mistaken for a deployable bundle.
- **Decimals.** JSON numbers in bundle documents are integers within the I-JSON
  safe range (magnitude at most 2^53 - 1). A fractional setting is a string in the
  grammar `^(0|[1-9][0-9]{0,15})(\.[0-9]{1,6})?$` (`schema.invalid_decimal`
  otherwise), canonicalized to its shortest exact spelling (`"0.10"` is `"0.1"`).
  It parses to exactly the floating-point value the same text gives in an
  environment variable.

## Referenced policy and tools documents

A bundle pins its policy and tools documents but does not redefine them. Each is
read as strict JSON (a duplicate member is refused, never overwritten), its
`schema_version` must equal the version the manifest declares
(`resource.schema_version_mismatch`), and the manifest may declare only a version
this reader implements (`resource.unsupported_schema_version`). Then:

- a policy document may not have a top-level member the policy loader would warn
  about and drop (`resource.unknown_member`), and must pass both
  [`policy.v0.schema.json`](schemas/policy.v0.schema.json) and the production
  policy validator;
- a tools document must pass the production tools validator, which applies
  [`tools.v0.schema.json`](schemas/tools.v0.schema.json).

A failure of either is `resource.invalid`. Validator messages can quote document
values, so they are not repeated.

## Digests

- **File pins.** Each referenced file's `sha256` is checked against its exact
  bytes before the file is parsed (`bundle.digest_mismatch`), so a document whose
  bytes differ from what was reviewed is never interpreted. Pins are what
  `sha256sum` prints, so CI and reviewers can verify them with standard tools.
- **Source digest.** The bundle's identity is `sha256:` and 64 lowercase hex
  digits over ADR-0004's `GGDIGEST` frame of the manifest's exact bytes, with
  kind `source`, media type `application/vnd.greengateway.bundle+yaml`, and the
  manifest's `apiVersion` as the schema version. Because the manifest pins every
  other file, it identifies the whole bundle.
- **Canonical form.** Bundle documents are compared and hashed as their RFC 8785
  canonical JSON, which is the same whether the document was written as YAML or
  JSON and whatever its member order or formatting.

A digest is integrity metadata. It does not make an unsigned bundle trusted,
verified, or authentic; control who can change the delivery channel (branch
protection, Kubernetes RBAC on the ConfigMaps, admission policy).

Two read bundles can be compared semantically: by their validated manifest,
deployment, policy and tools documents rather than their text, with each
change classified by how it takes effect and what it weakens, under stable
risk codes and with no value shown. Nothing reports that diff yet; see the
[semantic diff](semantic-diff.md).

## Files and the directory

The reader canonicalizes the bundle root once and opens it as a capability. Each
file is then opened beneath it by one name, without following links, checked on
the opened handle, and read once into memory under its byte bound; nothing is
reopened. Specifically:

- **Names.** A referenced file name matches `^[a-z0-9][a-z0-9._-]{0,62}$`, does
  not end in `.`, and is not a Windows device name (`con`, `prn`, `aux`, `nul`,
  `com0`-`com9`, `lpt0`-`lpt9`, with or without an extension); otherwise
  `reference.invalid_path`. Lowercase only, so valid names never collide under
  case folding, and no separator, `..`, drive, or `:` stream suffix can be
  written. A name must match a directory entry exactly, so on a case-insensitive
  filesystem `policy.json` does not open `POLICY.JSON` (`bundle.file_missing`,
  `bundle.manifest_missing`).
- **Flat and regular.** Symbolic links, junctions, and reparse points are
  refused wherever they are (`bundle.symlink_forbidden`); so are subdirectories
  and special files (`bundle.not_regular_file`) and files with more than one hard
  link (`bundle.hard_link_forbidden`).
- **Dot entries** (`.git`, `.gitattributes`) are ignored and never opened. Any
  other entry the manifest does not reference is a warning
  (`bundle.unreferenced_entry`) and, when reading strictly, an error.
- **Permissions (Unix).** The root, the directory files are read from, and each
  file must not be writable by group or other (`bundle.unsafe_permissions`). A
  world-writable directory is accepted only with the sticky bit, which is how the
  kubelet publishes volume roots. A read-only mount does not relax this check in
  this alpha. Windows ACLs remain an operator and platform
  responsibility, as they are for `CONNECTION_SECRETS_ROOT`.
- **Kubernetes ConfigMap and projected volumes.** When the root contains
  `..data`, it must be a symbolic link to one sibling directory whose name starts
  with `..`, and every other non-dot entry at the root must be one of the
  kubelet's per-key links. The reader resolves `..data` once, reads every file as
  a regular file from that one generation, and never follows the per-key links,
  so an update in the middle of a read cannot mix two generations. Anything else
  is `bundle.atomic_writer_invalid`.
- **Bounds.** Per-file bounds (`bundle.file_too_large`), the 4 MiB total
  (`bundle.bundle_too_large`), and the 256-entry listing bound
  (`bundle.too_many_entries`) are checked from metadata before a byte is
  allocated, and again while reading; a file whose length changes during the
  read is `bundle.changed_during_read`.
- **Text.** Every file is UTF-8 (`bundle.not_utf8`) without a byte-order mark
  (`bundle.byte_order_mark`) and with LF line endings (`bundle.carriage_return`).
  Add a `.gitattributes` with `* text eol=lf` to the bundle's directory so a
  Windows checkout with `core.autocrlf` cannot change a digest. Bundle documents
  (not policy or tools) also may not contain C0 or C1 control characters other
  than tab and line feed, DEL, the byte-order mark, bidirectional formatting
  characters, or the line and paragraph separators U+2028 and U+2029 (which,
  like NEL, YAML 1.1 readers treat as line breaks), anywhere including comments
  and escapes (`syntax.forbidden_character`): a reviewer, another YAML reader,
  and the gateway must not read the same bytes differently.

Bundles are directories only. There is no archive form of a bundle, so no
archive reader sits in the configuration path; the backup archive (a later #242
slice) has its own reader, which must apply the
[archive entry admission rules](archive-admission.md).

## The YAML subset

The manifest and a `.yaml` deployment document are read by a reader for a small
subset of YAML 1.2, so that a reviewer and the gateway can never read the same
file differently. It accepts:

- one document, optionally preceded by `---`;
- block mappings and block sequences indented with spaces, including a sequence
  written at its key's indentation and a mapping or sequence that starts on a
  `- ` line;
- flow sequences and mappings (`[a, b]`, `{ secret: idp-client }`) that close on
  the line they open, without trailing commas;
- double-quoted strings with exactly the JSON escapes (`\" \\ \/ \b \f \n \r \t \uXXXX`),
  single-quoted strings (`''` for a quote), and plain scalars, each ending on the
  line it starts;
- `#` comments, after whitespace.

A **plain (unquoted) scalar** is `true`, `false`, `null`, an RFC 8259 integer
(`0`, `-7`, `8443`), or a string that starts with an ASCII letter, `_`, `/`, or a
non-ASCII character and is not one of the YAML 1.1 boolean or null words in any
case. Anything else must be quoted (`yaml.ambiguous_scalar`): for example `yes`,
`No`, `ON`, `~`, `Null`, `TRUE`, `0x1F`, `017`, `1_000`, `12:30`, `2026-10-21`, `1.5`,
`.inf`, `-foo`, `0.0.0.0:8080`, and any hex digest that starts with a digit.
A plain key is an identifier (`[A-Za-z_][A-Za-z0-9_.-]*`) that is not a boolean or
null word; quote any other key (`yaml.key_must_be_quoted`, `yaml.non_string_key`).

Refused, each with its own code:

| Construct | Code |
| --- | --- |
| Anchors `&a` and aliases `*a` | `yaml.anchor_forbidden`, `yaml.alias_forbidden` |
| Tags `!t`, `!!str` | `yaml.tag_forbidden` |
| Merge keys `<<` | `yaml.merge_key_forbidden` |
| Directives `%YAML`, `%TAG` | `yaml.directive_forbidden` |
| A second document, or `...` | `yaml.multiple_documents` |
| Explicit `? ` keys and collection keys | `yaml.complex_key_forbidden` |
| Keys another reader would type as a boolean, null, or number | `yaml.non_string_key` |
| Block scalars `\|` and `>` | `yaml.block_scalar_forbidden` |
| Multi-line plain, quoted, or flow values | `yaml.multiline_value_forbidden` |
| YAML-only escapes (`\x41`, `\0`, `\N`, lone surrogates, ...) | `yaml.unsupported_escape` |
| Tabs outside quoted strings and comments | `yaml.tab_forbidden` |
| Inconsistent indentation | `yaml.bad_indentation` |
| A key or item with no value (write `null`) | `yaml.empty_value` |
| A key given twice | `yaml.duplicate_key` |
| Anything else outside the subset | `yaml.syntax_error` |

There are no includes, globs, remote URLs, templates, shell expansion,
environment interpolation, Git directives, or code. Every path in a manifest is
one file name in the bundle root, never relative to the caller's working
directory.

## Strict JSON

A `.json` deployment document and the policy and tools documents are read by a
strict RFC 8259 reader: a duplicate member name is `json.duplicate_key` (it is
refused when the second one is met, before any value could be replaced), and
trailing content, comments, single quotes, trailing commas, leading zeros, `NaN`,
`Infinity`, unescaped control characters, and lone surrogates are
`json.syntax_error`. In bundle documents a number with a fraction or exponent is
`syntax.number_not_integer` and an integer beyond the safe range is
`syntax.integer_out_of_range`; policy and tools documents keep their own
validators' number rules.

## Structural bounds

Applied while parsing, before the value they limit is built. A bound is a
ceiling; nothing raises one, and zero never means unlimited.

| Dimension | Bundle documents | Policy and tools documents |
| --- | --- | --- |
| Nested collections | 32 (`syntax.too_deep`) | 32 |
| Members per object | 1,024 (`syntax.too_many_members`) | their validators' limits |
| Elements per array | 4,096 (`syntax.too_many_elements`) | their validators' limits |
| Values per document | 65,536 (`syntax.too_many_nodes`) | their validators' limits |
| String | 64 KiB (`syntax.string_too_long`) | their validators' limits |
| Object key | 128 bytes (`syntax.key_too_long`) | their validators' limits |

An empty document is `syntax.empty_document`.

## Diagnostics

Every problem is reported, not just the first, as a diagnostic with a stable
`family.reason` code, a severity, the bundle-relative file name, a JSON Pointer,
and a line and column:

```text
bundle.yaml:8:13: error[reference.invalid_digest]: a pinned digest is not 64 lowercase hexadecimal digits (at /spec/deployment/sha256)
```

Diagnostics are value-free by construction: the message is fixed text chosen by
the code, the file name is one that passed the file-name grammar, and the pointer
is built from member names the reader itself defines. An unknown member is
reported at its parent's pointer and its own line and column, never by its name.
No document value, host path, environment value, or validator or library message
can appear in one. A published code never changes meaning.

| Code | Meaning |
| --- | --- |
| `bundle.root_unavailable` | The bundle directory cannot be opened. |
| `bundle.root_not_directory` | The bundle location is not a directory. |
| `bundle.unsafe_permissions` | A bundle directory or file is writable by group or other. |
| `bundle.too_many_entries` | The directory holds more than 256 entries. |
| `bundle.manifest_missing` | There is no `bundle.yaml`. |
| `bundle.file_missing` | A referenced file is not in the bundle. |
| `bundle.symlink_forbidden` | An entry is a symbolic link, junction, or reparse point. |
| `bundle.not_regular_file` | An entry is a directory or special file. |
| `bundle.hard_link_forbidden` | A file has more than one hard link. |
| `bundle.file_too_large` | A file is larger than its kind allows. |
| `bundle.bundle_too_large` | The referenced files exceed 4 MiB together. |
| `bundle.read_failed` | A file could not be read. |
| `bundle.changed_during_read` | A file changed while it was being read. |
| `bundle.atomic_writer_invalid` | The `..data` layout is not one resolvable generation. |
| `bundle.unreferenced_entry` | An entry is not referenced by the manifest (warning; an error when strict). |
| `bundle.byte_order_mark` | A file starts with a byte-order mark. |
| `bundle.carriage_return` | A file contains a carriage return. |
| `bundle.not_utf8` | A file is not valid UTF-8. |
| `bundle.digest_mismatch` | A file's SHA-256 differs from its pin. |
| `syntax.empty_document` | The document is empty. |
| `syntax.too_deep` | Too many nested collections. |
| `syntax.too_many_members` | An object has too many members. |
| `syntax.too_many_elements` | An array has too many elements. |
| `syntax.too_many_nodes` | The document has too many values. |
| `syntax.string_too_long` | A string is too long. |
| `syntax.key_too_long` | An object key is too long. |
| `syntax.number_not_integer` | A number in a bundle document is not an integer. |
| `syntax.integer_out_of_range` | An integer is outside the I-JSON safe range. |
| `syntax.forbidden_character` | A control, bidirectional formatting, or line or paragraph separator character. |
| `json.syntax_error` | Not valid JSON. |
| `json.duplicate_key` | An object names a member twice. |
| `yaml.syntax_error` | Outside the YAML subset. |
| `yaml.duplicate_key` | A mapping names a key twice. |
| `yaml.alias_forbidden` | A YAML alias. |
| `yaml.anchor_forbidden` | A YAML anchor. |
| `yaml.tag_forbidden` | A YAML tag. |
| `yaml.merge_key_forbidden` | A YAML merge key. |
| `yaml.directive_forbidden` | A YAML directive. |
| `yaml.multiple_documents` | More than one YAML document. |
| `yaml.complex_key_forbidden` | An explicit or collection key. |
| `yaml.non_string_key` | A key that would be read as a boolean, null, or number. |
| `yaml.key_must_be_quoted` | A key outside the plain identifier form. |
| `yaml.ambiguous_scalar` | An unquoted value another reader could type differently. |
| `yaml.block_scalar_forbidden` | A literal or folded block scalar. |
| `yaml.multiline_value_forbidden` | A value that does not end on the line it starts. |
| `yaml.unsupported_escape` | An escape outside the JSON set. |
| `yaml.tab_forbidden` | A tab outside quoted strings and comments. |
| `yaml.bad_indentation` | Inconsistent indentation. |
| `yaml.empty_value` | A key or item with no value. |
| `compat.unsupported_api_version` | An `apiVersion` this reader does not implement. |
| `compat.unsupported_kind` | A `kind` other than the one expected. |
| `schema.unknown_member` | A member the document version does not define. |
| `schema.missing_member` | A required member is missing. |
| `schema.wrong_type` | A value has the wrong type. |
| `schema.invalid_value` | A value the document version does not allow. |
| `schema.invalid_name` | `metadata.name` is not a lowercase DNS label. |
| `schema.invalid_decimal` | A decimal outside the decimal grammar. |
| `reference.invalid_path` | A referenced name is not a portable file name of the right type. |
| `reference.reserved_path` | A reference names `bundle.yaml`. |
| `reference.duplicate_path` | Two references name the same file. |
| `reference.invalid_digest` | A pin is not 64 lowercase hex digits. |
| `reference.source_unsupported` | The resource cannot come from this source in this version. |
| `reference.unresolved` | An unresolved placeholder. |
| `secret.inline_value` | A sensitive setting holds a literal value. |
| `secret.invalid_reference` | A secret reference is not a single opaque alias ID. |
| `resource.unsupported_schema_version` | The manifest declares a resource version this reader does not implement. |
| `resource.schema_version_mismatch` | The resource's `schema_version` differs from the declared one. |
| `resource.unknown_member` | A policy top-level member the loader would drop. |
| `resource.invalid` | The resource fails its published schema or production validator. |
