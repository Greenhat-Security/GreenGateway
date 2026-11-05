"""Package, check and verify the ggctl release artifacts (issue #242).

`.github/workflows/release-ggctl.yml` drives every mode; docs/RELEASING.md
and docs/ggctl.md describe the release and its verification.

  version    print ggctl's version; for a tag ref, require refs/tags/ggctl-v<version>
  package    archive one built binary with LICENSE, its man pages and its
             completion scripts, then write that archive's SPDX 2.3 SBOM
  compare    require two package outputs to be byte-identical (reproducibility)
  glibc      require a Linux binary to need no glibc newer than a floor
  artifact   check one target's archive and SBOM before they are attested
  checksums  write SHA256SUMS for every archive and SBOM
  manifest   write the release manifest: each artifact's checksum, SBOM and
             attestation entries
  check      require every published artifact to have a checksum, an SBOM and
             its attestation entries, and outside --dry-run the signed bundles
  verify     verify every attestation with the pinned GitHub CLI

Archives and SBOMs depend only on the binary, the commit and its timestamp,
so two builds of one commit package to the same bytes. Nothing here signs,
uploads or publishes anything.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import zipfile

from build_tools import versions
from image_evidence import install_gh, run_utf8

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/release-ggctl.yml"
PROVENANCE = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document/v2.3"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
DEFAULT_REPOSITORY = "Greenhat-Security/GreenGateway"

# Every release target and its archive format. The workflow's build matrix
# must list exactly these (scripts/test_ggctl_release.py holds it to them).
TARGETS = {
    "aarch64-apple-darwin": "tar.gz",
    "aarch64-unknown-linux-gnu": "tar.gz",
    "x86_64-apple-darwin": "tar.gz",
    "x86_64-pc-windows-msvc": "zip",
    "x86_64-unknown-linux-gnu": "tar.gz",
}
# Each completion script `ggctl completion SHELL` writes, and where it goes.
COMPLETIONS = {
    "bash": "completion/ggctl.bash",
    "fish": "completion/ggctl.fish",
    "powershell": "completion/ggctl.ps1",
    "zsh": "completion/_ggctl",
}
CHECKSUMS = "SHA256SUMS"
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
COMMAND = re.compile(r"[a-z][a-z-]*")
LICENSE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
# The zip format cannot record a time before 1980-01-01.
ZIP_EPOCH = 315532800
# Bounds on what a check reads.
MAX_SBOM = 16 * 1024 * 1024
MAX_BUNDLE = 4 * 1024 * 1024


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_bytes(path, data):
    """Writes exactly these bytes: no newline translation on Windows."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def json_bytes(value):
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


# Version and names.

def cargo_version(root=ROOT):
    manifest = tomllib.loads((root / "ggctl/Cargo.toml").read_text(encoding="utf-8"))
    version = manifest.get("package", {}).get("version")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ValueError("ggctl/Cargo.toml must declare an exact MAJOR.MINOR.PATCH version")
    return version


def release_version(ref, root=ROOT):
    """ggctl's version. A tag must be exactly ggctl-v<version>: any other tag,
    including a gateway release tag, is refused rather than renamed."""
    version = cargo_version(root)
    if ref.startswith("refs/tags/") and ref != "refs/tags/ggctl-v" + version:
        raise ValueError(f"the tag must be refs/tags/ggctl-v{version} for ggctl {version}")
    return version


def archive_name(version, target):
    if target not in TARGETS:
        raise ValueError("not a release target: " + target)
    return f"ggctl-{version}-{target}.{TARGETS[target]}"


def sbom_name(version, target):
    return f"ggctl-{version}-{target}.spdx.json"


def sbom_bundle_name(version, target):
    return f"ggctl-{version}-{target}.sbom.sigstore.jsonl"


def provenance_bundle_name(version):
    return f"ggctl-{version}.provenance.sigstore.jsonl"


def manifest_name(version):
    return f"ggctl-{version}-release.json"


def executable_name(target):
    return "ggctl.exe" if "-windows-" in target else "ggctl"


def git(*args, root=ROOT):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True,
                          encoding="utf-8", timeout=60).stdout.strip()


def source_date_epoch(root=ROOT):
    value = os.environ.get("SOURCE_DATE_EPOCH") or git("log", "-1", "--format=%ct", root=root)
    if not value.isdigit():
        raise ValueError("SOURCE_DATE_EPOCH must be a whole number of seconds")
    return int(value)


def source_identity(args):
    repository = args.repository or os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPOSITORY
    sha = args.sha or os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD")
    ref = args.ref or os.environ.get("GITHUB_REF") or ""
    if not REPOSITORY.fullmatch(repository) or not COMMIT.fullmatch(sha):
        raise ValueError("the repository must be OWNER/NAME and the commit 40 hexadecimal digits")
    return repository, sha, ref


# Man pages and their parity with help.

def collapsed(text):
    return " ".join(text.split())


def rendered(page):
    """What a reader of a `ggctl help --man` page sees: its text lines with
    the escapes ggctl writes undone, requests and comments dropped, and
    whitespace collapsed."""
    lines = []
    for line in page.splitlines():
        if line.startswith("."):
            continue
        for escape, text in [("\\fB", ""), ("\\fI", ""), ("\\fR", ""), ("\\&", ""), ("\\-", "-"), ("\\e", "\\")]:
            line = line.replace(escape, text)
        lines.append(line)
    return collapsed(" ".join(lines))


def help_blocks(help_text):
    """`ggctl help` output as the units a reader sees: each paragraph, each
    two-column entry with its wrapped continuation lines, and each usage line.
    Headings and the overview's versioned title line are left out."""
    blocks, current = [], []

    def finish():
        if current:
            blocks.append(collapsed(" ".join(current)))
            current.clear()

    for index, line in enumerate(help_text.splitlines()):
        if not line or line in {"Commands:", "Exit codes:", "Arguments:", "Options:"} \
                or (index == 0 and line.startswith("ggctl ")):
            finish()
        elif line.startswith("Usage: "):
            finish()
            blocks.append(collapsed(line[len("Usage: "):]))
        elif line.startswith("       ggctl "):
            blocks.append(collapsed(line))
        elif line.startswith("  ") and not line.startswith("   "):
            finish()
            current.append(line)
        else:
            current.append(line)
    finish()
    return blocks


def require_parity(help_text, page, name):
    """Fails unless the man page carries every block of its help text."""
    text = rendered(page)
    blocks = help_blocks(help_text)
    if not blocks:
        raise ValueError(f"{name}: the help text is empty")
    missing = [block for block in blocks if block not in text]
    if missing:
        raise ValueError(f"{name} does not say what its help says: {missing[0][:120]!r}")
    if not page.startswith('.\\" Generated by `ggctl help --man`') or "\n.TH " not in page:
        raise ValueError(f"{name} is not a page ggctl generated")


def listed_commands(overview):
    """The command names the `ggctl help` overview lists."""
    _, found, rest = overview.partition("\nCommands:\n")
    lines = rest.split("\n\n", 1)[0].splitlines() if found else []
    commands = [line.split()[0] for line in lines if line.startswith("  ") and not line.startswith("   ")]
    if not commands or any(not COMMAND.fullmatch(command) for command in commands) \
            or len(set(commands)) != len(commands):
        raise ValueError("the ggctl help overview does not list its commands")
    return commands


# Packaging.

def run_binary(binary, *args):
    """Runs the built ggctl, which reads no environment and makes no network
    request for any of these commands, and returns its standard output."""
    result = subprocess.run([str(binary), *args], capture_output=True, timeout=60, check=False)
    if result.returncode != 0 or result.stderr:
        raise ValueError(f"`ggctl {' '.join(args)}` exited {result.returncode}")
    return result.stdout


def text_output(data, what):
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(what + " is not ASCII") from error
    if "\r" in text or not text.endswith("\n"):
        raise ValueError(what + " must be LF-terminated lines")
    return text


def members(binary, target, version, license_text, run=run_binary):
    """The archive's files as (path, bytes, mode), from the binary itself:
    its man pages from `ggctl help --man`, held to `ggctl help`, and its
    completion scripts from `ggctl completion`."""
    if run(binary, "--version") != f"ggctl {version}\n".encode():
        raise ValueError(f"the binary does not report ggctl {version}")
    overview = text_output(run(binary, "help"), "ggctl help")
    files = [(executable_name(target), Path(binary).read_bytes(), 0o755),
             ("LICENSE", license_text.replace("\r\n", "\n").encode("utf-8"), 0o644)]
    page = text_output(run(binary, "help", "--man"), "ggctl help --man")
    require_parity(overview, page, "ggctl.1")
    files.append(("man/man1/ggctl.1", page.encode("ascii"), 0o644))
    for command in listed_commands(overview):
        name = f"ggctl-{command}.1"
        help_text = text_output(run(binary, "help", command), "ggctl help " + command)
        page = text_output(run(binary, "help", "--man", command), "ggctl help --man " + command)
        require_parity(help_text, page, name)
        files.append(("man/man1/" + name, page.encode("ascii"), 0o644))
    for shell, path in COMPLETIONS.items():
        script = text_output(run(binary, "completion", shell), "ggctl completion " + shell)
        files.append((path, script.encode("ascii"), 0o644))
    return sorted(files)


def entries(files):
    """Every file and the directories that hold them, sorted by path."""
    directories = {""}
    for path, _, _ in files:
        parts = path.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            directories.add("/".join(parts[:depth]))
    listed = [(directory, None, 0o755) for directory in directories]
    return sorted(listed + list(files), key=lambda entry: entry[0])


def tar_gz(top, files, epoch):
    """A gzip-compressed ustar archive whose bytes depend only on its input:
    fixed order, times, owners and modes, and no name or time in the gzip
    header beyond the given epoch."""
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=epoch, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for path, data, mode in entries(files):
                info = tarfile.TarInfo(f"{top}/{path}".rstrip("/"))
                info.mtime, info.mode, info.uid, info.gid, info.uname, info.gname = epoch, mode, 0, 0, "", ""
                if data is None:
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                else:
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def zip_archive(top, files, epoch):
    """A deflated zip archive whose bytes depend only on its input."""
    stamp = time.gmtime(max(epoch, ZIP_EPOCH))[:6]
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w") as archive:
        for path, data, mode in entries(files):
            if data is None:
                info = zipfile.ZipInfo(f"{top}/{path}".rstrip("/") + "/", stamp)
                info.create_system, info.external_attr = 3, ((0o040000 | mode) << 16) | 0x10
                archive.writestr(info, b"")
            else:
                info = zipfile.ZipInfo(f"{top}/{path}", stamp)
                info.create_system, info.external_attr = 3, (0o100000 | mode) << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return raw.getvalue()


# The SBOM.

def spdx_id(prefix, *parts):
    return prefix + "-" + re.sub(r"[^A-Za-z0-9.-]", "-", "-".join(parts))


def license_expression(value):
    """A Cargo license field as an SPDX expression, or NOASSERTION when it is
    absent or not one. Cargo's old `MIT/Apache-2.0` spelling means OR."""
    if not isinstance(value, str) or not value.strip():
        return "NOASSERTION"
    expression = " OR ".join(part.strip() for part in value.split("/"))
    tokens = expression.replace("(", " ( ").replace(")", " ) ").split()
    depth, expect_operand = 0, True
    for token in tokens:
        if token == "(" and expect_operand:
            depth += 1
        elif token == ")" and not expect_operand and depth:
            depth -= 1
        elif token in {"AND", "OR", "WITH"} and not expect_operand:
            expect_operand = True
        elif expect_operand and LICENSE_ID.fullmatch(token) and token not in {"AND", "OR", "WITH"}:
            expect_operand = False
        else:
            return "NOASSERTION"
    return expression if tokens and depth == 0 and not expect_operand else "NOASSERTION"


def workspace_license(text):
    """The repository LICENSE as an SPDX identifier, only when it is the
    Apache License 2.0 text; anything else is NOASSERTION, never a guess."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "Apache-2.0" if lines[:2] == ["Apache License", "Version 2.0, January 2004"] else "NOASSERTION"


def dependency_graph(metadata):
    """ggctl's packages for one target: everything reachable from the ggctl
    package through normal and build dependencies, never dev-dependencies,
    as `cargo metadata --filter-platform` resolved them."""
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    roots = [identity for identity in metadata["workspace_members"]
             if packages[identity]["name"] == "ggctl"]
    if len(roots) != 1:
        raise ValueError("cargo metadata names no single ggctl workspace package")
    reached, pending, edges = {roots[0]}, [roots[0]], set()
    while pending:
        current = pending.pop()
        for dependency in nodes[current]["deps"]:
            kinds = {kind.get("kind") for kind in dependency["dep_kinds"]} - {"dev"}
            if not kinds:
                continue
            target = dependency["pkg"]
            if None in kinds:
                edges.add((current, "DEPENDS_ON", target))
            if "build" in kinds:
                edges.add((target, "BUILD_DEPENDENCY_OF", current))
            if target not in reached:
                reached.add(target)
                pending.append(target)
    return roots[0], [packages[identity] for identity in sorted(reached)], sorted(edges)


def sbom_document(metadata, lock, *, target, version, archive, archive_sha256, binary_sha256,
                  epoch, repository, sha, license_id):
    """The archive's SPDX 2.3 SBOM: the archive, the ggctl executable in it,
    and the Cargo packages the executable was compiled from for this target,
    with Cargo.lock's checksum of each registry package."""
    locked = {(package["name"], package["version"], package.get("source")): package
              for package in lock["package"]}
    root, reached, edges = dependency_graph(metadata)
    workspace_root = Path(metadata["workspace_root"])
    identities, packages = {}, []
    for package in reached:
        name, package_version, source = package["name"], package["version"], package["source"]
        entry = {"name": name, "SPDXID": spdx_id("SPDXRef-Package", name, package_version),
                 "versionInfo": package_version, "filesAnalyzed": False,
                 "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION",
                 "primaryPackagePurpose": "LIBRARY"}
        if source == REGISTRY:
            checksum = locked.get((name, package_version, source), {}).get("checksum")
            if not isinstance(checksum, str) or not DIGEST.fullmatch(checksum):
                raise ValueError(f"Cargo.lock has no checksum for {name} {package_version}")
            entry["downloadLocation"] = f"https://crates.io/api/v1/crates/{name}/{package_version}/download"
            entry["licenseDeclared"] = license_expression(package.get("license"))
            entry["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
            locator = f"pkg:cargo/{name}@{package_version}"
        elif source is None and package["id"] in metadata["workspace_members"]:
            directory = Path(package["manifest_path"]).parent.relative_to(workspace_root).as_posix()
            entry["downloadLocation"] = f"git+https://github.com/{repository}@{sha}#{directory}"
            entry["licenseDeclared"] = (license_expression(package.get("license"))
                                        if package.get("license") else license_id)
            locator = f"pkg:github/{repository.lower()}@{sha}#{directory}"
        else:
            raise ValueError(f"{name} {package_version} comes from an unreviewed source")
        entry["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                                  "referenceLocator": locator}]
        if entry["SPDXID"] in identities.values():
            raise ValueError("two packages share the SPDX identifier " + entry["SPDXID"])
        identities[package["id"]] = entry["SPDXID"]
        packages.append(entry)
    executable = executable_name(target)
    head = [
        {"name": archive, "SPDXID": "SPDXRef-Archive", "versionInfo": version,
         "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
         "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
         "copyrightText": "NOASSERTION", "primaryPackagePurpose": "ARCHIVE",
         "checksums": [{"algorithm": "SHA256", "checksumValue": archive_sha256}]},
        {"name": executable, "SPDXID": "SPDXRef-Executable", "versionInfo": version,
         "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
         "licenseConcluded": "NOASSERTION", "licenseDeclared": license_id,
         "copyrightText": "NOASSERTION", "primaryPackagePurpose": "APPLICATION",
         "checksums": [{"algorithm": "SHA256", "checksumValue": binary_sha256}]},
    ]
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": "SPDXRef-Archive"},
        {"spdxElementId": "SPDXRef-Archive", "relationshipType": "CONTAINS",
         "relatedSpdxElement": "SPDXRef-Executable"},
        {"spdxElementId": "SPDXRef-Executable", "relationshipType": "GENERATED_FROM",
         "relatedSpdxElement": identities[root]},
    ]
    relationships += [{"spdxElementId": identities[left], "relationshipType": kind,
                       "relatedSpdxElement": identities[right]} for left, kind, right in edges]
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": archive,
        "documentNamespace": f"https://github.com/{repository}/ggctl/{version}/{target}/{archive_sha256}",
        "comment": (f"ggctl {version} for {target}, built from {repository} commit {sha}. The packages "
                    "are those Cargo compiles ggctl from for this target (its normal and build "
                    "dependencies, never dev-dependencies) as Cargo.lock pins them; the binary itself "
                    "was not scanned."),
        "creationInfo": {"created": created, "creators": ["Tool: ggctl_release.py"]},
        "packages": head + sorted(packages, key=lambda entry: entry["SPDXID"]),
        "relationships": relationships,
    }


def sbom_describes(document, archive, digest):
    """Fails unless the SBOM is an SPDX 2.3 document describing exactly this
    archive, by name and SHA-256, and the executable it contains."""
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3" \
            or document.get("SPDXID") != "SPDXRef-DOCUMENT" or document.get("name") != archive:
        raise ValueError(f"the SBOM for {archive} is not an SPDX 2.3 document about it")
    packages = {package.get("SPDXID"): package for package in document.get("packages", [])
                if isinstance(package, dict)}
    relationships = [(r.get("spdxElementId"), r.get("relationshipType"), r.get("relatedSpdxElement"))
                     for r in document.get("relationships", []) if isinstance(r, dict)]
    described = [right for left, kind, right in relationships
                 if left == "SPDXRef-DOCUMENT" and kind == "DESCRIBES"]
    subject = packages.get(described[0]) if len(described) == 1 else None
    if not subject or subject.get("name") != archive or subject.get("checksums") != [
            {"algorithm": "SHA256", "checksumValue": digest}]:
        raise ValueError(f"the SBOM does not describe {archive} with its SHA-256")
    contained = [right for left, kind, right in relationships
                 if left == described[0] and kind == "CONTAINS"]
    if len(contained) != 1 or packages.get(contained[0], {}).get("primaryPackagePurpose") != "APPLICATION" \
            or len(packages) < 4:
        raise ValueError(f"the SBOM for {archive} lists no executable and its packages")


def cargo_metadata(target, root=ROOT):
    output = subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1",
                             "--filter-platform", target], cwd=root, check=True,
                            capture_output=True, encoding="utf-8", timeout=600).stdout
    return json.loads(output)


def package(binary, target, output, repository, sha, root=ROOT, run=run_binary, metadata=None):
    """Writes the target's archive and SBOM into output, which must not yet
    hold either."""
    version = cargo_version(root)
    epoch = source_date_epoch(root)
    license_text = (root / "LICENSE").read_text(encoding="utf-8")
    files = members(binary, target, version, license_text, run)
    name = archive_name(version, target)
    top = f"ggctl-{version}-{target}"
    data = zip_archive(top, files, epoch) if TARGETS[target] == "zip" else tar_gz(top, files, epoch)
    for existing in (output / name, output / sbom_name(version, target)):
        if existing.exists():
            raise ValueError(f"{existing.name} already exists; package into an empty directory")
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    if metadata is None:
        metadata = cargo_metadata(target, root)
    document = sbom_document(metadata, lock, target=target,
                             version=version, archive=name, archive_sha256=sha256(data),
                             binary_sha256=file_sha256(binary), epoch=epoch,
                             repository=repository, sha=sha, license_id=workspace_license(license_text))
    sbom_describes(document, name, sha256(data))
    write_bytes(output / name, data)
    write_bytes(output / sbom_name(version, target), json_bytes(document))
    return output / name


def compare(first, second):
    """Fails unless both directories hold the same files with the same bytes."""
    names = sorted(path.name for path in first.iterdir())
    if not names or names != sorted(path.name for path in second.iterdir()):
        raise ValueError("the two builds packaged different files")
    for name in names:
        left, right = file_sha256(first / name), file_sha256(second / name)
        if left != right:
            raise ValueError(f"{name} is not reproducible: {left} then {right}")
        print(f"{left}  {name}  (reproduced)")


def glibc_floor(objdump):
    """The newest glibc symbol version an `objdump -T` listing requires."""
    versions = {tuple(int(part) for part in match.group(1).split("."))
                for match in re.finditer(r"\bGLIBC_([0-9]+(?:\.[0-9]+)+)\b", objdump)}
    if not versions:
        raise ValueError("the binary requires no versioned glibc symbol: is it a glibc binary?")
    return max(versions)


def check_glibc(binary, maximum):
    if not re.fullmatch(r"[0-9]+\.[0-9]+", maximum):
        raise ValueError("the glibc floor must be MAJOR.MINOR")
    listing = subprocess.run(["objdump", "-T", str(binary)], check=True, capture_output=True,
                             encoding="utf-8", timeout=120).stdout
    floor = glibc_floor(listing)
    if floor > tuple(int(part) for part in maximum.split(".")):
        raise ValueError(f"the binary needs glibc {'.'.join(map(str, floor))}, newer than {maximum}")
    print(f"needs glibc {'.'.join(map(str, floor))} (at most {maximum})")


# The release directory.

def artifact(dist, target, version):
    """Checks one target's build output before it is attested and returns
    the GitHub step outputs naming its files."""
    archive, sbom = archive_name(version, target), sbom_name(version, target)
    present = sorted(path.name for path in dist.iterdir())
    if present != sorted([archive, sbom]):
        raise ValueError(f"the {target} build output must be exactly {archive} and {sbom}")
    sbom_describes(read_json(dist / sbom, MAX_SBOM), archive, file_sha256(dist / archive))
    return {"archive": (dist / archive).as_posix(), "sbom": (dist / sbom).as_posix(),
            "bundle": sbom_bundle_name(version, target)}


def write_checksums(dist, version):
    names = sorted([archive_name(version, target) for target in TARGETS]
                   + [sbom_name(version, target) for target in TARGETS])
    lines = "".join(f"{file_sha256(dist / name)}  {name}\n" for name in names)
    write_bytes(dist / CHECKSUMS, lines.encode("ascii"))


def parse_checksums(data):
    """SHA256SUMS as {name: digest}: one `DIGEST  NAME` line per file."""
    text = data.decode("ascii")
    if not text.endswith("\n"):
        raise ValueError("SHA256SUMS must end with a newline")
    entries = {}
    for line in text[:-1].split("\n"):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if not match or match.group(2) in entries:
            raise ValueError("SHA256SUMS must be one `DIGEST  NAME` line per file")
        entries[match.group(2)] = match.group(1)
    return entries


def release_manifest(dist, version, repository, sha, ref):
    """The release manifest: each artifact with its digest, its SBOM, and
    the attestations that cover it, by predicate type and bundle file."""
    provenance = provenance_bundle_name(version)
    artifacts = []
    for target in sorted(TARGETS):
        archive, sbom = archive_name(version, target), sbom_name(version, target)
        artifacts.append({
            "target": target,
            "archive": archive,
            "sha256": file_sha256(dist / archive),
            "sbom": sbom,
            "sbom_sha256": file_sha256(dist / sbom),
            "attestations": [
                {"subject": archive, "predicate_type": PROVENANCE, "bundle": provenance},
                {"subject": archive, "predicate_type": SPDX, "bundle": sbom_bundle_name(version, target)},
                {"subject": sbom, "predicate_type": PROVENANCE, "bundle": provenance},
            ],
        })
    return {
        "format": 1,
        "name": "ggctl",
        "version": version,
        "repository": repository,
        "source_sha": sha,
        "source_ref": ref,
        "signer_workflow": f"{repository}/{WORKFLOW}",
        "checksums": {
            "file": CHECKSUMS,
            "sha256": file_sha256(dist / CHECKSUMS),
            "attestations": [{"subject": CHECKSUMS, "predicate_type": PROVENANCE, "bundle": provenance}],
        },
        "artifacts": artifacts,
    }


def read_json(path, limit):
    data = path.read_bytes()
    if not data or len(data) > limit:
        raise ValueError(f"{path.name} is empty or larger than {limit} bytes")
    return json.loads(data)


def bundle_statements(path):
    """The in-toto statements of a JSON Lines file of Sigstore bundles, read
    without verifying them: `verify` does that with the GitHub CLI."""
    data = path.read_bytes()
    if not data or len(data) > MAX_BUNDLE:
        raise ValueError(f"{path.name} is empty or larger than {MAX_BUNDLE} bytes")
    statements = []
    for line in data.decode("utf-8").splitlines():
        if not line.strip():
            continue
        envelope = json.loads(line).get("dsseEnvelope", {})
        if envelope.get("payloadType") != "application/vnd.in-toto+json" or not envelope.get("signatures"):
            raise ValueError(f"{path.name} holds a bundle without a signed in-toto statement")
        statements.append(json.loads(base64.b64decode(envelope["payload"], validate=True)))
    if not statements:
        raise ValueError(f"{path.name} holds no bundle")
    return statements


def covers(statements, predicate_type, name, digest):
    return [statement for statement in statements
            if statement.get("predicateType") == predicate_type
            and {"name": name, "digest": {"sha256": digest}} in statement.get("subject", [])]


def check(dist, dry_run, root=ROOT):
    """Fails unless every published artifact has a checksum, an SBOM that
    describes it, and its attestation entries. Outside a dry run every entry
    must also name a bundle here whose statement covers the artifact's digest
    with that predicate, and an SBOM attestation must carry the SBOM itself."""
    version = cargo_version(root)
    manifest = read_json(dist / manifest_name(version), MAX_SBOM)
    repository, sha = manifest.get("repository", ""), manifest.get("source_sha", "")
    if manifest.get("format") != 1 or manifest.get("name") != "ggctl" or manifest.get("version") != version \
            or not REPOSITORY.fullmatch(repository) or not COMMIT.fullmatch(sha) \
            or manifest.get("signer_workflow") != f"{repository}/{WORKFLOW}":
        raise ValueError("the release manifest does not describe this ggctl release")
    release_version(manifest.get("source_ref", ""), root)
    if not dry_run and manifest["source_ref"] != "refs/tags/ggctl-v" + version:
        raise ValueError("a release must be built from its ggctl tag")
    artifacts = manifest.get("artifacts", [])
    if sorted(item.get("target") for item in artifacts) != sorted(TARGETS) or len(artifacts) != len(TARGETS):
        raise ValueError("the release manifest must list each release target exactly once")
    checksums = parse_checksums((dist / CHECKSUMS).read_bytes())
    listed = manifest.get("checksums", {})
    if listed.get("file") != CHECKSUMS or listed.get("sha256") != file_sha256(dist / CHECKSUMS):
        raise ValueError("the release manifest names a different SHA256SUMS")
    expected = {CHECKSUMS, manifest_name(version)}
    required = [(CHECKSUMS, PROVENANCE, listed.get("attestations", []))]
    for item in artifacts:
        target = item["target"]
        archive, sbom = archive_name(version, target), sbom_name(version, target)
        if item.get("archive") != archive or item.get("sbom") != sbom:
            raise ValueError(f"the {target} artifact is misnamed")
        for name, key in [(archive, "sha256"), (sbom, "sbom_sha256")]:
            digest = file_sha256(dist / name)
            if item.get(key) != digest:
                raise ValueError(f"{name} differs from the release manifest")
            if checksums.get(name) != digest:
                raise ValueError(f"{name} has no matching SHA256SUMS entry")
        sbom_describes(read_json(dist / sbom, MAX_SBOM), archive, item["sha256"])
        attestations = item.get("attestations", [])
        required += [(archive, PROVENANCE, attestations), (archive, SPDX, attestations),
                     (sbom, PROVENANCE, attestations)]
        expected |= {archive, sbom}
    if set(checksums) != expected - {CHECKSUMS, manifest_name(version)}:
        raise ValueError("SHA256SUMS must list exactly the archives and SBOMs")
    bundles = {provenance_bundle_name(version)} | {sbom_bundle_name(version, t) for t in TARGETS}
    for subject, predicate_type, attestations in required:
        entries = [entry for entry in attestations if isinstance(entry, dict)
                   and entry.get("subject") == subject and entry.get("predicate_type") == predicate_type]
        if len(entries) != 1 or entries[0].get("bundle") not in bundles:
            raise ValueError(f"{subject} has no {predicate_type} attestation entry")
        if dry_run:
            continue
        bundle = entries[0]["bundle"]
        if not (dist / bundle).is_file():
            raise ValueError(f"the release directory is missing the bundle {bundle}")
        found = covers(bundle_statements(dist / bundle), predicate_type, subject, file_sha256(dist / subject))
        if not found:
            raise ValueError(f"{bundle} does not attest {subject} with {predicate_type}")
        if predicate_type == SPDX:
            sbom = next(item["sbom"] for item in artifacts if item["archive"] == subject)
            if any(statement.get("predicate") != read_json(dist / sbom, MAX_SBOM) for statement in found):
                raise ValueError(f"{bundle} attests an SBOM other than {sbom}")
        expected.add(bundle)
    present = {path.name for path in dist.iterdir()}
    if present != expected:
        extra, missing = sorted(present - expected), sorted(expected - present)
        raise ValueError(f"the release directory differs from its manifest: extra {extra}, missing {missing}")
    for path in dist.iterdir():
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"{path.name} is not a regular file")
    print(("Dry run: " if dry_run else "") + f"{len(artifacts)} archives, each with a checksum, an SBOM "
          f"and {'planned' if dry_run else 'bundled'} provenance and SBOM attestations.")
    return manifest


def verify(dist, gh=None, root=ROOT):
    """Verifies every attestation entry the check accepted with the pinned
    GitHub CLI: signature and trust, GitHub's OIDC issuer, a hosted runner,
    this repository, the release workflow at the tagged commit as signer,
    the tag as source ref, and the subject's exact digest."""
    manifest = check(dist, dry_run=False, root=root)
    repository, sha, ref = manifest["repository"], manifest["source_sha"], manifest["source_ref"]
    entries = list(manifest["checksums"]["attestations"])
    for item in manifest["artifacts"]:
        entries += item["attestations"]
    with tempfile.TemporaryDirectory(prefix="ggctl-verify-") as temporary:
        executable = gh or install_gh(Path(temporary) / "gh")
        version = run_utf8([executable, "--version"], timeout=60).splitlines()[0]
        if not version.startswith("gh version " + versions()["github_cli"] + " "):
            raise ValueError("attestation verifier version drift")
        for entry in entries:
            subject, predicate_type = entry["subject"], entry["predicate_type"]
            command = [executable, "attestation", "verify", str((dist / subject).resolve()),
                       "--bundle", str((dist / entry["bundle"]).resolve()),
                       "--repo", repository, "--signer-workflow", f"{repository}/{WORKFLOW}",
                       "--signer-digest", sha, "--source-digest", sha, "--source-ref", ref,
                       "--cert-oidc-issuer", OIDC_ISSUER, "--deny-self-hosted-runners",
                       "--predicate-type", predicate_type, "--format", "json"]
            result = json.loads(run_utf8(command, timeout=300))
            statements = [item["verificationResult"]["statement"] for item in result] \
                if isinstance(result, list) else []
            if not statements or len(covers(statements, predicate_type, subject,
                                            file_sha256(dist / subject))) != len(statements):
                raise ValueError(f"the verifier did not confirm {subject} with {predicate_type}")
            print(f"verified {predicate_type} for {subject}")
    return len(entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    modes = parser.add_subparsers(dest="mode", required=True)
    version = modes.add_parser("version")
    version.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    packaging = modes.add_parser("package")
    packaging.add_argument("--release-dir", type=Path, required=True,
                           help="the Cargo output directory holding ggctl or ggctl.exe")
    packaging.add_argument("--target", choices=sorted(TARGETS), required=True)
    packaging.add_argument("--output", type=Path, required=True)
    comparison = modes.add_parser("compare")
    comparison.add_argument("first", type=Path)
    comparison.add_argument("second", type=Path)
    glibc = modes.add_parser("glibc")
    glibc.add_argument("--binary", type=Path, required=True)
    glibc.add_argument("--max", required=True)
    single = modes.add_parser("artifact")
    single.add_argument("dist", type=Path)
    single.add_argument("--target", choices=sorted(TARGETS), required=True)
    sums = modes.add_parser("checksums")
    sums.add_argument("dist", type=Path)
    listing = modes.add_parser("manifest")
    listing.add_argument("dist", type=Path)
    checking = modes.add_parser("check")
    checking.add_argument("dist", type=Path)
    checking.add_argument("--dry-run", action="store_true")
    verifying = modes.add_parser("verify")
    verifying.add_argument("dist", type=Path)
    verifying.add_argument("--gh")
    for mode in (packaging, listing):
        mode.add_argument("--repository")
        mode.add_argument("--sha")
        mode.add_argument("--ref")
    args = parser.parse_args()
    try:
        if args.mode == "version":
            print(release_version(args.ref))
        elif args.mode == "package":
            repository, sha, _ = source_identity(args)
            binary = (args.release_dir / executable_name(args.target)).resolve(strict=True)
            print(package(binary, args.target, args.output, repository, sha).name)
        elif args.mode == "compare":
            compare(args.first, args.second)
        elif args.mode == "glibc":
            check_glibc(args.binary, args.max)
        elif args.mode == "artifact":
            outputs = artifact(args.dist, args.target, release_version(os.environ.get("GITHUB_REF", "")))
            print("".join(f"{key}={value}\n" for key, value in outputs.items()), end="")
        elif args.mode == "checksums":
            write_checksums(args.dist, cargo_version())
        elif args.mode == "manifest":
            repository, sha, ref = source_identity(args)
            version = release_version(ref)
            write_bytes(args.dist / manifest_name(version),
                        json_bytes(release_manifest(args.dist, version, repository, sha, ref)))
        elif args.mode == "check":
            check(args.dist, args.dry_run)
        else:
            verify(args.dist, args.gh)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"ggctl release {args.mode} failed ({type(error).__name__}): {error}"[:2000], file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
