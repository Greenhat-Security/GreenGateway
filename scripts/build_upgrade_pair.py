#!/usr/bin/env python3
"""Build issue #426's pinned upgrade pair: one gateway binary per pinned commit.

`gateway/tests/ha/rolling-upgrade-pair.json` names a prepared release and its
successor by full commit SHA. Each commit is checked out into its own detached
worktree under `--out` and built there with that commit's own sources,
`Cargo.lock` and default features. The binary is copied out beside a manifest
that records its commit and SHA-256. `ha_rolling_upgrade` reads the manifest
through `GATEWAY_TEST_UPGRADE_PAIR_DIR`, hashes both binaries again, and
refuses a pair that is not two distinct builds of the two pinned commits.

One substitution, stated here and in the manifest. Before building, each
worktree's `gateway/build.rs` is replaced by an empty build script and the
embedded admin UI by a one-file stub. The pinned build script checks that the
Node.js and npm on PATH are exactly its own commit's versions, then builds the
admin UI. It emits no Rust configuration, and this script refuses to replace
one that does, so the compiled Rust is the pinned commit's. The pair rows
exercise no admin UI. Without the substitution the pair would stop building
the first time the repository's Node pin moved past a pinned commit's.

Both builds share one target directory under the repository's `target/`,
separate from the one `cargo test` uses, so neither pinned build can replace
the binary the rest of the suite runs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PIN = ROOT / "gateway" / "tests" / "ha" / "rolling-upgrade-pair.json"
TARGET_DIR = ROOT / "target" / "upgrade-pair"
ROLES = ("prepared", "successor")
COMMIT = re.compile(r"[0-9a-f]{40}")
# `cargo:rustc-cfg=`, `cargo::rustc-env=` and the rest change what rustc
# compiles. A build script that prints any of them cannot be replaced.
RUSTC_DIRECTIVE = re.compile(r"cargo::?rustc-")
EMPTY_BUILD_SCRIPT = "fn main() {}\n"
STUB_ADMIN_UI = (
    "<!doctype html><title>Admin UI not built: issue #426 upgrade-pair binary</title>\n"
)
SUBSTITUTION = (
    "gateway/build.rs replaced by an empty build script and admin-ui/dist by a one-file stub; "
    "the pinned build script emits no Rust configuration, so the compiled Rust is the pinned commit's"
)


class PairError(Exception):
    pass


def run(*args: str, cwd: Path = ROOT) -> str:
    return subprocess.run(args, cwd=cwd, check=True, capture_output=True, encoding="utf-8").stdout


def load_pin(path: Path) -> dict:
    try:
        pin = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise PairError(f"cannot read the pair pin {path}: {error}") from error
    if not isinstance(pin, dict) or pin.get("schema") != 1:
        raise PairError("the pair pin must be a schema 1 object")
    commits = []
    for role in ROLES:
        entry = pin.get(role)
        commit = entry.get("commit") if isinstance(entry, dict) else None
        if not isinstance(commit, str) or not COMMIT.fullmatch(commit):
            raise PairError(f"{role} must name exactly one full lowercase commit SHA")
        commits.append(commit)
    if commits[0] == commits[1]:
        raise PairError(
            "the prepared and successor commits must differ: two builds of one commit are not an "
            "adjacent-version pair"
        )
    return pin


def check_build_script(source: str) -> None:
    if RUSTC_DIRECTIVE.search(source):
        raise PairError(
            "the pinned gateway/build.rs emits Rust configuration, so replacing it would change "
            "what is compiled; build this pair under the pinned commit's own toolchain instead"
        )


def check_manifest(source: str) -> None:
    if re.search(r"^\s*build\s*=", source, re.MULTILINE):
        raise PairError("the pinned gateway/Cargo.toml names its own build script")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def remove_worktree(path: Path) -> None:
    if path.exists():
        subprocess.run(["git", "worktree", "remove", "--force", str(path)], cwd=ROOT,
                       capture_output=True, encoding="utf-8")
    if path.exists():
        shutil.rmtree(path)
    run("git", "worktree", "prune")


def build_one(role: str, commit: str, out: Path, cargo: str) -> dict:
    try:
        run("git", "cat-file", "-e", f"{commit}^{{commit}}")
        run("git", "merge-base", "--is-ancestor", commit, "HEAD")
    except subprocess.CalledProcessError as error:
        raise PairError(
            f"the {role} commit {commit} is not in this checkout's history; the pair is built only "
            "from commits HEAD descends from (fetch the full history)"
        ) from error
    source = out / "src" / role
    remove_worktree(source)
    source.parent.mkdir(parents=True, exist_ok=True)
    run("git", "worktree", "add", "--detach", str(source), commit)
    build_script = source / "gateway" / "build.rs"
    check_build_script(build_script.read_text(encoding="utf-8"))
    check_manifest((source / "gateway" / "Cargo.toml").read_text(encoding="utf-8"))
    build_script.write_text(EMPTY_BUILD_SCRIPT, encoding="utf-8", newline="\n")
    admin_ui = source / "admin-ui" / "dist"
    admin_ui.mkdir(parents=True, exist_ok=True)
    (admin_ui / "index.html").write_text(STUB_ADMIN_UI, encoding="utf-8", newline="\n")
    print(f"building the {role} binary from {commit}", file=sys.stderr, flush=True)
    subprocess.run([cargo, "build", "--locked", "-p", "gateway", "--bin", "gateway",
                    "--target-dir", str(TARGET_DIR)], cwd=source, check=True)
    executable = "gateway.exe" if os.name == "nt" else "gateway"
    destination = out / role / executable
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(TARGET_DIR / "debug" / executable, destination)
    return {"commit": commit, "binary": f"{role}/{executable}", "sha256": sha256(destination)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, type=Path, help="directory for the binaries and manifest")
    parser.add_argument("--pin", default=PIN, type=Path, help="the pair pin (default: %(default)s)")
    args = parser.parse_args()
    out = args.out.resolve()
    cargo = os.environ.get("CARGO", "cargo")
    try:
        pin = load_pin(args.pin)
        out.mkdir(parents=True, exist_ok=True)
        built = {role: build_one(role, pin[role]["commit"], out, cargo) for role in ROLES}
        if built["prepared"]["sha256"] == built["successor"]["sha256"]:
            raise PairError("the two pinned builds produced identical binaries")
        (out / "evidence").mkdir(exist_ok=True)
        manifest = {"schema": 1, "issue": 426, "substitution": SUBSTITUTION, **built}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8",
                                           newline="\n")
        print(json.dumps(manifest))
    except (PairError, OSError, subprocess.CalledProcessError) as error:
        print(f"upgrade pair: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
