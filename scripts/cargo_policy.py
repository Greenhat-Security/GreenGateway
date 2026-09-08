"""Locked full-graph Cargo policy, verified executable, and review enforcement."""
import argparse
from collections import defaultdict
from datetime import date, datetime, timezone
import io
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tomllib
import urllib.request

from build_tools import versions, verify_download

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
LICENSES = ["Apache-2.0", "MIT", "MIT-0", "ISC", "BSD-3-Clause", "Unicode-3.0", "Zlib"]
BANNED = ["openssl", "openssl-sys", "native-tls", "tokio-native-tls", "hyper-tls"]
BAN_REASON = "Gateway transport and credential TLS must use the reviewed rustls stack."
VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def review_metadata(entry, today):
    for field in ["owner", "reason", "remediation"]:
        if not isinstance(entry.get(field), str) or len(entry[field].strip()) < 8:
            raise ValueError(f"{entry.get('crate', entry.get('name'))}: exception needs substantive {field}")
    expiry = date.fromisoformat(entry["expires"])
    if not 0 < (expiry - today).days <= 90:
        raise ValueError(f"{entry.get('crate', entry.get('name'))}: exception expired or exceeds 90-day review horizon")


def expected_config(exceptions):
    return {
        "graph": {"all-features": True, "no-default-features": False,
                  "exclude-dev": False, "exclude-unpublished": False, "targets": [], "exclude": []},
        "licenses": {"confidence-threshold": 0.95, "unused-allowed-license": "deny", "allow": LICENSES,
                     "exceptions": [{"crate": e["crate"], "allow": e["allow"]} for e in exceptions["licenses"]],
                     "private": {"ignore": False}},
        "sources": {"unknown-registry": "deny", "unknown-git": "deny",
                    "allow-registry": [REGISTRY.removeprefix("registry+")], "allow-git": []},
        "bans": {"multiple-versions": "deny", "wildcards": "deny",
                 "deny": [{"crate": name, "reason": BAN_REASON} for name in BANNED],
                 "skip": [{"crate": e["name"] + "@" + version, "reason": e["reason"]}
                          for e in exceptions["duplicates"] for version in e["versions"][:-1]],
                 "skip-tree": []},
    }


def validate_config(root=ROOT, today=None):
    today = today or datetime.now(timezone.utc).date()
    exceptions = read_json(root / "cargo-policy-exceptions.json")
    if set(exceptions) != {"schema_version", "duplicates", "licenses"} or exceptions["schema_version"] != 1:
        raise ValueError("invalid Cargo exception schema")
    seen = set()
    for entry in exceptions["duplicates"]:
        if set(entry) != {"name", "versions", "owner", "expires", "reason", "remediation", "parents"}:
            raise ValueError("invalid duplicate exception fields")
        review_metadata(entry, today)
        name = entry["name"]
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name) or name in seen:
            raise ValueError("duplicate exception must identify one unique crate name")
        seen.add(name)
        values = entry["versions"]
        if len(values) < 2 or len(values) != len(set(values)) or not all(VERSION.fullmatch(v) for v in values):
            raise ValueError("duplicate exception requires exact distinct versions")
        if set(entry["parents"]) != set(values) or not all(entry["parents"].values()):
            raise ValueError("duplicate exception requires parent evidence for every version")
    seen = set()
    for entry in exceptions["licenses"]:
        if set(entry) != {"crate", "allow", "owner", "expires", "reason", "remediation"}:
            raise ValueError("invalid license exception fields")
        review_metadata(entry, today)
        parts = entry["crate"].split("@")
        if len(parts) != 2 or not re.fullmatch(r"[A-Za-z0-9_-]+", parts[0]) or not VERSION.fullmatch(parts[1]) or entry["crate"] in seen:
            raise ValueError("license exception requires one unique exact crate version")
        seen.add(entry["crate"])
        if not entry["allow"] or not all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9. -]+", x) for x in entry["allow"]):
            raise ValueError("license exception requires explicit license identifiers")
    config = tomllib.loads((root / "deny.toml").read_text(encoding="utf-8"))
    if config != expected_config(exceptions):
        raise ValueError("deny.toml differs from the reviewed full-graph policy and exact exceptions")
    for hidden in ["deny.exceptions.toml", ".deny.exceptions.toml", ".cargo/deny.exceptions.toml", ".deny.toml", ".cargo/deny.toml"]:
        if (root / hidden).exists():
            raise ValueError("undeclared Cargo policy override: " + hidden)
    return exceptions


def lock_inventory(root=ROOT):
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    packages = lock["package"]
    if not packages:
        raise ValueError("empty Cargo lockfile")
    result = set()
    for package in packages:
        source = package.get("source")
        if source is not None and source != REGISTRY:
            raise ValueError(f"unapproved source for {package['name']}; refusing metadata fetch")
        if source and not re.fullmatch(r"[a-f0-9]{64}", package.get("checksum", "")):
            raise ValueError("registry package missing exact checksum")
        identity = (package["name"], package["version"], source)
        if identity in result:
            raise ValueError("duplicate lock identity")
        result.add(identity)
    return result


def validate_graph(metadata, locked, exceptions):
    packages = metadata["packages"]
    if len(packages) != len(locked) or {(p["name"], p["version"], p.get("source")) for p in packages} != locked:
        raise ValueError("metadata does not cover the entire locked package graph")
    members = set(metadata["workspace_members"])
    byid = {p["id"]: p for p in packages}
    for p in packages:
        if p.get("source") != REGISTRY and p["id"] not in members:
            raise ValueError("unreviewed source or external path dependency")
        if p["name"] in BANNED:
            raise ValueError("banned dependency: " + p["name"])
    parents = defaultdict(list)
    for node in metadata["resolve"]["nodes"]:
        for dep in node["dependencies"]:
            parent = byid[node["id"]]
            parents[dep].append(parent["name"] + "@" + parent["version"])
    groups = defaultdict(list)
    for package in packages:
        groups[package["name"]].append(package)
    duplicates = {name: ps for name, ps in groups.items() if len(ps) > 1}
    if set(duplicates) != {e["name"] for e in exceptions["duplicates"]}:
        raise ValueError("duplicate crate inventory changed; review exceptions")
    for entry in exceptions["duplicates"]:
        actual = {p["version"]: sorted(parents[p["id"]]) for p in duplicates[entry["name"]]}
        if set(actual) != set(entry["versions"]) or actual != entry["parents"]:
            raise ValueError("duplicate versions or parent chains changed: " + entry["name"])
    identities = {p["name"] + "@" + p["version"] for p in packages}
    for entry in exceptions["licenses"]:
        if entry["crate"] not in identities:
            raise ValueError("stale license exception: " + entry["crate"])


def executable(root=ROOT):
    return root / "target/build-tools" / ("cargo-deny.exe" if os.name == "nt" else "cargo-deny")


def install(root=ROOT):
    pins = versions(root)
    machine = platform.machine().lower()
    if machine not in {"amd64", "x86_64"} or platform.system() not in {"Windows", "Linux"}:
        raise ValueError("verified Cargo policy installer supports Linux/Windows x86_64 only")
    system = "windows" if platform.system() == "Windows" else "linux"
    triple = "x86_64-pc-windows-msvc" if system == "windows" else "x86_64-unknown-linux-musl"
    name = f"cargo-deny-{pins['cargo_deny']}-{triple}"
    url = f"https://github.com/EmbarkStudios/cargo-deny/releases/download/{pins['cargo_deny']}/{name}.tar.gz"
    with urllib.request.urlopen(url, timeout=90) as response:
        data = response.read(50 * 1024 * 1024 + 1)
    if len(data) > 50 * 1024 * 1024:
        raise ValueError("Cargo policy tool download too large")
    verify_download(data, pins[f"cargo_deny_{system}_amd64_sha256"])
    target = executable(root)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember(name + "/" + target.name)
        if not member.isfile() or member.size > 100 * 1024 * 1024:
            raise ValueError("invalid Cargo policy executable archive member")
        binary = archive.extractfile(member).read()
    target.parent.mkdir(parents=True, exist_ok=True)
    pending = target.with_suffix(".pending")
    pending.write_bytes(binary)
    pending.chmod(0o755)
    pending.replace(target)
    verify_tool(root)


def verify_tool(root=ROOT):
    actual = subprocess.check_output([str(executable(root)), "--version"], text=True).strip()
    if actual != "cargo-deny " + versions(root)["cargo_deny"]:
        raise ValueError("Cargo policy executable version mismatch")


def check(root=ROOT):
    output = root / "target/cargo-policy"
    output.mkdir(parents=True, exist_ok=True)
    report = {"status": "failed", "stage": "configuration"}
    try:
        exceptions = validate_config(root)
        locked = lock_inventory(root)
        report["stage"] = "tool"
        verify_tool(root)
        report["stage"] = "metadata"
        raw = subprocess.check_output(["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"], cwd=root)
        metadata = json.loads(raw)
        validate_graph(metadata, locked, exceptions)
        report.update(stage="native-policy", packages=len(metadata["packages"]), exceptions=exceptions,
                      input_sha256={file: hashlib.sha256((root / file).read_bytes()).hexdigest()
                                    for file in ["Cargo.lock", "deny.toml", "cargo-policy-exceptions.json", "build-tools.json"]})
        # Deliberately no metadata-path, target, feature pruning or lint override:
        # the real tool independently resolves the locked all-feature workspace.
        result = subprocess.run([str(executable(root)), "--locked", "--all-features", "--workspace",
                                 "--config", str(root / "deny.toml"), "--format", "json", "check",
                                 "licenses", "bans", "sources"], cwd=root, capture_output=True)
        (output / "diagnostics.jsonl").write_bytes(result.stdout + result.stderr)
        if result.returncode != 0:
            raise ValueError("cargo-deny rejected the graph; see target/cargo-policy/diagnostics.jsonl")
        report.update(status="passed", stage="complete", tool_version=versions(root)["cargo_deny"])
        print(f"Cargo policy passed: {len(locked)} packages; exact exceptions retained in report.")
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        (output / "decision.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["install", "check", "config"])
    args = parser.parse_args()
    try:
        if args.command == "install":
            install()
        elif args.command == "config":
            validate_config()
        else:
            check()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(f"Cargo policy failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
