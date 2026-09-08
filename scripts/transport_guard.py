#!/usr/bin/env python3
"""Fail-closed syntax/dependency review for production transport authority."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "transport-ownership.json"
OUTPUT = ROOT / "target/transport-guard"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"

def run(*args: str) -> str:
    return subprocess.run(args, cwd=ROOT, check=True, capture_output=True, encoding="utf-8").stdout

def read(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))

def write(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")

def relative(path: str) -> str:
    return Path(path).resolve().relative_to(ROOT).as_posix()

def graph(metadata, locked):
    packages = metadata["packages"]
    identities = {p["id"]: f'{p["name"]}@{p["version"]}|{p["source"] or "workspace"}' for p in packages}
    locks = {(p["name"], p["version"], p.get("source")): p for p in locked["package"]}
    if len(locks) != len(packages):
        raise ValueError("resolved metadata does not cover the complete lockfile")
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    result = []
    for package in packages:
        key = (package["name"], package["version"], package["source"])
        lock = locks[key]
        if package["source"] is None and package["id"] not in metadata["workspace_members"]:
            raise ValueError("external path dependency requires explicit guard support")
        node = nodes[package["id"]]
        result.append({"package": identities[package["id"]], "checksum": lock.get("checksum"),
                       "features": sorted(node["features"]),
                       "dependencies": sorted(identities[d] for d in node["dependencies"])})
    workspace = []
    for package in packages:
        if package["id"] in metadata["workspace_members"]:
            dependencies = []
            for dependency in package["dependencies"]:
                d = {k: dependency[k] for k in ("name", "rename", "kind", "target", "req", "optional", "uses_default_features", "features", "source")}
                dependencies.append(d)
            workspace.append({"package": package["name"], "dependencies": sorted(dependencies, key=lambda d: json.dumps(d, sort_keys=True)),
                              "features": package["features"],
                              "targets": sorted(({"name":t["name"], "kind":t["kind"], "file":relative(t["src_path"])} for t in package["targets"]),key=lambda t:t["file"])})
    return {"packages": sorted(result, key=lambda p:p["package"]), "workspace":sorted(workspace,key=lambda p:p["package"])}

def enumeration(metadata):
    files = sorted(set(f for f in run("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z").split("\0") if f.endswith(".rs")))
    if not files:
        raise ValueError("no Rust source files enumerated")
    roots = []
    build_inputs = []
    for package in metadata["packages"]:
        if package["id"] not in metadata["workspace_members"]:
            continue
        for target in package["targets"]:
            file = relative(target["src_path"])
            kind = set(target["kind"])
            if not kind <= {"bin", "lib", "rlib", "test", "bench", "example", "custom-build"}:
                raise ValueError(f"unexamined Cargo target kind: {kind}")
            nonproduction = bool(kind & {"test", "bench", "example", "custom-build"})
            roots.append({"file":file,"name":target["name"],"test":nonproduction,"kind":sorted(kind)})
            if kind & {"custom-build"}:
                build_inputs.append({"file":file,"sha256":hashlib.sha256((ROOT/file).read_bytes().replace(b"\r\n",b"\n")).hexdigest()})
    if not any(not r["test"] for r in roots):
        raise ValueError("no production Cargo target")
    return {"files": files, "roots":roots}, build_inputs

def validate_policy(policy):
    if set(policy) != {"schema", "owner", "purpose", "graph", "build_inputs", "scopes"} or policy["schema"] != 1:
        raise ValueError("invalid transport policy schema")
    for field in ("owner", "purpose"):
        if not isinstance(policy[field],str) or len(policy[field].strip()) < 12:
            raise ValueError(f"substantive {field} required")
    seen = set()
    for s in policy["scopes"]:
        if set(s) != {"file","scope","sha256","reasons","owner","purpose"}:
            raise ValueError("scope review requires exact fields")
        if not isinstance(s["file"],str) or not isinstance(s["scope"],str):
            raise ValueError("file/scope must be exact strings")
        if not s["file"].endswith(".rs") or not s["scope"] or any(c in s["file"] for c in "*?[]\\") or s["file"].startswith("/") or ".." in Path(s["file"]).parts:
            raise ValueError("broad or escaping file exception")
        # Rust type names can include * and []; exact equality below is mandatory.
        if s["scope"] in {"*", "**"} or not re.search(r"#[1-9][0-9]*$",s["scope"]):
            raise ValueError("broad scope exception")
        if not re.fullmatch(r"[a-f0-9]{64}",s["sha256"]):
            raise ValueError("exact syntax SHA256 required")
        if not s["reasons"] or not all(isinstance(r,str) for r in s["reasons"]):
            raise ValueError("review reasons required")
        if any(not isinstance(s[f],str) or len(s[f].strip())<12 for f in ("owner","purpose")):
            raise ValueError("scope owner and purpose required")
        key=(s["file"],s["scope"])
        if key in seen:
            raise ValueError("duplicate review scope")
        seen.add(key)

def compare_scopes(actual, reviewed):
    expected = {(s["file"],s["scope"]):{k:v for k,v in s.items() if k not in {"owner","purpose"}} for s in reviewed}
    found = {(s["file"],s["scope"]):s for s in actual}
    changed = [":".join(k) for k in sorted(set(expected)|set(found)) if expected.get(k)!=found.get(k)]
    if changed:
        raise ValueError("transport syntax review required:\n" + "\n".join(changed))

def check(inventory=False):
    decision = {"status":"failed","stage":"enumeration"}
    try:
        locked = tomllib.loads((ROOT/"Cargo.lock").read_text(encoding="utf-8"))
        for p in locked["package"]:
            if p.get("source") not in (None,REGISTRY):
                raise ValueError("unreviewed registry/Git source; refused before metadata resolution")
        metadata = json.loads(run("cargo","metadata","--locked","--all-features","--format-version","1"))
        current_graph = graph(metadata,locked)
        manifest, build_inputs = enumeration(metadata)
        policy = None if inventory else read(POLICY)
        if policy is not None:
            validate_policy(policy)
            decision["stage"]="dependency-review"
            if policy["graph"] != current_graph:
                raise ValueError("dependency/feature/target exposure changed; review before compiling the syntax tool")
            if policy["build_inputs"] != build_inputs:
                raise ValueError("build-script inputs changed; generated code review required")
        write(OUTPUT/"enumeration.json",manifest)
        decision["stage"]="syntax"
        facts=json.loads(run("cargo","run","--locked","--example","transport_guard","--",str(ROOT),str(OUTPUT/"enumeration.json")))
        write(OUTPUT/"syntax.json",facts)
        if facts.get("schema") != 1:
            raise ValueError("invalid syntax facts")
        missing=sorted(set(manifest["files"])-set(facts["files"]))
        if missing:
            raise ValueError("Rust files not owned by a Cargo target/module graph: " + ", ".join(missing))
        candidate={"schema":1,"owner":"GreenGateway maintainers", "purpose":"Review production transport authority and unexpanded syntax inputs.","graph":current_graph,"build_inputs":build_inputs,"scopes":facts["scopes"]}
        write(OUTPUT/"candidate.json",candidate)
        if policy is not None:
            decision["stage"]="scope-review"
            compare_scopes(facts["scopes"],policy["scopes"])
        decision.update(status="inventory" if inventory else "passed",stage="complete",files=len(facts["files"]),scopes=len(facts["scopes"]),packages=len(current_graph["packages"]))
        print(json.dumps(decision))
    except Exception as error:
        decision["error"]=str(error)
        raise
    finally:
        write(OUTPUT/"decision.json",decision)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=["check","inventory"])
    args=parser.parse_args()
    try:
        check(args.command=="inventory")
    except (ValueError,KeyError,OSError,subprocess.CalledProcessError) as error:
        print(f"transport guard: {error}",file=sys.stderr)
        if isinstance(error,subprocess.CalledProcessError):
            print(error.stderr,file=sys.stderr)
        return 1
    return 0

if __name__=="__main__":
    sys.exit(main())
