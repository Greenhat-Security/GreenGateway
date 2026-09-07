"""Declared build-tool versions, CI setup outputs and fail-closed drift checks."""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
EXACT = re.compile(r"\d+\.\d+\.\d+")


def versions(root=ROOT):
    data = json.loads((root / "build-tools.json").read_text(encoding="utf-8"))
    required = {"schema_version", "rust_ci", "rust_production", "rust_coverage",
                "node", "npm", "python", "cargo_audit", "cargo_llvm_cov", "pyyaml",
                "buildx", "buildkit_image", "gitleaks", "buildx_linux_amd64_sha256", "trivy", "trivy_linux_amd64_sha256", "github_cli", "github_cli_linux_amd64_sha256"}
    if set(data) != required or data["schema_version"] != 1:
        raise ValueError("unknown or incomplete build-tool contract")
    for key in required - {"schema_version", "rust_coverage", "buildkit_image", "buildx_linux_amd64_sha256", "trivy_linux_amd64_sha256", "github_cli_linux_amd64_sha256"}:
        if not isinstance(data[key], str) or not EXACT.fullmatch(data[key]):
            raise ValueError(f"{key} must be an exact version")
    if not re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", data["rust_coverage"]):
        raise ValueError("coverage compiler must select a dated nightly")
    if not re.fullmatch(r"moby/buildkit:[^@]+@sha256:[0-9a-f]{64}", data["buildkit_image"]):
        raise ValueError("BuildKit must select an immutable image")
    if not re.fullmatch(r"[0-9a-f]{64}", data["buildx_linux_amd64_sha256"]):
        raise ValueError("Buildx archive must have a reviewed checksum")
    if not re.fullmatch(r"[0-9a-f]{64}", data["trivy_linux_amd64_sha256"]):
        raise ValueError("Trivy archive must have a reviewed checksum")
    if not re.fullmatch(r"[0-9a-f]{64}", data["github_cli_linux_amd64_sha256"]):
        raise ValueError("GitHub CLI archive must have a reviewed checksum")
    return data


def verify_download(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("download checksum mismatch; refusing installation")


def install_buildx():
    # This installer is deliberately restricted to disposable Linux CI runners.
    if os.environ.get("GITHUB_ACTIONS") != "true" or platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("Buildx installer requires a Linux amd64 GitHub runner")
    pins = versions()
    url = f"https://github.com/docker/buildx/releases/download/v{pins['buildx']}/buildx-v{pins['buildx']}.linux-amd64"
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(100 * 1024 * 1024 + 1)
    if len(data) > 100 * 1024 * 1024:
        raise ValueError("Buildx download exceeds the size limit")
    verify_download(data, pins["buildx_linux_amd64_sha256"])
    target = Path.home() / ".docker/cli-plugins/docker-buildx"
    target.parent.mkdir(parents=True, exist_ok=True)
    pending = target.with_suffix(".pending")
    pending.write_bytes(data)
    pending.chmod(0o755)
    pending.replace(target)
    print(output(["docker", "buildx", "version"]))
    subprocess.run(["docker", "buildx", "create", "--use", "--name", "greengateway-ci",
                    "--driver", "docker-container", "--driver-opt", "image=" + pins["buildkit_image"],
                    "--driver-opt", "default-load=true"], check=True)
    subprocess.run(["docker", "buildx", "inspect", "--bootstrap"], check=True)
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
        stream.write("BUILDX_BUILDER=greengateway-ci\n")


def profile():
    value = os.environ.get("RUST_PROFILE", "none")
    if value not in {"none", "ci", "production", "coverage"}:
        raise ValueError("unknown Rust profile")
    return value


def output(cmd):
    return subprocess.run(cmd, check=True, text=True, capture_output=True).stdout.strip()


def verify():
    pins = versions()
    selected = profile()
    if selected != "none":
        active = output(["rustup", "show", "active-toolchain"]).split()[0]
        if not active.startswith(pins["rust_" + selected] + "-"):
            raise ValueError(f"unexpected active Rust toolchain: {active}")
        print(output(["rustc", "--version"]))
        print(output(["cargo", "--version"]))
    if os.environ.get("CHECK_NODE") == "true":
        for name, command in [("node", ["node", "--version"]),
                              ("npm", ["npm.cmd" if os.name == "nt" else "npm", "--version"])]:
            actual = output(command).removeprefix("v")
            if actual != pins[name]:
                raise ValueError(f"{name}: expected {pins[name]}, found {actual}")
            print(f"{name} {actual}")
    if ".".join(map(str, sys.version_info[:3])) != pins["python"]:
        raise ValueError("Python does not match build-tools.json")
    print("python " + pins["python"])


def check(root=ROOT):
    import yaml
    errors = []
    try:
        pins = versions(root)
        for path, key in [(".node-version", "node"), (".npm-version", "npm")]:
            if (root / path).read_text().strip() != pins[key]:
                errors.append(f"{path} disagrees with build-tools.json")
        channel = tomllib.loads((root / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        if channel != pins["rust_production"]:
            errors.append("default compiler differs from production compiler")
        for package in ["package.json", "admin-ui/package.json"]:
            data = json.loads((root / package).read_text())
            if data.get("engines") != {"node": pins["node"], "npm": pins["npm"]}:
                errors.append(f"{package}: exact Node/npm engines are required")
            npmrc = (root / Path(package).parent / ".npmrc").read_text().splitlines()
            if [line for line in npmrc if line.startswith("engine-strict=")] != ["engine-strict=true"]:
                errors.append(f"{package}: engine-strict must be enabled")
        dockerfile = (root / "Dockerfile").read_text()
        if f"FROM node:{pins['node']}-bookworm-slim@" not in dockerfile:
            errors.append("Docker Node tag differs from declared version")
        if f"FROM rust:{pins['rust_production']}-slim-bookworm@" not in dockerfile:
            errors.append("Docker production compiler differs from declared version")
        for line in dockerfile.splitlines():
            if "cargo build" in line and "--locked" not in line:
                errors.append("Docker Cargo builds must be locked")
        if not all(x + " --version" in dockerfile for x in ["node", "npm", "rustc"]):
            errors.append("Docker must verify actual compiler/runtime versions")
        for required in ["build-tools.json", "npm-script-policy.json", "scripts/npm-script-policy.mjs"]:
            if required not in dockerfile:
                errors.append(f"Docker must copy npm policy input {required}")
        cargo_build = (root / "gateway/build.rs").read_text()
        if 'repo_root.join("scripts/npm-script-policy.mjs")' not in cargo_build or '.args(["install", "admin-ui"])' not in cargo_build:
            errors.append("Cargo must use the reviewed npm installer")
        if 'run_npm(&admin_ui, &["ci"])' in cargo_build:
            errors.append("Cargo must not bypass npm identity review")
        tracked_inputs = re.search(r'for file in \[(.*?)\]\s*\{\s*println!\("cargo:rerun-if-changed=\{\}", repo_root\.join\(file\)\.display\(\)\);', cargo_build, re.DOTALL)
        for required in ["build-tools.json", "npm-script-policy.json", "scripts/npm-script-policy.mjs"]:
            if not tracked_inputs or f'"{required}"' not in tracked_inputs.group(1):
                errors.append(f"Cargo must track npm policy input {required}")
        action = yaml.load((root / ".github/actions/build-tools/action.yml").read_text(), Loader=yaml.BaseLoader)
        steps = action["runs"]["steps"]
        python = next(s for s in steps if s.get("uses", "").startswith("actions/setup-python@"))
        if python.get("with", {}).get("python-version") != pins["python"]:
            errors.append("composite Python version drift")
        node = next(s for s in steps if s.get("uses", "").startswith("actions/setup-node@"))
        if node.get("with", {}).get("node-version-file") != ".node-version":
            errors.append("composite must consume .node-version")
        rust = next(s for s in steps if s.get("uses", "").startswith("dtolnay/rust-toolchain@"))
        if rust.get("with", {}).get("toolchain") != "$" + "{{ steps.pins.outputs.rust }}":
            errors.append("composite must consume the explicit Rust profile")
        builder = yaml.load((root / ".github/actions/buildx/action.yml").read_text(), Loader=yaml.BaseLoader)
        if builder.get("runs", {}).get("steps") != [{"shell": "bash", "run": "python scripts/build_tools.py install-buildx"}]:
            errors.append("Buildx setup must use the verified installer")
        for path in (root / ".github/workflows").glob("*.y*ml"):
            doc = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            for job_name, job in doc.get("jobs", {}).items():
                if "uses" in job:
                    continue
                steps = job.get("steps", [])
                setups = [s for s in steps if s.get("uses") == "./.github/actions/build-tools"]
                if len(setups) != 1:
                    errors.append(f"{path.name}/{job_name}: exactly one pinned tool setup required")
                    continue
                config = setups[0].get("with", {})
                rust_profile = config.get("rust", "none")
                if rust_profile not in {"none", "ci", "production", "coverage"}:
                    errors.append(f"{job_name}: invalid Rust profile")
                if job_name == "security-coverage" and rust_profile != "coverage":
                    errors.append("coverage compiler profile must not change implicitly")
                commands = "\n".join(s.get("run", "") for s in steps)
                builds_image = any(s.get("uses", "").startswith("docker/build-push-action@") for s in steps)
                builds_image |= job_name in {"ha-compose-example", "dev-traffic-smoke", "promote-image"}
                if builds_image and not any(s.get("uses") == "./.github/actions/buildx" for s in steps):
                    errors.append(f"{job_name}: verified Buildx setup is required")
                if re.search(r"\bcargo\b", commands) and rust_profile == "none":
                    errors.append(f"{job_name}: Cargo uses an undeclared compiler")
                if re.search(r"\b(node|npm|npx)\b|\bcargo (build|test|clippy|llvm-cov)\b", commands) and config.get("node") != "true":
                    errors.append(f"{job_name}: Node/npm setup required before building")
                for s in steps:
                    use, opts, run = s.get("uses", ""), s.get("with", {}), s.get("run", "")
                    if any(use.startswith(x) for x in ["actions/setup-node@", "actions/setup-python@", "dtolnay/rust-toolchain@"]):
                        errors.append(f"{job_name}: use the shared tool contract")
                    if use.startswith("docker/setup-buildx-action@"):
                        errors.append(f"{job_name}: use the checksum-verified Buildx installer")
                    if use.startswith("taiki-e/install-action@"):
                        if opts.get("tool") != "cargo-audit@" + pins["cargo_audit"] or opts.get("checksum") != "true":
                            errors.append(f"{job_name}: tool install must pin version and verify checksums")
                    if "cargo install" in run and f"cargo-llvm-cov --version {pins['cargo_llvm_cov']} --locked" not in run:
                        errors.append(f"{job_name}: unreviewed Cargo tool installation")
                    if "pip install" in run and f"PyYAML=={pins['pyyaml']}" not in run:
                        errors.append(f"{job_name}: unreviewed Python dependency installation")
                    if re.search(r"\bnpx\s+(?!.*--no-install)", run):
                        errors.append(f"{job_name}: npx must not download missing tools")
                    if re.search(r"\bnpm\s+(ci|install|i|exec|x|rebuild)\b", run):
                        errors.append(f"{job_name}: use the reviewed npm installer or a locked no-download executable")
                    env = s.get("env", {})
                    if "GITLEAKS_VERSION" in env and env["GITLEAKS_VERSION"] != pins["gitleaks"]:
                        errors.append("gitleaks version drift")
        return errors
    except (OSError, KeyError, ValueError, StopIteration, TypeError) as error:
        return [f"invalid build-tool configuration: {error}"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["outputs", "verify", "check", "install-buildx"])
    args = parser.parse_args()
    try:
        pins = versions()
        if args.mode == "outputs":
            selected = profile()
            # A rust-toolchain.toml overrides rustup's user default. Select the
            # CI profile explicitly, including for later Cargo/build-script runs.
            if selected != "none":
                with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as stream:
                    stream.write("RUSTUP_TOOLCHAIN=" + pins["rust_" + selected] + "\n")
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
                stream.write("rust=" + pins.get("rust_" + selected, "") + "\n")
                components = "rustfmt,clippy" + (",llvm-tools-preview" if selected == "coverage" else "")
                stream.write("components=" + components + "\n")
        elif args.mode == "install-buildx":
            install_buildx()
        elif args.mode == "verify":
            verify()
        else:
            errors = check()
            print("\n".join(errors) if errors else "Build-tool contract verified.")
            return bool(errors)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"Build-tool check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
