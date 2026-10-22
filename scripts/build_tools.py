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
# A `run` command that builds an image: `docker build`, `docker buildx build`,
# `docker image build`, `compose build` or `compose ... --build`. Compose's
# `--no-build` is not a build.
IMAGE_BUILD = re.compile(
    r"\bdocker\s+(?:buildx\s+|image\s+)?build\b|\bcompose\b[^\n]*?\s(?:--build|build)\b")
# The only condition under which a pull-request-triggered workflow may write
# a cache: a push to main, whose code is reviewed. A pull request can then
# read main's caches but never write one a later run would restore.
TRUSTED_CACHE_WRITE = "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
# A job may also restore a cache it never writes: one that reads another
# job's dependency cache but builds something that cache must not hold.
NEVER_CACHE_WRITE = "false"
# The one other gate a reusable-workflow call may have: it keeps the call off
# pull requests, and the called workflow (which must then be one of ours) is
# held to these same rules, so a tag push cannot write a cache through it.
PUSH_ONLY = "github.event_name == 'push'"
# Setup actions that save a cache unless told `cache: false`.
SETUP_CACHES_BY_DEFAULT = ("actions/setup-go@",)


def pull_request_triggered(doc):
    events = doc.get("on", {})
    names = events if isinstance(events, list) else [events] if isinstance(events, str) else list(events)
    return bool({"pull_request", "pull_request_target"} & set(names))


def action_name(step):
    # GitHub resolves owners, repositories and input names without regard to
    # case, so `Actions/Cache@...` is actions/cache and `Save-If` is save-if.
    return str(step.get("uses", "")).strip().lower()


def expression(condition):
    text = str(condition).strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    return text


def cache_write_errors(where, steps):
    errors = []
    for step in steps:
        use, given = action_name(step), step.get("with") or {}
        opts = {str(key).strip().lower(): str(value) for key, value in given.items()}
        if len(opts) != len(given):
            errors.append(f"{where}: step inputs may not differ only in case")
        env = step.get("env") or {}
        commands = "\n".join([str(step.get("run", ""))] + [str(v) for v in (env.values() if isinstance(env, dict) else [env])])
        if use.startswith("swatinem/rust-cache@") and opts.get("save-if") not in (TRUSTED_CACHE_WRITE, NEVER_CACHE_WRITE):
            errors.append(f"{where}: Rust caches may be saved only from main pushes")
        if use.startswith(("actions/cache@", "actions/cache/save@")):
            errors.append(f"{where}: pull request jobs may only restore caches")
        if use.startswith("actions/setup-"):
            default = "true" if use.startswith(SETUP_CACHES_BY_DEFAULT) else "false"
            if opts.get("cache", default).strip().lower() != "false":
                errors.append(f"{where}: setup actions may not save caches in pull request jobs")
        if (use.startswith("docker/") and ("cache-to" in opts or any("cache-to" in v.lower() for v in opts.values()))) \
                or "cache-to" in commands.lower():
            errors.append(f"{where}: pull request jobs may not export image build caches")
    return errors


def reusable_call_errors(where, job, root, seen=()):
    """A job-level `uses:` in a pull request workflow, which runs another workflow's jobs."""
    called, gate = str(job.get("uses", "")).strip(), expression(job.get("if", ""))
    if gate == expression(TRUSTED_CACHE_WRITE):
        return []
    refusal = [f"{where}: reusable workflows may be called from pull request workflows only on pushes to main"]
    if gate != PUSH_ONLY or not re.fullmatch(r"\./\.github/workflows/[\w.-]+\.ya?ml", called) or called in seen:
        return refusal
    import yaml
    try:
        doc = yaml.load((root / called).read_text(), Loader=yaml.BaseLoader)
    except OSError:
        return refusal
    errors = []
    for job_name, called_job in (doc.get("jobs") or {}).items():
        inner = f"{where} -> {called[2:]}/{job_name}"
        errors += cache_write_errors(inner, called_job.get("steps", []))
        if "uses" in called_job:
            errors += reusable_call_errors(inner, called_job, root, (*seen, called))
    return errors


def versions(root=ROOT):
    data = json.loads((root / "build-tools.json").read_text(encoding="utf-8"))
    required = {"schema_version", "rust_ci", "rust_production", "rust_coverage",
                "node", "npm", "python", "cargo_audit", "cargo_llvm_cov", "pyyaml", "cargo_deny",
                "cargo_deny_linux_amd64_sha256", "cargo_deny_windows_amd64_sha256",
                "promtool", "promtool_linux_amd64_sha256",
                "buildx", "buildkit_image", "gitleaks", "buildx_linux_amd64_sha256", "trivy", "trivy_linux_amd64_sha256", "github_cli", "github_cli_linux_amd64_sha256"}
    if set(data) != required or data["schema_version"] != 1:
        raise ValueError("unknown or incomplete build-tool contract")
    for key in required - {"schema_version", "rust_coverage", "buildkit_image", "buildx_linux_amd64_sha256", "trivy_linux_amd64_sha256", "github_cli_linux_amd64_sha256", "cargo_deny_linux_amd64_sha256", "cargo_deny_windows_amd64_sha256", "promtool_linux_amd64_sha256"}:
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
    for key in ["cargo_deny_linux_amd64_sha256", "cargo_deny_windows_amd64_sha256"]:
        if not re.fullmatch(r"[0-9a-f]{64}", data[key]):
            raise ValueError("Cargo policy archive must have a reviewed checksum")
    if not re.fullmatch(r"[0-9a-f]{64}", data["promtool_linux_amd64_sha256"]):
        raise ValueError("Promtool archive must have a reviewed checksum")
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
        for path in sorted((root / ".github/actions").glob("*/action.y*ml")):
            composite = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            # Composite actions run inside pull request jobs too.
            errors += cache_write_errors(path.parent.name, composite.get("runs", {}).get("steps", []))
        for path in (root / ".github/workflows").glob("*.y*ml"):
            doc = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            if pull_request_triggered(doc):
                for job_name, job in doc.get("jobs", {}).items():
                    errors += cache_write_errors(f"{path.name}/{job_name}", job.get("steps", []))
                    if "uses" in job:
                        errors += reusable_call_errors(f"{path.name}/{job_name}", job, root)
            if path.name == "ci.yml" and "cargo-policy" not in doc.get("jobs", {}):
                errors.append("CI must retain the required Cargo policy job")
            if path.name == "ci.yml" and "egress-only" not in doc.get("jobs", {}):
                errors.append("CI must retain structural transport ownership")
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
                builds_image = any(action_name(s).startswith("docker/build-push-action@") for s in steps)
                builds_image |= bool(IMAGE_BUILD.search(commands))
                # promote_image.py drives `docker buildx imagetools` itself.
                builds_image |= job_name == "promote-image"
                if builds_image and not any(s.get("uses") == "./.github/actions/buildx" for s in steps):
                    errors.append(f"{job_name}: verified Buildx setup is required")
                if re.search(r"\bcargo\b", commands) and rust_profile == "none":
                    errors.append(f"{job_name}: Cargo uses an undeclared compiler")
                if re.search(r"\b(node|npm|npx)\b|\bcargo (build|test|clippy|llvm-cov)\b", commands) and config.get("node") != "true":
                    errors.append(f"{job_name}: Node/npm setup required before building")
                if job_name == "egress-only":
                    for required_command in ["bash scripts/check-egress-only.sh", "python scripts/transport_guard.py check", "cargo test --locked --example transport_guard", "test_transport_guard.py"]:
                        if required_command not in commands:
                            errors.append("Transport ownership must retain protocol guard, structural check and rejection fixtures")
                if job_name == "cargo-policy":
                    if job.get("strategy", {}).get("matrix", {}).get("os") != ["ubuntu-latest", "windows-latest"]:
                        errors.append("Cargo policy requires Linux and Windows qualification")
                    for required_command in ["python scripts/cargo_policy.py install", "python scripts/cargo_policy.py check", "test_cargo_policy.py"]:
                        if required_command not in commands:
                            errors.append("Cargo policy must retain verified installer, full-graph check and rejection fixtures")
                for s in steps:
                    use, opts, run = action_name(s), s.get("with", {}), s.get("run", "")
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
