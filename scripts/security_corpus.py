"""Build once, then run the pure security corpus under Linux process limits.

Only bounded receipts and identities are retained. Child stdout/stderr and corpus
contents are never copied into reports, including when a child fails.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
DOMAINS = ("jwt", "policy", "host", "path")
WORKER = "security_corpus::bounded_corpus_worker"
MUTATION_ALGORITHM = "splitmix64-byte-mutations-v1"
MAX_FILES = 64
MAX_INPUT = 16_384
MAX_TOTAL = 262_144
MAX_CASES = 100_000
MAX_REPORT = 65_536
DEFAULTS = {
    "regression": {"mutations_per_seed": 8, "cpu_seconds": 20, "wall_seconds": 30},
    "exploration": {"mutations_per_seed": 512, "cpu_seconds": 120, "wall_seconds": 180},
}


class Failure(Exception):
    """A fixed, safe reason code; never construct one from child/input text."""

    def __init__(self, reason, receipt=None):
        super().__init__(reason)
        self.receipt = receipt


def unsigned(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(data, reason):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Failure(reason)
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise Failure(reason) from None


def regular_bytes(path, maximum, reason):
    """Reject symlinks, nonregular files, and oversized files before reading."""
    try:
        if path.is_symlink():
            raise Failure(reason)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                raise Failure(reason)
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise Failure(reason)
        return data
    except OSError:
        raise Failure(reason) from None


def read_corpus(manifest):
    manifest = Path(manifest).absolute()
    # Reject symlink ancestors as well as the final component.
    if any(part.is_symlink() for part in (manifest, *manifest.parents)):
        raise Failure("invalid_manifest")
    raw = regular_bytes(manifest, MAX_REPORT, "invalid_manifest")
    doc = load_json(raw, "invalid_manifest")
    if (not isinstance(doc, dict) or set(doc) != {"schema_version", "entries"}
            or type(doc["schema_version"]) is not int or doc["schema_version"] != 1
            or not isinstance(doc["entries"], list)
            or not 1 <= len(doc["entries"]) <= MAX_FILES):
        raise Failure("invalid_manifest")
    inputs, identities, seen, total = [], [], set(), 0
    for entry in doc["entries"]:
        if (not isinstance(entry, dict) or set(entry) != {"target", "path"}
                or not isinstance(entry["target"], str) or entry["target"] not in DOMAINS
                or not isinstance(entry["path"], str)):
            raise Failure("invalid_manifest_entry")
        name = entry["path"]
        relative = PurePosixPath(name)
        if (not name or relative.is_absolute() or "\\" in name
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or any(ord(char) < 32 for char in name) or name in seen):
            raise Failure("invalid_corpus_path")
        seen.add(name)
        path = manifest.parent.joinpath(*relative.parts)
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise Failure("invalid_corpus_path")
        data = regular_bytes(path, MAX_INPUT, "invalid_corpus_file")
        if not data:
            raise Failure("empty_corpus_file")
        total += len(data)
        if total > MAX_TOTAL:
            raise Failure("corpus_size_limit")
        inputs.append({"target": entry["target"], "bytes": list(data)})
        identities.append({"target": entry["target"], "path": name,
                           "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    if {entry["target"] for entry in inputs} != set(DOMAINS):
        raise Failure("missing_corpus_domain")
    return inputs, {
        "sha256": hashlib.sha256(json_bytes({"manifest_sha256": hashlib.sha256(raw).hexdigest(),
                                            "entries": identities})).hexdigest(),
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "files": len(inputs), "bytes": total,
        "targets": {domain: sum(item["target"] == domain for item in inputs) for domain in DOMAINS},
    }


def require_linux():
    if os.name != "posix" or platform.system() != "Linux":
        raise Failure("unsupported_resource_platform")
    try:
        import resource
        for name in ("RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_CORE"):
            getattr(resource, name)
    except (ImportError, AttributeError):
        raise Failure("unsupported_resource_platform") from None


def child_limits(budgets):
    import resource
    memory = budgets["memory_mib"] * 1024 * 1024
    for kind, limits in (
        (resource.RLIMIT_AS, (memory, memory)),
        (resource.RLIMIT_CPU, (budgets["cpu_seconds"], budgets["cpu_seconds"] + 1)),
        (resource.RLIMIT_FSIZE, (MAX_REPORT, MAX_REPORT)),
        (resource.RLIMIT_CORE, (0, 0)),
    ):
        resource.setrlimit(kind, limits)


def run_limited(command, cwd, env, budgets, capture=False):
    require_linux()
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.Popen(
                command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                stdout=output if capture else subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True, preexec_fn=lambda: child_limits(budgets),
            )
        except (OSError, subprocess.SubprocessError):
            raise Failure("worker_start_failure") from None
        try:
            code = process.wait(timeout=budgets["wall_seconds"])
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise Failure("wall_timeout") from None
        if code:
            if code in {-signal.SIGXCPU, -signal.SIGKILL}:
                raise Failure("cpu_or_resource_limit")
            if code == -signal.SIGXFSZ:
                raise Failure("output_size_limit")
            if code in {-signal.SIGABRT, -signal.SIGSEGV}:
                raise Failure("memory_or_process_failure")
            raise Failure("worker_process_failure")
        if capture:
            output.seek(0)
            data = output.read(MAX_REPORT + 1)
            if len(data) > MAX_REPORT:
                raise Failure("output_size_limit")
            return data
    return b""


def selected_counts(inputs, mutations, executed, replay):
    counts = dict.fromkeys(DOMAINS, 0)
    if replay is not None:
        counts[inputs[replay // (1 + mutations)]["target"]] = executed
    else:
        remaining = executed
        for item in inputs:
            count = min(remaining, 1 + mutations)
            counts[item["target"]] += count
            remaining -= count
    return counts


def validate_receipt(data, inputs, mutations, replay):
    receipt = load_json(data, "invalid_receipt")
    expected = 1 if replay is not None else len(inputs) * (1 + mutations)
    if (not isinstance(receipt, dict)
            or set(receipt) != {"schema_version", "status", "executed", "targets", "failure"}
            or type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1
            or not isinstance(receipt["status"], str) or receipt["status"] not in {"passed", "failed"}
            or not unsigned(receipt["executed"], expected) or receipt["executed"] == 0
            or not isinstance(receipt["targets"], dict) or set(receipt["targets"]) != set(DOMAINS)
            or not all(unsigned(count, expected) for count in receipt["targets"].values())
            or receipt["targets"] != selected_counts(inputs, mutations, receipt["executed"], replay)):
        raise Failure("invalid_receipt")
    if receipt["status"] == "passed":
        if receipt["executed"] != expected or receipt["failure"] is not None:
            raise Failure("incomplete_receipt")
    else:
        failure = receipt["failure"]
        index = replay if replay is not None else receipt["executed"] - 1
        if (not isinstance(failure, dict)
                or set(failure) != {"case_index", "target", "input_sha256", "kind"}
                or not unsigned(failure["case_index"], MAX_CASES - 1)
                or failure["case_index"] != index
                or failure["target"] != inputs[index // (1 + mutations)]["target"]
                or not isinstance(failure["kind"], str) or failure["kind"] not in {"invariant", "panic"}
                or not isinstance(failure["input_sha256"], str)
                or re.fullmatch("[0-9a-f]{64}", failure["input_sha256"]) is None):
            raise Failure("invalid_receipt")
    return receipt


def run_worker(binary, root, env, inputs, seed, mutations, replay, budgets):
    total = len(inputs) * (1 + mutations)
    if not 1 <= total <= MAX_CASES or (replay is not None and not unsigned(replay, total - 1)):
        raise Failure("case_budget_exceeded")
    listing = run_limited([str(binary), WORKER, "--exact", "--ignored", "--list"],
                          root, env, budgets, capture=True)
    # Exact matching avoids libtest's successful zero-test behavior.
    if listing.splitlines().count((WORKER + ": test").encode()) != 1:
        raise Failure("missing_corpus_worker")
    with tempfile.TemporaryDirectory(prefix="greengateway-corpus-") as directory:
        job, result = Path(directory) / "job.json", Path(directory) / "result.json"
        job.write_bytes(json_bytes({"schema_version": 1, "seed": seed,
                                   "mutations_per_seed": mutations, "replay_case": replay,
                                   "inputs": inputs}))
        job.chmod(0o600)
        worker_env = {**env, "GREENGATEWAY_CORPUS_JOB": str(job),
                      "GREENGATEWAY_CORPUS_RESULT": str(result)}
        try:
            run_limited([str(binary), WORKER, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
                        root, worker_env, budgets)
        except Failure as error:
            # Libtest must also fail when invoked directly. Preserve a valid,
            # bounded failed receipt for replay without accepting a nonzero exit.
            try:
                receipt = validate_receipt(regular_bytes(result, MAX_REPORT, "missing_or_oversized_receipt"),
                                           inputs, mutations, replay)
            except Failure:
                raise error from None
            if receipt["status"] == "failed":
                error.receipt = receipt
            raise error from None
        receipt = validate_receipt(regular_bytes(result, MAX_REPORT, "missing_or_oversized_receipt"),
                                   inputs, mutations, replay)
    return receipt


def metadata(root, env):
    try:
        pins_raw = (root / "build-tools.json").read_bytes()
        pins = load_json(pins_raw, "invalid_tool_pins")
        if pins["python"] != ".".join(map(str, sys.version_info[:3])):
            raise Failure("python_version_mismatch")
        env["RUSTUP_TOOLCHAIN"] = pins["rust_ci"]
        outputs = {}
        for tool in ("rustc", "cargo"):
            proc = subprocess.run([tool, "--version"], cwd=root, env=env, capture_output=True,
                                  timeout=30, check=True)
            value = proc.stdout.decode("ascii").strip()
            if not re.fullmatch(tool + r" " + re.escape(pins["rust_ci"]) + r" \([a-zA-Z0-9 .-]+\)", value):
                raise Failure("rust_version_mismatch")
            outputs[tool] = value
        def git(*args):
            return subprocess.run(["git", *args], cwd=root, capture_output=True,
                                  timeout=30, check=True).stdout
        commit = git("rev-parse", "HEAD").decode("ascii").strip()
        if re.fullmatch("[0-9a-f]{40}", commit) is None:
            raise Failure("invalid_source_identity")
        names = sorted(set(git("ls-files", "-z", "--cached", "--others", "--exclude-standard").split(b"\0")) - {b""})
        digest = hashlib.sha256()
        for name in names:
            path = root / os.fsdecode(name)
            if path.is_symlink():
                contents = b"symlink:" + os.fsencode(os.readlink(path))
            elif path.is_file():
                contents = b"file:" + digest_file(path).encode()
            else:
                contents = b"absent"
            digest.update(len(name).to_bytes(8, "big") + name + contents + b"\0")
        return {"commit": commit, "dirty": bool(git("status", "--porcelain", "--untracked-files=all")),
                "source_sha256": digest.hexdigest(), "source_files": len(names),
                "cargo_lock_sha256": digest_file(root / "Cargo.lock"),
                "build_tools_sha256": hashlib.sha256(pins_raw).hexdigest(),
                "toolchain": outputs, "tool_pins": {key: pins[key] for key in ("rust_ci", "python", "node", "npm")}}
    except Failure:
        raise
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        raise Failure("metadata_failure") from None


def build_binary(root, env, timeout):
    command = ["cargo", "test", "-p", "gateway", "--bin", "gateway", "--locked",
               "--no-run", "--message-format=json"]
    # Compilation has its own wall budget. It does not inherit the worker's
    # address-space/CPU limits and occurs once, never once per corpus input.
    with tempfile.TemporaryFile() as output:
        try:
            process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                       stdout=output, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise Failure("compile_timeout") from None
            if code:
                raise Failure("compile_failure")
            output.seek(0)
            raw = output.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                raise Failure("compile_output_limit")
            binaries = set()
            for line in raw.splitlines():
                message = load_json(line, "invalid_cargo_artifact")
                if (isinstance(message, dict) and message.get("reason") == "compiler-artifact"
                        and message.get("target", {}).get("name") == "gateway"
                        and message.get("target", {}).get("kind") == ["bin"]
                        and message.get("profile", {}).get("test") is True and message.get("executable")):
                    binaries.add(message["executable"])
            if len(binaries) != 1:
                raise Failure("missing_or_ambiguous_binary")
            return Path(binaries.pop()).resolve()
        except Failure:
            raise
        except (OSError, ValueError, TypeError, AttributeError, subprocess.SubprocessError):
            raise Failure("compile_failure") from None


def write_report(path, report):
    data = json_bytes(report) + b"\n"
    if len(data) > MAX_REPORT:
        report = {"schema_version": 1, "status": "failed", "reason": "report_size_limit"}
        data = json_bytes(report) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".corpus-report-", delete=False) as stream:
        pending = Path(stream.name)
        stream.write(data)
    pending.replace(path)
    return report


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Failure("invalid_arguments")


def arguments(argv):
    parser = Parser(description=__doc__)
    parser.add_argument("--mode", choices=DEFAULTS, default="regression")
    parser.add_argument("--manifest", type=Path, default=ROOT / "fuzz/corpus/manifest.json")
    parser.add_argument("--report", type=Path, default=ROOT / "target/security-corpus/report.json")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--seed", type=int, default=435005)
    parser.add_argument("--mutations-per-seed", type=int)
    parser.add_argument("--replay-case", type=int)
    parser.add_argument("--cpu-seconds", type=int)
    parser.add_argument("--wall-seconds", type=int)
    parser.add_argument("--memory-mib", type=int, default=2048)
    parser.add_argument("--compile-timeout-seconds", type=int, default=3600)
    args = parser.parse_args(argv)
    for name, default in DEFAULTS[args.mode].items():
        if getattr(args, name) is None:
            setattr(args, name, default)
    if (not unsigned(args.seed, 2**64 - 1) or not unsigned(args.mutations_per_seed, MAX_CASES - 1)
            or not 1 <= args.cpu_seconds <= 3600 or not 1 <= args.wall_seconds <= 3600
            or not 128 <= args.memory_mib <= 8192 or not 1 <= args.compile_timeout_seconds <= 7200
            or (args.replay_case is not None and not unsigned(args.replay_case, MAX_CASES - 1))):
        raise Failure("invalid_arguments")
    return args


def main(argv=None):
    report = {"schema_version": 1, "status": "failed", "reason": "controller_failure"}
    report_path = ROOT / "target/security-corpus/report.json"
    started = time.monotonic()
    try:
        args = arguments(argv)
        report_path = args.report.absolute()
        budgets = {key: getattr(args, key) for key in ("cpu_seconds", "wall_seconds", "memory_mib")}
        report.update(mode=args.mode, seed=args.seed, mutations_per_seed=args.mutations_per_seed,
                      mutation_algorithm=MUTATION_ALGORITHM,
                      replay_case=args.replay_case, budgets={**budgets, "input_bytes": MAX_INPUT,
                      "corpus_bytes": MAX_TOTAL, "corpus_files": MAX_FILES, "cases": MAX_CASES,
                      "report_bytes": MAX_REPORT, "compile_timeout_seconds": args.compile_timeout_seconds})
        require_linux()
        env = os.environ.copy()
        report["source"] = metadata(ROOT, env)
        inputs, report["corpus"] = read_corpus(args.manifest)
        count = len(inputs) * (args.mutations_per_seed + 1)
        if count > MAX_CASES or (args.replay_case is not None and args.replay_case >= count):
            raise Failure("case_budget_exceeded")
        report["expected_cases"] = 1 if args.replay_case is not None else count
        binary = args.binary.resolve() if args.binary else build_binary(ROOT, env, args.compile_timeout_seconds)
        report["binary"] = {"sha256": digest_file(binary), "origin": "provided" if args.binary else "cargo_build"}
        report["receipt"] = run_worker(binary, ROOT, env, inputs, args.seed, args.mutations_per_seed,
                                       args.replay_case, budgets)
        report["status"] = report["receipt"]["status"]
        report["reason"] = "completed" if report["status"] == "passed" else "corpus_finding"
    except Failure as error:
        report["reason"] = str(error)
        if error.receipt is not None:
            report["receipt"] = error.receipt
    except Exception:
        # Unexpected errors remain fail-closed and never serialize exception text.
        report["reason"] = "controller_failure"
    report["elapsed_seconds"] = round(time.monotonic() - started, 3)
    try:
        report = write_report(report_path, report)
    except OSError:
        print("security corpus: failed (report_write_failure)", file=sys.stderr)
        return 1
    print("security corpus: " + report["status"] + " (" + report["reason"] + ")")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
