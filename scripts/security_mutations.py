#!/usr/bin/env python3
"""Bounded, fail-closed mutation campaign for the reviewed security registry.

The production campaign builds a clean HEAD archive with the ordinary Cargo/UI
build. Only the disposable archive is changed. JSON evidence never contains
compiler output, panic text, source snippets or environment values.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Any

VERSION = "1.0.0"
MAX_MANIFEST = 131072
MAX_SOURCE = 2097152
MAX_REPORT = 262144
MAX_BUILD_OUTPUT = 8388608
MAX_TEST_OUTPUT = 65536
MAX_ARCHIVE = 268435456
ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
TEST = re.compile(r"[A-Za-z_][A-Za-z0-9_:]{0,255}\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
OUTCOMES = ("killed", "survived", "unviable", "timed_out", "harness_error")
BUILD_COMMAND = ["cargo", "test", "-p", "gateway", "--bin", "gateway", "--locked", "--no-run", "--message-format=json"]


class HarnessError(Exception):
    """Only fixed category names from this module may cross the report boundary."""

    def __init__(self, category: str):
        self.category = category
        super().__init__(category)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def mutation_digest(target: dict, mutation: dict) -> str:
    return sha256(canonical({key: target[key] for key in ("path", "function", "source_sha256")} | {
        "target_id": target["id"], "old": mutation["old"], "new": mutation["new"],
    }))


def exact_keys(value: Any, keys: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise HarnessError("invalid_schema")


def bounded_text(value: Any, limit: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value) or len(value.encode()) > limit or "\x00" in value:
        raise HarnessError("invalid_text")
    return value


def regular_file(root: Path, relative: str, limit: int) -> Path:
    bounded_text(relative, 512)
    rel = PurePosixPath(relative)
    if rel.is_absolute() or ".." in rel.parts or not rel.parts or str(rel) != relative:
        raise HarnessError("unsafe_path")
    current = root
    for component in rel.parts:
        current = current / component
        if current.is_symlink():
            raise HarnessError("unsafe_path")
    if not current.is_file() or current.stat().st_size > limit:
        raise HarnessError("invalid_file")
    return current


def read_json(path: Path, limit: int) -> Any:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise HarnessError("invalid_file")

    def pairs(items: list[tuple[str, Any]]) -> dict:
        output: dict = {}
        for key, value in items:
            if key in output:
                raise HarnessError("duplicate_json_key")
            output[key] = value
        return output

    try:
        return json.loads(path.read_bytes(), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(HarnessError("invalid_json")))
    except (ValueError, UnicodeError):
        raise HarnessError("invalid_json") from None


def function_span(source: bytes, target: dict) -> tuple[int, int]:
    start_marker = target["start_marker"].encode()
    end_marker = target["end_marker"].encode()
    if source.count(start_marker) != 1 or end_marker != b"\n}\n":
        raise HarnessError("function_scope_drift")
    start = source.index(start_marker)
    if start > 0 and source[start - 1] != 10:
        raise HarnessError("function_scope_drift")
    end = source.find(end_marker, start + len(start_marker))
    if end < 0:
        raise HarnessError("function_scope_drift")
    end += len(end_marker)
    if sha256(source[start:end]) != target["source_sha256"]:
        raise HarnessError("function_hash_drift")
    return start, end


def load_manifest(root: Path, path: Path) -> tuple[dict, list[dict]]:
    manifest = read_json(path, MAX_MANIFEST)
    exact_keys(manifest, {"schema_version", "harness_version", "targets", "exceptions"})
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or manifest["harness_version"] != VERSION:
        raise HarnessError("unsupported_version")
    if not isinstance(manifest["targets"], list) or not 1 <= len(manifest["targets"]) <= 16:
        raise HarnessError("invalid_target_count")
    mutants: list[dict] = []
    target_ids: set[str] = set()
    global_tests: set[str] = set()
    spans: dict[str, list[tuple[int, int]]] = {}
    for target in manifest["targets"]:
        exact_keys(target, {"id", "path", "function", "start_marker", "end_marker", "source_sha256", "tests", "mutations"})
        for key in ("id",):
            if not isinstance(target[key], str) or not ID.fullmatch(target[key]):
                raise HarnessError("invalid_identifier")
        if not isinstance(target["function"], str) or not TEST.fullmatch(target["function"]):
            raise HarnessError("invalid_identifier")
        if target["id"] in target_ids:
            raise HarnessError("duplicate_target")
        target_ids.add(target["id"])
        bounded_text(target["start_marker"], 1024)
        bounded_text(target["end_marker"], 32)
        # The declaration itself anchors the named top-level function, not a comment.
        if not re.fullmatch(r"(?:pub(?:\(crate\))? )?fn " + re.escape(target["function"].split("::")[-1]) + r"\([^\n]*", target["start_marker"]):
            raise HarnessError("invalid_function_marker")
        if not isinstance(target["source_sha256"], str) or not SHA.fullmatch(target["source_sha256"]):
            raise HarnessError("invalid_digest")
        file = regular_file(root, target["path"], MAX_SOURCE)
        source = file.read_bytes()
        start, end = function_span(source, target)
        existing = spans.setdefault(target["path"], [])
        if any(start < other_end and end > other_start for other_start, other_end in existing):
            raise HarnessError("overlapping_targets")
        existing.append((start, end))
        tests = target["tests"]
        if not isinstance(tests, list) or not 1 <= len(tests) <= 16:
            raise HarnessError("invalid_test_count")
        if any(not isinstance(test, str) or not TEST.fullmatch(test) for test in tests):
            raise HarnessError("invalid_test_name")
        if len(set(tests)) != len(tests):
            raise HarnessError("duplicate_test")
        global_tests.update(tests)
        mutations = target["mutations"]
        if not isinstance(mutations, list) or not 1 <= len(mutations) <= 16:
            raise HarnessError("invalid_mutation_count")
        mutation_ids: set[str] = set()
        digests: set[str] = set()
        for mutation in mutations:
            exact_keys(mutation, {"id", "old", "new"})
            if not isinstance(mutation["id"], str) or not ID.fullmatch(mutation["id"]):
                raise HarnessError("invalid_identifier")
            if mutation["id"] in mutation_ids:
                raise HarnessError("duplicate_mutation")
            mutation_ids.add(mutation["id"])
            old = bounded_text(mutation["old"], 8192).encode()
            new = bounded_text(mutation["new"], 8192, empty=True).encode()
            if old == new or source[start:end].count(old) != 1:
                raise HarnessError("invalid_replacement")
            digest = mutation_digest(target, mutation)
            if digest in digests:
                raise HarnessError("duplicate_mutation")
            digests.add(digest)
            mutants.append({"id": target["id"] + "/" + mutation["id"], "mutation_sha256": digest,
                            "target": target, "mutation": mutation, "span": (start, end)})
    if len(mutants) > 64 or len(global_tests) > 64:
        raise HarnessError("campaign_too_large")
    exceptions = manifest["exceptions"]
    if not isinstance(exceptions, list) or len(exceptions) > len(mutants):
        raise HarnessError("invalid_exceptions")
    by_id = {mutant["id"]: mutant for mutant in mutants}
    seen: set[str] = set()
    for exception in exceptions:
        exact_keys(exception, {"mutant_id", "mutation_sha256", "outcome", "owner", "reason"})
        mutant_id = exception["mutant_id"]
        if not isinstance(mutant_id, str) or mutant_id not in by_id or mutant_id in seen:
            raise HarnessError("stale_exception")
        seen.add(mutant_id)
        if exception["mutation_sha256"] != by_id[mutant_id]["mutation_sha256"] or exception["outcome"] not in ("survived", "unviable"):
            raise HarnessError("stale_exception")
        if not isinstance(exception["owner"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_/-]{0,95}", exception["owner"]):
            raise HarnessError("invalid_exception_owner")
        bounded_text(exception["reason"], 512)
    return manifest, mutants


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    elapsed_seconds: float
    timed_out: bool = False
    output_exceeded: bool = False


def run_process(command: list[str], cwd: Path, env: dict[str, str], *, wall_seconds: float,
                cpu_seconds: int, memory_mib: int | None, output_limit: int = MAX_TEST_OUTPUT,
                file_limit: int | None = None) -> ProcessResult:
    if wall_seconds <= 0:
        return ProcessResult(-1, b"", b"", 0, timed_out=True)

    def limits() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        if memory_mib is not None:
            resource.setrlimit(resource.RLIMIT_AS, (memory_mib * 1048576,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit or output_limit + 1,) * 2)

    start = time.monotonic()
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                       stdin=subprocess.DEVNULL, start_new_session=True, preexec_fn=limits)
        except OSError:
            raise HarnessError("process_start_failure") from None
        timed_out = False
        try:
            process_deadline = start + wall_seconds
            while process.poll() is None:
                remaining = process_deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, wall_seconds)
                if os.fstat(stdout.fileno()).st_size > output_limit or os.fstat(stderr.fileno()).st_size > output_limit:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    break
                try:
                    process.wait(timeout=min(0.25, remaining))
                except subprocess.TimeoutExpired:
                    continue
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            raise
        # Descendants must not outlive a compiler/test which exited early.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        exceeded = stdout.tell() > output_limit or stderr.tell() > output_limit
        stdout.seek(0)
        stderr.seek(0)
        timed_out = timed_out or process.returncode == -signal.SIGXCPU
        return ProcessResult(process.returncode, stdout.read(output_limit), stderr.read(output_limit),
                             round(time.monotonic() - start, 4), timed_out, exceeded)


def require_process(result: ProcessResult) -> None:
    if result.timed_out:
        raise HarnessError("process_timeout")
    if result.output_exceeded:
        raise HarnessError("output_limit")
    if result.returncode != 0:
        raise HarnessError("process_failure")


def discover_test(result: ProcessResult, name: str) -> None:
    require_process(result)
    try:
        lines = [line for line in result.stdout.decode().splitlines() if line]
    except UnicodeError:
        raise HarnessError("invalid_test_discovery") from None
    if lines != [name + ": test", "1 test, 0 benchmarks"]:
        raise HarnessError("missing_or_ambiguous_test")


def classify_test(result: ProcessResult, name: str) -> str:
    if result.timed_out:
        return "timed_out"
    if result.output_exceeded or result.returncode < 0:
        return "harness_error"
    try:
        output = result.stdout.decode()
    except UnicodeError:
        return "harness_error"
    summaries = re.findall(r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [0-9.]+s\s*$", output, re.M)
    if len(summaries) != 1:
        return "harness_error"
    status, passed, failed, ignored, measured, _ = summaries[0]
    if ignored != "0" or measured != "0" or int(passed) + int(failed) != 1:
        return "harness_error"
    lines = re.findall(r"^test " + re.escape(name) + r" \.\.\. (ok|FAILED)$", output, re.M)
    if status == "ok" and passed == "1" and failed == "0" and result.returncode == 0 and lines == ["ok"]:
        return "survived"
    if status == "FAILED" and passed == "0" and failed == "1" and result.returncode == 101 and lines == ["FAILED"]:
        return "killed"
    return "harness_error"


def json_lines(raw: bytes) -> list[dict]:
    values = []
    for line in raw.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError):
            continue
        if isinstance(value, dict):
            values.append(value)
    return values


def classify_build(result: ProcessResult, snapshot: Path, target_dir: Path,
                   mutated_path: str | None = None) -> tuple[str, Path | None]:
    if result.timed_out:
        return "timed_out", None
    if result.output_exceeded or result.returncode < 0:
        return "harness_error", None
    messages = json_lines(result.stdout)
    if result.returncode != 0:
        errors = [message.get("message", {}) for message in messages if message.get("reason") == "compiler-message"]
        if mutated_path and any(error.get("level") == "error" and any(
            span.get("is_primary") is True and span.get("file_name") in (mutated_path, str(snapshot / mutated_path))
            for span in error.get("spans", []) if isinstance(span, dict)) for error in errors):
            return "unviable", None
        return "harness_error", None
    artifacts = [message.get("executable") for message in messages
                 if message.get("reason") == "compiler-artifact"
                 and message.get("target", {}).get("name") == "gateway"
                 and message.get("target", {}).get("kind") == ["bin"]
                 and message.get("profile", {}).get("test") is True and message.get("executable")]
    finished = [message for message in messages if message.get("reason") == "build-finished"]
    if len(artifacts) != 1 or len(finished) != 1 or finished[0].get("success") is not True:
        return "harness_error", None
    binary = Path(artifacts[0])
    if not binary.is_absolute() or not binary.is_file() or binary.is_symlink() or not binary.resolve().is_relative_to(target_dir.resolve()):
        return "harness_error", None
    return "built", binary


def counts(results: list[dict], generated: int | None = None) -> dict[str, int]:
    generated = len(results) if generated is None else generated
    return {"generated": generated, "completed": len(results), "not_run": generated - len(results), **{outcome: sum(item["outcome"] == outcome for item in results) for outcome in OUTCOMES},
            "excluded": sum(item.get("excluded", False) for item in results)}


def apply_exception(result: dict, exception: dict | None) -> bool:
    if exception is None:
        return result["outcome"] == "killed"
    if result["outcome"] != exception["outcome"]:
        result["exception_status"] = "stale"
        return False
    result["excluded"] = True
    result["exception"] = {"owner": exception["owner"], "reason_sha256": sha256(exception["reason"].encode())}
    return True


def validate_report_path(path: Path, root: Path) -> Path:
    absolute = path.absolute()
    if any(parent.is_symlink() for parent in (absolute, *absolute.parents)):
        raise HarnessError("unsafe_report_path")
    resolved = absolute.resolve()
    source_roots = {root.resolve(), Path(__file__).resolve().parents[1]}
    if any(resolved.is_relative_to(source_root) and not resolved.is_relative_to(source_root / "target") for source_root in source_roots):
        raise HarnessError("unsafe_report_path")
    if resolved.exists() and not resolved.is_file():
        raise HarnessError("unsafe_report_path")
    return resolved


def write_report(path: Path, report: dict) -> bool:
    payload = canonical(report) + b"\n"
    within_limit = len(payload) <= MAX_REPORT
    if not within_limit:
        payload = canonical({"schema_version": 1, "harness_version": VERSION, "status": "failed", "reason": "report_limit"}) + b"\n"
        report["status"] = "failed"
        report["reason"] = "report_limit"
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".mutation-report-", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return within_limit


def checkpoint_report(path: Path, report: dict) -> None:
    report["counts"] = counts(report["results"], report.get("expected_mutants"))
    if not write_report(path, report):
        # Abort now: later cleanup can shrink a report, but cannot erase this failure.
        raise HarnessError("report_limit")


def unpack_archive(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:") as source:
        total = 0
        seen: set[str] = set()
        for index, member in enumerate(source):
            path = PurePosixPath(member.name)
            if index >= 20000 or path.is_absolute() or ".." in path.parts or member.name in seen or not (member.isdir() or member.isfile()):
                raise HarnessError("unsafe_archive")
            seen.add(member.name)
            total += member.size
            if total > MAX_ARCHIVE or member.size > MAX_SOURCE * 32:
                raise HarnessError("archive_limit")
            output = destination / path
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
            else:
                output.parent.mkdir(parents=True, exist_ok=True)
                data = source.extractfile(member)
                if data is None:
                    raise HarnessError("unsafe_archive")
                with output.open("xb") as handle:
                    while chunk := data.read(1048576):
                        handle.write(chunk)
                output.chmod(member.mode & 0o777)


def pin_environment(root: Path, call: Any) -> tuple[dict, dict[str, str]]:
    pins = read_json(regular_file(root, "build-tools.json", MAX_MANIFEST), MAX_MANIFEST)
    required = ("rust_ci", "node", "npm", "python")
    if any(not isinstance(pins.get(key), str) or not re.fullmatch(r"\d+\.\d+\.\d+", pins[key]) for key in required):
        raise HarnessError("invalid_toolchain_pins")
    if sys.version.split()[0] != pins["python"]:
        raise HarnessError("python_pin_mismatch")
    env = dict(os.environ, RUSTUP_TOOLCHAIN=pins["rust_ci"], CARGO_BUILD_JOBS="1", CARGO_TERM_COLOR="never")
    checks = ((["rustc", "--version"], r"rustc " + re.escape(pins["rust_ci"]) + r"(?: |$)"),
              (["cargo", "--version"], r"cargo " + re.escape(pins["rust_ci"]) + r"(?: |$)"),
              (["node", "--version"], "v" + re.escape(pins["node"]) + r"\s*\Z"),
              (["npm", "--version"], re.escape(pins["npm"]) + r"\s*\Z"))
    for command, pattern in checks:
        result = call(command, root, env)
        require_process(result)
        if not re.match(pattern, result.stdout.decode(errors="replace")):
            raise HarnessError("toolchain_pin_mismatch")
    return {key: pins[key] for key in required}, env


def campaign(args: argparse.Namespace, report: dict) -> None:
    root = args.root.resolve()
    deadline = time.monotonic() + args.campaign_seconds

    def call(command: list[str], cwd: Path, env: dict[str, str], *, build: bool = False, archive: bool = False) -> ProcessResult:
        return run_process(command, cwd, env, wall_seconds=min(args.build_seconds if build else args.test_seconds, deadline - time.monotonic()),
                           cpu_seconds=args.build_cpu_seconds if build else args.test_cpu_seconds, memory_mib=None if build else args.memory_mib,
                           output_limit=MAX_BUILD_OUTPUT if build else MAX_TEST_OUTPUT,
                           file_limit=MAX_ARCHIVE if archive else (4294967296 if build else None))

    def checkpoint() -> None:
        checkpoint_report(args.report, report)

    pins, env = pin_environment(root, call)
    report["toolchain"] = pins
    status = call(["git", "status", "--porcelain", "--untracked-files=no"], root, env)
    require_process(status)
    if status.stdout.strip():
        raise HarnessError("dirty_tracked_source")
    head = call(["git", "rev-parse", "HEAD"], root, env)
    require_process(head)
    commit = head.stdout.decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise HarnessError("invalid_source_revision")
    report["base_commit"] = commit
    report["source_state"] = "tracked_clean_head_archive"
    manifest_path = args.manifest.resolve()
    if not manifest_path.is_relative_to(root):
        raise HarnessError("manifest_outside_repository")
    relative_manifest = manifest_path.relative_to(root).as_posix()
    tracked = call(["git", "ls-files", "--error-unmatch", "--", relative_manifest], root, env)
    require_process(tracked)
    regular_file(root, relative_manifest, MAX_MANIFEST)
    target_dir = args.target_dir.resolve()
    if root.is_relative_to(target_dir) or target_dir in (Path("/tmp"), Path("/var/tmp")) or (target_dir.is_relative_to(root) and not target_dir.is_relative_to(root / "target")):
        raise HarnessError("unsafe_target_directory")
    target_dir.mkdir(parents=True, exist_ok=True)
    env["CARGO_TARGET_DIR"] = str(target_dir)
    with tempfile.TemporaryDirectory(prefix="greengateway-security-mutations-") as temporary:
        work = Path(temporary)
        archive = work / "source.tar"
        archived = call(["git", "archive", "--format=tar", "--output=" + str(archive), commit], root, env, archive=True)
        require_process(archived)
        snapshot = work / "source"
        snapshot.mkdir()
        unpack_archive(archive, snapshot)
        manifest_file = regular_file(snapshot, relative_manifest, MAX_MANIFEST)
        manifest, mutants = load_manifest(snapshot, manifest_file)
        report["registry_sha256"] = sha256(manifest_file.read_bytes())
        report["source_archive_sha256"] = sha256(archive.read_bytes())
        report["cargo_lock_sha256"] = sha256(regular_file(snapshot, "Cargo.lock", MAX_SOURCE).read_bytes())
        report["build_tools_sha256"] = sha256(regular_file(snapshot, "build-tools.json", MAX_MANIFEST).read_bytes())
        report["expected_mutants"] = len(mutants)
        report["harness_sha256"] = sha256(Path(__file__).read_bytes())
        report["targets"] = [{key: target[key] for key in ("id", "path", "function", "source_sha256", "tests")} for target in manifest["targets"]]
        archived_pins = read_json(snapshot / "build-tools.json", MAX_MANIFEST)
        if any(archived_pins.get(key) != value for key, value in pins.items()):
            raise HarnessError("toolchain_snapshot_mismatch")
        report["selected_tests"] = sorted({test for target in manifest["targets"] for test in target["tests"]})
        report["commands"] = {"build": BUILD_COMMAND, "discover": ["<test-binary>", "<exact-test>", "--exact", "--list"],
                              "test": ["<test-binary>", "<exact-test>", "--exact", "--test-threads=1"]}
        report["phase"] = "baseline_build"
        checkpoint()
        built = call(BUILD_COMMAND, snapshot, env, build=True)
        outcome, binary = classify_build(built, snapshot, target_dir)
        report["baseline"] = {"build_outcome": outcome, "build_seconds": built.elapsed_seconds, "tests": []}
        checkpoint()
        if outcome != "built" or binary is None:
            raise HarnessError("baseline_build_" + outcome)
        report["phase"] = "baseline_tests"
        checkpoint()
        for test in report["selected_tests"]:
            discover_test(call([str(binary), test, "--exact", "--list"], snapshot, env), test)
            tested = call([str(binary), test, "--exact", "--test-threads=1"], snapshot, env)
            outcome = classify_test(tested, test)
            report["baseline"]["tests"].append({"test": test, "outcome": outcome, "elapsed_seconds": tested.elapsed_seconds})
            checkpoint()
            if outcome != "survived":
                raise HarnessError("baseline_test_" + outcome)
        exceptions = {exception["mutant_id"]: exception for exception in manifest["exceptions"]}
        acceptable = True
        for mutant in mutants:
            report["phase"] = "mutant"
            report["active_mutant"] = mutant["id"]
            checkpoint()
            target, mutation = mutant["target"], mutant["mutation"]
            file = snapshot / target["path"]
            original = file.read_bytes()
            start, end = function_span(original, target)
            mutated = original[:start] + original[start:end].replace(mutation["old"].encode(), mutation["new"].encode(), 1) + original[end:]
            result = {"id": mutant["id"], "mutation_sha256": mutant["mutation_sha256"], "tests": [], "excluded": False}
            try:
                file.write_bytes(mutated)
                built = call(BUILD_COMMAND, snapshot, env, build=True)
                outcome, binary = classify_build(built, snapshot, target_dir, target["path"])
                result["build_seconds"] = built.elapsed_seconds
                if outcome == "built" and binary is not None:
                    outcome = "survived"
                    for test in target["tests"]:
                        try:
                            discover_test(call([str(binary), test, "--exact", "--list"], snapshot, env), test)
                        except HarnessError as error:
                            outcome = "timed_out" if error.category == "process_timeout" else "harness_error"
                            break
                        tested = call([str(binary), test, "--exact", "--test-threads=1"], snapshot, env)
                        test_outcome = classify_test(tested, test)
                        result["tests"].append({"test": test, "outcome": test_outcome, "elapsed_seconds": tested.elapsed_seconds})
                        if test_outcome != "survived":
                            outcome = test_outcome
                            break
                result["outcome"] = outcome
            finally:
                file.write_bytes(original)
            acceptable = apply_exception(result, exceptions.get(mutant["id"])) and acceptable
            report["results"].append(result)
            checkpoint()
            if result["outcome"] in ("harness_error", "timed_out"):
                raise HarnessError("campaign_" + result["outcome"])
        report.pop("active_mutant", None)
        if len(report["results"]) != report["expected_mutants"]:
            raise HarnessError("incomplete_campaign")
        report["status"] = "passed" if acceptable else "failed"
        report["reason"] = "all_reviewed_mutants_accounted" if acceptable else "unapproved_or_stale_outcome"
        report["phase"] = "complete"
        checkpoint()


CALIBRATION_SOURCE = '''fn allowed(value: u8) -> bool { value < 4 }\n#[test]\nfn rejects_boundary() { assert!(!allowed(4)); assert!(allowed(3)); }\n'''


def calibrate(env: dict[str, str] | None = None) -> dict[str, str]:
    """Real rustc/libtest execution; never contributes to production counts."""
    if sys.platform != "linux":
        raise HarnessError("unsupported_platform")
    environment = dict(os.environ) if env is None else env
    observed: dict[str, str] = {}
    with tempfile.TemporaryDirectory(prefix="security-mutations-calibration-") as temporary:
        directory = Path(temporary)
        source, binary = directory / "calibration.rs", directory / "calibration"
        for name, expression in (("killed", "value <= 4"), ("survived", "value <= 3"), ("unviable", '"ill-typed"')):
            source.write_text(CALIBRATION_SOURCE.replace("value < 4", expression))
            built = run_process(["rustc", "--edition=2021", "--test", "--error-format=json", str(source), "-o", str(binary)], directory, environment,
                                wall_seconds=30, cpu_seconds=20, memory_mib=2048, output_limit=MAX_BUILD_OUTPUT)
            if built.timed_out or built.output_exceeded or built.returncode < 0:
                observed[name] = "harness_error"
            elif built.returncode != 0:
                # rustc's JSON diagnostics are the same payload Cargo wraps.
                wrapped = b"\n".join(canonical({"reason": "compiler-message", "message": item}) for item in json_lines(built.stderr))
                outcome, _ = classify_build(ProcessResult(built.returncode, wrapped, b"", built.elapsed_seconds), directory, directory, "calibration.rs")
                observed[name] = outcome
            else:
                discover_test(run_process([str(binary), "rejects_boundary", "--exact", "--list"], directory, environment,
                                          wall_seconds=10, cpu_seconds=5, memory_mib=512), "rejects_boundary")
                observed[name] = classify_test(run_process([str(binary), "rejects_boundary", "--exact", "--test-threads=1"], directory, environment,
                                                          wall_seconds=10, cpu_seconds=5, memory_mib=512), "rejects_boundary")
    if observed != {outcome: outcome for outcome in ("killed", "survived", "unviable")}:
        raise HarnessError("calibration_failed")
    return observed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--report", type=Path, default=Path("target/security-mutations/report.json"))
    parser.add_argument("--target-dir", type=Path)
    parser.add_argument("--campaign-seconds", type=int, default=7200)
    parser.add_argument("--build-seconds", type=int, default=3600)
    parser.add_argument("--build-cpu-seconds", type=int, default=1800)
    parser.add_argument("--test-seconds", type=int, default=30)
    parser.add_argument("--test-cpu-seconds", type=int, default=20)
    parser.add_argument("--memory-mib", type=int, default=2048)
    parser.add_argument("--calibrate", action="store_true")
    args = parser.parse_args(argv)
    args.manifest = args.manifest or args.root / "security-mutations.json"
    args.target_dir = args.target_dir or args.root / "target/security-mutations/build"
    try:
        args.report = validate_report_path(args.report, args.root)
    except HarnessError:
        # Writing to the rejected destination would itself violate isolation.
        print("security mutation campaign: failed (unsafe_report_path)", file=sys.stderr)
        return 1
    report: dict = {"schema_version": 1, "harness_version": VERSION, "status": "failed", "reason": "incomplete_campaign",
                    "phase": "initializing", "results": [], "counts": counts([]), "limits": {
                        key: getattr(args, key) for key in ("campaign_seconds", "build_seconds", "build_cpu_seconds", "test_seconds", "test_cpu_seconds", "memory_mib")}}
    started = time.monotonic()
    try:
        checkpoint_report(args.report, report)
        if sys.platform != "linux":
            raise HarnessError("unsupported_platform")
        if any(not 1 <= getattr(args, key) <= limit for key, limit in (("campaign_seconds", 21600), ("build_seconds", 7200),
                ("build_cpu_seconds", 3600), ("test_seconds", 120), ("test_cpu_seconds", 120))) or not 512 <= args.memory_mib <= 32768:
            raise HarnessError("invalid_limits")
        if args.calibrate:
            root = args.root.resolve()
            def call(command: list[str], cwd: Path, env: dict[str, str]) -> ProcessResult:
                return run_process(command, cwd, env, wall_seconds=30, cpu_seconds=20, memory_mib=2048)
            pins, env = pin_environment(root, call)
            report.update(toolchain=pins, calibration=calibrate(env), status="passed", reason="calibration_passed", phase="complete")
        else:
            campaign(args, report)
    except HarnessError as error:
        report.update(status="failed", reason=error.category)
    except KeyboardInterrupt:
        report.update(status="failed", reason="interrupted")
    except Exception:
        report.update(status="failed", reason="unexpected_harness_error")
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 4)
        report["counts"] = counts(report["results"], report.get("expected_mutants"))
        try:
            write_report(args.report, report)
        except OSError:
            print("security mutation report could not be written", file=sys.stderr)
            return 1
    print("security mutation campaign: " + report["status"] + " (" + report["reason"] + ")")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
