#!/usr/bin/env python3
"""Bounded, dependency-free comparisons of selected pure production Rust paths.

The head-owned benchmark is compiled against both immutable Git revisions. Its
SHA-256 and zero-growth budgets are owned by the base revision. Timings describe
this runner; only stable allocation counts and allocated bytes block the gate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time

SCHEMA_VERSION = 1
INITIAL_BASE = "c0b098a08df1091fc129ae54348f022d529cfb02"
INITIAL_HARNESS_SHA256 = "0e005f7903991f9f4eb7b22cf2b56871c9a0d0a554f3d4ecf4d9a85598881f73"
HARNESS_PATH = "scripts/benchmarks/pure_paths.rs"
BUDGET_PATH = "microbench-budget.json"
SOURCE_PATHS = (
    "gateway/src/path_match.rs",
    "gateway/src/egress.rs",
    "gateway/src/rbac/matcher.rs",
)
TARGET_IDS = ("request_path", "path_prefix", "rule_path", "egress_host")
# These dataset descriptors are part of schema 1; changing them needs a reviewed
# protocol update as well as the base-owned benchmark digest.
TARGET_METADATA = {
    "request_path": {"input_cases": 16, "input_bytes": 712, "operations_per_iteration": 32, "expected_checksum": 16000},
    "path_prefix": {"input_cases": 16, "input_bytes": 867, "operations_per_iteration": 16, "expected_checksum": 7000},
    "rule_path": {"input_cases": 16, "input_bytes": 1367, "operations_per_iteration": 16, "expected_checksum": 9000},
    "egress_host": {"input_cases": 16, "input_bytes": 1118, "operations_per_iteration": 16, "expected_checksum": 8000},
}
WARMUP = 100
ITERATIONS = 1000
SAMPLES = 9
RUN_SECONDS = 120
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
RUST_FLAGS = [
    "--edition=2021", "-C", "opt-level=3", "-C", "codegen-units=1",
    "-C", "debuginfo=0", "-D", "warnings", "--check-cfg", "cfg(regression_fixture)",
]


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _json_text(text):
    def invalid_constant(value):
        raise ValueError(f"non-finite JSON value: {value}")
    def finite_float(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("non-finite JSON number")
        return parsed
    return json.loads(text, object_pairs_hook=_unique_pairs,
                      parse_constant=invalid_constant, parse_float=finite_float)


def load_json(path):
    path = Path(path)
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("JSON evidence exceeds size bound")
    return _json_text(path.read_text(encoding="utf-8"))


def _keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f"{label}: unexpected or missing fields")


def _integer(value, label, low=0, high=10**15):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label}: expected integer in [{low}, {high}]")
    return value


def _sha(value, length=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None


def validate_budget(raw):
    _keys(raw, ("schema_version", "harness_sha256", "targets"), "budget")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unsupported budget schema")
    digests = raw["harness_sha256"]
    if (not isinstance(digests, list) or not 1 <= len(digests) <= 2
            or any(not _sha(digest) for digest in digests) or len(set(digests)) != len(digests)):
        raise ValueError("budget requires one or two unique lowercase SHA-256 harness digests")
    targets = raw["targets"]
    if not isinstance(targets, list) or len(targets) != len(TARGET_IDS):
        raise ValueError("budget target set is incomplete")
    for target, expected in zip(targets, TARGET_IDS):
        _keys(target, ("id", "max_allocation_growth", "max_allocated_bytes_growth"), "budget target")
        if target["id"] != expected:
            raise ValueError("budget targets differ from the schema order")
        for key in ("max_allocation_growth", "max_allocated_bytes_growth"):
            if type(target[key]) is not int or target[key] != 0:
                raise ValueError("schema 1 permits only zero allocation growth budgets")
    return raw


def validate_result(raw):
    _keys(raw, ("schema_version", "warmup", "iterations", "samples", "targets"), "result")
    for key, expected in (("schema_version", 1), ("warmup", WARMUP),
                          ("iterations", ITERATIONS), ("samples", SAMPLES)):
        if type(raw[key]) is not int or raw[key] != expected:
            raise ValueError(f"result {key} differs from the benchmark protocol")
    targets = raw["targets"]
    if not isinstance(targets, list) or len(targets) != len(TARGET_IDS):
        raise ValueError("result target set is incomplete")
    for target, expected_id in zip(targets, TARGET_IDS):
        _keys(target, ("id", "input_cases", "input_bytes", "operations_per_iteration",
                       "expected_checksum", "allocation_samples", "timing_samples_ns"), "target")
        if target["id"] != expected_id:
            raise ValueError("result targets differ from the schema order")
        expected = TARGET_METADATA.get(expected_id)
        if expected is None:
            raise ValueError("benchmark dataset protocol has not been configured")
        for key, value in expected.items():
            _integer(target[key], key, 1)
            if target[key] != value:
                raise ValueError(f"{expected_id}: incompatible {key}")
        allocations = target["allocation_samples"]
        timings = target["timing_samples_ns"]
        if not isinstance(allocations, list) or len(allocations) != SAMPLES:
            raise ValueError(f"{expected_id}: missing allocation samples")
        if not isinstance(timings, list) or len(timings) != SAMPLES:
            raise ValueError(f"{expected_id}: missing timing samples")
        for sample in allocations:
            _keys(sample, ("allocations", "allocated_bytes", "checksum"), "allocation sample")
            for key in ("allocations", "allocated_bytes", "checksum"):
                _integer(sample[key], key)
            if sample["checksum"] != target["expected_checksum"]:
                raise ValueError(f"{expected_id}: semantic checksum differs")
        for timing in timings:
            _integer(timing, "timing_samples_ns", 1, RUN_SECONDS * 10**9)
        if any(sample != allocations[0] for sample in allocations):
            raise ValueError(f"{expected_id}: allocation samples are not deterministic")
    return raw


def compare_results(base, head, budget):
    validate_result(base)
    validate_result(head)
    validate_budget(budget)
    report = {"schema_version": 1, "status": "passed", "targets": [], "errors": []}
    for before, after, limit in zip(base["targets"], head["targets"], budget["targets"]):
        before_count, after_count = before["allocation_samples"][0], after["allocation_samples"][0]
        deltas = {key: after_count[key] - before_count[key]
                  for key in ("allocations", "allocated_bytes")}
        passed = (deltas["allocations"] <= limit["max_allocation_growth"]
                  and deltas["allocated_bytes"] <= limit["max_allocated_bytes_growth"])
        timing = {}
        for label, result in (("base", before), ("head", after)):
            values = result["timing_samples_ns"]
            median = statistics.median(values)
            timing[label] = {"median_ns": median, "min_ns": min(values), "max_ns": max(values),
                             "relative_range": (max(values) - min(values)) / median}
        timing["median_change_ratio"] = timing["head"]["median_ns"] / timing["base"]["median_ns"] - 1
        report["targets"].append({"id": before["id"], "status": "passed" if passed else "failed",
                                   "base": before_count, "head": after_count, "growth": deltas,
                                   "budget": limit, "timing_informational": timing})
        if not passed:
            report["status"] = "failed"
            report["errors"].append(f"{before['id']}: allocation growth exceeds the base-owned budget")
    return report



def validate_envelope(raw):
    _keys(raw, ("schema_version", "context", "revision", "source_sha256", "projection_sha256", "regression_fixture", "result"), "saved result")
    if type(raw["regression_fixture"]) is not bool:
        raise ValueError("invalid saved fixture marker")
    if type(raw["schema_version"]) is not int or raw["schema_version"] != 1 or not _sha(raw["revision"], 40):
        raise ValueError("invalid saved result schema or commit")
    context = raw["context"]
    _keys(context, ("rust_ci", "rustc_vv", "rustc_flags", "harness_sha256", "machine",
                    "warmup", "iterations", "samples"), "saved context")
    if not isinstance(context["rust_ci"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", context["rust_ci"]):
        raise ValueError("saved context lacks an exact compiler pin")
    if (not isinstance(context["rustc_vv"], str) or len(context["rustc_vv"]) > 4096
            or not re.search(r"^release: " + re.escape(context["rust_ci"]) + r"$", context["rustc_vv"], re.MULTILINE)):
        raise ValueError("saved actual compiler differs from its pin")
    if context["rustc_flags"] != RUST_FLAGS or not _sha(context["harness_sha256"]):
        raise ValueError("saved profile or benchmark digest is invalid")
    for key, expected in (("warmup", WARMUP), ("iterations", ITERATIONS), ("samples", SAMPLES)):
        if type(context[key]) is not int or context[key] != expected:
            raise ValueError("saved measurement protocol differs")
    machine = context["machine"]
    required = {"platform", "machine", "logical_cpus", "python"}
    optional = {"cpu_affinity", "cpu_model", "cgroup_cpu_max", "cgroup_memory_max"}
    if not isinstance(machine, dict) or not required <= set(machine) or set(machine) - required - optional:
        raise ValueError("saved machine metadata is missing or unsupported")
    _integer(machine["logical_cpus"], "logical_cpus", 1, 65536)
    for key, value in machine.items():
        if key == "logical_cpus":
            continue
        if key == "cpu_affinity":
            if not isinstance(value, list) or not value or len(value) > 65536:
                raise ValueError("invalid saved CPU affinity")
            for cpu in value:
                _integer(cpu, "cpu_affinity", 0, 65535)
            if value != sorted(set(value)):
                raise ValueError("invalid saved CPU affinity order")
        elif not isinstance(value, str) or not 1 <= len(value) <= 4096:
            raise ValueError("invalid saved machine metadata")
    for key, paths in (("source_sha256", SOURCE_PATHS),
                       ("projection_sha256", ("path_match.rs", "egress.rs", "rule_path.rs"))):
        _keys(raw[key], paths, key)
        if any(not _sha(digest) for digest in raw[key].values()):
            raise ValueError("invalid saved source digest")
    validate_result(raw["result"])
    return raw


def compare_saved_results(base, head, budget):
    validate_envelope(base)
    validate_envelope(head)
    validate_budget(budget)
    if base["regression_fixture"] or head["regression_fixture"]:
        raise ValueError("deliberate regression fixtures cannot be used as normal comparison evidence")
    if base["context"] != head["context"]:
        raise ValueError("saved results have incompatible compiler, profile, dataset or runner metadata")
    if head["context"]["harness_sha256"] not in budget["harness_sha256"]:
        raise ValueError("saved benchmark differs from the base-owned budget")
    report = compare_results(base["result"], head["result"], budget)
    report["base"] = base["revision"]
    report["head"] = head["revision"]
    report["context"] = base["context"]
    return report


def mask_rust(source):
    """Mask comments and literals without moving offsets; reject incomplete text.

    This is deliberately a narrow lexical scanner, not a Rust parser. Rustc
    remains authoritative for syntax/types. Unsupported attributes, items and
    dependencies are rejected separately rather than stubbed out for a build.
    """
    chars = list(source)
    length, index = len(source), 0
    raw_pattern = re.compile(r'(?:br|cr|r)(#+)?"')
    char_pattern = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|[^\n])|[^'\\\n])'")
    lifetime_pattern = re.compile(r"'[A-Za-z_][A-Za-z0-9_]*")

    def blank(start, end):
        for position in range(start, end):
            if chars[position] != "\n":
                chars[position] = " "

    while index < length:
        start = index
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = length if end < 0 else end
            blank(start, index)
        elif source.startswith("/*", index):
            index += 2
            nesting = 1
            while index < length and nesting:
                if source.startswith("/*", index):
                    nesting += 1
                    index += 2
                elif source.startswith("*/", index):
                    nesting -= 1
                    index += 2
                else:
                    index += 1
            if nesting:
                raise ValueError("unterminated Rust block comment")
            blank(start, index)
        else:
            raw = raw_pattern.match(source, index)
            if raw and (index == 0 or not (source[index - 1].isalnum() or source[index - 1] == "_")):
                marker = '"' + (raw.group(1) or "")
                end = source.find(marker, index + len(raw.group(0)))
                if end < 0:
                    raise ValueError("unterminated Rust raw string")
                index = end + len(marker)
                blank(start, index)
            elif source[index] == '"':
                index += 1
                while index < length:
                    if source[index] == "\\":
                        index += 2
                    elif source[index] == '"':
                        index += 1
                        break
                    else:
                        index += 1
                else:
                    raise ValueError("unterminated Rust string")
                blank(start, index)
            elif source[index] == "'":
                # A lifetime ('a, '_) is not a character literal. Literal
                # escapes may contain more than one source character.
                char = char_pattern.match(source, index)
                if char:
                    index += len(char.group(0))
                    blank(start, index)
                elif lifetime_pattern.match(source, index):
                    index += 1
                else:
                    raise ValueError("unsupported Rust character or lifetime")
            else:
                index += 1
    return "".join(chars)


def _depths(masked):
    stack = []
    depths = []
    for char in masked:
        depths.append(len(stack))
        if char in "{([":
            stack.append(char)
        elif char in "})]":
            if not stack or stack.pop() != {"}": "{", ")": "(", "]": "["}[char]:
                raise ValueError("unbalanced Rust delimiters")
    if stack:
        raise ValueError("unbalanced Rust delimiters")
    return depths


def _production_prefix(source):
    masked = mask_rust(source)
    depths = _depths(masked)
    markers = [m for m in re.finditer(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]", masked)
               if depths[m.start()] == 0]
    if len(markers) == 2:
        # The path helper also has a separate property-test module. Strip it
        # from the projection only when its complete declaration is known.
        property_module = masked[markers[0].end():markers[1].start()]
        if not re.fullmatch(
            r"\s*#\[\s*path\s*=\s*\]\s*mod\s+property_tests\s*;\s*",
            property_module,
        ):
            raise ValueError("unexpected test module before the trailing tests module")
    elif len(markers) != 1:
        raise ValueError("expected one or two top-level test-module boundaries")
    marker = markers[-1]
    if not re.match(r"\s*mod\s+tests\s*\{", masked[marker.end():]):
        raise ValueError("test boundary is not the trailing tests module")
    opening = masked.index("{", marker.end())
    closing = next((i for i in range(opening + 1, len(masked))
                    if masked[i] == "}" and depths[i] == 1), None)
    if closing is None or masked[closing + 1:].strip():
        raise ValueError("production items follow the tests module")
    return source[:markers[0].start()]


def _top_function(source, name):
    masked = mask_rust(source)
    depths = _depths(masked)
    matches = list(re.finditer(r"\bfn\s+" + re.escape(name) + r"\s*\(", masked))
    if len(matches) != 1 or depths[matches[0].start()] != 0:
        raise ValueError(f"{name}: expected one unconditional top-level function")
    match = matches[0]
    start = match.start()
    previous = 0
    for position in range(start):
        if (masked[position] == ";" and depths[position] == 0
                or masked[position] == "}" and depths[position] == 1):
            previous = position + 1
    prefix = masked[previous:start].strip()
    if prefix not in ("", "pub", "pub(crate)"):
        raise ValueError(f"{name}: unsupported attributes or item prefix")
    opening = next((i for i in range(match.end(), len(masked))
                    if masked[i] == "{" and depths[i] == 0), None)
    if opening is None:
        raise ValueError(f"{name}: missing function body")
    closing = next((i for i in range(opening + 1, len(masked))
                    if masked[i] == "}" and depths[i] == 1), None)
    if closing is None:
        raise ValueError(f"{name}: missing function end")
    # Retain visibility, but omit preceding comments which could contain an
    # inner doc comment that changes meaning in the projected crate.
    actual_start = start if not prefix else masked.rfind(prefix, previous, start)
    return source[actual_start:closing + 1]


def _check_projection(source, allow_derives=False):
    masked = mask_rust(source)
    if re.search(r"\b(?:microbench_\w*|Microbench\w*)\b", masked):
        raise ValueError("projected source uses the reserved benchmark wrapper namespace")
    if re.search(r"\b(?:use|extern|mod|unsafe|static|async)\b", masked):
        raise ValueError("projected source gained an unsupported dependency or item")
    if re.search(r"\b(?:std|core|alloc|crate|super)\s*::", masked):
        raise ValueError("projected source gained an unsupported qualified dependency")
    if allow_derives:
        masked = re.sub(r"#\[derive\(Debug, Clone(?:, PartialEq, Eq)?\)\]", "", masked)
    if "#" in masked:
        raise ValueError("projected source has an unsupported attribute")
    for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*!\s*[({[]", masked):
        if name not in ("matches", "vec"):
            raise ValueError(f"projected source gained an unsupported macro: {name}")


def project_sources(sources):
    for source in SOURCE_PATHS:
        masked = mask_rust(sources[source])
        depths = _depths(masked)
        if any(depths[match.start()] == 0 for match in re.finditer(r"#\s*!\s*\[", masked)):
            raise ValueError("selected source has an unsupported inner attribute")
    path = _production_prefix(sources[SOURCE_PATHS[0]])
    path = re.sub(r"\A//![^\n]*(?:\n|$)", "", path)
    for name in ("exempt_path_matches", "path_prefix_matches", "is_unsafe_request_path"):
        _top_function(path, name)
    _check_projection(path)
    egress = _top_function(sources[SOURCE_PATHS[1]], "host_glob_matches")
    _check_projection(egress)
    matcher = _production_prefix(sources[SOURCE_PATHS[2]])
    masked = mask_rust(matcher)
    anchor = "#[derive(Debug, Clone)]\nenum MethodMatcher {"
    positions = [match.start() for match in re.finditer(re.escape(anchor), masked)]
    if len(positions) != 1 or _depths(masked)[positions[0]] != 0:
        raise ValueError("rule matcher projection anchor changed")
    # Attributes just before the anchor still apply to MethodMatcher and must
    # not be stripped away by slicing at its derive attribute.
    before = masked[:positions[0]].rstrip()
    if not before.endswith("}"):
        raise ValueError("rule matcher projection gained a preceding attribute")
    rule = matcher[positions[0]:]
    _check_projection(rule, allow_derives=True)
    for name in ("absolute_path_segments", "path_segments_match", "is_capture_segment",
                 "has_capture_delimiter", "is_valid_capture_name"):
        _top_function(rule, name)
    return {"path_match.rs": path, "egress.rs": egress + "\n", "rule_path.rs": rule}


def repo_root():
    result = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True,
                            text=True, timeout=10, check=True)
    return Path(result.stdout.strip())


def _git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, timeout=10)
    if result.returncode:
        raise ValueError("Git object lookup failed: " + " ".join(args))
    if len(result.stdout) > 8 * 1024 * 1024:
        raise ValueError("Git object exceeds the benchmark source bound")
    return result.stdout.decode("utf-8")


def resolve_commit(root, revision):
    if not _sha(revision, 40):
        raise ValueError("revision must be an explicit lowercase full 40-character commit SHA")
    actual = _git(root, "rev-parse", "--verify", revision + "^{commit}").strip()
    if actual != revision:
        raise ValueError("revision does not identify the requested commit")
    return actual


def _blob(root, revision, path):
    return _git(root, "show", revision + ":" + path)


def _has_blob(root, revision, path):
    return subprocess.run(["git", "-C", str(root), "cat-file", "-e", revision + ":" + path],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=10).returncode == 0


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _prepare_output(path):
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=True)
    if any(entry.name != "workflow.json" for entry in path.iterdir()):
        raise ValueError("output directory already contains evidence; choose a fresh directory")
    return path


def _bounded(command, directory, label, seconds, deadline, env=None):
    timeout = min(seconds, deadline - time.monotonic())
    if timeout <= 0:
        raise RuntimeError("benchmark exceeded its total runtime budget")
    stdout = directory / (label + ".stdout.log")
    stderr = directory / (label + ".stderr.log")
    started = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(command, cwd=directory, env=env, stdout=out, stderr=err,
                                   start_new_session=os.name == "posix")
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    raise RuntimeError(f"{label}: process exceeded its runtime bound")
                if stdout.stat().st_size > MAX_LOG_BYTES or stderr.stat().st_size > MAX_LOG_BYTES:
                    raise RuntimeError(f"{label}: process exceeded its output bound")
                time.sleep(0.02)
        except BaseException:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=5)
            raise
    if stdout.stat().st_size > MAX_LOG_BYTES or stderr.stat().st_size > MAX_LOG_BYTES:
        raise RuntimeError(f"{label}: process exceeded its output bound")
    if process.returncode != 0:
        raise RuntimeError(f"{label}: process failed with exit code {process.returncode}; see raw logs")
    return stdout.read_text(encoding="utf-8"), time.monotonic() - started


def _machine():
    result = {"platform": platform.platform(), "machine": platform.machine(),
              "logical_cpus": os.cpu_count(), "python": platform.python_version()}
    if hasattr(os, "sched_getaffinity"):
        result["cpu_affinity"] = sorted(os.sched_getaffinity(0))
    cpu = Path("/proc/cpuinfo")
    if cpu.exists():
        match = re.search(r"^model name\s*:\s*(.*)$", cpu.read_text(), re.MULTILINE)
        result["cpu_model"] = match.group(1) if match else "unknown"
    for name in ("cpu.max", "memory.max"):
        path = Path("/sys/fs/cgroup") / name
        if path.exists():
            result["cgroup_" + name.replace(".", "_")] = path.read_text().strip()
    return result


def _configuration(root, base, head, output, deadline):
    pins = []
    for revision in (base, head):
        manifest = _json_text(_blob(root, revision, "build-tools.json"))
        if not isinstance(manifest, dict) or "rust_ci" not in manifest:
            raise ValueError("build-tools manifest lacks its Rust CI pin")
        pins.append(manifest["rust_ci"])
    base_pin, head_pin = pins
    if any(not isinstance(pin, str) or not re.fullmatch(r"\d+\.\d+\.\d+", pin)
           for pin in (base_pin, head_pin)):
        raise ValueError("base and head must declare exact Rust CI toolchains")
    harness = _blob(root, head, HARNESS_PATH)
    # Validate the proposed budget as well, even when the current comparison is
    # governed by the previous budget. This supports reviewed two-PR updates.
    proposed_budget = validate_budget(_json_text(_blob(root, head, BUDGET_PATH)))
    if _has_blob(root, base, BUDGET_PATH):
        budget = validate_budget(_json_text(_blob(root, base, BUDGET_PATH)))
        owner = base
    elif base == INITIAL_BASE:
        if proposed_budget["harness_sha256"] != [INITIAL_HARNESS_SHA256]:
            raise ValueError("initial adoption requires the exact reviewed initial benchmark digest")
        budget = proposed_budget
        owner = "first-adoption:" + base
    else:
        raise ValueError("base budget is missing outside the single reviewed adoption commit")
    if _digest(harness) not in budget["harness_sha256"]:
        raise ValueError("head benchmark differs from the base-owned harness digest")
    if _digest(harness) not in proposed_budget["harness_sha256"]:
        raise ValueError("proposed budget must retain the active head benchmark digest")
    rustup = shutil.which("rustup")
    if rustup is None:
        raise ValueError("the pinned Rust toolchain must already be installed (rustup missing)")
    compiler, _ = _bounded([rustup, "which", "--toolchain", head_pin, "rustc"], output,
                           "toolchain", 10, deadline)
    compiler = compiler.strip()
    if not Path(compiler).is_file():
        raise ValueError("pinned Rust compiler is not installed")
    version, _ = _bounded([compiler, "-Vv"], output, "rustc-version", 10, deadline)
    if not re.search(r"^release: " + re.escape(head_pin) + r"$", version, re.MULTILINE):
        raise ValueError("actual Rust compiler differs from the pinned version")
    context = {"base": base, "head": head, "budget_owner": owner, "budget": budget,
               "harness_sha256": _digest(harness), "rust_ci": head_pin, "rustc_vv": version,
               "declared_source_rust_ci": {"base": base_pin, "head": head_pin},
               "rustc_flags": RUST_FLAGS, "machine": _machine(), "runtime_budget_seconds": RUN_SECONDS,
               "warmup": WARMUP, "iterations": ITERATIONS, "samples": SAMPLES,
               "timing_policy": "informational; relative range is descriptive, not a confidence interval"}
    _write_json(output / "context.json", context)
    return compiler, harness, budget, context


def _measure(root, revision, label, output, compiler, harness, context, deadline, regression=False):
    directory = output / label
    directory.mkdir()
    source_dir = directory / "source"
    source_dir.mkdir()
    sources = {name: _blob(root, revision, name) for name in SOURCE_PATHS}
    projected = project_sources(sources)
    for name, text in projected.items():
        (source_dir / name).write_text(text, encoding="utf-8")
    selected = "\n".join(projected.values())
    (source_dir / "selected.rs").write_text(selected, encoding="utf-8")
    (source_dir / "harness.rs").write_text(harness, encoding="utf-8")
    metadata = {"revision": revision, "source_sha256": {name: _digest(text) for name, text in sources.items()},
                "projection_sha256": {name: _digest(text) for name, text in projected.items()},
                "selected_sha256": _digest(selected), "harness_sha256": _digest(harness),
                "regression_fixture": regression}
    _write_json(directory / "source.json", metadata)
    binary = directory / ("benchmark.exe" if os.name == "nt" else "benchmark")
    command = [compiler, str(source_dir / "harness.rs"), *RUST_FLAGS, "-o", str(binary)]
    if regression:
        command += ["--cfg", "regression_fixture"]
    # Direct rustc ignores Cargo flags/wrappers. Also drop compiler bootstrap and
    # preload hooks so the recorded flags describe the actual invocation.
    environment = {key: value for key, value in os.environ.items()
                   if key not in ("RUSTC_BOOTSTRAP", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES")}
    _, compile_seconds = _bounded(command, directory, "compile", 30, deadline, environment)
    text, run_seconds = _bounded([str(binary)], directory, "run", 15, deadline, environment)
    (output / (label + ".raw.json")).write_text(text, encoding="utf-8")
    result = validate_result(load_json(output / (label + ".raw.json")))
    common = {key: context[key] for key in ("rust_ci", "rustc_vv", "rustc_flags", "harness_sha256",
                                          "machine", "warmup", "iterations", "samples")}
    envelope = {"schema_version": 1, "context": common, "revision": revision,
                "regression_fixture": regression,
                "source_sha256": metadata["source_sha256"],
                "projection_sha256": metadata["projection_sha256"], "result": result}
    validate_envelope(envelope)
    _write_json(output / (label + ".json"), envelope)
    metadata.update({"compile_seconds": compile_seconds, "run_seconds": run_seconds,
                     "command": command})
    _write_json(directory / "source.json", metadata)
    return envelope


def run_comparison(base, head, output, root=None):
    output = _prepare_output(output)
    started = time.monotonic()
    deadline = started + RUN_SECONDS
    summary = {"schema_version": 1, "status": "failed", "targets": [], "errors": []}
    try:
        root = Path(root) if root is not None else repo_root()
        base, head = resolve_commit(root, base), resolve_commit(root, head)
        compiler, harness, budget, context = _configuration(root, base, head, output, deadline)
        before = _measure(root, base, "base", output, compiler, harness, context, deadline)
        after = _measure(root, head, "head", output, compiler, harness, context, deadline)
        summary = compare_saved_results(before, after, budget)
        summary["context"] = context
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError, UnicodeError, KeyError) as error:
        summary["errors"].append(str(error))
    finally:
        summary["elapsed_seconds"] = time.monotonic() - started
        if summary["elapsed_seconds"] > RUN_SECONDS:
            summary["status"] = "failed"
            summary["errors"].append("comparison exceeded the total runtime budget")
        _write_json(output / "summary.json", summary)
    return summary


def self_test(revision, output, root=None):
    output = _prepare_output(output)
    started = time.monotonic()
    deadline = started + RUN_SECONDS
    summary = {"schema_version": 1, "status": "failed", "errors": []}
    try:
        root = Path(root) if root is not None else repo_root()
        revision = resolve_commit(root, revision)
        compiler, harness, budget, context = _configuration(root, revision, revision, output, deadline)
        baseline = _measure(root, revision, "base", output, compiler, harness, context, deadline)
        neutral = _measure(root, revision, "neutral", output, compiler, harness, context, deadline)
        regression = _measure(root, revision, "regression", output, compiler, harness, context, deadline, regression=True)
        neutral_report = compare_saved_results(baseline, neutral, budget)
        regression_report = compare_results(baseline["result"], regression["result"], budget)
        regression_report["deliberate_fixture"] = True
        _write_json(output / "neutral-comparison.json", neutral_report)
        _write_json(output / "regression-comparison.json", regression_report)
        if neutral_report["status"] != "passed" or regression_report["status"] != "failed":
            raise ValueError("neutral rebuild or deliberate allocation regression was not detected correctly")
        summary.update({"status": "passed", "neutral": neutral_report, "regression": regression_report,
                        "context": context})
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError, UnicodeError, KeyError) as error:
        summary["errors"].append(str(error))
    finally:
        summary["elapsed_seconds"] = time.monotonic() - started
        if summary["elapsed_seconds"] > RUN_SECONDS:
            summary["status"] = "failed"
            summary["errors"].append("self-test exceeded the total runtime budget")
        _write_json(output / "summary.json", summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="compare two immutable full Git commit SHAs")
    run.add_argument("--base", required=True)
    run.add_argument("--head", required=True)
    run.add_argument("--output", required=True)
    compare = commands.add_parser("compare", help="validate and compare saved raw binary results")
    compare.add_argument("--base", required=True)
    compare.add_argument("--head", required=True)
    compare.add_argument("--budget", default=BUDGET_PATH)
    compare.add_argument("--output", required=True)
    fixture = commands.add_parser("self-test", help="rebuild neutral and deliberately allocating local fixtures")
    fixture.add_argument("--revision", required=True)
    fixture.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result = run_comparison(args.base, args.head, args.output)
        elif args.command == "self-test":
            result = self_test(args.revision, args.output)
        else:
            try:
                result = compare_saved_results(load_json(args.base), load_json(args.head), load_json(args.budget))
            except (ValueError, OSError, KeyError) as error:
                result = {"schema_version": 1, "status": "failed", "targets": [], "errors": [str(error)]}
            _write_json(args.output, result)
        print(json.dumps({"status": result["status"], "errors": result["errors"]}, sort_keys=True))
        return 0 if result["status"] == "passed" else 1
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f"microbench: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
