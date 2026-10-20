#!/usr/bin/env python3
"""Bounded, dependency-free comparisons of selected production Rust paths.

The head-owned pure-path benchmark is compiled against both immutable Git
revisions. Its SHA-256 and zero-growth budgets are owned by the base revision.
The authoritative HTTP policy decision is measured inside each revision's own
gateway test binary, whose benchmark digest the budget approves in the same way.
Timings describe this runner; only stable allocation counts and allocated bytes
block the gate.
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
import tarfile
import tempfile
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
# The pure-path stage keeps its original acceptance budget inside the total.
PURE_SECONDS = 120
RUN_SECONDS = 480
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 1024 * 1024
RUST_FLAGS = [
    "--edition=2021", "-C", "opt-level=3", "-C", "codegen-units=1",
    "-C", "debuginfo=0", "-D", "warnings", "--check-cfg", "cfg(regression_fixture)",
]

# The authoritative HTTP policy decision runs in the gateway's own test binary:
# the crate is binary-only, so the benchmark is an ignored test whose counting
# global allocator exists only under cfg(test). Each revision builds its own copy.
KERNEL_TARGET = "http_policy"
KERNEL_HARNESS_PATH = "gateway/tests/support/policy_benchmark.rs"
KERNEL_MAIN_PATH = "gateway/src/main.rs"
KERNEL_ATTRIBUTES = '#[cfg(test)]\n#[path = "../tests/support/policy_benchmark.rs"]\n'
KERNEL_MODULE = "mod policy_benchmark;"
KERNEL_TEST = "policy_benchmark::http_policy_evaluation"
KERNEL_RESULT_ENV = "GREENGATEWAY_MICROBENCH_RESULT"
KERNEL_REGRESSION_ENV = "GREENGATEWAY_MICROBENCH_REGRESSION_FIXTURE"
KERNEL_WARMUP = 10
KERNEL_ITERATIONS = 100
KERNEL_SAMPLES = 9
# Part of the kernel protocol, like TARGET_METADATA for the pure paths.
KERNEL_METADATA = {"input_cases": 17, "input_bytes": 1459, "operations_per_iteration": 17,
                   "expected_checksum": 1700}
CARGO_ARGUMENTS = ["test", "-p", "gateway", "--bin", "gateway", "--locked", "--no-run",
                   "--message-format=json"]
# Cargo's default test profile, without debug info: allocation behaviour is
# unchanged and both builds fit the job's time limit.
CARGO_PROFILE_ENV = {"CARGO_INCREMENTAL": "0", "CARGO_PROFILE_DEV_DEBUG": "0"}
# gateway/build.rs builds and embeds the admin UI on every compile and accepts
# only the Node/npm pins its own tree declares. Both trees take these UI build
# inputs from the head, as both take the head's compiler; no Rust source or file
# included by Rust source is replaced, and the measured decision never reads them.
UI_BUILD_INPUTS = ("admin-ui", ".node-version", ".npm-version", "build-tools.json",
                   "npm-script-policy.json", "scripts/npm-script-policy.mjs")
CARGO_CONFIG_PATHS = (".cargo/config", ".cargo/config.toml")
STRIPPED_ENV = ("RUSTFLAGS", "RUSTDOCFLAGS", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                "RUSTC_BOOTSTRAP", "RUSTUP_TOOLCHAIN", "CARGO_INCREMENTAL", "LD_PRELOAD",
                "DYLD_INSERT_LIBRARIES")
STRIPPED_ENV_PREFIXES = ("CARGO_BUILD_", "CARGO_PROFILE_", "CARGO_TARGET_", "CARGO_ENCODED_",
                         "CARGO_UNSTABLE_", "GREENGATEWAY_MICROBENCH_")
BUILD_SECONDS = 300
KERNEL_PROCESS_SECONDS = 60
MAX_BUILD_LOG_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024


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


def _harness_digests(digests, label):
    if (not isinstance(digests, list) or not 1 <= len(digests) <= 2
            or any(not _sha(digest) for digest in digests) or len(set(digests)) != len(digests)):
        raise ValueError(f"budget requires one or two unique lowercase SHA-256 {label} digests")


def validate_budget(raw):
    """Schema 1 budgets the four pure paths. Schema 2 also budgets `http_policy`
    and approves the digests of the gateway test-binary benchmark."""
    if not isinstance(raw, dict) or type(raw.get("schema_version")) is not int:
        raise ValueError("unsupported budget schema")
    if raw["schema_version"] == 1:
        _keys(raw, ("schema_version", "harness_sha256", "targets"), "budget")
        identifiers = TARGET_IDS
    elif raw["schema_version"] == 2:
        _keys(raw, ("schema_version", "harness_sha256", "kernel_harness_sha256", "targets"), "budget")
        _harness_digests(raw["kernel_harness_sha256"], "kernel harness")
        identifiers = TARGET_IDS + (KERNEL_TARGET,)
    else:
        raise ValueError("unsupported budget schema")
    _harness_digests(raw["harness_sha256"], "harness")
    targets = raw["targets"]
    if not isinstance(targets, list) or len(targets) != len(identifiers):
        raise ValueError("budget target set is incomplete")
    for target, expected in zip(targets, identifiers):
        _keys(target, ("id", "max_allocation_growth", "max_allocated_bytes_growth"), "budget target")
        if target["id"] != expected:
            raise ValueError("budget targets differ from the schema order")
        for key in ("max_allocation_growth", "max_allocated_bytes_growth"):
            if type(target[key]) is not int or target[key] != 0:
                raise ValueError("budgets permit only zero allocation growth")
    return raw


def budgets_kernel(budget):
    return budget["schema_version"] == 2


def _validate_targets(targets, identifiers, metadata, samples, maximum_ns):
    if not isinstance(targets, list) or len(targets) != len(identifiers):
        raise ValueError("result target set is incomplete")
    for target, expected_id in zip(targets, identifiers):
        _keys(target, ("id", "input_cases", "input_bytes", "operations_per_iteration",
                       "expected_checksum", "allocation_samples", "timing_samples_ns"), "target")
        if target["id"] != expected_id:
            raise ValueError("result targets differ from the schema order")
        expected = metadata.get(expected_id)
        if expected is None:
            raise ValueError("benchmark dataset protocol has not been configured")
        for key, value in expected.items():
            _integer(target[key], key, 1)
            if target[key] != value:
                raise ValueError(f"{expected_id}: incompatible {key}")
        allocations = target["allocation_samples"]
        timings = target["timing_samples_ns"]
        if not isinstance(allocations, list) or len(allocations) != samples:
            raise ValueError(f"{expected_id}: missing allocation samples")
        if not isinstance(timings, list) or len(timings) != samples:
            raise ValueError(f"{expected_id}: missing timing samples")
        for sample in allocations:
            _keys(sample, ("allocations", "allocated_bytes", "checksum"), "allocation sample")
            for key in ("allocations", "allocated_bytes", "checksum"):
                _integer(sample[key], key)
            if sample["checksum"] != target["expected_checksum"]:
                raise ValueError(f"{expected_id}: semantic checksum differs")
        for timing in timings:
            _integer(timing, "timing_samples_ns", 1, maximum_ns)
        if any(sample != allocations[0] for sample in allocations):
            raise ValueError(f"{expected_id}: allocation samples are not deterministic")


def validate_result(raw):
    _keys(raw, ("schema_version", "warmup", "iterations", "samples", "targets"), "result")
    for key, expected in (("schema_version", 1), ("warmup", WARMUP),
                          ("iterations", ITERATIONS), ("samples", SAMPLES)):
        if type(raw[key]) is not int or raw[key] != expected:
            raise ValueError(f"result {key} differs from the benchmark protocol")
    _validate_targets(raw["targets"], TARGET_IDS, TARGET_METADATA, SAMPLES, PURE_SECONDS * 10**9)
    return raw


def validate_kernel_result(raw, regression=False):
    """Validate the gateway test binary's report, including its fixture marker."""
    _keys(raw, ("schema_version", "harness", "regression_fixture", "warmup", "iterations",
                "samples", "targets"), "kernel result")
    if raw["harness"] != "gateway-test-binary":
        raise ValueError("kernel result comes from an unexpected harness")
    if type(raw["regression_fixture"]) is not bool or raw["regression_fixture"] is not regression:
        raise ValueError("kernel result fixture marker differs from the requested run")
    for key, expected in (("schema_version", 1), ("warmup", KERNEL_WARMUP),
                          ("iterations", KERNEL_ITERATIONS), ("samples", KERNEL_SAMPLES)):
        if type(raw[key]) is not int or raw[key] != expected:
            raise ValueError(f"kernel result {key} differs from the benchmark protocol")
    _validate_targets(raw["targets"], (KERNEL_TARGET,), {KERNEL_TARGET: KERNEL_METADATA},
                      KERNEL_SAMPLES, KERNEL_PROCESS_SECONDS * 10**9)
    return raw


def _compare_target(before, after, limit):
    """One target's allocation growth against its budget; timing stays informational."""
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
    return {"id": before["id"], "status": "passed" if passed else "failed",
            "base": before_count, "head": after_count, "growth": deltas,
            "budget": limit, "timing_informational": timing}


def compare_results(base, head, budget):
    validate_result(base)
    validate_result(head)
    validate_budget(budget)
    report = {"schema_version": 1, "status": "passed", "targets": [], "errors": []}
    for before, after, limit in zip(base["targets"], head["targets"],
                                    budget["targets"][:len(TARGET_IDS)]):
        entry = _compare_target(before, after, limit)
        report["targets"].append(entry)
        if entry["status"] != "passed":
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
    _validate_compiler(context, ("rustc_vv",))
    if context["rustc_flags"] != RUST_FLAGS or not _sha(context["harness_sha256"]):
        raise ValueError("saved profile or benchmark digest is invalid")
    for key, expected in (("warmup", WARMUP), ("iterations", ITERATIONS), ("samples", SAMPLES)):
        if type(context[key]) is not int or context[key] != expected:
            raise ValueError("saved measurement protocol differs")
    _validate_machine(context["machine"])
    for key, paths in (("source_sha256", SOURCE_PATHS),
                       ("projection_sha256", ("path_match.rs", "egress.rs", "rule_path.rs"))):
        _keys(raw[key], paths, key)
        if any(not _sha(digest) for digest in raw[key].values()):
            raise ValueError("invalid saved source digest")
    validate_result(raw["result"])
    return raw


def _validate_compiler(context, reports):
    if not isinstance(context["rust_ci"], str) or not re.fullmatch(r"\d+\.\d+\.\d+", context["rust_ci"]):
        raise ValueError("saved context lacks an exact compiler pin")
    release = r"^release: " + re.escape(context["rust_ci"]) + r"$"
    for key in reports:
        if (not isinstance(context[key], str) or len(context[key]) > 4096
                or not re.search(release, context[key], re.MULTILINE)):
            raise ValueError("saved actual compiler differs from its pin")


def _validate_machine(machine):
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


KERNEL_CONTEXT_KEYS = ("rust_ci", "rustc_vv", "cargo_vv", "cargo_arguments", "cargo_env", "node",
                       "npm", "machine", "warmup", "iterations", "samples")


def validate_kernel_envelope(raw, regression=False):
    """A saved gateway test-binary measurement bound to its revision, harness
    digest, actual compiler and Cargo invocation, UI tools and machine."""
    _keys(raw, ("schema_version", "context", "revision", "harness_sha256", "regression_fixture",
                "result"), "saved kernel result")
    if type(raw["regression_fixture"]) is not bool or raw["regression_fixture"] is not regression:
        raise ValueError("invalid saved kernel fixture marker")
    if (type(raw["schema_version"]) is not int or raw["schema_version"] != 1
            or not _sha(raw["revision"], 40) or not _sha(raw["harness_sha256"])):
        raise ValueError("invalid saved kernel result schema, commit or harness digest")
    context = raw["context"]
    _keys(context, KERNEL_CONTEXT_KEYS, "saved kernel context")
    _validate_compiler(context, ("rustc_vv", "cargo_vv"))
    if context["cargo_arguments"] != CARGO_ARGUMENTS or context["cargo_env"] != CARGO_PROFILE_ENV:
        raise ValueError("saved kernel build profile differs")
    for key in ("node", "npm"):
        if not isinstance(context[key], str) or not re.fullmatch(r"\d+\.\d+\.\d+", context[key]):
            raise ValueError("saved kernel UI tool versions are invalid")
    for key, expected in (("warmup", KERNEL_WARMUP), ("iterations", KERNEL_ITERATIONS),
                          ("samples", KERNEL_SAMPLES)):
        if type(context[key]) is not int or context[key] != expected:
            raise ValueError("saved kernel measurement protocol differs")
    _validate_machine(context["machine"])
    validate_kernel_result(raw["result"], regression)
    return raw


def compare_kernel_results(base, head, limit, regression_head=False):
    """Compare two kernel envelopes under one budget entry. Approval of each
    side's harness digest is the caller's policy decision, made beforehand."""
    validate_kernel_envelope(base)
    validate_kernel_envelope(head, regression_head)
    _keys(limit, ("id", "max_allocation_growth", "max_allocated_bytes_growth"), "kernel budget")
    if limit["id"] != KERNEL_TARGET:
        raise ValueError("kernel budget names another target")
    if base["context"] != head["context"]:
        raise ValueError("kernel results have incompatible compiler, build, UI tool or runner metadata")
    entry = _compare_target(base["result"]["targets"][0], head["result"]["targets"][0], limit)
    entry.update(base_revision=base["revision"], head_revision=head["revision"],
                 base_harness_sha256=base["harness_sha256"],
                 head_harness_sha256=head["harness_sha256"])
    return entry


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


def kernel_wiring(main_source):
    """Whether `main.rs` declares the benchmark module with its reviewed wiring.

    False only when nothing names the module. Any other declaration, a second
    one, or extra attributes that could disable or redirect it are errors: the
    harness digest only means something if this exact file is what compiles.
    """
    masked = mask_rust(main_source)
    depths = _depths(masked)
    declarations = list(re.finditer(r"\bmod\s+policy_benchmark\b", masked))
    if not declarations:
        if re.search(r"\bpolicy_benchmark\b", masked):
            raise ValueError("benchmark module is referenced without its reviewed declaration")
        return False
    if len(declarations) != 1:
        raise ValueError("benchmark module is declared more than once")
    module = declarations[0].start()
    start = module - len(KERNEL_ATTRIBUTES)
    if (depths[module] != 0 or start < 0
            or main_source[start:module + len(KERNEL_MODULE)] != KERNEL_ATTRIBUTES + KERNEL_MODULE
            or not masked.startswith("#[cfg(test)]", start)):
        raise ValueError("benchmark module declaration differs from the reviewed test-only wiring")
    preceding = masked[:start].rstrip()
    if preceding and preceding[-1] not in ";}":
        raise ValueError("benchmark module declaration gained an attribute or item prefix")
    return True


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


def _bounded(command, directory, label, seconds, deadline, env=None, cwd=None, max_bytes=None):
    """Run one process with a wall-clock and output bound; logs stay in `directory`."""
    timeout = min(seconds, deadline - time.monotonic())
    if timeout <= 0:
        raise RuntimeError("benchmark exceeded its total runtime budget")
    limit = MAX_LOG_BYTES if max_bytes is None else max_bytes
    stdout = directory / (label + ".stdout.log")
    stderr = directory / (label + ".stderr.log")
    started = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(command, cwd=directory if cwd is None else cwd, env=env,
                                   stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                   start_new_session=os.name == "posix")
        try:
            while process.poll() is None:
                if time.monotonic() - started > timeout:
                    raise RuntimeError(f"{label}: process exceeded its runtime bound")
                if stdout.stat().st_size > limit or stderr.stat().st_size > limit:
                    raise RuntimeError(f"{label}: process exceeded its output bound")
                time.sleep(0.02)
        except BaseException:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=5)
            raise
    if stdout.stat().st_size > limit or stderr.stat().st_size > limit:
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
               "proposed_budget": proposed_budget,
               "harness_sha256": _digest(harness), "rust_ci": head_pin, "rustc_vv": version,
               "declared_source_rust_ci": {"base": base_pin, "head": head_pin},
               "rustc_flags": RUST_FLAGS, "machine": _machine(), "runtime_budget_seconds": RUN_SECONDS,
               "pure_path_budget_seconds": PURE_SECONDS,
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


def kernel_policy(base_budget, proposed_budget):
    """The adoption state of `http_policy`, from the two validated budgets.

    `pending`: no budget lists it. It is measured wherever the harness exists,
    and never blocks. `proposed`: only the head's budget lists it. The base must
    already carry the harness; the comparison is reported, but the base budget
    has approved nothing, so it does not block. `enforced`: the base budget
    lists it, and its zero-growth budget blocks like every pure-path target.
    """
    if budgets_kernel(base_budget):
        if not budgets_kernel(proposed_budget):
            raise ValueError("a proposed budget cannot retire the enforced http_policy target")
        return "enforced"
    return "proposed" if budgets_kernel(proposed_budget) else "pending"


def _kernel_harness(root, revision):
    """The revision's benchmark digest, or None when it predates the harness."""
    declared = kernel_wiring(_blob(root, revision, KERNEL_MAIN_PATH))
    if declared != _has_blob(root, revision, KERNEL_HARNESS_PATH):
        raise ValueError(f"{revision}: benchmark module declaration and harness file disagree")
    for path in CARGO_CONFIG_PATHS:
        if _has_blob(root, revision, path):
            raise ValueError(f"{revision}: repository Cargo configuration would change the benchmark build")
    return _digest(_blob(root, revision, KERNEL_HARNESS_PATH)) if declared else None


def _kernel_configuration(root, base, head, output, compiler, context, deadline):
    budget, proposed = context["budget"], context["proposed_budget"]
    state = kernel_policy(budget, proposed)
    digests = {"base": _kernel_harness(root, base), "head": _kernel_harness(root, head)}
    if digests["head"] is None:
        raise ValueError("head revision lacks the http_policy benchmark harness")
    if state != "pending" and digests["base"] is None:
        raise ValueError("http_policy is budgeted, but the base revision lacks its harness; "
                         "land the harness before its budget")
    # Each revision compiles its own benchmark against its own crate. Like the
    # pure-path harness, every digest that runs must be approved by the budget
    # that governs it; the head's proposal must also keep approving the head's.
    if state == "enforced":
        approvals = (("base", budget), ("head", budget), ("head", proposed))
        limit = budget["targets"][-1]
    elif state == "proposed":
        approvals = (("base", proposed), ("head", proposed))
        limit = proposed["targets"][-1]
    else:
        approvals = ()
        limit = {"id": KERNEL_TARGET, "max_allocation_growth": 0, "max_allocated_bytes_growth": 0}
    for label, policy in approvals:
        if digests[label] not in policy["kernel_harness_sha256"]:
            raise ValueError(f"{label} http_policy benchmark differs from its budget's approved digests")
    pins = _json_text(_blob(root, head, "build-tools.json"))
    if (not isinstance(pins, dict) or any(not isinstance(pins.get(key), str)
            or not re.fullmatch(r"\d+\.\d+\.\d+", pins[key]) for key in ("node", "npm"))):
        raise ValueError("head build-tools manifest lacks exact Node and npm pins")
    rustup = shutil.which("rustup")
    if rustup is None:
        raise ValueError("the pinned Rust toolchain must already be installed (rustup missing)")
    cargo, _ = _bounded([rustup, "which", "--toolchain", context["rust_ci"], "cargo"], output,
                        "cargo-toolchain", 10, deadline)
    cargo = cargo.strip()
    if not Path(cargo).is_file():
        raise ValueError("pinned Cargo is not installed")
    cargo_vv, _ = _bounded([cargo, "-vV"], output, "cargo-version", 10, deadline)
    if not re.search(r"^release: " + re.escape(context["rust_ci"]) + r"$", cargo_vv, re.MULTILINE):
        raise ValueError("actual Cargo differs from the pinned Rust version")
    for tool, expected in (("node", "v" + pins["node"]), ("npm", pins["npm"])):
        executable = shutil.which(tool)
        if executable is None:
            raise ValueError(f"the http_policy build needs the head's pinned {tool} on PATH")
        version, _ = _bounded([executable, "--version"], output, tool + "-version", 30, deadline)
        if version.strip() != expected:
            raise ValueError(f"{tool} on PATH differs from the head's pinned version")
    kernel = {"state": state, "target": KERNEL_TARGET, "test": KERNEL_TEST, "budget": limit,
              "harness_sha256": digests, "cargo": cargo, "ui_source": head,
              "ui_build_inputs": list(UI_BUILD_INPUTS),
              "context": {"rust_ci": context["rust_ci"], "rustc_vv": context["rustc_vv"],
                          "cargo_vv": cargo_vv, "cargo_arguments": CARGO_ARGUMENTS,
                          "cargo_env": CARGO_PROFILE_ENV, "node": pins["node"], "npm": pins["npm"],
                          "machine": context["machine"], "warmup": KERNEL_WARMUP,
                          "iterations": KERNEL_ITERATIONS, "samples": KERNEL_SAMPLES}}
    _write_json(output / "kernel-context.json", kernel)
    return kernel


def _extract(root, revision, destination, deadline, paths=()):
    """Write a revision's committed files, or the named subset, into `destination`."""
    if not hasattr(tarfile, "data_filter"):
        raise ValueError("this Python lacks tarfile's data extraction filter")
    timeout = min(60, deadline - time.monotonic())
    if timeout <= 0:
        raise RuntimeError("benchmark exceeded its total runtime budget")
    with tempfile.TemporaryFile() as archive:
        result = subprocess.run(["git", "-C", str(root), "archive", "--format=tar", revision,
                                 "--", *paths], stdout=archive, stderr=subprocess.DEVNULL,
                                stdin=subprocess.DEVNULL, timeout=timeout)
        if result.returncode:
            raise ValueError("Git archive failed: " + revision)
        if os.fstat(archive.fileno()).st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("revision archive exceeds the benchmark source bound")
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:") as bundle:
            bundle.extractall(destination, filter="data")


def _prepare_tree(root, revision, tree, ui_source, deadline):
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir(parents=True)
    _extract(root, revision, tree, deadline)
    if ui_source != revision:
        for name in UI_BUILD_INPUTS:
            path = tree / name
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
        _extract(root, ui_source, tree, deadline, UI_BUILD_INPUTS)
    if any((tree / name).exists() for name in CARGO_CONFIG_PATHS):
        raise ValueError("extracted tree carries Cargo configuration")


def _cargo_environment(compiler, pin, target_dir):
    """Cargo and the test binary run without inherited build overrides; the
    recorded profile and compiler then describe the actual invocation."""
    environment = {key: value for key, value in os.environ.items()
                   if key not in STRIPPED_ENV and not key.startswith(STRIPPED_ENV_PREFIXES)}
    environment.update(CARGO_PROFILE_ENV)
    environment.update({"CARGO_TARGET_DIR": str(target_dir), "RUSTC": compiler,
                        "RUSTUP_TOOLCHAIN": pin})
    return environment


def _test_executable(messages, target_dir):
    """The single gateway unit-test executable Cargo reported building."""
    executables = set()
    for line in messages.splitlines():
        if not line.strip():
            continue
        message = _json_text(line)
        if not isinstance(message, dict) or message.get("reason") != "compiler-artifact":
            continue
        target, profile = message.get("target"), message.get("profile")
        if (isinstance(target, dict) and isinstance(profile, dict)
                and target.get("name") == "gateway" and target.get("kind") == ["bin"]
                and profile.get("test") is True and isinstance(message.get("executable"), str)):
            executables.add(message["executable"])
    if len(executables) != 1:
        raise ValueError("Cargo did not report exactly one gateway test executable")
    executable = Path(executables.pop()).resolve()
    if not executable.is_file() or not executable.is_relative_to(Path(target_dir).resolve()):
        raise ValueError("gateway test executable is outside the benchmark target directory")
    return executable


def _file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _build_kernel(root, revision, label, output, compiler, kernel, digest, work, deadline):
    """Build one revision's gateway test binary and check test discovery
    against its source wiring. Returns the binary, environment and log directory."""
    directory = output / (label + "-kernel")
    directory.mkdir()
    tree = Path(work) / "trees" / label
    _prepare_tree(root, revision, tree, kernel["ui_source"], deadline)
    target_dir = Path(work) / "cargo-target"
    target_dir.mkdir(parents=True, exist_ok=True)
    environment = _cargo_environment(compiler, kernel["context"]["rust_ci"], target_dir)
    # The revisions share one target directory so dependencies build once, but
    # Cargo names a workspace member's artifacts without its source path: left
    # alone, the second tree is judged fresh and reuses the first revision's
    # gateway binary. Cleaning the gateway package makes each revision compile
    # its own source.
    _bounded([kernel["cargo"], "clean", "-p", "gateway", "--locked"], directory, "clean",
             KERNEL_PROCESS_SECONDS, deadline, environment, cwd=tree)
    command = [kernel["cargo"], *CARGO_ARGUMENTS]
    messages, build_seconds = _bounded(command, directory, "build", BUILD_SECONDS, deadline,
                                       environment, cwd=tree, max_bytes=MAX_BUILD_LOG_BYTES)
    built = _test_executable(messages, target_dir)
    # The next revision's clean removes this artifact, so measure a private copy.
    binary = Path(work) / "binaries" / label / built.name
    binary.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, binary)
    # Exact matching avoids libtest's successful zero-test behaviour.
    listing, _ = _bounded([str(binary), KERNEL_TEST, "--exact", "--ignored", "--list"], directory,
                          "list", KERNEL_PROCESS_SECONDS, deadline, environment)
    listed = listing.splitlines().count(KERNEL_TEST + ": test")
    if listed != (0 if digest is None else 1):
        raise ValueError(f"{label}: benchmark test discovery disagrees with its source wiring")
    _write_json(directory / "build.json", {
        "revision": revision, "harness_sha256": digest, "listed": listed == 1,
        "command": command, "cargo_env": CARGO_PROFILE_ENV, "tree": str(tree),
        "ui_source": kernel["ui_source"], "ui_build_inputs": kernel["ui_build_inputs"],
        "build_seconds": build_seconds, "binary_sha256": _file_digest(binary)})
    return binary, environment, directory


def _run_kernel(binary, environment, directory, label, revision, digest, kernel, output, deadline,
                regression=False):
    result_path = directory / (label + ".result.json")
    if result_path.exists():
        raise ValueError("kernel result path is not fresh")
    run_environment = dict(environment)
    run_environment[KERNEL_RESULT_ENV] = str(result_path)
    if regression:
        run_environment[KERNEL_REGRESSION_ENV] = "1"
    _bounded([str(binary), KERNEL_TEST, "--exact", "--ignored", "--nocapture", "--test-threads=1"],
             directory, label + "-run", KERNEL_PROCESS_SECONDS, deadline, run_environment)
    raw = load_json(result_path)
    shutil.copyfile(result_path, output / (label + ".kernel.raw.json"))
    envelope = {"schema_version": 1, "context": kernel["context"], "revision": revision,
                "harness_sha256": digest, "regression_fixture": regression,
                "result": validate_kernel_result(raw, regression)}
    validate_kernel_envelope(envelope, regression)
    _write_json(output / (label + ".kernel.json"), envelope)
    return envelope


def _kernel_stage(root, base, head, output, compiler, context, work, deadline):
    kernel = _kernel_configuration(root, base, head, output, compiler, context, deadline)
    digests = kernel["harness_sha256"]
    report = {"state": kernel["state"], "target": KERNEL_TARGET,
              "blocking": kernel["state"] == "enforced", "status": "failed", "base": "absent",
              "errors": []}
    # A base that predates the harness is still built, so pending runs pay and
    # record the same two-build cost as an enforced comparison, and discovery
    # proves the test is really absent rather than trusting the source scan.
    binary, environment, directory = _build_kernel(root, base, "base", output, compiler, kernel,
                                                   digests["base"], work, deadline)
    before = None
    if digests["base"] is not None:
        before = _run_kernel(binary, environment, directory, "base", base, digests["base"], kernel,
                             output, deadline)
        report["base"] = "measured"
    binary, environment, directory = _build_kernel(root, head, "head", output, compiler, kernel,
                                                   digests["head"], work, deadline)
    after = _run_kernel(binary, environment, directory, "head", head, digests["head"], kernel,
                        output, deadline)
    report["head"] = after["result"]["targets"][0]["allocation_samples"][0]
    if before is None:
        report["status"] = "informational"
        return report
    comparison = compare_kernel_results(before, after, kernel["budget"])
    report["comparison"] = comparison
    if not report["blocking"]:
        report["status"] = "informational"
    elif comparison["status"] == "passed":
        report["status"] = "passed"
    else:
        report["errors"].append("http_policy: allocation growth exceeds the base-owned budget")
    return report


def run_comparison(base, head, output, root=None, work=None):
    output = _prepare_output(output)
    started = time.monotonic()
    pure_deadline = started + PURE_SECONDS
    deadline = started + RUN_SECONDS
    summary = {"schema_version": 1, "status": "failed", "targets": [], "errors": []}
    try:
        root = Path(root) if root is not None else repo_root()
        work = Path(work) if work is not None else root / "target" / "microbench-work"
        base, head = resolve_commit(root, base), resolve_commit(root, head)
        compiler, harness, budget, context = _configuration(root, base, head, output, pure_deadline)
        before = _measure(root, base, "base", output, compiler, harness, context, pure_deadline)
        after = _measure(root, head, "head", output, compiler, harness, context, pure_deadline)
        summary = compare_saved_results(before, after, budget)
        summary["context"] = context
        if time.monotonic() > pure_deadline:
            raise RuntimeError("pure-path comparison exceeded its runtime budget")
        kernel = _kernel_stage(root, base, head, output, compiler, context, work, deadline)
        summary["kernel"] = kernel
        if kernel["status"] == "failed":
            summary["status"] = "failed"
            summary["errors"].extend(kernel["errors"])
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError, UnicodeError, KeyError) as error:
        # A failure after the pure-path comparison must not inherit its pass.
        summary["status"] = "failed"
        summary["errors"].append(str(error))
    finally:
        summary["elapsed_seconds"] = time.monotonic() - started
        if summary["elapsed_seconds"] > RUN_SECONDS:
            summary["status"] = "failed"
            summary["errors"].append("comparison exceeded the total runtime budget")
        _write_json(output / "summary.json", summary)
    return summary


def self_test(revision, output, root=None, work=None):
    output = _prepare_output(output)
    started = time.monotonic()
    pure_deadline = started + PURE_SECONDS
    deadline = started + RUN_SECONDS
    summary = {"schema_version": 1, "status": "failed", "errors": []}
    try:
        root = Path(root) if root is not None else repo_root()
        work = Path(work) if work is not None else root / "target" / "microbench-work"
        revision = resolve_commit(root, revision)
        compiler, harness, budget, context = _configuration(root, revision, revision, output, pure_deadline)
        baseline = _measure(root, revision, "base", output, compiler, harness, context, pure_deadline)
        neutral = _measure(root, revision, "neutral", output, compiler, harness, context, pure_deadline)
        regression = _measure(root, revision, "regression", output, compiler, harness, context, pure_deadline, regression=True)
        neutral_report = compare_saved_results(baseline, neutral, budget)
        regression_report = compare_results(baseline["result"], regression["result"], budget)
        regression_report["deliberate_fixture"] = True
        _write_json(output / "neutral-comparison.json", neutral_report)
        _write_json(output / "regression-comparison.json", regression_report)
        if time.monotonic() > pure_deadline:
            raise RuntimeError("pure-path self-test exceeded its runtime budget")
        # The kernel's neutral side is an independent build of the same revision
        # in another tree; its regression is the baseline binary run with the
        # fixture switch, which the report must echo.
        kernel = _kernel_configuration(root, revision, revision, output, compiler, context, deadline)
        digest = kernel["harness_sha256"]["head"]
        binary, environment, directory = _build_kernel(root, revision, "base", output, compiler,
                                                       kernel, digest, work, deadline)
        kernel_baseline = _run_kernel(binary, environment, directory, "base", revision, digest,
                                      kernel, output, deadline)
        kernel_fixture = _run_kernel(binary, environment, directory, "regression", revision, digest,
                                     kernel, output, deadline, regression=True)
        binary, environment, directory = _build_kernel(root, revision, "neutral", output, compiler,
                                                       kernel, digest, work, deadline)
        kernel_neutral = _run_kernel(binary, environment, directory, "neutral", revision, digest,
                                     kernel, output, deadline)
        kernel_neutral_report = compare_kernel_results(kernel_baseline, kernel_neutral, kernel["budget"])
        kernel_regression_report = compare_kernel_results(kernel_baseline, kernel_fixture,
                                                          kernel["budget"], regression_head=True)
        kernel_regression_report["deliberate_fixture"] = True
        _write_json(output / "kernel-neutral-comparison.json", kernel_neutral_report)
        _write_json(output / "kernel-regression-comparison.json", kernel_regression_report)
        if (neutral_report["status"] != "passed" or regression_report["status"] != "failed"
                or kernel_neutral_report["status"] != "passed"
                or kernel_regression_report["status"] != "failed"):
            raise ValueError("neutral rebuild or deliberate allocation regression was not detected correctly")
        summary.update({"status": "passed", "neutral": neutral_report, "regression": regression_report,
                        "kernel_neutral": kernel_neutral_report,
                        "kernel_regression": kernel_regression_report, "context": context})
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError, UnicodeError, KeyError) as error:
        summary["status"] = "failed"
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
