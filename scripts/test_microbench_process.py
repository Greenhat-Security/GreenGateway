"""Execution and policy contracts for the bounded pure-path comparison."""
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import microbench as bench

ROOT = Path(__file__).resolve().parents[1]
BASE = "1" * 40
HEAD = "2" * 40


def harness():
    return (ROOT / "scripts/benchmarks/pure_paths.rs").read_text(encoding="utf-8")


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def budget(text=None):
    return {
        "schema_version": 1,
        "harness_sha256": [digest(harness() if text is None else text)],
        "targets": [
            {"id": name, "max_allocation_growth": 0, "max_allocated_bytes_growth": 0}
            for name in ("request_path", "path_prefix", "rule_path", "egress_host")
        ],
    }


def measured_result():
    # Valid evidence lets execution tests get past the base measurement and
    # exercise failures in the head process, where a stale pass is dangerous.
    return {
        "schema_version": 1, "warmup": 100, "iterations": 1000, "samples": 9,
        "targets": [
            {
                "id": name, "input_cases": 16, "input_bytes": size,
                "operations_per_iteration": operations, "expected_checksum": checksum,
                "allocation_samples": [
                    {"allocations": calls, "allocated_bytes": allocated, "checksum": checksum}
                    for _ in range(9)
                ],
                "timing_samples_ns": [100000] * 9,
            }
            for name, size, operations, checksum, calls, allocated in (
                ("request_path", 712, 32, 16000, 0, 0),
                ("path_prefix", 867, 16, 7000, 0, 0),
                ("rule_path", 1367, 16, 9000, 87000, 5286000),
                ("egress_host", 1118, 16, 8000, 31000, 1118000),
            )
        ],
    }


def context():
    return {
        "rust_ci": "1.98.1", "rustc_vv": "rustc 1.98.1\nrelease: 1.98.1\n",
        "rustc_flags": bench.RUST_FLAGS, "harness_sha256": digest(harness()),
        "machine": {"platform": "test", "machine": "test", "logical_cpus": 1, "python": "3.13"},
        "warmup": 100, "iterations": 1000, "samples": 9,
    }


class BoundedProcessTests(unittest.TestCase):
    def invoke(self, directory, code, *, seconds=2):
        return bench._bounded(
            [sys.executable, "-c", code], Path(directory), "fixture",
            seconds, time.monotonic() + 3,
        )

    def test_success_returns_stdout_and_keeps_stderr_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output, elapsed = self.invoke(directory, "import sys; print('complete'); print('diagnostic', file=sys.stderr)")
            self.assertEqual(output, "complete\n")
            self.assertGreaterEqual(elapsed, 0)
            self.assertEqual((Path(directory) / "fixture.stderr.log").read_text(), "diagnostic\n")

    def test_nonzero_process_is_an_error_even_with_success_shaped_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "exit code 23"):
                self.invoke(directory, "print('{\"status\":\"passed\"}'); raise SystemExit(23)")
            self.assertIn("passed", (Path(directory) / "fixture.stdout.log").read_text())

    def test_timeout_kills_and_reaps_runaway_process(self):
        with tempfile.TemporaryDirectory() as directory:
            real_popen = subprocess.Popen
            children = []

            def start(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                children.append(process)
                return process

            started = time.monotonic()
            with mock.patch.object(bench.subprocess, "Popen", side_effect=start):
                with self.assertRaisesRegex(RuntimeError, "runtime bound"):
                    self.invoke(directory, "import time; time.sleep(30)", seconds=0.08)
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            if os.name == "posix":
                self.assertEqual(children[0].returncode, -signal.SIGKILL)

    def test_either_output_stream_has_a_hard_bound(self):
        for descriptor in (1, 2):
            with self.subTest(descriptor=descriptor), tempfile.TemporaryDirectory() as directory:
                code = f"import os, time; os.write({descriptor}, b'x' * 2048); time.sleep(30)"
                with mock.patch.object(bench, "MAX_LOG_BYTES", 1024):
                    with self.assertRaisesRegex(RuntimeError, "output bound"):
                        self.invoke(directory, code)

    def test_already_expired_total_deadline_never_starts_process(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(bench.subprocess, "Popen") as start:
            with self.assertRaisesRegex(RuntimeError, "total runtime budget"):
                bench._bounded([sys.executable, "-c", "pass"], Path(directory), "expired", 2, time.monotonic() - 1)
            start.assert_not_called()


class SourceIsolationCompileTests(unittest.TestCase):
    def test_production_cannot_capture_reserved_benchmark_bridge_names(self):
        for name in ("microbench_host_matches", "microbench_validate_method_matcher", "MicrobenchPreparedPattern"):
            with self.subTest(name=name):
                sources = {path: (ROOT / path).read_text(encoding="utf-8") for path in bench.SOURCE_PATHS}
                sources["gateway/src/egress.rs"] = sources["gateway/src/egress.rs"].replace(
                    "fn host_glob_matches(pattern: &str, host: &str) -> bool {",
                    f"fn host_glob_matches(pattern: &str, host: &str) -> bool {{\n    let _ = {name};",
                    1,
                )
                with self.assertRaises(ValueError):
                    bench.project_sources(sources)

    def test_projected_production_cannot_capture_benchmark_helpers_or_counters(self):
        pin = json.loads((ROOT / "build-tools.json").read_text(encoding="utf-8"))["rust_ci"]
        rustup = shutil.which("rustup")
        self.assertIsNotNone(rustup, "the repository's pinned Rust compiler must be installed")
        compiler = subprocess.run(
            [rustup, "which", "--toolchain", pin, "rustc"],
            capture_output=True, text=True, timeout=10, check=True,
        ).stdout.strip()
        for name, statement in (
            ("black_box", "let _ = black_box(false);"),
            ("COUNTING", "let _ = &COUNTING;"),
            ("decision", "let _ = decision(false);"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                working = Path(directory)
                sources = {path: (ROOT / path).read_text(encoding="utf-8") for path in bench.SOURCE_PATHS}
                sources["gateway/src/egress.rs"] = sources["gateway/src/egress.rs"].replace(
                    "fn host_glob_matches(pattern: &str, host: &str) -> bool {",
                    "fn host_glob_matches(pattern: &str, host: &str) -> bool {\n    " + statement,
                    1,
                )
                for path, content in bench.project_sources(sources).items():
                    (working / path).write_text(content, encoding="utf-8")
                (working / "harness.rs").write_text(harness(), encoding="utf-8")
                result = subprocess.run(
                    [compiler, "harness.rs", *bench.RUST_FLAGS, "-o", "benchmark"],
                    cwd=working, capture_output=True, text=True, timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("error[E0425]", result.stderr)
                self.assertIn(f"`{name}` in this scope", result.stderr)
                self.assertFalse((working / "benchmark").exists())


class ConfigurationPolicyTests(unittest.TestCase):
    def configure(self, directory, *, base=BASE, base_exists=True, head_harness=None,
                  base_budget=None, proposed_budget=None, base_pin="1.98.1", head_pin="1.98.1"):
        active = harness() if head_harness is None else head_harness
        previous = budget() if base_budget is None else base_budget
        proposed = budget(active) if proposed_budget is None else proposed_budget

        def blob(_root, revision, path):
            if path == "build-tools.json":
                return json.dumps({"rust_ci": base_pin if revision == base else head_pin})
            if path == bench.HARNESS_PATH and revision == HEAD:
                return active
            if path == bench.BUDGET_PATH:
                return json.dumps(previous if revision == base else proposed)
            raise AssertionError(f"unexpected source request: {revision}:{path}")

        def bounded(command, _directory, label, _seconds, _deadline, env=None):
            if label == "toolchain":
                self.assertEqual(command[1:], ["which", "--toolchain", head_pin, "rustc"])
                return sys.executable + "\n", 0.001
            if label == "rustc-version":
                self.assertEqual(command, [sys.executable, "-Vv"])
                return f"rustc {head_pin}\nrelease: {head_pin}\n", 0.001
            raise AssertionError(f"unexpected process: {label}")

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(bench, "_blob", side_effect=blob))
            stack.enter_context(mock.patch.object(bench, "_has_blob", return_value=base_exists))
            stack.enter_context(mock.patch.object(bench.shutil, "which", return_value=sys.executable))
            stack.enter_context(mock.patch.object(bench, "_bounded", side_effect=bounded))
            stack.enter_context(mock.patch.object(bench, "_machine", return_value=context()["machine"]))
            return bench._configuration(ROOT, base, HEAD, Path(directory), time.monotonic() + 10)

    def test_head_cannot_approve_its_own_changed_harness(self):
        changed = harness() + "\n// unapproved workload change\n"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "base-owned"):
                self.configure(directory, head_harness=changed)

    def test_proposed_budget_cannot_remove_active_harness_digest(self):
        proposed = budget()
        proposed["harness_sha256"] = ["a" * 64]
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                self.configure(directory, proposed_budget=proposed)

    def test_preapproved_harness_migration_preserves_active_digest(self):
        changed = harness() + "\n// explicitly preapproved revision\n"
        previous = budget()
        previous["harness_sha256"].append(digest(changed))
        proposed = budget(changed)
        with tempfile.TemporaryDirectory() as directory:
            _compiler, selected, governing, metadata = self.configure(
                directory, head_harness=changed, base_budget=previous, proposed_budget=proposed,
            )
            self.assertEqual(selected, changed)
            self.assertEqual(governing, previous)
            self.assertEqual(metadata["budget_owner"], BASE)

    def test_missing_base_budget_is_allowed_only_for_exact_adoption_commit(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "adoption"):
                self.configure(directory, base_exists=False)
        with tempfile.TemporaryDirectory() as directory:
            _, _, _, metadata = self.configure(directory, base=bench.INITIAL_BASE, base_exists=False)
            self.assertEqual(metadata["budget_owner"], "first-adoption:" + bench.INITIAL_BASE)

    def test_adoption_cannot_bootstrap_a_changed_or_extra_harness_digest(self):
        changed = harness() + "\n// different first workload\n"
        proposed = budget()
        proposed["harness_sha256"].append("a" * 64)
        for options in ({"head_harness": changed}, {"proposed_budget": proposed}):
            with self.subTest(options=list(options)), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    self.configure(directory, base=bench.INITIAL_BASE, base_exists=False, **options)

    def test_differing_source_pins_use_one_head_compiler_for_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            compiler, _, _, metadata = self.configure(directory, base_pin="1.97.0", head_pin="1.98.1")
            self.assertEqual(compiler, sys.executable)
            self.assertEqual(metadata["rust_ci"], "1.98.1")
            self.assertEqual(metadata["declared_source_rust_ci"], {"base": "1.97.0", "head": "1.98.1"})
            self.assertEqual(json.loads((Path(directory) / "context.json").read_text()), metadata)


class FailedComparisonEvidenceTests(unittest.TestCase):
    def assert_failed_evidence(self, output, returned):
        stored = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(stored, returned)
        self.assertEqual(stored["status"], "failed")
        self.assertTrue(stored["errors"])
        return stored

    def test_missing_base_or_head_git_object_saves_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(root), "-c", "user.name=Benchmark Fixture",
                 "-c", "user.email=fixture@example.test", "commit", "-q", "--allow-empty", "-m", "fixture"],
                check=True, capture_output=True,
            )
            known = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], check=True, text=True, capture_output=True).stdout.strip()
            for label, base, head in (("missing-base", BASE, known), ("missing-head", known, HEAD)):
                with self.subTest(label=label), mock.patch.object(bench, "_configuration") as configure:
                    output = root / label
                    report = bench.run_comparison(base, head, output, root=root)
                    self.assert_failed_evidence(output, report)
                    configure.assert_not_called()

    def test_head_compile_or_benchmark_crash_and_timeout_never_reuse_base_pass(self):
        real_bounded = bench._bounded
        raw = json.dumps(measured_result())
        for stage in ("compile", "run"):
            for failure in ("crash", "timeout"):
                with self.subTest(stage=stage, failure=failure), tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "comparison"

                    def bounded(_command, working, label, _seconds, deadline, env=None):
                        seconds = 2
                        if working.name == "head" and label == stage:
                            if failure == "crash":
                                code = "print('deliberate process failure'); raise SystemExit(19)"
                            else:
                                code = "import time; time.sleep(30)"
                                seconds = 0.08
                        elif label == "compile":
                            code = "pass"
                        else:
                            code = "print(" + repr(raw) + ")"
                        return real_bounded([sys.executable, "-c", code], working, label, seconds, deadline, env)

                    def source(_root, _revision, path):
                        return (ROOT / path).read_text(encoding="utf-8")

                    with ExitStack() as stack:
                        stack.enter_context(mock.patch.object(bench, "resolve_commit", side_effect=lambda _root, revision: revision))
                        stack.enter_context(mock.patch.object(bench, "_configuration", return_value=(sys.executable, harness(), budget(), context())))
                        stack.enter_context(mock.patch.object(bench, "_blob", side_effect=source))
                        stack.enter_context(mock.patch.object(bench, "_bounded", side_effect=bounded))
                        report = bench.run_comparison(BASE, HEAD, output, root=ROOT)
                    stored = self.assert_failed_evidence(output, report)
                    self.assertTrue((output / "base.json").is_file(), "base must complete before the head failure")
                    self.assertFalse((output / "head.json").exists(), "failed head cannot become valid evidence")
                    self.assertTrue((output / "head" / f"{stage}.stdout.log").exists())
                    expected_error = "exit code 19" if failure == "crash" else "runtime bound"
                    self.assertIn(expected_error, " ".join(stored["errors"]))


MAIN = (ROOT / bench.KERNEL_MAIN_PATH).read_text(encoding="utf-8")
DECLARATION = bench.KERNEL_ATTRIBUTES + bench.KERNEL_MODULE + "\n"
KERNEL_HARNESS = (ROOT / bench.KERNEL_HARNESS_PATH).read_text(encoding="utf-8")


def schema_two(kernel_digests, proposed=None):
    value = budget() if proposed is None else proposed
    value["schema_version"] = 2
    value["kernel_harness_sha256"] = list(kernel_digests)
    value["targets"].append({"id": "http_policy", "max_allocation_growth": 0,
                             "max_allocated_bytes_growth": 0})
    return value


def kernel_result(allocations=41700, regression=False):
    return {
        "schema_version": 1, "harness": "gateway-test-binary", "regression_fixture": regression,
        "warmup": 10, "iterations": 100, "samples": 9,
        "targets": [{
            "id": "http_policy", "input_cases": 17, "input_bytes": 1459,
            "operations_per_iteration": 17, "expected_checksum": 1700,
            "allocation_samples": [
                {"allocations": allocations, "allocated_bytes": 1439000, "checksum": 1700}
                for _ in range(9)
            ],
            "timing_samples_ns": [40000000] * 9,
        }],
    }


def kernel_context():
    return {
        "rust_ci": "1.98.1", "rustc_vv": "rustc 1.98.1\nrelease: 1.98.1\n",
        "cargo_vv": "cargo 1.98.1\nrelease: 1.98.1\n",
        "cargo_arguments": list(bench.CARGO_ARGUMENTS), "cargo_env": dict(bench.CARGO_PROFILE_ENV),
        "node": "26.10.0", "npm": "11.19.1", "machine": context()["machine"],
        "warmup": 10, "iterations": 100, "samples": 9,
    }


class KernelConfigurationPolicyTests(unittest.TestCase):
    def configure(self, directory, *, base_budget=None, proposed_budget=None,
                  base_harness=KERNEL_HARNESS, head_harness=KERNEL_HARNESS, base_wired=True,
                  head_wired=True, extra_head_files=(), cargo="1.98.1", node="v26.10.0",
                  npm="11.19.1"):
        def tree(wired, kernel_harness):
            files = {bench.KERNEL_MAIN_PATH: MAIN if wired else MAIN.replace(DECLARATION, ""),
                     "build-tools.json": json.dumps({"rust_ci": "1.98.1", "node": "26.10.0",
                                                     "npm": "11.19.1"})}
            if kernel_harness is not None:
                files[bench.KERNEL_HARNESS_PATH] = kernel_harness
            return files

        files = {BASE: tree(base_wired, base_harness), HEAD: tree(head_wired, head_harness)}
        files[HEAD].update({name: "" for name in extra_head_files})

        def blob(_root, revision, path):
            if path not in files[revision]:
                raise ValueError("Git object lookup failed: " + path)
            return files[revision][path]

        def bounded(command, _directory, label, _seconds, _deadline, env=None, cwd=None, max_bytes=None):
            outputs = {"cargo-toolchain": sys.executable,
                       "cargo-version": f"cargo {cargo}\nrelease: {cargo}\n",
                       "node-version": node, "npm-version": npm}
            if label not in outputs:
                raise AssertionError(f"unexpected process: {label}")
            return outputs[label] + "\n", 0.001

        state = {"budget": budget() if base_budget is None else base_budget,
                 "proposed_budget": budget() if proposed_budget is None else proposed_budget,
                 "rust_ci": "1.98.1", "rustc_vv": "rustc 1.98.1\nrelease: 1.98.1\n",
                 "machine": context()["machine"]}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(bench, "_blob", side_effect=blob))
            stack.enter_context(mock.patch.object(
                bench, "_has_blob", side_effect=lambda _root, revision, path: path in files[revision]))
            stack.enter_context(mock.patch.object(bench, "_bounded", side_effect=bounded))
            stack.enter_context(mock.patch.object(bench.shutil, "which", return_value=sys.executable))
            return bench._kernel_configuration(ROOT, BASE, HEAD, Path(directory), sys.executable,
                                               state, time.monotonic() + 10)

    def test_pending_harness_runs_on_head_over_a_base_that_predates_it(self):
        with tempfile.TemporaryDirectory() as directory:
            kernel = self.configure(directory, base_wired=False, base_harness=None)
            self.assertEqual(kernel["state"], "pending")
            self.assertEqual(kernel["harness_sha256"], {"base": None, "head": digest(KERNEL_HARNESS)})
            self.assertEqual(kernel["budget"], {"id": "http_policy", "max_allocation_growth": 0,
                                                "max_allocated_bytes_growth": 0})
            self.assertEqual(json.loads((Path(directory) / "kernel-context.json").read_text()), kernel)

    def test_budget_cannot_land_before_its_harness_is_on_the_base(self):
        proposed = schema_two([digest(KERNEL_HARNESS)])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "harness before its budget"):
                self.configure(directory, proposed_budget=proposed, base_wired=False, base_harness=None)

    def test_proposed_budget_must_approve_both_measured_harnesses(self):
        with tempfile.TemporaryDirectory() as directory:
            kernel = self.configure(directory, proposed_budget=schema_two([digest(KERNEL_HARNESS)]))
            self.assertEqual(kernel["state"], "proposed")
        changed = KERNEL_HARNESS + "\n// different head workload\n"
        for options in ({"proposed_budget": schema_two(["a" * 64])},
                        {"proposed_budget": schema_two([digest(KERNEL_HARNESS)]), "head_harness": changed}):
            with self.subTest(options=sorted(options)), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "approved digests"):
                    self.configure(directory, **options)

    def test_enforced_harness_changes_need_the_documented_two_step_transition(self):
        current = digest(KERNEL_HARNESS)
        changed = KERNEL_HARNESS + "\n// reviewed next workload\n"
        with tempfile.TemporaryDirectory() as directory:
            kernel = self.configure(directory, base_budget=schema_two([current]),
                                    proposed_budget=schema_two([current]))
            self.assertEqual(kernel["state"], "enforced")
            self.assertEqual(kernel["budget"]["id"], "http_policy")
        with tempfile.TemporaryDirectory() as directory:
            kernel = self.configure(directory, head_harness=changed,
                                    base_budget=schema_two([current, digest(changed)]),
                                    proposed_budget=schema_two([digest(changed)]))
            self.assertEqual(kernel["harness_sha256"]["head"], digest(changed))
        rejected = (
            {"head_harness": changed, "base_budget": schema_two([current]),
             "proposed_budget": schema_two([current, digest(changed)])},
            {"head_harness": changed, "base_budget": schema_two([current, digest(changed)]),
             "proposed_budget": schema_two([current])},
            {"base_harness": changed, "base_budget": schema_two([current]),
             "proposed_budget": schema_two([current])},
        )
        for options in rejected:
            with self.subTest(options=sorted(options)), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "approved digests"):
                    self.configure(directory, **options)

    def test_enforced_target_cannot_be_retired_by_the_proposal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "retire"):
                self.configure(directory, base_budget=schema_two([digest(KERNEL_HARNESS)]))

    def test_missing_or_inconsistent_harness_wiring_rejects(self):
        for options, message in (({"head_wired": False, "head_harness": None}, "lacks"),
                                 ({"head_harness": None}, "disagree"),
                                 ({"base_wired": False}, "disagree")):
            with self.subTest(options=sorted(options)), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, message):
                    self.configure(directory, **options)

    def test_repository_cargo_configuration_rejects(self):
        for path in bench.CARGO_CONFIG_PATHS:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "Cargo configuration"):
                    self.configure(directory, extra_head_files=(path,))

    def test_unpinned_cargo_or_ui_tools_reject(self):
        for options in ({"cargo": "1.97.0"}, {"node": "v24.15.0"}, {"npm": "10.9.2"}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "differs"):
                    self.configure(directory, **options)


LANE_DECLARATION = bench.LANE_ATTRIBUTES + bench.LANE_MODULE + "\n"
LANE_HARNESS = (ROOT / bench.LANE_HARNESS_PATH).read_text(encoding="utf-8")
LANE_CASES = {"tool_policy": 27, "rate_lane": 14}


def schema_three(kernel_digests, lane_digests):
    value = schema_two(kernel_digests)
    value["schema_version"] = 3
    value["lane_harness_sha256"] = list(lane_digests)
    value["targets"].extend({"id": target, "max_allocation_growth": 0,
                             "max_allocated_bytes_growth": 0}
                            for target in ("tool_policy", "rate_lane"))
    return value


def lane_result(target, allocations=None, regression=False):
    cases = LANE_CASES[target]
    metadata = bench.LANE_METADATA[target]
    return {
        "schema_version": 1, "harness": "gateway-test-binary", "regression_fixture": regression,
        "warmup": 10, "iterations": 100, "samples": 9,
        "targets": [{
            "id": target, "input_cases": cases, "input_bytes": metadata["input_bytes"],
            "operations_per_iteration": cases, "expected_checksum": cases * 100,
            "allocation_samples": [
                {"allocations": cases * 1000 if allocations is None else allocations,
                 "allocated_bytes": cases * 64000, "checksum": cases * 100}
                for _ in range(9)
            ],
            "timing_samples_ns": [20000000] * 9,
        }],
    }


def lane_results_by_target():
    return {target: lane_result(target) for target in LANE_CASES}


class LaneConfigurationPolicyTests(unittest.TestCase):
    def configure(self, directory, *, base_budget=None, proposed_budget=None,
                  base_lanes=LANE_HARNESS, head_lanes=LANE_HARNESS, base_declared=True,
                  head_declared=True, base_kernel=True):
        def tree(kernel, declared, lane_harness):
            files = {}
            if kernel:
                files[bench.KERNEL_HARNESS_PATH] = (
                    KERNEL_HARNESS if declared else KERNEL_HARNESS.replace(LANE_DECLARATION, ""))
            if lane_harness is not None:
                files[bench.LANE_HARNESS_PATH] = lane_harness
            return files

        files = {BASE: tree(base_kernel, base_declared, base_lanes),
                 HEAD: tree(True, head_declared, head_lanes)}

        def blob(_root, revision, path):
            if path not in files[revision]:
                raise ValueError("Git object lookup failed: " + path)
            return files[revision][path]

        state = {"budget": schema_two(["f" * 64]) if base_budget is None else base_budget,
                 "proposed_budget": (schema_two(["f" * 64]) if proposed_budget is None
                                     else proposed_budget)}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(bench, "_blob", side_effect=blob))
            stack.enter_context(mock.patch.object(
                bench, "_has_blob", side_effect=lambda _root, revision, path: path in files[revision]))
            return bench._lane_configuration(ROOT, BASE, HEAD, Path(directory), state)

    def test_pending_lanes_run_on_head_over_a_base_that_predates_them(self):
        for options in ({"base_declared": False, "base_lanes": None},
                        {"base_kernel": False, "base_lanes": None}):
            with self.subTest(options=sorted(options)), tempfile.TemporaryDirectory() as directory:
                lanes = self.configure(directory, **options)
                self.assertEqual(lanes["state"], "pending")
                self.assertEqual(lanes["harness_sha256"], {"base": None, "head": digest(LANE_HARNESS)})
                self.assertEqual(lanes["targets"], ["tool_policy", "rate_lane"])
                self.assertEqual(lanes["budget"], {
                    target: {"id": target, "max_allocation_growth": 0,
                             "max_allocated_bytes_growth": 0}
                    for target in ("tool_policy", "rate_lane")})
                self.assertEqual(json.loads((Path(directory) / "lane-context.json").read_text()),
                                 lanes)

    def test_lane_budget_cannot_land_before_its_harness_is_on_the_base(self):
        proposed = schema_three(["f" * 64], [digest(LANE_HARNESS)])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "harness before its budget"):
                self.configure(directory, proposed_budget=proposed, base_declared=False,
                               base_lanes=None)

    def test_proposed_lane_budget_must_approve_both_measured_harnesses(self):
        with tempfile.TemporaryDirectory() as directory:
            lanes = self.configure(
                directory, proposed_budget=schema_three(["f" * 64], [digest(LANE_HARNESS)]))
            self.assertEqual(lanes["state"], "proposed")
            self.assertEqual(lanes["budget"]["tool_policy"]["id"], "tool_policy")
        changed = LANE_HARNESS + "\n// different head workload\n"
        for options in ({"proposed_budget": schema_three(["f" * 64], ["a" * 64])},
                        {"proposed_budget": schema_three(["f" * 64], [digest(LANE_HARNESS)]),
                         "head_lanes": changed}):
            with self.subTest(options=sorted(options)), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "approved digests"):
                    self.configure(directory, **options)

    def test_enforced_lane_harness_changes_need_the_two_step_transition(self):
        current = digest(LANE_HARNESS)
        changed = LANE_HARNESS + "\n// reviewed next workload\n"
        with tempfile.TemporaryDirectory() as directory:
            lanes = self.configure(directory, base_budget=schema_three(["f" * 64], [current]),
                                   proposed_budget=schema_three(["f" * 64], [current]))
            self.assertEqual(lanes["state"], "enforced")
            self.assertEqual(lanes["budget"]["rate_lane"]["id"], "rate_lane")
        with tempfile.TemporaryDirectory() as directory:
            lanes = self.configure(directory, head_lanes=changed,
                                   base_budget=schema_three(["f" * 64], [current, digest(changed)]),
                                   proposed_budget=schema_three(["f" * 64], [digest(changed)]))
            self.assertEqual(lanes["harness_sha256"]["head"], digest(changed))
        rejected = (
            {"head_lanes": changed, "base_budget": schema_three(["f" * 64], [current]),
             "proposed_budget": schema_three(["f" * 64], [current, digest(changed)])},
            {"head_lanes": changed,
             "base_budget": schema_three(["f" * 64], [current, digest(changed)]),
             "proposed_budget": schema_three(["f" * 64], [current])},
            {"base_lanes": changed, "base_budget": schema_three(["f" * 64], [current]),
             "proposed_budget": schema_three(["f" * 64], [current])},
        )
        for options in rejected:
            with self.subTest(options=sorted(options)), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, "approved digests"):
                    self.configure(directory, **options)

    def test_enforced_lanes_cannot_be_retired_by_the_proposal(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "retire"):
                self.configure(directory,
                               base_budget=schema_three(["f" * 64], [digest(LANE_HARNESS)]))

    def test_missing_or_inconsistent_lane_wiring_rejects(self):
        for options, message in (({"head_declared": False, "head_lanes": None}, "lacks"),
                                 ({"head_lanes": None}, "disagree"),
                                 ({"base_declared": False}, "disagree"),
                                 ({"base_kernel": False}, "disagree")):
            with self.subTest(options=sorted(options)), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(ValueError, message):
                    self.configure(directory, **options)


class KernelBuildInputTests(unittest.TestCase):
    def test_cargo_report_must_name_one_gateway_test_executable_in_the_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            executable = target / "debug" / "deps" / "gateway-test"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"fixture")
            outside = Path(directory) / "elsewhere"
            outside.write_bytes(b"fixture")

            def artifact(path, test=True, name="gateway", kind=("bin",)):
                return json.dumps({"reason": "compiler-artifact", "executable": str(path),
                                   "target": {"name": name, "kind": list(kind)},
                                   "profile": {"test": test}})

            messages = "\n".join([artifact(executable), artifact(executable, test=False),
                                  artifact(executable, name="transport_guard", kind=("example",)),
                                  json.dumps({"reason": "build-finished", "success": True})])
            self.assertEqual(bench._test_executable(messages, target), executable.resolve())
            for invalid in ("", artifact(executable, test=False),
                            artifact(executable) + "\n" + artifact(outside),
                            artifact(outside), artifact(target / "missing"), "not json"):
                with self.subTest(messages=invalid[:40]), self.assertRaises(ValueError):
                    bench._test_executable(invalid, target)

    def test_inherited_build_overrides_are_removed_and_the_profile_is_explicit(self):
        inherited = {"RUSTFLAGS": "-C opt-level=3", "CARGO_ENCODED_RUSTFLAGS": "-Copt-level=3",
                     "CARGO_PROFILE_DEV_OPT_LEVEL": "3", "CARGO_BUILD_RUSTC_WRAPPER": "wrapper",
                     "RUSTC_WRAPPER": "wrapper", "CARGO_TARGET_DIR": "elsewhere",
                     "CARGO_INCREMENTAL": "1", "RUSTC_BOOTSTRAP": "1",
                     "GREENGATEWAY_MICROBENCH_REGRESSION_FIXTURE": "1", "KEEP_ME": "kept"}
        with mock.patch.dict(os.environ, inherited):
            environment = bench._cargo_environment("/toolchain/rustc", "1.98.1", Path("/work/target"))
        for key in inherited:
            if key not in ("CARGO_TARGET_DIR", "CARGO_INCREMENTAL", "KEEP_ME"):
                self.assertNotIn(key, environment)
        self.assertEqual(environment["KEEP_ME"], "kept")
        self.assertEqual(environment["CARGO_TARGET_DIR"], str(Path("/work/target")))
        self.assertEqual(environment["CARGO_INCREMENTAL"], "0")
        self.assertEqual(environment["CARGO_PROFILE_DEV_DEBUG"], "0")
        self.assertEqual(environment["RUSTC"], "/toolchain/rustc")
        self.assertEqual(environment["RUSTUP_TOOLCHAIN"], "1.98.1")


class KernelTreeTests(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.run(["git", "-C", str(root), "-c", "user.name=Benchmark Fixture",
                               "-c", "user.email=fixture@example.test", "-c", "commit.gpgsign=false",
                               *args], check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, root, files):
        for name, content in files.items():
            path = root / name
            if content is None:
                path.unlink()
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        self.git(root, "add", "-A")
        self.git(root, "commit", "-q", "-m", "fixture")
        return self.git(root, "rev-parse", "HEAD")

    def test_base_tree_keeps_its_rust_sources_and_takes_the_heads_ui_build_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "repository"
            root.mkdir()
            self.git(root, "init", "-q")
            ui = {name: f"base {name}\n" for name in (".node-version", ".npm-version", "build-tools.json",
                                                       "npm-script-policy.json",
                                                       "scripts/npm-script-policy.mjs")}
            base = self.commit(root, {**ui, "admin-ui/src/retired.ts": "base\n",
                                      "gateway/src/main.rs": "base rust\n",
                                      "docs/schemas/included.json": "base schema\n"})
            head = self.commit(root, {**{name: f"head {name}\n" for name in ui},
                                      "admin-ui/src/retired.ts": None, "admin-ui/src/new.ts": "head\n",
                                      "gateway/src/main.rs": "head rust\n",
                                      "docs/schemas/included.json": "head schema\n"})
            tree = Path(directory) / "work" / "base"
            bench._prepare_tree(root, base, tree, head, time.monotonic() + 30)
            self.assertEqual((tree / "gateway/src/main.rs").read_text(encoding="utf-8"), "base rust\n")
            self.assertEqual((tree / "docs/schemas/included.json").read_text(encoding="utf-8"),
                             "base schema\n")
            for name in ui:
                self.assertEqual((tree / name).read_text(encoding="utf-8"), f"head {name}\n")
            self.assertFalse((tree / "admin-ui/src/retired.ts").exists())
            self.assertEqual((tree / "admin-ui/src/new.ts").read_text(encoding="utf-8"), "head\n")
            bench._prepare_tree(root, head, Path(directory) / "work" / "head", head, time.monotonic() + 30)
            self.assertEqual((Path(directory) / "work/head/gateway/src/main.rs").read_text(encoding="utf-8"),
                             "head rust\n")
            configured = self.commit(root, {".cargo/config.toml": "[build]\n"})
            with self.assertRaisesRegex(ValueError, "Cargo configuration"):
                bench._prepare_tree(root, configured, Path(directory) / "work" / "configured",
                                    configured, time.monotonic() + 30)


class KernelStageExecutionTests(unittest.TestCase):
    """Real child processes stand in for Cargo, libtest discovery and the test."""

    def pure_envelope(self, revision):
        return {"schema_version": 1, "context": context(), "revision": revision,
                "regression_fixture": False,
                "source_sha256": {name: "c" * 64 for name in bench.SOURCE_PATHS},
                "projection_sha256": {name: "d" * 64 for name in ("path_match.rs", "egress.rs", "rule_path.rs")},
                "result": measured_result()}

    def run_stage(self, directory, *, state="pending", base_digest=None, base_listing=None,
                  results=None, failures=None, build_executables=1, lane_state="pending",
                  lane_base_digest=None, lane_base_listing=None, lane_results=None):
        """Run `run_comparison` with only the kernel processes simulated.

        `results` maps base/head to a kernel report (or None for no file), and
        `lane_results` maps base/head to each lane target's report;
        `failures` maps a process label to "crash" or "timeout".
        """
        directory = Path(directory)
        output, work = directory / "comparison", directory / "work"
        executable = work / "cargo-target" / "debug" / "deps" / "gateway-test"
        results = {"base": kernel_result(), "head": kernel_result()} if results is None else results
        if lane_results is None:
            lane_results = {"base": lane_results_by_target(), "head": lane_results_by_target()}
        failures = failures or {}
        if base_listing is None:
            base_listing = base_digest is not None
        if lane_base_listing is None:
            lane_base_listing = lane_base_digest is not None
        kernel = {"state": state, "target": "http_policy", "test": bench.KERNEL_TEST,
                  "budget": {"id": "http_policy", "max_allocation_growth": 0,
                             "max_allocated_bytes_growth": 0},
                  "harness_sha256": {"base": base_digest, "head": "f" * 64},
                  "cargo": sys.executable, "ui_source": HEAD,
                  "ui_build_inputs": list(bench.UI_BUILD_INPUTS), "context": kernel_context()}
        lanes = {"state": lane_state, "targets": list(bench.LANE_TARGETS),
                 "tests": dict(bench.LANE_TESTS),
                 "budget": {target: {"id": target, "max_allocation_growth": 0,
                                     "max_allocated_bytes_growth": 0}
                            for target in bench.LANE_TARGETS},
                 "harness_sha256": {"base": lane_base_digest, "head": "e" * 64}}
        real_bounded = bench._bounded
        self.kernel_calls = []

        def bounded(_command, working, label, _seconds, deadline, env=None, cwd=None, max_bytes=None):
            side = working.name.removesuffix("-kernel")
            self.kernel_calls.append((side, label))
            seconds = 2
            if failures.get(f"{side}:{label}") == "crash":
                code = "print('deliberate process failure'); raise SystemExit(23)"
            elif failures.get(f"{side}:{label}") == "timeout":
                code, seconds = "import time; time.sleep(30)", 0.08
            elif label == "clean":
                code = "pass"
            elif label == "build":
                artifact = {"reason": "compiler-artifact", "executable": str(executable),
                            "target": {"name": "gateway", "kind": ["bin"]}, "profile": {"test": True}}
                code = "print(" + repr("\n".join([json.dumps(artifact)] * build_executables)) + ")"
                if build_executables > 1:
                    other = dict(artifact, executable=str(executable) + "-other")
                    code = "print(" + repr(json.dumps(artifact) + "\n" + json.dumps(other)) + ")"
            elif label == "list":
                listing = ""
                if base_listing if side == "base" else True:
                    listing += f"{bench.KERNEL_TEST}: test\n"
                if lane_base_listing if side == "base" else True:
                    listing += "".join(f"{test}: test\n" for test in bench.LANE_TESTS.values())
                code = "print(" + repr(listing) + ")"
            elif label.endswith("-run"):
                if label == f"{side}-run":
                    report = results.get(side)
                else:
                    report = lane_results.get(side, {}).get(label[len(side) + 1:-len("-run")])
                code = "pass" if report is None else (
                    "import os; open(os.environ[" + repr(bench.KERNEL_RESULT_ENV) + "], 'x').write("
                    + repr(json.dumps(report)) + ")")
            else:
                raise AssertionError(f"unexpected kernel process: {label}")
            return real_bounded([sys.executable, "-c", code], working, label, seconds, deadline, env)

        def prepare(_root, _revision, tree, _ui_source, _deadline):
            tree.mkdir(parents=True, exist_ok=True)
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(b"fixture executable")
            (executable.parent / "gateway-test-other").write_bytes(b"fixture executable")

        configuration = (sys.executable, harness(), budget(),
                         {**context(), "budget": budget(), "proposed_budget": budget()})
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(bench, "resolve_commit", side_effect=lambda _root, revision: revision))
            stack.enter_context(mock.patch.object(bench, "_configuration", return_value=configuration))
            stack.enter_context(mock.patch.object(
                bench, "_measure", side_effect=lambda _root, revision, *_args, **_kwargs: self.pure_envelope(revision)))
            stack.enter_context(mock.patch.object(bench, "_kernel_configuration", return_value=kernel))
            stack.enter_context(mock.patch.object(bench, "_lane_configuration", return_value=lanes))
            stack.enter_context(mock.patch.object(bench, "_prepare_tree", side_effect=prepare))
            stack.enter_context(mock.patch.object(bench, "_bounded", side_effect=bounded))
            report = bench.run_comparison(BASE, HEAD, output, root=ROOT, work=work)
        stored = json.loads((output / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(stored, report)
        return report, output

    def test_each_revision_cleans_the_gateway_and_measures_its_own_binary_copy(self):
        # A shared target directory once let the head build reuse the base
        # binary: Cargo judged the second tree fresh and listed zero tests.
        with tempfile.TemporaryDirectory() as directory:
            report, _ = self.run_stage(directory, results={"base": None, "head": kernel_result()})
            self.assertEqual(report["status"], "passed", report["errors"])
            for side in ("base", "head"):
                labels = [label for owner, label in self.kernel_calls if owner == side]
                self.assertEqual(labels[:2], ["clean", "build"], labels)
                copy = Path(directory) / "work" / "binaries" / side / "gateway-test"
                self.assertEqual(copy.read_bytes(), b"fixture executable")

    def test_pending_head_measurement_over_a_base_without_the_harness_passes(self):
        with tempfile.TemporaryDirectory() as directory:
            report, output = self.run_stage(directory, results={"base": None, "head": kernel_result()})
            self.assertEqual(report["status"], "passed", report["errors"])
            self.assertEqual(report["kernel"]["state"], "pending")
            self.assertEqual(report["kernel"]["base"], "absent")
            self.assertEqual(report["kernel"]["status"], "informational")
            self.assertFalse((output / "base.kernel.json").exists())
            self.assertTrue((output / "head.kernel.json").is_file())
            build = json.loads((output / "base-kernel" / "build.json").read_text(encoding="utf-8"))
            self.assertFalse(build["listed"])

    def test_discovery_that_disagrees_with_the_source_wiring_fails(self):
        for options in ({"base_listing": True}, {"base_digest": "f" * 64, "base_listing": False}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                report, _ = self.run_stage(directory, **options)
                self.assertEqual(report["status"], "failed")
                self.assertIn("discovery", " ".join(report["errors"]))

    def test_enforced_growth_blocks_and_neutral_counts_pass(self):
        for allocations, status in ((41700, "passed"), (41600, "passed"), (41701, "failed")):
            with self.subTest(allocations=allocations), tempfile.TemporaryDirectory() as directory:
                report, _ = self.run_stage(
                    directory, state="enforced", base_digest="f" * 64,
                    results={"base": kernel_result(), "head": kernel_result(allocations)})
                self.assertEqual(report["status"], status)
                self.assertEqual(report["kernel"]["status"], status)
                self.assertEqual(report["kernel"]["comparison"]["status"], status)

    def test_unenforced_growth_is_reported_without_blocking(self):
        for state in ("pending", "proposed"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                report, _ = self.run_stage(
                    directory, state=state, base_digest="f" * 64,
                    results={"base": kernel_result(), "head": kernel_result(41701)})
                self.assertEqual(report["status"], "passed", report["errors"])
                self.assertEqual(report["kernel"]["status"], "informational")
                self.assertEqual(report["kernel"]["comparison"]["status"], "failed")

    def test_head_crash_timeout_missing_or_mislabelled_report_never_reuses_base(self):
        cases = (
            ({"failures": {"head:head-run": "crash"}}, "exit code 23"),
            ({"failures": {"head:head-run": "timeout"}}, "runtime bound"),
            ({"failures": {"head:build": "crash"}}, "exit code 23"),
            ({"results": {"base": kernel_result(), "head": None}}, ""),
            ({"results": {"base": kernel_result(), "head": kernel_result(regression=True)}}, "fixture marker"),
            ({"build_executables": 2}, "exactly one"),
        )
        for options, message in cases:
            with self.subTest(options=sorted(options)), tempfile.TemporaryDirectory() as directory:
                report, output = self.run_stage(directory, state="enforced", base_digest="f" * 64,
                                                **options)
                self.assertEqual(report["status"], "failed")
                self.assertTrue(report["errors"])
                self.assertIn(message, " ".join(report["errors"]))
                self.assertFalse((output / "head.kernel.json").exists())
                self.assertNotIn("kernel", report)

    def test_pending_lanes_over_a_base_without_them_are_measured_and_informational(self):
        with tempfile.TemporaryDirectory() as directory:
            report, output = self.run_stage(directory)
            self.assertEqual(report["status"], "passed", report["errors"])
            lanes = report["lanes"]
            self.assertEqual((lanes["state"], lanes["base"], lanes["status"], lanes["blocking"]),
                             ("pending", "absent", "informational", False))
            self.assertEqual(sorted(lanes["head"]), ["rate_lane", "tool_policy"])
            self.assertEqual(lanes["comparisons"], [])
            for target in ("tool_policy", "rate_lane"):
                self.assertTrue((output / f"head.{target}.kernel.json").is_file())
                self.assertTrue((output / f"head.{target}.kernel.raw.json").is_file())
                self.assertFalse((output / f"base.{target}.kernel.json").exists())
            for side, listed in (("base", False), ("head", True)):
                build = json.loads((output / f"{side}-kernel" / "build.json").read_text(encoding="utf-8"))
                self.assertEqual(build["lanes_listed"], {"tool_policy": listed, "rate_lane": listed})

    def test_enforced_lane_growth_blocks_and_neutral_counts_pass(self):
        for target in ("tool_policy", "rate_lane"):
            for delta, status in ((0, "passed"), (-1, "passed"), (1, "failed")):
                with self.subTest(target=target, delta=delta), tempfile.TemporaryDirectory() as directory:
                    head = lane_results_by_target()
                    head[target] = lane_result(target, LANE_CASES[target] * 1000 + delta)
                    report, _ = self.run_stage(
                        directory, lane_state="enforced", lane_base_digest="e" * 64,
                        lane_results={"base": lane_results_by_target(), "head": head})
                    self.assertEqual(report["status"], status, report["errors"])
                    self.assertEqual(report["lanes"]["status"], status)
                    self.assertEqual(report["lanes"]["base"], "measured")
                    statuses = {entry["id"]: entry["status"] for entry in report["lanes"]["comparisons"]}
                    self.assertEqual(statuses[target], status)
                    if status == "failed":
                        self.assertIn(f"{target}: allocation growth", " ".join(report["errors"]))

    def test_unenforced_lane_growth_is_reported_without_blocking(self):
        for lane_state in ("pending", "proposed"):
            with self.subTest(lane_state=lane_state), tempfile.TemporaryDirectory() as directory:
                head = lane_results_by_target()
                head["rate_lane"] = lane_result("rate_lane", 14001)
                report, _ = self.run_stage(
                    directory, lane_state=lane_state, lane_base_digest="e" * 64,
                    lane_results={"base": lane_results_by_target(), "head": head})
                self.assertEqual(report["status"], "passed", report["errors"])
                self.assertEqual(report["lanes"]["status"], "informational")
                statuses = {entry["id"]: entry["status"] for entry in report["lanes"]["comparisons"]}
                self.assertEqual(statuses, {"tool_policy": "passed", "rate_lane": "failed"})

    def test_lane_discovery_that_disagrees_with_the_source_wiring_fails(self):
        for options in ({"lane_base_listing": True},
                        {"lane_base_digest": "e" * 64, "lane_base_listing": False}):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as directory:
                report, _ = self.run_stage(directory, **options)
                self.assertEqual(report["status"], "failed")
                self.assertIn("lane benchmark test discovery", " ".join(report["errors"]))

    def test_lane_crash_timeout_missing_or_mislabelled_report_fails(self):
        def head(**reports):
            return {"base": lane_results_by_target(), "head": {**lane_results_by_target(), **reports}}

        cases = (
            ({"failures": {"head:head-tool_policy-run": "crash"}}, "exit code 23"),
            ({"failures": {"head:head-rate_lane-run": "timeout"}}, "runtime bound"),
            ({"lane_results": head(rate_lane=None)}, ""),
            ({"lane_results": head(tool_policy=lane_result("rate_lane"))}, "schema order"),
            ({"lane_results": head(rate_lane=lane_result("rate_lane", regression=True))},
             "fixture marker"),
        )
        for options, message in cases:
            with self.subTest(options=sorted(options)), tempfile.TemporaryDirectory() as directory:
                report, _ = self.run_stage(directory, lane_state="enforced",
                                           lane_base_digest="e" * 64, **options)
                self.assertEqual(report["status"], "failed")
                self.assertTrue(report["errors"])
                self.assertIn(message, " ".join(report["errors"]))
                self.assertNotIn("lanes", report)

    def test_kernel_failure_after_a_passing_pure_comparison_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(bench, "_kernel_stage", side_effect=ValueError("kernel unavailable")):
                configuration = (sys.executable, harness(), budget(),
                                 {**context(), "budget": budget(), "proposed_budget": budget()})
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.object(bench, "resolve_commit", side_effect=lambda _root, revision: revision))
                    stack.enter_context(mock.patch.object(bench, "_configuration", return_value=configuration))
                    stack.enter_context(mock.patch.object(
                        bench, "_measure", side_effect=lambda _root, revision, *_a, **_k: self.pure_envelope(revision)))
                    report = bench.run_comparison(BASE, HEAD, Path(directory) / "out", root=ROOT,
                                                  work=Path(directory) / "work")
            self.assertEqual(report["status"], "failed")
            self.assertEqual([target["status"] for target in report["targets"]], ["passed"] * 4)
            self.assertIn("kernel unavailable", report["errors"])


if __name__ == "__main__":
    unittest.main()
