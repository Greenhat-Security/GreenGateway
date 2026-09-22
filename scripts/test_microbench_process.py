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


if __name__ == "__main__":
    unittest.main()
