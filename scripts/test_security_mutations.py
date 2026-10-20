#!/usr/bin/env python3
"""Controller contracts and real Rust calibration for the security pilot."""
import copy
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

import security_mutations as mutations


SOURCE = b"fn allowed(value: u8) -> bool {\n    value < 4\n}\n"
TEST_NAME = "security::rejects_boundary"


def manifest_fixture():
    return {"schema_version": 1, "harness_version": mutations.VERSION, "targets": [{
        "id": "predicate", "path": "source.rs", "function": "allowed", "start_marker": "fn allowed(",
        "end_marker": "\n}\n", "source_sha256": mutations.sha256(SOURCE), "tests": [TEST_NAME],
        "mutations": [{"id": "weaken", "old": "value < 4", "new": "value <= 4"}],
    }], "exceptions": []}


def process(output=b"", code=0, **kwargs):
    return mutations.ProcessResult(code, output, b"", 0.01, **kwargs)


def test_output(passed=True, *, ignored=0, name=TEST_NAME):
    status = "ok" if passed else "FAILED"
    return (f"\nrunning 1 test\ntest {name} ... {status}\n\n"
            f"test result: {status}. {int(passed)} passed; {int(not passed)} failed; {ignored} ignored; "
            "0 measured; 9 filtered out; finished in 0.00s\n").encode()


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "source.rs").write_bytes(SOURCE)
        self.path = self.root / "manifest.json"
        self.manifest = manifest_fixture()

    def load(self):
        self.path.write_text(json.dumps(self.manifest))
        return mutations.load_manifest(self.root, self.path)

    def assert_rejected(self, category):
        with self.assertRaises(mutations.HarnessError) as raised:
            self.load()
        self.assertEqual(category, raised.exception.category)

    def validate(self, *arguments):
        report = self.root / "target/report.json"
        # A compiler, test or git process would make this more than a registry check.
        with mock.patch.object(mutations.subprocess, "Popen", side_effect=AssertionError("process started")) as popen, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            code = mutations.main(["--validate-registry", "--report", str(report), *arguments])
        popen.assert_not_called()
        self.printed = stdout.getvalue()
        return code, json.loads(report.read_text())

    def validate_fixture(self):
        self.path.write_text(json.dumps(self.manifest))
        return self.validate("--root", str(self.root), "--manifest", str(self.path))

    def test_current_registry_is_nonempty_and_resolves(self):
        root = Path(__file__).resolve().parents[1]
        manifest, mutants = mutations.load_manifest(root, root / "security-mutations.json")
        self.assertGreater(len(mutants), 0)
        self.assertEqual(len({mutant["id"] for mutant in mutants}), len(mutants))
        self.assertEqual(len(manifest["targets"]), 4)

    def test_current_registry_passes_the_pull_request_drift_check(self):
        root = Path(__file__).resolve().parents[1]
        code, report = self.validate()
        self.assertEqual((0, "passed", "registry_valid"), (code, report["status"], report["reason"]))
        self.assertEqual(mutations.sha256((root / "security-mutations.json").read_bytes()), report["registry_sha256"])
        self.assertEqual(len(mutations.load_manifest(root, root / "security-mutations.json")[1]), report["registered_mutants"])

    def test_valid_manifest_and_identity_bind_source_and_change(self):
        _, mutants = self.load()
        original = mutants[0]["mutation_sha256"]
        self.manifest["targets"][0]["mutations"][0]["new"] = "false"
        self.assertNotEqual(original, self.load()[1][0]["mutation_sha256"])
        self.assertEqual(mutants[0]["id"], "predicate/weaken")

    def test_empty_registry_fails(self):
        self.manifest["targets"] = []
        self.assert_rejected("invalid_target_count")

    def test_schema_bool_is_not_integer(self):
        self.manifest["schema_version"] = True
        self.assert_rejected("unsupported_version")

    def test_unknown_schema_key_fails(self):
        self.manifest["surprise"] = True
        self.assert_rejected("invalid_schema")

    def test_duplicate_json_key_fails(self):
        self.path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(mutations.HarnessError, "duplicate_json_key"):
            mutations.read_json(self.path, mutations.MAX_MANIFEST)

    def test_nonfinite_json_fails(self):
        self.path.write_text('{"value":NaN}')
        with self.assertRaisesRegex(mutations.HarnessError, "invalid_json"):
            mutations.read_json(self.path, mutations.MAX_MANIFEST)

    def test_stale_source_hash_fails(self):
        (self.root / "source.rs").write_bytes(SOURCE.replace(b"4", b"5"))
        self.assert_rejected("function_hash_drift")

    def test_renamed_function_fails(self):
        (self.root / "source.rs").write_bytes(SOURCE.replace(b"allowed", b"renamed"))
        self.assert_rejected("function_scope_drift")

    def test_moved_file_fails(self):
        (self.root / "source.rs").rename(self.root / "moved.rs")
        self.assert_rejected("invalid_file")

    def test_ambiguous_function_fails(self):
        (self.root / "source.rs").write_bytes(SOURCE + SOURCE)
        self.assert_rejected("function_scope_drift")

    def test_traversal_and_absolute_paths_fail(self):
        for path in ("../source.rs", "/source.rs", "./source.rs", "part/../source.rs"):
            with self.subTest(path=path):
                self.manifest["targets"][0]["path"] = path
                self.assert_rejected("unsafe_path")

    def test_symlink_file_and_parent_fail(self):
        (self.root / "link.rs").symlink_to(self.root / "source.rs")
        self.manifest["targets"][0]["path"] = "link.rs"
        self.assert_rejected("unsafe_path")
        (self.root / "linkdir").symlink_to(self.root, target_is_directory=True)
        self.manifest["targets"][0]["path"] = "linkdir/source.rs"
        self.assert_rejected("unsafe_path")

    def test_fifo_rejected_without_opening(self):
        (self.root / "source.rs").unlink()
        os.mkfifo(self.root / "source.rs")
        self.assert_rejected("invalid_file")

    def test_duplicate_target_and_overlapping_scope_fail(self):
        self.manifest["targets"].append(copy.deepcopy(self.manifest["targets"][0]))
        self.assert_rejected("duplicate_target")
        self.manifest["targets"][1]["id"] = "second"
        self.assert_rejected("overlapping_targets")

    def test_empty_and_duplicate_selected_tests_fail(self):
        self.manifest["targets"][0]["tests"] = []
        self.assert_rejected("invalid_test_count")
        self.manifest["targets"][0]["tests"] = [TEST_NAME, TEST_NAME]
        self.assert_rejected("duplicate_test")

    def test_duplicate_mutant_and_identical_replacement_fail(self):
        target = self.manifest["targets"][0]
        target["mutations"].append(copy.deepcopy(target["mutations"][0]))
        self.assert_rejected("duplicate_mutation")
        target["mutations"] = target["mutations"][:1]
        target["mutations"][0]["new"] = target["mutations"][0]["old"]
        self.assert_rejected("invalid_replacement")

    def test_missing_or_ambiguous_replacement_fails(self):
        self.manifest["targets"][0]["mutations"][0]["old"] = "missing"
        self.assert_rejected("invalid_replacement")
        self.manifest["targets"][0]["mutations"][0]["old"] = "value"
        self.assert_rejected("invalid_replacement")

    def exception(self):
        target = self.manifest["targets"][0]
        return {"mutant_id": "predicate/weaken", "mutation_sha256": mutations.mutation_digest(target, target["mutations"][0]),
                "outcome": "survived", "owner": "Greenhat-Security/maintainers", "reason": "Reviewed equivalent boundary."}

    def test_bound_exception_valid_but_stale_digest_rejected(self):
        self.manifest["exceptions"] = [self.exception()]
        self.load()
        self.manifest["exceptions"][0]["mutation_sha256"] = "0" * 64
        self.assert_rejected("stale_exception")

    def test_missing_mutant_duplicate_and_timeout_exceptions_fail(self):
        self.manifest["exceptions"] = [self.exception()]
        self.manifest["exceptions"][0]["mutant_id"] = "gone/missing"
        self.assert_rejected("stale_exception")
        self.manifest["exceptions"] = [self.exception()]
        self.manifest["exceptions"][0]["outcome"] = "timed_out"
        self.assert_rejected("stale_exception")
        self.manifest["exceptions"] = [self.exception(), self.exception()]
        self.assert_rejected("invalid_exceptions")

    def test_registry_check_reports_identity_but_never_a_score(self):
        code, report = self.validate_fixture()
        self.assertEqual((0, "passed", "registry_valid"), (code, report["status"], report["reason"]))
        self.assertEqual("checkout_registry_only", report["source_state"])
        self.assertEqual(mutations.sha256(self.path.read_bytes()), report["registry_sha256"])
        self.assertEqual([{"id": "predicate", "path": "source.rs", "function": "allowed",
                           "source_sha256": mutations.sha256(SOURCE), "tests": [TEST_NAME]}], report["targets"])
        self.assertEqual(1, report["registered_mutants"])
        self.assertEqual([], report["results"])
        self.assertEqual(mutations.counts([]), report["counts"])
        self.assertNotIn("baseline", report)
        # A registry check must never read as a campaign result in a CI log.
        self.assertEqual("security mutation registry check: passed (registry_valid)\n", self.printed)

    def test_registry_check_fails_closed_on_target_source_drift(self):
        for label, source, category in (("edited", SOURCE.replace(b"4", b"5"), "function_hash_drift"),
                                        ("renamed", SOURCE.replace(b"allowed", b"renamed"), "function_scope_drift"),
                                        ("duplicated", SOURCE + SOURCE, "function_scope_drift"),
                                        ("crlf", SOURCE.replace(b"\n", b"\r\n"), "function_scope_drift")):
            with self.subTest(label=label):
                (self.root / "source.rs").write_bytes(source)
                code, report = self.validate_fixture()
                self.assertEqual((1, "failed", category), (code, report["status"], report["reason"]))
                self.assertNotIn("targets", report)
                self.assertEqual(f"security mutation registry check: failed ({category})\n", self.printed)
        (self.root / "source.rs").unlink()
        code, report = self.validate_fixture()
        self.assertEqual((1, "invalid_file"), (code, report["reason"]))

    def test_registry_check_fails_closed_on_unreconciled_registry(self):
        def unknown_version(manifest):
            manifest["harness_version"] = "0.0.0"

        def duplicated_test(manifest):
            manifest["targets"][0]["tests"] = [TEST_NAME, TEST_NAME]

        def invalid_test_name(manifest):
            manifest["targets"][0]["tests"] = ["security::rejects boundary"]

        def missing_anchor(manifest):
            manifest["targets"][0]["mutations"][0]["old"] = "value <= 4"

        def stale_exception(manifest):
            manifest["exceptions"] = [self.exception()]
            manifest["exceptions"][0]["mutation_sha256"] = "0" * 64

        for change, category in ((unknown_version, "unsupported_version"), (duplicated_test, "duplicate_test"),
                                 (invalid_test_name, "invalid_test_name"), (missing_anchor, "invalid_replacement"),
                                 (stale_exception, "stale_exception")):
            with self.subTest(change=change.__name__):
                self.manifest = manifest_fixture()
                change(self.manifest)
                code, report = self.validate_fixture()
                self.assertEqual((1, "failed", category), (code, report["status"], report["reason"]))

    def test_registry_check_requires_a_registry_inside_the_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            self.path = Path(directory) / "manifest.json"
            code, report = self.validate_fixture()
        self.assertEqual((1, "manifest_outside_repository"), (code, report["reason"]))

    def test_registry_check_cannot_be_combined_with_calibration(self):
        report = self.root / "target/report.json"
        with mock.patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit) as raised:
            mutations.main(["--validate-registry", "--calibrate", "--report", str(report)])
        self.assertEqual(2, raised.exception.code)
        self.assertFalse(report.exists())


def listing(*names, kind="test"):
    return "".join(f"{name}: {kind}\n" for name in names).encode()


class TestListTests(unittest.TestCase):
    """`--check-test-list` reads a listing file; it never starts a compiler, test or git process."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "source.rs").write_bytes(SOURCE)
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps(manifest_fixture()))
        self.listing = self.root / "target/test-list.txt"
        self.listing.parent.mkdir()

    def check(self, listed=None):
        if listed is not None:
            self.listing.write_bytes(listed)
        report = self.root / "target/report.json"
        with mock.patch.object(mutations.subprocess, "Popen", side_effect=AssertionError("process started")) as popen, \
                mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            code = mutations.main(["--check-test-list", str(self.listing), "--root", str(self.root),
                                   "--manifest", str(self.manifest), "--report", str(report)])
        popen.assert_not_called()
        self.printed = stdout.getvalue()
        return code, json.loads(report.read_text())

    def test_each_selected_test_listed_exactly_once_passes(self):
        listed = listing("security::accepts_boundary", TEST_NAME, "other::tests::unrelated")
        code, report = self.check(listed)
        self.assertEqual((0, "passed", "registry_tests_listed"), (code, report["status"], report["reason"]))
        self.assertEqual("checkout_registry_and_test_list", report["source_state"])
        self.assertEqual(mutations.sha256(self.manifest.read_bytes()), report["registry_sha256"])
        self.assertEqual(mutations.sha256(listed), report["test_list_sha256"])
        self.assertEqual(3, report["listed_tests"])
        self.assertEqual([TEST_NAME], report["selected_tests"])
        self.assertEqual(([], []), (report["unlisted_tests"], report["ambiguous_tests"]))
        # Listing a test is not running it: there is no baseline and no score.
        self.assertEqual([], report["results"])
        self.assertEqual(mutations.counts([]), report["counts"])
        self.assertNotIn("baseline", report)
        self.assertEqual("security mutation registry check: passed (registry_tests_listed)\n", self.printed)

    def test_renamed_or_deleted_selected_test_fails_and_is_named(self):
        # Only the exact name counts, as with the campaign's `--exact` discovery.
        for label, listed in (("renamed", listing("security::rejects_the_boundary")),
                              ("deleted", listing("other::tests::unrelated")),
                              ("extended", listing(TEST_NAME + "_extended")),
                              ("nested", listing("outer::" + TEST_NAME)),
                              ("truncated", listing("security::rejects"))):
            with self.subTest(label=label):
                code, report = self.check(listed)
                self.assertEqual((1, "failed", "registry_test_not_listed"), (code, report["status"], report["reason"]))
                self.assertEqual(([TEST_NAME], []), (report["unlisted_tests"], report["ambiguous_tests"]))
                self.assertEqual("security mutation registry check: failed (registry_test_not_listed)\n"
                                 f"  unlisted: {TEST_NAME}\n", self.printed)

    def test_selected_test_listed_twice_or_as_benchmark_is_ambiguous(self):
        for label, listed in (("two binaries", listing(TEST_NAME, "other::tests::unrelated", TEST_NAME)),
                              ("benchmark", listing(TEST_NAME, kind="benchmark")),
                              ("test and benchmark", listing(TEST_NAME) + listing(TEST_NAME, kind="benchmark"))):
            with self.subTest(label=label):
                code, report = self.check(listed)
                self.assertEqual((1, "failed", "registry_test_ambiguous"), (code, report["status"], report["reason"]))
                self.assertEqual(([], [TEST_NAME]), (report["unlisted_tests"], report["ambiguous_tests"]))
                self.assertEqual("security mutation registry check: failed (registry_test_ambiguous)\n"
                                 f"  ambiguous: {TEST_NAME}\n", self.printed)

    def test_every_unlisted_and_ambiguous_test_is_reported(self):
        manifest = manifest_fixture()
        manifest["targets"][0]["tests"] = ["security::z_last", TEST_NAME, "security::a_first"]
        self.manifest.write_text(json.dumps(manifest))
        code, report = self.check(listing(TEST_NAME, TEST_NAME))
        self.assertEqual((1, "registry_test_not_listed"), (code, report["reason"]))
        self.assertEqual(["security::a_first", "security::z_last"], report["unlisted_tests"])
        self.assertEqual([TEST_NAME], report["ambiguous_tests"])

    def test_anything_but_a_terse_libtest_listing_fails_closed(self):
        for label, listed, category in (
                ("pretty summary", listing(TEST_NAME) + b"\n1 test, 0 benchmarks\n", "invalid_test_list"),
                ("test result line", listing(TEST_NAME) + f"test {TEST_NAME} ... ok\n".encode(), "invalid_test_list"),
                ("unknown kind", f"{TEST_NAME}: doctest\n".encode(), "invalid_test_list"),
                ("crlf", listing(TEST_NAME).replace(b"\n", b"\r\n"), "invalid_test_list"),
                ("unnamed", b": test\n" + listing(TEST_NAME), "invalid_test_list"),
                ("non-utf8", listing(TEST_NAME) + b"\xff: test\n", "invalid_test_list"),
                ("empty", b"", "empty_test_list"),
                ("blank lines", b"\n\n", "empty_test_list")):
            with self.subTest(label=label):
                code, report = self.check(listed)
                self.assertEqual((1, "failed", category), (code, report["status"], report["reason"]))
                self.assertNotIn("unlisted_tests", report)

    def reason(self, listed=None):
        code, report = self.check(listed)
        return code, report["reason"]

    def test_missing_linked_special_or_oversized_listing_fails(self):
        self.assertEqual((1, "invalid_test_list_file"), self.reason())
        real = self.root / "target/real.txt"
        real.write_bytes(listing(TEST_NAME))
        self.listing.symlink_to(real)
        self.assertEqual((1, "invalid_test_list_file"), self.reason())
        self.listing.unlink()
        # A FIFO is rejected without being opened, so this cannot block.
        os.mkfifo(self.listing)
        self.assertEqual((1, "invalid_test_list_file"), self.reason())
        self.listing.unlink()
        with mock.patch.object(mutations, "MAX_TEST_LIST", len(listing(TEST_NAME)) - 1):
            self.assertEqual((1, "test_list_limit"), self.reason(listing(TEST_NAME)))

    def test_registry_drift_fails_before_the_listing_is_read(self):
        (self.root / "source.rs").write_bytes(SOURCE.replace(b"4", b"5"))
        code, report = self.check(listing(TEST_NAME))
        self.assertEqual((1, "function_hash_drift"), (code, report["reason"]))
        self.assertNotIn("test_list_sha256", report)

    def test_listing_check_is_its_own_mode(self):
        report = self.root / "target/report.json"
        for other in ("--validate-registry", "--calibrate"):
            with self.subTest(other=other):
                with mock.patch("sys.stderr", new_callable=io.StringIO), self.assertRaises(SystemExit) as raised:
                    mutations.main(["--check-test-list", str(self.listing), other, "--report", str(report)])
                self.assertEqual(2, raised.exception.code)
        self.assertFalse(report.exists())


class ResultTests(unittest.TestCase):
    def test_only_exact_named_single_test_can_kill(self):
        self.assertEqual("killed", mutations.classify_test(process(test_output(False), 101), TEST_NAME))
        self.assertEqual("survived", mutations.classify_test(process(test_output(), 0), TEST_NAME))
        self.assertEqual("harness_error", mutations.classify_test(process(test_output(False, name="wrong"), 101), TEST_NAME))

    def test_zero_ignored_duplicate_and_missing_results_are_errors(self):
        outputs = [b"test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
                   test_output(ignored=1), test_output() * 2, b"panic: synthetic-private-input"]
        for output in outputs:
            with self.subTest(output=output):
                self.assertEqual("harness_error", mutations.classify_test(process(output), TEST_NAME))

    def test_nonzero_infrastructure_exit_is_never_kill(self):
        for code in (1, 2, -signal.SIGSEGV, -signal.SIGKILL):
            with self.subTest(code=code):
                self.assertEqual("harness_error", mutations.classify_test(process(test_output(False), code), TEST_NAME))

    def test_timeout_and_truncation_are_not_kills(self):
        self.assertEqual("timed_out", mutations.classify_test(process(test_output(False), 101, timed_out=True), TEST_NAME))
        self.assertEqual("harness_error", mutations.classify_test(process(test_output(False), 101, output_exceeded=True), TEST_NAME))

    def test_exact_discovery_rejects_missing_duplicate_or_wrong_test(self):
        mutations.discover_test(process((TEST_NAME + ": test\n\n1 test, 0 benchmarks\n").encode()), TEST_NAME)
        for output in (b"0 tests, 0 benchmarks\n", b"other: test\n\n1 test, 0 benchmarks\n", (TEST_NAME + ": test\n") .encode() * 2):
            with self.assertRaises(mutations.HarnessError):
                mutations.discover_test(process(output), TEST_NAME)

    def test_unviable_requires_primary_compiler_error_at_mutated_file(self):
        def diagnostic(file, primary=True, level="error"):
            return mutations.canonical({"reason": "compiler-message", "message": {"level": level,
                "spans": [{"file_name": file, "is_primary": primary}]}})
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for output, expected in ((diagnostic("source.rs"), "unviable"), (diagnostic("build.rs"), "harness_error"),
                                     (diagnostic("source.rs", False), "harness_error"), (diagnostic("source.rs", level="warning"), "harness_error"),
                                     (b"could not execute compiler: synthetic-private-error", "harness_error")):
                outcome, _ = mutations.classify_build(process(output, 101), path, path, "source.rs")
                self.assertEqual(expected, outcome)

    def test_baseline_compile_error_is_harness_failure(self):
        output = mutations.canonical({"reason": "compiler-message", "message": {"level": "error", "spans": [{"file_name": "source.rs", "is_primary": True}]}})
        self.assertEqual("harness_error", mutations.classify_build(process(output, 101), Path("/tmp"), Path("/tmp"))[0])

    def test_build_artifact_requires_exact_gateway_test_binary_and_finish(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            binary = path / "gateway"
            binary.write_bytes(b"synthetic executable placeholder")
            artifact = {"reason": "compiler-artifact", "target": {"name": "gateway", "kind": ["bin"]},
                        "profile": {"test": True}, "executable": str(binary)}
            finish = {"reason": "build-finished", "success": True}
            output = b"\n".join(map(mutations.canonical, [artifact, finish]))
            self.assertEqual(("built", binary), mutations.classify_build(process(output), path, path))
            self.assertEqual("harness_error", mutations.classify_build(process(mutations.canonical(artifact)), path, path)[0])
            self.assertEqual("harness_error", mutations.classify_build(process(output + b"\n" + mutations.canonical(artifact)), path, path)[0])
            artifact["profile"]["test"] = False
            self.assertEqual("harness_error", mutations.classify_build(process(b"\n".join(map(mutations.canonical, [artifact, finish]))), path, path)[0])

    def test_exceptions_execute_and_changed_outcome_is_stale(self):
        exception = {"outcome": "survived", "owner": "maintainer", "reason": "synthetic-private-review-text"}
        survived = {"outcome": "survived"}
        self.assertTrue(mutations.apply_exception(survived, exception))
        self.assertTrue(survived["excluded"])
        self.assertNotIn(exception["reason"], json.dumps(survived))
        killed = {"outcome": "killed"}
        self.assertFalse(mutations.apply_exception(killed, exception))
        self.assertEqual("stale", killed["exception_status"])
        self.assertFalse(mutations.apply_exception({"outcome": "survived"}, None))
        self.assertTrue(mutations.apply_exception({"outcome": "killed"}, None))

    def test_planned_counts_do_not_shrink_when_campaign_stops_early(self):
        result = mutations.counts([{"outcome": "killed"}, {"outcome": "timed_out"}], 8)
        self.assertEqual(8, result["generated"])
        self.assertEqual(2, result["completed"])
        self.assertEqual(6, result["not_run"])

    def test_counts_keep_exclusion_as_separate_subset(self):
        result = mutations.counts([{"outcome": "survived", "excluded": True}, {"outcome": "killed"}, {"outcome": "timed_out"}])
        self.assertEqual(3, result["generated"])
        self.assertEqual(1, result["survived"])
        self.assertEqual(1, result["excluded"])
        self.assertEqual(1, result["timed_out"])
        self.assertNotIn("score", result)


class ExecutionAndEvidenceTests(unittest.TestCase):
    def test_real_rust_calibration_distinguishes_three_outcomes(self):
        root = Path(__file__).resolve().parents[1]
        pins = json.loads((root / "build-tools.json").read_text())
        observed = mutations.calibrate(dict(os.environ, RUSTUP_TOOLCHAIN=pins["rust_ci"]))
        self.assertEqual({outcome: outcome for outcome in ("killed", "survived", "unviable")}, observed)

    def run_python(self, code, *, wall=3, cpu=2, memory=256, limit=65536):
        return mutations.run_process([sys.executable, "-c", code], Path.cwd(), dict(os.environ),
                                     wall_seconds=wall, cpu_seconds=cpu, memory_mib=memory, output_limit=limit)

    def test_actual_wall_timeout_is_not_killed(self):
        result = self.run_python("import time;time.sleep(10)", wall=0.2)
        self.assertTrue(result.timed_out)
        self.assertEqual("timed_out", mutations.classify_test(result, TEST_NAME))

    def test_actual_cpu_exhaustion_is_timeout(self):
        result = self.run_python("while True: pass", wall=5, cpu=1)
        self.assertTrue(result.timed_out)
        self.assertEqual("timed_out", mutations.classify_test(result, TEST_NAME))

    def test_actual_memory_failure_is_not_killed(self):
        result = self.run_python("bytearray(1024*1024*512)", memory=128)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual("harness_error", mutations.classify_test(result, TEST_NAME))

    def test_actual_output_flood_is_bounded_failure(self):
        result = self.run_python("import os;os.write(1,b'x'*100000)", limit=4096)
        self.assertTrue(result.output_exceeded)
        self.assertLessEqual(len(result.stdout), 4096)
        self.assertEqual("harness_error", mutations.classify_test(result, TEST_NAME))

    def test_report_destination_cannot_overwrite_original_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "source.rs"
            file.write_bytes(SOURCE)
            with mock.patch("builtins.print"):
                code = mutations.main(["--root", str(root), "--report", str(file)])
            self.assertEqual(1, code)
            self.assertEqual(SOURCE, file.read_bytes())
            self.assertEqual(root / "target/report.json", mutations.validate_report_path(root / "target/report.json", root))

    def test_report_symlink_and_symlink_parent_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "target").mkdir()
            (root / "source.rs").write_bytes(SOURCE)
            (root / "target/report.json").symlink_to(root / "source.rs")
            with self.assertRaisesRegex(mutations.HarnessError, "unsafe_report_path"):
                mutations.validate_report_path(root / "target/report.json", root)
            (root / "alias").symlink_to(root / "target", target_is_directory=True)
            with self.assertRaisesRegex(mutations.HarnessError, "unsafe_report_path"):
                mutations.validate_report_path(root / "alias/other.json", root)
            self.assertEqual(SOURCE, (root / "source.rs").read_bytes())

    def test_report_overflow_changes_success_to_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "report.json"
            report = {"status": "passed", "private": "do-not-publish" * mutations.MAX_REPORT}
            self.assertFalse(mutations.write_report(file, report))
            actual = json.loads(file.read_text())
            self.assertEqual("failed", report["status"])
            self.assertEqual("report_limit", actual["reason"])
            self.assertNotIn("do-not-publish", file.read_text())
            self.assertLess(file.stat().st_size, mutations.MAX_REPORT)

    def test_checkpoint_overflow_aborts_before_success_even_when_cleanup_shrinks_report(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            reached_success = []

            def last_case_checkpoint(args, report):
                report["active_mutant"] = "x" * mutations.MAX_REPORT
                try:
                    mutations.checkpoint_report(args.report, report)
                finally:
                    # Model the cleanup that made the final report fit again.
                    report.pop("active_mutant")
                reached_success.append(True)
                report.update(status="passed", reason="all_reviewed_mutants_accounted")

            with mock.patch.object(mutations, "campaign", side_effect=last_case_checkpoint), mock.patch("builtins.print"):
                code = mutations.main(["--report", str(destination)])
            final = json.loads(destination.read_text())
            self.assertEqual(1, code)
            self.assertEqual([], reached_success)
            self.assertEqual("failed", final["status"])
            self.assertEqual("report_limit", final["reason"])
            # This is the ordinary final report, not the oversized-report fallback.
            self.assertIn("counts", final)
            self.assertLess(destination.stat().st_size, mutations.MAX_REPORT)

    def test_failure_report_written_for_invalid_limits_without_raw_error(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            with mock.patch("builtins.print"):
                code = mutations.main(["--report", str(report), "--test-seconds", "0"])
            actual = json.loads(report.read_text())
            self.assertEqual(1, code)
            self.assertEqual("failed", actual["status"])
            self.assertEqual("invalid_limits", actual["reason"])
            self.assertEqual(0, actual["counts"]["generated"])

    def test_unexpected_errors_are_redacted_and_incomplete_is_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            def explode(args, record):
                self.assertEqual("failed", json.loads(report.read_text())["status"])
                raise RuntimeError("synthetic-private-raw-input")
            with mock.patch.object(mutations, "campaign", side_effect=explode), mock.patch("builtins.print"):
                self.assertEqual(1, mutations.main(["--report", str(report)]))
            self.assertNotIn("synthetic-private", report.read_text())
            self.assertEqual("unexpected_harness_error", json.loads(report.read_text())["reason"])

    def test_archive_rejects_traversal_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, kind in (("../escape", tarfile.REGTYPE), ("link", tarfile.SYMTYPE), ("hardlink", tarfile.LNKTYPE)):
                archive = root / "input.tar"
                with tarfile.open(archive, "w") as handle:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "outside"
                    handle.addfile(member, io.BytesIO())
                with self.assertRaisesRegex(mutations.HarnessError, "unsafe_archive"):
                    mutations.unpack_archive(archive, root / "extract")
            self.assertFalse((root.parent / "escape").exists())

    def test_archive_extracts_regular_files_with_executable_bit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "input.tar"
            with tarfile.open(archive, "w") as handle:
                member = tarfile.TarInfo("scripts/check")
                member.size = 4
                member.mode = 0o755
                handle.addfile(member, io.BytesIO(b"safe"))
            mutations.unpack_archive(archive, root / "extract")
            actual = root / "extract/scripts/check"
            self.assertEqual(b"safe", actual.read_bytes())
            self.assertTrue(actual.stat().st_mode & 0o100)


if __name__ == "__main__":
    unittest.main()
