"""Failure controls for the real bounded controller; workers are local doubles."""
import copy
import json
import os
from pathlib import Path
import platform
import signal
import sys
import tempfile
import unittest
from unittest import mock

import security_corpus as corpus


class CorpusSetup:
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.manifest = self.root / "manifest.json"
        self.entries = []
        for domain in corpus.DOMAINS:
            (self.root / domain).mkdir()
            (self.root / domain / "seed.json").write_text('{"synthetic":true}', encoding="utf-8")
            self.entries.append({"target": domain, "path": domain + "/seed.json"})
        self.save_manifest()

    def save_manifest(self):
        self.manifest.write_text(json.dumps({"schema_version": 1, "entries": self.entries}), encoding="utf-8")


class CorpusFixtures(CorpusSetup, unittest.TestCase):
    def test_identity_is_repeatable_and_content_sensitive(self):
        first_inputs, first = corpus.read_corpus(self.manifest)
        self.assertEqual((first_inputs, first), corpus.read_corpus(self.manifest))
        (self.root / self.entries[0]["path"]).write_bytes(b"changed synthetic bytes")
        self.assertNotEqual(first["sha256"], corpus.read_corpus(self.manifest)[1]["sha256"])
        self.assertEqual(first["files"], 4)
        self.assertNotIn("synthetic", json.dumps(first))

    def test_manifest_order_is_part_of_replay_identity(self):
        original = corpus.read_corpus(self.manifest)[1]["sha256"]
        self.entries.reverse()
        self.save_manifest()
        self.assertNotEqual(original, corpus.read_corpus(self.manifest)[1]["sha256"])

    def test_missing_invalid_and_empty_manifests_fail(self):
        for data in (b"", b"{", b"[]", b'{"schema_version":1,"entries":[]}',
                     b'{"schema_version":1,"schema_version":1,"entries":[]}'):
            with self.subTest(data=data):
                self.manifest.write_bytes(data)
                with self.assertRaises(corpus.Failure):
                    corpus.read_corpus(self.manifest)
        self.manifest.unlink()
        with self.assertRaises(corpus.Failure):
            corpus.read_corpus(self.manifest)

    def test_missing_domain_and_duplicate_paths_fail(self):
        original = copy.deepcopy(self.entries)
        for entries in (original[:-1], original + [original[0]]):
            self.entries = entries
            self.save_manifest()
            with self.assertRaises(corpus.Failure):
                corpus.read_corpus(self.manifest)

    def test_missing_empty_and_oversized_files_fail(self):
        path = self.root / self.entries[0]["path"]
        for data in (b"", b"a" * (corpus.MAX_INPUT + 1)):
            path.write_bytes(data)
            with self.assertRaises(corpus.Failure):
                corpus.read_corpus(self.manifest)
        path.unlink()
        with self.assertRaises(corpus.Failure):
            corpus.read_corpus(self.manifest)

    def test_traversal_absolute_and_ambiguous_paths_fail(self):
        for path in ("../seed", "/seed", "jwt/../jwt/seed.json", "jwt//seed.json",
                     "jwt/./seed.json", "jwt\\seed.json", "jwt/seed\n.json"):
            with self.subTest(path=path):
                self.entries[0]["path"] = path
                self.save_manifest()
                with self.assertRaises(corpus.Failure):
                    corpus.read_corpus(self.manifest)

    @unittest.skipUnless(os.name == "posix", "symlink checks need POSIX")
    def test_symlink_file_directory_and_manifest_fail(self):
        seed = self.root / "jwt/seed.json"
        seed.unlink()
        seed.symlink_to(self.root / "path/seed.json")
        with self.assertRaises(corpus.Failure):
            corpus.read_corpus(self.manifest)
        seed.unlink()
        (self.root / "jwt").rmdir()
        (self.root / "jwt").symlink_to(self.root / "path", target_is_directory=True)
        with self.assertRaises(corpus.Failure):
            corpus.read_corpus(self.manifest)
        manifest_link = self.root / "linked.json"
        manifest_link.symlink_to(self.manifest)
        with self.assertRaises(corpus.Failure):
            corpus.read_corpus(manifest_link)

    @unittest.skipUnless(os.name == "posix", "FIFO checks need POSIX")
    def test_nonregular_file_is_rejected_without_waiting_for_writer(self):
        path = self.root / "jwt/seed.json"
        path.unlink()
        os.mkfifo(path)
        with self.assertRaises(corpus.Failure):
            corpus.read_corpus(self.manifest)

    def test_total_size_and_file_count_limits(self):
        self.entries = []
        for index in range(17):
            domain = corpus.DOMAINS[index % 4]
            name = f"{domain}/{index}.json"
            (self.root / name).write_bytes(b"a" * corpus.MAX_INPUT)
            self.entries.append({"target": domain, "path": name})
        self.save_manifest()
        with self.assertRaisesRegex(corpus.Failure, "corpus_size_limit"):
            corpus.read_corpus(self.manifest)
        self.entries = [{"target": "jwt", "path": f"jwt/{index}.json"} for index in range(65)]
        self.save_manifest()
        with self.assertRaisesRegex(corpus.Failure, "invalid_manifest"):
            corpus.read_corpus(self.manifest)


@unittest.skipUnless(os.name == "posix" and platform.system() == "Linux", "Linux resource controller")
class WorkerControls(CorpusSetup, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.inputs, _ = corpus.read_corpus(self.manifest)
        self.budgets = {"cpu_seconds": 2, "wall_seconds": 3, "memory_mib": 128}
        self.binary = self.root / "worker"

    def worker(self, behavior="pass"):
        source = '''import json, os, signal, sys, time
from pathlib import Path
behavior = BEHAVIOR
if "--list" in sys.argv:
    if behavior != "zero_tests":
        print("security_corpus::bounded_corpus_worker: test")
    sys.exit(0)
if behavior == "timeout":
    time.sleep(10)
if behavior == "cpu":
    while True:
        pass
if behavior == "memory":
    try:
        bytearray(512 * 1024 * 1024)
    except MemoryError:
        sys.exit(7)
    sys.exit(0)
if behavior == "nonzero":
    print("SYNTHETIC_PRIVATE_DIAGNOSTIC", file=sys.stderr)
    print("SYNTHETIC_PRIVATE_INPUT")
    sys.exit(8)
if behavior == "missing":
    sys.exit(0)
if behavior == "oversized_receipt":
    Path(os.environ["GREENGATEWAY_CORPUS_RESULT"]).write_bytes(b"x" * 70000)
    sys.exit(0)
job = json.loads(Path(os.environ["GREENGATEWAY_CORPUS_JOB"]).read_text())
counts = dict.fromkeys(("jwt", "policy", "host", "path"), 0)
if job["replay_case"] is None:
    for item in job["inputs"]:
        counts[item["target"]] += 1 + job["mutations_per_seed"]
else:
    counts[job["inputs"][job["replay_case"] // (1 + job["mutations_per_seed"])]["target"]] = 1
receipt = dict(schema_version=1, status="passed", executed=sum(counts.values()), targets=counts, failure=None)
if behavior == "empty":
    receipt["executed"] = 0
    receipt["targets"] = dict.fromkeys(counts, 0)
if behavior == "partial":
    receipt["executed"] -= 1
    receipt["targets"]["path"] -= 1
if behavior == "wrong_target":
    receipt["targets"]["jwt"] -= 1
    receipt["targets"]["path"] += 1
if behavior in ("failure", "failure_nonzero"):
    receipt.update(status="failed", executed=1, targets=dict(jwt=1, policy=0, host=0, path=0),
                   failure=dict(case_index=0, target="jwt", input_sha256="a"*64, kind="invariant"))
output = "{" if behavior == "truncated" else json.dumps(receipt)
Path(os.environ["GREENGATEWAY_CORPUS_RESULT"]).write_text(output)
if behavior == "failure_nonzero":
    sys.exit(101)
'''.replace("BEHAVIOR", repr(behavior))
        self.binary.write_text("#!" + sys.executable + "\n" + source, encoding="utf-8")
        self.binary.chmod(0o755)

    def run_worker(self, replay=None):
        return corpus.run_worker(self.binary, self.root, os.environ.copy(), self.inputs,
                                 435005, 2, replay, self.budgets)

    def test_real_child_returns_exact_counts_and_replay(self):
        self.worker()
        receipt = self.run_worker()
        self.assertEqual(receipt["executed"], 12)
        self.assertEqual(receipt["targets"], dict.fromkeys(corpus.DOMAINS, 3))
        replay = self.run_worker(replay=9)
        self.assertEqual(replay["executed"], 1)
        self.assertEqual(replay["targets"], dict(jwt=0, policy=0, host=0, path=1))

    def test_zero_test_success_is_failure(self):
        self.worker("zero_tests")
        with self.assertRaisesRegex(corpus.Failure, "missing_corpus_worker"):
            self.run_worker()

    def test_missing_truncated_empty_partial_and_wrong_target_receipts_fail(self):
        for behavior in ("missing", "truncated", "empty", "partial", "wrong_target", "oversized_receipt"):
            with self.subTest(behavior=behavior):
                self.worker(behavior)
                with self.assertRaises(corpus.Failure):
                    self.run_worker()

    def test_nonzero_exit_fails_and_diagnostics_are_redacted(self):
        self.worker("nonzero")
        report = self.root / "report.json"
        with mock.patch.object(corpus, "metadata", return_value={"test_fixture": True}):
            self.assertEqual(corpus.main(["--manifest", str(self.manifest), "--binary", str(self.binary),
                                          "--report", str(report)]), 1)
        data = report.read_text()
        self.assertNotIn("SYNTHETIC_PRIVATE", data)
        self.assertNotIn(str(self.binary), data)
        self.assertLess(len(data.encode()), corpus.MAX_REPORT)
        self.assertEqual(json.loads(data)["reason"], "worker_process_failure")

    def test_wall_timeout_kills_real_child(self):
        self.worker("timeout")
        self.budgets["wall_seconds"] = 1
        with self.assertRaisesRegex(corpus.Failure, "wall_timeout"):
            self.run_worker()

    def test_cpu_limit_kills_real_child(self):
        self.worker("cpu")
        self.budgets.update(cpu_seconds=1, wall_seconds=4)
        with self.assertRaisesRegex(corpus.Failure, "cpu_or_resource_limit"):
            self.run_worker()

    def test_memory_allocation_over_limit_cannot_pass(self):
        self.worker("memory")
        with self.assertRaisesRegex(corpus.Failure, "worker_process_failure"):
            self.run_worker()

    def test_failure_receipt_preserves_only_replay_identity(self):
        self.worker("failure")
        receipt = self.run_worker()
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["failure"]["case_index"], 0)
        self.assertEqual(set(receipt["failure"]), {"case_index", "target", "input_sha256", "kind"})

    def test_nonzero_failure_receipt_is_retained_but_never_passes(self):
        self.worker("failure_nonzero")
        with self.assertRaises(corpus.Failure) as result:
            self.run_worker()
        self.assertEqual(result.exception.receipt["status"], "failed")
        self.assertEqual(result.exception.receipt["failure"]["case_index"], 0)

    def test_invalid_replay_and_case_budget_rejected_before_spawn(self):
        self.worker()
        with self.assertRaisesRegex(corpus.Failure, "case_budget_exceeded"):
            self.run_worker(replay=12)
        with self.assertRaisesRegex(corpus.Failure, "case_budget_exceeded"):
            corpus.run_worker(self.binary, self.root, os.environ.copy(), self.inputs,
                              435005, corpus.MAX_CASES, None, self.budgets)

    def test_report_overflow_changes_success_exit_to_failure(self):
        self.worker()
        report = self.root / "report.json"
        with mock.patch.object(corpus, "metadata", return_value={"oversized": "x" * corpus.MAX_REPORT}):
            self.assertEqual(corpus.main(["--manifest", str(self.manifest), "--binary", str(self.binary),
                                          "--report", str(report)]), 1)
        self.assertEqual(json.loads(report.read_bytes())["reason"], "report_size_limit")


class ControllerControls(unittest.TestCase):
    def test_unsupported_platform_fails_explicitly(self):
        with mock.patch.object(corpus.platform, "system", return_value="Unsupported"):
            with self.assertRaisesRegex(corpus.Failure, "unsupported_resource_platform"):
                corpus.require_linux()

    def test_invalid_budgets_and_unsigned_seed_fail(self):
        for args in (["--seed", "-1"], ["--seed", str(2**64)], ["--memory-mib", "8193"],
                     ["--wall-seconds", "0"], ["--mutations-per-seed", "-1"]):
            with self.subTest(args=args), self.assertRaises(corpus.Failure):
                corpus.arguments(args)

    def test_unexpected_exception_does_not_enter_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with mock.patch.object(corpus, "metadata", side_effect=RuntimeError("SYNTHETIC_PRIVATE_DIAGNOSTIC")):
                self.assertEqual(corpus.main(["--report", str(path)]), 1)
            report = path.read_text()
            self.assertNotIn("SYNTHETIC_PRIVATE", report)
            self.assertEqual(json.loads(report)["reason"], "controller_failure")

    def test_exact_python_pin_is_required_before_tool_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "build-tools.json").write_text('{"python":"0.0.0","rust_ci":"1.98.1"}')
            with mock.patch.object(corpus.subprocess, "run") as command:
                with self.assertRaisesRegex(corpus.Failure, "python_version_mismatch"):
                    corpus.metadata(root, {})
                command.assert_not_called()

    def test_report_size_is_bounded_even_on_internal_mistake(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            corpus.write_report(path, {"unexpected": "x" * corpus.MAX_REPORT})
            report = json.loads(path.read_bytes())
            self.assertEqual(report["status"], "failed")
            self.assertLess(path.stat().st_size, corpus.MAX_REPORT)


if __name__ == "__main__":
    unittest.main()
