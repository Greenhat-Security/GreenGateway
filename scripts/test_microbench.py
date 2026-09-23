"""Fail-closed contracts for the pure-path performance comparison."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import microbench as bench

ROOT = Path(__file__).resolve().parents[1]


def sources():
    return {
        name: (ROOT / name).read_text(encoding="utf-8")
        for name in (
            "gateway/src/path_match.rs",
            "gateway/src/egress.rs",
            "gateway/src/rbac/matcher.rs",
        )
    }


class SourceProjectionTests(unittest.TestCase):
    def test_current_production_sources_project_without_io_stubs(self):
        projected = "\n".join(bench.project_sources(sources()).values())
        self.assertIn("pub fn is_unsafe_request_path", projected)
        self.assertIn("pub fn exempt_path_matches", projected)
        self.assertIn("pub fn path_prefix_matches", projected)
        self.assertIn("fn host_glob_matches", projected)
        self.assertIn("impl PathPattern", projected)
        self.assertIn("fn path_segments_match", projected)
        self.assertNotIn("async fn", projected)
        self.assertNotIn("fn resolve_and_check", projected)
        self.assertNotIn("mod property_tests", projected)

    def test_unexpected_test_module_cannot_be_silently_stripped(self):
        data = sources()
        data["gateway/src/path_match.rs"] = data["gateway/src/path_match.rs"].replace(
            "mod property_tests;", "mod replacement_tests;"
        )
        with self.assertRaises(ValueError):
            bench.project_sources(data)

    def test_deleted_selected_function_is_an_error(self):
        data = sources()
        data["gateway/src/egress.rs"] = data["gateway/src/egress.rs"].replace(
            "fn host_glob_matches(", "fn retired_host_glob_matches("
        )
        with self.assertRaises((ValueError, RuntimeError)):
            bench.project_sources(data)

    def test_duplicate_selected_function_is_an_error(self):
        data = sources()
        data["gateway/src/egress.rs"] += (
            '\nfn host_glob_matches(pattern: &str, host: &str) -> bool { false }\n'
        )
        with self.assertRaises((ValueError, RuntimeError)):
            bench.project_sources(data)

    def test_conditional_selected_function_is_an_error(self):
        for attr in ('#[cfg(unix)]', '#[cfg_attr(unix, inline)]'):
            with self.subTest(attr=attr):
                data = sources()
                data["gateway/src/egress.rs"] = data["gateway/src/egress.rs"].replace(
                    "fn host_glob_matches(", attr + "\nfn host_glob_matches("
                )
                with self.assertRaises((ValueError, RuntimeError)):
                    bench.project_sources(data)

    def test_nested_replacement_cannot_impersonate_top_level_target(self):
        data = sources()
        data["gateway/src/egress.rs"] = data["gateway/src/egress.rs"].replace(
            "fn host_glob_matches(", "fn retired_host_glob_matches("
        )
        data["gateway/src/egress.rs"] += (
            '\nmod decoy { fn host_glob_matches(pattern: &str, host: &str) -> bool { false } }\n'
        )
        with self.assertRaises((ValueError, RuntimeError)):
            bench.project_sources(data)

    def test_comments_and_raw_strings_do_not_end_selected_function(self):
        data = sources()
        data["gateway/src/egress.rs"] = data["gateway/src/egress.rs"].replace(
            'fn host_glob_matches(pattern: &str, host: &str) -> bool {',
            'fn host_glob_matches(pattern: &str, host: &str) -> bool {\n'
            '    /* } /* nested { */ } */\n'
            '    let _braces = r###"} fn host_glob_matches() {}"###;\n'
            '    let _character = \'}\';\n',
        )
        projected = '\n'.join(bench.project_sources(data).values())
        self.assertIn('host == pattern', projected)
        self.assertIn('r###"} fn host_glob_matches() {}"###', projected)

    def test_module_level_attributes_cannot_be_lost(self):
        for name in sources():
            with self.subTest(name=name):
                data = sources()
                data[name] = '#![cfg(windows)]\n' + data[name]
                with self.assertRaises((ValueError, RuntimeError)):
                    bench.project_sources(data)

    def test_production_cannot_capture_reserved_benchmark_wrappers(self):
        for call in ('microbench_host_matches(pattern, host);', 'let _ = MicrobenchPreparedPattern::new(host);'):
            with self.subTest(call=call):
                data = sources()
                data['gateway/src/egress.rs'] = data['gateway/src/egress.rs'].replace(
                    'fn host_glob_matches(pattern: &str, host: &str) -> bool {',
                    'fn host_glob_matches(pattern: &str, host: &str) -> bool {\n    ' + call,
                )
                with self.assertRaises((ValueError, RuntimeError)):
                    bench.project_sources(data)

    def test_missing_source_is_an_error(self):
        data = sources()
        del data["gateway/src/rbac/matcher.rs"]
        with self.assertRaises((ValueError, RuntimeError, KeyError)):
            bench.project_sources(data)


class JsonEvidenceTests(unittest.TestCase):
    def test_duplicate_keys_and_nonfinite_values_are_rejected(self):
        for body in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":-Infinity}', '{"x":1e309}'):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'report.json'
                path.write_text(body, encoding='utf-8')
                with self.assertRaises((ValueError, RuntimeError)):
                    bench.load_json(path)


# Protocol fixture independent of the controller's constants, captured from a
# release build of the synthetic workload. Timings deliberately vary.
def result():
    rows = (
        ("request_path", 712, 32, 16000, 0, 0),
        ("path_prefix", 867, 16, 7000, 0, 0),
        ("rule_path", 1367, 16, 9000, 87000, 5286000),
        ("egress_host", 1118, 16, 8000, 31000, 1118000),
    )
    return {
        "schema_version": 1, "warmup": 100, "iterations": 1000, "samples": 9,
        "targets": [{
            "id": ident, "input_cases": 16, "input_bytes": size,
            "operations_per_iteration": ops, "expected_checksum": checksum,
            "allocation_samples": [
                {"allocations": calls, "allocated_bytes": size_sum, "checksum": checksum}
                for _ in range(9)
            ],
            "timing_samples_ns": [100000 + i * 1000 for i in range(9)],
        } for ident, size, ops, checksum, calls, size_sum in rows],
    }


def budget():
    return {
        "schema_version": 1, "harness_sha256": ["a" * 64],
        "targets": [{"id": row["id"], "max_allocation_growth": 0,
                     "max_allocated_bytes_growth": 0}
                    for row in result()["targets"]],
    }


class ComparisonTests(unittest.TestCase):
    def assert_invalid(self, value):
        with self.assertRaises((ValueError, RuntimeError)):
            bench.validate_result(value)

    def test_neutral_and_improved_counts_pass(self):
        base = result()
        head = copy.deepcopy(base)
        for sample in head["targets"][2]["allocation_samples"]:
            sample["allocations"] -= 1000
            sample["allocated_bytes"] -= 1000
        for value in (base, head):
            self.assertEqual(bench.compare_results(base, value, budget())["status"], "passed")

    def test_allocation_and_byte_growth_independently_fail(self):
        for field in ("allocations", "allocated_bytes"):
            for target_index in range(4):
                with self.subTest(field=field, target=target_index):
                    head = result()
                    for sample in head["targets"][target_index]["allocation_samples"]:
                        sample[field] += 1
                    report = bench.compare_results(result(), head, budget())
                    self.assertEqual(report["status"], "failed")
                    self.assertTrue(report["errors"])

    def test_extreme_timing_change_stays_informational(self):
        head = result()
        for target in head["targets"]:
            target["timing_samples_ns"] = [1000000000] * 9
        self.assertEqual(bench.compare_results(result(), head, budget())["status"], "passed")

    def test_missing_extra_duplicate_and_reordered_targets_reject(self):
        for kind in ("missing", "extra", "duplicate", "reordered", "none"):
            with self.subTest(kind=kind):
                value = result()
                if kind == "missing":
                    value["targets"].pop()
                elif kind == "extra":
                    extra = copy.deepcopy(value["targets"][0])
                    extra["id"] = "unexpected"
                    value["targets"].append(extra)
                elif kind == "duplicate":
                    value["targets"][1] = copy.deepcopy(value["targets"][0])
                elif kind == "reordered":
                    value["targets"].reverse()
                else:
                    value["targets"] = []
                self.assert_invalid(value)

    def test_incomplete_samples_wrong_checksum_and_count_drift_reject(self):
        for field in ("allocation_samples", "timing_samples_ns"):
            value = result()
            value["targets"][0][field].pop()
            self.assert_invalid(value)
        for field in ("checksum", "allocations", "allocated_bytes"):
            value = result()
            value["targets"][0]["allocation_samples"][0][field] += 1
            self.assert_invalid(value)

    def test_protocol_and_dataset_shrink_reject(self):
        for field, invalid in (("schema_version", 2), ("warmup", 0),
                               ("iterations", 999), ("samples", 1)):
            value = result()
            value[field] = invalid
            self.assert_invalid(value)
        for field in ("input_cases", "input_bytes", "operations_per_iteration", "expected_checksum"):
            value = result()
            value["targets"][0][field] -= 1
            self.assert_invalid(value)

    def test_numeric_boolean_negative_and_nonfinite_evidence_reject(self):
        for invalid in (True, False, -1, 1.5, float("inf"), float("nan"), "0", None):
            for field in ("allocations", "allocated_bytes", "checksum"):
                with self.subTest(field=field, invalid=invalid):
                    value = result()
                    for sample in value["targets"][0]["allocation_samples"]:
                        sample[field] = invalid
                    self.assert_invalid(value)
            value = result()
            value["targets"][0]["timing_samples_ns"] = [invalid] * 9
            self.assert_invalid(value)
        value = result()
        value["targets"][0]["timing_samples_ns"] = [0] * 9
        self.assert_invalid(value)

    def test_unknown_fields_cannot_silently_change_schema(self):
        for level in ("root", "target", "sample"):
            value = result()
            destination = {"root": value, "target": value["targets"][0],
                           "sample": value["targets"][0]["allocation_samples"][0]}[level]
            destination["skipped"] = True
            self.assert_invalid(value)

    def test_invalid_budget_cannot_authorize_comparison(self):
        for change in ("missing_target", "negative", "boolean", "schema", "hash"):
            value = budget()
            if change == "missing_target":
                value["targets"].pop()
            elif change == "negative":
                value["targets"][0]["max_allocation_growth"] = -1
            elif change == "boolean":
                value["targets"][0]["max_allocated_bytes_growth"] = False
            elif change == "schema":
                value["schema_version"] = 0
            else:
                value["harness_sha256"] = "not-a-digest"
            with self.subTest(change=change), self.assertRaises((ValueError, RuntimeError)):
                bench.compare_results(result(), result(), value)



def envelope():
    return {
        "schema_version": 1,
        "context": {
            "rust_ci": "1.98.1", "rustc_vv": "rustc 1.98.1\nrelease: 1.98.1\n",
            "rustc_flags": list(bench.RUST_FLAGS), "harness_sha256": "a" * 64,
            "machine": {"platform": "test-linux", "machine": "x86_64",
                        "logical_cpus": 2, "python": "3.13.15"},
            "warmup": 100, "iterations": 1000, "samples": 9,
        },
        "revision": "b" * 40,
        "source_sha256": {name: "c" * 64 for name in bench.SOURCE_PATHS},
        "projection_sha256": {name: "d" * 64 for name in
                              ("path_match.rs", "egress.rs", "rule_path.rs")},
        "regression_fixture": False,
        "result": result(),
    }


class SavedEvidenceTests(unittest.TestCase):
    def test_complete_compatible_envelopes_pass(self):
        self.assertEqual(bench.compare_saved_results(envelope(), envelope(), budget())["status"], "passed")

    def test_bare_results_cannot_prove_a_compatible_comparison(self):
        with self.assertRaises((ValueError, RuntimeError)):
            bench.compare_saved_results(result(), result(), budget())

    def test_incompatible_compiler_profile_dataset_runner_reject(self):
        changes = {
            "compiler": lambda x: x.update(rust_ci="1.99.0", rustc_vv="release: 1.99.0\n"),
            "compiler_build": lambda x: x.update(rustc_vv="other compiler build\nrelease: 1.98.1\n"),
            "profile": lambda x: x["rustc_flags"].append("--cfg=regression_fixture"),
            "dataset": lambda x: x.update(harness_sha256="e" * 64),
            "cpu": lambda x: x["machine"].update(logical_cpus=4),
            "runtime": lambda x: x["machine"].update(python="3.14.0"),
            "samples": lambda x: x.update(samples=8),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                head = envelope()
                change(head["context"])
                with self.assertRaises((ValueError, RuntimeError)):
                    bench.compare_saved_results(envelope(), head, budget())

    def test_regression_fixture_results_cannot_pass_as_normal_evidence(self):
        for side in ("base", "head", "both"):
            before, after = envelope(), envelope()
            if side in ("base", "both"):
                before["regression_fixture"] = True
            if side in ("head", "both"):
                after["regression_fixture"] = True
            with self.subTest(side=side), self.assertRaises((ValueError, RuntimeError)):
                bench.compare_saved_results(before, after, budget())

    def test_missing_provenance_and_unapproved_harness_reject(self):
        for key in ("context", "revision", "source_sha256", "projection_sha256", "regression_fixture"):
            head = envelope()
            del head[key]
            with self.subTest(key=key), self.assertRaises((ValueError, RuntimeError)):
                bench.compare_saved_results(envelope(), head, budget())
        policy = budget()
        policy["harness_sha256"] = ["e" * 64]
        with self.assertRaises((ValueError, RuntimeError)):
            bench.compare_saved_results(envelope(), envelope(), policy)


if __name__ == '__main__':
    unittest.main()
