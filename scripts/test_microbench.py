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


def kernel_budget():
    value = budget()
    value["schema_version"] = 2
    value["kernel_harness_sha256"] = ["f" * 64]
    value["targets"].append({"id": "http_policy", "max_allocation_growth": 0,
                             "max_allocated_bytes_growth": 0})
    return value


# Captured from the gateway test binary (unoptimized test profile) on the
# harness this change adds: 17 decisions per pass, 100 passes per sample.
def kernel_result(regression=False):
    calls, size_sum = (43400, 1547800) if regression else (41700, 1439000)
    return {
        "schema_version": 1, "harness": "gateway-test-binary", "regression_fixture": regression,
        "warmup": 10, "iterations": 100, "samples": 9,
        "targets": [{
            "id": "http_policy", "input_cases": 17, "input_bytes": 1459,
            "operations_per_iteration": 17, "expected_checksum": 1700,
            "allocation_samples": [
                {"allocations": calls, "allocated_bytes": size_sum, "checksum": 1700}
                for _ in range(9)
            ],
            "timing_samples_ns": [40000000 + i * 100000 for i in range(9)],
        }],
    }


def kernel_envelope(regression=False, revision="b" * 40):
    return {
        "schema_version": 1,
        "context": {
            "rust_ci": "1.98.1", "rustc_vv": "rustc 1.98.1\nrelease: 1.98.1\n",
            "cargo_vv": "cargo 1.98.1\nrelease: 1.98.1\n",
            "cargo_arguments": list(bench.CARGO_ARGUMENTS),
            "cargo_env": dict(bench.CARGO_PROFILE_ENV), "node": "26.10.0", "npm": "11.19.1",
            "machine": {"platform": "test-linux", "machine": "x86_64",
                        "logical_cpus": 2, "python": "3.13.15"},
            "warmup": 10, "iterations": 100, "samples": 9,
        },
        "revision": revision, "harness_sha256": "f" * 64, "regression_fixture": regression,
        "result": kernel_result(regression),
    }


def kernel_limit():
    return {"id": "http_policy", "max_allocation_growth": 0, "max_allocated_bytes_growth": 0}


class BudgetSchemaTests(unittest.TestCase):
    def test_both_budget_schemas_are_accepted_and_only_schema_two_budgets_the_kernel(self):
        self.assertFalse(bench.budgets_kernel(bench.validate_budget(budget())))
        self.assertTrue(bench.budgets_kernel(bench.validate_budget(kernel_budget())))
        repository = json.loads((ROOT / "microbench-budget.json").read_text(encoding="utf-8"))
        bench.validate_budget(repository)

    def test_kernel_budget_must_be_complete_ordered_approved_and_zero(self):
        changes = {
            "no kernel digests": lambda value: value.pop("kernel_harness_sha256"),
            "empty kernel digests": lambda value: value.update(kernel_harness_sha256=[]),
            "three kernel digests": lambda value: value.update(
                kernel_harness_sha256=["1" * 64, "2" * 64, "3" * 64]),
            "duplicate kernel digest": lambda value: value.update(
                kernel_harness_sha256=["1" * 64, "1" * 64]),
            "uppercase kernel digest": lambda value: value.update(kernel_harness_sha256=["F" * 64]),
            "kernel target missing": lambda value: value["targets"].pop(),
            "kernel target first": lambda value: value["targets"].insert(0, value["targets"].pop()),
            "kernel growth": lambda value: value["targets"][-1].update(max_allocation_growth=1),
            "kernel byte growth": lambda value: value["targets"][-1].update(
                max_allocated_bytes_growth=True),
            "unknown key": lambda value: value.update(skipped_targets=["http_policy"]),
            "future schema": lambda value: value.update(schema_version=4),
            "boolean schema": lambda value: value.update(schema_version=True),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                value = kernel_budget()
                change(value)
                with self.assertRaises(ValueError):
                    bench.validate_budget(value)
        schema_one_with_kernel = kernel_budget()
        schema_one_with_kernel["schema_version"] = 1
        with self.assertRaises(ValueError):
            bench.validate_budget(schema_one_with_kernel)
        del schema_one_with_kernel["kernel_harness_sha256"]
        with self.assertRaises(ValueError):
            bench.validate_budget(schema_one_with_kernel)

    def test_pure_comparison_ignores_the_kernel_entry_of_a_schema_two_budget(self):
        report = bench.compare_results(result(), result(), kernel_budget())
        self.assertEqual(report["status"], "passed")
        self.assertEqual([target["id"] for target in report["targets"]], list(bench.TARGET_IDS))

    def test_adoption_state_follows_the_base_budget_and_cannot_retire_enforcement(self):
        self.assertEqual(bench.kernel_policy(budget(), budget()), "pending")
        self.assertEqual(bench.kernel_policy(budget(), kernel_budget()), "proposed")
        self.assertEqual(bench.kernel_policy(kernel_budget(), kernel_budget()), "enforced")
        with self.assertRaisesRegex(ValueError, "retire"):
            bench.kernel_policy(kernel_budget(), budget())


class KernelResultTests(unittest.TestCase):
    def assert_invalid(self, value, regression=False):
        with self.assertRaises((ValueError, RuntimeError)):
            bench.validate_kernel_result(value, regression)

    def test_measured_report_and_requested_fixture_pass(self):
        bench.validate_kernel_result(kernel_result())
        bench.validate_kernel_result(kernel_result(True), regression=True)

    def test_fixture_marker_must_match_the_requested_run(self):
        self.assert_invalid(kernel_result(True))
        self.assert_invalid(kernel_result(), regression=True)
        value = kernel_result()
        value["regression_fixture"] = 0
        self.assert_invalid(value)

    def test_protocol_dataset_and_harness_drift_reject(self):
        for field, invalid in (("schema_version", 2), ("warmup", 100), ("iterations", 1000),
                               ("samples", 8), ("harness", "standalone")):
            with self.subTest(field=field):
                value = kernel_result()
                value[field] = invalid
                self.assert_invalid(value)
        for field in ("input_cases", "input_bytes", "operations_per_iteration", "expected_checksum"):
            with self.subTest(field=field):
                value = kernel_result()
                value["targets"][0][field] -= 1
                self.assert_invalid(value)

    def test_wrong_skipped_extra_or_unstable_targets_reject(self):
        value = kernel_result()
        value["targets"][0]["id"] = "rule_path"
        self.assert_invalid(value)
        value = kernel_result()
        value["targets"] = []
        self.assert_invalid(value)
        value = kernel_result()
        value["targets"].append(copy.deepcopy(value["targets"][0]))
        self.assert_invalid(value)
        value = kernel_result()
        value["targets"][0]["allocation_samples"][4]["allocations"] += 1
        self.assert_invalid(value)
        value = kernel_result()
        value["targets"][0]["allocation_samples"][0]["checksum"] -= 17
        self.assert_invalid(value)
        value = kernel_result()
        value["targets"][0]["timing_samples_ns"][0] = 0
        self.assert_invalid(value)
        value = kernel_result()
        value["targets"][0]["skipped"] = False
        self.assert_invalid(value)


class KernelComparisonTests(unittest.TestCase):
    def test_neutral_and_improved_counts_pass_and_timing_stays_informational(self):
        head = kernel_envelope()
        for sample in head["result"]["targets"][0]["allocation_samples"]:
            sample["allocations"] -= 100
            sample["allocated_bytes"] -= 100
        head["result"]["targets"][0]["timing_samples_ns"] = [10**10] * 9
        for after in (kernel_envelope(), head):
            report = bench.compare_kernel_results(kernel_envelope(), after, kernel_limit())
            self.assertEqual(report["status"], "passed")
            self.assertEqual(report["id"], "http_policy")

    def test_allocation_and_byte_growth_independently_fail(self):
        for field in ("allocations", "allocated_bytes"):
            with self.subTest(field=field):
                head = kernel_envelope()
                for sample in head["result"]["targets"][0]["allocation_samples"]:
                    sample[field] += 1
                report = bench.compare_kernel_results(kernel_envelope(), head, kernel_limit())
                self.assertEqual(report["status"], "failed")

    def test_deliberate_fixture_is_detected_and_never_normal_evidence(self):
        report = bench.compare_kernel_results(kernel_envelope(), kernel_envelope(True),
                                              kernel_limit(), regression_head=True)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["growth"], {"allocations": 1700, "allocated_bytes": 108800})
        for before, after in ((kernel_envelope(True), kernel_envelope()),
                              (kernel_envelope(), kernel_envelope(True))):
            with self.assertRaises(ValueError):
                bench.compare_kernel_results(before, after, kernel_limit())

    def test_incompatible_build_tools_profile_or_runner_reject(self):
        changes = {
            "compiler": lambda context: context.update(rust_ci="1.99.0"),
            "cargo build": lambda context: context.update(cargo_vv="cargo 1.98.1\nrelease: 1.98.1\nhost: other\n"),
            "profile": lambda context: context["cargo_env"].update(CARGO_PROFILE_DEV_DEBUG="2"),
            "arguments": lambda context: context["cargo_arguments"].append("--release"),
            "ui tools": lambda context: context.update(node="26.11.0"),
            "runner": lambda context: context["machine"].update(logical_cpus=4),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                head = kernel_envelope()
                change(head["context"])
                with self.assertRaises(ValueError):
                    bench.compare_kernel_results(kernel_envelope(), head, kernel_limit())

    def test_unpinned_cargo_and_bare_results_reject(self):
        head = kernel_envelope()
        head["context"]["cargo_vv"] = "cargo 1.97.0\nrelease: 1.97.0\n"
        with self.assertRaises(ValueError):
            bench.validate_kernel_envelope(head)
        with self.assertRaises((ValueError, KeyError)):
            bench.compare_kernel_results(kernel_result(), kernel_result(), kernel_limit())
        for key in ("context", "revision", "harness_sha256", "regression_fixture"):
            head = kernel_envelope()
            del head[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                bench.compare_kernel_results(kernel_envelope(), head, kernel_limit())

    def test_budget_entry_must_name_the_kernel_target(self):
        limit = kernel_limit()
        limit["id"] = "rule_path"
        with self.assertRaises(ValueError):
            bench.compare_kernel_results(kernel_envelope(), kernel_envelope(), limit)


DECLARATION = (
    '#[cfg(test)]\n#[path = "../tests/support/policy_benchmark.rs"]\nmod policy_benchmark;\n'
)


class KernelWiringTests(unittest.TestCase):
    def main_source(self):
        return (ROOT / "gateway/src/main.rs").read_text(encoding="utf-8")

    def test_repository_wiring_is_the_reviewed_test_only_declaration(self):
        self.assertIn(DECLARATION, self.main_source())
        self.assertTrue(bench.kernel_wiring(self.main_source()))

    def test_revision_without_the_declaration_is_absent(self):
        source = self.main_source().replace(DECLARATION, "")
        self.assertFalse(bench.kernel_wiring(source))
        commented = self.main_source().replace(
            DECLARATION, "".join("// " + line + "\n" for line in DECLARATION.splitlines()))
        self.assertFalse(bench.kernel_wiring(commented))

    def test_redirected_disabled_or_duplicated_wiring_is_rejected(self):
        replacements = {
            "other file": DECLARATION.replace("policy_benchmark.rs", "decoy.rs"),
            "production module": DECLARATION.replace("#[cfg(test)]\n", ""),
            "disabled": "#[cfg(any())]\n" + DECLARATION,
            "redirected": '#[cfg_attr(test, path = "decoy.rs")]\n' + DECLARATION,
            "duplicated": DECLARATION + "#[cfg(not(test))]\nmod policy_benchmark {}\n",
            "nested": "mod nested {\n" + DECLARATION + "}\n",
            "inline module": "#[cfg(test)]\nmod policy_benchmark {}\n",
            "renamed reference": "#[cfg(test)]\nuse crate::decoy as policy_benchmark;\n",
        }
        for name, replacement in replacements.items():
            with self.subTest(change=name):
                source = self.main_source().replace(DECLARATION, replacement)
                with self.assertRaises(ValueError):
                    bench.kernel_wiring(source)


def lane_budget():
    value = kernel_budget()
    value["schema_version"] = 3
    value["lane_harness_sha256"] = ["e" * 64]
    value["targets"].extend({"id": target, "max_allocation_growth": 0,
                             "max_allocated_bytes_growth": 0}
                            for target in ("tool_policy", "rate_lane"))
    return value


# Captured from the gateway test binary (unoptimized test profile) on the lane
# harness this change adds: cases, fact bytes, checksum, then the calls and
# requested bytes of one sample of 100 passes.
LANE_ROWS = {
    "tool_policy": (27, 1409, 2700, 9000, 1007400),
    "rate_lane": (14, 830, 1400, 19600, 909800),
}


def lane_result(target, regression=False):
    cases, size, checksum, calls, size_sum = LANE_ROWS[target]
    if regression:
        # The fixture adds one 64-byte allocation per decision.
        calls, size_sum = calls + cases * 100, size_sum + cases * 100 * 64
    return {
        "schema_version": 1, "harness": "gateway-test-binary", "regression_fixture": regression,
        "warmup": 10, "iterations": 100, "samples": 9,
        "targets": [{
            "id": target, "input_cases": cases, "input_bytes": size,
            "operations_per_iteration": cases, "expected_checksum": checksum,
            "allocation_samples": [
                {"allocations": calls, "allocated_bytes": size_sum, "checksum": checksum}
                for _ in range(9)
            ],
            "timing_samples_ns": [20000000 + i * 100000 for i in range(9)],
        }],
    }


def lane_envelope(target, regression=False):
    value = kernel_envelope(regression)
    value["harness_sha256"] = "e" * 64
    value["result"] = lane_result(target, regression)
    return value


def lane_limit(target):
    return {"id": target, "max_allocation_growth": 0, "max_allocated_bytes_growth": 0}


LANES = ("tool_policy", "rate_lane")


class LaneBudgetSchemaTests(unittest.TestCase):
    def test_schema_three_budgets_the_kernel_and_both_lanes(self):
        value = bench.validate_budget(lane_budget())
        self.assertTrue(bench.budgets_kernel(value))
        self.assertTrue(bench.budgets_lanes(value))
        self.assertFalse(bench.budgets_lanes(bench.validate_budget(kernel_budget())))
        self.assertFalse(bench.budgets_lanes(bench.validate_budget(budget())))
        # Entries are found by identifier, not position: http_policy is no
        # longer last once the lanes follow it.
        self.assertEqual(bench._budget_entry(value, "http_policy"), kernel_limit())
        self.assertEqual(bench._budget_entry(value, "rate_lane"), lane_limit("rate_lane"))
        with self.assertRaises(ValueError):
            bench._budget_entry(kernel_budget(), "tool_policy")
        report = bench.compare_results(result(), result(), value)
        self.assertEqual([target["id"] for target in report["targets"]], list(bench.TARGET_IDS))

    def test_lane_budget_must_be_complete_ordered_approved_and_zero(self):
        changes = {
            "no lane digests": lambda value: value.pop("lane_harness_sha256"),
            "empty lane digests": lambda value: value.update(lane_harness_sha256=[]),
            "three lane digests": lambda value: value.update(
                lane_harness_sha256=["1" * 64, "2" * 64, "3" * 64]),
            "duplicate lane digest": lambda value: value.update(
                lane_harness_sha256=["1" * 64, "1" * 64]),
            "uppercase lane digest": lambda value: value.update(lane_harness_sha256=["E" * 64]),
            "no kernel digests": lambda value: value.pop("kernel_harness_sha256"),
            "lane target missing": lambda value: value["targets"].pop(),
            "lane targets swapped": lambda value: value["targets"].insert(-1, value["targets"].pop()),
            "lane before kernel": lambda value: value["targets"].insert(4, value["targets"].pop()),
            "kernel target missing": lambda value: value["targets"].pop(4),
            "lane growth": lambda value: value["targets"][-1].update(max_allocation_growth=1),
            "lane byte growth": lambda value: value["targets"][-2].update(
                max_allocated_bytes_growth=True),
            "unknown key": lambda value: value.update(skipped_targets=["rate_lane"]),
        }
        for name, change in changes.items():
            with self.subTest(change=name):
                value = lane_budget()
                change(value)
                with self.assertRaises(ValueError):
                    bench.validate_budget(value)
        schema_two_with_lanes = lane_budget()
        schema_two_with_lanes["schema_version"] = 2
        with self.assertRaises(ValueError):
            bench.validate_budget(schema_two_with_lanes)
        del schema_two_with_lanes["lane_harness_sha256"]
        with self.assertRaises(ValueError):
            bench.validate_budget(schema_two_with_lanes)

    def test_lane_adoption_follows_the_base_budget_and_keeps_http_policy_enforced(self):
        self.assertEqual(bench.lane_policy(kernel_budget(), kernel_budget()), "pending")
        self.assertEqual(bench.lane_policy(kernel_budget(), lane_budget()), "proposed")
        self.assertEqual(bench.lane_policy(lane_budget(), lane_budget()), "enforced")
        with self.assertRaisesRegex(ValueError, "retire"):
            bench.lane_policy(lane_budget(), kernel_budget())
        self.assertEqual(bench.kernel_policy(kernel_budget(), lane_budget()), "enforced")
        self.assertEqual(bench.kernel_policy(lane_budget(), lane_budget()), "enforced")
        with self.assertRaisesRegex(ValueError, "retire"):
            bench.kernel_policy(lane_budget(), budget())


class LaneResultTests(unittest.TestCase):
    def test_each_lane_report_validates_only_as_its_own_target(self):
        for target in LANES:
            with self.subTest(target=target):
                bench.validate_kernel_result(lane_result(target), target=target)
                bench.validate_kernel_result(lane_result(target, True), True, target)
        mismatches = (
            (lane_result("tool_policy"), "rate_lane"),
            (lane_result("rate_lane"), "tool_policy"),
            (kernel_result(), "tool_policy"),
            (lane_result("rate_lane"), "http_policy"),
            (lane_result("tool_policy"), "egress_host"),
            (lane_result("tool_policy"), "unlisted_lane"),
        )
        for value, target in mismatches:
            with self.subTest(target=target), self.assertRaises(ValueError):
                bench.validate_kernel_result(value, target=target)

    def test_lane_protocol_dataset_fixture_and_stability_drift_reject(self):
        for target in LANES:
            for field in ("input_cases", "input_bytes", "operations_per_iteration",
                          "expected_checksum"):
                with self.subTest(target=target, field=field):
                    value = lane_result(target)
                    value["targets"][0][field] -= 1
                    with self.assertRaises(ValueError):
                        bench.validate_kernel_result(value, target=target)
            with self.subTest(target=target, change="unstable"):
                value = lane_result(target)
                value["targets"][0]["allocation_samples"][3]["allocated_bytes"] += 1
                with self.assertRaises(ValueError):
                    bench.validate_kernel_result(value, target=target)
            with self.subTest(target=target, change="fixture marker"):
                with self.assertRaises(ValueError):
                    bench.validate_kernel_result(lane_result(target, True), target=target)
                with self.assertRaises(ValueError):
                    bench.validate_kernel_result(lane_result(target), True, target)


class LaneComparisonTests(unittest.TestCase):
    def test_neutral_counts_pass_and_growth_or_fixture_fails_per_lane(self):
        for target in LANES:
            with self.subTest(target=target):
                report = bench.compare_kernel_results(lane_envelope(target), lane_envelope(target),
                                                      lane_limit(target))
                self.assertEqual((report["id"], report["status"]), (target, "passed"))
                for field in ("allocations", "allocated_bytes"):
                    head = lane_envelope(target)
                    for sample in head["result"]["targets"][0]["allocation_samples"]:
                        sample[field] += 1
                    report = bench.compare_kernel_results(lane_envelope(target), head,
                                                          lane_limit(target))
                    self.assertEqual(report["status"], "failed")
                cases = LANE_ROWS[target][0]
                report = bench.compare_kernel_results(lane_envelope(target),
                                                      lane_envelope(target, True),
                                                      lane_limit(target), regression_head=True)
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["growth"], {"allocations": cases * 100,
                                                    "allocated_bytes": cases * 6400})
                with self.assertRaises(ValueError):
                    bench.compare_kernel_results(lane_envelope(target), lane_envelope(target, True),
                                                 lane_limit(target))

    def test_envelopes_and_budget_entries_of_different_targets_reject(self):
        cases = (
            (lane_envelope("tool_policy"), lane_envelope("rate_lane"), lane_limit("tool_policy")),
            (lane_envelope("rate_lane"), lane_envelope("tool_policy"), lane_limit("rate_lane")),
            (kernel_envelope(), kernel_envelope(), lane_limit("tool_policy")),
            (lane_envelope("rate_lane"), lane_envelope("rate_lane"), kernel_limit()),
            (lane_envelope("rate_lane"), lane_envelope("rate_lane"), lane_limit("egress_host")),
        )
        for base, head, limit in cases:
            with self.subTest(limit=limit["id"]), self.assertRaises(ValueError):
                bench.compare_kernel_results(base, head, limit)


LANE_DECLARATION = '#[path = "lane_benchmark.rs"]\nmod lane_benchmark;\n'


class LaneWiringTests(unittest.TestCase):
    def harness_source(self):
        return (ROOT / bench.KERNEL_HARNESS_PATH).read_text(encoding="utf-8")

    def test_repository_harness_declares_the_reviewed_child_module(self):
        self.assertIn(LANE_DECLARATION, self.harness_source())
        self.assertTrue(bench.lane_wiring(self.harness_source()))
        self.assertTrue((ROOT / bench.LANE_HARNESS_PATH).is_file())

    def test_harness_without_the_declaration_is_absent(self):
        source = self.harness_source().replace(LANE_DECLARATION, "")
        self.assertFalse(bench.lane_wiring(source))
        commented = self.harness_source().replace(
            LANE_DECLARATION, "".join("// " + line + "\n" for line in LANE_DECLARATION.splitlines()))
        self.assertFalse(bench.lane_wiring(commented))

    def test_redirected_disabled_or_duplicated_wiring_is_rejected(self):
        replacements = {
            "other file": LANE_DECLARATION.replace("lane_benchmark.rs", "decoy.rs"),
            "disabled": "#[cfg(any())]\n" + LANE_DECLARATION,
            "redirected": '#[cfg_attr(test, path = "decoy.rs")]\n' + LANE_DECLARATION,
            "public": LANE_DECLARATION.replace("mod lane", "pub mod lane"),
            "duplicated": LANE_DECLARATION + "#[cfg(any())]\nmod lane_benchmark {}\n",
            "nested": "mod nested {\n" + LANE_DECLARATION + "}\n",
            "inline module": "mod lane_benchmark {}\n",
            "renamed reference": "use crate::decoy as lane_benchmark;\n",
        }
        for name, replacement in replacements.items():
            with self.subTest(change=name):
                source = self.harness_source().replace(LANE_DECLARATION, replacement)
                with self.assertRaises(ValueError):
                    bench.lane_wiring(source)


if __name__ == '__main__':
    unittest.main()
