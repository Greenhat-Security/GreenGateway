"""Tests for the check that ties issue #426's upgrade-pair evidence to the published matrix."""
import copy
import json
from pathlib import Path
import re
import tempfile
import unittest

import build_upgrade_pair as pair
import upgrade_pair_evidence as evidence

PREPARED = "0" * 39 + "1"
SUCCESSOR = "0" * 39 + "2"
GATE = "0" * 39 + "3"
SUBSTITUTION = "build.rs replaced"
SERVE_ROW = "serve_row"
GATE_ROW = "gate_row"
OPERATION_ROW = "the_successors_new_operation_waits_for_every_prepared_member_to_leave"
STEP = {"from": 24, "to": 25, "migration": "an_additive_migration", "checksum": "a" * 64}


def published_pair():
    return {
        "prepared": PREPARED,
        "successor": SUCCESSOR,
        "schema": 18,
        "operation": "policy.role_descriptions",
        "capability": "policy_role_descriptions",
        "procedure": "rolling",
        "rollback_cutoff": "the first described document",
        "evidence": {
            SERVE_ROW: {"schema": {"served": {"min": 18, "max": 18}}, "fingerprints": 1},
            GATE_ROW: {
                "operation_matrix": [
                    {"writer": "successor", "status": 409, "reason": "capability_not_advertised"},
                    {"writer": "successor", "status": 200, "outcome": "admitted"},
                ],
            },
        },
    }


class Fixture:
    """A pair directory, pin and matrix as a passing gate run leaves them."""

    def __init__(self, test: unittest.TestCase):
        temp = tempfile.TemporaryDirectory()
        test.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.dir = self.root / "pair"
        self.pin = self.root / "pin.json"
        self.matrix_path = self.root / "matrix.json"
        self.matrix = {"schema": 1, "qualified_pairs": [published_pair()]}
        self.write(self.pin, {
            "schema": 1, "issue": 426, "prepared": {"commit": PREPARED},
            "successor": {"commit": SUCCESSOR}, "schema_version": 18,
            "operation": "policy.role_descriptions", "capability": "policy_role_descriptions",
        })
        self.write(self.matrix_path, self.matrix)
        manifest = {"schema": 1, "issue": 426, "substitution": SUBSTITUTION}
        for role, content in (("prepared", b"prepared build"), ("successor", b"successor build")):
            binary = self.dir / role / "gateway"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(content)
            manifest[role] = {"commit": PREPARED if role == "prepared" else SUCCESSOR,
                              "binary": f"{role}/gateway", "sha256": pair.sha256(binary)}
        self.manifest = manifest
        self.write(self.dir / "manifest.json", manifest)
        observed = {
            SERVE_ROW: {"schema": {"served": {"min": 18, "max": 18}, "ledger_versions": 18},
                        "fingerprints": 1, "authority": {"security_revision": 9}},
            GATE_ROW: {"operation_matrix": [
                {"writer": "successor", "status": 409, "reason": "capability_not_advertised",
                 "outcome": "refused"},
                {"writer": "successor", "status": 200, "outcome": "admitted"},
            ]},
        }
        for row, value in observed.items():
            self.record(row, value)

    @staticmethod
    def write(path: Path, value) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def identity(self, role: str) -> dict:
        return {"commit": self.manifest[role]["commit"],
                "binary_sha256": self.manifest[role]["sha256"]}

    def record(self, row: str, observed, changes=None) -> None:
        record = {"schema": 1, "issue": 426, "row": row, "prepared": self.identity("prepared"),
                  "successor": self.identity("successor"), "build_substitution": SUBSTITUTION,
                  "observed": observed}
        record.update(changes or {})
        self.write(self.dir / "evidence" / f"{row}.json", record)

    def observed(self, row: str):
        return json.loads((self.dir / "evidence" / f"{row}.json").read_text(encoding="utf-8"))["observed"]

    def cross_schema_step(self) -> None:
        """Re-pin to a pair across one schema step whose successor registers no operation."""
        self.pin_value = {
            "schema": 1, "issue": 426, "prepared": {"commit": PREPARED},
            "successor": {"commit": SUCCESSOR}, "schema_version": 24,
            "schema_step": dict(STEP), "operation": None, "capability": None,
        }
        self.write(self.pin, self.pin_value)
        self.matrix["qualified_pairs"] = [{
            "prepared": PREPARED, "successor": SUCCESSOR, "schema": 24,
            "schema_step": dict(STEP), "operation": None, "capability": None,
            "procedure": "rolling", "rollback_cutoff": "a contraction",
            "evidence": {SERVE_ROW: {"schema": {"served": {"min": 25, "max": 25}}}},
        }]
        self.matrix["schema_steps"] = [
            {"from": 23, "to": 24, "migration": "before", "procedure": "coordinated"},
            {**STEP, "procedure": "rolling",
             "qualified_pair": {"prepared": PREPARED, "successor": SUCCESSOR}},
        ]
        self.write(self.matrix_path, self.matrix)
        (self.dir / "evidence" / f"{GATE_ROW}.json").unlink()
        self.record(SERVE_ROW, {"schema": {"served": {"min": 25, "max": 25}, "ledger_versions": 25}})

    def verify(self, gate_commit=GATE):
        return evidence.verify(self.dir, self.pin, self.matrix_path, gate_commit)


class RepositoryTests(unittest.TestCase):
    def test_the_repositorys_pin_is_a_published_qualified_pair(self):
        pin = pair.load_pin(pair.PIN)
        entry = evidence.find_pair(evidence.load_json(evidence.MATRIX, "the matrix"), pin)
        self.assertEqual(entry["procedure"], "rolling")

    def test_every_published_row_is_a_pair_row_of_the_suite_that_records_it(self):
        suite = (pair.ROOT / "gateway" / "tests" / "ha" / "rolling_upgrade.rs").read_text(encoding="utf-8")
        recorded = set(re.findall(r'write_evidence\(\s*"([a-z0-9_]+)"', suite))
        pin = pair.load_pin(pair.PIN)
        entry = evidence.find_pair(evidence.load_json(evidence.MATRIX, "the matrix"), pin)
        # The operation row records nothing for a successor that registers
        # no operation; every other row records for every pair.
        expected = set(recorded)
        if pin.get("operation") is None:
            expected.discard(OPERATION_ROW)
        self.assertEqual(set(entry["evidence"]), expected)
        self.assertIn(OPERATION_ROW, recorded)
        for row in recorded:
            self.assertRegex(suite, rf"async fn {row}\(\)")

    def test_the_repositorys_rolling_steps_name_only_published_pairs(self):
        matrix = evidence.load_json(evidence.MATRIX, "the matrix")
        for step in matrix["schema_steps"]:
            if step.get("procedure") != "rolling" or step.get("qualified_pair") is None:
                continue
            with self.subTest(step=step):
                published = [entry for entry in matrix["qualified_pairs"]
                             if entry["prepared"] == step["qualified_pair"]["prepared"]
                             and entry["successor"] == step["qualified_pair"]["successor"]]
                self.assertEqual(len(published), 1)
                self.assertEqual(published[0]["schema_step"], {
                    "from": step["from"], "to": step["to"], "migration": step["migration"],
                    "checksum": step["checksum"],
                })


class VerifyTests(unittest.TestCase):
    def test_a_complete_run_is_qualified_and_summarised(self):
        fixture = Fixture(self)
        summary = fixture.verify()
        self.assertEqual(summary["verdict"], "qualified")
        self.assertEqual(summary["gate_commit"], GATE)
        self.assertEqual(summary["pair"]["prepared"], fixture.identity("prepared"))
        self.assertEqual(summary["pair"]["successor"], fixture.identity("successor"))
        self.assertEqual(summary["pair"]["schema"], 18)
        # What the matrix does not judge is still carried as evidence.
        self.assertEqual(summary["rows"][SERVE_ROW]["authority"], {"security_revision": 9})
        written = json.loads((fixture.dir / evidence.SUMMARY).read_text(encoding="utf-8"))
        self.assertEqual(written, summary)

    def assert_refused(self, fixture: Fixture, pattern: str, gate_commit=GATE):
        with self.assertRaisesRegex(evidence.EvidenceError, pattern):
            fixture.verify(gate_commit)
        self.assertFalse((fixture.dir / evidence.SUMMARY).exists(), "a refusal writes no summary")

    def test_a_row_that_recorded_nothing_is_refused(self):
        fixture = Fixture(self)
        (fixture.dir / "evidence" / f"{GATE_ROW}.json").unlink()
        self.assert_refused(fixture, "recorded no evidence")

    def test_a_refusal_removes_the_summary_an_earlier_run_left(self):
        fixture = Fixture(self)
        fixture.verify()
        (fixture.dir / "evidence" / f"{SERVE_ROW}.json").unlink()
        self.assert_refused(fixture, "recorded no evidence")

    def test_a_row_the_matrix_does_not_publish_is_refused(self):
        fixture = Fixture(self)
        fixture.record("an_unpublished_row", {})
        self.assert_refused(fixture, "does not name")

    def test_an_observation_the_matrix_contradicts_is_refused(self):
        fixture = Fixture(self)
        observed = fixture.observed(GATE_ROW)
        observed["operation_matrix"][0]["status"] = 200
        fixture.record(GATE_ROW, observed)
        self.assert_refused(fixture, r"operation_matrix\[0\]\.status should be 409")

    def test_a_missing_or_reshaped_observation_is_refused(self):
        cases = (
            (lambda o: o["operation_matrix"].pop(), "should be a list of 2"),
            (lambda o: o["operation_matrix"][1].pop("outcome"), r"has no 'outcome'"),
            (lambda o: o.update(operation_matrix={"writer": "successor"}), "should be a list"),
        )
        for change, pattern in cases:
            with self.subTest(pattern=pattern):
                fixture = Fixture(self)
                observed = fixture.observed(GATE_ROW)
                change(observed)
                fixture.record(GATE_ROW, observed)
                self.assert_refused(fixture, pattern)

    def test_json_types_are_not_conflated(self):
        self.assertIsNone(evidence.mismatch({"a": [1, None]}, {"a": [1, None], "b": 2}))
        self.assertIsNotNone(evidence.mismatch(1, True))
        self.assertIsNotNone(evidence.mismatch(200, "200"))
        self.assertIsNotNone(evidence.mismatch(None, 0))

    def test_a_row_run_against_another_binary_is_refused(self):
        fixture = Fixture(self)
        fixture.record(GATE_ROW, fixture.observed(GATE_ROW),
                       {"prepared": {"commit": PREPARED, "binary_sha256": "f" * 64}})
        self.assert_refused(fixture, "ran a prepared binary other than the pair's")

    def test_a_row_naming_another_row_or_substitution_is_refused(self):
        for changes, pattern in (({"row": SERVE_ROW}, "says it is the row"),
                                 ({"build_substitution": "none"}, "build substitution"),
                                 ({"issue": 1}, "is not schema 1 issue #426")):
            with self.subTest(changes=changes):
                fixture = Fixture(self)
                fixture.record(GATE_ROW, fixture.observed(GATE_ROW), changes)
                self.assert_refused(fixture, pattern)

    def test_a_binary_replaced_after_the_build_is_refused(self):
        fixture = Fixture(self)
        (fixture.dir / "successor" / "gateway").write_bytes(b"something else")
        self.assert_refused(fixture, "not the one the build recorded")

    def test_two_identical_builds_are_refused(self):
        fixture = Fixture(self)
        (fixture.dir / "successor" / "gateway").write_bytes(b"prepared build")
        fixture.manifest["successor"]["sha256"] = fixture.manifest["prepared"]["sha256"]
        fixture.write(fixture.dir / "manifest.json", fixture.manifest)
        self.assert_refused(fixture, "same binary")

    def test_a_manifest_that_disagrees_with_the_pin_or_escapes_the_directory_is_refused(self):
        for role, key, value, pattern in (
            ("successor", "commit", PREPARED, "rebuild the pair"),
            ("prepared", "binary", "../outside", "outside the pair directory"),
            ("prepared", "binary", "prepared/missing", "cannot hash"),
        ):
            with self.subTest(key=key, value=value):
                fixture = Fixture(self)
                fixture.manifest[role][key] = value
                fixture.write(fixture.dir / "manifest.json", fixture.manifest)
                self.assert_refused(fixture, pattern)

    def test_a_pin_the_matrix_does_not_publish_is_refused(self):
        fixture = Fixture(self)
        fixture.matrix["qualified_pairs"] = []
        fixture.write(fixture.matrix_path, fixture.matrix)
        self.assert_refused(fixture, "publish the pair")

    def test_a_published_pair_that_disagrees_with_the_pin_is_refused(self):
        for key, value in (("schema", 17), ("operation", "policy.other"), ("capability", "other")):
            with self.subTest(key=key):
                fixture = Fixture(self)
                fixture.matrix["qualified_pairs"][0][key] = value
                fixture.write(fixture.matrix_path, fixture.matrix)
                self.assert_refused(fixture, f"says {key}")

    def test_a_pair_published_twice_or_without_rows_is_refused(self):
        for change, pattern in (
            (lambda m: m["qualified_pairs"].append(copy.deepcopy(m["qualified_pairs"][0])),
             "not exactly one"),
            (lambda m: m["qualified_pairs"][0].update(evidence={}), "names no evidence rows"),
            (lambda m: m.update(schema=2), "schema 1 object"),
        ):
            with self.subTest(pattern=pattern):
                fixture = Fixture(self)
                change(fixture.matrix)
                fixture.write(fixture.matrix_path, fixture.matrix)
                self.assert_refused(fixture, pattern)

    def test_a_pair_across_a_schema_step_is_qualified_as_that_steps_pair(self):
        fixture = Fixture(self)
        fixture.cross_schema_step()
        summary = fixture.verify()
        self.assertEqual(summary["verdict"], "qualified")
        self.assertEqual(summary["pair"]["schema_step"], STEP)
        self.assertIsNone(summary["pair"]["operation"])
        self.assertEqual(set(summary["rows"]), {SERVE_ROW})

    def test_a_schema_step_the_pin_and_the_matrix_disagree_on_is_refused(self):
        def published_pair(m):
            return m["qualified_pairs"][0]

        def rolling_step(m):
            return m["schema_steps"][1]

        cases = (
            (lambda m: published_pair(m)["schema_step"].update(checksum="b" * 64),
             "published pair says schema_step"),
            (lambda m: published_pair(m).pop("schema_step"),
             "published pair says schema_step"),
            (lambda m: rolling_step(m).update(checksum="b" * 64),
             "published schema step says checksum"),
            (lambda m: rolling_step(m).update(migration="another"),
             "published schema step says migration"),
            (lambda m: rolling_step(m).update(procedure="coordinated"), "not rolling"),
            (lambda m: rolling_step(m).update(qualified_pair=None), "not the pin"),
            (lambda m: rolling_step(m).update(
                qualified_pair={"prepared": SUCCESSOR, "successor": PREPARED}), "not the pin"),
            (lambda m: m["schema_steps"].pop(), "no single schema step from 24 to 25"),
            (lambda m: m["schema_steps"].append(copy.deepcopy(rolling_step(m))),
             "no single schema step from 24 to 25"),
        )
        for change, pattern in cases:
            with self.subTest(pattern=pattern):
                fixture = Fixture(self)
                fixture.cross_schema_step()
                change(fixture.matrix)
                fixture.write(fixture.matrix_path, fixture.matrix)
                self.assert_refused(fixture, pattern)

    def test_a_malformed_schema_step_in_the_pin_is_refused(self):
        cases = (
            ({"to": 26}, "one migration from the pin's schema_version"),
            ({"from": 23, "to": 24}, "one migration from the pin's schema_version"),
            ({"from": True}, "one migration from the pin's schema_version"),
            ({"checksum": "A" * 64}, "one lowercase SHA-256"),
            ({"migration": ""}, "names no migration"),
            ({"extra": 1}, "exactly from, to, migration and checksum"),
        )
        for change, pattern in cases:
            with self.subTest(change=change):
                fixture = Fixture(self)
                fixture.cross_schema_step()
                step = {**STEP, **change}
                fixture.pin_value["schema_step"] = step
                fixture.write(fixture.pin, fixture.pin_value)
                # The published pair agrees with the pin, so only the step's
                # own shape is judged.
                fixture.matrix["qualified_pairs"][0]["schema_step"] = step
                fixture.write(fixture.matrix_path, fixture.matrix)
                self.assert_refused(fixture, pattern)

    def test_a_pair_at_one_schema_point_must_not_be_published_across_a_step(self):
        fixture = Fixture(self)
        fixture.matrix["qualified_pairs"][0]["schema_step"] = dict(STEP)
        fixture.write(fixture.matrix_path, fixture.matrix)
        self.assert_refused(fixture, "published pair says schema_step")

    def test_the_gate_commit_must_be_a_full_sha_when_given(self):
        self.assert_refused(Fixture(self), "full lowercase commit SHA", gate_commit="abc123")
        self.assertIsNone(Fixture(self).verify(gate_commit=None)["gate_commit"])


if __name__ == "__main__":
    unittest.main()
