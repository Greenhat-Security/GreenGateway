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
        entry = evidence.find_pair(evidence.load_json(evidence.MATRIX, "the matrix"),
                                   pair.load_pin(pair.PIN))
        self.assertEqual(set(entry["evidence"]), recorded)
        for row in recorded:
            self.assertRegex(suite, rf"async fn {row}\(\)")


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

    def test_the_gate_commit_must_be_a_full_sha_when_given(self):
        self.assert_refused(Fixture(self), "full lowercase commit SHA", gate_commit="abc123")
        self.assertIsNone(Fixture(self).verify(gate_commit=None)["gate_commit"])


if __name__ == "__main__":
    unittest.main()
