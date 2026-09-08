"""Policy regressions and real pinned cargo-deny checks on inert metadata fixtures."""
import copy
from datetime import date
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import cargo_policy as policy

ROOT = policy.ROOT
REVIEW_DATE = date(2026, 9, 7)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="ggw-cargo-policy-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for file in ["deny.toml", "cargo-policy-exceptions.json", "Cargo.lock", "build-tools.json"]:
            shutil.copyfile(ROOT / file, self.root / file)

    def mutate_exceptions(self, edit):
        path = self.root / "cargo-policy-exceptions.json"
        data = policy.read_json(path)
        edit(data)
        path.write_text(json.dumps(data), encoding="utf-8")

    def rejects(self, expected):
        with self.assertRaisesRegex(ValueError, expected):
            policy.validate_config(self.root, REVIEW_DATE)

    def test_current_configuration(self):
        policy.validate_config(self.root, REVIEW_DATE)

    def test_expiry_and_excessive_horizon_fail(self):
        for expiry in ["2026-09-06", "2026-09-07", "2027-01-01"]:
            with self.subTest(expiry=expiry):
                self.mutate_exceptions(lambda d: d["duplicates"][0].update(expires=expiry))
                self.rejects("expired or exceeds")

    def test_unowned_exception_fails(self):
        self.mutate_exceptions(lambda d: d["licenses"][0].update(owner=""))
        self.rejects("owner")

    def test_version_wildcard_fails(self):
        self.mutate_exceptions(lambda d: d["duplicates"][0].update(versions=["*", "0.12.1"]))
        self.rejects("exact distinct versions")

    def test_license_exception_cannot_cover_all_versions(self):
        self.mutate_exceptions(lambda d: d["licenses"][0].update(crate="notify"))
        self.rejects("unique exact crate version")

    def test_missing_remediation_fails(self):
        self.mutate_exceptions(lambda d: d["duplicates"][0].update(remediation=""))
        self.rejects("remediation")

    def test_reduced_graph_or_weakened_policy_fails(self):
        path = self.root / "deny.toml"
        original = path.read_text()
        for before, after in [("all-features = true", "all-features = false"),
                              ("exclude-dev = false", "exclude-dev = true"),
                              ("targets = []", 'targets = ["x86_64-pc-windows-msvc"]'),
                              ('multiple-versions = "deny"', 'multiple-versions = "allow"'),
                              ('unknown-git = "deny"', 'unknown-git = "allow"'),
                              ("skip-tree = []", 'skip-tree = ["tokio"]')]:
            with self.subTest(after=after):
                path.write_text(original.replace(before, after))
                self.rejects("full-graph policy")

    def test_hidden_license_override_fails(self):
        (self.root / "deny.exceptions.toml").write_text('exceptions = []\n')
        self.rejects("undeclared Cargo policy override")

    def test_unapproved_lock_source_fails_before_fetch(self):
        path = self.root / "Cargo.lock"
        path.write_text(path.read_text().replace(policy.REGISTRY, "git+https://example.invalid/repo#" + "a" * 40, 1))
        with self.assertRaisesRegex(ValueError, "refusing metadata fetch"):
            policy.lock_inventory(self.root)

    def test_missing_tool_records_failure_not_clean(self):
        with self.assertRaises(OSError):
            policy.check(self.root)
        decision = policy.read_json(self.root / "target/cargo-policy/decision.json")
        self.assertEqual((decision["status"], decision["stage"]), ("failed", "tool"))

    def test_missing_config_records_failure_not_clean(self):
        (self.root / "deny.toml").unlink()
        with self.assertRaises(OSError):
            policy.check(self.root)
        self.assertEqual(policy.read_json(self.root / "target/cargo-policy/decision.json")["status"], "failed")


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--locked", "--all-features", "--format-version", "1"], cwd=ROOT))
        cls.locked = policy.lock_inventory()
        cls.exceptions = policy.validate_config()


class GraphTests(MetadataTests):
    def test_complete_current_graph(self):
        policy.validate_graph(self.metadata, self.locked, self.exceptions)

    def test_reduced_package_inventory_fails(self):
        data = copy.deepcopy(self.metadata)
        data["packages"].pop()
        with self.assertRaisesRegex(ValueError, "entire locked package graph"):
            policy.validate_graph(data, self.locked, self.exceptions)

    def test_duplicate_parent_drift_fails(self):
        exceptions = copy.deepcopy(self.exceptions)
        entry = exceptions["duplicates"][0]
        entry["parents"][entry["versions"][0]] = ["unreviewed-parent@1.0.0"]
        with self.assertRaisesRegex(ValueError, "parent chains changed"):
            policy.validate_graph(self.metadata, self.locked, exceptions)

    def test_removed_duplicate_exception_fails(self):
        exceptions = copy.deepcopy(self.exceptions)
        exceptions["duplicates"].pop()
        with self.assertRaisesRegex(ValueError, "duplicate crate inventory changed"):
            policy.validate_graph(self.metadata, self.locked, exceptions)

    def test_stale_license_exception_fails(self):
        exceptions = copy.deepcopy(self.exceptions)
        exceptions["licenses"][0]["crate"] = "notify@0.0.0"
        with self.assertRaisesRegex(ValueError, "stale license exception"):
            policy.validate_graph(self.metadata, self.locked, exceptions)


class NativeTests(MetadataTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        policy.verify_tool()

    def native(self, metadata, which):
        # Metadata mutations never alter dependencies, execute build scripts or
        # contact a registry/Git server. The native parser/checker is the subject.
        with tempfile.TemporaryDirectory(prefix="ggw-cargo-native-") as directory:
            path = Path(directory) / "metadata.json"
            path.write_text(json.dumps(metadata), encoding="utf-8")
            result = subprocess.run([str(policy.executable()), "--locked", "--offline",
                "--all-features", "--workspace", "--metadata-path", str(path),
                "--config", str(ROOT / "deny.toml"), "--format", "json", "check", which],
                cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=60)
            codes = [json.loads(line).get("fields", {}).get("code")
                     for line in (result.stdout + result.stderr).splitlines() if line.startswith("{")]
            return result, codes

    def modified(self, name=None, source=None, license=None):
        data = copy.deepcopy(self.metadata)
        package = next(p for p in data["packages"] if p["name"] == "memchr")
        old = package["id"]
        if license:
            package["license"] = license
        if name:
            package["name"] = name
        if source:
            package["source"] = source
        new = (source or policy.REGISTRY) + "#" + (name or "memchr") + "@" + package["version"]
        # Cargo IDs occur both in package records and graph edges.
        return json.loads(json.dumps(data).replace(old, new))

    def test_native_control_is_clean(self):
        for which in ["licenses", "bans", "sources"]:
            result, _ = self.native(self.metadata, which)
            self.assertEqual(result.returncode, 0, result.stderr[-1500:])

    def test_native_license_rejection(self):
        result, codes = self.native(self.modified(license="GPL-3.0-only"), "licenses")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rejected", codes)

    def test_native_banned_crate_rejection(self):
        result, codes = self.native(self.modified(name="openssl"), "bans")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("banned", codes)

    def test_native_registry_rejection(self):
        result, codes = self.native(self.modified(source="registry+https://unapproved.example.invalid/index"), "sources")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source-not-allowed", codes)

    def test_native_git_rejection(self):
        result, codes = self.native(self.modified(source="git+https://unapproved.example.invalid/repo?rev=" + "a" * 40), "sources")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source-not-allowed", codes)


if __name__ == "__main__":
    unittest.main()
