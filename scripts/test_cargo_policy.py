"""Policy regressions and real pinned cargo-deny checks on inert metadata fixtures.

Every rejection case starts from a baseline that is valid by construction, so it
can only fail for the one rule it mutates. The committed inventory is compared
with the live Cargo.lock in exactly one test, GraphTests.test_complete_current_graph
(and again by `cargo_policy.py check`): that test must fail on every unreviewed
lockfile change, and nothing else here may depend on the lockfile staying put.
"""
import copy
from datetime import date, timedelta
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

import cargo_policy as policy

ROOT = policy.ROOT


def review_date(exceptions):
    """The last day on which every exception in `exceptions` is inside its review window.

    Derived from the file instead of pinned, so the renewals each dependency bump
    brings never invalidate the baseline of the rule tests, and independent of the
    wall clock, which only the real check reads. A file with no such day (expiries
    90 or more days apart) can never pass the real check either, and fails here too.
    """
    entries = exceptions["duplicates"] + exceptions["licenses"]
    return min(date.fromisoformat(entry["expires"]) for entry in entries) - timedelta(days=1)


class ConfigTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="ggw-cargo-policy-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for file in ["deny.toml", "cargo-policy-exceptions.json", "Cargo.lock", "build-tools.json"]:
            shutil.copyfile(ROOT / file, self.root / file)
        self.today = review_date(policy.read_json(self.root / "cargo-policy-exceptions.json"))

    def mutate_exceptions(self, edit):
        path = self.root / "cargo-policy-exceptions.json"
        data = policy.read_json(path)
        edit(data)
        path.write_text(json.dumps(data), encoding="utf-8")

    def rejects(self, expected):
        with self.assertRaisesRegex(ValueError, expected):
            policy.validate_config(self.root, self.today)

    def test_current_configuration(self):
        policy.validate_config(self.root, self.today)

    def test_expiry_and_excessive_horizon_fail(self):
        name = policy.read_json(self.root / "cargo-policy-exceptions.json")["duplicates"][0]["name"]
        for days in [-1, 0, 91]:
            expiry = (self.today + timedelta(days=days)).isoformat()
            with self.subTest(expiry=expiry):
                self.mutate_exceptions(lambda d: d["duplicates"][0].update(expires=expiry))
                self.rejects("^" + re.escape(name) + ": exception expired or exceeds")

    def test_review_horizon_includes_its_first_and_ninetieth_day(self):
        for days in [1, 90]:
            expiry = (self.today + timedelta(days=days)).isoformat()
            with self.subTest(expiry=expiry):
                self.mutate_exceptions(lambda d: d["duplicates"][0].update(expires=expiry))
                policy.validate_config(self.root, self.today)

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
        # Structure only: whether the exceptions are still live today is the
        # real check's question (`cargo_policy.py check` runs next in CI).
        committed = policy.read_json(ROOT / "cargo-policy-exceptions.json")
        cls.exceptions = policy.validate_config(ROOT, review_date(committed))


class GraphTests(MetadataTests):
    def test_complete_current_graph(self):
        # The one deliberate coupling to the live lockfile: a Cargo.lock change
        # that moves a duplicate version or parent chain, or drops a
        # license-excepted crate version, must fail here until it is reviewed.
        try:
            policy.validate_graph(self.metadata, self.locked, self.exceptions)
        except ValueError as error:
            self.fail(f"{error}: Cargo.lock no longer matches the reviewed inventory; review the change and "
                      "update cargo-policy-exceptions.json and deny.toml (docs/deployment/cargo-dependency-policy.md)")

    def test_reduced_package_inventory_fails(self):
        # Metadata and lock inventory both come from the same Cargo.lock, and
        # coverage is checked before any exception, so this holds across bumps.
        data = copy.deepcopy(self.metadata)
        data["packages"].pop()
        with self.assertRaisesRegex(ValueError, "entire locked package graph"):
            policy.validate_graph(data, self.locked, self.exceptions)


def graph_fixture():
    """An inert graph that satisfies every graph rule by construction, independent of Cargo.lock.

    Workspace member app@0.1.0 depends on left, right and licensed; left pulls
    dup@1.0.0 and twin@0.1.0, right pulls dup@2.0.0 and twin@0.2.0. `dup` and
    `twin` are the only duplicates, each version with one reviewed parent chain,
    and licensed@3.1.4 carries the only license exception. Exceptions carry only
    the fields validate_graph reads; review metadata is ConfigTests' subject.
    """
    def package(name, version, source=policy.REGISTRY):
        prefix = source or "path+file:///fixture/" + name
        return {"name": name, "version": version, "source": source, "id": f"{prefix}#{name}@{version}"}

    app = package("app", "0.1.0", source=None)
    left, right, licensed = package("left", "1.0.0"), package("right", "1.0.0"), package("licensed", "3.1.4")
    dup1, dup2, twin1, twin2 = (package("dup", "1.0.0"), package("dup", "2.0.0"),
                                package("twin", "0.1.0"), package("twin", "0.2.0"))
    packages = [app, left, right, licensed, dup1, dup2, twin1, twin2]
    edges = {app["id"]: [left, right, licensed], left["id"]: [dup1, twin1], right["id"]: [dup2, twin2]}
    metadata = {"packages": packages, "workspace_members": [app["id"]],
                "resolve": {"nodes": [{"id": p["id"], "dependencies": [d["id"] for d in edges.get(p["id"], [])]}
                                      for p in packages]}}
    locked = {(p["name"], p["version"], p["source"]) for p in packages}
    exceptions = {"schema_version": 1, "duplicates": [
        {"name": "dup", "versions": ["1.0.0", "2.0.0"], "parents": {"1.0.0": ["left@1.0.0"], "2.0.0": ["right@1.0.0"]}},
        {"name": "twin", "versions": ["0.1.0", "0.2.0"], "parents": {"0.1.0": ["left@1.0.0"], "0.2.0": ["right@1.0.0"]}},
    ], "licenses": [{"crate": "licensed@3.1.4", "allow": ["MPL-2.0"]}]}
    return metadata, locked, exceptions


class GraphRuleTests(unittest.TestCase):
    """Each graph rule against the inert fixture: no lockfile, cargo or clock involved."""

    def setUp(self):
        self.metadata, self.locked, self.exceptions = graph_fixture()

    def rejects(self, expected, metadata=None, exceptions=None):
        with self.assertRaisesRegex(ValueError, expected):
            policy.validate_graph(self.metadata if metadata is None else metadata, self.locked,
                                  self.exceptions if exceptions is None else exceptions)

    def test_fixture_control_is_clean(self):
        # A clean control prevents a broken fixture from masquerading as rejection.
        policy.validate_graph(self.metadata, self.locked, self.exceptions)

    def test_duplicate_parent_drift_fails(self):
        exceptions = copy.deepcopy(self.exceptions)
        entry = exceptions["duplicates"][0]
        entry["parents"][entry["versions"][0]] = ["unreviewed-parent@1.0.0"]
        self.rejects("^duplicate versions or parent chains changed: dup$", exceptions=exceptions)

    def test_lockfile_reparenting_a_duplicate_fails(self):
        # What a dependency bump does: dup@2.0.0 is now reached from left too.
        metadata = copy.deepcopy(self.metadata)
        left = next(n for n in metadata["resolve"]["nodes"] if n["id"].endswith("#left@1.0.0"))
        left["dependencies"].append(next(p["id"] for p in metadata["packages"] if p["id"].endswith("#dup@2.0.0")))
        self.rejects("^duplicate versions or parent chains changed: dup$", metadata=metadata)

    def test_removed_duplicate_exception_fails(self):
        exceptions = copy.deepcopy(self.exceptions)
        exceptions["duplicates"].pop()
        self.rejects("^duplicate crate inventory changed", exceptions=exceptions)

    def test_stale_license_exception_fails(self):
        exceptions = copy.deepcopy(self.exceptions)
        exceptions["licenses"][0]["crate"] = "licensed@0.0.0"
        self.rejects("^stale license exception: licensed@0\\.0\\.0$", exceptions=exceptions)


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
