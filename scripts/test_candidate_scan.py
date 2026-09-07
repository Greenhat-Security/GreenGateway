"""Sanitized final-image decision and orchestration regressions; no live targets."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import os
import unittest
from unittest.mock import patch

import yaml
import scan_candidate_image as scan

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
CONFIG = "sha256:" + "c" * 64
IMAGE = "ghcr.io/example/gateway@" + DIGEST
NOW = datetime.now(timezone.utc)


def rules():
    return {"schema_version": 1, "platforms": ["linux/amd64"], "max_database_age_hours": 48, "exceptions": []}


def report():
    return {"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": IMAGE,
            "CreatedAt": NOW.isoformat(), "Metadata": {"ImageID": CONFIG, "RepoDigests": [IMAGE],
            "OS": {"Family": "debian"}, "ImageConfig": {"os": "linux", "architecture": "amd64",
            "config": {"Labels": {"org.opencontainers.image.revision": SHA}}}},
            "Results": [{"Class": "os-pkgs", "Packages": [{"Name": "fixture", "Version": "1.0"}],
                         "Vulnerabilities": []}]}


def finding(severity="HIGH"):
    return {"VulnerabilityID": "CVE-2099-12345", "PkgName": "fixture", "InstalledVersion": "1.0", "Severity": severity}


class DecisionTests(unittest.TestCase):
    def test_checked_in_policy_is_valid_today(self):
        scan.policy(json.loads((scan.ROOT / "image-scan-policy.json").read_text()), datetime.now(timezone.utc))

    def test_full_orchestration_only_outputs_digest_after_a_clean_scan(self):
        for mode in ["clean", "blocked", "stale", "unavailable", "empty"]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "evidence"
                github_output = Path(directory) / "job-output"
                def run(command, **kwargs):
                    if command[1:] == ["--version"]:
                        return subprocess.CompletedProcess(command, 0, stdout="Version: " + scan.versions()["trivy"])
                    if "--download-db-only" in command:
                        if mode == "unavailable":
                            raise subprocess.CalledProcessError(1, command)
                        cache = Path(command[command.index("--cache-dir")+1]) / "db"
                        cache.mkdir(parents=True)
                        age = 49 if mode == "stale" else 1
                        (cache/"metadata.json").write_text(json.dumps({"Version": 2, "UpdatedAt": (NOW-timedelta(hours=age)).isoformat()}))
                    else:
                        data = report()
                        if mode == "blocked":
                            data["Results"][0]["Vulnerabilities"] = [finding()]
                        Path(command[command.index("--output")+1]).write_text("" if mode == "empty" else json.dumps(data))
                    return subprocess.CompletedProcess(command, 0, stdout="")
                manifests = {"linux/amd64": {"digest": DIGEST, "config_digest": CONFIG}}
                with patch.dict(os.environ, {"GITHUB_OUTPUT": str(github_output)}), patch.object(scan, "Registry"), \
                     patch.object(scan, "runtime_manifests", return_value=(manifests, {})), patch.object(scan.subprocess, "run", side_effect=run):
                    if mode == "clean":
                        self.assertEqual(scan.scan("example/gateway", DIGEST, SHA, output, "trivy")["status"], "passed")
                        self.assertEqual(github_output.read_text().strip(), "digest="+DIGEST)
                    else:
                        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                            scan.scan("example/gateway", DIGEST, SHA, output, "trivy")
                        self.assertFalse(github_output.exists())
                        self.assertNotEqual(json.loads((output/"decision.json").read_text())["status"], "passed")

    def check_report(self, data, policy=None):
        return scan.evaluate(data, IMAGE, "linux/amd64", CONFIG, SHA, DIGEST, policy or rules(), NOW)

    def test_clean_inventory_passes_but_all_blocking_severities_fail(self):
        self.assertEqual(self.check_report(report())["blocked"], [])
        for severity in ["HIGH", "CRITICAL", "UNKNOWN"]:
            data = report()
            data["Results"][0]["Vulnerabilities"] = [finding(severity)]
            self.assertEqual(len(self.check_report(data)["blocked"]), 1)

    def test_report_cannot_substitute_identity_or_omit_inventory(self):
        mutations = [
            lambda r: r.update(ArtifactName="ghcr.io/example/gateway:latest"),
            lambda r: r.update(ArtifactType="filesystem"),
            lambda r: r.update(SchemaVersion=1),
            lambda r: r.update(Results=[]),
            lambda r: r["Results"][0].update(Packages=[]),
            lambda r: r["Results"][0].update(Vulnerabilities=None),
            lambda r: r["Metadata"].update(ImageID=DIGEST),
            lambda r: r["Metadata"].update(RepoDigests=[]),
            lambda r: r["Metadata"]["ImageConfig"].update(architecture="arm64"),
            lambda r: r["Metadata"]["ImageConfig"]["config"]["Labels"].clear(),
            lambda r: r["Metadata"]["OS"].update(EOSL=True),
            lambda r: r.update(CreatedAt=(NOW-timedelta(hours=2)).isoformat()),
        ]
        for mutate in mutations:
            data = report()
            mutate(data)
            with self.assertRaises(ValueError):
                self.check_report(data)

    def test_exception_is_exact_expiring_and_visible_in_evidence(self):
        entry = {"advisory": "CVE-2099-12345", "package": "fixture", "version": "1.0",
                 "digest": DIGEST, "owner": "release-maintainer", "rationale": "Sanitized test-only review rationale.",
                 "expires": (NOW+timedelta(days=7)).isoformat()}
        data, policy = report(), rules()
        data["Results"][0]["Vulnerabilities"] = [finding()]
        policy["exceptions"] = [entry]
        scan.policy(policy, NOW)
        result = self.check_report(data, policy)
        self.assertFalse(result["blocked"])
        self.assertEqual(result["applied_exceptions"][0]["exception"], entry)
        for field, value in [("version", "1.1"), ("package", "other"), ("digest", CONFIG), ("advisory", "CVE-2099-54321")]:
            changed = copy.deepcopy(policy)
            changed["exceptions"][0][field] = value
            self.assertTrue(self.check_report(data, changed)["blocked"])
        for field, value in [("version", "*"), ("owner", ""), ("expires", NOW.isoformat()),
                             ("expires", (NOW+timedelta(days=91)).isoformat()), ("digest", "latest")]:
            changed = copy.deepcopy(policy)
            changed["exceptions"][0][field] = value
            with self.assertRaises(ValueError):
                scan.policy(changed, NOW)

    def test_stale_future_or_timezone_free_database_is_rejected(self):
        for value in [(NOW-timedelta(hours=49)).isoformat(), (NOW+timedelta(minutes=6)).isoformat(), "2026-09-07T00:00:00"]:
            with self.assertRaises(ValueError):
                scan.fresh(value, NOW, 48)
        scan.fresh((NOW-timedelta(hours=2)).isoformat(), NOW, 48)

    def test_index_cannot_hide_an_unscanned_platform(self):
        class Registry:
            def get(self, digest, kind="manifests"):
                if kind == "blobs":
                    return report()["Metadata"]["ImageConfig"]
                return {"schemaVersion": 2, "config": {"digest": CONFIG}}
        found, _ = scan.runtime_manifests(Registry(), DIGEST, ["linux/amd64"], SHA)
        self.assertEqual(found["linux/amd64"]["digest"], DIGEST)
        with self.assertRaises(ValueError):
            scan.runtime_manifests(Registry(), DIGEST, ["linux/amd64", "linux/arm64"], SHA)
        with self.assertRaises(ValueError):
            scan.runtime_manifests(Registry(), DIGEST, ["linux/amd64"], "d"*40)

    def test_scanner_failure_preserves_error_verdict_and_never_outputs_success(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            with patch.object(scan, "Registry"), patch.object(scan, "runtime_manifests", return_value=({}, {})), \
                 patch.object(scan.subprocess, "run", side_effect=subprocess.CalledProcessError(2, "trivy")):
                with self.assertRaises(subprocess.CalledProcessError):
                    scan.scan("example/gateway", DIGEST, SHA, output, "trivy")
            self.assertEqual(json.loads((output/"decision.json").read_text())["status"], "error")

    def test_moving_tag_is_rejected_before_registry_access(self):
        with patch.object(scan, "Registry") as registry:
            with self.assertRaises(ValueError):
                scan.scan("example/gateway", "latest", SHA, Path("unused"))
            registry.assert_not_called()

    def test_scan_job_is_read_only_exact_and_required(self):
        ci = yaml.load((scan.ROOT/".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        job = ci["jobs"]["image-scan"]
        self.assertEqual(job["permissions"], {"contents": "read", "packages": "read"})
        self.assertEqual(job["needs"], "image-candidate")
        self.assertEqual(job["if"], "github.event_name == 'push'")
        step = next(s for s in job["steps"] if s.get("id") == "scan")
        self.assertEqual(step["env"]["CANDIDATE_DIGEST"], "${{ needs.image-candidate.outputs.digest }}")
        self.assertEqual(step["run"], "python scripts/scan_candidate_image.py")
        self.assertIn("image-scan", ci["jobs"]["promote-image"]["needs"])
        self.assertIn("!contains(needs.*.result, 'skipped')", ci["jobs"]["promote-image"]["if"])


if __name__ == "__main__":
    unittest.main()
