"""Offline publication regressions: workflow dependencies and Docker arguments."""

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from promote_image import promote


ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


def environment(ref="refs/heads/main"):
    return {
        "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "Example/Gateway",
        "GITHUB_SHA": SHA, "GITHUB_REF": ref, "CANDIDATE_DIGEST": DIGEST,
    }


class PromotionTests(unittest.TestCase):
    def invoke(self, env, current=SHA):
        with patch("promote_image.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess([], 0, stdout=current + "\n")
            result = promote(env)
        return result, run.call_args_list

    def test_main_promotes_only_built_digest_to_sha_and_latest(self):
        result, calls = self.invoke(environment())
        self.assertTrue(result)
        self.assertEqual(calls[0].args[0], [
            "gh", "api", "repos/Example/Gateway/commits/refs%2Fheads%2Fmain", "--jq", ".sha",
        ])
        self.assertEqual(calls[1].args[0], [
            "docker", "buildx", "imagetools", "create", "--prefer-index=false",
            "--tag", f"ghcr.io/example/gateway:{SHA}",
            "--tag", "ghcr.io/example/gateway:latest", f"ghcr.io/example/gateway@{DIGEST}",
        ])
        self.assertEqual(len(calls), 2)

    def test_version_promotion_never_changes_latest(self):
        result, calls = self.invoke(environment("refs/tags/v1.2.3"))
        self.assertTrue(result)
        command = calls[1].args[0]
        self.assertIn("ghcr.io/example/gateway:v1.2.3", command)
        self.assertIn("ghcr.io/example/gateway:1.2.3", command)
        self.assertNotIn("ghcr.io/example/gateway:latest", command)
        self.assertEqual(command[-1], f"ghcr.io/example/gateway@{DIGEST}")

    def test_superseded_main_or_moved_tag_cannot_promote(self):
        for ref in ["refs/heads/main", "refs/tags/v1.2.3"]:
            with self.subTest(ref=ref):
                result, calls = self.invoke(environment(ref), "c" * 40)
                self.assertFalse(result)
                self.assertEqual(len(calls), 1)

    def test_invalid_inputs_fail_before_registry_or_api_calls(self):
        for field, value in [
            ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_EVENT_NAME", "workflow_run"),
            ("GITHUB_SHA", "main"), ("CANDIDATE_DIGEST", ""),
            ("CANDIDATE_DIGEST", "candidate-tag"), ("CANDIDATE_DIGEST", DIGEST + ";echo bad"),
            ("GITHUB_REPOSITORY", "../other"), ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_REF", "refs/tags/v1.2.3-rc1"), ("GITHUB_REF", "refs/tags/v01.2.3"),
        ]:
            with self.subTest(field=field, value=value):
                env = environment()
                env[field] = value
                with patch("promote_image.subprocess.run") as run:
                    with self.assertRaises(ValueError):
                        promote(env)
                    run.assert_not_called()

    def test_lookup_failure_or_invalid_commit_cannot_promote(self):
        with patch("promote_image.subprocess.run", side_effect=subprocess.CalledProcessError(1, "gh")) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                promote(environment())
            self.assertEqual(run.call_count, 1)
        with self.assertRaises(ValueError):
            self.invoke(environment(), "null")

    def test_registry_failure_is_not_reported_as_success(self):
        with patch("promote_image.subprocess.run", side_effect=[
            subprocess.CompletedProcess([], 0, stdout=SHA),
            subprocess.CalledProcessError(1, "docker"),
        ]):
            with self.assertRaises(subprocess.CalledProcessError):
                promote(environment())


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        # BaseLoader preserves YAML keys such as 'on' and gives scalar strings;
        # these tests care about exact expressions, not YAML 1.1 booleans.
        self.ci = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        self.candidate = yaml.load((ROOT / ".github/workflows/publish-image.yml").read_text(), Loader=yaml.BaseLoader)

    def test_every_validation_job_gates_promotion_in_the_same_run(self):
        jobs = self.ci["jobs"]
        promotion = jobs["promote-image"]
        # image-preview is PR-only; on pushes its build is covered by candidate.
        self.assertEqual(set(promotion["needs"]), set(jobs) - {"promote-image", "image-preview"})
        self.assertEqual(promotion["if"], "${{ github.event_name == 'push' && success() && !contains(needs.*.result, 'skipped') }}")
        self.assertIn("gitleaks", promotion["needs"])
        self.assertIn("ha-release-gate", promotion["needs"])
        self.assertEqual(self.ci["on"]["push"]["branches"], ["main"])
        self.assertEqual(self.ci["on"]["push"]["tags"], ["v*.*.*"])
        self.assertFalse((ROOT / ".github/workflows/secrets.yml").exists())

    def test_candidates_are_built_from_the_checked_sha_and_only_output_digest(self):
        self.assertEqual(set(self.candidate["on"]), {"workflow_call"})
        call = self.ci["jobs"]["image-candidate"]
        self.assertEqual(call["if"], "github.event_name == 'push'")
        self.assertEqual(call["uses"], "./.github/workflows/publish-image.yml")
        build = self.candidate["jobs"]["build"]
        self.assertEqual(build["if"], "github.event_name == 'push'")
        checkout = build["steps"][0]
        self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")
        self.assertEqual(checkout["with"]["persist-credentials"], "false")
        naming = next(step for step in build["steps"] if step.get("id") == "image")["run"]
        self.assertIn("candidate-${GITHUB_SHA}-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}", naming)
        self.assertNotIn(":latest", naming)
        self.assertEqual(build["outputs"]["digest"], "${{ steps.build.outputs.digest }}")
        self.assertEqual(self.candidate["on"]["workflow_call"]["outputs"]["digest"]["value"], "${{ jobs.build.outputs.digest }}")

    def test_pull_requests_cannot_publish_and_promotion_never_rebuilds(self):
        preview = self.ci["jobs"]["image-preview"]
        self.assertEqual(preview["if"], "github.event_name == 'pull_request'")
        self.assertEqual(preview["permissions"], {"contents": "read"})
        self.assertEqual(preview["steps"][-1]["with"]["push"], "false")
        promotion = self.ci["jobs"]["promote-image"]
        self.assertEqual(promotion["concurrency"]["cancel-in-progress"], "false")
        self.assertEqual(promotion["steps"][0]["with"]["ref"], "${{ github.sha }}")
        for step in promotion["steps"]:
            self.assertNotIn("docker/build-push-action", step.get("uses", ""))
        self.assertEqual(promotion["steps"][-1]["env"]["CANDIDATE_DIGEST"], "${{ needs.image-candidate.outputs.digest }}")
        self.assertEqual(promotion["steps"][-1]["run"], "python scripts/promote_image.py")


if __name__ == "__main__":
    unittest.main()
