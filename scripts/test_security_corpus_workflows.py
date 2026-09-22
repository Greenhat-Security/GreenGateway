"""Offline contracts for mandatory regression and trusted corpus exploration."""

import json
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
REPORT = "target/security-corpus/report.json"
REGRESSION = f"python scripts/security_corpus.py --mode regression --report {REPORT}"
EXPLORATION = f"python scripts/security_corpus.py --mode exploration --report {REPORT}"


def read_workflow(name):
    # Preserve the `on` key and expressions instead of YAML 1.1 coercions.
    return yaml.load(
        (ROOT / ".github/workflows" / name).read_text(), Loader=yaml.BaseLoader
    )


class SecurityCorpusWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.ci = read_workflow("ci.yml")
        self.exploration = read_workflow("security-corpus.yml")
        self.regression_job = self.ci["jobs"]["security-corpus"]
        self.exploration_job = self.exploration["jobs"]["security-corpus-exploration"]
        self.jobs = (self.regression_job, self.exploration_job)

    def test_regression_is_mandatory_on_every_pull_request_main_push_and_tag(self):
        self.assertEqual(set(self.ci["on"]), {"push", "pull_request"})
        self.assertFalse(self.ci["on"]["pull_request"])
        self.assertEqual(self.ci["on"]["push"], {
            "branches": ["main"], "tags": ["v*.*.*"],
        })
        for optional in ("if", "needs", "continue-on-error", "strategy"):
            self.assertNotIn(optional, self.regression_job)

    def test_build_time_is_separate_from_runner_budget_on_linux(self):
        for job in self.jobs:
            with self.subTest(job=job["name"]):
                self.assertEqual(job["runs-on"], "ubuntu-latest")
                self.assertEqual(job["timeout-minutes"], "90")
                self.assertNotIn("continue-on-error", job)
                self.assertNotIn("services", job)
                self.assertNotIn("container", job)

    def test_runner_and_contract_tests_cannot_be_skipped_or_mask_failure(self):
        for job, command in zip(self.jobs, (REGRESSION, EXPLORATION)):
            with self.subTest(command=command):
                runs = [step for step in job["steps"] if "run" in step]
                commands = [step["run"] for step in runs]
                expected = [
                    "python scripts/test_security_corpus.py",
                    "python scripts/test_security_corpus_workflows.py",
                    command,
                ]
                self.assertEqual(commands[1:], expected)
                for step in runs:
                    self.assertNotIn("if", step)
                    self.assertNotIn("continue-on-error", step)
                    self.assertNotIn("${{", step["run"])

    def test_compiler_node_python_and_yaml_parser_use_repository_pins(self):
        pins = json.loads((ROOT / "build-tools.json").read_text())
        for job in self.jobs:
            with self.subTest(job=job["name"]):
                setup = [step for step in job["steps"]
                         if step.get("uses") == "./.github/actions/build-tools"]
                self.assertEqual(len(setup), 1)
                self.assertEqual(setup[0]["with"], {"rust": "ci", "node": "true"})
                self.assertNotIn("if", setup[0])
                runs = [step["run"] for step in job["steps"] if "run" in step]
                self.assertEqual(runs[0], f"python -m pip install PyYAML=={pins['pyyaml']}")
                self.assertTrue(any(step.get("uses", "").startswith("Swatinem/rust-cache@")
                                    for step in job["steps"]))

    def test_remote_actions_are_immutable_and_checkout_drops_credentials(self):
        for job in self.jobs:
            with self.subTest(job=job["name"]):
                checkout = job["steps"][0]
                self.assertTrue(checkout["uses"].startswith("actions/checkout@"))
                self.assertEqual(checkout["with"]["persist-credentials"], "false")
                for step in job["steps"]:
                    action = step.get("uses", "")
                    if action and not action.startswith("./"):
                        self.assertRegex(action, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
                    self.assertNotIn("continue-on-error", step)
        # The schedule and dispatch ref guard applies to this exact commit.
        self.assertEqual(self.exploration_job["steps"][0]["with"]["ref"], "${{ github.sha }}")
        # PR CI must retain checkout's merge-ref default.
        self.assertNotIn("ref", self.regression_job["steps"][0]["with"])

    def test_only_redacted_report_is_retained_even_on_failure(self):
        for job in self.jobs:
            with self.subTest(job=job["name"]):
                uploads = [step for step in job["steps"]
                           if step.get("uses", "").startswith("actions/upload-artifact@")]
                self.assertEqual(len(uploads), 1)
                upload = uploads[0]
                self.assertEqual(upload["if"], "${{ always() }}")
                self.assertEqual(upload["with"], {
                    "name": job["name"], "path": REPORT,
                    "if-no-files-found": "error", "retention-days": "14",
                })
                self.assertIs(job["steps"][-1], upload)

    def test_new_regression_gate_blocks_publication_until_success(self):
        jobs = self.ci["jobs"]
        promotion = jobs["promote-image"]
        self.assertIn("security-corpus", promotion["needs"])
        self.assertEqual(set(promotion["needs"]), set(jobs) - {"promote-image", "image-preview"})
        self.assertEqual(promotion["if"],
                         "${{ github.event_name == 'push' && success() && !contains(needs.*.result, 'skipped') }}")

    def test_existing_properties_still_run_in_the_full_required_suite(self):
        job = self.ci["jobs"]["test"]
        self.assertNotIn("if", job)
        tests = [step for step in job["steps"]
                 if step.get("run") == "cargo test --workspace --locked"]
        self.assertEqual(len(tests), 1)
        self.assertNotIn("if", tests[0])
        self.assertNotIn("continue-on-error", tests[0])

    def test_exploration_has_only_scheduled_or_input_free_manual_triggers(self):
        events = self.exploration["on"]
        self.assertEqual(set(events), {"schedule", "workflow_dispatch"})
        self.assertFalse(events["workflow_dispatch"])
        self.assertEqual(len(events["schedule"]), 1)
        self.assertRegex(events["schedule"][0]["cron"], r"^\d{1,2} \d{1,2} \* \* \*$")
        self.assertEqual(set(self.exploration["jobs"]), {"security-corpus-exploration"})

    def test_exploration_ref_guard_rejects_forks_tags_and_other_branches(self):
        expression = " ".join(self.exploration_job["if"].split())
        self.assertEqual(expression,
                         "${{ github.repository == 'Greenhat-Security/GreenGateway' && "
                         "github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && "
                         "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') }}")

    def test_corpus_workflows_never_receive_write_permissions_or_secrets(self):
        self.assertEqual(self.ci["permissions"], {"contents": "read"})
        self.assertEqual(self.regression_job["permissions"], {"contents": "read"})
        self.assertEqual(self.exploration["permissions"], {"contents": "read"})
        self.assertEqual(self.exploration_job.get("permissions", {"contents": "read"}),
                         {"contents": "read"})
        for job in self.jobs:
            serialized = json.dumps(job)
            self.assertNotIn("secrets.", serialized)
            self.assertNotIn("github.token", serialized)
            self.assertNotIn("pull_request_target", serialized)
            self.assertNotIn("workflow_run", serialized)
            self.assertNotIn("write", job.get("permissions", {}).values())


if __name__ == "__main__":
    unittest.main()
