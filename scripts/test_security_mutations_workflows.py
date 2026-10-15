"""Offline contracts for the trusted, bounded mutation workflow."""

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
UPLOAD = "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
CONTROLLER = "python scripts/security_mutations.py --report target/security-mutations/report.json"
REGISTRY_CHECK = "python scripts/security_mutations.py --validate-registry"
WORKFLOW_CONTRACTS = "python scripts/test_security_mutations_workflows.py"


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        # BaseLoader preserves `on` and scalar strings rather than applying
        # YAML 1.1's boolean interpretation to GitHub Actions syntax.
        self.workflow = yaml.load(
            (ROOT / ".github/workflows/security-mutations.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        self.ci = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(set(self.workflow["jobs"]), {"security-mutations"})
        self.job = self.workflow["jobs"]["security-mutations"]
        self.steps = self.job["steps"]

    def test_only_scheduled_and_manual_runs_without_caller_inputs(self):
        self.assertEqual(set(self.workflow["on"]), {"schedule", "workflow_dispatch"})
        self.assertEqual(self.workflow["on"]["schedule"], [{"cron": "41 4 * * *"}])
        self.assertIn(self.workflow["on"]["workflow_dispatch"], ("", None))

    def test_upstream_default_branch_and_event_guards_are_all_required(self):
        self.assertEqual(
            " ".join(self.job["if"].split()),
            "github.repository == 'Greenhat-Security/GreenGateway' && "
            "github.ref == format('refs/heads/{0}', github.event.repository.default_branch) && "
            "(github.event_name == 'schedule' || github.event_name == 'workflow_dispatch')",
        )

    def test_read_only_token_and_no_extra_authority(self):
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertNotIn("permissions", self.job)
        self.assertNotIn("secrets", self.job)
        self.assertNotIn("environment", self.job)
        self.assertNotIn("services", self.job)
        self.assertNotIn("container", self.job)

    def test_checkout_uses_exact_event_revision_without_persisted_credentials(self):
        checkout = self.steps[0]
        self.assertEqual(checkout["uses"], CHECKOUT)
        self.assertEqual(checkout["with"], {
            "ref": "${{ github.sha }}", "persist-credentials": "false",
        })
        self.assertEqual(sum(step.get("uses") == CHECKOUT for step in self.steps), 1)

    def test_only_reviewed_immutable_actions_and_local_tool_setup(self):
        self.assertEqual(
            [step["uses"] for step in self.steps if "uses" in step],
            [CHECKOUT, "./.github/actions/build-tools", UPLOAD],
        )

    def test_toolchain_and_workflow_parser_are_pinned(self):
        setup = self.steps[1]
        self.assertEqual(setup["uses"], "./.github/actions/build-tools")
        self.assertEqual(setup["with"], {"rust": "ci", "node": "true"})
        self.assertEqual(self.steps[2]["run"], "python -m pip install PyYAML==6.0.3")

    def test_job_is_bounded_and_builds_are_serial(self):
        self.assertEqual(self.job["runs-on"], "ubuntu-latest")
        self.assertEqual(self.job["timeout-minutes"], "150")
        self.assertEqual(self.job["env"], {
            "CARGO_BUILD_JOBS": "1", "CARGO_TERM_COLOR": "never",
        })
        self.assertEqual(self.workflow["concurrency"], {
            "group": "security-mutations-${{ github.ref }}",
            "cancel-in-progress": "false",
        })

    def test_controller_and_trust_tests_precede_the_full_campaign(self):
        self.assertEqual(
            [step["run"] for step in self.steps if "run" in step],
            [
                "python -m pip install PyYAML==6.0.3",
                "python scripts/test_security_mutations.py",
                WORKFLOW_CONTRACTS,
                CONTROLLER,
            ],
        )
        # Calibration, registry-only checks and single-mutant reproductions
        # cannot replace the complete reviewed campaign in the scheduled job.
        self.assertNotIn("--calibrate", CONTROLLER)
        self.assertNotIn("--validate-registry", CONTROLLER)
        self.assertNotIn("--mutant", CONTROLLER)

    def test_failed_or_skipped_measurements_cannot_be_ignored(self):
        self.assertNotIn("continue-on-error", self.job)
        self.assertNotIn("strategy", self.job)
        for step in self.steps:
            with self.subTest(step=step["name"]):
                self.assertNotIn("continue-on-error", step)
                if step.get("uses") != UPLOAD:
                    self.assertNotIn("if", step)

    def test_upload_only_bounded_report_even_after_failure(self):
        upload = self.steps[-1]
        self.assertEqual(upload["uses"], UPLOAD)
        self.assertEqual(upload["if"], "${{ always() }}")
        self.assertEqual(upload["with"], {
            "name": "security-mutations",
            "path": "target/security-mutations/report.json",
            "if-no-files-found": "error",
            "retention-days": "14",
        })

    def test_scheduled_measurement_is_separate_from_required_pr_jobs(self):
        self.assertNotIn("security-mutations", self.ci["jobs"])
        self.assertNotIn("security-mutations", self.ci["jobs"]["promote-image"]["needs"])
        self.assertIn("security-coverage", self.ci["jobs"]["promote-image"]["needs"])

    def test_registry_drift_check_runs_in_an_existing_required_job(self):
        self.assertIn("pull_request", self.ci["on"])
        # Reusing a required job keeps the required-check and promotion lists unchanged.
        self.assertIn("supply-chain", self.ci["jobs"]["promote-image"]["needs"])
        job = self.ci["jobs"]["supply-chain"]
        for optional in ("if", "needs", "continue-on-error", "strategy"):
            self.assertNotIn(optional, job)
        steps = job["steps"]
        checks = [step for step in steps if step.get("run") in (WORKFLOW_CONTRACTS, REGISTRY_CHECK)]
        self.assertEqual([step["run"] for step in checks], [WORKFLOW_CONTRACTS, REGISTRY_CHECK])
        setup = [index for index, step in enumerate(steps) if step.get("uses") == "./.github/actions/build-tools"]
        parser = [index for index, step in enumerate(steps) if step.get("run") == "python -m pip install PyYAML==6.0.3"]
        self.assertEqual(len(setup), 1)
        self.assertEqual(len(parser), 1)
        for step in checks:
            with self.subTest(step=step["name"]):
                self.assertNotIn("if", step)
                self.assertNotIn("continue-on-error", step)
                self.assertLess(max(setup[0], parser[0]), steps.index(step))

    def test_pull_request_ci_never_builds_or_measures_mutants(self):
        commands = [step["run"] for job in self.ci["jobs"].values() for step in job.get("steps", [])
                    if "security_mutations" in step.get("run", "")]
        # The controller tests calibrate with rustc and the campaign compiles
        # every mutant; both stay in the scheduled security-mutations.yml.
        self.assertEqual(commands, [WORKFLOW_CONTRACTS, REGISTRY_CHECK])


if __name__ == "__main__":
    unittest.main()
