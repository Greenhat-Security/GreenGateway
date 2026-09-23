"""Offline workflow policy and real-Git revision-resolution regressions."""

import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPARE = (
    'python scripts/microbench.py run --base "$BASE_SHA" --head "$HEAD_SHA" '
    '--output target/microbench'
)
FIXTURES = "python -m unittest discover -s scripts -p 'test_microbench*.py' -v"


def workflow():
    return yaml.load(
        (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_contract(ci):
    """Protect the comparison's trust boundary, evidence and promotion gate."""
    events = ci["on"]
    require(set(events) == {"push", "pull_request"}, "event boundary changed")
    require(not events["pull_request"], "pull requests must have no filters")
    require(events["push"] == {"branches": ["main"], "tags": ["v*.*.*"]},
            "main and release pushes must have no path filters")
    require(ci["permissions"] == {"contents": "read"}, "workflow permissions")
    job = ci["jobs"]["microbench"]
    require(job.get("permissions") == {"contents": "read"}, "fork permissions")
    require(job.get("runs-on") == "ubuntu-latest", "runner changed")
    require(job.get("timeout-minutes") == "10", "job runtime bound changed")
    require("if" not in job and "continue-on-error" not in job,
            "comparison cannot be skipped or ignored")
    steps = job["steps"]
    checkout = steps[0]
    require(checkout.get("uses", "").startswith("actions/checkout@"), "checkout first")
    require(checkout.get("with") == {
        "ref": "${{ github.sha }}", "fetch-depth": "0", "persist-credentials": "false",
    }, "checkout must use the event commit and preserve complete history")
    tools = next(step for step in steps if step.get("uses") == "./.github/actions/build-tools")
    require(tools.get("with") == {"rust": "ci", "node": "false"}, "pinned Rust profile")
    pins = json.loads((ROOT / "build-tools.json").read_text(encoding="utf-8"))
    require(any(step.get("run") == f"python -m pip install PyYAML=={pins['pyyaml']}"
                for step in steps), "pinned fixture parser")
    resolver = next(step for step in steps if step.get("id") == "revisions")
    require(resolver.get("env") == {
        "EVENT_NAME": "${{ github.event_name }}",
        "EVENT_HEAD_SHA": "${{ github.sha }}",
        "EVENT_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
        "EVENT_BEFORE_SHA": "${{ github.event.before }}",
        "EVENT_REF_TYPE": "${{ github.ref_type }}",
    }, "event input must be passed through environment variables")
    compare = next(step for step in steps if step.get("id") == "benchmark")
    require(compare.get("run") == COMPARE, "complete base/head comparison is mandatory")
    require(compare.get("env") == {
        "BASE_SHA": "${{ steps.revisions.outputs.base }}",
        "HEAD_SHA": "${{ steps.revisions.outputs.head }}",
    }, "comparison must consume resolved commits")
    fixture = next(step for step in steps if step.get("run") == FIXTURES)
    require(steps.index(resolver) < steps.index(fixture) < steps.index(compare),
            "revision resolution and rejection fixtures must precede comparison")
    formatter = next(step for step in steps if step.get("run") ==
                     "rustfmt --edition 2021 --check scripts/benchmarks/pure_paths.rs")
    require(steps.index(formatter) < steps.index(compare), "standalone harness formatting")
    uploads = [step for step in steps if step.get("uses", "").startswith("actions/upload-artifact@")]
    require(len(uploads) == 1, "one complete evidence upload required")
    upload = uploads[0]
    require(steps.index(upload) > steps.index(compare), "upload follows comparison")
    require(upload.get("if") == "always()", "failure evidence must be uploaded")
    require(upload.get("with") == {
        "name": "microbench-${{ github.sha }}", "path": "target/microbench/",
        "if-no-files-found": "error", "retention-days": "30",
    }, "complete evidence required")
    for step in steps:
        require("continue-on-error" not in step, "step failures cannot be ignored")
        require(step is upload or "if" not in step, "comparison steps cannot be skipped")
        require("${{" not in step.get("run", ""), "shell expression interpolation")
        if "uses" in step and not step["uses"].startswith("./"):
            require(bool(re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])), "immutable action pin")
    require("secrets." not in json.dumps(job), "fork job must not consume secrets")
    promotion = ci["jobs"]["promote-image"]
    require("microbench" in promotion["needs"], "promotion requires microbench")
    require(promotion["if"] == (
        "${{ github.event_name == 'push' && success() && !contains(needs.*.result, 'skipped') }}"
    ), "failed or skipped comparisons must prevent promotion")


class MicrobenchWorkflow(unittest.TestCase):
    def test_repository_workflow_enforces_contract(self):
        check_contract(workflow())

    def test_event_and_permission_bypasses_are_rejected(self):
        changes = [
            lambda ci: ci["on"].update(pull_request_target=None),
            lambda ci: ci["on"].update(pull_request={"paths": ["gateway/**"]}),
            lambda ci: ci["on"]["push"].update({"paths-ignore": ["docs/**"]}),
            lambda ci: ci["jobs"]["microbench"].update({"if": "github.event_name == 'push'"}),
            lambda ci: ci["jobs"]["microbench"].update({"continue-on-error": "true"}),
            lambda ci: ci["jobs"]["microbench"]["permissions"].update({"contents": "write"}),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                ci = copy.deepcopy(workflow())
                change(ci)
                with self.assertRaises(ValueError):
                    check_contract(ci)

    def test_checkout_and_comparison_bypasses_are_rejected(self):
        changes = [
            lambda steps: steps[0]["with"].update({"ref": "${{ github.event.pull_request.head.sha }}"}),
            lambda steps: steps[0]["with"].update({"fetch-depth": "1"}),
            lambda steps: steps[0]["with"].update({"persist-credentials": "true"}),
            lambda steps: next(s for s in steps if s.get("id") == "benchmark").update({"run": "true"}),
            lambda steps: next(s for s in steps if s.get("id") == "benchmark").update({"if": "success()"}),
            lambda steps: next(s for s in steps if s.get("id") == "benchmark").update({"continue-on-error": "true"}),
            lambda steps: next(s for s in steps if s.get("id") == "benchmark")["env"].update({"BASE_SHA": "main"}),
            lambda steps: next(s for s in steps if s.get("id") == "revisions").update({"run": "echo ${{ github.event.pull_request.title }}"}),
        ]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                ci = copy.deepcopy(workflow())
                change(ci["jobs"]["microbench"]["steps"])
                with self.assertRaises(ValueError):
                    check_contract(ci)

    def test_missing_failure_evidence_or_promotion_gate_is_rejected(self):
        for key, value in [("if", "success()"), ("path", "target/microbench/summary.json"),
                           ("if-no-files-found", "ignore")]:
            with self.subTest(key=key):
                ci = copy.deepcopy(workflow())
                upload = ci["jobs"]["microbench"]["steps"][-1]
                (upload if key == "if" else upload["with"])[key] = value
                with self.assertRaises(ValueError):
                    check_contract(ci)
        ci = copy.deepcopy(workflow())
        ci["jobs"]["promote-image"]["needs"].remove("microbench")
        with self.assertRaises(ValueError):
            check_contract(ci)


class ImmutableRevisionResolution(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name)
        self.git("init", "--quiet")
        self.git("config", "user.name", "Benchmark fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.commits = []
        for index in range(3):
            (self.repo / "fixture").write_text(str(index), encoding="utf-8")
            self.git("add", "fixture")
            self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", f"Fixture {index}")
            self.commits.append(self.git("rev-parse", "HEAD"))
        self.resolver = next(step for step in workflow()["jobs"]["microbench"]["steps"]
                             if step.get("id") == "revisions")["run"]

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.repo, text=True,
                                       stderr=subprocess.PIPE).strip()

    def resolve(self, event="pull_request", base=None, head=None,
                before=None, ref_type="branch"):
        env = dict(os.environ, EVENT_NAME=event,
                   EVENT_BASE_SHA=base if base is not None else self.commits[0],
                   EVENT_HEAD_SHA=head if head is not None else self.commits[-1],
                   EVENT_BEFORE_SHA=before if before is not None else self.commits[0],
                   EVENT_REF_TYPE=ref_type,
                   GITHUB_OUTPUT=str(self.repo / "outputs"))
        return subprocess.run(["bash", "-c", self.resolver], cwd=self.repo, env=env,
                              capture_output=True, text=True, timeout=10)

    def evidence(self):
        return json.loads((self.repo / "target/microbench/workflow.json").read_text(encoding="utf-8"))

    def test_fork_pull_request_uses_event_base_and_checked_out_merge(self):
        base = self.commits[-1]
        self.git("checkout", "--quiet", "-b", "fixture-feature", self.commits[0])
        (self.repo / "feature").write_text("fork fixture", encoding="utf-8")
        self.git("add", "feature")
        self.git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Fork fixture")
        self.git("checkout", "--quiet", base)
        self.git("-c", "commit.gpgsign=false", "merge", "--quiet", "--no-ff",
                 "-m", "Fixture PR merge", "fixture-feature")
        head = self.git("rev-parse", "HEAD")
        self.assertEqual(len(self.git("rev-list", "--parents", "-n", "1", head).split()), 3)
        result = self.resolve(base=base, head=head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.evidence(), {
            "schema_version": 1, "event_name": "pull_request",
            "base_sha": base, "head_sha": head,
            "head_kind": "pull_request_merge",
        })
        self.assertEqual((self.repo / "outputs").read_text(encoding="utf-8"),
                         f"base={base}\nhead={head}\n")

    def test_pull_request_base_is_not_substituted_with_first_parent(self):
        result = self.resolve(base=self.commits[0])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.evidence()["base_sha"], self.commits[0])
        self.assertNotEqual(self.evidence()["base_sha"], self.commits[-2])

    def test_multi_commit_branch_push_uses_previous_branch_tip(self):
        result = self.resolve(event="push")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.evidence()["base_sha"], self.commits[0])
        self.assertNotEqual(self.evidence()["base_sha"], self.commits[-2])
        self.assertEqual(self.evidence()["head_kind"], "push_branch")

    def test_release_tag_push_uses_first_parent(self):
        self.git("tag", "v0.0.0-fixture")
        self.git("checkout", "--quiet", "v0.0.0-fixture")
        result = self.resolve(event="push", base="", ref_type="tag", before="")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.evidence()["base_sha"], self.commits[-2])
        self.assertEqual(self.evidence()["head_kind"], "push_tag")

    def test_branch_push_with_invalid_before_or_ref_type_fails_closed(self):
        for arguments in [
            {"before": "0" * 40}, {"before": self.commits[0][:12]},
            {"ref_type": "unknown"},
            {"before": self.commits[-1], "head": self.commits[0]},
        ]:
            with self.subTest(arguments=arguments):
                self.assertNotEqual(self.resolve(event="push", **arguments).returncode, 0)
                self.assertFalse((self.repo / "outputs").exists())

    def test_mismatched_checkout_and_unknown_events_fail_closed(self):
        for arguments in [{"head": self.commits[0]}, {"event": "pull_request_target"},
                          {"event": "workflow_dispatch"}]:
            with self.subTest(arguments=arguments):
                self.assertNotEqual(self.resolve(**arguments).returncode, 0)
                self.assertFalse((self.repo / "outputs").exists())

    def test_missing_short_or_injected_commit_is_rejected_without_execution(self):
        for value in [self.commits[0][:12], "f" * 40, "$(touch injected)", "--help"]:
            with self.subTest(value=value):
                self.assertNotEqual(self.resolve(base=value).returncode, 0)
                self.assertFalse((self.repo / "outputs").exists())
                self.assertFalse((self.repo / "injected").exists())

    def test_root_push_without_a_base_cannot_pass(self):
        self.git("checkout", "--quiet", self.commits[0])
        self.assertNotEqual(self.resolve(event="push", head=self.commits[0]).returncode, 0)
        self.assertFalse((self.repo / "outputs").exists())


if __name__ == "__main__":
    unittest.main()
