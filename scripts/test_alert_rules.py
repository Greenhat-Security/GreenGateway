"""Rejection tests for the pinned alert tool and non-vacuous rule fixtures."""
import hashlib
import io
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import yaml

import alert_rules
import build_tools

ROOT = Path(__file__).resolve().parents[1]


class AlertRulesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        shutil.copyfile(ROOT / "build-tools.json", self.root / "build-tools.json")
        self.rules = {"groups": [{"name": "gateway", "rules": [
            {"alert": "Example", "expr": "vector(1)", "for": "1m"}]}]}
        self.fixtures = {"rule_files": [alert_rules.RULES.name], "tests": [
            {"input_series": [{"series": "example", "values": "1 1"}],
             "alert_rule_test": [
                 {"eval_time": "0m", "alertname": "Example", "exp_alerts": []},
                 {"eval_time": "1m", "alertname": "Example", "exp_alerts": [{"exp_labels": {}}]}]}]}
        self.inventory = {"groups": [{"name": "targets", "rules": [
            {"record": "greengateway_monitoring:target_expected", "expr": "vector(1)"}]}]}
        self.config = {"rule_files": [alert_rules.RULES.name, alert_rules.INVENTORY.name],
                       "scrape_configs": [{"job_name": "example", "static_configs": [
                           {"targets": ["127.0.0.1:8080"]}]}]}
        self.write_inputs()

    def write_inputs(self):
        directory = self.root / alert_rules.ALERTS
        directory.mkdir(parents=True, exist_ok=True)
        (self.root / alert_rules.RULES).write_text(yaml.safe_dump(self.rules))
        (self.root / alert_rules.TESTS).write_text(yaml.safe_dump(self.fixtures))
        (self.root / alert_rules.INVENTORY).write_text(yaml.safe_dump(self.inventory))
        (self.root / alert_rules.CONFIG).write_text(yaml.safe_dump(self.config))

    def process(self, command, **kwargs):
        self.assertEqual(kwargs["timeout"], 60)
        self.assertTrue(kwargs["capture_output"])
        output = "promtool, version " + build_tools.versions(self.root)["promtool"] + " (branch: HEAD)\n"
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    def test_check_runs_real_tool_commands_in_order_and_records_safe_summary(self):
        with patch("alert_rules.subprocess.run", side_effect=self.process) as run:
            alert_rules.check(self.root)
        commands = [call.args[0] for call in run.call_args_list]
        tool = str(alert_rules.executable(self.root))
        self.assertEqual(commands, [
            [tool, "--version"],
            [tool, "check", "rules", str(self.root / alert_rules.RULES), str(self.root / alert_rules.INVENTORY)],
            [tool, "check", "config", str(self.root / alert_rules.CONFIG)],
            [tool, "test", "rules", str(self.root / alert_rules.TESTS)]])
        report = json.loads((self.root / "target/alert-rules/decision.json").read_text())
        self.assertEqual(report["status"], "passed")
        self.assertEqual((report["alerts"], report["scenarios"], report["assertions"]), (1, 1, 2))
        self.assertNotIn("Example", json.dumps(report))

    def test_missing_empty_or_misdirected_inputs_fail_before_tool_execution(self):
        cases = [
            ({}, self.fixtures),
            ({"groups": []}, self.fixtures),
            ({"groups": [{"name": "empty", "rules": []}]}, self.fixtures),
            (self.rules, {}),
            (self.rules, {**self.fixtures, "tests": []}),
            (self.rules, {**self.fixtures, "rule_files": []}),
            (self.rules, {**self.fixtures, "rule_files": ["*.yml"]}),
            (self.rules, {**self.fixtures, "rule_files": ["../../other.yml"]}),
            (self.rules, {**self.fixtures, "tests": [{"input_series": [], "alert_rule_test": []}]}),
        ]
        for rules, fixtures in cases:
            with self.subTest(rules=rules, fixtures=fixtures):
                (self.root / alert_rules.RULES).write_text(yaml.safe_dump(rules))
                (self.root / alert_rules.TESTS).write_text(yaml.safe_dump(fixtures))
                with patch("alert_rules.subprocess.run") as run:
                    with self.assertRaises(ValueError):
                        alert_rules.check(self.root)
                    run.assert_not_called()
                report = json.loads((self.root / "target/alert-rules/decision.json").read_text())
                self.assertEqual(report["status"], "failed")
        (self.root / alert_rules.TESTS).unlink()
        with self.assertRaises(OSError):
            alert_rules.validate_inputs(self.root)

    def test_example_inventory_and_scrape_targets_cannot_be_empty(self):
        cases = [
            (alert_rules.INVENTORY, {}),
            (alert_rules.INVENTORY, {"groups": []}),
            (alert_rules.INVENTORY, {"groups": [{"name": "empty", "rules": []}]}),
            (alert_rules.CONFIG, {}),
            (alert_rules.CONFIG, {**self.config, "rule_files": []}),
            (alert_rules.CONFIG, {**self.config, "scrape_configs": []}),
            (alert_rules.CONFIG, {**self.config, "scrape_configs": [{"static_configs": [{"targets": []}]}]}),
        ]
        for path, value in cases:
            with self.subTest(path=path, value=value):
                self.write_inputs()
                (self.root / path).write_text(yaml.safe_dump(value))
                with self.assertRaises(ValueError):
                    alert_rules.validate_inputs(self.root)

    def test_new_alert_cannot_pass_without_firing_and_quiet_assertions(self):
        self.rules["groups"][0]["rules"].append({"alert": "Untested", "expr": "vector(1)"})
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "firing and non-firing"):
            alert_rules.validate_inputs(self.root)
        self.rules["groups"][0]["rules"].pop()
        assertions = self.fixtures["tests"][0]["alert_rule_test"]
        for keep in [0, 1]:
            self.fixtures["tests"][0]["alert_rule_test"] = assertions[keep:keep + 1]
            self.write_inputs()
            with self.assertRaises(ValueError):
                alert_rules.validate_inputs(self.root)

    def test_unknown_alert_or_implicit_expected_result_is_rejected(self):
        assertion = self.fixtures["tests"][0]["alert_rule_test"][0]
        assertion["alertname"] = "Unknown"
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "unknown alert"):
            alert_rules.validate_inputs(self.root)
        assertion["alertname"] = "Example"
        del assertion["exp_alerts"]
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "explicit exp_alerts"):
            alert_rules.validate_inputs(self.root)

    def test_absent_series_scenario_is_allowed_but_all_inputs_cannot_be_empty(self):
        self.fixtures["tests"].append({"input_series": [], "alert_rule_test": [
            {"eval_time": "1m", "alertname": "Example", "exp_alerts": []}]})
        self.write_inputs()
        self.assertEqual(alert_rules.validate_inputs(self.root)["scenarios"], 2)
        self.fixtures["tests"][0]["input_series"] = []
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "at least one input"):
            alert_rules.validate_inputs(self.root)

    def test_malformed_duplicate_and_oversized_rules_are_rejected(self):
        (self.root / alert_rules.RULES).write_text("groups: [\n")
        with self.assertRaises(yaml.YAMLError):
            alert_rules.validate_inputs(self.root)
        self.rules["groups"][0]["rules"] *= 2
        self.write_inputs()
        with self.assertRaisesRegex(ValueError, "distinct named"):
            alert_rules.validate_inputs(self.root)
        with patch("alert_rules.MAX_YAML_BYTES", 5):
            with self.assertRaisesRegex(ValueError, "size limit"):
                alert_rules.validate_inputs(self.root)

    def test_wrong_tool_version_fails_before_rule_execution(self):
        result = subprocess.CompletedProcess([], 0, stdout="promtool, version 0.0.0 (branch: test)\n", stderr="")
        with patch("alert_rules.subprocess.run", return_value=result) as run:
            with self.assertRaisesRegex(ValueError, "version differs"):
                alert_rules.check(self.root)
        self.assertEqual(run.call_count, 1)

    def test_rejected_rule_or_fixture_replaces_stale_success_with_failure(self):
        for fail_command, stage in [("rules", "syntax"), ("config", "configuration"), ("test", "tests")]:
            with self.subTest(stage=stage):
                directory = self.root / "target/alert-rules"
                directory.mkdir(parents=True, exist_ok=True)
                (directory / "decision.json").write_text('{"status":"passed"}')

                def process(command, **kwargs):
                    if command[1] == fail_command or (command[1] == "check" and command[2] == fail_command):
                        return subprocess.CompletedProcess(command, 1, stdout="", stderr="private fixture label")
                    return self.process(command, **kwargs)

                with patch("alert_rules.subprocess.run", side_effect=process):
                    with self.assertRaises(ValueError):
                        alert_rules.check(self.root)
                report_text = (directory / "decision.json").read_text()
                report = json.loads(report_text)
                self.assertEqual((report["status"], report["stage"]), ("failed", stage))
                self.assertNotIn("private fixture label", report_text)

    def test_subprocess_timeout_is_not_success(self):
        with patch("alert_rules.subprocess.run", side_effect=subprocess.TimeoutExpired("promtool", 60)):
            with self.assertRaises(subprocess.TimeoutExpired):
                alert_rules.check(self.root)
        self.assertEqual(json.loads((self.root / "target/alert-rules/decision.json").read_text())["status"], "failed")

    def archive(self, *, member_name=None, member_type=tarfile.REGTYPE, data=b"test binary"):
        name = member_name or "prometheus-" + build_tools.versions(self.root)["promtool"] + ".linux-amd64/promtool"
        result = io.BytesIO()
        with tarfile.open(fileobj=result, mode="w:gz") as archive:
            member = tarfile.TarInfo(name)
            member.type = member_type
            member.size = len(data) if member_type == tarfile.REGTYPE else 0
            if member_type == tarfile.SYMTYPE:
                member.linkname = "/outside"
            archive.addfile(member, io.BytesIO(data))
        payload = result.getvalue()
        pins = build_tools.versions(self.root)
        pins["promtool_linux_amd64_sha256"] = hashlib.sha256(payload).hexdigest()
        (self.root / "build-tools.json").write_text(json.dumps(pins))
        return payload

    def install_payload(self, payload):
        with patch("alert_rules.platform.system", return_value="Linux"), \
             patch("alert_rules.platform.machine", return_value="x86_64"), \
             patch("alert_rules.urllib.request.urlopen", return_value=io.BytesIO(payload)), \
             patch("alert_rules.subprocess.run", side_effect=self.process):
            alert_rules.install(self.root)

    def test_installer_extracts_only_the_pinned_regular_binary(self):
        self.install_payload(self.archive())
        target = alert_rules.executable(self.root)
        self.assertEqual(target.read_bytes(), b"test binary")
        self.assertEqual(target.stat().st_mode & 0o777, 0o755)
        self.assertFalse(target.with_suffix(".pending").exists())

    def test_checksum_mismatch_prevents_extraction_and_execution(self):
        with patch("alert_rules.tarfile.open") as unpack, patch("alert_rules.verify_tool") as run:
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                self.install_payload(b"substituted archive")
            unpack.assert_not_called()
            run.assert_not_called()
        self.assertFalse(alert_rules.executable(self.root).exists())

    def test_invalid_archive_member_is_never_installed(self):
        for options in [{"member_type": tarfile.SYMTYPE}, {"member_name": "../promtool"}, {"data": b""}]:
            with self.subTest(options=options):
                with self.assertRaises((ValueError, KeyError)):
                    self.install_payload(self.archive(**options))
                self.assertFalse(alert_rules.executable(self.root).exists())
        with patch("alert_rules.MAX_BINARY_BYTES", 1):
            with self.assertRaises(ValueError):
                self.install_payload(self.archive())

    def test_oversized_download_and_unsupported_platform_fail_closed(self):
        with patch("alert_rules.MAX_ARCHIVE_BYTES", 5):
            with self.assertRaisesRegex(ValueError, "download size limit"):
                self.install_payload(b"too big")
        with patch("alert_rules.platform.system", return_value="Darwin"), \
             patch("alert_rules.urllib.request.urlopen") as download:
            with self.assertRaisesRegex(ValueError, "Linux amd64 only"):
                alert_rules.install(self.root)
            download.assert_not_called()

    def test_version_rejection_does_not_replace_existing_installation(self):
        target = alert_rules.executable(self.root)
        target.parent.mkdir(parents=True)
        target.write_bytes(b"original")
        with patch("alert_rules.verify_tool", side_effect=ValueError("version mismatch")):
            with self.assertRaises(ValueError):
                self.install_payload(self.archive())
        self.assertEqual(target.read_bytes(), b"original")
        self.assertFalse(target.with_suffix(".pending").exists())


class AlertRepositoryContractTests(unittest.TestCase):
    """Keep deployment rules connected to runtime names, runbooks and CI."""

    def rules(self):
        document = yaml.safe_load((ROOT / alert_rules.RULES).read_text())
        return [rule for group in document["groups"] for rule in group["rules"]]

    def test_rule_metric_names_exist_in_the_runtime_registry(self):
        registry = "\n".join((ROOT / path).read_text() for path in [
            "gateway/src/metrics.rs", "gateway/src/audit/mod.rs"])
        declared = set(re.findall(r'^pub const \w+: &str\s*=\s*"([^"]+)";', registry, re.MULTILINE))
        self.assertTrue(declared, "runtime metric declarations must be discoverable")
        generated = {"up", "greengateway_monitoring:target_expected"}
        runtime_used = set()
        for rule in self.rules():
            with self.subTest(alert=rule["alert"]):
                # Every current selector is named and has scrape-label matchers.
                # Also catch bare gateway/audit names if an expression changes.
                expression = re.sub(r'"(?:\\.|[^"\\])*"', '""', rule["expr"])
                selectors = set(re.findall(r'([a-zA-Z_:][a-zA-Z0-9_:]*)\s*\{', expression))
                selectors.update(re.findall(r'\b(?:greengateway_|audit_events_)[a-zA-Z0-9_:]+', expression))
                self.assertTrue(selectors, "alert must select existing monitoring signals")
                runtime = selectors - generated
                self.assertEqual(runtime - declared, set(), "rule references an undeclared runtime metric")
                runtime_used.update(runtime)
        self.assertTrue(runtime_used, "the rule pack must exercise runtime metrics")

    def test_alerts_are_documented_and_runbook_anchors_exist(self):
        document = (ROOT / "docs/deployment/operational-alerts.md").read_text()
        headings = re.findall(r'^#{1,6}\s+(.+)$', document, re.MULTILINE)
        anchors = {re.sub(r'[^\w -]', '', heading.lower()).replace(' ', '-') for heading in headings}
        documented = set(re.findall(r'^\|\s*`(GreenGateway\w+)`\s*\|', document, re.MULTILINE))
        rules = self.rules()
        self.assertEqual(documented, {rule["alert"] for rule in rules})
        prefix = "https://github.com/Greenhat-Security/GreenGateway/blob/main/docs/deployment/operational-alerts.md#"
        for rule in rules:
            with self.subTest(alert=rule["alert"]):
                url = rule["annotations"]["runbook_url"]
                self.assertTrue(url.startswith(prefix), "runbook must point to the checked-in response guide")
                self.assertIn(url.removeprefix(prefix), anchors, "runbook heading was removed or renamed")

    def test_alert_validation_is_a_required_ci_and_promotion_gate(self):
        workflow = yaml.load((ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        jobs = workflow["jobs"]
        gate = jobs["operational-alerts"]
        self.assertNotIn("if", gate, "alert validation must run for every CI event")
        self.assertEqual(gate.get("continue-on-error", "false"), "false")
        setups = [step for step in gate["steps"] if step.get("uses") == "./.github/actions/build-tools"]
        self.assertEqual(len(setups), 1, "alert validation requires the shared pinned setup")
        self.assertNotIn("if", setups[0])
        required = [
            "python scripts/alert_rules.py install",
            "python -m unittest discover -s scripts -p test_alert_rules.py -v",
            "python scripts/alert_rules.py check",
        ]
        for command in required:
            with self.subTest(command=command):
                steps = [step for step in gate["steps"] if any(
                    shlex.split(line) == shlex.split(command) for line in step.get("run", "").splitlines())]
                self.assertEqual(len(steps), 1, "required validation command must execute directly")
                self.assertNotIn("if", steps[0], "required validation must not be conditional")
        for step in gate["steps"]:
            self.assertEqual(step.get("continue-on-error", "false"), "false")
        self.assertIn("operational-alerts", jobs["promote-image"]["needs"])


if __name__ == "__main__":
    unittest.main()
