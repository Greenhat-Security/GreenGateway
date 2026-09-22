"""Install pinned promtool and validate the executable alert-rule examples."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import urllib.request

import yaml

from build_tools import versions, verify_download

ROOT = Path(__file__).resolve().parents[1]
ALERTS = Path("docs/deployment/alerts")
RULES = ALERTS / "greengateway.rules.yml"
TESTS = ALERTS / "greengateway.test.yml"
INVENTORY = ALERTS / "targets.example.rules.yml"
CONFIG = ALERTS / "prometheus.example.yml"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_BINARY_BYTES = 192 * 1024 * 1024
MAX_YAML_BYTES = 1024 * 1024


def executable(root=ROOT):
    return root / "target/build-tools/promtool"


def run(command, cwd):
    # Only a checksum-verified local executable is used; no PATH lookup or shell.
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError("promtool rejected the version, rules, or test fixtures")
    return result.stdout


def verify_tool(root=ROOT, tool=None):
    actual = run([str(tool or executable(root)), "--version"], root)
    match = re.match(r"^promtool, version ([^\s]+) \(", actual)
    if not match or match.group(1) != versions(root)["promtool"]:
        raise ValueError("promtool executable version differs from build-tools.json")


def install(root=ROOT):
    if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise ValueError("verified promtool installer supports Linux amd64 only")
    pins = versions(root)
    name = f"prometheus-{pins['promtool']}.linux-amd64"
    url = f"https://github.com/prometheus/prometheus/releases/download/v{pins['promtool']}/{name}.tar.gz"
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise ValueError("promtool archive exceeds the download size limit")
    verify_download(data, pins["promtool_linux_amd64_sha256"])
    # Never extract archive paths. Read just the expected regular file into a
    # fixed local destination, after verifying the entire release archive.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        member = archive.getmember(name + "/promtool")
        if not member.isfile() or not 0 < member.size <= MAX_BINARY_BYTES:
            raise ValueError("invalid promtool executable archive member")
        binary = archive.extractfile(member).read(MAX_BINARY_BYTES + 1)
        if len(binary) != member.size:
            raise ValueError("invalid promtool executable size")
    target = executable(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    pending = target.with_suffix(".pending")
    try:
        pending.write_bytes(binary)
        pending.chmod(0o755)
        verify_tool(root, pending)
        pending.replace(target)
    finally:
        pending.unlink(missing_ok=True)
    print("Installed pinned promtool " + pins["promtool"])


def load_yaml(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_YAML_BYTES + 1)
    if len(data) > MAX_YAML_BYTES:
        raise ValueError("alert-rule input exceeds the size limit")
    value = yaml.safe_load(data)
    if not isinstance(value, dict):
        raise ValueError("alert-rule input must be a nonempty YAML mapping")
    return value


def nonempty_list(value, label):
    if not isinstance(value, list) or not value:
        raise ValueError(label + " must be a nonempty list")
    return value


def validate_inputs(root=ROOT):
    rules = load_yaml(root / RULES)
    alerts = set()
    for group in nonempty_list(rules.get("groups"), "rule groups"):
        if not isinstance(group, dict) or not isinstance(group.get("name"), str) or not group["name"].strip():
            raise ValueError("every rule group needs a name")
        for rule in nonempty_list(group.get("rules"), "group rules"):
            name = rule.get("alert") if isinstance(rule, dict) else None
            if not isinstance(name, str) or not name.strip() or name in alerts:
                raise ValueError("rules must declare distinct named alerts")
            alerts.add(name)
    fixtures = load_yaml(root / TESTS)
    if fixtures.get("rule_files") != [RULES.name]:
        raise ValueError("fixtures must target exactly the reviewed alert-rule file")
    tests = nonempty_list(fixtures.get("tests"), "rule tests")
    positive, negative = set(), set()
    input_count = 0
    assertion_count = 0
    for test in tests:
        if not isinstance(test, dict) or not isinstance(test.get("input_series"), list):
            raise ValueError("every rule test needs an input_series list")
        input_count += len(test["input_series"])
        for assertion in nonempty_list(test.get("alert_rule_test"), "alert assertions"):
            if not isinstance(assertion, dict):
                raise ValueError("invalid alert assertion")
            name = assertion.get("alertname")
            if not isinstance(name, str) or name not in alerts:
                raise ValueError("alert assertion names an unknown alert")
            expected = assertion.get("exp_alerts")
            if not isinstance(expected, list):
                raise ValueError("every alert assertion needs an explicit exp_alerts list")
            (positive if expected else negative).add(name)
            assertion_count += 1
    if not input_count:
        raise ValueError("alert fixtures must exercise at least one input series")
    if positive != alerts or negative != alerts:
        raise ValueError("every alert needs both firing and non-firing assertions")
    inventory = load_yaml(root / INVENTORY)
    for group in nonempty_list(inventory.get("groups"), "inventory rule groups"):
        if not isinstance(group, dict):
            raise ValueError("invalid inventory rule group")
        for rule in nonempty_list(group.get("rules"), "inventory rules"):
            if not isinstance(rule, dict) or rule.get("record") != "greengateway_monitoring:target_expected":
                raise ValueError("inventory must record expected gateway targets")
    config = load_yaml(root / CONFIG)
    if config.get("rule_files") != [RULES.name, INVENTORY.name]:
        raise ValueError("example config must load the reviewed alerts and target inventory")
    for scrape in nonempty_list(config.get("scrape_configs"), "scrape configurations"):
        if not isinstance(scrape, dict):
            raise ValueError("invalid example scrape configuration")
        for static in nonempty_list(scrape.get("static_configs"), "static scrape configurations"):
            if not isinstance(static, dict):
                raise ValueError("invalid static scrape configuration")
            nonempty_list(static.get("targets"), "scrape targets")
    return {"alerts": len(alerts), "scenarios": len(tests), "assertions": assertion_count}


def check(root=ROOT):
    output = root / "target/alert-rules"
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": 1, "status": "failed", "stage": "inputs"}
    try:
        counts = validate_inputs(root)
        report.update(counts)
        report["stage"] = "tool"
        verify_tool(root)
        report["stage"] = "syntax"
        run([str(executable(root)), "check", "rules", str(root / RULES), str(root / INVENTORY)], root / ALERTS)
        report["stage"] = "configuration"
        run([str(executable(root)), "check", "config", str(root / CONFIG)], root / ALERTS)
        report["stage"] = "tests"
        run([str(executable(root)), "test", "rules", str(root / TESTS)], root / ALERTS)
        report.update(status="passed", stage="complete", tool_version=versions(root)["promtool"],
                      input_sha256={str(path): hashlib.sha256((root / path).read_bytes()).hexdigest()
                                    for path in [RULES, TESTS, INVENTORY, CONFIG, Path("build-tools.json")]})
        print(f"Alert rules passed: {counts['alerts']} alerts, {counts['scenarios']} scenarios, {counts['assertions']} assertions.")
    finally:
        # The bounded report contains counts, hashes and stage only: no series,
        # label values, raw subprocess output, or exception payloads.
        (output / "decision.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["install", "check"])
    args = parser.parse_args()
    try:
        if args.command == "install":
            install()
        else:
            check()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError,
            tarfile.TarError, yaml.YAMLError):
        print("Alert-rule validation failed; inspect the pinned tool and reviewed rule fixtures.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
