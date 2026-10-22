"""Offline regressions for the production qualification kit (scripts/qualification.py).

Nothing here needs a cluster: Kubernetes reads are faked, HTTP targets are
loopback servers in this process, and the shipped examples are checked as
files. The load-profile tests need Node; they skip without it locally and fail
without it in CI.
"""
import base64
import contextlib
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qualification as q  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "docs/deployment/qualification"
BASE = [ROOT / "deploy/kubernetes/greengateway.example.yaml", ROOT / "deploy/kubernetes/network-policy.example.yaml"]
MANAGEMENT = ROOT / "deploy/kubernetes-management"
PINNED = re.search(r"greengateway:[0-9a-f]{40}@(sha256:[0-9a-f]{64})", BASE[0].read_text(encoding="utf-8")).group(1)
OTHER = "sha256:" + "1" * 64
TOKEN = "qualification-test-caller"
NO_PROXY = {"NO_PROXY": "*", "no_proxy": "*", "HTTP_PROXY": "", "HTTPS_PROXY": "", "http_proxy": "",
            "https_proxy": "", "ALL_PROXY": "", "all_proxy": ""}


def quietly(function, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return function(*args, **kwargs)


def statuses(results):
    return {result["check"]: result["status"] for result in results}


def failed(results):
    return sorted(name for name, status in statuses(results).items() if status == "fail")


def objects(paths):
    found = q.manifest_objects([str(path) for path in paths])
    named = {}
    for item in found:
        named.setdefault(item["kind"], {})[item["metadata"]["name"]] = item
    return named


def check_objects(named, *, digest=PINNED, exposure="loopback"):
    return q.workload_checks(named["Deployment"]["greengateway"], named.get("Service", {}),
                             list(named.get("NetworkPolicy", {}).values()), named.get("ConfigMap", {}),
                             container_name="gateway", expected_digest=digest,
                             repository="ghcr.io/greenhat-security/greengateway", data_service="greengateway",
                             admin_exposure=exposure)


def management_objects():
    """The management overlay, merged the way its strategic merge patch merges."""
    named = objects(BASE + [MANAGEMENT / "access.yaml"])
    patch = q.manifest_objects([str(MANAGEMENT / "patch.yaml")])[0]
    patched = patch["spec"]["template"]["spec"]["containers"][0]
    container = named["Deployment"]["greengateway"]["spec"]["template"]["spec"]["containers"][0]
    for entry in patched["env"]:
        container["env"] = [e for e in container["env"] if e["name"] != entry["name"]] + [entry]
    container["ports"] += patched["ports"]
    return named


def fake_secret(kind):
    """Secret-shaped values built at test time; none appears literally in source."""
    random = secrets.token_urlsafe(24)
    if kind == "pem":
        return "-----BEGIN " + "EC PRIVATE KEY" + "-----\n" + random
    if kind == "jwt":
        part = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "x"}).encode()).decode().rstrip("=")
        return part + "." + part + "." + random
    if kind == "userinfo":
        return "https://" + "operator" + ":" + random + "@" + "gateway.example.test/path"
    if kind == "dsn":
        return "postgres" + "ql://" + "gateway.example.test/greengateway"
    if kind == "assignment":
        return "pass" + "word=" + random
    if kind == "bearer":
        return "Bear" + "er " + random
    if kind == "aws":
        return "AK" + "IA" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    if kind == "entropy":
        while True:
            candidate = secrets.token_urlsafe(32).replace("-", "a").replace("_", "b")
            if any(c.isupper() for c in candidate) and any(c.islower() for c in candidate) and any(
                    c.isdigit() for c in candidate) and q.shannon_entropy(candidate) >= 4.2:
                return candidate
    raise ValueError(kind)


class SecretScanTests(unittest.TestCase):
    def test_every_secret_shape_is_found_without_echoing_it(self):
        for kind in ("pem", "jwt", "userinfo", "dsn", "assignment", "bearer", "aws", "entropy"):
            with self.subTest(kind=kind):
                value = fake_secret(kind)
                findings = q.secret_findings({"notes": [{"detail": value}]})
                self.assertTrue(findings)
                self.assertEqual(findings[0][0], "$.notes[0].detail")
                self.assertNotIn(value, json.dumps(findings))

    def test_secret_naming_keys_are_refused(self):
        for key in ("api_key", "accessToken", "database_dsn", "client-secret", "Authorization", "private_key"):
            with self.subTest(key=key):
                self.assertTrue(q.secret_findings({key: ""}))
        for key in ("keyring_label", "monkey", "bucket_label", "image_index_digest", "run_id"):
            with self.subTest(key=key):
                self.assertFalse(q.secret_findings({key: "value"}))

    def test_identifiers_records_carry_are_not_mistaken_for_secrets(self):
        record = {
            "digest": PINNED, "image": f"ghcr.io/greenhat-security/greengateway:{'a' * 40}@{PINNED}",
            "uuid": "1b4e28ba-2fa1-11d2-883f-0016d3cca427", "run": q.new_run_id("ggq-db-failover"),
            "at": q.iso(q.utc_now()), "path": "artifacts/qualification/ggq-upgrade-20261021t101500z-ab12cd/x.json",
            "alert": "GreenGatewayMonitoringConfigurationInvalid", "target": "greengateway.svc.cluster.local:8080",
            "notice": json.loads((KIT / "evidence-template.json").read_text(encoding="utf-8"))["notice"],
        }
        self.assertEqual(q.secret_findings(record), [])

    def test_a_record_with_a_secret_is_not_written(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(q.InputError):
                q.write_record(Path(directory), "x.json", {"detail": fake_secret("bearer")})
            self.assertEqual(list(Path(directory).iterdir()), [])


class DeployTests(unittest.TestCase):
    def test_the_shipped_base_example_passes_with_its_pinned_digest(self):
        results = check_objects(objects(BASE))
        self.assertEqual(failed(results), [])
        self.assertEqual(statuses(results)["seccomp_profile_set"], "advisory")

    def test_the_management_overlay_passes_only_as_cluster_exposure(self):
        self.assertEqual(failed(check_objects(management_objects(), exposure="cluster")), [])
        self.assertEqual(statuses(check_objects(management_objects(), exposure="cluster"))[
            "management_ingress_restricted"], "pass")
        self.assertEqual(failed(check_objects(management_objects())), ["admin_listener_exposure_expected"])

    def test_identity_failures(self):
        self.assertEqual(failed(check_objects(objects(BASE), digest=OTHER)), ["image_digest_expected"])
        named = objects(BASE)
        container = named["Deployment"]["greengateway"]["spec"]["template"]["spec"]["containers"][0]
        container["image"] = container["image"].split("@")[0]
        self.assertEqual(failed(check_objects(named)), ["image_digest_expected", "image_pinned_by_digest"])

    def test_each_hardening_regression_fails_its_check(self):
        def container(named):
            return named["Deployment"]["greengateway"]["spec"]["template"]["spec"]["containers"][0]

        def pod(named):
            return named["Deployment"]["greengateway"]["spec"]["template"]["spec"]

        mutations = {
            "privilege_escalation_disabled": lambda n: container(n)["securityContext"].pop("allowPrivilegeEscalation"),
            "read_only_root_filesystem": lambda n: container(n)["securityContext"].update(
                readOnlyRootFilesystem=False),
            "runs_as_non_root": lambda n: container(n)["securityContext"].update(runAsUser=0),
            "capabilities_dropped": lambda n: container(n)["securityContext"]["capabilities"].update(add=["NET_RAW"]),
            "not_privileged": lambda n: container(n)["securityContext"].update(privileged=True),
            "service_account_token_not_mounted": lambda n: pod(n).pop("automountServiceAccountToken"),
            "host_namespaces_unused": lambda n: pod(n).update(hostNetwork=True),
            "no_host_path_volumes": lambda n: pod(n).update(volumes=[{"name": "h", "hostPath": {"path": "/"}}]),
            "readiness_probe": lambda n: container(n)["readinessProbe"]["httpGet"].update(path="/livez"),
        }
        for name, mutate in mutations.items():
            with self.subTest(check=name):
                named = objects(BASE)
                mutate(named)
                self.assertIn(name, failed(check_objects(named)))

    def test_the_admin_listener_must_be_provably_separate(self):
        named = objects(BASE)
        container = named["Deployment"]["greengateway"]["spec"]["template"]["spec"]["containers"][0]
        container["env"] = [e for e in container["env"] if e["name"] != "ADMIN_LISTEN_ADDR"]
        configmaps = named["ConfigMap"]
        # The envFrom Secret, which is never read, could set it: unknown, so refused.
        self.assertEqual(q.environment_value(container, "ADMIN_LISTEN_ADDR", configmaps)[0], "unknown")
        self.assertIn("admin_listener_separated", failed(check_objects(named)))
        # A ConfigMap value still loses to the Secret listed after it.
        configmaps["greengateway"]["data"]["ADMIN_LISTEN_ADDR"] = "127.0.0.1:9090"
        self.assertIn("admin_listener_separated", failed(check_objects(named)))
        container["envFrom"] = list(reversed(container["envFrom"]))
        self.assertEqual(q.environment_value(container, "ADMIN_LISTEN_ADDR", configmaps),
                         ("set", "127.0.0.1:9090"))
        self.assertEqual(failed(check_objects(named)), [])
        container["envFrom"] = [{"configMapRef": {"name": "greengateway"}}]
        configmaps["greengateway"]["data"].pop("ADMIN_LISTEN_ADDR")
        self.assertEqual(q.environment_value(container, "ADMIN_LISTEN_ADDR", configmaps), ("unset", None))
        container["env"].append({"name": "ADMIN_LISTEN_ADDR", "value": "127.0.0.1:9090"})
        self.assertEqual(q.environment_value(container, "ADMIN_LISTEN_ADDR", named["ConfigMap"]),
                         ("set", "127.0.0.1:9090"))
        self.assertEqual(q.listener_state("[::1]:9090"), ("loopback", 9090))
        self.assertEqual(q.listener_state("0.0.0.0:9090"), ("exposed", 9090))
        self.assertEqual(q.listener_state("localhost:9090")[0], "invalid")

    def test_service_and_policy_regressions(self):
        named = objects(BASE)
        named["Service"]["greengateway"]["spec"]["ports"].append({"name": "admin", "port": 9090,
                                                                  "targetPort": 9090})
        self.assertIn("data_service_excludes_admin_port", failed(check_objects(named)))
        named = objects(BASE)
        named["NetworkPolicy"]["allow-all"] = {"metadata": {"name": "allow-all"},
                                               "spec": {"podSelector": {}, "ingress": [{}]}}
        self.assertIn("network_policy_no_allow_all_rule", failed(check_objects(named)))
        named = objects(BASE)
        policy = named["NetworkPolicy"]["greengateway-boundary"]
        policy["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}],
                                         "ports": [{"protocol": "TCP", "port": 443}]})
        self.assertIn("network_policy_egress_destinations_named", failed(check_objects(named)))
        policy["spec"]["egress"][-1]["ports"] = [{"protocol": "UDP", "port": 53}]
        self.assertEqual(failed(check_objects(named)), [])
        named = objects(BASE)
        del named["NetworkPolicy"]
        self.assertEqual(failed(check_objects(named)), ["network_policy_egress", "network_policy_ingress"])

    def test_selectors(self):
        selector = {"matchLabels": {"tier": "edge"},
                    "matchExpressions": [{"key": "app", "operator": "In", "values": ["a", "b"]},
                                         {"key": "canary", "operator": "DoesNotExist"}]}
        self.assertTrue(q.selector_matches(selector, {"tier": "edge", "app": "b"}))
        self.assertFalse(q.selector_matches(selector, {"tier": "edge", "app": "b", "canary": "1"}))
        self.assertFalse(q.selector_matches(selector, {"tier": "edge", "app": "c"}))
        self.assertTrue(q.selector_matches({}, {"any": "thing"}))
        self.assertEqual(q.selector_argument(selector), "tier=edge,app in (a,b),!canary")
        with self.assertRaises(q.InputError):
            q.selector_argument({})

    def pods(self, count=2, digest=PINNED, image_id_prefix="ghcr.io/greenhat-security/greengateway@"):
        image = f"ghcr.io/greenhat-security/greengateway@{PINNED}"
        return [{"metadata": {"name": f"gw-{i}"}, "spec": {"containers": [{"name": "gateway", "image": image}]},
                 "status": {"conditions": [{"type": "Ready", "status": "True"}],
                            "containerStatuses": [{"name": "gateway", "imageID": image_id_prefix + digest,
                                                   "restartCount": 0}]}} for i in range(count)]

    def deployment(self, replicas=2):
        return {"metadata": {"generation": 3}, "spec": {"replicas": replicas},
                "status": {"observedGeneration": 3, "updatedReplicas": replicas, "readyReplicas": replicas,
                           "availableReplicas": replicas}}

    def rollout(self, pods, accepted=frozenset({PINNED}), deployment=None):
        return q.rollout_checks(deployment or self.deployment(), pods, container_name="gateway",
                                expected_digest=PINNED, accepted=set(accepted), min_replicas=2)

    def test_rollout_checks(self):
        self.assertEqual(failed(self.rollout(self.pods())), [])
        self.assertEqual(failed(self.rollout(self.pods(image_id_prefix="docker-pullable://ghcr.io/x@"))), [])
        mixed = self.pods()
        mixed[1]["status"]["containerStatuses"][0]["imageID"] = "sha256:" + "2" * 64
        self.assertEqual(failed(self.rollout(mixed)), ["pods_run_verified_digest"])
        self.assertEqual(failed(self.rollout(mixed, accepted={PINNED, "sha256:" + "2" * 64})), [])
        rewritten = self.pods()
        rewritten[0]["spec"]["containers"][0]["image"] = "mirror.example.test/greengateway:latest"
        self.assertEqual(failed(self.rollout(rewritten)), ["pod_specs_keep_digest"])
        stalled = self.deployment()
        stalled["status"]["readyReplicas"] = 1
        self.assertEqual(failed(self.rollout(self.pods(), deployment=stalled)), ["rollout_complete"])
        self.assertIn("replica_count", failed(self.rollout(self.pods(1), deployment=self.deployment(1))))

    def test_the_command_writes_a_record_offline(self):
        with tempfile.TemporaryDirectory() as directory:
            code = quietly(q.main, ["deploy", "--expected-digest", PINNED, "--output-dir", directory,
                                    *[arg for path in BASE for arg in ("--manifest", str(path))]])
            self.assertEqual(code, 0)
            record = json.loads((Path(directory) / "deploy.json").read_text(encoding="utf-8"))
            self.assertEqual((record["mode"], record["verdict"]), ("manifest", "passed"))
            code = quietly(q.main, ["deploy", "--expected-digest", PINNED, "--deployment", "absent",
                                    "--output-dir", directory, "--manifest", str(BASE[0])])
            self.assertEqual(code, 2)
            self.assertEqual(quietly(q.main, ["deploy", "--expected-digest", PINNED]), 2)


class FakeKubectl:
    def __init__(self, pods_sequence, apply_code=0):
        self.pods_sequence, self.apply_code, self.calls = list(pods_sequence), apply_code, []

    def run(self, args, namespace=None, stdin=None, check=True, quiet=False):
        self.calls.append((args[0], namespace))
        return types.SimpleNamespace(returncode=self.apply_code if args[0] == "apply" else 0, stdout="", stderr="")

    def json(self, args, namespace=None, quiet=False):
        if len(self.pods_sequence) > 1:
            return {"items": self.pods_sequence.pop(0)}
        return {"items": self.pods_sequence[0]}


def terminated(code, reason="Error"):
    return [{"status": {"containerStatuses": [{"state": {"terminated": {"exitCode": code, "reason": reason}}}]}}]


class NetpolTests(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads((KIT / "netpol-cases.example.json").read_text(encoding="utf-8"))

    def test_the_example_plan_renders_safe_never_ready_probe_jobs(self):
        plan = q.load_cases(self.raw)
        jobs = [q.probe_job(plan, case, "ggq-test-run") for case in plan["cases"]]
        self.assertEqual(len({job["metadata"]["name"] for job in jobs}), len(jobs))
        for case, job in zip(plan["cases"], jobs):
            with self.subTest(case=case["name"]):
                self.assertRegex(job["metadata"]["name"], r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
                spec = job["spec"]["template"]["spec"]
                container = spec["containers"][0]
                self.assertEqual(container["readinessProbe"]["exec"]["command"], ["false"])
                self.assertIs(spec["automountServiceAccountToken"], False)
                self.assertIs(spec["securityContext"]["runAsNonRoot"], True)
                self.assertIs(container["securityContext"]["allowPrivilegeEscalation"], False)
                self.assertEqual(container["securityContext"]["capabilities"]["drop"], ["ALL"])
                self.assertEqual(spec["restartPolicy"], "Never")
                self.assertEqual(job["spec"]["backoffLimit"], 0)
                self.assertIsNotNone(q.image_digest(container["image"])[1])
                labels = job["spec"]["template"]["metadata"]["labels"]
                self.assertLessEqual(case["labels"].items(), labels.items())
                self.assertEqual(labels[q.RUN_LABEL], "ggq-test-run")
                self.assertIn(case["host"], container["command"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = q.main(["netpol", "--cases", str(KIT / "netpol-cases.example.json"), "--plan"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(output.getvalue())["items"]), len(plan["cases"]))

    def test_invalid_cases_are_refused(self):
        def mutated(change):
            raw = copy.deepcopy(self.raw)
            change(raw)
            return raw
        invalid = {
            "tag-only image": lambda r: r.update(probe_image="busybox:1.37.0"),
            "deny without attribution": lambda r: r["cases"][1].pop("control"),
            "deny with both": lambda r: r["cases"][1].update(unattributed_reason="x"),
            "control to another target": lambda r: r["cases"][6].update(control="ingress-from-controller"),
            "control that is a deny": lambda r: r["cases"][2].update(control="ingress-from-same-namespace"),
            "allow with control": lambda r: r["cases"][0].update(control="dns-from-gateway"),
            "no allow case": lambda r: r.update(cases=[c for c in r["cases"] if c["name"] == "egress-to-metadata"]),
            "unknown key": lambda r: r["cases"][0].update(expected="allow"),
            "reserved label": lambda r: r["cases"][0]["labels"].update({q.RUN_LABEL: "x"}),
            "host with scheme": lambda r: r["cases"][0].update(host="https://greengateway"),
            "bad port": lambda r: r["cases"][0].update(port=70000),
            "dns with port": lambda r: r["cases"][3].update(port=53),
            "duplicate name": lambda r: r["cases"].append(dict(r["cases"][0])),
            "command placeholder": lambda r: r.update(commands={"tcp": ["nc", "{target}"]}),
        }
        for name, change in invalid.items():
            with self.subTest(case=name):
                with self.assertRaises(q.InputError):
                    q.load_cases(mutated(change))

    def test_probe_outcomes(self):
        self.assertEqual(q.probe_outcome(terminated(0, "Completed"))[0], "connected")
        self.assertEqual(q.probe_outcome(terminated(1))[0], "blocked")
        for code, reason in ((127, "Error"), (137, "Error"), (1, "OOMKilled"), (2, "DeadlineExceeded")):
            with self.subTest(code=code, reason=reason):
                self.assertEqual(q.probe_outcome(terminated(code, reason))[0], "inconclusive")
        waiting = [{"status": {"containerStatuses": [{"state": {"waiting": {"reason": "ImagePullBackOff"}}}]}}]
        self.assertEqual(q.probe_outcome(waiting)[0], "inconclusive")
        running = [{"status": {"containerStatuses": [{"state": {"running": {}}}]}}]
        self.assertIsNone(q.probe_outcome(running)[0])

    def test_a_denial_counts_only_when_its_control_connected(self):
        plan = q.load_cases(self.raw)
        expected = {case["name"]: ("connected" if case["expect"] == "allow" else "blocked", "")
                    for case in plan["cases"]}
        results, unattributed, verdict = q.case_verdicts(plan, expected)
        self.assertEqual(verdict, "passed")
        self.assertEqual(unattributed, ["egress-to-metadata"])
        broken = dict(expected, **{"ingress-from-controller": ("blocked", "")})
        results, _, verdict = q.case_verdicts(plan, broken)
        by_name = {r["case"]: r["verdict"] for r in results}
        self.assertEqual(by_name["ingress-from-controller"], "fail")
        self.assertEqual(by_name["ingress-from-same-namespace"], "inconclusive")
        self.assertEqual(verdict, "failed")
        leaked = dict(expected, **{"egress-to-api-server": ("connected", "")})
        self.assertEqual(q.case_verdicts(plan, leaked)[2], "failed")
        unknown = dict(expected, **{"dns-from-gateway": ("inconclusive", "")})
        self.assertEqual(q.case_verdicts(plan, unknown)[2], "inconclusive")

    def test_run_probe_reads_the_pod_and_always_deletes_its_job(self):
        plan = q.load_cases(self.raw)
        case = plan["cases"][1]
        kubectl = FakeKubectl([[], [{"status": {"containerStatuses": [{"state": {"running": {}}}]}}],
                               terminated(1)])
        self.assertEqual(q.run_probe(kubectl, plan, case, "ggq-test", poll_seconds=0)[0], "blocked")
        self.assertEqual([call[0] for call in kubectl.calls], ["apply", "delete"])
        refused = FakeKubectl([[]], apply_code=1)
        self.assertEqual(quietly(q.run_probe, refused, plan, case, "ggq-test", poll_seconds=0)[0], "inconclusive")


class Target:
    """A loopback HTTP target: healthy until /__fault makes it answer 503 for a moment."""

    def __init__(self, healthy=True, down_seconds=1.0):
        self.healthy, self.down_seconds, self.down_until = healthy, down_seconds, 0.0
        self.faults, self.headers, self.alerts = 0, [], []
        target = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, status, body=b""):
                self.send_response(status)
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urllib.parse.urlsplit(self.path)
                if parsed.path == "/__fault":
                    target.faults += 1
                    target.down_until = time.monotonic() + target.down_seconds
                    return self.reply(200)
                target.record(parsed.path, self.headers)
                if parsed.path == "/api/v2/alerts":
                    matchers = [re.fullmatch(r'([^=]+)="(.*)"', value).groups()
                                for key, value in urllib.parse.parse_qsl(parsed.query) if key == "filter"]
                    found = [a for a in target.alerts if all(a["labels"].get(k) == v for k, v in matchers)]
                    return self.reply(200, json.dumps(found).encode())
                ok = target.healthy and time.monotonic() >= target.down_until
                self.reply(200 if ok else 503, b"ok")

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["content-length"])))
                target.record(urllib.parse.urlsplit(self.path).path, self.headers)
                for alert in body:
                    target.alerts.append(dict(alert, status={"state": "active"},
                                              receivers=[{"name": "platform-critical"}]))
                self.reply(200)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def record(self, path, headers):
        self.headers.append(dict({key.lower(): value for key, value in headers.items()}, path=path))

    def requests(self, path):
        return [headers for headers in self.headers if headers["path"] == path]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def ready_pods(_self, args, namespace=None, quiet=False):
    return {"items": [{"metadata": {"name": f"gw-{i}"},
                       "status": {"conditions": [{"type": "Ready", "status": "True"}],
                                  "containerStatuses": [{"name": "gateway", "imageID": f"x@{PINNED}",
                                                         "restartCount": 0}]}} for i in range(2)]}


def observation(fault=10.0, bad=(11.0, 14.0), end=40.0, step=1.0):
    traffic, cluster, t = [], [], 0.0
    while t <= end:
        ok = not (bad[0] <= t <= bad[1])
        traffic.append({"t": t, "ok": ok, "status": 200 if ok else 503})
        cluster.append({"t": t + 0.5, "pods": 2, "ready": 2 if ok else 1, "restarts": 0, "digests": [PINNED],
                        "error": None})
        t += step
    return traffic, cluster


class ObserveTests(unittest.TestCase):
    def test_recovery_needs_a_stable_window_after_the_last_bad_sample(self):
        traffic, cluster = observation()
        args = dict(fault_t=10.0, ready_t=10.0, replicas=2, accepted={PINNED}, stable=10.0, expect_disruption=True)
        self.assertIsNone(q.recovery(traffic, cluster, now_t=20.0, **args))
        result = q.recovery(traffic, cluster, now_t=30.0, **args)
        self.assertEqual(result, {"first_unhealthy_t": 11.0, "recovered_t": 15.5})
        healthy_traffic, healthy_cluster = observation(bad=(-2, -1))
        self.assertIsNone(q.recovery(healthy_traffic, healthy_cluster, now_t=40.0, **args))
        args["expect_disruption"] = False
        self.assertEqual(q.recovery(healthy_traffic, healthy_cluster, now_t=40.0, **args)["recovered_t"], 10.0)
        # An upgrade is not recovered until every pod runs the new digest.
        args["accepted"] = {OTHER}
        self.assertIsNone(q.recovery(healthy_traffic, healthy_cluster, now_t=40.0, **args))

    def test_denials_after_a_fault_fail_the_drill(self):
        traffic, cluster = observation()
        traffic[12]["status"] = 401
        reasons = []
        facts = q.fault_facts(traffic, cluster, 10.0, {"first_unhealthy_t": 11.0, "recovered_t": 15.5},
                              q.utc_now(), 2, {PINNED}, reasons)
        self.assertEqual(facts["denials_after_fault"], 1)
        self.assertEqual(len(reasons), 1)
        self.assertEqual(facts["longest_traffic_outage_seconds"], 4.0)

    def run_observe(self, target, directory, *extra, fault=True):
        command = ["observe", "--drill", "replica-loss", "--namespace", "greengateway", "--url",
                   target.url + "/api/probe", "--interval", "0.1", "--cluster-interval", "0.1",
                   "--baseline-seconds", "1", "--stable-seconds", "1", "--timeout-seconds", "20",
                   "--request-timeout", "2", "--output-dir", directory, *extra]
        if fault:
            command += ["--", sys.executable, "-c",
                        f"import urllib.request; urllib.request.urlopen('{target.url}/__fault').read()"]
        with mock.patch.dict(os.environ, dict(NO_PROXY, GREENGATEWAY_BEARER_TOKEN=TOKEN)), \
                mock.patch.object(q.Kubectl, "json", ready_pods):
            return quietly(q.main, command)

    def test_an_observed_fault_measures_detection_and_recovery(self):
        target = Target()
        try:
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(self.run_observe(target, directory, "--expect-disruption"), 0)
                text = (Path(directory) / "observe-replica-loss.json").read_text(encoding="utf-8")
                record = json.loads(text)
                self.assertNotIn(TOKEN, text)
                self.assertEqual(record["verdict"], "passed")
                self.assertEqual(record["fault_command_exit"], 0)
                self.assertGreaterEqual(record["rto_seconds"], 0.5)
                self.assertLess(record["rto_seconds"], 10)
                self.assertLess(record["detection_seconds"], 3)
                self.assertIn("503", record["phases"]["disruption"]["traffic"])
                self.assertEqual(set(record["phases"]["recovered"]["traffic"]), {"200"})
                sql = (Path(directory) / "audit-markers.sql").read_text(encoding="utf-8")
                self.assertIn(f"LIKE '{record['run_id']}-%'", sql)
                probes = target.requests("/api/probe")
                ids = [h["x-request-id"] for h in probes]
                self.assertTrue(all(re.fullmatch(re.escape(record["run_id"]) + r"-\d{6}", i) for i in ids))
                self.assertEqual({h["authorization"] for h in probes}, {f"Bearer {TOKEN}"})
                self.assertEqual(len(record["markers"]), len(ids))
        finally:
            target.close()

    def test_an_unhealthy_baseline_aborts_before_the_fault(self):
        target = Target(healthy=False)
        try:
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(self.run_observe(target, directory), 1)
                record = json.loads((Path(directory) / "observe-replica-loss.json").read_text(encoding="utf-8"))
                self.assertEqual(record["verdict"], "aborted")
                self.assertIsNone(record["fault_at"])
                self.assertEqual(target.faults, 0)
        finally:
            target.close()

    def test_unsafe_targets_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            base = ["observe", "--drill", "x", "--namespace", "n", "--output-dir", directory, "--duration-seconds", "1"]
            cases = [
                (["--url", "http://gateway.internal/api"], {"GREENGATEWAY_BEARER_TOKEN": TOKEN}),
                (["--url", "https://" + "user" + "@gateway.example.test/api"], {"GREENGATEWAY_BEARER_TOKEN": TOKEN}),
                (["--url", "https://gateway.example.test/api", "--anonymous"], {"GREENGATEWAY_BEARER_TOKEN": TOKEN}),
                (["--url", "https://gateway.example.test/api"], {}),
                (["--url", "https://gateway.example.test/api", "--manual-fault"], {"GREENGATEWAY_BEARER_TOKEN": TOKEN}),
            ]
            for extra, environment in cases:
                with self.subTest(extra=extra):
                    with mock.patch.dict(os.environ, environment, clear=False):
                        if not environment:
                            os.environ.pop("GREENGATEWAY_BEARER_TOKEN", None)
                        self.assertEqual(quietly(q.main, base + extra), 2)


def marker(run_id, seq, at, ok=True):
    stamp = q.iso(at)
    return {"seq": seq, "sent_at": stamp, "acknowledged_at": stamp, "status": 200 if ok else 503,
            "error": None, "ok": ok}


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.start = q.parse_iso("2026-10-21T10:00:00.000Z", "start")
        self.run_id = "ggq-db-failover-20261021t100000z-abc123"
        markers = [marker(self.run_id, i, self.start + q.timedelta(seconds=i), ok=not 30 <= i < 40)
                   for i in range(1, 61)]
        self.observation = {"kind": "greengateway-qualification-observation", "run_id": self.run_id,
                            "drill": "db-failover", "fault_at": q.iso(self.start + q.timedelta(seconds=30)),
                            "recovered_at": q.iso(self.start + q.timedelta(seconds=40)), "resolution_seconds": 2,
                            "markers": markers}

    def lines(self, seqs):
        return [f"{self.run_id}-{seq:06d}" for seq in seqs]

    def test_lost_acknowledged_markers_set_the_recovery_point(self):
        result = q.reconcile(self.observation, self.lines(list(range(1, 27)) + list(range(40, 61))),
                             rpo_target=2)
        self.assertEqual(result["acknowledged_before_cutoff"], 29)
        self.assertEqual(result["missing_acknowledged"], 3)
        self.assertEqual(result["rpo_seconds"], 3.0)
        self.assertEqual(result["during_outage"], {"sent": 10, "recorded": 0, "missing": 10})
        self.assertEqual(result["after_recovery"]["missing"], 0)
        self.assertEqual(result["verdict"], "failed")
        clean = q.reconcile(self.observation, self.lines(range(1, 61)), rpo_target=0)
        self.assertEqual((clean["rpo_seconds"], clean["verdict"]), (0.0, "passed"))
        self.assertEqual(q.reconcile(self.observation, self.lines(range(1, 61)))["verdict"], "measured")

    def test_a_restore_past_its_target_is_reported(self):
        cutoff = self.start + q.timedelta(seconds=20, milliseconds=500)
        exact = q.reconcile(self.observation, self.lines(range(1, 21)), cutoff=cutoff, rpo_target=1)
        self.assertEqual((exact["restored_past_target"], exact["recovery_point_gap_seconds"]), (0, 0.5))
        self.assertEqual(exact["verdict"], "passed")
        past = q.reconcile(self.observation, self.lines(range(1, 25)), cutoff=cutoff, rpo_target=1)
        self.assertEqual((past["restored_past_target"], past["verdict"]), (4, "failed"))

    def test_foreign_or_unsent_markers_are_refused(self):
        for lines in (["ggq-other-run-000001"], [f"{self.run_id}-000999"], ["DROP TABLE"]):
            with self.subTest(lines=lines):
                with self.assertRaises(q.InputError):
                    q.reconcile(self.observation, lines)
        without_fault = dict(self.observation, fault_at=None)
        with self.assertRaises(q.InputError):
            q.reconcile(without_fault, self.lines([1]))


class AlertTests(unittest.TestCase):
    def run_alert(self, target, directory, *extra):
        with mock.patch.dict(os.environ, dict(NO_PROXY, ALERTMANAGER_BEARER_TOKEN=TOKEN)):
            return quietly(q.main, ["alert", "--alertmanager-url", target.url, "--output-dir", directory,
                                    "--poll", "0.1", "--timeout-seconds", "5", *extra])

    def test_a_synthetic_alert_must_route_to_the_expected_receiver(self):
        target = Target()
        try:
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(self.run_alert(target, directory, "--synthetic", "--expect-receiver",
                                                "platform-critical"), 0)
                text = (Path(directory) / "alert.json").read_text(encoding="utf-8")
                record = json.loads(text)
                self.assertNotIn(TOKEN, text)
                self.assertEqual(record["verdict"], "routed")
                self.assertEqual(record["alert"]["labels"]["alertname"], q.DRILL_ALERT)
                self.assertEqual(record["alert"]["receivers"], ["platform-critical"])
                self.assertIsNone(record["notified_at"])
                self.assertEqual({h["authorization"] for h in target.requests("/api/v2/alerts")},
                                 {f"Bearer {TOKEN}"})
                self.assertEqual(self.run_alert(target, directory, "--synthetic", "--expect-receiver",
                                                "security-page"), 1)
        finally:
            target.close()

    def test_a_rule_alert_is_awaited_after_the_fault(self):
        target = Target()
        try:
            with tempfile.TemporaryDirectory() as directory:
                self.assertEqual(self.run_alert(target, directory, "--expect", "GreenGatewayMetricsTargetDown",
                                                "--timeout-seconds", "0.5"), 1)
                target.alerts.append({"labels": {"alertname": "GreenGatewayMetricsTargetDown",
                                                 "instance": "gateway-2"}, "startsAt": q.iso(q.utc_now()),
                                      "status": {"state": "active"}, "receivers": [{"name": "platform-critical"}]})
                self.assertEqual(self.run_alert(target, directory, "--expect", "GreenGatewayMetricsTargetDown",
                                                "--match-label", "instance=gateway-2", "--", sys.executable, "-c",
                                                "pass"), 0)
                record = json.loads((Path(directory) / "alert.json").read_text(encoding="utf-8"))
                self.assertEqual((record["mode"], record["fault_command_exit"]), ("rule", 0))
                self.assertIn("rule_fired_after_seconds", record)
        finally:
            target.close()


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.template = json.loads((KIT / "evidence-template.json").read_text(encoding="utf-8"))

    def test_the_template_is_complete_and_claims_nothing(self):
        self.assertEqual(q.evidence_problems(self.template), [])
        self.assertEqual(set(self.template["drills"]), set(q.EVIDENCE_DRILLS))
        self.assertIs(self.template["sign_off"]["approved"], False)
        self.assertTrue(all(d["status"] == "not_run" for d in self.template["drills"].values()))
        self.assertEqual(quietly(q.main, ["evidence", str(KIT / "evidence-template.json")]), 0)

    def test_unsupported_claims_are_refused(self):
        document = copy.deepcopy(self.template)
        drill = document["drills"]["database_failover"]
        drill.update(status="passed", completed_at="2026-10-21T10:00:00Z", records=["observe-db-failover.json"])
        self.assertTrue(any("passed without" in p for p in q.evidence_problems(document)))
        drill["measured"] = {key: 1 for key in drill["measured"]}
        self.assertEqual(q.evidence_problems(document), [])
        drill["records"] = ["/etc/observe.json"]
        self.assertTrue(q.evidence_problems(document))
        drill["records"] = ["../observe.json"]
        self.assertTrue(q.evidence_problems(document))
        drill["records"] = ["observe-db-failover.json"]
        document["sign_off"]["approved"] = True
        problems = q.evidence_problems(document)
        self.assertTrue(any("not passed or waived" in p for p in problems))
        self.assertTrue(any("image_index_digest" in p for p in problems))
        document["drills"]["upgrade"]["status"] = "waived"
        self.assertTrue(any("waiver needs notes" in p for p in q.evidence_problems(document)))

    def test_listed_records_are_scanned_too(self):
        document = copy.deepcopy(self.template)
        drill = document["drills"]["network_policy"]
        drill.update(status="failed", completed_at="2026-10-21T10:00:00Z", records=["netpol.json"])
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "evidence.json"
            evidence.write_text(json.dumps(document), encoding="utf-8")
            self.assertEqual(quietly(q.main, ["evidence", str(evidence), "--records-dir", directory]), 1)
            (Path(directory) / "netpol.json").write_text(json.dumps({"verdict": "failed"}), encoding="utf-8")
            self.assertEqual(quietly(q.main, ["evidence", str(evidence), "--records-dir", directory]), 0)
            (Path(directory) / "netpol.json").write_text(json.dumps({"note": fake_secret("dsn")}), encoding="utf-8")
            self.assertEqual(quietly(q.main, ["evidence", str(evidence), "--records-dir", directory]), 1)


NODE = shutil.which("node")


@unittest.skipIf(NODE is None and not os.environ.get("CI"), "Node is not installed")
class LoadProfileTests(unittest.TestCase):
    def node(self, *args, environment=None):
        if NODE is None:
            self.fail("Node is required in CI")
        env = {k: v for k, v in os.environ.items() if not k.startswith("GREENGATEWAY_")}
        env.update(NO_PROXY, **(environment or {}))
        return subprocess.run([NODE, *args], cwd=ROOT, capture_output=True, text=True, timeout=120, env=env)

    def test_the_scripts_parse_and_the_example_profile_is_valid(self):
        for script in ("run-load-suite.mjs", "proxy-load.mjs"):
            self.assertEqual(self.node("--check", f"scripts/{script}").returncode, 0)
        result = self.node("scripts/run-load-suite.mjs", "--profile",
                           "docs/deployment/qualification/load-profile.example.json", "--validate-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no traffic sent", result.stdout)

    def test_invalid_profiles_and_targets_are_refused(self):
        example = json.loads((KIT / "load-profile.example.json").read_text(encoding="utf-8"))
        invalid = {
            "no slo anywhere": lambda p: p.update(scenarios=[
                {k: v for k, v in s.items() if k not in ("slo", "observe_only")} | {"observe_only": True}
                for s in p["scenarios"]]),
            "unknown key": lambda p: p.update(base_url="https://gateway.example.test"),
            "slo on observe_only": lambda p: p["scenarios"][2].update(slo={"p99_ms": 1, "max_error_rate": 0}),
            "fragment": lambda p: p.update(path="/a#b"),
            "no tail target": lambda p: p["scenarios"][0].update(slo={"max_error_rate": 0}),
            "both sizes": lambda p: p["scenarios"][0].update(requests=10),
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, change in invalid.items():
                with self.subTest(profile=name):
                    profile = copy.deepcopy(example)
                    change(profile)
                    path = Path(directory) / "profile.json"
                    path.write_text(json.dumps(profile), encoding="utf-8")
                    self.assertEqual(self.node("scripts/run-load-suite.mjs", "--profile", str(path),
                                               "--validate-only").returncode, 2)
            profile = str(KIT / "load-profile.example.json")
            refused = [
                {},
                {"GREENGATEWAY_BASE_URL": "https://gateway.example.test"},
                {"GREENGATEWAY_BASE_URL": "http://gateway.internal:8080", "GREENGATEWAY_BEARER_TOKEN": TOKEN},
                {"GREENGATEWAY_BASE_URL": "https://" + "u" + ":" + "p" + "@gateway.example.test", "GREENGATEWAY_BEARER_TOKEN": TOKEN},
            ]
            for environment in refused:
                with self.subTest(environment=sorted(environment)):
                    self.assertEqual(self.node("scripts/run-load-suite.mjs", "--profile", profile,
                                               environment=environment).returncode, 2)
        self.assertNotEqual(self.node("scripts/proxy-load.mjs", "--exact-path", "--scenario", "mixed").returncode, 0)

    def test_a_profile_run_judges_each_scenario_against_its_slo(self):
        target = Target()
        profile = {"schema_version": 1, "label": "loopback-check", "path": "/api/read?page=1",
                   "warmup": {"concurrency": 2, "requests": 5},
                   "scenarios": [
                       {"name": "met", "concurrency": 2, "requests": 40, "slo": {"p99_ms": 5000, "max_error_rate": 0}},
                       {"name": "missed", "concurrency": 2, "requests": 10,
                        "slo": {"p95_ms": 0.0001, "max_error_rate": 0}},
                       {"name": "ramp", "concurrency": 4, "requests": 20, "observe_only": True}]}
        try:
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "profile.json"
                path.write_text(json.dumps(profile), encoding="utf-8")
                result = self.node("scripts/run-load-suite.mjs", "--profile", str(path), "--output-dir",
                                   str(Path(directory) / "out"),
                                   environment={"GREENGATEWAY_BASE_URL": target.url,
                                                "GREENGATEWAY_BEARER_TOKEN": TOKEN})
                self.assertEqual(result.returncode, 1, result.stderr)
                text = (Path(directory) / "out/slo-summary.json").read_text(encoding="utf-8")
                summary = json.loads(text)
                self.assertNotIn(TOKEN, text)
                self.assertNotIn("127.0.0.1", text)
                self.assertEqual({s["name"]: s["verdict"] for s in summary["scenarios"]},
                                 {"met": "passed", "missed": "failed", "ramp": "observed"})
                self.assertEqual((summary["slo_scenarios_passed"], summary["slo_scenarios_total"]), (1, 2))
                self.assertEqual(summary["request"], {"path": "/api/read", "has_query": True, "method": "GET",
                                                      "body_bytes": 0, "expected_statuses": ["200"],
                                                      "timeout_ms": 5000})
                self.assertEqual(q.secret_findings(summary), [])
                self.assertEqual({h["authorization"] for h in target.requests("/api/read")},
                                 {f"Bearer {TOKEN}"})
        finally:
            target.close()


class WiringTests(unittest.TestCase):
    def test_a_required_job_runs_the_kit_checks_unconditionally(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8").replace("\r\n", "\n")
        job = re.search(r"\n  dev-traffic-smoke:\n(.*?)(?=\n  [a-z][a-z0-9-]*:\n|\Z)", workflow, re.DOTALL)
        self.assertIsNotNone(job)
        steps = re.split(r"\n      - ", job.group(1))
        names = [step.split("\n", 1)[0] for step in steps]
        index = names.index("name: Check the production qualification kit")
        step = steps[index]
        self.assertNotRegex(step, r"\n        (if|continue-on-error|working-directory):")
        self.assertIn("python -m unittest discover -s scripts -p test_qualification.py -v", step)
        self.assertIn("node scripts/run-load-suite.mjs --profile docs/deployment/qualification/"
                      "load-profile.example.json --validate-only", step)
        self.assertIn("python scripts/qualification.py evidence docs/deployment/qualification/"
                      "evidence-template.json", step)
        self.assertLess(index, names.index("name: Load the production image"))

    def test_the_procedure_names_files_that_exist(self):
        document = (ROOT / "docs/deployment/qualification.md").read_text(encoding="utf-8")
        for command in ("deploy", "netpol", "observe", "reconcile", "alert", "evidence"):
            self.assertIn(f"qualification.py {command}", document)
        referenced = set(re.findall(r"`((?:scripts|docs|deploy)/[A-Za-z0-9_./-]+)`", document))
        self.assertTrue(referenced)
        for path in referenced:
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).exists())
        self.assertIn("qualification.md", (ROOT / "deploy/kubernetes/README.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
