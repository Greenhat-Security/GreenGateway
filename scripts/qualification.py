#!/usr/bin/env python3
"""Run the production qualification drills on any conformant Kubernetes cluster.

docs/deployment/qualification.md is the procedure; each subcommand is one of
its drills or checks:

  deploy     the running (or rendered) workload carries the verified image
             digest and the documented hardening, and its rollout is complete
  netpol     the CNI enforces the NetworkPolicy boundary: short-lived probe
             Jobs carrying chosen labels try each allowed and denied path
  observe    a drill observer: cluster health and audited traffic markers
             before, during and after an operator-supplied fault, failover,
             restore or upgrade command, with detection and recovery times
  reconcile  recovery-point and audit-continuity figures from an observation
             and the markers a recovered database actually holds
  alert      alert delivery: a synthetic Alertmanager alert, or a real rule
             firing after a fault
  evidence   an evidence record holds no secret-shaped value and claims no
             result without its measurements

Only `kubectl` and the Kubernetes API are assumed, so the same commands serve
EKS, GKE, AKS, k3s or any other conformant cluster. The tool reads cluster
state; it creates nothing except the probe Jobs `netpol` deletes again, and it
changes nothing except through the command an operator passes after `--`.
Records hold digests, check names, counts, timestamps and durations. Every
record is scanned for secret-shaped values before it is written and refused
if one is found; tokens are read from the environment, never from arguments.

Exit status: 0 passed, 1 failed or inconclusive, 2 invalid input or
environment (nothing was decided).
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from pool_sizing import InputError as ManifestInputError, load_documents

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = 1
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
RUN_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?")
DRILL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?")
DNS_LABEL = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?")
CASE_NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]{0,30}[a-z0-9])?")
LABEL_KEY = re.compile(r"(?:[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?/)?"
                       r"[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?")
LABEL_VALUE = re.compile(r"(?:[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?")
HOSTNAME = re.compile(r"[A-Za-z0-9](?:[-A-Za-z0-9]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[-A-Za-z0-9]{0,61}[A-Za-z0-9])?)*\.?")
# The published runtime image runs as this user (Dockerfile, check-runtime-image.py).
IMAGE_USER = 10001
PROBES = (("startupProbe", "startup_probe", "/startupz"),
          ("livenessProbe", "liveness_probe", "/livez"),
          ("readinessProbe", "readiness_probe", "/readyz"))
MANAGED_BY = ("app.kubernetes.io/managed-by", "greengateway-qualification")
RUN_LABEL = "greengateway-qualification-run"
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
MARKER_DIGITS = 6
# A container that never ran its command: the probe proves nothing either way.
STARTUP_FAILURES = {"ErrImagePull", "ImagePullBackOff", "InvalidImageName", "CreateContainerConfigError",
                    "CreateContainerError", "RunContainerError", "ContainerCannotRun", "StartError"}
EVIDENCE_KIND = "greengateway-production-qualification"
EVIDENCE_STATUSES = ("not_run", "passed", "failed", "waived")
EVIDENCE_DRILLS = {
    "deploy_verification": (),
    "network_policy": (),
    "load_slo": ("profile_sha256", "slo_scenarios_passed", "slo_scenarios_total"),
    "replica_loss": ("rto_seconds",),
    "database_failover": ("rto_seconds", "rto_target_seconds", "rpo_seconds", "rpo_target_seconds",
                          "audit_markers_missing_during_outage"),
    "backup_pitr": ("restore_duration_seconds", "rto_target_seconds", "recovery_point_gap_seconds",
                    "rpo_target_seconds", "restore_checks_passed"),
    "upgrade": ("from_image_digest", "to_image_digest", "schema_change", "procedure", "unavailable_seconds"),
    "alert_delivery": ("alert", "detection_seconds", "notification_seconds", "acknowledgement_seconds"),
    "audit_outage_decision": ("decision", "decided_by_role"),
}


class InputError(ValueError):
    """The input or environment cannot be used with certainty; nothing was decided."""


# ---------------------------------------------------------------------------
# Records never carry secrets.

SECRET_VALUES = (
    ("private key block", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY")),
    ("JWT-shaped token", re.compile(r"\bey[A-Za-z0-9_-]{8,}\.ey[A-Za-z0-9_-]{8,}")),
    ("URL with embedded user information", re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s/@]+@")),
    ("PostgreSQL connection string", re.compile(r"(?i)\bpostgres(?:ql)?://")),
    ("credential assignment", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|sslpassword)\s*[=:]\s*\S")),
    ("bearer credential", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("cloud or SaaS access key", re.compile(
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{20,}"
        r"|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}")),
)
TOKEN_LIKE = re.compile(r"[A-Za-z0-9+_=-]{32,}")
HEX_LIKE = re.compile(r"(?:sha256:)?[0-9a-f-]+")
SECRET_KEY_WORDS = {"password", "passwd", "secret", "secrets", "token", "tokens", "bearer", "authorization",
                    "cookie", "cookies", "credential", "credentials", "dsn", "apikey", "passphrase"}
SECRET_KEY_PAIRS = {("private", "key"), ("api", "key"), ("connection", "string"), ("client", "secret"),
                    ("access", "key")}


def shannon_entropy(text):
    counts = {}
    for character in text:
        counts[character] = counts.get(character, 0) + 1
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def high_entropy(text):
    for match in TOKEN_LIKE.finditer(text):
        candidate = match.group(0)
        if HEX_LIKE.fullmatch(candidate.lower()):
            continue
        classes = (any(c.islower() for c in candidate), any(c.isupper() for c in candidate),
                   any(c.isdigit() for c in candidate))
        if all(classes) and shannon_entropy(candidate) >= 4.2:
            return True
    return False


def secret_key(key):
    words = re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower())
    words = [word for word in words if word]
    return bool(SECRET_KEY_WORDS & set(words)) or any(pair in SECRET_KEY_PAIRS for pair in zip(words, words[1:]))


def secret_findings(value, path="$"):
    """(path, reason) for every secret-shaped key or value; the value itself is never echoed."""
    findings = []
    if isinstance(value, dict):
        for key, item in value.items():
            where = f"{path}.{key}"
            if not isinstance(key, str):
                findings.append((path, "non-string key"))
                continue
            if secret_key(key):
                findings.append((where, "key names a secret"))
            else:
                findings.extend(secret_findings(key, f"{where}<key>"))
            findings.extend(secret_findings(item, where))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(secret_findings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        for reason, pattern in SECRET_VALUES:
            if pattern.search(value):
                findings.append((path, reason))
        if high_entropy(value):
            findings.append((path, "high-entropy token-like string"))
    return findings


def refuse_secrets(value, source):
    findings = secret_findings(value)
    if findings:
        listed = "; ".join(f"{where}: {reason}" for where, reason in findings[:10])
        raise InputError(f"{source} holds secret-shaped content ({listed}); records keep identifiers only")


# ---------------------------------------------------------------------------
# Shared plumbing.


def utc_now():
    return datetime.now(timezone.utc)


def iso(moment):
    return moment.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_iso(text, what):
    if not isinstance(text, str):
        raise InputError(f"{what} must be an ISO 8601 timestamp")
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise InputError(f"{what} must be an ISO 8601 timestamp") from error
    if moment.tzinfo is None:
        raise InputError(f"{what} must name its UTC offset")
    return moment


def new_run_id(prefix):
    return f"{prefix}-{utc_now():%Y%m%dt%H%M%Sz}-{secrets.token_hex(3)}"


def run_id_argument(value):
    if not RUN_ID.fullmatch(value):
        raise argparse.ArgumentTypeError("a run ID is 1-48 lowercase letters, digits and inner hyphens")
    return value


def drill_argument(value):
    if not DRILL.fullmatch(value):
        raise argparse.ArgumentTypeError("a drill name is 1-40 lowercase letters, digits and inner hyphens")
    return value


def digest_argument(value):
    if not DIGEST.fullmatch(value):
        raise argparse.ArgumentTypeError("expected sha256:<64 lowercase hex>")
    return value


def positive_number(value):
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a positive number") from error
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("expected a positive number")
    return number


def non_negative_number(value):
    try:
        number = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a non-negative number") from error
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError("expected a non-negative number")
    return number


def output_directory(args, run_id):
    if args.output_dir:
        return Path(args.output_dir)
    return ROOT / "artifacts" / "qualification" / run_id


def write_record(directory, name, record):
    refuse_secrets(record, name)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(record, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    print(f"record: {path}")
    return path


def read_json(path, what):
    try:
        data = Path(path).read_bytes()
    except OSError as error:
        raise InputError(f"{what} cannot be read: {error.strerror}") from error
    if len(data) > MAX_INPUT_BYTES:
        raise InputError(f"{what} exceeds the {MAX_INPUT_BYTES}-byte input limit")
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InputError(f"{what} is not valid UTF-8 JSON") from error


def image_digest(reference):
    """(repository, digest) of an image reference; digest is None for a tag-only reference."""
    if not isinstance(reference, str) or not reference:
        return None, None
    name, separator, digest = reference.partition("@")
    last = name.rsplit("/", 1)[-1]
    repository = name[: len(name) - len(last)] + last.split(":", 1)[0]
    return repository, digest if separator and DIGEST.fullmatch(digest) else None


def runtime_digest(image_id):
    """The digest a container runtime reports in containerStatuses[].imageID, if any."""
    matches = DIGEST.findall(image_id or "")
    return matches[-1] if matches else None


def check(name, ok, detail, advisory=False):
    return {"check": name, "status": "pass" if ok else ("advisory" if advisory else "fail"), "detail": detail}


def selector_matches(selector, labels):
    """Kubernetes label-selector semantics; an empty selector selects everything."""
    if selector is None:
        return False
    for key, value in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != value:
            return False
    for expression in selector.get("matchExpressions") or []:
        key, operator, values = expression.get("key"), expression.get("operator"), expression.get("values") or []
        if operator == "In":
            if labels.get(key) not in values:
                return False
        elif operator == "NotIn":
            if key in labels and labels[key] in values:
                return False
        elif operator == "Exists":
            if key not in labels:
                return False
        elif operator == "DoesNotExist":
            if key in labels:
                return False
        else:
            raise InputError(f"label selector operator {operator!r} is not a Kubernetes operator")
    return True


def selector_argument(selector):
    """A Deployment's selector as `kubectl -l` syntax."""
    terms = [f"{key}={value}" for key, value in sorted((selector.get("matchLabels") or {}).items())]
    for expression in selector.get("matchExpressions") or []:
        key, operator, values = expression.get("key"), expression.get("operator"), expression.get("values") or []
        if operator == "In":
            terms.append(f"{key} in ({','.join(values)})")
        elif operator == "NotIn":
            terms.append(f"{key} notin ({','.join(values)})")
        elif operator == "Exists":
            terms.append(key)
        elif operator == "DoesNotExist":
            terms.append(f"!{key}")
        else:
            raise InputError(f"label selector operator {operator!r} is not a Kubernetes operator")
    if not terms:
        raise InputError("the Deployment's selector is empty")
    return ",".join(terms)


class Kubectl:
    """`kubectl` with an explicit context; its own messages reach the terminal, never a record."""

    def __init__(self, executable="kubectl", context=None, timeout=30):
        self.executable, self.context, self.timeout = executable, context, timeout

    def command(self, args, namespace=None):
        command = [self.executable]
        if self.context:
            command += ["--context", self.context]
        if namespace:
            command += ["--namespace", namespace]
        return command + [f"--request-timeout={self.timeout}s"] + list(args)

    def run(self, args, namespace=None, stdin=None, check=True, quiet=False):
        try:
            result = subprocess.run(self.command(args, namespace), input=stdin, capture_output=True, text=True,
                                    encoding="utf-8", timeout=self.timeout + 30)
        except FileNotFoundError as error:
            raise InputError(f"{self.executable} was not found; pass --kubectl PATH") from error
        except subprocess.TimeoutExpired as error:
            raise InputError(f"kubectl {args[0]} did not finish in time") from error
        if result.returncode and check:
            if not quiet:
                sys.stderr.write(result.stderr)
            raise InputError(f"kubectl {' '.join(args[:2])} failed with exit {result.returncode}")
        return result

    def json(self, args, namespace=None, quiet=False):
        output = self.run(list(args) + ["-o", "json"], namespace, quiet=quiet).stdout
        try:
            return json.loads(output)
        except json.JSONDecodeError as error:
            raise InputError(f"kubectl {' '.join(args[:2])} did not return JSON") from error

    def optional(self, args, namespace=None):
        """One object as JSON, or None when it is absent or unreadable."""
        result = self.run(list(args) + ["-o", "json"], namespace, check=False)
        if result.returncode:
            return None
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it could carry the Authorization header to another origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_opener(ca_file=None):
    context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    return urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=context))


def checked_url(value, what):
    parsed = urllib.parse.urlsplit(value or "")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise InputError(f"{what} must be an absolute http or https URL")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise InputError(f"{what} must not carry user information; supply credentials through the environment")
    if parsed.fragment:
        raise InputError(f"{what} must not carry a fragment")
    return parsed


def error_class(error):
    """A fixed category for a transport failure; its text never reaches a record."""
    reason = getattr(error, "reason", error)
    if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower():
        return "timeout"
    if isinstance(reason, ssl.SSLError):
        return "tls"
    if isinstance(reason, OSError):
        return "connection"
    return "error"


# ---------------------------------------------------------------------------
# deploy: image identity and hardening of the workload.


def environment_value(container, name, configmaps):
    """('set', value), ('unset', None) or ('unknown', why) for one container variable.

    Kubernetes applies envFrom sources in order and then env entries, the last
    definition winning. A Secret is never read, so a variable a Secret could set
    after the last readable definition is unknown rather than guessed.
    """
    state = ("unset", None)
    for source in container.get("envFrom") or []:
        prefix = source.get("prefix") or ""
        if not name.startswith(prefix):
            continue
        key = name[len(prefix):]
        if "configMapRef" in source:
            configmap = configmaps.get(source["configMapRef"].get("name"))
            if configmap is None:
                state = ("unknown", "an envFrom ConfigMap could not be read")
            elif key in (configmap.get("data") or {}):
                state = ("set", configmap["data"][key])
        elif "secretRef" in source:
            state = ("unknown", "an envFrom Secret may set it and Secrets are never read")
    for entry in container.get("env") or []:
        if entry.get("name") != name:
            continue
        if "value" in entry:
            state = ("set", entry["value"])
        elif "configMapKeyRef" in (entry.get("valueFrom") or {}):
            reference = entry["valueFrom"]["configMapKeyRef"]
            configmap = configmaps.get(reference.get("name"))
            data = (configmap or {}).get("data") or {}
            state = ("set", data[reference.get("key")]) if reference.get("key") in data else (
                "unknown", "its ConfigMap key could not be read")
        else:
            state = ("unknown", "it comes from a Secret or field reference")
    return state


def listener_state(value):
    """('loopback'|'exposed'|'invalid', port) for a socket address such as 127.0.0.1:9090."""
    host, separator, port = str(value or "").strip().rpartition(":")
    if not separator or not port.isdigit() or not 0 < int(port) < 65536:
        return "invalid", None
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return "invalid", int(port)
    return ("loopback" if address.is_loopback else "exposed"), int(port)


def referenced_configmaps(container):
    names = {source["configMapRef"].get("name") for source in container.get("envFrom") or []
             if "configMapRef" in source}
    names |= {entry["valueFrom"]["configMapKeyRef"].get("name") for entry in container.get("env") or []
              if "configMapKeyRef" in (entry.get("valueFrom") or {})}
    return sorted(name for name in names if name)


def policy_types(policy):
    spec = policy.get("spec") or {}
    if spec.get("policyTypes"):
        return set(spec["policyTypes"])
    return {"Ingress"} | ({"Egress"} if "egress" in spec else set())


def open_destination(peer_list):
    if not peer_list:
        return True
    for peer in peer_list:
        block = peer.get("ipBlock")
        if block and block.get("cidr") in ("0.0.0.0/0", "::/0") and not block.get("except"):
            return True
    return False


def rule_covers_port(rule, port, port_names):
    ports = rule.get("ports")
    if not ports:
        return True
    for entry in ports:
        value = entry.get("port")
        if value is None or value == port or (isinstance(value, str) and port_names.get(value) == port):
            return True
    return False


def policy_checks(policies, labels, admin_exposure, admin_port, port_names):
    selecting = [policy for policy in policies
                 if selector_matches((policy.get("spec") or {}).get("podSelector"), labels)]
    results = [
        check("network_policy_ingress", any("Ingress" in policy_types(p) for p in selecting),
              f"{sum('Ingress' in policy_types(p) for p in selecting)} selecting policy(ies) restrict ingress"),
        check("network_policy_egress", any("Egress" in policy_types(p) for p in selecting),
              f"{sum('Egress' in policy_types(p) for p in selecting)} selecting policy(ies) restrict egress"),
    ]
    allow_all, open_egress, open_ingress = [], [], []
    for policy in selecting:
        name = (policy.get("metadata") or {}).get("name", "<unnamed>")
        spec = policy.get("spec") or {}
        for rule in spec.get("ingress") or []:
            if not rule.get("from"):
                (allow_all if not rule.get("ports") else open_ingress).append(name)
        for rule in spec.get("egress") or []:
            if open_destination(rule.get("to")):
                ports = rule.get("ports") or []
                if not ports:
                    allow_all.append(name)
                elif any(entry.get("port") != 53 for entry in ports):
                    open_egress.append(name)
    results.append(check("network_policy_no_allow_all_rule", not allow_all,
                         "no selecting policy allows every peer on every port" if not allow_all else
                         f"allow-all rule in {', '.join(sorted(set(allow_all)))}; policies are additive, so it "
                         "defeats the boundary"))
    results.append(check("network_policy_egress_destinations_named", not open_egress,
                         "every egress rule beyond DNS names its destinations" if not open_egress else
                         f"egress to any destination in {', '.join(sorted(set(open_egress)))}"))
    results.append(check("network_policy_ingress_sources_named", not open_ingress,
                         "every ingress rule names its sources" if not open_ingress else
                         f"ingress from any source in {', '.join(sorted(set(open_ingress)))}", advisory=True))
    if admin_exposure == "cluster" and admin_port is not None:
        covering = [(p, rule) for p in selecting for rule in (p.get("spec") or {}).get("ingress") or []
                    if rule_covers_port(rule, admin_port, port_names)]
        restricted = bool(covering) and all(rule.get("from") for _, rule in covering)
        results.append(check("management_ingress_restricted", restricted,
                             f"{len(covering)} ingress rule(s) reach the admin port, each from named peers"
                             if restricted else "the admin port is unreachable or reachable from any source"))
    return results


def workload_checks(deployment, services, policies, configmaps, *, container_name, expected_digest,
                    repository=None, data_service, admin_exposure):
    """Static checks of one Deployment; the same in manifest mode and against a live cluster."""
    template = ((deployment.get("spec") or {}).get("template") or {})
    spec = template.get("spec") or {}
    labels = (template.get("metadata") or {}).get("labels") or {}
    containers = [c for c in spec.get("containers") or [] if c.get("name") == container_name]
    if len(containers) != 1:
        return [check("gateway_container_present", False, f"no single container named {container_name!r}")]
    container = containers[0]
    found_repository, digest = image_digest(container.get("image"))
    results = [
        check("gateway_container_present", True, f"container {container_name!r}"),
        check("image_pinned_by_digest", digest is not None,
              "the image reference carries a sha256 digest" if digest else
              "the image reference has no digest; a tag can move"),
        check("image_digest_expected", digest == expected_digest,
              "the digest is the verified release" if digest == expected_digest else
              "the digest differs from the verified release"),
    ]
    if repository:
        results.append(check("image_repository_expected", found_repository == repository,
                             "the repository is the verified one" if found_repository == repository else
                             "the repository differs from the verified one"))
    pod_context = spec.get("securityContext") or {}
    context = container.get("securityContext") or {}
    non_root = context.get("runAsNonRoot", pod_context.get("runAsNonRoot"))
    user = context.get("runAsUser", pod_context.get("runAsUser"))
    capabilities = context.get("capabilities") or {}
    seccomp = (context.get("seccompProfile") or pod_context.get("seccompProfile") or {}).get("type")
    limits = (container.get("resources") or {}).get("limits") or {}
    selector = spec.get("nodeSelector") or {}
    results += [
        check("runs_as_non_root", non_root is True and user != 0, f"runAsNonRoot={non_root}, runAsUser={user}"),
        check("runs_as_image_user", user in (None, IMAGE_USER),
              f"runAsUser={user}; the image's user is {IMAGE_USER}", advisory=True),
        check("privilege_escalation_disabled", context.get("allowPrivilegeEscalation") is False,
              f"allowPrivilegeEscalation={context.get('allowPrivilegeEscalation')}"),
        check("not_privileged", context.get("privileged") is not True, f"privileged={context.get('privileged')}"),
        check("read_only_root_filesystem", context.get("readOnlyRootFilesystem") is True,
              f"readOnlyRootFilesystem={context.get('readOnlyRootFilesystem')}"),
        check("capabilities_dropped", "ALL" in (capabilities.get("drop") or []) and not capabilities.get("add"),
              f"drop={capabilities.get('drop') or []}, add={capabilities.get('add') or []}"),
        check("service_account_token_not_mounted", spec.get("automountServiceAccountToken") is False,
              f"automountServiceAccountToken={spec.get('automountServiceAccountToken')}"),
        check("host_namespaces_unused", not any(spec.get(k) for k in ("hostNetwork", "hostPID", "hostIPC")),
              "hostNetwork, hostPID and hostIPC are unset or false"),
        check("no_host_path_volumes", not any("hostPath" in v for v in spec.get("volumes") or []),
              f"{len(spec.get('volumes') or [])} volume(s), none hostPath"),
        check("seccomp_profile_set", seccomp in ("RuntimeDefault", "Localhost"), f"seccompProfile={seccomp}",
              advisory=True),
        check("resource_limits_set", "cpu" in limits and "memory" in limits,
              f"limits for {', '.join(sorted(limits)) or 'nothing'}", advisory=True),
        check("linux_amd64_node_selector", selector.get("kubernetes.io/os") == "linux"
              and selector.get("kubernetes.io/arch") == "amd64",
              "the published runtime platform is linux/amd64", advisory=True),
    ]
    for field, name, path in PROBES:
        probe_path = ((container.get(field) or {}).get("httpGet") or {}).get("path")
        results.append(check(name, probe_path == path, f"{field} httpGet {probe_path}, expected {path}"))
    state, value = environment_value(container, "ADMIN_LISTEN_ADDR", configmaps)
    admin_port = None
    if state == "set":
        listener, admin_port = listener_state(value)
    else:
        listener = state
    expected_listener = "loopback" if admin_exposure == "loopback" else "exposed"
    results.append(check("admin_listener_separated", listener in ("loopback", "exposed"), {
        "loopback": "admin routes listen on a loopback address, apart from the data listener",
        "exposed": "admin routes listen on their own non-loopback address",
        "invalid": "ADMIN_LISTEN_ADDR is not a socket address",
        "unset": "ADMIN_LISTEN_ADDR is unset, so admin routes share the data listener",
        "unknown": f"ADMIN_LISTEN_ADDR cannot be verified: {value}; set it in the pod spec or a ConfigMap",
    }[listener]))
    results.append(check("admin_listener_exposure_expected", listener == expected_listener,
                         f"admin listener is {listener}, expected {expected_listener}"))
    port_names = {p.get("name"): p.get("containerPort") for p in container.get("ports") or [] if p.get("name")}
    service = services.get(data_service)
    if service is None:
        results.append(check("data_service_present", False, f"no Service named {data_service!r}"))
    else:
        service_spec = service.get("spec") or {}
        exposes = admin_port is not None and any(
            port.get("port") == admin_port
            or port.get("targetPort") == admin_port
            or (isinstance(port.get("targetPort"), str) and port_names.get(port["targetPort"]) == admin_port)
            or port.get("targetPort") == "admin"
            for port in service_spec.get("ports") or [])
        results.append(check("data_service_present", True, f"Service {data_service!r}"))
        results.append(check("data_service_excludes_admin_port", admin_port is not None and not exposes,
                             "the data Service does not reach the admin listener" if admin_port and not exposes
                             else "the data Service reaches the admin port, or the admin port is unknown"))
        results.append(check("data_service_cluster_internal", service_spec.get("type") in (None, "ClusterIP"),
                             f"type={service_spec.get('type') or 'ClusterIP'}; expose it through the reviewed "
                             "ingress", advisory=True))
    results += policy_checks(policies, labels, admin_exposure, admin_port, port_names)
    return results


def rollout_checks(deployment, pods, *, container_name, expected_digest, accepted, min_replicas):
    """Runtime checks: the rollout completed and every live pod runs an accepted digest."""
    metadata, spec, status = (deployment.get(k) or {} for k in ("metadata", "spec", "status"))
    replicas = spec.get("replicas", 1)
    counts = {k: status.get(k, 0) for k in ("updatedReplicas", "readyReplicas", "availableReplicas")}
    complete = (status.get("observedGeneration", 0) >= metadata.get("generation", 0)
                and all(value == replicas for value in counts.values())
                and not status.get("unavailableReplicas"))
    live = [pod for pod in pods if not (pod.get("metadata") or {}).get("deletionTimestamp")]
    ready = runtime_ok = spec_ok = restarts = 0
    observed = set()
    for pod in live:
        conditions = {c.get("type"): c.get("status") for c in (pod.get("status") or {}).get("conditions") or []}
        ready += conditions.get("Ready") == "True"
        statuses = [s for s in (pod.get("status") or {}).get("containerStatuses") or []
                    if s.get("name") == container_name]
        digest = runtime_digest(statuses[0].get("imageID")) if statuses else None
        observed.add(digest or "unreported")
        runtime_ok += digest in accepted
        restarts += statuses[0].get("restartCount", 0) if statuses else 0
        containers = [c for c in (pod.get("spec") or {}).get("containers") or [] if c.get("name") == container_name]
        spec_ok += bool(containers) and image_digest(containers[0].get("image"))[1] == expected_digest
    return [
        check("rollout_complete", complete, f"replicas={replicas}, " + ", ".join(
            f"{key}={value}" for key, value in counts.items())),
        check("replica_count", replicas >= min_replicas, f"replicas={replicas}, required at least {min_replicas}"),
        check("pod_count_matches", len(live) == replicas, f"{len(live)} live pod(s) for {replicas} replica(s)"),
        check("pods_ready", bool(live) and ready == len(live), f"{ready}/{len(live)} pods Ready"),
        check("pods_run_verified_digest", bool(live) and runtime_ok == len(live),
              f"{runtime_ok}/{len(live)} pods report an accepted runtime digest; observed "
              f"{', '.join(sorted(observed)) or 'none'}"),
        check("pod_specs_keep_digest", bool(live) and spec_ok == len(live),
              f"{spec_ok}/{len(live)} pod specs keep the verified digest (no admission rewrite)"),
        check("no_container_restarts", restarts == 0, f"{restarts} restart(s) across live pods", advisory=True),
    ]


def summarise(results):
    counts = {status: sum(r["status"] == status for r in results) for status in ("pass", "fail", "advisory")}
    return counts, "passed" if counts["fail"] == 0 else "failed"


def yaml_typed(node):
    """YAML core-schema booleans and integers for the reader's plain-string scalars.

    pool_sizing's reader keeps every scalar as text. Kubernetes reads `true`
    and `10001` as a boolean and an integer, and the hardening checks compare
    types, so manifest mode applies the same resolution. JSON input is typed
    already and is left alone.
    """
    if isinstance(node, dict):
        return {key: yaml_typed(value) for key, value in node.items()}
    if isinstance(node, list):
        return [yaml_typed(value) for value in node]
    if isinstance(node, str):
        if node in ("true", "True", "TRUE"):
            return True
        if node in ("false", "False", "FALSE"):
            return False
        if re.fullmatch(r"[-+]?[0-9]+", node):
            return int(node)
    return node


def manifest_objects(paths):
    objects = []
    for path in paths:
        try:
            documents = load_documents(path, path)
            with open(path, "rb") as stream:
                json_input = stream.read(4096).decode("utf-8-sig", errors="replace").lstrip()[:1] in ("{", "[")
        except ManifestInputError as error:
            raise InputError(str(error)) from error
        except OSError as error:
            raise InputError(f"{path} cannot be read: {error.strerror}") from error
        if not json_input:
            documents = [yaml_typed(document) for document in documents]
        for document in documents:
            if isinstance(document, dict) and document.get("kind") == "List":
                objects += [item for item in document.get("items") or [] if isinstance(item, dict)]
            elif isinstance(document, dict):
                objects.append(document)
    return objects


def command_deploy(args):
    run_id = args.run_id or new_run_id("deploy")
    accepted = {args.expected_digest, *args.runtime_digest}
    if args.manifest:
        objects = manifest_objects(args.manifest)

        def named(kind):
            return {(o.get("metadata") or {}).get("name"): o for o in objects if o.get("kind") == kind}
        deployments = named("Deployment")
        if args.deployment not in deployments:
            raise InputError(f"the manifests hold no Deployment named {args.deployment!r}")
        deployment = deployments[args.deployment]
        results = workload_checks(deployment, named("Service"), list(named("NetworkPolicy").values()),
                                  named("ConfigMap"), container_name=args.container,
                                  expected_digest=args.expected_digest, repository=args.repository,
                                  data_service=args.service or args.deployment, admin_exposure=args.admin_exposure)
        mode = "manifest"
    else:
        if not args.namespace:
            raise InputError("name the namespace with --namespace (or check rendered files with --manifest)")
        kubectl = Kubectl(args.kubectl, args.context)
        deployment = kubectl.json(["get", "deployment", args.deployment], args.namespace)
        template = ((deployment.get("spec") or {}).get("template") or {}).get("spec") or {}
        containers = [c for c in template.get("containers") or [] if c.get("name") == args.container]
        # A ConfigMap or Service that cannot be read stays absent, and the
        # checks that need it fail rather than assume.
        configmaps = {name: found for name in (referenced_configmaps(containers[0]) if containers else [])
                      if (found := kubectl.optional(["get", "configmap", name], args.namespace)) is not None}
        service_name = args.service or args.deployment
        found = kubectl.optional(["get", "service", service_name], args.namespace)
        services = {} if found is None else {service_name: found}
        policies = kubectl.json(["get", "networkpolicies"], args.namespace).get("items") or []
        results = workload_checks(deployment, services, policies, configmaps, container_name=args.container,
                                  expected_digest=args.expected_digest, repository=args.repository,
                                  data_service=service_name, admin_exposure=args.admin_exposure)
        selector = selector_argument((deployment.get("spec") or {}).get("selector") or {})
        pods = kubectl.json(["get", "pods", "-l", selector], args.namespace).get("items") or []
        results += rollout_checks(deployment, pods, container_name=args.container,
                                  expected_digest=args.expected_digest, accepted=accepted,
                                  min_replicas=args.min_replicas)
        mode = "cluster"
    counts, verdict = summarise(results)
    record = {
        "schema_version": SCHEMA_VERSION, "kind": "greengateway-qualification-deploy", "run_id": run_id,
        "recorded_at": iso(utc_now()), "mode": mode,
        "target": {"namespace": args.namespace, "deployment": args.deployment, "container": args.container,
                   "data_service": args.service or args.deployment, "admin_exposure": args.admin_exposure},
        "expected": {"image_digest": args.expected_digest, "runtime_digests": sorted(args.runtime_digest),
                     "repository": args.repository},
        "checks": results, "summary": counts, "verdict": verdict,
    }
    for result in results:
        print(f"{result['status']:>8}  {result['check']}: {result['detail']}")
    write_record(output_directory(args, run_id), "deploy.json", record)
    print(f"deploy verification {verdict}: {counts['pass']} passed, {counts['fail']} failed, "
          f"{counts['advisory']} advisory")
    return 0 if verdict == "passed" else 1


# ---------------------------------------------------------------------------
# netpol: enforcement, proved with probe Jobs on both sides of each rule.

DEFAULT_COMMANDS = {"tcp": ["nc", "-z", "-w", "{timeout}", "{host}", "{port}"], "dns": ["nslookup", "{host}"]}
CASE_KEYS = {"name", "namespace", "labels", "kind", "host", "port", "expect", "purpose", "control",
             "unattributed_reason"}
CASES_KEYS = {"schema_version", "probe_image", "timeout_seconds", "node_selector", "commands", "cases"}


def text_field(value, what, limit=300):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise InputError(f"{what} must be non-empty text of at most {limit} characters")
    return value


def label_map(value, what):
    if not isinstance(value, dict):
        raise InputError(f"{what} must be an object of label keys and values")
    for key, item in value.items():
        if not LABEL_KEY.fullmatch(key) or not isinstance(item, str) or not LABEL_VALUE.fullmatch(item):
            raise InputError(f"{what} holds an invalid label {key!r}")
        if key == RUN_LABEL or key == MANAGED_BY[0]:
            raise InputError(f"{what} must not set {key}; the probe sets it")
    return dict(value)


def target_host(value, what):
    if not isinstance(value, str) or len(value) > 253:
        raise InputError(f"{what} must be a host name or IP address")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if HOSTNAME.fullmatch(value):
            return value
    raise InputError(f"{what} must be a bare host name or IP address, without scheme, port or path")


def load_cases(data):
    if not isinstance(data, dict) or set(data) - CASES_KEYS:
        raise InputError(f"the cases file allows only {', '.join(sorted(CASES_KEYS))}")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise InputError(f"the cases file must declare schema_version {SCHEMA_VERSION}")
    image = data.get("probe_image")
    if image_digest(image)[1] is None:
        raise InputError("probe_image must be pinned by digest (name@sha256:...)")
    timeout = data.get("timeout_seconds", 5)
    if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 60:
        raise InputError("timeout_seconds must be an integer from 1 to 60")
    node_selector = label_map(data.get("node_selector", {}), "node_selector")
    commands = dict(DEFAULT_COMMANDS)
    for kind, command in (data.get("commands") or {}).items():
        if kind not in DEFAULT_COMMANDS or not isinstance(command, list) or not command or not all(
                isinstance(part, str) and part for part in command):
            raise InputError("commands maps tcp and dns to non-empty argument lists")
        placeholders = set(re.findall(r"\{([a-z]+)\}", " ".join(command)))
        allowed = {"host", "port", "timeout"} if kind == "tcp" else {"host", "timeout"}
        if placeholders - allowed or "host" not in placeholders:
            raise InputError(f"the {kind} command uses only {', '.join(f'{{{p}}}' for p in sorted(allowed))}, "
                             "and needs {host}")
        commands[kind] = command
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise InputError("cases must be a non-empty list")
    cases, names = [], set()
    for index, raw in enumerate(raw_cases):
        where = f"cases[{index}]"
        if not isinstance(raw, dict) or set(raw) - CASE_KEYS:
            raise InputError(f"{where} allows only {', '.join(sorted(CASE_KEYS))}")
        name = raw.get("name")
        if not isinstance(name, str) or not CASE_NAME.fullmatch(name) or name in names:
            raise InputError(f"{where}.name must be a unique lowercase name of at most 32 characters")
        names.add(name)
        namespace = raw.get("namespace")
        if not isinstance(namespace, str) or not DNS_LABEL.fullmatch(namespace):
            raise InputError(f"{where}.namespace must be a namespace name")
        kind = raw.get("kind", "tcp")
        if kind not in DEFAULT_COMMANDS:
            raise InputError(f"{where}.kind must be tcp or dns")
        port = raw.get("port")
        if kind == "tcp" and (not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536):
            raise InputError(f"{where}.port must be a TCP port")
        if kind == "dns" and port is not None:
            raise InputError(f"{where}.port does not apply to a dns case")
        expect = raw.get("expect")
        if expect not in ("allow", "deny"):
            raise InputError(f"{where}.expect must be allow or deny")
        case = {"name": name, "namespace": namespace, "labels": label_map(raw.get("labels", {}), f"{where}.labels"),
                "kind": kind, "host": target_host(raw.get("host"), f"{where}.host"), "port": port,
                "expect": expect, "purpose": text_field(raw.get("purpose"), f"{where}.purpose")}
        attribution = [key for key in ("control", "unattributed_reason") if key in raw]
        if expect == "allow" and attribution:
            raise InputError(f"{where}: an allow case is its own evidence; control applies to deny cases")
        if expect == "deny":
            if len(attribution) != 1:
                raise InputError(f"{where}: a deny case names exactly one of control (an allow case to the same "
                                 "target) or unattributed_reason")
            if "control" in raw:
                case["control"] = raw["control"]
            else:
                case["unattributed_reason"] = text_field(raw["unattributed_reason"], f"{where}.unattributed_reason")
        cases.append(case)
    by_name = {case["name"]: case for case in cases}
    for case in cases:
        control = by_name.get(case.get("control")) if "control" in case else None
        if "control" in case and (control is None or control["expect"] != "allow" or (
                control["kind"], control["host"], control["port"]) != (case["kind"], case["host"], case["port"])):
            raise InputError(f"case {case['name']}: control must name an allow case for the same kind, host "
                             "and port")
    if not any(case["expect"] == "allow" for case in cases):
        raise InputError("at least one allow case is required; denials alone cannot tell enforcement from a "
                         "broken probe")
    return {"probe_image": image, "timeout_seconds": timeout, "node_selector": node_selector,
            "commands": commands, "cases": cases}


def probe_command(plan, case):
    values = {"host": case["host"], "port": str(case["port"]), "timeout": str(plan["timeout_seconds"])}
    return [re.sub(r"\{([a-z]+)\}", lambda m: values[m.group(1)], part) for part in plan["commands"][case["kind"]]]


def probe_job_name(run_id, case):
    suffix = hashlib.sha256(f"{run_id}/{case['name']}".encode()).hexdigest()[:8]
    return f"ggq-{case['name']}"[:54].rstrip("-") + f"-{suffix}"


def probe_job(plan, case, run_id):
    """A Job whose single pod carries the case's labels and is never Ready.

    The readiness probe never passes, so no Service routes traffic to a probe
    that borrows a workload's labels; the Job owns the pod, so no ReplicaSet
    adopts it. The pod runs as a non-root user with no service-account token.
    """
    marker = {MANAGED_BY[0]: MANAGED_BY[1], RUN_LABEL: run_id}
    pod_spec = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "terminationGracePeriodSeconds": 1,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": "probe",
            "image": plan["probe_image"],
            "imagePullPolicy": "IfNotPresent",
            "command": probe_command(plan, case),
            "readinessProbe": {"exec": {"command": ["false"]}, "periodSeconds": 5},
            "securityContext": {"allowPrivilegeEscalation": False, "privileged": False,
                                "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "resources": {"requests": {"cpu": "10m", "memory": "16Mi"},
                          "limits": {"cpu": "100m", "memory": "32Mi"}},
        }],
    }
    if plan["node_selector"]:
        pod_spec["nodeSelector"] = plan["node_selector"]
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": probe_job_name(run_id, case), "namespace": case["namespace"], "labels": marker},
        "spec": {
            "backoffLimit": 0,
            "activeDeadlineSeconds": plan["timeout_seconds"] + 120,
            "ttlSecondsAfterFinished": 600,
            "template": {"metadata": {"labels": {**case["labels"], **marker}}, "spec": pod_spec},
        },
    }


def probe_outcome(pods):
    """('connected'|'blocked'|'inconclusive'|None, detail); None while the probe is still running."""
    for pod in pods:
        for status in (pod.get("status") or {}).get("containerStatuses") or []:
            state = status.get("state") or {}
            waiting = (state.get("waiting") or {}).get("reason")
            if waiting in STARTUP_FAILURES:
                return "inconclusive", f"the probe container did not start ({waiting})"
            terminated = state.get("terminated")
            if terminated:
                code, reason = terminated.get("exitCode"), terminated.get("reason")
                if code == 0 and reason in (None, "Completed"):
                    return "connected", "the probe connected"
                # Only the probe's own failure exit is a denial. A signal, a
                # missing command or a runtime reason says the probe did not
                # finish its attempt, which proves nothing about the policy.
                if isinstance(code, int) and 0 < code < 126 and reason in (None, "Error"):
                    return "blocked", f"the probe could not connect (exit {code})"
                return "inconclusive", f"the probe did not complete its attempt (exit {code}, {reason})"
    return None, "the probe has not finished"


def run_probe(kubectl, plan, case, run_id, poll_seconds=1.0):
    manifest = probe_job(plan, case, run_id)
    name, namespace = manifest["metadata"]["name"], case["namespace"]
    applied = kubectl.run(["apply", "-f", "-"], namespace, stdin=json.dumps(manifest), check=False)
    if applied.returncode:
        sys.stderr.write(applied.stderr)
        return "inconclusive", "the probe Job was not admitted"
    try:
        # Past the Job's own deadline, so the Job controller has stopped it.
        deadline = time.monotonic() + plan["timeout_seconds"] + 150
        started = False
        while time.monotonic() < deadline:
            pods = kubectl.json(["get", "pods", "-l", f"job-name={name}"], namespace).get("items") or []
            if pods:
                started = True
                outcome, detail = probe_outcome(pods)
                if outcome:
                    return outcome, detail
            time.sleep(poll_seconds)
        return "inconclusive", ("the probe did not finish in time" if started else
                                "no probe pod started (admission, quota or scheduling)")
    finally:
        kubectl.run(["delete", "job", name, "--ignore-not-found", "--wait=true", "--cascade=foreground",
                     "--timeout=60s"], namespace, check=False)


def case_verdicts(plan, outcomes):
    """Per-case verdicts; a denial counts only when its control reached the same target."""
    results, by_name = [], {}
    for case in plan["cases"]:
        observed, detail = outcomes[case["name"]]
        if observed == "inconclusive":
            verdict = "inconclusive"
        elif (observed == "connected") == (case["expect"] == "allow"):
            verdict = "pass"
        else:
            verdict = "fail"
        by_name[case["name"]] = verdict
        results.append({"case": case["name"], "namespace": case["namespace"], "kind": case["kind"],
                        "target": case["host"] if case["port"] is None else f"{case['host']}:{case['port']}",
                        "expect": case["expect"], "observed": observed, "detail": detail, "verdict": verdict,
                        "purpose": case["purpose"]})
    unattributed = []
    for case, result in zip(plan["cases"], results):
        if case["expect"] != "deny":
            continue
        if "control" in case:
            result["control"] = case["control"]
            if result["verdict"] == "pass" and by_name[case["control"]] != "pass":
                result["verdict"] = "inconclusive"
                result["detail"] += "; its control did not reach the target, so the denial is not attributable"
        else:
            result["unattributed_reason"] = case["unattributed_reason"]
            unattributed.append(case["name"])
    passed = all(r["verdict"] == "pass" for r in results)
    return results, unattributed, "passed" if passed else (
        "failed" if any(r["verdict"] == "fail" for r in results) else "inconclusive")


def command_netpol(args):
    plan = load_cases(read_json(args.cases, "the cases file"))
    if args.case:
        unknown = set(args.case) - {case["name"] for case in plan["cases"]}
        if unknown:
            raise InputError(f"no case named {', '.join(sorted(unknown))}")
        keep = set(args.case) | {case["control"] for case in plan["cases"] if case["name"] in args.case
                                 and "control" in case}
        plan["cases"] = [case for case in plan["cases"] if case["name"] in keep]
    run_id = args.run_id or new_run_id("netpol")
    if args.plan:
        print(json.dumps({"kind": "List", "apiVersion": "v1",
                          "items": [probe_job(plan, case, run_id) for case in plan["cases"]]}, indent=2))
        return 0
    kubectl = Kubectl(args.kubectl, args.context)
    started = utc_now()
    outcomes = {}
    try:
        for case in plan["cases"]:
            outcomes[case["name"]] = run_probe(kubectl, plan, case, run_id)
            print(f"{case['name']}: expected {case['expect']}, observed {outcomes[case['name']][0]}")
    finally:
        for namespace in sorted({case["namespace"] for case in plan["cases"]}):
            kubectl.run(["delete", "jobs", "-l", f"{RUN_LABEL}={run_id}", "--ignore-not-found", "--wait=true",
                         "--timeout=60s"], namespace, check=False)
    results, unattributed, verdict = case_verdicts(plan, outcomes)
    record = {
        "schema_version": SCHEMA_VERSION, "kind": "greengateway-qualification-netpol", "run_id": run_id,
        "started_at": iso(started), "recorded_at": iso(utc_now()),
        "probe_image": plan["probe_image"], "timeout_seconds": plan["timeout_seconds"],
        "cases_sha256": hashlib.sha256(Path(args.cases).read_bytes()).hexdigest(),
        "results": results, "unattributed_denials": unattributed, "verdict": verdict,
    }
    write_record(output_directory(args, run_id), "netpol.json", record)
    print(f"network policy enforcement {verdict}; {len(unattributed)} denial(s) recorded without a control")
    return 0 if verdict == "passed" else 1


# ---------------------------------------------------------------------------
# observe: what a fault does to readiness and to audited traffic.


class Samples:
    def __init__(self):
        self.lock, self.items = threading.Lock(), []

    def add(self, item):
        with self.lock:
            self.items.append(item)

    def snapshot(self):
        with self.lock:
            return list(self.items)


class TrafficProbe(threading.Thread):
    """One audited request per interval, each carrying an `x-request-id` marker."""

    def __init__(self, *, url, token, method, success, interval, timeout, run_id, origin, opener, stop):
        super().__init__(daemon=True)
        self.url, self.token, self.method, self.success = url, token, method, success
        self.interval, self.timeout, self.run_id, self.origin = interval, timeout, run_id, origin
        self.opener, self.stop, self.samples = opener, stop, Samples()

    def probe(self, sequence):
        headers = {"user-agent": "greengateway-qualification/1",
                   "x-request-id": f"{self.run_id}-{sequence:0{MARKER_DIGITS}d}"}
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.url, method=self.method, headers=headers)
        sent, wall = time.monotonic(), utc_now()
        status, error = None, None
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                status = response.status
                response.read(MAX_RESPONSE_BYTES)
        except urllib.error.HTTPError as failure:
            status = failure.code
            failure.close()
        except (urllib.error.URLError, OSError, ValueError) as failure:
            error = error_class(failure)
        done = time.monotonic()
        return {"seq": sequence, "t": round(sent - self.origin, 3), "sent_at": iso(wall),
                "acknowledged_at": iso(wall + timedelta(seconds=done - sent)),
                "latency_ms": round((done - sent) * 1000, 1), "status": status, "error": error,
                "ok": status in self.success}

    def run(self):
        sequence, next_at = 0, time.monotonic()
        while not self.stop.is_set():
            sequence += 1
            self.samples.add(self.probe(sequence))
            next_at += self.interval
            self.stop.wait(max(0.0, next_at - time.monotonic()))


class ClusterProbe(threading.Thread):
    """Pod readiness, restarts and runtime digests of the selected workload."""

    def __init__(self, *, kubectl, namespace, selector, container, interval, origin, stop):
        super().__init__(daemon=True)
        self.kubectl, self.namespace, self.selector, self.container = kubectl, namespace, selector, container
        self.interval, self.origin, self.stop, self.samples = interval, origin, stop, Samples()

    def sample(self):
        at = time.monotonic()
        try:
            pods = self.kubectl.json(["get", "pods", "-l", self.selector], self.namespace, quiet=True)
        except InputError:
            return {"t": round(at - self.origin, 3), "at": iso(utc_now()), "error": "kubectl"}
        return dict(pod_summary(pods.get("items") or [], self.container), t=round(at - self.origin, 3),
                    at=iso(utc_now()), error=None)

    def run(self):
        next_at = time.monotonic()
        while not self.stop.is_set():
            self.samples.add(self.sample())
            next_at += self.interval
            self.stop.wait(max(0.0, next_at - time.monotonic()))


def pod_summary(pods, container):
    live = [pod for pod in pods if not (pod.get("metadata") or {}).get("deletionTimestamp")]
    ready, restarts, digests = 0, 0, []
    for pod in live:
        conditions = {c.get("type"): c.get("status") for c in (pod.get("status") or {}).get("conditions") or []}
        ready += conditions.get("Ready") == "True"
        for status in (pod.get("status") or {}).get("containerStatuses") or []:
            if status.get("name") == container:
                restarts += status.get("restartCount", 0)
                digests.append(runtime_digest(status.get("imageID")) or "unreported")
    return {"pods": len(live), "ready": ready, "restarts": restarts, "digests": sorted(set(digests))}


def cluster_healthy(sample, replicas, accepted):
    return (sample.get("error") is None and sample["pods"] == replicas and sample["ready"] == replicas
            and (not accepted or set(sample["digests"]) <= accepted))


def histogram(samples):
    counts = {}
    for sample in samples:
        key = str(sample["status"]) if sample["status"] is not None else f"error:{sample['error']}"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def longest_outage(traffic):
    longest, started = 0.0, None
    for sample in traffic:
        if not sample["ok"] and started is None:
            started = sample["t"]
        elif sample["ok"] and started is not None:
            longest, started = max(longest, sample["t"] - started), None
    if started is not None and traffic:
        longest = max(longest, traffic[-1]["t"] - started)
    return round(longest, 3)


def recovery(traffic, cluster, *, fault_t, ready_t, replicas, accepted, stable, expect_disruption, now_t):
    """Recovery facts after a fault, or None while recovery is not yet established.

    Recovered means: the fault command has returned, and for `stable` seconds
    after the last unhealthy sample every traffic and cluster sample was
    healthy, with at least three of each. The recovery moment is when both
    signals were first healthy again. A drill that expects a disruption is not
    recovered until one was observed.
    """
    after_traffic = [s for s in traffic if s["t"] >= fault_t]
    after_cluster = [s for s in cluster if s["t"] >= fault_t]
    unhealthy = sorted([s["t"] for s in after_traffic if not s["ok"]]
                       + [s["t"] for s in after_cluster if not cluster_healthy(s, replicas, accepted)])
    if expect_disruption and not unhealthy:
        return None
    last_bad = unhealthy[-1] if unhealthy else None
    window_start = ready_t if last_bad is None else max(ready_t, last_bad)

    def settled(samples):
        return [s for s in samples if s["t"] >= window_start and (last_bad is None or s["t"] > last_bad)]
    good_traffic, good_cluster = settled(after_traffic), settled(after_cluster)
    if now_t - window_start < stable or len(good_traffic) < 3 or len(good_cluster) < 3:
        return None
    if last_bad is None:
        recovered_t = fault_t
    else:
        recovered_t = max(next(s["t"] for s in after_traffic if s["t"] > last_bad),
                          next(s["t"] for s in after_cluster if s["t"] > last_bad))
    return {"first_unhealthy_t": unhealthy[0] if unhealthy else None, "recovered_t": recovered_t}


def run_fault_command(command):
    """Run the operator's command without a shell; only its exit status and duration are kept."""
    started = time.monotonic()
    try:
        code = subprocess.run(command, check=False).returncode
    except OSError:
        code = None
    return code, round(time.monotonic() - started, 3)


def plain_http_allowed(parsed, allow):
    if parsed.scheme == "https" or allow:
        return True
    try:
        return ipaddress.ip_address(parsed.hostname.strip("[]")).is_loopback
    except ValueError:
        return parsed.hostname == "localhost"


def baseline_healthy(traffic, cluster, replicas):
    # The baseline runs the current release, so its digest is not judged here.
    return bool(traffic and cluster and replicas) and all(s["ok"] for s in traffic) and all(
        s.get("error") is None and s["pods"] == replicas and s["ready"] == replicas for s in cluster)


def observation_mode(args):
    chosen = [mode for mode, given in (("command", bool(args.fault_command)), ("manual", args.manual_fault),
                                       ("duration", args.duration_seconds is not None)) if given]
    if len(chosen) != 1:
        raise InputError("give exactly one of a fault command after --, --manual-fault, or --duration-seconds "
                         "to observe without a fault")
    return chosen[0]


def command_observe(args):
    mode = observation_mode(args)
    if args.baseline_seconds == 0 and args.replicas is None:
        raise InputError("--baseline-seconds 0 skips the baseline, so name the expected --replicas")
    url = args.url or os.environ.get("GREENGATEWAY_PROBE_URL")
    parsed = checked_url(url, "the probe URL (--url or GREENGATEWAY_PROBE_URL)")
    token = os.environ.get("GREENGATEWAY_BEARER_TOKEN")
    if args.anonymous == bool(token):
        raise InputError("set GREENGATEWAY_BEARER_TOKEN for the audited probe route, or pass --anonymous "
                         "without it")
    if token and not plain_http_allowed(parsed, args.allow_plain_http):
        raise InputError("refusing to send a bearer token over plain HTTP to a non-loopback host; use https, "
                         "a port-forward, or --allow-plain-http inside a reviewed private network")
    run_id = args.run_id or new_run_id(f"ggq-{args.drill}"[:24].rstrip("-"))
    accepted = set(args.accept_digest) | ({args.expect_digest} if args.expect_digest else set())
    origin, stop, started = time.monotonic(), threading.Event(), utc_now()
    traffic = TrafficProbe(url=url, token=token, method=args.method, success=set(args.success_status),
                           interval=args.interval, timeout=args.request_timeout, run_id=run_id, origin=origin,
                           opener=http_opener(args.ca_file), stop=stop)
    cluster = ClusterProbe(kubectl=Kubectl(args.kubectl, args.context), namespace=args.namespace,
                           selector=args.selector, container=args.container, interval=args.cluster_interval,
                           origin=origin, stop=stop)
    record = {"schema_version": SCHEMA_VERSION, "kind": "greengateway-qualification-observation",
              "run_id": run_id, "drill": args.drill, "mode": mode, "started_at": iso(started),
              "fault_at": None, "fault_command_exit": None, "fault_command_seconds": None}
    replicas, reasons, fault_t, result, aborted = args.replicas, [], None, None, False
    traffic.start()
    cluster.start()
    try:
        stop.wait(args.baseline_seconds)
        if args.baseline_seconds:
            samples = cluster.samples.snapshot()
            if replicas is None:
                replicas = max((s["pods"] for s in samples if s.get("error") is None), default=0)
            if not baseline_healthy(traffic.samples.snapshot(), samples, replicas):
                aborted = True
                reasons.append("the baseline was not healthy, so no fault was injected")
        if not aborted and mode == "duration":
            stop.wait(args.duration_seconds)
        elif not aborted:
            if mode == "manual":
                print("inject the fault now, then press Enter", flush=True)
                sys.stdin.readline()
            fault_t = time.monotonic() - origin
            record["fault_at"] = iso(started + timedelta(seconds=fault_t))
            if mode == "command":
                record["fault_command_exit"], record["fault_command_seconds"] = run_fault_command(args.fault_command)
                if record["fault_command_exit"] != 0:
                    reasons.append("the fault command did not exit 0")
            ready_t = time.monotonic() - origin
            deadline = time.monotonic() + args.timeout_seconds
            while result is None and time.monotonic() < deadline:
                stop.wait(min(args.interval, args.cluster_interval))
                result = recovery(traffic.samples.snapshot(), cluster.samples.snapshot(), fault_t=fault_t,
                                  ready_t=ready_t, replicas=replicas, accepted=accepted,
                                  stable=args.stable_seconds, expect_disruption=args.expect_disruption,
                                  now_t=time.monotonic() - origin)
            if result is None:
                reasons.append("no disruption and recovery within --timeout-seconds" if args.expect_disruption
                               else "no recovery within --timeout-seconds")
    finally:
        stop.set()
        traffic.join(args.request_timeout + 5)
        cluster.join(60)
    traffic_samples, cluster_samples = traffic.samples.snapshot(), cluster.samples.snapshot()
    record.update({
        "recorded_at": iso(utc_now()),
        "parameters": {"namespace": args.namespace, "selector": args.selector, "container": args.container,
                       "probe_scheme": parsed.scheme, "probe_path": parsed.path or "/",
                       "probe_has_query": bool(parsed.query), "method": args.method,
                       "authenticated": not args.anonymous, "success_statuses": sorted(args.success_status),
                       "interval_seconds": args.interval, "cluster_interval_seconds": args.cluster_interval,
                       "baseline_seconds": args.baseline_seconds, "stable_seconds": args.stable_seconds,
                       "timeout_seconds": args.timeout_seconds, "expected_replicas": replicas,
                       "accepted_digests": sorted(accepted), "expect_disruption": args.expect_disruption},
        "resolution_seconds": max(args.interval, args.cluster_interval),
    })
    if fault_t is None:
        healthy = baseline_healthy(traffic_samples, cluster_samples, replicas) and all(
            cluster_healthy(s, replicas, accepted) for s in cluster_samples)
        if not aborted and not healthy:
            reasons.append("an unhealthy sample was observed")
        verdict = "aborted" if aborted else "observed" if healthy else "failed"
        record["phases"] = {"observed": {"traffic": histogram(traffic_samples)}}
    else:
        record.update(fault_facts(traffic_samples, cluster_samples, fault_t, result, started, replicas, accepted,
                                  reasons))
        verdict = "passed" if result and not reasons else "failed"
    record["markers"] = [{k: s[k] for k in ("seq", "sent_at", "acknowledged_at", "status", "error", "ok")}
                         for s in traffic_samples]
    record["verdict"], record["reasons"] = verdict, reasons
    directory = output_directory(args, run_id)
    write_record(directory, f"observe-{args.drill}.json", record)
    sql = directory / "audit-markers.sql"
    sql.write_text(audit_marker_sql(run_id), encoding="utf-8")
    print(f"audit marker query: {sql}")
    measured = {k: record.get(k) for k in ("detection_seconds", "rto_seconds", "longest_traffic_outage_seconds")}
    print(f"observation {verdict}: " + ", ".join(f"{k}={v}" for k, v in measured.items() if v is not None))
    for reason in reasons:
        print(f"  {reason}")
    return 0 if verdict in ("passed", "observed") else 1


def fault_facts(traffic, cluster, fault_t, result, started, replicas, accepted, reasons):
    """Detection, recovery and invariant facts of one injected fault; appends failed invariants to reasons."""
    before = [s for s in traffic if s["t"] < fault_t]
    after = [s for s in traffic if s["t"] >= fault_t]
    after_cluster = [s for s in cluster if s["t"] >= fault_t]
    recovered_t = result["recovered_t"] if result else None
    unhealthy = [s["t"] for s in after if not s["ok"]]
    unhealthy += [s["t"] for s in after_cluster if not cluster_healthy(s, replicas, accepted)]
    first_bad = min(unhealthy) if unhealthy else None
    denials = sum(s["status"] in (401, 403) for s in after)
    if denials > sum(s["status"] in (401, 403) for s in before):
        reasons.append("authentication or authorization denials appeared after the fault; a replica that "
                       "cannot check must answer 503, never deny")
    restarts = [s["restarts"] for s in cluster if s.get("error") is None]

    def at(offset):
        return None if offset is None else iso(started + timedelta(seconds=offset))
    return {
        "first_unhealthy_at": at(first_bad),
        "recovered_at": at(recovered_t),
        "detection_seconds": None if first_bad is None else round(first_bad - fault_t, 3),
        "rto_seconds": None if recovered_t is None else round(recovered_t - fault_t, 3),
        "longest_traffic_outage_seconds": longest_outage(after),
        "phases": {
            "baseline": {"traffic": histogram(before)},
            "disruption": {"traffic": histogram([s for s in after if recovered_t is None or s["t"] < recovered_t])},
            "recovered": {"traffic": histogram([s for s in after if recovered_t is not None
                                                and s["t"] >= recovered_t])},
        },
        "cluster": {
            "min_ready_after_fault": min((s["ready"] for s in after_cluster if s.get("error") is None),
                                         default=None),
            "api_errors_after_fault": sum(s.get("error") is not None for s in after_cluster),
            "restarts_during_drill": (max(restarts) - min(restarts)) if restarts else None,
            "digests_observed": sorted({d for s in cluster for d in s.get("digests", [])}),
        },
        "denials_after_fault": denials,
    }


def audit_marker_sql(run_id):
    if not RUN_ID.fullmatch(run_id):
        raise InputError("refusing to build a query from an invalid run ID")
    return (f"-- GreenGateway qualification markers of run {run_id}; prints request IDs only.\n"
            "-- Run with a read-only or the migration role against the database to examine,\n"
            "-- after the audit queue has drained, e.g. `psql -At -f audit-markers.sql > recorded.txt`.\n"
            "SELECT request_id FROM greengateway.audit_events\n"
            f"WHERE request_id LIKE '{run_id}-%'\n"
            "ORDER BY request_id;\n")


# ---------------------------------------------------------------------------
# reconcile: what survived, against what was acknowledged.


def reconcile(observation, recorded_lines, *, cutoff=None, rpo_target=None):
    run_id = observation.get("run_id")
    if observation.get("kind") != "greengateway-qualification-observation" or not RUN_ID.fullmatch(run_id or ""):
        raise InputError("the observation is not a qualification observation record")
    pattern = re.compile(re.escape(run_id) + r"-(\d{" + str(MARKER_DIGITS) + r"})")
    recorded = set()
    for number, line in enumerate(recorded_lines, start=1):
        line = line.strip()
        if not line:
            continue
        match = pattern.fullmatch(line)
        if not match:
            raise InputError(f"recorded line {number} is not a marker of run {run_id}")
        recorded.add(int(match.group(1)))
    markers = observation.get("markers") or []
    if not markers:
        raise InputError("the observation holds no traffic markers")
    explicit = cutoff is not None
    cutoff = cutoff or (parse_iso(observation["fault_at"], "fault_at") if observation.get("fault_at") else None)
    if cutoff is None:
        raise InputError("this observation injected no fault, so name the recovery target with --cutoff")
    known = {m["seq"] for m in markers}
    if recorded - known:
        raise InputError("the database holds markers this observation never sent")
    acknowledged = [m for m in markers if m["ok"] and parse_iso(m["acknowledged_at"], "a marker") < cutoff]
    missing = [m for m in acknowledged if m["seq"] not in recorded]
    durable = [m for m in acknowledged if m["seq"] in recorded]
    lost_window = 0.0
    if missing:
        lost_window = (cutoff - min(parse_iso(m["acknowledged_at"], "a marker") for m in missing)).total_seconds()
    gap = None
    if durable:
        gap = (cutoff - max(parse_iso(m["acknowledged_at"], "a marker") for m in durable)).total_seconds()
    after = [m for m in markers if parse_iso(m["sent_at"], "a marker") >= cutoff]
    recovered_at = observation.get("recovered_at")
    recovered = parse_iso(recovered_at, "recovered_at") if recovered_at else None
    outage = [m for m in after if recovered is None or parse_iso(m["sent_at"], "a marker") < recovered]
    settled = [m for m in after if recovered is not None and parse_iso(m["sent_at"], "a marker") >= recovered]
    result = {
        "schema_version": SCHEMA_VERSION, "kind": "greengateway-qualification-reconcile", "run_id": run_id,
        "drill": observation.get("drill"), "recorded_at": iso(utc_now()), "cutoff": iso(cutoff),
        "cutoff_source": "explicit recovery target" if explicit else "fault_at",
        "resolution_seconds": observation.get("resolution_seconds"),
        "acknowledged_before_cutoff": len(acknowledged), "recorded_of_those": len(durable),
        "missing_acknowledged": len(missing), "rpo_seconds": round(lost_window, 3),
        "recovery_point_gap_seconds": None if gap is None else round(gap, 3),
        "after_cutoff": {"sent": len(after), "recorded": sum(m["seq"] in recorded for m in after)},
        "during_outage": {"sent": len(outage), "recorded": sum(m["seq"] in recorded for m in outage),
                          "missing": sum(m["seq"] not in recorded for m in outage)},
        "after_recovery": {"sent": len(settled), "recorded": sum(m["seq"] in recorded for m in settled),
                           "missing": sum(m["seq"] not in recorded for m in settled)},
        "rpo_target_seconds": rpo_target,
    }
    if explicit:
        result["restored_past_target"] = result["after_cutoff"]["recorded"]
    if rpo_target is None:
        result["verdict"] = "measured"
    else:
        within = lost_window <= rpo_target and not result.get("restored_past_target")
        result["verdict"] = "passed" if within else "failed"
    return result


def command_reconcile(args):
    observation = read_json(args.observation, "the observation")
    try:
        lines = Path(args.recorded).read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise InputError("the recorded marker file cannot be read as UTF-8 text") from error
    cutoff = parse_iso(args.cutoff, "--cutoff") if args.cutoff else None
    result = reconcile(observation, lines, cutoff=cutoff, rpo_target=args.rpo_target_seconds)
    directory = Path(args.output_dir) if args.output_dir else Path(args.observation).resolve().parent
    write_record(directory, f"reconcile-{result['drill']}.json", result)
    print(f"reconcile {result['verdict']}: rpo_seconds={result['rpo_seconds']}, "
          f"missing_acknowledged={result['missing_acknowledged']}, "
          f"during_outage_missing={result['during_outage']['missing']}")
    return 0 if result["verdict"] in ("passed", "measured") else 1


# ---------------------------------------------------------------------------
# alert: delivery through the real Alertmanager.

DRILL_ALERT = "GreenGatewayQualificationDrill"
ALERT_NAME = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]{0,199}")
RECORDED_LABELS = ("alertname", "severity", "owner", "job", "instance", "deployment_mode", "qualification_run")


class Alertmanager:
    def __init__(self, url, token, opener, timeout=15):
        self.base = url.rstrip("/")
        self.token, self.opener, self.timeout = token, opener, timeout

    def request(self, method, path, body=None):
        headers = {"accept": "application/json", "user-agent": "greengateway-qualification/1"}
        if body is not None:
            headers["content-type"] = "application/json"
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                payload = response.read(MAX_INPUT_BYTES)
        except urllib.error.HTTPError as error:
            error.close()
            raise InputError(f"Alertmanager answered {method} {path.split('?')[0]} with HTTP {error.code}") from error
        except (urllib.error.URLError, OSError) as error:
            raise InputError(f"Alertmanager could not be reached ({error_class(error)})") from error
        try:
            return json.loads(payload) if payload.strip() else None
        except ValueError as error:
            raise InputError(f"Alertmanager returned no JSON for {method} {path.split('?')[0]}") from error

    def active(self, matchers):
        query = urllib.parse.urlencode([("filter", f'{key}="{value}"') for key, value in matchers]
                                       + [("active", "true"), ("silenced", "false"), ("inhibited", "false")])
        alerts = self.request("GET", "/api/v2/alerts?" + query)
        if not isinstance(alerts, list):
            raise InputError("Alertmanager returned an unexpected alert listing")
        return alerts


def alert_facts(alert):
    labels = alert.get("labels") or {}
    return {"labels": {k: labels[k] for k in RECORDED_LABELS if k in labels},
            "starts_at": alert.get("startsAt"), "state": (alert.get("status") or {}).get("state"),
            "receivers": sorted(r.get("name") for r in alert.get("receivers") or [] if r.get("name"))}


def wait_for(predicate, timeout, interval):
    deadline = time.monotonic() + timeout
    while True:
        value = predicate()
        if value or time.monotonic() >= deadline:
            return value
        time.sleep(interval)


def command_alert(args):
    url = args.alertmanager_url or os.environ.get("ALERTMANAGER_URL")
    parsed = checked_url(url, "the Alertmanager URL (--alertmanager-url or ALERTMANAGER_URL)")
    token = os.environ.get("ALERTMANAGER_BEARER_TOKEN")
    if token and not plain_http_allowed(parsed, args.allow_plain_http):
        raise InputError("refusing to send ALERTMANAGER_BEARER_TOKEN over plain HTTP to a non-loopback host")
    if bool(args.synthetic) == bool(args.expect):
        raise InputError("give exactly one of --synthetic or --expect ALERTNAME")
    if args.expect and not ALERT_NAME.fullmatch(args.expect):
        raise InputError("--expect takes a Prometheus alert name")
    if args.synthetic and args.fault_command:
        raise InputError("a synthetic alert needs no fault command")
    matchers = []
    for entry in args.match_label:
        key, separator, value = entry.partition("=")
        if not separator or not LABEL_KEY.fullmatch(key) or not value or '"' in value or "\\" in value:
            raise InputError("--match-label expects KEY=VALUE")
        matchers.append((key, value))
    manager = Alertmanager(url, token, http_opener(args.ca_file))
    run_id = args.run_id or new_run_id("alert")
    record = {"schema_version": SCHEMA_VERSION, "kind": "greengateway-qualification-alert", "run_id": run_id,
              "mode": "synthetic" if args.synthetic else "rule", "started_at": iso(utc_now()),
              "notified_at": None, "acknowledged_at": None,
              "responder_times_source": "copy notified_at and acknowledged_at from the paging system's own record"}
    reasons = []
    if args.synthetic:
        now = utc_now()
        labels = {"alertname": DRILL_ALERT, "severity": args.severity, "owner": args.owner, "job": "greengateway",
                  "instance": "qualification-drill", "qualification_run": run_id}
        manager.request("POST", "/api/v2/alerts", [{
            "labels": labels,
            "annotations": {"summary": "GreenGateway qualification drill: confirm delivery to the responder",
                            "description": f"Synthetic alert from qualification run {run_id}. No gateway action "
                                           "is required; record when it was received and acknowledged."},
            "startsAt": iso(now), "endsAt": iso(now + timedelta(minutes=args.hold_minutes)),
        }])
        record["sent_at"] = iso(now)
        matchers = [("qualification_run", run_id)]
        name = DRILL_ALERT
    else:
        name = args.expect
        if args.fault_command:
            record["fault_at"] = iso(utc_now())
            record["fault_command_exit"], record["fault_command_seconds"] = run_fault_command(args.fault_command)
            if record["fault_command_exit"] != 0:
                reasons.append("the fault command did not exit 0")
    started = time.monotonic()
    found = wait_for(lambda: manager.active([("alertname", name)] + matchers), args.timeout_seconds, args.poll)
    if found:
        facts = alert_facts(found[0])
        record.update({"alert": facts, "seen_active_at": iso(utc_now()),
                       "seen_after_seconds": round(time.monotonic() - started, 3)})
        if record.get("fault_at") and facts["starts_at"]:
            try:
                record["rule_fired_after_seconds"] = round(
                    (parse_iso(facts["starts_at"], "startsAt") - parse_iso(record["fault_at"], "fault_at"))
                    .total_seconds(), 3)
            except InputError:
                reasons.append("Alertmanager reported an unreadable startsAt")
        missing = set(args.expect_receiver) - set(facts["receivers"])
        if missing:
            reasons.append(f"the alert did not route to {', '.join(sorted(missing))}")
        if args.wait_resolved:
            gone = wait_for(lambda: not manager.active([("alertname", name)] + matchers),
                            args.timeout_seconds, args.poll)
            record["resolved_seen_at"] = iso(utc_now()) if gone else None
            if not gone:
                reasons.append("the alert did not resolve within --timeout-seconds")
    else:
        reasons.append(f"no active {name} alert within --timeout-seconds")
    record["verdict"] = "routed" if not reasons else "failed"
    record["reasons"] = reasons
    write_record(output_directory(args, run_id), "alert.json", record)
    print(f"alert {record['verdict']}; delivery is proved only by the responder's own record")
    for reason in reasons:
        print(f"  {reason}")
    return 0 if not reasons else 1


# ---------------------------------------------------------------------------
# evidence: the record that is shared, checked.


def relative_record(value):
    if not isinstance(value, str) or not value or "://" in value or value.startswith(("/", "\\")) \
            or re.match(r"^[A-Za-z]:", value) or ".." in re.split(r"[\\/]", value):
        return False
    return True


def evidence_problems(document):
    problems = []
    if not isinstance(document, dict) or document.get("kind") != EVIDENCE_KIND:
        return [f"kind must be {EVIDENCE_KIND}"]
    if document.get("schema_version") != SCHEMA_VERSION:
        problems.append(f"schema_version must be {SCHEMA_VERSION}")
    drills = document.get("drills")
    if not isinstance(drills, dict):
        return problems + ["drills must be an object"]
    if set(drills) != set(EVIDENCE_DRILLS):
        problems.append("drills must be exactly " + ", ".join(EVIDENCE_DRILLS))
    for name, fields in EVIDENCE_DRILLS.items():
        drill = drills.get(name)
        if not isinstance(drill, dict):
            continue
        status = drill.get("status")
        if status not in EVIDENCE_STATUSES:
            problems.append(f"drills.{name}.status must be one of {', '.join(EVIDENCE_STATUSES)}")
            continue
        records = drill.get("records")
        if not isinstance(records, list) or not all(relative_record(r) for r in records):
            problems.append(f"drills.{name}.records must list relative record file names")
            records = []
        measured = drill.get("measured", {}) if fields else {}
        if fields and (not isinstance(measured, dict) or set(measured) != set(fields)):
            problems.append(f"drills.{name}.measured must hold exactly {', '.join(fields)}")
            measured = {}
        if status in ("passed", "failed"):
            try:
                parse_iso(drill.get("completed_at"), "completed_at")
            except InputError:
                problems.append(f"drills.{name}: a {status} drill needs completed_at")
            if not records:
                problems.append(f"drills.{name}: a {status} drill needs at least one record")
        if status == "passed":
            empty = [f for f in fields if measured.get(f) in (None, "")]
            if empty:
                problems.append(f"drills.{name}: passed without {', '.join(empty)}")
        if status == "waived" and not (isinstance(drill.get("notes"), str) and drill["notes"].strip()):
            problems.append(f"drills.{name}: a waiver needs notes saying why and who accepted it")
    sign_off = document.get("sign_off")
    if not isinstance(sign_off, dict):
        problems.append("sign_off must be an object")
    elif sign_off.get("approved") is True:
        open_drills = [n for n, d in drills.items() if not isinstance(d, dict) or d.get("status") not in
                       ("passed", "waived")]
        if open_drills:
            problems.append(f"sign_off.approved with drills not passed or waived: {', '.join(open_drills)}")
        if not sign_off.get("approver_role"):
            problems.append("sign_off.approved needs approver_role")
        try:
            parse_iso(sign_off.get("date"), "sign_off.date")
        except InputError:
            problems.append("sign_off.approved needs date")
        release = document.get("release") or {}
        if not DIGEST.fullmatch(str(release.get("image_index_digest", ""))):
            problems.append("sign_off.approved needs release.image_index_digest")
        environment = document.get("environment") or {}
        empty = [k for k, v in environment.items() if v in (None, "")]
        if empty or not environment:
            problems.append(f"sign_off.approved needs environment {', '.join(empty) or 'details'}")
        if not document.get("slo_source"):
            problems.append("sign_off.approved needs slo_source")
    elif sign_off.get("approved") is not False:
        problems.append("sign_off.approved must be true or false")
    return problems


def command_evidence(args):
    document = read_json(args.file, "the evidence file")
    problems = [f"{where}: {reason}" for where, reason in secret_findings(document)]
    if isinstance(document, dict) and document.get("kind") == EVIDENCE_KIND:
        problems += evidence_problems(document)
        if args.records_dir:
            base = Path(args.records_dir)
            for name, drill in (document.get("drills") or {}).items():
                for record in (drill or {}).get("records") or []:
                    if not relative_record(record):
                        continue
                    path = base / record
                    try:
                        data = path.read_bytes()
                    except OSError:
                        problems.append(f"drills.{name}: record {record} is missing")
                        continue
                    if len(data) > MAX_INPUT_BYTES:
                        problems.append(f"drills.{name}: record {record} exceeds the input limit")
                        continue
                    text = data.decode("utf-8", errors="replace")
                    try:
                        content = json.loads(text)
                    except json.JSONDecodeError:
                        content = text
                    problems += [f"{record}{where[1:]}: {reason}" for where, reason in secret_findings(content)]
    if problems:
        for problem in problems:
            print(f"evidence: {problem}", file=sys.stderr)
        return 1
    print("evidence: no secret-shaped content and no unsupported claim")
    return 0


# ---------------------------------------------------------------------------


def split_fault_command(argv):
    if "--" in argv:
        index = argv.index("--")
        return argv[:index], argv[index + 1:]
    return argv, []


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    argv, fault_command = split_fault_command(argv)
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     epilog="See docs/deployment/qualification.md.")
    commands = parser.add_subparsers(dest="command", required=True)

    def cluster_options(command):
        command.add_argument("--context", help="kubectl context (default: kubectl's current context)")
        command.add_argument("--kubectl", default="kubectl", help="kubectl executable (default: kubectl)")
        command.add_argument("--run-id", type=run_id_argument, help="reuse a run ID (default: generated)")
        command.add_argument("--output-dir", help="record directory (default: artifacts/qualification/<run-id>)")

    deploy = commands.add_parser("deploy", help="verify image identity, hardening and rollout")
    cluster_options(deploy)
    deploy.add_argument("--namespace")
    deploy.add_argument("--deployment", default="greengateway")
    deploy.add_argument("--container", default="gateway")
    deploy.add_argument("--service", help="the data Service (default: the Deployment's name)")
    deploy.add_argument("--expected-digest", required=True, type=digest_argument,
                        help="the verified OCI index digest of the release")
    deploy.add_argument("--runtime-digest", action="append", default=[], type=digest_argument,
                        help="also accept this runtime manifest or config digest from the release's subjects.json, "
                        "for runtimes that report it instead of the index digest; repeatable")
    deploy.add_argument("--repository", help="the verified image repository, e.g. ghcr.io/greenhat-security/"
                        "greengateway")
    deploy.add_argument("--admin-exposure", choices=("loopback", "cluster"), default="loopback",
                        help="loopback (base example) or cluster (management overlay)")
    deploy.add_argument("--min-replicas", type=int, default=1)
    deploy.add_argument("--manifest", action="append", default=[], metavar="FILE",
                        help="check rendered manifests (kubectl kustomize output) offline instead of a cluster")

    netpol = commands.add_parser("netpol", help="probe NetworkPolicy enforcement with short-lived Jobs")
    cluster_options(netpol)
    netpol.add_argument("--cases", required=True, help="the cases file (see docs/deployment/qualification/)")
    netpol.add_argument("--case", action="append", default=[], help="run only this case (and its control)")
    netpol.add_argument("--plan", action="store_true", help="print the probe Jobs without contacting the cluster")

    observe = commands.add_parser("observe", help="observe a fault, failover, restore or upgrade; command after --")
    cluster_options(observe)
    observe.add_argument("--drill", required=True, type=drill_argument,
                         help="the drill's name, e.g. replica-loss, db-failover, pitr-restore, upgrade")
    observe.add_argument("--namespace", required=True)
    observe.add_argument("--selector", default="app=greengateway", help="pods of the workload (kubectl -l)")
    observe.add_argument("--container", default="gateway")
    observe.add_argument("--url", help="the audited probe route's full URL (or GREENGATEWAY_PROBE_URL)")
    observe.add_argument("--anonymous", action="store_true", help="probe without GREENGATEWAY_BEARER_TOKEN")
    observe.add_argument("--method", choices=("GET", "HEAD"), default="GET")
    observe.add_argument("--success-status", type=int, action="append", default=None,
                         help="a status that counts as served (default 200); repeatable")
    observe.add_argument("--ca-file", help="CA bundle for a private certificate authority")
    observe.add_argument("--allow-plain-http", action="store_true",
                         help="send the token over http to a non-loopback host (reviewed private networks only)")
    observe.add_argument("--interval", type=positive_number, default=1.0, help="seconds between requests")
    observe.add_argument("--cluster-interval", type=positive_number, default=2.0, help="seconds between pod reads")
    observe.add_argument("--request-timeout", type=positive_number, default=5.0)
    observe.add_argument("--baseline-seconds", type=non_negative_number, default=60.0)
    observe.add_argument("--stable-seconds", type=positive_number, default=60.0)
    observe.add_argument("--timeout-seconds", type=positive_number, default=1800.0)
    observe.add_argument("--replicas", type=int, help="expected ready replicas (default: the baseline's)")
    observe.add_argument("--expect-digest", type=digest_argument, help="recovery requires every pod on this digest")
    observe.add_argument("--accept-digest", type=digest_argument, action="append", default=[],
                         help="a runtime digest equivalent to --expect-digest; repeatable")
    observe.add_argument("--expect-disruption", action="store_true",
                         help="recovery counts only after a disruption was observed")
    observe.add_argument("--manual-fault", action="store_true", help="press Enter when the fault is injected")
    observe.add_argument("--duration-seconds", type=positive_number, help="only observe, for this long")

    reconcile_parser = commands.add_parser("reconcile", help="recovery point and audit continuity from markers")
    reconcile_parser.add_argument("--observation", required=True)
    reconcile_parser.add_argument("--recorded", required=True, help="request IDs found, one per line")
    reconcile_parser.add_argument("--cutoff", help="the recovery target time (default: the observation's fault)")
    reconcile_parser.add_argument("--rpo-target-seconds", type=non_negative_number)
    reconcile_parser.add_argument("--output-dir")

    alert = commands.add_parser("alert", help="prove routing through Alertmanager; fault command after --")
    alert.add_argument("--run-id", type=run_id_argument)
    alert.add_argument("--output-dir")
    alert.add_argument("--alertmanager-url", help="(or ALERTMANAGER_URL; bearer token from ALERTMANAGER_BEARER_TOKEN)")
    alert.add_argument("--ca-file")
    alert.add_argument("--allow-plain-http", action="store_true",
                       help="send ALERTMANAGER_BEARER_TOKEN over http to a non-loopback host")
    alert.add_argument("--synthetic", action="store_true", help=f"post a {DRILL_ALERT} alert")
    alert.add_argument("--severity", choices=("critical", "warning"), default="critical")
    alert.add_argument("--owner", default="gateway-operations")
    alert.add_argument("--hold-minutes", type=positive_number, default=15.0)
    alert.add_argument("--expect", help="wait for this rule's alert, e.g. GreenGatewayMetricsTargetDown")
    alert.add_argument("--match-label", action="append", default=[], metavar="KEY=VALUE")
    alert.add_argument("--expect-receiver", action="append", default=[])
    alert.add_argument("--wait-resolved", action="store_true")
    alert.add_argument("--timeout-seconds", type=positive_number, default=900.0)
    alert.add_argument("--poll", type=positive_number, default=10.0)

    evidence = commands.add_parser("evidence", help="check an evidence file or record for secrets and claims")
    evidence.add_argument("file")
    evidence.add_argument("--records-dir", help="also scan the record files the evidence lists")

    args = parser.parse_args(argv)
    args.fault_command = fault_command
    if fault_command and args.command not in ("observe", "alert"):
        parser.error("a command after -- applies to observe and alert only")
    if args.command == "observe" and args.success_status is None:
        args.success_status = [200]
    handlers = {"deploy": command_deploy, "netpol": command_netpol, "observe": command_observe,
                "reconcile": command_reconcile, "alert": command_alert, "evidence": command_evidence}
    try:
        return handlers[args.command](args)
    except InputError as error:
        print(f"qualification {args.command}: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
