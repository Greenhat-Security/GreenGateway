"""Fail-closed, digest-bound final image scan. No daemon or registry writes."""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from urllib.parse import urlsplit

from build_tools import versions, verify_download

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")


def timestamp(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return result


def fresh(value, now, hours):
    age = now - timestamp(value)
    if age < -timedelta(minutes=5) or age > timedelta(hours=hours):
        raise ValueError("evidence timestamp is stale or in the future")


def policy(data, now):
    if set(data) != {"schema_version", "platforms", "max_database_age_hours", "exceptions"} or data["schema_version"] != 1:
        raise ValueError("unknown scan policy schema")
    if data["platforms"] != ["linux/amd64"] or data["max_database_age_hours"] != 48:
        raise ValueError("platform or freshness policy requires a reviewed implementation change")
    if not isinstance(data["exceptions"], list):
        raise ValueError("exceptions must be a list")
    seen = set()
    for item in data["exceptions"]:
        required = {"advisory", "package", "version", "owner", "rationale", "expires"}
        if set(item) not in (required, required | {"digest"}):
            raise ValueError("exceptions require exact advisory/package/version and review metadata")
        if any(not isinstance(value, str) or not value.strip() or any(x in value for x in ["*", "\n", "\r"]) for value in item.values()):
            raise ValueError("empty or wildcard exceptions are forbidden")
        if not re.fullmatch(r"(?:CVE-\d{4}-\d+|GHSA-[a-z0-9-]+)", item["advisory"]) or len(item["rationale"]) < 20:
            raise ValueError("exception needs an advisory ID and substantive rationale")
        if "digest" in item and not DIGEST.fullmatch(item["digest"]):
            raise ValueError("exception digest is invalid")
        expiry = timestamp(item["expires"])
        if not now < expiry <= now + timedelta(days=90):
            raise ValueError("exceptions must expire in the next 90 days")
        key = tuple(item.get(k) for k in ["advisory", "package", "version", "digest"])
        if key in seen:
            raise ValueError("duplicate exception")
        seen.add(key)
    return data


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        if urlsplit(new_url).scheme != "https":
            raise ValueError("registry redirects must use HTTPS")
        redirected = super().redirect_request(request, response, code, message, headers, new_url)
        if urlsplit(request.full_url).netloc != urlsplit(new_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


class Registry:
    """GHCR read-only client; validate every object against its OCI digest."""
    def __init__(self, repository):
        if not REPOSITORY.fullmatch(repository):
            raise ValueError("invalid repository")
        self.name = repository.lower()
        request = urllib.request.Request("https://ghcr.io/token?service=ghcr.io&scope=repository:" + self.name + ":pull")
        if token := os.environ.get("GH_TOKEN"):
            credentials = base64.b64encode((os.environ.get("GITHUB_ACTOR", "token") + ":" + token).encode()).decode()
            request.add_header("Authorization", "Basic " + credentials)
        self.opener = urllib.request.build_opener(SafeRedirect())
        with self.opener.open(request, timeout=60) as response:
            self.token = json.load(response)["token"]

    def get(self, digest, kind="manifests"):
        return json.loads(self.raw(digest, kind))

    def raw(self, digest, kind="manifests"):
        if not DIGEST.fullmatch(digest) or kind not in {"manifests", "blobs"}:
            raise ValueError("invalid registry object")
        request = urllib.request.Request(f"https://ghcr.io/v2/{self.name}/{kind}/{digest}", headers={
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json",
        })
        with self.opener.open(request, timeout=60) as response:
            raw = response.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024 or "sha256:" + hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("registry object exceeds limit or differs from its digest")
        return raw


def runtime_manifests(registry, digest, platforms, sha):
    index = registry.get(digest)
    if index.get("schemaVersion") != 2:
        raise ValueError("unsupported image manifest")
    found = {}
    metadata = []
    descriptors = index.get("manifests")
    if descriptors is None:
        descriptors = [{"digest": digest}]
    if not isinstance(descriptors, list) or not descriptors:
        raise ValueError("empty image index")
    for item in descriptors:
        annotations = item.get("annotations", {})
        if annotations.get("vnd.docker.reference.type") == "attestation-manifest":
            if item.get("platform") != {"architecture": "unknown", "os": "unknown"}:
                raise ValueError("invalid BuildKit evidence descriptor")
            metadata.append(item)
            continue
        manifest = registry.get(item["digest"])
        config_digest = manifest["config"]["digest"]
        config = registry.get(config_digest, "blobs")
        platform = config["os"] + "/" + config["architecture"]
        if platform not in platforms or platform in found or config.get("variant"):
            raise ValueError("unexpected or duplicate runtime platform")
        if item.get("platform", {"os": config["os"], "architecture": config["architecture"]}) != {"os": config["os"], "architecture": config["architecture"]}:
            raise ValueError("descriptor/config platform mismatch")
        if config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != sha:
            raise ValueError("image revision differs from checked source")
        found[platform] = {"digest": item["digest"], "config_digest": config_digest}
    if set(found) != set(platforms):
        raise ValueError("missing runtime platform")
    if any(item["annotations"].get("vnd.docker.reference.digest") not in {x["digest"] for x in found.values()} for item in metadata):
        raise ValueError("BuildKit evidence refers to an unexpected runtime")
    return found, index


def evaluate(report, image, platform, config_digest, sha, candidate, rules, now):
    if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image" or report.get("ArtifactName") != image:
        raise ValueError("report is not for the requested immutable image")
    fresh(report["CreatedAt"], now, 1)
    meta = report["Metadata"]
    config = meta["ImageConfig"]
    if meta.get("ImageID") != config_digest or image not in meta.get("RepoDigests", []):
        raise ValueError("report digest/config mismatch")
    if config.get("os", "") + "/" + config.get("architecture", "") != platform:
        raise ValueError("report platform mismatch")
    if config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") != sha:
        raise ValueError("report source revision mismatch")
    if meta.get("OS", {}).get("Family") != "debian" or meta["OS"].get("EOSL") is True:
        raise ValueError("unsupported or end-of-life runtime OS")
    results = report.get("Results")
    if not isinstance(results, list) or not results or not any(r.get("Class") == "os-pkgs" and r.get("Packages") for r in results):
        raise ValueError("missing final OS package inventory")
    blocked, applied = [], []
    for result in results:
        if result.get("Class") not in {"os-pkgs", "lang-pkgs"}:
            raise ValueError("unexpected report class")
        packages = result.get("Packages")
        if not isinstance(packages, list) or not packages:
            raise ValueError("result lacks a package inventory")
        if any(not isinstance(package, dict) or
               any(not isinstance(package.get(key), str) or not package[key] for key in ["Name", "Version"])
               for package in packages):
            raise ValueError("malformed package inventory")
        if result["Class"] == "os-pkgs" and result.get("Type") != "debian":
            raise ValueError("OS inventory type mismatch")
        findings = result.get("Vulnerabilities", [])
        if not isinstance(findings, list):
            raise ValueError("malformed findings")
        for finding in findings:
            for key in ["VulnerabilityID", "PkgName", "InstalledVersion", "Severity"]:
                if not isinstance(finding.get(key), str) or not finding[key]:
                    raise ValueError("incomplete finding")
            if finding["Severity"] not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                raise ValueError("unrecognized severity")
            match = next((item for item in rules["exceptions"] if
                          (item["advisory"], item["package"], item["version"]) ==
                          (finding["VulnerabilityID"], finding["PkgName"], finding["InstalledVersion"])
                          and item.get("digest", candidate) == candidate), None)
            if match:
                applied.append({"finding": finding, "exception": match})
            elif finding["Severity"] in {"HIGH", "CRITICAL", "UNKNOWN"}:
                blocked.append(finding)
    return {"blocked": blocked, "applied_exceptions": applied}


def install_trivy(destination):
    pins = versions()
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{pins['trivy']}/trivy_{pins['trivy']}_Linux-64bit.tar.gz"
    with urllib.request.urlopen(url, timeout=120) as response:
        raw = response.read(150 * 1024 * 1024 + 1)
    if len(raw) > 150 * 1024 * 1024:
        raise ValueError("scanner archive exceeds limit")
    verify_download(raw, pins["trivy_linux_amd64_sha256"])
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        member = archive.getmember("trivy")
        if not member.isfile() or member.size > 300 * 1024 * 1024:
            raise ValueError("invalid scanner executable")
        destination.write_bytes(archive.extractfile(member).read())
    destination.chmod(0o755)
    return str(destination.resolve())


def scan(repository, digest, sha, output, scanner=None):
    if not REPOSITORY.fullmatch(repository) or not DIGEST.fullmatch(digest) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid immutable candidate identity")
    output.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    rules = policy(json.loads((ROOT / "image-scan-policy.json").read_text()), now)
    evidence = {"schema_version": 1, "repository": repository.lower(), "candidate_digest": digest,
                "source_sha": sha, "created_at": now.isoformat(), "status": "error", "platforms": {}}
    try:
        evidence["stage"] = "registry-identity"
        registry = Registry(repository)
        manifests, index = runtime_manifests(registry, digest, rules["platforms"], sha)
        (output / "index.json").write_text(json.dumps(index, indent=2))
        with tempfile.TemporaryDirectory(prefix="greengateway-scan-") as temporary:
            evidence["stage"] = "scanner-install"
            sandbox = Path(temporary)
            executable = scanner or install_trivy(sandbox / "trivy")
            # Ignore repository-local Trivy config/ignore files and ambient TRIVY_* overrides.
            env = {k: v for k, v in os.environ.items() if not k.startswith("TRIVY_")}
            def run(arguments):
                return subprocess.run([executable, *arguments], cwd=sandbox, env=env, check=True, capture_output=True, text=True, timeout=900).stdout
            version = run(["--version"]).splitlines()[0]
            if version != "Version: " + versions()["trivy"]:
                raise ValueError("scanner version drift")
            evidence["scanner"] = version
            cache = str(sandbox / "cache")
            common = ["image", "--cache-dir", cache, "--no-progress", "--disable-telemetry"]
            # Fresh cache every run: an unavailable download never falls back to old data.
            evidence["stage"] = "database-refresh"
            run(common + ["--download-db-only"])
            db = json.loads((sandbox / "cache/db/metadata.json").read_text())
            if db.get("Version") != 2:
                raise ValueError("unsupported advisory database")
            fresh(db["UpdatedAt"], datetime.now(timezone.utc), rules["max_database_age_hours"])
            evidence["database"] = db
            (output / "database.json").write_text(json.dumps(db, indent=2))
            for platform, subject in manifests.items():
                evidence["stage"] = "scan-" + platform
                image = f"ghcr.io/{repository.lower()}@{subject['digest']}"
                report_path = output / (platform.replace("/", "-") + ".json")
                run(common + ["--image-src", "remote", "--platform", platform, "--scanners", "vuln",
                              "--pkg-types", "os,library", "--list-all-pkgs", "--skip-db-update",
                              "--format", "json", "--output", str(report_path.resolve()), image])
                raw = report_path.read_bytes()
                decision = evaluate(json.loads(raw), image, platform, subject["config_digest"], sha, digest, rules, datetime.now(timezone.utc))
                evidence["platforms"][platform] = {**subject, **decision, "report_sha256": hashlib.sha256(raw).hexdigest()}
            fresh(db["UpdatedAt"], datetime.now(timezone.utc), rules["max_database_age_hours"])
            evidence["status"] = "blocked" if any(p["blocked"] for p in evidence["platforms"].values()) else "passed"
            evidence["stage"] = "complete"
    finally:
        (output / "decision.json").write_text(json.dumps(evidence, indent=2) + "\n")
        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(summary, "a", encoding="utf-8") as stream:
                stream.write(f"Candidate scan: **{evidence['status']}** ({evidence.get('stage')})\n\n")
                stream.write(f"Source: `{sha}`\n\nCandidate: `ghcr.io/{repository.lower()}@{digest}`\n\n")
                stream.write("Raw inventory, database metadata and decisions: `image-scan-" + sha + "` artifact.\n")
    if evidence["status"] != "passed":
        raise ValueError("candidate has unexcepted blocking findings; see scan evidence")
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as stream:
            stream.write("digest=" + digest + "\n")
    return evidence


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--digest", default=os.environ.get("CANDIDATE_DIGEST"))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA"))
    parser.add_argument("--output", type=Path, default=Path("target/image-scan"))
    parser.add_argument("--scanner", help="Locally installed, version-checked scanner; CI uses the verified installer")
    args = parser.parse_args()
    try:
        scan(args.repository or "", args.digest or "", args.sha or "", args.output.resolve(), args.scanner)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        # Avoid logging registry credentials or scanner subprocess output.
        print("Candidate scan failed (" + type(error).__name__ + "). Inspect preserved scan evidence.", file=sys.stderr)
        sys.exit(1)
