"""Produce final-image SPDX evidence and independently verify signed subjects."""
import argparse
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

from build_tools import versions, verify_download
from scan_candidate_image import DIGEST, REPOSITORY, Registry, runtime_manifests, install_trivy

PROVENANCE = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document/v2.3"
WORKFLOW = ".github/workflows/publish-image.yml"


def identity(repository, digest, sha, ref):
    if not REPOSITORY.fullmatch(repository) or not DIGEST.fullmatch(digest) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid evidence identity")
    if ref != "refs/heads/main" and not re.fullmatch(r"refs/tags/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", ref):
        raise ValueError("evidence requires a supported source ref")
    return "ghcr.io/" + repository.lower()


def sbom_document(data, image, config_digest=None):
    if data.get("spdxVersion") != "SPDX-2.3" or data.get("SPDXID") != "SPDXRef-DOCUMENT" or data.get("name") != image:
        raise ValueError("SBOM schema or immutable subject mismatch")
    packages = data.get("packages")
    if not isinstance(packages, list) or len(packages) < 2 or not data.get("relationships"):
        raise ValueError("SBOM has no usable package inventory")
    containers = [p for p in packages if p.get("primaryPackagePurpose") == "CONTAINER"]
    if len(containers) != 1 or containers[0].get("name") != image:
        raise ValueError("SBOM container subject mismatch")
    if config_digest and not any(a.get("comment") == "ImageID: " + config_digest for a in containers[0].get("annotations", [])):
        raise ValueError("SBOM describes a different runtime configuration")
    return data


def generate(repository, digest, sha, ref, output, scanner=None):
    image = identity(repository, digest, sha, ref) + "@" + digest
    output.mkdir(parents=True, exist_ok=True)
    registry = Registry(repository)
    manifests, _ = runtime_manifests(registry, digest, ["linux/amd64"], sha)
    # Keep original bytes so offline verification hashes the real index subject.
    (output / "image-index.oci.json").write_bytes(registry.raw(digest))
    with tempfile.TemporaryDirectory(prefix="greengateway-sbom-") as temporary:
        sandbox = Path(temporary)
        executable = scanner or install_trivy(sandbox / "trivy")
        env = {k: v for k, v in os.environ.items() if not k.startswith("TRIVY_")}
        def run(args):
            return subprocess.run([executable, *args], cwd=sandbox, env=env, check=True,
                                  text=True, capture_output=True, timeout=900).stdout
        if run(["--version"]).splitlines()[0] != "Version: " + versions()["trivy"]:
            raise ValueError("SBOM generator version drift")
        path = output / "sbom.spdx.json"
        # SPDX output inventories packages without a vulnerability verdict.
        # Vulnerability qualification remains the independent image-scan job.
        run(["image", "--image-src", "remote", "--platform", "linux/amd64", "--format", "spdx-json",
             "--no-progress", "--disable-telemetry", "--output", str(path.resolve()), image])
        sbom_document(json.loads(path.read_bytes()), image, manifests["linux/amd64"]["config_digest"])
    (output / "subjects.json").write_text(json.dumps({"image": image, "source_sha": sha, "source_ref": ref,
        "signer_workflow": repository + "/" + WORKFLOW, "platforms": manifests,
        "sbom_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}, indent=2) + "\n")


def install_gh(destination):
    pins = versions()
    archive_name = f"gh_{pins['github_cli']}_linux_amd64"
    url = f"https://github.com/cli/cli/releases/download/v{pins['github_cli']}/{archive_name}.tar.gz"
    with urllib.request.urlopen(url, timeout=120) as response:
        raw = response.read(100 * 1024 * 1024 + 1)
    if len(raw) > 100 * 1024 * 1024:
        raise ValueError("verifier archive exceeds limit")
    verify_download(raw, pins["github_cli_linux_amd64_sha256"])
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        member = archive.getmember(archive_name + "/bin/gh")
        if not member.isfile() or member.size > 200 * 1024 * 1024:
            raise ValueError("invalid verifier executable")
        destination.write_bytes(archive.extractfile(member).read())
    destination.chmod(0o755)
    return str(destination.resolve())


def constraints(repository, sha, ref):
    return ["--repo", repository, "--signer-workflow", repository + "/" + WORKFLOW,
            "--signer-digest", sha, "--source-digest", sha, "--source-ref", ref,
            "--cert-oidc-issuer", "https://token.actions.githubusercontent.com",
            "--deny-self-hosted-runners", "--format", "json"]


def statement(result, predicate, digest, name=None):
    if not isinstance(result, list) or not result:
        raise ValueError("verifier returned no verified attestations")
    statements = []
    for item in result:
        verified = item["verificationResult"]["statement"]
        if verified.get("predicateType") != predicate:
            raise ValueError("unexpected verified predicate type")
        subjects = verified.get("subject", [])
        if len(subjects) != 1 or subjects[0].get("digest") != {"sha256": digest.removeprefix("sha256:")}:
            raise ValueError("verified subject digest mismatch")
        if name and subjects[0].get("name") != name:
            raise ValueError("verified image name mismatch")
        statements.append(verified)
    return statements


def verify(repository, digest, sha, ref, evidence, output, gh=None, trusted_root=None):
    image = identity(repository, digest, sha, ref)
    if trusted_root and not gh:
        raise ValueError("offline verification requires an already installed verifier via --gh")
    output.mkdir(parents=True, exist_ok=True)
    sbom_path = evidence / "sbom.spdx.json"
    raw_sbom = sbom_path.read_bytes()
    if not raw_sbom or len(raw_sbom) > 16 * 1024 * 1024:
        raise ValueError("missing or excessive SBOM")
    sbom = sbom_document(json.loads(raw_sbom), image + "@" + digest)
    file_digest = "sha256:" + hashlib.sha256(raw_sbom).hexdigest()
    with tempfile.TemporaryDirectory(prefix="greengateway-verify-") as temporary:
        executable = gh or install_gh(Path(temporary) / "gh")
        def run(args):
            return subprocess.run([executable, *args], check=True, text=True, capture_output=True, timeout=300).stdout
        version = run(["--version"]).splitlines()[0]
        if not version.startswith("gh version " + versions()["github_cli"] + " "):
            raise ValueError("attestation verifier version drift")
        image_subject = "oci://" + image + "@" + digest
        if trusted_root:
            image_subject = str((evidence / "image-index.oci.json").resolve())
            if "sha256:" + hashlib.sha256(Path(image_subject).read_bytes()).hexdigest() != digest:
                raise ValueError("offline OCI index bytes differ from expected digest")
        cases = [("image-provenance", image_subject, PROVENANCE, digest, image),
                 ("image-sbom", image_subject, SPDX, digest, image),
                 ("sbom-bytes", str(sbom_path.resolve()), PROVENANCE, file_digest, None)]
        for label, subject, predicate, expected, name in cases:
            command = ["attestation", "verify", subject, *constraints(repository, sha, ref), "--predicate-type", predicate]
            if trusted_root:
                command.extend(["--bundle", str((evidence / (label + ".jsonl")).resolve()),
                                "--custom-trusted-root", str(trusted_root.resolve())])
            elif label != "sbom-bytes":
                command.append("--bundle-from-oci")
            verified = json.loads(run(command))
            statements = statement(verified, predicate, expected, name)
            if label == "image-sbom" and any(s["predicate"] != sbom for s in statements):
                raise ValueError("downloaded SBOM differs from the image's signed predicate")
            (output / (label + "-verified.json")).write_text(json.dumps(verified, indent=2) + "\n")
    verdict = {"status": "passed", "candidate_digest": digest, "source_sha": sha, "source_ref": ref,
               "repository": repository, "signer_workflow": repository + "/" + WORKFLOW,
               "sbom_sha256": file_digest, "verifier": version}
    (output / "verification.json").write_text(json.dumps(verdict, indent=2) + "\n")
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a", encoding="utf-8") as stream:
            stream.write("digest=" + digest + "\n")
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(f"Verified image provenance, SBOM predicate and exact SBOM bytes: `{image}@{digest}`\n\n")
            stream.write(f"Signer: `{repository}/{WORKFLOW}`\n\nSource: `{sha}` (`{ref}`)\n\nSBOM bytes: `{file_digest}`\n")
    return verdict


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["generate", "verify"])
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--digest", default=os.environ.get("CANDIDATE_DIGEST", ""))
    parser.add_argument("--sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF", ""))
    parser.add_argument("--evidence", type=Path, default=Path("target/image-evidence"))
    parser.add_argument("--output", type=Path, default=Path("target/image-verification"))
    parser.add_argument("--scanner")
    parser.add_argument("--gh")
    parser.add_argument("--trusted-root", type=Path, help="Enable offline verification with independently trusted Sigstore roots")
    args = parser.parse_args()
    try:
        if args.mode == "generate":
            generate(args.repository, args.digest, args.sha, args.ref, args.evidence.resolve(), args.scanner)
        else:
            verify(args.repository, args.digest, args.sha, args.ref, args.evidence.resolve(), args.output.resolve(), args.gh, args.trusted_root)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print("Image evidence failed (" + type(error).__name__ + "). No passing digest issued.", file=sys.stderr)
        sys.exit(1)
