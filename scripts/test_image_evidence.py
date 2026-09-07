"""Trusted-verifier constraints and digest/SBOM substitution regressions."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
import image_evidence as evidence

REPO = "Example/Gateway"
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
IMAGE = "ghcr.io/example/gateway"
REF = "refs/heads/main"


def sbom():
    return {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": IMAGE + "@" + DIGEST,
            "packages": [{"name": IMAGE + "@" + DIGEST, "primaryPackagePurpose": "CONTAINER"},
                         {"name": "fixture", "versionInfo": "1.0"}],
            "relationships": [{"relationshipType": "DESCRIBES"}]}


def verified(predicate, digest, name, value=None):
    return [{"verificationResult": {"statement": {"predicateType": predicate,
        "subject": [{"name": name, "digest": {"sha256": digest.removeprefix("sha256:")}}],
        "predicate": value or {}}}}]


class EvidenceTests(unittest.TestCase):
    def test_cli_unicode_json_uses_utf8_independent_of_windows_locale(self):
        command = [sys.executable, "-c", "import sys; sys.stdout.buffer.write(bytes.fromhex('7b22617574686f72223a20224dc3bc6c6c6572227d'))"]
        self.assertEqual(json.loads(evidence.run_utf8(command, timeout=10)), {"author": "M\u00fcller"})

    def test_constraints_pin_certificate_identity_not_only_claimed_predicate(self):
        args = evidence.constraints(REPO, SHA, REF)
        for flag, expected in [("--repo", REPO), ("--signer-workflow", REPO + "/.github/workflows/publish-image.yml"),
                               ("--signer-digest", SHA), ("--source-digest", SHA), ("--source-ref", REF),
                               ("--cert-oidc-issuer", "https://token.actions.githubusercontent.com")]:
            self.assertEqual(args[args.index(flag)+1], expected)
        self.assertIn("--deny-self-hosted-runners", args)

    def test_missing_substituted_or_wrong_predicate_result_fails(self):
        good = verified(evidence.PROVENANCE, DIGEST, IMAGE)
        for bad in [[], {}, verified(evidence.SPDX, DIGEST, IMAGE),
                    verified(evidence.PROVENANCE, "sha256:"+"c"*64, IMAGE),
                    verified(evidence.PROVENANCE, DIGEST, "ghcr.io/other/gateway")]:
            with self.assertRaises(ValueError):
                evidence.statement(bad, evidence.PROVENANCE, DIGEST, IMAGE)
        self.assertEqual(len(evidence.statement(good, evidence.PROVENANCE, DIGEST, IMAGE)), 1)

    def test_invalid_sbom_cannot_claim_complete_final_image_inventory(self):
        for mutation in [lambda d: d.update(name=IMAGE+":latest"), lambda d: d.update(packages=[]),
                         lambda d: d.update(relationships=[]), lambda d: d.update(spdxVersion="SPDX-2.2")]:
            doc = sbom()
            mutation(doc)
            with self.assertRaises(ValueError):
                evidence.sbom_document(doc, IMAGE+"@"+DIGEST)

    def exercise(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root/"source", root/"verified"
            source.mkdir()
            output.mkdir()
            (output/"verification.json").write_text('{"status":"passed"}')
            path = source/"sbom.spdx.json"
            path.write_text(json.dumps(sbom()))
            file_digest = "sha256:"+hashlib.sha256(path.read_bytes()).hexdigest()
            calls = []
            def run(command, **kwargs):
                calls.append(command)
                if command[1:] == ["--version"]:
                    return subprocess.CompletedProcess(command, 0, stdout="gh version " + evidence.versions()["github_cli"] + " (fixture)")
                # Model the real cryptographic verifier rejecting an identity/signature mismatch.
                if mode in {"bad-signature", "wrong-repo", "wrong-workflow", "wrong-commit", "wrong-ref", "missing"}:
                    raise subprocess.CalledProcessError(1, command)
                predicate = command[command.index("--predicate-type")+1]
                is_file = command[3] == str(path.resolve())
                digest = file_digest if is_file else DIGEST
                name = "sbom.spdx.json" if is_file else IMAGE
                if mode == "wrong-digest":
                    digest = "sha256:"+"f"*64
                payload = sbom() if predicate == evidence.SPDX else {}
                if mode == "substituted-sbom" and predicate == evidence.SPDX:
                    payload["packages"][1]["versionInfo"] = "2.0"
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps(verified(predicate, digest, name, payload)))
            job_output = root/"job-output"
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(job_output)}), patch.object(evidence.subprocess, "run", side_effect=run):
                if mode == "clean":
                    result = evidence.verify(REPO, DIGEST, SHA, REF, source, output, "gh")
                    self.assertEqual(result["status"], "passed")
                    self.assertEqual(job_output.read_text().strip(), "digest="+DIGEST)
                    self.assertEqual(len(calls), 4)
                    for call in calls[1:]:
                        self.assertIn("--source-digest", call)
                        self.assertIn("--signer-workflow", call)
                    self.assertIn("--bundle-from-oci", calls[1])
                    self.assertIn("--bundle-from-oci", calls[2])
                    self.assertNotIn("--bundle-from-oci", calls[3])
                else:
                    with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                        evidence.verify(REPO, DIGEST, SHA, REF, source, output, "gh")
                    self.assertFalse(job_output.exists())
                    self.assertEqual(json.loads((output/"verification.json").read_text())["status"], "error")

    def test_independent_verification_requires_all_three_signed_subjects(self):
        self.exercise("clean")
        for mode in ["bad-signature", "wrong-repo", "wrong-workflow", "wrong-commit", "wrong-ref", "missing", "wrong-digest", "substituted-sbom"]:
            with self.subTest(mode=mode):
                self.exercise(mode)

    def test_offline_mode_hashes_original_index_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"sbom.spdx.json").write_text(json.dumps(sbom()))
            (root/"image-index.oci.json").write_text("substituted index")
            with patch.object(evidence.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="gh version " + evidence.versions()["github_cli"] + " (fixture)")) as run:
                with self.assertRaises(ValueError):
                    evidence.verify(REPO, DIGEST, SHA, REF, root, root/"verified", "gh", root/"trusted-root.jsonl")
                self.assertEqual(run.call_count, 1)

    def test_only_trusted_build_can_sign_and_read_only_verifier_gates_promotion(self):
        root = Path(__file__).resolve().parents[1]
        ci = yaml.load((root/".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        reusable = yaml.load((root/".github/workflows/publish-image.yml").read_text(), Loader=yaml.BaseLoader)
        build = reusable["jobs"]["build"]
        self.assertEqual(build["permissions"], {"contents": "read", "packages": "write", "attestations": "write", "id-token": "write"})
        self.assertEqual(ci["jobs"]["image-candidate"]["permissions"], build["permissions"])
        self.assertEqual(build["if"], "github.event_name == 'push'")
        signed = [s for s in build["steps"] if s.get("uses", "").startswith("actions/attest@")]
        self.assertEqual(len(signed), 3)
        self.assertEqual(signed[0]["with"]["subject-digest"], "${{ steps.build.outputs.digest }}")
        self.assertEqual(signed[1]["with"]["sbom-path"], signed[2]["with"]["subject-path"])
        verifier = ci["jobs"]["image-verification"]
        self.assertEqual(verifier["permissions"], {"contents": "read", "packages": "read", "attestations": "read"})
        self.assertEqual(verifier["needs"], "image-candidate")
        self.assertIn("image-verification", ci["jobs"]["promote-image"]["needs"])
        self.assertEqual(ci["jobs"]["promote-image"]["steps"][-1]["env"]["VERIFIED_DIGEST"], "${{ needs.image-verification.outputs.digest }}")
        self.assertEqual(ci["jobs"]["image-preview"]["permissions"], {"contents": "read"})


if __name__ == "__main__":
    unittest.main()
