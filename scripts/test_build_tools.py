"""Negative fixtures for actual tool-contract drift and runtime mismatches."""
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import build_tools

ROOT = Path(__file__).resolve().parents[1]


class ToolContractTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        files = ["build-tools.json", ".node-version", ".npm-version",
                 "rust-toolchain.toml", "Dockerfile", "gateway/build.rs", "package.json",
                 "admin-ui/package.json", ".npmrc", "admin-ui/.npmrc",
                 ".github/actions/build-tools/action.yml", ".github/actions/buildx/action.yml"]
        files += [str(p.relative_to(ROOT)) for p in (ROOT / ".github/workflows").glob("*.y*ml")]
        for file in files:
            target = self.root / file
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / file, target)

    def replace(self, file, old, new):
        path = self.root / file
        text = path.read_text()
        self.assertIn(old, text)
        path.write_text(text.replace(old, new))

    def rejects(self, fragment):
        errors = build_tools.check(self.root)
        self.assertTrue(any(fragment in e for e in errors), errors)

    def test_current_contract_passes(self):
        self.assertEqual(build_tools.check(self.root), [])

    def test_missing_contract_fails(self):
        (self.root / "build-tools.json").unlink()
        self.rejects("invalid build-tool")

    def test_floating_compiler_fails(self):
        self.replace("build-tools.json", '"1.98.1"', '"stable"')
        self.rejects("exact version")

    def test_native_node_version_drift_fails(self):
        (self.root / ".node-version").write_text("24.19.0\n")
        self.rejects(".node-version disagrees")

    def test_docker_version_or_lock_drift_fails(self):
        self.replace("Dockerfile", "node:24.20.0-", "node:24-")
        self.replace("Dockerfile", "cargo build --locked", "cargo build")
        self.rejects("Docker Node")
        self.rejects("must be locked")

    def test_unversioned_audit_or_disabled_checksums_fail(self):
        self.replace(".github/workflows/ci.yml", "cargo-audit@0.22.2", "cargo-audit")
        self.replace(".github/workflows/ci.yml", "checksum: true", "checksum: false")
        self.rejects("tool install must pin")

    def test_buildkit_floating_image_fails(self):
        self.replace("build-tools.json", build_tools.versions()["buildkit_image"], "moby/buildkit:latest")
        self.rejects("immutable image")

    def test_missing_builder_or_wrong_download_cannot_pass(self):
        self.replace(".github/workflows/publish-image.yml", "uses: ./.github/actions/buildx", "run: docker buildx create")
        self.rejects("verified Buildx setup")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            build_tools.verify_download(b"substituted binary", "a" * 64)

    def test_coverage_profile_cannot_silently_become_stable(self):
        self.replace(".github/workflows/ci.yml", "rust: coverage", "rust: ci")
        self.rejects("coverage compiler")

    def test_new_job_cannot_use_undeclared_compiler(self):
        path = self.root / ".github/workflows/ci.yml"
        path.write_text(path.read_text() + "\n  unpinned:\n    runs-on: ubuntu-latest\n    steps:\n      - run: cargo test\n")
        self.rejects("exactly one pinned")

    def test_npx_cannot_download_a_missing_executable(self):
        self.replace(".github/workflows/ci.yml", "npx --no-install playwright", "npx playwright")
        self.rejects("npx must not download")

    def test_cargo_policy_gate_cannot_be_removed_or_reduced(self):
        self.replace(".github/workflows/ci.yml", "python scripts/cargo_policy.py check", "echo skipped")
        self.rejects("full-graph check")
        self.replace(".github/workflows/ci.yml", "os: [ubuntu-latest, windows-latest]", "os: [ubuntu-latest]")
        self.rejects("Linux and Windows qualification")

    def test_cargo_policy_tool_requires_exact_version_and_checksum(self):
        self.replace("build-tools.json", '"cargo_deny": "0.20.2"', '"cargo_deny": "latest"')
        self.rejects("exact version")

    def test_raw_npm_install_or_exec_cannot_bypass_review(self):
        for command in ["npm ci", "npm install", "npm exec playwright", "npm rebuild"]:
            with self.subTest(command=command):
                path = self.root / ".github/workflows/ci.yml"
                original = path.read_text()
                self.replace(".github/workflows/ci.yml", "node scripts/npm-script-policy.mjs install .", command)
                self.rejects("reviewed npm installer")
                path.write_text(original)

    def test_docker_cannot_omit_policy_inputs(self):
        self.replace("Dockerfile", "build-tools.json npm-script-policy.json", "build-tools.json")
        self.rejects("Docker must copy npm policy input")

    def test_cargo_cannot_bypass_installer(self):
        self.replace("gateway/build.rs", '.args(["install", "admin-ui"])', '.args(["ci"])')
        self.rejects("Cargo must use the reviewed npm installer")

    def test_cargo_must_rebuild_when_policy_changes(self):
        self.replace("gateway/build.rs", '        "npm-script-policy.json",\n', '')
        self.rejects("Cargo must track npm policy input")

    def test_duplicate_engine_override_is_rejected(self):
        path = self.root / "admin-ui/.npmrc"
        path.write_text(path.read_text() + "engine-strict=false\n")
        self.rejects("engine-strict")

    def test_npm_engines_and_strictness_required(self):
        (self.root / "admin-ui/.npmrc").write_text("engine-strict=false\n")
        self.rejects("engine-strict")
        data = json.loads((self.root / "package.json").read_text())
        data["engines"]["node"] = ">=24"
        (self.root / "package.json").write_text(json.dumps(data))
        self.rejects("exact Node/npm")

    def test_runtime_rejects_wrong_node_before_npm_execution(self):
        with patch.dict(os.environ, {"RUST_PROFILE": "none", "CHECK_NODE": "true"}):
            with patch("build_tools.output", return_value="v24.19.0") as run:
                with self.assertRaisesRegex(ValueError, "node: expected"):
                    build_tools.verify()
                self.assertEqual(run.call_count, 1)

    def test_runtime_rejects_wrong_active_compiler(self):
        with patch.dict(os.environ, {"RUST_PROFILE": "production", "CHECK_NODE": "false"}):
            with patch("build_tools.output", return_value="stable-x86_64-unknown-linux-gnu"):
                with self.assertRaisesRegex(ValueError, "unexpected active"):
                    build_tools.verify()


if __name__ == "__main__":
    unittest.main()
