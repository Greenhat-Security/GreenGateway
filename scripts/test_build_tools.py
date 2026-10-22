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
        files += [str(p.relative_to(ROOT)) for p in (ROOT / ".github/actions").glob("*/action.y*ml")]
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
        self.replace("Dockerfile", f"node:{build_tools.versions()['node']}-", "node:26-")
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

    def test_image_builds_in_run_commands_require_verified_buildx(self):
        path = self.root / ".github/workflows/ci.yml"
        original = path.read_text()
        for command in ["docker build -t example .", "docker buildx build .", "docker image build .",
                        "docker compose -f a.yml up -d --build", "docker compose -f a.yml build"]:
            with self.subTest(command=command):
                path.write_text(original + "\n  unpinned:\n    runs-on: ubuntu-latest\n    steps:\n"
                                "      - uses: ./.github/actions/build-tools\n"
                                f"      - run: {command}\n")
                self.rejects("verified Buildx setup")
        # Running an already-built image is not a build.
        path.write_text(original + "\n  loader:\n    runs-on: ubuntu-latest\n    steps:\n"
                        "      - uses: ./.github/actions/build-tools\n"
                        "      - run: docker compose -f a.yml up -d --no-build\n")
        self.assertEqual(build_tools.check(self.root), [])

    def test_pull_request_runs_cannot_write_caches(self):
        trusted = "save-if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}"
        path = self.root / ".github/workflows/ci.yml"
        original = path.read_text()
        self.assertIn(trusted, original)
        for replacement in ["save-if: true", "save-if: ${{ github.ref == 'refs/heads/main' }}"]:
            with self.subTest(replacement=replacement):
                path.write_text(original.replace(trusted, replacement, 1))
                self.rejects("saved only from main pushes")
        path.write_text(original.replace("\n        with:\n          " + trusted, "", 1))
        self.rejects("saved only from main pushes")
        # Restoring without ever saving is allowed; only the literal never-save is.
        path.write_text(original.replace(trusted, "save-if: false", 1))
        self.assertEqual(build_tools.check(self.root), [])
        for replacement in ["save-if: ${{ false }}", "save-if: 'no'", "save-if: ''"]:
            with self.subTest(replacement=replacement):
                path.write_text(original.replace(trusted, replacement, 1))
                self.rejects("saved only from main pushes")
        for step in ["      - uses: actions/cache@" + "c" * 40 + "\n        with:\n          path: x\n          key: y\n",
                     "      - uses: actions/cache/save@" + "c" * 40 + "\n        with:\n          path: x\n          key: y\n",
                     "      - uses: docker/build-push-action@" + "c" * 40 + "\n        with:\n          cache-to: type=gha\n"]:
            with self.subTest(step=step.split("@")[0]):
                path.write_text(original + "\n  writer:\n    runs-on: ubuntu-latest\n    steps:\n"
                                "      - uses: ./.github/actions/build-tools\n"
                                "      - uses: ./.github/actions/buildx\n" + step)
                self.rejects("pull request jobs may")
        path.write_text(original)
        # A composite action runs inside pull request jobs as well.
        action = self.root / ".github/actions/buildx/action.yml"
        action.write_text(action.read_text() + "    - uses: actions/cache@" + "c" * 40 + "\n")
        self.rejects("pull request jobs may only restore caches")

    def add_pull_request_job(self, steps, prefix="      - uses: ./.github/actions/build-tools\n"
                                                "      - uses: ./.github/actions/buildx\n"):
        path = self.root / ".github/workflows/ci.yml"
        path.write_text(self.ci + "\n  writer:\n    runs-on: ubuntu-latest\n    steps:\n" + prefix + steps)

    @property
    def ci(self):
        if not hasattr(self, "_ci"):
            self._ci = (self.root / ".github/workflows/ci.yml").read_text()
        return self._ci

    def test_cache_writes_are_found_whatever_the_case_of_the_action_or_input(self):
        pin = "@" + "c" * 40
        for step, fragment in [
                ("      - uses: Actions/cache" + pin + "\n        with:\n          path: x\n          key: y\n",
                 "may only restore caches"),
                ("      - uses: ACTIONS/CACHE/SAVE" + pin + "\n        with:\n          path: x\n          key: y\n",
                 "may only restore caches"),
                ("      - uses: swatinem/rust-cache" + pin + "\n", "saved only from main pushes"),
                ("      - uses: SWATINEM/Rust-Cache" + pin + "\n        with:\n          save-if: true\n",
                 "saved only from main pushes"),
                ("      - uses: Docker/Build-Push-Action" + pin + "\n        with:\n          Cache-To: type=gha\n",
                 "image build caches"),
                ("      - uses: Actions/Setup-Node" + pin + "\n        with:\n          Cache: npm\n",
                 "setup actions may not save caches")]:
            with self.subTest(step=step.split("@")[0].strip()):
                self.add_pull_request_job(step)
                self.rejects(fragment)
        # Two spellings of one input are one input to GitHub: neither may hide the other.
        trusted = build_tools.TRUSTED_CACHE_WRITE
        self.add_pull_request_job("      - uses: Swatinem/rust-cache" + pin + "\n        with:\n"
                                  f"          save-if: {trusted}\n          Save-If: true\n")
        self.rejects("inputs may not differ only in case")

    def test_rust_cache_saves_unless_save_if_is_the_main_push_expression(self):
        pin = "@" + "c" * 40
        # An absent save-if means save, for every spelling of the action.
        for name in ["Swatinem/rust-cache", "swatinem/rust-cache"]:
            for inputs in ["", "        with:\n          workspaces: .\n"]:
                with self.subTest(name=name, inputs=inputs):
                    self.add_pull_request_job(f"      - uses: {name}{pin}\n" + inputs)
                    self.rejects("saved only from main pushes")
        for condition in ["${{ github.event_name == 'push' }}", "${{ github.ref == 'refs/heads/main' }}",
                          "${{ github.event_name == 'pull_request' }}", "${{ always() }}", "'true'", "False",
                          "${{ github.event_name=='push' && github.ref=='refs/heads/main' }}",
                          "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' || true }}"]:
            with self.subTest(condition=condition):
                self.add_pull_request_job(f"      - uses: swatinem/rust-cache{pin}\n        with:\n"
                                          f"          save-if: {condition}\n")
                self.rejects("saved only from main pushes")
        for condition in [build_tools.TRUSTED_CACHE_WRITE, "false"]:
            with self.subTest(condition=condition):
                self.add_pull_request_job(f"      - uses: swatinem/rust-cache{pin}\n        with:\n"
                                          f"          save-if: {condition}\n")
                self.assertEqual(build_tools.check(self.root), [])

    def test_run_commands_cannot_export_image_build_caches(self):
        for step in ["      - run: docker buildx build --cache-to type=gha,mode=max -t x .\n",
                     "      - run: docker buildx build --cache-from type=gha --CACHE-TO=type=local,dest=c .\n",
                     "      - run: docker buildx bake --set '*.cache-to=type=gha'\n",
                     "      - run: docker buildx build $FLAGS .\n        env:\n          FLAGS: --cache-to=type=gha\n",
                     "      - uses: docker/bake-action@" + "c" * 40 + "\n        with:\n          set: '*.cache-to=type=gha'\n"]:
            with self.subTest(step=step):
                self.add_pull_request_job(step)
                self.rejects("may not export image build caches")
        # Reading a build cache writes nothing.
        self.add_pull_request_job("      - run: docker buildx build --cache-from type=gha -t x .\n")
        self.assertEqual(build_tools.check(self.root), [])
        # A composite action runs inside pull request jobs as well.
        self.add_pull_request_job("")
        action = self.root / ".github/actions/buildx/action.yml"
        action.write_text(action.read_text() + "    - shell: bash\n      run: docker buildx build --cache-to type=gha .\n")
        self.rejects("buildx: pull request jobs may not export image build caches")

    def test_setup_actions_cannot_save_caches_in_pull_requests(self):
        composite = ".github/actions/build-tools/action.yml"
        for old, new in [("python-version: '3.13.15'", "python-version: '3.13.15'\n        cache: pip"),
                         ("node-version-file: .node-version", "node-version-file: .node-version\n        cache: npm"),
                         ("node-version-file: .node-version", "node-version-file: .node-version\n        cache: ''")]:
            with self.subTest(new=new.split("\n")[-1].strip()):
                original = (self.root / composite).read_text()
                self.replace(composite, old, new)
                self.rejects("build-tools: setup actions may not save caches in pull request jobs")
                (self.root / composite).write_text(original)
        pin = "@" + "c" * 40
        for step in ["      - uses: actions/setup-java" + pin + "\n        with:\n          cache: gradle\n",
                     "      - uses: actions/setup-dotnet" + pin + "\n        with:\n          cache: true\n",
                     "      - uses: actions/setup-python" + pin + "\n        with:\n          cache: ${{ github.event_name == 'push' && 'pip' || '' }}\n",
                     # setup-go saves its module cache unless told not to.
                     "      - uses: actions/setup-go" + pin + "\n        with:\n          go-version: '1.25'\n",
                     "      - uses: actions/setup-go" + pin + "\n"]:
            with self.subTest(step=step.split("@")[0].strip()):
                self.add_pull_request_job(step)
                self.rejects("setup actions may not save caches")
        self.add_pull_request_job("      - uses: actions/setup-go" + pin + "\n        with:\n          cache: false\n")
        self.assertFalse([e for e in build_tools.check(self.root) if "setup actions may not save" in e])

    def test_reusable_workflow_calls_must_be_gated_to_main_pushes(self):
        call = "  image-candidate:\n    if: github.event_name == 'push'\n"
        self.assertIn(call, self.ci)
        path = self.root / ".github/workflows/ci.yml"
        for gate in ["", "    if: ${{ always() }}\n", "    if: github.event_name != 'pull_request'\n",
                     "    if: github.ref == 'refs/heads/main'\n", "    if: github.event_name == 'push' || true\n"]:
            with self.subTest(gate=gate):
                path.write_text(self.ci.replace(call, "  image-candidate:\n" + gate, 1))
                self.rejects("ci.yml/image-candidate: reusable workflows may be called from pull request workflows only on pushes to main")
        # The same gate inside an expression is the same gate.
        path.write_text(self.ci.replace(call, "  image-candidate:\n    if: ${{ github.event_name == 'push' }}\n", 1))
        self.assertEqual(build_tools.check(self.root), [])
        # A push-only call is accepted only for a workflow of ours that writes
        # no cache on a tag push either.
        called = self.root / ".github/workflows/publish-image.yml"
        original = called.read_text()
        buildx = "      - name: Set up verified Buildx and pinned BuildKit\n        uses: ./.github/actions/buildx\n"
        self.assertIn(buildx, original)
        path.write_text(self.ci)
        called.write_text(original.replace(buildx, buildx + "      - uses: Swatinem/rust-cache@" + "c" * 40 + "\n", 1))
        self.rejects("ci.yml/image-candidate -> .github/workflows/publish-image.yml/build: Rust caches may be saved only from main pushes")
        called.write_text(original)
        remote = "\n  remote:\n    {gate}\n    uses: octo/workflows/.github/workflows/build.yml@" + "c" * 40 + "\n"
        path.write_text(self.ci + remote.format(gate="if: github.event_name == 'push'"))
        self.rejects("ci.yml/remote: reusable workflows may be called")
        path.write_text(self.ci + "\n  again:\n    uses: ./.github/workflows/publish-image.yml\n")
        self.rejects("ci.yml/again: reusable workflows may be called")
        path.write_text(self.ci + remote.format(gate="if: " + build_tools.TRUSTED_CACHE_WRITE))
        self.assertEqual(build_tools.check(self.root), [])

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

    def test_transport_guard_or_fixtures_cannot_be_removed(self):
        for command in ["bash scripts/check-egress-only.sh", "python scripts/transport_guard.py check", "cargo test --locked --example transport_guard", "test_transport_guard.py"]:
            with self.subTest(command=command):
                path = self.root / ".github/workflows/ci.yml"
                original = path.read_text()
                self.replace(".github/workflows/ci.yml", command, "echo skipped")
                self.rejects("Transport ownership must retain")
                path.write_text(original)

    def test_cargo_policy_tool_requires_exact_version_and_checksum(self):
        self.replace("build-tools.json", '"cargo_deny": "0.20.2"', '"cargo_deny": "latest"')
        self.rejects("exact version")

    def test_promtool_requires_exact_version_and_reviewed_checksum(self):
        original = (self.root / "build-tools.json").read_text()
        for key, value, message in [("promtool", "latest", "exact version"),
                                    ("promtool_linux_amd64_sha256", "missing", "reviewed checksum")]:
            with self.subTest(key=key):
                data = json.loads(original)
                data[key] = value
                (self.root / "build-tools.json").write_text(json.dumps(data))
                self.rejects(message)

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
