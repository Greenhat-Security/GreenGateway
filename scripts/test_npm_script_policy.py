"""Exercise the pinned npm with disposable local tarballs; no registry or hooks from real dependencies."""
import base64
import hashlib
import gzip
import functools
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NpmLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if not cls.npm:
            raise RuntimeError("Pinned npm must be on PATH")
        for tool, pin in [(shutil.which("node"), ".node-version"), (cls.npm, ".npm-version")]:
            actual = subprocess.check_output([tool, "--version"], text=True).strip().removeprefix("v")
            if actual != (ROOT / pin).read_text().strip():
                raise RuntimeError(f"{tool}: unexpected version {actual}")

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="ggw-npm-policy-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        # Isolate developer npm preferences; fixtures must exercise strict mode.
        self.env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")}
        self.env.update({"CI": "true", "npm_config_userconfig": str(self.root / "user.npmrc"),
                         "npm_config_globalconfig": str(self.root / "global.npmrc")})
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(self.root))
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        (self.root / ".npmrc").write_text("strict-allow-scripts=true\naudit=false\nfund=false\n")

    def project(self, decision=None, version="1.0.0", policy_spec=None):
        filename = f"marker-{version}.tgz"
        spec = f"{self.url}/{filename}"
        package = {"name": "ggw-policy-marker", "version": version,
                   "scripts": {"postinstall": "node marker.cjs"}}
        with tarfile.open(self.root / filename, "w:gz") as archive:
            for name, data in {
                "package.json": json.dumps(package).encode(),
                "marker.cjs": b"require('node:fs').writeFileSync('executed.txt', 'fixture only')",
            }.items():
                member = tarfile.TarInfo(f"package/{name}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        integrity = "sha512-" + base64.b64encode(hashlib.sha512((self.root / filename).read_bytes()).digest()).decode()
        manifest = {"name": "policy-fixture", "version": "1.0.0", "private": True,
                    "dependencies": {package["name"]: spec},
                    "scripts": {"build": "node build.cjs"}}
        if decision is not None:
            manifest["allowScripts"] = {f"{self.url}/{policy_spec}" if policy_spec else spec: decision}
        (self.root / "package.json").write_text(json.dumps(manifest))
        (self.root / "build.cjs").write_text("require('node:fs').writeFileSync('built.txt', 'intentional build')")
        lock = {"name": manifest["name"], "version": "1.0.0", "lockfileVersion": 3,
                "requires": True, "packages": {
                    "": {"name": manifest["name"], "version": "1.0.0", "dependencies": manifest["dependencies"]},
                    "node_modules/ggw-policy-marker": {"version": version, "resolved": spec,
                        "integrity": integrity, "hasInstallScript": True}}}
        (self.root / "package-lock.json").write_text(json.dumps(lock))

    def npm_run(self, *args):
        return subprocess.run([self.npm, *args, "--registry=" + self.url], cwd=self.root, env=self.env,
                              text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=60)

    def marker_exists(self):
        return (self.root / "node_modules/ggw-policy-marker/executed.txt").exists()

    def test_unreviewed_script_fails_before_execution(self):
        self.project()
        result = self.npm_run("ci")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ESTRICTALLOWSCRIPTS", result.stderr)
        self.assertFalse(self.marker_exists())

    def test_explicit_denial_skips_hook_but_intentional_build_works(self):
        self.project(False)
        result = self.npm_run("ci")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.marker_exists())
        result = self.npm_run("run", "build")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / "built.txt").exists())

    def test_reviewed_resolved_identity_can_run(self):
        self.project(True)
        result = self.npm_run("ci")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.marker_exists())

    def test_changed_tarball_bytes_cannot_use_an_existing_approval(self):
        self.project(True)
        archive = self.root / "marker-1.0.0.tgz"
        payload = gzip.decompress(archive.read_bytes()).replace(b"fixture only", b"fixture edit")
        archive.write_bytes(gzip.compress(payload, mtime=0))
        result = self.npm_run("ci", "--fetch-retries=0")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("EINTEGRITY", result.stderr)
        self.assertFalse(self.marker_exists())

    def test_changed_resolved_identity_requires_new_review(self):
        self.project(True, version="1.0.1", policy_spec="marker-1.0.0.tgz")
        result = self.npm_run("ci")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ESTRICTALLOWSCRIPTS", result.stderr)
        self.assertFalse(self.marker_exists())


if __name__ == "__main__":
    unittest.main()
