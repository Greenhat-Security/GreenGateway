"""Regressions for the operator-client pin in scripts/check-egress-only.sh (issue #242).

Each case runs the unmodified script in a scratch git repository that holds the
shipped copies of the files it reads, with ggctl/src/remote.rs changed. A fake
`cargo` answers the HTTP/2 feature query with http2 off, so nothing is built or
fetched, and no fixture opens a connection.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = "scripts/check-egress-only.sh"
OPERATOR_CLIENT = "ggctl/src/remote.rs"
# Every other file the script reads: the egress boundary and its MCP factory, and the two h2 owners.
FIXTURE_FILES = (SCRIPT, OPERATOR_CLIENT, "gateway/src/egress.rs", "gateway/src/egress/grpc.rs",
                 "gateway/src/proxy/grpc/listen.rs")
FAKE_CARGO = """#!/bin/sh
printf '%s\\n' 'ggctl v0.1.0 | default' 'hyper-util v0.1.0 | client,tokio' 'axum v0.8.0 | json,tokio' \\
    'reqwest v0.13.2 | json,rustls,stream'
"""
BUILDER_LINE = "    reqwest::Client::builder()\n"
ONE_CLIENT = "must build exactly one client, in admin_http_client()"
DEFAULT_TRAIT = "uses the Default trait"


def appended(snippet):
    return lambda source: source + "\n" + snippet


class OperatorClientTests(unittest.TestCase):
    def run_guard(self, change=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in FIXTURE_FILES:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                source = (ROOT / name).read_bytes().replace(b"\r\n", b"\n").decode("utf-8")
                if name == OPERATOR_CLIENT and change:
                    changed = change(source)
                    self.assertNotEqual(changed, source, "the change did not apply")
                    source = changed
                target.write_bytes(source.encode("utf-8"))
            cargo = root / "fake-bin" / "cargo"
            cargo.parent.mkdir()
            cargo.write_text(FAKE_CARGO, encoding="utf-8", newline="\n")
            cargo.chmod(0o755)
            env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
            env["PATH"] = str(cargo.parent) + os.pathsep + env.get("PATH", "")
            for command in (["init", "-q"], ["-c", "core.autocrlf=false", "add", "--", *FIXTURE_FILES]):
                subprocess.run(["git", *command], cwd=root, env=env, check=True, capture_output=True)
            result = subprocess.run(["sh", SCRIPT], cwd=root, env=env, capture_output=True, text=True, timeout=120)
            return result.returncode, result.stdout + result.stderr

    def test_the_shipped_operator_client_passes(self):
        for name, change in (("unchanged", None),
                             ("a clone of the one client is not a construction",
                              appended("fn same_client(client: &AdminClient) -> reqwest::Client {\n"
                                       "    client.http.clone()\n}\n"))):
            with self.subTest(name):
                code, output = self.run_guard(change)
                self.assertEqual(code, 0, output)
                self.assertIn("egress-only check passed", output)

    def test_every_second_client_is_refused(self):
        cases = (
            ("Client::default()", ONE_CLIENT,
             appended("fn spare_client() -> reqwest::Client {\n    reqwest::Client::default()\n}\n")),
            ("ClientBuilder::default()", ONE_CLIENT,
             appended("fn spare_client() -> Result<reqwest::Client, reqwest::Error> {\n"
                      "    reqwest::ClientBuilder::default().build()\n}\n")),
            ("reqwest::get builds a default client per call", ONE_CLIENT,
             appended("async fn fetch(url: &str) -> Result<reqwest::Response, reqwest::Error> {\n"
                      "    reqwest::get(url).await\n}\n")),
            ("a qualified path", ONE_CLIENT,
             appended("fn spare_client() -> reqwest::Client {\n    <reqwest::Client>::new()\n}\n")),
            ("two constructions on one line", ONE_CLIENT,
             lambda source: source.replace(BUILDER_LINE, "    let _spare = reqwest::Client::new(); "
                                                         + BUILDER_LINE.lstrip(), 1)),
            ("a renamed import", "imports from reqwest",
             appended("use reqwest::Client as Http;\n\nfn spare_client() -> Http {\n    Http::new()\n}\n")),
            ("a renamed free function", "imports from reqwest",
             appended("use reqwest::get as fetch;\n")),
            ("a type alias", "aliases a reqwest client type",
             appended("type Http = reqwest::Client;\n\nfn spare_client() -> Http {\n    Http::new()\n}\n")),
            ("derive(Default) on a struct holding a client", DEFAULT_TRAIT,
             appended("#[derive(Default)]\nstruct Spare {\n    http: reqwest::Client,\n}\n")),
            ("Default::default()", DEFAULT_TRAIT,
             appended("fn spare_client() -> reqwest::Client {\n    Default::default()\n}\n")),
            ("unwrap_or_default()", DEFAULT_TRAIT,
             appended("fn spare_client(client: Option<reqwest::Client>) -> reqwest::Client {\n"
                      "    client.unwrap_or_default()\n}\n")),
            ("mem::take", DEFAULT_TRAIT,
             appended("fn take_client(client: &mut AdminClient) -> reqwest::Client {\n"
                      "    std::mem::take(&mut client.http)\n}\n")),
        )
        for name, problem, change in cases:
            with self.subTest(name):
                code, output = self.run_guard(change)
                self.assertEqual(code, 1, output)
                self.assertIn("the operator CLI client must keep its reviewed transport properties", output)
                self.assertIn(f"{OPERATOR_CLIENT} {problem}", output)


if __name__ == "__main__":
    unittest.main()
