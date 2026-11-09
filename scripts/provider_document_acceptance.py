"""Prepare the pinned Slack and Gmail snapshots and run their catalog acceptance tests."""
import argparse
from hashlib import sha256
from http.client import HTTPException
import os
from pathlib import Path
import subprocess
import sys
from tempfile import NamedTemporaryFile
from urllib.request import build_opener, HTTPRedirectHandler

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "target" / "provider-documents"
MAX_BYTES = 2 * 1024 * 1024
SNAPSHOTS = {
    "GGW_SLACK_SWAGGER_FILE": (
        "https://raw.githubusercontent.com/slackapi/slack-api-specs/"
        "dfea73e06d146c368d7f94b52ac90796dc4e27e1/web-api/slack_web_openapi_v2.json",
        "742a5c977180a829df8767cf57bc417d99b3713583aee83741efb9c08ca731e7",
    ),
    "GGW_GMAIL_DISCOVERY_FILE": (
        "https://raw.githubusercontent.com/googleapis/discovery-artifact-manager/"
        "b54f57986191f04556a56ce2d90e8b1fe5dd8a0f/discoveries/gmail.v1.json",
        "f651441dcc942f428d92768e8b20c94a28ff82bf485b79872d9eef267a894225",
    ),
}


class PinnedSource(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError(f"unexpected redirect from pinned source {req.full_url}")


def verified_bytes(stream, expected, label):
    data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{label}: exceeds {MAX_BYTES} bytes")
    if sha256(data).hexdigest() != expected:
        raise ValueError(f"{label}: SHA-256 differs from the pinned snapshot")
    return data


def fixture_path(variable, url, digest, fetch):
    supplied = os.environ.get(variable)
    path = Path(supplied).resolve() if supplied else CACHE / url.rsplit("/", 1)[1]
    try:
        with path.open("rb") as stream:
            verified_bytes(stream, digest, path)
        return path
    except FileNotFoundError:
        if supplied:
            raise
        if not fetch:
            raise ValueError(f"set {variable} or run with --fetch to populate {CACHE}") from None
    except ValueError:
        if supplied or not fetch:
            raise

    with build_opener(PinnedSource()).open(url, timeout=45) as response:
        data = verified_bytes(response, digest, url)
    CACHE.mkdir(parents=True, exist_ok=True)
    temp = NamedTemporaryFile(dir=CACHE, delete=False)
    temporary = Path(temp.name)
    try:
        with temp:
            temp.write(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fetch", action="store_true",
                        help="download missing or invalid cache entries from their pinned HTTPS sources")
    parser.add_argument("--verify-only", action="store_true",
                        help="verify the documents and print their paths without running Cargo")
    args = parser.parse_args()
    env = os.environ.copy()
    for variable, (url, digest) in SNAPSHOTS.items():
        path = fixture_path(variable, url, digest, args.fetch)
        env[variable] = str(path)
        print(f"{variable}={path}", flush=True)
    if args.verify_only:
        return 0
    return subprocess.run([
        "cargo", "test", "--locked", "-p", "gateway", "--bin", "gateway",
        "pinned_provider_document_", "--", "--ignored",
    ], cwd=ROOT, env=env).returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, HTTPException) as error:
        sys.exit(str(error))
