"""Promote the current run's checked candidate by digest, without rebuilding."""

import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import quote


def promote(environ):
    repository = environ.get("GITHUB_REPOSITORY", "")
    sha = environ.get("GITHUB_SHA", "")
    ref = environ.get("GITHUB_REF", "")
    digest = environ.get("CANDIDATE_DIGEST", "")
    if environ.get("GITHUB_EVENT_NAME") != "push":
        raise ValueError("only push runs may promote images")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        raise ValueError("invalid repository")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid checked commit")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("missing or invalid candidate digest")
    version = re.fullmatch(r"refs/tags/(v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))", ref)
    if ref != "refs/heads/main" and version is None:
        raise ValueError("only main and vMAJOR.MINOR.PATCH refs may promote images")

    # This resolves annotated tags to their commit too. Never check out the
    # moving ref: the candidate and this script come from the checked SHA.
    current = subprocess.run(
        ["gh", "api", f"repos/{repository}/commits/{quote(ref, safe='')}", "--jq", ".sha"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", current):
        raise ValueError("source ref did not resolve to a commit")
    if current != sha:
        print(f"Source ref {ref} moved; leaving this candidate unpromoted.")
        return False

    image = f"ghcr.io/{repository.lower()}"
    tags = [f"{image}:{sha}"]
    if version is None:
        tags.append(f"{image}:latest")
    else:
        tags.extend([f"{image}:{version[1]}", f"{image}:{version[1][1:]}"])
    command = ["docker", "buildx", "imagetools", "create", "--prefer-index=false"]
    for tag in tags:
        command.extend(["--tag", tag])
    # The unique candidate tag is deliberately not consulted here. The digest
    # output from our build job identifies the exact artifact being promoted.
    command.append(f"{image}@{digest}")
    subprocess.run(command, check=True)
    print(f"Promoted checked commit {sha}: {image}@{digest}")
    if summary := environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as output:
            output.write(f"Checked commit: `{sha}`\n\nImage: `{image}@{digest}`\n\n")
            output.write("Published tags: " + ", ".join(f"`{tag}`" for tag in tags) + "\n")
    return True


if __name__ == "__main__":
    try:
        promote(os.environ)
    except (ValueError, subprocess.CalledProcessError) as error:
        print(f"Image promotion failed: {error}", file=sys.stderr)
        sys.exit(1)
