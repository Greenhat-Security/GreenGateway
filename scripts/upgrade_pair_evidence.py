#!/usr/bin/env python3
"""Verify issue #426's upgrade-pair evidence against the published support matrix.

`ha_rolling_upgrade`'s pair rows each write what they observed to
`<pair dir>/evidence/<row>.json` once every assertion of the row has passed,
beside the `manifest.json` that `scripts/build_upgrade_pair.py` wrote. This
script is the last step of the `ha-release-gate (ha_rolling_upgrade)` leg, and
the gate is the same three commands wherever it runs: build the pair, run the
suite, verify the evidence.

* The pin must be a qualified pair that the published matrix
  (`docs/deployment/upgrade-support-matrix.json`) lists, with the same schema
  point, operation and capability.
* The manifest must name the pinned commits, and each binary must still hash
  to what the build recorded: two distinct builds.
* Every evidence row the matrix names must exist, carry both binaries'
  identities and the build substitution exactly as the manifest records them,
  and match the observations the matrix publishes. A row the matrix does not
  name is refused, so the published matrix cannot fall behind the suite.

A row that was deleted, renamed or `#[ignore]`d leaves its evidence missing,
which fails here although the suite itself passed. On success the script
writes `summary.json` beside the manifest: the release evidence record naming
both builds, the gate's own commit, the pair's schema point and procedure,
and everything each row observed. It writes nothing on failure.

Matching is by subset. Every key the matrix states must be present with the
same value, recursively, and a list must have the same length with each item
matching in order. What the matrix leaves out (ETags, revision numbers, exit
codes) is carried into the summary without being judged.
"""
import argparse
import json
from pathlib import Path
import sys

import build_upgrade_pair as pair

MATRIX = pair.ROOT / "docs" / "deployment" / "upgrade-support-matrix.json"
SUMMARY = "summary.json"


class EvidenceError(Exception):
    pass


def load_json(path: Path, what: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise EvidenceError(f"cannot read {what} {path}: {error}") from error


def find_pair(matrix, pin: dict) -> dict:
    """The matrix's qualified pair for this pin, checked against it."""
    if not isinstance(matrix, dict) or matrix.get("schema") != 1:
        raise EvidenceError("the support matrix must be a schema 1 object")
    pairs = matrix.get("qualified_pairs")
    if not isinstance(pairs, list):
        raise EvidenceError("the support matrix lists no qualified_pairs")
    prepared = pin["prepared"]["commit"]
    successor = pin["successor"]["commit"]
    found = [entry for entry in pairs if isinstance(entry, dict)
             and entry.get("prepared") == prepared and entry.get("successor") == successor]
    if len(found) != 1:
        raise EvidenceError(
            f"the pin ({prepared} -> {successor}) is not exactly one qualified pair of the "
            "published support matrix; publish the pair before the gate can qualify it"
        )
    entry = found[0]
    for key, pinned in (("schema", pin.get("schema_version")), ("operation", pin.get("operation")),
                        ("capability", pin.get("capability"))):
        if entry.get(key) != pinned:
            raise EvidenceError(
                f"the published pair says {key} {entry.get(key)!r} but the pin says {pinned!r}"
            )
    evidence = entry.get("evidence")
    if not isinstance(evidence, dict) or not evidence:
        raise EvidenceError("the published pair names no evidence rows")
    return entry


def identities(manifest, pin: dict, pair_dir: Path) -> dict:
    """Each side's commit and re-hashed binary, as the manifest records them."""
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise EvidenceError("the pair manifest must be a schema 1 object")
    sides = {}
    root = pair_dir.resolve()
    for role in pair.ROLES:
        entry = manifest.get(role)
        if not isinstance(entry, dict):
            raise EvidenceError(f"the pair manifest has no {role} entry")
        commit = entry.get("commit")
        if commit != pin[role]["commit"]:
            raise EvidenceError(
                f"the {role} binary was built from {commit!r}, but the pin names "
                f"{pin[role]['commit']}; rebuild the pair"
            )
        binary = entry.get("binary")
        if not isinstance(binary, str):
            raise EvidenceError(f"the pair manifest names no {role} binary")
        path = (root / binary).resolve()
        if root not in path.parents:
            raise EvidenceError(f"the {role} binary {binary!r} is outside the pair directory")
        try:
            digest = pair.sha256(path)
        except OSError as error:
            raise EvidenceError(f"cannot hash the {role} binary {path}: {error}") from error
        if digest != entry.get("sha256"):
            raise EvidenceError(f"the {role} binary at {path} is not the one the build recorded")
        sides[role] = {"commit": commit, "binary_sha256": digest}
    if sides["prepared"]["binary_sha256"] == sides["successor"]["binary_sha256"]:
        raise EvidenceError("the two pinned builds are the same binary")
    substitution = manifest.get("substitution")
    if not isinstance(substitution, str) or not substitution:
        raise EvidenceError("the pair manifest states no build substitution")
    return {"sides": sides, "substitution": substitution}


def mismatch(expected, observed, at: str = "observed"):
    """The first place `observed` does not carry what `expected` states, or None."""
    if isinstance(expected, dict):
        if not isinstance(observed, dict):
            return f"{at} should be an object, and is {json.dumps(observed)}"
        for key, value in expected.items():
            if key not in observed:
                return f"{at} has no {key!r}"
            found = mismatch(value, observed[key], f"{at}.{key}")
            if found:
                return found
        return None
    if isinstance(expected, list):
        if not isinstance(observed, list) or len(observed) != len(expected):
            return f"{at} should be a list of {len(expected)}, and is {json.dumps(observed)}"
        for index, (value, item) in enumerate(zip(expected, observed)):
            found = mismatch(value, item, f"{at}[{index}]")
            if found:
                return found
        return None
    # `True == 1` in Python; the evidence is JSON, where they differ.
    if type(expected) is not type(observed) or expected != observed:
        return f"{at} should be {json.dumps(expected)}, and is {json.dumps(observed)}"
    return None


def verify(pair_dir: Path, pin_path: Path = pair.PIN, matrix_path: Path = MATRIX,
           gate_commit=None) -> dict:
    """Check the pair directory against the pin and the matrix; write and return the summary."""
    # A summary left by an earlier run must not outlive a refusal of this one.
    try:
        (pair_dir / SUMMARY).unlink(missing_ok=True)
    except OSError as error:
        raise EvidenceError(f"cannot remove the previous summary: {error}") from error
    if gate_commit is not None and not pair.COMMIT.fullmatch(gate_commit):
        raise EvidenceError("the gate commit must be one full lowercase commit SHA")
    try:
        pin = pair.load_pin(pin_path)
    except pair.PairError as error:
        raise EvidenceError(str(error)) from error
    entry = find_pair(load_json(matrix_path, "the support matrix"), pin)
    built = identities(load_json(pair_dir / "manifest.json", "the pair manifest"), pin, pair_dir)

    evidence_dir = pair_dir / "evidence"
    published = entry["evidence"]
    recorded = sorted(path.stem for path in evidence_dir.glob("*.json")) if evidence_dir.is_dir() else []
    unpublished = [row for row in recorded if row not in published]
    if unpublished:
        raise EvidenceError(
            f"the suite recorded {unpublished}, which the published matrix does not name; publish "
            "what the row proves before the gate counts it"
        )
    rows = {}
    for row, expected in published.items():
        path = evidence_dir / f"{row}.json"
        if not path.is_file():
            raise EvidenceError(
                f"the row {row} recorded no evidence: it did not run to completion, or was "
                "renamed, removed or ignored"
            )
        record = load_json(path, "the evidence")
        if not isinstance(record, dict) or record.get("schema") != 1 or record.get("issue") != 426:
            raise EvidenceError(f"{path} is not schema 1 issue #426 evidence")
        if record.get("row") != row:
            raise EvidenceError(f"{path} says it is the row {record.get('row')!r}")
        for role in pair.ROLES:
            if record.get(role) != built["sides"][role]:
                raise EvidenceError(
                    f"the row {row} ran a {role} binary other than the pair's: "
                    f"{json.dumps(record.get(role))}"
                )
        if record.get("build_substitution") != built["substitution"]:
            raise EvidenceError(f"the row {row} states a build substitution the manifest does not")
        found = mismatch(expected, record.get("observed"))
        if found:
            raise EvidenceError(f"the row {row} disagrees with the published matrix: {found}")
        rows[row] = record["observed"]

    summary = {
        "schema": 1,
        "issue": 426,
        "verdict": "qualified",
        "gate_commit": gate_commit,
        "pair": {
            "schema": entry["schema"],
            "procedure": entry.get("procedure"),
            "operation": entry["operation"],
            "capability": entry["capability"],
            "rollback_cutoff": entry.get("rollback_cutoff"),
            **built["sides"],
        },
        "build_substitution": built["substitution"],
        "rows": rows,
    }
    (pair_dir / SUMMARY).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8",
                                    newline="\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--pair-dir", required=True, type=Path,
                        help="the directory build_upgrade_pair.py --out wrote")
    parser.add_argument("--pin", default=pair.PIN, type=Path, help="the pair pin (default: %(default)s)")
    parser.add_argument("--matrix", default=MATRIX, type=Path,
                        help="the published support matrix (default: %(default)s)")
    parser.add_argument("--gate-commit", help="the commit whose suite produced the evidence")
    args = parser.parse_args()
    try:
        verify(args.pair_dir, args.pin, args.matrix, args.gate_commit)
    except EvidenceError as error:
        print(f"upgrade pair evidence: {error}", file=sys.stderr)
        return 1
    print(f"upgrade pair evidence: qualified; wrote {args.pair_dir / SUMMARY}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
