#!/usr/bin/env python3
"""Enforce per-file line and branch floors from cargo llvm-cov JSON."""
import argparse
import json
import math
from pathlib import Path


def check(report, requirements):
    files = [entry for unit in report.get('data', []) for entry in unit.get('files', [])]
    errors = []
    for path, limits in requirements.items():
        matches = [entry for entry in files if entry.get('filename', '').replace('\\', '/').endswith('/' + path)]
        if len(matches) != 1:
            errors.append(f'{path}: expected exactly one instrumented source file, found {len(matches)}')
            continue
        summary = matches[0].get('summary', {})
        for metric in ('lines', 'branches'):
            value = summary.get(metric, {})
            count, covered = value.get('count', 0), value.get('covered', -1)
            if not isinstance(count, (int, float)) or not isinstance(covered, (int, float)) or not (0 <= covered <= count) or count <= 0:
                errors.append(f'{path}: missing or invalid {metric} instrumentation')
                continue
            percent = 100 * covered / count
            required = limits[metric]
            if not math.isfinite(percent) or percent < required:
                errors.append(f'{path}: {metric} {percent:.2f}% is below {required}%')
            else:
                print(f'{path}: {metric} {percent:.2f}% >= {required}%')
    if not requirements:
        errors.append('coverage requirements must not be empty')
    return errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--requirements', type=Path, default=Path(__file__).resolve().parents[1] / '.github/security-coverage.json')
    args = parser.parse_args()
    errors = check(json.loads(args.report.read_text(encoding='utf-8')), json.loads(args.requirements.read_text(encoding='utf-8')))
    if errors:
        raise SystemExit('\n'.join(errors))
