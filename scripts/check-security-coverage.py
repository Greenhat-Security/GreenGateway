#!/usr/bin/env python3
"""Enforce per-file line and branch floors from cargo llvm-cov JSON.

Each floor is a percentage of the file's instrumented lines or branches, so it
is only comparable while that denominator is: a toolchain, linker or build
setting that drops the coverage records of uncovered code would raise the
percentage without any new test. Every entry therefore also records the
smallest line and branch counts the file may report. A smaller count fails the
gate; a larger one (new code) passes.

Several reports (one per measured package) are checked as one: every gated file
must appear in exactly one of them, so a file measured twice fails rather than
passing on its better run.
"""
import argparse
import json
import math
from pathlib import Path

REQUIREMENTS = '.github/security-coverage.json'
# The percentage floor and the recorded denominator for each metric.
MINIMUM_COUNT = {'lines': 'min_line_count', 'branches': 'min_branch_count'}


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def check(report, requirements):
    files = [entry for unit in report.get('data', []) for entry in unit.get('files', [])]
    errors = []
    for path, limits in requirements.items():
        matches = [entry for entry in files
                   if (filename := entry.get('filename', '').replace('\\', '/')) == path
                   or filename.endswith('/' + path)]
        if len(matches) != 1:
            errors.append(f'{path}: expected exactly one instrumented source file, found {len(matches)}')
            continue
        summary = matches[0].get('summary', {})
        for metric, key in MINIMUM_COUNT.items():
            required, minimum = limits.get(metric), limits.get(key)
            if not number(required) or not 0 < required <= 100:
                errors.append(f'{path}: {REQUIREMENTS} must give a {metric} floor between 0 and 100%')
                continue
            if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum <= 0:
                errors.append(f'{path}: {REQUIREMENTS} must record "{key}", the positive integer '
                              f'{metric} count this file was measured with')
                continue
            value = summary.get(metric, {})
            count, covered = value.get('count', 0), value.get('covered', -1)
            if not number(count) or not number(covered) or not (0 <= covered <= count) or count <= 0:
                errors.append(f'{path}: missing or invalid {metric} instrumentation')
                continue
            passed = True
            if count < minimum:
                passed = False
                errors.append(
                    f'{path}: the instrumented {metric} denominator shrank: {count} {metric}, below the '
                    f'recorded minimum of {minimum}, so the {metric} percentage no longer measures what '
                    f'its floor was set against. '
                    f'If the toolchain, linker or a build setting changed, find out why coverage records '
                    f'were dropped and do not change the minimum. Only when code was really removed '
                    f'from this file, set "{key}" to {count} in {REQUIREMENTS} in the same change '
                    f'and say which code was removed.')
            percent = 100 * covered / count
            if not math.isfinite(percent) or percent < required:
                passed = False
                errors.append(f'{path}: {metric} {percent:.2f}% ({covered}/{count}) is below {required}%')
            if passed:
                print(f'{path}: {metric} {percent:.2f}% ({covered}/{count}) >= {required}%; '
                      f'count {count} >= recorded minimum {minimum}')
    if not requirements:
        errors.append('coverage requirements must not be empty')
    return errors


def merged(reports):
    """The files of several cargo llvm-cov JSON reports, as one report."""
    return {'data': [unit for report in reports for unit in report.get('data', [])]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('reports', type=Path, nargs='+', metavar='report',
                        help='a cargo llvm-cov JSON report; give one per measured package')
    parser.add_argument('--requirements', type=Path, default=Path(__file__).resolve().parents[1] / REQUIREMENTS)
    args = parser.parse_args()
    report = merged([json.loads(path.read_text(encoding='utf-8')) for path in args.reports])
    errors = check(report, json.loads(args.requirements.read_text(encoding='utf-8')))
    if errors:
        raise SystemExit('\n'.join(errors))
