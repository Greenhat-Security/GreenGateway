#!/usr/bin/env python3
"""Validate successful CI test evidence and retain only bounded report fields."""
import argparse
import json
import math
from pathlib import Path


def read_json(path):
    try:
        document = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        # Report contents can contain fixture credentials or raw errors.
        raise ValueError('required JSON evidence is missing, empty or invalid') from None
    if not isinstance(document, dict):
        raise ValueError('required JSON evidence must be an object')
    return document


def count(value):
    if type(value) is not int or value < 0:
        raise ValueError('evidence counts must be nonnegative integers')
    return value


def playwright_summary(report):
    counts = {key: count(report.get('stats', {}).get(key))
              for key in ('expected', 'skipped', 'unexpected', 'flaky')}
    tests = []

    def collect(suites):
        for suite in suites:
            for spec in suite.get('specs', []):
                tests.extend(spec.get('tests', []))
            collect(suite.get('suites', []))

    collect(report.get('suites', []))
    actual = {key: 0 for key in counts}
    for test in tests:
        status = test.get('status')
        if status not in actual or not test.get('results'):
            raise ValueError('Playwright evidence has missing test outcomes')
        actual[status] += 1
    if actual != counts or counts['expected'] + counts['flaky'] == 0:
        raise ValueError('Playwright evidence has inconsistent or empty executed test counts')
    if counts['unexpected'] or report.get('errors'):
        raise ValueError('Playwright evidence reports a failed run')
    return {'schema_version': 1, 'producer': 'playwright', 'counts': counts}


def screenshot_count(directory):
    files = sorted(directory.rglob('*.png'))
    if not files:
        raise ValueError('required screenshot group is missing or empty')
    for path in files:
        data = path.read_bytes()
        # Reject empty, non-PNG and truncated files without installing an image
        # library. Pixel/layout assertions remain in the browser tests.
        if (len(data) < 45 or not data.startswith(b'\x89PNG\r\n\x1a\n')
                or data[12:16] != b'IHDR' or data[-12:] != b'\x00\x00\x00\x00IEND\xaeB`\x82'):
            raise ValueError('required screenshot is empty or not a complete PNG')
    return len(files)


def stream_summary(report):
    configuration = report.get('configuration', {})
    result = report.get('result', {})
    requested, completed = count(configuration.get('requests')), count(result.get('completed'))
    if requested == 0 or completed != requested:
        raise ValueError('stream evidence did not complete the requested work')
    if (result.get('error_counts') != {} or result.get('unexpected_statuses') != []
            or result.get('assertion_failures') != []):
        raise ValueError('stream evidence reports failures or omits their results')
    statuses = result.get('status_counts', {})
    if (not statuses or any(not key.isdigit() or not 200 <= int(key) < 300 for key in statuses)
            or sum(count(value) for value in statuses.values()) != completed):
        raise ValueError('stream evidence has missing or unsuccessful response counts')
    duration = result.get('duration_ms')
    if type(duration) not in (int, float) or not math.isfinite(duration) or duration <= 0:
        raise ValueError('stream evidence has no positive measurement duration')
    # Do not copy source configuration, URLs, run IDs or error text.
    return {'schema_version': 1, 'producer': 'ci-stream', 'requested': requested,
            'completed': completed, 'duration_ms': duration, 'status_counts': statuses}


def validate(kind, source, destination, screenshots=None):
    report = read_json(source)
    try:
        summary = playwright_summary(report) if kind == 'playwright' else stream_summary(report)
        if screenshots is not None:
            summary['screenshots'] = screenshot_count(screenshots)
    except (AttributeError, KeyError, TypeError, OSError, RecursionError):
        raise ValueError('required evidence has an invalid structure') from None
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=('playwright', 'stream'))
    parser.add_argument('source', type=Path)
    parser.add_argument('summary', type=Path)
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    try:
        validate(args.kind, args.source, args.summary, args.screenshots)
    except ValueError as error:
        raise SystemExit(str(error)) from None
