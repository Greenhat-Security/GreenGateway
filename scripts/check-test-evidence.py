#!/usr/bin/env python3
"""Validate successful CI test evidence and retain only bounded report fields."""
import argparse
import json
import math
from pathlib import Path
import struct
import zlib


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


def test_outcome(test):
    """Reconcile attempts using the pinned Playwright reporter outcome rules."""
    statuses = {'passed', 'failed', 'timedOut', 'skipped', 'interrupted'}
    expected_status = test.get('expectedStatus')
    results = test.get('results')
    if expected_status not in statuses or not isinstance(results, list):
        raise ValueError('Playwright evidence has missing test outcomes')
    expected = unexpected = skipped = executed = 0
    for result in results:
        status = result.get('status') if isinstance(result, dict) else None
        if status not in statuses:
            raise ValueError('Playwright evidence has invalid attempt outcomes')
        if status == 'interrupted':
            raise ValueError('Playwright evidence reports an interrupted run')
        if status == 'skipped':
            skipped += expected_status == 'skipped'
        else:
            executed += 1
            if status == expected_status:
                expected += 1
            else:
                unexpected += 1
    # Playwright 1.63's computeTestCaseOutcome. Expected failures and a failed
    # attempt followed by an expected skip are legitimate reporter outcomes.
    if expected == 0 and unexpected == 0:
        outcome = 'skipped'
    elif unexpected == 0:
        outcome = 'expected'
    elif expected == 0 and skipped == 0:
        outcome = 'unexpected'
    else:
        outcome = 'flaky'
    return outcome, executed


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
    executed = 0
    for test in tests:
        outcome, attempts = test_outcome(test)
        if test.get('status') != outcome:
            raise ValueError('Playwright evidence has inconsistent test outcomes')
        actual[outcome] += 1
        executed += attempts
    if actual != counts or executed == 0:
        raise ValueError('Playwright evidence has inconsistent or empty executed test counts')
    if counts['unexpected'] or report.get('errors'):
        raise ValueError('Playwright evidence reports a failed run')
    return {'schema_version': 1, 'producer': 'playwright', 'counts': counts}


# These limits apply to individual CI screenshots, not application image input.
# Bound both file reads and decompression before allocating decoded scanlines.
MAX_PNG_BYTES = 32 * 1024 * 1024
MAX_PNG_DECODED_BYTES = 128 * 1024 * 1024
PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
PNG_ERROR = 'required screenshot is empty or not a complete PNG within evidence limits'


def png_rows(header):
    width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', header)
    depths = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
    if (not 0 < width < 2**31 or not 0 < height < 2**31
            or depth not in depths.get(color, ()) or compression != 0
            or filtering != 0 or interlace not in (0, 1)):
        raise ValueError(PNG_ERROR)
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    # Each nonempty Adam7 pass has its own scanlines and filter bytes.
    passes = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
              (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)) if interlace else ((0, 0, 1, 1),)
    rows = []
    for x, y, dx, dy in passes:
        columns = max(0, (width - x + dx - 1) // dx)
        lines = max(0, (height - y + dy - 1) // dy)
        if columns and lines:
            rows.append((lines, (columns * channels * depth + 7) // 8))
    if sum(lines * (stride + 1) for lines, stride in rows) > MAX_PNG_DECODED_BYTES:
        raise ValueError(PNG_ERROR)
    return rows, color, depth


def validate_png(data):
    if len(data) > MAX_PNG_BYTES or not data.startswith(PNG_SIGNATURE):
        raise ValueError(PNG_ERROR)
    offset = len(PNG_SIGNATURE)
    rows = None
    color = depth = None
    palette = ended_data = False
    compressed = []
    while offset < len(data):
        if len(data) - offset < 12:
            raise ValueError(PNG_ERROR)
        length = int.from_bytes(data[offset:offset + 4], 'big')
        kind = data[offset + 4:offset + 8]
        end = offset + 12 + length
        if (end > len(data) or any(not (65 <= c <= 90 or 97 <= c <= 122) for c in kind)
                or kind[2] & 32):
            raise ValueError(PNG_ERROR)
        payload = data[offset + 8:end - 4]
        checksum = int.from_bytes(data[end - 4:end], 'big')
        if zlib.crc32(payload, zlib.crc32(kind)) != checksum:
            raise ValueError(PNG_ERROR)
        if rows is None and kind != b'IHDR':
            raise ValueError(PNG_ERROR)
        if kind == b'IHDR':
            if rows is not None or length != 13:
                raise ValueError(PNG_ERROR)
            rows, color, depth = png_rows(payload)
        elif kind == b'PLTE':
            if (palette or compressed or color in (0, 4) or length == 0
                    or length % 3 or length > 768 or (color == 3 and length // 3 > 2**depth)):
                raise ValueError(PNG_ERROR)
            palette = True
        elif kind == b'IDAT':
            if ended_data or (color == 3 and not palette):
                raise ValueError(PNG_ERROR)
            compressed.append(payload)
        elif kind == b'IEND':
            if length or end != len(data) or not compressed:
                raise ValueError(PNG_ERROR)
            break
        elif not kind[0] & 32:
            # An unknown critical chunk cannot be safely interpreted.
            raise ValueError(PNG_ERROR)
        if compressed and kind != b'IDAT':
            ended_data = True
        offset = end
    else:
        raise ValueError(PNG_ERROR)
    expected = sum(lines * (stride + 1) for lines, stride in rows)
    decoder = zlib.decompressobj()
    try:
        pixels = decoder.decompress(b''.join(compressed), expected + 1)
    except zlib.error:
        raise ValueError(PNG_ERROR) from None
    if (len(pixels) != expected or not decoder.eof
            or decoder.unused_data or decoder.unconsumed_tail):
        raise ValueError(PNG_ERROR)
    offset = 0
    for lines, stride in rows:
        for _ in range(lines):
            if pixels[offset] > 4:
                raise ValueError(PNG_ERROR)
            offset += stride + 1


def screenshot_count(directory):
    files = sorted(directory.rglob('*.png'))
    if not files:
        raise ValueError('required screenshot group is missing or empty')
    for path in files:
        with path.open('rb') as source:
            data = source.read(MAX_PNG_BYTES + 1)
        validate_png(data)
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
