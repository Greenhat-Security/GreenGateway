#!/usr/bin/env python3
"""Validate successful CI test evidence and retain only bounded report fields."""
import argparse
import json
import math
from pathlib import Path
import re
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


# The #439 capacity matrix (gateway/tests/ha/capacity.rs). The producer
# sanitizes its report; this rebuilds it from the fields named here, so a field
# the producer starts emitting by mistake never reaches the artifact, and fails
# unless every declared cell produced complete evidence. Numbers are checked
# for shape and consistency only: there are no capacity budgets to compare with.
CAPACITY_OPERATION_CLASSES = ('revision_check', 'credential_check', 'rate_limit', 'execution_lease',
                              'security_state_read', 'control_plane_write', 'maintenance')
CAPACITY_ERROR_CLASSES = ('none', 'unavailable', 'timeout', 'conflict', 'invalid_data',
                          'incompatible_schema', 'internal', 'cancelled')
CAPACITY_MIXES = {
    'jwt_proxy': {'kinds': ('jwt_proxy',),
                  'classes': ('rate_limit', 'credential_check', 'revision_check')},
    'mixed_credentials': {'kinds': ('jwt_proxy', 'service_token_proxy', 'admin_policy_read'),
                          'classes': ('rate_limit', 'credential_check', 'revision_check',
                                      'security_state_read')},
}
# Served, or refused because a dependency could not be consulted. Any other
# status is a harness or configuration failure, not a capacity result.
CAPACITY_STATUSES = ('200', '503')
CAPACITY_SPREADS = ('runtime_backends', 'active', 'idle', 'idle_in_transaction', 'lock_waiting',
                    'lwlock_waiting', 'io_waiting', 'ungranted_locks')
CAPACITY_COUNTERS = ('xact_commit', 'xact_rollback', 'deadlocks', 'blks_hit', 'blks_read',
                     'temp_files')
CAPACITY_METHOD = ('concurrency', 'measured_seconds', 'warmup_seconds', 'client_timeout_ms',
                   'sample_interval_ms')
CAPACITY_REPLICA_NAMES = 'abcdefgh'
MAX_CAPACITY_CELLS = 16
MAX_CAPACITY_POOL = 256
MIN_CAPACITY_SAMPLES = 3


def capacity_number(value, high=None):
    if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
            or (high is not None and value > high)):
        raise ValueError('capacity evidence numbers must be finite, nonnegative and in range')
    return value


def capacity_text(value, pattern):
    if type(value) is not str or not re.fullmatch(pattern, value):
        raise ValueError('capacity evidence carries an unrecognised name or label')
    return value


def capacity_choice(value, choices):
    if type(value) is not str or value not in choices:
        raise ValueError('capacity evidence carries an unrecognised name or label')
    return value


def capacity_latency(value):
    """Nearest-rank quantiles and the maximum of the same samples: exact, so ordered."""
    if value is None:
        return None
    latency = {key: capacity_number(value[key]) for key in ('p50_ms', 'p95_ms', 'p99_ms', 'max_ms')}
    if not latency['p50_ms'] <= latency['p95_ms'] <= latency['p99_ms'] <= latency['max_ms']:
        raise ValueError('capacity quantiles are out of order')
    return latency


def capacity_exporter_latency(value):
    """The exporter's summary quantiles for one acquisition series.

    metrics-exporter-prometheus renders a quantile below 1 as the
    representative of its DDSketch bucket (metrics-util's default summary,
    within 0.01 % of the true value) and quantile 1 as the exact maximum. A
    p99 in the maximum's bucket can therefore sit just above the maximum,
    and a series with one sample in the window renders p50 = p95 = p99
    above it. Only the sketch's own quantiles are ordered; the maximum is
    checked on its own.
    """
    latency = {key: capacity_number(value[key]) for key in ('p50_ms', 'p95_ms', 'p99_ms', 'max_ms')}
    if not latency['p50_ms'] <= latency['p95_ms'] <= latency['p99_ms']:
        raise ValueError('capacity quantiles are out of order')
    return latency


def capacity_statuses(value, total):
    if type(value) is not dict or any(key not in CAPACITY_STATUSES for key in value):
        raise ValueError('capacity evidence has a status a capacity run cannot produce')
    statuses = {key: count(value[key]) for key in CAPACITY_STATUSES if key in value}
    if sum(statuses.values()) > total:
        raise ValueError('capacity status counts exceed their requests')
    return statuses


def capacity_requests(requests, mix, method):
    completed = count(requests['completed'])
    timeouts, errors = count(requests['client_timeouts']), count(requests['client_errors'])
    statuses = capacity_statuses(requests['status_counts'], completed)
    if completed < method['concurrency'] or errors or sum(statuses.values()) + timeouts != completed:
        raise ValueError('a capacity cell has too few requests or failures outside the capacity outcomes')
    # Refusals are results; a cell that served nothing measured a broken harness.
    if statuses.get('200', 0) == 0:
        raise ValueError('a capacity cell served no request')
    rates = {'rate_503': statuses.get('503', 0) / completed, 'rate_client_timeout': timeouts / completed}
    for key, expected in rates.items():
        if abs(capacity_number(requests[key], 1) - expected) > 1e-6:
            raise ValueError('capacity rates do not match their counts')
    kinds = CAPACITY_MIXES[mix]['kinds']
    if type(requests['by_kind']) is not dict or set(requests['by_kind']) != set(kinds):
        raise ValueError('capacity request kinds do not match the mix')
    by_kind = {}
    for kind in kinds:
        entry = requests['by_kind'][kind]
        kind_completed, kind_timeouts = count(entry['completed']), count(entry['client_timeouts'])
        kind_statuses = capacity_statuses(entry['status_counts'], kind_completed)
        kind_latency = capacity_latency(entry['latency_ms'])
        if (kind_completed == 0 or kind_latency is None
                or sum(kind_statuses.values()) + kind_timeouts != kind_completed):
            raise ValueError('a capacity request kind has no complete evidence')
        by_kind[kind] = {'completed': kind_completed, 'status_counts': kind_statuses,
                         'client_timeouts': kind_timeouts, 'latency_ms': kind_latency}
    if sum(entry['completed'] for entry in by_kind.values()) != completed:
        raise ValueError('capacity request kinds do not add up to the cell')
    latency, served = capacity_latency(requests['latency_ms']), capacity_latency(requests['served_latency_ms'])
    duration = capacity_number(requests['duration_ms'])
    if latency is None or served is None:
        raise ValueError('capacity request latency is missing')
    # The load runs until the measured window ends, so the cell cannot be shorter.
    if duration < method['measured_seconds'] * 1000:
        raise ValueError('a capacity cell ended before its measured window')
    return {'completed': completed, 'duration_ms': duration,
            'throughput_rps': capacity_number(requests['throughput_rps']),
            'status_counts': statuses, 'client_timeouts': timeouts, 'client_errors': errors,
            'rate_503': requests['rate_503'], 'rate_client_timeout': requests['rate_client_timeout'],
            'latency_ms': latency, 'served_latency_ms': served, 'by_kind': by_kind}


def capacity_pool(pool, replicas, pool_max, classes):
    ceiling = count(pool['connection_ceiling'])
    if ceiling != replicas * pool_max or type(pool['replicas']) is not list or len(pool['replicas']) != replicas:
        raise ValueError('capacity pool evidence does not cover every replica')
    pairs = [(name, error) for name in CAPACITY_OPERATION_CLASSES for error in CAPACITY_ERROR_CLASSES]
    totals = {}
    rebuilt = []
    for index, row in enumerate(pool['replicas']):
        if row['replica'] != CAPACITY_REPLICA_NAMES[index] or type(row['acquire']) is not list:
            raise ValueError('capacity pool evidence does not cover every replica')
        series = []
        for entry in row['acquire']:
            pair = (capacity_choice(entry['operation_class'], CAPACITY_OPERATION_CLASSES),
                    capacity_choice(entry['error_class'], CAPACITY_ERROR_CLASSES))
            samples = count(entry['count'])
            if samples == 0 or any(pair == (seen['operation_class'], seen['error_class']) for seen in series):
                raise ValueError('capacity acquisition series are empty or repeated')
            totals[pair] = totals.get(pair, 0) + samples
            series.append({'operation_class': pair[0], 'error_class': pair[1], 'count': samples,
                           'sum_seconds': capacity_number(entry['sum_seconds']),
                           **capacity_exporter_latency(entry)})
        # Every replica reads the revision; how those reads ended is the result.
        if not any(entry['operation_class'] == 'revision_check' for entry in series):
            raise ValueError('a replica left no acquisition evidence')
        size, available = count(row['size_max']), count(row['available_min'])
        if size > pool_max or available > pool_max:
            raise ValueError('capacity pool gauges exceed the pool ceiling')
        # A replica that handed out a connection holds one: zero is a gauge that was not read.
        if size == 0:
            raise ValueError('a replica left no pool gauge evidence')
        rebuilt.append({'replica': row['replica'], 'pool_timeouts': count(row['pool_timeouts']),
                        'audit_events_dropped': count(row['audit_events_dropped']),
                        'size_max': size, 'available_min': available,
                        'waiting_max': count(row['waiting_max']), 'acquire': series})
    counts = pool['acquire_counts']
    if type(counts) is not list or len(counts) != len(pairs):
        raise ValueError('capacity acquisition counts must list every class and outcome')
    acquire_counts = []
    for (name, error), entry in zip(pairs, counts):
        if ((entry['operation_class'], entry['error_class']) != (name, error)
                or count(entry['count']) != totals.get((name, error), 0)):
            raise ValueError('capacity acquisition counts do not match the replicas')
        acquire_counts.append({'operation_class': name, 'error_class': error, 'count': entry['count']})
    if any(not any(totals.get((name, error)) for error in CAPACITY_ERROR_CLASSES) for name in classes):
        raise ValueError('a class the mix exercises left no acquisition evidence')
    return {'connection_ceiling': ceiling, 'replicas': rebuilt, 'acquire_counts': acquire_counts}


def capacity_database(database):
    spreads = {}
    for key in CAPACITY_SPREADS:
        maximum, mean = count(database[key]['max']), capacity_number(database[key]['mean'])
        if mean > maximum:
            raise ValueError('capacity database samples are inconsistent')
        spreads[key] = {'max': maximum, 'mean': mean}
    samples = count(database['activity_samples'])
    if samples < MIN_CAPACITY_SAMPLES or spreads['runtime_backends']['max'] < 1:
        raise ValueError('capacity database activity was not sampled')
    counters = database['stat_delta']
    if type(counters) is not dict or set(counters) != set(CAPACITY_COUNTERS):
        raise ValueError('capacity database counters are missing')
    return {'activity_samples': samples, **spreads,
            'longest_lock_wait_ms': capacity_number(database['longest_lock_wait_ms']),
            'stat_delta': {key: count(counters[key]) for key in CAPACITY_COUNTERS}}


def capacity_control_plane(churn):
    attempted = count(churn['commits_attempted'])
    statuses = capacity_statuses(churn['status_counts'], attempted)
    samples, timeouts = count(churn['convergence_samples']), count(churn['convergence_timeouts'])
    commit_latency, convergence = capacity_latency(churn['commit_latency_ms']), capacity_latency(churn['convergence_ms'])
    committed = statuses.get('200', 0)
    if (committed == 0 or samples == 0 or sum(statuses.values()) != attempted
            or samples + timeouts != committed or commit_latency is None or convergence is None):
        raise ValueError('the contention cell did not commit and converge')
    return {'commits_attempted': attempted, 'status_counts': statuses,
            'commit_latency_ms': commit_latency, 'convergence_samples': samples,
            'convergence_timeouts': timeouts, 'convergence_ms': convergence}


def capacity_projector(projector):
    fields = {key: count(projector[key]) for key in
              ('events_ingested', 'checkpoint_delta', 'projected_events_delta', 'lag_events_after')}
    if not (fields['events_ingested'] and fields['checkpoint_delta'] and fields['projected_events_delta']):
        raise ValueError('the contention cell left the discovery projector idle')
    return fields


def capacity_cell(cell, name, method):
    if cell['name'] != name:
        raise ValueError('capacity cells do not match the declared matrix')
    if cell['complete'] is not True or cell['incomplete_reasons'] != []:
        raise ValueError('a capacity cell did not produce complete evidence')
    replicas, pool_max = count(cell['replicas']), count(cell['pool_max'])
    mix, contention = capacity_choice(cell['mix'], CAPACITY_MIXES), cell['contention']
    if (type(contention) is not bool or not 1 <= replicas <= len(CAPACITY_REPLICA_NAMES)
            or not 1 <= pool_max <= MAX_CAPACITY_POOL):
        raise ValueError('a capacity cell configuration is out of range')
    if name != f'r{replicas}-p{pool_max}-{mix}' + ('-contention' if contention else ''):
        raise ValueError('a capacity cell name does not describe its configuration')
    classes = CAPACITY_MIXES[mix]['classes'] + (('control_plane_write',) if contention else ())
    if not contention and (cell['control_plane'] is not None or cell['projector'] is not None):
        raise ValueError('only the contention cell carries concurrent work')
    return {'name': name, 'replicas': replicas, 'pool_max': pool_max, 'mix': mix,
            'contention': contention,
            'requests': capacity_requests(cell['requests'], mix, method),
            'pool': capacity_pool(cell['pool'], replicas, pool_max, classes),
            'database': capacity_database(cell['database']),
            'control_plane': capacity_control_plane(cell['control_plane']) if contention else None,
            'projector': capacity_projector(cell['projector']) if contention else None,
            'complete': True}


def capacity_summary(report):
    if report.get('schema_version') != 1 or report.get('producer') != 'ha-capacity':
        raise ValueError('capacity evidence has an unknown producer or schema')
    method = {key: count(report['method'][key]) for key in CAPACITY_METHOD}
    matrix, cells = report['matrix'], report['cells']
    if (not all(method.values()) or type(matrix) is not list or type(cells) is not list
            or not 1 <= len(matrix) <= MAX_CAPACITY_CELLS or len(set(map(str, matrix))) != len(matrix)
            or len(cells) != len(matrix)):
        raise ValueError('capacity evidence does not cover every declared cell')
    rebuilt = [capacity_cell(cell, name, method) for cell, name in zip(cells, matrix)]
    # The matrix itself: every replica count by every pool ceiling by both
    # mixes, at least two of each, plus exactly one contention cell. That
    # cell runs the mixed load on a configuration a plain cell also ran, so
    # the two differ only by the concurrent work.
    plain = [(cell['replicas'], cell['pool_max'], cell['mix']) for cell in rebuilt if not cell['contention']]
    contended = [(cell['replicas'], cell['pool_max'], cell['mix']) for cell in rebuilt if cell['contention']]
    replica_counts, ceilings = {cell[0] for cell in plain}, {cell[1] for cell in plain}
    crossed = {(replicas, ceiling, mix) for replicas in replica_counts
               for ceiling in ceilings for mix in CAPACITY_MIXES}
    if (len(replica_counts) < 2 or len(ceilings) < 2 or len(plain) != len(crossed)
            or set(plain) != crossed or len(contended) != 1
            or contended[0] not in crossed or contended[0][2] != 'mixed_credentials'):
        raise ValueError('the capacity matrix does not cross two replica counts, two pool ceilings '
                         'and both mixes plus one mixed contention cell')
    return {'schema_version': 1, 'producer': 'ha-capacity',
            'recorded_at': capacity_text(report['recorded_at'],
                                         r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z|unknown'),
            'git_sha': capacity_text(report['git_sha'], r'[0-9a-f]{40}|unknown'),
            'binary_version': capacity_text(report['binary_version'],
                                            r'\d+\.\d+\.\d+([-+][0-9A-Za-z.-]{1,32})?'),
            'runner': {'os': capacity_text(report['runner']['os'], r'[a-z]{1,16}'),
                       'cores': count(report['runner']['cores'])},
            'database': {key: count(report['database'][key]) for key in
                         ('server_version_num', 'max_connections', 'superuser_reserved_connections')},
            'method': method, 'matrix': [cell['name'] for cell in rebuilt], 'cells': rebuilt}


SUMMARIES = {'playwright': playwright_summary, 'stream': stream_summary, 'capacity': capacity_summary}


def validate(kind, source, destination, screenshots=None):
    report = read_json(source)
    try:
        summary = SUMMARIES[kind](report)
        if screenshots is not None:
            summary['screenshots'] = screenshot_count(screenshots)
    except (AttributeError, KeyError, TypeError, OSError, RecursionError):
        raise ValueError('required evidence has an invalid structure') from None
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(summary, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=tuple(SUMMARIES))
    parser.add_argument('source', type=Path)
    parser.add_argument('summary', type=Path)
    parser.add_argument('--screenshots', type=Path)
    args = parser.parse_args()
    try:
        validate(args.kind, args.source, args.summary, args.screenshots)
    except ValueError as error:
        raise SystemExit(str(error)) from None
