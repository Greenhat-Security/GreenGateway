"""Offline regressions for supply-chain, coverage and test-evidence gates."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import struct
import subprocess
import sys
import zlib
from unittest.mock import patch
import unittest

import yaml


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    if spec is None or spec.loader is None:
        raise RuntimeError(f'cannot load security gate module: {name}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


coverage = load('check-security-coverage')
pins = load('check-supply-chain')
evidence = load('check-test-evidence')


class CoverageGate(unittest.TestCase):
    limits = {'gateway/src/auth/jwt.rs': {'lines': 80, 'branches': 70, 'min_line_count': 10, 'min_branch_count': 10}}

    def report(self, branches=8, lines=(10, 9), branch_count=10):
        return {'data': [{'files': [{'filename': 'C:\\repo\\gateway\\src\\auth\\jwt.rs', 'summary': {
            'lines': {'count': lines[0], 'covered': lines[1]},
            'branches': {'count': branch_count, 'covered': branches}}}]}]}

    def limits_with(self, **changes):
        limits = {**self.limits['gateway/src/auth/jwt.rs'], **changes}
        return {'gateway/src/auth/jwt.rs': {key: value for key, value in limits.items() if value is not None}}

    def test_accepts_instrumented_windows_paths(self):
        self.assertEqual(coverage.check(self.report(), self.limits), [])

    def test_a_grown_denominator_passes(self):
        # New code in a file raises its counts; only a smaller count than recorded fails.
        self.assertEqual(coverage.check(self.report(branches=10, lines=(14, 13), branch_count=12), self.limits), [])

    def test_fewer_instrumented_lines_than_recorded_fail_even_at_full_coverage(self):
        errors = coverage.check(self.report(lines=(9, 9)), self.limits)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn('instrumented lines denominator shrank: 9 lines, below the recorded minimum of 10', errors[0])
        self.assertIn('set "min_line_count" to 9 in .github/security-coverage.json', errors[0])
        self.assertIn('code was really removed', errors[0])

    def test_fewer_instrumented_branches_than_recorded_fail_even_at_full_coverage(self):
        errors = coverage.check(self.report(branches=9, branch_count=9), self.limits)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn('instrumented branches denominator shrank: 9 branches, below the recorded minimum of 10', errors[0])
        self.assertIn('set "min_branch_count" to 9', errors[0])

    def test_a_missing_or_invalid_recorded_minimum_fails(self):
        for key in ('min_line_count', 'min_branch_count'):
            for value in (None, 0, -1, True, 10.0, '10'):
                with self.subTest(key=key, value=value):
                    errors = coverage.check(self.report(), self.limits_with(**{key: value}))
                    self.assertEqual(len(errors), 1, errors)
                    self.assertIn(f'must record "{key}"', errors[0])

    def test_a_missing_percentage_floor_fails(self):
        for metric in ('lines', 'branches'):
            with self.subTest(metric=metric):
                errors = coverage.check(self.report(), self.limits_with(**{metric: None}))
                self.assertEqual(len(errors), 1, errors)
                self.assertIn(f'must give a {metric} floor', errors[0])

    def test_committed_floors_record_every_denominator(self):
        floors = json.loads((Path(__file__).resolve().parents[1] / '.github/security-coverage.json').read_text())
        self.assertTrue(floors)
        for path, limits in floors.items():
            with self.subTest(path=path):
                self.assertEqual(set(limits), {'lines', 'branches', 'min_line_count', 'min_branch_count'})
                for key in ('min_line_count', 'min_branch_count'):
                    self.assertIs(type(limits[key]), int)
                    self.assertGreater(limits[key], 0)

    def test_accepts_repository_relative_paths(self):
        report = self.report()
        report['data'][0]['files'][0]['filename'] = 'gateway/src/auth/jwt.rs'
        self.assertEqual(coverage.check(report, self.limits), [])

    def test_duplicate_source_cannot_silently_pass(self):
        report = self.report()
        report['data'][0]['files'].append({
            **report['data'][0]['files'][0], 'filename': 'gateway/src/auth/jwt.rs'})
        self.assertTrue(coverage.check(report, self.limits))

    def test_partial_path_cannot_match(self):
        report = self.report()
        report['data'][0]['files'][0]['filename'] = 'othergateway/src/auth/jwt.rs'
        self.assertTrue(coverage.check(report, self.limits))

    def test_rejects_branch_regression(self):
        self.assertTrue(coverage.check(self.report(6), self.limits))

    def test_missing_file_cannot_silently_pass(self):
        self.assertTrue(coverage.check({'data': []}, self.limits))

    def test_zero_branch_instrumentation_cannot_pass(self):
        report = self.report()
        report['data'][0]['files'][0]['summary']['branches'] = {'count': 0, 'covered': 0}
        self.assertTrue(coverage.check(report, self.limits))

    def test_reports_of_several_packages_are_checked_as_one(self):
        # ggctl (issue #242) is measured in its own run: each gated file is
        # found in whichever report measured it.
        cli = {'filename': 'C:\\repo\\ggctl\\src\\credential.rs', 'summary': {
            'lines': {'count': 10, 'covered': 10}, 'branches': {'count': 10, 'covered': 9}}}
        limits = {**self.limits, 'ggctl/src/credential.rs': {
            'lines': 90, 'branches': 90, 'min_line_count': 10, 'min_branch_count': 10}}
        both = coverage.merged([self.report(), {'data': [{'files': [cli]}]}])
        self.assertEqual(coverage.check(both, limits), [])
        errors = coverage.check(coverage.merged([self.report()]), limits)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn('ggctl/src/credential.rs: expected exactly one instrumented source file, found 0', errors[0])

    def test_a_file_measured_by_two_reports_cannot_pass_on_its_better_run(self):
        better = self.report(branches=10)
        errors = coverage.check(coverage.merged([self.report(branches=1), better]), self.limits)
        self.assertEqual(errors, ['gateway/src/auth/jwt.rs: expected exactly one instrumented source file, found 2'])

    def test_committed_floors_cover_the_operator_cli_credential_and_transport_code(self):
        floors = json.loads((Path(__file__).resolve().parents[1] / '.github/security-coverage.json').read_text())
        for path in ('ggctl/src/cli.rs', 'ggctl/src/credential.rs', 'ggctl/src/remote.rs'):
            with self.subTest(path=path):
                self.assertIn(path, floors)


class SupplyChainGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('.github/workflows', 'docs/deployment', 'deploy/kubernetes'):
            (self.root / directory).mkdir(parents=True)
        (self.root / 'Dockerfile').write_text('FROM node:24@sha256:' + 'a' * 64 + '\n')
        (self.root / 'docs/deployment/docker-compose.ha.yml').write_text('services: {}\n')

    def test_immutable_inputs_and_local_workflows_pass(self):
        (self.root / '.github/workflows/test.yml').write_text('uses: actions/checkout@' + 'b' * 40 + '\nuses: ./.github/workflows/local.yml\n')
        self.assertEqual(pins.check(self.root), [])

    def test_mutable_action_is_rejected(self):
        (self.root / '.github/workflows/test.yaml').write_text('uses: actions/checkout@v4\n')
        self.assertTrue(pins.check(self.root))

    def test_mutable_deployment_image_is_rejected(self):
        (self.root / 'deploy/kubernetes/test.yaml').write_text('image: gateway:latest\n')
        self.assertTrue(pins.check(self.root))


class TestEvidenceGate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'raw.json'
        self.summary = self.root / 'summary.json'
        self.screenshots = self.root / '.screenshots'
        self.screenshots.mkdir()
        self.png = self.make_png()

    @staticmethod
    def chunk(kind, payload=b''):
        return (struct.pack('>I', len(payload)) + kind + payload
                + struct.pack('>I', zlib.crc32(kind + payload)))

    def make_png(self, width=1, height=1, depth=8, color=6, interlace=0, pixels=None):
        if pixels is None:
            pixels = b'\0\xff\x80\0\xff'
        header = struct.pack('>IIBBBBB', width, height, depth, color, 0, 0, interlace)
        return (evidence.PNG_SIGNATURE + self.chunk(b'IHDR', header)
                + self.chunk(b'IDAT', zlib.compress(pixels)) + self.chunk(b'IEND'))

    def report(self):
        return {'stats': {'expected': 1, 'skipped': 0, 'unexpected': 0, 'flaky': 0},
                'errors': [], 'suites': [{'suites': [{'specs': [{'tests': [
                    {'expectedStatus': 'passed', 'status': 'expected', 'results': [{'status': 'passed'}]}
                ]}]}]}]}

    def write_report(self, report=None):
        self.source.write_text(json.dumps(self.report() if report is None else report))

    def validate(self, screenshots=True):
        evidence.validate('playwright', self.source, self.summary,
                          self.screenshots if screenshots else None)

    def test_complete_groups_pass_without_optional_diagnostics(self):
        self.write_report()
        (self.screenshots / 'current.png').write_bytes(self.png)
        self.validate()
        summary = json.loads(self.summary.read_text())
        self.assertEqual(summary['counts']['expected'], 1)
        self.assertEqual(summary['screenshots'], 1)
        self.assertFalse((self.root / 'test-results').exists())

    def test_one_group_cannot_mask_another_or_empty_member(self):
        self.write_report()
        (self.root / 'optional-trace.zip').write_bytes(b'optional')
        with self.assertRaisesRegex(ValueError, 'screenshot group'):
            self.validate()
        (self.screenshots / 'current.png').write_bytes(self.png)
        (self.screenshots / 'empty.png').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'complete PNG'):
            self.validate()
        (self.screenshots / 'empty.png').unlink()
        for contents in ('', '{', '[]'):
            with self.subTest(contents=contents):
                self.source.write_text(contents)
                with self.assertRaises(ValueError):
                    self.validate()
        self.source.unlink()
        with self.assertRaisesRegex(ValueError, 'missing, empty or invalid'):
            self.validate()

    def test_truncated_png_is_rejected(self):
        self.write_report()
        (self.screenshots / 'current.png').write_bytes(self.png[:-12])
        with self.assertRaisesRegex(ValueError, 'complete PNG'):
            self.validate()

    def test_empty_skipped_inconsistent_and_failed_runs_are_rejected(self):
        for change in ('empty', 'skipped', 'count', 'failure', 'errors', 'no-results'):
            with self.subTest(change=change):
                report = self.report()
                test = report['suites'][0]['suites'][0]['specs'][0]['tests'][0]
                if change == 'empty':
                    report['stats']['expected'] = 0
                    report['suites'] = []
                elif change == 'skipped':
                    report['stats'].update(expected=0, skipped=1)
                    test['status'] = 'skipped'
                elif change == 'count':
                    report['stats']['expected'] = 2
                elif change == 'failure':
                    report['stats'].update(expected=0, unexpected=1)
                    test['status'] = 'unexpected'
                elif change == 'errors':
                    report['errors'] = [{'message': 'sensitive fixture error'}]
                else:
                    test['results'] = []
                self.write_report(report)
                with self.assertRaises(ValueError):
                    self.validate(screenshots=False)
                self.assertFalse(self.summary.exists())

    def test_report_retains_counts_without_sensitive_freeform_fields(self):
        report = self.report()
        canary = 'fixture-sensitive-value'
        report['config'] = {'metadata': {'credential': canary}}
        report['suites'][0]['title'] = canary
        report['suites'][0]['suites'][0]['specs'][0]['tests'][0]['results'][0]['stdout'] = [{'text': canary}]
        self.write_report(report)
        self.validate(screenshots=False)
        self.assertNotIn(canary, self.summary.read_text())
        self.assertEqual(set(json.loads(self.summary.read_text())), {'schema_version', 'producer', 'counts'})

    def test_report_outcomes_must_agree_with_executed_attempts(self):
        for results in ([{'status': 'skipped'}], [{'status': 'failed'}], [{}],
                        ['anything'], [{'status': 'timedOut'}], [{'status': 'interrupted'}],
                        {'status': 'passed'}, [{'status': 'fixture-sensitive-status'}]):
            with self.subTest(results=results):
                report = self.report()
                report['suites'][0]['suites'][0]['specs'][0]['tests'][0]['results'] = results
                self.write_report(report)
                with self.assertRaises(ValueError):
                    self.validate(screenshots=False)
                self.assertFalse(self.summary.exists())
        for field, value in [('expectedStatus', None), ('expectedStatus', 'invalid'),
                             ('status', 'flaky'), ('status', 'skipped')]:
            report = self.report()
            report['suites'][0]['suites'][0]['specs'][0]['tests'][0][field] = value
            self.write_report(report)
            with self.assertRaises(ValueError):
                self.validate(screenshots=False)

    def test_expected_failures_and_actual_retry_outcomes_remain_supported(self):
        for expected_status, results, outcome in [
            ('failed', ['failed'], 'expected'),
            ('passed', ['failed', 'passed'], 'flaky'),
            ('failed', ['passed', 'failed'], 'flaky'),
            ('skipped', ['failed', 'skipped'], 'flaky'),
        ]:
            with self.subTest(results=results):
                report = self.report()
                test = report['suites'][0]['suites'][0]['specs'][0]['tests'][0]
                test.update(expectedStatus=expected_status, status=outcome,
                            results=[{'status': status} for status in results])
                report['stats'].update(expected=int(outcome == 'expected'), flaky=int(outcome == 'flaky'))
                self.assertEqual(evidence.playwright_summary(report)['counts'], report['stats'])

    def test_skipped_tests_are_not_counted_as_executed_and_interrupts_fail(self):
        for expected_status, results in [('skipped', [{'status': 'skipped'}]), ('passed', [])]:
            report = self.report()
            tests = report['suites'][0]['suites'][0]['specs'][0]['tests']
            tests.append({'expectedStatus': expected_status, 'status': 'skipped', 'results': results})
            report['stats']['skipped'] = 1
            self.assertEqual(evidence.playwright_summary(report)['counts']['expected'], 1)
            # Removing the only executed test cannot leave a successful report.
            tests.pop(0)
            report['stats']['expected'] = 0
            with self.assertRaises(ValueError):
                evidence.playwright_summary(report)
        report = self.report()
        report['suites'][0]['suites'][0]['specs'][0]['tests'].append({
            'expectedStatus': 'passed', 'status': 'skipped', 'results': [{'status': 'interrupted'}]})
        report['stats']['skipped'] = 1
        with self.assertRaisesRegex(ValueError, 'interrupted'):
            evidence.playwright_summary(report)

    def test_png_chunk_and_compressed_payload_integrity(self):
        header = self.chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0))
        data = self.chunk(b'IDAT', zlib.compress(b'\0\xff\x80\0\xff'))
        end = self.chunk(b'IEND')
        invalid = {
            'header-only': evidence.PNG_SIGNATURE + header + end,
            'forged-markers': evidence.PNG_SIGNATURE + b'\0' * 4 + b'IHDR' + b'\0' * 17 + end,
            'bad-crc': self.png[:29] + bytes([self.png[29] ^ 1]) + self.png[30:],
            'zero-width': self.make_png(width=0),
            'invalid-depth': self.make_png(depth=3),
            'invalid-color': self.make_png(color=1),
            'invalid-interlace': self.make_png(interlace=2),
            'duplicate-header': evidence.PNG_SIGNATURE + header + header + data + end,
            'wrong-order': evidence.PNG_SIGNATURE + data + header + end,
            'unknown-critical': evidence.PNG_SIGNATURE + header + self.chunk(b'ABCD') + data + end,
            'split-data': evidence.PNG_SIGNATURE + header + data + self.chunk(b'tEXt', b'fixture') + data + end,
            'bad-zlib': evidence.PNG_SIGNATURE + header + self.chunk(b'IDAT', b'not compressed') + end,
            'truncated-zlib': evidence.PNG_SIGNATURE + header + self.chunk(b'IDAT', zlib.compress(b'\0' * 5)[:-1]) + end,
            'extra-zlib-stream': evidence.PNG_SIGNATURE + header + self.chunk(b'IDAT', zlib.compress(b'\0' * 5) * 2) + end,
            'short-scanline': self.make_png(pixels=b'\0'),
            'long-scanline': self.make_png(pixels=b'\0' * 6),
            'bad-filter': self.make_png(pixels=b'\x05' + b'\0' * 4),
            'missing-palette': self.make_png(color=3, pixels=b'\0\0'),
            'extra-file-bytes': self.png + b'extra',
            'truncated-chunk': evidence.PNG_SIGNATURE + header + struct.pack('>I', 1000) + b'IDAT',
        }
        for label, contents in invalid.items():
            with self.subTest(label=label):
                self.write_report()
                (self.screenshots / 'current.png').write_bytes(contents)
                with self.assertRaisesRegex(ValueError, 'complete PNG'):
                    self.validate()
                self.assertFalse(self.summary.exists())

    def test_png_accepts_color_depths_filters_palette_and_adam7(self):
        # Each tuple supplies a valid filtered row, independent of the parser's
        # row-size calculation. This includes packed and 16-bit formats.
        for color, depth, row in [(0, 1, b'\0\x80'), (0, 16, b'\0\xff\xff'),
                                  (2, 8, b'\0' + b'\xff' * 3), (2, 16, b'\0' + b'\xff' * 6),
                                  (4, 8, b'\0' + b'\xff' * 2), (6, 16, b'\0' + b'\xff' * 8)]:
            with self.subTest(color=color, depth=depth):
                evidence.validate_png(self.make_png(color=color, depth=depth, pixels=row))
        for filtering in range(5):
            evidence.validate_png(self.make_png(pixels=bytes([filtering]) + b'\0' * 4))
        palette_header = self.chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 1, 3, 0, 0, 0))
        evidence.validate_png(evidence.PNG_SIGNATURE + palette_header + self.chunk(b'PLTE', b'\0' * 6)
                              + self.chunk(b'IDAT', zlib.compress(b'\0\x80')) + self.chunk(b'IEND'))
        # 2x2 RGBA Adam7 has three nonempty passes: 1x1, 1x1, then 2x1.
        evidence.validate_png(self.make_png(width=2, height=2, interlace=1, pixels=b'\0' * 19))
        compressed = zlib.compress(b'\0' * 5)
        header = self.chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 6, 0, 0, 0))
        evidence.validate_png(evidence.PNG_SIGNATURE + header + self.chunk(b'tEXt', b'fixture')
                              + self.chunk(b'IDAT', compressed[:3]) + self.chunk(b'IDAT', compressed[3:])
                              + self.chunk(b'IEND'))

    def test_png_work_limits_fail_before_unbounded_decoding(self):
        with patch.object(evidence, 'MAX_PNG_BYTES', len(self.png) - 1):
            with self.assertRaises(ValueError):
                evidence.validate_png(self.png)
        with patch.object(evidence, 'MAX_PNG_DECODED_BYTES', 4):
            with self.assertRaises(ValueError):
                evidence.validate_png(self.png)
        # The tiny compressed file claims a huge image, or expands past a tiny
        # IHDR. Neither may allocate the claimed/expanded raster unboundedly.
        for contents in [self.make_png(width=2**30, height=2**30), self.make_png(pixels=b'\0' * 1000000)]:
            with self.assertRaises(ValueError):
                evidence.validate_png(contents)

    def test_invalid_attempt_diagnostics_do_not_expose_report_contents(self):
        report = self.report()
        report['suites'][0]['suites'][0]['specs'][0]['tests'][0]['results'] = [{'status': 'fixture-sensitive-value'}]
        self.write_report(report)
        result = subprocess.run([sys.executable, str(Path(evidence.__file__)), 'playwright',
                                 str(self.source), str(self.summary)], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('fixture-sensitive-value', result.stderr + result.stdout)
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse(self.summary.exists())

    def stream_report(self):
        return {'configuration': {'requests': 3, 'base_url': 'fixture-private-locator'},
                'result': {'completed': 3, 'duration_ms': 12.5, 'status_counts': {'200': 3},
                           'error_counts': {}, 'unexpected_statuses': [], 'assertion_failures': []}}

    def test_stream_requires_complete_successful_measurements(self):
        report = self.stream_report()
        self.write_report(report)
        evidence.validate('stream', self.source, self.summary)
        self.assertNotIn('fixture-private-locator', self.summary.read_text())
        for key, value in [('completed', 0), ('completed', 2), ('duration_ms', 0),
                           ('status_counts', {}), ('status_counts', {'500': 3}),
                           ('error_counts', {'failure': 1}), ('assertion_failures', ['failure'])]:
            with self.subTest(key=key, value=value):
                report = self.stream_report()
                report['result'][key] = value
                with self.assertRaises(ValueError):
                    evidence.stream_summary(report)


class CapacityEvidenceGate(unittest.TestCase):
    """The #439 capacity matrix: complete evidence or nothing, from an allowlist."""

    LATENCY = {'p50_ms': 1.0, 'p95_ms': 2.0, 'p99_ms': 3.0, 'max_ms': 4.0}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / 'raw.json'
        self.summary = Path(self.temp.name) / 'summary.json'

    def cell(self, replicas, pool_max, mix, contention=False):
        kinds = evidence.CAPACITY_MIXES[mix]['kinds']
        classes = evidence.CAPACITY_MIXES[mix]['classes'] + (('control_plane_write',) if contention else ())
        completed = 40 * len(kinds)
        totals = {}
        replica_rows = []
        for index in range(replicas):
            series = []
            for name, error, samples in [(name, 'none', 50) for name in classes] + [('revision_check', 'cancelled', 2)]:
                totals[(name, error)] = totals.get((name, error), 0) + samples
                series.append({'operation_class': name, 'error_class': error, 'count': samples,
                               'sum_seconds': 0.05, **self.LATENCY})
            replica_rows.append({'replica': 'abc'[index], 'pool_timeouts': 0, 'audit_events_dropped': 0,
                                 'size_max': pool_max, 'available_min': 0, 'waiting_max': 3,
                                 'acquire': series})
        cell = {
            'name': f'r{replicas}-p{pool_max}-{mix}' + ('-contention' if contention else ''),
            'replicas': replicas, 'pool_max': pool_max, 'mix': mix, 'contention': contention,
            'requests': {
                'completed': completed, 'duration_ms': 20000.0, 'throughput_rps': completed / 20,
                'status_counts': {'200': completed - 4 * len(kinds), '503': 4 * len(kinds)},
                'client_timeouts': 0, 'client_errors': 0, 'rate_503': 0.1, 'rate_client_timeout': 0.0,
                'latency_ms': dict(self.LATENCY), 'served_latency_ms': dict(self.LATENCY),
                'by_kind': {kind: {'completed': 40, 'status_counts': {'200': 36, '503': 4},
                                   'client_timeouts': 0, 'latency_ms': dict(self.LATENCY)}
                            for kind in kinds}},
            'pool': {'connection_ceiling': replicas * pool_max, 'replicas': replica_rows,
                     'acquire_counts': [{'operation_class': name, 'error_class': error,
                                         'count': totals.get((name, error), 0)}
                                        for name in evidence.CAPACITY_OPERATION_CLASSES
                                        for error in evidence.CAPACITY_ERROR_CLASSES]},
            'database': {'activity_samples': 40,
                         **{key: {'max': 4, 'mean': 2.5} for key in evidence.CAPACITY_SPREADS},
                         'longest_lock_wait_ms': 0.0,
                         'stat_delta': {key: 10 for key in evidence.CAPACITY_COUNTERS}},
            'control_plane': None, 'projector': None,
            'complete': True, 'incomplete_reasons': []}
        if contention:
            cell['control_plane'] = {'commits_attempted': 20, 'status_counts': {'200': 19, '503': 1},
                                     'commit_latency_ms': dict(self.LATENCY), 'convergence_samples': 19,
                                     'convergence_timeouts': 0, 'convergence_ms': dict(self.LATENCY)}
            cell['projector'] = {'events_ingested': 4000, 'checkpoint_delta': 9000,
                                 'projected_events_delta': 8000, 'lag_events_after': 10}
        return cell

    def report(self):
        cells = [self.cell(replicas, pool_max, mix)
                 for replicas in (2, 3) for pool_max in (2, 10)
                 for mix in ('jwt_proxy', 'mixed_credentials')]
        cells.append(self.cell(2, 10, 'mixed_credentials', contention=True))
        return {'schema_version': 1, 'producer': 'ha-capacity',
                'recorded_at': '2026-10-20T03:17:00.123456789Z', 'git_sha': 'a' * 40,
                'binary_version': '1.0.1', 'runner': {'os': 'linux', 'cores': 4},
                'database': {'server_version_num': 160010, 'max_connections': 100,
                             'superuser_reserved_connections': 3},
                'method': {'concurrency': 24, 'measured_seconds': 20, 'warmup_seconds': 2,
                           'client_timeout_ms': 10000, 'sample_interval_ms': 500},
                'matrix': [cell['name'] for cell in cells], 'cells': cells}

    def rejects(self, report):
        self.source.write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            evidence.validate('capacity', self.source, self.summary)

    def test_complete_matrix_is_rebuilt_from_its_allowlist(self):
        report = self.report()
        report['base_url'] = 'http://127.0.0.1:41234'
        report['cells'][0]['error'] = 'fixture-private-locator'
        report['cells'][0]['requests']['run_id'] = 'fixture-private-locator'
        report['cells'][0]['pool']['replicas'][0]['dsn'] = 'postgres://fixture-private-locator'
        self.source.write_text(json.dumps(report))
        evidence.validate('capacity', self.source, self.summary)
        rendered = self.summary.read_text()
        self.assertNotIn('fixture-private-locator', rendered)
        self.assertNotIn('127.0.0.1', rendered)
        summary = json.loads(rendered)
        self.assertEqual(summary['matrix'], report['matrix'])
        self.assertEqual(len(summary['cells']), 9)
        cancelled = [entry for entry in summary['cells'][0]['pool']['acquire_counts']
                     if entry['error_class'] == 'cancelled' and entry['operation_class'] == 'revision_check']
        self.assertEqual(cancelled[0]['count'], 4)
        self.assertIsNone(summary['cells'][0]['control_plane'])
        self.assertEqual(summary['cells'][8]['control_plane']['convergence_samples'], 19)

    def test_an_incomplete_or_missing_cell_fails(self):
        incomplete = self.report()
        incomplete['cells'][3]['complete'] = False
        incomplete['cells'][3]['incomplete_reasons'] = ['activity_not_sampled']
        missing = self.report()
        missing['cells'].pop()
        renamed = self.report()
        renamed['cells'][1]['name'] = renamed['cells'][0]['name']
        for report in (incomplete, missing, renamed):
            with self.subTest(report=report['cells'][-1]['name']):
                self.rejects(report)

    def test_a_shrunken_matrix_fails(self):
        report = self.report()
        report['cells'] = [cell for cell in report['cells'] if cell['replicas'] == 2]
        report['matrix'] = [cell['name'] for cell in report['cells']]
        self.rejects(report)
        no_contention = self.report()
        no_contention['cells'].pop()
        no_contention['matrix'].pop()
        self.rejects(no_contention)

    def test_outcomes_a_capacity_run_cannot_produce_fail(self):
        mutations = {
            'unauthorized': lambda cell: cell['requests']['status_counts'].update({'401': 1}),
            'client error': lambda cell: cell['requests'].update({'client_errors': 1}),
            'too few': lambda cell: cell['requests'].update({'completed': 10}),
            'rate drift': lambda cell: cell['requests'].update({'rate_503': 0.5}),
            'unordered': lambda cell: cell['requests']['latency_ms'].update({'p95_ms': 9.0}),
            # Nearest-rank over the generator's own samples: p99 never exceeds the maximum.
            'p99 above max': lambda cell: cell['requests']['latency_ms'].update({'p99_ms': 4.001}),
            'boolean count': lambda cell: cell['requests'].update({'client_timeouts': False}),
            'nan': lambda cell: cell['requests'].update({'throughput_rps': float('nan')}),
            'nothing served': lambda cell: cell['requests'].update(
                {'status_counts': {'503': cell['requests']['completed']}, 'rate_503': 1.0,
                 'served_latency_ms': None}),
            'every request timed out': lambda cell: cell['requests'].update(
                {'status_counts': {}, 'client_timeouts': cell['requests']['completed'], 'rate_503': 0.0,
                 'rate_client_timeout': 1.0, 'served_latency_ms': None}),
            'shorter than the window': lambda cell: cell['requests'].update({'duration_ms': 19999.0}),
        }
        for name, mutate in mutations.items():
            with self.subTest(mutation=name):
                report = self.report()
                mutate(report['cells'][0])
                self.rejects(report)

    def test_acquisition_evidence_must_be_bounded_and_consistent(self):
        def hostile_label(cell):
            cell['pool']['replicas'][0]['acquire'][0]['operation_class'] = '/v1/admin/tokens'

        def drop_replica(cell):
            cell['pool']['replicas'].pop()

        def miscount(cell):
            cell['pool']['acquire_counts'][0]['count'] += 1

        def no_revision_check(cell):
            for row in cell['pool']['replicas']:
                row['acquire'] = [entry for entry in row['acquire']
                                  if entry['operation_class'] != 'revision_check']

        def oversized_pool(cell):
            cell['pool']['replicas'][0]['size_max'] = cell['pool_max'] + 1

        def unread_size_gauge(cell):
            cell['pool']['replicas'][1]['size_max'] = 0

        def unordered_sketch(cell):
            cell['pool']['replicas'][0]['acquire'][0].update({'p50_ms': 2.5})

        def unreadable_maximum(cell):
            cell['pool']['replicas'][0]['acquire'][0].update({'max_ms': -1.0})

        def unexercised(cell):
            for row in cell['pool']['replicas']:
                row['acquire'] = [entry for entry in row['acquire']
                                  if entry['operation_class'] != 'security_state_read']
            for entry in cell['pool']['acquire_counts']:
                if entry['operation_class'] == 'security_state_read':
                    entry['count'] = 0

        for mutate in (hostile_label, drop_replica, miscount, no_revision_check, oversized_pool,
                       unread_size_gauge, unordered_sketch, unreadable_maximum, unexercised):
            with self.subTest(mutation=mutate.__name__):
                report = self.report()
                mutate(report['cells'][1])
                self.rejects(report)

    def test_database_and_contention_evidence_is_required(self):
        def unsampled(report):
            report['cells'][0]['database']['activity_samples'] = 1

        def idle_projector(report):
            report['cells'][8]['projector']['checkpoint_delta'] = 0

        def nothing_committed(report):
            report['cells'][8]['control_plane']['status_counts'] = {'503': 20}

        def never_converged(report):
            report['cells'][8]['control_plane'].update(
                {'convergence_samples': 0, 'convergence_timeouts': 19, 'convergence_ms': None})

        def stray_concurrent_work(report):
            report['cells'][0]['projector'] = report['cells'][8]['projector']

        def convergence_above_its_maximum(report):
            report['cells'][8]['control_plane']['convergence_ms'].update({'p99_ms': 4.001})

        def contention_on_an_unmatched_ceiling(report):
            report['cells'][8] = self.cell(2, 4, 'mixed_credentials', contention=True)
            report['matrix'][8] = report['cells'][8]['name']

        def contention_without_the_mixed_load(report):
            report['cells'][8] = self.cell(2, 10, 'jwt_proxy', contention=True)
            report['matrix'][8] = report['cells'][8]['name']

        for mutate in (unsampled, idle_projector, nothing_committed, never_converged,
                       stray_concurrent_work, convergence_above_its_maximum,
                       contention_on_an_unmatched_ceiling, contention_without_the_mixed_load):
            with self.subTest(mutation=mutate.__name__):
                report = self.report()
                mutate(report)
                self.rejects(report)

    def series(self, cell, replica, operation_class, error_class):
        return next(entry for entry in cell['pool']['replicas'][replica]['acquire']
                    if (entry['operation_class'], entry['error_class']) == (operation_class, error_class))

    def recount(self, cell, operation_class, error_class):
        total = sum(entry['count'] for row in cell['pool']['replicas'] for entry in row['acquire']
                    if (entry['operation_class'], entry['error_class']) == (operation_class, error_class))
        for entry in cell['pool']['acquire_counts']:
            if (entry['operation_class'], entry['error_class']) == (operation_class, error_class):
                entry['count'] = total

    def test_exporter_quantiles_may_sit_just_above_their_maximum(self):
        # The exporter renders quantiles below 1 as DDSketch bucket
        # representatives and quantile 1 as the exact maximum. One cancelled
        # revision check alone in the window, waited 258.0 ms, renders as this.
        single = {'p50_ms': 258.025, 'p95_ms': 258.025, 'p99_ms': 258.025, 'max_ms': 258.0}
        report = self.report()
        cell = report['cells'][0]
        self.series(cell, 0, 'revision_check', 'cancelled').update({'count': 1, 'sum_seconds': 0.258, **single})
        # A clustered tail: p99 in the maximum's bucket, just above it.
        self.series(cell, 1, 'rate_limit', 'none').update(
            {'p50_ms': 40.0, 'p95_ms': 2590.627, 'p99_ms': 2590.811, 'max_ms': 2590.756})
        self.recount(cell, 'revision_check', 'cancelled')
        self.source.write_text(json.dumps(report))
        evidence.validate('capacity', self.source, self.summary)
        rows = json.loads(self.summary.read_text())['cells'][0]['pool']['replicas'][0]['acquire']
        self.assertIn({'operation_class': 'revision_check', 'error_class': 'cancelled', 'count': 1,
                       'sum_seconds': 0.258, **single}, rows)
        # The generator's own latencies are nearest-rank and stay strictly ordered.
        report['cells'][0]['requests']['latency_ms'] = dict(single)
        self.rejects(report)

    def test_a_replica_whose_revision_checks_were_all_cancelled_was_measured(self):
        report = self.report()
        cell = report['cells'][2]
        row = cell['pool']['replicas'][0]
        row['acquire'] = [entry for entry in row['acquire']
                          if (entry['operation_class'], entry['error_class']) != ('revision_check', 'none')]
        self.recount(cell, 'revision_check', 'none')
        self.source.write_text(json.dumps(report))
        evidence.validate('capacity', self.source, self.summary)
        rows = json.loads(self.summary.read_text())['cells'][2]['pool']['replicas'][0]['acquire']
        self.assertEqual([entry['error_class'] for entry in rows if entry['operation_class'] == 'revision_check'],
                         ['cancelled'])

    def test_free_text_outside_its_shape_fails(self):
        for key, value in [('git_sha', 'not-a-sha'), ('recorded_at', 'yesterday'),
                           ('binary_version', '1.0.1; rm -rf')]:
            with self.subTest(key=key):
                report = self.report()
                report[key] = value
                self.rejects(report)


class EvidenceWorkflowGate(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).resolve().parents[1]
        self.ci = yaml.load((root / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        self.nightly = yaml.load((root / '.github/workflows/nightly-performance.yml').read_text(), Loader=yaml.BaseLoader)

    def step(self, job, name):
        return next(step for step in self.ci['jobs'][job]['steps'] if step.get('name') == name)

    def test_success_only_evidence_is_eligible_by_producer_outcome(self):
        groups = [
            ('security-coverage', 'coverage', 'Enforce production-code coverage floors', 'Preserve coverage evidence'),
            ('admin-ui', 'live-ui', 'Validate live admin UI evidence', 'Retain live admin UI evidence'),
            ('admin-ui', 'screenshots', 'Validate screenshot and report groups', 'Retain required screenshot evidence'),
            ('dev-traffic-smoke', 'dev-smoke', 'Validate stream evidence', 'Retain stream evidence'),
        ]
        for job, producer, validator, uploader in groups:
            with self.subTest(job=job, producer=producer):
                steps = self.ci['jobs'][job]['steps']
                producing = next(step for step in steps if step.get('id') == producer)
                checking, upload = self.step(job, validator), self.step(job, uploader)
                expression = "${{ always() && steps." + producer + ".outcome == 'success' }}"
                self.assertEqual(checking['if'], expression)
                self.assertEqual(upload['if'], expression)
                self.assertEqual(upload['with']['if-no-files-found'], 'error')
                self.assertLess(steps.index(producing), steps.index(checking))
                self.assertLess(steps.index(checking), steps.index(upload))
                self.assertNotIn('continue-on-error', producing)
                self.assertNotIn('continue-on-error', checking)

    def test_browser_reports_are_distinct_and_raw_results_are_not_uploaded(self):
        live = self.step('admin-ui', 'Test live Connection admin UI')
        screenshots = self.step('admin-ui', 'Test admin UI screenshots')
        for step in (live, screenshots):
            self.assertIn('--reporter=line,json', step['run'])
            self.assertIn('${{ runner.temp }}/', step['env']['PLAYWRIGHT_JSON_OUTPUT_NAME'])
        self.assertNotEqual(live['env'], screenshots['env'])
        upload = self.step('admin-ui', 'Retain required screenshot evidence')['with']
        self.assertEqual(upload['include-hidden-files'], 'true')
        self.assertEqual(set(upload['path'].splitlines()), {
            'admin-ui/.screenshots/**/*.png', 'admin-ui/playwright-report/screenshots-summary.json'})
        for step in self.ci['jobs']['admin-ui']['steps']:
            if 'upload-artifact@' in step.get('uses', ''):
                self.assertNotIn('runner.temp', step['with']['path'])

    def test_coverage_measures_the_same_run_and_only_compiles_the_crate_faster(self):
        steps = self.ci['jobs']['security-coverage']['steps']
        measure = next(step for step in steps if step.get('id') == 'coverage')
        self.assertEqual(measure['run'], 'cargo llvm-cov --no-rustc-wrapper --branch --json --output-path '
                         'target/security-coverage.json -p gateway --bin gateway --locked --jobs 4 -- '
                         '--test-threads=8 --skip '
                         'audit::sqlite_sink::tests::moderate_scale_batched_inserts_complete_quickly')
        self.assertNotIn('env', measure)
        self.assertNotIn('env', self.ci['jobs']['security-coverage'])
        # The one build setting step: exactly these lines, for the gateway
        # package only, before the measurement. Nothing that changes what is
        # compiled (optimisation, assertions, overflow checks, features) may
        # join them.
        tuning = self.step('security-coverage', 'Compile the instrumented gateway crate faster')
        self.assertEqual(tuning['shell'], 'pwsh')
        lines = [line.strip().rstrip(',').strip("'") for line in tuning['run'].splitlines()]
        start, end = lines.index('[unstable]'), lines.index(')')
        self.assertEqual(lines[start:end], [
            '[unstable]', 'profile-rustflags = true', '[profile.test.package.gateway]',
            'debug = 0', 'rustflags = ["-Zthreads=4", "-Clinker=rust-lld"]'])
        self.assertIn("$config = Join-Path $env:CARGO_HOME 'config.toml'", tuning['run'])
        self.assertNotIn('if', tuning)
        self.assertNotIn('continue-on-error', tuning)
        self.assertLess(steps.index(tuning), steps.index(measure))

    def test_the_operator_cli_is_measured_in_its_own_run_before_the_gateway(self):
        steps = self.ci['jobs']['security-coverage']['steps']
        gateway = next(step for step in steps if step.get('id') == 'coverage')
        ggctl = self.step('security-coverage', 'Measure operator CLI security branches')
        self.assertEqual(ggctl['run'], 'cargo llvm-cov --no-rustc-wrapper --branch --json --output-path '
                         'target/ggctl-security-coverage.json -p ggctl --locked --jobs 4')
        # Before the gateway run and unconditional, so a failure here skips
        # the gateway measurement and with it the floor check and the upload.
        self.assertLess(steps.index(ggctl), steps.index(gateway))
        for key in ('if', 'env', 'continue-on-error'):
            self.assertNotIn(key, ggctl)
        enforce = self.step('security-coverage', 'Enforce production-code coverage floors')
        self.assertEqual(enforce['run'], 'python scripts/check-security-coverage.py '
                         'target/security-coverage.json target/ggctl-security-coverage.json')
        for name in ('Preserve coverage evidence', 'Preserve available coverage failure diagnostics'):
            with self.subTest(step=name):
                self.assertEqual(self.step('security-coverage', name)['with']['path'].split(), [
                    'target/security-coverage.json', 'target/ggctl-security-coverage.json'])

    def test_failed_or_skipped_producers_keep_optional_diagnostics(self):
        coverage_diagnostics = self.step('security-coverage', 'Preserve available coverage failure diagnostics')
        self.assertEqual(coverage_diagnostics['if'], "${{ always() && steps.coverage.outcome != 'success' }}")
        ui_diagnostics = self.step('admin-ui', 'Retain available admin UI diagnostics')
        self.assertEqual(ui_diagnostics['if'], '${{ always() }}')
        for step in (coverage_diagnostics, ui_diagnostics):
            self.assertEqual(step['with']['if-no-files-found'], 'ignore')

    def test_nightly_strict_upload_and_anti_vacuity_guards_remain(self):
        steps = self.nightly['jobs']['ha-performance']['steps']
        upload = next(step for step in steps if step.get('name') == 'Publish the performance report')
        self.assertEqual(upload['if'], '${{ always() }}')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')
        self.assertEqual(upload['with']['path'], '${{ runner.temp }}/ha/ha-performance.json')
        measure = next(step for step in steps if step.get('name') == 'Measure the blocking budgets')
        self.assertIn('test result: ok. 0 passed', measure['run'])
        self.assertIn('e < 10.0', measure['run'])

    def test_nightly_capacity_evidence_is_validated_and_uploaded_only_on_success(self):
        job = self.nightly['jobs']['ha-performance']
        steps = job['steps']
        named = {step.get('name'): step for step in steps}
        budgets = next(step for step in steps if step.get('id') == 'budgets')
        producing = next(step for step in steps if step.get('id') == 'capacity')
        checking = named['Validate the capacity report']
        upload = named['Publish the capacity report']
        diagnostics = named['Retain available capacity diagnostics']
        # Scheduled and manual only: the matrix never becomes a pull-request check.
        self.assertEqual(set(self.nightly['on']), {'schedule', 'workflow_dispatch'})
        # The budget step leaves the matrix to its own step, which runs exactly it.
        self.assertIn('--skip capacity::', budgets['run'])
        self.assertIn('--exact capacity::the_capacity_matrix_records_complete_evidence_for_every_cell',
                      producing['run'])
        self.assertIn("test result: ok. 1 passed", producing['run'])
        self.assertIn('e < 60.0', producing['run'])
        self.assertEqual(producing['if'], "${{ !cancelled() && steps.budgets.outcome != 'skipped' }}")
        self.assertLess(0, int(producing['timeout-minutes']))
        self.assertLess(int(producing['timeout-minutes']), int(job['timeout-minutes']))
        # Strict, success-only upload of the validator's output, never the raw report.
        expression = "${{ always() && steps.capacity.outcome == 'success' }}"
        self.assertEqual(checking['if'], expression)
        self.assertEqual(upload['if'], expression)
        self.assertIn('check-test-evidence.py capacity', checking['run'])
        self.assertTrue(checking['run'].endswith('"${{ runner.temp }}/ha/ha-capacity.json"'))
        self.assertEqual(upload['with']['path'], '${{ runner.temp }}/ha/ha-capacity.json')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')
        self.assertEqual(producing['env']['GATEWAY_TEST_CAPACITY_REPORT'],
                         '${{ runner.temp }}/ha/capacity-raw.json')
        # Best-effort diagnostics only when the producer did not succeed or
        # its report was rejected, so a red night always leaves something.
        self.assertEqual(checking['id'], 'capacity_evidence')
        self.assertEqual(diagnostics['if'], "${{ always() && (steps.capacity.outcome != 'success'"
                                            " || steps.capacity_evidence.outcome != 'success') }}")
        self.assertEqual(diagnostics['with']['if-no-files-found'], 'ignore')
        self.assertNotEqual(diagnostics['with']['name'], upload['with']['name'])
        self.assertLess(steps.index(producing), steps.index(checking))
        self.assertLess(steps.index(checking), steps.index(upload))
        self.assertLess(steps.index(upload), steps.index(diagnostics))
        for step in (budgets, producing, checking, upload, diagnostics):
            self.assertNotIn('continue-on-error', step)

    def test_nightly_baseline_is_the_last_scheduled_night_on_main(self):
        # A manual run on a branch must never become the next night's budget baseline.
        steps = self.nightly['jobs']['ha-performance']['steps']
        baseline = next(step for step in steps if step.get('name') == "Fetch the previous night's report")
        self.assertIn('runs?branch=main&event=schedule&status=success&per_page=1', baseline['run'])
        self.assertNotIn('continue-on-error', baseline)


def run_bash(script, env, path_prefix=None):
    environment = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'), **env}
    if path_prefix:
        environment['PATH'] = str(path_prefix) + os.pathsep + environment['PATH']
    return subprocess.run(['bash', '-c', script], env=environment, capture_output=True, text=True, timeout=30)


class DependentRequiredJobGate(unittest.TestCase):
    """A required check that waits on other jobs must fail, not vanish, when one of them did not succeed.

    GitHub reports a job skipped because a dependency failed as passing a
    required check, so every such job runs under `always()` and itself
    requires `success` from each job it waits on.
    """
    SHARDS = ['postgres-foundation-pg', 'postgres-foundation-no-default', 'postgres-foundation-lint']
    OUTCOMES = ['failure', 'skipped', 'cancelled', '']

    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.ci = yaml.load((self.root / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        self.jobs = self.ci['jobs']
        action = yaml.load((self.root / '.github/actions/gateway-image/action.yml').read_text(), Loader=yaml.BaseLoader)
        self.load_steps = action['runs']['steps']

    def test_every_pull_request_job_with_dependencies_runs_and_checks_them(self):
        # Push-only publication jobs and the non-required PR preview scan are
        # the only dependents that may be skipped.
        exempt = {'promote-image', 'image-scan', 'image-verification', 'image-preview'}
        dependents = {name for name, job in self.jobs.items() if 'needs' in job} - exempt
        self.assertEqual(dependents, {'connections-acceptance', 'postgres-foundation',
                                      'ha-compose-example', 'dev-traffic-smoke',
                                      'ha-release-gate'})
        for name in dependents:
            with self.subTest(job=name):
                job = self.jobs[name]
                self.assertEqual(job['if'], '${{ always() }}')
                self.assertNotIn('continue-on-error', job)
                needs = job['needs'] if isinstance(job['needs'], list) else [job['needs']]
                text = json.dumps(job['steps'])
                for need in needs:
                    self.assertIn('${{ needs.' + need + '.result }}', text)
        for name in ('image-scan', 'image-verification'):
            self.assertEqual(self.jobs[name]['if'], "github.event_name == 'push'")

    def test_postgres_foundation_is_exactly_its_three_original_passes(self):
        aggregator = self.jobs['postgres-foundation']
        self.assertEqual(aggregator['needs'], self.SHARDS)
        self.assertEqual(aggregator['name'], 'postgres-foundation')
        commands = {
            'postgres-foundation-pg': 'cargo test -p gateway --locked',
            'postgres-foundation-no-default': 'cargo test -p gateway --locked --no-default-features',
            'postgres-foundation-lint': 'cargo clippy -p gateway --locked --no-default-features --all-targets -- -D warnings',
        }
        for shard, command in commands.items():
            with self.subTest(shard=shard):
                job = self.jobs[shard]
                for optional in ('if', 'needs', 'continue-on-error', 'strategy', 'env'):
                    self.assertNotIn(optional, job)
                runs = [step for step in job['steps'] if step.get('run') == command]
                self.assertEqual(len(runs), 1)
                self.assertNotIn('if', runs[0])
                self.assertNotIn('continue-on-error', runs[0])
                self.assertIn(shard, self.jobs['promote-image']['needs'])
        pg = self.jobs['postgres-foundation-pg']
        self.assertIn('postgres', pg['services'])
        test = next(step for step in pg['steps'] if step.get('run') == commands['postgres-foundation-pg'])
        self.assertEqual(test['env'], {
            'GATEWAY_TEST_POSTGRES_URL_FILE': '${{ runner.temp }}/pg/database-url',
            'GATEWAY_TEST_POSTGRES_NODDL_URL_FILE': '${{ runner.temp }}/pg/database-url-noddl',
        })
        names = [step.get('name') for step in pg['steps']]
        self.assertLess(names.index('Create the no-DDL runtime role'), names.index('Test against a real PostgreSQL (feature on)'))

    def aggregate(self, results):
        step = next(step for step in self.jobs['postgres-foundation']['steps']
                    if step.get('name') == 'Require every PostgreSQL foundation pass')
        self.assertEqual(step['shell'], 'bash')
        expected = {f'{key}': '${{ needs.' + shard + '.result }}' for key, shard in
                    zip(('FEATURE_ON_RESULT', 'NO_DEFAULT_RESULT', 'LINT_RESULT'), self.SHARDS)}
        self.assertEqual(step['env'], expected)
        return run_bash(step['run'], dict(zip(expected, results)))

    def test_the_aggregate_passes_only_when_every_shard_succeeded(self):
        self.assertEqual(self.aggregate(['success'] * 3).returncode, 0)
        for index in range(3):
            for outcome in self.OUTCOMES:
                with self.subTest(shard=self.SHARDS[index], outcome=outcome):
                    results = ['success'] * 3
                    results[index] = outcome
                    result = self.aggregate(results)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(self.SHARDS[index], result.stdout)

    def test_an_image_consumer_stops_unless_the_build_succeeded(self):
        names = [step['name'] for step in self.load_steps]
        self.assertEqual(names, ['Require the image build', 'Download this run\'s production image',
                                 'Load and identify the production image'])
        require = self.load_steps[0]
        self.assertEqual(require['env'], {'PRODUCER_RESULT': '${{ inputs.producer-result }}'})
        self.assertEqual(run_bash(require['run'], {'PRODUCER_RESULT': 'success'}).returncode, 0)
        for outcome in self.OUTCOMES:
            with self.subTest(outcome=outcome):
                self.assertNotEqual(run_bash(require['run'], {'PRODUCER_RESULT': outcome}).returncode, 0)
        for step in self.load_steps:
            self.assertNotIn('if', step)
            self.assertNotIn('continue-on-error', step)

    def test_a_consumer_refuses_an_image_other_than_the_one_built(self):
        load = self.load_steps[2]
        built = 'sha256:' + 'a' * 64
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            log = directory / 'docker.log'
            fake = directory / 'docker'
            # Records every call; `image inspect` reports the ID in $LOADED_ID.
            fake.write_text('#!/bin/sh\necho "$@" >> "$DOCKER_LOG"\n'
                            'if [ "$1" = image ] && [ "$2" = inspect ]; then echo "$LOADED_ID"; fi\n')
            fake.chmod(0o755)
            def attempt(expected, loaded):
                log.write_text('')
                return run_bash(load['run'], {'EXPECTED_IMAGE_ID': expected, 'IMAGE_TAG': 'example:tag',
                                              'LOADED_ID': loaded, 'DOCKER_LOG': str(log),
                                              'RUNNER_TEMP': temporary}, path_prefix=directory)
            accepted = attempt(built, built)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertIn('tag greengateway:ci example:tag', log.read_text().splitlines())
            for expected, loaded in [(built, 'sha256:' + 'b' * 64), ('', built), ('latest', 'latest')]:
                with self.subTest(expected=expected, loaded=loaded):
                    result = attempt(expected, loaded)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse([line for line in log.read_text().splitlines() if line.startswith('tag ')])

    def test_the_dev_stack_runs_the_loaded_image_without_rebuilding(self):
        smoke = next(step for step in self.jobs['dev-traffic-smoke']['steps'] if step.get('id') == 'dev-smoke')
        self.assertIn('up -d --no-build', smoke['run'])
        self.assertNotRegex(smoke['run'], r'\s--build\b')
        load = next(step for step in self.jobs['dev-traffic-smoke']['steps']
                    if step.get('uses') == './.github/actions/gateway-image')
        # Compose names a built service image `<project>-<service>`.
        self.assertIn('compose_files=(-p greengateway-dev ', smoke['run'])
        self.assertEqual(load['with']['tag'], 'greengateway-dev-gateway')
        steps = self.jobs['dev-traffic-smoke']['steps']
        self.assertLess(steps.index(load), steps.index(smoke))


class ReleaseGateBinariesGate(unittest.TestCase):
    """The HA legs run executables built once per run, and only the verified ones.

    Each leg used to build its suite with `cargo test -p gateway --test
    <suite>`. ha-release-gate-build now runs that build for every leg and
    ha-upgrade-pair builds the rolling-upgrade pair; a leg must refuse to run
    when its producer did not succeed or the archive is not the one built.
    """
    OUTCOMES = ['failure', 'skipped', 'cancelled', '']
    SHA = 'a' * 64

    def setUp(self):
        self.root = Path(__file__).resolve().parents[1]
        self.ci = yaml.load((self.root / '.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        self.jobs = self.ci['jobs']
        self.leg = self.jobs['ha-release-gate']
        self.suites = self.leg['strategy']['matrix']['suite']
        action = yaml.load((self.root / '.github/actions/run-binaries/action.yml').read_text(),
                           Loader=yaml.BaseLoader)
        self.unpack_steps = action['runs']['steps']

    def named(self, job, name):
        return next(step for step in self.jobs[job]['steps'] if step.get('name') == name)

    def test_the_producer_builds_exactly_every_leg_with_the_legs_own_build(self):
        producer = self.jobs['ha-release-gate-build']
        self.assertEqual(producer['env']['SUITES'].split(), self.suites)
        self.assertEqual(len(set(self.suites)), len(self.suites))
        for optional in ('if', 'needs', 'continue-on-error', 'strategy'):
            self.assertNotIn(optional, producer)
        self.assertEqual(set(producer['env']), {'SUITES'})
        build = self.named('ha-release-gate-build', 'Build every release-gate suite and the gateway it spawns')
        self.assertIn('cargo test -p gateway --locked --no-run "${targets[@]}"', build['run'])
        self.assertIn('targets+=(--test "${suite}")', build['run'])
        for flag in ('--release', '--profile', '--features', '--no-default-features', '--all-features', 'RUSTFLAGS'):
            self.assertNotIn(flag, build['run'])
        self.assertNotIn('env', build)
        # One executable per suite and the gateway they spawn, at the path
        # compiled into them, or the producer fails.
        self.assertIn('expected one test executable for each of', build['run'])
        self.assertIn('target" / "debug" / "gateway"', build['run'])
        cache = next(step for step in producer['steps'] if step.get('uses', '').startswith('Swatinem/rust-cache@'))
        self.assertEqual(cache['with']['shared-key'], 'postgres-foundation')
        pack = next(step for step in producer['steps'] if step.get('id') == 'pack')
        self.assertIn('tar --zstd -cf "${archive}" target/debug/gateway target/ha-release-gate', pack['run'])
        self.assertEqual(producer['outputs']['archive-sha256'], '${{ steps.pack.outputs.sha256 }}')
        upload = next(step for step in producer['steps'] if step.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(upload['with']['name'], 'ha-release-gate-binaries')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')
        steps = producer['steps']
        self.assertLess(steps.index(build), steps.index(pack))
        self.assertLess(steps.index(pack), steps.index(upload))

    def test_the_pair_producer_is_the_legs_former_pair_build(self):
        producer = self.jobs['ha-upgrade-pair']
        for optional in ('if', 'needs', 'continue-on-error', 'strategy', 'env'):
            self.assertNotIn(optional, producer)
        checkout = producer['steps'][0]
        self.assertEqual(checkout['with']['fetch-depth'], '0')
        build = self.named('ha-upgrade-pair', 'Build the pinned upgrade pair')
        self.assertIn("python -m unittest discover -s scripts -p 'test_build_upgrade_pair.py' -v", build['run'])
        self.assertIn('python scripts/build_upgrade_pair.py --out "${RUNNER_TEMP}/upgrade-pair"', build['run'])
        self.assertIn('for role in prepared successor; do', build['run'])
        self.assertNotIn('if', build)
        # The pair is the build without dev-dependencies, so it starts from
        # the dependency cache of the job that runs exactly that build, and
        # never writes it: this job's target directory also holds the pair.
        cache = next(step for step in producer['steps'] if step.get('uses', '').startswith('Swatinem/rust-cache@'))
        self.assertEqual(cache['with'], {'shared-key': 'admin-ui', 'save-if': 'false'})
        source = self.jobs[cache['with']['shared-key']]
        self.assertIn('cargo build --locked -p gateway', [step.get('run') for step in source['steps']])
        source_cache = next(step for step in source['steps'] if step.get('uses', '').startswith('Swatinem/rust-cache@'))
        self.assertNotIn('shared-key', source_cache['with'])
        self.assertNotIn('workspaces', source_cache['with'])
        pack = next(step for step in producer['steps'] if step.get('id') == 'pack')
        self.assertIn('-C "${RUNNER_TEMP}/upgrade-pair"', pack['run'])
        self.assertIn('manifest.json evidence prepared successor', pack['run'])
        upload = next(step for step in producer['steps'] if step.get('uses', '').startswith('actions/upload-artifact@'))
        self.assertEqual(upload['with']['name'], 'ha-upgrade-pair')
        self.assertEqual(upload['with']['if-no-files-found'], 'error')

    def test_every_leg_unpacks_verified_executables_and_compiles_nothing(self):
        self.assertEqual(self.leg['needs'], ['ha-release-gate-build', 'ha-upgrade-pair'])
        self.assertEqual(self.leg['if'], '${{ always() }}')
        setup = next(step for step in self.leg['steps'] if step.get('uses') == './.github/actions/build-tools')
        self.assertEqual(setup['with'], {'rust': 'none', 'node': 'false'})
        for step in self.leg['steps']:
            self.assertNotIn('continue-on-error', step)
            self.assertNotRegex(step.get('run', ''), r'\bcargo\b')
            self.assertFalse(step.get('uses', '').startswith('Swatinem/rust-cache@'))
        unpacks = [step for step in self.leg['steps'] if step.get('uses') == './.github/actions/run-binaries']
        self.assertEqual([step['with'] for step in unpacks], [
            {'producer': 'ha-release-gate-build',
             'producer-result': '${{ needs.ha-release-gate-build.result }}',
             'archive': 'ha-release-gate-binaries',
             'sha256': '${{ needs.ha-release-gate-build.outputs.archive-sha256 }}',
             'destination': '${{ github.workspace }}'},
            {'producer': 'ha-upgrade-pair',
             'producer-result': '${{ needs.ha-upgrade-pair.result }}',
             'archive': 'ha-upgrade-pair',
             'sha256': '${{ needs.ha-upgrade-pair.outputs.archive-sha256 }}',
             'destination': '${{ runner.temp }}/upgrade-pair'},
        ])
        # Every leg needs the suites; only the rolling-upgrade leg needs the pair.
        self.assertNotIn('if', unpacks[0])
        self.assertEqual(unpacks[1]['if'], "${{ matrix.suite == 'ha_rolling_upgrade' }}")
        run = self.named('ha-release-gate', 'Run the release-gate suite')
        self.assertNotIn('if', run)
        self.assertEqual(run['env']['SUITE'], '${{ matrix.suite }}')
        self.assertEqual(run['env']['GATEWAY_TEST_HA_GATE'], '1')
        self.assertEqual(run['env']['GATEWAY_TEST_UPGRADE_PAIR_DIR'], '${{ runner.temp }}/upgrade-pair')
        self.assertIn('(cd gateway && "../target/ha-release-gate/${SUITE}" --test-threads=1) 2>&1 | tee gate.log',
                      run['run'])
        self.assertIn('"${producer_workspace}" != "${GITHUB_WORKSPACE}"', run['run'])
        for guard in ('test result: ok. 0 passed', 'printed no test-result line', 'e < 1.0'):
            self.assertIn(guard, run['run'])
        steps = self.leg['steps']
        locator = self.named('ha-release-gate', 'Check the locator resolves before trusting a pass')
        for unpack in unpacks:
            self.assertLess(steps.index(unpack), steps.index(run))
        self.assertLess(steps.index(locator), steps.index(run))

    def test_the_rolling_upgrade_leg_verifies_its_evidence_after_the_suite(self):
        # Issue #426 PR 4: only a suite that passed is verified, the check's
        # own tests run first, and the summary it writes is retained.
        steps = self.leg['steps']
        run = self.named('ha-release-gate', 'Run the release-gate suite')
        verify = self.named('ha-release-gate', 'Verify the upgrade-pair evidence against the published matrix')
        self.assertEqual(verify['if'], "${{ matrix.suite == 'ha_rolling_upgrade' }}")
        tests = "python -m unittest discover -s scripts -p 'test_upgrade_pair_evidence.py' -v"
        check = ('python scripts/upgrade_pair_evidence.py --pair-dir "${RUNNER_TEMP}/upgrade-pair" '
                 '--gate-commit "${GITHUB_SHA}"')
        self.assertIn(tests, verify['run'])
        self.assertIn(check, verify['run'])
        self.assertLess(verify['run'].index(tests), verify['run'].index(check))
        retain = self.named('ha-release-gate', 'Retain the upgrade-pair evidence')
        self.assertIn('${{ runner.temp }}/upgrade-pair/summary.json',
                      [line.strip() for line in retain['with']['path'].splitlines()])
        self.assertLess(steps.index(run), steps.index(verify))
        self.assertLess(steps.index(verify), steps.index(retain))

    def test_a_binary_consumer_stops_unless_the_producer_succeeded(self):
        names = [step['name'] for step in self.unpack_steps]
        self.assertEqual(names, ['Require the producer', "Download this run's archive", 'Verify and unpack the archive'])
        require = self.unpack_steps[0]
        self.assertEqual(require['env'], {'PRODUCER': '${{ inputs.producer }}',
                                          'PRODUCER_RESULT': '${{ inputs.producer-result }}'})
        self.assertEqual(run_bash(require['run'], {'PRODUCER': 'p', 'PRODUCER_RESULT': 'success'}).returncode, 0)
        for outcome in self.OUTCOMES:
            with self.subTest(outcome=outcome):
                result = run_bash(require['run'], {'PRODUCER': 'p', 'PRODUCER_RESULT': outcome})
                self.assertNotEqual(result.returncode, 0)
        for step in self.unpack_steps:
            self.assertNotIn('if', step)
            self.assertNotIn('continue-on-error', step)

    def test_a_binary_consumer_refuses_an_archive_other_than_the_one_built(self):
        unpack = self.unpack_steps[2]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / 'bin').mkdir()
            archive = directory / 'example' / 'example.tar.zst'
            archive.parent.mkdir()
            archive.write_bytes(b'not really an archive')
            built = subprocess.run(['sha256sum', str(archive)], capture_output=True, text=True,
                                   check=True).stdout.split()[0]
            log = directory / 'tar.log'
            fake = directory / 'bin' / 'tar'
            # Records every unpack instead of performing it.
            fake.write_text('#!/bin/sh\necho "$@" >> "$TAR_LOG"\n')
            fake.chmod(0o755)

            def attempt(expected):
                log.write_text('')
                return run_bash(unpack['run'], {'ARCHIVE_NAME': 'example', 'EXPECTED_SHA256': expected,
                                                'DESTINATION': str(directory / 'out'), 'TAR_LOG': str(log),
                                                'RUNNER_TEMP': temporary}, path_prefix=directory / 'bin')
            accepted = attempt(built)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(log.read_text().splitlines(),
                             [f'--zstd -xf {archive} -C {directory / "out"}'])
            for expected in (self.SHA, '', 'latest', built.upper(), built + '0'):
                with self.subTest(expected=expected):
                    result = attempt(expected)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(log.read_text(), '')


if __name__ == '__main__':
    unittest.main()
