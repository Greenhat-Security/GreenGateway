"""Offline regressions for supply-chain, coverage and test-evidence gates."""
import base64
import importlib.util
import json
from pathlib import Path
import tempfile
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
    limits = {'gateway/src/auth/jwt.rs': {'lines': 80, 'branches': 70}}

    def report(self, branches=8):
        return {'data': [{'files': [{'filename': 'C:\\repo\\gateway\\src\\auth\\jwt.rs', 'summary': {
            'lines': {'count': 10, 'covered': 9}, 'branches': {'count': 10, 'covered': branches}}}]}]}

    def test_accepts_instrumented_windows_paths(self):
        self.assertEqual(coverage.check(self.report(), self.limits), [])

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
        # A complete one-pixel PNG, not a filename-only screenshot fixture.
        self.png = base64.b64decode(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aZ1kAAAAASUVORK5CYII=')

    def report(self):
        return {'stats': {'expected': 1, 'skipped': 0, 'unexpected': 0, 'flaky': 0},
                'errors': [], 'suites': [{'suites': [{'specs': [{'tests': [
                    {'status': 'expected', 'results': [{'status': 'passed'}]}
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


if __name__ == '__main__':
    unittest.main()
