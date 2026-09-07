"""Exercise the actual Linux runtime; optionally scan a read-only PR preview.

The trusted release still requires scan_candidate_image.py against GHCR digests.
This preview scan has no exceptions and cannot emit a passing release digest.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
import urllib.request

from build_tools import versions
from scan_candidate_image import evaluate_inventory, fresh, install_trivy, policy, ROOT


def require(condition):
    if not condition:
        raise ValueError('runtime image contract failed; see the calling check')


def command(*args, check=True):
    return subprocess.run(list(args), check=check, capture_output=True,
                          text=True, encoding='utf-8', timeout=120)


def runtime_check(image, output):
    config = json.loads(command('docker', 'image', 'inspect', image).stdout)[0]
    image_id = config['Id']
    require(config['Os'] == 'linux' and config['Architecture'] == 'amd64')
    require(config['Config']['User'] == '10001:10001')
    require(config['Config']['WorkingDir'] == '/')
    require(config['Config']['Entrypoint'] == ['/usr/local/bin/gateway'])
    require(config['Config']['Healthcheck']['Test'] == [
        'CMD', '/usr/local/bin/gateway', 'healthcheck', 'http://127.0.0.1:8080/livez'])
    container = command('docker', 'create', '--read-only', '--tmpfs', '/tmp:rw,nosuid,nodev',
                        '--cap-drop=ALL', '--security-opt=no-new-privileges',
                        '-p', '127.0.0.1::8080',
                        '-e', 'AUDIT_LOG_FILE=/tmp/audit.jsonl',
                        '-e', 'AUDIT_SQLITE_PATH=/tmp/audit.sqlite',
                        image_id).stdout.strip()
    try:
        # Inspect the filesystem without relying on any tools inside it.
        with tempfile.TemporaryDirectory(prefix='ggw-runtime-') as temporary:
            archive = Path(temporary) / 'rootfs.tar'
            command('docker', 'export', '-o', str(archive), container)
            with tarfile.open(archive) as filesystem:
                paths = {item.name.lstrip('./'): item for item in filesystem}
                require(not ({'bin/sh', 'bin/bash', 'usr/bin/curl', 'usr/bin/perl',
                             'usr/bin/apt', 'usr/bin/mount', 'bin/mount'} & paths.keys()))
                require('var/lib/dpkg/status.d/libc6' in paths)
                require(paths['etc/ssl/certs/ca-certificates.crt'].size > 10000)
                passwd = filesystem.extractfile(paths['etc/passwd']).read().decode()
                require('greengateway:x:10001:10001::/nonexistent:' in passwd)
        # The loader exits nonzero for a missing shared library or ABI mismatch.
        linkage = command('docker', 'run', '--rm', '--read-only', '--network=none',
                          '--entrypoint', '/lib64/ld-linux-x86-64.so.2', image_id,
                          '--list', '/usr/local/bin/gateway').stdout
        (output / 'linkage.txt').write_text(linkage, encoding='utf-8')
        command('docker', 'start', container)
        port = command('docker', 'port', container, '8080/tcp').stdout.strip()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for attempt in range(60):
            try:
                with opener.open('http://' + port + '/readyz', timeout=2) as response:
                    require(response.status == 200)
                break
            except OSError:
                if attempt == 59:
                    raise
                time.sleep(1)
        for path in ('livez', 'readyz', 'startupz'):
            # Even broken proxy/application settings must not affect one-shot probes.
            command('docker', 'exec', '-e', 'STATE_BACKEND=invalid',
                    '-e', 'HTTP_PROXY=http://127.0.0.1:1', '-e', 'ALL_PROXY=http://127.0.0.1:1',
                    '-e', 'NO_PROXY=', container, '/usr/local/bin/gateway',
                    'healthcheck', 'http://127.0.0.1:8080/' + path)
        for arguments in ([], ['http://127.0.0.1:8080/readyz', 'extra'],
                          ['http://127.0.0.1:8080/admin'], ['http://127.0.0.1:1/livez']):
            result = command('docker', 'exec', container, '/usr/local/bin/gateway',
                             'healthcheck', *arguments, check=False)
            require(result.returncode != 0)
        command('docker', 'stop', '--time', '45', container)
        state = json.loads(command('docker', 'inspect', container).stdout)[0]['State']
        require(state['ExitCode'] == 0 and not state['OOMKilled'])
        (output / 'runtime.json').write_text(json.dumps({
            'image_id': image_id, 'status': 'passed', 'user': '10001:10001',
            'read_only': True, 'native_probes': ['livez', 'readyz', 'startupz'],
            'shutdown_exit_code': state['ExitCode'],
        }, indent=2), encoding='utf-8')
    finally:
        logs = command('docker', 'logs', container, check=False)
        (output / 'runtime.log').write_text(logs.stdout + logs.stderr, encoding='utf-8')
        command('docker', 'rm', '-f', container)
    return config


def scan_preview(image, config, output):
    rules = policy(json.loads((ROOT / 'image-scan-policy.json').read_text()), datetime.now(timezone.utc))
    # PR previews have no signed release index to which an exception can bind.
    rules = {**rules, 'exceptions': []}
    with tempfile.TemporaryDirectory(prefix='ggw-preview-scan-') as temporary:
        sandbox = Path(temporary)
        scanner = install_trivy(sandbox / 'trivy')
        env = {k: v for k, v in os.environ.items() if not k.startswith('TRIVY_')}
        def scan(*arguments):
            return subprocess.run([scanner, *arguments], check=True, capture_output=True,
                                  text=True, encoding='utf-8', cwd=sandbox, env=env, timeout=900).stdout
        require(scan('--version').splitlines()[0] == 'Version: ' + versions()['trivy'])
        common = ['image', '--cache-dir', str(sandbox / 'cache'), '--no-progress', '--disable-telemetry']
        scan(*common, '--download-db-only')
        db = json.loads((sandbox / 'cache/db/metadata.json').read_text())
        require(db['Version'] == 2)
        fresh(db['UpdatedAt'], datetime.now(timezone.utc), rules['max_database_age_hours'])
        (output / 'database.json').write_text(json.dumps(db, indent=2))
        report_path = output / 'preview-scan.json'
        scan(*common, '--image-src', 'docker', '--platform', 'linux/amd64', '--scanners', 'vuln',
             '--pkg-types', 'os,library', '--list-all-pkgs', '--skip-db-update',
             '--format', 'json', '--output', str(report_path), image)
        report = json.loads(report_path.read_bytes())
        require(report['SchemaVersion'] == 2 and report['ArtifactType'] == 'container_image')
        require(report['ArtifactName'] == image and report['Metadata']['ImageID'] == config['Id'])
        subject = report['Metadata']['ImageConfig']
        require(subject['os'] == 'linux' and subject['architecture'] == 'amd64')
        fresh(report['CreatedAt'], datetime.now(timezone.utc), 1)
        fresh(db['UpdatedAt'], datetime.now(timezone.utc), rules['max_database_age_hours'])
        decision = evaluate_inventory(report, config['Id'], rules)
        (output / 'preview-decision.json').write_text(json.dumps(decision, indent=2))
        if decision['blocked']:
            raise ValueError('preview contains blocking findings; inspect preview-scan.json')
        print('PR preview scan passed with no exceptions.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, default=Path('target/runtime-check'))
    parser.add_argument('--scan-preview', action='store_true')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    config = runtime_check(args.image, output)
    if args.scan_preview:
        scan_preview(args.image, config, output)
    print('Runtime checks passed.')
