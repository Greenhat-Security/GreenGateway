#!/usr/bin/env python3
"""Rehearse the documented Compose bootstrap on a disposable Linux Docker host.

Build the image first, then run as root (fixture files need UID 999/10001):
  docker build -t greengateway:bootstrap .
  sudo python3 scripts/check-ha-bootstrap.py --image greengateway:bootstrap

Uses only random test credentials and a unique Compose project. It never starts
the example load balancer or publishes ports. All created resources are removed.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        parser.error('run on Linux as root so private fixture ownership matches the containers')
    root = Path(__file__).resolve().parents[1]
    scratch = Path(tempfile.mkdtemp(prefix='ggw-bootstrap-'))
    project = 'ggw-bootstrap-' + uuid.uuid4().hex[:12]
    env = dict(os.environ)
    for name in ('GG_POSTGRES_PASSWORD', 'GG_RUNTIME_PASSWORD', 'GG_MIGRATION_PASSWORD'):
        env[name] = secrets.token_hex(24)

    def run(command, *, data=None, capture=False):
        return subprocess.run(command, input=data, check=True, env=env,
                              stdout=subprocess.PIPE if capture else None)

    compose = ['docker', 'compose', '--project-directory', str(scratch), '-p', project,
               '-f', str(root / 'docs/deployment/docker-compose.ha.yml'),
               '-f', str(scratch / 'override.json'), '--profile', 'bootstrap', '--profile', 'import']

    def dc(*arguments, **kwargs):
        return run(compose + list(arguments), **kwargs)

    try:
        for name in ('tls', 'secrets', 'keys', 'standalone', 'wal-archive'):
            (scratch / name).mkdir()
        override = {'services': {name: {'image': args.image}
                                for name in ('gateway-1', 'gateway-2', 'migrate', 'import')}}
        (scratch / 'override.json').write_text(json.dumps(override))
        tls = scratch / 'tls'
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
             '-subj', '/CN=Bootstrap test CA', '-keyout', str(tls / 'ca.key'), '-out', str(tls / 'ca.pem')], capture=True)
        run(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=db',
             '-keyout', str(tls / 'server.key'), '-out', str(tls / 'server.csr')], capture=True)
        (tls / 'extensions').write_text('subjectAltName=DNS:db\nextendedKeyUsage=serverAuth\n')
        run(['openssl', 'x509', '-req', '-in', str(tls / 'server.csr'), '-CA', str(tls / 'ca.pem'),
             '-CAkey', str(tls / 'ca.key'), '-CAcreateserial', '-days', '2',
             '-extfile', str(tls / 'extensions'), '-out', str(tls / 'server.crt')], capture=True)
        os.chown(tls / 'server.key', 999, 999)
        (tls / 'server.key').chmod(0o600)
        os.chown(scratch / 'wal-archive', 999, 999)
        key = scratch / 'keys/rate-limit.primary'
        key.write_bytes(secrets.token_bytes(32))
        for path in (key, key.parent):
            os.chown(path, 10001, 10001)
        key.chmod(0o400)
        key.parent.chmod(0o700)
        for suffix, role, password in [('runtime', 'greengateway', 'GG_RUNTIME_PASSWORD'),
                                       ('migration', 'greengateway_migrator', 'GG_MIGRATION_PASSWORD')]:
            path = scratch / f'secrets/database-url-{suffix}'
            path.write_text(f'postgresql://{role}:{env[password]}@db:5432/greengateway\n')
            os.chown(path, 10001, 10001)
            path.chmod(0o400)
        (scratch / 'standalone/policy.json').write_text(json.dumps({
            'schema_version': '0.1.0', 'default_action': 'deny', 'enforcement_mode': 'enforce',
            'roles': {}, 'routes': [], 'rules': []}))
        (scratch / 'standalone/standalone.env').write_text('POLICY_FILE=/standalone/policy.json\n')
        dc('config', '--quiet')
        dc('up', '-d', '--wait', '--wait-timeout', '120', 'db')
        for service in ('db-bootstrap', 'migrate', 'db-grants'):
            dc('run', '--rm', '--no-deps', service)
        dc('run', '--rm', '--no-deps', 'import', 'import-standalone',
           '--from', '/standalone/standalone.env', '--apply')
        dc('up', '-d', '--no-deps', '--no-build', '--wait', '--wait-timeout', '120', 'gateway-1', 'gateway-2')
        for service in ('gateway-1', 'gateway-2'):
            dc('exec', '-T', service, 'curl', '--fail', '--silent', 'http://127.0.0.1:8080/readyz')
        result = dc('exec', '-T', 'db', 'psql', '-U', 'postgres', '-d', 'greengateway', '-Atc',
                    "SELECT has_database_privilege('greengateway_migrator','greengateway','CREATE'), "
                    "has_schema_privilege('greengateway','greengateway','CREATE')", capture=True)
        assert result.stdout.strip() == b't|f', 'DDL privileges must stay separated'
        # A restored copy preserves its binding; the restore cannot invent a new ID.
        dc('stop', 'gateway-1', 'gateway-2')
        backup = dc('exec', '-T', 'db', 'pg_dump', '-U', 'postgres', '-d', 'greengateway', capture=True).stdout
        dc('exec', '-T', 'db', 'createdb', '-U', 'postgres', 'ggw_restore_drill')
        dc('exec', '-T', 'db', 'psql', '-U', 'postgres', '-d', 'ggw_restore_drill', '-v', 'ON_ERROR_STOP=1', data=backup, capture=True)
        for suffix in ('migration', 'runtime'):
            dsn = scratch / f'secrets/database-url-{suffix}'
            dsn.chmod(0o600)
            dsn.write_text(dsn.read_text().replace('/greengateway\n', '/ggw_restore_drill\n'))
            dsn.chmod(0o400)
        dc('run', '--rm', '--no-deps', 'migrate', 'migrate', 'check')
        dc('up', '-d', '--no-deps', '--no-build', '--force-recreate', '--wait',
           '--wait-timeout', '120', 'gateway-1', 'gateway-2')
        for service in ('gateway-1', 'gateway-2'):
            dc('exec', '-T', service, 'curl', '--fail', '--silent', 'http://127.0.0.1:8080/readyz')
        print('PASS: clean bootstrap, least privilege, two ready replicas, restored-schema verification, and restored readiness', flush=True)
    finally:
        if (scratch / 'override.json').exists():
            subprocess.run(compose + ['down', '--volumes', '--remove-orphans'], env=env, check=False)
        shutil.rmtree(scratch)


if __name__ == '__main__':
    main()
