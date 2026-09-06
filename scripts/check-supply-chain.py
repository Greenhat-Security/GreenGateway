#!/usr/bin/env python3
"""Reject mutable action and container references in production/CI inputs."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def check(root=ROOT):
    errors = []
    workflows = list((root / '.github/workflows').glob('*.yml'))
    for path in workflows:
        for line, value in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            match = re.match(r'\s*(?:-\s*)?uses:\s*(\S+)', value)
            if match and not match[1].startswith('./'):
                if not re.fullmatch(r'[^@]+@[0-9a-f]{40}', match[1]):
                    errors.append(f'{path.relative_to(root)}:{line}: action must use a full commit SHA')
    paths = workflows + [root / 'Dockerfile', root / 'docs/deployment/docker-compose.ha.yml']
    paths += list((root / 'deploy/kubernetes').glob('*.yaml'))
    for path in paths:
        for line, value in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
            match = re.match(r'(?:FROM\s+|# syntax=|\s*image:\s*)(\S+)', value)
            if match and not re.fullmatch(r'[^@]+@sha256:[0-9a-f]{64}', match[1]):
                errors.append(f'{path.relative_to(root)}:{line}: image must use a SHA-256 digest')
    return errors


if __name__ == '__main__':
    problems = check()
    print('\n'.join(problems) if problems else 'Supply-chain input pins verified.')
    sys.exit(bool(problems))
