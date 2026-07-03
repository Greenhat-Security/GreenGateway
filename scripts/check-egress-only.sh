#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

cd "$ROOT"

matches="$(
    grep -RInE 'reqwest::Client|reqwest::get[[:space:]]*\(' gateway/src --include='*.rs' \
        | grep -v '^gateway/src/egress\.rs:' \
        || true
)"

if [ -n "$matches" ]; then
    echo "raw outbound HTTP client usage must go through gateway/src/egress.rs"
    printf '%s\n' "$matches"
    exit 1
fi

echo "egress-only check passed"
