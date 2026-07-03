#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

cd "$ROOT"

matches="$(
    git ls-files '*.rs' |
        while IFS= read -r file; do
            if [ "$file" = "gateway/src/egress.rs" ]; then
                continue
            fi

            if file_matches="$(grep -nE '\breqwest\b' "$file")"; then
                printf '%s\n' "$file_matches" | awk -v file="$file" '{ print file ":" $0 }'
            else
                status=$?
                if [ "$status" -ne 1 ]; then
                    exit "$status"
                fi
            fi
        done
)"

if [ -n "$matches" ]; then
    echo "raw outbound HTTP client usage must go through gateway/src/egress.rs"
    printf '%s\n' "$matches"
    exit 1
fi

echo "egress-only check passed"
