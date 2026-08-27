#!/bin/sh
# Enforce that outbound HTTP is constructed only inside the egress boundary.
#
# Grepping for `reqwest` alone does not do that. `gateway/src/egress.rs`
# re-exports the crate under a different name so the MCP transport can be handed
# a client type it needs by name, and a module using that alias never mentions
# `reqwest` at all. A guard that only looks for the crate name therefore reports
# success while a second, independently configured HTTP client exists outside
# the boundary -- which is the situation this check was written to prevent.
#
# So the alias names are read out of `egress.rs` rather than hardcoded: adding a
# new re-export automatically extends enforcement instead of quietly narrowing
# it.
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

cd "$ROOT"

EGRESS_FILE="gateway/src/egress.rs"

# `git ls-files` failing inside a command substitution does not trip `set -e`,
# so an empty listing would otherwise be reported as a clean pass. A tree with
# no tracked Rust files means the enumeration broke, not that the invariant
# holds.
rust_files="$(git ls-files '*.rs')"
if [ -z "$rust_files" ]; then
    echo "no tracked .rs files found; refusing to report a pass"
    exit 1
fi

if [ ! -f "$EGRESS_FILE" ]; then
    echo "$EGRESS_FILE not found; refusing to report a pass"
    exit 1
fi

# Files permitted to build a client from an egress re-export. Keep this list
# short and deliberate: an entry here opts a file out of the boundary, so adding
# one should be a reviewed decision rather than a side effect. Every listed file
# is still subject to the pinning check below.
ALIAS_CONSUMER_ALLOWLIST="gateway/src/tools/mcp_upstream.rs"

# `path:function` pairs naming the one function in each allowlisted file that is
# allowed to construct a client, and which must pin the checked address. Scoped
# to a named function rather than the whole file because the same files build
# deliberately unpinned clients in tests, and `#[cfg(test)]` appears throughout
# them rather than only in a trailing module.
PINNED_CLIENT_BUILDERS="gateway/src/tools/mcp_upstream.rs:mcp_http_client"

# `pub(crate) use reqwest as rmcp_http;` -> `rmcp_http`
aliases="$(
    sed -nE 's/^[[:space:]]*(pub(\([^)]*\))?[[:space:]]+)?use[[:space:]]+reqwest[[:space:]]+as[[:space:]]+([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*;.*/\3/p' \
        "$EGRESS_FILE" | sort -u
)"

pattern='\breqwest\b'
for alias in $aliases; do
    pattern="$pattern|\b$alias\b"
done

matches="$(
    printf '%s
' "$rust_files" |
        while IFS= read -r file; do
            case "$file" in
                "$EGRESS_FILE" | gateway/src/egress/*.rs)
                    continue
                    ;;
            esac

            allowed=no
            for permitted in $ALIAS_CONSUMER_ALLOWLIST; do
                if [ "$file" = "$permitted" ]; then
                    allowed=yes
                    break
                fi
            done
            [ "$allowed" = yes ] && continue

            if file_matches="$(grep -nE "$pattern" "$file")"; then
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
    echo "raw outbound HTTP client usage must go through $EGRESS_FILE"
    echo "(searched for: $pattern)"
    printf '%s\n' "$matches"
    exit 1
fi

# An allowlisted file builds its own client, so the address pinning that
# `checked_destination()` established is the only thing stopping that client
# from doing its own DNS resolution at request time. Losing it would silently
# reopen DNS rebinding against every MCP upstream with CI still green, so
# require the pinning call inside the function that builds the client.
#
# A missing function is a failure, not a pass: renaming it must force this
# check to be updated deliberately rather than disable it silently.
problems=""
for entry in $PINNED_CLIENT_BUILDERS; do
    file="${entry%%:*}"
    function_name="${entry##*:}"

    if [ ! -f "$file" ]; then
        problems="$problems|$file is listed as a pinned client builder but does not exist"
        continue
    fi

    body="$(
        awk -v want="fn $function_name(" '
            index($0, want) { inside = 1 }
            inside { print }
            inside && /^\}/ { exit }
        ' "$file"
    )"

    if [ -z "$body" ]; then
        problems="$problems|$file no longer defines $function_name(); update PINNED_CLIENT_BUILDERS"
        continue
    fi

    if ! printf '%s
' "$body" | grep -qE 'Client::builder\(\)'; then
        problems="$problems|$file:$function_name no longer builds a client; update PINNED_CLIENT_BUILDERS"
        continue
    fi

    if ! printf '%s
' "$body" | grep -qE '\.resolve\('; then
        problems="$problems|$file:$function_name builds a client without pinning it via .resolve()"
    fi
done

if [ -n "$problems" ]; then
    echo "a client built outside $EGRESS_FILE must pin the checked address with .resolve()"
    printf '%s
' "$problems" | tr '|' '
' | sed '/^$/d;s/^/  /'
    exit 1
fi

# The HTTP/2 feature guard.
#
# Two distinct properties depend on HTTP/2 staying off, and they are enabled by
# different feature edges, so they are checked by name rather than by looking
# for the `h2` crate.
#
# Inbound: `axum::serve` builds on `hyper-util`'s `auto::Builder`, which sniffs
# the HTTP/2 connection preface and serves h2c when hyper-util itself has
# `http2`. If that feature is ever enabled, EVERY listener -- including the
# admin listener -- begins accepting HTTP/2 prior-knowledge connections, with
# no code change and nothing in the diff to notice.
#
# Outbound: enabling `reqwest/http2` rewrites its ALPN list to prefer h2, so
# every existing HTTPS upstream that supports h2 silently changes protocol, and
# hyper strips hop-by-hop headers on h2 rather than erroring.
#
# Note what is deliberately NOT checked: the mere presence of the `h2` crate.
# Feature definitions are one-way -- `hyper-util/http2 = ["hyper/http2"]` --
# so depending on `hyper` directly with `http2` does NOT enable hyper-util's,
# and does NOT open h2c on any listener. A transport that drives its own h2
# client is therefore compatible with both properties above, and an earlier
# version of this check would have rejected it for the wrong reason.
if command -v cargo >/dev/null 2>&1; then
    features="$(cargo tree -f '{p} | {f}' --edges normal 2>/dev/null || true)"
    if [ -z "$features" ]; then
        echo "could not resolve the dependency features; refusing to report a pass"
        exit 1
    fi

    h2_violations=""
    for crate in hyper-util axum reqwest; do
        # "<crate> v1.2.3 | feat-a,feat-b" -> the feature list, for this crate only.
        crate_features="$(
            printf '%s
' "$features" |
                grep -oE "(^|[^a-z-])$crate v[0-9][^|]*\| [a-z0-9,_-]*" |
                sed 's/.*| //' |
                tr ',' '
' |
                sort -u
        )"
        if [ -z "$crate_features" ]; then
            echo "$crate was not found in the resolved build; refusing to report a pass"
            exit 1
        fi
        if printf '%s
' "$crate_features" | grep -qx 'http2'; then
            h2_violations="$h2_violations $crate"
        fi
    done

    if [ -n "$h2_violations" ]; then
        echo "HTTP/2 is enabled on a crate where it changes behaviour beyond the caller:"
        for crate in $h2_violations; do
            case "$crate" in
                hyper-util|axum)
                    echo "  $crate/http2 -- every listener, including the admin listener, would serve h2c"
                    ;;
                reqwest)
                    echo "  $crate/http2 -- every existing HTTPS upstream would silently switch to h2"
                    ;;
            esac
        done
        echo "if that is deliberate, update this check and the protocol pins in $EGRESS_FILE together"
        exit 1
    fi
else
    echo "cargo not found; skipping the HTTP/2 feature guard"
fi

echo "egress-only check passed"
