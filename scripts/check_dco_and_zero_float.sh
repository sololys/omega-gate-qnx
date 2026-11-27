#!/bin/sh
set -eu

REPO_ROOT=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$REPO_ROOT"

BASE="${1:-HEAD~1}"
HEAD_REF="${2:-HEAD}"
ZERO_SHA="0000000000000000000000000000000000000000"

if [ "$BASE" = "$ZERO_SHA" ] || ! git cat-file -e "${BASE}^{commit}" 2>/dev/null; then
    if git cat-file -e "${HEAD_REF}~1^{commit}" 2>/dev/null; then
        BASE="${HEAD_REF}~1"
    else
        BASE=""
    fi
fi

if [ -n "$BASE" ]; then
    RANGE="${BASE}..${HEAD_REF}"
    COMMITS=$(git rev-list "$RANGE")
else
    RANGE="$HEAD_REF"
    COMMITS=$(git rev-list -n 1 "$HEAD_REF")
fi

for c in $COMMITS; do
    git log -n 1 --format=%B "$c" | grep -Eq '^Signed-off-by: .+ <.+@.+>$' || {
        echo "KILL: missing DCO 1.1 Signed-off-by in $c" >&2
        exit 1
    }
done

if [ -n "$BASE" ]; then
    DIFF_OUT=$(git diff -U0 "$BASE" "$HEAD_REF" -- '*.c' '*.h' '*.py' '*.sv')
else
    DIFF_OUT=$(git show --format= -U0 "$HEAD_REF" -- '*.c' '*.h' '*.py' '*.sv')
fi

if printf '%s
' "$DIFF_OUT" |    grep -Eq '^\+[^+].*(^|[^A-Za-z0-9_])(float|double|float32|float64)([^A-Za-z0-9_]|$)'; then
    echo "KILL: floating-point token in gated diff" >&2
    exit 1
fi

echo "OPEN: DCO 1.1 + 0-float diff gate PASS (${RANGE})"
