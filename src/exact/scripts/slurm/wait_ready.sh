#!/usr/bin/env bash
set -euo pipefail
exact_bin=$1; exact_target=$2
for ((exact_attempt=0; exact_attempt<600; exact_attempt++)); do
    if "$exact_bin" probe --target "$exact_target" 2>/dev/null; then exit 0; fi
    sleep 1
done
echo 'Target did not become ready within the preflight deadline' >&2
exit 1
