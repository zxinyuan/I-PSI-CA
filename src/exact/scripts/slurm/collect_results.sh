#!/usr/bin/env bash
set -euo pipefail
exact_source=${1:?Usage: collect_results.sh RESULT_DIRECTORY [ARCHIVE.tar.gz]}
exact_scripts=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 "$exact_scripts/../../analysis/analyze.py" "$exact_source" --output "$exact_source/analysis" --require-distributed --verify --no-plots
if [[ -n ${2:-} ]]; then
    # Do not archive the monitor group's secret key.
    tar --exclude=monitor.key --exclude='*.partial' -czf "$2" -C "$exact_source" .
fi
