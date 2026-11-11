#!/usr/bin/env bash
set -euo pipefail
exact_bin=$1; exact_persistent=$2; exact_role=$3; shift 3
exact_local=$(mktemp -d "${SLURM_TMPDIR:-/tmp}/exact-${SLURM_JOB_ID:?}-${exact_role}-XXXXXX")
exact_child=''
copy_results() {
    local code=$?
    if [[ -n $exact_child ]] && kill -0 "$exact_child" 2>/dev/null; then kill -TERM "$exact_child"; wait "$exact_child" || true; fi
    for exact_file in "$exact_local"/*.json "$exact_local"/*.jsonl; do
        [[ -f $exact_file ]] && cp -- "$exact_file" "$exact_persistent/"
    done
    return "$code"
}
trap copy_results EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
"$exact_bin" "$@" --output "$exact_local/$exact_role.json" &
exact_child=$!
wait "$exact_child"
