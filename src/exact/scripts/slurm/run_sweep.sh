#!/usr/bin/env bash
# Submission only: safe on a login node. Every measurement uses a fresh job.
set -euo pipefail
exact_scripts=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exact_plan=$(mktemp /tmp/exact-matrix-XXXXXX.tsv)
python3 "$exact_scripts/../../analysis/matrix.py" "$@" > "$exact_plan"
printf 'job_id\texperiment\trepetition\tset_size\tnum_sets\tmonitors_per_set\tworkers\tclient_nodes\tmode\toffered_rate\tseed\n'
while IFS=$'\t' read -r exact_exp exact_rep exact_s exact_n exact_m exact_w exact_k exact_mode exact_rate exact_seed; do
    exact_job=$(sbatch --parsable --partition=compsci --nodes="$((exact_k+1))" --ntasks-per-node=1 --cpus-per-task=16 \
        --export="ALL,EXPERIMENT=$exact_exp,REPETITION=$exact_rep,SET_SIZE=$exact_s,NUM_SETS=$exact_n,MONITORS_PER_SET=$exact_m,WORKERS=$exact_w,CLIENT_WORKERS=16,MODE=$exact_mode,OFFERED_RATE=$exact_rate,SEED=$exact_seed" \
        "$exact_scripts/benchmark.sbatch")
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$exact_job" "$exact_exp" "$exact_rep" "$exact_s" "$exact_n" "$exact_m" "$exact_w" "$exact_k" "$exact_mode" "$exact_rate" "$exact_seed"
done < "$exact_plan"
