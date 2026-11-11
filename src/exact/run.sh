#!/usr/bin/env bash
#SBATCH --job-name=exact-submit
#SBATCH --partition=skynet
#SBATCH --nodelist=skynet-02
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=1
#SBATCH --mem=512M
#SBATCH --time=00:05:00
#SBATCH --output=exact-submit-%j.log
# Bootstrap only. Actual target/client resources are requested together by the
# generated heterogeneous job; sbatch cannot interpolate positional arguments.
set -euo pipefail
if (($#!=3)); then echo 'Usage: sbatch run.sh SET_SIZE NUM_SETS MONITORS_PER_SET' >&2; exit 2; fi
: "${SLURM_JOB_ID:?Submit with sbatch; benchmark processes must run on compute nodes}"
exact_submit=${SLURM_SUBMIT_DIR:?}
if [[ -f $exact_submit/benchmark/Cargo.toml ]]; then
    exact_dir=$exact_submit
elif [[ -f $exact_submit/src/exact/benchmark/Cargo.toml ]]; then
    exact_dir=$exact_submit/src/exact
else
    echo 'Submit from the repository root or from src/exact' >&2; exit 2
fi
exec python3 "$exact_dir/scripts/slurm/run_once.py" submit "$@"
