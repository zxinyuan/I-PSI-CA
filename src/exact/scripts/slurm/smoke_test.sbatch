#!/usr/bin/env bash
#SBATCH --partition=compsci
#SBATCH --nodes=3
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=2
#SBATCH --mem=16G
#SBATCH --time=00:10:00
#SBATCH --output=exact-smoke-%j.log
set -euo pipefail
export SET_SIZE=4 NUM_SETS=1 MONITORS_PER_SET=4 WORKERS=2 CLIENT_WORKERS=2 WARMUP=1 DURATION=3 WORKLOAD=shared SMOKE_ASSERT=true
source "${SLURM_SUBMIT_DIR:?}/src/exact/scripts/slurm/driver.sh"
