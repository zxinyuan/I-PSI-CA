#!/usr/bin/env bash
#SBATCH --partition=compsci
#SBATCH --nodes=4
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=16G
#SBATCH --time=00:30:00
#SBATCH --output=exact-%j.log
set -euo pipefail
source "${SLURM_SUBMIT_DIR:?}/src/exact/scripts/slurm/driver.sh"
