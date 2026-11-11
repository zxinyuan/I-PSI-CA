#!/usr/bin/env bash
set -euo pipefail
: "${SLURM_JOB_ID:?Run inside a Slurm compute allocation, never on a login node}"
: "${SLURM_JOB_NODELIST:?Missing allocated nodes}"
for program in scontrol srun python3; do command -v "$program" >/dev/null; done
mapfile -t exact_nodes < <(scontrol show hostnames "$SLURM_JOB_NODELIST")
if ((${#exact_nodes[@]} < 2)); then echo 'Need one target plus at least one separate physical client node' >&2; exit 1; fi
exact_unique=$(printf '%s\n' "${exact_nodes[@]}" | sort -u | wc -l)
[[ $exact_unique -eq ${#exact_nodes[@]} ]] || { echo 'Duplicate allocated nodes' >&2; exit 1; }
[[ -n ${SLURMD_NODENAME:-} ]] || { echo 'Preflight must run on an allocated compute node' >&2; exit 1; }
if [[ -n ${EXACT_BIN:-} ]]; then [[ -x $EXACT_BIN ]] || { echo "Build binary first: $EXACT_BIN" >&2; exit 1; }; fi
# Check actual hostnames as well as Slurm node names, catching aliases for the
# same host. This step completes before any target/load-generator step starts.
mapfile -t exact_physical < <(srun --exact --nodes="${#exact_nodes[@]}" --ntasks="${#exact_nodes[@]}" --ntasks-per-node=1 --cpus-per-task=1 --mem=256M hostname)
[[ ${#exact_physical[@]} -eq ${#exact_nodes[@]} ]] || { echo 'Could not inspect every compute node' >&2; exit 1; }
[[ $(printf '%s\n' "${exact_physical[@]}" | sort -u | wc -l) -eq ${#exact_nodes[@]} ]] || { echo 'Allocated node names resolve to duplicate physical hosts' >&2; exit 1; }
printf 'Preflight OK: target=%s; separate client nodes=%s\n' "${exact_nodes[0]}" "$((${#exact_nodes[@]}-1))"
