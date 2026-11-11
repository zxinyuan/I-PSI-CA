#!/usr/bin/env bash
# Sourced by the sbatch entry points; all CPU-intensive roles run through srun.
set -euo pipefail
exact_scripts=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exact_dir=$(cd -- "$exact_scripts/../.." && pwd)
export EXACT_BIN=${EXACT_BIN:-$exact_dir/benchmark/target/release/exact-bench}
"$exact_scripts/preflight.sh"
mapfile -t exact_nodes < <(scontrol show hostnames "$SLURM_JOB_NODELIST")
exact_target=${exact_nodes[0]}
exact_clients=("${exact_nodes[@]:1}")
exact_k=${#exact_clients[@]}
if [[ ${SMOKE_ASSERT:-false} == true ]] && ((exact_k<2)); then echo 'Cross-client shared-set smoke requires at least 3 allocated nodes' >&2; exit 1; fi
: "${SET_SIZE:=1000}" "${NUM_SETS:=10}" "${MONITORS_PER_SET:=10}"
: "${WORKERS:=8}" "${CLIENT_WORKERS:=${SLURM_CPUS_PER_TASK:-8}}"
: "${WARMUP:=5}" "${DURATION:=30}" "${SEED:=42}" "${MODE:=closed-loop}" "${WORKLOAD:=mixed}" "${OFFERED_RATE:=100}"
: "${TIMEOUT_MS:=120000}" "${MAX_INFLIGHT:=256}" "${MAX_QUEUE_PER_SET:=100}" "${STEP_MEM:=16G}"
: "${RUN_ID:=slurm-${SLURM_JOB_ID}}" "${EXPERIMENT:=manual}" "${REPETITION:=0}"
export EXPERIMENT REPETITION
python3 - "$SET_SIZE" "$NUM_SETS" "$MONITORS_PER_SET" "$exact_k" "$WORKERS" "$CLIENT_WORKERS" "${SLURM_CPUS_PER_TASK:-8}" <<'PY'
import sys
s,n,m,k,w,cw,cpus=map(int,sys.argv[1:])
assert 0<s<=16383 and 0<n<=1000 and 0<m, 'S/N/M must be positive and inside safety limits'
assert k<=n*m<=10000 and s*n<=1000000, 'invalid monitor/element count or topology overflow'
assert 0<w<=cpus and 0<cw<=cpus, 'worker counts must fit the allocated CPU count'
print(f'Validated: S={s}, N={n}, M={m}, total monitors={n*m}, clients={k}')
PY
[[ $RUN_ID =~ ^[A-Za-z0-9._-]+$ ]] || { echo 'Unsafe run ID' >&2; exit 1; }
exact_out=${RESULTS_ROOT:-$exact_dir/benchmark/results}/$RUN_ID
mkdir -p -- "$(dirname -- "$exact_out")"
mkdir -- "$exact_out"
python3 - "$exact_out/placement.json" "$exact_target" "${exact_clients[@]}" <<'PY'
import json, os, sys
json.dump({'target_node':sys.argv[2], 'client_nodes':sys.argv[3:], 'slurm_job_id':os.environ['SLURM_JOB_ID'], 'experiment':os.environ.get('EXPERIMENT','manual'), 'repetition':int(os.environ.get('REPETITION','0'))},open(sys.argv[1],'w'),indent=2)
PY
# Lightweight key provisioning on the batch node. The target receives public
# keys only; secret shares are consumed exclusively by client processes.
"$EXACT_BIN" keygen --num-sets "$NUM_SETS" --key-file "$exact_out/monitor.key" --public-keys "$exact_out/public.json"
exact_target_pid=''; exact_agent_pids=()
cleanup() {
    local code=$?
    for exact_pid in "${exact_agent_pids[@]}"; do kill -TERM "$exact_pid" 2>/dev/null || true; done
    [[ -z $exact_target_pid ]] || kill -TERM "$exact_target_pid" 2>/dev/null || true
    for exact_pid in "${exact_agent_pids[@]}"; do wait "$exact_pid" 2>/dev/null || true; done
    [[ -z $exact_target_pid ]] || wait "$exact_target_pid" 2>/dev/null || true
    if ((code!=0)); then printf '%s\n' "$code" > "$exact_out/FAILED"; fi
    return "$code"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
exact_port=${PORT:-50051}
exact_host_csv=$(IFS=,; echo "${exact_clients[*]}")
exact_extra=()
[[ -z ${HISTORY_BYTES_PER_SET:-} ]] || exact_extra+=(--history-bytes-per-set "$HISTORY_BYTES_PER_SET")
srun --exact --nodes=1 --ntasks=1 --nodelist="$exact_target" --cpus-per-task="${SLURM_CPUS_PER_TASK:-8}" --mem="$STEP_MEM" \
    "$exact_scripts/run_role.sh" "$EXACT_BIN" "$exact_out" target target-server \
    --bind "0.0.0.0:$exact_port" --set-size "$SET_SIZE" --num-sets "$NUM_SETS" --monitors-per-set "$MONITORS_PER_SET" \
    --client-nodes "$exact_k" --client-hosts "$exact_host_csv" --target-host "$exact_target" --distributed true \
    --worker-threads "$WORKERS" --seed "$SEED" --run-id "$RUN_ID" --mode "$MODE" --workload "$WORKLOAD" --offered-rate "$OFFERED_RATE" \
    --warmup-seconds "$WARMUP" --duration-seconds "$DURATION" --timeout-ms "$TIMEOUT_MS" --max-inflight "$MAX_INFLIGHT" --max-queue-per-set "$MAX_QUEUE_PER_SET" \
    --public-keys "$exact_out/public.json" "${exact_extra[@]}" >"$exact_out/target.log" 2>&1 &
exact_target_pid=$!
# Readiness is checked from a client node, never by starting a client on target.
srun --exact --nodes=1 --ntasks=1 --nodelist="${exact_clients[0]}" --cpus-per-task=1 --mem=256M \
    "$exact_scripts/wait_ready.sh" "$EXACT_BIN" "$exact_target:$exact_port" > "$exact_out/manifest.json"
for ((exact_agent=0; exact_agent<exact_k; exact_agent++)); do
    srun --exact --nodes=1 --ntasks=1 --nodelist="${exact_clients[exact_agent]}" --cpus-per-task=1 --mem=256M \
        "$EXACT_BIN" probe --target "$exact_target:$exact_port" > "$exact_out/connectivity-$exact_agent.json"
done
for ((exact_agent=0; exact_agent<exact_k; exact_agent++)); do
    srun --exact --nodes=1 --ntasks=1 --nodelist="${exact_clients[exact_agent]}" --cpus-per-task="${SLURM_CPUS_PER_TASK:-8}" --mem="$STEP_MEM" \
        "$exact_scripts/run_role.sh" "$EXACT_BIN" "$exact_out" "agent$exact_agent" monitor-load \
        --target "$exact_target:$exact_port" --agent-id "$exact_agent" --key-file "$exact_out/monitor.key" --client-workers "$CLIENT_WORKERS" \
        > "$exact_out/agent$exact_agent.log" 2>&1 &
    exact_agent_pids+=("$!")
done
for exact_pid in "${exact_agent_pids[@]}"; do wait "$exact_pid"; done
exact_agent_pids=()
wait "$exact_target_pid"; exact_target_pid=''
"$exact_scripts/collect_results.sh" "$exact_out"
if [[ ${SMOKE_ASSERT:-false} == true ]]; then
    python3 - "$exact_out/target.json" <<'PY'
import json, sys
t=json.load(open(sys.argv[1]))
assert t['distributed'] and t['initialized_sets']==1
assert t['manifest']['config']['client_nodes']>=2
assert t['registered_monitors']==t['manifest']['total_monitors']==4
assert t['sets'][0]['distinct_matches']==1, 'cross-node duplicate counted twice'
assert t['active_sets_peak']==1
print('Distributed shared-set smoke assertions passed')
PY
fi
printf 'Results: %s\n' "$exact_out"
