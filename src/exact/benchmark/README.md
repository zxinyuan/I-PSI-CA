# Distributed exact-protocol benchmark

This crate benchmarks only `src/exact`. It links the existing library with
`default-features = false`, leaving the unrelated experimental protocol out of
the build. All benchmark code, scripts, tests, and analysis live under `src/exact`.
The original single-process executable and its flags retain their behavior.

## Build and local verification

From the repository root:

```bash
cargo fmt --manifest-path src/exact/benchmark/Cargo.toml --check
cargo clippy --manifest-path src/exact/benchmark/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path src/exact/benchmark/Cargo.toml --locked
cargo test --locked --no-default-features --lib exact::
RUSTFLAGS='-C target-cpu=x86-64' cargo build --release --locked --manifest-path src/exact/benchmark/Cargo.toml
python3 -m unittest discover -s src/exact/analysis -p 'test_*.py'
```

The explicit portable CPU flag overrides the repository's existing
`target-cpu=native` setting. Use a compatible portable architecture when moving a
binary between heterogeneous compute nodes. On Duke, compile inside a compute
allocation, for example prefix the build command with
`srun -p compsci -N1 -n1 -c8 --mem=16G --time=00:20:00 env`.
The pinned Rust toolchain needs the `rustfmt` and `clippy` components.
Plotting requires Python 3 and Matplotlib; aggregation with `--no-plots` uses only
the Python standard library.

Run actual cryptography across separate **local processes** for development:

```bash
python3 src/exact/scripts/local_smoke.py --output /tmp/exact-local-closed
python3 src/exact/scripts/local_smoke.py --output /tmp/exact-local-open \
  --mode open-loop --offered-rate 10000 --workload shared --port 50052
python3 src/exact/scripts/local_smoke.py --output /tmp/exact-local-interrupt \
  --duration 20 --interrupt-after 2
```

These runs are labeled `distributed=false`. They are never distributed benchmark
evidence. Output directories must be new so existing results cannot be replaced.

## Roles and authoritative configuration

```bash
BIN=src/exact/benchmark/target/release/exact-bench
$BIN keygen --num-sets 10 --key-file /tmp/monitor.key --public-keys /tmp/public.json
$BIN target-server --bind 0.0.0.0:50051 \
  --set-size 1000 --num-sets 10 --monitors-per-set 20 \
  --client-nodes 3 --worker-threads 8 --seed 42 \
  --public-keys /tmp/public.json --output /tmp/target.json
# On each client host, using a securely provisioned copy of monitor.key:
$BIN monitor-load --target target-host:50051 --agent-id 0 \
  --key-file /tmp/monitor.key --client-workers 8 --output /tmp/agent0.json
# Repeat on the other hosts with agent IDs 1 and 2.
$BIN probe --target target-host:50051
```

The keygen invocation is an orchestration step based on the target's N. Agents
receive S/N/M, IDs, mappings, seed, workload, and timing from the target; they do
not accept their own copies of N or M. The manifest contains all assignments:
`set_id = monitor_id / M`, `agent_id = monitor_id % K`. These mappings remain
independent, including monitors for one set hosted on different client nodes.
Each monitor has its own connection, random session identifier, sequence number,
verified polynomial, update cursor, and cryptographic prover state.

For enforced distributed placement, the scripts also provide `--distributed true`,
`--target-host`, and `--client-hosts` using allocated Slurm node names. Both roles
check their actual Slurm node identity and reject target/client overlap.
The transport is intended for a trusted cluster network: it is length-framed
bincode over persistent TCP, with TCP_NODELAY and a 64 MiB frame limit. It does
not add TLS or adversarial identity authentication.

Target options and defaults:

| Option | Default | Meaning |
| --- | --- | --- |
| `--set-size`, `--num-sets`, `--monitors-per-set` | 1000, 10, 20 | Independent S, N, M |
| `--client-nodes` | 1 | Physical client agents K |
| `--worker-threads` | 8 | Maximum target cryptographic CPU jobs |
| `--max-inflight` | 256 | Accepted active + queued interactions globally |
| `--max-queue-per-set` | 100 | Waiting interactions, plus one active lease |
| `--history-bytes-per-set` | min(32 MiB, 512 MiB/N) | Bounded verification journal |
| `--timeout-ms` | 120000 | Socket operations, full set lease, and deployment barrier |
| `--warmup-seconds`, `--duration-seconds` | 5, 30 | Separate warmup and measurement |
| `--mode` | closed-loop | `closed-loop` or `open-loop` |
| `--offered-rate` | 100 | Global open-loop arrivals/second across all monitors |
| `--workload` | mixed | `fresh`, `nonmatch`, `repeated`, `shared`, `mixed` |
| `--seed`, `--run-id` | 42, local | Reproducible inputs and experiment identity |

All count options are positive. Validation rejects overflow, S > 16383,
N > 1000, N*M > 10000, S*N > 1000000, (S+1)*N*M > 10000000,
K > N*M, workers > 256, inflight/queue > 10000, and invalid timings/rates.
History is limited to 32 MiB/set and 512 MiB total, must fit a conservative
single-update bound, and is checked against the actual serialized update before
commit. Public key files are limited to 2 MiB. Connections are bounded to N*M+32;
CPU submissions and event-writer buffering are bounded independently.

## Protocol and shared-set behavior

The original flow is target initial encrypted polynomial + initial PoK; monitor
division/evaluation/partial-decryption proof; target verification and zero test;
conditional quotient selection; rerandomization + disjunctive proof. A match
removes one root. Subsequent reports of that root fail the zero test. The fixed
ciphertext width, quotient padding, proof equations, private randomness, and
rerandomization behavior are unchanged. `session.rs` exposes reusable operations
around those existing functions; it does not substitute a plaintext lookup.

Exactly N private root vectors are generated and encrypted once during target
initialization. Roots are discarded after encryption, avoiding a redundant
plaintext match-history map. The evolving polynomial implements distinctness;
the target retains a distinct-match counter per set. Synthetic root zero is
deliberately common to all sets for independent-history tests; other roots are
domain separated by seed, set, and index. Only benchmark inputs are deterministic.
Keys, sessions, and proof randomness use secret randomness.

Each monitor deployment verifies the original initial PoK. All N*M deployments
must acknowledge readiness before a shared start schedule is issued. No target
set is reinitialized for a new monitor. Warmup mutates the same set state that
measurement uses; independent experiments launch a fresh target and fresh keys.

One FIFO async mutex per set acts as its actor mailbox. A bounded admission
semaphore counts its active and waiting requests. The set guard spans delivery
of the current verified history, monitor computation and report, target CPU work,
commit, delivery of the update, and monitor verification/acknowledgement. Network
awaits do not block an OS thread. Other sets hold different guards and may proceed.
CPU work runs in a separately bounded blocking pool, including during initialization.

A monitor catches up by checking every intervening original division proof and
target OR proof. This prevents accepting an unanchored or stale polynomial from
another session. Request transcripts bind the random server incarnation, monitor
session, sequence, and current set version. The server never sends a plaintext
item, match result, or branch selector to a monitor.

The journal is pruned only up to the slowest monitor's verified cursor. A slow
or disconnected monitor can fill it; `history_backpressure` then rejects new
updates until monitors catch up. This is intentional, visible overload, rather
than silently dropping the proof chain. Its cost is part of this protocol's
shared-set benchmark and should be compared across M.

State updates are pure CPU proposals committed atomically by the async owner.
Disconnect/timeout/cancel before commit releases the lease without changing the
set. A disconnect after commit leaves the removal committed. Reconnection with
the same live session returns `next_seq` and a verifiable catchup journal, so a
lost response cannot count the request twice. An already committed or out-of-order
sequence is rejected. Cancel applies to a granted request; closing a connection
also cancels it, and queued dead connections are reclaimed on admission/deadline.
CPU jobs finishing after cancellation retain their worker permits and cannot
commit a detached result. SIGINT/SIGTERM saves available target results. Client
signal handling stops new admissions, completes or cancels the current exchange
subject to protocol timeouts, drains its event writer, and saves partial results
marked `interrupted=true`. Analysis rejects interrupted runs as complete evidence.

**Protocol-specific trust limitation:** the existing exact ciphertext is bound
to a single combined threshold public key. Monitors sharing a set therefore
belong to one trusted monitor group and share that set's monitor-side key share.
The random 0600 secret file derives domain-separated shares per set and is never
read by the target role. Sessions and observations remain separate; neither the
target nor a monitor acting alone receives the other threshold share. Supporting
mutually distrustful monitors with unrelated threshold keys would require a new
key-switching/group-key protocol and a separate security analysis. This benchmark
does not claim that extension. Synthetic benchmark input indices are written to
client event logs solely to validate workload composition offline.

Target state is in memory. A target restart creates a fresh incarnation and
requires a new experiment; durable crash recovery is not implemented. A client
process must retain its verified state and session token to resume. If an update's
commit response was lost, target distinctness still holds; missing client event
history is explicitly flagged by analysis, rather than inventing observations.

## Workloads and metric definitions

Closed-loop monitors wait for their full previous exchange. Open-loop arrivals
are deterministic and evenly interleaved at the configured global rate. Each
monitor allows one outstanding exchange. Arrivals while it is busy are counted
as `dependency_dropped`; they are not buffered into a later burst. Offered,
actually sent, accepted, rejected, timed out, and completed counts are separate.
Latency begins at the scheduled arrival, including client scheduling delay.

`fresh` enumerates per-monitor disjoint member indices until the finite S-element
set is exhausted, then wraps. `repeated` reuses one item per monitor; `shared`
has every monitor use root zero; `nonmatch` uses a separate input domain; `mixed`
cycles these four. Warmup can consume fresh roots. Client JSONL events record
set version, session sequence, input category/index, and phase. Offline replay
in commit order determines actual new-match/replay/nonmatch composition, including
warmup history, and checks the target's distinct counters.

`throughput_rps` counts completions **inside** the measurement window, divided by
its duration; drain completions do not inflate throughput. Latencies and
admission counters use the measurement-admission cohort, which may finish during
drain, exposed as `admission_cohort_completed`. Target latency ends at atomic
commit; client latency ends at verified acknowledgement. Queue time, target
worker wait, actual target crypto, client worker/crypto time, and scheduling
delays are measured separately with monotonic clocks. Relative server deadlines
avoid dependence on clock synchronization; control-message transit can cause
small target/client boundary-cohort differences, which analysis labels.

Socket-await time is labeled `io_and_peer_wait`: it includes the remote monitor's
proof computation, and is not an isolated network propagation measurement.
Traffic counts length headers and serialized bytes, excluding TCP/IP overhead.
Fixed 512-bin histograms provide bounded memory and p50/p95/p99 upper-bin estimates
with up to 12.5% quantization error. Linux process CPU seconds, RSS/HWM, traffic,
queue depth, active sets and CPU jobs are sampled every 250 ms. CPU percentages
can exceed 100% on a multicore process; compare against workers*100%.

## Duke CS Slurm

The orchestration follows [Duke's Slurm FAQ](https://cs.duke.edu/csl/faqs/slurm),
[Duke CS compute documentation](https://computing.cs.duke.edu/compute/slurm/), and
[SchedMD's srun step-resource documentation](https://slurm.schedmd.com/srun.html).
It uses `compsci`, discovers hosts with `scontrol`, and launches every role with
explicit `srun --nodes=1 --ntasks=1 --nodelist=... --exact` CPU/memory allocations.
The first allocated node runs the sole target; all remaining nodes run exactly
one agent each. Hostname preflight checks reject aliases for the same physical
machine. Readiness/TCP probes run on client nodes. The default smoke job allocates
three nodes to exercise monitors sharing one set across two physical clients.

Submit from the repository root after building the portable binary:

```bash
sbatch src/exact/scripts/slurm/smoke_test.sbatch
sbatch --nodes=4 --export=ALL,SET_SIZE=1000,NUM_SETS=10,MONITORS_PER_SET=20 \
  src/exact/scripts/slurm/benchmark.sbatch
src/exact/scripts/slurm/run_sweep.sh --experiments A,B,C,D,E --repeats 3 > submissions.tsv
# After a measured pilot, use its sustainable throughput for overload rates:
src/exact/scripts/slurm/run_sweep.sh --experiments F --baseline-rps 123.4 --repeats 3
```

Each job receives fresh state. A fixes total monitors at 100 while sweeping N;
B fixes N=10 and sweeps M; C tests S=100/1000/10000 on representative A/B topologies;
D sweeps target workers 1/2/4/8/16; E allocates 1/2/4/8 clients **plus one target**;
F sweeps 0.25/0.5/0.8/1/1.2/1.5/2 times a supplied measured baseline.
The F baseline must use the same S/N/M, workers, client count, workload, and CPU
allocation as the F sweep.
Submission scripts do no benchmark computation on login nodes. Sweeps keep the per-node
CPU allocation at 16, client workers at 16, warmup/duration/workload fixed, and
vary only the intended dimension. Customize WARMUP, DURATION, RESULTS_ROOT,
STEP_MEM, TIMEOUT_MS, MAX_INFLIGHT, MAX_QUEUE_PER_SET, HISTORY_BYTES_PER_SET, or
EXACT_BIN via exported environment variables. Target/client workers must fit
the allocation. N*M and safety checks run before deployment.

Roles write summaries/events to local Slurm temporary storage, then copy them
to persistent `src/exact/benchmark/results/slurm-JOBID/`. Placement, connectivity,
logs, manifest, public keys, and private provisioning file are retained with it.
The collector validates exact assignment coverage and distinctness and can
archive results while excluding `monitor.key`. Failed jobs retain a FAILED marker.
No Duke Slurm execution is claimed by local tests.

## Analysis

```bash
python3 src/exact/analysis/analyze.py src/exact/benchmark/results \
  --output /tmp/exact-plots --require-distributed --verify
src/exact/scripts/slurm/collect_results.sh PATH_TO_ONE_RUN /tmp/exact-results.tar.gz
```

Outputs include runs/aggregate CSV, validation JSON, diagnostic notes, and PNG/PDF
figures for throughput/latency vs sets; throughput/queue vs monitors per set;
throughput vs set size, workers, client nodes and offered rate; memory vs sets;
and per-set throughput distributions. Plots are generated only for experiments
with actual input data. Error bars are sample standard deviations across repeated
runs, and groups with fewer than three repeats are flagged. Local/distributed,
CPU model, commit, workload, timing and non-swept topology dimensions remain
separate. Diagnostic notes explain contention vs worker saturation, client
capacity, network evidence and memory evidence without claiming causation from
one utilization counter. Raw time series and histograms remain in JSON.

Network regression tests cover all four topologies, shared-item removal,
independent histories, simultaneous set leases, queue rejection, cancellation,
disconnect/reconnect, replay/assignment checks, invalid frames and restart epochs.
The Slurm smoke asserts physical placement and cross-node shared-item distinctness
when actually run on the cluster. Local tests do not substitute for that check.
