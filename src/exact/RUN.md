# One observation per monitor on Duke Slurm

From the repository root:

```bash
sbatch src/exact/run.sh 1000 4 5
```

Or, to use the requested `sbatch run.sh` form:

```bash
cd src/exact
sbatch run.sh 1000 4 5
```

The three arguments are set size S, number of sets N, and monitors per set M.
The target initializes exactly N sets and all N*M monitors deploy before the
reporting barrier. Every monitor then submits exactly one synthetic matching
observation, with `--pok true --round1 false`. When M exceeds S some observations
repeat; the original distinctness behavior still applies.

The target is fixed to **skynet-02**, partition **skynet**, with **12 physical CPU
cores** and up to 12 cryptographic workers. Live `sinfo` selects Linux machines
in `compsci` first, then additional eligible Linux machines in `compsci-gpu` when
needed. This uses the permission to run on any Linux machine. Draining, drained,
down, unresponsive, and fully allocated nodes are excluded from selection.
`scontrol` CPU topology discounts SMT sibling threads when estimating free cores.

The client placement policy is:

- If enough eligible machines exist, one machine and one core per monitor,
  including when this needs more than ten machines.
- Otherwise, at most ten machines, with monitor counts differing by at most one.
  Twenty monitors on ten available machines receive two cores per machine.
- Each host runs one load-generator process with one CPU worker and one reserved
  physical core per hosted monitor. Each monitor has independent protocol/session
  state and performs its cryptography on one worker at a time. Network and event
  writer threads share that same CPU allocation.

Slurm uses `--hint=nomultithread` and explicit CPU binding. A runtime affinity
wrapper restricts each process to one hardware thread per allocated physical
core. Target and clients occupy different physical hosts, checked before startup.
The scheduler remains authoritative: machines that become busy after the inventory
snapshot can make the job wait in the queue.

Slurm cannot substitute script arguments into `#SBATCH` resource directives.
`run.sh` therefore runs a small submission bootstrap on skynet-02 and automatically
submits a dependent [heterogeneous job](https://slurm.schedmd.com/heterogeneous_jobs.html)
with the calculated resources. Component
zero is the target; every client component selects its own Linux host, partition,
and core count. They are scheduled together. The experiment builds the portable
release binary on its allocated target cores, so no manual build or benchmark
computation on the login node is required. Cargo/Rust 1.88 and Python 3 must be
available on compute nodes, and the project directory must be shared between hosts.
If cluster account selection is required, export `SKYNET_ACCOUNT`,
`COMPSCI_ACCOUNT`, and/or `GPU_ACCOUNT` before submission. If skynet requires
an explicit account for the bootstrap too, pass `sbatch --account=ACCOUNT run.sh S N M`.

The first job's `exact-submit-JOBID.log` prints the selected hosts, experiment job
ID, and results directory. The final mean is appended to that log when using its
default name. Full experiment logs and summaries live under
`src/exact/benchmark/results/once-JOBID/`, including:

```text
Average latency: 0.123 s
```

`average_latency.txt` contains that line; `summary.json` retains full precision,
completed-request count, timing definition, and clock-calibration uncertainty.
The average weights every completed observation equally and is printed only after
all N*M monitors have completed exactly one report. Failures do not produce a
successful average.

Latency begins immediately before the monitor first submits its observation
request, retaining that start across backpressure retries. It includes waiting
for its set, receipt/verification of current encrypted state, monitor proof
computation, network transfer, target verification, and target counter/ciphertext/
proof commit in memory. Deployment, the initial barrier wait, final response
transfer, and the monitor's final response verification are excluded.

Each client agent calibrates its monotonic clock against the target using eight
four-timestamp exchanges before deployment. The minimum-RTT exchange estimates
the clock offset; half its residual RTT is recorded as offset uncertainty at
calibration. Thus the cross-machine endpoint latency is an estimate, without an
assumption of synchronized wall clocks. Drift after calibration is not corrected.
Three decimal places specify output formatting, not a guarantee of sub-millisecond
measurement accuracy.

Monitors sharing one set use its common monitor-side threshold key share, as
required by the existing protocol; the target receives public shares only. The
target state is in memory and a new experiment initializes fresh state. The
script has local planner, protocol, and process tests; successful Duke execution
must still be confirmed on the actual cluster.
