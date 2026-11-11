#!/usr/bin/env python3
"""Submit and run the finite skynet-target/Linux-monitor latency experiment."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import sys
import time

EXACT = Path(__file__).resolve().parents[2]
REPO = EXACT.parent.parent
TARGET = "skynet-02"


def validate_parameters(size, sets, monitors):
    if min(size, sets, monitors) <= 0 or size > 16383 or sets > 1000:
        raise ValueError("S/N/M must be positive; S <= 16383 and N <= 1000")
    total = sets * monitors
    if total > 10000 or size * sets > 1000000 or (size + 1) * total > 10000000:
        raise ValueError("configuration exceeds the exact benchmark's safety limits")
    history = min(32 * 1024**2, 512 * 1024**2 // sets)
    if history < (size + 1) * 1024 + 32768:
        raise ValueError("configuration exceeds the bounded verification-history budget")
    return total


def thread_topology(text):
    result={}
    for line in text.splitlines():
        fields=dict(re.findall(r'(\w+)=([^\s]+)',line))
        if 'NodeName' in fields and 'ThreadsPerCore' in fields:
            result[fields['NodeName']]=max(1,int(fields['ThreadsPerCore']))
    return result


def inventory(text,threads=None):
    """Deduplicate physical node names; prefer CPU partition when listed twice."""
    nodes = {}
    for line in text.splitlines():
        fields = line.strip().split("|")
        if len(fields) != 4:
            continue
        name, partition, state, cpus = fields
        partition = partition.rstrip("*")
        if not re.fullmatch(r"linux[0-9]+", name) or partition not in ("compsci", "compsci-gpu"):
            continue
        if state.lower() not in ("idle", "mixed"):
            continue
        try:
            _, free, _, total = map(int, cpus.split("/"))
        except ValueError:
            continue
        if free <= 0:
            continue
        if threads is not None and name not in threads:
            raise ValueError(f"Cannot determine physical CPU topology for {name}")
        siblings=threads.get(name,1) if threads is not None else 1
        free_cores=free//siblings
        if free_cores==0:
            continue
        node = {"node": name, "partition": partition, "free_cpus_snapshot": free,
                "threads_per_core":siblings,"free_cores_estimate":free_cores,
                "total_cpus": total, "state_snapshot": state.lower()}
        if name not in nodes or partition == "compsci":
            nodes[name] = node
    return sorted(nodes.values(), key=lambda n: (n["partition"] != "compsci", n["state_snapshot"] != "idle", int(n["node"][5:])))


def choose_clients(total, nodes):
    if not nodes:
        raise ValueError("No eligible idle/mixed Linux client nodes with free CPUs")
    # User policy: one node per monitor whenever possible, with no 10-node cap
    # in that case. Cap at 10 only when monitors outnumber available machines.
    upper = total if total <= len(nodes) else min(10, len(nodes))
    for count in range(upper, 0, -1):
        base, extra = divmod(total, count)
        if base+(extra>0)>256:
            continue
        high = [n for n in nodes if n["free_cores_estimate"] >= base + 1][:extra]
        if len(high) != extra:
            continue
        selected = {n["node"] for n in high}
        rest = [n for n in nodes if n["node"] not in selected and n["free_cores_estimate"] >= base][:count-extra]
        if len(rest) != count-extra:
            continue
        return [{**node, "agent_id": i, "cores": base + (i < extra),
                 "monitor_ids": list(range(i, total, count))}
                for i, node in enumerate(high + rest)]
    raise ValueError(f"Cannot fit {total} monitors evenly on at most {upper} eligible machines with one free core per monitor")


def render_batch(plan, path):
    lines = ["#!/usr/bin/env bash", "#SBATCH --job-name=exact-latency",
             f"#SBATCH --output={shlex.quote(str(Path(plan['output'])/'slurm-%j.log'))}"]
    roles = [{"node": TARGET, "partition": "skynet", "cores": 12}, *plan["clients"]]
    for group, role in enumerate(roles):
        if group:
            lines.append("#SBATCH hetjob")
        lines.extend([f"#SBATCH --partition={role['partition']}", f"#SBATCH --nodelist={role['node']}",
                      "#SBATCH --nodes=1", "#SBATCH --ntasks=1", f"#SBATCH --cpus-per-task={role['cores']}",
                      "#SBATCH --hint=nomultithread", "#SBATCH --mem=16G", "#SBATCH --time=01:00:00"])
        account = os.environ.get({"skynet": "SKYNET_ACCOUNT", "compsci": "COMPSCI_ACCOUNT", "compsci-gpu": "GPU_ACCOUNT"}[role["partition"]])
        if account:
            if not re.fullmatch(r"[a-zA-Z0-9_.-]+", account):
                raise ValueError("invalid Slurm account name")
            lines.append(f"#SBATCH --account={account}")
    lines.extend(["set -euo pipefail", "exec " + shlex.join([sys.executable, str(Path(__file__).resolve()), "execute", str(path)]), ""])
    return "\n".join(lines)


def submit(args):
    if not os.environ.get("SLURM_JOB_ID") or not os.environ.get("SLURMD_NODENAME"):
        raise ValueError("submission bootstrap must run inside its Slurm compute allocation")
    total = validate_parameters(args.set_size, args.num_sets, args.monitors_per_set)
    text = subprocess.check_output(["sinfo", "--Node", "--noheader", "--format=%N|%P|%T|%C"], text=True)
    topology = subprocess.check_output(["scontrol","show","nodes","--oneliner"],text=True)
    clients = choose_clients(total, inventory(text,thread_topology(topology)))
    output = EXACT / "benchmark/results" / f"once-{os.environ['SLURM_JOB_ID']}"
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    plan = {"set_size": args.set_size, "num_sets": args.num_sets, "monitors_per_set": args.monitors_per_set,
            "total_monitors": total, "target_node": TARGET, "target_cores": 12,
            "pok": True, "round1": False, "rounds_per_monitor": 1,
            "clients": clients, "output": str(output), "inventory_snapshot": text,
            "topology_snapshot":topology,
            "submission_log":str(Path(os.environ.get("SLURM_SUBMIT_DIR",str(EXACT)))/f"exact-submit-{os.environ['SLURM_JOB_ID']}.log"),
            "latency_definition": "monitor observation submission (including set queue and proof computation) to target counter/ciphertext/proof commit; excludes deployment and response verification"}
    path = output / "plan.json"
    path.write_text(json.dumps(plan, indent=2))
    batch = output / "experiment.sbatch"
    batch.write_text(render_batch(plan, path))
    job = subprocess.check_output(["sbatch", "--parsable", f"--chdir={REPO}",
                                   f"--dependency=afterok:{os.environ['SLURM_JOB_ID']}", str(batch)], text=True).strip()
    (output / "job-id.txt").write_text(job + "\n")
    print(f"Target: {TARGET}, 12 cores; {total} monitors on {len(clients)} Linux machines")
    for node in clients:
        print(f"  {node['node']} ({node['partition']}): {node['cores']} monitors / cores")
    print(f"Experiment job: {job}\nResults and final average: {output}")


def step(group, role, cores=None, mem="16G"):
    return ["srun", f"--het-group={group}", "--exact", "--nodes=1", "--ntasks=1",
            f"--nodelist={role['node']}", f"--cpus-per-task={cores or role['cores']}",
            "--cpu-bind=cores", f"--mem={mem}"]


def affinity(cores, command):
    if command and command[0] == "--":
        command = command[1:]
    representatives = {}
    for cpu in sorted(os.sched_getaffinity(0)):
        topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
        key = ((topology / "physical_package_id").read_text().strip(), (topology / "core_id").read_text().strip())
        representatives.setdefault(key, cpu)
    if len(representatives) < cores:
        raise ValueError(f"Slurm affinity exposes {len(representatives)} physical cores, expected {cores}")
    selected = list(representatives.values())[:cores]
    os.sched_setaffinity(0, selected)
    print(f"{os.environ.get('SLURMD_NODENAME')}: binding {cores} cores to CPU IDs {selected}", file=sys.stderr, flush=True)
    os.execvp(command[0], command)


def report(output):
    target = json.loads((output / "target.json").read_text())
    plan = json.loads((output / "plan.json").read_text())
    c = target["manifest"]["config"]
    total = plan["total_monitors"]
    if any(c[key]!=plan[key] for key in ('set_size','num_sets','monitors_per_set')) or target['initialized_sets']!=plan['num_sets'] or target['manifest']['total_monitors']!=total:
        raise ValueError("target S/N/M topology differs from the requested experiment")
    if not target.get("pok") or target.get("round1") or c["rounds_per_monitor"] != 1:
        raise ValueError("wrong proof/round configuration")
    if c["target_host"] != TARGET or c["worker_threads"] != 12 or not target["distributed"]:
        raise ValueError("wrong target placement or CPU configuration")
    histogram = target["histograms"]["submission_to_commit"]
    if histogram["count"] != total or target["registered_monitors"] != total or target["deployed_monitors"] != total or not all(target["finished_agents"]):
        raise ValueError("not every monitor deployed and completed its observation; no successful average will be printed")
    ids = []
    uncertainty = 0
    for node in plan["clients"]:
        client = json.loads((output / f"agent{node['agent_id']}.json").read_text())
        if client.get("interrupted") or client["errors"] or client["hostname"] != node["node"]:
            raise ValueError("client failed or executed on the wrong host")
        actual = sorted(m["monitor_id"] for m in client["monitors"])
        if actual != node["monitor_ids"] or client["client_worker_threads"] != node["cores"]:
            raise ValueError("client core count or monitor assignment mismatch")
        if any(m["reporting"]["admission_cohort_completed"] != 1 for m in client["monitors"]):
            raise ValueError("a monitor did not complete exactly one observation")
        ids.extend(actual)
        uncertainty = max(uncertainty, client["clock_calibration"]["uncertainty_ns"])
    if sorted(ids) != list(range(total)):
        raise ValueError("duplicate or missing monitors")
    average = histogram["sum_s"] / total
    result = {"completed_requests": total, "average_latency_s": average,
              "average_latency_formatted_s": f"{average:.3f}", "clock_offset_uncertainty_s": uncertainty/1e9,
              "deployment_included": False, "definition": plan["latency_definition"],
              "target_node": TARGET, "target_cores": 12, "client_nodes": len(plan["clients"]), "pok": True, "round1": False}
    (output / "summary.json").write_text(json.dumps(result, indent=2))
    line = f"Average latency: {average:.3f} s"
    (output / "average_latency.txt").write_text(line + "\n")
    if plan.get("submission_log"):
        with Path(plan["submission_log"]).open("a") as log:
            log.write(line+f"\nResults: {output}\n")
    print(line, flush=True)


def execute(path):
    plan = json.loads(path.read_text())
    output = Path(plan["output"])
    if os.environ.get("SLURMD_NODENAME") != TARGET or int(os.environ.get("SLURM_HET_SIZE", "0")) != len(plan["clients"]) + 1:
        raise ValueError("execute requires the generated heterogeneous Slurm allocation on skynet-02")
    target_role = {"node": TARGET, "cores": 12}
    roles = [target_role, *plan["clients"]]
    for group, role in enumerate(roles):
        actual = subprocess.check_output(["scontrol", "show", "hostnames", os.environ[f"SLURM_JOB_NODELIST_HET_GROUP_{group}"]], text=True).split()
        if actual != [role["node"]]:
            raise ValueError("allocated node differs from requested placement")
    # Verify real physical names before any protocol session starts.
    physical = [subprocess.check_output(step(i, role, 1, "256M") + ["hostname"], text=True).strip() for i, role in enumerate(roles)]
    if len(set(physical)) != len(physical):
        raise ValueError("two allocation components refer to the same physical machine")
    placement = {"target_node": TARGET, "client_nodes": [r["node"] for r in plan["clients"]],
                 "physical_hostnames": physical, "slurm_job_id": os.environ["SLURM_JOB_ID"], "experiment": "finite-latency", "repetition": 0}
    (output / "placement.json").write_text(json.dumps(placement, indent=2))
    binary = EXACT / "benchmark/target/release/exact-bench"
    subprocess.run(step(0, target_role) + ["env", "RUSTFLAGS=-C target-cpu=x86-64", "cargo", "build", "--release", "--locked", "--jobs", "12", "--manifest-path", str(EXACT / "benchmark/Cargo.toml")], check=True, cwd=REPO)
    subprocess.run([str(binary), "keygen", "--num-sets", str(plan["num_sets"]), "--key-file", str(output/"monitor.key"), "--public-keys", str(output/"public.json")], check=True)
    port = 20000 + int(os.environ["SLURM_JOB_ID"].split("_")[0]) % 30000
    target = f"{TARGET}:{port}"
    wrapper = EXACT / "scripts/slurm/run_role.sh"
    helper = Path(__file__).resolve()
    processes, logs = [], []

    def start(group, role, name, command):
        log = (output/f"{name}.log").open("w")
        logs.append(log)
        full = step(group, role) + [sys.executable, str(helper), "affinity", str(role["cores"]), "--", str(wrapper), str(binary), str(output), name, *command]
        process = subprocess.Popen(full, stdout=log, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def stop(signum, _frame):
        raise RuntimeError(f"experiment interrupted by signal {signum}")

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server = start(0, target_role, "target", ["target-server", "--bind", f"0.0.0.0:{port}",
            "--set-size", str(plan["set_size"]), "--num-sets", str(plan["num_sets"]), "--monitors-per-set", str(plan["monitors_per_set"]),
            "--client-nodes", str(len(plan["clients"])), "--target-host", TARGET, "--client-hosts", ",".join(n["node"] for n in plan["clients"]),
            "--distributed", "true", "--worker-threads", "12", "--pok", "true", "--round1", "false", "--rounds-per-monitor", "1",
            "--warmup-seconds", "0", "--duration-seconds", "3000", "--timeout-ms", "600000", "--workload", "fresh",
            "--run-id", output.name, "--public-keys", str(output/"public.json")])
        # Server readiness and each TCP probe execute only on client components.
        for i, node in enumerate(plan["clients"], 1):
            probe = [str(EXACT/"scripts/slurm/wait_ready.sh"), str(binary), target] if i == 1 else [str(binary), "probe", "--target", target]
            with (output/f"connectivity-{i-1}.json").open("w") as f:
                subprocess.run(step(i, node, 1, "256M") + probe, stdout=f, check=True)
        clients = [start(i, node, f"agent{node['agent_id']}", ["monitor-load", "--target", target,
            "--agent-id", str(node["agent_id"]), "--key-file", str(output/"monitor.key"), "--client-workers", str(node["cores"])])
            for i, node in enumerate(plan["clients"], 1)]
        deadline = time.monotonic()+3300
        while any(p.poll() is None for p in clients):
            if server.poll() is not None and any(p.poll() is None for p in clients):
                # Finish acknowledgements can precede the last client's process exit.
                if server.returncode != 0:
                    raise RuntimeError("target failed; inspect target.log")
            if any(p.poll() not in (None, 0) for p in clients):
                raise RuntimeError("a client failed; inspect agent logs")
            if time.monotonic() > deadline:
                raise RuntimeError("finite experiment deadline exceeded")
            time.sleep(.1)
        if any(p.returncode for p in clients) or server.wait(timeout=30):
            raise RuntimeError("target or client exited unsuccessfully")
        report(output)
    except BaseException:
        (output/"FAILED").write_text("Experiment failed; no complete average is valid. Inspect role logs.\n")
        raise
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("submit")
    for name in ("set_size", "num_sets", "monitors_per_set"):
        s.add_argument(name, type=int)
    sub.add_parser("execute").add_argument("plan", type=Path)
    a = sub.add_parser("affinity")
    a.add_argument("cores", type=int)
    a.add_argument("program", nargs=argparse.REMAINDER)
    sub.add_parser("report").add_argument("output", type=Path)
    args = p.parse_args()
    if args.command == "submit":
        submit(args)
    elif args.command == "execute":
        execute(args.plan)
    elif args.command == "affinity":
        affinity(args.cores, args.program)
    else:
        report(args.output)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error)) from error
