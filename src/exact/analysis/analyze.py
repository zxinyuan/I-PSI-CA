#!/usr/bin/env python3
"""Validate, aggregate, and plot exact-bench results. No fabricated measurements."""
import argparse
import csv
import json
import math
import os
from pathlib import Path
import statistics
import tempfile
from collections import defaultdict


def percentile(hist, fraction):
    count = hist["count"]
    if not count:
        return 0
    target = math.ceil(count * fraction)
    running = 0
    for i, n in enumerate(hist["bins"]):
        running += n
        if running >= target:
            return min(hist["max_s"], 2 ** (i // 8) * (1 + (i % 8 + 1) / 8) / 1e9)
    return hist["max_s"]


def validate(target, clients, placement, require_distributed=False):
    errors = []
    m = target["manifest"]
    c = m["config"]
    total = c["num_sets"] * c["monitors_per_set"]
    check = lambda condition, message: errors.append(message) if not condition else None
    check(m["total_monitors"] == total, "N*M differs from total monitors")
    check(target["initialized_sets"] == c["num_sets"], "target did not initialize exactly N sets")
    check(target["registered_monitors"] == target["deployed_monitors"] == total, "missing registrations/deployments")
    check(len(target["sets"]) == c["num_sets"], "wrong set count in results")
    assignments = m["assignments"]
    check(len(assignments) == total, "wrong assignment count")
    check(sorted(a["monitor_id"] for a in assignments) == list(range(total)), "duplicate or missing monitor IDs")
    for a in assignments:
        check(a["set_id"] == a["monitor_id"] // c["monitors_per_set"], "wrong set mapping")
        check(a["agent_id"] == a["monitor_id"] % c["client_nodes"], "wrong client mapping")
    check(target["active_sets_peak"] <= c["num_sets"], "same-set execution overlap")
    check(target["active_cpu_jobs_peak"] <= c["worker_threads"], "CPU worker capacity exceeded")
    check(len(clients) == c["client_nodes"], "missing client result files")
    check(sorted(x["agent_id"] for x in clients) == list(range(c["client_nodes"])), "duplicate/missing client agent")
    check(all(target["finished_agents"]), "one or more client agents did not finish")
    observed_ids = []
    sessions = []
    for client in clients:
        check(client["manifest"] == m, "client used a different topology/run incarnation")
        check(not client["errors"], "client monitor failed")
        check(not client.get('interrupted',False), "client benchmark was interrupted")
        expected = [a["monitor_id"] for a in assignments if a["agent_id"] == client["agent_id"]]
        check(client["assigned_monitor_ids"] == expected, "agent hosted an incorrect monitor assignment")
        check(sorted(x["monitor_id"] for x in client["monitors"]) == expected, "missing monitor result")
        observed_ids += [x["monitor_id"] for x in client["monitors"]]
        sessions += [tuple(x["session"]) for x in client["monitors"]]
    check(sorted(observed_ids) == list(range(total)), "monitors missing from client nodes")
    check(len(set(sessions)) == total, "virtual monitors reused session identities")
    if target["distributed"] or require_distributed:
        check(target["distributed"] and c["distributed"], "loopback run is not a distributed result")
        hosts = [c["target_host"], *c["client_hosts"]]
        check(len(set(hosts)) == c["client_nodes"] + 1, "target/client host placement overlaps")
        check(bool(target["slurm_job_id"]), "distributed result lacks Slurm job ID")
        check(placement is not None, "distributed result lacks placement evidence")
        if placement:
            check(placement["target_node"] == c["target_host"], "Slurm target placement mismatch")
            check(placement["client_nodes"] == c["client_hosts"], "Slurm client placement mismatch")
            check(str(placement["slurm_job_id"]) == str(target["slurm_job_id"]), "Slurm job mismatch")
        for client in clients:
            check(client["hostname"] == c["client_hosts"][client["agent_id"]], "client executed on wrong physical host")
            check(str(client["slurm_job_id"]) == str(target["slurm_job_id"]), "client Slurm job mismatch")
    return errors


def composition(target, events):
    """Reconstruct actual synthetic composition in target commit order, including warmup."""
    sets = defaultdict(list)
    for event in events:
        sets[event["set_id"]].append(event)
    counts = {"new_matches": 0, "replays": 0, "nonmatches": 0, "unknown_commits": 0}
    errors = []
    for state in target["sets"]:
        rows = sorted(sets[state["set_id"]], key=lambda e: e["version"])
        seen = set()
        versions = [e["version"] for e in rows]
        expected = list(range(1, state["version"] + 1))
        if versions != expected:
            counts["unknown_commits"] += max(0, state["version"] - len(set(versions)))
            errors.append(f"set {state['set_id']}: incomplete/duplicate client event history")
        for event in rows:
            member = event["member"]
            replay = member and event["item_index"] in seen
            if event["phase"] == "Measurement":
                counts["replays" if replay else "new_matches" if member else "nonmatches"] += 1
            if member:
                seen.add(event["item_index"])
        if versions == expected and len(seen) != state["distinct_matches"]:
            errors.append(f"set {state['set_id']}: cryptographic distinct count disagrees with synthetic history")
    if not errors and counts["new_matches"] != target["reporting"]["matches"]:
        # Network delivery can put the client admission in a different boundary
        # cohort than the target. Report it explicitly rather than silently
        # asserting that host clocks are synchronized.
        counts["boundary_cohort_difference"] = counts["new_matches"] - target["reporting"]["matches"]
    return counts, errors


def run_row(path, require_distributed=False):
    target = json.loads(path.read_text())
    c = target["manifest"]["config"]
    clients = [json.loads(p.read_text()) for p in sorted(path.parent.glob("agent[0-9]*.json"))]
    placement_file = path.parent / "placement.json"
    placement = json.loads(placement_file.read_text()) if placement_file.exists() else None
    errors = validate(target, clients, placement, require_distributed)
    events = []
    for client in clients:
        event_file = path.parent / client["events_file"]
        if event_file.exists():
            events.extend(json.loads(line) for line in event_file.read_text().splitlines() if line)
        else:
            errors.append(f"missing event file {event_file.name}")
    mix, mix_errors = composition(target, events)
    errors.extend(mix_errors)
    samples = [s for s in target["samples"] if s["phase"] == "Measurement"]
    cpu_percent = 0
    network_mbps = 0
    if len(samples) >= 2:
        first, last = samples[0], samples[-1]
        seconds = last.get('elapsed_s',last['unix_ms']/1000)-first.get('elapsed_s',first['unix_ms']/1000)
        if seconds>0:
            cpu_percent = 100 * (last["cpu_s"] - first["cpu_s"]) / seconds
            network_mbps = 8 * (last["sent_bytes"] + last["received_bytes"] - first["sent_bytes"] - first["received_bytes"]) / seconds / 1e6
    report = target["reporting"]
    h = target["histograms"]
    row = {"run_id": c["run_id"], "experiment": (placement or {}).get("experiment", "manual"),
           "repetition": (placement or {}).get("repetition", 0), "distributed": target["distributed"],
           "set_size": c["set_size"], "num_sets": c["num_sets"], "monitors_per_set": c["monitors_per_set"],
           "total_monitors": target["manifest"]["total_monitors"], "client_nodes": c["client_nodes"],
           "worker_threads": c["worker_threads"], "mode": c["mode"], "workload": c["workload"],
           "offered_rate": c["offered_rate"], "duration_s": c["duration_s"], "warmup_s": c["warmup_s"],
           "seed": c["seed"], "throughput_rps": report["throughput_rps"],
           "p50_s": percentile(h["latency"], .5), "p95_s": percentile(h["latency"], .95), "p99_s": percentile(h["latency"], .99),
           "queue_s": report["set_wait"]["mean_s"], "worker_wait_s": report["worker_wait"]["mean_s"],
           "crypto_s": report["crypto"]["mean_s"], "io_peer_wait_s": report["io_and_peer_wait"]["mean_s"],
           "rejected": report["rejected"], "timeouts": report["timeouts"], "failures": report["failures"],
           "cpu_percent": cpu_percent, "network_mbps": network_mbps,
           "peak_rss_kib": target["resources"]["peak_rss_kib"], "mean_queued": statistics.mean(s["queued"] for s in samples) if samples else 0,
           "client_completed_rps": sum(x["reporting"]["throughput_rps"] for x in clients),
           "client_generated_rps": sum((x["reporting"]["offered"] - x["reporting"]["dependency_dropped"]) / c["duration_s"] for x in clients),
           "client_dependency_dropped": sum(x["reporting"]["dependency_dropped"] for x in clients),
           "max_client_cpu_percent": max((x.get('reporting_resources',{}).get('cpu_utilization_percent') or 0 for x in clients), default=0),
           "cpu_model": target["cpu_model"], "git_commit": target["git_commit"], "slurm_job_id": target["slurm_job_id"],
           "valid": not errors, **mix}
    return row, target, errors


def aggregate(rows):
    group_columns = ("experiment", "distributed", "set_size", "num_sets", "monitors_per_set", "total_monitors", "client_nodes", "worker_threads", "mode", "workload", "offered_rate", "duration_s", "warmup_s", "cpu_model", "git_commit")
    measures = ("throughput_rps", "p50_s", "p95_s", "p99_s", "queue_s", "worker_wait_s", "crypto_s", "io_peer_wait_s", "cpu_percent", "network_mbps", "peak_rss_kib", "mean_queued", "client_generated_rps", "client_completed_rps", "client_dependency_dropped", "rejected", "timeouts")
    grouped = defaultdict(list)
    for row in rows:
        if row["valid"]:
            grouped[tuple(row[k] for k in group_columns)].append(row)
    result = []
    for key, runs in sorted(grouped.items()):
        item = dict(zip(group_columns, key))
        item["repeats"] = len(runs)
        item["distinct_seeds"] = len(set(r["seed"] for r in runs))
        for measure in measures:
            values = [r[measure] for r in runs]
            item[measure + "_mean"] = statistics.mean(values)
            item[measure + "_stddev"] = statistics.stdev(values) if len(values) > 1 else 0
        result.append(item)
    return result


def write_csv(path, rows):
    if not rows:
        path.write_text("")
        return
    fields = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fields)
        writer.writeheader()
        writer.writerows(rows)


def plots(groups, targets, output):
    os.environ.setdefault("MPLCONFIGDIR", str(Path(tempfile.gettempdir()) / "exact-matplotlib"))
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    specs = [("A", "num_sets", "throughput_rps", "Throughput (rounds/s)", "throughput-vs-sets"),
             ("A", "num_sets", "p95_s", "p95 latency (s)", "latency-vs-sets"),
             ("B", "monitors_per_set", "throughput_rps", "Throughput (rounds/s)", "throughput-vs-monitors"),
             ("B", "monitors_per_set", "queue_s", "Mean set queue wait (s)", "queue-vs-monitors"),
             ("C", "set_size", "throughput_rps", "Throughput (rounds/s)", "throughput-vs-set-size"),
             ("D", "worker_threads", "throughput_rps", "Throughput (rounds/s)", "throughput-vs-workers"),
             ("E", "client_nodes", "throughput_rps", "Throughput (rounds/s)", "throughput-vs-client-nodes"),
             ("F", "offered_rate", "throughput_rps", "Throughput (rounds/s)", "throughput-vs-offered-rate"),
             ("A", "num_sets", "peak_rss_kib", "Peak RSS (KiB)", "memory-vs-sets")]
    for experiment, x, y, ylabel, name in specs:
        selected = [g for g in groups if g["experiment"] == experiment]
        if not selected:
            continue
        # Every non-swept topology/workload/hardware field defines a separate
        # curve. Never pool distinct set sizes, local/distributed, CPUs, or modes.
        curves = defaultdict(list)
        ignore = {"experiment", x, "repeats", "distinct_seeds"}
        if experiment == "A":
            ignore.add("monitors_per_set")
        if experiment == "B":
            ignore.add("total_monitors")
        for g in selected:
            key = tuple((k, v) for k, v in g.items() if k not in ignore and not k.endswith(("_mean", "_stddev")))
            curves[key].append(g)
        fig, ax = plt.subplots(figsize=(8, 5))
        for key, curve in curves.items():
            curve.sort(key=lambda g: g[x])
            label = ", ".join(f"{k}={v}" for k, v in key if k in ("set_size", "num_sets", "monitors_per_set", "client_nodes", "worker_threads", "distributed"))
            ax.errorbar([g[x] for g in curve], [g[y + "_mean"] for g in curve], yerr=[g[y + "_stddev"] for g in curve], marker="o", capsize=3, label=label)
        ax.set(xlabel=x.replace("_", " "), ylabel=ylabel, title=f"Experiment {experiment}: mean ± sample standard deviation")
        ax.grid(alpha=.25)
        ax.legend(fontsize=7)
        fig.tight_layout()
        fig.savefig(output / (name + ".png"), dpi=180)
        fig.savefig(output / (name + ".pdf"))
        plt.close(fig)
    if targets:
        fig, ax = plt.subplots(figsize=(8, 5))
        ranked=defaultdict(list)
        for t in targets:
            c=t['manifest']['config']
            key=tuple((k,c[k]) for k in ('set_size','num_sets','monitors_per_set','client_nodes','worker_threads','mode','workload','offered_rate','duration_s','warmup_s','distributed') if k in c)
            key+=tuple((k,t[k]) for k in ('cpu_model','git_commit') if k in t)
            ranked[key].append(sorted(s["reporting"]["throughput_rps"] for s in t["sets"]))
        for key,runs in ranked.items():
            columns=list(zip(*runs))
            means=[statistics.mean(v) for v in columns]
            stddev=[statistics.stdev(v) if len(v)>1 else 0 for v in columns]
            label=', '.join(f'{k}={v}' for k,v in key if k in ('set_size','num_sets','monitors_per_set','client_nodes','worker_threads'))+f' (n={len(runs)})'
            ax.errorbar(range(len(means)),means,yerr=stddev,fmt='.-',capsize=2,label=label)
        ax.set(xlabel="Set throughput rank", ylabel="Set throughput (rounds/s)", title="Per-set throughput distribution")
        if len(ranked) <= 10:
            ax.legend(fontsize=7)
        fig.tight_layout()
        fig.savefig(output / "per-set-throughput.png", dpi=180)
        fig.savefig(output / "per-set-throughput.pdf")
        plt.close(fig)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("inputs", nargs="+", type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--require-distributed", action="store_true")
    p.add_argument("--verify", action="store_true", help="fail if topology, event history, or distinctness checks fail")
    p.add_argument("--no-plots", action="store_true")
    args = p.parse_args()
    paths = set()
    for source in args.inputs:
        paths.update(source.rglob("target.json") if source.is_dir() else [source])
    if not paths:
        p.error("no actual target.json results found")
    rows, targets, issues = [], [], []
    for path in sorted(paths):
        row, target, errors = run_row(path, args.require_distributed)
        rows.append(row)
        if not errors:
            targets.append(target)
        issues.extend(f"{path}: {e}" for e in errors)
    groups = aggregate(rows)
    args.output.mkdir(parents=True, exist_ok=True)
    write_csv(args.output / "runs.csv", rows)
    write_csv(args.output / "aggregate.csv", groups)
    (args.output / "validation.json").write_text(json.dumps({"runs": len(rows), "valid_runs": sum(r["valid"] for r in rows), "issues": issues}, indent=2))
    warnings = [f"{g['experiment']} S={g['set_size']} N={g['num_sets']} M={g['monitors_per_set']}: only {g['repeats']} repeat(s)" for g in groups if g["repeats"] < 3]
    evidence=[]
    for r in rows:
        evidence.append(f"{r['run_id']}: S={r['set_size']} N={r['num_sets']} M={r['monitors_per_set']} K={r['client_nodes']} W={r['worker_threads']}; throughput={r['throughput_rps']:.3f}/s; mean set wait={r['queue_s']:.6f}s; worker wait={r['worker_wait_s']:.6f}s; crypto={r['crypto_s']:.6f}s; I/O+peer={r['io_peer_wait_s']:.6f}s; target CPU={r['cpu_percent']:.1f}% of one core ({r['cpu_percent']/(100*r['worker_threads']):.1%} of worker budget); traffic={r['network_mbps']:.3f} Mbps; peak RSS={r['peak_rss_kib']} KiB; client sent={r['client_generated_rps']:.3f}/s; dependency drops={r['client_dependency_dropped']}; rejections={r['rejected']}; timeouts={r['timeouts']}")
    notes = ["Diagnostic evidence (correlations, not causal attribution):", "Compare mean set wait with worker wait to separate contention from CPU scheduling.", "Use the time series to compare CPU use against W*100%, queue growth, RSS, and network Mbps.", "High io_and_peer_wait includes client proof generation/verification; it is not network-only time.", "Compare client generated rps and dependency drops with offered load; sweep client nodes/workers before attributing saturation to target.", "Network bottlenecks require interface/link capacity or an independent network baseline; RSS growth alone does not prove memory pressure.", "Local loopback results remain labeled distributed=false and are never pooled with distributed runs.", "Target and client boundary cohorts may differ; percentiles use bounded histograms (up to 12.5% bin error).", *evidence, *warnings, *issues]
    (args.output / "diagnostics.txt").write_text("\n".join(notes) + "\n")
    if not args.no_plots:
        plots(groups, targets, args.output)
    print(f"{len(rows)} run(s), {sum(r['valid'] for r in rows)} valid; outputs in {args.output}")
    if args.verify and issues:
        raise SystemExit("validation failed; see validation.json")


if __name__ == "__main__":
    main()
