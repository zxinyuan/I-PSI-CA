"""Plot the CSV from `go run . --compare`; requires matplotlib.

Usage: python3 plot_comparison.py [results/packing-comparison-three.csv]
"""
import csv
import json
import math
from pathlib import Path
from statistics import median
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


MAX_RING_N = 1 << 20
MIN_RING_N = 2048


def packing_plan(coefficients):
    """Match comparison.go: single below the limit, compact mixed above it."""
    if coefficients <= MAX_RING_N:
        return (max(MIN_RING_N, 1 << (coefficients - 1).bit_length()),)
    remaining = (coefficients + MIN_RING_N - 1) // MIN_RING_N * MIN_RING_N
    plan = []
    while remaining:
        N = min(MAX_RING_N, 1 << (remaining.bit_length() - 1))
        plan.append(N)
        remaining -= N
    return tuple(plan)


def main():
    source = Path(sys.argv[1] if len(sys.argv) > 1 else "results/packing-comparison-three.csv")
    with source.open(newline="") as f:
        rows = [{k: (v if k in ("coefficients", "rlwe_plan") else float(v)) for k, v in row.items()}
                for row in csv.DictReader(f)]
    if not rows:
        raise ValueError("CSV contains no measurements")
    items = [int(r["items"]) for r in rows]
    per_ring = {}
    timings_per_ring = {}
    for r in rows:
        plan = tuple(map(int, r["rlwe_plan"].split(":"))) if r.get("rlwe_plan") else (int(r["rlwe_N"]),)
        expected = packing_plan(int(r["bloom_degree"]) + 1)
        if plan != expected:
            raise ValueError(f"Unexpected RLWE packing plan at n={r['items']}: {plan}")
        if int(r["bloom_bytes"]) != 16 * sum(plan) + 318 * len(plan):
            raise ValueError("RLWE payload differs from measured 16N+318 bytes per ciphertext")
        for N in plan:
            per_ring.setdefault(N, 16 * N + 318)
        if len(plan) == 1:
            N = plan[0]
            per_ring[N] = int(r["bloom_bytes"])
            timings_per_ring.setdefault(N, []).append(r["bloom_ms"])
        for prefix, degree in [("exact", int(r["items"])), ("bloom_elgamal", int(r["bloom_degree"]))]:
            if int(r[f"{prefix}_bytes"]) != 64 * (degree + 1):
                raise ValueError("ElGamal ciphertexts are not 64 bytes per coefficient")
    dense_items = list(range(items[0], items[-1] + 1))
    dense_m = [math.ceil(-n * math.log(0.01) / math.log(2)**2) for n in dense_items]
    dense_plans = [packing_plan(m + 1) for m in dense_m]
    dense_bytes = [16 * sum(plan) + 318 * len(plan) for plan in dense_plans]
    # Major boundaries: changing the single-ring size or exceeding another
    # maximum-ring capacity. Smaller tail adjustments remain visible in curves.
    boundaries = [(max(plan), (m + MAX_RING_N) // MAX_RING_N)
                  for m, plan in zip(dense_m, dense_plans)]
    median_per_ring = {N: median(samples) for N, samples in timings_per_ring.items()}
    lines = [
        "Packing comparison (encryption only)",
        f"Measured {len(rows)} set sizes, {items[0]}..{items[-1]} items; "
        f"{int(rows[0]['trials'])} trials, median, GOMAXPROCS=1.",
        "Bloom m=ceil(-n ln(0.01)/ln(2)^2); degree m, m+1 coefficients.",
        "Synthetic monic coefficient vectors; no Bloom construction or polynomial construction timed.",
        "Setup, encoding, serialization, verification, threshold decryption and network excluded from latency.",
        "Bytes are actual serialized ciphertext payloads; no keys or protocol traffic.",
        "Latency plot: RLWE squares are measured whole-vector encryption times.",
        "The solid guide sums measured single-ring median times for the required blocks; mixed-plan guide values are estimates.",
        f"Repository parameters: Ed25519 ElGamal; RLWE Q approximately 50 bits, N={min(per_ring)}..{max(per_ring)}.",
        "These are repository computation/storage parameters, not a matched-security comparison.",
        "Exact (ElGamal): degree n, n+1 ciphertexts; BF (ElGamal): degree m, m+1 ciphertexts.",
        "BF (RLWE): degree m, m+1 coefficients; one ciphertext below capacity, then byte-minimal mixed-size packing.",
        "Mixed sizes use separate key contexts. Key generation, key bytes and protocol headers are excluded.",
        "RLWE serializes approximately 16N bytes, vs Exact ElGamal 64(n+1) or BF ElGamal 64(m+1).",
        "Since m ~ 9.585n, the large-n BF RLWE / Exact ElGamal byte ratio is at least ~2.40 before padding.",
        "The field is Z_65537: degrees above 65537 cannot have all distinct item or position roots here.",
        "The sizing formula uses optimal real-valued hash count; an actual integer-hash Bloom implementation",
        "may need slightly more bits to guarantee FPR <= 0.01. No membership protocol is implemented.",
        "",
    ]
    for metric, ylabel, filename in [
        ("ms", "Median encryption latency (ms)", "packing-latency.png"),
        ("bytes", "Serialized ciphertext size (KiB)", "packing-ciphertext-size.png"),
    ]:
        scale = 1024 if metric == "bytes" else 1
        fig, ax = plt.subplots(figsize=(10, 6), constrained_layout=True)
        for prefix, label, marker in [("exact", "Exact (ElGamal)", "o"),
                                      ("bloom_elgamal", "BF (ElGamal)", "^"),
                                      ("bloom", "BF (RLWE)", "s")]:
            measured = [r[f"{prefix}_{metric}"] / scale for r in rows]
            if metric == "bytes":
                # Reconstruct fixed-size payloads at every integer n so packing
                # jumps appear at their true boundaries, even with sparse timings.
                if prefix == "exact":
                    values = [64 * (n + 1) / scale for n in dense_items]
                elif prefix == "bloom_elgamal":
                    values = [64 * (m + 1) / scale for m in dense_m]
                else:
                    values = [size / scale for size in dense_bytes]
                curve, = ax.plot(dense_items, values, label=label)
                ax.scatter(items, measured, marker=marker, s=18, color=curve.get_color())
            elif prefix == "bloom":
                # A straight connection between sparse samples makes a ring
                # jump look like continuous growth over many item counts.
                # Keep the observations visible and explicitly label this
                # per-dimension summary as a guide, not extra measurements.
                values = [sum(median_per_ring.get(N, math.nan) for N in plan) for plan in dense_plans]
                curve, = ax.plot(dense_items, values, "-", label=label)
                ax.scatter(items, measured, marker=marker, s=22, color=curve.get_color(), zorder=3)
            else:
                ax.plot(items, measured, marker + "-", markersize=4, label=label)
        for i in range(1, len(dense_items)):
            if boundaries[i] != boundaries[i-1]:
                ax.axvline(dense_items[i], color="gray", alpha=0.18, linewidth=0.8)
        ax.set(xscale="log", yscale="log", xlabel="Original set size n (items)",
               ylabel=ylabel, title="Exact and Bloom-sized polynomial encryption (target FPR 1%)")
        ax.set_xlim(items[0], items[-1])
        if items[0] == 1:
            powers = [p for p in range(int(math.log10(items[-1])) + 1) if 10**p < items[-1]]
            ticks = [10**p for p in powers] + [items[-1]]
            endpoint = f"{items[-1] // 1000}k" if items[-1] >= 1000 and items[-1] % 1000 == 0 else f"{items[-1]:,}"
            exponent = int(math.log10(items[-1]))
            if 10**exponent == items[-1]:
                endpoint = rf"$10^{{{exponent}}}$"
            ax.set_xticks(ticks, [rf"$10^{p}$" for p in powers] + [endpoint])
        ax.grid(True, which="both", alpha=0.2)
        ax.legend(loc="best", fontsize=9)
        caption = "Encryption only • synthetic monic coefficients • gray: ring / full-capacity boundaries"
        if metric == "ms":
            caption += "\nRLWE: squares = whole-vector measurements; line = sum of measured per-ring medians (guide)"
        fig.supxlabel(caption, fontsize=9)
        fig.savefig(source.parent / filename, dpi=180)
        plt.close(fig)
        for baseline, label in [("exact", "Exact (ElGamal)"), ("bloom_elgamal", "BF (ElGamal)")]:
            lines.append(f"{ylabel} — BF (RLWE) versus {label}, measured sample transitions:")
            states = [r[f"bloom_{metric}"] < r[f"{baseline}_{metric}"] for r in rows]
            lines.append(f"  At n={items[0]}: BF (RLWE) {'wins' if states[0] else 'does not win'}.")
            for i in range(1, len(rows)):
                if states[i] != states[i - 1]:
                    lines.append(f"  Between sampled n={items[i-1]} and n={items[i]}: "
                                 f"BF (RLWE) {'starts winning' if states[i] else 'stops winning'}.")
            if all(states):
                lines.append("  BF (RLWE) wins at every sampled size; no loss of advantage observed.")
            elif not any(states):
                lines.append("  BF (RLWE) never wins at the sampled sizes.")
            lines.append("  No extrapolation beyond the measured range; latency transitions are noisy brackets.")
            lines.append("")

    lines.append("RLWE latency measurements grouped by N (range of per-item-count trial medians, ms):")
    for N, samples in sorted(timings_per_ring.items()):
        lines.append(f"  N={N}: {min(samples):.6f}..{max(samples):.6f}; median={median_per_ring[N]:.6f}")
    lines.append("")

    # Serialization is fixed per ring dimension. Evaluate every integer n using
    # measured sizes, rather than claiming an exact crossing from sparse samples.
    for baseline in ["Exact (ElGamal)", "BF (ElGamal)"]:
        lines.append(f"Communication advantage intervals: BF (RLWE) versus {baseline}")
        start, previous = items[0], None
        for index, n in enumerate(range(items[0], items[-1] + 2)):
            state = None
            if n <= items[-1]:
                degree = n if baseline == "Exact (ElGamal)" else dense_m[index]
                delta = dense_bytes[index] - 64 * (degree + 1)
                state = "BF (RLWE) smaller" if delta < 0 else "equal" if delta == 0 else f"{baseline} smaller"
            if previous is not None and state != previous:
                lines.append(f"  n={start}..{n-1}: {previous}")
                start = n
            previous = state
    report = source.parent / "packing-comparison.txt"
    report.write_text("\n".join(lines) + "\n")
    print(report.read_text())
    study_path = source.parent / "packing-study-500k.json"
    if study_path.exists():
        study = json.loads(study_path.read_text())
        results = study["results"]
        table = ["# RLWE packing at 500,000 original items", "",
                 f"Bloom degree: {study['bloom_degree']:,}; coefficients: {study['coefficients']:,}.", "",
                 "Three-trial whole-vector encryption medians, verified by decrypting every block.",
                 "Ciphertext bytes exclude keys and external protocol framing.", "",
                 "| Plan | Ciphertexts | Key contexts | Capacity | Size (MiB) | Encryption (ms) |",
                 "|---|---:|---:|---:|---:|---:|"]
        for r in results:
            table.append(f"| {r['name']} | {r['ciphertexts']:,} | {r['key_contexts']} | "
                         f"{r['coefficient_capacity']:,} | {r['ciphertext_bytes']/2**20:.4f} | {r['encryption_ms']:.3f} |")
        compact = next(r for r in results if r["name"] == "compact_mixed")
        fastest = min(results, key=lambda r: r["encryption_ms"])
        table.extend(["", "Compact plan: " + " + ".join(map(str, compact["ring_dimensions"])) + ".", "",
                      f"Fastest measured candidate: {fastest['name']}. This is a comparison of these candidates, not a proof of global latency optimality.",
                      "The compact plan minimizes serialized ciphertext bytes within N=2048..2^20 when the vector exceeds one maximum ring.",
                      "Mixed dimensions require separate key contexts; no cross-ciphertext polynomial evaluation is benchmarked."])
        (source.parent / "packing-study-500k.md").write_text("\n".join(table) + "\n")


if __name__ == "__main__":
    main()
