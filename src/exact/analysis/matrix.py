#!/usr/bin/env python3
"""Print the A-F experiment matrix as TSV; never launches benchmark processes."""
import argparse
import itertools


def configurations(experiments, size=1000, clients=3, workers=8, baseline=None):
    for experiment in experiments:
        rows = []
        if experiment == "A":
            rows = [(size, n, 100 // n, workers, clients, "closed-loop", 100)
                    for n in (1, 2, 5, 10, 20, 50, 100)]
        elif experiment == "B":
            rows = [(size, 10, m, workers, clients, "closed-loop", 100)
                    for m in (1, 2, 5, 10, 20, 50, 100)]
        elif experiment == "C":
            rows = [(s, n, m, workers, clients, "closed-loop", 100)
                    for s, (n, m) in itertools.product((100, 1000, 10000), ((1, 100), (10, 10), (10, 50)))]
        elif experiment == "D":
            rows = [(size, 10, 10, w, clients, "closed-loop", 100) for w in (1, 2, 4, 8, 16)]
        elif experiment == "E":
            rows = [(size, 10, 10, workers, k, "closed-loop", 100) for k in (1, 2, 4, 8)]
        elif experiment == "F":
            if baseline is None or baseline <= 0:
                raise ValueError("F requires --baseline-rps from a measured sustainable-throughput pilot")
            rows = [(size, 10, 10, workers, clients, "open-loop", baseline * factor)
                    for factor in (.25, .5, .8, 1, 1.2, 1.5, 2)]
        else:
            raise ValueError(f"Unknown experiment {experiment}")
        for row in rows:
            yield experiment, row


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--experiments", default="A,B,C,D,E")
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--set-size", type=int, default=1000)
    p.add_argument("--client-nodes", type=int, default=3)
    p.add_argument("--workers", type=int, default=8)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--baseline-rps", type=float)
    args = p.parse_args()
    if args.repeats < 3 or min(args.set_size, args.client_nodes, args.workers) <= 0:
        p.error("at least three repeats and positive configuration values are required")
    try:
        rows = list(configurations(args.experiments.split(","), args.set_size, args.client_nodes, args.workers, args.baseline_rps))
    except ValueError as e:
        p.error(str(e))
    for experiment, (s, n, m, w, k, mode, rate) in rows:
        if k > n * m:
            p.error("more client nodes than logical monitors")
        for rep in range(args.repeats):
            print(experiment, rep, s, n, m, w, k, mode, rate, args.seed + rep, sep="\t")


if __name__ == "__main__":
    main()
