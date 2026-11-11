#!/usr/bin/env python3
"""Real TCP/crypto process smoke run; always labeled LOCAL, never distributed."""
import argparse
import json
from pathlib import Path
import subprocess
import time
import socket


def main():
    exact = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, default=exact / "benchmark/target/release/exact-bench")
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--set-size", type=int, default=4)
    p.add_argument("--num-sets", type=int, default=2)
    p.add_argument("--monitors-per-set", type=int, default=2)
    p.add_argument("--agents", type=int, default=2)
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--duration", type=float, default=2)
    p.add_argument("--warmup", type=float, default=.5)
    p.add_argument("--mode", choices=("closed-loop", "open-loop"), default="closed-loop")
    p.add_argument("--offered-rate", type=float, default=1000)
    p.add_argument("--workload", choices=("fresh", "nonmatch", "repeated", "shared", "mixed"), default="mixed")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--experiment", default="local-smoke")
    p.add_argument("--rounds-per-monitor",type=int,default=0)
    p.add_argument("--interrupt-after",type=float,help="development shutdown test: interrupt clients after this many seconds")
    args = p.parse_args()
    args.binary = args.binary.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    binary = str(args.binary)
    if args.port==0:
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1',0))
            args.port=reservation.getsockname()[1]
    key = str(args.output / "monitor.key")
    public = str(args.output / "public.json")
    subprocess.run([binary, "keygen", "--num-sets", str(args.num_sets), "--key-file", key, "--public-keys", public], check=True)
    endpoint = f"127.0.0.1:{args.port}"
    logs, processes = [], []
    try:
        log = (args.output / "target.log").open("w")
        logs.append(log)
        command = [binary, "target-server", "--bind", endpoint,
                   "--set-size", str(args.set_size), "--num-sets", str(args.num_sets),
                   "--monitors-per-set", str(args.monitors_per_set), "--client-nodes", str(args.agents),
                   "--worker-threads", str(args.workers), "--public-keys", public,
                   "--warmup-seconds", str(args.warmup), "--duration-seconds", str(args.duration),
                   "--mode", args.mode, "--offered-rate", str(args.offered_rate), "--workload", args.workload,
                   "--rounds-per-monitor",str(args.rounds_per_monitor),"--pok","true","--round1","false",
                   "--run-id", args.output.name, "--output", str(args.output / "target.json")]
        target = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        processes.append(target)
        for _ in range(200):
            if target.poll() is not None:
                raise RuntimeError("target failed; see target.log")
            probe = subprocess.run([binary, "probe", "--target", endpoint], capture_output=True)
            if probe.returncode == 0:
                manifest = json.loads(probe.stdout)
                if manifest['config']['run_id']!=args.output.name:
                    raise RuntimeError('readiness reached another target; choose another port')
                (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2))
                break
            time.sleep(.05)
        else:
            raise RuntimeError("target readiness timed out")
        for agent in range(args.agents):
            log = (args.output / f"agent{agent}.log").open("w")
            logs.append(log)
            processes.append(subprocess.Popen([binary, "monitor-load", "--target", endpoint,
                "--agent-id", str(agent), "--key-file", key, "--client-workers", str(args.workers),
                "--output", str(args.output / f"agent{agent}.json")], stdout=log, stderr=subprocess.STDOUT))
        if args.interrupt_after is not None:
            time.sleep(args.interrupt_after)
            for process in processes[1:]:
                process.terminate()
        for process in processes[1:]:
            if args.interrupt_after is not None:
                process.wait(timeout=130)
                continue
            if process.wait(timeout=args.duration + args.warmup + 130) != 0:
                raise RuntimeError("client failed; see agent logs")
        if args.interrupt_after is not None:
            target.terminate()
            target.wait(timeout=15)
            for agent in range(args.agents):
                summary=json.loads((args.output/f'agent{agent}.json').read_text())
                assert summary['interrupted'], 'client did not save graceful interruption status'
            assert (args.output/'target.json').exists(), 'target did not save its state summary'
            print(f'LOCAL interrupted-shutdown check passed: {args.output}; partial results are not benchmark evidence')
            return
        if target.wait(timeout=15) != 0:
            raise RuntimeError("target failed; see target.log")
        (args.output / "placement.json").write_text(json.dumps({"experiment": args.experiment, "repetition": 0, "local_only": True}, indent=2))
        subprocess.run(["python3", str(exact / "analysis/analyze.py"), str(args.output),
                        "--output", str(args.output / "analysis"), "--verify"], check=True)
        print(f"LOCAL loopback smoke results: {args.output}")
    except Exception:
        (args.output / "FAILED").write_text("Local smoke run failed; inspect logs\n")
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
