"""Analysis and orchestration tests. Fixtures below are synthetic test data only."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


analyze = module("analyze")
matrix = module("matrix")


def fixture():
    manifest = {"total_monitors": 2, "config": {"num_sets": 1, "monitors_per_set": 2, "client_nodes": 2,
                "target_host": "target", "client_hosts": ["client0", "client1"], "worker_threads": 2, "distributed": True},
                "assignments": [{"monitor_id": 0, "set_id": 0, "agent_id": 0}, {"monitor_id": 1, "set_id": 0, "agent_id": 1}]}
    target = {"manifest": manifest, "initialized_sets": 1, "registered_monitors": 2, "deployed_monitors": 2,
              "sets": [{"set_id": 0, "distinct_matches": 1, "version": 2}], "active_sets_peak": 1,
              "active_cpu_jobs_peak": 2, "finished_agents": [True, True], "distributed": True,
              "slurm_job_id": "fixture", "reporting": {"matches": 0}}
    clients = [{"agent_id": i, "manifest": copy.deepcopy(manifest), "errors": [], "assigned_monitor_ids": [i],
                "monitors": [{"monitor_id": i, "session": [i] * 32}], "hostname": f"client{i}", "slurm_job_id": "fixture"} for i in range(2)]
    placement = {"target_node": "target", "client_nodes": ["client0", "client1"], "slurm_job_id": "fixture"}
    return target, clients, placement


class AnalysisTests(unittest.TestCase):
    def test_topology_validation_catches_target_host_monitor_and_assignment_errors(self):
        t, c, p = fixture()
        self.assertEqual(analyze.validate(t, c, p, True), [])
        c[1]["hostname"] = "target"
        self.assertIn("client executed on wrong physical host", analyze.validate(t, c, p, True))
        t, c, p = fixture()
        c[1]["monitors"][0]["monitor_id"] = 0
        self.assertTrue(analyze.validate(t, c, p, True))
        t, c, p = fixture()
        t["distributed"] = False
        self.assertIn("loopback run is not a distributed result", analyze.validate(t, c, p, True))

    def test_actual_replay_composition_includes_warmup_and_independent_sets(self):
        t, _, _ = fixture()
        events = [{"set_id": 0, "version": 1, "member": True, "item_index": 0, "phase": "Warmup"},
                  {"set_id": 0, "version": 2, "member": True, "item_index": 0, "phase": "Measurement"}]
        counts, errors = analyze.composition(t, events)
        self.assertEqual(errors, [])
        self.assertEqual(counts["new_matches"], 0)
        self.assertEqual(counts["replays"], 1)
        t["sets"].append({"set_id": 1, "distinct_matches": 1, "version": 1})
        t["reporting"]["matches"] = 1
        events.append({"set_id": 1, "version": 1, "member": True, "item_index": 0, "phase": "Measurement"})
        self.assertEqual(analyze.composition(t, events)[0]["new_matches"], 1)
        self.assertTrue(analyze.composition(t, events[:-1])[1])

    def test_matrix_has_all_required_dimensions_and_calibrates_overload(self):
        rows = list(matrix.configurations("ABCDEF", baseline=100))
        self.assertEqual(len(rows), 39)
        a = [r for e, r in rows if e == "A"]
        self.assertEqual([r[1] for r in a], [1, 2, 5, 10, 20, 50, 100])
        self.assertTrue(all(r[1] * r[2] == 100 for r in a))
        self.assertEqual([r[4] for e, r in rows if e == "E"], [1, 2, 4, 8])
        self.assertEqual([r[6] for e, r in rows if e == "F"], [25, 50, 80, 100, 120, 150, 200])
        with self.assertRaises(ValueError):
            list(matrix.configurations("F"))

    def test_three_repeats_are_required_by_submission_plan(self):
        p = subprocess.run(["python3", str(HERE / "matrix.py"), "--repeats", "2"], capture_output=True)
        self.assertNotEqual(p.returncode, 0)

    def test_plots_cover_all_ten_requested_views_with_error_bars(self):
        # Artificial fixtures exercise the plot code; never saved as benchmark results.
        rows = []
        for experiment, (s, n, m, w, k, mode, rate) in matrix.configurations("ABCDEF", baseline=100):
            for rep in range(3):
                rows.append({"valid": True, "experiment": experiment, "distributed": False, "set_size": s,
                             "num_sets": n, "monitors_per_set": m, "total_monitors": n*m, "client_nodes": k,
                             "worker_threads": w, "mode": mode, "workload": "fixture", "offered_rate": rate,
                             "duration_s": 1, "warmup_s": 0, "cpu_model": "fixture", "git_commit": "fixture", "seed": rep,
                             **{name: 10 + rep for name in ("throughput_rps", "p50_s", "p95_s", "p99_s", "queue_s", "worker_wait_s", "crypto_s", "io_peer_wait_s", "cpu_percent", "network_mbps", "peak_rss_kib", "mean_queued", "client_generated_rps", "client_completed_rps", "client_dependency_dropped", "rejected", "timeouts")}})
        groups = analyze.aggregate(rows)
        self.assertTrue(all(g["repeats"] == 3 and g["throughput_rps_stddev"] == 1 for g in groups))
        target = {"sets": [{"reporting": {"throughput_rps": 10}}], "manifest": {"config": {"run_id": "fixture"}}}
        with tempfile.TemporaryDirectory() as temp:
            analyze.plots(groups, [target], Path(temp))
            self.assertEqual(len(list(Path(temp).glob("*.png"))), 10)
            self.assertEqual(len(list(Path(temp).glob("*.pdf"))), 10)


class SlurmTests(unittest.TestCase):
    def test_preflight_rejects_one_node_and_duplicate_physical_hostnames(self):
        script = HERE.parent / "scripts/slurm/preflight.sh"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, text in {"scontrol": "#!/bin/bash\nprintf '%s\\n' $TEST_NODES\n",
                               "srun": "#!/bin/bash\nprintf '%s\\n' $TEST_HOSTS\n"}.items():
                path = root / name
                path.write_text(text)
                path.chmod(0o755)
            env = {**os.environ, "PATH": temp + ":" + os.environ["PATH"], "SLURM_JOB_ID": "fixture",
                   "SLURM_JOB_NODELIST": "fixture", "SLURMD_NODENAME": "n0"}
            env.pop("EXACT_BIN", None)
            for nodes, hosts, success in [("n0", "h0", False), ("n0 n1", "h0 h0", False), ("n0 n1 n2", "h0 h1 h2", True)]:
                p = subprocess.run(["bash", str(script)], env={**env, "TEST_NODES": nodes, "TEST_HOSTS": hosts}, capture_output=True)
                self.assertEqual(p.returncode == 0, success, p.stderr.decode())

    def test_sweep_requests_clients_plus_one_target_and_fixed_cpu_allocation(self):
        script = HERE.parent / "scripts/slurm/run_sweep.sh"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stub = root / "sbatch"
            stub.write_text("#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$TEST_SUBMISSIONS\"\necho fixture-job\n")
            stub.chmod(0o755)
            env = {**os.environ, "PATH": temp + ":" + os.environ["PATH"], "TEST_SUBMISSIONS": str(root / "calls")}
            subprocess.run(["bash", str(script), "--experiments", "E", "--repeats", "3"], env=env, check=True, capture_output=True)
            calls = (root / "calls").read_text().splitlines()
            self.assertEqual(len(calls), 12)
            self.assertTrue(all("--cpus-per-task=16" in c for c in calls))
            for i, nodes in enumerate((2, 3, 5, 9)):
                self.assertTrue(all(f"--nodes={nodes} " in c for c in calls[3*i:3*i+3]))


if __name__ == "__main__":
    unittest.main()
