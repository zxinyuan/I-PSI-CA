"""Test live-node selection and finite experiment submission without a cluster."""
import importlib.util
import io
from contextlib import redirect_stdout
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

SCRIPT = Path(__file__).resolve().parents[1]/"scripts/slurm/run_once.py"
spec=importlib.util.spec_from_file_location('run_once',SCRIPT)
run=importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)


def nodes(count,free=40):
    return run.inventory('\n'.join(f'linux{i}|compsci|idle|0/{free}/0/{free}' for i in range(31,31+count)))


class RunOnceTests(unittest.TestCase):
    def test_submission_uses_a_dependent_job_with_resources_from_live_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            exact=Path(temp)/'src/exact'
            live='\n'.join(f'linux{i}|compsci|idle|0/40/0/40' for i in range(31,41))
            topology='\n'.join(f'NodeName=linux{i} CPUTot=40 ThreadsPerCore=1' for i in range(31,41))
            env={'SLURM_JOB_ID':'fixture','SLURMD_NODENAME':'skynet-02','SLURM_SUBMIT_DIR':temp}
            with patch.object(run,'EXACT',exact),patch.object(run,'REPO',Path(temp)),patch.dict(run.os.environ,env),patch.object(run.subprocess,'check_output',side_effect=[live,topology,'12346\n']) as command:
                with redirect_stdout(io.StringIO()):
                    run.submit(SimpleNamespace(set_size=1000,num_sets=4,monitors_per_set=5))
            output=exact/'benchmark/results/once-fixture'
            plan=json.loads((output/'plan.json').read_text())
            self.assertEqual(plan['total_monitors'],20)
            self.assertEqual(len(plan['clients']),10)
            self.assertTrue(all(c['cores']==2 for c in plan['clients']))
            self.assertIn('--dependency=afterok:fixture',command.call_args.args[0])
            self.assertEqual((output/'job-id.txt').read_text(),'12346\n')
    def test_one_monitor_per_machine_even_above_ten_when_available(self):
        clients=run.choose_clients(12,nodes(15))
        self.assertEqual(len(clients),12)
        self.assertTrue(all(c['cores']==1 and c['monitor_ids']==[i] for i,c in enumerate(clients)))

    def test_twenty_monitors_are_balanced_on_ten_machines(self):
        clients=run.choose_clients(20,nodes(10))
        self.assertEqual(len(clients),10)
        self.assertTrue(all(c['cores']==2 for c in clients))
        self.assertEqual(sorted(m for c in clients for m in c['monitor_ids']),list(range(20)))
        self.assertEqual(clients[0]['monitor_ids'],[0,10])

    def test_uneven_counts_differ_by_at_most_one_and_fit_free_cores(self):
        clients=run.choose_clients(23,nodes(10))
        self.assertEqual([c['cores'] for c in clients],[3,3,3,2,2,2,2,2,2,2])
        self.assertTrue(all(len(c['monitor_ids'])==c['cores'] for c in clients))
        with self.assertRaises(ValueError):
            run.choose_clients(25,nodes(10,2))

    def test_inventory_excludes_target_nonlinux_draining_and_unresponsive(self):
        found=run.inventory('''linux31|compsci|idle|0/40/0/40
linux31|compsci-gpu*|idle|0/40/0/40
linux35|compsci|draining|0/0/40/40
linux42|compsci-gpu*|mixed-|4/20/0/24
linux44|compsci-gpu*|idle|0/40/0/40
skynet-02|skynet|idle|0/48/0/48
jerry1|grisman|idle|0/48/0/48''')
        self.assertEqual([n['node'] for n in found],['linux31','linux44'])
        self.assertEqual(found[0]['partition'],'compsci')

    def test_cpu_capacity_counts_physical_cores_rather_than_smt_threads(self):
        topology=run.thread_topology('NodeName=linux31 CPUTot=40 ThreadsPerCore=2\nNodeName=linux32 CPUTot=40 ThreadsPerCore=1')
        found=run.inventory('linux31|compsci|idle|0/40/0/40\nlinux32|compsci|mixed|39/1/0/40',topology)
        self.assertEqual([n['free_cores_estimate'] for n in found],[20,1])
        with self.assertRaises(ValueError):
            run.choose_clients(42,found)

    def test_generated_heterogeneous_batch_reserves_exact_core_counts(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            plan={'output':temp,'clients':run.choose_clients(20,nodes(10))}
            text=run.render_batch(plan,p/'plan.json')
            self.assertEqual(text.count('#SBATCH hetjob'),10)
            self.assertEqual(text.count('#SBATCH --cpus-per-task=12\n'),1)
            self.assertEqual(text.count('#SBATCH --cpus-per-task=2\n'),10)
            self.assertIn('#SBATCH --partition=skynet\n',text)
            self.assertIn('#SBATCH --nodelist=skynet-02\n',text)
            self.assertEqual(text.count('--hint=nomultithread'),11)
            (p/'run.sh').write_text(text)
            subprocess.run(['bash','-n',str(p/'run.sh')],check=True)
            step=run.step(1,plan['clients'][0])
            self.assertIn('--het-group=1',step)
            self.assertIn('--cpu-bind=cores',step)

    def test_average_weights_every_request_and_prints_three_decimals(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            clients=run.choose_clients(3,nodes(2))
            plan={'clients':clients,'total_monitors':3,'latency_definition':'fixture','set_size':1000,'num_sets':1,'monitors_per_set':3,'submission_log':str(p/'submission.log')}
            target={'pok':True,'round1':False,'distributed':True,
                    'manifest':{'config':{'rounds_per_monitor':1,'target_host':'skynet-02','worker_threads':12,'set_size':1000,'num_sets':1,'monitors_per_set':3},'total_monitors':3},'initialized_sets':1,
                    'histograms':{'submission_to_commit':{'count':3,'sum_s':.37037}},
                    'registered_monitors':3,'deployed_monitors':3,'finished_agents':[True,True]}
            (p/'plan.json').write_text(json.dumps(plan))
            (p/'target.json').write_text(json.dumps(target))
            for c in clients:
                result={'errors':[],'hostname':c['node'],'client_worker_threads':c['cores'],
                        'clock_calibration':{'uncertainty_ns':100},
                        'monitors':[{'monitor_id':i,'reporting':{'admission_cohort_completed':1}} for i in c['monitor_ids']]}
                (p/f"agent{c['agent_id']}.json").write_text(json.dumps(result))
            with redirect_stdout(io.StringIO()):
                run.report(p)
            self.assertEqual((p/'average_latency.txt').read_text(),'Average latency: 0.123 s\n')
            self.assertIn('Average latency: 0.123 s\n',(p/'submission.log').read_text())
            target['histograms']['submission_to_commit']['count']=2
            (p/'target.json').write_text(json.dumps(target))
            with self.assertRaises(ValueError):
                run.report(p)

    def test_configuration_validation_precedes_deployment(self):
        for args in [(0,1,1),(1000,0,1),(1000,1,0),(16384,1,1),(1,2**64,2),(1000,10,1001)]:
            with self.assertRaises(ValueError):
                run.validate_parameters(*args)
        self.assertEqual(run.validate_parameters(1000,4,5),20)


if __name__=='__main__':
    unittest.main()
