use exact_bench::{
    client::{self, ClientOptions},
    config::{Config, Manifest},
    metrics::CpuPool,
    server::{PublicKeys, Server},
    wire::{Channel, Request, Response, Traffic},
    Result,
};
use i_psi_ca::exact::session::{self, MonitorState};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task::JoinSet};

fn directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "exact-test-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&path).unwrap();
    path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn all_four_topologies_use_real_crypto_and_independent_virtual_monitors() -> Result<()> {
    for (sets, monitors, agents, mode) in [
        (1, 1, 1, "closed-loop"),
        (3, 1, 1, "closed-loop"),
        (1, 4, 2, "closed-loop"),
        (2, 2, 2, "closed-loop"),
        (1, 2, 1, "open-loop"),
    ] {
        let dir = directory();
        let secret = [77; 32];
        std::fs::write(dir.join("secret"), secret)?;
        let c = Config {
            set_size: 2,
            num_sets: sets,
            monitors_per_set: monitors,
            client_nodes: agents,
            client_hosts: vec!["local".into(); agents],
            worker_threads: 2,
            warmup_s: 0.15,
            duration_s: 0.65,
            timeout_ms: 20000,
            workload: "shared".into(),
            mode: mode.into(),
            offered_rate: 10000.0,
            ..Config::default()
        };
        let keys = PublicKeys {
            monitor_public_keys: (0..sets)
                .map(|s| session::monitor_key(&secret, s).1 .0.compress().to_bytes())
                .collect(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = listener.local_addr()?.to_string();
        let server = Server::initialize(c.clone(), keys, dir.join("target.json")).await?;
        let task = tokio::spawn(server.serve(listener));
        let mut clients = JoinSet::new();
        for agent in 0..agents {
            let options = ClientOptions {
                target: target.clone(),
                agent,
                key_file: dir.join("secret"),
                output: dir.join(format!("agent{agent}.json")),
                workers: 2,
            };
            clients.spawn(client::run(options));
        }
        while let Some(result) = clients.join_next().await {
            result??;
        }
        tokio::time::timeout(Duration::from_secs(10), task).await???;
        let output: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("target.json"))?)?;
        assert_eq!(output["initialized_sets"], sets);
        assert_eq!(output["registered_monitors"], sets * monitors);
        assert_eq!(output["deployed_monitors"], sets * monitors);
        assert!(output["active_sets_peak"].as_u64().unwrap() <= sets as u64);
        assert!(output["active_cpu_jobs_peak"].as_u64().unwrap() <= 2);
        assert!(!output["distributed"].as_bool().unwrap());
        for set in output["sets"].as_array().unwrap() {
            assert_eq!(set["distinct_matches"], 1);
            assert_eq!(set["assigned_monitors"], monitors);
        }
        let mut ids = Vec::new();
        let mut sessions = std::collections::HashSet::new();
        for agent in 0..agents {
            let client: serde_json::Value =
                serde_json::from_slice(&std::fs::read(dir.join(format!("agent{agent}.json")))?)?;
            assert!(client["errors"].as_array().unwrap().is_empty());
            if mode == "open-loop" {
                assert!(client["reporting"]["dependency_dropped"].as_u64().unwrap() > 0);
                let offered = client["reporting"]["offered"].as_u64().unwrap();
                assert!((6000..=7000).contains(&offered), "offered={offered}");
            }
            for monitor in client["monitors"].as_array().unwrap() {
                ids.push(monitor["monitor_id"].as_u64().unwrap());
                assert!(sessions.insert(monitor["session"].to_string()));
            }
        }
        ids.sort();
        assert_eq!(ids, (0..(sets * monitors) as u64).collect::<Vec<_>>());
    }
    Ok(())
}

struct Harness {
    dir: PathBuf,
    target: String,
    manifest: Manifest,
    task: tokio::task::JoinHandle<Result<()>>,
    secret: [u8; 32],
}
impl Harness {
    async fn new(sets: usize, monitors: usize, queue: usize) -> Result<Self> {
        let dir = directory();
        let secret = [78; 32];
        let config = Config {
            set_size: 1,
            num_sets: sets,
            monitors_per_set: monitors,
            worker_threads: 2,
            max_queue_per_set: queue,
            warmup_s: 0.0,
            duration_s: 1.5,
            timeout_ms: 2000,
            ..Config::default()
        };
        let keys = PublicKeys {
            monitor_public_keys: (0..sets)
                .map(|s| session::monitor_key(&secret, s).1 .0.compress().to_bytes())
                .collect(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let target = listener.local_addr()?.to_string();
        let server = Server::initialize(config, keys, dir.join("target.json")).await?;
        let manifest = server.manifest.clone();
        let task = tokio::spawn(server.serve(listener));
        Ok(Self {
            dir,
            target,
            manifest,
            task,
            secret,
        })
    }
    async fn channel(&self) -> Result<Channel> {
        Channel::connect(&self.target, 4000, Arc::new(Traffic::default())).await
    }
    async fn register(
        &self,
        id: usize,
        token: [u8; 32],
        cursor: u64,
    ) -> Result<(Channel, Response)> {
        let mut ch = self.channel().await?;
        ch.send(&Request::Register {
            epoch: self.manifest.epoch,
            monitor: id,
            set: id / self.manifest.config.monitors_per_set,
            agent: 0,
            host: "local".into(),
            session: token,
            cursor,
        })
        .await?;
        let response = ch.recv().await?;
        Ok((ch, response))
    }
    async fn deploy_all(&self) -> Result<Vec<(Channel, MonitorState, [u8; 32])>> {
        let mut channels = Vec::new();
        let pool = CpuPool::new(2);
        for id in 0..self.manifest.total_monitors {
            let token = [id as u8 + 1; 32];
            let (mut ch, response) = self.register(id, token, 0).await?;
            let initial = match response {
                Response::Registered {
                    initial: Some(s), ..
                } => s,
                _ => panic!("expected deployment"),
            };
            let set = id / self.manifest.config.monitors_per_set;
            let secret = self.secret;
            let state = pool
                .run(move || {
                    MonitorState::deploy(&secret, set, &initial).map_err(exact_bench::error)
                })
                .await?
                .0;
            ch.send(&Request::Ready).await?;
            channels.push((ch, state, token));
        }
        let mut start = None;
        for (ch, _, _) in &mut channels {
            match ch.recv().await? {
                Response::Schedule {
                    server_unix_ms,
                    warmup_unix_ms,
                    ..
                } => {
                    start.get_or_insert(
                        tokio::time::Instant::now()
                            + Duration::from_millis(warmup_unix_ms.saturating_sub(server_unix_ms)),
                    );
                }
                _ => panic!("expected barrier"),
            }
        }
        tokio::time::sleep_until(start.unwrap()).await;
        Ok(channels)
    }
    async fn finish(self) -> Result<serde_json::Value> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let mut ch = self.channel().await?;
            ch.send(&Request::Finish {
                epoch: self.manifest.epoch,
                agent: 0,
            })
            .await?;
            if matches!(ch.recv().await?, Response::Ok) {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "measurement did not end"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        self.task.await??;
        Ok(serde_json::from_slice(&std::fs::read(
            self.dir.join("target.json"),
        )?)?)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn registration_binding_replay_queue_backpressure_cancellation_and_disconnect() -> Result<()>
{
    let h = Harness::new(1, 3, 1).await?;
    assert!(matches!(
        h.register(99, [8; 32], 0).await?.1,
        Response::Rejected {
            retryable: false,
            ..
        }
    ));
    let mut all = h.deploy_all().await?;
    assert!(matches!(
        h.register(0, [9; 32], 0).await?.1,
        Response::Rejected {
            retryable: false,
            ..
        }
    ));
    all[0]
        .0
        .send(&Request::Acquire { seq: 0, cursor: 0 })
        .await?;
    assert!(matches!(all[0].0.recv().await?, Response::Granted { .. }));
    all[1]
        .0
        .send(&Request::Acquire { seq: 0, cursor: 0 })
        .await?;
    // Wait until the second connection is parked behind the first lease.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), all[1].0.recv::<Response>())
            .await
            .is_err()
    );
    all[2]
        .0
        .send(&Request::Acquire { seq: 0, cursor: 0 })
        .await?;
    match all[2].0.recv().await? {
        Response::Rejected {
            reason,
            retryable: true,
        } => assert_eq!(reason, "set_queue_full"),
        _ => panic!("queue did not reject"),
    }
    let (first, _, token) = all.remove(0);
    drop(first);
    assert!(matches!(all[0].0.recv().await?, Response::Granted { .. }));
    all[0].0.send(&Request::Cancel { seq: 0 }).await?;
    assert!(matches!(all[0].0.recv().await?, Response::Ok));
    tokio::time::sleep(Duration::from_millis(20)).await;
    let (mut recovered, response) = h.register(0, token, 0).await?;
    assert!(matches!(response, Response::Registered { next_seq: 0, .. }));
    recovered.send(&Request::Ready).await?;
    let _: Response = recovered.recv().await?;
    recovered
        .send(&Request::Acquire { seq: 5, cursor: 0 })
        .await?;
    assert!(matches!(
        recovered.recv().await?,
        Response::Rejected {
            retryable: false,
            ..
        }
    ));
    drop(recovered);
    drop(all);
    let output = h.finish().await?;
    assert_eq!(output["sets"][0]["version"], 0);
    assert_eq!(output["sets"][0]["distinct_matches"], 0);
    assert!(output["reporting"]["rejected"].as_u64().unwrap() >= 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independent_set_leases_overlap_while_cpu_capacity_is_bounded() -> Result<()> {
    let h = Harness::new(2, 1, 1).await?;
    let mut all = h.deploy_all().await?;
    for (ch, _, _) in &mut all {
        ch.send(&Request::Acquire { seq: 0, cursor: 0 }).await?;
        assert!(matches!(ch.recv().await?, Response::Granted { .. }));
    }
    // Both full stateful exchanges are active before either is completed.
    for (ch, _, _) in &mut all {
        ch.send(&Request::Cancel { seq: 0 }).await?;
        let _: Response = ch.recv().await?;
    }
    drop(all);
    let output = h.finish().await?;
    assert_eq!(output["active_sets_peak"], 2);
    assert!(output["active_cpu_jobs_peak"].as_u64().unwrap() <= 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn framing_limits_and_server_restart_epoch_are_enforced() -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let h = Harness::new(1, 1, 1).await?;
    let mut ch = h.channel().await?;
    ch.stream.write_u32(u32::MAX).await?;
    assert!(ch.recv::<Response>().await.is_err());
    let mut ch = h.channel().await?;
    ch.send(&Request::Register {
        epoch: [0; 32],
        monitor: 0,
        set: 0,
        agent: 0,
        host: "local".into(),
        session: [1; 32],
        cursor: 0,
    })
    .await?;
    assert!(matches!(
        ch.recv().await?,
        Response::Rejected {
            retryable: false,
            ..
        }
    ));
    h.task.abort();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_update_survives_disconnect_and_replays_cannot_remove_twice() -> Result<()> {
    let h = Harness::new(1, 1, 1).await?;
    let (mut ch, mut state, token) = h.deploy_all().await?.remove(0);
    ch.send(&Request::Acquire { seq: 0, cursor: 0 }).await?;
    let context = match ch.recv().await? {
        Response::Granted { context, .. } => context,
        _ => panic!("expected grant"),
    };
    let item = session::synthetic_item(h.manifest.config.seed, 0, 0, true);
    let report = state.report(item, context).unwrap();
    ch.send(&Request::Report {
        seq: 0,
        context,
        bytes: report,
    })
    .await?;
    assert!(matches!(
        ch.recv().await?,
        Response::Committed { seq: 0, .. }
    ));
    drop(ch); // The local monitor deliberately has not applied or acknowledged it.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let (mut ch, updates) = loop {
        let (ch, response) = h.register(0, token, 0).await?;
        if let Response::Registered {
            next_seq, updates, ..
        } = response
        {
            assert_eq!(next_seq, 1);
            break (ch, updates);
        }
        assert!(tokio::time::Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    assert_eq!(updates.len(), 1);
    state.apply(&updates[0]).unwrap();
    ch.send(&Request::Ready).await?;
    let _: Response = ch.recv().await?;
    ch.send(&Request::Acquire { seq: 0, cursor: 1 }).await?;
    assert!(matches!(
        ch.recv().await?,
        Response::Rejected {
            retryable: false,
            ..
        }
    ));
    ch.send(&Request::Acquire { seq: 1, cursor: 1 }).await?;
    let context = match ch.recv().await? {
        Response::Granted { context, .. } => context,
        _ => panic!("expected resumed grant"),
    };
    ch.send(&Request::Report {
        seq: 1,
        context,
        bytes: state.report(item, context).unwrap(),
    })
    .await?;
    let update = match ch.recv().await? {
        Response::Committed { seq: 1, update, .. } => update,
        _ => panic!("expected resumed commit"),
    };
    state.apply(&update).unwrap();
    ch.send(&Request::Ack { version: 2 }).await?;
    let _: Response = ch.recv().await?;
    drop(ch);
    let output = h.finish().await?;
    assert_eq!(output["sets"][0]["distinct_matches"], 1);
    assert_eq!(output["sets"][0]["version"], 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timed_out_full_exchange_releases_shared_set_without_committing() -> Result<()> {
    let h = Harness::new(1, 2, 1).await?;
    let mut all = h.deploy_all().await?;
    all[0]
        .0
        .send(&Request::Acquire { seq: 0, cursor: 0 })
        .await?;
    assert!(matches!(all[0].0.recv().await?, Response::Granted { .. }));
    tokio::time::sleep(Duration::from_millis(100)).await;
    all[1]
        .0
        .send(&Request::Acquire { seq: 0, cursor: 0 })
        .await?;
    assert!(all[0].0.recv::<Response>().await.is_err());
    assert!(matches!(all[1].0.recv().await?, Response::Granted { .. }));
    all[1].0.send(&Request::Cancel { seq: 0 }).await?;
    let _: Response = all[1].0.recv().await?;
    drop(all);
    let output = h.finish().await?;
    assert_eq!(output["sets"][0]["version"], 0);
    assert_eq!(output["reporting"]["timeouts"], 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finite_batch_reports_once_per_monitor_then_finishes_without_waiting_for_deadline(
) -> Result<()> {
    let dir = directory();
    let secret = [81; 32];
    std::fs::write(dir.join("secret"), secret)?;
    let c = Config {
        set_size: 3,
        num_sets: 2,
        monitors_per_set: 5,
        client_nodes: 3,
        client_hosts: vec!["local".into(); 3],
        worker_threads: 2,
        warmup_s: 0.0,
        duration_s: 20.0,
        rounds_per_monitor: 1,
        timeout_ms: 20000,
        workload: "fresh".into(),
        ..Config::default()
    };
    let keys = PublicKeys {
        monitor_public_keys: (0..2)
            .map(|s| session::monitor_key(&secret, s).1 .0.compress().to_bytes())
            .collect(),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let target = listener.local_addr()?.to_string();
    let server = Server::initialize(c, keys, dir.join("target.json")).await?;
    let task = tokio::spawn(server.serve(listener));
    let started = std::time::Instant::now();
    let mut clients = JoinSet::new();
    for agent in 0..3 {
        clients.spawn(client::run(ClientOptions {
            target: target.clone(),
            agent,
            key_file: dir.join("secret"),
            output: dir.join(format!("agent{agent}.json")),
            workers: 4,
        }));
    }
    while let Some(result) = clients.join_next().await {
        result??;
    }
    task.await??;
    assert!(started.elapsed() < Duration::from_secs(15));
    let t: serde_json::Value = serde_json::from_slice(&std::fs::read(dir.join("target.json"))?)?;
    assert_eq!(t["reporting"]["admission_cohort_completed"], 10);
    assert_eq!(t["reporting"]["submission_to_commit"]["count"], 10);
    assert!(
        t["reporting"]["submission_to_commit"]["mean_s"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    for set in t["sets"].as_array().unwrap() {
        assert_eq!(set["version"], 5);
        assert_eq!(set["distinct_matches"], 3);
    }
    for agent in 0..3 {
        let c: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(format!("agent{agent}.json")))?)?;
        assert!(c["clock_calibration"]["uncertainty_ns"].is_u64());
        for monitor in c["monitors"].as_array().unwrap() {
            assert_eq!(monitor["reporting"]["admission_cohort_completed"], 1);
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn submission_latency_ends_at_target_commit_before_final_acknowledgement() -> Result<()> {
    let h = Harness::new(1, 1, 1).await?;
    let (mut ch, mut state, _) = h.deploy_all().await?.remove(0);
    let mut clock = h.channel().await?;
    let started = std::time::Instant::now();
    clock.send(&Request::Clock).await?;
    let stamp = match clock.recv().await? {
        Response::Clock { sent_ns, .. } => sent_ns,
        _ => panic!("expected clock"),
    };
    ch.send(&Request::Observe {
        seq: 0,
        cursor: 0,
        submitted_server_ns: stamp,
    })
    .await?;
    let context = match ch.recv().await? {
        Response::Granted { context, .. } => context,
        _ => panic!("expected grant"),
    };
    let item = session::synthetic_item(h.manifest.config.seed, 0, 0, true);
    ch.send(&Request::Report {
        seq: 0,
        context,
        bytes: state.report(item, context).unwrap(),
    })
    .await?;
    let update = match ch.recv().await? {
        Response::Committed { update, .. } => update,
        _ => panic!("expected commit"),
    };
    tokio::time::sleep(Duration::from_millis(250)).await;
    state.apply(&update).unwrap();
    ch.send(&Request::Ack { version: 1 }).await?;
    let _: Response = ch.recv().await?;
    let acknowledgement_s = started.elapsed().as_secs_f64();
    drop(ch);
    let output = h.finish().await?;
    let mean = output["reporting"]["submission_to_commit"]["mean_s"]
        .as_f64()
        .unwrap();
    assert!(
        mean < acknowledgement_s - 0.2,
        "latency included final acknowledgement"
    );
    Ok(())
}
