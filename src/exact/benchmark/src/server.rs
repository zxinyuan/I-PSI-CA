use crate::{
    config::{Config, Manifest},
    error,
    metrics::{self, CpuPool, Gauge, RoundTiming, Stats},
    wire::{self, Channel, Phase, Request, Response, Traffic},
    Result,
};
use i_psi_ca::exact::session::{self, InitialState, TargetState, Update};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex as SyncMutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::TcpListener,
    sync::{watch, Mutex, Semaphore},
    task::JoinSet,
    time::timeout,
};

struct MonitorSession {
    token: Option<[u8; 32]>,
    connected: Arc<AtomicBool>,
    deployed: bool,
    cursor: u64,
    next_seq: u64,
    last_commit_version: u64,
    retired: bool,
}
struct SetData {
    state: Arc<TargetState>,
    initial: Arc<InitialState>,
    history: VecDeque<Arc<Update>>,
    history_bytes: usize,
    monitors: Vec<MonitorSession>,
}
struct SetActor {
    data: Mutex<SetData>,
    queue: Arc<Semaphore>,
    waiting: Arc<Gauge>,
    stats: SyncMutex<Stats>,
    warmup: AtomicU64,
}
#[derive(Clone)]
struct Schedule {
    warmup: Instant,
    measure: Instant,
    end: Instant,
    warmup_ms: u64,
    measure_ms: u64,
    end_ms: u64,
}
impl Schedule {
    fn phase(&self, now: Instant) -> Phase {
        if now < self.warmup {
            Phase::Deployment
        } else if now < self.measure {
            Phase::Warmup
        } else if now < self.end {
            Phase::Measurement
        } else {
            Phase::Drain
        }
    }
}

pub struct Server {
    pub manifest: Manifest,
    sets: Vec<SetActor>,
    pool: CpuPool,
    inflight: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    traffic: Arc<Traffic>,
    active_sets: Arc<Gauge>,
    ready: AtomicUsize,
    registered: AtomicUsize,
    schedule: watch::Sender<Option<Schedule>>,
    finished: SyncMutex<Vec<bool>>,
    stop: watch::Sender<bool>,
    initialization_s: f64,
    clock_origin: Instant,
    samples: SyncMutex<Vec<serde_json::Value>>,
    output: PathBuf,
}

struct ConnectionClaim(Arc<AtomicBool>);
impl Drop for ConnectionClaim {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeys {
    pub monitor_public_keys: Vec<[u8; 32]>,
}

impl Server {
    pub async fn initialize(
        config: Config,
        keys: PublicKeys,
        output: PathBuf,
    ) -> Result<Arc<Self>> {
        let manifest = config.manifest()?;
        if keys.monitor_public_keys.len() != config.num_sets {
            return Err(error("public key count must equal N"));
        }
        let pool = CpuPool::new(config.worker_threads);
        let start = Instant::now();
        // Bounded parallel initialization. There are exactly N states, never N*M.
        let mut pending = JoinSet::new();
        let mut initialized = Vec::with_capacity(config.num_sets);
        for (set, public) in keys.monitor_public_keys.into_iter().enumerate() {
            let pool = pool.clone();
            let seed = config.seed;
            let size = config.set_size;
            let epoch = manifest.epoch;
            pending.spawn(async move {
                let (value, _, _) = pool
                    .run(move || {
                        let roots = (0..size)
                            .map(|i| session::synthetic_item(seed, set, i as u64, true))
                            .collect::<Vec<_>>();
                        let context = session::request_context(&epoch, &epoch, set as u64, 0);
                        TargetState::initialize(&roots, public, context).map_err(error)
                    })
                    .await?;
                Ok::<_, crate::Error>((set, value))
            });
            if pending.len() >= config.worker_threads {
                initialized.push(
                    pending
                        .join_next()
                        .await
                        .ok_or_else(|| error("initialization lost job"))???,
                );
            }
        }
        while let Some(result) = pending.join_next().await {
            initialized.push(result??);
        }
        initialized.sort_by_key(|(set, _)| *set);
        let sets = initialized
            .into_iter()
            .map(|(_, (state, initial))| SetActor {
                data: Mutex::new(SetData {
                    state: Arc::new(state),
                    initial: Arc::new(initial),
                    history: VecDeque::new(),
                    history_bytes: 0,
                    monitors: (0..config.monitors_per_set)
                        .map(|_| MonitorSession {
                            token: None,
                            connected: Arc::new(AtomicBool::new(false)),
                            deployed: false,
                            cursor: 0,
                            next_seq: 0,
                            last_commit_version: 0,
                            retired: false,
                        })
                        .collect(),
                }),
                queue: Arc::new(Semaphore::new(config.max_queue_per_set + 1)),
                waiting: Arc::new(Gauge::default()),
                stats: SyncMutex::new(Stats::default()),
                warmup: AtomicU64::new(0),
            })
            .collect();
        let (schedule, _) = watch::channel(None);
        let (stop, _) = watch::channel(false);
        Ok(Arc::new(Self {
            manifest,
            sets,
            pool,
            inflight: Arc::new(Semaphore::new(config.max_inflight)),
            connections: Arc::new(Semaphore::new(config.total()? + 32)),
            traffic: Arc::new(Traffic::default()),
            active_sets: Arc::new(Gauge::default()),
            ready: AtomicUsize::new(0),
            registered: AtomicUsize::new(0),
            schedule,
            finished: SyncMutex::new(vec![false; config.client_nodes]),
            stop,
            initialization_s: start.elapsed().as_secs_f64(),
            clock_origin: start,
            samples: SyncMutex::new(Vec::new()),
            output,
        }))
    }

    fn phase(&self) -> Phase {
        self.schedule
            .borrow()
            .as_ref()
            .map(|s| s.phase(Instant::now()))
            .unwrap_or(Phase::Deployment)
    }
    fn clock_ns(&self) -> u64 {
        self.clock_origin.elapsed().as_nanos() as u64
    }
    fn stats<F: FnOnce(&mut Stats)>(&self, set: usize, phase: Phase, f: F) {
        if phase == Phase::Measurement {
            f(&mut self.sets[set].stats.lock().unwrap());
        }
    }

    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        eprintln!(
            "target ready on {}; {} sets, {} monitors; distributed={}",
            listener.local_addr()?,
            self.sets.len(),
            self.manifest.total_monitors,
            self.manifest.config.distributed
        );
        let mut connections = JoinSet::new();
        let mut stop = self.stop.subscribe();
        let mut sampler = tokio::time::interval(Duration::from_millis(250));
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        loop {
            tokio::select! {
                accepted=listener.accept(), if connections.len()<self.manifest.total_monitors+32=> {
                    let (stream,_) = accepted?;
                    if let Ok(permit)=self.connections.clone().try_acquire_owned() {
                        let server=self.clone();
                        connections.spawn(async move {
                            let _permit=permit;
                            let channel=Channel::new(stream,server.manifest.config.timeout_ms,server.traffic.clone())?;
                            server.connection(channel).await
                        });
                    }
                }
                Some(result)=connections.join_next()=> { match result {Ok(Ok(()))=>{},Ok(Err(e))=>eprintln!("connection ended: {e}"),Err(e)=>eprintln!("connection task failed: {e}")}; }
                _=sampler.tick()=> {
                    self.sample().await;
                    let expired=self.schedule.borrow().as_ref().is_some_and(|s|Instant::now()>s.end+Duration::from_millis(self.manifest.config.timeout_ms));
                    if expired {eprintln!("run drain deadline exceeded; saving incomplete run");break;}
                }
                _=stop.changed()=> { if *stop.borrow() {break;} }
                _=tokio::signal::ctrl_c()=>{break;}
                _=sigterm.recv()=>{break;}
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        // CPU computations may finish after cancellation, but are pure proposals
        // and cannot update state without their async owner.
        self.save().await
    }

    async fn connection(self: Arc<Self>, mut ch: Channel) -> Result<()> {
        let first: Request = ch.recv().await?;
        let (monitor, set, agent, host, token, cursor) = match first {
            Request::Clock => {
                let received_ns = self.clock_ns();
                let sent_ns = self.clock_ns();
                ch.send(&Response::Clock {
                    received_ns,
                    sent_ns,
                })
                .await?;
                return Ok(());
            }
            Request::Probe => {
                ch.send(&Response::Manifest(Box::new(self.manifest.clone())))
                    .await?;
                return Ok(());
            }
            Request::Finish { epoch, agent } => {
                if epoch != self.manifest.epoch
                    || agent >= self.manifest.config.client_nodes
                    || (self.phase() != Phase::Drain
                        && self.manifest.config.rounds_per_monitor == 0)
                {
                    ch.reject(
                        "finish before measurement end or invalid agent/epoch",
                        false,
                    )
                    .await?;
                    return Ok(());
                }
                if self.manifest.config.rounds_per_monitor > 0 {
                    for (set_id, set) in self.sets.iter().enumerate() {
                        let data = set.data.lock().await;
                        if data.monitors.iter().enumerate().any(|(index, m)| {
                            (set_id * self.manifest.config.monitors_per_set + index)
                                % self.manifest.config.client_nodes
                                == agent
                                && (m.next_seq < self.manifest.config.rounds_per_monitor
                                    || !m.deployed
                                    || !m.retired)
                        }) {
                            ch.reject("agent still has unfinished monitor reports", false)
                                .await?;
                            return Ok(());
                        }
                    }
                }
                let done = {
                    let mut finished = self.finished.lock().unwrap();
                    finished[agent] = true;
                    finished.iter().all(|v| *v)
                };
                ch.send(&Response::Ok).await?;
                if done {
                    self.stop.send_replace(true);
                }
                return Ok(());
            }
            Request::Register {
                epoch,
                monitor,
                set,
                agent,
                host,
                session,
                cursor,
            } if epoch == self.manifest.epoch => (monitor, set, agent, host, session, cursor),
            _ => {
                ch.reject("expected registration for this server incarnation", false)
                    .await?;
                return Ok(());
            }
        };
        let config = &self.manifest.config;
        if monitor >= self.manifest.total_monitors
            || set != monitor / config.monitors_per_set
            || agent != monitor % config.client_nodes
            || (config.distributed
                && (host != config.client_hosts[agent] || host == config.target_host))
            || token == [0; 32]
        {
            ch.reject(
                "unknown monitor, wrong set/agent/host, or invalid session",
                false,
            )
            .await?;
            return Ok(());
        }
        let index = monitor % config.monitors_per_set;
        let registration_start = Instant::now();
        let (_claim, initial, next_seq, updates) = {
            let mut data = self.sets[set].data.lock().await;
            let version = data.state.version;
            let oldest = data
                .history
                .front()
                .map(|u| u.version - 1)
                .unwrap_or(version);
            if cursor > version || cursor < oldest {
                ch.reject("cursor unavailable; restart the run", false)
                    .await?;
                return Ok(());
            }
            let initial = if cursor == 0 {
                Some(Box::new((*data.initial).clone()))
            } else {
                None
            };
            let updates = data
                .history
                .iter()
                .filter(|u| u.version > cursor)
                .cloned()
                .collect();
            let m = &mut data.monitors[index];
            if m.token.is_some_and(|t| t != token) || m.connected.swap(true, Ordering::AcqRel) {
                ch.reject("duplicate monitor registration or session ownership", false)
                    .await?;
                return Ok(());
            }
            let claim = ConnectionClaim(m.connected.clone());
            if m.token.is_none() {
                m.token = Some(token);
                self.registered.fetch_add(1, Ordering::Relaxed);
            }
            (claim, initial, m.next_seq, updates)
        };
        ch.send(&Response::Registered {
            initial,
            updates,
            next_seq,
            deployment_s: registration_start.elapsed().as_secs_f64(),
        })
        .await?;
        loop {
            let request = ch.recv::<Request>().await?;
            let submitted = match &request {
                Request::Observe {
                    submitted_server_ns,
                    ..
                } => Some(*submitted_server_ns),
                _ => None,
            };
            match request {
                Request::Retire { version } => {
                    let mut data = self.sets[set].data.lock().await;
                    let current = data.state.version;
                    let m = &mut data.monitors[index];
                    if config.rounds_per_monitor == 0
                        || m.next_seq < config.rounds_per_monitor
                        || version < m.last_commit_version
                        || version > current
                    {
                        ch.reject("cannot retire an unfinished monitor", false)
                            .await?;
                    } else {
                        m.cursor = version;
                        m.retired = true;
                        ch.send(&Response::Ok).await?;
                    }
                }
                Request::Ready => {
                    let all_ready = {
                        let mut data = self.sets[set].data.lock().await;
                        let m = &mut data.monitors[index];
                        if !m.deployed {
                            m.deployed = true;
                            self.ready.fetch_add(1, Ordering::AcqRel) + 1
                                == self.manifest.total_monitors
                        } else {
                            false
                        }
                    };
                    if all_ready {
                        let now = Instant::now();
                        let unix = wire::unix_ms();
                        let warmup = now + Duration::from_millis(500);
                        let measure = warmup + Duration::from_secs_f64(config.warmup_s);
                        let end = measure + Duration::from_secs_f64(config.duration_s);
                        self.schedule.send_replace(Some(Schedule {
                            warmup,
                            measure,
                            end,
                            warmup_ms: unix + 500,
                            measure_ms: unix + 500 + (config.warmup_s * 1000.0) as u64,
                            end_ms: unix
                                + 500
                                + ((config.warmup_s + config.duration_s) * 1000.0) as u64,
                        }));
                    }
                    let mut schedule = self.schedule.subscribe();
                    timeout(Duration::from_millis(config.timeout_ms), async {
                        while schedule.borrow().is_none() {
                            schedule.changed().await.map_err(error)?;
                        }
                        Ok::<_, crate::Error>(())
                    })
                    .await??;
                    let s = schedule.borrow().clone().unwrap();
                    ch.send(&Response::Schedule {
                        server_unix_ms: wire::unix_ms(),
                        warmup_unix_ms: s.warmup_ms,
                        measure_unix_ms: s.measure_ms,
                        end_unix_ms: s.end_ms,
                    })
                    .await?;
                }
                Request::Acquire { seq, cursor } | Request::Observe { seq, cursor, .. } => {
                    let phase = self.phase();
                    let started = Instant::now();
                    if phase == Phase::Deployment || phase == Phase::Drain {
                        ch.reject("outside reporting window", true).await?;
                        continue;
                    }
                    self.stats(set, phase, |s| s.offered += 1);
                    let global = match self.inflight.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            self.stats(set, phase, |s| s.rejected += 1);
                            ch.reject("global_inflight_full", true).await?;
                            continue;
                        }
                    };
                    let queued = match self.sets[set].queue.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            self.stats(set, phase, |s| s.rejected += 1);
                            ch.reject("set_queue_full", true).await?;
                            continue;
                        }
                    };
                    let waiting = self.sets[set].waiting.enter();
                    self.stats(set, phase, |s| {
                        s.queue_peak = s.queue_peak.max(
                            self.sets[set]
                                .waiting
                                .current
                                .load(Ordering::Relaxed)
                                .saturating_sub(1),
                        )
                    });
                    let result = timeout(
                        Duration::from_millis(config.timeout_ms),
                        self.interaction(
                            &mut ch, set, index, token, seq, cursor, phase, started, submitted,
                        ),
                    )
                    .await;
                    drop(waiting);
                    drop(queued);
                    drop(global);
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            self.stats(set, phase, |s| {
                                s.failures += 1;
                                s.timeouts += u64::from(metrics::is_timeout(&e));
                            });
                            return Err(e);
                        }
                        Err(_) => {
                            self.stats(set, phase, |s| {
                                s.failures += 1;
                                s.timeouts += 1;
                            });
                            return Err(error("full set interaction timed out; lease released"));
                        }
                    }
                }
                _ => {
                    ch.reject("unexpected session message", false).await?;
                    return Ok(());
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn interaction(
        &self,
        ch: &mut Channel,
        set: usize,
        index: usize,
        token: [u8; 32],
        seq: u64,
        cursor: u64,
        phase: Phase,
        started: Instant,
        submitted: Option<u64>,
    ) -> Result<()> {
        let actor = &self.sets[set];
        let mut data = actor.data.lock().await;
        let _active = self.active_sets.enter();
        let queue_s = started.elapsed().as_secs_f64();
        let version = data.state.version;
        let m = &data.monitors[index];
        let oldest = data
            .history
            .front()
            .map(|u| u.version - 1)
            .unwrap_or(version);
        if !m.deployed
            || (self.manifest.config.rounds_per_monitor > 0
                && seq >= self.manifest.config.rounds_per_monitor)
            || seq != m.next_seq
            || cursor > version
            || cursor < oldest
            || cursor < m.cursor
        {
            self.stats(set, phase, |s| s.rejected += 1);
            ch.reject(
                "undeployed, stale cursor, duplicate/out-of-order sequence, or history unavailable",
                false,
            )
            .await?;
            return Ok(());
        }
        self.stats(set, phase, |s| s.accepted += 1);
        data.monitors[index].cursor = cursor;
        let context = session::request_context(&self.manifest.epoch, &token, seq, version);
        let updates = data
            .history
            .iter()
            .filter(|u| u.version > cursor)
            .cloned()
            .collect();
        let io_start = Instant::now();
        ch.send(&Response::Granted {
            seq,
            context,
            updates,
            queue_s,
        })
        .await?;
        let report = match ch.recv::<Request>().await? {
            Request::Report {
                seq: s,
                context: c,
                bytes,
            } if s == seq && c == context => bytes,
            Request::Cancel { seq: s } if s == seq => {
                self.stats(set, phase, |s| s.cancellations += 1);
                ch.send(&Response::Ok).await?;
                return Ok(());
            }
            _ => return Err(error("unexpected report or context/sequence mismatch")),
        };
        let io_peer_wait_s = io_start.elapsed().as_secs_f64();
        // A valid report is bound to this exact snapshot. No other monitor can
        // mutate it while this async set guard spans all network messages.
        let snapshot = data.state.clone();
        let ((new_state, update, matched), worker_s, crypto_s) = self
            .pool
            .run(move || snapshot.propose(report, context).map_err(error))
            .await?;
        data.monitors[index].cursor = version;
        let min_cursor = data
            .monitors
            .iter()
            .filter(|m| !m.retired)
            .map(|m| m.cursor)
            .min()
            .unwrap_or(version);
        while data
            .history
            .front()
            .is_some_and(|u| u.version <= min_cursor)
        {
            let old = data.history.pop_front().unwrap();
            data.history_bytes -= bincode::serialized_size(&*old)? as usize;
        }
        let size = bincode::serialized_size(&update)? as usize;
        if size > self.manifest.config.history_bytes_per_set {
            return Err(error("single update exceeds history budget"));
        }
        if data.history_bytes + size > self.manifest.config.history_bytes_per_set {
            self.stats(set, phase, |s| s.rejected += 1);
            ch.reject("history_backpressure: lagging monitors must catch up", true)
                .await?;
            return Ok(());
        }
        let update = Arc::new(update);
        // Linearization point. A lost response never rolls back a committed
        // removal; reconnect returns next_seq and the verifiable update journal.
        data.state = Arc::new(new_state);
        data.history.push_back(update.clone());
        data.history_bytes += size;
        data.monitors[index].next_seq += 1;
        data.monitors[index].last_commit_version = update.version;
        let committed_ns = self.clock_ns();
        if self.phase() == Phase::Measurement {
            actor.stats.lock().unwrap().completed_in_window += 1;
        }
        let timing = RoundTiming {
            queue_s,
            worker_s,
            crypto_s,
            io_peer_wait_s,
            target_s: started.elapsed().as_secs_f64(),
        };
        self.stats(set, phase, |s| {
            s.complete(timing, timing.target_s);
            if let Some(submitted) = submitted {
                s.submission_to_commit
                    .record(committed_ns.saturating_sub(submitted) as f64 / 1e9);
            }
            s.matches += u64::from(matched);
            s.nonmatches_or_replays += u64::from(!matched);
        });
        if phase == Phase::Warmup {
            actor.warmup.fetch_add(1, Ordering::Relaxed);
        }
        ch.send(&Response::Committed {
            seq,
            update: update.clone(),
            timing,
        })
        .await?;
        match ch.recv::<Request>().await? {
            Request::Ack { version: v } if v == update.version => {
                data.monitors[index].cursor = v;
                if self.manifest.config.rounds_per_monitor > 0
                    && data.monitors[index].next_seq >= self.manifest.config.rounds_per_monitor
                {
                    data.monitors[index].retired = true;
                }
                ch.send(&Response::Ok).await?;
            }
            _ => return Err(error("expected verified update acknowledgement")),
        }
        Ok(())
    }

    async fn sample(&self) {
        if self.schedule.borrow().is_none() {
            return;
        }
        let queues = self
            .sets
            .iter()
            .map(|s| {
                s.waiting
                    .current
                    .load(Ordering::Relaxed)
                    .saturating_sub(usize::from(s.data.try_lock().is_err()))
            })
            .sum::<usize>();
        let elapsed_s = self
            .schedule
            .borrow()
            .as_ref()
            .map(|s| {
                Instant::now()
                    .saturating_duration_since(s.warmup)
                    .as_secs_f64()
            })
            .unwrap_or(0.0);
        let resource = metrics::resources();
        self.samples.lock().unwrap().push(serde_json::json!({
            "unix_ms":wire::unix_ms(),
            "elapsed_s":elapsed_s,
            "phase":self.phase(),
            "cpu_s":resource.cpu_s,
            "rss_kib":resource.rss_kib,
            "peak_rss_kib":resource.peak_rss_kib,
            "active_sets":self.active_sets.current.load(Ordering::Relaxed),
            "active_cpu_jobs":self.pool.jobs.current.load(Ordering::Relaxed),
            "queued":queues,
            "sent_bytes":self.traffic.sent.load(Ordering::Relaxed),
            "received_bytes":self.traffic.received.load(Ordering::Relaxed),
        }));
    }

    async fn save(&self) -> Result<()> {
        let duration = self.manifest.config.duration_s;
        let mut sets = Vec::new();
        let mut total = Stats::default();
        for (id, set) in self.sets.iter().enumerate() {
            let data = set.data.lock().await;
            let stats = set.stats.lock().unwrap().clone();
            total.offered += stats.offered;
            total.accepted += stats.accepted;
            total.rejected += stats.rejected;
            total.completed += stats.completed;
            total.completed_in_window += stats.completed_in_window;
            total.failures += stats.failures;
            total.timeouts += stats.timeouts;
            total.cancellations += stats.cancellations;
            total.matches += stats.matches;
            total.nonmatches_or_replays += stats.nonmatches_or_replays;
            total.queue_peak = total.queue_peak.max(stats.queue_peak);
            for (dst, src) in [
                (&mut total.latency, &stats.latency),
                (&mut total.queue, &stats.queue),
                (&mut total.worker, &stats.worker),
                (&mut total.crypto, &stats.crypto),
                (&mut total.io_peer_wait, &stats.io_peer_wait),
                (&mut total.submission_to_commit, &stats.submission_to_commit),
            ] {
                dst.count += src.count;
                dst.sum_s += src.sum_s;
                dst.max_s = dst.max_s.max(src.max_s);
                for (d, s) in dst.bins.iter_mut().zip(&src.bins) {
                    *d += s;
                }
            }
            sets.push(serde_json::json!({
                "set_id":id,
                "assigned_monitors":data.monitors.len(),
                "distinct_matches":data.state.distinct_matches,
                "version":data.state.version,
                "warmup_completed":set.warmup.load(Ordering::Relaxed),
                "history_bytes":data.history_bytes,
                "reporting":stats.summary(duration),
                "histograms":stats,
            }));
        }
        let reporting_resources = {
            let samples = self.samples.lock().unwrap();
            metrics::sampled_resources(&samples)
        };
        metrics::write_json(
            &self.output,
            &serde_json::json!({
                "schema":"exact-bench-v1",
                "role":"target",
                "pok":true,
                "round1":false,
                "distributed":self.manifest.config.distributed,
                "manifest":self.manifest,
                "initialized_sets":self.sets.len(),
                "registered_monitors":self.registered.load(Ordering::Relaxed),
                "deployed_monitors":self.ready.load(Ordering::Relaxed),
                "finished_agents":*self.finished.lock().unwrap(),
                "initialization_s":self.initialization_s,
                "cpu_model":metrics::cpu_model(),
                "slurm_job_id":std::env::var("SLURM_JOB_ID").ok(),
                "git_commit":metrics::git_commit(),
                "git_dirty":metrics::git_dirty(),
                "slurm_cpus_per_task":std::env::var("SLURM_CPUS_PER_TASK").ok(),
                "reporting_resources":reporting_resources,
                "resources":metrics::resources(),
                "active_sets_peak":self.active_sets.peak.load(Ordering::Relaxed),
                "active_cpu_jobs_peak":self.pool.jobs.peak.load(Ordering::Relaxed),
                "sent_bytes":self.traffic.sent.load(Ordering::Relaxed),
                "received_bytes":self.traffic.received.load(Ordering::Relaxed),
                "reporting":total.summary(duration),
                "histograms":total,
                "sets":sets,
                "samples":*self.samples.lock().unwrap(),
                "latency_definition":"admission to committed target update; admission-window cohort includes drain; monotonic clocks",
                "io_definition":"socket await includes peer cryptographic computation, not isolated network transit",
            }),
        )
    }
}
