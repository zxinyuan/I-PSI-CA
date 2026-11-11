use crate::{
    config::{self, Manifest},
    error,
    metrics::{self, CpuPool, RoundTiming, Stats},
    wire::{self, Channel, Phase, Request, Response, Traffic},
    Result,
};
use i_psi_ca::exact::session::{self, MonitorState};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    path::PathBuf,
    sync::{atomic::Ordering, Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch},
    task::JoinSet,
    time::sleep_until,
};
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct ClientOptions {
    pub target: String,
    pub agent: usize,
    pub key_file: PathBuf,
    pub output: PathBuf,
    pub workers: usize,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    pub monitor_id: usize,
    pub set_id: usize,
    pub version: u64,
    pub seq: u64,
    pub phase: Phase,
    pub member: bool,
    pub item_index: u64,
    pub requested_kind: String,
}
#[derive(Serialize)]
struct MonitorResult {
    monitor_id: usize,
    set_id: usize,
    session: [u8; 32],
    deployment_s: f64,
    reconnects: u64,
    reporting: serde_json::Value,
    histograms: Stats,
    warmup_completed: u64,
    requested_members: u64,
    requested_nonmembers: u64,
}

#[derive(Clone)]
struct ClientContext {
    options: ClientOptions,
    manifest: Arc<Manifest>,
    secret: Arc<Zeroizing<[u8; 32]>>,
    pool: CpuPool,
    traffic: Arc<Traffic>,
    events: mpsc::Sender<Event>,
    schedule: Arc<Mutex<Option<Schedule>>>,
    cancel: watch::Sender<bool>,
    calibration: Option<Calibration>,
}

#[derive(Clone)]
struct Calibration {
    origin: Instant,
    offset_ns: i128,
    uncertainty_ns: u64,
}
impl Calibration {
    fn target_ns(&self, when: Instant) -> u64 {
        (when.saturating_duration_since(self.origin).as_nanos() as i128 + self.offset_ns)
            .clamp(0, u64::MAX as i128) as u64
    }
}

async fn calibrate(target: &str, timeout_ms: u64, traffic: Arc<Traffic>) -> Result<Calibration> {
    let origin = Instant::now();
    let mut best = None;
    for _ in 0..8 {
        let mut ch = Channel::connect(target, timeout_ms, traffic.clone()).await?;
        let sent = origin.elapsed().as_nanos() as i128;
        ch.send(&Request::Clock).await?;
        let response = ch.recv().await?;
        let received = origin.elapsed().as_nanos() as i128;
        let (server_received, server_sent) = match response {
            Response::Clock {
                received_ns,
                sent_ns,
            } if sent_ns >= received_ns => (received_ns as i128, sent_ns as i128),
            _ => return Err(error("invalid clock calibration response")),
        };
        let network = (received - sent - (server_sent - server_received)).max(0) as u64;
        let offset = ((server_received - sent) + (server_sent - received)) / 2;
        if best.as_ref().is_none_or(|(rtt, _)| network < *rtt) {
            best = Some((network, offset));
        }
    }
    let (network, offset_ns) = best.unwrap();
    Ok(Calibration {
        origin,
        offset_ns,
        uncertainty_ns: network.div_ceil(2),
    })
}
#[derive(Clone)]
struct Schedule {
    warmup: Instant,
    measure: Instant,
    end: Instant,
}
impl Schedule {
    fn phase(&self, t: Instant) -> Phase {
        if t < self.measure {
            Phase::Warmup
        } else if t < self.end {
            Phase::Measurement
        } else {
            Phase::Drain
        }
    }
}

async fn wait_until(context: &ClientContext, when: Instant) -> bool {
    let mut cancel = context.cancel.subscribe();
    if *cancel.borrow() {
        return false;
    }
    tokio::select! {_=sleep_until(when.into())=>true,_=cancel.changed()=>false}
}

pub async fn probe(target: &str) -> Result<Manifest> {
    let mut ch = Channel::connect(target, 5000, Arc::new(Traffic::default())).await?;
    ch.send(&Request::Probe).await?;
    match ch.recv().await? {
        Response::Manifest(m) => {
            m.validate()?;
            Ok(*m)
        }
        Response::Rejected { reason, .. } => Err(error(reason)),
        _ => Err(error("expected manifest")),
    }
}

pub async fn run(options: ClientOptions) -> Result<()> {
    if options.workers == 0 || options.workers > 256 {
        return Err(error("client workers must be 1..256"));
    }
    let manifest = Arc::new(probe(&options.target).await?);
    let config = &manifest.config;
    if options.agent >= config.client_nodes {
        return Err(error("unknown agent ID"));
    }
    if config.distributed
        && (config::hostname() != config.client_hosts[options.agent]
            || config::hostname() == config.target_host
            || std::env::var("SLURM_JOB_ID").is_err())
    {
        return Err(error(
            "client is not on its assigned separate Slurm compute node",
        ));
    }
    if std::fs::metadata(&options.key_file)?.len() != 32 {
        return Err(error("monitor key file must contain 32 random bytes"));
    }
    let secret_bytes = Zeroizing::new(std::fs::read(&options.key_file)?);
    let secret: [u8; 32] = secret_bytes
        .as_slice()
        .try_into()
        .map_err(|_| error("monitor key file must contain 32 random bytes"))?;
    let secret = Arc::new(Zeroizing::new(secret));
    let pool = CpuPool::new(options.workers);
    let traffic = Arc::new(Traffic::default());
    let calibration = if config.rounds_per_monitor > 0 {
        Some(calibrate(&options.target, config.timeout_ms, traffic.clone()).await?)
    } else {
        None
    };
    let calibration_metadata=calibration.as_ref().map(|c|serde_json::json!({"method":"minimum-RTT four-timestamp monotonic clock offset (8 samples)","offset_ns":c.offset_ns,"uncertainty_ns":c.uncertainty_ns}));
    let events_path = options.output.with_extension("events.jsonl");
    let file = std::fs::File::create(&events_path)?;
    let (events, mut event_rx) = mpsc::channel::<Event>(256);
    let writer = tokio::task::spawn_blocking(move || {
        let mut writer = std::io::BufWriter::new(file);
        while let Some(event) = event_rx.blocking_recv() {
            serde_json::to_writer(&mut writer, &event)?;
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
        Ok::<_, crate::Error>(())
    });
    let context = ClientContext {
        options: options.clone(),
        manifest: manifest.clone(),
        secret,
        pool: pool.clone(),
        traffic: traffic.clone(),
        events,
        schedule: Arc::new(Mutex::new(None)),
        cancel: watch::channel(false).0,
        calibration,
    };
    let start = Instant::now();
    let mut monitors = JoinSet::new();
    let mut results = Vec::new();
    let mut errors = Vec::new();
    for assignment in manifest
        .assignments
        .iter()
        .filter(|a| a.agent_id == options.agent)
    {
        let context = context.clone();
        let id = assignment.monitor_id;
        monitors.spawn(async move { run_monitor(context, id).await });
    }
    let mut sampler = tokio::time::interval(Duration::from_millis(250));
    let mut samples = Vec::new();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupted = false;
    while !monitors.is_empty() {
        tokio::select! {
            Some(result)=monitors.join_next()=>match result {Ok(Ok(result))=>results.push(result),Ok(Err(e))=>errors.push(e.to_string()),Err(e)=>errors.push(e.to_string())},
            _=sampler.tick()=>{let phase=context.schedule.lock().unwrap().as_ref().map(|s|s.phase(Instant::now())).unwrap_or(Phase::Deployment);samples.push(serde_json::json!({
            "unix_ms":wire::unix_ms(),
            "elapsed_s":start.elapsed().as_secs_f64(),
            "phase":phase,
            "resources":metrics::resources(),
            "active_cpu_jobs":pool.jobs.current.load(Ordering::Relaxed),
            "sent_bytes":traffic.sent.load(Ordering::Relaxed),
            "received_bytes":traffic.received.load(Ordering::Relaxed),
        }));}
            _=tokio::signal::ctrl_c(), if !interrupted=>{interrupted=true;context.cancel.send_replace(true);}
            _=sigterm.recv(), if !interrupted=>{interrupted=true;context.cancel.send_replace(true);}
        }
    }
    drop(context);
    writer.await??;
    results.sort_by_key(|r| r.monitor_id);
    let elapsed = start.elapsed().as_secs_f64();
    let duration = config.duration_s;
    let completed = results
        .iter()
        .map(|r| r.histograms.completed_in_window)
        .sum::<u64>();
    let offered = results.iter().map(|r| r.histograms.offered).sum::<u64>();
    let dropped = results
        .iter()
        .map(|r| r.histograms.dependency_dropped)
        .sum::<u64>();
    metrics::write_json(
        &options.output,
        &serde_json::json!({
            "schema":"exact-bench-v1",
            "role":"client",
            "clock_calibration":calibration_metadata,
            "distributed":config.distributed,
            "manifest":manifest,
            "agent_id":options.agent,
            "hostname":config::hostname(),
            "hosted_monitors":results.len(),
            "assigned_monitor_ids":manifest.assignments.iter().filter(|a|a.agent_id==options.agent).map(|a|a.monitor_id).collect::<Vec<_>>(),
            "client_worker_threads":options.workers,
            "cpu_model":metrics::cpu_model(),
            "slurm_job_id":std::env::var("SLURM_JOB_ID").ok(),
            "git_commit":metrics::git_commit(),
            "git_dirty":metrics::git_dirty(),
            "slurm_cpus_per_task":std::env::var("SLURM_CPUS_PER_TASK").ok(),
            "reporting_resources":metrics::sampled_resources(&samples),
            "elapsed_s":elapsed,
            "resources":metrics::resources(),
            "active_cpu_jobs_peak":pool.jobs.peak.load(Ordering::Relaxed),
            "sent_bytes":traffic.sent.load(Ordering::Relaxed),
            "received_bytes":traffic.received.load(Ordering::Relaxed),
            "reporting":{"completed":completed,"throughput_rps":completed as f64/duration,"offered":offered,"offered_rps":offered as f64/duration,"dependency_dropped":dropped},
            "events_file":events_path.file_name().unwrap_or_default().to_string_lossy(),
            "monitors":results,
            "samples":samples,
            "errors":errors,
            "interrupted":interrupted,
            "latency_definition":"scheduled arrival to verified update acknowledgement; monotonic local clock; includes client worker and scheduling delay",
        }),
    )?;
    if interrupted {
        return Err(error(
            "client interrupted; available metrics and events saved",
        ));
    }
    let mut finish = Channel::connect(&options.target, config.timeout_ms, traffic).await?;
    finish
        .send(&Request::Finish {
            epoch: manifest.epoch,
            agent: options.agent,
        })
        .await?;
    match finish.recv().await? {
        Response::Ok => {}
        Response::Rejected { reason, .. } => return Err(error(reason)),
        _ => return Err(error("expected finish acknowledgement")),
    }
    if !errors.is_empty() {
        return Err(error(format!(
            "{} monitor(s) failed; see client JSON",
            errors.len()
        )));
    }
    Ok(())
}

async fn connect_monitor(
    context: &ClientContext,
    id: usize,
    token: [u8; 32],
    state: &mut Option<MonitorState>,
) -> Result<(Channel, u64, Schedule, f64)> {
    let config = &context.manifest.config;
    let set = id / config.monitors_per_set;
    let start = Instant::now();
    let mut ch = Channel::connect(
        &context.options.target,
        config.timeout_ms,
        context.traffic.clone(),
    )
    .await?;
    ch.send(&Request::Register {
        epoch: context.manifest.epoch,
        monitor: id,
        set,
        agent: context.options.agent,
        host: config::hostname(),
        session: token,
        cursor: state.as_ref().map(|s| s.version).unwrap_or(0),
    })
    .await?;
    let (initial, seq, updates) = match ch.recv().await? {
        Response::Registered {
            initial,
            next_seq,
            updates,
            ..
        } => (initial, next_seq, updates),
        Response::Rejected { reason, .. } => return Err(error(reason)),
        _ => return Err(error("expected registration")),
    };
    if state.is_none() {
        let initial = initial.ok_or_else(|| error("missing deployment"))?;
        let secret = context.secret.clone();
        *state = Some(
            context
                .pool
                .run(move || MonitorState::deploy(&secret, set, &initial).map_err(error))
                .await?
                .0,
        );
    }
    if !updates.is_empty() {
        let mut current = state.take().unwrap();
        let (returned, result) = context
            .pool
            .run(move || {
                let result = (|| {
                    for update in &updates {
                        current.apply(update).map_err(error)?;
                    }
                    Ok::<_, crate::Error>(())
                })();
                Ok((current, result))
            })
            .await?
            .0;
        *state = Some(returned);
        result?;
    }
    let deployment_s = start.elapsed().as_secs_f64();
    ch.send(&Request::Ready).await?;
    let schedule = match ch.recv().await? {
        Response::Schedule {
            server_unix_ms,
            warmup_unix_ms,
            measure_unix_ms,
            end_unix_ms,
        } => {
            // Relative server times avoid depending on synchronized host clocks.
            // Delivery adds a small one-way control-message scheduling offset.
            let now = Instant::now();
            let at = |t: u64| {
                if t >= server_unix_ms {
                    now + Duration::from_millis(t - server_unix_ms)
                } else {
                    now.checked_sub(Duration::from_millis(server_unix_ms - t))
                        .unwrap_or(now)
                }
            };
            Schedule {
                warmup: at(warmup_unix_ms),
                measure: at(measure_unix_ms),
                end: at(end_unix_ms),
            }
        }
        Response::Rejected { reason, .. } => return Err(error(reason)),
        _ => return Err(error("expected synchronized schedule")),
    };
    context
        .schedule
        .lock()
        .unwrap()
        .get_or_insert_with(|| schedule.clone());
    Ok((ch, seq, schedule, deployment_s))
}

async fn reconnect(
    context: &ClientContext,
    id: usize,
    token: [u8; 32],
    state: &mut Option<MonitorState>,
) -> Result<(Channel, u64, Schedule, f64)> {
    let deadline = Instant::now() + Duration::from_millis(context.manifest.config.timeout_ms);
    loop {
        if *context.cancel.borrow() {
            return Err(error("client interrupted during reconnect"));
        }
        match connect_monitor(context, id, token, state).await {
            Ok(connection) => return Ok(connection),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(e);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

fn input(manifest: &Manifest, id: usize, round: u64) -> (u64, bool, String) {
    let c = &manifest.config;
    let offset = id % c.monitors_per_set;
    let kind = if c.workload == "mixed" {
        match round % 4 {
            0 => "fresh",
            1 => "nonmatch",
            2 => "repeated",
            _ => "shared",
        }
    } else {
        c.workload.as_str()
    };
    let index = match kind {
        "fresh" => (round * c.monitors_per_set as u64 + offset as u64) % c.set_size as u64,
        "nonmatch" => round,
        "repeated" => offset as u64 % c.set_size as u64,
        _ => 0,
    };
    (index, kind != "nonmatch", kind.into())
}

async fn run_monitor(context: ClientContext, id: usize) -> Result<MonitorResult> {
    let mut token = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    let mut state = None;
    let (mut ch, mut seq, schedule, deployment_s) =
        connect_monitor(&context, id, token, &mut state).await?;
    let config = &context.manifest.config;
    let set = id / config.monitors_per_set;
    let mut stats = Stats::default();
    let mut reconnects = 0;
    let mut round = 0u64;
    let mut warmup_completed = 0;
    let mut requested_members = 0;
    let mut requested_nonmembers = 0;
    wait_until(&context, schedule.warmup).await;
    let period =
        Duration::from_secs_f64(context.manifest.total_monitors as f64 / config.offered_rate);
    let first = schedule.warmup + Duration::from_secs_f64(id as f64 / config.offered_rate);
    let mut tick = 0u64;
    let mut pending_since = None;
    loop {
        if *context.cancel.borrow() {
            break;
        }
        if config.rounds_per_monitor > 0 && seq >= config.rounds_per_monitor {
            break;
        }
        if config.mode == "open-loop" && tick > 0 {
            let now = Instant::now().min(schedule.end);
            let next = first + period.mul_f64(tick as f64);
            if now > next {
                let skip = ((now.duration_since(next).as_secs_f64() / period.as_secs_f64()).floor()
                    as u64)
                    + 1;
                let first_measure = ((schedule
                    .measure
                    .saturating_duration_since(first)
                    .as_secs_f64()
                    / period.as_secs_f64())
                .ceil() as u64)
                    .max(tick);
                let end_tick = ((schedule.end.saturating_duration_since(first).as_secs_f64()
                    / period.as_secs_f64())
                .ceil() as u64)
                    .min(tick + skip);
                let measured_skips = end_tick.saturating_sub(first_measure);
                stats.dependency_dropped += measured_skips;
                stats.offered += measured_skips;
                tick += skip;
            }
        }
        let planned = if config.rounds_per_monitor > 0 {
            *pending_since.get_or_insert_with(Instant::now)
        } else if config.mode == "open-loop" {
            first + period.mul_f64(tick as f64)
        } else {
            Instant::now()
        };
        if planned >= schedule.end || Instant::now() >= schedule.end {
            break;
        }
        if config.mode == "open-loop" {
            if !wait_until(&context, planned).await {
                break;
            }
            tick += 1;
        }
        let phase = schedule.phase(planned);
        let measured = phase == Phase::Measurement;
        if measured {
            stats.offered += 1;
            stats.scheduling_delay.record(
                Instant::now()
                    .saturating_duration_since(planned)
                    .as_secs_f64(),
            );
        }
        let cursor = state.as_ref().unwrap().version;
        let request = async {
            if let Some(calibration) = &context.calibration {
                ch.send(&Request::Observe {
                    seq,
                    cursor,
                    submitted_server_ns: calibration.target_ns(planned),
                })
                .await?;
            } else {
                ch.send(&Request::Acquire { seq, cursor }).await?;
            }
            ch.recv::<Response>().await
        }
        .await;
        let response = match request {
            Ok(r) => r,
            Err(e) => {
                if measured {
                    stats.failures += 1;
                    if metrics::is_timeout(&e) {
                        stats.timeouts += 1;
                    }
                }
                // The current verified state and session token survive transport
                // failure. Server next_seq disambiguates a lost commit response.
                reconnects += 1;
                drop(ch);
                tokio::time::sleep(Duration::from_millis(20)).await;
                let connected = reconnect(&context, id, token, &mut state).await?;
                ch = connected.0;
                seq = connected.1;
                continue;
            }
        };
        let (ctx, updates, queue_s) = match response {
            Response::Granted {
                seq: s,
                context,
                updates,
                queue_s,
            } if s == seq => (context, updates, queue_s),
            Response::Rejected { reason, retryable } => {
                if measured {
                    stats.rejected += 1;
                }
                if !retryable {
                    return Err(error(reason));
                }
                if config.mode == "closed-loop" {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                continue;
            }
            _ => return Err(error("expected set grant")),
        };
        if measured {
            stats.accepted += 1;
        }
        let (index, member, requested_kind) = input(&context.manifest, id, round);
        round += 1;
        let item = session::synthetic_item(config.seed, set, index, member);
        let mut current = state.take().unwrap();
        let ((returned, report), client_worker, client_crypto) = context
            .pool
            .run(move || {
                let result = (|| {
                    for update in &updates {
                        current.apply(update).map_err(error)?;
                    }
                    current.report(item, ctx).map_err(error)
                })();
                Ok((current, result))
            })
            .await?;
        state = Some(returned);
        let report = report?;
        if Instant::now() >= schedule.end || *context.cancel.borrow() {
            ch.send(&Request::Cancel { seq }).await?;
            let _: Response = ch.recv().await?;
            if measured {
                stats.cancellations += 1;
            }
            break;
        }
        let commit = async {
            ch.send(&Request::Report {
                seq,
                context: ctx,
                bytes: report,
            })
            .await?;
            ch.recv::<Response>().await
        }
        .await;
        let (update, target_timing) = match commit {
            Ok(Response::Committed {
                seq: s,
                update,
                timing,
            }) if s == seq => (update, timing),
            Ok(Response::Rejected { reason, retryable }) => {
                if measured {
                    stats.rejected += 1;
                }
                if !retryable {
                    return Err(error(reason));
                }
                continue;
            }
            Ok(_) => return Err(error("expected commit")),
            Err(e) => {
                if measured {
                    stats.failures += 1;
                    stats.timeouts += u64::from(metrics::is_timeout(&e));
                }
                reconnects += 1;
                drop(ch);
                tokio::time::sleep(Duration::from_millis(20)).await;
                let connected = reconnect(&context, id, token, &mut state).await?;
                ch = connected.0;
                seq = connected.1;
                continue;
            }
        };
        let mut current = state.take().unwrap();
        let version = update.version;
        let (current, verify_worker, verify_crypto) = context
            .pool
            .run(move || {
                current.apply(&update).map_err(error)?;
                Ok(current)
            })
            .await?;
        state = Some(current);
        let acknowledgement = async {
            ch.send(&Request::Ack { version }).await?;
            ch.recv::<Response>().await
        }
        .await;
        let ack_failed = match acknowledgement {
            Ok(Response::Ok) => false,
            Ok(_) => return Err(error("expected verified acknowledgement")),
            Err(e) => {
                if measured {
                    stats.failures += 1;
                    stats.timeouts += u64::from(metrics::is_timeout(&e));
                }
                true
            }
        };
        if schedule.phase(Instant::now()) == Phase::Measurement {
            stats.completed_in_window += 1;
        }
        if measured {
            stats.complete(
                RoundTiming {
                    queue_s,
                    worker_s: client_worker + verify_worker,
                    crypto_s: client_crypto + verify_crypto,
                    io_peer_wait_s: target_timing.io_peer_wait_s,
                    target_s: target_timing.target_s,
                },
                Instant::now().duration_since(planned).as_secs_f64(),
            );
            requested_members += u64::from(member);
            requested_nonmembers += u64::from(!member);
        } else {
            warmup_completed += 1;
        }
        context
            .events
            .send(Event {
                monitor_id: id,
                set_id: set,
                version,
                seq,
                phase,
                member,
                item_index: index,
                requested_kind,
            })
            .await
            .map_err(error)?;
        seq += 1;
        pending_since = None;
        if ack_failed {
            reconnects += 1;
            drop(ch);
            let connected = reconnect(&context, id, token, &mut state).await?;
            ch = connected.0;
            seq = connected.1;
        }
    }
    if config.mode == "open-loop" && !*context.cancel.borrow() {
        // Include arrivals remaining while the final state-dependent request
        // drained or was cancelled at the end of the measurement window.
        let first_measure = ((schedule
            .measure
            .saturating_duration_since(first)
            .as_secs_f64()
            / period.as_secs_f64())
        .ceil() as u64)
            .max(tick);
        let end_tick = (schedule.end.saturating_duration_since(first).as_secs_f64()
            / period.as_secs_f64())
        .ceil() as u64;
        let remaining = end_tick.saturating_sub(first_measure);
        stats.dependency_dropped += remaining;
        stats.offered += remaining;
    }
    if config.rounds_per_monitor > 0 && !*context.cancel.borrow() {
        if seq < config.rounds_per_monitor {
            return Err(error(
                "finite batch deadline reached before every observation committed",
            ));
        }
        ch.send(&Request::Retire {
            version: state.as_ref().unwrap().version,
        })
        .await?;
        match ch.recv().await? {
            Response::Ok => {}
            _ => return Err(error("monitor retirement rejected")),
        }
    }
    if config.rounds_per_monitor == 0 {
        wait_until(&context, schedule.end).await;
    }
    Ok(MonitorResult {
        monitor_id: id,
        set_id: set,
        session: token,
        deployment_s,
        reconnects,
        reporting: stats.summary(config.duration_s),
        histograms: stats,
        warmup_completed,
        requested_members,
        requested_nonmembers,
    })
}
