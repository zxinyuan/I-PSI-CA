use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::sync::Semaphore;

pub fn is_timeout(error: &crate::Error) -> bool {
    error.is::<tokio::time::error::Elapsed>()
        || error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|e| e.kind() == std::io::ErrorKind::TimedOut)
}

/// Fixed 512-bin log histogram (eight bins per power of two, nanoseconds).
/// Memory is independent of the number of requests; percentiles are upper bin
/// bounds with at most 12.5% quantization error.
#[derive(Clone, Serialize, Deserialize)]
pub struct Histogram {
    pub bins: Vec<u64>,
    pub count: u64,
    pub sum_s: f64,
    pub max_s: f64,
}
impl Default for Histogram {
    fn default() -> Self {
        Self {
            bins: vec![0; 512],
            count: 0,
            sum_s: 0.0,
            max_s: 0.0,
        }
    }
}
impl Histogram {
    pub fn record(&mut self, seconds: f64) {
        let ns = (seconds.max(0.0) * 1e9) as u64;
        let exp = 63 - ns.max(1).leading_zeros() as usize;
        let base = 1u64 << exp;
        let sub = (((ns.saturating_sub(base)) as u128 * 8) / base as u128) as usize;
        self.bins[(exp * 8 + sub).min(511)] += 1;
        self.count += 1;
        self.sum_s += seconds;
        self.max_s = self.max_s.max(seconds);
    }
    pub fn percentile(&self, p: f64) -> f64 {
        if self.count == 0 {
            return 0.0;
        }
        let threshold = (self.count as f64 * p).ceil() as u64;
        let mut n = 0;
        for (i, count) in self.bins.iter().enumerate() {
            n += count;
            if n >= threshold {
                return (2f64.powi((i / 8) as i32) * (1.0 + (i % 8 + 1) as f64 / 8.0) / 1e9)
                    .min(self.max_s);
            }
        }
        self.max_s
    }
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "count":self.count,
            "mean_s":if self.count==0 {0.0}else{self.sum_s/self.count as f64},
            "p50_s":self.percentile(0.5),
            "p95_s":self.percentile(0.95),
            "p99_s":self.percentile(0.99),
            "max_s":self.max_s,
        })
    }
}

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
pub struct RoundTiming {
    pub queue_s: f64,
    pub worker_s: f64,
    pub crypto_s: f64,
    pub io_peer_wait_s: f64,
    pub target_s: f64,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub offered: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub completed: u64,
    pub completed_in_window: u64,
    pub failures: u64,
    pub timeouts: u64,
    pub cancellations: u64,
    pub matches: u64,
    pub nonmatches_or_replays: u64,
    pub dependency_dropped: u64,
    pub queue_peak: usize,
    pub latency: Histogram,
    pub queue: Histogram,
    pub worker: Histogram,
    pub crypto: Histogram,
    pub io_peer_wait: Histogram,
    pub scheduling_delay: Histogram,
    pub submission_to_commit: Histogram,
}
impl Stats {
    pub fn complete(&mut self, t: RoundTiming, latency: f64) {
        self.completed += 1;
        self.latency.record(latency);
        self.queue.record(t.queue_s);
        self.worker.record(t.worker_s);
        self.crypto.record(t.crypto_s);
        self.io_peer_wait.record(t.io_peer_wait_s);
    }
    pub fn summary(&self, duration: f64) -> serde_json::Value {
        serde_json::json!({
            "offered":self.offered,
            "accepted":self.accepted,
            "rejected":self.rejected,
            "completed":self.completed_in_window,
            "admission_cohort_completed":self.completed,
            "failures":self.failures,
            "timeouts":self.timeouts,
            "cancellations":self.cancellations,
            "matches":self.matches,
            "nonmatches_or_replays":self.nonmatches_or_replays,
            "dependency_dropped":self.dependency_dropped,
            "queue_peak":self.queue_peak,
            "throughput_rps":self.completed_in_window as f64/duration,
            "offered_rps":self.offered as f64/duration,
            "accepted_rps":self.accepted as f64/duration,
            "rejected_rps":self.rejected as f64/duration,
            "latency":self.latency.summary(),
            "set_wait":self.queue.summary(),
            "worker_wait":self.worker.summary(),
            "crypto":self.crypto.summary(),
            "io_and_peer_wait":self.io_peer_wait.summary(),
            "scheduling_delay":self.scheduling_delay.summary(),
            "submission_to_commit":self.submission_to_commit.summary(),
        })
    }
}

#[derive(Default)]
pub struct Gauge {
    pub current: AtomicUsize,
    pub peak: AtomicUsize,
}
pub struct GaugeGuard(Arc<Gauge>);
impl Gauge {
    pub fn enter(self: &Arc<Self>) -> GaugeGuard {
        let n = self.current.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(n, Ordering::Relaxed);
        GaugeGuard(self.clone())
    }
}
impl Drop for GaugeGuard {
    fn drop(&mut self) {
        self.0.current.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct CpuPool {
    slots: Arc<Semaphore>,
    pub jobs: Arc<Gauge>,
}
impl CpuPool {
    pub fn new(workers: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(workers)),
            jobs: Arc::new(Gauge::default()),
        }
    }
    pub async fn run<F, T>(&self, f: F) -> Result<(T, f64, f64)>
    where
        F: FnOnce() -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let start = Instant::now();
        let permit = self.slots.clone().acquire_owned().await?;
        let wait = start.elapsed().as_secs_f64();
        let jobs = self.jobs.clone();
        // The permit lives in the CPU closure, including if its async caller is
        // cancelled. Cancellation can never make the physical pool exceed W.
        let (result, elapsed) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _active = jobs.enter();
            let start = Instant::now();
            let result = f();
            (result, start.elapsed().as_secs_f64())
        })
        .await?;
        Ok((result?, wait, elapsed))
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Resources {
    pub cpu_s: f64,
    pub peak_rss_kib: u64,
    pub rss_kib: u64,
}
pub fn resources() -> Resources {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // getrusage initializes the entire structure on success.
    let cpu_s = unsafe {
        if libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) == 0 {
            let u = usage.assume_init();
            u.ru_utime.tv_sec as f64
                + u.ru_utime.tv_usec as f64 / 1e6
                + u.ru_stime.tv_sec as f64
                + u.ru_stime.tv_usec as f64 / 1e6
        } else {
            0.0
        }
    };
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find(|s| s.starts_with(name))
            .and_then(|s| s.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    };
    Resources {
        cpu_s,
        peak_rss_kib: field("VmHWM:"),
        rss_kib: field("VmRSS:"),
    }
}
pub fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find_map(|s| {
            s.strip_prefix("model name")
                .and_then(|s| s.split_once(':'))
                .map(|(_, v)| v.trim().to_string())
        })
        .unwrap_or_default()
}
pub fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn git_dirty() -> bool {
    std::process::Command::new("git")
        .args([
            "status",
            "--porcelain",
            "--",
            "src/exact",
            "Cargo.toml",
            "Cargo.lock",
        ])
        .output()
        .is_ok_and(|o| !o.stdout.is_empty())
}

/// Reporting-window resource rates use monotonic sample spacing. Absolute CPU
/// seconds and traffic counters include deployment, so only differences between
/// reporting samples belong in these utilization/throughput estimates.
pub fn sampled_resources(samples: &[serde_json::Value]) -> serde_json::Value {
    let rows = samples
        .iter()
        .filter(|s| s["phase"] == "Measurement")
        .collect::<Vec<_>>();
    let field =
        |s: &serde_json::Value, k: &str| s.get("resources").unwrap_or(s)[k].as_f64().unwrap_or(0.0);
    let mut span = 0.0;
    let mut cpu = 0.0;
    let mut sent = 0.0;
    let mut received = 0.0;
    if let (Some(first), Some(last)) = (rows.first(), rows.last()) {
        span =
            last["elapsed_s"].as_f64().unwrap_or(0.0) - first["elapsed_s"].as_f64().unwrap_or(0.0);
        if span > 0.0 {
            cpu = 100.0 * (field(last, "cpu_s") - field(first, "cpu_s")) / span;
            sent = (last["sent_bytes"].as_f64().unwrap_or(0.0)
                - first["sent_bytes"].as_f64().unwrap_or(0.0))
                / span;
            received = (last["received_bytes"].as_f64().unwrap_or(0.0)
                - first["received_bytes"].as_f64().unwrap_or(0.0))
                / span;
        }
    }
    serde_json::json!({
        "sample_span_s":span,
        "cpu_utilization_percent":(span>0.0).then_some(cpu),
        "network_sent_bytes_per_second":(span>0.0).then_some(sent),
        "network_received_bytes_per_second":(span>0.0).then_some(received),
        "network_mbps":(span>0.0).then_some((sent+received)*8.0/1e6),
        "peak_sampled_rss_kib":rows.iter().map(|s|field(s,"rss_kib")).fold(0.0,f64::max),
    })
}
pub fn write_json(path: &std::path::Path, value: &serde_json::Value) -> Result<()> {
    let temp = path.with_extension("json.partial");
    std::fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    std::fs::rename(temp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn histogram_is_bounded_and_counts() {
        let mut h = Histogram::default();
        for i in 1..10001 {
            h.record(i as f64 / 1000.0);
        }
        assert_eq!(h.count, 10000);
        assert_eq!(h.bins.len(), 512);
        assert!((5.0..5.7).contains(&h.percentile(0.5)));
    }
}
