use crate::{error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_MONITORS: usize = 10_000;
pub const MAX_SETS: usize = 1_000;
pub const MAX_TOTAL_ELEMENTS: usize = 1_000_000;
pub const MAX_SESSION_COEFFICIENTS: usize = 10_000_000;
pub const MAX_HISTORY_BYTES: usize = 512 * 1024 * 1024;
pub const MAX_FRAME: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub set_size: usize,
    pub num_sets: usize,
    pub monitors_per_set: usize,
    pub client_nodes: usize,
    pub worker_threads: usize,
    pub max_inflight: usize,
    pub max_queue_per_set: usize,
    pub history_bytes_per_set: usize,
    pub timeout_ms: u64,
    pub warmup_s: f64,
    pub duration_s: f64,
    /// Zero selects the timed throughput benchmark; positive values select a
    /// finite batch with this many successful reports per logical monitor.
    #[serde(default)]
    pub rounds_per_monitor: u64,
    pub seed: u64,
    pub run_id: String,
    pub mode: String,
    pub workload: String,
    pub offered_rate: f64,
    pub distributed: bool,
    pub target_host: String,
    pub client_hosts: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            set_size: 1000,
            num_sets: 10,
            monitors_per_set: 20,
            client_nodes: 1,
            worker_threads: 8,
            max_inflight: 256,
            max_queue_per_set: 100,
            history_bytes_per_set: 8 * 1024 * 1024,
            timeout_ms: 120_000,
            warmup_s: 5.0,
            duration_s: 30.0,
            rounds_per_monitor: 0,
            seed: 42,
            run_id: "local".into(),
            mode: "closed-loop".into(),
            workload: "mixed".into(),
            offered_rate: 100.0,
            distributed: false,
            target_host: hostname(),
            client_hosts: vec![hostname()],
        }
    }
}

pub fn hostname() -> String {
    std::env::var("SLURMD_NODENAME")
        .or_else(|_| {
            std::fs::read_to_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|_| "unknown".into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assignment {
    pub monitor_id: usize,
    pub set_id: usize,
    pub agent_id: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub protocol: String,
    pub config: Config,
    pub total_monitors: usize,
    pub assignments: Vec<Assignment>,
    /// A fresh random server incarnation. A restart is a new run, never a
    /// silent continuation of a stateful benchmark.
    pub epoch: [u8; 32],
}

impl Config {
    pub fn total(&self) -> Result<usize> {
        self.num_sets
            .checked_mul(self.monitors_per_set)
            .ok_or_else(|| error("N*M overflow"))
    }
    pub fn validate(&self) -> Result<()> {
        let total = self.total()?;
        if self.rounds_per_monitor > 0
            && (self.rounds_per_monitor > 10000
                || self.warmup_s != 0.0
                || self.mode != "closed-loop")
        {
            return Err(error(
                "finite batches require 1..10000 rounds, zero warmup, and closed-loop mode",
            ));
        }
        if self.set_size == 0
            || self.set_size >= i_psi_ca::exact::MAX_COEFFICIENTS
            || self.num_sets == 0
            || self.monitors_per_set == 0
            || self.client_nodes == 0
            || self.worker_threads == 0
            || self.max_inflight == 0
            || self.max_queue_per_set == 0
        {
            return Err(error(
                "S,N,M,clients,workers,inflight,queue must be positive; S <= 16383",
            ));
        }
        if total > MAX_MONITORS
            || self.num_sets > MAX_SETS
            || self
                .set_size
                .checked_mul(self.num_sets)
                .is_none_or(|n| n > MAX_TOTAL_ELEMENTS)
            || self.client_nodes > total
            || self.worker_threads > 256
            || self.max_inflight > MAX_MONITORS
            || self.max_queue_per_set > MAX_MONITORS
            || self
                .set_size
                .checked_add(1)
                .and_then(|s| s.checked_mul(total))
                .is_none_or(|n| n > MAX_SESSION_COEFFICIENTS)
        {
            return Err(error(
                "configuration exceeds explicit monitor/set/element/worker/queue safety limits",
            ));
        }
        if self.history_bytes_per_set < 1024
            || self.history_bytes_per_set > MAX_FRAME / 2
            || self
                .history_bytes_per_set
                .checked_mul(self.num_sets)
                .is_none_or(|n| n > MAX_HISTORY_BYTES)
        {
            return Err(error(
                "history budget must be 1 KiB..32 MiB/set and <=512 MiB total",
            ));
        }
        // At least one update must fit the history/frame budgets. An actual
        // serialized-size check still protects the commit path.
        if self.history_bytes_per_set < (self.set_size + 1) * 1024 + 32_768 {
            return Err(error("history budget too small for one exact proof/update"));
        }
        if !self.duration_s.is_finite()
            || self.duration_s <= 0.0
            || self.duration_s > 86400.0
            || !self.warmup_s.is_finite()
            || !(0.0..=86400.0).contains(&self.warmup_s)
            || !(100..=3_600_000).contains(&self.timeout_ms)
        {
            return Err(error("invalid duration/warmup/timeout"));
        }
        if !["closed-loop", "open-loop"].contains(&self.mode.as_str())
            || !["fresh", "nonmatch", "repeated", "shared", "mixed"]
                .contains(&self.workload.as_str())
            || !self.offered_rate.is_finite()
            || !(0.0001..=1_000_000.0).contains(&self.offered_rate)
        {
            return Err(error("invalid workload, mode, or offered rate"));
        }
        if self.run_id.is_empty()
            || self.run_id.len() > 128
            || self.client_hosts.len() != self.client_nodes
        {
            return Err(error("invalid run ID or client host list"));
        }
        if self.distributed {
            let mut hosts = std::collections::HashSet::new();
            hosts.insert(self.target_host.as_str());
            for host in &self.client_hosts {
                if host.is_empty() || !hosts.insert(host.as_str()) {
                    return Err(error(
                        "distributed runs require distinct target and client physical hosts",
                    ));
                }
            }
            if self.target_host != hostname() {
                return Err(error("target running on a different host than manifest"));
            }
            if std::env::var("SLURM_JOB_ID").is_err() {
                return Err(error(
                    "distributed mode requires a Slurm compute allocation",
                ));
            }
        }
        Ok(())
    }
    pub fn manifest(&self) -> Result<Manifest> {
        self.validate()?;
        use rand::RngCore;
        let mut epoch = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut epoch);
        let total_monitors = self.total()?;
        Ok(Manifest {
            protocol: "exact-distributed-v2".into(),
            config: self.clone(),
            total_monitors,
            assignments: (0..total_monitors)
                .map(|monitor_id| Assignment {
                    monitor_id,
                    set_id: monitor_id / self.monitors_per_set,
                    agent_id: monitor_id % self.client_nodes,
                })
                .collect(),
            epoch,
        })
    }
}

impl Manifest {
    pub fn validate(&self) -> Result<()> {
        // Client validation doesn't apply the target's host check.
        let mut local = self.config.clone();
        local.distributed = false;
        local.validate()?;
        if self.protocol != "exact-distributed-v2"
            || self.total_monitors != self.config.total()?
            || self.assignments.len() != self.total_monitors
        {
            return Err(error("invalid manifest topology"));
        }
        let mut seen = vec![false; self.total_monitors];
        for a in &self.assignments {
            if a.monitor_id >= self.total_monitors
                || seen[a.monitor_id]
                || a.set_id != a.monitor_id / self.config.monitors_per_set
                || a.agent_id != a.monitor_id % self.config.client_nodes
            {
                return Err(error(
                    "duplicate, unknown, or inconsistent monitor assignment",
                ));
            }
            seen[a.monitor_id] = true;
        }
        Ok(())
    }
}

/// Small strict CLI parser: rejects duplicate and unknown arguments.
pub struct Args(BTreeMap<String, String>);
impl Args {
    pub fn parse(args: impl Iterator<Item = String>) -> Result<Self> {
        let mut map = BTreeMap::new();
        let mut args = args;
        while let Some(key) = args.next() {
            if !key.starts_with("--") {
                return Err(error(format!("expected --option, got {key}")));
            }
            let value = args
                .next()
                .ok_or_else(|| error(format!("missing value for {key}")))?;
            if value.starts_with("--") || map.insert(key.clone(), value).is_some() {
                return Err(error(format!("missing value or duplicate {key}")));
            }
        }
        Ok(Self(map))
    }
    pub fn get(&mut self, key: &str, default: &str) -> String {
        self.0.remove(key).unwrap_or_else(|| default.into())
    }
    pub fn required(&mut self, key: &str) -> Result<String> {
        self.0
            .remove(key)
            .ok_or_else(|| error(format!("required {key}")))
    }
    pub fn number<T: std::str::FromStr>(&mut self, key: &str, default: T) -> Result<T> {
        self.0
            .remove(key)
            .map(|s| s.parse().map_err(|_| error(format!("invalid {key}"))))
            .unwrap_or(Ok(default))
    }
    pub fn finish(self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(error(format!("unknown options: {:?}", self.0.keys())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_mappings_and_validation() {
        let c = Config {
            set_size: 2,
            num_sets: 3,
            monitors_per_set: 2,
            client_nodes: 2,
            client_hosts: vec!["a".into(), "b".into()],
            ..Config::default()
        };
        let mut m = c.manifest().unwrap();
        m.validate().unwrap();
        assert_eq!(
            m.assignments.iter().map(|a| a.set_id).collect::<Vec<_>>(),
            vec![0, 0, 1, 1, 2, 2]
        );
        assert_eq!(
            m.assignments.iter().map(|a| a.agent_id).collect::<Vec<_>>(),
            vec![0, 1, 0, 1, 0, 1]
        );
        m.assignments[1] = m.assignments[0].clone();
        assert!(m.validate().is_err());
        for bad in [
            Config {
                num_sets: 0,
                ..c.clone()
            },
            Config {
                monitors_per_set: 0,
                ..c.clone()
            },
            Config {
                num_sets: usize::MAX,
                monitors_per_set: 2,
                ..c.clone()
            },
            Config {
                set_size: 16384,
                ..c.clone()
            },
            Config {
                worker_threads: 0,
                ..c.clone()
            },
        ] {
            assert!(bad.validate().is_err());
        }
    }
}
