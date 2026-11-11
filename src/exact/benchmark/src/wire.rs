use crate::{
    config::{Manifest, MAX_FRAME},
    error,
    metrics::RoundTiming,
    Result,
};
use bincode::Options;
use i_psi_ca::exact::session::{InitialState, Update};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

#[derive(Serialize, Deserialize)]
pub enum Request {
    Probe,
    Clock,
    Register {
        epoch: [u8; 32],
        monitor: usize,
        set: usize,
        agent: usize,
        host: String,
        session: [u8; 32],
        cursor: u64,
    },
    Ready,
    Retire {
        version: u64,
    },
    Acquire {
        seq: u64,
        cursor: u64,
    },
    Observe {
        seq: u64,
        cursor: u64,
        submitted_server_ns: u64,
    },
    Report {
        seq: u64,
        context: [u8; 32],
        bytes: Vec<u8>,
    },
    Ack {
        version: u64,
    },
    Cancel {
        seq: u64,
    },
    Finish {
        epoch: [u8; 32],
        agent: usize,
    },
}

#[derive(Serialize, Deserialize)]
pub enum Response {
    Manifest(Box<Manifest>),
    Clock {
        received_ns: u64,
        sent_ns: u64,
    },
    Registered {
        initial: Option<Box<InitialState>>,
        updates: Vec<Arc<Update>>,
        next_seq: u64,
        deployment_s: f64,
    },
    Schedule {
        server_unix_ms: u64,
        warmup_unix_ms: u64,
        measure_unix_ms: u64,
        end_unix_ms: u64,
    },
    Granted {
        seq: u64,
        context: [u8; 32],
        updates: Vec<Arc<Update>>,
        queue_s: f64,
    },
    Committed {
        seq: u64,
        update: Arc<Update>,
        timing: RoundTiming,
    },
    Ok,
    Rejected {
        reason: String,
        retryable: bool,
    },
}

#[derive(Default)]
pub struct Traffic {
    pub sent: AtomicU64,
    pub received: AtomicU64,
}
pub struct Channel {
    pub stream: TcpStream,
    pub timeout: Duration,
    pub traffic: Arc<Traffic>,
}
impl Channel {
    pub fn new(stream: TcpStream, timeout_ms: u64, traffic: Arc<Traffic>) -> Result<Self> {
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            timeout: Duration::from_millis(timeout_ms),
            traffic,
        })
    }
    pub async fn connect(addr: &str, timeout_ms: u64, traffic: Arc<Traffic>) -> Result<Self> {
        Self::new(
            timeout(Duration::from_millis(timeout_ms), TcpStream::connect(addr)).await??,
            timeout_ms,
            traffic,
        )
    }
    pub async fn send<T: Serialize>(&mut self, value: &T) -> Result<()> {
        let size = bincode::serialized_size(value)? as usize;
        if size > MAX_FRAME {
            return Err(error("outgoing frame exceeds 64 MiB"));
        }
        let bytes = bincode::serialize(value)?;
        timeout(self.timeout, async {
            self.stream.write_u32(bytes.len() as u32).await?;
            self.stream.write_all(&bytes).await
        })
        .await??;
        self.traffic
            .sent
            .fetch_add((size + 4) as u64, Ordering::Relaxed);
        Ok(())
    }
    pub async fn recv<T: for<'de> Deserialize<'de>>(&mut self) -> Result<T> {
        let bytes = timeout(self.timeout, async {
            let size = self.stream.read_u32().await? as usize;
            if size > MAX_FRAME {
                return Err(std::io::Error::other("incoming frame exceeds 64 MiB"));
            }
            let mut bytes = vec![0; size];
            self.stream.read_exact(&mut bytes).await?;
            Ok(bytes)
        })
        .await??;
        self.traffic
            .received
            .fetch_add((bytes.len() + 4) as u64, Ordering::Relaxed);
        Ok(bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(bytes.len() as u64)
            .reject_trailing_bytes()
            .deserialize(&bytes)?)
    }
    pub async fn reject(&mut self, reason: impl Into<String>, retryable: bool) -> Result<()> {
        self.send(&Response::Rejected {
            reason: reason.into(),
            retryable,
        })
        .await
    }
}
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Phase {
    Deployment,
    Warmup,
    Measurement,
    Drain,
}
