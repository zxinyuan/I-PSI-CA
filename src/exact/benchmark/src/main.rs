use exact_bench::{
    client::{self, ClientOptions},
    config::{self, Args, Config},
    error,
    server::{PublicKeys, Server},
    Result,
};
use rand::RngCore;
use std::{path::PathBuf, sync::Arc};
use zeroize::Zeroizing;

fn main() {
    if let Err(e) = run() {
        eprintln!("exact-bench: {e}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let mut raw = std::env::args().skip(1);
    let command = raw.next().unwrap_or_else(|| "help".into());
    if command == "help" || command == "--help" {
        println!("exact-bench target-server --bind ADDR --set-size S --num-sets N --monitors-per-set M --public-keys FILE [--client-nodes K --worker-threads W --output FILE ...]\nexact-bench monitor-load --target ADDR --agent-id ID --key-file FILE --output FILE [--client-workers W]\nexact-bench keygen --num-sets N --key-file SECRET --public-keys PUBLIC\nexact-bench probe --target ADDR\nSee src/exact/benchmark/README.md for all settings and Slurm commands.");
        return Ok(());
    }
    let mut args = Args::parse(raw)?;
    match command.as_str() {
        "keygen" => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let sets: usize = args.number("--num-sets", 10)?;
            let secret_path = args.required("--key-file")?;
            let public_path = args.required("--public-keys")?;
            args.finish()?;
            if sets == 0 || sets > config::MAX_SETS {
                return Err(error("N must be 1..1000"));
            }
            let mut secret = Zeroizing::new([0; 32]);
            rand::rngs::OsRng.fill_bytes(&mut *secret);
            let public = PublicKeys {
                monitor_public_keys: (0..sets)
                    .map(|set| {
                        i_psi_ca::exact::session::monitor_key(&secret, set)
                            .1
                             .0
                            .compress()
                            .to_bytes()
                    })
                    .collect(),
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(secret_path)?;
            file.write_all(&*secret)?;
            let mut public_file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(public_path)?;
            serde_json::to_writer_pretty(&mut public_file, &public)?;
            Ok(())
        }
        "probe" => {
            let target = args.required("--target")?;
            args.finish()?;
            let rt = runtime(1)?;
            let m = rt.block_on(client::probe(&target))?;
            println!("{}", serde_json::to_string_pretty(&m)?);
            Ok(())
        }
        "monitor-load" => {
            let options = ClientOptions {
                target: args.required("--target")?,
                agent: args.number("--agent-id", 0)?,
                key_file: PathBuf::from(args.required("--key-file")?),
                output: PathBuf::from(args.get("--output", "agent.json")),
                workers: args.number("--client-workers", 8)?,
            };
            args.finish()?;
            runtime(options.workers)?.block_on(client::run(options))
        }
        "target-server" => {
            let pok = args.number("--pok", true)?;
            let round1 = args.number("--round1", false)?;
            if !pok || round1 {
                return Err(error(
                    "distributed reporting requires --pok true --round1 false",
                ));
            }
            let defaults = Config::default();
            let bind = args.get("--bind", "0.0.0.0:50051");
            let public = PathBuf::from(args.required("--public-keys")?);
            let output = PathBuf::from(args.get("--output", "target.json"));
            let clients = args.number("--client-nodes", defaults.client_nodes)?;
            if clients == 0 || clients > config::MAX_MONITORS {
                return Err(error("client nodes must be 1..10000"));
            }
            let num_sets = args.number("--num-sets", defaults.num_sets)?;
            let history_default =
                (config::MAX_HISTORY_BYTES / num_sets.max(1)).min(config::MAX_FRAME / 2);
            let hosts = args
                .get(
                    "--client-hosts",
                    &vec![config::hostname(); clients].join(","),
                )
                .split(',')
                .map(str::to_string)
                .collect();
            let config = Config {
                set_size: args.number("--set-size", defaults.set_size)?,
                num_sets,
                monitors_per_set: args.number("--monitors-per-set", defaults.monitors_per_set)?,
                client_nodes: clients,
                worker_threads: args.number("--worker-threads", defaults.worker_threads)?,
                max_inflight: args.number("--max-inflight", defaults.max_inflight)?,
                max_queue_per_set: args
                    .number("--max-queue-per-set", defaults.max_queue_per_set)?,
                history_bytes_per_set: args.number("--history-bytes-per-set", history_default)?,
                timeout_ms: args.number("--timeout-ms", defaults.timeout_ms)?,
                warmup_s: args.number("--warmup-seconds", defaults.warmup_s)?,
                duration_s: args.number("--duration-seconds", defaults.duration_s)?,
                rounds_per_monitor: args.number("--rounds-per-monitor", 0)?,
                seed: args.number("--seed", defaults.seed)?,
                run_id: args.get("--run-id", &defaults.run_id),
                mode: args.get("--mode", &defaults.mode),
                workload: args.get("--workload", &defaults.workload),
                offered_rate: args.number("--offered-rate", defaults.offered_rate)?,
                distributed: args.number("--distributed", false)?,
                target_host: args.get("--target-host", &defaults.target_host),
                client_hosts: hosts,
            };
            args.finish()?;
            config.validate()?;
            if std::fs::metadata(&public)?.len() > 2 * 1024 * 1024 {
                return Err(error("public key file exceeds 2 MiB"));
            }
            let keys: PublicKeys = serde_json::from_slice(&std::fs::read(public)?)?;
            runtime(config.worker_threads)?.block_on(async move {
                let listener = tokio::net::TcpListener::bind(bind).await?;
                let server = Server::initialize(config, keys, output).await?;
                Arc::clone(&server).serve(listener).await
            })
        }
        _ => Err(error(format!("unknown role {command}"))),
    }
}
fn runtime(workers: usize) -> Result<tokio::runtime::Runtime> {
    if !(1..=256).contains(&workers) {
        return Err(error("workers must be 1..256"));
    }
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(workers + 1)
        .enable_all()
        .build()?)
}
