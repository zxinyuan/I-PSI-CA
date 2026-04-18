//! I-PSI-CA demo: Target (TCP server) and Monitor (TCP client)
//!
//! TSet and MElmt are uniformly random elements of 𝔽_ℓ,
//! the scalar field of Ristretto255.
//!
//! Usage:
//!   cargo run --release -- exact 1000 true    # exact with custom degree, match
//!   cargo run --release -- exact 1000 false   # exact with custom degree, no match
//!   cargo run --release -- bf 1000 3 158 true # bf with size, k, marked positions, match
//!   cargo run --release -- bf 1000 3 158 false
//!   cargo run --release -- fuzzy 1000 128 3 false  # fuzzy with set size, vector size, threshold

use std::thread;
use std::time::Duration;

use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;

use i_psi_ca::bf::bloom::{
    find_non_member_scalar, recommended_hash_count, sample_marked_positions, sample_query_scalar,
    BloomFilterConfig,
};
use i_psi_ca::crypto::elgamal::generate_key_share;

const ADDR: &str = "127.0.0.1:7878";
const DEGREE: usize = 1_000;
const BLOOM_FILTER_SIZE: usize = 1_000;
const BF_HONEYWORD_PROBABILITY: f64 = 0.004;
const ACCUM_DEGREE: usize = 5;
const FUZZY_VECTOR_SIZE: usize = 128;
const FUZZY_THRESHOLD: usize = 3;

#[derive(Clone, Copy, Debug)]
enum ProtocolVersion {
    Exact,
    Bf,
    Fuzzy,
}

impl ProtocolVersion {
    fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.unwrap_or("exact") {
            "exact" => Ok(Self::Exact),
            "bf" => Ok(Self::Bf),
            "fuzzy" => Ok(Self::Fuzzy),
            other => Err(format!(
                "unknown protocol '{other}', expected one of: exact, bf, fuzzy"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RunConfig {
    protocol: ProtocolVersion,
    size: usize,
    bf_hash_count: usize,
    bf_marked_count: usize,
    fuzzy_vector_size: usize,
    fuzzy_threshold: usize,
    in_set: bool,
}

impl RunConfig {
    fn parse(args: &[String]) -> Result<Self, String> {
        let protocol = ProtocolVersion::parse(args.get(1).map(String::as_str))?;

        match protocol {
            ProtocolVersion::Exact => {
                let degree = match args.get(2) {
                    Some(raw) => raw.parse::<usize>().map_err(|_| {
                        "for exact, second arg must be a positive integer degree".to_string()
                    })?,
                    None => DEGREE,
                };
                if degree == 0 {
                    return Err("degree must be greater than zero".to_string());
                }

                let in_set = match args.get(3) {
                    Some(flag) => flag
                        .parse::<bool>()
                        .map_err(|_| "for exact, third arg must be true/false".to_string())?,
                    None => true,
                };

                Ok(Self {
                    protocol,
                    size: degree,
                    bf_hash_count: recommended_hash_count(BF_HONEYWORD_PROBABILITY),
                    bf_marked_count: default_bf_marked_count(
                        degree,
                        recommended_hash_count(BF_HONEYWORD_PROBABILITY),
                    ),
                    fuzzy_vector_size: FUZZY_VECTOR_SIZE,
                    fuzzy_threshold: FUZZY_THRESHOLD,
                    in_set,
                })
            }
            ProtocolVersion::Bf => {
                let bloom_filter_size = match args.get(2) {
                    Some(raw) => raw.parse::<usize>().map_err(|_| {
                        "for bf, second arg must be a positive integer bloom filter size"
                            .to_string()
                    })?,
                    None => BLOOM_FILTER_SIZE,
                };
                if bloom_filter_size == 0 {
                    return Err("bloom filter size must be greater than zero".to_string());
                }

                let default_k = recommended_hash_count(BF_HONEYWORD_PROBABILITY);
                let default_marked_count = default_bf_marked_count(bloom_filter_size, default_k);
                let (bf_hash_count, bf_marked_count, in_set) = match (
                    args.get(3),
                    args.get(4),
                    args.get(5),
                ) {
                    (None, None, None) => (default_k, default_marked_count, true),
                    (Some(third), None, None) => match third.parse::<bool>() {
                        Ok(in_set) => (default_k, default_marked_count, in_set),
                        Err(_) => {
                            let bf_hash_count = third.parse::<usize>().map_err(|_| {
                                    "for bf, third arg must be true/false or a positive integer hash count k"
                                        .to_string()
                                })?;
                            if bf_hash_count == 0 {
                                return Err("hash count k must be greater than zero".to_string());
                            }
                            (
                                bf_hash_count,
                                default_bf_marked_count(bloom_filter_size, bf_hash_count),
                                true,
                            )
                        }
                    },
                    (Some(third), Some(fourth), None) => {
                        let bf_hash_count = third.parse::<usize>().map_err(|_| {
                                "for bf, third arg must be a positive integer hash count k when a fourth arg is provided"
                                    .to_string()
                            })?;
                        if bf_hash_count == 0 {
                            return Err("hash count k must be greater than zero".to_string());
                        }

                        match fourth.parse::<bool>() {
                            Ok(in_set) => (
                                bf_hash_count,
                                default_bf_marked_count(bloom_filter_size, bf_hash_count),
                                in_set,
                            ),
                            Err(_) => {
                                let bf_marked_count =
                                        fourth.parse::<usize>().map_err(|_| {
                                            "for bf, fourth arg must be true/false or a positive integer marked-position count"
                                                .to_string()
                                        })?;
                                (bf_hash_count, bf_marked_count, true)
                            }
                        }
                    }
                    (Some(third), Some(fourth), Some(fifth)) => {
                        let bf_hash_count = third.parse::<usize>().map_err(|_| {
                                "for bf, third arg must be a positive integer hash count k when a fifth arg is provided"
                                    .to_string()
                            })?;
                        if bf_hash_count == 0 {
                            return Err("hash count k must be greater than zero".to_string());
                        }
                        let bf_marked_count = fourth.parse::<usize>().map_err(|_| {
                                "for bf, fourth arg must be a positive integer marked-position count when a fifth arg is provided"
                                    .to_string()
                            })?;
                        let in_set = fifth
                            .parse::<bool>()
                            .map_err(|_| "for bf, fifth arg must be true/false".to_string())?;
                        (bf_hash_count, bf_marked_count, in_set)
                    }
                    _ => unreachable!("bf arguments are positional"),
                };

                if bf_marked_count > bloom_filter_size {
                    return Err(
                        "target marked-position count must be at most the bloom filter size"
                            .to_string(),
                    );
                };

                Ok(Self {
                    protocol,
                    size: bloom_filter_size,
                    bf_hash_count,
                    bf_marked_count,
                    fuzzy_vector_size: FUZZY_VECTOR_SIZE,
                    fuzzy_threshold: FUZZY_THRESHOLD,
                    in_set,
                })
            }
            ProtocolVersion::Fuzzy => {
                let (set_size, fuzzy_vector_size, fuzzy_threshold, in_set) = match (
                    args.get(2),
                    args.get(3),
                    args.get(4),
                    args.get(5),
                ) {
                    (None, None, None, None) => (DEGREE, FUZZY_VECTOR_SIZE, FUZZY_THRESHOLD, true),
                    (Some(second), None, None, None) => match second.parse::<bool>() {
                        Ok(in_set) => (DEGREE, FUZZY_VECTOR_SIZE, FUZZY_THRESHOLD, in_set),
                        Err(_) => {
                            let set_size = second.parse::<usize>().map_err(|_| {
                                "for fuzzy, second arg must be true/false or a positive integer set size"
                                    .to_string()
                            })?;
                            (set_size, FUZZY_VECTOR_SIZE, FUZZY_THRESHOLD, true)
                        }
                    },
                    (Some(second), Some(third), None, None) => {
                        let set_size = second.parse::<usize>().map_err(|_| {
                            "for fuzzy, second arg must be a positive integer set size when a third arg is provided"
                                .to_string()
                        })?;
                        match third.parse::<bool>() {
                            Ok(in_set) => (set_size, FUZZY_VECTOR_SIZE, FUZZY_THRESHOLD, in_set),
                            Err(_) => {
                                let vector_size = third.parse::<usize>().map_err(|_| {
                                    "for fuzzy, third arg must be true/false or a positive integer vector size"
                                        .to_string()
                                })?;
                                (set_size, vector_size, FUZZY_THRESHOLD, true)
                            }
                        }
                    }
                    (Some(second), Some(third), Some(fourth), None) => {
                        let set_size = second.parse::<usize>().map_err(|_| {
                            "for fuzzy, second arg must be a positive integer set size when a fourth arg is provided"
                                .to_string()
                        })?;
                        match fourth.parse::<bool>() {
                            Ok(in_set) => {
                                let vector_size = third.parse::<usize>().map_err(|_| {
                                    "for fuzzy, third arg must be a positive integer vector size when a fourth arg is provided"
                                        .to_string()
                                })?;
                                (set_size, vector_size, FUZZY_THRESHOLD, in_set)
                            }
                            Err(_) => {
                                let vector_size = third.parse::<usize>().map_err(|_| {
                                    "for fuzzy, third arg must be a positive integer vector size when a fourth arg is provided"
                                        .to_string()
                                })?;
                                let threshold = fourth.parse::<usize>().map_err(|_| {
                                    "for fuzzy, fourth arg must be true/false or a non-negative integer threshold"
                                        .to_string()
                                })?;
                                (set_size, vector_size, threshold, true)
                            }
                        }
                    }
                    (Some(second), Some(third), Some(fourth), Some(fifth)) => {
                        let set_size = second.parse::<usize>().map_err(|_| {
                            "for fuzzy, second arg must be a positive integer set size when a fifth arg is provided"
                                .to_string()
                        })?;
                        let vector_size = third.parse::<usize>().map_err(|_| {
                            "for fuzzy, third arg must be a positive integer vector size when a fifth arg is provided"
                                .to_string()
                        })?;
                        let threshold = fourth.parse::<usize>().map_err(|_| {
                            "for fuzzy, fourth arg must be a non-negative integer threshold when a fifth arg is provided"
                                .to_string()
                        })?;
                        let in_set = fifth
                            .parse::<bool>()
                            .map_err(|_| "for fuzzy, fifth arg must be true/false".to_string())?;
                        (set_size, vector_size, threshold, in_set)
                    }
                    _ => unreachable!("fuzzy arguments are positional"),
                };
                if set_size == 0 {
                    return Err("fuzzy set size must be greater than zero".to_string());
                }
                if fuzzy_vector_size == 0 {
                    return Err("fuzzy vector size must be greater than zero".to_string());
                }

                Ok(Self {
                    protocol,
                    size: set_size,
                    bf_hash_count: recommended_hash_count(BF_HONEYWORD_PROBABILITY),
                    bf_marked_count: default_bf_marked_count(
                        DEGREE,
                        recommended_hash_count(BF_HONEYWORD_PROBABILITY),
                    ),
                    fuzzy_vector_size,
                    fuzzy_threshold,
                    in_set,
                })
            }
        }
    }
}

fn default_bf_marked_count(bloom_filter_size: usize, hash_count: usize) -> usize {
    let density = BF_HONEYWORD_PROBABILITY.powf(1.0 / hash_count as f64);
    (density * bloom_filter_size as f64)
        .round()
        .clamp(0.0, bloom_filter_size as f64) as usize
}

fn sample_fuzzy_scalar(rng: &mut OsRng, vector_size: usize) -> Scalar {
    let kept_bits = vector_size.min(256);
    loop {
        let mut bytes = [0u8; 32];
        use rand::RngCore;
        rng.fill_bytes(&mut bytes);

        let full_bytes = kept_bits / 8;
        let extra_bits = kept_bits % 8;

        if full_bytes < 32 {
            for byte in &mut bytes[(full_bytes + usize::from(extra_bits > 0))..] {
                *byte = 0;
            }
        }
        if extra_bits > 0 && full_bytes < 32 {
            let mask = (1u8 << extra_bits) - 1;
            bytes[full_bytes] &= mask;
        }

        if let Some(scalar) = Scalar::from_canonical_bytes(bytes) {
            return scalar;
        }
    }
}

fn main() {
    // Parse optional CLI args
    let args: Vec<String> = std::env::args().collect();
    let config = RunConfig::parse(&args).expect(
        "usage: exact [degree] [true|false], bf [bloom_filter_size] [k] [marked_positions] [true|false], or fuzzy [set_size] [vector_size] [threshold] [true|false]",
    );

    let mut rng = OsRng;

    // Key generation (shared setup for simplicity)
    let (sk1, pk1) = generate_key_share(&mut rng);
    let (sk2, pk2) = generate_key_share(&mut rng);
    let pk2_for_target = pk2.clone();
    let pk1_for_monitor = pk1.clone();

    match config.protocol {
        ProtocolVersion::Exact => {
            // Sample TSet: `size` independent uniform random field elements.
            let t_set: Vec<Scalar> = (0..config.size).map(|_| Scalar::random(&mut rng)).collect();
            let m_elmt = if config.in_set {
                t_set[0]
            } else {
                Scalar::random(&mut rng)
            };

            println!("Protocol    = {:?}", config.protocol);
            println!(
                "TSet        = [{} uniform random 𝔽_ℓ elements]",
                config.size
            );
            println!(
                "MElmt       = uniform random 𝔽_ℓ element  (in_set={})",
                config.in_set
            );
            println!(
                "Expected    = {}",
                if config.in_set { "MATCH" } else { "NO MATCH" }
            );
            println!();

            run_exact(
                t_set,
                m_elmt,
                sk1,
                pk1,
                pk2_for_target,
                sk2,
                pk1_for_monitor,
                pk2,
                config.size,
            );
        }
        ProtocolVersion::Bf => {
            let bf_config = BloomFilterConfig {
                bloom_filter_size: config.size,
                hash_count: config.bf_hash_count,
                target_marked_count: config.bf_marked_count,
            }
            .validate()
            .expect("BF config should be valid after CLI parsing");

            let real_input = sample_query_scalar(&mut rng, bf_config);
            let real_input_positions = i_psi_ca::bf::bloom::scalar_positions(real_input, bf_config);
            let marked_positions =
                sample_marked_positions(&mut rng, bf_config, &real_input_positions);
            let query_input = if config.in_set {
                real_input
            } else {
                find_non_member_scalar(&marked_positions, bf_config).expect(
                    "could not find a non-member password; choose p_h < 1.0 for negative BF queries",
                )
            };

            println!("Protocol    = {:?}", config.protocol);
            println!("Bloom size  = [{} positions]", config.size);
            println!("k hashes    = {}", config.bf_hash_count);
            println!(
                "Target bits = [{} marked positions]",
                config.bf_marked_count
            );
            println!(
                "Marked bits = [{} positions set to 1]",
                marked_positions.len()
            );
            println!(
                "Input y     = {:?}  (in_set={})",
                query_input, config.in_set
            );
            println!(
                "Expected    = {}",
                if config.in_set { "MATCH" } else { "NO MATCH" }
            );
            println!();

            run_bf(
                marked_positions,
                query_input,
                bf_config,
                sk1,
                pk1,
                pk2_for_target,
                sk2,
                pk1_for_monitor,
                pk2,
            );
        }
        ProtocolVersion::Fuzzy => {
            let t_set: Vec<Scalar> = (0..config.size)
                .map(|_| sample_fuzzy_scalar(&mut rng, config.fuzzy_vector_size))
                .collect();
            let m_elmt = if config.in_set {
                t_set[0]
            } else {
                sample_fuzzy_scalar(&mut rng, config.fuzzy_vector_size)
            };

            println!("Protocol    = {:?}", config.protocol);
            println!("Set size    = {}", config.size);
            println!("Vector size = {}", config.fuzzy_vector_size);
            println!("Threshold   = {}", config.fuzzy_threshold);
            println!(
                "MElmt       = uniform random 𝔽_ℓ element  (in_set={})",
                config.in_set
            );
            println!();

            run_fuzzy(
                t_set,
                m_elmt,
                sk1,
                pk1,
                pk2_for_target,
                sk2,
                pk1_for_monitor,
                pk2,
                config.fuzzy_vector_size,
                config.fuzzy_threshold,
            );
        }
    }
}

fn run_exact(
    t_set: Vec<Scalar>,
    m_elmt: Scalar,
    sk1: i_psi_ca::crypto::elgamal::SecretKeyShare,
    pk1: i_psi_ca::crypto::elgamal::PublicKeyShare,
    pk2_for_target: i_psi_ca::crypto::elgamal::PublicKeyShare,
    sk2: i_psi_ca::crypto::elgamal::SecretKeyShare,
    pk1_for_monitor: i_psi_ca::crypto::elgamal::PublicKeyShare,
    pk2: i_psi_ca::crypto::elgamal::PublicKeyShare,
    set_size: usize,
) {
    let target_handle = thread::spawn(move || {
        let mut target =
            i_psi_ca::exact::target::Target::new(t_set, ACCUM_DEGREE, sk1, pk1, pk2_for_target);
        target.run(ADDR).expect("[Target] server error");
        println!("[Target] Final match count: {}", target.state);
    });

    thread::sleep(Duration::from_millis(50));

    let monitor =
        i_psi_ca::exact::monitor::Monitor::new(m_elmt, sk2, pk1_for_monitor, pk2, set_size);
    monitor.run(ADDR, 1).expect("[Monitor] client error");

    target_handle.join().expect("Target thread panicked");
}

fn run_bf(
    marked_positions: Vec<Scalar>,
    input_y: Scalar,
    bf_config: BloomFilterConfig,
    sk1: i_psi_ca::crypto::elgamal::SecretKeyShare,
    pk1: i_psi_ca::crypto::elgamal::PublicKeyShare,
    pk2_for_target: i_psi_ca::crypto::elgamal::PublicKeyShare,
    sk2: i_psi_ca::crypto::elgamal::SecretKeyShare,
    pk1_for_monitor: i_psi_ca::crypto::elgamal::PublicKeyShare,
    pk2: i_psi_ca::crypto::elgamal::PublicKeyShare,
) {
    let outsourced_degree = marked_positions.len();
    let target_handle = thread::spawn(move || {
        let mut target = i_psi_ca::bf::target::Target::new(
            marked_positions,
            bf_config,
            ACCUM_DEGREE,
            sk1,
            pk1,
            pk2_for_target,
        );
        target.run(ADDR).expect("[Target] server error");
        println!("[Target] Final match count: {}", target.state);
    });

    thread::sleep(Duration::from_millis(50));

    let monitor = i_psi_ca::bf::monitor::Monitor::new(
        input_y,
        bf_config,
        sk2,
        pk1_for_monitor,
        pk2,
        outsourced_degree,
    );
    monitor.run(ADDR).expect("[Monitor] client error");

    target_handle.join().expect("Target thread panicked");
}

fn run_fuzzy(
    t_set: Vec<Scalar>,
    m_elmt: Scalar,
    sk1: i_psi_ca::crypto::elgamal::SecretKeyShare,
    pk1: i_psi_ca::crypto::elgamal::PublicKeyShare,
    pk2_for_target: i_psi_ca::crypto::elgamal::PublicKeyShare,
    sk2: i_psi_ca::crypto::elgamal::SecretKeyShare,
    pk1_for_monitor: i_psi_ca::crypto::elgamal::PublicKeyShare,
    pk2: i_psi_ca::crypto::elgamal::PublicKeyShare,
    vector_size: usize,
    threshold: usize,
) {
    let target_handle = thread::spawn(move || {
        let mut target = i_psi_ca::fuzzy::target::Target::new(
            t_set,
            ACCUM_DEGREE,
            sk1,
            pk1,
            pk2_for_target,
            vector_size,
            threshold,
        );
        target.run(ADDR).expect("[Target] server error");
    });

    thread::sleep(Duration::from_millis(50));

    let monitor = i_psi_ca::fuzzy::monitor::Monitor::new(
        m_elmt,
        sk2,
        pk1_for_monitor,
        pk2,
        vector_size,
        threshold,
    );
    monitor.run(ADDR, 1).expect("[Monitor] client error");

    target_handle.join().expect("Target thread panicked");
}
