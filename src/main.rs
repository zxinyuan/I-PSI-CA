use std::thread;
use std::time::Duration;

use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;

use i_psi_ca::bf::bloom::{
    find_non_member_scalar, sample_marked_positions, sample_query_scalar, BloomFilterConfig,
};
use i_psi_ca::crypto::elgamal::generate_key_share;

const ADDR: &str = "127.0.0.1:7878";
const DEGREE: usize = 1_000;
const BLOOM_FILTER_SIZE: usize = 1_000;
const BF_DEFAULT_HASH_COUNT: usize = 20;
const ACCUM_DEGREE: usize = 5;

#[derive(Clone, Copy, Debug)]
enum ProtocolVersion {
    Exact,
    Bf,
}

impl ProtocolVersion {
    fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw.unwrap_or("exact") {
            "exact" => Ok(Self::Exact),
            "bf" => Ok(Self::Bf),
            other => Err(format!(
                "unknown protocol '{other}', expected one of: exact, bf"
            )),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RunConfig {
    protocol: ProtocolVersion,
    size: usize,
    in_set: bool,
    bf_accum_degree: Option<usize>,
}

impl RunConfig {
    fn parse(args: &[String]) -> Result<Self, String> {
        let protocol = ProtocolVersion::parse(args.get(1).map(String::as_str))?;

        match protocol {
            ProtocolVersion::Exact => {
                let mut positional = Vec::with_capacity(2);
                let mut flags = Vec::new();
                let mut saw_flag = false;
                let mut remaining = args.iter().skip(2);
                while let Some(arg) = remaining.next() {
                    if arg.starts_with("--") {
                        saw_flag = true;
                        if arg != "--pok" && arg != "--round1" {
                            return Err(format!("unknown exact option '{arg}'"));
                        }
                        flags.push(arg.clone());
                        flags.push(
                            remaining
                                .next()
                                .ok_or_else(|| format!("{arg} requires true or false"))?
                                .clone(),
                        );
                    } else {
                        if saw_flag || positional.len() == 2 {
                            return Err("exact accepts only [degree] [in_set] before --pok/--round1; there is no accumulator-size argument".into());
                        }
                        positional.push(arg.as_str());
                    }
                }
                i_psi_ca::exact::ProtocolConfig::from_args(&flags)?;
                let degree = match positional.first() {
                    Some(raw) => raw
                        .parse::<usize>()
                        .map_err(|_| "for exact, degree must be a positive integer".to_string())?,
                    None => DEGREE,
                };
                if degree == 0 {
                    return Err("degree must be greater than zero".into());
                }
                let in_set = match positional.get(1) {
                    Some(raw) => raw
                        .parse::<bool>()
                        .map_err(|_| "for exact, in_set must be true/false".to_string())?,
                    None => true,
                };

                Ok(Self {
                    protocol,
                    size: degree,
                    in_set,
                    bf_accum_degree: None,
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

                let in_set = match args.get(3) {
                    Some(flag) => flag
                        .parse::<bool>()
                        .map_err(|_| "for bf, third arg must be true/false".to_string())?,
                    None => true,
                };

                let accum_degree = match args.get(4) {
                    Some(raw) => raw.parse::<usize>().map_err(|_| {
                        "for bf, fourth arg must be a positive integer accum degree".to_string()
                    })?,
                    None => ACCUM_DEGREE,
                };
                if accum_degree == 0 {
                    return Err("accum degree must be greater than zero".to_string());
                }

                Ok(Self {
                    protocol,
                    size: bloom_filter_size,
                    in_set,
                    bf_accum_degree: Some(accum_degree),
                })
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config = RunConfig::parse(&args).expect(
        "usage: exact [degree] [true|false] [--pok true|false] [--round1 true|false] or bf [bloom_filter_size] [true|false] [accum_degree]",
    );

    let mut rng = OsRng;

    let (sk1, pk1) = generate_key_share(&mut rng);
    let (sk2, pk2) = generate_key_share(&mut rng);
    let pk2_for_target = pk2.clone();
    let pk1_for_monitor = pk1.clone();

    match config.protocol {
        ProtocolVersion::Exact => {
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
            let bf_hash_count = BF_DEFAULT_HASH_COUNT;
            let bf_marked_count = config.size / 2;
            let bf_config = BloomFilterConfig {
                bloom_filter_size: config.size,
                hash_count: bf_hash_count,
                target_marked_count: bf_marked_count,
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
            println!("k hashes    = {}", bf_hash_count);
            println!("Target bits = [{} marked positions]", bf_marked_count);
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
                query_input,
                bf_config,
                sk1,
                pk1,
                pk2_for_target,
                sk2,
                pk1_for_monitor,
                pk2,
                config.bf_accum_degree.unwrap_or(ACCUM_DEGREE),
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
        let mut target = i_psi_ca::exact::target::Target::new(t_set, sk1, pk1, pk2_for_target);
        target.run(ADDR, 1).expect("[Target] server error");
        println!("[Target] Final match count: {}", target.state);
    });

    thread::sleep(Duration::from_millis(50));

    let monitor =
        i_psi_ca::exact::monitor::Monitor::new(m_elmt, sk2, pk1_for_monitor, pk2, set_size);
    monitor.run(ADDR, 1).expect("[Monitor] client error");

    target_handle.join().expect("Target thread panicked");
}

fn run_bf(
    input_y: Scalar,
    bf_config: BloomFilterConfig,
    sk1: i_psi_ca::crypto::elgamal::SecretKeyShare,
    pk1: i_psi_ca::crypto::elgamal::PublicKeyShare,
    pk2_for_target: i_psi_ca::crypto::elgamal::PublicKeyShare,
    sk2: i_psi_ca::crypto::elgamal::SecretKeyShare,
    pk1_for_monitor: i_psi_ca::crypto::elgamal::PublicKeyShare,
    pk2: i_psi_ca::crypto::elgamal::PublicKeyShare,
    accum_degree: usize,
) {
    let outsourced_degree = bf_config.bloom_filter_size;
    let target_handle = thread::spawn(move || {
        let mut target =
            i_psi_ca::bf::target::Target::new(bf_config, accum_degree, sk1, pk1, pk2_for_target);
        target.run(ADDR, 1).expect("[Target] server error");
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
    monitor.run(ADDR, 1).expect("[Monitor] client error");

    target_handle.join().expect("Target thread panicked");
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(args: &[&str]) -> Result<RunConfig, String> {
        RunConfig::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }
    #[test]
    fn exact_flags_follow_only_degree_and_query_selection() {
        for args in [
            vec![
                "app", "exact", "32", "false", "--pok", "true", "--round1", "false",
            ],
            vec![
                "app", "exact", "32", "false", "--round1", "true", "--pok", "false",
            ],
        ] {
            let config = parse(&args).unwrap();
            assert!(matches!(config.protocol, ProtocolVersion::Exact));
            assert_eq!(config.size, 32);
            assert!(!config.in_set);
            assert_eq!(config.bf_accum_degree, None);
        }
        assert_eq!(parse(&["app","exact","32","true","5"]).unwrap_err(),"exact accepts only [degree] [in_set] before --pok/--round1; there is no accumulator-size argument");
    }
    #[test]
    fn exact_positionals_can_be_omitted_before_flags() {
        let config = parse(&["app", "exact", "--pok", "true", "--round1", "false"]).unwrap();
        assert_eq!(config.size, DEGREE);
        assert!(config.in_set);
        let config = parse(&["app", "exact", "12", "--round1", "true"]).unwrap();
        assert_eq!(config.size, 12);
        assert!(config.in_set);
        assert!(parse(&["app"]).is_ok());
    }
    #[test]
    fn exact_rejects_invalid_removed_and_misspelled_arguments() {
        for args in [
            vec!["app", "exact", "0"],
            vec!["app", "exact", "12", "yes"],
            vec!["app", "exact", "12", "true", "5", "--pok", "true"],
            vec!["app", "exact", "--pok"],
            vec!["app", "exact", "--round1", "yes"],
            vec!["app", "exact", "--pok", "true", "--pok", "false"],
            vec!["app", "exact", "--round1", "true", "--round1", "false"],
            vec!["app", "exact", "--accum-degree", "5"],
            vec!["app", "exact", "--pok", "true", "12"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }
    #[test]
    fn bf_retains_its_accumulator_argument() {
        let custom = parse(&["app", "bf", "1000", "false", "8"]).unwrap();
        assert!(matches!(custom.protocol, ProtocolVersion::Bf));
        assert_eq!(custom.bf_accum_degree, Some(8));
        assert!(!custom.in_set);
        assert_eq!(
            parse(&["app", "bf"]).unwrap().bf_accum_degree,
            Some(ACCUM_DEGREE)
        );
        assert!(parse(&["app", "bf", "1000", "true", "0"]).is_err());
    }
}
