//! Opt-in release timings; kept out of ordinary correctness test runs.
use super::{
    division,
    proofs::{self, ProofContext},
    target::{poly_from_roots, WireEncryptedPoly},
    TPolyProof,
};
use crate::crypto::elgamal::{self, Ciphertext, EncryptedPoly, PublicKey};
use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use rand::{rngs::StdRng, SeedableRng};
use std::time::Instant;

#[test]
#[ignore = "run with cargo test --release exact::benchmarks -- --ignored --nocapture"]
fn benchmark_exact() {
    let mut rng = StdRng::seed_from_u64(215);
    let mut degrees = vec![32usize, 128];
    if std::env::var_os("EXACT_BENCH_LARGE").is_some() {
        degrees.push(1000);
    }
    for degree in degrees {
        super::performance::reset_for_benchmark();
        let (_, pk1) = elgamal::generate_key_share(&mut rng);
        let (sk2, pk2) = elgamal::generate_key_share(&mut rng);
        let pk = PublicKey(pk1.0 + pk2.0);
        let roots: Vec<_> = (0..degree).map(|i| Scalar::from(i as u64 + 1)).collect();
        let coeffs = poly_from_roots(&roots);
        let randomness: Vec<_> = coeffs.iter().map(|_| Scalar::random(&mut rng)).collect();
        let ct = EncryptedPoly(
            coeffs
                .iter()
                .zip(&randomness)
                .map(|(m, r)| Ciphertext {
                    c1: r * G,
                    c2: m * G + r * pk.0,
                })
                .collect(),
        );
        let ctx = ProofContext {
            session: [12; 32],
            round: 1,
        };
        let start = Instant::now();
        let initial =
            proofs::generate_initial_pok(&mut rng, &pk, &roots, &randomness, &ct, &ctx).unwrap();
        let first_ms = start.elapsed().as_secs_f64() * 1000.0;
        let initial_setup = super::performance::generator_activity();
        let start = Instant::now();
        proofs::verify_initial_pok(&pk, &ct, &initial, &ctx).unwrap();
        let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        let _ =
            proofs::generate_initial_pok(&mut rng, &pk, &roots, &randomness, &ct, &ctx).unwrap();
        let repeat_ms = start.elapsed().as_secs_f64() * 1000.0;
        super::performance::reset_for_benchmark();
        let start = Instant::now();
        let reply = division::prove(&mut rng, &pk, &pk1, &pk2, &sk2, &ct, roots[0], &ctx).unwrap();
        let monitor_ms = start.elapsed().as_secs_f64() * 1000.0;
        let monitor_setup = super::performance::generator_activity();
        let start = Instant::now();
        let (next, _) = division::verify(&pk, &pk1, &pk2, &ct, &reply, &ctx).unwrap();
        let monitor_verify_ms = start.elapsed().as_secs_f64() * 1000.0;
        let (updated, rho) = elgamal::rerandomize_poly_with_witness(&mut rng, &pk, &next);
        let ctx2 = ProofContext { round: 2, ..ctx };
        let start = Instant::now();
        let or =
            proofs::prove_rerandomization_or(&mut rng, &pk, &ct, &next, &updated, 1, &rho, &ctx2)
                .unwrap();
        let or_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        proofs::verify_rerandomization_or(&pk, &ct, &next, &updated, &or, &ctx2).unwrap();
        let or_verify_ms = start.elapsed().as_secs_f64() * 1000.0;
        eprintln!("SETUP degree={degree} initial_builds={} initial_setup_ms={:.3} monitor_builds={} monitor_setup_ms={:.3} (first calls cold; repeats/verifiers warm)",initial_setup.builds,initial_setup.setup_ns as f64/1_000_000.0,monitor_setup.builds,monitor_setup.setup_ns as f64/1_000_000.0);
        eprintln!("BENCH degree={degree} initial_first_ms={first_ms:.3} initial_repeat_ms={repeat_ms:.3} initial_verify_ms={verify_ms:.3} monitor_prove_ms={monitor_ms:.3} monitor_verify_ms={monitor_verify_ms:.3} or_prove_ms={or_ms:.3} or_verify_ms={or_verify_ms:.3} initial_bytes={} or_bytes={} ciphertext_bytes={}",bincode::serialized_size(&TPolyProof::Initial(initial)).unwrap(),bincode::serialized_size(&TPolyProof::RerandomizationOr(or)).unwrap(),bincode::serialized_size(&WireEncryptedPoly::from_native(&ct)).unwrap());
    }
}
