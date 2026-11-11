//! Opt-in release timings; kept out of ordinary correctness test runs.
use super::{
    division,
    measurements::{mb, significant},
    proofs::{self, ProofContext},
    target::{poly_from_roots, WireEncryptedPoly},
    TPolyProof,
};
use crate::crypto::elgamal::{self, EncryptedPoly, PublicKey};
use curve25519_dalek_ng::scalar::Scalar;
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
    if let Ok(degree) = std::env::var("EXACT_BENCH_DEGREE") {
        degrees = vec![degree
            .parse()
            .expect("EXACT_BENCH_DEGREE must be an integer")];
    }
    for degree in degrees {
        super::performance::reset_for_benchmark();
        let (_, pk1) = elgamal::generate_key_share(&mut rng);
        let (sk2, pk2) = elgamal::generate_key_share(&mut rng);
        let pk = PublicKey(pk1.0 + pk2.0);
        let roots: Vec<_> = (0..degree).map(|i| Scalar::from(i as u64 + 1)).collect();
        let coeffs = poly_from_roots(&roots);
        let randomness: Vec<_> = coeffs.iter().map(|_| Scalar::random(&mut rng)).collect();
        let pk_table = super::performance::table(&pk.0);
        let ct = EncryptedPoly(
            coeffs
                .iter()
                .zip(&randomness)
                .map(|(m, r)| super::encryption::encrypt_with_randomness(&pk_table, *m, *r))
                .collect(),
        );
        let ctx = ProofContext {
            session: [12; 32],
            round: 1,
        };
        let start = Instant::now();
        let initial =
            proofs::generate_initial_pok(&mut rng, &pk, &coeffs, &randomness, &ct, &ctx).unwrap();
        let first_s = start.elapsed().as_secs_f64();
        let initial_setup = super::performance::generator_activity();
        let start = Instant::now();
        proofs::verify_initial_pok(&pk, &ct, &initial, &ctx).unwrap();
        let verify_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        let _ =
            proofs::generate_initial_pok(&mut rng, &pk, &coeffs, &randomness, &ct, &ctx).unwrap();
        let repeat_s = start.elapsed().as_secs_f64();
        super::performance::reset_for_benchmark();
        let start = Instant::now();
        let reply = division::prove(&mut rng, &pk, &pk1, &pk2, &sk2, &ct, roots[0], &ctx).unwrap();
        let monitor_s = start.elapsed().as_secs_f64();
        let monitor_setup = super::performance::generator_activity();
        let start = Instant::now();
        let (next, _) = division::verify(&pk, &pk1, &pk2, &ct, &reply, &ctx).unwrap();
        let monitor_verify_s = start.elapsed().as_secs_f64();
        let (updated, rho) = super::encryption::rerandomize_poly_with_witness(&mut rng, &pk, &next);
        let ctx2 = ProofContext { round: 2, ..ctx };
        let start = Instant::now();
        let or =
            proofs::prove_rerandomization_or(&mut rng, &pk, &ct, &next, &updated, 1, &rho, &ctx2)
                .unwrap();
        let or_s = start.elapsed().as_secs_f64();
        let start = Instant::now();
        proofs::verify_rerandomization_or(&pk, &ct, &next, &updated, &or, &ctx2).unwrap();
        let or_verify_s = start.elapsed().as_secs_f64();
        eprintln!("SETUP degree={degree} initial_builds={} initial_setup_s={} monitor_builds={} monitor_setup_s={} (first calls cold; repeats/verifiers warm)", initial_setup.builds, significant(initial_setup.setup_ns as f64 / 1_000_000_000.0), monitor_setup.builds, significant(monitor_setup.setup_ns as f64 / 1_000_000_000.0));
        eprintln!("BENCH degree={degree} initial_first_s={} initial_repeat_s={} initial_verify_s={} monitor_prove_s={} monitor_verify_s={} or_prove_s={} or_verify_s={} initial_mb={} or_mb={} ciphertext_mb={}", significant(first_s), significant(repeat_s), significant(verify_s), significant(monitor_s), significant(monitor_verify_s), significant(or_s), significant(or_verify_s), significant(mb(bincode::serialized_size(&TPolyProof::Initial(initial)).unwrap())), significant(mb(bincode::serialized_size(&TPolyProof::RerandomizationOr(or)).unwrap())), significant(mb(bincode::serialized_size(&WireEncryptedPoly::from_native(&ct)).unwrap())));
    }
}
