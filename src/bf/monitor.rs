
use std::io;
use std::net::TcpStream;

use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_TABLE, scalar::Scalar};
use rand::rngs::OsRng;

use crate::bf::bloom::BloomFilterConfig;
use crate::bf::proof as bfproof;
use crate::crypto::elgamal::{
    combine_public_keys, ct_add, ct_scalar_mul, eval_poly, partial_decrypt_with_witness,
    poly_scalar_mul, Ciphertext, PublicKey, PublicKeyShare, SecretKeyShare,
};
use crate::bf::target::{
    recv_msg, send_msg, MonitorToTarget, TargetToMonitor, WireCiphertext, WireEncryptedPoly,
};
use bulletproofs::{BulletproofGens, PedersenGens};

pub struct Monitor {
    input_y: Scalar,
    bf_config: BloomFilterConfig,
    sk2: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
}

struct RoundPrecomputation {
    scaled: Ciphertext,
    m_poly_ct: Ciphertext,
    proof: bfproof::RoundProofPrecomputation,
}

impl Monitor {
    pub fn new(
        input_y: Scalar,
        bf_config: BloomFilterConfig,
        sk2: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        max_degree: usize,
    ) -> Self {
        let pk = combine_public_keys(&pk1, &pk2);
        let cap = crate::bf::bp_capacity(max_degree, bf_config);
        Monitor {
            input_y,
            bf_config,
            sk2,
            pk1,
            pk2,
            pk,
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(cap, 1),
        }
    }

    fn preprocess_round(
        &self,
        rng: &mut OsRng,
        t_poly_ct: &WireEncryptedPoly,
    ) -> Result<RoundPrecomputation, String> {
        let poly = t_poly_ct.to_native()?;

        let mask = non_zero_scalar(rng);
        let aggregate = bfproof::build_aggregate_eval_witness(
            &poly,
            self.input_y,
            self.bf_config,
            mask,
            &self.pk,
        )?;
        let scaled = aggregate.scaled_eval;
        let (m_poly_ct, r_prime) = partial_decrypt_with_witness(rng, &self.sk2, &self.pk1, &scaled);

        let proof = bfproof::preprocess_round_proof(
            rng,
            &self.pc_gens,
            &self.bp_gens,
            &poly,
            self.bf_config.hash_count,
            &aggregate.e_vals,
            &aggregate.term_masks,
            &scaled,
            self.input_y,
            mask,
            &self.pk,
            &self.pk1,
            &self.pk2,
            &m_poly_ct,
            r_prime,
            self.sk2.as_scalar(),
        )
        .map_err(|e| format!("BF round proof preprocess: {e:?}"))?;

        Ok(RoundPrecomputation {
            scaled,
            m_poly_ct,
            proof,
        })
    }

    fn finish_round(
        &self,
        rng: &mut OsRng,
        precomputed: RoundPrecomputation,
        accum_ct: &WireEncryptedPoly,
    ) -> Result<MonitorToTarget, String> {
        let accum = accum_ct.to_native()?;
        let accum_eval = eval_poly(&accum, &self.input_y);

        let accum_mask = non_zero_scalar(rng);
        let accum_scaled = self.mask_eval(accum_eval, accum_mask);
        let (accum_m_poly_ct, accum_r_prime) =
            partial_decrypt_with_witness(rng, &self.sk2, &self.pk1, &accum_scaled);

        let next_accum = poly_scalar_mul(&accum, &self.input_y);
        let required_bp_capacity = (2 * accum.0.len()).next_power_of_two().max(64);
        let expanded_bp_gens = (self.bp_gens.gens_capacity < required_bp_capacity)
            .then(|| BulletproofGens::new(required_bp_capacity, 1));
        let accum_bp_gens = expanded_bp_gens.as_ref().unwrap_or(&self.bp_gens);

        let (proved_scaled_eval, round_proof) = bfproof::finish_round_proof(
            rng,
            &self.pc_gens,
            accum_bp_gens,
            &self.pk,
            &precomputed.scaled,
            &self.pk1,
            &self.pk2,
            &accum_scaled,
            &accum_m_poly_ct,
            &accum,
            &next_accum,
            accum_mask,
            accum_r_prime,
            precomputed.proof,
        )
        .map_err(|e| format!("BF round prove: {e:?}"))?;

        Ok(MonitorToTarget {
            accum_next: WireEncryptedPoly::from_native(&next_accum),
            accum_eval_masked: WireCiphertext::from_native(&accum_scaled),
            accum_eval_ctext: WireCiphertext::from_native(&accum_m_poly_ct),
            scaled_eval: WireCiphertext::from_native(&proved_scaled_eval),
            m_poly_ctext: WireCiphertext::from_native(&precomputed.m_poly_ct),
            round_proof,
        })
    }

    #[cfg(test)]
    pub(crate) fn compute_round(
        &self,
        rng: &mut OsRng,
        t_poly_ct: &WireEncryptedPoly,
        accum_ct: &WireEncryptedPoly,
    ) -> Result<MonitorToTarget, String> {
        let precomputed = self.preprocess_round(rng, t_poly_ct)?;
        self.finish_round(rng, precomputed, accum_ct)
    }

    pub fn run(&self, addr: &str, rounds: usize) -> io::Result<()> {
        let mut stream = TcpStream::connect(addr)?;
        eprintln!("[Monitor] Connected to {addr}");

        let mut rng = OsRng;

        for round in 1..=rounds {
            let incoming: TargetToMonitor = match recv_msg(&mut stream) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    eprintln!(
                        "[Monitor] Target disconnected after {} round(s).",
                        round - 1
                    );
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            eprintln!(
                "[Monitor] Round {round}/{rounds}: received TPolyCtext (len={}) + Accum",
                incoming.t_poly_ct.0.len()
            );

            let t_compute_start = std::time::Instant::now();
            let t_preprocess_start = std::time::Instant::now();
            let precomputed = self
                .preprocess_round(&mut rng, &incoming.t_poly_ct)
                .map_err(io::Error::other)?;
            let preprocess_ms = t_preprocess_start.elapsed().as_secs_f64() * 1000.0;
            let reply = self
                .finish_round(&mut rng, precomputed, &incoming.accum)
                .map_err(io::Error::other)?;
            let compute_ms = t_compute_start.elapsed().as_secs_f64() * 1000.0;

            send_msg(&mut stream, &reply)?;
            eprintln!(
                "[Monitor] Round {round}: Preprocess Time (accum-independent): {preprocess_ms:.3} ms"
            );
            eprintln!("[Monitor] Round {round}: Compute Time: {compute_ms:.3} ms; reply sent");
        }

        eprintln!("[Monitor] Done after {rounds} round(s).");
        Ok(())
    }
}

impl Monitor {
    fn mask_eval(
        &self,
        eval_ct: crate::crypto::elgamal::Ciphertext,
        mask: Scalar,
    ) -> crate::crypto::elgamal::Ciphertext {
        let scaled_no_blind = ct_scalar_mul(&eval_ct, &mask);
        let enc_zero_mask = crate::crypto::elgamal::Ciphertext {
            c1: &mask * &RISTRETTO_BASEPOINT_TABLE,
            c2: mask * self.pk.0,
        };
        ct_add(&scaled_no_blind, &enc_zero_mask)
    }
}

fn non_zero_scalar(rng: &mut OsRng) -> Scalar {
    loop {
        let s = Scalar::random(rng);
        if s != Scalar::zero() {
            return s;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bf::bloom::scalar_positions;
    use crate::bf::target::{poly_from_roots, Target, WireEncryptedPoly};
    use crate::crypto::elgamal::{
        encrypt_one, encrypt_poly, encrypt_zero, generate_key_share, test_zero, EncryptedPoly,
    };

    fn test_config() -> BloomFilterConfig {
        BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 1,
            target_marked_count: 4,
        }
    }

    fn input_for_position(target_position: Scalar) -> Scalar {
        let config = test_config();
        for candidate in 1u64..10_000 {
            let input = Scalar::from(candidate);
            if scalar_positions(input, config) == vec![target_position] {
                return input;
            }
        }
        panic!("no scalar input found for target position {target_position:?}");
    }

    #[test]
    fn test_match_element() {
        let mut rng = OsRng;
        let t_set = vec![Scalar::from(3u64), Scalar::from(17u64)];
        let target_position = Scalar::from(3u64);
        let m = input_for_position(target_position);

        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        let monitor = Monitor::new(m, test_config(), sk2, pk1.clone(), pk2.clone(), t_set.len());

        let coeffs = poly_from_roots(&t_set);
        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);
        let accum_ct = EncryptedPoly(vec![
            encrypt_one(&mut rng, &pk),
            encrypt_zero(&mut rng, &pk),
            encrypt_zero(&mut rng, &pk),
        ]);
        let wire_poly = WireEncryptedPoly::from_native(&poly_ct);
        let wire_accum = WireEncryptedPoly::from_native(&accum_ct);

        let msg = monitor
            .compute_round(&mut rng, &wire_poly, &wire_accum)
            .unwrap();

        let m_poly_ct = msg.m_poly_ctext.to_native().unwrap();
        assert!(
            test_zero(&sk1, &m_poly_ct),
            "hashed input should map to a marked Bloom position, so MPolyCtext should decrypt to 0"
        );
    }

    #[test]
    fn test_no_match_element() {
        let mut rng = OsRng;
        let t_set = vec![Scalar::from(3u64), Scalar::from(17u64)];
        let target_position = Scalar::from(9u64);
        let m = input_for_position(target_position);

        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        let monitor = Monitor::new(m, test_config(), sk2, pk1.clone(), pk2.clone(), t_set.len());

        let coeffs = poly_from_roots(&t_set);
        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);
        let accum_ct = EncryptedPoly(vec![
            encrypt_one(&mut rng, &pk),
            encrypt_zero(&mut rng, &pk),
            encrypt_zero(&mut rng, &pk),
        ]);
        let wire_poly = WireEncryptedPoly::from_native(&poly_ct);
        let wire_accum = WireEncryptedPoly::from_native(&accum_ct);

        let msg = monitor
            .compute_round(&mut rng, &wire_poly, &wire_accum)
            .unwrap();
        let m_poly_ct = msg.m_poly_ctext.to_native().unwrap();

        assert!(
            !test_zero(&sk1, &m_poly_ct),
            "hashed input should map to an unmarked Bloom position, so MPolyCtext should NOT decrypt to 0"
        );
    }

    #[test]
    fn test_full_round_in_process() {
        let mut rng = OsRng;
        let t_set = vec![Scalar::from(7u64), Scalar::from(42u64)];

        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);

        let mut target = Target::new(test_config(), 5, sk1, pk1.clone(), pk2.clone());
        let monitor_hit = Monitor::new(
            input_for_position(Scalar::from(7u64)),
            test_config(),
            sk2,
            pk1.clone(),
            pk2.clone(),
            t_set.len(),
        );

        let coeffs = poly_from_roots(&t_set);
        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);
        let accum_ct = EncryptedPoly(vec![
            encrypt_one(&mut rng, &pk),
            encrypt_zero(&mut rng, &pk),
            encrypt_zero(&mut rng, &pk),
        ]);
        let wire_poly = WireEncryptedPoly::from_native(&poly_ct);
        let wire_accum = WireEncryptedPoly::from_native(&accum_ct);

        let msg = monitor_hit
            .compute_round(&mut rng, &wire_poly, &wire_accum)
            .unwrap();
        let (next_accum, matched) = target
            .process_round(&mut rng, &poly_ct, &accum_ct, &msg)
            .unwrap();
        assert!(matched);
        assert_eq!(target.state, 1);
        let _ = next_accum;
    }
}
