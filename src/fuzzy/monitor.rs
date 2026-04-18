use std::io;
use std::net::TcpStream;

use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use rand::rngs::OsRng;

use crate::crypto::elgamal::{
    combine_public_keys, ct_add, ct_scalar_mul, eval_poly, partial_decrypt_with_witness,
    poly_scalar_mul, Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare, SecretKeyShare,
};
use crate::fuzzy::proof;
use crate::fuzzy::utils::{encode_scalar_bits, encrypt_with_randomness};
use crate::fuzzy::target::{
    recv_msg, send_msg, MonitorToTarget, TargetToMonitor, WireCiphertext, WireEncryptedPoly,
};

pub struct Monitor {
    m_elmt: Scalar,
    sk2: SecretKeyShare,
    pk1: PublicKeyShare,
    _pk2: PublicKeyShare,
    pk: PublicKey,
    vector_size: usize,
    threshold: usize,
}

impl Monitor {
    pub fn new(
        m_elmt: Scalar,
        sk2: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        vector_size: usize,
        threshold: usize,
    ) -> Self {
        let pk = combine_public_keys(&pk1, &pk2);
        Self {
            m_elmt,
            sk2,
            pk1,
            _pk2: pk2,
            pk,
            vector_size,
            threshold,
        }
    }

    fn compute_round(
        &self,
        rng: &mut OsRng,
        accum: &EncryptedPoly,
        encrypted_item_bits: &[Vec<Ciphertext>],
    ) -> Result<MonitorToTarget, String> {
        let accum_eval_joint = eval_poly(accum, &self.m_elmt);
        let accum_mask = non_zero_scalar(rng);
        let accum_scaled_eval = self.mask_eval(accum_eval_joint, accum_mask);
        let (accum_eval, accum_r_prime) =
            partial_decrypt_with_witness(rng, &self.sk2, &self.pk1, &accum_scaled_eval);
        let next_accum = poly_scalar_mul(accum, &self.m_elmt);
        let input_bits = encode_scalar_bits(&self.m_elmt, self.vector_size);
        let mut c = Vec::with_capacity(encrypted_item_bits.len());
        let mut c_randomness = Vec::with_capacity(encrypted_item_bits.len());
        for item_bits in encrypted_item_bits.iter() {
            let (c_i, r_i) = compute_c_for_item(rng, &self.pk, item_bits, &input_bits)?;
            c.push(c_i);
            c_randomness.push(r_i);
        }
        let (threshold_distances, threshold_distance_witnesses): (Vec<_>, Vec<_>) = c
            .iter()
            .flat_map(|distance| {
                (0..=self.threshold)
                    .map(|threshold| {
                        partial_decrypt_threshold_distance(
                            rng,
                            &self.sk2,
                            &self.pk1,
                            distance,
                            threshold,
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .unzip();
        let proof = proof::prove_round(
            rng,
            &self.pk,
            &self.pk1,
            &self._pk2,
            accum,
            &next_accum,
            &accum_scaled_eval,
            &accum_eval,
            self.m_elmt,
            &input_bits,
            accum_mask,
            accum_r_prime,
            &self.sk2,
            encrypted_item_bits,
            &c,
            &c_randomness,
            &threshold_distances,
            &threshold_distance_witnesses,
            self.threshold,
        )?;

        Ok(MonitorToTarget {
            next_accum: WireEncryptedPoly::from_native(&next_accum),
            accum_eval: WireCiphertext::from_native(&accum_eval),
            threshold_distances: threshold_distances
                .iter()
                .map(WireCiphertext::from_native)
                .collect(),
            proof,
        })
    }

    #[cfg(test)]
    pub(crate) fn build_round_message(
        &self,
        rng: &mut OsRng,
        accum: &EncryptedPoly,
        encrypted_item_bits: &[Vec<Ciphertext>],
    ) -> Result<MonitorToTarget, String> {
        self.compute_round(rng, accum, encrypted_item_bits)
    }

    pub fn run(&self, addr: &str, rounds: usize) -> io::Result<()> {
        let mut stream = TcpStream::connect(addr)?;
        eprintln!("[Monitor] Connected to {addr}");

        let first: TargetToMonitor = recv_msg(&mut stream)?;
        let outsource_bytes = bincode::serialized_size(&first)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            + 4;
        let (current_accum_wire, encrypted_item_bits) = match first {
            TargetToMonitor::Outsource {
                accum,
                encrypted_item_bits,
            } => (accum, encrypted_item_bits),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected Outsource, got {other:?}"),
                ))
            }
        };
        eprintln!(
            "[Monitor] Received Accum ciphertext (len={})",
            current_accum_wire.0.len()
        );
        eprintln!(
            "[Monitor] Received threshold-encrypted target item bits for {} item(s)",
            encrypted_item_bits.len()
        );
        let mut current_accum = current_accum_wire
            .to_native()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let encrypted_item_bits: Vec<Vec<Ciphertext>> = encrypted_item_bits
            .iter()
            .map(|item_bits| {
                item_bits
                    .iter()
                    .map(WireCiphertext::to_native)
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<_, _>>()
            .map_err(|e: String| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let latency_start = std::time::Instant::now();

        let mut rng = OsRng;

        for round in 1..=rounds {
            eprintln!("[Monitor] Round {round}/{rounds}");
            let round_compute_start = std::time::Instant::now();
            let msg = self
                .compute_round(&mut rng, &current_accum, &encrypted_item_bits)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let monitor_compute_proof_ms = round_compute_start.elapsed().as_secs_f64() * 1000.0;

            let monitor_to_target_bytes = bincode::serialized_size(&msg)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                + 4;

            send_msg(&mut stream, &msg)?;

            let reply: TargetToMonitor = recv_msg(&mut stream)?;
            let target_to_monitor_bytes = bincode::serialized_size(&reply)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                + 4;

            match reply {
                TargetToMonitor::NextRound {
                    accum,
                } => {
                    current_accum = accum
                        .to_native()
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    let latency_ms = latency_start.elapsed().as_secs_f64() * 1000.0;
                    eprintln!(
                        "[Monitor] Latency (recv encrypted_item_bits -> recv new accum): {latency_ms:.3} ms"
                    );
                    eprintln!(
                        "[Monitor] Compute Time: monitor compute+proof={monitor_compute_proof_ms:.3} ms"
                    );
                    eprintln!(
                        "[Monitor] Network Traffic: outsource={:.2} KB  monitor->target={:.2} KB  target->monitor={:.2} KB",
                        outsource_bytes as f64 / 1024.0,
                        monitor_to_target_bytes as f64 / 1024.0,
                        target_to_monitor_bytes as f64 / 1024.0,
                    );
                    eprintln!("[Monitor] Round {round}: accepted");
                }
                TargetToMonitor::Reject {
                    reason,
                    target_compute_proof_ms,
                } => {
                    let latency_ms = latency_start.elapsed().as_secs_f64() * 1000.0;
                    eprintln!(
                        "[Monitor] Latency (recv encrypted_item_bits -> recv new accum): {latency_ms:.3} ms"
                    );
                    eprintln!(
                        "[Monitor] Compute Time: monitor compute+proof={monitor_compute_proof_ms:.3} ms  target compute+proof={target_compute_proof_ms:.3} ms"
                    );
                    eprintln!(
                        "[Monitor] Network Traffic: outsource={:.2} KB  monitor->target={:.2} KB  target->monitor={:.2} KB",
                        outsource_bytes as f64 / 1024.0,
                        monitor_to_target_bytes as f64 / 1024.0,
                        target_to_monitor_bytes as f64 / 1024.0,
                    );
                    eprintln!("[Monitor] Round {round}: rejected — {reason}");
                    return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
                }
                TargetToMonitor::Outsource { .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected Outsource mid-protocol",
                    ));
                }
            }
        }

        eprintln!("[Monitor] Done after {rounds} round(s).");
        Ok(())
    }

    fn mask_eval(&self, eval_ct: Ciphertext, mask: Scalar) -> Ciphertext {
        let scaled_no_blind = ct_scalar_mul(&eval_ct, &mask);
        let enc_zero_mask = Ciphertext {
            c1: &mask * &RISTRETTO_BASEPOINT_TABLE,
            c2: mask * self.pk.0,
        };
        ct_add(&scaled_no_blind, &enc_zero_mask)
    }
}

fn non_zero_scalar<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Scalar {
    loop {
        let s = Scalar::random(rng);
        if s != Scalar::zero() {
            return s;
        }
    }
}

fn compute_c_for_item<R: rand::CryptoRng + rand::RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    encrypted_x_bits: &[Ciphertext],
    y_bits: &[Scalar],
) -> Result<(Ciphertext, Vec<Scalar>), String> {
    if encrypted_x_bits.len() != y_bits.len() {
        return Err("target item bit length mismatch".to_string());
    }

    let mut acc = Ciphertext {
        c1: RistrettoPoint::default(),
        c2: RistrettoPoint::default(),
    };
    let mut randomness = Vec::with_capacity(y_bits.len());
    for (x_j, y_j) in encrypted_x_bits.iter().zip(y_bits.iter()) {
        let r_j = Scalar::random(rng);
        randomness.push(r_j);
        let enc_y_j = encrypt_with_randomness(pk, y_j, r_j);
        let mut term = ct_add(x_j, &enc_y_j);
        if *y_j == Scalar::one() {
            term = ct_add(&term, &ct_scalar_mul(x_j, &(-Scalar::from(2u64))));
        } else if *y_j != Scalar::zero() {
            return Err("embedded monitor bit is not binary".to_string());
        }
        acc = ct_add(&acc, &term);
    }

    Ok((acc, randomness))
}

fn mask_distance_difference_with_scalar(
    distance: &Ciphertext,
    threshold: usize,
    mask: Scalar,
) -> Ciphertext {
    let threshold_scalar = Scalar::from(threshold as u64);
    let threshold_offset = Ciphertext {
        c1: RistrettoPoint::default(),
        c2: -(&threshold_scalar * &RISTRETTO_BASEPOINT_TABLE),
    };
    let shifted_distance = ct_add(distance, &threshold_offset);
    ct_scalar_mul(&shifted_distance, &mask)
}

fn partial_decrypt_threshold_distance<R: rand::CryptoRng + rand::RngCore>(
    rng: &mut R,
    sk2: &SecretKeyShare,
    pk1: &PublicKeyShare,
    distance: &Ciphertext,
    threshold: usize,
) -> (Ciphertext, (Ciphertext, Scalar, Scalar)) {
    let mask = non_zero_scalar(rng);
    let masked = mask_distance_difference_with_scalar(distance, threshold, mask);
    let (partial, rerand) = partial_decrypt_with_witness(rng, sk2, pk1, &masked);
    (partial, (masked, mask, rerand))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{
        combine_public_keys, encrypt_one, encrypt_zero, generate_key_share, EncryptedPoly,
    };
    use crate::fuzzy::target::Target;
    use crate::fuzzy::utils::encode_scalar_bits;

    #[test]
    fn test_encode_scalar_bits_padding() {
        let bits = encode_scalar_bits(&Scalar::from(5u64), 10);
        let expected = vec![
            Scalar::from(1u64),
            Scalar::from(0u64),
            Scalar::from(1u64),
            Scalar::from(0u64),
            Scalar::from(0u64),
            Scalar::from(0u64),
            Scalar::from(0u64),
            Scalar::from(0u64),
            Scalar::from(0u64),
            Scalar::from(0u64),
        ];
        assert_eq!(bits, expected);
    }

    #[test]
    fn test_compute_round_outputs_per_item_c() {
        let mut rng = OsRng;
        let (_sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let threshold_pk = combine_public_keys(&pk1, &pk2);
        let vector_size = 12;
        let monitor = Monitor::new(
            Scalar::from(13u64),
            sk2,
            pk1.clone(),
            pk2,
            vector_size,
            3,
        );
        let accum_ct = EncryptedPoly(vec![
            encrypt_one(&mut rng, &threshold_pk),
            encrypt_zero(&mut rng, &threshold_pk),
            encrypt_zero(&mut rng, &threshold_pk),
        ]);
        let target = Target::new(
            vec![Scalar::from(5u64), Scalar::from(9u64)],
            5,
            generate_key_share(&mut rng).0,
            pk1,
            pk2,
            vector_size,
            3,
        );
        let encrypted_item_bits = target.encrypt_encoded_item_bits(&mut rng);
        let msg = monitor
            .compute_round(&mut rng, &accum_ct, &encrypted_item_bits)
            .unwrap();
        assert_eq!(msg.threshold_distances.len(), 8);
        assert_eq!(msg.next_accum.0.len(), accum_ct.0.len());
    }

    #[test]
    fn test_full_round_in_process() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let vector_size = 16;

        let mut target = Target::new(
            vec![Scalar::from(5u64), Scalar::from(9u64)],
            5,
            sk1,
            pk1.clone(),
            pk2,
            vector_size,
            2,
        );
        let monitor = Monitor::new(
            Scalar::from(7u64),
            sk2,
            pk1,
            pk2,
            vector_size,
            2,
        );
        let accum_ct = target.build_accum_ctext(&mut rng);
        let encrypted_item_bits = target.encrypt_encoded_item_bits(&mut rng);
        target.set_outsourced_item_bits(encrypted_item_bits.clone());
        let msg = monitor
            .compute_round(&mut rng, &accum_ct, &encrypted_item_bits)
            .unwrap();
        let next_accum = target.process_round(&mut rng, &accum_ct, &msg).unwrap();
        assert_eq!(next_accum.0.len(), accum_ct.0.len());
    }

    #[test]
    fn test_monitor_round_shape_independent_of_target_set_size() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let vector_size = 16;
        let monitor = Monitor::new(
            Scalar::from(7u64),
            sk2,
            pk1.clone(),
            pk2.clone(),
            vector_size,
            1,
        );

        let small_target = Target::new(
            vec![Scalar::from(5u64)],
            5,
            sk1,
            pk1.clone(),
            pk2.clone(),
            vector_size,
            1,
        );
        let large_target = Target::new(
            vec![
                Scalar::from(5u64),
                Scalar::from(9u64),
                Scalar::from(12u64),
                Scalar::from(15u64),
                Scalar::from(18u64),
            ],
            5,
            generate_key_share(&mut rng).0,
            pk1,
            pk2,
            vector_size,
            1,
        );

        let small_accum = small_target.build_accum_ctext(&mut rng);
        let large_accum = large_target.build_accum_ctext(&mut rng);
        let small_item_bits = small_target.encrypt_encoded_item_bits(&mut rng);
        let large_item_bits = large_target.encrypt_encoded_item_bits(&mut rng);
        let small_msg = monitor
            .compute_round(&mut rng, &small_accum, &small_item_bits)
            .unwrap();
        let large_msg = monitor
            .compute_round(&mut rng, &large_accum, &large_item_bits)
            .unwrap();

        assert_eq!(small_msg.threshold_distances.len(), 2);
        assert_eq!(large_msg.threshold_distances.len(), 10);
        assert_eq!(small_msg.next_accum.0.len(), large_msg.next_accum.0.len());
    }
}
