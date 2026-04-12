use std::io;
use std::net::TcpStream;

use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_TABLE, scalar::Scalar};
use rand::rngs::OsRng;

use crate::crypto::elgamal::{
    combine_public_keys, ct_add, ct_scalar_mul, eval_poly, partial_decrypt_with_witness,
    poly_scalar_mul, Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare, SecretKeyShare,
};
use crate::fuzzy::proof;
use crate::fuzzy::target_proof::{self, WireTargetHybridProof};
use crate::fuzzy::target::{
    recv_msg, send_msg, MonitorToTarget, TargetToMonitor, WireCiphertext, WireEncryptedPoly,
};

pub struct Monitor {
    m_elmt: Scalar,
    _monitor_only_sk: SecretKeyShare,
    monitor_only_pk: PublicKey,
    sk2: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
    vector_size: usize,
}

impl Monitor {
    pub fn new(
        m_elmt: Scalar,
        monitor_only_sk: SecretKeyShare,
        monitor_only_pk: PublicKey,
        sk2: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        vector_size: usize,
    ) -> Self {
        Self {
            m_elmt,
            _monitor_only_sk: monitor_only_sk,
            monitor_only_pk,
            sk2,
            pk1,
            pk2,
            pk: combine_public_keys(&pk1, &pk2),
            vector_size,
        }
    }

    fn compute_round(
        &self,
        rng: &mut OsRng,
        accum: &EncryptedPoly,
    ) -> Result<MonitorToTarget, String> {
        let accum_eval_joint = eval_poly(accum, &self.m_elmt);
        let accum_mask = non_zero_scalar(rng);
        let accum_scaled_eval = self.mask_eval(accum_eval_joint, accum_mask);
        let (accum_eval, accum_r_prime) =
            partial_decrypt_with_witness(rng, &self.sk2, &self.pk1, &accum_scaled_eval);
        let next_accum = poly_scalar_mul(accum, &self.m_elmt);
        let input_bits = encode_scalar_bits(&self.m_elmt, self.vector_size);
        let (encrypted_input_bits, input_bit_randomness): (Vec<_>, Vec<_>) = input_bits
            .iter()
            .map(|bit| {
                let enc_r = Scalar::random(rng);
                (encrypt_with_randomness(&self.monitor_only_pk, bit, enc_r), enc_r)
            })
            .unzip();
        let proof = proof::prove_round(
            rng,
            &self.monitor_only_pk,
            &self.pk,
            &self.pk1,
            &self.pk2,
            accum,
            &next_accum,
            &accum_scaled_eval,
            &accum_eval,
            self.m_elmt,
            &input_bits,
            &input_bit_randomness,
            accum_mask,
            accum_r_prime,
            &self.sk2,
            &encrypted_input_bits,
        )?;

        Ok(MonitorToTarget {
            next_accum: WireEncryptedPoly::from_native(&next_accum),
            accum_eval: WireCiphertext::from_native(&accum_eval),
            encrypted_input_bits: encrypted_input_bits
                .iter()
                .map(WireCiphertext::from_native)
                .collect(),
            proof,
        })
    }

    pub fn run(&self, addr: &str, rounds: usize) -> io::Result<()> {
        let mut stream = TcpStream::connect(addr)?;
        eprintln!("[Monitor] Connected to {addr}");

        let first: TargetToMonitor = recv_msg(&mut stream)?;
        let outsource_bytes = bincode::serialized_size(&first)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            + 4;
        let current_accum_wire = match first {
            TargetToMonitor::Outsource { accum } => accum,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected Outsource, got {other:?}"),
                ))
            }
        };
        eprintln!("[Monitor] Received Accum ciphertext (len={})", current_accum_wire.0.len());
        let current_accum = current_accum_wire
            .to_native()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let mut rng = OsRng;

        for round in 1..=rounds {
            eprintln!("[Monitor] Round {round}/{rounds}");
            let latency_start = std::time::Instant::now();

            let msg = self
                .compute_round(&mut rng, &current_accum)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let monitor_compute_proof_ms = latency_start.elapsed().as_secs_f64() * 1000.0;

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
                    masked_distances,
                    masked_distance_proofs,
                    target_compute_proof_ms,
                } => {
                    self.verify_target_reply(
                        &msg,
                        &masked_distances,
                        &masked_distance_proofs,
                    )
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    let latency_ms = latency_start.elapsed().as_secs_f64() * 1000.0;
                    eprintln!("[Monitor] Latency (recv accum -> monitor decrypt): {latency_ms:.3} ms");
                    eprintln!(
                        "[Monitor] Compute Time: monitor compute+proof={monitor_compute_proof_ms:.3} ms  target compute+proof={target_compute_proof_ms:.3} ms"
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
                    eprintln!("[Monitor] Latency (recv accum -> monitor decrypt): {latency_ms:.3} ms");
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

    fn verify_target_reply(
        &self,
        msg: &MonitorToTarget,
        masked_distances: &[WireCiphertext],
        masked_distance_proofs: &[WireTargetHybridProof],
    ) -> Result<(), String> {
        if masked_distances.len() != masked_distance_proofs.len() {
            return Err("masked distance proof length mismatch".to_string());
        }

        let encrypted_input_bits: Vec<_> = msg
            .encrypted_input_bits
            .iter()
            .map(WireCiphertext::to_native)
            .collect::<Result<_, _>>()?;

        let (pc_gens, bp_gens) = target_proof::default_gens(encrypted_input_bits.len());
        for (ciphertext, proof) in masked_distances.iter().zip(masked_distance_proofs.iter()) {
            let ciphertext = ciphertext.to_native()?;
            let proof = proof.to_native()?;
            target_proof::verify(
                &pc_gens,
                &bp_gens,
                &self.monitor_only_pk,
                &ciphertext,
                &encrypted_input_bits,
                &proof,
            )?;
        }

        Ok(())
    }
}

fn encode_scalar_bits(input: &Scalar, vector_size: usize) -> Vec<Scalar> {
    let bytes = input.to_bytes();
    let mut bits = Vec::with_capacity(vector_size);
    for bit_idx in 0..vector_size {
        let bit = if bit_idx < bytes.len() * 8 {
            let byte = bytes[bit_idx / 8];
            ((byte >> (bit_idx % 8)) & 1) as u64
        } else {
            0
        };
        bits.push(Scalar::from(bit));
    }
    bits
}

fn non_zero_scalar(rng: &mut OsRng) -> Scalar {
    loop {
        let s = Scalar::random(rng);
        if s != Scalar::zero() {
            return s;
        }
    }
}

fn encrypt_with_randomness(pk: &PublicKey, msg: &Scalar, r: Scalar) -> Ciphertext {
    Ciphertext {
        c1: &r * &RISTRETTO_BASEPOINT_TABLE,
        c2: msg * &RISTRETTO_BASEPOINT_TABLE + r * pk.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{
        combine_public_keys, encrypt_one, encrypt_zero, generate_key_share, EncryptedPoly,
    };
    use crate::fuzzy::target::Target;

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
    fn test_compute_round_outputs_encrypted_input_bits() {
        let mut rng = OsRng;
        let (_sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let (monitor_sk, monitor_pk_share) = generate_key_share(&mut rng);
        let monitor_pk = PublicKey(monitor_pk_share.0);
        let threshold_pk = combine_public_keys(&pk1, &pk2);
        let vector_size = 12;
        let monitor =
            Monitor::new(Scalar::from(13u64), monitor_sk, monitor_pk, sk2, pk1, pk2, vector_size);
        let accum_ct = EncryptedPoly(vec![
            encrypt_one(&mut rng, &threshold_pk),
            encrypt_zero(&mut rng, &threshold_pk),
            encrypt_zero(&mut rng, &threshold_pk),
        ]);
        let msg = monitor.compute_round(&mut rng, &accum_ct).unwrap();
        assert_eq!(msg.encrypted_input_bits.len(), vector_size);
        assert_eq!(msg.next_accum.0.len(), accum_ct.0.len());
        assert!(!msg.proof.is_empty());
    }

    #[test]
    fn test_full_round_in_process() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let (monitor_sk, monitor_pk_share) = generate_key_share(&mut rng);
        let monitor_pk = PublicKey(monitor_pk_share.0);
        let vector_size = 16;

        let mut target = Target::new(
            vec![Scalar::from(5u64), Scalar::from(9u64)],
            5,
            sk1,
            pk1.clone(),
            pk2,
            monitor_pk,
            vector_size,
        );
        let monitor =
            Monitor::new(Scalar::from(7u64), monitor_sk, monitor_pk, sk2, pk1, pk2, vector_size);
        let accum_ct = target.build_accum_ctext(&mut rng);
        let msg = monitor.compute_round(&mut rng, &accum_ct).unwrap();
        let (next_accum, masked_distances, masked_distance_proofs) =
            target.process_round(&mut rng, &accum_ct, &msg).unwrap();
        assert_eq!(next_accum.0.len(), accum_ct.0.len());
        assert_eq!(masked_distances.len(), 2);
        assert_eq!(masked_distance_proofs.len(), 2);
    }

    #[test]
    fn test_monitor_round_shape_independent_of_target_set_size() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let (monitor_sk, monitor_pk_share) = generate_key_share(&mut rng);
        let monitor_pk = PublicKey(monitor_pk_share.0);

        let vector_size = 16;
        let monitor = Monitor::new(
            Scalar::from(7u64),
            monitor_sk,
            monitor_pk,
            sk2,
            pk1.clone(),
            pk2.clone(),
            vector_size,
        );

        let small_target = Target::new(
            vec![Scalar::from(5u64)],
            5,
            sk1,
            pk1.clone(),
            pk2.clone(),
            monitor_pk,
            vector_size,
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
            monitor_pk,
            vector_size,
        );

        let small_accum = small_target.build_accum_ctext(&mut rng);
        let large_accum = large_target.build_accum_ctext(&mut rng);
        let small_msg = monitor
            .compute_round(&mut rng, &small_accum)
            .unwrap();
        let large_msg = monitor
            .compute_round(&mut rng, &large_accum)
            .unwrap();

        assert_eq!(small_msg.encrypted_input_bits.len(), vector_size);
        assert_eq!(large_msg.encrypted_input_bits.len(), vector_size);
        assert_eq!(small_msg.next_accum.0.len(), large_msg.next_accum.0.len());
        assert!(!small_msg.proof.is_empty());
        assert!(!large_msg.proof.is_empty());
    }
}
