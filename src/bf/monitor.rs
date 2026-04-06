//! Monitor's side of the Bloom-filter I-PSI-CA protocol.
//!
//! # Role
//! Holds an input `y`, derives its Bloom-filter positions locally, and uses a
//! secret key share `sk2`. For each round:
//!
//!   M.1  Compute `nextAccum = y · Accum`.
//!   M.2  Evaluate the encrypted target polynomial at every Bloom-filter
//!        position `j` derived from `y`, sum the ciphertexts, randomize, and
//!        partially decrypt to obtain `MPolyCtext`.
//!   M.3  Evaluate `Accum` at `y`, randomize, and partially decrypt to obtain
//!        the accumulated-evaluation ciphertext used by the target to decide
//!        whether the witness remains non-zero.
//!   M.4  Build proofs that the aggregate target evaluation, the accumulated
//!        evaluation, and the accumulated update are all computed correctly and
//!        tied to the same `y`.
//!
//! # ZK proof structure
//! Uses the Sigma-Bullet hybrid proof (`crypto/sigma-bullet.rs`) to bind:
//! - arithmetic consistency (`e_0 = mask`, `e_{i+1}=e_i·position`, `mask ≠ 0`)
//! - ciphertext consistency (`scaled_eval = Σ e_i·C_i + Enc(0; mask)`).
//!
//! # Network
//! Runs as a **TCP client**; connects to the target's address and submits one
//! BF aggregate query round per input `y`.

use std::io;
use std::net::TcpStream;

use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_TABLE, scalar::Scalar};
use rand::rngs::OsRng;

use crate::bf::bloom::BloomFilterConfig;
use crate::bf::proof as bfproof;
use crate::crypto::elgamal::{
    combine_public_keys, ct_add, ct_scalar_mul, eval_poly, partial_decrypt_with_witness,
    poly_scalar_mul, PublicKey, PublicKeyShare, SecretKeyShare,
};
// Re-use all wire types from target.rs.
use crate::bf::target::{
    recv_msg, send_msg, MonitorToTarget, TargetToMonitor, WireCiphertext, WireEncryptedPoly,
};
use bulletproofs::{BulletproofGens, PedersenGens};

// ── Monitor ───────────────────────────────────────────────────────────────────

pub struct Monitor {
    /// Input element `y`; hashed into a Bloom-filter position set locally.
    input_y: Scalar,
    /// Bloom filter parameters used to derive the monitor-side queried set.
    bf_config: BloomFilterConfig,
    /// Secret key share 2 (stays local; used for partial decryption).
    sk2: SecretKeyShare,
    /// Party 1's public key share (needed to re-randomise during partial decrypt).
    pk1: PublicKeyShare,
    /// Monitor public key share; needed for partial decrypt proofs.
    pk2: PublicKeyShare,
    /// Joint public key.
    pk: PublicKey,
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
}

impl Monitor {
    /// Construct a Monitor.
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

    // ── Core computation ──────────────────────────────────────────────────────

    /// Compute one protocol round given the current encrypted T-polynomial.
    ///
    /// Returns `MonitorToTarget` ready to be sent to the target.
    pub(crate) fn compute_round(
        &self,
        rng: &mut OsRng,
        t_poly_ct: &WireEncryptedPoly,
        accum_ct: &WireEncryptedPoly,
    ) -> Result<MonitorToTarget, String> {
        let poly = t_poly_ct.to_native()?;
        let accum = accum_ct.to_native()?;
        let accum_eval = eval_poly(&accum, &self.input_y);

        // M.2  Build the BF aggregate-evaluation witness once. This keeps the
        //      sigma-side work linear in the outsourced polynomial size:
        //      derive the e_d coefficients and fold the ciphertext once,
        //      instead of evaluating the encrypted polynomial separately for
        //      each Bloom index.
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

        // M.3  Apply the same masking-and-partial-decryption flow to the
        //      accumulated polynomial evaluation at y.
        let accum_mask = non_zero_scalar(rng);
        let accum_scaled = self.mask_eval(accum_eval, accum_mask);
        let (accum_m_poly_ct, accum_r_prime) =
            partial_decrypt_with_witness(rng, &self.sk2, &self.pk1, &accum_scaled);

        let next_accum = poly_scalar_mul(&accum, &self.input_y);

        let (proved_scaled_eval, round_proof) = bfproof::prove_round(
            rng,
            &self.pc_gens,
            &self.bp_gens,
            &poly,
            aggregate.positions.len(),
            &aggregate.e_vals,
            &scaled,
            self.input_y,
            mask,
            &self.pk,
            &self.pk1,
            &self.pk2,
            &m_poly_ct,
            &accum_scaled,
            &accum_m_poly_ct,
            &accum,
            &next_accum,
            r_prime,
            accum_r_prime,
            self.sk2.as_scalar(),
        )
        .map_err(|e| format!("BF round prove: {e:?}"))?;

        Ok(MonitorToTarget {
            accum_next: WireEncryptedPoly::from_native(&next_accum),
            accum_eval_masked: WireCiphertext::from_native(&accum_scaled),
            accum_eval_ctext: WireCiphertext::from_native(&accum_m_poly_ct),
            scaled_eval: WireCiphertext::from_native(&proved_scaled_eval),
            m_poly_ctext: WireCiphertext::from_native(&m_poly_ct),
            round_proof,
        })
    }

    // ── TCP client ────────────────────────────────────────────────────────────

    /// Connect to `addr`, run one aggregate BF query round, then disconnect.
    pub fn run(&self, addr: &str) -> io::Result<()> {
        let mut stream = TcpStream::connect(addr)?;
        eprintln!("[Monitor] Connected to {addr}");

        // Receive the initial T-polynomial ciphertext from the target.
        let first: TargetToMonitor = recv_msg(&mut stream)?;
        let outsource_bytes = bincode::serialized_size(&first)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            + 4;
        let (current_poly_ct, mut current_accum_ct) = match first {
            TargetToMonitor::Outsource { t_poly_ct, accum } => (t_poly_ct, accum),
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected Outsource, got {other:?}"),
                ))
            }
        };
        eprintln!(
            "[Monitor] Received TPolyCtext (len={})",
            current_poly_ct.0.len()
        );

        let mut rng = OsRng;

        let t_received_current = std::time::Instant::now();
        let msg = self
            .compute_round(&mut rng, &current_poly_ct, &current_accum_ct)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let compute_ms = t_received_current.elapsed().as_secs_f64() * 1000.0;

        let sent_bytes = bincode::serialized_size(&msg)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            + 4;

        let t_send = std::time::Instant::now();
        send_msg(&mut stream, &msg)?;

        let reply: TargetToMonitor = recv_msg(&mut stream)?;

        let latency_ms = t_received_current.elapsed().as_secs_f64() * 1000.0;
        let rtt_ms = t_send.elapsed().as_secs_f64() * 1000.0;

        let recv_bytes = bincode::serialized_size(&reply)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            + 4;

        eprintln!("[Monitor] Latency (recv outsource/prev -> recv next): {latency_ms:.3} ms");
        eprintln!("[Monitor] Compute Time (recv outsource/prev -> send): {compute_ms:.3} ms");
        eprintln!("[Monitor] RTT (send -> recv next): {rtt_ms:.3} ms");
        eprintln!(
            "[Monitor] Network Traffic: outsource={:.2} KB  send={:.2} KB  recv={:.2} KB",
            outsource_bytes as f64 / 1024.0,
            sent_bytes as f64 / 1024.0,
            recv_bytes as f64 / 1024.0,
        );

        match reply {
            TargetToMonitor::NextRound { accum } => {
                eprintln!("[Monitor] Round 1: accepted");
                current_accum_ct = accum;
            }
            TargetToMonitor::Reject { reason } => {
                eprintln!("[Monitor] Round 1: rejected — {reason}");
                return Err(io::Error::new(io::ErrorKind::InvalidData, reason));
            }
            TargetToMonitor::Outsource { .. } => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected Outsource mid-protocol",
                ));
            }
        }

        // Graceful close: just drop the stream.
        let _ = current_accum_ct;
        eprintln!("[Monitor] Done after 1 round.");
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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

/// Sample a uniformly random non-zero scalar (mask ∈ 𝔽*).
fn non_zero_scalar(rng: &mut OsRng) -> Scalar {
    loop {
        let s = Scalar::random(rng);
        if s != Scalar::zero() {
            return s;
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
            honeyword_probability: 0.125,
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

    // ── Helpers ───────────────────────────────────────────────────────────────

    // ── In-process round-trip tests ───────────────────────────────────────────

    /// Check that a matching element yields `test_zero == true`.
    #[test]
    fn test_match_element() {
        let mut rng = OsRng;
        let t_set = vec![Scalar::from(3u64), Scalar::from(17u64)];
        let target_position = Scalar::from(3u64); // is in TSet
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

        // Run the monitor's computation.
        let msg = monitor
            .compute_round(&mut rng, &wire_poly, &wire_accum)
            .unwrap();

        // Verify the MPolyCtext decrypts to zero under sk1.
        let m_poly_ct = msg.m_poly_ctext.to_native().unwrap();
        assert!(
            test_zero(&sk1, &m_poly_ct),
            "hashed input should map to a marked Bloom position, so MPolyCtext should decrypt to 0"
        );
    }

    /// Check that a non-matching element yields `test_zero == false`.
    #[test]
    fn test_no_match_element() {
        let mut rng = OsRng;
        let t_set = vec![Scalar::from(3u64), Scalar::from(17u64)];
        let target_position = Scalar::from(9u64); // NOT in TSet
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

    /// Full in-process protocol simulation (no network).
    #[test]
    fn test_full_round_in_process() {
        let mut rng = OsRng;
        let t_set = vec![Scalar::from(7u64), Scalar::from(42u64)];

        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);

        let mut target = Target::new(
            t_set.clone(),
            test_config(),
            5,
            sk1,
            pk1.clone(),
            pk2.clone(),
        );
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

        // Round 1: hit
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
