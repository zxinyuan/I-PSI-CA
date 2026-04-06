//! Monitor's side of the exact I-PSI-CA protocol (Figure 2).
//!
//! # Role
//! Holds an element `MElmt ∈ 𝔽` and a secret key share `sk2`.
//! For each round:
//!
//!   M.1  Choose a random non-zero mask and evaluate the encrypted polynomial:
//!          `eval_ct = THEval[pk](TPolyCtext, MElmt)`
//!   M.2  Scale and partially decrypt:
//!          `MPolyCtext = THDec[sk2](mask · eval_ct)`
//!   M.3  Update the accumulated polynomial:
//!          `nextAccum = MElmt · Accum`
//!   M.4  Build a ZKPoK (`MEzkp`) proving the evaluation, partial decryptions,
//!        and `nextAccum` update are consistent, then send the result to the target.
//!
//! # ZK proof structure
//! Uses the Sigma-Bullet hybrid proof (`crypto/sigma-bullet.rs`) to bind:
//! - arithmetic consistency (`e_0 = mask`, `e_{i+1}=e_i·MElmt`, `mask ≠ 0`)
//! - ciphertext consistency (`scaled_eval = Σ e_i·C_i + Enc(0; mask)`).
//!
//! # Network
//! Runs as a **TCP client**; connects to the target's address and submits
//! one element per round.  The same element is submitted for every round
//! (multi-round use is useful e.g. for testing).

use std::io;
use std::net::TcpStream;

use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek_ng::{constants::RISTRETTO_BASEPOINT_TABLE, scalar::Scalar};
use rand::rngs::OsRng;

use crate::crypto::elgamal::{
    combine_public_keys, ct_add, ct_scalar_mul, eval_poly, partial_decrypt_with_witness,
    poly_scalar_mul, PublicKey, PublicKeyShare, SecretKeyShare,
};
use crate::crypto::sigma_bullet;
// Re-use all wire types from target.rs.
use crate::exact::target::{
    recv_msg, send_msg, MonitorToTarget, TargetToMonitor, WireCiphertext, WireCombinedSigmaProof,
    WireEncryptedPoly,
};

// ── Monitor ───────────────────────────────────────────────────────────────────

pub struct Monitor {
    /// The element the monitor wants to check against the target's set.
    m_elmt: Scalar,
    /// Secret key share 2 (stays local; used for partial decryption).
    sk2: SecretKeyShare,
    /// Party 1's public key share (needed to re-randomise during partial decrypt).
    pk1: PublicKeyShare,
    /// Monitor's own public key share (needed to generate the sigma proof).
    pk2: PublicKeyShare,
    /// Joint public key.
    pk: PublicKey,
    /// Shared generator sets — must match the target's.
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
}

impl Monitor {
    /// Construct a Monitor.
    ///
    /// `max_degree` should equal `|TSet|` (the target's set size) so the
    /// Bulletproof generator capacity is pre-allocated correctly.
    pub fn new(
        m_elmt: Scalar,
        sk2: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
        max_degree: usize,
    ) -> Self {
        let pk = combine_public_keys(&pk1, &pk2);
        let n = max_degree + 2;
        let cap = 1usize << (usize::BITS - (2 * n).leading_zeros()) as usize;
        let cap = cap.max(64);
        Monitor {
            m_elmt,
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
    fn compute_round(
        &self,
        rng: &mut OsRng,
        t_poly_ct: &WireEncryptedPoly,
        accum_ct: &WireEncryptedPoly,
    ) -> Result<MonitorToTarget, String> {
        let poly = t_poly_ct.to_native()?;
        let accum = accum_ct.to_native()?;

        // M.1  THEval[pk]{TPolyCtext}{MElmt} — evaluate the encrypted polynomial.
        let eval_ct = eval_poly(&poly, &self.m_elmt);
        let accum_eval = eval_poly(&accum, &self.m_elmt);

        // M.2  Choose mask ←$ 𝔽* (non-zero), scale, blind with Enc(0; mask),
        //      then partially decrypt with sk2.
        let mask = non_zero_scalar(rng);
        let scaled = self.mask_eval(eval_ct, mask);
        let (m_poly_ct, r_prime) = partial_decrypt_with_witness(rng, &self.sk2, &self.pk1, &scaled);

        // Apply the same masking-and-partial-decryption flow to the accumulated
        // polynomial evaluation before sending it back to the target.
        let accum_mask = non_zero_scalar(rng);
        let accum_scaled = self.mask_eval(accum_eval, accum_mask);
        let (accum_m_poly_ct, accum_r_prime) =
            partial_decrypt_with_witness(rng, &self.sk2, &self.pk1, &accum_scaled);

        let next_accum = poly_scalar_mul(&accum, &self.m_elmt);

        // M.3  Build the combined proof for the evaluation and accum update.
        let round_proof = sigma_bullet::prove_round(
            rng,
            &self.pc_gens,
            &self.bp_gens,
            &self.pk,
            &self.pk1,
            &self.pk2,
            &poly.0,
            &scaled,
            &m_poly_ct,
            &accum_scaled,
            &accum_m_poly_ct,
            &accum,
            &next_accum,
            self.m_elmt,
            mask,
            r_prime,
            accum_r_prime,
            self.sk2.as_scalar(),
        )
        .map_err(|e| format!("round prove: {e:?}"))?;

        Ok(MonitorToTarget {
            next_accum: WireEncryptedPoly::from_native(&next_accum),
            accum_scaled_eval: WireCiphertext::from_native(&accum_scaled),
            accum_m_poly_ctext: WireCiphertext::from_native(&accum_m_poly_ct),
            scaled_eval: WireCiphertext::from_native(&scaled),
            m_poly_ctext: WireCiphertext::from_native(&m_poly_ct),
            round_proof: WireCombinedSigmaProof::from_proof(&round_proof),
        })
    }

    // ── TCP client ────────────────────────────────────────────────────────────

    /// Connect to `addr`, run `rounds` protocol interactions, then disconnect.
    ///
    /// Set `rounds = 1` for a single check.
    pub fn run(&self, addr: &str, rounds: usize) -> io::Result<()> {
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

        for round in 1..=rounds {
            eprintln!("[Monitor] Round {round}/{rounds}");
            let t_received_current = std::time::Instant::now();

            // Compute this round's message.
            let msg = self
                .compute_round(&mut rng, &current_poly_ct, &current_accum_ct)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            let compute_ms = t_received_current.elapsed().as_secs_f64() * 1000.0;

            // Measure sent bytes (4-byte length prefix + payload).
            let sent_bytes = bincode::serialized_size(&msg)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                + 4;

            let t_send = std::time::Instant::now();
            send_msg(&mut stream, &msg)?;

            // Receive the target's response.
            let reply: TargetToMonitor = recv_msg(&mut stream)?;

            let latency_ms = t_received_current.elapsed().as_secs_f64() * 1000.0;
            let rtt_ms = t_send.elapsed().as_secs_f64() * 1000.0;

            // Measure received bytes (4-byte length prefix + payload).
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
                    eprintln!("[Monitor] Round {round}: accepted");
                    current_accum_ct = accum;
                }
                TargetToMonitor::Reject { reason } => {
                    eprintln!("[Monitor] Round {round}: proof rejected — {reason}");
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

        // Graceful close: just drop the stream.
        let _ = current_accum_ct;
        eprintln!("[Monitor] Done after {rounds} round(s).");
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
    use crate::crypto::elgamal::{
        encrypt_one, encrypt_poly, encrypt_zero, generate_key_share, test_zero, EncryptedPoly,
    };
    use crate::exact::target::{poly_from_roots, Target, WireEncryptedPoly};

    // ── Helpers ───────────────────────────────────────────────────────────────

    // ── In-process round-trip tests ───────────────────────────────────────────

    /// Check that a matching element yields `test_zero == true`.
    #[test]
    fn test_match_element() {
        let mut rng = OsRng;
        let t_set = vec![Scalar::from(3u64), Scalar::from(17u64)];
        let m = Scalar::from(3u64); // is in TSet

        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        let monitor = Monitor::new(m, sk2, pk1.clone(), pk2.clone(), t_set.len());

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
            "MElmt = 3 is in TSet, so MPolyCtext should decrypt to 0"
        );
    }

    /// Check that a non-matching element yields `test_zero == false`.
    #[test]
    fn test_no_match_element() {
        let mut rng = OsRng;
        let t_set = vec![Scalar::from(3u64), Scalar::from(17u64)];
        let m = Scalar::from(99u64); // NOT in TSet

        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        let monitor = Monitor::new(m, sk2, pk1.clone(), pk2.clone(), t_set.len());

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
            "MElmt = 99 is not in TSet, so MPolyCtext should NOT decrypt to 0"
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

        let mut target = Target::new(t_set.clone(), 5, sk1, pk1.clone(), pk2.clone());
        let monitor_hit = Monitor::new(
            Scalar::from(7u64),
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
