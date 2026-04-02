//! Target's side of the exact I-PSI-CA protocol (Figure 2).
//!
//! # Role
//! Holds a set `TSet ⊆ 𝔽`.  Encodes it as a polynomial whose roots are
//! exactly the set elements, encrypts it under the joint public key, and
//! outsources the ciphertext to the monitor.  For each subsequent round it
//! verifies the monitor's proof and decides whether to increment its counter.
//!
//! # Network
//! Runs as a **TCP server**; accepts one monitor connection and drives the
//! protocol for an arbitrary number of rounds.
//!
//! # Module layout assumed
//! ```text
//! src/
//!   crypto/elgamal.rs     ← ../Crypto/ElGamal.rs
//!   crypto/bulletproof.rs ← ../Crypto/bulletproof.rs
//!   exact/target.rs       ← this file
//!   exact/monitor.rs
//!   exact/wire.rs         ← shared wire types (defined here, re-exported)
//! ```
//!
//! # Extra Cargo deps
//! ```toml
//! serde   = { version = "1", features = ["derive"] }
//! bincode = "1"
//! ```

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::bulletproof as bp;
use crate::crypto::elgamal::{
    combine_public_keys, encrypt_poly, encrypt_zero, rerandomize_poly_with_witness, test_zero,
    Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare, SecretKeyShare,
};
use crate::crypto::sigma_bullet as sb;

// ── Wire types (shared with Monitor) ─────────────────────────────────────────

/// Serialisable ElGamal ciphertext: two 32-byte compressed Ristretto points.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireCiphertext {
    pub c1: [u8; 32],
    pub c2: [u8; 32],
}

impl WireCiphertext {
    pub fn from_native(ct: &Ciphertext) -> Self {
        WireCiphertext {
            c1: ct.c1.compress().to_bytes(),
            c2: ct.c2.compress().to_bytes(),
        }
    }
    pub fn to_native(&self) -> Result<Ciphertext, String> {
        let c1 = CompressedRistretto::from_slice(&self.c1)
            .decompress()
            .ok_or("c1 not on curve")?;
        let c2 = CompressedRistretto::from_slice(&self.c2)
            .decompress()
            .ok_or("c2 not on curve")?;
        Ok(Ciphertext { c1, c2 })
    }
}

/// Serialisable encrypted polynomial: a length-prefixed vector of wire ciphertexts.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireEncryptedPoly(pub Vec<WireCiphertext>);

impl WireEncryptedPoly {
    pub fn from_native(p: &EncryptedPoly) -> Self {
        WireEncryptedPoly(p.0.iter().map(WireCiphertext::from_native).collect())
    }
    pub fn to_native(&self) -> Result<EncryptedPoly, String> {
        let cts: Result<Vec<_>, _> = self.0.iter().map(|w| w.to_native()).collect();
        Ok(EncryptedPoly(cts?))
    }
}

/// Serialisable form of `bp::EvalChainProof`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireEvalChainProof {
    pub proof_bytes: Vec<u8>,
    pub e_comms: Vec<[u8; 32]>,
    pub y_comm: [u8; 32],
    pub inv_en_comm: [u8; 32],
}

impl WireEvalChainProof {
    pub fn from_proof(p: &bp::EvalChainProof) -> Self {
        WireEvalChainProof {
            proof_bytes: p.proof.to_bytes(),
            e_comms: p.e_comms.iter().map(|c| c.to_bytes()).collect(),
            y_comm: p.y_comm.to_bytes(),
            inv_en_comm: p.inv_en_comm.to_bytes(),
        }
    }
    pub fn to_proof(&self) -> Result<bp::EvalChainProof, String> {
        use bulletproofs::r1cs::R1CSProof;
        let proof = R1CSProof::from_bytes(&self.proof_bytes)
            .map_err(|e| format!("R1CSProof decode: {e:?}"))?;
        let e_comms: Vec<_> = self
            .e_comms
            .iter()
            .map(|b| CompressedRistretto::from_slice(b))
            .collect();
        let y_comm = CompressedRistretto::from_slice(&self.y_comm);
        let inv_en_comm = CompressedRistretto::from_slice(&self.inv_en_comm);
        Ok(bp::EvalChainProof {
            proof,
            e_comms,
            y_comm,
            inv_en_comm,
        })
    }
}

/// The monitor's ZKPoK composed of two Bulletproof R1CS sub-proofs.
///
/// **power_chain**: proves `[y^n, y^{n-1}, …, y, 1]` is geometric with ratio `y`
/// (binds the evaluation to a single consistent input point).
///
/// **mask_nonzero**: proves `mask ≠ 0` via the n=0 eval-chain gadget
/// (just the inverse-exists gate: `mask · mask⁻¹ = 1`).
///
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireMonitorProof {
    pub power_chain: WireEvalChainProof,
    pub mask_nonzero: WireEvalChainProof,
}

/// Serialisable form of `sigma_bullet::GlueProof`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireGlueProof {
    pub alpha_tag: [u8; 32],
    pub a_t: [u8; 32],
    pub z_e: Vec<[u8; 32]>,
    pub z_alpha: [u8; 32],
    pub z_y_blind: [u8; 32],
}

impl WireGlueProof {
    pub fn from_proof(p: &sb::GlueProof) -> Self {
        WireGlueProof {
            alpha_tag: p.alpha_tag.to_bytes(),
            a_t: p.a_t.to_bytes(),
            z_e: p.z_e.iter().map(|s| s.to_bytes()).collect(),
            z_alpha: p.z_alpha.to_bytes(),
            z_y_blind: p.z_y_blind.to_bytes(),
        }
    }

    pub fn to_proof(&self) -> sb::GlueProof {
        sb::GlueProof {
            alpha_tag: CompressedRistretto::from_slice(&self.alpha_tag),
            a_t: CompressedRistretto::from_slice(&self.a_t),
            z_e: self
                .z_e
                .iter()
                .map(|b| Scalar::from_bytes_mod_order(*b))
                .collect(),
            z_alpha: Scalar::from_bytes_mod_order(self.z_alpha),
            z_y_blind: Scalar::from_bytes_mod_order(self.z_y_blind),
        }
    }
}

/// Serialisable form of `sigma_bullet::SigmaBulletProof`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireSigmaBulletProof {
    pub chain_proof: WireEvalChainProof,
    pub glue: WireGlueProof,
}

impl WireSigmaBulletProof {
    pub fn from_proof(p: &sb::SigmaBulletProof) -> Self {
        WireSigmaBulletProof {
            chain_proof: WireEvalChainProof::from_proof(&p.chain_proof),
            glue: WireGlueProof::from_proof(&p.glue),
        }
    }

    pub fn to_proof(&self) -> Result<sb::SigmaBulletProof, String> {
        Ok(sb::SigmaBulletProof {
            chain_proof: self.chain_proof.to_proof()?,
            glue: self.glue.to_proof(),
        })
    }
}

/// Serialisable form of the full combined round proof.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireCombinedSigmaProof {
    pub chain_proof: WireEvalChainProof,
    pub alpha_tag: [u8; 32],
    pub glue_a_t: [u8; 32],
    pub glue_z_e: Vec<[u8; 32]>,
    pub glue_z_alpha: [u8; 32],
    pub glue_z_y_blind: [u8; 32],
    pub partial_a: [u8; 32],
    pub partial_z1: [u8; 32],
    pub partial_z2: [u8; 32],
    pub poly_a1: [u8; 32],
    pub poly_a2: [u8; 32],
    pub poly_a_m: [u8; 32],
    pub poly_s_y: [u8; 32],
    pub poly_s_delta: [u8; 32],
}

impl WireCombinedSigmaProof {
    pub fn from_proof(p: &sb::CombinedSigmaProof) -> Self {
        WireCombinedSigmaProof {
            chain_proof: WireEvalChainProof::from_proof(&p.chain_proof),
            alpha_tag: p.alpha_tag.to_bytes(),
            glue_a_t: p.glue_a_t.to_bytes(),
            glue_z_e: p.glue_z_e.iter().map(|s| s.to_bytes()).collect(),
            glue_z_alpha: p.glue_z_alpha.to_bytes(),
            glue_z_y_blind: p.glue_z_y_blind.to_bytes(),
            partial_a: p.partial_a.to_bytes(),
            partial_z1: p.partial_z1.to_bytes(),
            partial_z2: p.partial_z2.to_bytes(),
            poly_a1: p.poly_a1.to_bytes(),
            poly_a2: p.poly_a2.to_bytes(),
            poly_a_m: p.poly_a_m.to_bytes(),
            poly_s_y: p.poly_s_y.to_bytes(),
            poly_s_delta: p.poly_s_delta.to_bytes(),
        }
    }

    pub fn to_proof(&self) -> Result<sb::CombinedSigmaProof, String> {
        Ok(sb::CombinedSigmaProof {
            chain_proof: self.chain_proof.to_proof()?,
            alpha_tag: CompressedRistretto::from_slice(&self.alpha_tag),
            glue_a_t: CompressedRistretto::from_slice(&self.glue_a_t),
            glue_z_e: self
                .glue_z_e
                .iter()
                .map(|b| Scalar::from_bytes_mod_order(*b))
                .collect(),
            glue_z_alpha: Scalar::from_bytes_mod_order(self.glue_z_alpha),
            glue_z_y_blind: Scalar::from_bytes_mod_order(self.glue_z_y_blind),
            partial_a: CompressedRistretto::from_slice(&self.partial_a),
            partial_z1: Scalar::from_bytes_mod_order(self.partial_z1),
            partial_z2: Scalar::from_bytes_mod_order(self.partial_z2),
            poly_a1: CompressedRistretto::from_slice(&self.poly_a1),
            poly_a2: CompressedRistretto::from_slice(&self.poly_a2),
            poly_a_m: CompressedRistretto::from_slice(&self.poly_a_m),
            poly_s_y: Scalar::from_bytes_mod_order(self.poly_s_y),
            poly_s_delta: Scalar::from_bytes_mod_order(self.poly_s_delta),
        })
    }
}

// ── Protocol messages ─────────────────────────────────────────────────────────

/// Target → Monitor messages.
#[derive(Serialize, Deserialize, Debug)]
pub enum TargetToMonitor {
    /// Initial outsource: the encrypted T-polynomial ciphertext.
    Outsource { t_poly_ct: WireEncryptedPoly },
    /// Next-round ciphertext (re-randomised; either updated or the same poly).
    NextRound { t_poly_ct_alt: WireEncryptedPoly },
    /// Monitor's proof was rejected; contains a debug reason string.
    Reject { reason: String },
}

/// Monitor → Target message (one per round).
#[derive(Serialize, Deserialize, Debug)]
pub struct MonitorToTarget {
    /// `nextTPoly = TPolyCtext THDiv[pk] (X − MElmt)`.
    pub next_t_poly: WireEncryptedPoly,
    /// `scaled_eval = mask · THEval[pk](TPolyCtext, MElmt)` — the ciphertext
    /// fed into partial decryption; needed by the target to verify the sigma proof.
    pub scaled_eval: WireCiphertext,
    /// `MPolyCtext = THDec[sk2](scaled_eval)`.
    pub m_poly_ctext: WireCiphertext,
    /// One composite proof covering encrypted evaluation, partial decryption,
    /// and polynomial division under a shared Fiat-Shamir challenge.
    pub round_proof: WireCombinedSigmaProof,
}

// ── Framed TCP helpers ────────────────────────────────────────────────────────

pub fn send_msg<T: Serialize>(stream: &mut TcpStream, msg: &T) -> io::Result<()> {
    let bytes =
        bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = (bytes.len() as u32).to_be_bytes();
    stream.write_all(&len)?;
    stream.write_all(&bytes)
}

pub fn recv_msg<T: for<'de> Deserialize<'de>>(stream: &mut TcpStream) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    bincode::deserialize(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

// ── Polynomial utilities ──────────────────────────────────────────────────────

/// Build the monic polynomial `P(X) = ∏_{t ∈ roots} (X − t)`.
///
/// Returns `[a_0, a_1, …, a_n]` where `a_d` is the coefficient of `X^d`.
pub fn poly_from_roots(roots: &[Scalar]) -> Vec<Scalar> {
    // Start from polynomial "1" (constant) and multiply in each linear factor.
    let mut coeffs = vec![Scalar::one()];
    for root in roots {
        let prev = coeffs.clone();
        let n = prev.len();
        coeffs = vec![Scalar::zero(); n + 1];
        coeffs[n] = prev[n - 1];                          // leading term
        for d in 1..n {
            coeffs[d] = prev[d - 1] - root * prev[d];    // middle terms
        }
        coeffs[0] = -root * prev[0];                      // constant term
    }
    coeffs
}

// ── Target ────────────────────────────────────────────────────────────────────

pub struct Target {
    t_set: Vec<Scalar>,
    sk1: SecretKeyShare,
    pk1: PublicKeyShare,
    pk: PublicKey,
    /// Matching counter, incremented on each genuine match.
    pub state: u64,
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
}

impl Target {
    /// Construct a Target from its secret key share and the public parameters.
    pub fn new(
        t_set: Vec<Scalar>,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
    ) -> Self {
        let pk = combine_public_keys(&pk1, &pk2);
        // Choose BP generator capacity ≥ 2·(|TSet|+2) rounded up to a power of two.
        let n = t_set.len() + 2;
        let cap = 1usize << (usize::BITS - (2 * n).leading_zeros()) as usize;
        let cap = cap.max(64);
        Target {
            t_set,
            sk1,
            pk1,
            pk,
            state: 0,
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(cap, 1),
        }
    }

    // ── Setup ─────────────────────────────────────────────────────────────────

    /// `THEnc[pk](T-poly)`: construct P(X) from TSet and encrypt.
    fn build_poly_ctext(&self, rng: &mut OsRng) -> EncryptedPoly {
        let coeffs = poly_from_roots(&self.t_set);
        encrypt_poly(rng, &self.pk, &coeffs)
    }

    // ── Protocol round ────────────────────────────────────────────────────────

    /// One complete round: verify proof, test match, produce next poly ctext.
    ///
    /// Returns `(next_poly, is_match)`.
    pub(crate) fn process_round(
        &mut self,
        rng: &mut OsRng,
        current: &EncryptedPoly,
        msg: &MonitorToTarget,
    ) -> Result<(EncryptedPoly, bool), String> {
        let next_t_poly = msg.next_t_poly.to_native()?;
        let scaled_eval = msg.scaled_eval.to_native()?;
        let m_poly_ct   = msg.m_poly_ctext.to_native()?;

        // T.1  Verify the Sigma-Bullet glue proof for encrypted evaluation.
        let pk2 = PublicKeyShare(self.pk.0 - self.pk1.0);
        let round_proof = msg.round_proof.to_proof()?;
        sb::verify_round(
            &self.pc_gens,
            &self.bp_gens,
            &self.pk,
            &self.pk1,
            &pk2,
            &current.0,
            &scaled_eval,
            &m_poly_ct,
            current,
            &next_t_poly,
            &round_proof,
        )
        .map_err(|e| format!("round proof invalid: {e}"))?;

        // T.2  THTest[sk1]{0}{MPolyCtext}:
        //      MPolyCtext was partially decrypted by the monitor (THDec[sk2]),
        //      so it lives in THCtextSpace[pk1].  test_zero finishes the job.
        let is_match = test_zero(&self.sk1, &m_poly_ct);

        // T.3  Choose and re-randomise the next polynomial ciphertext.
        //      If match: adopt nextTPoly (monitor already removed MElmt root).
        //      If no match: keep the current polynomial.
        let base_poly = if is_match { self.state += 1; &next_t_poly } else { current };
        let (mut next_poly, _) = rerandomize_poly_with_witness(rng, &self.pk, base_poly);
        while next_poly.0.len() < current.0.len() {
            next_poly.0.push(encrypt_zero(rng, &self.pk));
        }

        Ok((next_poly, is_match))
    }

    // ── TCP server ────────────────────────────────────────────────────────────

    /// Bind to `addr`, accept one monitor, and run the protocol.
    pub fn run(&mut self, addr: &str) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        eprintln!("[Target] Listening on {addr}");
        let (stream, peer) = listener.accept()?;
        eprintln!("[Target] Monitor connected from {peer}");
        self.handle(stream)
    }

    fn handle(&mut self, mut s: TcpStream) -> io::Result<()> {
        let mut rng = OsRng;

        // Outsource: encrypt the T-polynomial and send it to the monitor.
        let t_outsource_start = std::time::Instant::now();
        let mut current = self.build_poly_ctext(&mut rng);
        send_msg(&mut s, &TargetToMonitor::Outsource {
            t_poly_ct: WireEncryptedPoly::from_native(&current),
        })?;
        let outsource_ms = t_outsource_start.elapsed().as_secs_f64() * 1000.0;
        eprintln!("[Target] Outsource Time (compute -> send): {outsource_ms:.3} ms");
        eprintln!("[Target] Sent TPolyCtext (deg {})", self.t_set.len());

        // Main loop: one iteration per monitor submission.
        loop {
            let msg: MonitorToTarget = match recv_msg(&mut s) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    eprintln!("[Target] Done. state = {}", self.state);
                    return Ok(());
                }
                Err(e) => return Err(e),
            };

            match self.process_round(&mut rng, &current, &msg) {
                Ok((next, matched)) => {
                    eprintln!("[Target] match={matched}  state={}", self.state);
                    current = next;
                    send_msg(&mut s, &TargetToMonitor::NextRound {
                        t_poly_ct_alt: WireEncryptedPoly::from_native(&current),
                    })?;
                }
                Err(reason) => {
                    eprintln!("[Target] Reject: {reason}");
                    send_msg(&mut s, &TargetToMonitor::Reject { reason })?;
                    return Ok(());
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{ct_add, ct_scalar_mul, div_poly_linear, eval_poly};
    use crate::crypto::elgamal::generate_key_share;

    /// Verify that `poly_from_roots` evaluates to zero at each root.
    #[test]
    fn test_poly_roots_eval_zero() {
        let roots = [Scalar::from(2u64), Scalar::from(5u64), Scalar::from(11u64)];
        let coeffs = poly_from_roots(&roots);
        for r in &roots {
            // Horner evaluation.
            let mut val = *coeffs.last().unwrap();
            for c in coeffs[..coeffs.len() - 1].iter().rev() {
                val = val * r + c;
            }
            assert_eq!(val, Scalar::zero(), "P({r:?}) must be zero");
        }
    }

    /// End-to-end test of one matched round using in-process crypto.
    #[test]
    fn test_process_round_match() {
        use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT as G;
        use crate::crypto::elgamal::partial_decrypt_with_witness;
        use crate::crypto::sigma_bullet as sb_mod;

        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);

        let t_set = vec![Scalar::from(7u64), Scalar::from(42u64)];
        let mut target = Target::new(t_set.clone(), sk1, pk1, pk2.clone());
        let poly_ct = target.build_poly_ctext(&mut rng);

        // Monitor side: MElmt = 7 (is a root).
        let m = Scalar::from(7u64);
        let next_t_poly = div_poly_linear(&poly_ct, &m);
        let eval_ct = eval_poly(&poly_ct, &m);
        let mask    = Scalar::from(13u64);
        let scaled_no_blind = ct_scalar_mul(&eval_ct, &mask);
        let enc_zero_mask = Ciphertext { c1: mask * G, c2: mask * target.pk.0 };
        let scaled  = ct_add(&scaled_no_blind, &enc_zero_mask);
        let (m_poly_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &target.pk1, &scaled);

        let delta_vec = vec![Scalar::zero(); next_t_poly.0.len()];
        let round_proof = sb_mod::prove_round(
            &mut rng,
            &target.pc_gens,
            &target.bp_gens,
            &target.pk,
            &target.pk1,
            &pk2,
            &poly_ct.0,
            &scaled,
            &m_poly_ct,
            &poly_ct,
            &next_t_poly,
            m,
            mask,
            r_prime,
            sk2.as_scalar(),
            &delta_vec,
        )
        .expect("round prove");

        let msg = MonitorToTarget {
            next_t_poly:  WireEncryptedPoly::from_native(&next_t_poly),
            scaled_eval:  WireCiphertext::from_native(&scaled),
            m_poly_ctext: WireCiphertext::from_native(&m_poly_ct),
            round_proof: WireCombinedSigmaProof::from_proof(&round_proof),
        };

        let (next_poly_out, matched) = target.process_round(&mut rng, &poly_ct, &msg).unwrap();
        assert!(matched, "7 should be detected as a match");
        assert_eq!(target.state, 1);
        assert_eq!(next_poly_out.0.len(), poly_ct.0.len(), "target should pad back to constant length");
    }

    /// Non-match round: state stays at 0.
    #[test]
    fn test_process_round_no_match() {
        use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT as G;
        use crate::crypto::elgamal::partial_decrypt_with_witness;
        use crate::crypto::sigma_bullet as sb_mod;

        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);

        let t_set = vec![Scalar::from(7u64)];
        let mut target = Target::new(t_set.clone(), sk1, pk1, pk2.clone());
        let poly_ct = target.build_poly_ctext(&mut rng);

        // MElmt = 99 (NOT a root).
        let m    = Scalar::from(99u64);
        let mask = Scalar::from(5u64);
        let next_t_poly = div_poly_linear(&poly_ct, &m);
        let scaled_no_blind = ct_scalar_mul(&eval_poly(&poly_ct, &m), &mask);
        let enc_zero_mask = Ciphertext { c1: mask * G, c2: mask * target.pk.0 };
        let scaled = ct_add(&scaled_no_blind, &enc_zero_mask);
        let (m_poly_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &target.pk1, &scaled);

        let delta_vec = vec![Scalar::zero(); next_t_poly.0.len()];
        let round_proof = sb_mod::prove_round(
            &mut rng,
            &target.pc_gens,
            &target.bp_gens,
            &target.pk,
            &target.pk1,
            &pk2,
            &poly_ct.0,
            &scaled,
            &m_poly_ct,
            &poly_ct,
            &next_t_poly,
            m,
            mask,
            r_prime,
            sk2.as_scalar(),
            &delta_vec,
        )
        .unwrap();

        let msg = MonitorToTarget {
            next_t_poly:  WireEncryptedPoly::from_native(&next_t_poly),
            scaled_eval:  WireCiphertext::from_native(&scaled),
            m_poly_ctext: WireCiphertext::from_native(&m_poly_ct),
            round_proof: WireCombinedSigmaProof::from_proof(&round_proof),
        };

        let (next_poly_out, matched) = target.process_round(&mut rng, &poly_ct, &msg).unwrap();
        assert!(!matched, "99 should not match");
        assert_eq!(target.state, 0);
        assert_eq!(next_poly_out.0.len(), poly_ct.0.len(), "non-match keeps the same length");
    }
}
