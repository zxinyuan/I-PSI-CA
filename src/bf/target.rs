//! Target's side of the Bloom-filter I-PSI-CA protocol.
//!
//! # Role
//! Holds the Bloom filter index set `B ⊆ 𝔽` consisting of the positions whose
//! bits are marked `1`. Encodes it as a polynomial whose roots are exactly
//! those marked positions, encrypts it under the joint public key, and
//! outsources the ciphertext to the monitor. For each subsequent round it
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

use std::io::{self, IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream};

use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::bf::bloom::BloomFilterConfig;
use crate::bf::proof as bfproof;
use crate::crypto::elgamal::{
    combine_public_keys, encrypt_one, encrypt_poly, encrypt_zero, rerandomize_poly_with_witness,
    test_zero, Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare, SecretKeyShare,
};

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

// ── Protocol messages ─────────────────────────────────────────────────────────

/// Target → Monitor messages.
#[derive(Serialize, Deserialize, Debug)]
pub enum TargetToMonitor {
    /// Initial outsource: the encrypted T-polynomial ciphertext.
    Outsource {
        t_poly_ct: WireEncryptedPoly,
        accum: WireEncryptedPoly,
    },
    /// Next-round ciphertext (re-randomised; either updated or the same poly).
    NextRound { accum: WireEncryptedPoly },
    /// Monitor's proof was rejected; contains a debug reason string.
    Reject { reason: String },
}

/// Monitor → Target message (one per round).
#[derive(Serialize, Deserialize, Debug)]
pub struct MonitorToTarget {
    /// `accumNext = y · Accum`.
    pub accum_next: WireEncryptedPoly,
    /// Masked accumulated evaluation `accum_mask · THEval[pk](Accum, y)`,
    /// included so the target can verify the corresponding sigma proof.
    pub accum_eval_masked: WireCiphertext,
    /// Partially decrypted accumulated evaluation used for the target's
    /// non-zero test before advancing state.
    pub accum_eval_ctext: WireCiphertext,
    /// `scaled_eval = mask · Σ_j THEval[pk](TPolyCtext, j)` over the bloom
    /// positions derived from `y`, fed into partial decryption.
    pub scaled_eval: WireCiphertext,
    /// `MPolyCtext = THDec[sk2](scaled_eval)`.
    pub m_poly_ctext: WireCiphertext,
    /// BF-specific proof bundle for position hashing, partial decryptions, and
    /// accumulated-polynomial update.
    pub round_proof: bfproof::RoundProof,
}

// ── Framed TCP helpers ────────────────────────────────────────────────────────

pub fn send_msg<T: Serialize>(stream: &mut TcpStream, msg: &T) -> io::Result<()> {
    let bytes =
        bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = (bytes.len() as u32).to_be_bytes();
    // Write length prefix and payload in a single syscall via vectored I/O.
    let mut bufs: &mut [IoSlice<'_>] = &mut [IoSlice::new(&len), IoSlice::new(&bytes)];
    let total = len.len() + bytes.len();
    let mut written = 0;
    while written < total {
        written += stream.write_vectored(bufs)?;
        IoSlice::advance_slices(&mut bufs, written);
    }
    Ok(())
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
    // Start from polynomial "1" (constant) and multiply in each linear factor
    // in-place, walking the coefficient vector backwards to avoid a clone.
    let mut coeffs = Vec::with_capacity(roots.len() + 1);
    coeffs.push(Scalar::one());
    for root in roots {
        let n = coeffs.len();
        // The new leading coefficient (degree n) equals the old leading
        // coefficient (degree n-1) — copy it before the in-place updates below
        // overwrite it.
        let leading = *coeffs.last().unwrap();
        coeffs.push(leading); // extend for the new degree-n term
        for d in (1..n).rev() {
            coeffs[d] = coeffs[d - 1] - root * coeffs[d]; // middle terms
        }
        coeffs[0] *= -root; // constant term
    }
    coeffs
}

// ── Target ────────────────────────────────────────────────────────────────────

pub struct Target {
    marked_positions: Vec<Scalar>,
    bf_config: BloomFilterConfig,
    accum_degree: usize,
    sk1: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
    /// Matching counter, incremented on each genuine match.
    pub state: u64,
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
}

impl Target {
    /// Construct a Target from its secret key share and the public parameters.
    pub fn new(
        marked_positions: Vec<Scalar>,
        bf_config: BloomFilterConfig,
        accum_degree: usize,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
    ) -> Self {
        let pk = combine_public_keys(&pk1, &pk2);
        let max_degree = marked_positions.len();
        let cap = crate::bf::bp_capacity(max_degree, bf_config);
        Target {
            marked_positions,
            bf_config,
            accum_degree,
            sk1,
            pk1,
            pk2,
            pk,
            state: 0,
            pc_gens: PedersenGens::default(),
            bp_gens: BulletproofGens::new(cap, 1),
        }
    }

    // ── Setup ─────────────────────────────────────────────────────────────────

    /// `THEnc[pk](T-poly)`: construct P(X) from the Bloom filter positions
    /// whose bits are `1`, then encrypt.
    fn build_poly_ctext(&self, rng: &mut OsRng) -> EncryptedPoly {
        let coeffs = poly_from_roots(&self.marked_positions);
        encrypt_poly(rng, &self.pk, &coeffs)
    }

    /// Build the initial accumulated polynomial ciphertext:
    /// an encryption of the constant polynomial `1`, padded with encrypted `0`s
    /// through the configured accumulated-polynomial degree. This degree stays
    /// fixed across outsourcing and every subsequent rerandomized update.
    fn build_accum_ctext(&self, rng: &mut OsRng) -> EncryptedPoly {
        let mut coeffs = Vec::with_capacity(self.accum_degree + 1);
        coeffs.push(encrypt_one(rng, &self.pk));
        while coeffs.len() < self.accum_degree + 1 {
            coeffs.push(encrypt_zero(rng, &self.pk));
        }
        EncryptedPoly(coeffs)
    }

    // ── Protocol round ────────────────────────────────────────────────────────

    /// One complete round: verify proof, test match, produce next accumulated ciphertext.
    ///
    /// Returns `(next_accum, is_match)`.
    pub(crate) fn process_round(
        &mut self,
        rng: &mut OsRng,
        current: &EncryptedPoly,
        current_accum: &EncryptedPoly,
        msg: &MonitorToTarget,
    ) -> Result<(EncryptedPoly, bool), String> {
        let next_accum = msg.accum_next.to_native()?;
        let accum_eval_masked = msg.accum_eval_masked.to_native()?;
        let accum_eval_ctext = msg.accum_eval_ctext.to_native()?;
        let scaled_eval = msg.scaled_eval.to_native()?;
        let m_poly_ct = msg.m_poly_ctext.to_native()?;

        if next_accum.0.len() != current_accum.0.len() {
            return Err("next_accum length mismatch".to_string());
        }

        let _y = bfproof::verify_round(
            &self.pc_gens,
            &self.bp_gens,
            self.bf_config,
            &self.pk,
            &self.pk1,
            &self.pk2,
            current,
            &scaled_eval,
            &m_poly_ct,
            &accum_eval_masked,
            &accum_eval_ctext,
            current_accum,
            &next_accum,
            &msg.round_proof,
        )?;

        // T.2  THTest[sk1]{0}{MPolyCtext}:
        //      MPolyCtext was partially decrypted by the monitor (THDec[sk2]),
        //      so it lives in THCtextSpace[pk1].  test_zero finishes the job.
        let is_match = test_zero(&self.sk1, &m_poly_ct);
        let accum_is_nonzero = !test_zero(&self.sk1, &accum_eval_ctext);
        let should_advance = is_match && accum_is_nonzero;

        // T.3  Advance the accumulated polynomial only when the accum witness
        //      stays non-zero and the membership test matched.
        let base_accum = if should_advance {
            self.state += 1;
            &next_accum
        } else {
            current_accum
        };
        let (rerand_accum, _) = rerandomize_poly_with_witness(rng, &self.pk, base_accum);
        if rerand_accum.0.len() != current_accum.0.len() {
            return Err("rerandomized accum length mismatch".to_string());
        }

        Ok((rerand_accum, is_match))
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
        let current = self.build_poly_ctext(&mut rng);
        let mut current_accum = self.build_accum_ctext(&mut rng);
        send_msg(
            &mut s,
            &TargetToMonitor::Outsource {
                t_poly_ct: WireEncryptedPoly::from_native(&current),
                accum: WireEncryptedPoly::from_native(&current_accum),
            },
        )?;
        let outsource_ms = t_outsource_start.elapsed().as_secs_f64() * 1000.0;
        eprintln!("[Target] Outsource Time (compute -> send): {outsource_ms:.3} ms");
        eprintln!(
            "[Target] Sent TPolyCtext for {} marked Bloom positions",
            self.marked_positions.len()
        );

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

            match self.process_round(&mut rng, &current, &current_accum, &msg) {
                Ok((next_accum, matched)) => {
                    eprintln!("[Target] match={matched}  state={}", self.state);
                    current_accum = next_accum;
                    send_msg(
                        &mut s,
                        &TargetToMonitor::NextRound {
                            accum: WireEncryptedPoly::from_native(&current_accum),
                        },
                    )?;
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
    use crate::bf::bloom::BloomFilterConfig;
    use crate::bf::monitor::Monitor;
    use crate::crypto::elgamal::generate_key_share;

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
            if crate::bf::bloom::scalar_positions(input, config) == vec![target_position] {
                return input;
            }
        }
        panic!("no scalar input found for target position {target_position:?}");
    }

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
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);

        let t_set = vec![Scalar::from(7u64), Scalar::from(42u64)];
        let mut target = Target::new(
            t_set.clone(),
            test_config(),
            5,
            sk1,
            pk1.clone(),
            pk2.clone(),
        );
        let poly_ct = target.build_poly_ctext(&mut rng);
        let accum_ct = target.build_accum_ctext(&mut rng);
        let monitor = Monitor::new(
            input_for_position(Scalar::from(7u64)),
            test_config(),
            sk2,
            pk1,
            pk2,
            t_set.len(),
        );

        let msg = monitor
            .compute_round(
                &mut rng,
                &WireEncryptedPoly::from_native(&poly_ct),
                &WireEncryptedPoly::from_native(&accum_ct),
            )
            .unwrap();

        let (next_accum_out, matched) = target
            .process_round(&mut rng, &poly_ct, &accum_ct, &msg)
            .unwrap();
        assert!(matched, "7 should be detected as a match");
        assert_eq!(target.state, 1);
        assert_eq!(
            next_accum_out.0.len(),
            accum_ct.0.len(),
            "accum length should stay constant"
        );
    }

    /// Non-match round: state stays at 0.
    #[test]
    fn test_process_round_no_match() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);

        let t_set = vec![Scalar::from(7u64)];
        let mut target = Target::new(
            t_set.clone(),
            test_config(),
            5,
            sk1,
            pk1.clone(),
            pk2.clone(),
        );
        let poly_ct = target.build_poly_ctext(&mut rng);
        let accum_ct = target.build_accum_ctext(&mut rng);
        let monitor = Monitor::new(
            Scalar::from(9u64),
            test_config(),
            sk2,
            pk1,
            pk2,
            t_set.len(),
        );
        let msg = monitor
            .compute_round(
                &mut rng,
                &WireEncryptedPoly::from_native(&poly_ct),
                &WireEncryptedPoly::from_native(&accum_ct),
            )
            .unwrap();

        let (next_accum_out, matched) = target
            .process_round(&mut rng, &poly_ct, &accum_ct, &msg)
            .unwrap();
        assert!(!matched, "9 should not match");
        assert_eq!(target.state, 0);
        assert_eq!(
            next_accum_out.0.len(),
            accum_ct.0.len(),
            "accum length should stay constant"
        );
    }

    #[test]
    fn test_build_accum_ctext_uses_fixed_degree() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (_sk2, pk2) = generate_key_share(&mut rng);

        let accum_degree = 5;
        let target = Target::new(
            vec![Scalar::from(7u64)],
            test_config(),
            accum_degree,
            sk1,
            pk1,
            pk2,
        );
        let accum_ct = target.build_accum_ctext(&mut rng);

        assert_eq!(
            accum_ct.0.len(),
            accum_degree + 1,
            "outsourced accum polynomial should be padded to the configured fixed degree"
        );
    }

    #[test]
    fn test_process_round_rejects_tampered_accum_witness() {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);

        let t_set = vec![Scalar::from(7u64), Scalar::from(42u64)];
        let mut target = Target::new(
            t_set.clone(),
            test_config(),
            5,
            sk1,
            pk1.clone(),
            pk2.clone(),
        );
        let poly_ct = target.build_poly_ctext(&mut rng);
        let accum_ct = target.build_accum_ctext(&mut rng);
        let monitor = Monitor::new(
            Scalar::from(7u64),
            test_config(),
            sk2,
            pk1,
            pk2,
            t_set.len(),
        );

        let msg = monitor
            .compute_round(
                &mut rng,
                &WireEncryptedPoly::from_native(&poly_ct),
                &WireEncryptedPoly::from_native(&accum_ct),
            )
            .unwrap();

        let mut tampered_next = msg;
        tampered_next.accum_next = WireEncryptedPoly::from_native(&accum_ct);
        assert!(
            target
                .process_round(&mut rng, &poly_ct, &accum_ct, &tampered_next)
                .is_err(),
            "tampering with accum_next should break the sigma proof binding to the hidden y"
        );

        let msg = monitor
            .compute_round(
                &mut rng,
                &WireEncryptedPoly::from_native(&poly_ct),
                &WireEncryptedPoly::from_native(&accum_ct),
            )
            .unwrap();
        let mut tampered_eval = msg;
        tampered_eval.accum_eval_masked =
            WireCiphertext::from_native(&tampered_eval.m_poly_ctext.to_native().unwrap());
        assert!(
            target
                .process_round(&mut rng, &poly_ct, &accum_ct, &tampered_eval)
                .is_err(),
            "tampering with accum_eval should break the sigma proof binding to the hidden y"
        );
    }
}
