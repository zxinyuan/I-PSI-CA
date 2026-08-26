use std::io::{self, IoSlice, Read, Write};
use std::net::{TcpListener, TcpStream};

use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use curve25519_dalek_ng::scalar::Scalar;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::crypto::bulletproof as bp;
use crate::crypto::elgamal::{
    combine_public_keys, encrypt_one, encrypt_poly, encrypt_zero, rerandomize_poly_with_witness,
    test_zero, Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare, SecretKeyShare,
};
use crate::crypto::sigma_bullet as sb;

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireMonitorProof {
    pub power_chain: WireEvalChainProof,
    pub mask_nonzero: WireEvalChainProof,
}

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

    pub fn to_proof(&self) -> Result<sb::GlueProof, String> {
        let z_e: Result<Vec<_>, _> = self
            .z_e
            .iter()
            .map(|b| Scalar::from_canonical_bytes(*b).ok_or("z_e: non-canonical scalar"))
            .collect();
        Ok(sb::GlueProof {
            alpha_tag: CompressedRistretto::from_slice(&self.alpha_tag),
            a_t: CompressedRistretto::from_slice(&self.a_t),
            z_e: z_e?,
            z_alpha: Scalar::from_canonical_bytes(self.z_alpha)
                .ok_or("z_alpha: non-canonical scalar")?,
            z_y_blind: Scalar::from_canonical_bytes(self.z_y_blind)
                .ok_or("z_y_blind: non-canonical scalar")?,
        })
    }
}

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
            glue: self.glue.to_proof()?,
        })
    }
}

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
    pub accum_chain_proof: WireEvalChainProof,
    pub accum_glue_a_t: [u8; 32],
    pub accum_glue_z_e: Vec<[u8; 32]>,
    pub accum_glue_z_alpha: [u8; 32],
    pub accum_glue_z_y_blind: [u8; 32],
    pub accum_partial_a: [u8; 32],
    pub accum_partial_z1: [u8; 32],
    pub accum_partial_z2: [u8; 32],
    pub accum_mul_a1: [u8; 32],
    pub accum_mul_a2: [u8; 32],
    pub accum_mul_a_m: [u8; 32],
    pub accum_mul_s_y: [u8; 32],
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
            accum_chain_proof: WireEvalChainProof::from_proof(&p.accum_chain_proof),
            accum_glue_a_t: p.accum_glue_a_t.to_bytes(),
            accum_glue_z_e: p.accum_glue_z_e.iter().map(|s| s.to_bytes()).collect(),
            accum_glue_z_alpha: p.accum_glue_z_alpha.to_bytes(),
            accum_glue_z_y_blind: p.accum_glue_z_y_blind.to_bytes(),
            accum_partial_a: p.accum_partial_a.to_bytes(),
            accum_partial_z1: p.accum_partial_z1.to_bytes(),
            accum_partial_z2: p.accum_partial_z2.to_bytes(),
            accum_mul_a1: p.accum_mul_a1.to_bytes(),
            accum_mul_a2: p.accum_mul_a2.to_bytes(),
            accum_mul_a_m: p.accum_mul_a_m.to_bytes(),
            accum_mul_s_y: p.accum_mul_s_y.to_bytes(),
        }
    }

    pub fn to_proof(&self) -> Result<sb::CombinedSigmaProof, String> {
        let glue_z_e: Result<Vec<_>, _> = self
            .glue_z_e
            .iter()
            .map(|b| Scalar::from_canonical_bytes(*b).ok_or("glue_z_e: non-canonical scalar"))
            .collect();
        let accum_glue_z_e: Result<Vec<_>, _> = self
            .accum_glue_z_e
            .iter()
            .map(|b| Scalar::from_canonical_bytes(*b).ok_or("accum_glue_z_e: non-canonical scalar"))
            .collect();
        Ok(sb::CombinedSigmaProof {
            chain_proof: self.chain_proof.to_proof()?,
            alpha_tag: CompressedRistretto::from_slice(&self.alpha_tag),
            glue_a_t: CompressedRistretto::from_slice(&self.glue_a_t),
            glue_z_e: glue_z_e?,
            glue_z_alpha: Scalar::from_canonical_bytes(self.glue_z_alpha)
                .ok_or("glue_z_alpha: non-canonical scalar")?,
            glue_z_y_blind: Scalar::from_canonical_bytes(self.glue_z_y_blind)
                .ok_or("glue_z_y_blind: non-canonical scalar")?,
            partial_a: CompressedRistretto::from_slice(&self.partial_a),
            partial_z1: Scalar::from_canonical_bytes(self.partial_z1)
                .ok_or("partial_z1: non-canonical scalar")?,
            partial_z2: Scalar::from_canonical_bytes(self.partial_z2)
                .ok_or("partial_z2: non-canonical scalar")?,
            accum_chain_proof: self.accum_chain_proof.to_proof()?,
            accum_glue_a_t: CompressedRistretto::from_slice(&self.accum_glue_a_t),
            accum_glue_z_e: accum_glue_z_e?,
            accum_glue_z_alpha: Scalar::from_canonical_bytes(self.accum_glue_z_alpha)
                .ok_or("accum_glue_z_alpha: non-canonical scalar")?,
            accum_glue_z_y_blind: Scalar::from_canonical_bytes(self.accum_glue_z_y_blind)
                .ok_or("accum_glue_z_y_blind: non-canonical scalar")?,
            accum_partial_a: CompressedRistretto::from_slice(&self.accum_partial_a),
            accum_partial_z1: Scalar::from_canonical_bytes(self.accum_partial_z1)
                .ok_or("accum_partial_z1: non-canonical scalar")?,
            accum_partial_z2: Scalar::from_canonical_bytes(self.accum_partial_z2)
                .ok_or("accum_partial_z2: non-canonical scalar")?,
            accum_mul_a1: CompressedRistretto::from_slice(&self.accum_mul_a1),
            accum_mul_a2: CompressedRistretto::from_slice(&self.accum_mul_a2),
            accum_mul_a_m: CompressedRistretto::from_slice(&self.accum_mul_a_m),
            accum_mul_s_y: Scalar::from_canonical_bytes(self.accum_mul_s_y)
                .ok_or("accum_mul_s_y: non-canonical scalar")?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TargetToMonitor {
    pub t_poly_ct: WireEncryptedPoly,
    pub accum: WireEncryptedPoly,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MonitorToTarget {
    pub next_accum: WireEncryptedPoly,
    pub accum_scaled_eval: WireCiphertext,
    pub accum_m_poly_ctext: WireCiphertext,
    pub scaled_eval: WireCiphertext,
    pub m_poly_ctext: WireCiphertext,
    pub round_proof: WireCombinedSigmaProof,
}

pub fn send_msg<T: Serialize>(stream: &mut TcpStream, msg: &T) -> io::Result<()> {
    let bytes =
        bincode::serialize(msg).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = (bytes.len() as u32).to_be_bytes();
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

pub fn poly_from_roots(roots: &[Scalar]) -> Vec<Scalar> {
    let mut coeffs = Vec::with_capacity(roots.len() + 1);
    coeffs.push(Scalar::one());
    for root in roots {
        let n = coeffs.len();
        let leading = *coeffs.last().unwrap();
        coeffs.push(leading);
        for d in (1..n).rev() {
            coeffs[d] = coeffs[d - 1] - root * coeffs[d];
        }
        coeffs[0] *= -root;
    }
    coeffs
}

pub struct Target {
    t_set: Vec<Scalar>,
    accum_degree: usize,
    sk1: SecretKeyShare,
    pk1: PublicKeyShare,
    pk2: PublicKeyShare,
    pk: PublicKey,
    pub state: u64,
    pc_gens: PedersenGens,
    bp_gens: BulletproofGens,
}

impl Target {
    pub fn new(
        t_set: Vec<Scalar>,
        accum_degree: usize,
        sk1: SecretKeyShare,
        pk1: PublicKeyShare,
        pk2: PublicKeyShare,
    ) -> Self {
        let pk = combine_public_keys(&pk1, &pk2);
        let n = t_set.len().max(accum_degree) + 2;
        let cap = 1usize << (usize::BITS - (2 * n).leading_zeros()) as usize;
        let cap = cap.max(64);
        Target {
            t_set,
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

    fn build_poly_ctext(&self, rng: &mut OsRng) -> EncryptedPoly {
        let coeffs = poly_from_roots(&self.t_set);
        encrypt_poly(rng, &self.pk, &coeffs)
    }

    fn build_accum_ctext(&self, rng: &mut OsRng) -> EncryptedPoly {
        let mut coeffs = Vec::with_capacity(self.accum_degree + 1);
        coeffs.push(encrypt_one(rng, &self.pk));
        while coeffs.len() < self.accum_degree + 1 {
            coeffs.push(encrypt_zero(rng, &self.pk));
        }
        EncryptedPoly(coeffs)
    }

    pub(crate) fn process_round(
        &mut self,
        rng: &mut OsRng,
        current: &EncryptedPoly,
        current_accum: &EncryptedPoly,
        msg: &MonitorToTarget,
    ) -> Result<(EncryptedPoly, bool), String> {
        let next_accum = msg.next_accum.to_native()?;
        let accum_scaled_eval = msg.accum_scaled_eval.to_native()?;
        let accum_m_poly_ct = msg.accum_m_poly_ctext.to_native()?;
        let scaled_eval = msg.scaled_eval.to_native()?;
        let m_poly_ct = msg.m_poly_ctext.to_native()?;

        if next_accum.0.len() != current_accum.0.len() {
            return Err("next_accum length mismatch".to_string());
        }

        let round_proof = msg.round_proof.to_proof()?;
        sb::verify_round(
            &self.pc_gens,
            &self.bp_gens,
            &self.pk,
            &self.pk1,
            &self.pk2,
            &current.0,
            &scaled_eval,
            &m_poly_ct,
            &accum_scaled_eval,
            &accum_m_poly_ct,
            current_accum,
            &next_accum,
            &round_proof,
        )
        .map_err(|e| format!("round proof invalid: {e}"))?;

        let is_match = test_zero(&self.sk1, &m_poly_ct);
        if is_match {
            self.state += 1;
        }

        let (rerand_accum, _) = rerandomize_poly_with_witness(rng, &self.pk, &next_accum);
        if rerand_accum.0.len() != current_accum.0.len() {
            return Err("rerandomized accum length mismatch".to_string());
        }

        Ok((rerand_accum, is_match))
    }

    pub fn run(&mut self, addr: &str, rounds: usize) -> io::Result<()> {
        let listener = TcpListener::bind(addr)?;
        eprintln!("[Target] Listening on {addr}");
        let (stream, peer) = listener.accept()?;
        eprintln!("[Target] Monitor connected from {peer}");
        self.handle(stream, rounds)
    }

    fn handle(&mut self, mut s: TcpStream, rounds: usize) -> io::Result<()> {
        let mut rng = OsRng;

        let t_deploy = std::time::Instant::now();
        let current = self.build_poly_ctext(&mut rng);
        let mut deploy_ms = None;
        let mut current_accum = self.build_accum_ctext(&mut rng);
        eprintln!(
            "[Target] Built TPolyCtext (deg {}), Accum (deg {})",
            self.t_set.len(),
            self.accum_degree
        );

        for round in 1..=rounds {
            eprintln!("[Target] Round {round}/{rounds}");

            let outgoing = TargetToMonitor {
                t_poly_ct: WireEncryptedPoly::from_native(&current),
                accum: WireEncryptedPoly::from_native(&current_accum),
            };
            let sent_bytes = bincode::serialized_size(&outgoing)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                + 4;

            let t_send = std::time::Instant::now();
            send_msg(&mut s, &outgoing)?;
            if deploy_ms.is_none() {
                deploy_ms = Some(t_deploy.elapsed().as_secs_f64() * 1000.0);
            }

            let msg: MonitorToTarget = match recv_msg(&mut s) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    eprintln!("[Target] Monitor disconnected. state = {}", self.state);
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            let latency_ms = t_send.elapsed().as_secs_f64() * 1000.0;

            let recv_bytes = bincode::serialized_size(&msg)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                + 4;

            eprintln!(
                "[Target] Latency (send t_poly_ct+accum -> recv monitor reply): {latency_ms:.3} ms"
            );
            eprintln!(
                "[Target] Network Traffic: sent={:.2} KB  recv={:.2} KB",
                sent_bytes as f64 / 1024.0,
                recv_bytes as f64 / 1024.0,
            );
            if let Some(deploy_ms) = deploy_ms.take() {
                eprintln!(
                    "[Target] Deploy Time (generate t_poly_ct -> first forward to monitor): {deploy_ms:.3} ms"
                );
            }

            let t_verify = std::time::Instant::now();
            let round_result = self.process_round(&mut rng, &current, &current_accum, &msg);
            let verification_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
            eprintln!("[Target] Verification Time: {verification_ms:.3} ms");

            match round_result {
                Ok((next_accum, matched)) => {
                    eprintln!("[Target] match={matched}  state={}", self.state);
                    current_accum = next_accum;
                }
                Err(reason) => {
                    eprintln!("[Target] Reject: {reason}");
                    return Ok(());
                }
            }
        }

        eprintln!(
            "[Target] Done after {rounds} round(s). state = {}",
            self.state
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::generate_key_share;
    use crate::crypto::elgamal::{ct_add, ct_scalar_mul, eval_poly, poly_scalar_mul};

    #[test]
    fn test_poly_roots_eval_zero() {
        let roots = [Scalar::from(2u64), Scalar::from(5u64), Scalar::from(11u64)];
        let coeffs = poly_from_roots(&roots);
        for r in &roots {
            let mut val = *coeffs.last().unwrap();
            for c in coeffs[..coeffs.len() - 1].iter().rev() {
                val = val * r + c;
            }
            assert_eq!(val, Scalar::zero(), "P({r:?}) must be zero");
        }
    }

    #[test]
    fn test_process_round_match() {
        use crate::crypto::elgamal::partial_decrypt_with_witness;
        use crate::crypto::sigma_bullet as sb_mod;
        use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT as G;

        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);

        let t_set = vec![Scalar::from(7u64), Scalar::from(42u64)];
        let mut target = Target::new(t_set.clone(), 5, sk1, pk1, pk2.clone());
        let poly_ct = target.build_poly_ctext(&mut rng);
        let accum_ct = target.build_accum_ctext(&mut rng);

        let m = Scalar::from(7u64);
        let next_accum = poly_scalar_mul(&accum_ct, &m);
        let accum_eval = eval_poly(&accum_ct, &m);
        let eval_ct = eval_poly(&poly_ct, &m);
        let accum_mask = Scalar::from(29u64);
        let accum_scaled_no_blind = ct_scalar_mul(&accum_eval, &accum_mask);
        let accum_enc_zero_mask = Ciphertext {
            c1: accum_mask * G,
            c2: accum_mask * target.pk.0,
        };
        let accum_scaled = ct_add(&accum_scaled_no_blind, &accum_enc_zero_mask);
        let (accum_m_poly_ct, _accum_r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &target.pk1, &accum_scaled);
        let mask = Scalar::from(13u64);
        let scaled_no_blind = ct_scalar_mul(&eval_ct, &mask);
        let enc_zero_mask = Ciphertext {
            c1: mask * G,
            c2: mask * target.pk.0,
        };
        let scaled = ct_add(&scaled_no_blind, &enc_zero_mask);
        let (m_poly_ct, r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &target.pk1, &scaled);

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
            &accum_scaled,
            &accum_m_poly_ct,
            &accum_ct,
            &next_accum,
            m,
            mask,
            r_prime,
            accum_mask,
            _accum_r_prime,
            sk2.as_scalar(),
        )
        .expect("round prove");

        let msg = MonitorToTarget {
            next_accum: WireEncryptedPoly::from_native(&next_accum),
            accum_scaled_eval: WireCiphertext::from_native(&accum_scaled),
            accum_m_poly_ctext: WireCiphertext::from_native(&accum_m_poly_ct),
            scaled_eval: WireCiphertext::from_native(&scaled),
            m_poly_ctext: WireCiphertext::from_native(&m_poly_ct),
            round_proof: WireCombinedSigmaProof::from_proof(&round_proof),
        };

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

    #[test]
    fn test_process_round_no_match() {
        use crate::crypto::elgamal::partial_decrypt_with_witness;
        use crate::crypto::sigma_bullet as sb_mod;
        use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT as G;

        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);

        let t_set = vec![Scalar::from(7u64)];
        let mut target = Target::new(t_set.clone(), 5, sk1, pk1, pk2.clone());
        let poly_ct = target.build_poly_ctext(&mut rng);
        let accum_ct = target.build_accum_ctext(&mut rng);

        let m = Scalar::from(99u64);
        let mask = Scalar::from(5u64);
        let next_accum = poly_scalar_mul(&accum_ct, &m);
        let accum_eval = eval_poly(&accum_ct, &m);
        let accum_mask = Scalar::from(31u64);
        let accum_scaled_no_blind = ct_scalar_mul(&accum_eval, &accum_mask);
        let accum_enc_zero_mask = Ciphertext {
            c1: accum_mask * G,
            c2: accum_mask * target.pk.0,
        };
        let accum_scaled = ct_add(&accum_scaled_no_blind, &accum_enc_zero_mask);
        let (accum_m_poly_ct, _accum_r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &target.pk1, &accum_scaled);
        let scaled_no_blind = ct_scalar_mul(&eval_poly(&poly_ct, &m), &mask);
        let enc_zero_mask = Ciphertext {
            c1: mask * G,
            c2: mask * target.pk.0,
        };
        let scaled = ct_add(&scaled_no_blind, &enc_zero_mask);
        let (m_poly_ct, r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &target.pk1, &scaled);

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
            &accum_scaled,
            &accum_m_poly_ct,
            &accum_ct,
            &next_accum,
            m,
            mask,
            r_prime,
            accum_mask,
            _accum_r_prime,
            sk2.as_scalar(),
        )
        .unwrap();

        let msg = MonitorToTarget {
            next_accum: WireEncryptedPoly::from_native(&next_accum),
            accum_scaled_eval: WireCiphertext::from_native(&accum_scaled),
            accum_m_poly_ctext: WireCiphertext::from_native(&accum_m_poly_ct),
            scaled_eval: WireCiphertext::from_native(&scaled),
            m_poly_ctext: WireCiphertext::from_native(&m_poly_ct),
            round_proof: WireCombinedSigmaProof::from_proof(&round_proof),
        };

        let (next_accum_out, matched) = target
            .process_round(&mut rng, &poly_ct, &accum_ct, &msg)
            .unwrap();
        assert!(!matched, "99 should not match");
        assert_eq!(target.state, 0);
        assert_eq!(
            next_accum_out.0.len(),
            accum_ct.0.len(),
            "accum length should stay constant"
        );
    }
}
