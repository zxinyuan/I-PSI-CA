use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Verifier},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::{
    constants::{RISTRETTO_BASEPOINT_POINT as G, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::MultiscalarMul,
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::bf::bloom::{scalar_positions, scalar_to_usize, BloomFilterConfig};
use crate::crypto::elgamal::{
    ct_add, ct_scalar_mul, eval_poly, poly_add, Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare,
};
use crate::crypto::sigma_bullet as sb;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PositionHashProof {
    pub proof_bytes: Vec<u8>,
    pub y_comm: [u8; 32],
    pub position_comms: Vec<[u8; 32]>,
    pub inv_y_comm: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PositionGlueProof {
    pub a_tag: [u8; 32],
    pub a_comm: [u8; 32],
    pub z_y: [u8; 32],
    pub z_blind: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireEvalChainProof {
    pub proof_bytes: Vec<u8>,
    pub e_comms: Vec<[u8; 32]>,
    pub y_comm: [u8; 32],
    pub inv_en_comm: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub accum_partial_a: [u8; 32],
    pub accum_partial_z1: [u8; 32],
    pub accum_partial_z2: [u8; 32],
    pub accum_mul_a1: [u8; 32],
    pub accum_mul_a2: [u8; 32],
    pub accum_mul_a_m: [u8; 32],
    pub accum_mul_s_y: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundProof {
    pub aggregate_eval_proof: WireCombinedSigmaProof,
    pub position_proof: PositionHashProof,
    pub position_glue: PositionGlueProof,
}

struct PositionWitness {
    proof: PositionHashProof,
    y_blind: Scalar,
}

pub struct RoundWitness {
    pub aggregate_poly: EncryptedPoly,
    pub positions: Vec<Scalar>,
}

#[allow(clippy::too_many_arguments)]
pub fn prove_round<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    bf_config: BloomFilterConfig,
    t_poly: &EncryptedPoly,
    y: Scalar,
    eval_mask: Scalar,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    m_poly_ct: &Ciphertext,
    accum_scaled_eval: &Ciphertext,
    accum_m_poly_ct: &Ciphertext,
    accum_in: &EncryptedPoly,
    next_accum: &EncryptedPoly,
    mpoly_r_prime: Scalar,
    accum_r_prime: Scalar,
    sk2: &Scalar,
) -> Result<(Ciphertext, Ciphertext, RoundProof, RoundWitness), R1CSError> {
    let positions = scalar_positions(y, bf_config);
    let aggregate_poly = aggregate_poly_by_positions(t_poly, bf_config).map_err(|e| R1CSError::GadgetError {
        description: e,
    })?;
    let aggregate_eval = eval_poly(&aggregate_poly, &y);
    let scaled_eval = mask_eval(&aggregate_eval, eval_mask, pk);

    let aggregate_eval_proof = sb::prove_round(
        rng,
        pc_gens,
        bp_gens,
        pk,
        pk1,
        pk2,
        &aggregate_poly.0,
        &scaled_eval,
        m_poly_ct,
        accum_scaled_eval,
        accum_m_poly_ct,
        accum_in,
        next_accum,
        y,
        eval_mask,
        mpoly_r_prime,
        accum_r_prime,
        sk2,
    )?;

    let position_witness = prove_positions(rng, pc_gens, bp_gens, bf_config, y, &positions)?;
    let position_glue = prove_position_glue(
        rng,
        pc_gens,
        &position_witness.proof,
        position_witness.y_blind,
        &aggregate_eval_proof.alpha_tag,
        y,
    );

    Ok((
        scaled_eval,
        aggregate_eval,
        RoundProof {
            aggregate_eval_proof: WireCombinedSigmaProof::from_proof(&aggregate_eval_proof),
            position_proof: position_witness.proof,
            position_glue,
        },
        RoundWitness {
            aggregate_poly,
            positions,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_round(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    bf_config: BloomFilterConfig,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    t_poly: &EncryptedPoly,
    scaled_eval: &Ciphertext,
    m_poly_ct: &Ciphertext,
    accum_scaled_eval: &Ciphertext,
    accum_m_poly_ct: &Ciphertext,
    current_accum: &EncryptedPoly,
    next_accum: &EncryptedPoly,
    round_proof: &RoundProof,
) -> Result<(), String> {
    let aggregate_eval_proof = round_proof.aggregate_eval_proof.to_proof()?;
    let aggregate_poly = aggregate_poly_by_positions(t_poly, bf_config)?;

    sb::verify_round(
        pc_gens,
        bp_gens,
        pk,
        pk1,
        pk2,
        &aggregate_poly.0,
        scaled_eval,
        m_poly_ct,
        accum_scaled_eval,
        accum_m_poly_ct,
        current_accum,
        next_accum,
        &aggregate_eval_proof,
    )
    .map_err(|e| format!("aggregate sigma-bullet invalid: {e}"))?;

    verify_positions(pc_gens, bp_gens, bf_config, &round_proof.position_proof)
        .map_err(|e| format!("position proof invalid: {e}"))?;

    verify_position_glue(
        pc_gens,
        &round_proof.position_proof,
        &round_proof.position_glue,
        &aggregate_eval_proof.alpha_tag,
    )
    .map_err(|e| format!("position glue invalid: {e}"))?;

    Ok(())
}

pub fn aggregate_poly_by_positions(
    poly: &EncryptedPoly,
    bf_config: BloomFilterConfig,
) -> Result<EncryptedPoly, String> {
    let offsets: Vec<Scalar> = (0..bf_config.hash_count)
        .map(|offset| Scalar::from(offset as u64))
        .collect();
    aggregate_poly_by_offsets(poly, &offsets)
}

fn aggregate_poly_by_offsets(poly: &EncryptedPoly, offsets: &[Scalar]) -> Result<EncryptedPoly, String> {
    if poly.0.is_empty() {
        return Err("polynomial must not be empty".to_string());
    }

    let degree_len = poly.0.len();
    let zero_ct = ct_scalar_mul(&poly.0[0], &Scalar::zero());
    let mut result = EncryptedPoly(vec![zero_ct; degree_len]);

    for offset in offsets {
        let shifted = shift_poly(poly, offset)?;
        result = poly_add(&result, &shifted);
    }
    Ok(result)
}

fn shift_poly(poly: &EncryptedPoly, offset: &Scalar) -> Result<EncryptedPoly, String> {
    if poly.0.is_empty() {
        return Err("polynomial must not be empty".to_string());
    }

    let degree_len = poly.0.len();
    let zero_ct = ct_scalar_mul(&poly.0[0], &Scalar::zero());
    let mut result = vec![zero_ct; degree_len];
    let mut binom = vec![Scalar::zero(); degree_len];
    binom[0] = Scalar::one();
    let mut offset_pows = vec![Scalar::one(); degree_len];
    for p in 1..degree_len {
        offset_pows[p] = offset_pows[p - 1] * offset;
    }

    for d in 0..degree_len {
        if d > 0 {
        for m in (1..=d).rev() {
            let prev = binom[m - 1];
            binom[m] += prev;
        }
        }
        for m in 0..=d {
            let factor = binom[m] * offset_pows[d - m];
            let term = ct_scalar_mul(&poly.0[d], &factor);
            result[m] = ct_add(&result[m], &term);
        }
    }

    Ok(EncryptedPoly(result))
}

fn mask_eval(eval_ct: &Ciphertext, mask: Scalar, pk: &PublicKey) -> Ciphertext {
    let scaled_no_blind = ct_scalar_mul(eval_ct, &mask);
    let enc_zero_mask = Ciphertext {
        c1: &mask * &RISTRETTO_BASEPOINT_TABLE,
        c2: mask * pk.0,
    };
    ct_add(&scaled_no_blind, &enc_zero_mask)
}

fn prove_positions<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    bf_config: BloomFilterConfig,
    y: Scalar,
    positions: &[Scalar],
) -> Result<PositionWitness, R1CSError> {
    if positions.len() != bf_config.hash_count {
        return Err(R1CSError::GadgetError {
            description: "position vector length does not match hash count".to_string(),
        });
    }
    if scalar_to_usize(y) == 0 || scalar_to_usize(y) > (bf_config.bloom_filter_size - bf_config.hash_count + 1) {
        return Err(R1CSError::GadgetError {
            description: "hidden y lies outside the supported Bloom domain".to_string(),
        });
    }

    let mut transcript = Transcript::new(b"I-PSI-CA::bf_position_hash_v2");
    let mut prover = Prover::new(pc_gens, &mut transcript);

    let y_blind = Scalar::random(rng);
    let (y_comm, y_var) = prover.commit(y, y_blind);

    let mut position_comms = Vec::with_capacity(positions.len());
    let mut position_vars = Vec::with_capacity(positions.len());
    for position in positions {
        let blind = Scalar::random(rng);
        let (comm, var) = prover.commit(*position, blind);
        position_comms.push(comm);
        position_vars.push(var);
    }

    let inv_y = y.invert();
    let (inv_y_comm, inv_y_var) = prover.commit(inv_y, Scalar::random(rng));

    for (hash_index, position_var) in position_vars.iter().copied().enumerate() {
        let offset = Scalar::from(hash_index as u64);
        prover.constrain(LinearCombination::from(position_var) - LinearCombination::from(y_var) - offset);
    }
    let (_, _, prod) = prover.multiply(LinearCombination::from(y_var), LinearCombination::from(inv_y_var));
    prover.constrain(LinearCombination::from(prod) - Scalar::one());

    let proof = prover.prove(bp_gens)?;
    Ok(PositionWitness {
        proof: PositionHashProof {
            proof_bytes: proof.to_bytes(),
            y_comm: y_comm.to_bytes(),
            position_comms: position_comms.iter().map(|c| c.to_bytes()).collect(),
            inv_y_comm: inv_y_comm.to_bytes(),
        },
        y_blind,
    })
}

fn verify_positions(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    bf_config: BloomFilterConfig,
    proof: &PositionHashProof,
) -> Result<(), &'static str> {
    if proof.position_comms.len() != bf_config.hash_count {
        return Err("position proof length mismatch");
    }

    let mut transcript = Transcript::new(b"I-PSI-CA::bf_position_hash_v2");
    let mut verifier = Verifier::new(&mut transcript);

    let y_var = verifier.commit(CompressedRistretto::from_slice(&proof.y_comm));
    let position_vars: Vec<_> = proof
        .position_comms
        .iter()
        .map(|comm| verifier.commit(CompressedRistretto::from_slice(comm)))
        .collect();
    let inv_y_var = verifier.commit(CompressedRistretto::from_slice(&proof.inv_y_comm));

    for (hash_index, position_var) in position_vars.into_iter().enumerate() {
        let offset = Scalar::from(hash_index as u64);
        verifier.constrain(LinearCombination::from(position_var) - LinearCombination::from(y_var) - offset);
    }
    let (_, _, prod) = verifier.multiply(LinearCombination::from(y_var), LinearCombination::from(inv_y_var));
    verifier.constrain(LinearCombination::from(prod) - Scalar::one());

    let proof_native =
        R1CSProof::from_bytes(&proof.proof_bytes).map_err(|_| "position proof bytes invalid")?;
    verifier
        .verify(&proof_native, pc_gens, bp_gens)
        .map_err(|_| "position proof verification failed")
}

fn prove_position_glue<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    position_proof: &PositionHashProof,
    y_blind: Scalar,
    alpha_tag: &CompressedRistretto,
    y: Scalar,
) -> PositionGlueProof {
    let k_y = Scalar::random(rng);
    let k_blind = Scalar::random(rng);
    let a_tag = (k_y * G).compress();
    let a_comm = RistrettoPoint::multiscalar_mul(
        [k_y, k_blind],
        [pc_gens.B, pc_gens.B_blinding],
    )
    .compress();

    let challenge = position_glue_challenge(position_proof, alpha_tag, &a_tag, &a_comm);
    PositionGlueProof {
        a_tag: a_tag.to_bytes(),
        a_comm: a_comm.to_bytes(),
        z_y: (k_y + challenge * y).to_bytes(),
        z_blind: (k_blind + challenge * y_blind).to_bytes(),
    }
}

fn verify_position_glue(
    pc_gens: &PedersenGens,
    position_proof: &PositionHashProof,
    glue: &PositionGlueProof,
    alpha_tag: &CompressedRistretto,
) -> Result<(), &'static str> {
    let alpha_tag_pt = alpha_tag.decompress().ok_or("invalid alpha_tag point")?;
    let y_comm_pt = CompressedRistretto::from_slice(&position_proof.y_comm)
        .decompress()
        .ok_or("invalid y commitment point")?;
    let a_tag = CompressedRistretto::from_slice(&glue.a_tag)
        .decompress()
        .ok_or("invalid glue tag commitment")?;
    let a_comm = CompressedRistretto::from_slice(&glue.a_comm)
        .decompress()
        .ok_or("invalid glue comm commitment")?;
    let z_y = Scalar::from_canonical_bytes(glue.z_y).ok_or("invalid glue z_y")?;
    let z_blind = Scalar::from_canonical_bytes(glue.z_blind).ok_or("invalid glue z_blind")?;
    let challenge = position_glue_challenge(position_proof, alpha_tag, &a_tag.compress(), &a_comm.compress());

    if z_y * G != a_tag + challenge * alpha_tag_pt {
        return Err("position glue alpha_tag relation failed");
    }
    let lhs = RistrettoPoint::multiscalar_mul([z_y, z_blind], [pc_gens.B, pc_gens.B_blinding]);
    if lhs != a_comm + challenge * y_comm_pt {
        return Err("position glue y-commitment relation failed");
    }
    Ok(())
}

fn position_glue_challenge(
    position_proof: &PositionHashProof,
    alpha_tag: &CompressedRistretto,
    a_tag: &CompressedRistretto,
    a_comm: &CompressedRistretto,
) -> Scalar {
    let mut transcript = Transcript::new(b"I-PSI-CA::bf_position_glue_v1");
    transcript.append_message(b"y_comm", &position_proof.y_comm);
    for comm in &position_proof.position_comms {
        transcript.append_message(b"j_comm", comm);
    }
    transcript.append_message(b"alpha_tag", alpha_tag.as_bytes());
    transcript.append_message(b"a_tag", a_tag.as_bytes());
    transcript.append_message(b"a_comm", a_comm.as_bytes());
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

impl WireEvalChainProof {
    fn from_proof(p: &crate::crypto::bulletproof::EvalChainProof) -> Self {
        WireEvalChainProof {
            proof_bytes: p.proof.to_bytes(),
            e_comms: p.e_comms.iter().map(|c| c.to_bytes()).collect(),
            y_comm: p.y_comm.to_bytes(),
            inv_en_comm: p.inv_en_comm.to_bytes(),
        }
    }

    fn to_proof(&self) -> Result<crate::crypto::bulletproof::EvalChainProof, String> {
        Ok(crate::crypto::bulletproof::EvalChainProof {
            proof: R1CSProof::from_bytes(&self.proof_bytes)
                .map_err(|e| format!("R1CSProof decode: {e:?}"))?,
            e_comms: self
                .e_comms
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
            y_comm: CompressedRistretto::from_slice(&self.y_comm),
            inv_en_comm: CompressedRistretto::from_slice(&self.inv_en_comm),
        })
    }
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
