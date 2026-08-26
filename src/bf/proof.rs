use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Variable, Verifier},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::{
    constants::{RISTRETTO_BASEPOINT_POINT as G, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, MultiscalarMul, VartimeMultiscalarMul},
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::bf::bloom::{hash_params, scalar_positions, BloomFilterConfig};
use crate::crypto::bulletproof as bp;
use crate::crypto::elgamal::{
    Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare,
};
use crate::crypto::sigma::{self, PolyScalarMulProof};
use crate::crypto::sigma_bullet;

pub(crate) struct AggregateEvalWitness {
    pub term_masks: Vec<Scalar>,
    pub e_vals: Vec<Scalar>,
    pub scaled_eval: Ciphertext,
}

#[derive(Clone, Debug)]
struct EvalSumProof {
    proof: R1CSProof,
    e_comms: Vec<CompressedRistretto>,
    mask_comms: Vec<CompressedRistretto>,
    inv_mask_comms: Vec<CompressedRistretto>,
    y_comm: CompressedRistretto,
    r_comm: CompressedRistretto,
    inv_r_comm: CompressedRistretto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireEvalSumProof {
    pub proof_bytes: Vec<u8>,
    pub e_comms: Vec<[u8; 32]>,
    pub mask_comms: Vec<[u8; 32]>,
    pub inv_mask_comms: Vec<[u8; 32]>,
    pub y_comm: [u8; 32],
    pub r_comm: [u8; 32],
    pub inv_r_comm: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireAccumEvalProof {
    pub proof_bytes: Vec<u8>,
    pub e_comms: Vec<[u8; 32]>,
    pub y_comm: [u8; 32],
    pub inv_en_comm: [u8; 32],
}

struct CombinedSigmaProof {
    eval_proof: EvalSumProof,
    alpha_tag: CompressedRistretto,
    mask_a_tags: Vec<CompressedRistretto>,
    mask_a_comms: Vec<CompressedRistretto>,
    mask_z: Vec<Scalar>,
    mask_z_blind: Vec<Scalar>,
    glue_a_t: CompressedRistretto,
    glue_z_e: Vec<Scalar>,
    glue_z_alpha: Scalar,
    glue_z_y_blind: Scalar,
    partial_a: CompressedRistretto,
    partial_z1: Scalar,
    partial_z2: Scalar,
    accum_chain_proof: bp::EvalChainProof,
    accum_glue_a_t: CompressedRistretto,
    accum_glue_z_e: Vec<Scalar>,
    accum_glue_z_alpha: Scalar,
    accum_glue_z_y_blind: Scalar,
    accum_partial_a: CompressedRistretto,
    accum_partial_z1: Scalar,
    accum_partial_z2: Scalar,
    accum_mul_a1: CompressedRistretto,
    accum_mul_a2: CompressedRistretto,
    accum_mul_a_m: CompressedRistretto,
    accum_mul_s_y: Scalar,
}

pub(crate) struct RoundProofPrecomputation {
    eval_proof: EvalSumProof,
    y_blind: Scalar,
    e_vals: Vec<Scalar>,
    term_masks: Vec<Scalar>,
    mask_blinds: Vec<Scalar>,
    y: Scalar,
    k_e: Vec<Scalar>,
    k_alpha: Scalar,
    k_y_blind: Scalar,
    alpha_tag_pt: RistrettoPoint,
    alpha_tag: CompressedRistretto,
    mask_k: Vec<Scalar>,
    mask_k_blind: Vec<Scalar>,
    mask_a_tags: Vec<CompressedRistretto>,
    mask_a_comms: Vec<CompressedRistretto>,
    glue_a_t: CompressedRistretto,
    k_sk2: Scalar,
    k_r_prime: Scalar,
    partial_a: CompressedRistretto,
    mpoly_r_prime: Scalar,
    sk2: Scalar,
    transcript: Transcript,
}

#[derive(Clone, Copy, Debug)]
struct RoundBatchScalars {
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    beta_pd: Scalar,
    gamma_pd: Scalar,
    beta_accum_y: Scalar,
    beta_accum_c1: Scalar,
    beta_accum_c2: Scalar,
    beta_accum_pd: Scalar,
    gamma_accum_pd: Scalar,
    beta_accum_mul: Scalar,
    gamma_accum_mul: Scalar,
    challenge: Scalar,
    rho_glue: Scalar,
    rho_mask_bridge: Scalar,
    rho_partial: Scalar,
    rho_accum_glue: Scalar,
    rho_accum_partial: Scalar,
    rho_accum_mul: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireCombinedSigmaProof {
    pub eval_proof: WireEvalSumProof,
    pub alpha_tag: [u8; 32],
    pub mask_a_tags: Vec<[u8; 32]>,
    pub mask_a_comms: Vec<[u8; 32]>,
    pub mask_z: Vec<[u8; 32]>,
    pub mask_z_blind: Vec<[u8; 32]>,
    pub glue_a_t: [u8; 32],
    pub glue_z_e: Vec<[u8; 32]>,
    pub glue_z_alpha: [u8; 32],
    pub glue_z_y_blind: [u8; 32],
    pub partial_a: [u8; 32],
    pub partial_z1: [u8; 32],
    pub partial_z2: [u8; 32],
    pub accum_chain_proof: WireAccumEvalProof,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundProof {
    pub aggregate_eval_proof: WireCombinedSigmaProof,
}

fn append_point(t: &mut Transcript, label: &'static [u8], p: &RistrettoPoint) {
    t.append_message(label, p.compress().as_bytes());
}

fn append_compressed(t: &mut Transcript, label: &'static [u8], p: &CompressedRistretto) {
    t.append_message(label, p.as_bytes());
}

#[inline]
fn mul_g(s: &Scalar) -> RistrettoPoint {
    s * &RISTRETTO_BASEPOINT_TABLE
}

fn challenge_scalar(t: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"challenge", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn batch_scalar(t: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(label, &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn eval_sum_relation_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    e_vars: &[Variable],
    y_var: Variable,
    r_var: Variable,
    mask_vars: &[Variable],
    hash_count: usize,
    inv_r_var: Variable,
    inv_mask_vars: &[Variable],
) -> Result<(), R1CSError> {
    if e_vars.is_empty() {
        return Err(R1CSError::GadgetError {
            description: "e_vars must not be empty".to_string(),
        });
    }

    let (_, _, r_nonzero) = cs.multiply(
        LinearCombination::from(r_var),
        LinearCombination::from(inv_r_var),
    );
    cs.constrain(LinearCombination::from(r_nonzero) - Scalar::one());

    if mask_vars.len() != hash_count || inv_mask_vars.len() != hash_count {
        return Err(R1CSError::GadgetError {
            description: "mask witness lengths must equal hash_count".to_string(),
        });
    }

    for (hash_index, (&mask_var, &inv_mask_var)) in
        mask_vars.iter().zip(inv_mask_vars.iter()).enumerate()
    {
        let (slope, intercept) = hash_params(hash_index);
        cs.constrain(
            LinearCombination::from(mask_var) - slope * LinearCombination::from(y_var) - intercept,
        );
        let (_, _, mask_nonzero) = cs.multiply(
            LinearCombination::from(mask_var),
            LinearCombination::from(inv_mask_var),
        );
        cs.constrain(LinearCombination::from(mask_nonzero) - Scalar::one());
    }

    let mut expected_e = vec![LinearCombination::default(); e_vars.len()];
    let witness_len = expected_e.len();
    for &mask_var in mask_vars {
        let (_, _, initial) = cs.multiply(
            LinearCombination::from(r_var),
            LinearCombination::from(mask_var),
        );
        let mut current = LinearCombination::from(initial);
        for (degree, expected) in expected_e.iter_mut().enumerate() {
            *expected = expected.clone() + current.clone();
            if degree + 1 < witness_len {
                let (_, _, next) = cs.multiply(current, LinearCombination::from(mask_var));
                current = LinearCombination::from(next);
            }
        }
    }
    for (expected, &e_var) in expected_e.into_iter().zip(e_vars.iter()) {
        cs.constrain(expected - LinearCombination::from(e_var));
    }

    Ok(())
}

struct EvalSumOpenings {
    proof: EvalSumProof,
    y_blind: Scalar,
    mask_blinds: Vec<Scalar>,
}

fn prove_eval_sum_with_openings<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    y: Scalar,
    hash_count: usize,
    e_vals: &[Scalar],
    r: Scalar,
    term_masks: &[Scalar],
) -> Result<EvalSumOpenings, R1CSError> {
    if hash_count == 0 {
        return Err(R1CSError::GadgetError {
            description: "hash_count must be non-zero".to_string(),
        });
    }
    if e_vals.is_empty() {
        return Err(R1CSError::GadgetError {
            description: "e witness vector must be non-empty".to_string(),
        });
    }
    if r == Scalar::zero() {
        return Err(R1CSError::GadgetError {
            description: "mask r must be non-zero".to_string(),
        });
    }
    if term_masks.len() != hash_count {
        return Err(R1CSError::GadgetError {
            description: "term-mask vector length must equal hash_count".to_string(),
        });
    }
    if term_masks.iter().any(|mask| *mask == Scalar::zero()) {
        return Err(R1CSError::GadgetError {
            description: "per-term Bloom mask must be non-zero".to_string(),
        });
    }

    let mut transcript = Transcript::new(b"I-PSI-CA::bf_eval_sum_v1");
    let mut prover = Prover::new(pc_gens, &mut transcript);

    let mut e_comms = Vec::with_capacity(e_vals.len());
    let mut e_vars = Vec::with_capacity(e_vals.len());
    for &e_val in e_vals {
        let (comm, var) = prover.commit(e_val, Scalar::random(rng));
        e_comms.push(comm);
        e_vars.push(var);
    }

    let y_blind = Scalar::random(rng);
    let (y_comm, y_var) = prover.commit(y, y_blind);

    let mut mask_comms = Vec::with_capacity(term_masks.len());
    let mut mask_vars = Vec::with_capacity(term_masks.len());
    let mut mask_blinds = Vec::with_capacity(term_masks.len());
    let mut inv_mask_comms = Vec::with_capacity(term_masks.len());
    let mut inv_mask_vars = Vec::with_capacity(term_masks.len());
    for &mask in term_masks {
        let blind = Scalar::random(rng);
        let (comm, var) = prover.commit(mask, blind);
        mask_comms.push(comm);
        mask_vars.push(var);
        mask_blinds.push(blind);
    }
    for &mask in term_masks {
        let (inv_comm, inv_var) = prover.commit(mask.invert(), Scalar::random(rng));
        inv_mask_comms.push(inv_comm);
        inv_mask_vars.push(inv_var);
    }

    let (r_comm, r_var) = prover.commit(r, Scalar::random(rng));
    let (inv_r_comm, inv_r_var) = prover.commit(r.invert(), Scalar::random(rng));

    eval_sum_relation_gadget(
        &mut prover,
        &e_vars,
        y_var,
        r_var,
        &mask_vars,
        hash_count,
        inv_r_var,
        &inv_mask_vars,
    )?;

    let proof = prover.prove(bp_gens)?;
    Ok(EvalSumOpenings {
        proof: EvalSumProof {
            proof,
            e_comms,
            mask_comms,
            inv_mask_comms,
            y_comm,
            r_comm,
            inv_r_comm,
        },
        y_blind,
        mask_blinds,
    })
}

fn verify_eval_sum(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    hash_count: usize,
    proof: &EvalSumProof,
) -> Result<(), String> {
    if proof.e_comms.is_empty() {
        return Err("e commitment vector must not be empty".to_string());
    }
    if proof.mask_comms.len() != hash_count || proof.inv_mask_comms.len() != hash_count {
        return Err("per-term mask commitment length mismatch".to_string());
    }

    let mut transcript = Transcript::new(b"I-PSI-CA::bf_eval_sum_v1");
    let mut verifier = Verifier::new(&mut transcript);

    let e_vars: Vec<_> = proof
        .e_comms
        .iter()
        .copied()
        .map(|comm| verifier.commit(comm))
        .collect();
    let y_var = verifier.commit(proof.y_comm);
    let mask_vars: Vec<_> = proof
        .mask_comms
        .iter()
        .copied()
        .map(|comm| verifier.commit(comm))
        .collect();
    let inv_mask_vars: Vec<_> = proof
        .inv_mask_comms
        .iter()
        .copied()
        .map(|comm| verifier.commit(comm))
        .collect();
    let r_var = verifier.commit(proof.r_comm);
    let inv_r_var = verifier.commit(proof.inv_r_comm);

    eval_sum_relation_gadget(
        &mut verifier,
        &e_vars,
        y_var,
        r_var,
        &mask_vars,
        hash_count,
        inv_r_var,
        &inv_mask_vars,
    )
    .map_err(|e| format!("BF Bulletproof gadget invalid: {e:?}"))?;

    verifier
        .verify(&proof.proof, pc_gens, bp_gens)
        .map_err(|e| format!("BF Bulletproof verification failed: {e:?}"))
}

fn eval_witnesses_from_positions(
    coeff_len: usize,
    positions: &[Scalar],
    term_masks: &[Scalar],
    r: Scalar,
) -> Vec<Scalar> {
    assert_eq!(positions.len(), term_masks.len());
    let mut sums = vec![Scalar::zero(); coeff_len];
    for (&position, &term_mask) in positions.iter().zip(term_masks.iter()) {
        let mut power = Scalar::one();
        for sum in &mut sums {
            *sum += term_mask * power;
            power *= position;
        }
    }
    sums.into_iter().map(|sum| r * sum).collect()
}

pub(crate) fn build_aggregate_eval_witness(
    poly: &EncryptedPoly,
    y: Scalar,
    bf_config: BloomFilterConfig,
    eval_mask: Scalar,
    pk: &PublicKey,
) -> Result<AggregateEvalWitness, String> {
    let positions = scalar_positions(y, bf_config);
    if positions.is_empty() {
        return Err("position set must be non-empty".to_string());
    }
    if poly.0.is_empty() {
        return Err("coeff_cts must not be empty".to_string());
    }

    if eval_mask == Scalar::zero() {
        return Err("outer evaluation mask must be non-zero".to_string());
    }

    let term_masks = positions.clone();
    if term_masks.iter().any(|mask| *mask == Scalar::zero()) {
        return Err("Bloom hash produced a zero per-term mask".to_string());
    }

    let e_vals = eval_witnesses_from_positions(poly.0.len(), &positions, &term_masks, eval_mask);

    let c1 = RistrettoPoint::multiscalar_mul(e_vals.iter().copied(), poly.0.iter().map(|ct| ct.c1))
        + &e_vals[0] * &RISTRETTO_BASEPOINT_TABLE;
    let c2 = RistrettoPoint::multiscalar_mul(e_vals.iter().copied(), poly.0.iter().map(|ct| ct.c2))
        + e_vals[0] * pk.0;

    Ok(AggregateEvalWitness {
        term_masks,
        e_vals,
        scaled_eval: Ciphertext { c1, c2 },
    })
}

fn glue_transcript(
    eval_proof: &EvalSumProof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::bf_sigma_bullet_glue_v1");
    append_point(&mut t, b"pk", &pk.0);
    for ct in coeff_cts {
        append_point(&mut t, b"coef_c1", &ct.c1);
        append_point(&mut t, b"coef_c2", &ct.c2);
    }
    append_point(&mut t, b"cstar_c1", &c_star.c1);
    append_point(&mut t, b"cstar_c2", &c_star.c2);
    for comm in &eval_proof.e_comms {
        append_compressed(&mut t, b"e_comm", comm);
    }
    for comm in &eval_proof.mask_comms {
        append_compressed(&mut t, b"mask_comm", comm);
    }
    for comm in &eval_proof.inv_mask_comms {
        append_compressed(&mut t, b"inv_mask_comm", comm);
    }
    append_compressed(&mut t, b"y_comm", &eval_proof.y_comm);
    append_compressed(&mut t, b"r_comm", &eval_proof.r_comm);
    t.append_message(b"r1cs", &eval_proof.proof.to_bytes());
    t
}

fn relation_scalars(
    eval_proof: &EvalSumProof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
) -> (Scalar, Scalar, Scalar) {
    let mut t = glue_transcript(eval_proof, pk, coeff_cts, c_star);
    let beta_y = batch_scalar(&mut t, b"batch_y");
    let beta_c1 = batch_scalar(&mut t, b"batch_c1");
    let beta_c2 = batch_scalar(&mut t, b"batch_c2");
    (beta_y, beta_c1, beta_c2)
}

fn append_glue_section(
    t: &mut Transcript,
    eval_proof: &EvalSumProof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    alpha_tag: &CompressedRistretto,
    glue_a_t: &CompressedRistretto,
) {
    t.append_message(b"section", b"bf_sigma_bullet_glue");
    append_point(t, b"pk", &pk.0);
    for ct in coeff_cts {
        append_point(t, b"coef_c1", &ct.c1);
        append_point(t, b"coef_c2", &ct.c2);
    }
    append_point(t, b"cstar_c1", &c_star.c1);
    append_point(t, b"cstar_c2", &c_star.c2);
    for comm in &eval_proof.e_comms {
        append_compressed(t, b"e_comm", comm);
    }
    for comm in &eval_proof.mask_comms {
        append_compressed(t, b"mask_comm", comm);
    }
    for comm in &eval_proof.inv_mask_comms {
        append_compressed(t, b"inv_mask_comm", comm);
    }
    append_compressed(t, b"y_comm", &eval_proof.y_comm);
    append_compressed(t, b"r_comm", &eval_proof.r_comm);
    t.append_message(b"r1cs", &eval_proof.proof.to_bytes());
    t.append_message(b"beta_y", &beta_y.to_bytes());
    t.append_message(b"beta_c1", &beta_c1.to_bytes());
    t.append_message(b"beta_c2", &beta_c2.to_bytes());
    append_compressed(t, b"alpha_tag", alpha_tag);
    append_compressed(t, b"A_t", glue_a_t);
}

fn append_mask_bridge_section(
    t: &mut Transcript,
    eval_proof: &EvalSumProof,
    alpha_tag: &CompressedRistretto,
    mask_a_tags: &[CompressedRistretto],
    mask_a_comms: &[CompressedRistretto],
) {
    t.append_message(b"section", b"bf_per_term_mask_bridge");
    append_compressed(t, b"alpha_tag", alpha_tag);
    for (index, ((mask_comm, a_tag), a_comm)) in eval_proof
        .mask_comms
        .iter()
        .zip(mask_a_tags.iter())
        .zip(mask_a_comms.iter())
        .enumerate()
    {
        t.append_message(b"hash_index", &(index as u64).to_le_bytes());
        append_compressed(t, b"mask_comm", mask_comm);
        append_compressed(t, b"mask_A_tag", a_tag);
        append_compressed(t, b"mask_A_comm", a_comm);
    }
}

fn append_partial_decrypt_section(
    t: &mut Transcript,
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    partial_in_ct: &Ciphertext,
    partial_out_ct: &Ciphertext,
    beta_pd: Scalar,
    gamma_pd: Scalar,
    partial_a: &CompressedRistretto,
) {
    t.append_message(b"section", b"partial_decrypt");
    append_point(t, b"pk2", &pk2.0);
    append_point(t, b"pk1", &pk1.0);
    append_point(t, b"c1_in", &partial_in_ct.c1);
    append_point(t, b"c2_in", &partial_in_ct.c2);
    append_point(t, b"c1_out", &partial_out_ct.c1);
    append_point(t, b"c2_out", &partial_out_ct.c2);
    t.append_message(b"beta", &beta_pd.to_bytes());
    t.append_message(b"gamma", &gamma_pd.to_bytes());
    append_compressed(t, b"A", partial_a);
}

fn append_poly_scalar_mul_section(
    t: &mut Transcript,
    poly_in: &EncryptedPoly,
    poly_out: &EncryptedPoly,
    alpha_tag: &CompressedRistretto,
    beta_poly: Scalar,
    gamma_poly: Scalar,
    poly_a1: &CompressedRistretto,
    poly_a2: &CompressedRistretto,
    poly_a_m: &CompressedRistretto,
) {
    t.append_message(b"section", b"poly_scalar_mul");
    append_compressed(t, b"alpha_tag", alpha_tag);
    for ct in &poly_in.0 {
        append_point(t, b"in_c1", &ct.c1);
        append_point(t, b"in_c2", &ct.c2);
    }
    for ct in &poly_out.0 {
        append_point(t, b"out_c1", &ct.c1);
        append_point(t, b"out_c2", &ct.c2);
    }
    append_compressed(t, b"A1", poly_a1);
    append_compressed(t, b"A2", poly_a2);
    append_compressed(t, b"A_m", poly_a_m);
    t.append_message(b"beta", &beta_poly.to_bytes());
    t.append_message(b"gamma", &gamma_poly.to_bytes());
}

#[allow(clippy::too_many_arguments)]
fn combined_transcript_prefix(
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    eval_proof: &EvalSumProof,
    alpha_tag: &CompressedRistretto,
    mask_a_tags: &[CompressedRistretto],
    mask_a_comms: &[CompressedRistretto],
    glue_a_t: &CompressedRistretto,
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    partial_in_ct: &Ciphertext,
    partial_out_ct: &Ciphertext,
    beta_pd: Scalar,
    gamma_pd: Scalar,
    partial_a: &CompressedRistretto,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::bf_combined_sigma_round_v2");
    append_glue_section(
        &mut t, eval_proof, pk, coeff_cts, c_star, beta_y, beta_c1, beta_c2, alpha_tag, glue_a_t,
    );
    append_mask_bridge_section(&mut t, eval_proof, alpha_tag, mask_a_tags, mask_a_comms);
    append_partial_decrypt_section(
        &mut t,
        pk2,
        pk1,
        partial_in_ct,
        partial_out_ct,
        beta_pd,
        gamma_pd,
        partial_a,
    );
    t
}

#[allow(clippy::too_many_arguments)]
fn combined_transcript(
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    eval_proof: &EvalSumProof,
    alpha_tag: &CompressedRistretto,
    mask_a_tags: &[CompressedRistretto],
    mask_a_comms: &[CompressedRistretto],
    glue_a_t: &CompressedRistretto,
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    partial_in_ct: &Ciphertext,
    partial_out_ct: &Ciphertext,
    beta_pd: Scalar,
    gamma_pd: Scalar,
    partial_a: &CompressedRistretto,
    accum_chain_proof: &bp::EvalChainProof,
    accum_glue_a_t: &CompressedRistretto,
    beta_accum_y: Scalar,
    beta_accum_c1: Scalar,
    beta_accum_c2: Scalar,
    accum_partial_in_ct: &Ciphertext,
    accum_partial_out_ct: &Ciphertext,
    beta_accum_pd: Scalar,
    gamma_accum_pd: Scalar,
    accum_partial_a: &CompressedRistretto,
    accum_in: &EncryptedPoly,
    accum_out: &EncryptedPoly,
    beta_accum_mul: Scalar,
    gamma_accum_mul: Scalar,
    accum_mul_a1: &CompressedRistretto,
    accum_mul_a2: &CompressedRistretto,
    accum_mul_a_m: &CompressedRistretto,
) -> Transcript {
    let mut t = combined_transcript_prefix(
        pk,
        coeff_cts,
        c_star,
        eval_proof,
        alpha_tag,
        mask_a_tags,
        mask_a_comms,
        glue_a_t,
        beta_y,
        beta_c1,
        beta_c2,
        pk2,
        pk1,
        partial_in_ct,
        partial_out_ct,
        beta_pd,
        gamma_pd,
        partial_a,
    );
    sigma_bullet::append_glue_section(
        &mut t,
        b"bf_accum_sigma_bullet_glue",
        accum_chain_proof,
        pk,
        &accum_in.0,
        accum_partial_in_ct,
        beta_accum_y,
        beta_accum_c1,
        beta_accum_c2,
        alpha_tag,
        accum_glue_a_t,
    );
    append_partial_decrypt_section(
        &mut t,
        pk2,
        pk1,
        accum_partial_in_ct,
        accum_partial_out_ct,
        beta_accum_pd,
        gamma_accum_pd,
        accum_partial_a,
    );
    append_poly_scalar_mul_section(
        &mut t,
        accum_in,
        accum_out,
        alpha_tag,
        beta_accum_mul,
        gamma_accum_mul,
        accum_mul_a1,
        accum_mul_a2,
        accum_mul_a_m,
    );
    t
}

#[allow(clippy::too_many_arguments)]
fn combined_challenge(
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    eval_proof: &EvalSumProof,
    alpha_tag: &CompressedRistretto,
    mask_a_tags: &[CompressedRistretto],
    mask_a_comms: &[CompressedRistretto],
    glue_a_t: &CompressedRistretto,
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    partial_in_ct: &Ciphertext,
    partial_out_ct: &Ciphertext,
    beta_pd: Scalar,
    gamma_pd: Scalar,
    partial_a: &CompressedRistretto,
    accum_chain_proof: &bp::EvalChainProof,
    accum_glue_a_t: &CompressedRistretto,
    beta_accum_y: Scalar,
    beta_accum_c1: Scalar,
    beta_accum_c2: Scalar,
    accum_partial_in_ct: &Ciphertext,
    accum_partial_out_ct: &Ciphertext,
    beta_accum_pd: Scalar,
    gamma_accum_pd: Scalar,
    accum_partial_a: &CompressedRistretto,
    accum_in: &EncryptedPoly,
    accum_out: &EncryptedPoly,
    beta_accum_mul: Scalar,
    gamma_accum_mul: Scalar,
    accum_mul_a1: &CompressedRistretto,
    accum_mul_a2: &CompressedRistretto,
    accum_mul_a_m: &CompressedRistretto,
) -> (Scalar, Scalar, Scalar, Scalar, Scalar, Scalar, Scalar) {
    let mut t = combined_transcript(
        pk,
        coeff_cts,
        c_star,
        eval_proof,
        alpha_tag,
        mask_a_tags,
        mask_a_comms,
        glue_a_t,
        beta_y,
        beta_c1,
        beta_c2,
        pk2,
        pk1,
        partial_in_ct,
        partial_out_ct,
        beta_pd,
        gamma_pd,
        partial_a,
        accum_chain_proof,
        accum_glue_a_t,
        beta_accum_y,
        beta_accum_c1,
        beta_accum_c2,
        accum_partial_in_ct,
        accum_partial_out_ct,
        beta_accum_pd,
        gamma_accum_pd,
        accum_partial_a,
        accum_in,
        accum_out,
        beta_accum_mul,
        gamma_accum_mul,
        accum_mul_a1,
        accum_mul_a2,
        accum_mul_a_m,
    );
    let challenge = challenge_scalar(&mut t);
    let rho_glue = batch_scalar(&mut t, b"rho_glue");
    let rho_mask_bridge = batch_scalar(&mut t, b"rho_mask_bridge");
    let rho_partial = batch_scalar(&mut t, b"rho_partial");
    let rho_accum_glue = batch_scalar(&mut t, b"rho_accum_glue");
    let rho_accum_partial = batch_scalar(&mut t, b"rho_accum_partial");
    let rho_accum_mul = batch_scalar(&mut t, b"rho_accum_mul");
    (
        challenge,
        rho_glue,
        rho_mask_bridge,
        rho_partial,
        rho_accum_glue,
        rho_accum_partial,
        rho_accum_mul,
    )
}

#[allow(clippy::too_many_arguments)]
fn derive_round_batch_scalars(
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    eval_proof: &EvalSumProof,
    alpha_tag: &CompressedRistretto,
    mask_a_tags: &[CompressedRistretto],
    mask_a_comms: &[CompressedRistretto],
    glue_a_t: &CompressedRistretto,
    partial_out_ct: &Ciphertext,
    partial_a: &CompressedRistretto,
    accum_chain_proof: &bp::EvalChainProof,
    accum_glue_a_t: &CompressedRistretto,
    accum_c_star: &Ciphertext,
    accum_partial_out_ct: &Ciphertext,
    accum_partial_a: &CompressedRistretto,
    accum_in: &EncryptedPoly,
    accum_out: &EncryptedPoly,
    accum_mul_a1: &CompressedRistretto,
    accum_mul_a2: &CompressedRistretto,
    accum_mul_a_m: &CompressedRistretto,
    accum_mul_s_y: Scalar,
) -> Result<RoundBatchScalars, String> {
    let (beta_y, beta_c1, beta_c2) = relation_scalars(eval_proof, pk, coeff_cts, c_star);
    let (beta_pd, gamma_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, c_star, partial_out_ct);
    let (beta_accum_y, beta_accum_c1, beta_accum_c2) =
        sigma_bullet::relation_scalars(accum_chain_proof, pk, &accum_in.0, accum_c_star);
    let (beta_accum_pd, gamma_accum_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, accum_c_star, accum_partial_out_ct);

    let alpha_tag_pt = alpha_tag
        .decompress()
        .ok_or_else(|| "invalid alpha_tag point".to_string())?;
    let (beta_accum_mul, gamma_accum_mul) = sigma::poly_scalar_mul_batch_scalars(
        &PolyScalarMulProof {
            a1: *accum_mul_a1,
            a2: *accum_mul_a2,
            alpha_tag: *alpha_tag,
            a_m: *accum_mul_a_m,
            s_y: accum_mul_s_y,
        },
        accum_in,
        accum_out,
        &alpha_tag_pt,
    )
    .map_err(str::to_string)?;

    let (
        challenge,
        rho_glue,
        rho_mask_bridge,
        rho_partial,
        rho_accum_glue,
        rho_accum_partial,
        rho_accum_mul,
    ) = combined_challenge(
        pk,
        coeff_cts,
        c_star,
        eval_proof,
        alpha_tag,
        mask_a_tags,
        mask_a_comms,
        glue_a_t,
        beta_y,
        beta_c1,
        beta_c2,
        pk2,
        pk1,
        c_star,
        partial_out_ct,
        beta_pd,
        gamma_pd,
        partial_a,
        accum_chain_proof,
        accum_glue_a_t,
        beta_accum_y,
        beta_accum_c1,
        beta_accum_c2,
        accum_c_star,
        accum_partial_out_ct,
        beta_accum_pd,
        gamma_accum_pd,
        accum_partial_a,
        accum_in,
        accum_out,
        beta_accum_mul,
        gamma_accum_mul,
        accum_mul_a1,
        accum_mul_a2,
        accum_mul_a_m,
    );

    Ok(RoundBatchScalars {
        beta_y,
        beta_c1,
        beta_c2,
        beta_pd,
        gamma_pd,
        beta_accum_y,
        beta_accum_c1,
        beta_accum_c2,
        beta_accum_pd,
        gamma_accum_pd,
        beta_accum_mul,
        gamma_accum_mul,
        challenge,
        rho_glue,
        rho_mask_bridge,
        rho_partial,
        rho_accum_glue,
        rho_accum_partial,
        rho_accum_mul,
    })
}

impl WireEvalSumProof {
    fn from_proof(p: &EvalSumProof) -> Self {
        Self {
            proof_bytes: p.proof.to_bytes(),
            e_comms: p.e_comms.iter().map(|c| c.to_bytes()).collect(),
            mask_comms: p.mask_comms.iter().map(|c| c.to_bytes()).collect(),
            inv_mask_comms: p.inv_mask_comms.iter().map(|c| c.to_bytes()).collect(),
            y_comm: p.y_comm.to_bytes(),
            r_comm: p.r_comm.to_bytes(),
            inv_r_comm: p.inv_r_comm.to_bytes(),
        }
    }

    fn to_proof(&self) -> Result<EvalSumProof, String> {
        Ok(EvalSumProof {
            proof: R1CSProof::from_bytes(&self.proof_bytes)
                .map_err(|e| format!("R1CSProof decode: {e:?}"))?,
            e_comms: self
                .e_comms
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
            mask_comms: self
                .mask_comms
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
            inv_mask_comms: self
                .inv_mask_comms
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
            y_comm: CompressedRistretto::from_slice(&self.y_comm),
            r_comm: CompressedRistretto::from_slice(&self.r_comm),
            inv_r_comm: CompressedRistretto::from_slice(&self.inv_r_comm),
        })
    }
}

impl WireAccumEvalProof {
    fn from_proof(p: &bp::EvalChainProof) -> Self {
        Self {
            proof_bytes: p.proof.to_bytes(),
            e_comms: p.e_comms.iter().map(|c| c.to_bytes()).collect(),
            y_comm: p.y_comm.to_bytes(),
            inv_en_comm: p.inv_en_comm.to_bytes(),
        }
    }

    fn to_proof(&self) -> Result<bp::EvalChainProof, String> {
        Ok(bp::EvalChainProof {
            proof: R1CSProof::from_bytes(&self.proof_bytes)
                .map_err(|e| format!("accum R1CSProof decode: {e:?}"))?,
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
    fn from_proof(p: &CombinedSigmaProof) -> Self {
        Self {
            eval_proof: WireEvalSumProof::from_proof(&p.eval_proof),
            alpha_tag: p.alpha_tag.to_bytes(),
            mask_a_tags: p.mask_a_tags.iter().map(|p| p.to_bytes()).collect(),
            mask_a_comms: p.mask_a_comms.iter().map(|p| p.to_bytes()).collect(),
            mask_z: p.mask_z.iter().map(|s| s.to_bytes()).collect(),
            mask_z_blind: p.mask_z_blind.iter().map(|s| s.to_bytes()).collect(),
            glue_a_t: p.glue_a_t.to_bytes(),
            glue_z_e: p.glue_z_e.iter().map(|s| s.to_bytes()).collect(),
            glue_z_alpha: p.glue_z_alpha.to_bytes(),
            glue_z_y_blind: p.glue_z_y_blind.to_bytes(),
            partial_a: p.partial_a.to_bytes(),
            partial_z1: p.partial_z1.to_bytes(),
            partial_z2: p.partial_z2.to_bytes(),
            accum_chain_proof: WireAccumEvalProof::from_proof(&p.accum_chain_proof),
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

    fn to_proof(&self) -> Result<CombinedSigmaProof, String> {
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
        let mask_z: Result<Vec<_>, _> = self
            .mask_z
            .iter()
            .map(|b| Scalar::from_canonical_bytes(*b).ok_or("mask_z: non-canonical scalar"))
            .collect();
        let mask_z_blind: Result<Vec<_>, _> = self
            .mask_z_blind
            .iter()
            .map(|b| Scalar::from_canonical_bytes(*b).ok_or("mask_z_blind: non-canonical scalar"))
            .collect();
        Ok(CombinedSigmaProof {
            eval_proof: self.eval_proof.to_proof()?,
            alpha_tag: CompressedRistretto::from_slice(&self.alpha_tag),
            mask_a_tags: self
                .mask_a_tags
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
            mask_a_comms: self
                .mask_a_comms
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
            mask_z: mask_z.map_err(str::to_string)?,
            mask_z_blind: mask_z_blind.map_err(str::to_string)?,
            glue_a_t: CompressedRistretto::from_slice(&self.glue_a_t),
            glue_z_e: glue_z_e.map_err(str::to_string)?,
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
            accum_glue_z_e: accum_glue_z_e.map_err(str::to_string)?,
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn preprocess_round_proof<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    t_poly: &EncryptedPoly,
    hash_count: usize,
    e_vals: &[Scalar],
    term_masks: &[Scalar],
    scaled_eval: &Ciphertext,
    y: Scalar,
    eval_mask: Scalar,
    pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    m_poly_ct: &Ciphertext,
    mpoly_r_prime: Scalar,
    sk2: &Scalar,
) -> Result<RoundProofPrecomputation, R1CSError> {
    let EvalSumOpenings {
        proof: eval_proof,
        y_blind,
        mask_blinds,
    } = prove_eval_sum_with_openings(
        rng, pc_gens, bp_gens, y, hash_count, e_vals, eval_mask, term_masks,
    )?;

    let mut k_e = Vec::with_capacity(e_vals.len());
    for _ in 0..e_vals.len() {
        k_e.push(Scalar::random(rng));
    }
    let k_alpha = Scalar::random(rng);
    let k_y_blind = Scalar::random(rng);
    let alpha_tag_pt = mul_g(&y);
    let alpha_tag = alpha_tag_pt.compress();

    let mut mask_k = Vec::with_capacity(term_masks.len());
    let mut mask_k_blind = Vec::with_capacity(term_masks.len());
    let mut mask_a_tags = Vec::with_capacity(term_masks.len());
    let mut mask_a_comms = Vec::with_capacity(term_masks.len());
    for _ in term_masks {
        let k = Scalar::random(rng);
        let k_blind = Scalar::random(rng);
        mask_a_tags.push(mul_g(&k).compress());
        mask_a_comms.push(
            RistrettoPoint::multiscalar_mul([k, k_blind], [pc_gens.B, pc_gens.B_blinding])
                .compress(),
        );
        mask_k.push(k);
        mask_k_blind.push(k_blind);
    }

    let mut scalars = Vec::with_capacity(4 + k_e.len());
    let mut points = Vec::with_capacity(4 + k_e.len());
    scalars.push(k_alpha);
    points.push(G);
    let (beta_y, beta_c1, beta_c2) = relation_scalars(&eval_proof, pk, &t_poly.0, scaled_eval);
    scalars.push(beta_y * k_alpha);
    points.push(pc_gens.B);
    scalars.push(beta_y * k_y_blind);
    points.push(pc_gens.B_blinding);
    for (idx, (k, ct)) in k_e.iter().zip(t_poly.0.iter()).enumerate() {
        scalars.push(*k);
        let basis = if idx == 0 {
            RistrettoPoint::vartime_multiscalar_mul(
                [beta_c1, beta_c2, beta_c1, beta_c2],
                [ct.c1, ct.c2, G, pk.0],
            )
        } else {
            RistrettoPoint::vartime_multiscalar_mul([beta_c1, beta_c2], [ct.c1, ct.c2])
        };
        points.push(basis);
    }
    let glue_a_t =
        RistrettoPoint::multiscalar_mul(scalars.iter().copied(), points.iter().copied()).compress();

    let k_sk2 = Scalar::random(rng);
    let k_r_prime = Scalar::random(rng);
    let (beta_pd, gamma_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, scaled_eval, m_poly_ct);
    let beta_g = mul_g(&beta_pd);
    let gamma_c1 = RistrettoPoint::vartime_multiscalar_mul([gamma_pd], [scaled_eval.c1]);
    let gamma_rhs = RistrettoPoint::vartime_multiscalar_mul([gamma_pd], [pk1.0 + beta_g]);
    let partial_a = (mul_g(&k_sk2) - k_sk2 * gamma_c1 + k_r_prime * gamma_rhs).compress();
    let transcript = combined_transcript_prefix(
        pk,
        &t_poly.0,
        scaled_eval,
        &eval_proof,
        &alpha_tag,
        &mask_a_tags,
        &mask_a_comms,
        &glue_a_t,
        beta_y,
        beta_c1,
        beta_c2,
        pk2,
        pk1,
        scaled_eval,
        m_poly_ct,
        beta_pd,
        gamma_pd,
        &partial_a,
    );

    Ok(RoundProofPrecomputation {
        eval_proof,
        y_blind,
        e_vals: e_vals.to_vec(),
        term_masks: term_masks.to_vec(),
        mask_blinds,
        y,
        k_e,
        k_alpha,
        k_y_blind,
        alpha_tag_pt,
        alpha_tag,
        mask_k,
        mask_k_blind,
        mask_a_tags,
        mask_a_comms,
        glue_a_t,
        k_sk2,
        k_r_prime,
        partial_a,
        mpoly_r_prime,
        sk2: *sk2,
        transcript,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_round_proof<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    pk: &PublicKey,
    scaled_eval: &Ciphertext,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    accum_scaled_eval: &Ciphertext,
    accum_m_poly_ct: &Ciphertext,
    accum_in: &EncryptedPoly,
    next_accum: &EncryptedPoly,
    accum_mask: Scalar,
    accum_r_prime: Scalar,
    precomputed: RoundProofPrecomputation,
) -> Result<(Ciphertext, RoundProof), R1CSError> {
    let RoundProofPrecomputation {
        eval_proof,
        y_blind,
        e_vals,
        term_masks,
        mask_blinds,
        y,
        k_e,
        k_alpha,
        k_y_blind,
        alpha_tag_pt,
        alpha_tag,
        mask_k,
        mask_k_blind,
        mask_a_tags,
        mask_a_comms,
        glue_a_t,
        k_sk2,
        k_r_prime,
        partial_a,
        mpoly_r_prime,
        sk2,
        mut transcript,
    } = precomputed;

    let mut accum_e_asc = Vec::with_capacity(accum_in.0.len());
    accum_e_asc.push(accum_mask);
    for i in 1..accum_in.0.len() {
        accum_e_asc.push(accum_e_asc[i - 1] * y);
    }
    let accum_e_rev: Vec<Scalar> = accum_e_asc.iter().cloned().rev().collect();
    let (accum_chain_proof, accum_y_blind) =
        sigma_bullet::prove_chain_with_openings(rng, pc_gens, bp_gens, &accum_e_rev, y)?;
    let (beta_accum_y, beta_accum_c1, beta_accum_c2) =
        sigma_bullet::relation_scalars(&accum_chain_proof, pk, &accum_in.0, accum_scaled_eval);
    let mut k_accum_e = Vec::with_capacity(accum_e_asc.len());
    for _ in 0..accum_e_asc.len() {
        k_accum_e.push(Scalar::random(rng));
    }
    let k_accum_alpha = Scalar::random(rng);
    let k_accum_y_blind = Scalar::random(rng);
    let mut accum_glue_scalars = Vec::with_capacity(3 + k_accum_e.len());
    let mut accum_glue_points = Vec::with_capacity(3 + k_accum_e.len());
    accum_glue_scalars.push(k_accum_alpha);
    accum_glue_points.push(G);
    accum_glue_scalars.push(beta_accum_y * k_accum_alpha);
    accum_glue_points.push(pc_gens.B);
    accum_glue_scalars.push(beta_accum_y * k_accum_y_blind);
    accum_glue_points.push(pc_gens.B_blinding);
    for (idx, (k, ct)) in k_accum_e.iter().zip(accum_in.0.iter()).enumerate() {
        let basis = if idx == 0 {
            RistrettoPoint::vartime_multiscalar_mul(
                [beta_accum_c1, beta_accum_c2, beta_accum_c1, beta_accum_c2],
                [ct.c1, ct.c2, G, pk.0],
            )
        } else {
            RistrettoPoint::vartime_multiscalar_mul(
                [beta_accum_c1, beta_accum_c2],
                [ct.c1, ct.c2],
            )
        };
        accum_glue_scalars.push(*k);
        accum_glue_points.push(basis);
    }
    let accum_glue_a_t = RistrettoPoint::multiscalar_mul(
        accum_glue_scalars.iter().copied(),
        accum_glue_points.iter().copied(),
    )
    .compress();

    let k_accum_sk2 = Scalar::random(rng);
    let k_accum_r_prime = Scalar::random(rng);
    let (beta_accum_pd, gamma_accum_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, accum_scaled_eval, accum_m_poly_ct);
    let accum_beta_g = mul_g(&beta_accum_pd);
    let accum_gamma_c1 =
        RistrettoPoint::vartime_multiscalar_mul([gamma_accum_pd], [accum_scaled_eval.c1]);
    let accum_gamma_rhs =
        RistrettoPoint::vartime_multiscalar_mul([gamma_accum_pd], [pk1.0 + accum_beta_g]);
    let accum_partial_a = (mul_g(&k_accum_sk2) - k_accum_sk2 * accum_gamma_c1
        + k_accum_r_prime * accum_gamma_rhs)
        .compress();

    let (accum_x_c1, accum_x_c2) =
        sigma::poly_scalar_mul_x_points(accum_in, next_accum, &alpha_tag_pt);
    let k_accum_mul_y = Scalar::random(rng);
    let accum_mul_a1 = (k_accum_mul_y * accum_x_c1).compress();
    let accum_mul_a2 = (k_accum_mul_y * accum_x_c2).compress();
    let accum_mul_a_m = mul_g(&k_accum_mul_y).compress();

    let (beta_accum_mul, gamma_accum_mul) = sigma::poly_scalar_mul_batch_scalars(
        &PolyScalarMulProof {
            a1: accum_mul_a1,
            a2: accum_mul_a2,
            alpha_tag,
            a_m: accum_mul_a_m,
            s_y: Scalar::zero(),
        },
        accum_in,
        next_accum,
        &alpha_tag_pt,
    )
    .map_err(|description| R1CSError::GadgetError {
        description: description.to_string(),
    })?;
    sigma_bullet::append_glue_section(
        &mut transcript,
        b"bf_accum_sigma_bullet_glue",
        &accum_chain_proof,
        pk,
        &accum_in.0,
        accum_scaled_eval,
        beta_accum_y,
        beta_accum_c1,
        beta_accum_c2,
        &alpha_tag,
        &accum_glue_a_t,
    );
    append_partial_decrypt_section(
        &mut transcript,
        pk2,
        pk1,
        accum_scaled_eval,
        accum_m_poly_ct,
        beta_accum_pd,
        gamma_accum_pd,
        &accum_partial_a,
    );
    append_poly_scalar_mul_section(
        &mut transcript,
        accum_in,
        next_accum,
        &alpha_tag,
        beta_accum_mul,
        gamma_accum_mul,
        &accum_mul_a1,
        &accum_mul_a2,
        &accum_mul_a_m,
    );
    let challenge = challenge_scalar(&mut transcript);

    Ok((
        scaled_eval.clone(),
        RoundProof {
            aggregate_eval_proof: WireCombinedSigmaProof::from_proof(&CombinedSigmaProof {
                eval_proof,
                alpha_tag,
                mask_a_tags,
                mask_a_comms,
                mask_z: mask_k
                    .iter()
                    .zip(term_masks.iter())
                    .map(|(k, mask)| k + challenge * mask)
                    .collect(),
                mask_z_blind: mask_k_blind
                    .iter()
                    .zip(mask_blinds.iter())
                    .map(|(k, blind)| k + challenge * blind)
                    .collect(),
                glue_a_t,
                glue_z_e: k_e
                    .iter()
                    .zip(e_vals.iter())
                    .map(|(k, e)| k + challenge * e)
                    .collect(),
                glue_z_alpha: k_alpha + challenge * y,
                glue_z_y_blind: k_y_blind + challenge * y_blind,
                partial_a,
                partial_z1: k_sk2 + challenge * sk2,
                partial_z2: k_r_prime + challenge * mpoly_r_prime,
                accum_chain_proof,
                accum_glue_a_t,
                accum_glue_z_e: k_accum_e
                    .iter()
                    .zip(accum_e_asc.iter())
                    .map(|(k, e)| k + challenge * e)
                    .collect(),
                accum_glue_z_alpha: k_accum_alpha + challenge * y,
                accum_glue_z_y_blind: k_accum_y_blind + challenge * accum_y_blind,
                accum_partial_a,
                accum_partial_z1: k_accum_sk2 + challenge * sk2,
                accum_partial_z2: k_accum_r_prime + challenge * accum_r_prime,
                accum_mul_a1,
                accum_mul_a2,
                accum_mul_a_m,
                accum_mul_s_y: k_accum_mul_y + challenge * y,
            }),
        },
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn prove_round<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    t_poly: &EncryptedPoly,
    hash_count: usize,
    e_vals: &[Scalar],
    term_masks: &[Scalar],
    scaled_eval: &Ciphertext,
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
    accum_mask: Scalar,
    accum_r_prime: Scalar,
    sk2: &Scalar,
) -> Result<(Ciphertext, RoundProof), R1CSError> {
    let precomputed = preprocess_round_proof(
        rng,
        pc_gens,
        bp_gens,
        t_poly,
        hash_count,
        e_vals,
        term_masks,
        scaled_eval,
        y,
        eval_mask,
        pk,
        pk1,
        pk2,
        m_poly_ct,
        mpoly_r_prime,
        sk2,
    )?;
    finish_round_proof(
        rng,
        pc_gens,
        bp_gens,
        pk,
        scaled_eval,
        pk1,
        pk2,
        accum_scaled_eval,
        accum_m_poly_ct,
        accum_in,
        next_accum,
        accum_mask,
        accum_r_prime,
        precomputed,
    )
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
    let proof = round_proof.aggregate_eval_proof.to_proof()?;
    if proof.eval_proof.e_comms.len() != t_poly.0.len() {
        return Err("e commitment length mismatch".to_string());
    }
    if proof.glue_z_e.len() != t_poly.0.len() {
        return Err("glue vector length mismatch".to_string());
    }
    if proof.eval_proof.mask_comms.len() != bf_config.hash_count
        || proof.mask_a_tags.len() != bf_config.hash_count
        || proof.mask_a_comms.len() != bf_config.hash_count
        || proof.mask_z.len() != bf_config.hash_count
        || proof.mask_z_blind.len() != bf_config.hash_count
    {
        return Err("per-term mask bridge length mismatch".to_string());
    }
    if proof.accum_chain_proof.e_comms.len() != current_accum.0.len() {
        return Err("accum e commitment length mismatch".to_string());
    }
    if proof.accum_glue_z_e.len() != current_accum.0.len() {
        return Err("accum glue vector length mismatch".to_string());
    }

    verify_eval_sum(pc_gens, bp_gens, bf_config.hash_count, &proof.eval_proof)?;
    bp::verify(pc_gens, bp_gens, &proof.accum_chain_proof)
        .map_err(|e| format!("accum chain Bulletproof invalid: {e:?}"))?;

    let alpha_tag = proof
        .alpha_tag
        .decompress()
        .ok_or_else(|| "invalid alpha_tag point".to_string())?;
    let mask_a_tags: Result<Vec<_>, _> = proof
        .mask_a_tags
        .iter()
        .map(|point| point.decompress().ok_or("invalid mask A_tag point"))
        .collect();
    let mask_a_tags = mask_a_tags?;
    let mask_a_comms: Result<Vec<_>, _> = proof
        .mask_a_comms
        .iter()
        .map(|point| point.decompress().ok_or("invalid mask A_comm point"))
        .collect();
    let mask_a_comms = mask_a_comms?;
    let mask_comms: Result<Vec<_>, _> = proof
        .eval_proof
        .mask_comms
        .iter()
        .map(|point| point.decompress().ok_or("invalid mask commitment point"))
        .collect();
    let mask_comms = mask_comms?;
    let glue_a_t = proof
        .glue_a_t
        .decompress()
        .ok_or_else(|| "invalid glue A_t point".to_string())?;
    let partial_a = proof
        .partial_a
        .decompress()
        .ok_or_else(|| "invalid partial A point".to_string())?;
    let accum_glue_a_t = proof
        .accum_glue_a_t
        .decompress()
        .ok_or_else(|| "invalid accum glue A_t point".to_string())?;
    let accum_partial_a = proof
        .accum_partial_a
        .decompress()
        .ok_or_else(|| "invalid accum partial A point".to_string())?;
    let accum_mul_a1 = proof
        .accum_mul_a1
        .decompress()
        .ok_or_else(|| "invalid accum mul A1 point".to_string())?;
    let accum_mul_a2 = proof
        .accum_mul_a2
        .decompress()
        .ok_or_else(|| "invalid accum mul A2 point".to_string())?;
    let accum_mul_a_m = proof
        .accum_mul_a_m
        .decompress()
        .ok_or_else(|| "invalid accum mul A_m point".to_string())?;
    let y_comm_pt = proof
        .eval_proof
        .y_comm
        .decompress()
        .ok_or_else(|| "invalid y commitment point".to_string())?;
    let accum_y_comm_pt = proof
        .accum_chain_proof
        .y_comm
        .decompress()
        .ok_or_else(|| "invalid accum y commitment point".to_string())?;

    let delta_c1 = m_poly_ct.c1 - scaled_eval.c1;
    let delta_c2 = m_poly_ct.c2 - scaled_eval.c2;
    let accum_delta_c1 = accum_m_poly_ct.c1 - accum_scaled_eval.c1;
    let accum_delta_c2 = accum_m_poly_ct.c2 - accum_scaled_eval.c2;
    let (accum_mul_x_c1, accum_mul_x_c2, accum_mul_y_c1, accum_mul_y_c2, _) =
        sigma::poly_scalar_mul_relation_points(current_accum, next_accum, &alpha_tag);
    let batch = derive_round_batch_scalars(
        pk,
        pk1,
        pk2,
        &t_poly.0,
        scaled_eval,
        &proof.eval_proof,
        &proof.alpha_tag,
        &proof.mask_a_tags,
        &proof.mask_a_comms,
        &proof.glue_a_t,
        m_poly_ct,
        &proof.partial_a,
        &proof.accum_chain_proof,
        &proof.accum_glue_a_t,
        accum_scaled_eval,
        accum_m_poly_ct,
        &proof.accum_partial_a,
        current_accum,
        next_accum,
        &proof.accum_mul_a1,
        &proof.accum_mul_a2,
        &proof.accum_mul_a_m,
        proof.accum_mul_s_y,
    )?;

    let mut scalars = Vec::new();
    let mut points = Vec::new();

    scalars.push(batch.rho_glue * proof.glue_z_alpha);
    points.push(G);
    scalars.push(batch.rho_glue * batch.beta_y * proof.glue_z_alpha);
    points.push(pc_gens.B);
    scalars.push(batch.rho_glue * batch.beta_y * proof.glue_z_y_blind);
    points.push(pc_gens.B_blinding);
    for (idx, (z, ct)) in proof.glue_z_e.iter().zip(t_poly.0.iter()).enumerate() {
        scalars.push(batch.rho_glue * *z);
        let mut basis = batch.beta_c1 * ct.c1 + batch.beta_c2 * ct.c2;
        if idx == 0 {
            basis += batch.beta_c1 * G + batch.beta_c2 * pk.0;
        }
        points.push(basis);
    }
    scalars.push(-batch.rho_glue);
    points.push(glue_a_t);
    scalars.push(-batch.rho_glue * batch.challenge);
    points.push(alpha_tag);
    scalars.push(-batch.rho_glue * batch.challenge * batch.beta_y);
    points.push(y_comm_pt);
    scalars.push(-batch.rho_glue * batch.challenge * batch.beta_c1);
    points.push(scaled_eval.c1);
    scalars.push(-batch.rho_glue * batch.challenge * batch.beta_c2);
    points.push(scaled_eval.c2);

    for (hash_index, (((&z, &z_blind), a_tag), (a_comm, mask_comm))) in proof
        .mask_z
        .iter()
        .zip(proof.mask_z_blind.iter())
        .zip(mask_a_tags.iter())
        .zip(mask_a_comms.iter().zip(mask_comms.iter()))
        .enumerate()
    {
        let (slope, intercept) = hash_params(hash_index);
        scalars.push(batch.rho_mask_bridge * z);
        points.push(G);
        scalars.push(-batch.rho_mask_bridge);
        points.push(*a_tag);
        scalars.push(-batch.rho_mask_bridge * batch.challenge * slope);
        points.push(alpha_tag);
        scalars.push(-batch.rho_mask_bridge * batch.challenge * intercept);
        points.push(G);

        scalars.push(batch.rho_mask_bridge * z);
        points.push(pc_gens.B);
        scalars.push(batch.rho_mask_bridge * z_blind);
        points.push(pc_gens.B_blinding);
        scalars.push(-batch.rho_mask_bridge);
        points.push(*a_comm);
        scalars.push(-batch.rho_mask_bridge * batch.challenge);
        points.push(*mask_comm);
    }

    scalars.push(
        batch.rho_partial * (proof.partial_z1 + proof.partial_z2 * batch.gamma_pd * batch.beta_pd),
    );
    points.push(G);
    scalars.push(batch.rho_partial * proof.partial_z2 * batch.gamma_pd);
    points.push(pk1.0);
    scalars.push(-batch.rho_partial * proof.partial_z1 * batch.gamma_pd);
    points.push(scaled_eval.c1);
    scalars.push(-batch.rho_partial);
    points.push(partial_a);
    scalars.push(-batch.rho_partial * batch.challenge);
    points.push(pk2.0);
    scalars.push(-batch.rho_partial * batch.challenge * batch.gamma_pd);
    points.push(delta_c2);
    scalars.push(-batch.rho_partial * batch.challenge * batch.gamma_pd * batch.beta_pd);
    points.push(delta_c1);

    scalars.push(batch.rho_accum_glue * proof.accum_glue_z_alpha);
    points.push(G);
    scalars.push(batch.rho_accum_glue * batch.beta_accum_y * proof.accum_glue_z_alpha);
    points.push(pc_gens.B);
    scalars.push(batch.rho_accum_glue * batch.beta_accum_y * proof.accum_glue_z_y_blind);
    points.push(pc_gens.B_blinding);
    for (idx, (z, ct)) in proof
        .accum_glue_z_e
        .iter()
        .zip(current_accum.0.iter())
        .enumerate()
    {
        let mut basis = batch.beta_accum_c1 * ct.c1 + batch.beta_accum_c2 * ct.c2;
        if idx == 0 {
            basis += batch.beta_accum_c1 * G + batch.beta_accum_c2 * pk.0;
        }
        scalars.push(batch.rho_accum_glue * *z);
        points.push(basis);
    }
    scalars.push(-batch.rho_accum_glue);
    points.push(accum_glue_a_t);
    scalars.push(-batch.rho_accum_glue * batch.challenge);
    points.push(alpha_tag);
    scalars.push(-batch.rho_accum_glue * batch.challenge * batch.beta_accum_y);
    points.push(accum_y_comm_pt);
    scalars.push(-batch.rho_accum_glue * batch.challenge * batch.beta_accum_c1);
    points.push(accum_scaled_eval.c1);
    scalars.push(-batch.rho_accum_glue * batch.challenge * batch.beta_accum_c2);
    points.push(accum_scaled_eval.c2);

    scalars.push(
        batch.rho_accum_partial
            * (proof.accum_partial_z1
                + proof.accum_partial_z2 * batch.gamma_accum_pd * batch.beta_accum_pd),
    );
    points.push(G);
    scalars.push(batch.rho_accum_partial * proof.accum_partial_z2 * batch.gamma_accum_pd);
    points.push(pk1.0);
    scalars.push(-batch.rho_accum_partial * proof.accum_partial_z1 * batch.gamma_accum_pd);
    points.push(accum_scaled_eval.c1);
    scalars.push(-batch.rho_accum_partial);
    points.push(accum_partial_a);
    scalars.push(-batch.rho_accum_partial * batch.challenge);
    points.push(pk2.0);
    scalars.push(-batch.rho_accum_partial * batch.challenge * batch.gamma_accum_pd);
    points.push(accum_delta_c2);
    scalars.push(
        -batch.rho_accum_partial * batch.challenge * batch.gamma_accum_pd * batch.beta_accum_pd,
    );
    points.push(accum_delta_c1);

    scalars.push(batch.rho_accum_mul * proof.accum_mul_s_y);
    points.push(accum_mul_x_c1);
    scalars.push(batch.rho_accum_mul * batch.beta_accum_mul * proof.accum_mul_s_y);
    points.push(accum_mul_x_c2);
    scalars.push(batch.rho_accum_mul * batch.gamma_accum_mul * proof.accum_mul_s_y);
    points.push(G);
    scalars.push(-batch.rho_accum_mul);
    points.push(accum_mul_a1);
    scalars.push(-batch.rho_accum_mul * batch.beta_accum_mul);
    points.push(accum_mul_a2);
    scalars.push(-batch.rho_accum_mul * batch.gamma_accum_mul);
    points.push(accum_mul_a_m);
    scalars.push(-batch.rho_accum_mul * batch.challenge);
    points.push(accum_mul_y_c1);
    scalars.push(-batch.rho_accum_mul * batch.challenge * batch.beta_accum_mul);
    points.push(accum_mul_y_c2);
    scalars.push(-batch.rho_accum_mul * batch.challenge * batch.gamma_accum_mul);
    points.push(alpha_tag);

    let check =
        RistrettoPoint::vartime_multiscalar_mul(scalars.iter().copied(), points.iter().copied());
    if check != RistrettoPoint::identity() {
        return Err("combined sigma batch check failed".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{
        combine_public_keys, ct_add, ct_scalar_mul, encrypt_poly, eval_poly, generate_key_share,
        partial_decrypt_with_witness, poly_scalar_mul,
    };
    use rand::rngs::OsRng;

    #[test]
    fn round_rejects_well_formed_but_false_accum_eval() {
        let mut rng = OsRng;
        let (_sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        let config = BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 1,
            target_marked_count: 3,
        };
        let y = Scalar::from(19u64);

        let t_poly = encrypt_poly(
            &mut rng,
            &pk,
            &[Scalar::from(3u64), Scalar::from(7u64), Scalar::from(11u64)],
        );
        let eval_mask = Scalar::from(13u64);
        let aggregate = build_aggregate_eval_witness(&t_poly, y, config, eval_mask, &pk).unwrap();
        let (m_poly_ct, mpoly_r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &aggregate.scaled_eval);

        let accum = encrypt_poly(
            &mut rng,
            &pk,
            &[Scalar::one(), Scalar::from(2u64), Scalar::from(4u64)],
        );
        let next_accum = poly_scalar_mul(&accum, &y);
        let accum_mask = Scalar::from(17u64);
        let accum_eval = eval_poly(&accum, &y);
        let correct_accum_scaled = ct_add(
            &ct_scalar_mul(&accum_eval, &accum_mask),
            &Ciphertext {
                c1: mul_g(&accum_mask),
                c2: accum_mask * pk.0,
            },
        );
        let false_accum_scaled = Ciphertext {
            c1: correct_accum_scaled.c1 + G,
            c2: correct_accum_scaled.c2,
        };
        let (false_accum_partial, accum_r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &false_accum_scaled);

        let pc_gens = PedersenGens::default();
        let target_cap = crate::bf::bp_capacity(t_poly.0.len() - 1, config);
        let accum_cap = (2 * accum.0.len()).next_power_of_two().max(64);
        let bp_gens = BulletproofGens::new(target_cap.max(accum_cap), 1);
        let (_, proof) = prove_round(
            &mut rng,
            &pc_gens,
            &bp_gens,
            &t_poly,
            config.hash_count,
            &aggregate.e_vals,
            &aggregate.term_masks,
            &aggregate.scaled_eval,
            y,
            eval_mask,
            &pk,
            &pk1,
            &pk2,
            &m_poly_ct,
            &false_accum_scaled,
            &false_accum_partial,
            &accum,
            &next_accum,
            mpoly_r_prime,
            accum_mask,
            accum_r_prime,
            sk2.as_scalar(),
        )
        .expect("prover can construct commitments from a false witness");

        assert!(
            verify_round(
                &pc_gens,
                &bp_gens,
                config,
                &pk,
                &pk1,
                &pk2,
                &t_poly,
                &aggregate.scaled_eval,
                &m_poly_ct,
                &false_accum_scaled,
                &false_accum_partial,
                &accum,
                &next_accum,
                &proof,
            )
            .is_err(),
            "a valid partial decrypt of an unrelated accumulator ciphertext must be rejected",
        );
    }

    #[test]
    fn multi_hash_term_masks_are_bound_to_the_l9_sigma_bullet_bridge() {
        let mut rng = OsRng;
        let (_sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        let config = BloomFilterConfig {
            bloom_filter_size: 32,
            hash_count: 3,
            target_marked_count: 8,
        };
        let y = Scalar::from(2u64);
        let t_poly = encrypt_poly(
            &mut rng,
            &pk,
            &[Scalar::from(3u64), Scalar::from(7u64), Scalar::from(11u64)],
        );
        let eval_mask = Scalar::from(13u64);
        let aggregate = build_aggregate_eval_witness(&t_poly, y, config, eval_mask, &pk).unwrap();
        assert_eq!(aggregate.term_masks, scalar_positions(y, config));
        let (m_poly_ct, mpoly_r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &aggregate.scaled_eval);

        let accum = encrypt_poly(
            &mut rng,
            &pk,
            &[Scalar::one(), Scalar::from(2u64), Scalar::from(4u64)],
        );
        let next_accum = poly_scalar_mul(&accum, &y);
        let accum_mask = Scalar::from(17u64);
        let accum_eval = eval_poly(&accum, &y);
        let accum_scaled = ct_add(
            &ct_scalar_mul(&accum_eval, &accum_mask),
            &Ciphertext {
                c1: mul_g(&accum_mask),
                c2: accum_mask * pk.0,
            },
        );
        let (accum_m_poly_ct, accum_r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &accum_scaled);

        let pc_gens = PedersenGens::default();
        let target_cap = crate::bf::bp_capacity(t_poly.0.len() - 1, config);
        let accum_cap = (2 * accum.0.len()).next_power_of_two().max(64);
        let bp_gens = BulletproofGens::new(target_cap.max(accum_cap), 1);
        let (_, proof) = prove_round(
            &mut rng,
            &pc_gens,
            &bp_gens,
            &t_poly,
            config.hash_count,
            &aggregate.e_vals,
            &aggregate.term_masks,
            &aggregate.scaled_eval,
            y,
            eval_mask,
            &pk,
            &pk1,
            &pk2,
            &m_poly_ct,
            &accum_scaled,
            &accum_m_poly_ct,
            &accum,
            &next_accum,
            mpoly_r_prime,
            accum_mask,
            accum_r_prime,
            sk2.as_scalar(),
        )
        .expect("valid multi-hash round proof");

        verify_round(
            &pc_gens,
            &bp_gens,
            config,
            &pk,
            &pk1,
            &pk2,
            &t_poly,
            &aggregate.scaled_eval,
            &m_poly_ct,
            &accum_scaled,
            &accum_m_poly_ct,
            &accum,
            &next_accum,
            &proof,
        )
        .expect("valid per-term masks must verify");

        let mut tampered = proof.clone();
        let z = Scalar::from_canonical_bytes(tampered.aggregate_eval_proof.mask_z[1])
            .expect("prover emitted canonical scalar");
        tampered.aggregate_eval_proof.mask_z[1] = (z + Scalar::one()).to_bytes();
        assert!(
            verify_round(
                &pc_gens,
                &bp_gens,
                config,
                &pk,
                &pk1,
                &pk2,
                &t_poly,
                &aggregate.scaled_eval,
                &m_poly_ct,
                &accum_scaled,
                &accum_m_poly_ct,
                &accum,
                &next_accum,
                &tampered,
            )
            .is_err(),
            "tampering with a per-term mask bridge response must be rejected",
        );
    }
}
