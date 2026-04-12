use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

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
use crate::crypto::elgamal::{
    ct_add, ct_scalar_mul, Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare,
};
use crate::crypto::sigma::{self, PolyScalarMulProof};

pub(crate) struct AggregateEvalWitness {
    pub e_vals: Vec<Scalar>,
    pub scaled_eval: Ciphertext,
}

#[derive(Clone, Debug)]
struct EvalSumProof {
    proof: R1CSProof,
    e_comms: Vec<CompressedRistretto>,
    y_comm: CompressedRistretto,
    r_comm: CompressedRistretto,
    inv_r_comm: CompressedRistretto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireEvalSumProof {
    pub proof_bytes: Vec<u8>,
    pub e_comms: Vec<[u8; 32]>,
    pub y_comm: [u8; 32],
    pub r_comm: [u8; 32],
    pub inv_r_comm: [u8; 32],
}

#[derive(Clone, Debug)]
struct CombinedSigmaProof {
    eval_proof: EvalSumProof,
    alpha_tag: CompressedRistretto,
    glue_a_t: CompressedRistretto,
    glue_z_e: Vec<Scalar>,
    glue_z_alpha: Scalar,
    glue_z_y_blind: Scalar,
    partial_a: CompressedRistretto,
    partial_z1: Scalar,
    partial_z2: Scalar,
    accum_partial_a: CompressedRistretto,
    accum_partial_z1: Scalar,
    accum_partial_z2: Scalar,
    accum_mul_a1: CompressedRistretto,
    accum_mul_a2: CompressedRistretto,
    accum_mul_a_m: CompressedRistretto,
    accum_mul_s_y: Scalar,
}

#[derive(Clone, Copy, Debug)]
struct RoundBatchScalars {
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    beta_pd: Scalar,
    gamma_pd: Scalar,
    beta_accum_pd: Scalar,
    gamma_accum_pd: Scalar,
    beta_accum_mul: Scalar,
    gamma_accum_mul: Scalar,
    challenge: Scalar,
    rho_glue: Scalar,
    rho_partial: Scalar,
    rho_accum_partial: Scalar,
    rho_accum_mul: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireCombinedSigmaProof {
    pub eval_proof: WireEvalSumProof,
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

fn power_sum_coefficients(hash_count: usize, coeff_len: usize) -> Arc<Vec<Vec<Scalar>>> {
    static CACHE: OnceLock<Mutex<HashMap<(usize, usize), Arc<Vec<Vec<Scalar>>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(coeffs) = cache
        .lock()
        .expect("power_sum_coefficients cache poisoned")
        .get(&(hash_count, coeff_len))
        .cloned()
    {
        return coeffs;
    }

    let mut coeffs = vec![vec![Scalar::zero(); coeff_len]; coeff_len];
    for hash_index in 0..hash_count {
        let (slope, intercept) = hash_params(hash_index);
        let mut slope_pows = vec![Scalar::one(); coeff_len];
        let mut intercept_pows = vec![Scalar::one(); coeff_len];
        for idx in 1..coeff_len {
            slope_pows[idx] = slope_pows[idx - 1] * slope;
            intercept_pows[idx] = intercept_pows[idx - 1] * intercept;
        }

        let mut binom = vec![Scalar::zero(); coeff_len];
        binom[0] = Scalar::one();
        for degree in 0..coeff_len {
            if degree > 0 {
                for t in (1..=degree).rev() {
                    let prev = binom[t - 1];
                    binom[t] += prev;
                }
            }
            for t in 0..=degree {
                coeffs[degree][t] += binom[t] * slope_pows[t] * intercept_pows[degree - t];
            }
        }
    }
    let coeffs = Arc::new(coeffs);
    cache
        .lock()
        .expect("power_sum_coefficients cache poisoned")
        .insert((hash_count, coeff_len), coeffs.clone());
    coeffs
}

fn characteristic_coefficients(hash_count: usize) -> Arc<Vec<Vec<Scalar>>> {
    static CACHE: OnceLock<Mutex<HashMap<usize, Arc<Vec<Vec<Scalar>>>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(coeffs) = cache
        .lock()
        .expect("characteristic_coefficients cache poisoned")
        .get(&hash_count)
        .cloned()
    {
        return coeffs;
    }

    let max_deg = hash_count;
    let mut coeffs = vec![vec![Scalar::zero(); max_deg + 1]; max_deg + 1];
    let mut next = vec![vec![Scalar::zero(); max_deg + 1]; max_deg + 1];
    coeffs[0][0] = Scalar::one();
    let mut poly_deg = 0usize;
    for hash_index in 0..hash_count {
        let (slope, intercept) = hash_params(hash_index);
        for row in &mut next {
            for val in row.iter_mut() {
                *val = Scalar::zero();
            }
        }
        for x_deg in 0..=poly_deg {
            for y_deg in 0..=max_deg {
                let coeff = coeffs[x_deg][y_deg];
                if coeff == Scalar::zero() {
                    continue;
                }
                next[x_deg + 1][y_deg] += coeff;
                next[x_deg][y_deg] -= intercept * coeff;
                if y_deg < max_deg {
                    next[x_deg][y_deg + 1] -= slope * coeff;
                }
            }
        }
        std::mem::swap(&mut coeffs, &mut next);
        poly_deg += 1;
    }

    let coeffs = Arc::new(coeffs);
    cache
        .lock()
        .expect("characteristic_coefficients cache poisoned")
        .insert(hash_count, coeffs.clone());
    coeffs
}

fn eval_sum_relation_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    e_vars: &[Variable],
    y_var: Variable,
    r_var: Variable,
    hash_count: usize,
    inv_r_var: Variable,
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

    let init_len = hash_count.min(e_vars.len());
    let init_coeffs = power_sum_coefficients(hash_count, init_len);
    let char_coeffs = characteristic_coefficients(hash_count);

    let mut q_vars = Vec::with_capacity(init_len);
    if init_len > 0 {
        q_vars.push(r_var);
    }
    let mut current_q = r_var;
    for _ in 1..init_len {
        let (_, _, next_q) = cs.multiply(
            LinearCombination::from(current_q),
            LinearCombination::from(y_var),
        );
        q_vars.push(next_q);
        current_q = next_q;
    }

    let mut z_vars = Vec::with_capacity(hash_count + 1);
    z_vars.push(None);
    let mut current_z: Option<Variable> = None;
    for _ in 0..hash_count {
        let left = current_z.map_or_else(
            || LinearCombination::from(Scalar::one()),
            LinearCombination::from,
        );
        let (_, _, next_z) = cs.multiply(left, LinearCombination::from(y_var));
        z_vars.push(Some(next_z));
        current_z = Some(next_z);
    }

    for degree in 0..init_len {
        let mut expected = LinearCombination::default();
        for (t, q_var) in q_vars.iter().copied().take(degree + 1).enumerate() {
            let coeff = init_coeffs[degree][t];
            if coeff != Scalar::zero() {
                expected = expected + coeff * LinearCombination::from(q_var);
            }
        }
        cs.constrain(expected - LinearCombination::from(e_vars[degree]));
    }

    for m in 0..e_vars.len().saturating_sub(hash_count) {
        let mut recurrence = LinearCombination::from(e_vars[m + hash_count]);
        for coeff_index in 0..hash_count {
            let mut coeff_lc = LinearCombination::default();
            for (y_deg, z_var) in z_vars.iter().enumerate() {
                let coeff = char_coeffs[coeff_index][y_deg];
                if coeff == Scalar::zero() {
                    continue;
                }
                coeff_lc = match z_var {
                    Some(z_var) => coeff_lc + coeff * LinearCombination::from(*z_var),
                    None => coeff_lc + coeff,
                };
            }
            let (_, _, prod) =
                cs.multiply(coeff_lc, LinearCombination::from(e_vars[m + coeff_index]));
            recurrence = recurrence + LinearCombination::from(prod);
        }
        cs.constrain(recurrence);
    }

    Ok(())
}

fn prove_eval_sum_with_openings<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    y: Scalar,
    hash_count: usize,
    e_vals: &[Scalar],
    r: Scalar,
) -> Result<(EvalSumProof, Scalar), R1CSError> {
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

    let (r_comm, r_var) = prover.commit(r, Scalar::random(rng));
    let (inv_r_comm, inv_r_var) = prover.commit(r.invert(), Scalar::random(rng));

    eval_sum_relation_gadget(&mut prover, &e_vars, y_var, r_var, hash_count, inv_r_var)?;

    let proof = prover.prove(bp_gens)?;
    Ok((
        EvalSumProof {
            proof,
            e_comms,
            y_comm,
            r_comm,
            inv_r_comm,
        },
        y_blind,
    ))
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

    let mut transcript = Transcript::new(b"I-PSI-CA::bf_eval_sum_v1");
    let mut verifier = Verifier::new(&mut transcript);

    let e_vars: Vec<_> = proof
        .e_comms
        .iter()
        .copied()
        .map(|comm| verifier.commit(comm))
        .collect();
    let y_var = verifier.commit(proof.y_comm);
    let r_var = verifier.commit(proof.r_comm);
    let inv_r_var = verifier.commit(proof.inv_r_comm);

    eval_sum_relation_gadget(&mut verifier, &e_vars, y_var, r_var, hash_count, inv_r_var)
        .map_err(|e| format!("BF Bulletproof gadget invalid: {e:?}"))?;

    verifier
        .verify(&proof.proof, pc_gens, bp_gens)
        .map_err(|e| format!("BF Bulletproof verification failed: {e:?}"))
}

fn eval_witnesses_from_positions(coeff_len: usize, positions: &[Scalar], r: Scalar) -> Vec<Scalar> {
    let mut sums = vec![Scalar::zero(); coeff_len];
    for &position in positions {
        let mut power = Scalar::one();
        for sum in &mut sums {
            *sum += power;
            power *= position;
        }
    }
    sums.into_iter().map(|sum| r * sum).collect()
}

fn weighted_ciphertext_sum(
    coeff_cts: &[Ciphertext],
    weights: &[Scalar],
) -> Result<Ciphertext, String> {
    if coeff_cts.is_empty() {
        return Err("coeff_cts must not be empty".to_string());
    }
    if coeff_cts.len() != weights.len() {
        return Err("ciphertext/weight length mismatch".to_string());
    }

    let init = ct_scalar_mul(&coeff_cts[0], &weights[0]);
    Ok(coeff_cts[1..]
        .iter()
        .zip(weights[1..].iter())
        .fold(init, |acc, (ct, weight)| {
            ct_add(&acc, &ct_scalar_mul(ct, weight))
        }))
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

    let e_vals = eval_witnesses_from_positions(poly.0.len(), &positions, eval_mask);
    let scaled_eval_no_blind = weighted_ciphertext_sum(&poly.0, &e_vals)?;
    let scaled_eval = ct_add(
        &scaled_eval_no_blind,
        &Ciphertext {
            c1: &eval_mask * &RISTRETTO_BASEPOINT_TABLE,
            c2: eval_mask * pk.0,
        },
    );
    Ok(AggregateEvalWitness {
        e_vals,
        scaled_eval,
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
    append_compressed(t, b"y_comm", &eval_proof.y_comm);
    append_compressed(t, b"r_comm", &eval_proof.r_comm);
    t.append_message(b"r1cs", &eval_proof.proof.to_bytes());
    t.append_message(b"beta_y", &beta_y.to_bytes());
    t.append_message(b"beta_c1", &beta_c1.to_bytes());
    t.append_message(b"beta_c2", &beta_c2.to_bytes());
    append_compressed(t, b"alpha_tag", alpha_tag);
    append_compressed(t, b"A_t", glue_a_t);
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
fn combined_transcript(
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    eval_proof: &EvalSumProof,
    alpha_tag: &CompressedRistretto,
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
    let mut t = Transcript::new(b"I-PSI-CA::bf_combined_sigma_round_v1");
    append_glue_section(
        &mut t, eval_proof, pk, coeff_cts, c_star, beta_y, beta_c1, beta_c2, alpha_tag, glue_a_t,
    );
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
) -> (Scalar, Scalar, Scalar, Scalar, Scalar) {
    let mut t = combined_transcript(
        pk,
        coeff_cts,
        c_star,
        eval_proof,
        alpha_tag,
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
    let rho_partial = batch_scalar(&mut t, b"rho_partial");
    let rho_accum_partial = batch_scalar(&mut t, b"rho_accum_partial");
    let rho_accum_mul = batch_scalar(&mut t, b"rho_accum_mul");
    (
        challenge,
        rho_glue,
        rho_partial,
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
    glue_a_t: &CompressedRistretto,
    partial_out_ct: &Ciphertext,
    partial_a: &CompressedRistretto,
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

    let (challenge, rho_glue, rho_partial, rho_accum_partial, rho_accum_mul) = combined_challenge(
        pk,
        coeff_cts,
        c_star,
        eval_proof,
        alpha_tag,
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
        beta_accum_pd,
        gamma_accum_pd,
        beta_accum_mul,
        gamma_accum_mul,
        challenge,
        rho_glue,
        rho_partial,
        rho_accum_partial,
        rho_accum_mul,
    })
}

impl WireEvalSumProof {
    fn from_proof(p: &EvalSumProof) -> Self {
        Self {
            proof_bytes: p.proof.to_bytes(),
            e_comms: p.e_comms.iter().map(|c| c.to_bytes()).collect(),
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
            y_comm: CompressedRistretto::from_slice(&self.y_comm),
            r_comm: CompressedRistretto::from_slice(&self.r_comm),
            inv_r_comm: CompressedRistretto::from_slice(&self.inv_r_comm),
        })
    }
}

impl WireCombinedSigmaProof {
    fn from_proof(p: &CombinedSigmaProof) -> Self {
        Self {
            eval_proof: WireEvalSumProof::from_proof(&p.eval_proof),
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

    fn to_proof(&self) -> Result<CombinedSigmaProof, String> {
        let glue_z_e: Result<Vec<_>, _> = self
            .glue_z_e
            .iter()
            .map(|b| Scalar::from_canonical_bytes(*b).ok_or("glue_z_e: non-canonical scalar"))
            .collect();
        Ok(CombinedSigmaProof {
            eval_proof: self.eval_proof.to_proof()?,
            alpha_tag: CompressedRistretto::from_slice(&self.alpha_tag),
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
pub fn prove_round<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    t_poly: &EncryptedPoly,
    hash_count: usize,
    e_vals: &[Scalar],
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
    accum_r_prime: Scalar,
    sk2: &Scalar,
) -> Result<(Ciphertext, RoundProof), R1CSError> {
    let (eval_proof, y_blind) =
        prove_eval_sum_with_openings(rng, pc_gens, bp_gens, y, hash_count, e_vals, eval_mask)?;
    let hash_count_inv = Scalar::from(hash_count as u64).invert();

    let mut k_e = Vec::with_capacity(e_vals.len());
    for _ in 0..e_vals.len() {
        k_e.push(Scalar::random(rng));
    }
    let k_alpha = Scalar::random(rng);
    let k_y_blind = Scalar::random(rng);
    let alpha_tag_pt = mul_g(&y);
    let alpha_tag = alpha_tag_pt.compress();

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
        let mut basis = beta_c1 * ct.c1 + beta_c2 * ct.c2;
        if idx == 0 {
            basis += hash_count_inv * (beta_c1 * G + beta_c2 * pk.0);
        }
        points.push(basis);
    }
    let glue_a_t =
        RistrettoPoint::multiscalar_mul(scalars.iter().copied(), points.iter().copied()).compress();

    let k_sk2 = Scalar::random(rng);
    let k_r_prime = Scalar::random(rng);
    let (beta_pd, gamma_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, scaled_eval, m_poly_ct);
    let beta_g = mul_g(&beta_pd);
    let partial_a = (mul_g(&k_sk2) - k_sk2 * (gamma_pd * scaled_eval.c1)
        + k_r_prime * (gamma_pd * (pk1.0 + beta_g)))
        .compress();

    let k_accum_sk2 = Scalar::random(rng);
    let k_accum_r_prime = Scalar::random(rng);
    let (beta_accum_pd, gamma_accum_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, accum_scaled_eval, accum_m_poly_ct);
    let accum_beta_g = mul_g(&beta_accum_pd);
    let accum_partial_a = (mul_g(&k_accum_sk2)
        - k_accum_sk2 * (gamma_accum_pd * accum_scaled_eval.c1)
        + k_accum_r_prime * (gamma_accum_pd * (pk1.0 + accum_beta_g)))
        .compress();

    let (accum_x_c1, accum_x_c2, _accum_y_c1, _accum_y_c2, _) =
        sigma::poly_scalar_mul_relation_points(accum_in, next_accum, &alpha_tag_pt);
    let k_accum_mul_y = Scalar::random(rng);
    let accum_mul_a1 = (k_accum_mul_y * accum_x_c1).compress();
    let accum_mul_a2 = (k_accum_mul_y * accum_x_c2).compress();
    let accum_mul_a_m = mul_g(&k_accum_mul_y).compress();
    let batch = derive_round_batch_scalars(
        pk,
        pk1,
        pk2,
        &t_poly.0,
        scaled_eval,
        &eval_proof,
        &alpha_tag,
        &glue_a_t,
        m_poly_ct,
        &partial_a,
        accum_scaled_eval,
        accum_m_poly_ct,
        &accum_partial_a,
        accum_in,
        next_accum,
        &accum_mul_a1,
        &accum_mul_a2,
        &accum_mul_a_m,
        Scalar::zero(),
    )
    .map_err(|description| R1CSError::GadgetError { description })?;

    Ok((
        scaled_eval.clone(),
        RoundProof {
            aggregate_eval_proof: WireCombinedSigmaProof::from_proof(&CombinedSigmaProof {
                eval_proof,
                alpha_tag,
                glue_a_t,
                glue_z_e: k_e
                    .iter()
                    .zip(e_vals.iter())
                    .map(|(k, e)| k + batch.challenge * e)
                    .collect(),
                glue_z_alpha: k_alpha + batch.challenge * y,
                glue_z_y_blind: k_y_blind + batch.challenge * y_blind,
                partial_a,
                partial_z1: k_sk2 + batch.challenge * sk2,
                partial_z2: k_r_prime + batch.challenge * mpoly_r_prime,
                accum_partial_a,
                accum_partial_z1: k_accum_sk2 + batch.challenge * sk2,
                accum_partial_z2: k_accum_r_prime + batch.challenge * accum_r_prime,
                accum_mul_a1,
                accum_mul_a2,
                accum_mul_a_m,
                accum_mul_s_y: k_accum_mul_y + batch.challenge * y,
            }),
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
    let proof = round_proof.aggregate_eval_proof.to_proof()?;
    if proof.eval_proof.e_comms.len() != t_poly.0.len() {
        return Err("e commitment length mismatch".to_string());
    }
    if proof.glue_z_e.len() != t_poly.0.len() {
        return Err("glue vector length mismatch".to_string());
    }

    verify_eval_sum(pc_gens, bp_gens, bf_config.hash_count, &proof.eval_proof)?;

    let alpha_tag = proof
        .alpha_tag
        .decompress()
        .ok_or_else(|| "invalid alpha_tag point".to_string())?;
    let glue_a_t = proof
        .glue_a_t
        .decompress()
        .ok_or_else(|| "invalid glue A_t point".to_string())?;
    let partial_a = proof
        .partial_a
        .decompress()
        .ok_or_else(|| "invalid partial A point".to_string())?;
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
    let hash_count_inv = Scalar::from(bf_config.hash_count as u64).invert();

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
        &proof.glue_a_t,
        m_poly_ct,
        &proof.partial_a,
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
            basis += hash_count_inv * (batch.beta_c1 * G + batch.beta_c2 * pk.0);
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
