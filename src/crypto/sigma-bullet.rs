//! Sigma-Bullet "glue" proof for encrypted polynomial evaluation.
//!
//! Statement proved:
//!   C* = sum_{i=0}^d e_i * C_i + Enc_pk(0; r)
//! with hidden witnesses (alpha, r, e_0..e_d) such that:
//!   e_0 = r,  e_{i+1} = e_i * alpha,  r != 0.
//!
//! The proof has two layers:
//! 1) Bulletproof R1CS (`chain_proof`) over commitments to [e_d..e_0], proving
//!    the geometric chain and non-zero seed.
//! 2) Schnorr-style glue proof (`glue`) showing the same committed e_i values
//!    satisfy the ciphertext relation above.

use bulletproofs::{
    r1cs::{LinearCombination, Prover, R1CSError, Variable},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::{
    constants::{RISTRETTO_BASEPOINT_POINT as G, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, MultiscalarMul, VartimeMultiscalarMul},
};
use merlin::Transcript;
use rand::{thread_rng, CryptoRng, RngCore};

use crate::crypto::bulletproof as bp;
use crate::crypto::elgamal::{Ciphertext, PublicKey};
use crate::crypto::sigma::{self, PolyScalarMulProof};

/// Schnorr glue proof binding committed `e_i` values to the ciphertext relation.
#[derive(Clone, Debug)]
pub struct GlueProof {
    /// Public tag binding the hidden alpha across proofs: `alpha_tag = alpha * G`.
    pub alpha_tag: CompressedRistretto,
    /// Single batched Sigma-Bullet nonce commitment.
    pub a_t: CompressedRistretto,
    /// Responses for e_i witnesses.
    pub z_e: Vec<Scalar>,
    /// Response for alpha witness: `z_alpha = k_alpha + c * alpha`.
    pub z_alpha: Scalar,
    /// Response for y-commitment blinding: `z_y_blind = k_y + c * blind_y`.
    pub z_y_blind: Scalar,
}

/// Hybrid proof output: arithmetic Bulletproof + Sigma glue.
pub struct SigmaBulletProof {
    pub chain_proof: bp::EvalChainProof,
    pub glue: GlueProof,
}

/// Full round proof: arithmetic Bulletproof layer plus batched Schnorr
/// relations for:
/// 1. `t_poly_ct` evaluation glue,
/// 2. partial decryption of the masked `t_poly_ct` evaluation,
/// 3. `accum` evaluation glue under an independent non-zero mask,
/// 4. partial decryption of the masked `accum` evaluation,
/// 5. `next_accum = y · accum`,
/// all sharing one Fiat-Shamir challenge and one `alpha_tag = y·G`.
pub struct CombinedSigmaProof {
    pub chain_proof: bp::EvalChainProof,
    pub alpha_tag: CompressedRistretto,
    pub glue_a_t: CompressedRistretto,
    pub glue_z_e: Vec<Scalar>,
    pub glue_z_alpha: Scalar,
    pub glue_z_y_blind: Scalar,
    pub partial_a: CompressedRistretto,
    pub partial_z1: Scalar,
    pub partial_z2: Scalar,
    pub accum_chain_proof: bp::EvalChainProof,
    pub accum_glue_a_t: CompressedRistretto,
    pub accum_glue_z_e: Vec<Scalar>,
    pub accum_glue_z_alpha: Scalar,
    pub accum_glue_z_y_blind: Scalar,
    pub accum_partial_a: CompressedRistretto,
    pub accum_partial_z1: Scalar,
    pub accum_partial_z2: Scalar,
    pub accum_mul_a1: CompressedRistretto,
    pub accum_mul_a2: CompressedRistretto,
    pub accum_mul_a_m: CompressedRistretto,
    pub accum_mul_s_y: Scalar,
}

/// Accumulator-independent part of a full monitor-round proof.
///
/// This contains every commitment that can be built before the accumulator is
/// available. The Fiat-Shamir challenge is deliberately deferred because it
/// binds both these commitments and the accumulator-dependent relations.
pub(crate) struct RoundProofPrecomputation {
    chain_proof: bp::EvalChainProof,
    e_asc: Vec<Scalar>,
    y_blind: Scalar,
    k_e: Vec<Scalar>,
    alpha: Scalar,
    alpha_tag_pt: RistrettoPoint,
    alpha_tag: CompressedRistretto,
    k_alpha: Scalar,
    k_y_blind: Scalar,
    glue_a_t: CompressedRistretto,
    k_sk2: Scalar,
    k_r_prime: Scalar,
    partial_a: CompressedRistretto,
    r_prime: Scalar,
    sk2: Scalar,
    transcript: Transcript,
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

fn glue_transcript(
    chain_proof: &bp::EvalChainProof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::sigma_bullet_glue_v1");
    append_point(&mut t, b"pk", &pk.0);

    for c in coeff_cts {
        append_point(&mut t, b"coef_c1", &c.c1);
        append_point(&mut t, b"coef_c2", &c.c2);
    }
    append_point(&mut t, b"cstar_c1", &c_star.c1);
    append_point(&mut t, b"cstar_c2", &c_star.c2);

    for c in &chain_proof.e_comms {
        append_compressed(&mut t, b"e_comm", c);
    }
    append_compressed(&mut t, b"y_comm", &chain_proof.y_comm);
    append_compressed(&mut t, b"inv_comm", &chain_proof.inv_en_comm);
    t.append_message(b"r1cs", &chain_proof.proof.to_bytes());

    t
}

pub(crate) fn append_glue_section(
    t: &mut Transcript,
    section: &'static [u8],
    chain_proof: &bp::EvalChainProof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    alpha_tag: &CompressedRistretto,
    glue_a_t: &CompressedRistretto,
) {
    t.append_message(b"section", section);
    append_point(t, b"pk", &pk.0);
    for c in coeff_cts {
        append_point(t, b"coef_c1", &c.c1);
        append_point(t, b"coef_c2", &c.c2);
    }
    append_point(t, b"cstar_c1", &c_star.c1);
    append_point(t, b"cstar_c2", &c_star.c2);
    for c in &chain_proof.e_comms {
        append_compressed(t, b"e_comm", c);
    }
    append_compressed(t, b"y_comm", &chain_proof.y_comm);
    append_compressed(t, b"inv_comm", &chain_proof.inv_en_comm);
    t.append_message(b"r1cs", &chain_proof.proof.to_bytes());
    t.append_message(b"beta_y", &beta_y.to_bytes());
    t.append_message(b"beta_c1", &beta_c1.to_bytes());
    t.append_message(b"beta_c2", &beta_c2.to_bytes());
    append_compressed(t, b"alpha_tag", alpha_tag);
    append_compressed(t, b"A_t", glue_a_t);
}

fn append_partial_decrypt_section(
    t: &mut Transcript,
    pk2: &crate::crypto::elgamal::PublicKeyShare,
    pk1: &crate::crypto::elgamal::PublicKeyShare,
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
    poly_in: &crate::crypto::elgamal::EncryptedPoly,
    poly_out: &crate::crypto::elgamal::EncryptedPoly,
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
    chain_proof: &bp::EvalChainProof,
    alpha_tag: &CompressedRistretto,
    glue_a_t: &CompressedRistretto,
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    pk2: &crate::crypto::elgamal::PublicKeyShare,
    pk1: &crate::crypto::elgamal::PublicKeyShare,
    partial_in_ct: &Ciphertext,
    partial_out_ct: &Ciphertext,
    beta_pd: Scalar,
    gamma_pd: Scalar,
    partial_a: &CompressedRistretto,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::combined_sigma_round_v2");
    append_glue_section(
        &mut t,
        b"sigma_bullet_glue",
        chain_proof,
        pk,
        coeff_cts,
        c_star,
        beta_y,
        beta_c1,
        beta_c2,
        alpha_tag,
        glue_a_t,
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
    t
}

#[allow(clippy::too_many_arguments)]
fn combined_transcript(
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    chain_proof: &bp::EvalChainProof,
    alpha_tag: &CompressedRistretto,
    glue_a_t: &CompressedRistretto,
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    pk2: &crate::crypto::elgamal::PublicKeyShare,
    pk1: &crate::crypto::elgamal::PublicKeyShare,
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
    accum_in: &crate::crypto::elgamal::EncryptedPoly,
    accum_out: &crate::crypto::elgamal::EncryptedPoly,
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
        chain_proof,
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
    );
    append_glue_section(
        &mut t,
        b"accum_sigma_bullet_glue",
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
    chain_proof: &bp::EvalChainProof,
    alpha_tag: &CompressedRistretto,
    glue_a_t: &CompressedRistretto,
    beta_y: Scalar,
    beta_c1: Scalar,
    beta_c2: Scalar,
    pk2: &crate::crypto::elgamal::PublicKeyShare,
    pk1: &crate::crypto::elgamal::PublicKeyShare,
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
    accum_in: &crate::crypto::elgamal::EncryptedPoly,
    accum_out: &crate::crypto::elgamal::EncryptedPoly,
    beta_accum_mul: Scalar,
    gamma_accum_mul: Scalar,
    accum_mul_a1: &CompressedRistretto,
    accum_mul_a2: &CompressedRistretto,
    accum_mul_a_m: &CompressedRistretto,
) -> (Scalar, Scalar, Scalar, Scalar, Scalar, Scalar) {
    let mut t = combined_transcript(
        pk,
        coeff_cts,
        c_star,
        chain_proof,
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
    let rho_partial = batch_scalar(&mut t, b"rho_partial");
    let rho_accum_glue = batch_scalar(&mut t, b"rho_accum_glue");
    let rho_accum_partial = batch_scalar(&mut t, b"rho_accum_partial");
    let rho_accum_mul = batch_scalar(&mut t, b"rho_accum_mul");
    (
        challenge,
        rho_glue,
        rho_partial,
        rho_accum_glue,
        rho_accum_partial,
        rho_accum_mul,
    )
}

/// Recompute the shared Fiat-Shamir challenge and per-relation batching
/// scalars for a full combined round proof from public inputs only.
#[allow(clippy::too_many_arguments)]
pub fn round_challenge_and_batch_scalars(
    pk: &PublicKey,
    pk1: &crate::crypto::elgamal::PublicKeyShare,
    pk2: &crate::crypto::elgamal::PublicKeyShare,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    partial_out_ct: &Ciphertext,
    accum_c_star: &Ciphertext,
    accum_partial_out_ct: &Ciphertext,
    accum_in: &crate::crypto::elgamal::EncryptedPoly,
    accum_out: &crate::crypto::elgamal::EncryptedPoly,
    proof: &CombinedSigmaProof,
) -> Result<(Scalar, Scalar, Scalar, Scalar, Scalar, Scalar), String> {
    let alpha_tag = proof
        .alpha_tag
        .decompress()
        .ok_or_else(|| "invalid alpha_tag point".to_string())?;
    let (beta_y, beta_c1, beta_c2) = relation_scalars(&proof.chain_proof, pk, coeff_cts, c_star);
    let (beta_pd, gamma_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, c_star, partial_out_ct);
    let (beta_accum_y, beta_accum_c1, beta_accum_c2) =
        relation_scalars(&proof.accum_chain_proof, pk, &accum_in.0, accum_c_star);
    let (beta_accum_pd, gamma_accum_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, accum_c_star, accum_partial_out_ct);
    let accum_mul_temp = PolyScalarMulProof {
        a1: proof.accum_mul_a1,
        a2: proof.accum_mul_a2,
        alpha_tag: proof.alpha_tag,
        a_m: proof.accum_mul_a_m,
        s_y: proof.accum_mul_s_y,
    };
    let (beta_accum_mul, gamma_accum_mul) =
        sigma::poly_scalar_mul_batch_scalars(&accum_mul_temp, accum_in, accum_out, &alpha_tag)
            .map_err(str::to_string)?;

    Ok(combined_challenge(
        pk,
        coeff_cts,
        c_star,
        &proof.chain_proof,
        &proof.alpha_tag,
        &proof.glue_a_t,
        beta_y,
        beta_c1,
        beta_c2,
        pk2,
        pk1,
        c_star,
        partial_out_ct,
        beta_pd,
        gamma_pd,
        &proof.partial_a,
        &proof.accum_chain_proof,
        &proof.accum_glue_a_t,
        beta_accum_y,
        beta_accum_c1,
        beta_accum_c2,
        accum_c_star,
        accum_partial_out_ct,
        beta_accum_pd,
        gamma_accum_pd,
        &proof.accum_partial_a,
        accum_in,
        accum_out,
        beta_accum_mul,
        gamma_accum_mul,
        &proof.accum_mul_a1,
        &proof.accum_mul_a2,
        &proof.accum_mul_a_m,
    ))
}

pub(crate) fn relation_scalars(
    chain_proof: &bp::EvalChainProof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
) -> (Scalar, Scalar, Scalar) {
    let mut t = glue_transcript(chain_proof, pk, coeff_cts, c_star);
    let beta_y = batch_scalar(&mut t, b"batch_y");
    let beta_c1 = batch_scalar(&mut t, b"batch_c1");
    let beta_c2 = batch_scalar(&mut t, b"batch_c2");
    (beta_y, beta_c1, beta_c2)
}

/// Build Bulletproof chain proof while retaining e-commitment blindings for glue.
pub(crate) fn prove_chain_with_openings<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    e_rev: &[Scalar],
    alpha: Scalar,
) -> Result<(bp::EvalChainProof, Scalar), R1CSError> {
    let n = e_rev.len() - 1;

    let mut transcript = Transcript::new(b"I-PSI-CA::eval_chain");
    let mut prover = Prover::new(pc_gens, &mut transcript);

    let mut e_comms = Vec::with_capacity(e_rev.len());
    let mut e_vars: Vec<Variable> = Vec::with_capacity(e_rev.len());
    for &ei in e_rev {
        let blind = Scalar::random(rng);
        let (comm, var) = prover.commit(ei, blind);
        e_comms.push(comm);
        e_vars.push(var);
    }

    let y_blind = Scalar::random(rng);
    let (y_comm, y_var) = prover.commit(alpha, y_blind);

    let inv_en = e_rev[n].invert();
    let (inv_en_comm, inv_en_var) = prover.commit(inv_en, Scalar::random(rng));

    let e_lcs: Vec<LinearCombination> = e_vars.into_iter().map(Into::into).collect();
    let y_lc: LinearCombination = y_var.into();
    bp::eval_chain_gadget(&mut prover, e_lcs, y_lc, inv_en_var)?;

    let proof = prover.prove(bp_gens)?;
    Ok((
        bp::EvalChainProof {
            proof,
            e_comms,
            y_comm,
            inv_en_comm,
        },
        y_blind,
    ))
}

/// Prove the Sigma-Bullet glue statement for ciphertext relation consistency.
pub fn prove(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    alpha: Scalar,
    r: Scalar,
) -> Result<SigmaBulletProof, R1CSError> {
    assert!(!coeff_cts.is_empty(), "coeff_cts must not be empty");

    // Build e_i chain in ascending order: e_0=r, e_{i+1}=e_i*alpha.
    let mut e_asc = Vec::with_capacity(coeff_cts.len());
    e_asc.push(r);
    for i in 1..coeff_cts.len() {
        e_asc.push(e_asc[i - 1] * alpha);
    }

    // Bulletproof gadget expects [e_d..e_0] so its non-zero check is on e_0=r.
    let e_rev: Vec<Scalar> = e_asc.iter().cloned().rev().collect();

    let mut rng = thread_rng();
    let (chain_proof, y_blind) =
        prove_chain_with_openings(&mut rng, pc_gens, bp_gens, &e_rev, alpha)?;

    let mut t = glue_transcript(&chain_proof, pk, coeff_cts, c_star);
    let (beta_y, beta_c1, beta_c2) = relation_scalars(&chain_proof, pk, coeff_cts, c_star);

    // One nonce per witness e_i.
    let mut k_e = Vec::with_capacity(e_asc.len());
    for _ in 0..e_asc.len() {
        let ke = Scalar::random(&mut rng);
        k_e.push(ke);
    }

    let alpha_tag = mul_g(&alpha).compress();
    let k_alpha = Scalar::random(&mut rng);
    let k_y_blind = Scalar::random(&mut rng);
    let mut scalars = Vec::with_capacity(3 + k_e.len());
    let mut points = Vec::with_capacity(3 + k_e.len());
    scalars.push(k_alpha);
    points.push(G);
    scalars.push(beta_y * k_alpha);
    points.push(pc_gens.B);
    scalars.push(beta_y * k_y_blind);
    points.push(pc_gens.B_blinding);
    for (idx, (ke, ct)) in k_e.iter().zip(coeff_cts.iter()).enumerate() {
        let mut basis = beta_c1 * ct.c1 + beta_c2 * ct.c2;
        if idx == 0 {
            basis = basis + beta_c1 * G + beta_c2 * pk.0;
        }
        scalars.push(*ke);
        points.push(basis);
    }
    let a_t = RistrettoPoint::multiscalar_mul(scalars.iter().copied(), points.iter().copied());

    t.append_message(b"beta_y", &beta_y.to_bytes());
    t.append_message(b"beta_c1", &beta_c1.to_bytes());
    t.append_message(b"beta_c2", &beta_c2.to_bytes());
    append_compressed(&mut t, b"alpha_tag", &alpha_tag);
    append_point(&mut t, b"A_t", &a_t);
    let chal = challenge_scalar(&mut t);

    let z_e: Vec<Scalar> = k_e
        .iter()
        .zip(e_asc.iter())
        .map(|(k, x)| k + chal * x)
        .collect();
    Ok(SigmaBulletProof {
        chain_proof,
        glue: GlueProof {
            alpha_tag,
            a_t: a_t.compress(),
            z_e,
            z_alpha: k_alpha + chal * alpha,
            z_y_blind: k_y_blind + chal * y_blind,
        },
    })
}

/// Prove the full monitor round with one shared Fiat-Shamir challenge across
/// Sigma-Bullet glue, two partial-decrypt relations, and `accum` scalar multiplication.
#[allow(clippy::too_many_arguments)]
pub(crate) fn preprocess_round_proof<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    pk: &PublicKey,
    pk1: &crate::crypto::elgamal::PublicKeyShare,
    pk2: &crate::crypto::elgamal::PublicKeyShare,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    partial_out_ct: &Ciphertext,
    alpha: Scalar,
    r: Scalar,
    r_prime: Scalar,
    sk2: &Scalar,
) -> Result<RoundProofPrecomputation, R1CSError> {
    assert!(!coeff_cts.is_empty(), "coeff_cts must not be empty");

    let mut e_asc = Vec::with_capacity(coeff_cts.len());
    e_asc.push(r);
    for i in 1..coeff_cts.len() {
        e_asc.push(e_asc[i - 1] * alpha);
    }
    let e_rev: Vec<Scalar> = e_asc.iter().cloned().rev().collect();
    let (chain_proof, y_blind) = prove_chain_with_openings(rng, pc_gens, bp_gens, &e_rev, alpha)?;

    let (beta_y, beta_c1, beta_c2) = relation_scalars(&chain_proof, pk, coeff_cts, c_star);
    let mut k_e = Vec::with_capacity(e_asc.len());
    for _ in 0..e_asc.len() {
        k_e.push(Scalar::random(rng));
    }

    let alpha_tag_pt = mul_g(&alpha);
    let alpha_tag = alpha_tag_pt.compress();
    let k_alpha = Scalar::random(rng);
    let k_y_blind = Scalar::random(rng);
    let mut scalars = Vec::with_capacity(3 + k_e.len());
    let mut points = Vec::with_capacity(3 + k_e.len());
    scalars.push(k_alpha);
    points.push(G);
    scalars.push(beta_y * k_alpha);
    points.push(pc_gens.B);
    scalars.push(beta_y * k_y_blind);
    points.push(pc_gens.B_blinding);
    for (idx, (ke, ct)) in k_e.iter().zip(coeff_cts.iter()).enumerate() {
        let mut basis = beta_c1 * ct.c1 + beta_c2 * ct.c2;
        if idx == 0 {
            basis = basis + beta_c1 * G + beta_c2 * pk.0;
        }
        scalars.push(*ke);
        points.push(basis);
    }
    let glue_a_t =
        RistrettoPoint::multiscalar_mul(scalars.iter().copied(), points.iter().copied()).compress();

    let (beta_pd, gamma_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, c_star, partial_out_ct);
    let k_sk2 = Scalar::random(rng);
    let k_r_prime = Scalar::random(rng);
    let beta_g = mul_g(&beta_pd);
    let partial_a = (mul_g(&k_sk2) - k_sk2 * (gamma_pd * c_star.c1)
        + k_r_prime * (gamma_pd * (pk1.0 + beta_g)))
        .compress();
    let transcript = combined_transcript_prefix(
        pk,
        coeff_cts,
        c_star,
        &chain_proof,
        &alpha_tag,
        &glue_a_t,
        beta_y,
        beta_c1,
        beta_c2,
        pk2,
        pk1,
        c_star,
        partial_out_ct,
        beta_pd,
        gamma_pd,
        &partial_a,
    );

    Ok(RoundProofPrecomputation {
        chain_proof,
        e_asc,
        y_blind,
        k_e,
        alpha,
        alpha_tag_pt,
        alpha_tag,
        k_alpha,
        k_y_blind,
        glue_a_t,
        k_sk2,
        k_r_prime,
        partial_a,
        r_prime,
        sk2: *sk2,
        transcript,
    })
}

/// Complete a monitor-round proof after the accumulator becomes available.
///
/// The shared random-oracle challenge is generated here, after all accumulator
/// statements and nonce commitments have been added to the transcript.
#[allow(clippy::too_many_arguments)]
pub(crate) fn finish_round_proof<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    pk: &PublicKey,
    pk1: &crate::crypto::elgamal::PublicKeyShare,
    pk2: &crate::crypto::elgamal::PublicKeyShare,
    accum_c_star: &Ciphertext,
    accum_partial_out_ct: &Ciphertext,
    accum_in: &crate::crypto::elgamal::EncryptedPoly,
    accum_out: &crate::crypto::elgamal::EncryptedPoly,
    accum_mask: Scalar,
    accum_r_prime: Scalar,
    precomputed: RoundProofPrecomputation,
) -> Result<CombinedSigmaProof, R1CSError> {
    let RoundProofPrecomputation {
        chain_proof,
        e_asc,
        y_blind,
        k_e,
        alpha,
        alpha_tag_pt,
        alpha_tag,
        k_alpha,
        k_y_blind,
        glue_a_t,
        k_sk2,
        k_r_prime,
        partial_a,
        r_prime,
        sk2,
        mut transcript,
    } = precomputed;

    let mut accum_e_asc = Vec::with_capacity(accum_in.0.len());
    accum_e_asc.push(accum_mask);
    for i in 1..accum_in.0.len() {
        accum_e_asc.push(accum_e_asc[i - 1] * alpha);
    }
    let accum_e_rev: Vec<Scalar> = accum_e_asc.iter().cloned().rev().collect();
    let (accum_chain_proof, accum_y_blind) =
        prove_chain_with_openings(rng, pc_gens, bp_gens, &accum_e_rev, alpha)?;
    let (beta_accum_y, beta_accum_c1, beta_accum_c2) =
        relation_scalars(&accum_chain_proof, pk, &accum_in.0, accum_c_star);
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
        let mut basis = beta_accum_c1 * ct.c1 + beta_accum_c2 * ct.c2;
        if idx == 0 {
            basis += beta_accum_c1 * G + beta_accum_c2 * pk.0;
        }
        accum_glue_scalars.push(*k);
        accum_glue_points.push(basis);
    }
    let accum_glue_a_t = RistrettoPoint::multiscalar_mul(
        accum_glue_scalars.iter().copied(),
        accum_glue_points.iter().copied(),
    )
    .compress();

    let (beta_accum_pd, gamma_accum_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, accum_c_star, accum_partial_out_ct);
    let k_accum_sk2 = Scalar::random(rng);
    let k_accum_r_prime = Scalar::random(rng);
    let accum_beta_g = mul_g(&beta_accum_pd);
    let accum_partial_a = (mul_g(&k_accum_sk2) - k_accum_sk2 * (gamma_accum_pd * accum_c_star.c1)
        + k_accum_r_prime * (gamma_accum_pd * (pk1.0 + accum_beta_g)))
        .compress();

    let (accum_x_c1, accum_x_c2, _accum_y_c1, _accum_y_c2, _) =
        sigma::poly_scalar_mul_relation_points(accum_in, accum_out, &alpha_tag_pt);
    let k_accum_mul_y = Scalar::random(rng);
    let accum_mul_a1 = (k_accum_mul_y * accum_x_c1).compress();
    let accum_mul_a2 = (k_accum_mul_y * accum_x_c2).compress();
    let accum_mul_a_m = mul_g(&k_accum_mul_y).compress();
    let accum_mul_temp = PolyScalarMulProof {
        a1: accum_mul_a1,
        a2: accum_mul_a2,
        alpha_tag,
        a_m: accum_mul_a_m,
        s_y: Scalar::zero(),
    };
    let (beta_accum_mul, gamma_accum_mul) =
        sigma::poly_scalar_mul_batch_scalars(&accum_mul_temp, accum_in, accum_out, &alpha_tag_pt)
            .map_err(|_| R1CSError::FormatError)?;

    // The accumulator evaluation is bound to the same hidden `alpha` through
    // the shared alpha tag and challenge.
    append_glue_section(
        &mut transcript,
        b"accum_sigma_bullet_glue",
        &accum_chain_proof,
        pk,
        &accum_in.0,
        accum_c_star,
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
        accum_c_star,
        accum_partial_out_ct,
        beta_accum_pd,
        gamma_accum_pd,
        &accum_partial_a,
    );
    append_poly_scalar_mul_section(
        &mut transcript,
        accum_in,
        accum_out,
        &alpha_tag,
        beta_accum_mul,
        gamma_accum_mul,
        &accum_mul_a1,
        &accum_mul_a2,
        &accum_mul_a_m,
    );
    let shared_chal = challenge_scalar(&mut transcript);

    Ok(CombinedSigmaProof {
        chain_proof,
        alpha_tag,
        glue_a_t,
        glue_z_e: k_e
            .iter()
            .zip(e_asc.iter())
            .map(|(k, x)| k + shared_chal * x)
            .collect(),
        glue_z_alpha: k_alpha + shared_chal * alpha,
        glue_z_y_blind: k_y_blind + shared_chal * y_blind,
        partial_a,
        partial_z1: k_sk2 + shared_chal * sk2,
        partial_z2: k_r_prime + shared_chal * r_prime,
        accum_chain_proof,
        accum_glue_a_t,
        accum_glue_z_e: k_accum_e
            .iter()
            .zip(accum_e_asc.iter())
            .map(|(k, x)| k + shared_chal * x)
            .collect(),
        accum_glue_z_alpha: k_accum_alpha + shared_chal * alpha,
        accum_glue_z_y_blind: k_accum_y_blind + shared_chal * accum_y_blind,
        accum_partial_a,
        accum_partial_z1: k_accum_sk2 + shared_chal * sk2,
        accum_partial_z2: k_accum_r_prime + shared_chal * accum_r_prime,
        accum_mul_a1,
        accum_mul_a2,
        accum_mul_a_m,
        accum_mul_s_y: k_accum_mul_y + shared_chal * alpha,
    })
}

/// Prove a complete monitor round sequentially.
///
/// This compatibility wrapper preserves the original all-at-once behavior;
/// callers that receive the accumulator later can invoke
/// [`preprocess_round_proof`] and [`finish_round_proof`] separately.
#[allow(clippy::too_many_arguments)]
pub fn prove_round<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    pk: &PublicKey,
    pk1: &crate::crypto::elgamal::PublicKeyShare,
    pk2: &crate::crypto::elgamal::PublicKeyShare,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    partial_out_ct: &Ciphertext,
    accum_c_star: &Ciphertext,
    accum_partial_out_ct: &Ciphertext,
    accum_in: &crate::crypto::elgamal::EncryptedPoly,
    accum_out: &crate::crypto::elgamal::EncryptedPoly,
    alpha: Scalar,
    r: Scalar,
    r_prime: Scalar,
    accum_mask: Scalar,
    accum_r_prime: Scalar,
    sk2: &Scalar,
) -> Result<CombinedSigmaProof, R1CSError> {
    let precomputed = preprocess_round_proof(
        rng,
        pc_gens,
        bp_gens,
        pk,
        pk1,
        pk2,
        coeff_cts,
        c_star,
        partial_out_ct,
        alpha,
        r,
        r_prime,
        sk2,
    )?;
    finish_round_proof(
        rng,
        pc_gens,
        bp_gens,
        pk,
        pk1,
        pk2,
        accum_c_star,
        accum_partial_out_ct,
        accum_in,
        accum_out,
        accum_mask,
        accum_r_prime,
        precomputed,
    )
}

/// Verify Sigma-Bullet glue proof.
pub fn verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    proof: &SigmaBulletProof,
) -> Result<(), String> {
    if coeff_cts.is_empty() {
        return Err("coeff_cts must not be empty".to_string());
    }

    // 1) Verify arithmetic chain/non-zero Bulletproof layer.
    bp::verify(pc_gens, bp_gens, &proof.chain_proof)
        .map_err(|e| format!("chain Bulletproof invalid: {e:?}"))?;

    if proof.chain_proof.e_comms.len() != coeff_cts.len() {
        return Err("e commitment length mismatch".to_string());
    }
    if proof.glue.z_e.len() != coeff_cts.len() {
        return Err("glue vector length mismatch".to_string());
    }

    let mut t = glue_transcript(&proof.chain_proof, pk, coeff_cts, c_star);
    let (beta_y, beta_c1, beta_c2) = relation_scalars(&proof.chain_proof, pk, coeff_cts, c_star);
    let alpha_tag = proof
        .glue
        .alpha_tag
        .decompress()
        .ok_or_else(|| "invalid glue alpha_tag point".to_string())?;
    let a_t = proof
        .glue
        .a_t
        .decompress()
        .ok_or_else(|| "invalid glue A_t point".to_string())?;

    t.append_message(b"beta_y", &beta_y.to_bytes());
    t.append_message(b"beta_c1", &beta_c1.to_bytes());
    t.append_message(b"beta_c2", &beta_c2.to_bytes());
    append_compressed(&mut t, b"alpha_tag", &proof.glue.alpha_tag);
    append_point(&mut t, b"A_t", &a_t);

    let chal = challenge_scalar(&mut t);

    let y_comm_pt = proof
        .chain_proof
        .y_comm
        .decompress()
        .ok_or_else(|| "invalid y commitment point".to_string())?;
    let mut lhs_scalars = Vec::with_capacity(3 + proof.glue.z_e.len());
    let mut lhs_points = Vec::with_capacity(3 + proof.glue.z_e.len());
    lhs_scalars.push(proof.glue.z_alpha);
    lhs_points.push(G);
    lhs_scalars.push(beta_y * proof.glue.z_alpha);
    lhs_points.push(pc_gens.B);
    lhs_scalars.push(beta_y * proof.glue.z_y_blind);
    lhs_points.push(pc_gens.B_blinding);
    for (idx, (z, ct)) in proof.glue.z_e.iter().zip(coeff_cts.iter()).enumerate() {
        let mut basis = beta_c1 * ct.c1 + beta_c2 * ct.c2;
        if idx == 0 {
            basis = basis + beta_c1 * G + beta_c2 * pk.0;
        }
        lhs_scalars.push(*z);
        lhs_points.push(basis);
    }
    let lhs = RistrettoPoint::vartime_multiscalar_mul(
        lhs_scalars.iter().copied(),
        lhs_points.iter().copied(),
    );
    let rhs =
        a_t + chal * (alpha_tag + beta_y * y_comm_pt + beta_c1 * c_star.c1 + beta_c2 * c_star.c2);
    if lhs != rhs {
        return Err("glue batched relation failed".to_string());
    }

    Ok(())
}

/// Verify the full monitor round proof under one shared Fiat-Shamir challenge.
#[allow(clippy::too_many_arguments)]
pub fn verify_round(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    pk: &PublicKey,
    pk1: &crate::crypto::elgamal::PublicKeyShare,
    pk2: &crate::crypto::elgamal::PublicKeyShare,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    partial_out_ct: &Ciphertext,
    accum_c_star: &Ciphertext,
    accum_partial_out_ct: &Ciphertext,
    accum_in: &crate::crypto::elgamal::EncryptedPoly,
    accum_out: &crate::crypto::elgamal::EncryptedPoly,
    proof: &CombinedSigmaProof,
) -> Result<(), String> {
    if proof.chain_proof.e_comms.len() != coeff_cts.len() {
        return Err("e commitment length mismatch".to_string());
    }
    if proof.glue_z_e.len() != coeff_cts.len() {
        return Err("glue vector length mismatch".to_string());
    }
    if proof.accum_chain_proof.e_comms.len() != accum_in.0.len() {
        return Err("accum e commitment length mismatch".to_string());
    }
    if proof.accum_glue_z_e.len() != accum_in.0.len() {
        return Err("accum glue vector length mismatch".to_string());
    }

    bp::verify(pc_gens, bp_gens, &proof.chain_proof)
        .map_err(|e| format!("chain Bulletproof invalid: {e:?}"))?;
    bp::verify(pc_gens, bp_gens, &proof.accum_chain_proof)
        .map_err(|e| format!("accum chain Bulletproof invalid: {e:?}"))?;

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

    let (beta_y, beta_c1, beta_c2) = relation_scalars(&proof.chain_proof, pk, coeff_cts, c_star);
    let y_comm_pt = proof
        .chain_proof
        .y_comm
        .decompress()
        .ok_or_else(|| "invalid y commitment point".to_string())?;
    let (beta_accum_y, beta_accum_c1, beta_accum_c2) =
        relation_scalars(&proof.accum_chain_proof, pk, &accum_in.0, accum_c_star);
    let accum_y_comm_pt = proof
        .accum_chain_proof
        .y_comm
        .decompress()
        .ok_or_else(|| "invalid accum y commitment point".to_string())?;
    let (beta_pd, gamma_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, c_star, partial_out_ct);
    let delta_c1 = partial_out_ct.c1 - c_star.c1;
    let delta_c2 = partial_out_ct.c2 - c_star.c2;
    let (beta_accum_pd, gamma_accum_pd) =
        sigma::partial_decrypt_relation_scalars(pk2, pk1, accum_c_star, accum_partial_out_ct);
    let accum_delta_c1 = accum_partial_out_ct.c1 - accum_c_star.c1;
    let accum_delta_c2 = accum_partial_out_ct.c2 - accum_c_star.c2;
    let (accum_mul_x_c1, accum_mul_x_c2, accum_mul_y_c1, accum_mul_y_c2, _) =
        sigma::poly_scalar_mul_relation_points(accum_in, accum_out, &alpha_tag);
    let (chal, rho_glue, rho_partial, rho_accum_glue, rho_accum_partial, rho_accum_mul) =
        round_challenge_and_batch_scalars(
            pk,
            pk1,
            pk2,
            coeff_cts,
            c_star,
            partial_out_ct,
            accum_c_star,
            accum_partial_out_ct,
            accum_in,
            accum_out,
            proof,
        )?;
    let (beta_accum_mul, gamma_accum_mul) = sigma::poly_scalar_mul_batch_scalars(
        &PolyScalarMulProof {
            a1: proof.accum_mul_a1,
            a2: proof.accum_mul_a2,
            alpha_tag: proof.alpha_tag,
            a_m: proof.accum_mul_a_m,
            s_y: proof.accum_mul_s_y,
        },
        accum_in,
        accum_out,
        &alpha_tag,
    )
    .map_err(str::to_string)?;

    let mut scalars = Vec::new();
    let mut points = Vec::new();

    scalars.push(rho_glue * proof.glue_z_alpha);
    points.push(G);
    scalars.push(rho_glue * beta_y * proof.glue_z_alpha);
    points.push(pc_gens.B);
    scalars.push(rho_glue * beta_y * proof.glue_z_y_blind);
    points.push(pc_gens.B_blinding);
    for (idx, (z, ct)) in proof.glue_z_e.iter().zip(coeff_cts.iter()).enumerate() {
        let mut basis = beta_c1 * ct.c1 + beta_c2 * ct.c2;
        if idx == 0 {
            basis = basis + beta_c1 * G + beta_c2 * pk.0;
        }
        scalars.push(rho_glue * *z);
        points.push(basis);
    }
    scalars.push(-rho_glue);
    points.push(glue_a_t);
    scalars.push(-rho_glue * chal);
    points.push(alpha_tag);
    scalars.push(-rho_glue * chal * beta_y);
    points.push(y_comm_pt);
    scalars.push(-rho_glue * chal * beta_c1);
    points.push(c_star.c1);
    scalars.push(-rho_glue * chal * beta_c2);
    points.push(c_star.c2);

    scalars.push(rho_partial * (proof.partial_z1 + proof.partial_z2 * gamma_pd * beta_pd));
    points.push(G);
    scalars.push(rho_partial * proof.partial_z2 * gamma_pd);
    points.push(pk1.0);
    scalars.push(-rho_partial * proof.partial_z1 * gamma_pd);
    points.push(c_star.c1);
    scalars.push(-rho_partial);
    points.push(partial_a);
    scalars.push(-rho_partial * chal);
    points.push(pk2.0);
    scalars.push(-rho_partial * chal * gamma_pd);
    points.push(delta_c2);
    scalars.push(-rho_partial * chal * gamma_pd * beta_pd);
    points.push(delta_c1);

    scalars.push(rho_accum_glue * proof.accum_glue_z_alpha);
    points.push(G);
    scalars.push(rho_accum_glue * beta_accum_y * proof.accum_glue_z_alpha);
    points.push(pc_gens.B);
    scalars.push(rho_accum_glue * beta_accum_y * proof.accum_glue_z_y_blind);
    points.push(pc_gens.B_blinding);
    for (idx, (z, ct)) in proof
        .accum_glue_z_e
        .iter()
        .zip(accum_in.0.iter())
        .enumerate()
    {
        let mut basis = beta_accum_c1 * ct.c1 + beta_accum_c2 * ct.c2;
        if idx == 0 {
            basis += beta_accum_c1 * G + beta_accum_c2 * pk.0;
        }
        scalars.push(rho_accum_glue * *z);
        points.push(basis);
    }
    scalars.push(-rho_accum_glue);
    points.push(accum_glue_a_t);
    scalars.push(-rho_accum_glue * chal);
    points.push(alpha_tag);
    scalars.push(-rho_accum_glue * chal * beta_accum_y);
    points.push(accum_y_comm_pt);
    scalars.push(-rho_accum_glue * chal * beta_accum_c1);
    points.push(accum_c_star.c1);
    scalars.push(-rho_accum_glue * chal * beta_accum_c2);
    points.push(accum_c_star.c2);

    scalars.push(
        rho_accum_partial
            * (proof.accum_partial_z1 + proof.accum_partial_z2 * gamma_accum_pd * beta_accum_pd),
    );
    points.push(G);
    scalars.push(rho_accum_partial * proof.accum_partial_z2 * gamma_accum_pd);
    points.push(pk1.0);
    scalars.push(-rho_accum_partial * proof.accum_partial_z1 * gamma_accum_pd);
    points.push(accum_c_star.c1);
    scalars.push(-rho_accum_partial);
    points.push(accum_partial_a);
    scalars.push(-rho_accum_partial * chal);
    points.push(pk2.0);
    scalars.push(-rho_accum_partial * chal * gamma_accum_pd);
    points.push(accum_delta_c2);
    scalars.push(-rho_accum_partial * chal * gamma_accum_pd * beta_accum_pd);
    points.push(accum_delta_c1);

    scalars.push(rho_accum_mul * proof.accum_mul_s_y);
    points.push(accum_mul_x_c1);
    scalars.push(rho_accum_mul * beta_accum_mul * proof.accum_mul_s_y);
    points.push(accum_mul_x_c2);
    scalars.push(rho_accum_mul * gamma_accum_mul * proof.accum_mul_s_y);
    points.push(G);
    scalars.push(-rho_accum_mul);
    points.push(accum_mul_a1);
    scalars.push(-rho_accum_mul * beta_accum_mul);
    points.push(accum_mul_a2);
    scalars.push(-rho_accum_mul * gamma_accum_mul);
    points.push(accum_mul_a_m);
    scalars.push(-rho_accum_mul * chal);
    points.push(accum_mul_y_c1);
    scalars.push(-rho_accum_mul * chal * beta_accum_mul);
    points.push(accum_mul_y_c2);
    scalars.push(-rho_accum_mul * chal * gamma_accum_mul);
    points.push(alpha_tag);

    let check =
        RistrettoPoint::vartime_multiscalar_mul(scalars.iter().copied(), points.iter().copied());
    if check != RistrettoPoint::identity() {
        return Err("combined sigma batch check failed".to_string());
    }

    Ok(())
}

/// Helper for tests: deterministic Enc_pk(0; r).
#[cfg(test)]
fn enc_zero_with_r(pk: &PublicKey, r: Scalar) -> Ciphertext {
    Ciphertext {
        c1: mul_g(&r),
        c2: r * pk.0,
    }
}

/// Helper for tests/examples: homomorphic sum_i (e_i * C_i).
#[cfg(test)]
fn weighted_sum(coeff_cts: &[Ciphertext], e_asc: &[Scalar]) -> Ciphertext {
    let mut c1 = RistrettoPoint::identity();
    let mut c2 = RistrettoPoint::identity();
    for (e, ct) in e_asc.iter().zip(coeff_cts.iter()) {
        c1 = c1 + e * ct.c1;
        c2 = c2 + e * ct.c2;
    }
    Ciphertext { c1, c2 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{
        combine_public_keys, ct_add, ct_scalar_mul, encrypt_poly, eval_poly, generate_key_share,
        partial_decrypt_with_witness, poly_scalar_mul,
    };
    use rand::rngs::OsRng;

    fn make_bp_gens(n_mul: usize) -> BulletproofGens {
        let cap = (n_mul.max(1)).next_power_of_two();
        BulletproofGens::new(cap, 1)
    }

    #[test]
    fn sigma_bullet_glue_valid() {
        let mut rng = OsRng;
        let (_sk1, pk1) = generate_key_share(&mut rng);
        let (_sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);

        let coeffs = [
            Scalar::from(3u64),
            Scalar::from(5u64),
            Scalar::from(7u64),
            Scalar::from(11u64),
        ];
        let poly = encrypt_poly(&mut rng, &pk, &coeffs);

        let alpha = Scalar::from(9u64);
        let r = Scalar::from(13u64);

        let mut e_asc = Vec::with_capacity(poly.0.len());
        e_asc.push(r);
        for i in 1..poly.0.len() {
            e_asc.push(e_asc[i - 1] * alpha);
        }

        let sum = weighted_sum(&poly.0, &e_asc);
        let ez = enc_zero_with_r(&pk, r);
        let c_star = Ciphertext {
            c1: sum.c1 + ez.c1,
            c2: sum.c2 + ez.c2,
        };

        let pc_gens = PedersenGens::default();
        let bp_gens = make_bp_gens(2 * poly.0.len());
        let proof =
            prove(&pc_gens, &bp_gens, &pk, &poly.0, &c_star, alpha, r).expect("prove must succeed");

        verify(&pc_gens, &bp_gens, &pk, &poly.0, &c_star, &proof).expect("verify must succeed");
    }

    #[test]
    fn sigma_bullet_glue_rejects_tampered_cstar() {
        let mut rng = OsRng;
        let (_sk1, pk1) = generate_key_share(&mut rng);
        let (_sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);

        let coeffs = [Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let poly = encrypt_poly(&mut rng, &pk, &coeffs);

        let alpha = Scalar::from(4u64);
        let r = Scalar::from(6u64);

        let mut e_asc = Vec::with_capacity(poly.0.len());
        e_asc.push(r);
        for i in 1..poly.0.len() {
            e_asc.push(e_asc[i - 1] * alpha);
        }

        let sum = weighted_sum(&poly.0, &e_asc);
        let ez = enc_zero_with_r(&pk, r);
        let c_star = Ciphertext {
            c1: sum.c1 + ez.c1,
            c2: sum.c2 + ez.c2,
        };

        let pc_gens = PedersenGens::default();
        let bp_gens = make_bp_gens(2 * poly.0.len());
        let proof =
            prove(&pc_gens, &bp_gens, &pk, &poly.0, &c_star, alpha, r).expect("prove must succeed");

        let tampered = Ciphertext {
            c1: c_star.c1 + G,
            c2: c_star.c2,
        };

        assert!(
            verify(&pc_gens, &bp_gens, &pk, &poly.0, &tampered, &proof).is_err(),
            "tampered c_star must fail",
        );
    }

    #[test]
    fn combined_round_rejects_well_formed_but_false_accum_eval() {
        let mut rng = OsRng;
        let (_sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        let alpha = Scalar::from(5u64);

        let poly = encrypt_poly(
            &mut rng,
            &pk,
            &[Scalar::from(3u64), Scalar::from(7u64), Scalar::from(11u64)],
        );
        let mask = Scalar::from(13u64);
        let eval = eval_poly(&poly, &alpha);
        let scaled = ct_add(&ct_scalar_mul(&eval, &mask), &enc_zero_with_r(&pk, mask));
        let (m_poly_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &scaled);

        let accum = encrypt_poly(
            &mut rng,
            &pk,
            &[Scalar::one(), Scalar::from(2u64), Scalar::from(4u64)],
        );
        let next_accum = poly_scalar_mul(&accum, &alpha);
        let accum_mask = Scalar::from(17u64);
        let accum_eval = eval_poly(&accum, &alpha);
        let correct_accum_scaled = ct_add(
            &ct_scalar_mul(&accum_eval, &accum_mask),
            &enc_zero_with_r(&pk, accum_mask),
        );
        let false_accum_scaled = Ciphertext {
            c1: correct_accum_scaled.c1 + G,
            c2: correct_accum_scaled.c2,
        };
        // The partial-decryption statement remains valid for this arbitrary
        // ciphertext; only the new accumulator-evaluation glue must reject it.
        let (false_accum_partial, accum_r_prime) =
            partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &false_accum_scaled);

        let pc_gens = PedersenGens::default();
        let bp_gens = make_bp_gens(2 * poly.0.len().max(accum.0.len()));
        let proof = prove_round(
            &mut rng,
            &pc_gens,
            &bp_gens,
            &pk,
            &pk1,
            &pk2,
            &poly.0,
            &scaled,
            &m_poly_ct,
            &false_accum_scaled,
            &false_accum_partial,
            &accum,
            &next_accum,
            alpha,
            mask,
            r_prime,
            accum_mask,
            accum_r_prime,
            sk2.as_scalar(),
        )
        .expect("prover can construct commitments from a false witness");

        assert!(
            verify_round(
                &pc_gens,
                &bp_gens,
                &pk,
                &pk1,
                &pk2,
                &poly.0,
                &scaled,
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
}
