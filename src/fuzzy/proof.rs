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

use crate::crypto::elgamal::{
    Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare, SecretKeyShare,
};
use crate::crypto::sigma::{self, PartialDecryptProof, PolyScalarMulProof};
use crate::fuzzy::target::WireCiphertext;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WireMonitorBulletproof {
    proof_bytes: Vec<u8>,
    bit_comms: Vec<[u8; 32]>,
    y_comm: [u8; 32],
    e_comms: Vec<[u8; 32]>,
    inv_e0_comm: [u8; 32],
}

#[derive(Clone, Debug)]
struct MonitorBulletproof {
    proof: R1CSProof,
    bit_comms: Vec<CompressedRistretto>,
    y_comm: CompressedRistretto,
    e_comms: Vec<CompressedRistretto>,
    inv_e0_comm: CompressedRistretto,
}

impl WireMonitorBulletproof {
    fn from_native(proof: &MonitorBulletproof) -> Self {
        Self {
            proof_bytes: proof.proof.to_bytes(),
            bit_comms: proof.bit_comms.iter().map(|c| c.to_bytes()).collect(),
            y_comm: proof.y_comm.to_bytes(),
            e_comms: proof.e_comms.iter().map(|c| c.to_bytes()).collect(),
            inv_e0_comm: proof.inv_e0_comm.to_bytes(),
        }
    }

    fn to_native(&self) -> Result<MonitorBulletproof, String> {
        Ok(MonitorBulletproof {
            proof: R1CSProof::from_bytes(&self.proof_bytes)
                .map_err(|e| format!("monitor bulletproof decode: {e:?}"))?,
            bit_comms: self
                .bit_comms
                .iter()
                .map(|bytes| CompressedRistretto::from_slice(bytes))
                .collect(),
            y_comm: CompressedRistretto::from_slice(&self.y_comm),
            e_comms: self
                .e_comms
                .iter()
                .map(|bytes| CompressedRistretto::from_slice(bytes))
                .collect(),
            inv_e0_comm: CompressedRistretto::from_slice(&self.inv_e0_comm),
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WireBitEncryptionProof {
    a1: [u8; 32],
    a2: [u8; 32],
    a3: [u8; 32],
    z_bit: [u8; 32],
    z_r: [u8; 32],
    z_blind: [u8; 32],
}

#[derive(Clone, Debug)]
struct BitEncryptionProof {
    a1: CompressedRistretto,
    a2: CompressedRistretto,
    a3: CompressedRistretto,
    z_bit: Scalar,
    z_r: Scalar,
    z_blind: Scalar,
}

struct ParsedBitEncryptionProof {
    a1: RistrettoPoint,
    a2: RistrettoPoint,
    a3: RistrettoPoint,
    z_bit: Scalar,
    z_r: Scalar,
    z_blind: Scalar,
}

impl WireBitEncryptionProof {
    fn from_native(proof: &BitEncryptionProof) -> Self {
        Self {
            a1: proof.a1.to_bytes(),
            a2: proof.a2.to_bytes(),
            a3: proof.a3.to_bytes(),
            z_bit: proof.z_bit.to_bytes(),
            z_r: proof.z_r.to_bytes(),
            z_blind: proof.z_blind.to_bytes(),
        }
    }

    fn to_native(&self) -> Result<BitEncryptionProof, String> {
        Ok(BitEncryptionProof {
            a1: CompressedRistretto::from_slice(&self.a1),
            a2: CompressedRistretto::from_slice(&self.a2),
            a3: CompressedRistretto::from_slice(&self.a3),
            z_bit: Scalar::from_canonical_bytes(self.z_bit).ok_or("z_bit: non-canonical scalar")?,
            z_r: Scalar::from_canonical_bytes(self.z_r).ok_or("z_r: non-canonical scalar")?,
            z_blind: Scalar::from_canonical_bytes(self.z_blind)
                .ok_or("z_blind: non-canonical scalar")?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WireGlueProof {
    alpha_tag: [u8; 32],
    a_t: [u8; 32],
    z_e: Vec<[u8; 32]>,
    z_alpha: [u8; 32],
    z_y_blind: [u8; 32],
}

#[derive(Clone, Debug)]
struct GlueProof {
    alpha_tag: CompressedRistretto,
    a_t: CompressedRistretto,
    z_e: Vec<Scalar>,
    z_alpha: Scalar,
    z_y_blind: Scalar,
}

impl WireGlueProof {
    fn from_native(proof: &GlueProof) -> Self {
        Self {
            alpha_tag: proof.alpha_tag.to_bytes(),
            a_t: proof.a_t.to_bytes(),
            z_e: proof.z_e.iter().map(Scalar::to_bytes).collect(),
            z_alpha: proof.z_alpha.to_bytes(),
            z_y_blind: proof.z_y_blind.to_bytes(),
        }
    }

    fn to_native(&self) -> Result<GlueProof, String> {
        Ok(GlueProof {
            alpha_tag: CompressedRistretto::from_slice(&self.alpha_tag),
            a_t: CompressedRistretto::from_slice(&self.a_t),
            z_e: self
                .z_e
                .iter()
                .map(|bytes| {
                    Scalar::from_canonical_bytes(*bytes).ok_or("glue z_e: non-canonical scalar")
                })
                .collect::<Result<Vec<_>, _>>()?,
            z_alpha: Scalar::from_canonical_bytes(self.z_alpha)
                .ok_or("glue z_alpha: non-canonical scalar")?,
            z_y_blind: Scalar::from_canonical_bytes(self.z_y_blind)
                .ok_or("glue z_y_blind: non-canonical scalar")?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct FuzzyProofBundle {
    monitor_bulletproof: WireMonitorBulletproof,
    bit_encryption_proofs: Vec<WireBitEncryptionProof>,
    accum_scaled_eval: WireCiphertext,
    accum_eval_proof: PartialDecryptProof,
    next_accum_proof: PolyScalarMulProof,
    glue_proof: WireGlueProof,
}

struct MonitorBulletproofWitness {
    bit_blindings: Vec<Scalar>,
    y_blind: Scalar,
}

#[inline]
fn mul_g(s: &Scalar) -> RistrettoPoint {
    s * &RISTRETTO_BASEPOINT_TABLE
}

fn challenge_scalar(transcript: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn nontrivial_challenge(transcript: &mut Transcript) -> Scalar {
    let challenge = challenge_scalar(transcript);
    if challenge == -Scalar::one() {
        Scalar::from(2u64)
    } else {
        challenge + Scalar::one()
    }
}

fn fixed_batch_weights(count: usize) -> Vec<Scalar> {
    let mut weights = Vec::with_capacity(count);
    let mut weight = Scalar::one();
    for _ in 0..count {
        weights.push(weight);
        weight += Scalar::one();
    }
    weights
}

fn make_monitor_bp_gens(vector_size: usize, coeff_len: usize) -> BulletproofGens {
    let multipliers = (vector_size + coeff_len + 2).max(2);
    let cap = 1usize << (usize::BITS - (multipliers - 1).leading_zeros()) as usize;
    BulletproofGens::new(cap.max(64), 1)
}

fn monitor_bulletproof_transcript(coeff_len: usize, vector_size: usize) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_monitor_bulletproof_v1");
    t.append_u64(b"coeff_len", coeff_len as u64);
    t.append_u64(b"vector_size", vector_size as u64);
    t
}

fn monitor_bulletproof_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    bit_vars: &[Variable],
    y_var: Variable,
    e_vars: &[Variable],
    inv_e0_var: Variable,
) -> Result<(), R1CSError> {
    if e_vars.is_empty() {
        return Err(R1CSError::GadgetError {
            description: "e vars must not be empty".to_string(),
        });
    }

    for &bit_var in bit_vars {
        let (_, _, out) = cs.multiply(
            LinearCombination::from(bit_var),
            LinearCombination::from(Scalar::one()) - LinearCombination::from(bit_var),
        );
        cs.constrain(LinearCombination::from(out));
    }

    let mut y_lc = -LinearCombination::from(y_var);
    let mut coeff = Scalar::one();
    for &bit_var in bit_vars {
        y_lc = y_lc + coeff * LinearCombination::from(bit_var);
        coeff = coeff + coeff;
    }
    cs.constrain(y_lc);

    for d in 0..e_vars.len() - 1 {
        let (_, _, out) = cs.multiply(
            LinearCombination::from(e_vars[d]),
            LinearCombination::from(y_var),
        );
        cs.constrain(LinearCombination::from(out) - LinearCombination::from(e_vars[d + 1]));
    }

    let (_, _, prod) = cs.multiply(
        LinearCombination::from(e_vars[0]),
        LinearCombination::from(inv_e0_var),
    );
    cs.constrain(LinearCombination::from(prod) - Scalar::one());

    Ok(())
}

fn prove_monitor_bulletproof<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    input_bits: &[Scalar],
    y: Scalar,
    e_asc: &[Scalar],
) -> Result<(MonitorBulletproof, MonitorBulletproofWitness), R1CSError> {
    let mut transcript = monitor_bulletproof_transcript(e_asc.len(), input_bits.len());
    let mut prover = Prover::new(pc_gens, &mut transcript);

    let mut bit_comms = Vec::with_capacity(input_bits.len());
    let mut bit_vars = Vec::with_capacity(input_bits.len());
    let mut bit_blindings = Vec::with_capacity(input_bits.len());
    for &bit in input_bits {
        let blind = Scalar::random(rng);
        let (comm, var) = prover.commit(bit, blind);
        bit_comms.push(comm);
        bit_vars.push(var);
        bit_blindings.push(blind);
    }

    let y_blind = Scalar::random(rng);
    let (y_comm, y_var) = prover.commit(y, y_blind);

    let mut e_comms = Vec::with_capacity(e_asc.len());
    let mut e_vars = Vec::with_capacity(e_asc.len());
    for &e_d in e_asc {
        let (comm, var) = prover.commit(e_d, Scalar::random(rng));
        e_comms.push(comm);
        e_vars.push(var);
    }

    let inv_e0 = e_asc[0].invert();
    let (inv_e0_comm, inv_e0_var) = prover.commit(inv_e0, Scalar::random(rng));

    monitor_bulletproof_gadget(&mut prover, &bit_vars, y_var, &e_vars, inv_e0_var)?;

    let proof = prover.prove(bp_gens)?;
    Ok((
        MonitorBulletproof {
            proof,
            bit_comms,
            y_comm,
            e_comms,
            inv_e0_comm,
        },
        MonitorBulletproofWitness {
            bit_blindings,
            y_blind,
        },
    ))
}

fn verify_monitor_bulletproof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proof: &MonitorBulletproof,
) -> Result<(), String> {
    let mut transcript = monitor_bulletproof_transcript(proof.e_comms.len(), proof.bit_comms.len());
    let mut verifier = Verifier::new(&mut transcript);

    let bit_vars: Vec<Variable> = proof
        .bit_comms
        .iter()
        .map(|&c| verifier.commit(c))
        .collect();
    let y_var = verifier.commit(proof.y_comm);
    let e_vars: Vec<Variable> = proof.e_comms.iter().map(|&c| verifier.commit(c)).collect();
    let inv_e0_var = verifier.commit(proof.inv_e0_comm);

    monitor_bulletproof_gadget(&mut verifier, &bit_vars, y_var, &e_vars, inv_e0_var)
        .map_err(|e| format!("monitor bulletproof gadget invalid: {e:?}"))?;

    verifier
        .verify(&proof.proof, pc_gens, bp_gens)
        .map_err(|e| format!("monitor bulletproof invalid: {e:?}"))
}

fn bit_encryption_transcript(
    pk: &PublicKey,
    ct: &Ciphertext,
    bit_comm: &CompressedRistretto,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_bit_encrypt_v1");
    t.append_message(b"pk", pk.0.compress().as_bytes());
    t.append_message(b"ct_c1", ct.c1.compress().as_bytes());
    t.append_message(b"ct_c2", ct.c2.compress().as_bytes());
    t.append_message(b"bit_comm", bit_comm.as_bytes());
    t
}

fn prove_bit_encryption<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    pk: &PublicKey,
    ct: &Ciphertext,
    bit_comm: &CompressedRistretto,
    bit: Scalar,
    enc_r: Scalar,
    bit_blind: Scalar,
) -> BitEncryptionProof {
    let k_bit = Scalar::random(rng);
    let k_r = Scalar::random(rng);
    let k_blind = Scalar::random(rng);

    let a1 = (k_r * G).compress();
    let a2 = (k_bit * G + k_r * pk.0).compress();
    let a3 = (k_bit * pc_gens.B + k_blind * pc_gens.B_blinding).compress();

    let mut t = bit_encryption_transcript(pk, ct, bit_comm);
    t.append_message(b"a1", a1.as_bytes());
    t.append_message(b"a2", a2.as_bytes());
    t.append_message(b"a3", a3.as_bytes());
    let chal = nontrivial_challenge(&mut t);

    BitEncryptionProof {
        a1,
        a2,
        a3,
        z_bit: k_bit + chal * bit,
        z_r: k_r + chal * enc_r,
        z_blind: k_blind + chal * bit_blind,
    }
}

fn parse_bit_encryption_proof(
    proof: &BitEncryptionProof,
) -> Result<ParsedBitEncryptionProof, String> {
    Ok(ParsedBitEncryptionProof {
        a1: proof
            .a1
            .decompress()
            .ok_or("bit encryption A1 invalid point")?,
        a2: proof
            .a2
            .decompress()
            .ok_or("bit encryption A2 invalid point")?,
        a3: proof
            .a3
            .decompress()
            .ok_or("bit encryption A3 invalid point")?,
        z_bit: proof.z_bit,
        z_r: proof.z_r,
        z_blind: proof.z_blind,
    })
}

fn verify_bit_encryptions_batched(
    pc_gens: &PedersenGens,
    pk: &PublicKey,
    encrypted_input_bits: &[Ciphertext],
    bit_comms: &[CompressedRistretto],
    proofs: &[BitEncryptionProof],
) -> Result<(), String> {
    if encrypted_input_bits.len() != bit_comms.len() || bit_comms.len() != proofs.len() {
        return Err("bit encryption batch length mismatch".to_string());
    }

    let parsed_proofs: Vec<_> = proofs
        .iter()
        .map(parse_bit_encryption_proof)
        .collect::<Result<_, _>>()?;
    let bit_comm_pts: Vec<_> = bit_comms
        .iter()
        .map(|comm| comm.decompress().ok_or("bit commitment invalid point"))
        .collect::<Result<_, _>>()?;

    let batch_weights = fixed_batch_weights(3 * proofs.len());

    let mut scalars = Vec::with_capacity(4 + 6 * proofs.len());
    let mut points = Vec::with_capacity(4 + 6 * proofs.len());
    let mut g_scalar = Scalar::zero();
    let mut pk_scalar = Scalar::zero();
    let mut b_scalar = Scalar::zero();
    let mut b_blind_scalar = Scalar::zero();

    for (idx, (((ct, bit_comm), proof), parsed)) in encrypted_input_bits
        .iter()
        .zip(bit_comms.iter())
        .zip(proofs.iter())
        .zip(parsed_proofs.iter())
        .enumerate()
    {
        let mut t = bit_encryption_transcript(pk, ct, bit_comm);
        t.append_message(b"a1", proof.a1.as_bytes());
        t.append_message(b"a2", proof.a2.as_bytes());
        t.append_message(b"a3", proof.a3.as_bytes());
        let chal = nontrivial_challenge(&mut t);

        let rho1 = batch_weights[3 * idx];
        let rho2 = batch_weights[3 * idx + 1];
        let rho3 = batch_weights[3 * idx + 2];

        g_scalar += rho1 * parsed.z_r + rho2 * parsed.z_bit;
        pk_scalar += rho2 * parsed.z_r;
        b_scalar += rho3 * parsed.z_bit;
        b_blind_scalar += rho3 * parsed.z_blind;

        scalars.push(-rho1);
        points.push(parsed.a1);
        scalars.push(-rho1 * chal);
        points.push(ct.c1);

        scalars.push(-rho2);
        points.push(parsed.a2);
        scalars.push(-rho2 * chal);
        points.push(ct.c2);

        scalars.push(-rho3);
        points.push(parsed.a3);
        scalars.push(-rho3 * chal);
        points.push(bit_comm_pts[idx]);
    }

    scalars.push(g_scalar);
    points.push(G);
    scalars.push(pk_scalar);
    points.push(pk.0);
    scalars.push(b_scalar);
    points.push(pc_gens.B);
    scalars.push(b_blind_scalar);
    points.push(pc_gens.B_blinding);

    let check =
        RistrettoPoint::vartime_multiscalar_mul(scalars.iter().copied(), points.iter().copied());
    if check != RistrettoPoint::identity() {
        return Err("batched bit encryption proof verification failed".to_string());
    }

    Ok(())
}

fn glue_transcript(
    monitor_bulletproof: &MonitorBulletproof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_sigma_bullet_glue_v1");
    t.append_message(b"pk", pk.0.compress().as_bytes());
    for c in coeff_cts {
        t.append_message(b"coef_c1", c.c1.compress().as_bytes());
        t.append_message(b"coef_c2", c.c2.compress().as_bytes());
    }
    t.append_message(b"cstar_c1", c_star.c1.compress().as_bytes());
    t.append_message(b"cstar_c2", c_star.c2.compress().as_bytes());
    for bit_comm in &monitor_bulletproof.bit_comms {
        t.append_message(b"bit_comm", bit_comm.as_bytes());
    }
    t.append_message(b"y_comm", monitor_bulletproof.y_comm.as_bytes());
    for e_comm in &monitor_bulletproof.e_comms {
        t.append_message(b"e_comm", e_comm.as_bytes());
    }
    t.append_message(b"inv_e0_comm", monitor_bulletproof.inv_e0_comm.as_bytes());
    t.append_message(b"r1cs", &monitor_bulletproof.proof.to_bytes());
    t
}

fn glue_relation_scalars(
    _monitor_bulletproof: &MonitorBulletproof,
    _pk: &PublicKey,
    _coeff_cts: &[Ciphertext],
    _c_star: &Ciphertext,
) -> (Scalar, Scalar, Scalar) {
    let weights = fixed_batch_weights(3);
    (weights[0], weights[1], weights[2])
}

fn prove_glue<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    monitor_bulletproof: &MonitorBulletproof,
    witness: &MonitorBulletproofWitness,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    y: Scalar,
    e_asc: &[Scalar],
) -> GlueProof {
    let (beta_y, beta_c1, beta_c2) =
        glue_relation_scalars(monitor_bulletproof, pk, coeff_cts, c_star);

    let k_e: Vec<Scalar> = (0..e_asc.len()).map(|_| Scalar::random(rng)).collect();
    let k_alpha = Scalar::random(rng);
    let k_y_blind = Scalar::random(rng);
    let alpha_tag = mul_g(&y).compress();

    let fixed_scalars = [k_alpha, beta_y * k_alpha, beta_y * k_y_blind];
    let fixed_points = [G, pc_gens.B, pc_gens.B_blinding];
    let (var_scalars, var_points): (Vec<_>, Vec<_>) = k_e
        .iter()
        .zip(coeff_cts.iter())
        .enumerate()
        .map(|(idx, (ke, ct))| {
            let mut basis = beta_c1 * ct.c1 + beta_c2 * ct.c2;
            if idx == 0 {
                basis = basis + beta_c1 * G + beta_c2 * pk.0;
            }
            (*ke, basis)
        })
        .unzip();
    let a_t = RistrettoPoint::multiscalar_mul(
        fixed_scalars.iter().copied().chain(var_scalars),
        fixed_points.iter().copied().chain(var_points),
    );

    let mut t = glue_transcript(monitor_bulletproof, pk, coeff_cts, c_star);
    t.append_message(b"beta_y", &beta_y.to_bytes());
    t.append_message(b"beta_c1", &beta_c1.to_bytes());
    t.append_message(b"beta_c2", &beta_c2.to_bytes());
    t.append_message(b"alpha_tag", alpha_tag.as_bytes());
    t.append_message(b"A_t", a_t.compress().as_bytes());
    let chal = nontrivial_challenge(&mut t);

    GlueProof {
        alpha_tag,
        a_t: a_t.compress(),
        z_e: k_e
            .iter()
            .zip(e_asc.iter())
            .map(|(k, e_d)| k + chal * e_d)
            .collect(),
        z_alpha: k_alpha + chal * y,
        z_y_blind: k_y_blind + chal * witness.y_blind,
    }
}

fn verify_glue(
    pc_gens: &PedersenGens,
    monitor_bulletproof: &MonitorBulletproof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    proof: &GlueProof,
) -> Result<RistrettoPoint, String> {
    if proof.z_e.len() != coeff_cts.len() || monitor_bulletproof.e_comms.len() != coeff_cts.len() {
        return Err("glue vector length mismatch".to_string());
    }

    let alpha_tag = proof
        .alpha_tag
        .decompress()
        .ok_or("invalid glue alpha_tag point")?;
    let a_t = proof.a_t.decompress().ok_or("invalid glue A_t point")?;
    let y_comm_pt = monitor_bulletproof
        .y_comm
        .decompress()
        .ok_or("invalid y commitment point")?;

    let (beta_y, beta_c1, beta_c2) =
        glue_relation_scalars(monitor_bulletproof, pk, coeff_cts, c_star);

    let mut t = glue_transcript(monitor_bulletproof, pk, coeff_cts, c_star);
    t.append_message(b"beta_y", &beta_y.to_bytes());
    t.append_message(b"beta_c1", &beta_c1.to_bytes());
    t.append_message(b"beta_c2", &beta_c2.to_bytes());
    t.append_message(b"alpha_tag", proof.alpha_tag.as_bytes());
    t.append_message(b"A_t", proof.a_t.as_bytes());
    let chal = nontrivial_challenge(&mut t);

    let fixed_scalars = [
        proof.z_alpha,
        beta_y * proof.z_alpha,
        beta_y * proof.z_y_blind,
    ];
    let fixed_points = [G, pc_gens.B, pc_gens.B_blinding];
    let (var_scalars, var_points): (Vec<_>, Vec<_>) = proof
        .z_e
        .iter()
        .zip(coeff_cts.iter())
        .enumerate()
        .map(|(idx, (z, ct))| {
            let mut basis = beta_c1 * ct.c1 + beta_c2 * ct.c2;
            if idx == 0 {
                basis = basis + beta_c1 * G + beta_c2 * pk.0;
            }
            (*z, basis)
        })
        .unzip();
    let lhs = RistrettoPoint::vartime_multiscalar_mul(
        fixed_scalars.iter().copied().chain(var_scalars),
        fixed_points.iter().copied().chain(var_points),
    );

    let mut rhs_points = Vec::with_capacity(4);
    let mut rhs_scalars = Vec::with_capacity(4);
    rhs_points.push(alpha_tag);
    rhs_scalars.push(chal);
    rhs_points.push(y_comm_pt);
    rhs_scalars.push(chal * beta_y);
    rhs_points.push(c_star.c1);
    rhs_scalars.push(chal * beta_c1);
    rhs_points.push(c_star.c2);
    rhs_scalars.push(chal * beta_c2);
    let rhs = a_t
        + RistrettoPoint::vartime_multiscalar_mul(
            rhs_scalars.iter().copied(),
            rhs_points.iter().copied(),
        );

    if lhs != rhs {
        return Err("sigma-bullet glue relation failed".to_string());
    }

    Ok(alpha_tag)
}

fn build_e_chain(y: Scalar, r: Scalar, coeff_len: usize) -> Vec<Scalar> {
    let mut e_asc = Vec::with_capacity(coeff_len);
    e_asc.push(r);
    for idx in 1..coeff_len {
        e_asc.push(e_asc[idx - 1] * y);
    }
    e_asc
}

#[allow(clippy::too_many_arguments)]
pub fn prove_round<R: CryptoRng + RngCore>(
    rng: &mut R,
    monitor_pk: &PublicKey,
    threshold_pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current_accum: &EncryptedPoly,
    next_accum: &EncryptedPoly,
    accum_scaled_eval: &Ciphertext,
    accum_eval: &Ciphertext,
    y: Scalar,
    input_bits: &[Scalar],
    input_bit_randomness: &[Scalar],
    accum_mask: Scalar,
    accum_r_prime: Scalar,
    sk2: &SecretKeyShare,
    encrypted_input_bits: &[Ciphertext],
) -> Result<Vec<u8>, String> {
    if input_bits.len() != input_bit_randomness.len()
        || input_bits.len() != encrypted_input_bits.len()
    {
        return Err("bit witness length mismatch".to_string());
    }
    if current_accum.0.is_empty() {
        return Err("current_accum must not be empty".to_string());
    }

    let pc_gens = PedersenGens::default();
    let bp_gens = make_monitor_bp_gens(input_bits.len(), current_accum.0.len());
    let e_asc = build_e_chain(y, accum_mask, current_accum.0.len());
    let (monitor_bulletproof, monitor_witness) =
        prove_monitor_bulletproof(rng, &pc_gens, &bp_gens, input_bits, y, &e_asc)
            .map_err(|e| format!("monitor bulletproof: {e:?}"))?;

    let bit_encryption_proofs: Vec<_> = encrypted_input_bits
        .iter()
        .zip(monitor_bulletproof.bit_comms.iter())
        .zip(input_bits.iter().zip(input_bit_randomness.iter()))
        .zip(monitor_witness.bit_blindings.iter())
        .map(|(((ct, bit_comm), (bit, enc_r)), bit_blind)| {
            WireBitEncryptionProof::from_native(&prove_bit_encryption(
                rng, &pc_gens, monitor_pk, ct, bit_comm, *bit, *enc_r, *bit_blind,
            ))
        })
        .collect();

    let accum_eval_proof = sigma::prove(
        rng,
        sk2.as_scalar(),
        accum_r_prime,
        pk2,
        pk1,
        accum_scaled_eval,
        accum_eval,
    );
    let alpha_tag_pt = mul_g(&y);
    let next_accum_proof =
        sigma::prove_poly_scalar_mul(rng, &y, current_accum, next_accum, &alpha_tag_pt);
    let glue_proof = prove_glue(
        rng,
        &pc_gens,
        &monitor_bulletproof,
        &monitor_witness,
        threshold_pk,
        &current_accum.0,
        accum_scaled_eval,
        y,
        &e_asc,
    );

    let bundle = FuzzyProofBundle {
        monitor_bulletproof: WireMonitorBulletproof::from_native(&monitor_bulletproof),
        bit_encryption_proofs,
        accum_scaled_eval: WireCiphertext::from_native(accum_scaled_eval),
        accum_eval_proof,
        next_accum_proof,
        glue_proof: WireGlueProof::from_native(&glue_proof),
    };

    bincode::serialize(&bundle).map_err(|e| format!("serialize fuzzy proof bundle: {e}"))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_round(
    proof_bytes: &[u8],
    monitor_pk: &PublicKey,
    threshold_pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current_accum: &EncryptedPoly,
    next_accum: &EncryptedPoly,
    accum_eval: &Ciphertext,
    encrypted_input_bits: &[Ciphertext],
) -> Result<(), String> {
    let bundle: FuzzyProofBundle =
        bincode::deserialize(proof_bytes).map_err(|e| format!("decode fuzzy proof bundle: {e}"))?;

    let monitor_bulletproof = bundle.monitor_bulletproof.to_native()?;
    if monitor_bulletproof.bit_comms.len() != encrypted_input_bits.len() {
        return Err("bit commitment length mismatch".to_string());
    }
    if monitor_bulletproof.e_comms.len() != current_accum.0.len() {
        return Err("e commitment length mismatch".to_string());
    }

    let pc_gens = PedersenGens::default();
    let bp_gens = make_monitor_bp_gens(encrypted_input_bits.len(), current_accum.0.len());
    verify_monitor_bulletproof(&pc_gens, &bp_gens, &monitor_bulletproof)?;

    if bundle.bit_encryption_proofs.len() != encrypted_input_bits.len() {
        return Err("bit encryption proof vector length mismatch".to_string());
    }
    let bit_encryption_proofs: Vec<_> = bundle
        .bit_encryption_proofs
        .iter()
        .map(WireBitEncryptionProof::to_native)
        .collect::<Result<_, _>>()?;
    verify_bit_encryptions_batched(
        &pc_gens,
        monitor_pk,
        encrypted_input_bits,
        &monitor_bulletproof.bit_comms,
        &bit_encryption_proofs,
    )?;

    let accum_scaled_eval = bundle.accum_scaled_eval.to_native()?;
    let glue_proof = bundle.glue_proof.to_native()?;
    let alpha_tag = verify_glue(
        &pc_gens,
        &monitor_bulletproof,
        threshold_pk,
        &current_accum.0,
        &accum_scaled_eval,
        &glue_proof,
    )?;

    sigma::verify(
        &bundle.accum_eval_proof,
        pk2,
        pk1,
        &accum_scaled_eval,
        accum_eval,
    )
    .map_err(|e| format!("accum_eval sigma invalid: {e}"))?;

    sigma::verify_poly_scalar_mul(
        &bundle.next_accum_proof,
        current_accum,
        next_accum,
        &alpha_tag,
    )
    .map_err(|e| format!("next_accum sigma invalid: {e}"))?;

    Ok(())
}
