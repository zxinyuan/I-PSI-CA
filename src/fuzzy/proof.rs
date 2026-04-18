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
use crate::crypto::sigma;
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
struct WireCBatchProof {
    a_c1: [u8; 32],
    a_c2: [u8; 32],
    a_bits: [u8; 32],
    z_y: Vec<[u8; 32]>,
    z_r: Vec<Vec<[u8; 32]>>,
    z_blind: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WireThresholdBatchProof {
    a_c1: [u8; 32],
    a_c2: [u8; 32],
    a_masks: [u8; 32],
    z_mask: Vec<[u8; 32]>,
    z_blind: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct ThresholdBatchProof {
    a_c1: CompressedRistretto,
    a_c2: CompressedRistretto,
    a_masks: CompressedRistretto,
    z_mask: Vec<Scalar>,
    z_blind: Vec<Scalar>,
}

impl WireThresholdBatchProof {
    fn from_native(proof: &ThresholdBatchProof) -> Self {
        Self {
            a_c1: proof.a_c1.to_bytes(),
            a_c2: proof.a_c2.to_bytes(),
            a_masks: proof.a_masks.to_bytes(),
            z_mask: proof.z_mask.iter().map(Scalar::to_bytes).collect(),
            z_blind: proof.z_blind.iter().map(Scalar::to_bytes).collect(),
        }
    }

    fn to_native(&self) -> Result<ThresholdBatchProof, String> {
        Ok(ThresholdBatchProof {
            a_c1: CompressedRistretto::from_slice(&self.a_c1),
            a_c2: CompressedRistretto::from_slice(&self.a_c2),
            a_masks: CompressedRistretto::from_slice(&self.a_masks),
            z_mask: self
                .z_mask
                .iter()
                .map(|bytes| {
                    Scalar::from_canonical_bytes(*bytes)
                        .ok_or("threshold z_mask: non-canonical scalar")
                })
                .collect::<Result<_, _>>()?,
            z_blind: self
                .z_blind
                .iter()
                .map(|bytes| {
                    Scalar::from_canonical_bytes(*bytes)
                        .ok_or("threshold z_blind: non-canonical scalar")
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Clone, Debug)]
struct CBatchProof {
    a_c1: CompressedRistretto,
    a_c2: CompressedRistretto,
    a_bits: CompressedRistretto,
    z_y: Vec<Scalar>,
    z_r: Vec<Vec<Scalar>>,
    z_blind: Vec<Scalar>,
}

impl WireCBatchProof {
    fn from_native(proof: &CBatchProof) -> Self {
        Self {
            a_c1: proof.a_c1.to_bytes(),
            a_c2: proof.a_c2.to_bytes(),
            a_bits: proof.a_bits.to_bytes(),
            z_y: proof.z_y.iter().map(Scalar::to_bytes).collect(),
            z_r: proof
                .z_r
                .iter()
                .map(|row| row.iter().map(Scalar::to_bytes).collect())
                .collect(),
            z_blind: proof.z_blind.iter().map(Scalar::to_bytes).collect(),
        }
    }

    fn to_native(&self) -> Result<CBatchProof, String> {
        Ok(CBatchProof {
            a_c1: CompressedRistretto::from_slice(&self.a_c1),
            a_c2: CompressedRistretto::from_slice(&self.a_c2),
            a_bits: CompressedRistretto::from_slice(&self.a_bits),
            z_y: self
                .z_y
                .iter()
                .map(|bytes| {
                    Scalar::from_canonical_bytes(*bytes)
                        .ok_or("c batch z_y: non-canonical scalar")
                })
                .collect::<Result<_, _>>()?,
            z_r: self
                .z_r
                .iter()
                .map(|row| {
                    row.iter()
                        .map(|bytes| {
                            Scalar::from_canonical_bytes(*bytes)
                                .ok_or("c batch z_r: non-canonical scalar")
                        })
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<_, _>>()?,
            z_blind: self
                .z_blind
                .iter()
                .map(|bytes| {
                    Scalar::from_canonical_bytes(*bytes)
                        .ok_or("c batch z_blind: non-canonical scalar")
                })
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WireGlueProof {
    alpha_tag: [u8; 32],
    a_t: [u8; 32],
    z_y: [u8; 32],
    z_e: Vec<[u8; 32]>,
    z_tau: [u8; 32],
}

#[derive(Clone, Debug)]
struct GlueProof {
    alpha_tag: CompressedRistretto,
    a_t: CompressedRistretto,
    z_y: Scalar,
    z_e: Vec<Scalar>,
    z_tau: Scalar,
}

impl WireGlueProof {
    fn from_native(proof: &GlueProof) -> Self {
        Self {
            alpha_tag: proof.alpha_tag.to_bytes(),
            a_t: proof.a_t.to_bytes(),
            z_y: proof.z_y.to_bytes(),
            z_e: proof.z_e.iter().map(Scalar::to_bytes).collect(),
            z_tau: proof.z_tau.to_bytes(),
        }
    }

    fn to_native(&self) -> Result<GlueProof, String> {
        Ok(GlueProof {
            alpha_tag: CompressedRistretto::from_slice(&self.alpha_tag),
            a_t: CompressedRistretto::from_slice(&self.a_t),
            z_y: Scalar::from_canonical_bytes(self.z_y)
                .ok_or("glue z_y: non-canonical scalar")?,
            z_e: self
                .z_e
                .iter()
                .map(|bytes| {
                    Scalar::from_canonical_bytes(*bytes).ok_or("glue z_e: non-canonical scalar")
                })
                .collect::<Result<_, _>>()?,
            z_tau: Scalar::from_canonical_bytes(self.z_tau)
                .ok_or("glue z_tau: non-canonical scalar")?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WirePartialDecryptProof {
    a: [u8; 32],
    z1: [u8; 32],
    z2: [u8; 32],
}

#[derive(Clone, Debug)]
struct PartialDecryptProof {
    a: CompressedRistretto,
    z1: Scalar,
    z2: Scalar,
}

impl WirePartialDecryptProof {
    fn from_native(proof: &PartialDecryptProof) -> Self {
        Self {
            a: proof.a.to_bytes(),
            z1: proof.z1.to_bytes(),
            z2: proof.z2.to_bytes(),
        }
    }

    fn to_native(&self) -> Result<PartialDecryptProof, String> {
        Ok(PartialDecryptProof {
            a: CompressedRistretto::from_slice(&self.a),
            z1: Scalar::from_canonical_bytes(self.z1)
                .ok_or("partial decrypt z1: non-canonical scalar")?,
            z2: Scalar::from_canonical_bytes(self.z2)
                .ok_or("partial decrypt z2: non-canonical scalar")?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct WirePolyScalarMulProof {
    a1: [u8; 32],
    a2: [u8; 32],
    alpha_tag: [u8; 32],
    a_m: [u8; 32],
    s_y: [u8; 32],
}

#[derive(Clone, Debug)]
struct PolyScalarMulProof {
    a1: CompressedRistretto,
    a2: CompressedRistretto,
    alpha_tag: CompressedRistretto,
    a_m: CompressedRistretto,
    s_y: Scalar,
}

impl WirePolyScalarMulProof {
    fn from_native(proof: &PolyScalarMulProof) -> Self {
        Self {
            a1: proof.a1.to_bytes(),
            a2: proof.a2.to_bytes(),
            alpha_tag: proof.alpha_tag.to_bytes(),
            a_m: proof.a_m.to_bytes(),
            s_y: proof.s_y.to_bytes(),
        }
    }

    fn to_native(&self) -> Result<PolyScalarMulProof, String> {
        Ok(PolyScalarMulProof {
            a1: CompressedRistretto::from_slice(&self.a1),
            a2: CompressedRistretto::from_slice(&self.a2),
            alpha_tag: CompressedRistretto::from_slice(&self.alpha_tag),
            a_m: CompressedRistretto::from_slice(&self.a_m),
            s_y: Scalar::from_canonical_bytes(self.s_y)
                .ok_or("poly scalar mul s_y: non-canonical scalar")?,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct FuzzyProofBundle {
    monitor_bulletproof: WireMonitorBulletproof,
    c_proof: WireCBatchProof,
    c: Vec<WireCiphertext>,
    threshold_alpha_tags: Vec<[u8; 32]>,
    raw_threshold_distances: Vec<WireCiphertext>,
    threshold_proof: WireThresholdBatchProof,
    threshold_partial_decrypt_proofs: Vec<WirePartialDecryptProof>,
    accum_scaled_eval: WireCiphertext,
    glue_proof: WireGlueProof,
    accum_eval_proof: WirePartialDecryptProof,
    next_accum_proof: WirePolyScalarMulProof,
}

struct MonitorBulletproofWitness {
    bit_blindings: Vec<Scalar>,
    y_blind: Scalar,
    e_blindings: Vec<Scalar>,
}

#[inline]
fn mul_g(s: &Scalar) -> RistrettoPoint {
    s * &RISTRETTO_BASEPOINT_TABLE
}

fn append_point(t: &mut Transcript, label: &'static [u8], p: &RistrettoPoint) {
    t.append_message(label, p.compress().as_bytes());
}

fn append_compressed(t: &mut Transcript, label: &'static [u8], p: &CompressedRistretto) {
    t.append_message(label, p.as_bytes());
}

fn challenge_scalar(transcript: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(b"challenge", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn batch_scalar(transcript: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut buf = [0u8; 64];
    transcript.challenge_bytes(label, &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn powers(base: Scalar, count: usize) -> Vec<Scalar> {
    let mut out = Vec::with_capacity(count);
    let mut cur = Scalar::one();
    for _ in 0..count {
        out.push(cur);
        cur *= base;
    }
    out
}

fn fixed_weights(count: usize) -> Vec<Scalar> {
    let mut weights = Vec::with_capacity(count);
    let mut w = Scalar::one();
    for _ in 0..count {
        weights.push(w);
        w += Scalar::one();
    }
    weights
}

fn make_monitor_bp_gens(vector_size: usize, coeff_len: usize) -> BulletproofGens {
    let multipliers = (vector_size + coeff_len + 1).max(2);
    BulletproofGens::new(multipliers.next_power_of_two().max(64), 1)
}

fn monitor_bulletproof_transcript(coeff_len: usize, vector_size: usize) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_monitor_bulletproof_v2");
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
        coeff += coeff;
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
    let mut e_blindings = Vec::with_capacity(e_asc.len());
    for &e_d in e_asc {
        let blind = Scalar::random(rng);
        let (comm, var) = prover.commit(e_d, blind);
        e_comms.push(comm);
        e_vars.push(var);
        e_blindings.push(blind);
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
            e_blindings,
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

    let bit_vars: Vec<Variable> = proof.bit_comms.iter().map(|&c| verifier.commit(c)).collect();
    let y_var = verifier.commit(proof.y_comm);
    let e_vars: Vec<Variable> = proof.e_comms.iter().map(|&c| verifier.commit(c)).collect();
    let inv_e0_var = verifier.commit(proof.inv_e0_comm);

    monitor_bulletproof_gadget(&mut verifier, &bit_vars, y_var, &e_vars, inv_e0_var)
        .map_err(|e| format!("monitor bulletproof gadget invalid: {e:?}"))?;

    verifier
        .verify(&proof.proof, pc_gens, bp_gens)
        .map_err(|e| format!("monitor bulletproof invalid: {e:?}"))
}

fn c_relation_transcript(
    pc_gens: &PedersenGens,
    threshold_pk: &PublicKey,
    encrypted_item_bits: &[Vec<Ciphertext>],
    c: &[Ciphertext],
    bit_comms: &[CompressedRistretto],
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_c_relation_v2");
    append_point(&mut t, b"pc_b", &pc_gens.B);
    append_point(&mut t, b"pc_b_blind", &pc_gens.B_blinding);
    append_point(&mut t, b"threshold_pk", &threshold_pk.0);
    for c_i in c {
        append_point(&mut t, b"c_c1", &c_i.c1);
        append_point(&mut t, b"c_c2", &c_i.c2);
    }
    for item_bits in encrypted_item_bits {
        for x in item_bits {
            append_point(&mut t, b"x_c1", &x.c1);
            append_point(&mut t, b"x_c2", &x.c2);
        }
    }
    for bit_comm in bit_comms {
        append_compressed(&mut t, b"bit_comm", bit_comm);
    }
    t
}

fn c_item_weights(
    pc_gens: &PedersenGens,
    threshold_pk: &PublicKey,
    encrypted_item_bits: &[Vec<Ciphertext>],
    c: &[Ciphertext],
    bit_comms: &[CompressedRistretto],
) -> Vec<Scalar> {
    let mut t = c_relation_transcript(pc_gens, threshold_pk, encrypted_item_bits, c, bit_comms);
    let base = batch_scalar(&mut t, b"item_weight_base");
    powers(base, c.len())
}

fn prove_c_relation<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    threshold_pk: &PublicKey,
    encrypted_item_bits: &[Vec<Ciphertext>],
    c: &[Ciphertext],
    item_weights: &[Scalar],
    input_bits: &[Scalar],
    bit_blindings: &[Scalar],
    c_randomness: &[Vec<Scalar>],
    challenge: Scalar,
) -> Result<CBatchProof, String> {
    if encrypted_item_bits.len() != c.len() || encrypted_item_bits.len() != c_randomness.len() {
        return Err("c relation witness length mismatch".to_string());
    }
    if input_bits.len() != bit_blindings.len() {
        return Err("c relation witness length mismatch".to_string());
    }
    if !encrypted_item_bits.iter().all(|row| row.len() == input_bits.len())
        || !c_randomness.iter().all(|row| row.len() == input_bits.len())
    {
        return Err("c relation witness length mismatch".to_string());
    }

    let bit_weights = fixed_weights(input_bits.len());
    let sum_item_weights = item_weights.iter().copied().sum::<Scalar>();

    let k_y: Vec<Scalar> = (0..input_bits.len()).map(|_| Scalar::random(rng)).collect();
    let k_blind: Vec<Scalar> = (0..input_bits.len()).map(|_| Scalar::random(rng)).collect();
    let k_r: Vec<Vec<Scalar>> = c_randomness
        .iter()
        .map(|row| (0..row.len()).map(|_| Scalar::random(rng)).collect())
        .collect();

    let mut a_c1 = RistrettoPoint::identity();
    let mut a_c2 = RistrettoPoint::identity();
    let mut sum_k_r_weighted = Scalar::zero();
    let mut weighted_x_c1 = vec![RistrettoPoint::identity(); input_bits.len()];
    let mut weighted_x_c2 = vec![RistrettoPoint::identity(); input_bits.len()];
    for (item_idx, item_bits) in encrypted_item_bits.iter().enumerate() {
        let w_item = item_weights[item_idx];
        for (bit_idx, x) in item_bits.iter().enumerate() {
            weighted_x_c1[bit_idx] += w_item * x.c1;
            weighted_x_c2[bit_idx] += w_item * x.c2;
            sum_k_r_weighted += w_item * k_r[item_idx][bit_idx];
        }
    }
    a_c1 += mul_g(&sum_k_r_weighted);
    a_c2 += sum_k_r_weighted * threshold_pk.0;
    for bit_idx in 0..input_bits.len() {
        a_c1 -= (Scalar::from(2u64) * k_y[bit_idx]) * weighted_x_c1[bit_idx];
        a_c2 += k_y[bit_idx] * (sum_item_weights * G - Scalar::from(2u64) * weighted_x_c2[bit_idx]);
    }

    let a_bits = RistrettoPoint::multiscalar_mul(
        bit_weights
            .iter()
            .zip(k_y.iter())
            .map(|(w, k)| *w * *k)
            .chain(bit_weights.iter().zip(k_blind.iter()).map(|(w, k)| *w * *k)),
        std::iter::repeat(pc_gens.B)
            .take(input_bits.len())
            .chain(std::iter::repeat(pc_gens.B_blinding).take(input_bits.len())),
    );

    Ok(CBatchProof {
        a_c1: a_c1.compress(),
        a_c2: a_c2.compress(),
        a_bits: a_bits.compress(),
        z_y: k_y
            .iter()
            .zip(input_bits.iter())
            .map(|(k, y)| k + challenge * y)
            .collect(),
        z_r: k_r
            .iter()
            .zip(c_randomness.iter())
            .map(|(k_row, r_row)| {
                k_row
                    .iter()
                    .zip(r_row.iter())
                    .map(|(k, r)| k + challenge * r)
                    .collect()
            })
            .collect(),
        z_blind: k_blind
            .iter()
            .zip(bit_blindings.iter())
            .map(|(k, b)| k + challenge * b)
            .collect(),
    })
}

fn threshold_relation_transcript(
    c: &[Ciphertext],
    raw_threshold_distances: &[Ciphertext],
    alpha_tags: &[CompressedRistretto],
    threshold: usize,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_threshold_relation_v1");
    t.append_u64(b"threshold", threshold as u64);
    for c_i in c {
        append_point(&mut t, b"c_c1", &c_i.c1);
        append_point(&mut t, b"c_c2", &c_i.c2);
    }
    for ct in raw_threshold_distances {
        append_point(&mut t, b"raw_threshold_c1", &ct.c1);
        append_point(&mut t, b"raw_threshold_c2", &ct.c2);
    }
    for alpha_tag in alpha_tags {
        append_compressed(&mut t, b"threshold_alpha_tag", alpha_tag);
    }
    t
}

fn threshold_item_weights(
    c: &[Ciphertext],
    raw_threshold_distances: &[Ciphertext],
    alpha_tags: &[CompressedRistretto],
    threshold: usize,
) -> Vec<Scalar> {
    let mut t = threshold_relation_transcript(
        c,
        raw_threshold_distances,
        alpha_tags,
        threshold,
    );
    let base = batch_scalar(&mut t, b"threshold_weight_base");
    powers(base, raw_threshold_distances.len())
}

fn threshold_base_ciphertext(c: &[Ciphertext], flat_idx: usize, threshold: usize) -> Ciphertext {
    let thresholds_per_item = threshold + 1;
    let item_idx = flat_idx / thresholds_per_item;
    let threshold_value = flat_idx % thresholds_per_item;
    let threshold_scalar = Scalar::from(threshold_value as u64);
    Ciphertext {
        c1: c[item_idx].c1,
        c2: c[item_idx].c2 - mul_g(&threshold_scalar),
    }
}

fn prove_threshold_relation<R: CryptoRng + RngCore>(
    rng: &mut R,
    c: &[Ciphertext],
    raw_threshold_distances: &[Ciphertext],
    alpha_tags: &[CompressedRistretto],
    item_weights: &[Scalar],
    threshold_masks: &[Scalar],
    threshold: usize,
    challenge: Scalar,
) -> Result<ThresholdBatchProof, String> {
    if raw_threshold_distances.len() != threshold_masks.len()
        || threshold_masks.len() != item_weights.len()
        || threshold_masks.len() != alpha_tags.len()
    {
        return Err("threshold relation witness length mismatch".to_string());
    }
    if c.is_empty() {
        return Err("threshold relation requires at least one c ciphertext".to_string());
    }

    let k_mask: Vec<Scalar> = (0..threshold_masks.len()).map(|_| Scalar::random(rng)).collect();

    let mut a_c1 = RistrettoPoint::identity();
    let mut a_c2 = RistrettoPoint::identity();
    let mut a_alpha = RistrettoPoint::identity();
    for (idx, k) in k_mask.iter().enumerate() {
        let base = threshold_base_ciphertext(c, idx, threshold);
        a_c1 += item_weights[idx] * *k * base.c1;
        a_c2 += item_weights[idx] * *k * base.c2;
        a_alpha += item_weights[idx] * mul_g(k);
    }

    Ok(ThresholdBatchProof {
        a_c1: a_c1.compress(),
        a_c2: a_c2.compress(),
        a_masks: a_alpha.compress(),
        z_mask: k_mask
            .iter()
            .zip(threshold_masks.iter())
            .map(|(k, z)| k + challenge * z)
            .collect(),
        z_blind: Vec::new(),
    })
}

struct GlueWeights {
    y_weight: Scalar,
    e_weights: Vec<Scalar>,
    commit_weight: Scalar,
    eval_weight: Scalar,
    c1_weight: Scalar,
    c2_weight: Scalar,
}

fn glue_transcript(
    monitor_bulletproof: &MonitorBulletproof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_sigma_bullet_glue_v2");
    append_point(&mut t, b"pk", &pk.0);
    for c in coeff_cts {
        append_point(&mut t, b"coef_c1", &c.c1);
        append_point(&mut t, b"coef_c2", &c.c2);
    }
    append_point(&mut t, b"cstar_c1", &c_star.c1);
    append_point(&mut t, b"cstar_c2", &c_star.c2);
    for bit_comm in &monitor_bulletproof.bit_comms {
        append_compressed(&mut t, b"bit_comm", bit_comm);
    }
    append_compressed(&mut t, b"y_comm", &monitor_bulletproof.y_comm);
    for e_comm in &monitor_bulletproof.e_comms {
        append_compressed(&mut t, b"e_comm", e_comm);
    }
    append_compressed(&mut t, b"inv_e0_comm", &monitor_bulletproof.inv_e0_comm);
    t.append_message(b"r1cs", &monitor_bulletproof.proof.to_bytes());
    t
}

fn glue_weights(
    monitor_bulletproof: &MonitorBulletproof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
) -> GlueWeights {
    let mut t = glue_transcript(monitor_bulletproof, pk, coeff_cts, c_star);
    let e_weight_base = batch_scalar(&mut t, b"glue_e_weight_base");
    GlueWeights {
        y_weight: batch_scalar(&mut t, b"glue_y_weight"),
        e_weights: powers(e_weight_base, coeff_cts.len()),
        commit_weight: batch_scalar(&mut t, b"glue_commit_weight"),
        eval_weight: batch_scalar(&mut t, b"glue_eval_weight"),
        c1_weight: batch_scalar(&mut t, b"glue_c1_weight"),
        c2_weight: batch_scalar(&mut t, b"glue_c2_weight"),
    }
}

fn prove_glue<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    witness: &MonitorBulletproofWitness,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    weights: &GlueWeights,
    y: Scalar,
    e_asc: &[Scalar],
    challenge: Scalar,
) -> Result<(GlueProof, Scalar), String> {
    if e_asc.len() != coeff_cts.len() || e_asc.len() != witness.e_blindings.len() {
        return Err("glue witness length mismatch".to_string());
    }
    let alpha_tag = mul_g(&y).compress();
    let k_y = Scalar::random(rng);
    let k_tau = Scalar::random(rng);
    let k_e: Vec<Scalar> = (0..e_asc.len()).map(|_| Scalar::random(rng)).collect();

    let tau = weights.y_weight * witness.y_blind
        + weights
            .e_weights
            .iter()
            .zip(witness.e_blindings.iter())
            .map(|(w, b)| *w * *b)
            .sum::<Scalar>();

    let mut basis_scalars = Vec::with_capacity(3 + e_asc.len() * 2);
    let mut basis_points = Vec::with_capacity(3 + e_asc.len() * 2);
    basis_scalars.push(k_y);
    basis_points.push(G);
    basis_scalars.push(weights.commit_weight * weights.y_weight * k_y);
    basis_points.push(pc_gens.B);
    basis_scalars.push(weights.commit_weight * k_tau);
    basis_points.push(pc_gens.B_blinding);

    for (idx, (k, ct)) in k_e.iter().zip(coeff_cts.iter()).enumerate() {
        basis_scalars.push(weights.commit_weight * weights.e_weights[idx] * *k);
        basis_points.push(pc_gens.B);

        let mut eval_basis = weights.c1_weight * ct.c1 + weights.c2_weight * ct.c2;
        if idx == 0 {
            eval_basis += weights.c1_weight * G + weights.c2_weight * pk.0;
        }
        basis_scalars.push(weights.eval_weight * *k);
        basis_points.push(eval_basis);
    }
    let a_t =
        RistrettoPoint::multiscalar_mul(basis_scalars.iter().copied(), basis_points.iter().copied());

    Ok((GlueProof {
        alpha_tag,
        a_t: a_t.compress(),
        z_y: k_y + challenge * y,
        z_e: k_e
            .iter()
            .zip(e_asc.iter())
            .map(|(k, e)| k + challenge * e)
            .collect(),
        z_tau: k_tau + challenge * tau,
    }, tau))
}

fn build_e_chain(y: Scalar, r: Scalar, coeff_len: usize) -> Vec<Scalar> {
    let mut e_asc = Vec::with_capacity(coeff_len);
    e_asc.push(r);
    for idx in 1..coeff_len {
        e_asc.push(e_asc[idx - 1] * y);
    }
    e_asc
}

fn append_monitor_section(t: &mut Transcript, proof: &MonitorBulletproof) {
    t.append_message(b"section", b"monitor_bulletproof");
    for c in &proof.bit_comms {
        append_compressed(t, b"bit_comm", c);
    }
    append_compressed(t, b"y_comm", &proof.y_comm);
    for c in &proof.e_comms {
        append_compressed(t, b"e_comm", c);
    }
    append_compressed(t, b"inv_e0_comm", &proof.inv_e0_comm);
    t.append_message(b"r1cs", &proof.proof.to_bytes());
}

fn append_c_section(
    t: &mut Transcript,
    threshold_pk: &PublicKey,
    item_weights: &[Scalar],
    proof: &CBatchProof,
) {
    t.append_message(b"section", b"c_relation");
    append_point(t, b"threshold_pk", &threshold_pk.0);
    for w in item_weights {
        t.append_message(b"item_weight", &w.to_bytes());
    }
    append_compressed(t, b"A_c1", &proof.a_c1);
    append_compressed(t, b"A_c2", &proof.a_c2);
    append_compressed(t, b"A_bits", &proof.a_bits);
}

fn append_threshold_section(
    t: &mut Transcript,
    threshold_alpha_tags: &[CompressedRistretto],
    raw_threshold_distances: &[Ciphertext],
    proof: &ThresholdBatchProof,
) {
    t.append_message(b"section", b"threshold_relation");
    for alpha_tag in threshold_alpha_tags {
        append_compressed(t, b"threshold_alpha_tag", alpha_tag);
    }
    for ct in raw_threshold_distances {
        append_point(t, b"raw_threshold_c1", &ct.c1);
        append_point(t, b"raw_threshold_c2", &ct.c2);
    }
    append_compressed(t, b"A_threshold_c1", &proof.a_c1);
    append_compressed(t, b"A_threshold_c2", &proof.a_c2);
    append_compressed(t, b"A_threshold_alpha", &proof.a_masks);
}

fn append_glue_section(
    t: &mut Transcript,
    weights: &GlueWeights,
    proof: &GlueProof,
) {
    t.append_message(b"section", b"glue_relation");
    t.append_message(b"glue_y_weight", &weights.y_weight.to_bytes());
    for w in &weights.e_weights {
        t.append_message(b"glue_e_weight", &w.to_bytes());
    }
    t.append_message(b"glue_commit_weight", &weights.commit_weight.to_bytes());
    t.append_message(b"glue_eval_weight", &weights.eval_weight.to_bytes());
    t.append_message(b"glue_c1_weight", &weights.c1_weight.to_bytes());
    t.append_message(b"glue_c2_weight", &weights.c2_weight.to_bytes());
    append_compressed(t, b"alpha_tag", &proof.alpha_tag);
    append_compressed(t, b"A_t", &proof.a_t);
}

fn append_partial_decrypt_section(
    t: &mut Transcript,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    in_ct: &Ciphertext,
    out_ct: &Ciphertext,
    proof: &PartialDecryptProof,
) {
    t.append_message(b"section", b"partial_decrypt");
    let (beta, gamma) = sigma::partial_decrypt_relation_scalars(pk2, pk1, in_ct, out_ct);
    t.append_message(b"beta", &beta.to_bytes());
    t.append_message(b"gamma", &gamma.to_bytes());
    append_compressed(t, b"A", &proof.a);
}

fn append_threshold_partial_decrypt_sections(
    t: &mut Transcript,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    in_cts: &[Ciphertext],
    out_cts: &[Ciphertext],
    proofs: &[PartialDecryptProof],
) {
    for ((in_ct, out_ct), proof) in in_cts.iter().zip(out_cts.iter()).zip(proofs.iter()) {
        append_partial_decrypt_section(t, pk1, pk2, in_ct, out_ct, proof);
    }
}

fn append_poly_scalar_mul_section(
    t: &mut Transcript,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
    proof: &PolyScalarMulProof,
) -> Result<(), String> {
    t.append_message(b"section", b"poly_scalar_mul");
    let temp = sigma::PolyScalarMulProof {
        a1: proof.a1,
        a2: proof.a2,
        alpha_tag: proof.alpha_tag,
        a_m: proof.a_m,
        s_y: proof.s_y,
    };
    let (beta, gamma) =
        sigma::poly_scalar_mul_batch_scalars(&temp, in_poly, out_poly, alpha_tag)
            .map_err(str::to_string)?;
    t.append_message(b"beta", &beta.to_bytes());
    t.append_message(b"gamma", &gamma.to_bytes());
    append_compressed(t, b"A1", &proof.a1);
    append_compressed(t, b"A2", &proof.a2);
    append_compressed(t, b"A_m", &proof.a_m);
    Ok(())
}

fn combined_challenge(
    threshold_pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current_accum: &EncryptedPoly,
    next_accum: &EncryptedPoly,
    accum_scaled_eval: &Ciphertext,
    accum_eval: &Ciphertext,
    monitor_bulletproof: &MonitorBulletproof,
    item_weights: &[Scalar],
    threshold_alpha_tags: &[CompressedRistretto],
    raw_threshold_distances: &[Ciphertext],
    threshold_distances: &[Ciphertext],
    glue_weights: &GlueWeights,
    c_proof: &CBatchProof,
    threshold_proof: &ThresholdBatchProof,
    glue_proof: &GlueProof,
    accum_eval_proof: &PartialDecryptProof,
    threshold_partial_decrypt_proofs: &[PartialDecryptProof],
    next_accum_proof: &PolyScalarMulProof,
) -> Result<(Scalar, RistrettoPoint), String> {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_round_combined_sigma_v1");
    append_monitor_section(&mut t, monitor_bulletproof);
    append_c_section(&mut t, threshold_pk, item_weights, c_proof);
    append_threshold_section(
        &mut t,
        threshold_alpha_tags,
        raw_threshold_distances,
        threshold_proof,
    );
    append_point(&mut t, b"accum_scaled_eval_c1", &accum_scaled_eval.c1);
    append_point(&mut t, b"accum_scaled_eval_c2", &accum_scaled_eval.c2);
    append_glue_section(&mut t, glue_weights, glue_proof);
    append_point(&mut t, b"accum_eval_c1", &accum_eval.c1);
    append_point(&mut t, b"accum_eval_c2", &accum_eval.c2);
    append_partial_decrypt_section(
        &mut t,
        pk1,
        pk2,
        accum_scaled_eval,
        accum_eval,
        accum_eval_proof,
    );
    append_threshold_partial_decrypt_sections(
        &mut t,
        pk1,
        pk2,
        raw_threshold_distances,
        threshold_distances,
        threshold_partial_decrypt_proofs,
    );
    let alpha_tag = glue_proof
        .alpha_tag
        .decompress()
        .ok_or("combined challenge: invalid alpha tag")?;
    append_poly_scalar_mul_section(
        &mut t,
        current_accum,
        next_accum,
        &alpha_tag,
        next_accum_proof,
    )?;
    Ok((challenge_scalar(&mut t), alpha_tag))
}

fn prove_partial_decrypt_for_output<R: CryptoRng + RngCore>(
    rng: &mut R,
    sk2: &Scalar,
    r_prime: Scalar,
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    in_ct: &Ciphertext,
    out_ct: &Ciphertext,
    challenge: Scalar,
) -> PartialDecryptProof {
    let (beta, gamma) = sigma::partial_decrypt_relation_scalars(pk2, pk1, in_ct, out_ct);
    let k_sk2 = Scalar::random(rng);
    let k_r_prime = Scalar::random(rng);
    let beta_g = mul_g(&beta);
    let a = (mul_g(&k_sk2) - k_sk2 * (gamma * in_ct.c1)
        + k_r_prime * (gamma * (pk1.0 + beta_g)))
        .compress();
    PartialDecryptProof {
        a,
        z1: k_sk2 + challenge * sk2,
        z2: k_r_prime + challenge * r_prime,
    }
}

fn prove_poly_scalar_mul<R: CryptoRng + RngCore>(
    rng: &mut R,
    y: Scalar,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
    challenge: Scalar,
) -> PolyScalarMulProof {
    let (x_c1, x_c2, _, _, _) = sigma::poly_scalar_mul_relation_points(in_poly, out_poly, alpha_tag);
    let k_y = Scalar::random(rng);
    PolyScalarMulProof {
        a1: (k_y * x_c1).compress(),
        a2: (k_y * x_c2).compress(),
        alpha_tag: alpha_tag.compress(),
        a_m: mul_g(&k_y).compress(),
        s_y: k_y + challenge * y,
    }
}

fn finalize_c_relation(
    proof: &mut CBatchProof,
    challenge: Scalar,
    input_bits: &[Scalar],
    bit_blindings: &[Scalar],
    c_randomness: &[Vec<Scalar>],
) {
    for (z, y) in proof.z_y.iter_mut().zip(input_bits.iter()) {
        *z += challenge * *y;
    }
    for (z, b) in proof.z_blind.iter_mut().zip(bit_blindings.iter()) {
        *z += challenge * *b;
    }
    for (z_row, r_row) in proof.z_r.iter_mut().zip(c_randomness.iter()) {
        for (z, r) in z_row.iter_mut().zip(r_row.iter()) {
            *z += challenge * *r;
        }
    }
}

fn finalize_glue(
    proof: &mut GlueProof,
    tau: Scalar,
    y: Scalar,
    e_asc: &[Scalar],
    challenge: Scalar,
) {
    proof.z_y += challenge * y;
    for (z, e) in proof.z_e.iter_mut().zip(e_asc.iter()) {
        *z += challenge * *e;
    }
    proof.z_tau += challenge * tau;
}

fn finalize_partial_decrypt(
    proof: &mut PartialDecryptProof,
    sk2: &Scalar,
    r_prime: Scalar,
    challenge: Scalar,
) {
    proof.z1 += challenge * sk2;
    proof.z2 += challenge * r_prime;
}

fn finalize_poly_scalar_mul(proof: &mut PolyScalarMulProof, y: Scalar, challenge: Scalar) {
    proof.s_y += challenge * y;
}

#[allow(clippy::too_many_arguments)]
pub fn prove_round<R: CryptoRng + RngCore>(
    rng: &mut R,
    threshold_pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current_accum: &EncryptedPoly,
    next_accum: &EncryptedPoly,
    accum_scaled_eval: &Ciphertext,
    accum_eval: &Ciphertext,
    y: Scalar,
    input_bits: &[Scalar],
    accum_mask: Scalar,
    accum_r_prime: Scalar,
    sk2: &SecretKeyShare,
    encrypted_item_bits: &[Vec<Ciphertext>],
    c: &[Ciphertext],
    c_randomness: &[Vec<Scalar>],
    threshold_distances: &[Ciphertext],
    threshold_distance_witnesses: &[(Ciphertext, Scalar, Scalar)],
    _threshold: usize,
) -> Result<Vec<u8>, String> {
    if encrypted_item_bits.len() != c.len() || encrypted_item_bits.len() != c_randomness.len() {
        return Err("c witness length mismatch".to_string());
    }
    if threshold_distances.len() != threshold_distance_witnesses.len() {
        return Err("threshold witness length mismatch".to_string());
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
    let threshold_masks: Vec<_> = threshold_distance_witnesses.iter().map(|(_, z, _)| *z).collect();
    let threshold_alpha_tags: Vec<_> = threshold_masks.iter().map(|z| mul_g(z).compress()).collect();
    let raw_threshold_distances: Vec<_> = threshold_distance_witnesses
        .iter()
        .map(|(ct, _, _)| ct.clone())
        .collect();
    let threshold_r_primes: Vec<_> = threshold_distance_witnesses
        .iter()
        .map(|(_, _, r_prime)| *r_prime)
        .collect();

    let item_weights = c_item_weights(
        &pc_gens,
        threshold_pk,
        encrypted_item_bits,
        &c,
        &monitor_bulletproof.bit_comms,
    );
    let threshold_weights = threshold_item_weights(
        c,
        &raw_threshold_distances,
        &threshold_alpha_tags,
        _threshold,
    );
    let glue_weights_val = glue_weights(&monitor_bulletproof, threshold_pk, &current_accum.0, accum_scaled_eval);

    let mut c_proof = prove_c_relation(
        rng,
        &pc_gens,
        threshold_pk,
        encrypted_item_bits,
        c,
        &item_weights,
        input_bits,
        &monitor_witness.bit_blindings,
        c_randomness,
        Scalar::zero(),
    )?;
    let mut threshold_proof = prove_threshold_relation(
        rng,
        c,
        &raw_threshold_distances,
        &threshold_alpha_tags,
        &threshold_weights,
        &threshold_masks,
        _threshold,
        Scalar::zero(),
    )?;
    let (mut glue_proof, glue_tau) = prove_glue(
        rng,
        &pc_gens,
        &monitor_witness,
        threshold_pk,
        &current_accum.0,
        &glue_weights_val,
        y,
        &e_asc,
        Scalar::zero(),
    )?;
    let mut accum_eval_proof = prove_partial_decrypt_for_output(
        rng,
        sk2.as_scalar(),
        accum_r_prime,
        pk2,
        pk1,
        accum_scaled_eval,
        accum_eval,
        Scalar::zero(),
    );
    let mut threshold_partial_decrypt_proofs = raw_threshold_distances
        .iter()
        .zip(threshold_distances.iter())
        .zip(threshold_r_primes.iter())
        .map(|((in_ct, out_ct), r_prime)| {
            prove_partial_decrypt_for_output(
                rng,
                sk2.as_scalar(),
                *r_prime,
                pk2,
                pk1,
                in_ct,
                out_ct,
                Scalar::zero(),
            )
        })
        .collect::<Vec<_>>();
    let mut next_accum_proof =
        prove_poly_scalar_mul(rng, y, current_accum, next_accum, &mul_g(&y), Scalar::zero());
    let (challenge, _alpha_tag) = combined_challenge(
        threshold_pk,
        pk1,
        pk2,
        current_accum,
        next_accum,
        accum_scaled_eval,
        accum_eval,
        &monitor_bulletproof,
        &item_weights,
        &threshold_alpha_tags,
        &raw_threshold_distances,
        threshold_distances,
        &glue_weights_val,
        &c_proof,
        &threshold_proof,
        &glue_proof,
        &accum_eval_proof,
        &threshold_partial_decrypt_proofs,
        &next_accum_proof,
    )?;
    next_accum_proof.alpha_tag = glue_proof.alpha_tag;

    finalize_c_relation(
        &mut c_proof,
        challenge,
        input_bits,
        &monitor_witness.bit_blindings,
        c_randomness,
    );
    for (z, mask) in threshold_proof.z_mask.iter_mut().zip(threshold_masks.iter()) {
        *z += challenge * *mask;
    }
    for (proof, r_prime) in threshold_partial_decrypt_proofs
        .iter_mut()
        .zip(threshold_r_primes.iter())
    {
        finalize_partial_decrypt(proof, sk2.as_scalar(), *r_prime, challenge);
    }
    finalize_glue(&mut glue_proof, glue_tau, y, &e_asc, challenge);
    finalize_partial_decrypt(&mut accum_eval_proof, sk2.as_scalar(), accum_r_prime, challenge);
    finalize_poly_scalar_mul(&mut next_accum_proof, y, challenge);
    let bundle = FuzzyProofBundle {
        monitor_bulletproof: WireMonitorBulletproof::from_native(&monitor_bulletproof),
        c_proof: WireCBatchProof::from_native(&c_proof),
        c: c.iter().map(WireCiphertext::from_native).collect(),
        threshold_alpha_tags: threshold_alpha_tags.iter().map(CompressedRistretto::to_bytes).collect(),
        raw_threshold_distances: raw_threshold_distances
            .iter()
            .map(WireCiphertext::from_native)
            .collect(),
        threshold_proof: WireThresholdBatchProof::from_native(&threshold_proof),
        threshold_partial_decrypt_proofs: threshold_partial_decrypt_proofs
            .iter()
            .map(WirePartialDecryptProof::from_native)
            .collect(),
        accum_scaled_eval: WireCiphertext::from_native(accum_scaled_eval),
        glue_proof: WireGlueProof::from_native(&glue_proof),
        accum_eval_proof: WirePartialDecryptProof::from_native(&accum_eval_proof),
        next_accum_proof: WirePolyScalarMulProof::from_native(&next_accum_proof),
    };

    bincode::serialize(&bundle).map_err(|e| format!("serialize fuzzy proof bundle: {e}"))
}

fn verify_c_relation(
    pc_gens: &PedersenGens,
    threshold_pk: &PublicKey,
    encrypted_item_bits: &[Vec<Ciphertext>],
    c: &[Ciphertext],
    bit_comms: &[CompressedRistretto],
    item_weights: &[Scalar],
    proof: &CBatchProof,
    challenge: Scalar,
) -> Result<(), String> {
    if encrypted_item_bits.len() != c.len() || encrypted_item_bits.len() != proof.z_r.len() {
        return Err("c relation proof length mismatch".to_string());
    }
    if bit_comms.len() != proof.z_y.len() || proof.z_blind.len() != proof.z_y.len() {
        return Err("c relation proof length mismatch".to_string());
    }
    if !encrypted_item_bits.iter().all(|row| row.len() == proof.z_y.len())
        || !proof.z_r.iter().all(|row| row.len() == proof.z_y.len())
    {
        return Err("c relation proof length mismatch".to_string());
    }

    let a_c1 = proof.a_c1.decompress().ok_or("c proof a_c1 invalid point")?;
    let a_c2 = proof.a_c2.decompress().ok_or("c proof a_c2 invalid point")?;
    let a_bits = proof.a_bits.decompress().ok_or("c proof a_bits invalid point")?;
    let bit_comm_pts: Vec<_> = bit_comms
        .iter()
        .map(|comm| comm.decompress().ok_or("bit commitment invalid point"))
        .collect::<Result<_, _>>()?;
    let bit_weights = fixed_weights(proof.z_y.len());
    let sum_item_weights = item_weights.iter().copied().sum::<Scalar>();

    let weighted_c1 = RistrettoPoint::vartime_multiscalar_mul(
        item_weights.iter().copied(),
        c.iter().map(|ct| ct.c1),
    );
    let weighted_c2 = RistrettoPoint::vartime_multiscalar_mul(
        item_weights.iter().copied(),
        c.iter().map(|ct| ct.c2),
    );
    let weighted_x_c1: Vec<_> = (0..proof.z_y.len())
        .map(|bit_idx| {
            RistrettoPoint::vartime_multiscalar_mul(
                item_weights.iter().copied(),
                encrypted_item_bits.iter().map(|item_bits| item_bits[bit_idx].c1),
            )
        })
        .collect();
    let weighted_x_c2: Vec<_> = (0..proof.z_y.len())
        .map(|bit_idx| {
            RistrettoPoint::vartime_multiscalar_mul(
                item_weights.iter().copied(),
                encrypted_item_bits.iter().map(|item_bits| item_bits[bit_idx].c2),
            )
        })
        .collect();
    let delta_c1 = weighted_c1 - weighted_x_c1.iter().copied().sum::<RistrettoPoint>();
    let delta_c2 = weighted_c2 - weighted_x_c2.iter().copied().sum::<RistrettoPoint>();

    let sum_z_r = proof
        .z_r
        .iter()
        .zip(item_weights.iter())
        .map(|(row, w_item)| row.iter().map(|z| *w_item * *z).sum::<Scalar>())
        .sum::<Scalar>();

    let lhs_c1 = mul_g(&sum_z_r)
        - RistrettoPoint::vartime_multiscalar_mul(
            proof.z_y.iter().map(|z| Scalar::from(2u64) * *z),
            weighted_x_c1.iter().copied(),
        );
    if lhs_c1 != a_c1 + challenge * delta_c1 {
        return Err("c relation c1 check failed".to_string());
    }

    let lhs_c2 = sum_z_r * threshold_pk.0
        + RistrettoPoint::vartime_multiscalar_mul(
            proof.z_y.iter().copied(),
            weighted_x_c2
                .iter()
                .map(|pt| sum_item_weights * G - Scalar::from(2u64) * *pt),
        );
    if lhs_c2 != a_c2 + challenge * delta_c2 {
        return Err("c relation c2 check failed".to_string());
    }

    let lhs_bits = RistrettoPoint::vartime_multiscalar_mul(
        bit_weights
            .iter()
            .zip(proof.z_y.iter())
            .map(|(w, z)| *w * *z)
            .chain(bit_weights.iter().zip(proof.z_blind.iter()).map(|(w, z)| *w * *z)),
        std::iter::repeat(pc_gens.B)
            .take(proof.z_y.len())
            .chain(std::iter::repeat(pc_gens.B_blinding).take(proof.z_blind.len())),
    );
    let weighted_bit_comm_sum =
        RistrettoPoint::vartime_multiscalar_mul(bit_weights.iter().copied(), bit_comm_pts.iter().copied());
    if lhs_bits != a_bits + challenge * weighted_bit_comm_sum {
        return Err("c relation bit commitment check failed".to_string());
    }

    Ok(())
}

fn verify_threshold_relation(
    c: &[Ciphertext],
    raw_threshold_distances: &[Ciphertext],
    alpha_tags: &[CompressedRistretto],
    item_weights: &[Scalar],
    threshold: usize,
    proof: &ThresholdBatchProof,
    challenge: Scalar,
) -> Result<(), String> {
    if raw_threshold_distances.len() != item_weights.len()
        || raw_threshold_distances.len() != alpha_tags.len()
        || proof.z_mask.len() != raw_threshold_distances.len()
        || !proof.z_blind.is_empty()
    {
        return Err("threshold relation proof length mismatch".to_string());
    }

    let a_c1 = proof
        .a_c1
        .decompress()
        .ok_or("threshold proof a_c1 invalid point")?;
    let a_c2 = proof
        .a_c2
        .decompress()
        .ok_or("threshold proof a_c2 invalid point")?;
    let a_masks = proof
        .a_masks
        .decompress()
        .ok_or("threshold proof a_masks invalid point")?;
    let alpha_tag_pts: Vec<_> = alpha_tags
        .iter()
        .map(|comm| comm.decompress().ok_or("alpha tag invalid point"))
        .collect::<Result<_, _>>()?;

    let base_cts: Vec<_> = (0..raw_threshold_distances.len())
        .map(|idx| threshold_base_ciphertext(c, idx, threshold))
        .collect();
    let weighted_masks: Vec<_> = proof
        .z_mask
        .iter()
        .enumerate()
        .map(|(idx, z)| item_weights[idx] * *z)
        .collect();

    let lhs_c1 = RistrettoPoint::vartime_multiscalar_mul(
        weighted_masks.iter().copied(),
        base_cts.iter().map(|b| b.c1),
    );
    let rhs_c1 = a_c1
        + challenge
            * RistrettoPoint::vartime_multiscalar_mul(
                item_weights.iter().copied(),
                raw_threshold_distances.iter().map(|ct| ct.c1),
            );
    if lhs_c1 != rhs_c1 {
        return Err("threshold relation c1 check failed".to_string());
    }

    let lhs_c2 = RistrettoPoint::vartime_multiscalar_mul(
        weighted_masks.iter().copied(),
        base_cts.iter().map(|b| b.c2),
    );
    let rhs_c2 = a_c2
        + challenge
            * RistrettoPoint::vartime_multiscalar_mul(
                item_weights.iter().copied(),
                raw_threshold_distances.iter().map(|ct| ct.c2),
            );
    if lhs_c2 != rhs_c2 {
        return Err("threshold relation c2 check failed".to_string());
    }

    let lhs_masks = mul_g(
        &item_weights
            .iter()
            .zip(proof.z_mask.iter())
            .map(|(w, z)| *w * *z)
            .sum::<Scalar>(),
    );
    let rhs_masks = a_masks
        + challenge
            * RistrettoPoint::vartime_multiscalar_mul(
                item_weights.iter().copied(),
                alpha_tag_pts.iter().copied(),
            );
    if lhs_masks != rhs_masks {
        return Err("threshold relation alpha-tag check failed".to_string());
    }

    Ok(())
}

fn verify_glue(
    pc_gens: &PedersenGens,
    monitor_bulletproof: &MonitorBulletproof,
    pk: &PublicKey,
    coeff_cts: &[Ciphertext],
    c_star: &Ciphertext,
    weights: &GlueWeights,
    alpha_tag: &RistrettoPoint,
    proof: &GlueProof,
    challenge: Scalar,
) -> Result<(), String> {
    if proof.z_e.len() != coeff_cts.len() || monitor_bulletproof.e_comms.len() != coeff_cts.len() {
        return Err("glue vector length mismatch".to_string());
    }

    let a_t = proof.a_t.decompress().ok_or("invalid glue A_t point")?;
    let y_comm_pt = monitor_bulletproof
        .y_comm
        .decompress()
        .ok_or("invalid y commitment point")?;
    let e_comm_pts: Vec<_> = monitor_bulletproof
        .e_comms
        .iter()
        .map(|comm| comm.decompress().ok_or("invalid e commitment point"))
        .collect::<Result<_, _>>()?;

    let commitment_sum = weights.y_weight * y_comm_pt
        + RistrettoPoint::vartime_multiscalar_mul(weights.e_weights.iter().copied(), e_comm_pts.iter().copied());
    let eval_public = weights.c1_weight * c_star.c1 + weights.c2_weight * c_star.c2;

    let mut lhs_scalars = Vec::with_capacity(3 + proof.z_e.len() * 2);
    let mut lhs_points = Vec::with_capacity(3 + proof.z_e.len() * 2);
    lhs_scalars.push(proof.z_y);
    lhs_points.push(G);
    lhs_scalars.push(weights.commit_weight * weights.y_weight * proof.z_y);
    lhs_points.push(pc_gens.B);
    lhs_scalars.push(weights.commit_weight * proof.z_tau);
    lhs_points.push(pc_gens.B_blinding);
    for (idx, (z, ct)) in proof.z_e.iter().zip(coeff_cts.iter()).enumerate() {
        lhs_scalars.push(weights.commit_weight * weights.e_weights[idx] * *z);
        lhs_points.push(pc_gens.B);
        let mut eval_basis = weights.c1_weight * ct.c1 + weights.c2_weight * ct.c2;
        if idx == 0 {
            eval_basis += weights.c1_weight * G + weights.c2_weight * pk.0;
        }
        lhs_scalars.push(weights.eval_weight * *z);
        lhs_points.push(eval_basis);
    }
    let lhs = RistrettoPoint::vartime_multiscalar_mul(
        lhs_scalars.iter().copied(),
        lhs_points.iter().copied(),
    );
    let rhs = a_t + challenge * (*alpha_tag + weights.commit_weight * commitment_sum + weights.eval_weight * eval_public);
    if lhs != rhs {
        return Err("sigma-bullet glue relation failed".to_string());
    }

    Ok(())
}

fn verify_partial_decrypt(
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    in_ct: &Ciphertext,
    out_ct: &Ciphertext,
    proof: &PartialDecryptProof,
    challenge: Scalar,
) -> Result<(), String> {
    let a = proof.a.decompress().ok_or("partial decrypt A invalid point")?;
    let (beta, gamma) = sigma::partial_decrypt_relation_scalars(pk2, pk1, in_ct, out_ct);
    let beta_g = mul_g(&beta);
    let delta_c1 = out_ct.c1 - in_ct.c1;
    let delta_c2 = out_ct.c2 - in_ct.c2;
    let lhs =
        mul_g(&proof.z1) - proof.z1 * (gamma * in_ct.c1) + proof.z2 * (gamma * (pk1.0 + beta_g));
    let rhs = a + challenge * (pk2.0 + gamma * (delta_c2 + beta * delta_c1));
    if lhs != rhs {
        return Err("partial decrypt relation failed".to_string());
    }
    Ok(())
}

fn verify_poly_scalar_mul(
    proof: &PolyScalarMulProof,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    expected_alpha_tag: &RistrettoPoint,
    challenge: Scalar,
) -> Result<(), String> {
    let alpha_tag = proof
        .alpha_tag
        .decompress()
        .ok_or("poly alpha_tag is not a valid Ristretto point")?;
    if alpha_tag != *expected_alpha_tag {
        return Err("alpha_tag mismatch across proofs".to_string());
    }

    let a1 = proof.a1.decompress().ok_or("poly A1 invalid point")?;
    let a2 = proof.a2.decompress().ok_or("poly A2 invalid point")?;
    let a_m = proof.a_m.decompress().ok_or("poly A_m invalid point")?;
    let temp = sigma::PolyScalarMulProof {
        a1: proof.a1,
        a2: proof.a2,
        alpha_tag: proof.alpha_tag,
        a_m: proof.a_m,
        s_y: proof.s_y,
    };
    let (beta, gamma) =
        sigma::poly_scalar_mul_batch_scalars(&temp, in_poly, out_poly, expected_alpha_tag)
            .map_err(str::to_string)?;
    let (x_c1, x_c2, y_c1, y_c2, _) =
        sigma::poly_scalar_mul_relation_points(in_poly, out_poly, expected_alpha_tag);
    let lhs = RistrettoPoint::vartime_multiscalar_mul(
        [proof.s_y, beta * proof.s_y, gamma * proof.s_y],
        [x_c1, x_c2, G],
    );
    let rhs = a1 + beta * a2 + gamma * a_m + challenge * (y_c1 + beta * y_c2 + gamma * alpha_tag);
    if lhs != rhs {
        return Err("poly scalar mul relation failed".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn verify_round(
    proof_bytes: &[u8],
    threshold_pk: &PublicKey,
    pk1: &PublicKeyShare,
    pk2: &PublicKeyShare,
    current_accum: &EncryptedPoly,
    next_accum: &EncryptedPoly,
    accum_eval: &Ciphertext,
    encrypted_item_bits: &[Vec<Ciphertext>],
    threshold_distances: &[Ciphertext],
) -> Result<(), String> {
    let bundle: FuzzyProofBundle =
        bincode::deserialize(proof_bytes).map_err(|e| format!("decode fuzzy proof bundle: {e}"))?;

    let monitor_bulletproof = bundle.monitor_bulletproof.to_native()?;
    let c: Vec<_> = bundle
        .c
        .iter()
        .map(WireCiphertext::to_native)
        .collect::<Result<_, _>>()?;
    let threshold_alpha_tags: Vec<_> = bundle
        .threshold_alpha_tags
        .iter()
        .map(|bytes| CompressedRistretto::from_slice(bytes))
        .collect();
    let raw_threshold_distances: Vec<_> = bundle
        .raw_threshold_distances
        .iter()
        .map(WireCiphertext::to_native)
        .collect::<Result<_, _>>()?;
    if current_accum.0.is_empty() {
        return Err("current_accum must not be empty".to_string());
    }
    if monitor_bulletproof.bit_comms.is_empty() {
        return Err("bit commitment length mismatch".to_string());
    }
    if encrypted_item_bits.len() != c.len() {
        return Err("c vector length mismatch".to_string());
    }
    if !encrypted_item_bits
        .iter()
        .all(|item_bits| item_bits.len() == monitor_bulletproof.bit_comms.len())
    {
        return Err("bit commitment length mismatch".to_string());
    }
    if monitor_bulletproof.e_comms.len() != current_accum.0.len() {
        return Err("e commitment length mismatch".to_string());
    }
    if raw_threshold_distances.len() != threshold_distances.len() {
        return Err("threshold vector length mismatch".to_string());
    }
    if threshold_alpha_tags.len() != threshold_distances.len() {
        return Err("threshold alpha-tag length mismatch".to_string());
    }

    let pc_gens = PedersenGens::default();
    let bp_gens = make_monitor_bp_gens(monitor_bulletproof.bit_comms.len(), current_accum.0.len());
    verify_monitor_bulletproof(&pc_gens, &bp_gens, &monitor_bulletproof)?;

    let c_proof = bundle.c_proof.to_native()?;
    let threshold_proof = bundle.threshold_proof.to_native()?;
    let accum_scaled_eval = bundle.accum_scaled_eval.to_native()?;
    let glue_proof = bundle.glue_proof.to_native()?;
    let accum_eval_proof = bundle.accum_eval_proof.to_native()?;
    let threshold_partial_decrypt_proofs = bundle
        .threshold_partial_decrypt_proofs
        .iter()
        .map(WirePartialDecryptProof::to_native)
        .collect::<Result<Vec<_>, _>>()?;
    let next_accum_proof = bundle.next_accum_proof.to_native()?;

    let item_weights = c_item_weights(
        &pc_gens,
        threshold_pk,
        encrypted_item_bits,
        &c,
        &monitor_bulletproof.bit_comms,
    );
    if c.is_empty() || raw_threshold_distances.len() % c.len() != 0 {
        return Err("invalid threshold shape".to_string());
    }
    let threshold = raw_threshold_distances.len() / c.len() - 1;
    let threshold_weights = threshold_item_weights(
        &c,
        &raw_threshold_distances,
        &threshold_alpha_tags,
        threshold,
    );
    let glue_weights_val = glue_weights(&monitor_bulletproof, threshold_pk, &current_accum.0, &accum_scaled_eval);
    let (challenge, alpha_tag) = combined_challenge(
        threshold_pk,
        pk1,
        pk2,
        current_accum,
        next_accum,
        &accum_scaled_eval,
        accum_eval,
        &monitor_bulletproof,
        &item_weights,
        &threshold_alpha_tags,
        &raw_threshold_distances,
        threshold_distances,
        &glue_weights_val,
        &c_proof,
        &threshold_proof,
        &glue_proof,
        &accum_eval_proof,
        &threshold_partial_decrypt_proofs,
        &next_accum_proof,
    )?;

    verify_c_relation(
        &pc_gens,
        threshold_pk,
        encrypted_item_bits,
        &c,
        &monitor_bulletproof.bit_comms,
        &item_weights,
        &c_proof,
        challenge,
    )?;
    verify_threshold_relation(
        &c,
        &raw_threshold_distances,
        &threshold_alpha_tags,
        &threshold_weights,
        threshold,
        &threshold_proof,
        challenge,
    )?;
    for alpha_tag in &threshold_alpha_tags {
        let pt = alpha_tag
            .decompress()
            .ok_or("threshold alpha tag invalid point")?;
        if pt == RistrettoPoint::identity() {
            return Err("threshold mask must be non-zero".to_string());
        }
    }

    verify_glue(
        &pc_gens,
        &monitor_bulletproof,
        threshold_pk,
        &current_accum.0,
        &accum_scaled_eval,
        &glue_weights_val,
        &alpha_tag,
        &glue_proof,
        challenge,
    )?;

    verify_partial_decrypt(
        pk1,
        pk2,
        &accum_scaled_eval,
        accum_eval,
        &accum_eval_proof,
        challenge,
    )?;
    for ((in_ct, out_ct), proof) in raw_threshold_distances
        .iter()
        .zip(threshold_distances.iter())
        .zip(threshold_partial_decrypt_proofs.iter())
    {
        verify_partial_decrypt(pk1, pk2, in_ct, out_ct, proof, challenge)?;
    }

    verify_poly_scalar_mul(
        &next_accum_proof,
        current_accum,
        next_accum,
        &alpha_tag,
        challenge,
    )
    .map_err(|e| format!("next_accum sigma invalid: {e}"))?;

    Ok(())
}
