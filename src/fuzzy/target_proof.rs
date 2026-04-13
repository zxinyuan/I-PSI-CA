use bulletproofs::{
    r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSError, R1CSProof, Variable, Verifier},
    BulletproofGens, PedersenGens,
};
use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::{Ciphertext, PublicKey};

// ----- proof structures -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ArithmeticProof {
    pub proof: R1CSProof,
    pub x_comms: Vec<CompressedRistretto>,
    pub z_comm: CompressedRistretto,
    pub r_x_comms: Vec<CompressedRistretto>,
    pub q_comms: Vec<CompressedRistretto>,
    pub s_comms: Vec<CompressedRistretto>,
    // beta_comms removed: beta_j = z - 2*q_j is linear, no commitment needed
}

#[derive(Clone, Debug)]
pub struct SigmaProof {
    pub a_open: CompressedRistretto,
    pub a_c1: CompressedRistretto,
    pub a_c2: CompressedRistretto,
    pub z_q: Vec<Scalar>,
    pub z_s: Vec<Scalar>,
    /// Response for z itself (replaces the n z_beta responses).
    pub z_z: Scalar,
    pub z_zu: Scalar,
    pub z_zru: Scalar,
    pub z_blind_agg: Scalar,
}

#[derive(Clone, Debug)]
pub struct TargetHybridProof {
    pub arithmetic: ArithmeticProof,
    pub sigma: SigmaProof,
}

// z_val / z_blind added so the sigma prover can open z_comm.
// beta_vals / beta_blinds removed.
#[derive(Clone, Debug)]
struct ArithmeticWitness {
    q_vals: Vec<Scalar>,
    s_vals: Vec<Scalar>,
    q_blinds: Vec<Scalar>,
    s_blinds: Vec<Scalar>,
    z_val: Scalar,
    z_blind: Scalar,
    u_val: Scalar,
    r_u_val: Scalar,
}

// ----- wire (serialisable) types ----------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireArithmeticProof {
    proof_bytes: Vec<u8>,
    x_comms: Vec<[u8; 32]>,
    z_comm: [u8; 32],
    r_x_comms: Vec<[u8; 32]>,
    q_comms: Vec<[u8; 32]>,
    s_comms: Vec<[u8; 32]>,
    // beta_comms removed
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireSigmaProof {
    a_open: [u8; 32],
    a_c1: [u8; 32],
    a_c2: [u8; 32],
    z_q: Vec<[u8; 32]>,
    z_s: Vec<[u8; 32]>,
    /// Response for z (replaces the n z_beta scalars).
    z_z: [u8; 32],
    z_u: [u8; 32],
    z_r_u: [u8; 32],
    z_blind_agg: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WireTargetHybridProof {
    arithmetic: WireArithmeticProof,
    sigma: WireSigmaProof,
}

// ----- wire conversions -------------------------------------------------------

fn scalar_from_bytes(bytes: [u8; 32], label: &str) -> Result<Scalar, String> {
    Scalar::from_canonical_bytes(bytes).ok_or_else(|| format!("{label}: non-canonical scalar"))
}

impl WireArithmeticProof {
    pub fn from_native(proof: &ArithmeticProof) -> Self {
        Self {
            proof_bytes: proof.proof.to_bytes(),
            x_comms: proof.x_comms.iter().map(|c| c.to_bytes()).collect(),
            z_comm: proof.z_comm.to_bytes(),
            r_x_comms: proof.r_x_comms.iter().map(|c| c.to_bytes()).collect(),
            q_comms: proof.q_comms.iter().map(|c| c.to_bytes()).collect(),
            s_comms: proof.s_comms.iter().map(|c| c.to_bytes()).collect(),
        }
    }

    pub fn to_native(&self) -> Result<ArithmeticProof, String> {
        Ok(ArithmeticProof {
            proof: R1CSProof::from_bytes(&self.proof_bytes)
                .map_err(|e| format!("target arithmetic proof decode: {e:?}"))?,
            x_comms: self
                .x_comms
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
            z_comm: CompressedRistretto::from_slice(&self.z_comm),
            r_x_comms: self
                .r_x_comms
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
            q_comms: self
                .q_comms
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
            s_comms: self
                .s_comms
                .iter()
                .map(|b| CompressedRistretto::from_slice(b))
                .collect(),
        })
    }
}

impl WireSigmaProof {
    fn from_native(proof: &SigmaProof) -> Self {
        Self {
            a_open: proof.a_open.to_bytes(),
            a_c1: proof.a_c1.to_bytes(),
            a_c2: proof.a_c2.to_bytes(),
            z_q: proof.z_q.iter().map(Scalar::to_bytes).collect(),
            z_s: proof.z_s.iter().map(Scalar::to_bytes).collect(),
            z_z: proof.z_z.to_bytes(),
            z_u: proof.z_zu.to_bytes(),
            z_r_u: proof.z_zru.to_bytes(),
            z_blind_agg: proof.z_blind_agg.to_bytes(),
        }
    }

    fn to_native(&self) -> Result<SigmaProof, String> {
        Ok(SigmaProof {
            a_open: CompressedRistretto::from_slice(&self.a_open),
            a_c1: CompressedRistretto::from_slice(&self.a_c1),
            a_c2: CompressedRistretto::from_slice(&self.a_c2),
            z_q: self
                .z_q
                .iter()
                .map(|b| scalar_from_bytes(*b, "target sigma z_q"))
                .collect::<Result<_, _>>()?,
            z_s: self
                .z_s
                .iter()
                .map(|b| scalar_from_bytes(*b, "target sigma z_s"))
                .collect::<Result<_, _>>()?,
            z_z: scalar_from_bytes(self.z_z, "target sigma z_z")?,
            z_zu: scalar_from_bytes(self.z_u, "target sigma z_u")?,
            z_zru: scalar_from_bytes(self.z_r_u, "target sigma z_r_u")?,
            z_blind_agg: scalar_from_bytes(self.z_blind_agg, "target sigma z_blind_agg")?,
        })
    }
}

impl WireTargetHybridProof {
    pub fn from_native(proof: &TargetHybridProof) -> Self {
        Self {
            arithmetic: WireArithmeticProof::from_native(&proof.arithmetic),
            sigma: WireSigmaProof::from_native(&proof.sigma),
        }
    }

    pub fn to_native(&self) -> Result<TargetHybridProof, String> {
        Ok(TargetHybridProof {
            arithmetic: self.arithmetic.to_native()?,
            sigma: self.sigma.to_native()?,
        })
    }
}

// ----- transcript helpers -----------------------------------------------------

fn challenge_scalar(t: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"challenge", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn nontrivial_challenge(t: &mut Transcript) -> Scalar {
    let challenge = challenge_scalar(t);
    if challenge == -Scalar::one() {
        Scalar::from(2u64)
    } else {
        challenge + Scalar::one()
    }
}

// Bumped to v4: beta_comms removed, z_z added, transcript structure changed.
fn arithmetic_transcript(
    encrypted_monitor_bits: &[Ciphertext],
    ciphertext: &Ciphertext,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_target_bp_v4");
    t.append_message(b"ct_c1", ciphertext.c1.compress().as_bytes());
    t.append_message(b"ct_c2", ciphertext.c2.compress().as_bytes());
    for ct in encrypted_monitor_bits {
        t.append_message(b"m_ct_c1", ct.c1.compress().as_bytes());
        t.append_message(b"m_ct_c2", ct.c2.compress().as_bytes());
    }
    t
}

fn sigma_transcript(
    pk: &PublicKey,
    encrypted_monitor_bits: &[Ciphertext],
    ciphertext: &Ciphertext,
    arithmetic: &ArithmeticProof,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::fuzzy_target_sigma_v4");
    t.append_message(b"pk", pk.0.compress().as_bytes());
    t.append_message(b"ct_c1", ciphertext.c1.compress().as_bytes());
    t.append_message(b"ct_c2", ciphertext.c2.compress().as_bytes());
    for ct in encrypted_monitor_bits {
        t.append_message(b"m_ct_c1", ct.c1.compress().as_bytes());
        t.append_message(b"m_ct_c2", ct.c2.compress().as_bytes());
    }
    for comm in &arithmetic.x_comms {
        t.append_message(b"x_comm", comm.as_bytes());
    }
    t.append_message(b"z_comm", arithmetic.z_comm.as_bytes());
    for comm in &arithmetic.r_x_comms {
        t.append_message(b"rx_comm", comm.as_bytes());
    }
    for comm in &arithmetic.q_comms {
        t.append_message(b"q_comm", comm.as_bytes());
    }
    for comm in &arithmetic.s_comms {
        t.append_message(b"s_comm", comm.as_bytes());
    }
    // No beta_comms
    t.append_message(b"r1cs", &arithmetic.proof.to_bytes());
    t
}

fn sigma_challenge_transcript(
    pk: &PublicKey,
    encrypted_monitor_bits: &[Ciphertext],
    ciphertext: &Ciphertext,
    arithmetic: &ArithmeticProof,
) -> Transcript {
    sigma_transcript(pk, encrypted_monitor_bits, ciphertext, arithmetic)
}

// Use fixed public batching weights so the outer sigma proof needs only one
// Fiat-Shamir challenge, sampled after the prover's first message.
fn sigma_weights(count: usize) -> Vec<Scalar> {
    let mut weights = Vec::with_capacity(count);
    let mut power = Scalar::one();
    for _ in 0..count {
        weights.push(power);
        power += Scalar::one();
    }
    weights
}

// ----- BulletproofGens sizing -------------------------------------------------

fn make_bp_gens(bit_len: usize) -> BulletproofGens {
    // 3 multiply gates per bit: x*(x-1)=0, q=z*x, s=z*r_x.
    // beta=z-2q is linear — no multiply gate.
    let multipliers = (3 * bit_len + 4).max(2);
    BulletproofGens::new(multipliers.next_power_of_two().max(64), 1)
}

// ----- R1CS gadget ------------------------------------------------------------

// beta_j = z - 2*q_j is a linear identity, so we don't commit to beta or add
// a linear constraint here; it is enforced in the sigma proof via z_z.
fn arithmetic_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x_vars: &[Variable],
    z_var: Variable,
    r_x_vars: &[Variable],
    q_vars: &[Variable],
    s_vars: &[Variable],
) -> Result<(), R1CSError> {
    if x_vars.len() != r_x_vars.len()
        || x_vars.len() != q_vars.len()
        || x_vars.len() != s_vars.len()
    {
        return Err(R1CSError::GadgetError {
            description: "target witness length mismatch".to_string(),
        });
    }

    for (((&x_var, &r_x_var), &q_var), &s_var) in x_vars
        .iter()
        .zip(r_x_vars.iter())
        .zip(q_vars.iter())
        .zip(s_vars.iter())
    {
        // x_j ∈ {0, 1}
        let (_, _, bit_out) = cs.multiply(
            LinearCombination::from(x_var),
            LinearCombination::from(x_var) - Scalar::one(),
        );
        cs.constrain(LinearCombination::from(bit_out));

        // q_j = z * x_j
        let (_, _, q_out) = cs.multiply(
            LinearCombination::from(z_var),
            LinearCombination::from(x_var),
        );
        cs.constrain(LinearCombination::from(q_out) - LinearCombination::from(q_var));

        // s_j = z * r_{x_j}
        let (_, _, s_out) = cs.multiply(
            LinearCombination::from(z_var),
            LinearCombination::from(r_x_var),
        );
        cs.constrain(LinearCombination::from(s_out) - LinearCombination::from(s_var));
    }

    Ok(())
}

// ----- arithmetic prove/verify ------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn prove_arithmetic<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    encrypted_monitor_bits: &[Ciphertext],
    ciphertext: &Ciphertext,
    secret_bits: &[Scalar],
    bit_randomness: &[Scalar],
    z: Scalar,
    u: Scalar,
    r_u: Scalar,
) -> Result<(ArithmeticProof, ArithmeticWitness), R1CSError> {
    if secret_bits.len() != bit_randomness.len() {
        return Err(R1CSError::GadgetError {
            description: "target bit witness length mismatch".to_string(),
        });
    }

    let mut transcript = arithmetic_transcript(encrypted_monitor_bits, ciphertext);
    let mut prover = Prover::new(pc_gens, &mut transcript);

    let mut x_comms = Vec::with_capacity(secret_bits.len());
    let mut x_vars = Vec::with_capacity(secret_bits.len());
    for &bit in secret_bits {
        let blind = Scalar::random(rng);
        let (comm, var) = prover.commit(bit, blind);
        x_comms.push(comm);
        x_vars.push(var);
    }

    let z_blind = Scalar::random(rng);
    let (z_comm, z_var) = prover.commit(z, z_blind);

    let mut r_x_comms = Vec::with_capacity(bit_randomness.len());
    let mut r_x_vars = Vec::with_capacity(bit_randomness.len());
    for &r_x in bit_randomness {
        let blind = Scalar::random(rng);
        let (comm, var) = prover.commit(r_x, blind);
        r_x_comms.push(comm);
        r_x_vars.push(var);
    }

    let q_vals: Vec<_> = secret_bits.iter().map(|x| z * *x).collect();
    let s_vals: Vec<_> = bit_randomness.iter().map(|r_x| z * *r_x).collect();

    let mut q_comms = Vec::with_capacity(q_vals.len());
    let mut q_vars = Vec::with_capacity(q_vals.len());
    let mut q_blinds = Vec::with_capacity(q_vals.len());
    for &q in &q_vals {
        let blind = Scalar::random(rng);
        let (comm, var) = prover.commit(q, blind);
        q_comms.push(comm);
        q_vars.push(var);
        q_blinds.push(blind);
    }

    let mut s_comms = Vec::with_capacity(s_vals.len());
    let mut s_vars = Vec::with_capacity(s_vals.len());
    let mut s_blinds = Vec::with_capacity(s_vals.len());
    for &s in &s_vals {
        let blind = Scalar::random(rng);
        let (comm, var) = prover.commit(s, blind);
        s_comms.push(comm);
        s_vars.push(var);
        s_blinds.push(blind);
    }

    arithmetic_gadget(&mut prover, &x_vars, z_var, &r_x_vars, &q_vars, &s_vars)?;
    let proof = prover.prove(bp_gens)?;

    Ok((
        ArithmeticProof {
            proof,
            x_comms,
            z_comm,
            r_x_comms,
            q_comms,
            s_comms,
        },
        ArithmeticWitness {
            q_vals,
            s_vals,
            q_blinds,
            s_blinds,
            z_val: z,
            z_blind,
            u_val: u,
            r_u_val: r_u,
        },
    ))
}

fn verify_arithmetic(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    encrypted_monitor_bits: &[Ciphertext],
    ciphertext: &Ciphertext,
    proof: &ArithmeticProof,
) -> Result<(), String> {
    let n = proof.x_comms.len();
    if proof.r_x_comms.len() != n || proof.q_comms.len() != n || proof.s_comms.len() != n {
        return Err("target arithmetic commitment length mismatch".to_string());
    }

    let mut transcript = arithmetic_transcript(encrypted_monitor_bits, ciphertext);
    let mut verifier = Verifier::new(&mut transcript);

    let x_vars: Vec<_> = proof.x_comms.iter().map(|&c| verifier.commit(c)).collect();
    let z_var = verifier.commit(proof.z_comm);
    let r_x_vars: Vec<_> = proof
        .r_x_comms
        .iter()
        .map(|&c| verifier.commit(c))
        .collect();
    let q_vars: Vec<_> = proof.q_comms.iter().map(|&c| verifier.commit(c)).collect();
    let s_vars: Vec<_> = proof.s_comms.iter().map(|&c| verifier.commit(c)).collect();

    arithmetic_gadget(&mut verifier, &x_vars, z_var, &r_x_vars, &q_vars, &s_vars)
        .map_err(|e| format!("target arithmetic gadget invalid: {e:?}"))?;

    verifier
        .verify(&proof.proof, pc_gens, bp_gens)
        .map_err(|e| format!("target arithmetic proof invalid: {e:?}"))
}

// ----- sigma prove/verify -----------------------------------------------------

fn prove_sigma<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    pk: &PublicKey,
    encrypted_monitor_bits: &[Ciphertext],
    ciphertext: &Ciphertext,
    arithmetic: &ArithmeticProof,
    witness: &ArithmeticWitness,
) -> SigmaProof {
    let n = arithmetic.q_comms.len();
    let weights = sigma_weights(2 * n + 3);
    let (w_q, rest) = weights.split_at(n);
    let (w_s, rest) = rest.split_at(n);
    let w_z = rest[0];

    // Nonces
    let k_q: Vec<_> = (0..n).map(|_| Scalar::random(rng)).collect();
    let k_s: Vec<_> = (0..n).map(|_| Scalar::random(rng)).collect();
    let k_z = Scalar::random(rng);
    let k_u = Scalar::random(rng);
    let k_r_u = Scalar::random(rng);
    let k_blinds_q: Vec<_> = (0..n).map(|_| Scalar::random(rng)).collect();
    let k_blinds_s: Vec<_> = (0..n).map(|_| Scalar::random(rng)).collect();
    let k_z_blind = Scalar::random(rng);

    // --- a_open: batch Pedersen opening for q, s, z (beta dropped) ---
    let mut a_open_pt = w_z * (k_z * pc_gens.B + k_z_blind * pc_gens.B_blinding);
    let mut blind_agg = w_z * k_z_blind;
    for idx in 0..n {
        a_open_pt += w_q[idx] * (k_q[idx] * pc_gens.B + k_blinds_q[idx] * pc_gens.B_blinding);
        blind_agg += w_q[idx] * k_blinds_q[idx];
        a_open_pt += w_s[idx] * (k_s[idx] * pc_gens.B + k_blinds_s[idx] * pc_gens.B_blinding);
        blind_agg += w_s[idx] * k_blinds_s[idx];
    }

    // --- a_c1, a_c2: substitute k_beta[j] = k_z - 2*k_q[j] ---
    // Opt 4: precompute M_c1 = Σ m_j.c1, M_c2 = Σ m_j.c2 for the k_z term.
    let m_sum_c1: RistrettoPoint = encrypted_monitor_bits.iter().map(|m| m.c1).sum();
    let m_sum_c2: RistrettoPoint = encrypted_monitor_bits.iter().map(|m| m.c2).sum();

    let two = Scalar::from(2u64);
    let mut a_c1_pt = k_r_u * G + k_z * m_sum_c1;
    let mut a_c2_pt = k_u * G + k_r_u * pk.0 + k_z * m_sum_c2;
    for idx in 0..n {
        // k_beta contribution to c1: k_z * m.c1 - 2*k_q * m.c1 (k_z part already added above)
        a_c1_pt += k_s[idx] * G - two * k_q[idx] * encrypted_monitor_bits[idx].c1;
        // k_beta contribution to c2: k_z * m.c2 - 2*k_q * m.c2
        a_c2_pt += k_q[idx] * G + k_s[idx] * pk.0 - two * k_q[idx] * encrypted_monitor_bits[idx].c2;
    }

    let a_open = a_open_pt.compress();
    let a_c1 = a_c1_pt.compress();
    let a_c2 = a_c2_pt.compress();

    let mut t = sigma_challenge_transcript(pk, encrypted_monitor_bits, ciphertext, arithmetic);
    t.append_message(b"A_open", a_open.as_bytes());
    t.append_message(b"A_c1", a_c1.as_bytes());
    t.append_message(b"A_c2", a_c2.as_bytes());
    let chal = nontrivial_challenge(&mut t);

    let z_q: Vec<_> = k_q
        .iter()
        .zip(witness.q_vals.iter())
        .map(|(k, v)| *k + chal * *v)
        .collect();
    let z_s: Vec<_> = k_s
        .iter()
        .zip(witness.s_vals.iter())
        .map(|(k, v)| *k + chal * *v)
        .collect();
    let z_z = k_z + chal * witness.z_val;
    let z_zu = k_u + chal * witness.u_val;
    let z_zru = k_r_u + chal * witness.r_u_val;

    // Aggregate blinding response: includes z's blinding contribution.
    let mut z_blind_agg = blind_agg + chal * w_z * witness.z_blind;
    for idx in 0..n {
        z_blind_agg += chal * (w_q[idx] * witness.q_blinds[idx] + w_s[idx] * witness.s_blinds[idx]);
    }

    SigmaProof {
        a_open,
        a_c1,
        a_c2,
        z_q,
        z_s,
        z_z,
        z_zu,
        z_zru,
        z_blind_agg,
    }
}

fn verify_sigma(
    pc_gens: &PedersenGens,
    pk: &PublicKey,
    encrypted_monitor_bits: &[Ciphertext],
    ciphertext: &Ciphertext,
    arithmetic: &ArithmeticProof,
    sigma: &SigmaProof,
) -> Result<(), String> {
    let n = arithmetic.q_comms.len();
    if sigma.z_q.len() != n || sigma.z_s.len() != n {
        return Err("target sigma vector length mismatch".to_string());
    }
    if encrypted_monitor_bits.len() != n || arithmetic.s_comms.len() != n {
        return Err("target sigma statement length mismatch".to_string());
    }

    let a_open = sigma
        .a_open
        .decompress()
        .ok_or("target sigma A_open invalid point")?;
    let a_c1 = sigma
        .a_c1
        .decompress()
        .ok_or("target sigma A_c1 invalid point")?;
    let a_c2 = sigma
        .a_c2
        .decompress()
        .ok_or("target sigma A_c2 invalid point")?;

    let mut t = sigma_challenge_transcript(pk, encrypted_monitor_bits, ciphertext, arithmetic);
    t.append_message(b"A_open", sigma.a_open.as_bytes());
    t.append_message(b"A_c1", sigma.a_c1.as_bytes());
    t.append_message(b"A_c2", sigma.a_c2.as_bytes());
    let chal = nontrivial_challenge(&mut t);
    let weights = sigma_weights(2 * n + 3);

    let (w_q, rest) = weights.split_at(n);
    let (w_s, rest) = rest.split_at(n);
    let w_z = rest[0];

    // Derive z_beta[j] = z_z - 2*z_q[j]  (no longer transmitted).
    let two = Scalar::from(2u64);

    // --- Opt 2: collapse all B-coefficient terms into one MSM entry ---
    // open check:
    //   (w_z*z_z + Σ_j(w_q[j]*z_q[j] + w_s[j]*z_s[j])) * B
    //   + z_blind_agg * B_blinding
    //   - a_open
    //   - chal * (w_z*z_comm + Σ_j(w_q[j]*q_comm[j] + w_s[j]*s_comm[j])) = 0
    let mut b_coeff = w_z * sigma.z_z;
    // 2n decompressed commitment points + B + B_blinding + a_open + z_comm = 2n+4 points
    let mut open_scalars: Vec<Scalar> = Vec::with_capacity(2 * n + 4);
    let mut open_points: Vec<RistrettoPoint> = Vec::with_capacity(2 * n + 4);

    for idx in 0..n {
        b_coeff += w_q[idx] * sigma.z_q[idx] + w_s[idx] * sigma.z_s[idx];
        open_scalars.push(-chal * w_q[idx]);
        open_points.push(
            arithmetic.q_comms[idx]
                .decompress()
                .ok_or("target q commitment invalid point")?,
        );
        open_scalars.push(-chal * w_s[idx]);
        open_points.push(
            arithmetic.s_comms[idx]
                .decompress()
                .ok_or("target s commitment invalid point")?,
        );
    }
    open_scalars.push(b_coeff);
    open_points.push(pc_gens.B);
    open_scalars.push(sigma.z_blind_agg);
    open_points.push(pc_gens.B_blinding);
    open_scalars.push(-Scalar::one());
    open_points.push(a_open);
    open_scalars.push(-chal * w_z);
    open_points.push(
        arithmetic
            .z_comm
            .decompress()
            .ok_or("target z commitment invalid point")?,
    );

    let open_check = RistrettoPoint::vartime_multiscalar_mul(
        open_scalars.iter().copied(),
        open_points.iter().copied(),
    );
    if open_check != RistrettoPoint::identity() {
        return Err("target sigma commitment opening relation failed".to_string());
    }

    // --- c1 check ---
    // (z_zru + Σ z_s[j]) * G + Σ (z_beta[j] * m_j.c1) - a_c1 - chal * c.c1 = 0
    let mut c1_scalars = Vec::with_capacity(2 * n + 3);
    let mut c1_points = Vec::with_capacity(2 * n + 3);
    let mut g1 = sigma.z_zru;
    for idx in 0..n {
        let z_beta_j = sigma.z_z - two * sigma.z_q[idx];
        g1 += sigma.z_s[idx];
        c1_scalars.push(z_beta_j);
        c1_points.push(encrypted_monitor_bits[idx].c1);
    }
    c1_scalars.push(g1);
    c1_points.push(G);
    c1_scalars.push(-Scalar::one());
    c1_points.push(a_c1);
    c1_scalars.push(-chal);
    c1_points.push(ciphertext.c1);
    let c1_check = RistrettoPoint::vartime_multiscalar_mul(
        c1_scalars.iter().copied(),
        c1_points.iter().copied(),
    );
    if c1_check != RistrettoPoint::identity() {
        return Err("target sigma c1 relation failed".to_string());
    }

    // --- c2 check ---
    // (z_zu + Σ z_q[j]) * G + (z_zru + Σ z_s[j]) * pk
    // + Σ (z_beta[j] * m_j.c2) - a_c2 - chal * c.c2 = 0
    let mut c2_scalars = Vec::with_capacity(3 * n + 5);
    let mut c2_points = Vec::with_capacity(3 * n + 5);
    let mut g2 = sigma.z_zu;
    let mut pk2 = sigma.z_zru;
    for idx in 0..n {
        let z_beta_j = sigma.z_z - two * sigma.z_q[idx];
        g2 += sigma.z_q[idx];
        pk2 += sigma.z_s[idx];
        c2_scalars.push(z_beta_j);
        c2_points.push(encrypted_monitor_bits[idx].c2);
    }
    c2_scalars.push(g2);
    c2_points.push(G);
    c2_scalars.push(pk2);
    c2_points.push(pk.0);
    c2_scalars.push(-Scalar::one());
    c2_points.push(a_c2);
    c2_scalars.push(-chal);
    c2_points.push(ciphertext.c2);
    let c2_check = RistrettoPoint::vartime_multiscalar_mul(
        c2_scalars.iter().copied(),
        c2_points.iter().copied(),
    );
    if c2_check != RistrettoPoint::identity() {
        return Err("target sigma c2 relation failed".to_string());
    }

    Ok(())
}

// ----- public API -------------------------------------------------------------

pub fn default_gens(bit_len: usize) -> (PedersenGens, BulletproofGens) {
    (PedersenGens::default(), make_bp_gens(bit_len))
}

#[allow(clippy::too_many_arguments)]
pub fn prove<R: CryptoRng + RngCore>(
    rng: &mut R,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    pk: &PublicKey,
    ciphertext: &Ciphertext,
    encrypted_monitor_bits: &[Ciphertext],
    secret_bits: &[Scalar],
    bit_randomness: &[Scalar],
    z: Scalar,
    u: Scalar,
    u_randomness: Scalar,
) -> Result<TargetHybridProof, String> {
    let (arithmetic, witness) = prove_arithmetic(
        rng,
        pc_gens,
        bp_gens,
        encrypted_monitor_bits,
        ciphertext,
        secret_bits,
        bit_randomness,
        z,
        u,
        u_randomness,
    )
    .map_err(|e| format!("target arithmetic prove failed: {e:?}"))?;

    let sigma = prove_sigma(
        rng,
        pc_gens,
        pk,
        encrypted_monitor_bits,
        ciphertext,
        &arithmetic,
        &witness,
    );
    Ok(TargetHybridProof { arithmetic, sigma })
}

pub fn verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    pk: &PublicKey,
    ciphertext: &Ciphertext,
    encrypted_monitor_bits: &[Ciphertext],
    proof: &TargetHybridProof,
) -> Result<(), String> {
    verify_arithmetic(
        pc_gens,
        bp_gens,
        encrypted_monitor_bits,
        ciphertext,
        &proof.arithmetic,
    )?;
    verify_sigma(
        pc_gens,
        pk,
        encrypted_monitor_bits,
        ciphertext,
        &proof.arithmetic,
        &proof.sigma,
    )?;
    Ok(())
}

// ----- tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn encrypt_with_randomness(pk: &PublicKey, msg: Scalar, r: Scalar) -> Ciphertext {
        Ciphertext {
            c1: r * G,
            c2: msg * G + r * pk.0,
        }
    }

    fn build_target_ciphertext<R: CryptoRng + RngCore>(
        _rng: &mut R,
        pk: &PublicKey,
        secret_bits: &[Scalar],
        encrypted_monitor_bits: &[Ciphertext],
        bit_randomness: &[Scalar],
        z: Scalar,
        u: Scalar,
        u_randomness: Scalar,
    ) -> Ciphertext {
        let mut acc = Ciphertext {
            c1: RistrettoPoint::identity(),
            c2: RistrettoPoint::identity(),
        };
        for ((x, m_ct), r_x) in secret_bits
            .iter()
            .zip(encrypted_monitor_bits.iter())
            .zip(bit_randomness.iter())
        {
            let enc_x = encrypt_with_randomness(pk, *x, *r_x);
            let coeff = Scalar::one() - Scalar::from(2u64) * *x;
            let term = Ciphertext {
                c1: enc_x.c1 + coeff * m_ct.c1,
                c2: enc_x.c2 + coeff * m_ct.c2,
            };
            acc = Ciphertext {
                c1: acc.c1 + term.c1,
                c2: acc.c2 + term.c2,
            };
        }
        let enc_u = encrypt_with_randomness(pk, u, u_randomness);
        Ciphertext {
            c1: z * acc.c1 + enc_u.c1,
            c2: z * acc.c2 + enc_u.c2,
        }
    }

    #[test]
    fn test_target_hybrid_proof_roundtrip_public_encrypted_bits() {
        let mut rng = OsRng;
        let (pc_gens, bp_gens) = default_gens(8);
        let sk = Scalar::random(&mut rng);
        let pk = PublicKey(sk * G);
        let monitor_bits = vec![
            Scalar::zero(),
            Scalar::one(),
            Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::one(),
            Scalar::zero(),
            Scalar::one(),
        ];
        let secret_bits = vec![
            Scalar::one(),
            Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::one(),
            Scalar::zero(),
            Scalar::zero(),
            Scalar::one(),
        ];

        let mut encrypted_monitor_bits = Vec::with_capacity(monitor_bits.len());
        for &bit in &monitor_bits {
            encrypted_monitor_bits.push(encrypt_with_randomness(
                &pk,
                bit,
                Scalar::random(&mut rng),
            ));
        }
        let bit_randomness: Vec<_> = (0..secret_bits.len())
            .map(|_| Scalar::random(&mut rng))
            .collect();
        let z = Scalar::from(7u64);
        let u = Scalar::from(9u64);
        let u_randomness = Scalar::random(&mut rng);
        let ciphertext = build_target_ciphertext(
            &mut rng,
            &pk,
            &secret_bits,
            &encrypted_monitor_bits,
            &bit_randomness,
            z,
            u,
            u_randomness,
        );

        let proof = prove(
            &mut rng,
            &pc_gens,
            &bp_gens,
            &pk,
            &ciphertext,
            &encrypted_monitor_bits,
            &secret_bits,
            &bit_randomness,
            z,
            u,
            u_randomness,
        )
        .unwrap();

        verify(
            &pc_gens,
            &bp_gens,
            &pk,
            &ciphertext,
            &encrypted_monitor_bits,
            &proof,
        )
        .unwrap();
    }

    #[test]
    fn test_target_hybrid_proof_rejects_tampered_monitor_ciphertext() {
        let mut rng = OsRng;
        let (pc_gens, bp_gens) = default_gens(4);
        let sk = Scalar::random(&mut rng);
        let pk = PublicKey(sk * G);
        let monitor_bits = vec![Scalar::zero(), Scalar::one(), Scalar::zero(), Scalar::one()];
        let secret_bits = vec![Scalar::one(), Scalar::one(), Scalar::zero(), Scalar::zero()];
        let mut encrypted_monitor_bits = Vec::with_capacity(monitor_bits.len());
        for &bit in &monitor_bits {
            encrypted_monitor_bits.push(encrypt_with_randomness(
                &pk,
                bit,
                Scalar::random(&mut rng),
            ));
        }
        let bit_randomness: Vec<_> = (0..secret_bits.len())
            .map(|_| Scalar::random(&mut rng))
            .collect();
        let z = Scalar::from(3u64);
        let u = Scalar::from(2u64);
        let u_randomness = Scalar::random(&mut rng);
        let ciphertext = build_target_ciphertext(
            &mut rng,
            &pk,
            &secret_bits,
            &encrypted_monitor_bits,
            &bit_randomness,
            z,
            u,
            u_randomness,
        );
        let proof = prove(
            &mut rng,
            &pc_gens,
            &bp_gens,
            &pk,
            &ciphertext,
            &encrypted_monitor_bits,
            &secret_bits,
            &bit_randomness,
            z,
            u,
            u_randomness,
        )
        .unwrap();

        let mut bad_encrypted_monitor_bits = encrypted_monitor_bits.clone();
        bad_encrypted_monitor_bits[0].c2 += G;
        assert!(verify(
            &pc_gens,
            &bp_gens,
            &pk,
            &ciphertext,
            &bad_encrypted_monitor_bits,
            &proof
        )
        .is_err());
    }
}
