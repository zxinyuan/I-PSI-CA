//! Non-interactive Sigma (Schnorr) proof of correct partial decryption.
//!
//! # Statement
//!
//! The monitor proves knowledge of `(sk2, r') ∈ 𝔽²` satisfying three
//! simultaneous linear relations, without revealing either witness:
//!
//! ```text
//!   (R1)  pk2        =  sk2 · G
//!   (R2)  c1' − c1  =  r' · G
//!   (R3)  c2' − c2  =  −sk2 · c1  +  r' · pk1
//! ```
//!
//! Relations (R1)–(R3) together certify:
//! - *Key ownership*: `sk2` is the discrete-log of the monitor's published
//!   public key `pk2` w.r.t. the Ristretto255 basepoint `G`.
//! - *Correct partial decryption*: the output ciphertext `(c1', c2')` was
//!   produced by running `THDec[sk2]` on the input ciphertext `(c1, c2)` and
//!   re-randomizing with scalar `r'`, i.e. `c2' = c2 − sk2·c1 + r'·pk1`
//!   used the same key as `pk2`.
//!
//! # Protocol (two-witness linear Schnorr, Fiat-Shamir via Merlin)
//!
//! **Commit**: sample `a, b ←$ 𝔽` and compute
//! ```text
//!   A1 =  a · G
//!   A2 =  b · G
//!   A3 = −a · c1  +  b · pk1
//! ```
//!
//! **Challenge**: `e = H(pk2, pk1, c1, c2, c1', c2', A1, A2, A3)` via Merlin.
//!
//! **Response**:
//! ```text
//!   z1 = a + e · sk2
//!   z2 = b + e · r'
//! ```
//!
//! **Verification** (all three must hold):
//! ```text
//!   (V1)  z1 · G               == A1 + e · pk2
//!   (V2)  z2 · G               == A2 + e · (c1' − c1)
//!   (V3)  −z1 · c1 + z2 · pk1 == A3 + e · (c2' − c2)
//! ```
//!
//! Soundness follows from the discrete-log hardness in Ristretto255.
//! Zero-knowledge follows from the standard Schnorr simulator argument.

use curve25519_dalek_ng::{
    constants::{RISTRETTO_BASEPOINT_POINT as G, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, MultiscalarMul, VartimeMultiscalarMul},
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::{Ciphertext, EncryptedPoly, PublicKey, PublicKeyShare};

// ── Proof type ────────────────────────────────────────────────────────────────

/// Non-interactive proof that `out_ct = THDec[sk2](in_ct)` using the same
/// `sk2` that corresponds to the monitor's published public key `pk2 = sk2·G`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialDecryptProof {
    /// Single batched round-1 commitment that binds both witnesses
    /// (`sk2` and `r'`) in one sigma relation.
    pub a: CompressedRistretto,
    /// Response `z1 = a + e·sk2`.
    pub z1: Scalar,
    /// Response `z2 = b + e·r'`.
    pub z2: Scalar,
}

// ── Transcript helpers ────────────────────────────────────────────────────────

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

/// Squeeze a 512-bit challenge and reduce modulo the group order.
/// Using 512 bits eliminates statistical bias (ℓ ≈ 2^252, so 2^512/ℓ ≈ 2^260).
fn challenge_scalar(t: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"challenge", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

/// Independent transcript-derived scalar used to batch multiple linear checks
/// into a single verifier equation.
fn batch_scalar(t: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"batch", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

fn batch_scalar_labeled(t: &mut Transcript, label: &'static [u8]) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(label, &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

/// Independent transcript-derived scalar used to linearly combine the key
/// relation and the ciphertext relation into one verifier equation.
fn combine_scalar(t: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"combine", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

// ── Statement transcript ──────────────────────────────────────────────────────

/// Domain-separated transcript binding all public statement inputs.
/// Prover and verifier must call this with identical arguments to derive the
/// same challenge.
fn statement_transcript(
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    in_ct: &Ciphertext,
    out_ct: &Ciphertext,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::partial_decrypt_sigma_v1");
    append_point(&mut t, b"pk2",    &pk2.0);
    append_point(&mut t, b"pk1",    &pk1.0);
    append_point(&mut t, b"c1_in",  &in_ct.c1);
    append_point(&mut t, b"c2_in",  &in_ct.c2);
    append_point(&mut t, b"c1_out", &out_ct.c1);
    append_point(&mut t, b"c2_out", &out_ct.c2);
    t
}

/// Batch coefficient used to combine the rerandomization and partial-decrypt
/// relations into one prover commitment and one verifier check.
pub(crate) fn partial_decrypt_relation_scalars(
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    in_ct: &Ciphertext,
    out_ct: &Ciphertext,
) -> (Scalar, Scalar) {
    let mut t = statement_transcript(pk2, pk1, in_ct, out_ct);
    let beta = batch_scalar(&mut t);
    let gamma = combine_scalar(&mut t);
    (beta, gamma)
}

// ── Prove ─────────────────────────────────────────────────────────────────────

/// Prove that `out_ct` was produced by `THDec[sk2](in_ct)` with the secret
/// key `sk2` whose public counterpart is `pk2 = sk2·G`.
///
/// # Arguments
///
/// * `rng`     – cryptographically secure RNG (used for nonce scalars `a`, `b`)
/// * `sk2`     – monitor's secret key scalar (witness 1)
/// * `r_prime` – re-randomization scalar returned by `partial_decrypt_with_witness`
///               (witness 2)
/// * `pk2`     – monitor's public key share (`sk2·G`)
/// * `pk1`     – target's public key share
/// * `in_ct`   – the ciphertext fed into `THDec[sk2]`
/// * `out_ct`  – the ciphertext produced by `THDec[sk2]`
pub fn prove<R: CryptoRng + RngCore>(
    rng: &mut R,
    sk2: &Scalar,
    r_prime: Scalar,
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    in_ct: &Ciphertext,
    out_ct: &Ciphertext,
) -> PartialDecryptProof {
    // ── Commit ────────────────────────────────────────────────────────────────
    let a = Scalar::random(rng);
    let b = Scalar::random(rng);

    // Transcript-derived scalars used by both prover and verifier.
    let (beta, gamma) = partial_decrypt_relation_scalars(pk2, pk1, in_ct, out_ct);

    // Single round-1 commitment:
    // A = A1 + gamma*A23
    //   = a*(G - gamma*c1) + b*gamma*(pk1 + beta*G)
    let beta_g = mul_g(&beta);
    let a_g = mul_g(&a);
    let rhs_base = pk1.0 + beta_g;
    let a_comb = a_g - a * (gamma * in_ct.c1) + b * (gamma * rhs_base);

    // ── Challenge (Fiat-Shamir via Merlin) ────────────────────────────────────
    let mut t = statement_transcript(pk2, pk1, in_ct, out_ct);
    t.append_message(b"beta", &beta.to_bytes());
    t.append_message(b"gamma", &gamma.to_bytes());
    append_point(&mut t, b"A", &a_comb);
    let e = challenge_scalar(&mut t);

    // ── Response ──────────────────────────────────────────────────────────────
    let z1 = a + e * sk2;
    let z2 = b + e * r_prime;

    PartialDecryptProof {
        a: a_comb.compress(),
        z1,
        z2,
    }
}

// ── Verify ────────────────────────────────────────────────────────────────────

/// Verify a [`PartialDecryptProof`].
///
/// Returns `Ok(())` if all three verification equations hold, or `Err` with a
/// description of the first failing check.
///
/// # Arguments
///
/// * `proof`  – the proof to verify
/// * `pk2`    – monitor's public key share
/// * `pk1`    – target's public key share
/// * `in_ct`  – the ciphertext given to the monitor for partial decryption
/// * `out_ct` – the ciphertext the monitor returned
pub fn verify(
    proof: &PartialDecryptProof,
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    in_ct: &Ciphertext,
    out_ct: &Ciphertext,
) -> Result<(), &'static str> {
    // Decompress nonce commitments.
    let a = proof.a.decompress().ok_or("A is not a valid Ristretto point")?;

    let (beta, gamma) = partial_decrypt_relation_scalars(pk2, pk1, in_ct, out_ct);

    // Recompute the Fiat-Shamir challenge using the identical transcript.
    let mut t = statement_transcript(pk2, pk1, in_ct, out_ct);
    t.append_message(b"beta", &beta.to_bytes());
    t.append_message(b"gamma", &gamma.to_bytes());
    append_point(&mut t, b"A", &a);
    let e = challenge_scalar(&mut t);

    let z1 = proof.z1;
    let z2 = proof.z2;

    // Single round-3 batched verifier relation:
    //
    // z1*(G - γ*c1) + z2*γ*(pk1 + β*G)
    //     == A + e*(pk2 + γ*(Δc2 + β*Δc1))
    //
    // This checks key-ownership, rerandomization, and partial-decrypt
    // consistency together in one equation.
    let delta_c1 = out_ct.c1 - in_ct.c1;
    let delta_c2 = out_ct.c2 - in_ct.c2;
    let beta_g = mul_g(&beta);
    let lhs = mul_g(&z1) - z1 * (gamma * in_ct.c1) + z2 * (gamma * (pk1.0 + beta_g));
    let rhs = a + e * (pk2.0 + gamma * (delta_c2 + beta * delta_c1));
    if lhs != rhs {
        return Err("V failed: batched key-ownership + rerandomization + partial-decryption consistency");
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════════
// PolyDivProof — correct homomorphic polynomial division
// ═══════════════════════════════════════════════════════════════════════════════
//
// The monitor proves that `out_poly` was produced from `in_poly` by the
// homomorphic synthetic division `TPolyCtext THDiv[pk] (X − m)` using the
// same secret element `m = MElmt`.
//
// # Structure of the division
//
// `div_poly_linear` (degree-n input → degree-(n−1) output) computes:
//
// ```text
//   b[n−1] = a[n]                            (leading term: exact copy)
//   b[d]   = a[d+1] + m · b[d+1]   d = n−2…0  (n−1 scalar-multiplication steps)
// ```
//
// Each step gives the relation  `b[d] − a[d+1] = m · b[d+1]`,  applied
// component-wise to the two Ristretto-point halves of each ElGamal ciphertext.
//
// # Batched single-witness DLEQ
//
// All n−1 steps share the same scalar witness `m`.  The proof batches them:
//
// 1.  The statement transcript squeezes n−1 random weights `α[0], …, α[n−2]`.
// 2.  Define (using component index j ∈ {c1, c2}):
//
//       X_j = Σ_d  α[d] · b[d+1].cj
//       Y_j = Σ_d  α[d] · (b[d].cj − a[d+1].cj)
//
// 3.  Prove knowledge of `m` satisfying:
//
//       Y_c1 = m · X_c1   and   Y_c2 = m · X_c2
//
//     with one nonce `r` shared across both components.
//
// **Commit**: `A1 = r · X_c1`,  `A2 = r · X_c2`
// **Challenge**: `e = H(statement, A1, A2)`
// **Response**: `z = r + e · m`
//
// **Verify**:
//   `z · X_c1  ==  A1 + e · Y_c1`
//   `z · X_c2  ==  A2 + e · Y_c2`
//
// Proof size: 2 compressed Ristretto points + 1 scalar = 96 bytes (constant).

/// Non-interactive proof that `out_poly` was produced from `in_poly` by the
/// homomorphic polynomial division `in_poly THDiv[pk] (X − m)` for some
/// secret `m`, i.e. each step `b[d] = a[d+1] + m·b[d+1]` used the same `m`.
///
/// The leading-term identity `b[n−1] = a[n]` is verified without a proof
/// (it is publicly checkable from the wire ciphertexts).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolyDivProof {
    /// Batched round-1 commitment for c1:
    /// `A1 = k_y·X_c1 + k_δ·G`.
    pub a1: CompressedRistretto,
    /// Batched round-1 commitment for c2:
    /// `A2 = k_y·X_c2 + k_δ·pk`.
    pub a2: CompressedRistretto,
    /// Public tag for the shared monitor input: `alpha_tag = m · G`.
    pub alpha_tag: CompressedRistretto,
    /// Round-1 commitment for monitor-input linkage: `A_m = k_y·G`.
    pub a_m: CompressedRistretto,
    /// Response `s_y = k_y + c·y`.
    pub s_y: Scalar,
    /// Batched response `s_δ = k_δ + c·δ*`, where `δ* = Σ α_d·δ_d`.
    pub s_delta: Scalar,
}

// ── Poly-div transcript helpers ───────────────────────────────────────────────

/// Domain-separated transcript for the polynomial-division sigma proof.
fn poly_div_transcript(
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::poly_div_sigma_v1");
    append_point(&mut t, b"alpha_tag", alpha_tag);
    for ct in &in_poly.0 {
        append_point(&mut t, b"in_c1", &ct.c1);
        append_point(&mut t, b"in_c2", &ct.c2);
    }
    for ct in &out_poly.0 {
        append_point(&mut t, b"out_c1", &ct.c1);
        append_point(&mut t, b"out_c2", &ct.c2);
    }
    t
}

pub(crate) fn poly_div_batch_scalars(
    proof: &PolyDivProof,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
) -> Result<(Scalar, Scalar), &'static str> {
    proof.a1.decompress().ok_or("A1 is not a valid Ristretto point")?;
    proof.a2.decompress().ok_or("A2 is not a valid Ristretto point")?;
    proof.a_m.decompress().ok_or("A_m is not a valid Ristretto point")?;

    let mut t = poly_div_transcript(in_poly, out_poly, alpha_tag);
    append_compressed(&mut t, b"A1", &proof.a1);
    append_compressed(&mut t, b"A2", &proof.a2);
    append_compressed(&mut t, b"A_m", &proof.a_m);
    let beta = batch_scalar_labeled(&mut t, b"poly_div_batch_1");
    let gamma = batch_scalar_labeled(&mut t, b"poly_div_batch_2");
    Ok((beta, gamma))
}

/// Squeeze one 512-bit batch weight from the transcript and reduce mod ℓ.
fn squeeze_weight(t: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"alpha", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

pub(crate) fn poly_div_relation_points(
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
) -> (RistrettoPoint, RistrettoPoint, RistrettoPoint, RistrettoPoint, Vec<Scalar>) {
    let n = out_poly.0.len();
    let mut t = poly_div_transcript(in_poly, out_poly, alpha_tag);
    let alphas: Vec<Scalar> = (0..n).map(|_| squeeze_weight(&mut t)).collect();

    let x_c1_points: Vec<RistrettoPoint> = (0..n)
        .map(|d| {
            if d + 1 < n {
                out_poly.0[d + 1].c1
            } else {
                RistrettoPoint::identity()
            }
        })
        .collect();
    let x_c2_points: Vec<RistrettoPoint> = (0..n)
        .map(|d| {
            if d + 1 < n {
                out_poly.0[d + 1].c2
            } else {
                RistrettoPoint::identity()
            }
        })
        .collect();
    let y_c1_points: Vec<RistrettoPoint> = (0..n)
        .map(|d| out_poly.0[d].c1 - in_poly.0[d + 1].c1)
        .collect();
    let y_c2_points: Vec<RistrettoPoint> = (0..n)
        .map(|d| out_poly.0[d].c2 - in_poly.0[d + 1].c2)
        .collect();

    let x_c1 = RistrettoPoint::multiscalar_mul(alphas.iter().copied(), x_c1_points.iter().copied());
    let x_c2 = RistrettoPoint::multiscalar_mul(alphas.iter().copied(), x_c2_points.iter().copied());
    let y_c1 = RistrettoPoint::multiscalar_mul(alphas.iter().copied(), y_c1_points.iter().copied());
    let y_c2 = RistrettoPoint::multiscalar_mul(alphas.iter().copied(), y_c2_points.iter().copied());

    (x_c1, x_c2, y_c1, y_c2, alphas)
}

fn rerandom_relation_points(
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alphas: &[Scalar],
) -> (RistrettoPoint, RistrettoPoint) {
    let x1_points: Vec<RistrettoPoint> = in_poly
        .0
        .iter()
        .zip(out_poly.0.iter())
        .map(|(i, o)| o.c1 - i.c1)
        .collect();
    let x2_points: Vec<RistrettoPoint> = in_poly
        .0
        .iter()
        .zip(out_poly.0.iter())
        .map(|(i, o)| o.c2 - i.c2)
        .collect();

    let x1 = RistrettoPoint::multiscalar_mul(alphas.iter().copied(), x1_points.iter().copied());
    let x2 = RistrettoPoint::multiscalar_mul(alphas.iter().copied(), x2_points.iter().copied());
    (x1, x2)
}

// ── prove_poly_div ────────────────────────────────────────────────────────────

/// Prove that `out_poly = in_poly THDiv[pk] (X − m)` for secret `m`.
///
/// # Arguments
///
/// * `rng`      – cryptographically secure RNG
/// * `m`        – the monitor's secret element (witness)
/// * `in_poly`  – the current encrypted polynomial (input to division)
/// * `out_poly` – the output of `div_poly_linear(in_poly, m)`
pub fn prove_poly_div<R: CryptoRng + RngCore>(
    rng: &mut R,
    y: &Scalar,
    pk: &PublicKey,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    delta_vec: &[Scalar],
    alpha_tag: &RistrettoPoint,
) -> PolyDivProof {
    let n = in_poly.0.len().saturating_sub(1);
    if out_poly.0.len() != n || delta_vec.len() != n {
        return PolyDivProof {
            a1: RistrettoPoint::identity().compress(),
            a2: RistrettoPoint::identity().compress(),
            alpha_tag: alpha_tag.compress(),
            a_m: RistrettoPoint::identity().compress(),
            s_y: Scalar::zero(),
            s_delta: Scalar::zero(),
        };
    }

    if n == 0 {
        return PolyDivProof {
            a1: RistrettoPoint::identity().compress(),
            a2: RistrettoPoint::identity().compress(),
            alpha_tag: alpha_tag.compress(),
            a_m: RistrettoPoint::identity().compress(),
            s_y: Scalar::zero(),
            s_delta: Scalar::zero(),
        };
    }

    let mut t = poly_div_transcript(in_poly, out_poly, alpha_tag);
    let (x_c1, x_c2, _y_c1, _y_c2, alphas) =
        poly_div_relation_points(in_poly, out_poly, alpha_tag);
    let delta_star: Scalar = alphas
        .iter()
        .zip(delta_vec.iter())
        .map(|(alpha, delta)| alpha * delta)
        .sum();
    let k_y = Scalar::random(rng);
    let k_delta = Scalar::random(rng);
    let a1 = (k_y * x_c1 + mul_g(&k_delta)).compress();
    let a2 = (k_y * x_c2 + k_delta * pk.0).compress();
    let a_m = mul_g(&k_y).compress();

    append_compressed(&mut t, b"A1", &a1);
    append_compressed(&mut t, b"A2", &a2);
    append_compressed(&mut t, b"A_m", &a_m);
    let _beta = batch_scalar_labeled(&mut t, b"poly_div_batch_1");
    let _gamma = batch_scalar_labeled(&mut t, b"poly_div_batch_2");
    let e = challenge_scalar(&mut t);

    PolyDivProof {
        a1,
        a2,
        alpha_tag: alpha_tag.compress(),
        a_m,
        s_y: k_y + e * y,
        s_delta: k_delta + e * delta_star,
    }
}

// ── verify_poly_div ───────────────────────────────────────────────────────────

/// Verify a [`PolyDivProof`].
///
/// # Arguments
///
/// * `proof`    – the proof to verify
/// * `in_poly`  – the input encrypted polynomial
/// * `out_poly` – the output polynomial returned by the monitor
pub fn verify_poly_div(
    proof: &PolyDivProof,
    pk: &PublicKey,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    expected_alpha_tag: &RistrettoPoint,
) -> Result<(), &'static str> {
    let n = in_poly.0.len().checked_sub(1).ok_or("in_poly must have degree ≥ 1")?;

    if out_poly.0.len() != n {
        return Err("out_poly length does not match expected quotient degree");
    }

    let alpha_tag = proof
        .alpha_tag
        .decompress()
        .ok_or("alpha_tag is not a valid Ristretto point")?;
    if alpha_tag != *expected_alpha_tag {
        return Err("alpha_tag mismatch across proofs");
    }

    // Rebuild statement transcript.
    let mut t = poly_div_transcript(in_poly, out_poly, &alpha_tag);
    let (x_c1, x_c2, y_c1, y_c2, _) =
        poly_div_relation_points(in_poly, out_poly, &alpha_tag);

    let a1 = proof.a1.decompress().ok_or("A1 is not a valid Ristretto point")?;
    let a2 = proof.a2.decompress().ok_or("A2 is not a valid Ristretto point")?;
    let a_m = proof.a_m.decompress().ok_or("A_m is not a valid Ristretto point")?;

    // Recompute challenge.
    append_compressed(&mut t, b"A1", &proof.a1);
    append_compressed(&mut t, b"A2", &proof.a2);
    append_compressed(&mut t, b"A_m", &proof.a_m);
    let beta = batch_scalar_labeled(&mut t, b"poly_div_batch_1");
    let gamma = batch_scalar_labeled(&mut t, b"poly_div_batch_2");
    let e = challenge_scalar(&mut t);
    let lhs = RistrettoPoint::vartime_multiscalar_mul(
        [
            proof.s_y,
            beta * proof.s_y,
            gamma * proof.s_y,
            proof.s_delta,
            beta * proof.s_delta,
        ],
        [x_c1, x_c2, G, G, pk.0],
    );
    let rhs = a1 + beta * a2 + gamma * a_m + e * (y_c1 + beta * y_c2 + gamma * alpha_tag);
    if lhs != rhs {
        return Err("poly-div batched verifier check failed");
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{
        combine_public_keys, ct_scalar_mul, div_poly_linear, encrypt, encrypt_poly, eval_poly,
        generate_key_share, partial_decrypt_with_witness,
    };
    use rand::rngs::OsRng;

    fn setup() -> (
        crate::crypto::elgamal::SecretKeyShare, PublicKeyShare,
        crate::crypto::elgamal::SecretKeyShare, PublicKeyShare,
        crate::crypto::elgamal::PublicKey,
    ) {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        (sk1, pk1, sk2, pk2, pk)
    }

    /// Happy path: an honestly generated proof verifies.
    #[test]
    fn test_valid_proof() {
        let mut rng = OsRng;
        let (_sk1, pk1, sk2, pk2, pk) = setup();

        let in_ct = encrypt(&mut rng, &pk, &Scalar::from(42u64));
        let (out_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &in_ct);

        let proof = prove(&mut rng, sk2.as_scalar(), r_prime, &pk2, &pk1, &in_ct, &out_ct);
        verify(&proof, &pk2, &pk1, &in_ct, &out_ct).expect("valid proof must verify");
    }

    /// Protocol usage: input is a masked polynomial evaluation.
    #[test]
    fn test_valid_proof_scaled_poly_eval() {
        let mut rng = OsRng;
        let (_sk1, pk1, sk2, pk2, pk) = setup();

        // P(X) = (X − 2)(X − 3) = X² − 5X + 6.
        let coeffs = [Scalar::from(6u64), -Scalar::from(5u64), Scalar::from(1u64)];
        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);

        // Evaluate at x = 2 (a root → P(2) = 0) and scale by a random mask.
        let x    = Scalar::from(2u64);
        let mask = Scalar::from(13u64);
        let scaled_ct = ct_scalar_mul(&eval_poly(&poly_ct, &x), &mask);

        let (out_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &scaled_ct);
        let proof = prove(&mut rng, sk2.as_scalar(), r_prime, &pk2, &pk1, &scaled_ct, &out_ct);
        verify(&proof, &pk2, &pk1, &scaled_ct, &out_ct)
            .expect("valid proof for scaled eval must verify");
    }

    /// A proof for one output must not verify against a different output.
    #[test]
    fn test_tampered_output_rejected() {
        let mut rng = OsRng;
        let (_sk1, pk1, sk2, pk2, pk) = setup();

        let in_ct = encrypt(&mut rng, &pk, &Scalar::from(7u64));
        let (out_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &in_ct);
        let proof = prove(&mut rng, sk2.as_scalar(), r_prime, &pk2, &pk1, &in_ct, &out_ct);

        let tampered = encrypt(&mut rng, &pk, &Scalar::from(99u64));
        assert!(
            verify(&proof, &pk2, &pk1, &in_ct, &tampered).is_err(),
            "proof must not verify against a tampered output ciphertext"
        );
    }

    /// A proof made with one key pair must not verify against a different pk2.
    #[test]
    fn test_wrong_public_key_rejected() {
        let mut rng = OsRng;
        let (_sk1, pk1, sk2, pk2, pk) = setup();
        let (_sk2_other, pk2_other) = generate_key_share(&mut rng);

        let in_ct = encrypt(&mut rng, &pk, &Scalar::from(5u64));
        let (out_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &in_ct);
        let proof = prove(&mut rng, sk2.as_scalar(), r_prime, &pk2, &pk1, &in_ct, &out_ct);

        assert!(
            verify(&proof, &pk2_other, &pk1, &in_ct, &out_ct).is_err(),
            "proof must not verify against a wrong public key"
        );
    }

    /// A proof made with one input ciphertext must not verify against a different input.
    #[test]
    fn test_wrong_input_rejected() {
        let mut rng = OsRng;
        let (_sk1, pk1, sk2, pk2, pk) = setup();

        let in_ct  = encrypt(&mut rng, &pk, &Scalar::from(3u64));
        let in_ct2 = encrypt(&mut rng, &pk, &Scalar::from(4u64));
        let (out_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &in_ct);
        let proof = prove(&mut rng, sk2.as_scalar(), r_prime, &pk2, &pk1, &in_ct, &out_ct);

        assert!(
            verify(&proof, &pk2, &pk1, &in_ct2, &out_ct).is_err(),
            "proof must not verify against a different input ciphertext"
        );
    }

    // ── PolyDivProof tests ────────────────────────────────────────────────────

    /// Happy path: an honest poly-div proof over a degree-3 polynomial verifies.
    #[test]
    fn test_poly_div_valid() {
        let mut rng = OsRng;
        let (_sk1, _pk1, _sk2, _pk2, pk) = setup();

        // P(X) = (X−2)(X−3)(X−5) — encrypt it.
        let coeffs = [
            -Scalar::from(30u64),                          // constant: −2·3·5
             Scalar::from(31u64),                          // X:       2·3 + 2·5 + 3·5
            -Scalar::from(10u64),                          // X²:      −(2+3+5)
             Scalar::from(1u64),                           // X³
        ];
        let in_poly = encrypt_poly(&mut rng, &pk, &coeffs);
        let m = Scalar::from(2u64);
        let out_poly = div_poly_linear(&in_poly, &m);

        let alpha_tag = mul_g(&m);
        let delta_vec = vec![Scalar::zero(); out_poly.0.len()];
        let proof = prove_poly_div(&mut rng, &m, &pk, &in_poly, &out_poly, &delta_vec, &alpha_tag);
        verify_poly_div(&proof, &pk, &in_poly, &out_poly, &alpha_tag)
            .expect("valid poly-div proof must verify");
    }

    /// A proof for one output polynomial must not verify against a different output.
    #[test]
    fn test_poly_div_wrong_output_rejected() {
        let mut rng = OsRng;
        let (_sk1, _pk1, _sk2, _pk2, pk) = setup();

        let coeffs = [Scalar::from(6u64), -Scalar::from(5u64), Scalar::from(1u64)];
        let in_poly   = encrypt_poly(&mut rng, &pk, &coeffs);
        let m         = Scalar::from(2u64);
        let out_poly  = div_poly_linear(&in_poly, &m);
        // A different division (wrong m).
        let out_wrong = div_poly_linear(&in_poly, &Scalar::from(3u64));

        let alpha_tag = mul_g(&m);
        let delta_vec = vec![Scalar::zero(); out_poly.0.len()];
        let proof = prove_poly_div(&mut rng, &m, &pk, &in_poly, &out_poly, &delta_vec, &alpha_tag);
        assert!(
            verify_poly_div(&proof, &pk, &in_poly, &out_wrong, &alpha_tag).is_err(),
            "proof must not verify against a different output poly"
        );
    }

    /// A proof generated with one secret m must not verify if the witness is wrong.
    #[test]
    fn test_poly_div_wrong_witness_rejected() {
        let mut rng = OsRng;
        let (_sk1, _pk1, _sk2, _pk2, pk) = setup();

        let coeffs  = [Scalar::from(6u64), -Scalar::from(5u64), Scalar::from(1u64)];
        let in_poly = encrypt_poly(&mut rng, &pk, &coeffs);
        let m       = Scalar::from(2u64);
        let out_poly = div_poly_linear(&in_poly, &m);

        // Prove with a *wrong* witness m' ≠ m.
        let m_wrong = Scalar::from(7u64);
        let alpha_tag = mul_g(&m);
        let delta_vec = vec![Scalar::zero(); out_poly.0.len()];
        let proof   = prove_poly_div(&mut rng, &m_wrong, &pk, &in_poly, &out_poly, &delta_vec, &alpha_tag);
        assert!(
            verify_poly_div(&proof, &pk, &in_poly, &out_poly, &alpha_tag).is_err(),
            "proof with wrong witness must be rejected"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RerandomProof — correct re-randomization of an encrypted polynomial
// ═══════════════════════════════════════════════════════════════════════════════
//
// The target proves that `out_poly` was produced from `in_poly` by honest
// re-randomization under the joint public key `pk`:
//
//   out_poly[i] = in_poly[i] + r_i · (G, pk)   for all i,  some r_i ∈ 𝔽.
//
// Equivalently, for each i:
//   Δc1_i = r_i · G     (c1 component)
//   Δc2_i = r_i · pk    (c2 component)
//
// # Batched single-witness DLEQ
//
// Using Fiat-Shamir weights α_i derived from the transcript of all points:
//
//   X1 = Σ α_i · Δc1_i = (Σ α_i · r_i) · G  = r* · G
//   X2 = Σ α_i · Δc2_i = (Σ α_i · r_i) · pk = r* · pk
//
// Prove knowledge of `r* = Σ α_i · r_i` satisfying  (X1, X2) = r* · (G, pk).
//
// **Commit**: `A1 = k · G`,  `A2 = k · pk`
// **Challenge**: `e = H(statement, A1, A2)`
// **Response**: `z = k + e · r*`
//
// **Verify**:
//   `z · G  == A1 + e · X1`
//   `z · pk == A2 + e · X2`
//
// Proof size: 2 compressed Ristretto points + 1 scalar = 96 bytes (constant).

/// Non-interactive proof that `out_poly` was produced from `in_poly` by honest
/// per-coefficient re-randomization under `pk`:
/// `out_poly[i] = in_poly[i] + r_i · (G, pk)` for secret scalars `r_i`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RerandomProof {
    /// Batched nonce commitment for c1: `A1 = k · G`.
    pub a1: CompressedRistretto,
    /// Batched nonce commitment for c2: `A2 = k · pk`.
    pub a2: CompressedRistretto,
    /// Response `z = k + e · r*`.
    pub z: Scalar,
}

// ── Rerandom transcript helper ────────────────────────────────────────────────

fn rerandom_transcript(pk: &PublicKey, in_poly: &EncryptedPoly, out_poly: &EncryptedPoly) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::rerandom_poly_sigma_v1");
    append_point(&mut t, b"pk", &pk.0);
    for ct in &in_poly.0 {
        append_point(&mut t, b"in_c1",  &ct.c1);
        append_point(&mut t, b"in_c2",  &ct.c2);
    }
    for ct in &out_poly.0 {
        append_point(&mut t, b"out_c1", &ct.c1);
        append_point(&mut t, b"out_c2", &ct.c2);
    }
    t
}

// ── prove_rerandom ────────────────────────────────────────────────────────────

/// Prove that `out_poly` is a valid re-randomization of `in_poly` under `pk`.
///
/// # Arguments
///
/// * `rng`     – cryptographically secure RNG
/// * `pk`      – the joint public key used for re-randomization
/// * `r_vec`   – re-randomization scalars returned by `rerandomize_poly_with_witness`;
///               `r_vec[i]` is the scalar added for ciphertext i
/// * `in_poly` – the polynomial before re-randomization
/// * `out_poly` – the polynomial after re-randomization
pub fn prove_rerandom<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    r_vec: &[Scalar],
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
) -> RerandomProof {
    debug_assert_eq!(r_vec.len(), in_poly.0.len());
    debug_assert_eq!(in_poly.0.len(), out_poly.0.len());

    // Build statement transcript and squeeze per-coefficient batch weights α_i.
    let mut t = rerandom_transcript(pk, in_poly, out_poly);
    let alphas: Vec<Scalar> = (0..r_vec.len()).map(|_| squeeze_weight(&mut t)).collect();

    // Aggregate witness: r* = Σ α_i · r_i
    let r_star: Scalar = alphas.iter().zip(r_vec.iter()).map(|(a, r)| a * r).sum();

    // Commit: A1 = k·G,  A2 = k·pk
    let k = Scalar::random(rng);
    let a1 = mul_g(&k);
    let a2 = k * pk.0;

    // Challenge
    append_point(&mut t, b"A1", &a1);
    append_point(&mut t, b"A2", &a2);
    let _beta = batch_scalar_labeled(&mut t, b"rerandom_batch");
    let e = challenge_scalar(&mut t);

    RerandomProof {
        a1: a1.compress(),
        a2: a2.compress(),
        z: k + e * r_star,
    }
}

// ── verify_rerandom ───────────────────────────────────────────────────────────

/// Verify a [`RerandomProof`].
///
/// Returns `Ok(())` if both verification equations hold, or `Err` with a
/// description of the failing check.
///
/// # Arguments
///
/// * `proof`    – the proof to verify
/// * `pk`       – the joint public key used for re-randomization
/// * `in_poly`  – the polynomial before re-randomization
/// * `out_poly` – the polynomial claimed to be a re-randomization of `in_poly`
pub fn verify_rerandom(
    proof: &RerandomProof,
    pk: &PublicKey,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
) -> Result<(), &'static str> {
    if in_poly.0.len() != out_poly.0.len() {
        return Err("re-random: polynomial length mismatch");
    }

    // Rebuild statement transcript and derive the same batch weights.
    let mut t = rerandom_transcript(pk, in_poly, out_poly);
    let alphas: Vec<Scalar> = (0..in_poly.0.len()).map(|_| squeeze_weight(&mut t)).collect();
    let (x1, x2) = rerandom_relation_points(in_poly, out_poly, &alphas);

    let a1 = proof.a1.decompress().ok_or("re-random A1 is not a valid Ristretto point")?;
    let a2 = proof.a2.decompress().ok_or("re-random A2 is not a valid Ristretto point")?;

    // Recompute challenge.
    append_point(&mut t, b"A1", &a1);
    append_point(&mut t, b"A2", &a2);
    let beta = batch_scalar_labeled(&mut t, b"rerandom_batch");
    let e = challenge_scalar(&mut t);

    let z = proof.z;

    let lhs = RistrettoPoint::vartime_multiscalar_mul([z, beta * z], [G, pk.0]);
    let rhs = a1 + beta * a2 + e * (x1 + beta * x2);
    if lhs != rhs {
        return Err("re-random batched verifier check failed");
    }

    Ok(())
}

/// Verify the full polynomial transition seen by the monitor in one API:
///
/// 1. `next_poly` is a valid `THDiv(X - m)` output from `current_poly`
///    using monitor-input tag `alpha_tag`.
/// 2. `alt_poly` is a valid re-randomization of either:
///    - `next_poly` (match branch), or
///    - `current_poly` (no-match branch).
///
/// Returns `Ok(true)` for the match branch and `Ok(false)` for the no-match branch.
pub fn verify_poly_transition(
    poly_div_proof: &PolyDivProof,
    rerandom_proof: &RerandomProof,
    pk: &PublicKey,
    current_poly: &EncryptedPoly,
    next_poly: &EncryptedPoly,
    alt_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
) -> Result<bool, &'static str> {
    verify_poly_div(poly_div_proof, pk, current_poly, next_poly, alpha_tag)?;

    let is_match_branch = alt_poly.0.len() == next_poly.0.len();
    let base_poly = if is_match_branch { next_poly } else { current_poly };
    verify_rerandom(rerandom_proof, pk, base_poly, alt_poly)?;

    Ok(is_match_branch)
}

// ── RerandomProof tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod rerandom_tests {
    use super::*;
    use crate::crypto::elgamal::{
        combine_public_keys, encrypt_poly, generate_key_share, rerandomize_poly_with_witness,
    };
    use rand::rngs::OsRng;

    fn setup_pk() -> PublicKey {
        let mut rng = OsRng;
        let (_sk1, pk1) = generate_key_share(&mut rng);
        let (_sk2, pk2) = generate_key_share(&mut rng);
        combine_public_keys(&pk1, &pk2)
    }

    /// Happy path: an honestly generated re-random proof verifies.
    #[test]
    fn test_rerandom_valid() {
        let mut rng = OsRng;
        let pk = setup_pk();

        let coeffs = [Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let in_poly = encrypt_poly(&mut rng, &pk, &coeffs);
        let (out_poly, r_vec) = rerandomize_poly_with_witness(&mut rng, &pk, &in_poly);

        let proof = prove_rerandom(&mut rng, &pk, &r_vec, &in_poly, &out_poly);
        verify_rerandom(&proof, &pk, &in_poly, &out_poly)
            .expect("valid re-random proof must verify");
    }

    /// A proof for one output must not verify against a differently re-randomized output.
    #[test]
    fn test_rerandom_wrong_output_rejected() {
        let mut rng = OsRng;
        let pk = setup_pk();

        let coeffs = [Scalar::from(5u64), Scalar::from(6u64)];
        let in_poly = encrypt_poly(&mut rng, &pk, &coeffs);
        let (out_poly, r_vec) = rerandomize_poly_with_witness(&mut rng, &pk, &in_poly);
        let (out_other, _)    = rerandomize_poly_with_witness(&mut rng, &pk, &in_poly);

        let proof = prove_rerandom(&mut rng, &pk, &r_vec, &in_poly, &out_poly);
        assert!(
            verify_rerandom(&proof, &pk, &in_poly, &out_other).is_err(),
            "proof must not verify against a different output polynomial"
        );
    }

    /// A proof built with wrong witnesses (r_vec doesn't match out_poly) must fail.
    #[test]
    fn test_rerandom_wrong_witness_rejected() {
        let mut rng = OsRng;
        let pk = setup_pk();

        let coeffs = [Scalar::from(7u64), Scalar::from(8u64), Scalar::from(9u64)];
        let in_poly = encrypt_poly(&mut rng, &pk, &coeffs);
        let (out_poly, _)       = rerandomize_poly_with_witness(&mut rng, &pk, &in_poly);
        let (_out_other, r_bad) = rerandomize_poly_with_witness(&mut rng, &pk, &in_poly);

        let proof = prove_rerandom(&mut rng, &pk, &r_bad, &in_poly, &out_poly);
        assert!(
            verify_rerandom(&proof, &pk, &in_poly, &out_poly).is_err(),
            "proof with wrong witnesses must be rejected"
        );
    }

    /// A proof under one key must not verify under a different key.
    #[test]
    fn test_rerandom_wrong_key_rejected() {
        let mut rng = OsRng;
        let pk      = setup_pk();
        let pk_other = setup_pk();

        let coeffs = [Scalar::from(3u64), Scalar::from(4u64)];
        let in_poly = encrypt_poly(&mut rng, &pk, &coeffs);
        let (out_poly, r_vec) = rerandomize_poly_with_witness(&mut rng, &pk, &in_poly);

        let proof = prove_rerandom(&mut rng, &pk, &r_vec, &in_poly, &out_poly);
        assert!(
            verify_rerandom(&proof, &pk_other, &in_poly, &out_poly).is_err(),
            "proof must not verify under a different public key"
        );
    }
}
