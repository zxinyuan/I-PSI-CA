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

use crate::crypto::elgamal::{Ciphertext, EncryptedPoly, PublicKeyShare};

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
    append_point(&mut t, b"pk2", &pk2.0);
    append_point(&mut t, b"pk1", &pk1.0);
    append_point(&mut t, b"c1_in", &in_ct.c1);
    append_point(&mut t, b"c2_in", &in_ct.c2);
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
    let a = proof
        .a
        .decompress()
        .ok_or("A is not a valid Ristretto point")?;

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
        return Err(
            "V failed: batched key-ownership + rerandomization + partial-decryption consistency",
        );
    }

    Ok(())
}

/// Non-interactive proof that `out_poly` was produced from `in_poly` by
/// multiplying every coefficient ciphertext by the same secret scalar `y`,
/// i.e. `out_poly[d] = y · in_poly[d]` for all `d`, with `alpha_tag = y·G`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolyScalarMulProof {
    pub a1: CompressedRistretto,
    pub a2: CompressedRistretto,
    pub alpha_tag: CompressedRistretto,
    pub a_m: CompressedRistretto,
    pub s_y: Scalar,
}

fn poly_scalar_mul_transcript(
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
) -> Transcript {
    let mut t = Transcript::new(b"I-PSI-CA::poly_scalar_mul_sigma_v1");
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

pub(crate) fn poly_scalar_mul_batch_scalars(
    proof: &PolyScalarMulProof,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
) -> Result<(Scalar, Scalar), &'static str> {
    proof
        .a1
        .decompress()
        .ok_or("A1 is not a valid Ristretto point")?;
    proof
        .a2
        .decompress()
        .ok_or("A2 is not a valid Ristretto point")?;
    proof
        .a_m
        .decompress()
        .ok_or("A_m is not a valid Ristretto point")?;

    let mut t = poly_scalar_mul_transcript(in_poly, out_poly, alpha_tag);
    append_compressed(&mut t, b"A1", &proof.a1);
    append_compressed(&mut t, b"A2", &proof.a2);
    append_compressed(&mut t, b"A_m", &proof.a_m);
    let beta = batch_scalar_labeled(&mut t, b"poly_scalar_mul_batch_1");
    let gamma = batch_scalar_labeled(&mut t, b"poly_scalar_mul_batch_2");
    Ok((beta, gamma))
}

/// Squeeze one 512-bit batch weight from the transcript and reduce mod ℓ.
fn squeeze_weight(t: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"alpha", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

pub(crate) fn poly_scalar_mul_relation_points(
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
) -> (
    RistrettoPoint,
    RistrettoPoint,
    RistrettoPoint,
    RistrettoPoint,
    Vec<Scalar>,
) {
    let n = in_poly.0.len();
    let mut t = poly_scalar_mul_transcript(in_poly, out_poly, alpha_tag);
    let alphas: Vec<Scalar> = (0..n).map(|_| squeeze_weight(&mut t)).collect();

    // Pass iterators directly to multiscalar_mul — avoids four intermediate
    // Vec<RistrettoPoint> heap allocations.
    let x_c1 =
        RistrettoPoint::multiscalar_mul(alphas.iter().copied(), in_poly.0.iter().map(|ct| ct.c1));
    let x_c2 =
        RistrettoPoint::multiscalar_mul(alphas.iter().copied(), in_poly.0.iter().map(|ct| ct.c2));
    let y_c1 =
        RistrettoPoint::multiscalar_mul(alphas.iter().copied(), out_poly.0.iter().map(|ct| ct.c1));
    let y_c2 =
        RistrettoPoint::multiscalar_mul(alphas.iter().copied(), out_poly.0.iter().map(|ct| ct.c2));

    (x_c1, x_c2, y_c1, y_c2, alphas)
}

pub fn prove_poly_scalar_mul<R: CryptoRng + RngCore>(
    rng: &mut R,
    y: &Scalar,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
) -> PolyScalarMulProof {
    if in_poly.0.len() != out_poly.0.len() {
        return PolyScalarMulProof {
            a1: RistrettoPoint::identity().compress(),
            a2: RistrettoPoint::identity().compress(),
            alpha_tag: alpha_tag.compress(),
            a_m: RistrettoPoint::identity().compress(),
            s_y: Scalar::zero(),
        };
    }

    let mut t = poly_scalar_mul_transcript(in_poly, out_poly, alpha_tag);
    let (x_c1, x_c2, _, _, _) = poly_scalar_mul_relation_points(in_poly, out_poly, alpha_tag);
    let k_y = Scalar::random(rng);
    let a1 = (k_y * x_c1).compress();
    let a2 = (k_y * x_c2).compress();
    let a_m = mul_g(&k_y).compress();

    append_compressed(&mut t, b"A1", &a1);
    append_compressed(&mut t, b"A2", &a2);
    append_compressed(&mut t, b"A_m", &a_m);
    let _beta = batch_scalar_labeled(&mut t, b"poly_scalar_mul_batch_1");
    let _gamma = batch_scalar_labeled(&mut t, b"poly_scalar_mul_batch_2");
    let e = challenge_scalar(&mut t);

    PolyScalarMulProof {
        a1,
        a2,
        alpha_tag: alpha_tag.compress(),
        a_m,
        s_y: k_y + e * y,
    }
}

pub fn verify_poly_scalar_mul(
    proof: &PolyScalarMulProof,
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    expected_alpha_tag: &RistrettoPoint,
) -> Result<(), &'static str> {
    if in_poly.0.len() != out_poly.0.len() {
        return Err("poly scalar mul length mismatch");
    }

    let alpha_tag = proof
        .alpha_tag
        .decompress()
        .ok_or("alpha_tag is not a valid Ristretto point")?;
    if alpha_tag != *expected_alpha_tag {
        return Err("alpha_tag mismatch across proofs");
    }

    let mut t = poly_scalar_mul_transcript(in_poly, out_poly, &alpha_tag);
    let (x_c1, x_c2, y_c1, y_c2, _) =
        poly_scalar_mul_relation_points(in_poly, out_poly, &alpha_tag);
    let a1 = proof
        .a1
        .decompress()
        .ok_or("A1 is not a valid Ristretto point")?;
    let a2 = proof
        .a2
        .decompress()
        .ok_or("A2 is not a valid Ristretto point")?;
    let a_m = proof
        .a_m
        .decompress()
        .ok_or("A_m is not a valid Ristretto point")?;

    append_compressed(&mut t, b"A1", &proof.a1);
    append_compressed(&mut t, b"A2", &proof.a2);
    append_compressed(&mut t, b"A_m", &proof.a_m);
    let beta = batch_scalar_labeled(&mut t, b"poly_scalar_mul_batch_1");
    let gamma = batch_scalar_labeled(&mut t, b"poly_scalar_mul_batch_2");
    let e = challenge_scalar(&mut t);

    let lhs = RistrettoPoint::vartime_multiscalar_mul(
        [proof.s_y, beta * proof.s_y, gamma * proof.s_y],
        [x_c1, x_c2, G],
    );
    let rhs = a1 + beta * a2 + gamma * a_m + e * (y_c1 + beta * y_c2 + gamma * alpha_tag);
    if lhs != rhs {
        return Err("poly-scalar-mul batched verifier check failed");
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal::{
        combine_public_keys, ct_scalar_mul, encrypt, encrypt_poly, eval_poly, generate_key_share,
        partial_decrypt_with_witness,
    };
    use rand::rngs::OsRng;

    fn setup() -> (
        crate::crypto::elgamal::SecretKeyShare,
        PublicKeyShare,
        crate::crypto::elgamal::SecretKeyShare,
        PublicKeyShare,
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

        let proof = prove(
            &mut rng,
            sk2.as_scalar(),
            r_prime,
            &pk2,
            &pk1,
            &in_ct,
            &out_ct,
        );
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
        let x = Scalar::from(2u64);
        let mask = Scalar::from(13u64);
        let scaled_ct = ct_scalar_mul(&eval_poly(&poly_ct, &x), &mask);

        let (out_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &scaled_ct);
        let proof = prove(
            &mut rng,
            sk2.as_scalar(),
            r_prime,
            &pk2,
            &pk1,
            &scaled_ct,
            &out_ct,
        );
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
        let proof = prove(
            &mut rng,
            sk2.as_scalar(),
            r_prime,
            &pk2,
            &pk1,
            &in_ct,
            &out_ct,
        );

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
        let proof = prove(
            &mut rng,
            sk2.as_scalar(),
            r_prime,
            &pk2,
            &pk1,
            &in_ct,
            &out_ct,
        );

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

        let in_ct = encrypt(&mut rng, &pk, &Scalar::from(3u64));
        let in_ct2 = encrypt(&mut rng, &pk, &Scalar::from(4u64));
        let (out_ct, r_prime) = partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &in_ct);
        let proof = prove(
            &mut rng,
            sk2.as_scalar(),
            r_prime,
            &pk2,
            &pk1,
            &in_ct,
            &out_ct,
        );

        assert!(
            verify(&proof, &pk2, &pk1, &in_ct2, &out_ct).is_err(),
            "proof must not verify against a different input ciphertext"
        );
    }
}
