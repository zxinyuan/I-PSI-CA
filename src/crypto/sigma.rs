use curve25519_dalek_ng::{
    constants::{RISTRETTO_BASEPOINT_POINT as G, RISTRETTO_BASEPOINT_TABLE},
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{Identity, VartimeMultiscalarMul},
};
use merlin::Transcript;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::crypto::elgamal::{Ciphertext, EncryptedPoly, PublicKeyShare};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialDecryptProof {
    pub a: CompressedRistretto,
    pub z1: Scalar,
    pub z2: Scalar,
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

fn combine_scalar(t: &mut Transcript) -> Scalar {
    let mut buf = [0u8; 64];
    t.challenge_bytes(b"combine", &mut buf);
    Scalar::from_bytes_mod_order_wide(&buf)
}

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

pub fn prove<R: CryptoRng + RngCore>(
    rng: &mut R,
    sk2: &Scalar,
    r_prime: Scalar,
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    in_ct: &Ciphertext,
    out_ct: &Ciphertext,
) -> PartialDecryptProof {
    let a = Scalar::random(rng);
    let b = Scalar::random(rng);

    let (beta, gamma) = partial_decrypt_relation_scalars(pk2, pk1, in_ct, out_ct);

    let beta_g = mul_g(&beta);
    let a_g = mul_g(&a);
    let rhs_base = pk1.0 + beta_g;
    let gamma_c1 = RistrettoPoint::vartime_multiscalar_mul([gamma], [in_ct.c1]);
    let gamma_rhs = RistrettoPoint::vartime_multiscalar_mul([gamma], [rhs_base]);
    let a_comb = a_g - a * gamma_c1 + b * gamma_rhs;

    let mut t = statement_transcript(pk2, pk1, in_ct, out_ct);
    t.append_message(b"beta", &beta.to_bytes());
    t.append_message(b"gamma", &gamma.to_bytes());
    append_point(&mut t, b"A", &a_comb);
    let e = challenge_scalar(&mut t);

    let z1 = a + e * sk2;
    let z2 = b + e * r_prime;

    PartialDecryptProof {
        a: a_comb.compress(),
        z1,
        z2,
    }
}

pub fn verify(
    proof: &PartialDecryptProof,
    pk2: &PublicKeyShare,
    pk1: &PublicKeyShare,
    in_ct: &Ciphertext,
    out_ct: &Ciphertext,
) -> Result<(), &'static str> {
    let a = proof
        .a
        .decompress()
        .ok_or("A is not a valid Ristretto point")?;

    let (beta, gamma) = partial_decrypt_relation_scalars(pk2, pk1, in_ct, out_ct);

    let mut t = statement_transcript(pk2, pk1, in_ct, out_ct);
    t.append_message(b"beta", &beta.to_bytes());
    t.append_message(b"gamma", &gamma.to_bytes());
    append_point(&mut t, b"A", &a);
    let e = challenge_scalar(&mut t);

    let z1 = proof.z1;
    let z2 = proof.z2;

    let delta_c1 = out_ct.c1 - in_ct.c1;
    let delta_c2 = out_ct.c2 - in_ct.c2;

    let check = RistrettoPoint::vartime_multiscalar_mul(
        [
            z1 + z2 * gamma * beta,
            -(z1 * gamma),
            z2 * gamma,
            -Scalar::one(),
            -e,
            -(e * gamma),
            -(e * gamma * beta),
        ],
        [G, in_ct.c1, pk1.0, a, pk2.0, delta_c2, delta_c1],
    );
    if check != RistrettoPoint::identity() {
        return Err(
            "V failed: batched key-ownership + rerandomization + partial-decryption consistency",
        );
    }

    Ok(())
}

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

    let x_c1 = RistrettoPoint::vartime_multiscalar_mul(
        alphas.iter().copied(),
        in_poly.0.iter().map(|ct| ct.c1),
    );
    let x_c2 = RistrettoPoint::vartime_multiscalar_mul(
        alphas.iter().copied(),
        in_poly.0.iter().map(|ct| ct.c2),
    );
    let y_c1 = RistrettoPoint::vartime_multiscalar_mul(
        alphas.iter().copied(),
        out_poly.0.iter().map(|ct| ct.c1),
    );
    let y_c2 = RistrettoPoint::vartime_multiscalar_mul(
        alphas.iter().copied(),
        out_poly.0.iter().map(|ct| ct.c2),
    );

    (x_c1, x_c2, y_c1, y_c2, alphas)
}

pub(crate) fn poly_scalar_mul_x_points(
    in_poly: &EncryptedPoly,
    out_poly: &EncryptedPoly,
    alpha_tag: &RistrettoPoint,
) -> (RistrettoPoint, RistrettoPoint) {
    let n = in_poly.0.len();
    let mut t = poly_scalar_mul_transcript(in_poly, out_poly, alpha_tag);
    let alphas: Vec<Scalar> = (0..n).map(|_| squeeze_weight(&mut t)).collect();

    let x_c1 = RistrettoPoint::vartime_multiscalar_mul(
        alphas.iter().copied(),
        in_poly.0.iter().map(|ct| ct.c1),
    );
    let x_c2 = RistrettoPoint::vartime_multiscalar_mul(
        alphas.iter().copied(),
        in_poly.0.iter().map(|ct| ct.c2),
    );
    (x_c1, x_c2)
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
    let (x_c1, x_c2) = poly_scalar_mul_x_points(in_poly, out_poly, alpha_tag);
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

    #[test]
    fn test_valid_proof_scaled_poly_eval() {
        let mut rng = OsRng;
        let (_sk1, pk1, sk2, pk2, pk) = setup();

        let coeffs = [Scalar::from(6u64), -Scalar::from(5u64), Scalar::from(1u64)];
        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);

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
