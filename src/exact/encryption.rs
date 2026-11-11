//! Exact-only ElGamal operations that expose the randomness used by the proof witnesses.
//! Shared ciphertext/key types are kept. Multiplications by G use the static basepoint
//! table and multiplications by PK a cached table for that key.
use super::performance::{mul_g, table};
use crate::crypto::elgamal::{Ciphertext, EncryptedPoly, PublicKey};
use curve25519_dalek_ng::{
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
    traits::Identity,
};
use rand::{CryptoRng, RngCore};

/// Enc(m; r) = (rG, mG + rPK), where `pk` is the key's fixed-base table.
pub(crate) fn encrypt_with_randomness(
    pk: &RistrettoBasepointTable,
    m: Scalar,
    r: Scalar,
) -> Ciphertext {
    Ciphertext {
        c1: mul_g(&r),
        c2: mul_g(&m) + &r * pk,
    }
}
pub(crate) fn encrypt_poly<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    coeffs: &[Scalar],
) -> Result<EncryptedPoly, String> {
    if pk.0 == RistrettoPoint::identity() {
        return Err("identity encryption key".into());
    }
    let pk = table(&pk.0);
    Ok(EncryptedPoly(
        coeffs
            .iter()
            .map(|m| encrypt_with_randomness(&pk, *m, Scalar::random(rng)))
            .collect(),
    ))
}
pub(crate) fn rerandomize_poly_with_witness<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    poly: &EncryptedPoly,
) -> (EncryptedPoly, Vec<Scalar>) {
    let pk = table(&pk.0);
    let mut randomness = Vec::with_capacity(poly.0.len());
    let out = poly
        .0
        .iter()
        .map(|ct| {
            let r = Scalar::random(rng);
            randomness.push(r);
            Ciphertext {
                c1: ct.c1 + mul_g(&r),
                c2: ct.c2 + &r * &*pk,
            }
        })
        .collect();
    (EncryptedPoly(out), randomness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::elgamal;
    use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT as G;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn encryption_and_shared_types_preserve_threshold_relations() {
        let mut rng = StdRng::seed_from_u64(915);
        let (sk1, pk1) = elgamal::generate_key_share(&mut rng);
        let (sk2, pk2) = elgamal::generate_key_share(&mut rng);
        let pk = elgamal::combine_public_keys(&pk1, &pk2);
        for m in [Scalar::zero(), Scalar::one(), -Scalar::one()] {
            for r in [Scalar::zero(), Scalar::from(13u64)] {
                let ct = encrypt_with_randomness(&table(&pk.0), m, r);
                assert_eq!(ct.c1, r * G);
                assert_eq!(ct.c2, m * G + r * pk.0);
                let (partial, rho) =
                    elgamal::partial_decrypt_with_witness(&mut rng, &sk2, &pk1, &ct);
                assert_eq!(partial.c1, ct.c1 + rho * G);
                assert_eq!(partial.c2, ct.c2 - sk2.as_scalar() * ct.c1 + rho * pk1.0);
                assert_eq!(elgamal::test_zero(&sk1, &partial), m == Scalar::zero());
            }
        }
        let poly = encrypt_poly(&mut rng, &pk, &[Scalar::zero(), Scalar::one()]).unwrap();
        for (ct, m) in poly.0.iter().zip([Scalar::zero(), Scalar::one()]) {
            let half = elgamal::partial_decrypt(&mut rng, &sk2, &pk1, ct);
            assert!(elgamal::test_eq(&sk1, &half, &m));
        }
        let (updated, r) = rerandomize_poly_with_witness(&mut rng, &pk, &poly);
        for (i, rho) in r.iter().enumerate() {
            assert_eq!(updated.0[i].c1, poly.0[i].c1 + rho * G);
            assert_eq!(updated.0[i].c2, poly.0[i].c2 + rho * pk.0);
        }
        let identity = PublicKey(RistrettoPoint::identity());
        assert!(encrypt_poly(&mut rng, &identity, &[Scalar::one()]).is_err());
    }
}
