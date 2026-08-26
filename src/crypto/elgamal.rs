use curve25519_dalek_ng::{
    constants::RISTRETTO_BASEPOINT_TABLE, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use rand::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyShare {
    sk: Scalar,
}

impl SecretKeyShare {
    pub(crate) fn as_scalar(&self) -> &Scalar {
        &self.sk
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKeyShare(pub RistrettoPoint);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub RistrettoPoint);

#[derive(Clone, Debug)]
pub struct Ciphertext {
    pub c1: RistrettoPoint,
    pub c2: RistrettoPoint,
}

#[derive(Clone, Debug)]
pub struct EncryptedPoly(pub Vec<Ciphertext>);

#[inline]
fn mul_g(s: &Scalar) -> RistrettoPoint {
    s * &RISTRETTO_BASEPOINT_TABLE
}

pub fn generate_key_share<R: CryptoRng + RngCore>(rng: &mut R) -> (SecretKeyShare, PublicKeyShare) {
    let sk = Scalar::random(rng);
    let pk_share = mul_g(&sk);
    (SecretKeyShare { sk }, PublicKeyShare(pk_share))
}

pub fn combine_public_keys(pk1: &PublicKeyShare, pk2: &PublicKeyShare) -> PublicKey {
    PublicKey(pk1.0 + pk2.0)
}

pub fn encrypt<R: CryptoRng + RngCore>(rng: &mut R, pk: &PublicKey, msg: &Scalar) -> Ciphertext {
    encrypt_point(rng, pk, &mul_g(msg))
}

pub fn encrypt_point<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    msg_point: &RistrettoPoint,
) -> Ciphertext {
    let r = Scalar::random(rng);
    let r_g = mul_g(&r);
    Ciphertext {
        c1: r_g,
        c2: msg_point + r * pk.0,
    }
}

pub fn encrypt_zero<R: CryptoRng + RngCore>(rng: &mut R, pk: &PublicKey) -> Ciphertext {
    encrypt_point(rng, pk, &RistrettoPoint::identity())
}

pub fn encrypt_one<R: CryptoRng + RngCore>(rng: &mut R, pk: &PublicKey) -> Ciphertext {
    encrypt(rng, pk, &Scalar::one())
}

#[inline]
pub fn ct_add(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    Ciphertext {
        c1: a.c1 + b.c1,
        c2: a.c2 + b.c2,
    }
}

#[inline]
pub fn ct_scalar_mul(ct: &Ciphertext, s: &Scalar) -> Ciphertext {
    Ciphertext {
        c1: s * ct.c1,
        c2: s * ct.c2,
    }
}

pub fn rerandomize<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    ct: &Ciphertext,
) -> Ciphertext {
    let r = Scalar::random(rng);
    Ciphertext {
        c1: ct.c1 + mul_g(&r),
        c2: ct.c2 + r * pk.0,
    }
}

pub fn partial_decrypt_with_witness<R: CryptoRng + RngCore>(
    rng: &mut R,
    sk2: &SecretKeyShare,
    pk1: &PublicKeyShare,
    ct: &Ciphertext,
) -> (Ciphertext, Scalar) {
    let d = ct.c2 - sk2.sk * ct.c1;
    let r_prime = Scalar::random(rng);
    let out = Ciphertext {
        c1: ct.c1 + mul_g(&r_prime),
        c2: d + r_prime * pk1.0,
    };
    (out, r_prime)
}

pub fn partial_decrypt<R: CryptoRng + RngCore>(
    rng: &mut R,
    sk2: &SecretKeyShare,
    pk1: &PublicKeyShare,
    ct: &Ciphertext,
) -> Ciphertext {
    partial_decrypt_with_witness(rng, sk2, pk1, ct).0
}

pub fn test_zero(sk1: &SecretKeyShare, ct: &Ciphertext) -> bool {
    let m_point = ct.c2 - sk1.sk * ct.c1;
    m_point == RistrettoPoint::identity()
}

pub fn test_eq(sk1: &SecretKeyShare, ct: &Ciphertext, msg: &Scalar) -> bool {
    let m_point = ct.c2 - sk1.sk * ct.c1;
    m_point == mul_g(msg)
}

pub fn encrypt_poly<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    coeffs: &[Scalar],
) -> EncryptedPoly {
    EncryptedPoly(coeffs.iter().map(|c| encrypt(rng, pk, c)).collect())
}

pub fn rerandomize_poly_with_witness<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    poly: &EncryptedPoly,
) -> (EncryptedPoly, Vec<Scalar>) {
    let mut r_vec = Vec::with_capacity(poly.0.len());
    let mut out_cts = Vec::with_capacity(poly.0.len());
    for ct in &poly.0 {
        let r = Scalar::random(rng);
        out_cts.push(Ciphertext {
            c1: ct.c1 + mul_g(&r),
            c2: ct.c2 + r * pk.0,
        });
        r_vec.push(r);
    }
    (EncryptedPoly(out_cts), r_vec)
}

pub fn rerandomize_poly<R: CryptoRng + RngCore>(
    rng: &mut R,
    pk: &PublicKey,
    poly: &EncryptedPoly,
) -> EncryptedPoly {
    rerandomize_poly_with_witness(rng, pk, poly).0
}

pub fn eval_poly(poly: &EncryptedPoly, x: &Scalar) -> Ciphertext {
    assert!(
        !poly.0.is_empty(),
        "polynomial must have at least one coefficient"
    );

    let mut acc = poly.0.last().unwrap().clone();
    for ct in poly.0[..poly.0.len() - 1].iter().rev() {
        acc = ct_add(&ct_scalar_mul(&acc, x), ct);
    }
    acc
}

pub fn div_poly_linear(poly: &EncryptedPoly, x: &Scalar) -> EncryptedPoly {
    let n = poly
        .0
        .len()
        .checked_sub(1)
        .expect("polynomial must have degree >= 1");
    assert!(n >= 1, "can only divide a polynomial of degree >= 1");

    let mut quotient = Vec::with_capacity(n);
    quotient.push(poly.0[n].clone());
    for d in (0..n - 1).rev() {
        let scaled = ct_scalar_mul(quotient.last().unwrap(), x);
        quotient.push(ct_add(&poly.0[d + 1], &scaled));
    }
    quotient.reverse();

    EncryptedPoly(quotient)
}

pub fn poly_scalar_mul(poly: &EncryptedPoly, s: &Scalar) -> EncryptedPoly {
    EncryptedPoly(poly.0.iter().map(|ct| ct_scalar_mul(ct, s)).collect())
}

pub fn poly_add(a: &EncryptedPoly, b: &EncryptedPoly) -> EncryptedPoly {
    let (longer, shorter) = if a.0.len() >= b.0.len() {
        (&a.0, &b.0)
    } else {
        (&b.0, &a.0)
    };
    let mut result = longer.clone();
    for (d, ct) in shorter.iter().enumerate() {
        result[d] = ct_add(&result[d], ct);
    }
    EncryptedPoly(result)
}

pub fn poly_mul_linear(poly: &EncryptedPoly, x: &Scalar) -> EncryptedPoly {
    let n = poly.0.len();
    let neg_x = -x;
    let mut result = Vec::with_capacity(n + 1);

    result.push(ct_scalar_mul(&poly.0[0], &neg_x));

    for d in 1..n {
        let term = ct_add(&poly.0[d - 1], &ct_scalar_mul(&poly.0[d], &neg_x));
        result.push(term);
    }

    result.push(poly.0[n - 1].clone());

    EncryptedPoly(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn setup() -> (
        SecretKeyShare,
        PublicKeyShare,
        SecretKeyShare,
        PublicKeyShare,
        PublicKey,
    ) {
        let mut rng = OsRng;
        let (sk1, pk1) = generate_key_share(&mut rng);
        let (sk2, pk2) = generate_key_share(&mut rng);
        let pk = combine_public_keys(&pk1, &pk2);
        (sk1, pk1, sk2, pk2, pk)
    }

    #[test]
    fn test_threshold_decrypt_zero() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let ct = encrypt_zero(&mut rng, &pk);

        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct);
        assert!(test_zero(&sk1, &ct_half));
    }

    #[test]
    fn test_threshold_decrypt_nonzero() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let msg = Scalar::from(42u64);
        let ct = encrypt(&mut rng, &pk, &msg);

        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct);
        assert!(!test_zero(&sk1, &ct_half));
        assert!(test_eq(&sk1, &ct_half, &msg));
    }

    #[test]
    fn test_homomorphic_add() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let a = Scalar::from(7u64);
        let b = Scalar::from(11u64);
        let ct_a = encrypt(&mut rng, &pk, &a);
        let ct_b = encrypt(&mut rng, &pk, &b);

        let ct_sum = ct_add(&ct_a, &ct_b);
        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct_sum);
        assert!(test_eq(&sk1, &ct_half, &(a + b)));
    }

    #[test]
    fn test_scalar_mul() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let m = Scalar::from(5u64);
        let s = Scalar::from(3u64);
        let ct = encrypt(&mut rng, &pk, &m);

        let ct_scaled = ct_scalar_mul(&ct, &s);
        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct_scaled);
        assert!(test_eq(&sk1, &ct_half, &(m * s)));
    }

    #[test]
    fn test_rerandomize() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let msg = Scalar::from(99u64);
        let ct = encrypt(&mut rng, &pk, &msg);
        let ct_rand = rerandomize(&mut rng, &pk, &ct);

        assert_ne!(ct.c1, ct_rand.c1);

        let ct_half = partial_decrypt(&mut rng, &sk2, &pk1, &ct_rand);
        assert!(test_eq(&sk1, &ct_half, &msg));
    }

    #[test]
    fn test_eval_poly() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let coeffs = [Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let x = Scalar::from(4u64);
        let expected = Scalar::from(57u64);

        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);
        let eval_ct = eval_poly(&poly_ct, &x);

        let eval_half = partial_decrypt(&mut rng, &sk2, &pk1, &eval_ct);
        assert!(test_eq(&sk1, &eval_half, &expected));
    }

    #[test]
    fn test_div_poly_linear() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let coeffs = [Scalar::from(6u64), -Scalar::from(5u64), Scalar::from(1u64)];
        let root = Scalar::from(2u64);

        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);
        let quot_ct = div_poly_linear(&poly_ct, &root);

        assert_eq!(quot_ct.0.len(), 2);

        let c0_half = partial_decrypt(&mut rng, &sk2, &pk1, &quot_ct.0[0]);
        assert!(test_eq(&sk1, &c0_half, &(-Scalar::from(3u64))));

        let c1_half = partial_decrypt(&mut rng, &sk2, &pk1, &quot_ct.0[1]);
        assert!(test_eq(&sk1, &c1_half, &Scalar::from(1u64)));
    }

    #[test]
    fn test_mul_then_div() {
        let mut rng = OsRng;
        let (sk1, pk1, sk2, _pk2, pk) = setup();

        let coeffs = [Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64)];
        let root = Scalar::from(7u64);

        let poly_ct = encrypt_poly(&mut rng, &pk, &coeffs);
        let expanded = poly_mul_linear(&poly_ct, &root);
        let recovered = div_poly_linear(&expanded, &root);

        assert_eq!(recovered.0.len(), coeffs.len());

        for (d, (orig, recov)) in coeffs.iter().zip(recovered.0.iter()).enumerate() {
            let half = partial_decrypt(&mut rng, &sk2, &pk1, recov);
            assert!(test_eq(&sk1, &half, orig), "mismatch at degree {d}");
        }
    }
}
